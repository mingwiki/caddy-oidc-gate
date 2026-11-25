package caddyauthoidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(Handler{})
}

type Handler struct {
	Provider string `json:"provider,omitempty"`

	// IssuerURL overrides the issuer URL for OIDC provider validation.
	// Use this when the discovery URL differs from the issuer URL in the
	// provider's metadata (e.g. discovering via localhost but validating
	// against the external domain).
	IssuerURL string `json:"issuer_url,omitempty"`

	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`

	Scopes []string `json:"scopes,omitempty"`

	CookieDomain string         `json:"cookie_domain,omitempty"`
	CookieName   string         `json:"cookie_name,omitempty"`
	CookiePath   string         `json:"cookie_path,omitempty"`
	CookieTTL    caddy.Duration `json:"cookie_ttl,omitempty"`
	StateTTL     caddy.Duration `json:"state_ttl,omitempty"`

	InjectHeaders bool   `json:"inject_headers,omitempty"`
	HeaderPrefix  string `json:"header_prefix,omitempty"`

	LogoutRedirect string `json:"logout_redirect,omitempty"`

	RefreshLeeway caddy.Duration `json:"refresh_leeway,omitempty"`

	ForceHTTPSCookie *bool `json:"force_https_cookie,omitempty"`

	logger       *zap.Logger
	flowCodec    *securecookie.SecureCookie
	sessionCodec *securecookie.SecureCookie

	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.auth_oidc",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	h.applyDefaults()
	if err := h.validate(); err != nil {
		return err
	}
	if err := h.initCookieCodecs(); err != nil {
		return err
	}
	return h.initOIDC(ctx.Context)
}

func (h Handler) Validate() error {
	return h.validate()
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	switch r.URL.Path {
	case "/auth/login":
		return h.serveLogin(w, r)
	case "/auth/callback":
		return h.serveCallback(w, r)
	case "/auth/logout":
		return h.serveLogout(w, r)
	}

	h.stripAuthHeaders(r)

	if idToken, ok := h.authenticate(w, r); ok {
		if !h.InjectHeaders || h.injectHeaders(w, r, idToken) {
			return next.ServeHTTP(w, r)
		}
	}

	loginURL := url.URL{Path: "/auth/login"}
	q := loginURL.Query()
	q.Set("return_to", r.URL.RequestURI())
	loginURL.RawQuery = q.Encode()
	http.Redirect(w, r, loginURL.String(), http.StatusFound)
	return nil
}

// authenticate returns the verified ID token for the request, refreshing the
// session when its ID token is near expiry. A session that cannot be refreshed
// or verified is cleared so the browser performs a clean login instead of
// retrying on every request.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (*oidc.IDToken, bool) {
	sess, err := h.readSessionCookie(r)
	if err != nil {
		return nil, false
	}

	refreshed := false
	if sess.RefreshToken != "" && time.Until(sess.ExpiresAt) < time.Duration(h.RefreshLeeway) {
		sess, err = h.refresh(r, sess)
		if err != nil {
			h.logger.Warn("token refresh failed, clearing session", zap.Error(err))
			h.clearSessionCookie(w, r)
			return nil, false
		}
		refreshed = true
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	idToken, err := h.verifier.Verify(ctx, sess.IDToken)
	if err != nil {
		h.logger.Warn("failed to verify session id token, clearing session", zap.Error(err))
		h.clearSessionCookie(w, r)
		return nil, false
	}

	if refreshed {
		sess.ExpiresAt = idToken.Expiry
		if err := h.setSessionCookie(w, r, sess); err != nil {
			h.logger.Error("failed to set refreshed session cookie", zap.Error(err))
		}
	}
	return idToken, true
}

// refresh exchanges the refresh token for a new session token set. The returned
// session is not verified here; authenticate verifies it once for every request.
func (h *Handler) refresh(r *http.Request, sess sessionData) (sessionData, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// The access token is only a cache hint for oauth2; the refresh token alone
	// is enough to request a new pair.
	token, err := h.oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: sess.RefreshToken}).Token()
	if err != nil {
		return sessionData{}, err
	}

	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return sessionData{}, errors.New("refresh response has no id_token")
	}
	sess.IDToken = rawIDToken
	if token.RefreshToken != "" {
		sess.RefreshToken = token.RefreshToken
	}
	return sess, nil
}

// stripAuthHeaders removes client-supplied headers with the configured prefix
// so upstream apps can trust injected identity headers.
func (h Handler) stripAuthHeaders(r *http.Request) {
	prefix := http.CanonicalHeaderKey(h.HeaderPrefix)
	if prefix == "" {
		return
	}
	for name := range r.Header {
		if strings.HasPrefix(name, prefix) {
			r.Header.Del(name)
		}
	}
}

// injectHeaders adds the verified claims to the request. It reports whether the
// claims could be decoded; on failure the session is cleared so the caller
// redirects to login instead of forwarding an unauthenticated request.
func (h Handler) injectHeaders(w http.ResponseWriter, r *http.Request, idToken *oidc.IDToken) bool {
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		h.logger.Warn("failed to decode session id token claims, clearing session", zap.Error(err))
		h.clearSessionCookie(w, r)
		return false
	}

	if sub, ok := claims["sub"].(string); ok {
		r.Header.Set(h.HeaderPrefix+"Subject", sub)
	}
	if email, ok := claims["email"].(string); ok {
		r.Header.Set(h.HeaderPrefix+"Email", email)
	}
	if name, ok := claims["name"].(string); ok {
		r.Header.Set(h.HeaderPrefix+"Name", name)
	} else if prefName, ok := claims["preferred_username"].(string); ok {
		r.Header.Set(h.HeaderPrefix+"Name", prefName)
	}
	r.Header.Set(h.HeaderPrefix+"Issuer", idToken.Issuer)
	return true
}
