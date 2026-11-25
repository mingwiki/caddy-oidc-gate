package caddyoidcgate

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(&Handler{})
}

// Fixed auth actions, appended to path_prefix. They are the only routing
// knowledge in the plugin: dispatch, the login redirect and the callback
// redirect_uri all read them from here.
const (
	actionLogin    = "/login"
	actionCallback = "/callback"
	actionLogout   = "/logout"
)

// authHandler resolves the part of the request path below path_prefix to an
// endpoint, or nil when the request is not an auth request.
func (h *Handler) authHandler(p string) func(http.ResponseWriter, *http.Request) error {
	switch p {
	case actionLogin:
		return h.serveLogin
	case actionCallback:
		return h.serveCallback
	case actionLogout:
		return h.serveLogout
	}
	return nil
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

	// PathPrefix is where the login, callback and logout endpoints live
	// (default "/auth"). Upstreams often own /auth/* themselves.
	PathPrefix string `json:"path_prefix,omitempty"`

	// AllowedGroups restricts login to users holding one of these groups. Empty
	// means no group filtering: whoever the provider authenticates gets in.
	AllowedGroups []string `json:"allowed_groups,omitempty"`
	// GroupsClaim is the claim carrying group names (default "groups").
	GroupsClaim string `json:"groups_claim,omitempty"`

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

	// mu guards the provider fields, which are initialised lazily so Caddy can
	// start while the provider is unreachable.
	mu            sync.Mutex
	lastInitErr   error
	lastInitTried time.Time

	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

func (*Handler) CaddyModule() caddy.ModuleInfo {
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
	// Best effort: an unreachable provider must not stop Caddy from loading.
	// ServeHTTP retries and answers 503 until discovery succeeds.
	_ = h.ensureOIDC(ctx.Context)
	return nil
}

func (h *Handler) Validate() error {
	return h.validate()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if err := h.ensureOIDC(r.Context()); err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return nil
	}

	if p, ok := strings.CutPrefix(r.URL.Path, h.PathPrefix); ok {
		if serve := h.authHandler(p); serve != nil {
			return serve(w, r)
		}
	}

	h.stripAuthHeaders(r)

	if idToken, ok := h.authenticate(w, r); ok {
		if !h.InjectHeaders || h.injectHeaders(w, r, idToken) {
			return next.ServeHTTP(w, r)
		}
	}

	loginURL := url.URL{Path: h.PathPrefix + actionLogin}
	q := loginURL.Query()
	q.Set("return_to", r.URL.RequestURI())
	loginURL.RawQuery = q.Encode()
	http.Redirect(w, r, loginURL.String(), http.StatusFound)
	return nil
}

const providerRetryInterval = 30 * time.Second

// ensureOIDC initialises the OIDC provider on first use. Failed attempts are
// retried at most once per providerRetryInterval so a provider outage costs one
// failing discovery call per window instead of one per request.
func (h *Handler) ensureOIDC(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.verifier != nil {
		return nil
	}
	if h.lastInitErr != nil && time.Since(h.lastInitTried) < providerRetryInterval {
		return h.lastInitErr
	}
	if h.logger == nil {
		return errors.New("auth_oidc: handler not provisioned")
	}

	h.lastInitTried = time.Now()
	if err := h.initOIDC(ctx); err != nil {
		h.lastInitErr = err
		h.logger.Error("oidc provider unavailable, retrying later", zap.Error(err))
		return err
	}
	h.lastInitErr = nil
	h.logger.Info("oidc provider ready", zap.String("discovery_url", h.Provider))
	return nil
}

// authReady reports whether the provider is initialised, answering 503 when it
// is not. It keeps the auth endpoints safe to call without ServeHTTP's gate.
func (h *Handler) authReady(w http.ResponseWriter) bool {
	if h.verifier != nil {
		return true
	}
	http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	return false
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
func (h *Handler) stripAuthHeaders(r *http.Request) {
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
func (h *Handler) injectHeaders(w http.ResponseWriter, r *http.Request, idToken *oidc.IDToken) bool {
	claims := map[string]interface{}{}
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
