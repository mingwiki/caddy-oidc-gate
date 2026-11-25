package caddyauthoidc

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func (h *Handler) serveLogin(w http.ResponseWriter, r *http.Request) error {
	if !h.authReady(w) {
		return nil
	}
	w.Header().Set("Cache-Control", "no-store")

	returnTo := r.URL.Query().Get("return_to")
	if !isLocalPath(returnTo) {
		returnTo = "/"
	}
	// Already logged in: skip the provider round trip.
	if _, err := h.readSessionCookie(r); err == nil {
		http.Redirect(w, r, returnTo, http.StatusFound)
		return nil
	}

	state, err := generateRandomString(32)
	if err != nil {
		h.logger.Error("failed to generate state", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	nonce, err := generateRandomString(32)
	if err != nil {
		h.logger.Error("failed to generate nonce", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		h.logger.Error("failed to generate pkce", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	fs := flowState{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ReturnTo:     returnTo,
	}

	if err := h.setFlowStateCookie(w, r, fs); err != nil {
		h.logger.Error("failed to set flow state cookie", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	authURL := h.oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("redirect_uri", h.getCallbackURL(r)),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

func (h *Handler) serveCallback(w http.ResponseWriter, r *http.Request) error {
	if !h.authReady(w) {
		return nil
	}
	w.Header().Set("Cache-Control", "no-store")

	fs, err := h.readFlowStateCookie(r)
	if err != nil {
		h.logger.Warn("failed to read flow state cookie", zap.Error(err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	// Clear flow state cookie
	h.clearFlowStateCookie(w, r)

	q := r.URL.Query()
	if providerErr := q.Get("error"); providerErr != "" {
		h.logger.Warn("provider returned error",
			zap.String("error", providerErr),
			zap.String("description", q.Get("error_description")))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(fs.State)) != 1 {
		h.logger.Warn("state mismatch")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	code := q.Get("code")
	if code == "" {
		h.logger.Warn("no code in callback")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	oauth2Token, err := h.oauth2Config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", fs.PKCEVerifier),
		oauth2.SetAuthURLParam("redirect_uri", h.getCallbackURL(r)),
	)
	if err != nil {
		h.logger.Error("failed to exchange code", zap.Error(err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		h.logger.Error("no id_token in token response")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	idToken, err := h.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		h.logger.Error("failed to verify id token", zap.Error(err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	if idToken.Nonce != fs.Nonce {
		h.logger.Warn("nonce mismatch", zap.String("sub", idToken.Subject))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	sess := sessionData{
		IDToken:      rawIDToken,
		RefreshToken: oauth2Token.RefreshToken,
		ExpiresAt:    idToken.Expiry,
	}

	if err := h.setSessionCookie(w, r, sess); err != nil {
		h.logger.Error("failed to set session cookie", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	h.logger.Info("login succeeded",
		zap.String("sub", idToken.Subject),
		zap.String("remote_ip", r.RemoteAddr))
	http.Redirect(w, r, fs.ReturnTo, http.StatusFound)
	return nil
}

func (h *Handler) serveLogout(w http.ResponseWriter, r *http.Request) error {
	if !h.authReady(w) {
		return nil
	}
	w.Header().Set("Cache-Control", "no-store")

	// Logout is a state change reachable via top-level GET navigation, so refuse
	// cross-site requests (logout CSRF).
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		h.logger.Warn("cross-site logout blocked", zap.String("remote_ip", r.RemoteAddr))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil
	}

	h.clearFlowStateCookie(w, r)

	// Read session before clearing to get ID token hint if possible
	var idTokenHint string
	if sess, err := h.readSessionCookie(r); err == nil {
		idTokenHint = sess.IDToken
	}

	h.clearSessionCookie(w, r)

	redirectURL := h.LogoutRedirect

	// Best-effort provider end-session
	if h.provider != nil {
		var claims struct {
			EndSessionEndpoint string `json:"end_session_endpoint"`
		}
		if err := h.provider.Claims(&claims); err == nil && claims.EndSessionEndpoint != "" {
			u, err := url.Parse(claims.EndSessionEndpoint)
			if err == nil {
				q := u.Query()
				if idTokenHint != "" {
					q.Set("id_token_hint", idTokenHint)
				}

				absRedirect := h.getAbsoluteRedirectURL(r, redirectURL)
				if absRedirect != "" {
					q.Set("post_logout_redirect_uri", absRedirect)
				}

				u.RawQuery = q.Encode()
				redirectURL = u.String()
			}
		}
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

// isLocalPath reports whether p is a same-origin absolute path, so a return_to
// value cannot be turned into an open redirect (//host and /\\host are rejected).
func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "/") &&
		!strings.HasPrefix(p, "//") &&
		!strings.HasPrefix(p, "/\\") &&
		!strings.ContainsAny(p, "\r\n")
}

func (h *Handler) getAbsoluteRedirectURL(r *http.Request, target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	if u.IsAbs() {
		return u.String()
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	u.Scheme = scheme
	u.Host = host
	return u.String()
}
