package caddyoidcgate

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// testState is a realistic state value: base64url, 32 bytes.
const testState = "0123456789abcdef0123456789abcdef"

func TestFlowStateCookie_RoundTripAndAttributes(t *testing.T) {
	h := &Handler{
		Provider:     "https://issuer.example",
		ClientID:     "client",
		ClientSecret: "secret",
		CookieDomain: ".example.com",
		CookiePath:   "/",
	}
	h.applyDefaults()
	if err := h.initCookieCodecs(); err != nil {
		t.Fatalf("initCookieCodecs: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/login", nil)
	w := httptest.NewRecorder()

	in := flowState{
		Version:      cookieVersion,
		State:        testState,
		Nonce:        "nonce123",
		PKCEVerifier: "verifier123",
		ReturnTo:     "/app",
	}
	if err := h.setFlowStateCookie(w, r, in); err != nil {
		t.Fatalf("setFlowStateCookie: %v", err)
	}

	resp := w.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 Set-Cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != h.flowStateCookieName(in.State) {
		t.Fatalf("unexpected cookie name: %q", c.Name)
	}
	if c.Domain != strings.TrimPrefix(h.CookieDomain, ".") {
		t.Fatalf("unexpected Domain: %q", c.Domain)
	}
	if c.Path != h.CookiePath {
		t.Fatalf("unexpected Path: %q", c.Path)
	}
	if !c.HttpOnly {
		t.Fatalf("expected HttpOnly=true")
	}
	if !c.Secure {
		t.Fatalf("expected Secure=true (force_https_cookie default)")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected SameSite: %v", c.SameSite)
	}
	if c.MaxAge <= 0 {
		t.Fatalf("expected MaxAge>0, got %d", c.MaxAge)
	}

	r2 := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/callback", nil)
	r2.AddCookie(c)

	out, err := h.readFlowStateCookie(r2, in.State)
	if err != nil {
		t.Fatalf("readFlowStateCookie: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch: %#v != %#v", out, in)
	}
}

func TestFlowStateCookie_TTLExpiry(t *testing.T) {
	h := &Handler{
		Provider:     "https://issuer.example",
		ClientID:     "client",
		ClientSecret: "secret",
		StateTTL:     caddyDuration(1 * time.Second),
	}
	h.applyDefaults()
	if err := h.initCookieCodecs(); err != nil {
		t.Fatalf("initCookieCodecs: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/auth/login", nil)
	w := httptest.NewRecorder()
	if err := h.setFlowStateCookie(w, r, flowState{State: testState}); err != nil {
		t.Fatalf("setFlowStateCookie: %v", err)
	}
	c := w.Result().Cookies()[0]

	time.Sleep(2 * time.Second)

	r2 := httptest.NewRequest(http.MethodGet, "http://example.com/auth/callback", nil)
	r2.AddCookie(c)

	_, err := h.readFlowStateCookie(r2, testState)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrCookieExpired) {
		t.Fatalf("expected ErrCookieExpired, got %v", err)
	}
}

func TestSessionCookie_RoundTripAndSecureOverride(t *testing.T) {
	forceFalse := false
	h := &Handler{
		Provider:         "https://issuer.example",
		ClientID:         "client",
		ClientSecret:     "secret",
		ForceHTTPSCookie: &forceFalse,
		CookieDomain:     "",
		CookiePath:       "/",
		CookieTTL:        caddyDuration(30 * time.Minute),
		RefreshLeeway:    caddyDuration(0),
	}
	h.applyDefaults()
	if err := h.initCookieCodecs(); err != nil {
		t.Fatalf("initCookieCodecs: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()

	in := sessionData{
		Version:      cookieVersion,
		IDToken:      "jwt",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(10 * time.Minute).UTC(),
	}
	if err := h.setSessionCookie(w, r, in); err != nil {
		t.Fatalf("setSessionCookie: %v", err)
	}
	c := w.Result().Cookies()[0]
	if c.Name != h.CookieName {
		t.Fatalf("unexpected cookie name: %q", c.Name)
	}
	if c.Secure {
		t.Fatalf("expected Secure=false when force_https_cookie=false and no TLS")
	}

	r2 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r2.AddCookie(c)
	out, err := h.readSessionCookie(r2)
	if err != nil {
		t.Fatalf("readSessionCookie: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch: %#v != %#v", out, in)
	}
}

func TestSessionCookie_RejectsUnknownVersion(t *testing.T) {
	h := &Handler{Provider: "https://issuer.example", ClientID: "client", ClientSecret: "secret"}
	h.applyDefaults()
	if err := h.initCookieCodecs(); err != nil {
		t.Fatalf("initCookieCodecs: %v", err)
	}

	encoded, err := h.sessionCodec.Encode(h.CookieName, sessionData{
		Version:   cookieVersion + 1,
		IDToken:   "jwt",
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.AddCookie(&http.Cookie{Name: h.CookieName, Value: encoded})

	if _, err := h.readSessionCookie(r); !errors.Is(err, ErrCookieInvalid) {
		t.Fatalf("expected ErrCookieInvalid for unknown version, got %v", err)
	}
}

func TestFlowStateCookie_RejectsUnknownVersion(t *testing.T) {
	h := &Handler{Provider: "https://issuer.example", ClientID: "client", ClientSecret: "secret"}
	h.applyDefaults()
	if err := h.initCookieCodecs(); err != nil {
		t.Fatalf("initCookieCodecs: %v", err)
	}

	name := h.flowStateCookieName(testState)
	encoded, err := h.flowCodec.Encode(name, flowState{Version: cookieVersion + 1, State: testState, Nonce: "n"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.AddCookie(&http.Cookie{Name: name, Value: encoded})

	if _, err := h.readFlowStateCookie(r, testState); !errors.Is(err, ErrCookieInvalid) {
		t.Fatalf("expected ErrCookieInvalid for unknown version, got %v", err)
	}
}

func TestClearCookies(t *testing.T) {
	h := &Handler{
		Provider:     "https://issuer.example",
		ClientID:     "client",
		ClientSecret: "secret",
	}
	h.applyDefaults()
	if err := h.initCookieCodecs(); err != nil {
		t.Fatalf("initCookieCodecs: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "https://example.com/auth/logout", nil)
	w := httptest.NewRecorder()

	h.clearFlowStateCookie(w, r, testState)
	h.clearSessionCookie(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 Set-Cookie, got %d", len(cookies))
	}
	for _, c := range cookies {
		if c.MaxAge >= 0 {
			t.Fatalf("expected MaxAge<0, got %d for %s", c.MaxAge, c.Name)
		}
		if c.Expires.After(time.Now()) {
			t.Fatalf("expected Expires in past for %s", c.Name)
		}
	}
}

func caddyDuration(d time.Duration) caddy.Duration {
	return caddy.Duration(d)
}
