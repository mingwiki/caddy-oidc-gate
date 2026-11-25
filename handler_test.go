package caddyauthoidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"go.uber.org/zap"
)

// idp is a throwaway OIDC provider: oidctest serves discovery and JWKS, this
// file adds the token endpoint the plugin actually exchanges codes against.
type idp struct {
	srv   *httptest.Server
	key   *ecdsa.PrivateKey
	keyID string

	mu           sync.Mutex
	down         bool
	nonce        string
	failRefresh  bool
	refreshCalls int
	lastForm     url.Values
}

func newIdP(t *testing.T) *idp {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	p := &idp{key: key, keyID: "test-key"}
	oidcSrv := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{{
			PublicKey: key.Public(),
			KeyID:     p.keyID,
			Algorithm: oidc.ES256,
		}},
		Algorithms: []string{oidc.ES256},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", p.serveToken)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		down := p.down
		p.mu.Unlock()
		if down {
			http.Error(w, "provider down", http.StatusServiceUnavailable)
			return
		}
		oidcSrv.ServeHTTP(w, r)
	}))
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	oidcSrv.SetIssuer(p.srv.URL)
	return p
}

func (p *idp) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	p.lastForm = r.Form
	refresh := r.Form.Get("grant_type") == "refresh_token"
	if refresh {
		p.refreshCalls++
	}
	fail := p.failRefresh
	nonce := p.nonce
	p.mu.Unlock()

	if refresh && fail {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":"invalid_grant"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "access-token",
		"token_type":    "Bearer",
		"refresh_token": "refresh-token",
		"expires_in":    3600,
		"id_token":      p.sign(nonce),
	})
}

func (p *idp) sign(nonce string) string {
	now := time.Now()
	claims := fmt.Sprintf(
		`{"iss":%q,"aud":"client","sub":"user-1","email":"user@example.com","name":"User One","nonce":%q,"iat":%d,"exp":%d}`,
		p.srv.URL, nonce, now.Unix(), now.Add(time.Hour).Unix())
	return oidctest.SignIDToken(p.key, p.keyID, oidc.ES256, claims)
}

func (p *idp) setDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
}

func (p *idp) setNonce(nonce string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nonce = nonce
}

func (p *idp) setFailRefresh(fail bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failRefresh = fail
}

func (p *idp) stats() (refreshCalls int, form url.Values) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshCalls, p.lastForm
}

// newHandler builds a provisioned-enough handler (defaults + cookie codecs) but
// talks to no provider, so tests can drive provider discovery themselves.
func newHandler(t *testing.T, provider *idp) *Handler {
	t.Helper()

	forceHTTPS := false
	h := &Handler{
		Provider:         provider.srv.URL,
		ClientID:         "client",
		ClientSecret:     "secret",
		InjectHeaders:    true,
		HeaderPrefix:     "X-Auth-",
		ForceHTTPSCookie: &forceHTTPS,
	}
	h.applyDefaults()
	h.logger = zap.NewNop()

	if err := h.initCookieCodecs(); err != nil {
		t.Fatalf("initCookieCodecs: %v", err)
	}
	return h
}

func newTestHandler(t *testing.T, provider *idp) *Handler {
	t.Helper()

	h := newHandler(t, provider)
	if err := h.initOIDC(context.Background()); err != nil {
		t.Fatalf("initOIDC: %v", err)
	}
	return h
}

// nextHandler records what the protected upstream would receive.
type nextHandler struct {
	called  bool
	headers http.Header
}

func (n *nextHandler) handler() caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		n.called = true
		n.headers = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		return nil
	})
}

func serve(h *Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	_ = h.ServeHTTP(w, req, (&nextHandler{}).handler())
	return w
}

// login runs the authorization request and returns the flow cookie plus the
// authorize URL the provider would have received.
func login(t *testing.T, h *Handler, provider *idp, returnTo string) (flowCookie *http.Cookie, authURL *url.URL) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/auth/login?return_to="+url.QueryEscape(returnTo), nil)
	w := httptest.NewRecorder()
	if err := h.serveLogin(w, req); err != nil {
		t.Fatalf("serveLogin: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Fatalf("serveLogin status = %d, want 302 (body %q)", w.Code, w.Body.String())
	}

	authURL, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	provider.setNonce(authURL.Query().Get("nonce"))

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login set no flow cookie")
	}
	return cookies[0], authURL
}

func callback(t *testing.T, h *Handler, flowCookie *http.Cookie, query string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/callback?"+query, nil)
	req.AddCookie(flowCookie)
	w := httptest.NewRecorder()
	if err := h.serveCallback(w, req); err != nil {
		t.Fatalf("serveCallback: %v", err)
	}
	return w
}

// sessionCookie returns a valid session cookie produced by the real login+callback flow.
func sessionCookie(t *testing.T, h *Handler, provider *idp) *http.Cookie {
	t.Helper()

	flowCookie, authURL := login(t, h, provider, "/app")
	q := authURL.Query()
	w := callback(t, h, flowCookie, "state="+q.Get("state")+"&code=abc")
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 (body %q)", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == h.CookieName {
			return c
		}
	}
	t.Fatal("callback set no session cookie")
	return nil
}

func TestServeHTTP_RedirectsUnauthenticated(t *testing.T) {
	h := newTestHandler(t, newIdP(t))

	w := serve(h, httptest.NewRequest(http.MethodGet, "http://app.example.com/some/page?x=1", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if got, want := w.Header().Get("Location"), "/auth/login?return_to=%2Fsome%2Fpage%3Fx%3D1"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func TestLoginCallbackFlowInjectsHeaders(t *testing.T) {
	provider := newIdP(t)
	h := newTestHandler(t, provider)

	cookie := sessionCookie(t, h, provider)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil)
	req.AddCookie(cookie)
	next := &nextHandler{}
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, req, next.handler()); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusOK || !next.called {
		t.Fatalf("protected request not passed upstream: status=%d called=%v", w.Code, next.called)
	}
	for header, want := range map[string]string{
		"X-Auth-Subject": "user-1",
		"X-Auth-Email":   "user@example.com",
		"X-Auth-Name":    "User One",
		"X-Auth-Issuer":  provider.srv.URL,
	} {
		if got := next.headers.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestServeHTTP_StripsSpoofedAuthHeaders(t *testing.T) {
	provider := newIdP(t)
	h := newTestHandler(t, provider)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil)
	req.AddCookie(sessionCookie(t, h, provider))
	req.Header.Set("X-Auth-Email", "spoofed@evil.example")
	req.Header.Set("X-Auth-Group", "admin")

	next := &nextHandler{}
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, req, next.handler()); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Fatalf("request not passed upstream: status=%d", w.Code)
	}
	if got := next.headers.Get("X-Auth-Email"); got != "user@example.com" {
		t.Errorf("X-Auth-Email = %q, spoofed value survived", got)
	}
	if got := next.headers.Get("X-Auth-Group"); got != "" {
		t.Errorf("X-Auth-Group = %q, unknown prefixed header survived", got)
	}
}

func TestLoginRejectsOpenRedirect(t *testing.T) {
	provider := newIdP(t)
	h := newTestHandler(t, provider)

	flowCookie, authURL := login(t, h, provider, "//evil.example/phish")
	w := callback(t, h, flowCookie, "state="+authURL.Query().Get("state")+"&code=abc")
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want %q (open redirect)", got, "/")
	}
}

func TestLoginSkipsProviderWhenAuthenticated(t *testing.T) {
	provider := newIdP(t)
	h := newTestHandler(t, provider)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/login?return_to=/app", nil)
	req.AddCookie(sessionCookie(t, h, provider))
	w := httptest.NewRecorder()
	if err := h.serveLogin(w, req); err != nil {
		t.Fatalf("serveLogin: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/app" {
		t.Fatalf("Location = %q, want /app", got)
	}
}

func TestServeHTTP_RefreshesNearExpirySession(t *testing.T) {
	provider := newIdP(t)
	h := newTestHandler(t, provider)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil)
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	w := httptest.NewRecorder()
	if err := h.setSessionCookie(w, r, sessionData{
		IDToken:      provider.sign(""),
		RefreshToken: "old-refresh-token",
		ExpiresAt:    time.Now().Add(time.Minute), // inside RefreshLeeway
	}); err != nil {
		t.Fatalf("setSessionCookie: %v", err)
	}
	req.AddCookie(w.Result().Cookies()[0])

	next := &nextHandler{}
	resp := httptest.NewRecorder()
	if err := h.ServeHTTP(resp, req, next.handler()); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Fatalf("request not passed upstream: status=%d body=%q", resp.Code, resp.Body.String())
	}

	calls, form := provider.stats()
	if calls < 1 {
		t.Fatal("no refresh request was made")
	}
	if got := form.Get("grant_type"); got != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", got)
	}
	if got := form.Get("refresh_token"); got != "old-refresh-token" {
		t.Errorf("refresh_token = %q, want old-refresh-token", got)
	}

	var refreshed *http.Cookie
	for _, c := range resp.Result().Cookies() {
		if c.Name == h.CookieName {
			refreshed = c
		}
	}
	if refreshed == nil {
		t.Fatal("refreshed session cookie not set")
	}
	if refreshed.MaxAge <= 0 {
		t.Fatalf("refreshed cookie MaxAge = %d, want > 0", refreshed.MaxAge)
	}
	if refreshed.Value == "" || refreshed.Value == req.Cookies()[0].Value {
		t.Fatal("session cookie value was not replaced")
	}
}

func TestServeHTTP_RefreshFailureClearsSession(t *testing.T) {
	provider := newIdP(t)
	h := newTestHandler(t, provider)
	provider.setFailRefresh(true)

	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	w := httptest.NewRecorder()
	if err := h.setSessionCookie(w, r, sessionData{
		IDToken:      provider.sign(""),
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("setSessionCookie: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil)
	req.AddCookie(w.Result().Cookies()[0])
	next := &nextHandler{}
	resp := httptest.NewRecorder()
	if err := h.ServeHTTP(resp, req, next.handler()); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if next.called {
		t.Fatal("request with unusable session was passed upstream")
	}
	if resp.Code != http.StatusFound || resp.Header().Get("Location") != "/auth/login?return_to=%2Fprivate" {
		t.Fatalf("status=%d Location=%q, want redirect to login", resp.Code, resp.Header().Get("Location"))
	}

	var cleared *http.Cookie
	for _, c := range resp.Result().Cookies() {
		if c.Name == h.CookieName {
			cleared = c
		}
	}
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("session cookie not cleared: %+v", cleared)
	}

	// After the cookie is cleared the next request must not try to refresh again.
	before, _ := provider.stats()
	serve(h, httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil))
	if after, _ := provider.stats(); after != before {
		t.Fatalf("refresh calls grew from %d to %d for a cleared session", before, after)
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	provider := newIdP(t)
	h := newTestHandler(t, provider)

	flowCookie, _ := login(t, h, provider, "/app")
	w := callback(t, h, flowCookie, "state=forged&code=abc")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestCallbackHandlesProviderError(t *testing.T) {
	provider := newIdP(t)
	h := newTestHandler(t, provider)

	flowCookie, authURL := login(t, h, provider, "/app")
	w := callback(t, h, flowCookie,
		"error=access_denied&error_description=nope&state="+authURL.Query().Get("state"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestLogoutClearsSessionAndBlocksCrossSite(t *testing.T) {
	provider := newIdP(t)
	h := newTestHandler(t, provider)
	cookie := sessionCookie(t, h, provider)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/logout", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	if err := h.serveLogout(w, req); err != nil {
		t.Fatalf("serveLogout: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want /", got)
	}
	var cleared bool
	for _, c := range w.Result().Cookies() {
		if c.Name == h.CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear the session cookie")
	}

	csrf := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/logout", nil)
	csrf.AddCookie(cookie)
	csrf.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	if err := h.serveLogout(w, csrf); err != nil {
		t.Fatalf("serveLogout: %v", err)
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site logout status = %d, want 403", w.Code)
	}
}

func TestServeHTTP_ProviderOutageReturns503ThenRecovers(t *testing.T) {
	provider := newIdP(t)
	h := newHandler(t, provider)
	provider.setDown(true)

	w := serve(h, httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status with provider down = %d, want 503", w.Code)
	}

	// Recovered provider: the next attempt (after the retry window) must succeed.
	provider.setDown(false)
	h.mu.Lock()
	h.lastInitTried = time.Time{}
	h.mu.Unlock()

	w = serve(h, httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("status after recovery = %d, want 302 (body %q)", w.Code, w.Body.String())
	}
	if w.Header().Get("Location") != "/auth/login?return_to=%2Fprivate" {
		t.Fatalf("Location = %q", w.Header().Get("Location"))
	}
}

func TestAuthEndpointsAnswer503BeforeProviderIsReady(t *testing.T) {
	h := newHandler(t, newIdP(t)) // deliberately without initOIDC

	for path, serve := range authRoutes {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
		if err := serve(h, w, r); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: expected 503, got %d", path, w.Code)
		}
	}
}
