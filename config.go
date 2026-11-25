package caddyauthoidc

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

const (
	defaultCookieName     = "caddy_auth_oidc"
	defaultCookiePath     = "/"
	defaultCookieTTL      = caddy.Duration(168 * time.Hour)
	defaultStateTTL       = caddy.Duration(10 * time.Minute)
	defaultHeaderPrefix   = "X-Auth-"
	defaultLogoutRedirect = "/"
	defaultRefreshLeeway  = caddy.Duration(2 * time.Minute)
	defaultPathPrefix     = "/auth"
	defaultGroupsClaim    = "groups"
)

var defaultScopes = []string{"openid", "profile", "email"}

func (h *Handler) applyDefaults() {
	if len(h.Scopes) == 0 {
		h.Scopes = append([]string(nil), defaultScopes...)
	}
	if h.CookieName == "" {
		h.CookieName = defaultCookieName
	}
	if h.CookiePath == "" {
		h.CookiePath = defaultCookiePath
	}
	if h.CookieTTL == 0 {
		h.CookieTTL = defaultCookieTTL
	}
	if h.StateTTL == 0 {
		h.StateTTL = defaultStateTTL
	}
	if h.HeaderPrefix == "" {
		h.HeaderPrefix = defaultHeaderPrefix
	}
	if h.LogoutRedirect == "" {
		h.LogoutRedirect = defaultLogoutRedirect
	}
	if strings.TrimSpace(h.PathPrefix) == "" {
		h.PathPrefix = defaultPathPrefix
	}
	h.PathPrefix = strings.TrimSuffix(h.PathPrefix, "/")
	if strings.TrimSpace(h.GroupsClaim) == "" {
		h.GroupsClaim = defaultGroupsClaim
	}
	if h.AllowedGroups != nil {
		groups := make([]string, 0, len(h.AllowedGroups))
		for _, g := range h.AllowedGroups {
			if g = strings.TrimSpace(g); g != "" {
				groups = append(groups, g)
			}
		}
		h.AllowedGroups = groups
	}
	if h.RefreshLeeway == 0 {
		h.RefreshLeeway = defaultRefreshLeeway
	}
	if h.ForceHTTPSCookie == nil {
		v := true
		h.ForceHTTPSCookie = &v
	}
}

func (h *Handler) validate() error {
	if strings.TrimSpace(h.Provider) == "" {
		return errors.New("provider is required")
	}
	if strings.TrimSpace(h.ClientID) == "" {
		return errors.New("client_id is required")
	}
	if strings.TrimSpace(h.ClientSecret) == "" {
		return errors.New("client_secret is required")
	}
	if strings.TrimSpace(h.HeaderPrefix) == "" {
		return errors.New("header_prefix must not be empty")
	}
	if h.CookieTTL <= 0 {
		return errors.New("cookie_ttl must be positive")
	}
	if h.StateTTL <= 0 {
		return errors.New("state_ttl must be positive")
	}
	if !slices.Contains(h.Scopes, "openid") {
		return errors.New("scopes must include \"openid\"")
	}
	if h.RefreshLeeway < 0 {
		return errors.New("refresh_leeway must be non-negative")
	}
	if !strings.HasPrefix(h.PathPrefix, "/") || strings.ContainsAny(h.PathPrefix, " \t") {
		return errors.New("path_prefix must be an absolute path without spaces, e.g. /auth")
	}
	if strings.ContainsAny(h.GroupsClaim, " \t\r\n") {
		return errors.New("groups_claim must not contain whitespace")
	}
	return nil
}
