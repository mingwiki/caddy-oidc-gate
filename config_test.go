package caddyauthoidc

import (
	"strings"
	"testing"
)

func TestApplyDefaultsNormalizesPathsAndClaims(t *testing.T) {
	tests := []struct {
		name        string
		pathPrefix  string
		groupsClaim string
		groups      []string
		wantPath    string
		wantClaim   string
		wantGroups  []string
	}{
		{name: "empty falls back to defaults", wantPath: "/auth", wantClaim: "groups"},
		{name: "trailing slash trimmed", pathPrefix: "/auth/", wantPath: "/auth", wantClaim: "groups"},
		{name: "nested prefix kept", pathPrefix: "/sso/auth", wantPath: "/sso/auth", wantClaim: "groups"},
		{name: "custom claim", groupsClaim: "roles", wantPath: "/auth", wantClaim: "roles"},
		{name: "blank groups dropped", groups: []string{" team-a ", "", "  "}, wantPath: "/auth", wantClaim: "groups", wantGroups: []string{"team-a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{PathPrefix: tt.pathPrefix, GroupsClaim: tt.groupsClaim, AllowedGroups: tt.groups}
			h.applyDefaults()

			if h.PathPrefix != tt.wantPath {
				t.Errorf("PathPrefix = %q, want %q", h.PathPrefix, tt.wantPath)
			}
			if h.GroupsClaim != tt.wantClaim {
				t.Errorf("GroupsClaim = %q, want %q", h.GroupsClaim, tt.wantClaim)
			}
			if tt.wantGroups != nil && strings.Join(h.AllowedGroups, ",") != strings.Join(tt.wantGroups, ",") {
				t.Errorf("AllowedGroups = %v, want %v", h.AllowedGroups, tt.wantGroups)
			}
		})
	}
}

func TestValidateRejectsBadPathAndClaim(t *testing.T) {
	base := func() *Handler {
		h := &Handler{Provider: "https://issuer.example", ClientID: "client", ClientSecret: "secret"}
		h.applyDefaults()
		return h
	}

	h := base()
	h.PathPrefix = "auth" // relative: the endpoints would never be reached
	if err := h.validate(); err == nil {
		t.Fatal("expected an error for a relative path_prefix")
	}

	h = base()
	h.GroupsClaim = "a b"
	if err := h.validate(); err == nil {
		t.Fatal("expected an error for a groups_claim containing a space")
	}

	h = base()
	h.Scopes = []string{"profile"}
	if err := h.validate(); err == nil {
		t.Fatal("expected an error when scopes lack openid")
	}
}
