package caddyauthoidc

import "testing"

func TestUserAllowed(t *testing.T) {
	noUsers := []string{}
	if !userAllowed(noUsers, map[string]interface{}{"preferred_username": "anyone"}) {
		t.Fatal("empty allowlist must allow everyone")
	}

	users := []string{"mingwiki", "alice"}

	cases := []struct {
		name   string
		claims map[string]interface{}
		want   bool
	}{
		{"hit preferred_username", map[string]interface{}{"preferred_username": "mingwiki"}, true},
		{"hit name fallback", map[string]interface{}{"name": "alice"}, true},
		{"miss", map[string]interface{}{"preferred_username": "mallory"}, false},
		{"no username claims", map[string]interface{}{"email": "x@y.z"}, false},
		{"case sensitive", map[string]interface{}{"preferred_username": "MingWiki"}, false},
	}
	for _, tc := range cases {
		if got := userAllowed(users, tc.claims); got != tc.want {
			t.Errorf("%s: userAllowed = %v, want %v", tc.name, got, tc.want)
		}
	}
}
