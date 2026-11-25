package caddyauthoidc

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestGetAbsoluteRedirectURL(t *testing.T) {
	h := &Handler{}

	tests := []struct {
		name     string
		target   string
		reqURL   string
		fwdHost  string
		fwdProto string
		tls      bool
		want     string
	}{
		{
			name:   "absolute target",
			target: "https://example.com/foo",
			reqURL: "http://localhost",
			want:   "https://example.com/foo",
		},
		{
			name:   "relative target",
			target: "/foo",
			reqURL: "http://localhost:8080/bar",
			want:   "http://localhost:8080/foo",
		},
		{
			name:     "forwarded host and proto",
			target:   "/foo",
			reqURL:   "http://internal:8080/bar",
			fwdHost:  "example.com",
			fwdProto: "https",
			want:     "https://example.com/foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.reqURL, nil)
			if tt.fwdHost != "" {
				r.Header.Set("X-Forwarded-Host", tt.fwdHost)
			}
			if tt.fwdProto != "" {
				r.Header.Set("X-Forwarded-Proto", tt.fwdProto)
			}
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}

			got := h.getAbsoluteRedirectURL(r, tt.target)
			if got != tt.want {
				t.Errorf("getAbsoluteRedirectURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsLocalPath(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"/", true},
		{"/app", true},
		{"/a?b=c", true},
		{"", false},
		{"https://evil.example", false},
		{"//evil.example", false},
		{"/\\evil.example", false},
		{"/a\r\nSet-Cookie: x=1", false},
	}
	for _, tt := range tests {
		if got := isLocalPath(tt.in); got != tt.want {
			t.Errorf("isLocalPath(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestStripAuthHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("X-Auth-Email", "spoofed@example.com")
	r.Header.Set("X-Other", "keep")

	(&Handler{HeaderPrefix: "X-Auth-"}).stripAuthHeaders(r)

	if got := r.Header.Get("X-Auth-Email"); got != "" {
		t.Fatalf("spoofed X-Auth-Email not stripped: %q", got)
	}
	if got := r.Header.Get("X-Other"); got != "keep" {
		t.Fatalf("unrelated header dropped: %q", got)
	}
}
