// Package caddyauthoidc implements an OIDC gate for Caddy: users log in at the
// provider and the session lives in an encrypted cookie, so Caddy needs no
// session store. Upstreams receive the verified identity as X-Auth-* headers.
//
// Only authentication is in scope — authorization (which user may log in) is
// the provider's job. See README.md for the full contract.
package caddyauthoidc
