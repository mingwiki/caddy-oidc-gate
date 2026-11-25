# Changelog

Notable changes per tag. This project is pre-1.0: config keys and the cookie format may change
between minor tags.

## v0.1.0 — 2026-11-25

First tagged release. What is here:

### Added

- `auth_oidc` Caddyfile directive / `http.handlers.auth_oidc` module: OIDC login with PKCE,
  nonce and state, cookie-only sessions, optional identity header injection.
- Lazy provider discovery: Caddy starts even while the provider is unreachable, protected sites
  answer `503` and retry discovery every 30s.
- `allowed_groups` + `groups_claim`: optional group allow-list, failing closed when the claim is
  missing or unparsable. Accepts array or whitespace-separated string claims.
- `path_prefix` (default `/auth`) so the endpoints can move out of an upstream app's way.
- `return_to` is validated as a same-origin path; client-supplied `X-Auth-*` headers are stripped.
- Cross-site `GET` logout is refused (`403`).
- Session cookies carry a format version; an unrecognised version is rejected (forces re-login
  instead of being silently misread).
- Warning when the session cookie approaches the 4KB browser limit.

### Security

- Authorization is delegated to the provider: earlier prototypes had a static username
  allow-list, which is gone.

### Notes

- The cookie keys derive from `client_secret`, so rotating it logs everyone out.
