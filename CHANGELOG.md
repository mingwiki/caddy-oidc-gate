# Changelog

Notable changes per tag. This project is pre-1.0: config keys and the cookie format may change
between minor tags.

## v0.1.1 — 2026-11-26

### Fixed

- Spurious `Unauthorized` on the first visit: the flow cookie had one fixed name, so a second
  login flow started while the first was in flight (favicon fetch, prefetch, second tab) replaced
  its state and the callback died with `state mismatch`. Flow cookies are now named per attempt
  (`<cookie>_flow_<state>`); parallel flows no longer interfere. The state in the callback is
  validated against a base64url pattern before it is used as a cookie name.

### Changed

- Repository and Go module renamed to `github.com/mingwiki/caddy-oidc-gate`. The module ID
  (`http.handlers.auth_oidc`) and the Caddyfile directive (`auth_oidc`) are unchanged, so existing
  configurations keep working — only the `--with` path in your build has to be updated.

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
