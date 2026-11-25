# Security policy

## Reporting

Open a private report via GitHub → **Security** → **Report a vulnerability**. Please do not file
a public issue for anything exploitable. You get an answer when I have one; this is a
single-maintainer project with no SLA, but authentication bugs get priority over everything else.

## Supported versions

The latest tag. Pre-1.0 there are no backports: a fix ships as a new tag.

## What this plugin does and does not protect

It answers one question — "did this browser authenticate at the provider, and is that session
still valid?" — and nothing else.

- **Authentication only.** Any user the provider authenticates may log in, unless
  `allowed_groups` is configured. There are no roles, no per-path rules, no
  authorization decisions beyond the group allow-list.
- **`client_secret` is also the cookie encryption key.** The session cookie is encrypted and
  signed with keys derived from it (HKDF). Anyone who reads the secret can mint valid session
  cookies for your site. Rotating it in the provider invalidates every session.
- **The cookie carries the ID token and the refresh token.** It is `HttpOnly`, `Secure` (unless
  `force_https_cookie false`), `SameSite=Lax`, and encrypted — but it is a bearer credential:
  whoever steals it is logged in until expiry. Cookie contents are never logged.
- **`X-Forwarded-Host`/`X-Forwarded-Proto` are trusted** to build the `redirect_uri` and the
  logout redirect. Caddy strips nothing here; only expose this site behind Caddy itself.
- **Injected `X-Auth-*` headers are trusted by the upstream.** Client-supplied headers with that
  prefix are stripped on every request, but the upstream must be reachable only through Caddy,
  otherwise the header can be forged directly.

## Secrets in configuration

`client_secret` belongs in an environment variable (`{env.OIDC_CLIENT_SECRET}`), not in the
Caddyfile and not in a git repo.
