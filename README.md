# caddy-oidc-gate

OIDC login for Caddy-served sites, as a native Caddy v2 handler. No extra container, no
auth proxy, one cookie per site (or per domain for SSO).

Built for homelabs where Pocket ID (or Keycloak, Authentik, Authelia, Zitadel…) is already the
identity provider and `oauth2-proxy` feels like a second project to operate.

```caddyfile
example.com {
    auth_oidc {
        provider      https://id.example.com
        client_id     my-client
        client_secret {env.OIDC_CLIENT_SECRET}
    }
    reverse_proxy localhost:8080
}
```

---

## Project status

Early, single-maintainer, used in production on my own homelab. Pre-1.0: config keys and cookie
format may change between minor tags, and a cookie format change logs everyone out (CHANGELOG says
when). Pin production to a tag — `xcaddy build --with github.com/mingwiki/caddy-oidc-gate@v0.1.1`.
The session cookie format and
the `auth_oidc` option names are stable as of now, but this is a small project with no
compatibility guarantees across majors. Read [Scope](#scope-what-this-plugin-does-and-does-not-do)
before deploying it somewhere that matters.

## Scope: what this plugin does and does not do

### What it does

- Gates a Caddy site behind an OIDC login (authorization code flow with PKCE).
- Keeps the login in an encrypted, signed cookie — no server-side session store, no Redis,
  nothing to back up.
- Shares that session across subdomains (`cookie_domain`) so users log in once for
  `app1.example.com`, `app2.example.com`, …
- Optionally passes verified claims upstream as headers (`X-Auth-Email`, …) for apps that can
  consume them.
- Renews the session in the background when the provider hands out refresh tokens.
- Survives provider restarts without taking Caddy down (sites answer `503` for the outage
  window instead of the whole config failing to load).

### What it does not do

- **Authorize.** There is no user allow-list, no group/role check, no per-path ACL. Whoever the
  provider authenticates gets in. Deciding *who* may log in is the provider's job (Pocket ID
  users/groups) or the upstream app's job.
- **Forward tokens.** No `Authorization` header, no access token, no ID token passed upstream —
  only the four identity headers below. Apps needing to call APIs on behalf of the user are out
  of scope.
- **Forward arbitrary claims.** Injected headers are exactly: `X-Auth-Subject`, `X-Auth-Email`,
  `X-Auth-Name` (`name`, falling back to `preferred_username`), `X-Auth-Issuer`. `groups`,
  `roles`, custom claims: not forwarded (yet).
- **Serve APIs.** Cookie-based browser sessions only. No bearer-token validation, no
  machine-to-machine.
- **Support multiple providers** in one site, or per-user routing between providers.
- **Manage users.** No signup, no password reset, no profile — that is the provider's UI.

If you need claim-based authorization or token pass-through, use a proxy that does that
(`oauth2-proxy`, `caddy-security`) — this plugin deliberately stays out of it.

---

## How a login works

```text
browser ──GET /private──▶ Caddy (auth_oidc)
                          │ no valid cookie
                          └─302 /auth/login?return_to=/private
       ──GET /auth/login──▶ generate state + nonce + PKCE verifier
                          │ store them in encrypted *_flow cookie (10m)
                          └─302 to provider /authorize (code_challenge=S256)
       ──passkey etc.────▶ provider
                          └─302 /auth/callback?code=…&state=…
       ──GET /auth/callback▶ state compare (constant time) → code exchange with code_verifier
                          │ verify ID token (JWKS, iss, aud, exp) → compare nonce
                          │ store ID token + refresh token + expiry in session cookie
                          └─302 back to return_to (same-origin paths only)
       ──GET /private─────▶ cookie decrypts & verifies → (refresh if near expiry)
                          │ inject identity headers if enabled
                          └─▶ upstream
```

- `return_to` is forced to a same-origin path (`//evil.com`, `/\evil.com` are rejected), so the
  login endpoint cannot be used as an open redirect.
- Client-supplied headers with `header_prefix` are **stripped** on every request before
  injection, so upstream apps can trust `X-Auth-*` blindly.
- The session cookie is `HttpOnly`, `Secure` (by default), `SameSite=Lax`, encrypted and signed
  with keys derived (HKDF-SHA256) from `client_secret` + `client_id` + `provider`.
- Logout clears the local cookie and, if the provider advertises `end_session_endpoint`, also
  ends the provider session (`id_token_hint` included). Cross-site logout requests are refused.
- If the provider is unreachable, discovery is retried at most every 30s and protected sites
  return `503` meanwhile.

---

## Quick start with Pocket ID

Pocket ID is a passkey-only OIDC provider — a good match for this plugin: no passwords to
phish, one client per trust domain, and it advertises `end_session_endpoint` so logout really
logs you out.

### 1. Create the client in Pocket ID

1. Pocket ID → **Admin → OIDC Clients → Create**.
2. Name: whatever you recognize (`caddy-homelab`).
3. Callback URLs — one per protected host, exactly matching what Caddy will send:
   - `https://app1.example.com/auth/callback`
   - `https://app2.example.com/auth/callback`
   
   No wildcards: the plugin sends `redirect_uri` built from the request scheme and host, and
   the provider validates it against this list.
4. Copy the **Client ID** and **Client Secret**.

Pocket ID's issuer is its own external URL (`APP_URL`) — remember it, it goes into
`issuer_url` below if Caddy also proxies Pocket ID.

### 2. Point Caddy at it

If Caddy proxies Pocket ID itself (typical homelab: `id.example.com` → `127.0.0.1:1411`), do
**not** discover through the public URL — Caddy is not listening yet while loading its config.
Use the local backend for discovery and the public URL as issuer:

```caddyfile
{
    order auth_oidc before reverse_proxy
}

(auth) {
    auth_oidc {
        provider      http://127.0.0.1:1411
        issuer_url    https://id.example.com
        client_id     {env.OIDC_CLIENT_ID}
        client_secret {env.OIDC_CLIENT_SECRET}

        cookie_domain .example.com      # one login for every subdomain
        scopes        openid profile email

        inject_headers true
        header_prefix  X-Auth-
    }
}

app1.example.com {
    import auth
    reverse_proxy localhost:8081
}

app2.example.com {
    import auth
    reverse_proxy localhost:8082
}

id.example.com {
    reverse_proxy 127.0.0.1:1411
}
```

`scopes` must contain `openid` — the config is rejected otherwise.

### 3. Verify

```bash
curl -sI https://app1.example.com/ | grep -i location
# location: https://app1.example.com/auth/login?return_to=%2F

curl -sI https://app1.example.com/auth/login | grep -i location
# location: https://id.example.com/authorize?client_id=…&code_challenge=…&code_challenge_method=S256&nonce=…&state=…
```

Then open the site in a browser: passkey prompt → back to the app. Append `-v` to the curl
calls if you want to see PKCE and the state cookie.

### Pocket ID specifics worth knowing

| Topic | Behaviour |
| --- | --- |
| Logout | Pocket ID advertises `end_session_endpoint`, so `/auth/logout` kills the SSO session too. Next login asks for the passkey again. |
| Claims | Pocket ID sends `sub`, `email`, `name`/`preferred_username` → that is exactly what lands in `X-Auth-*`. It does not give this plugin `groups`. |
| Refresh | With a refresh token issued, sessions renew silently up to `cookie_ttl`. Without one, every ID-token expiry costs one invisible round trip through Pocket ID (still logged in there → no prompt). |
| Secret rotation | The cookie keys are derived from `client_secret`. Rotating it in Pocket ID invalidates all sessions — everyone logs in again. |
| Outage | Stop Pocket ID and protected sites return `503`, not a login loop. Caddy keeps serving unauthenticated paths and other sites. |
| Passkeys only | There is no fallback password. Lose the device, use Pocket ID's recovery flow; this plugin has no say in it. |

---

## Build

```bash
xcaddy build --with github.com/mingwiki/caddy-oidc-gate
```

With extra plugins (e.g. WebDAV, DNS challenge):

```bash
xcaddy build \
    --with github.com/mingwiki/caddy-oidc-gate \
    --with github.com/mholt/caddy-webdav \
    --with github.com/caddy-dns/alidns
```

Docker:

```dockerfile
FROM caddy:2-builder AS builder
RUN xcaddy build --with github.com/mingwiki/caddy-oidc-gate

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

### Handler order

`auth_oidc` must run before whatever it protects:

```caddyfile
{
    order auth_oidc before reverse_proxy
}
```

For `file_server`/`webdav` sites, order it before those too
(`order auth_oidc before file_server webdav`).

---

## Configuration

| Option | Description | Default |
| --- | --- | --- |
| `provider` | Discovery base URL (`/.well-known/openid-configuration` is appended). Required. | |
| `issuer_url` | Expected `iss` — set it when discovery goes through a different URL than the public issuer | same as `provider` |
| `client_id` | OIDC client ID. Required. | |
| `client_secret` | OIDC client secret. Required; also derives the cookie keys. | |
| `scopes` | Must include `openid` | `openid profile email` |
| `cookie_domain` | Cookie domain; set it to share one session across subdomains | host-only |
| `cookie_name` | Session cookie name | `caddy_auth_oidc` |
| `cookie_path` | Cookie path | `/` |
| `path_prefix` | Where the auth endpoints live | `/auth` |
| `allowed_groups` | Only users in one of these groups may log in (see below) | *(empty: no filtering)* |
| `groups_claim` | Claim holding group names | `groups` |
| `cookie_ttl` | Local session lifetime | `168h` |
| `state_ttl` | Lifetime of the in-flight login cookie | `10m` |
| `inject_headers` | Inject identity headers upstream | `false` |
| `header_prefix` | Prefix for injected headers | `X-Auth-` |
| `logout_redirect` | Where to go after logout | `/` |
| `refresh_leeway` | How early before expiry to refresh | `2m` |
| `force_https_cookie` | Force `Secure` on cookies (needed behind a TLS-terminating proxy that Caddy does not see) | `true` |

## Endpoints

Reserved on every protected site (they sit in front of your upstream, below `path_prefix`):

| Path | Purpose |
| --- | --- |
| `/auth/login` | Starts the flow. Skips straight to `return_to` if the session is already valid. |
| `/auth/callback` | Code exchange, token verification, session cookie. |
| `/auth/logout` | Clears the local cookie, then the provider session if advertised. |

The three paths are fixed relative to `path_prefix`. If an upstream app needs `/auth/*` for
itself, move the plugin out of the way with `path_prefix /sso`. The plugin cannot be mounted
below a subpath of the site (there is no `handle_path` interaction to worry about).

---

## Group authorization (optional)

By default any user the provider authenticates may log in. `allowed_groups` narrows that:

```caddyfile
auth_oidc {
    provider       https://id.example.com
    client_id      my-client
    client_secret  {env.OIDC_CLIENT_SECRET}
    allowed_groups admins family
    groups_claim   groups        # default; only change it if your provider differs
}
```

- The claim may be a JSON array (`["admin","ops"]`) or a whitespace-separated string
  (`"admin ops"`). Both are common; unknown shapes are rejected, not ignored.
- Matching is exact and case-sensitive. No wildcards, no nesting.
- **Fails closed**: with `allowed_groups` set and no such claim in the token, login is denied with
  `403` and a `Warn` log — a typo in the claim name should not open the site to everyone.
- `groups_claim` values that need it: Auth0 uses a namespaced URL
  (`https://you.example.com/groups`), GitLab uses `groups_direct`, Keycloak/Authentik/Zitadel
  use the mapper's claim name (`groups` by default).
- If your IdP can restrict a client's users by group (Pocket ID can, per OIDC client), doing it
  there is more robust: the token then never leaves the IdP for a user who may not log in.

## Tested providers

| Provider | Status | Notes |
| --- | --- | --- |
| Pocket ID | verified | Used in production by the author. Emits no group claim, so `allowed_groups` needs a provider that does (or per-client restriction inside Pocket ID). |
| Keycloak | untested | Group mapper outputs an array; set `groups_claim` to the mapper's claim name. |
| Authentik | untested | `groups` array scope. |
| Zitadel, Auth0, Google, GitLab | untested | Auth0 needs a namespaced claim URL; GitLab uses `groups_direct`. |

"Untested" means the code path is the same standard OIDC discovery + code flow, but nobody has
run it and written down the config. A PR adding a working snippet for a provider is the single
most useful contribution.

## Non-goals

These are deliberate, not backlog items. Each one is a different project:

- **Authorization policies / per-path ACLs.** Use Authelia, Authentik, or greenpau/caddy-security.
  This plugin answers "is this an authenticated user?", not "may this user see `/admin`?".
- **Token pass-through (access token / ID token upstream).** Apps that call APIs *as* the user need
  `oauth2-proxy` or the app's own OIDC support. Only the four identity headers are forwarded.
- **Multiple providers per site, or per-path providers.** One site, one provider.
- **User database, portal, registration, MFA enrolment.** The IdP owns all of that.

---

## Development

```bash
go test -race -cover ./...        # unit + end-to-end tests against a fake OIDC provider
go vet ./...
staticcheck ./...                 # optional
golangci-lint run                 # optional
```

Build against local sources:

```bash
xcaddy build --with github.com/mingwiki/caddy-oidc-gate=./
./caddy run --config Caddyfile
```

Layout: `config.go` (defaults/validation), `caddyfile.go` (Caddyfile parsing), `oidc.go`
(discovery, PKCE, URL building), `session.go` (cookie codec), `endpoints.go`
(login/callback/logout), `handler.go` (middleware, session refresh, header injection).

## Security notes

- Everything rides on TLS and on `client_secret` staying secret: it is the HKDF input for the
  cookie keys. Leak it and cookies are forgeable; rotate it and sessions die.
- The session cookie is the credential. `cookie_ttl` is how long a stolen browser keeps access —
  shorten it and rely on refresh, or accept 7 days.
- Behind another reverse proxy, configure Caddy's `trusted_proxies`; the plugin takes the
  `redirect_uri` host and scheme from the request (`X-Forwarded-*`). The provider's callback
  whitelist is the backstop.
- `inject_headers` makes `X-Auth-*` an authentication boundary for the upstream app: keep the
  upstream off the public internet, or it will believe any client that can reach it directly.
- Who may log in is the provider's decision. This plugin never had an allow-list and will not
  grow one.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `503 Service Unavailable` on protected sites | Discovery failed — check `provider` reachability and Caddy logs (`oidc provider unavailable`); it retries every 30s |
| Login loops forever | Session cookie never stored: `cookie_domain` too broad/narrow, `Secure` cookie over plain HTTP, or an upstream rewriting `Set-Cookie` |
| `401 Unauthorized` right after the provider redirect | `state` cookie missing/expired (`state_ttl`), clock skew on `exp`, or wrong `issuer_url` (token `iss` mismatch) |
| Login works, app sees no user | `inject_headers` not enabled, or the app reads different header names than `header_prefix` |
| Everyone logged out after a provider change | `client_secret` rotated → cookie keys changed |
| `403` right after a successful provider login | `allowed_groups` is set but the token has no `groups_claim`, or the group name differs. The log line names the claim and the groups the user does hold. |
| The app's own `/auth/*` pages return the plugin's endpoints | Set `path_prefix /sso` (or any other prefix). |
| `state mismatch` in logs | Two tabs racing the same flow, or a stale flow cookie (>10m between login and callback) |

## Contributing

Bug reports are most useful with: provider + version, the `auth_oidc` block you used, and the
relevant `Warn`/`Error` lines from Caddy's log. Scope is intentionally small — see
[Non-goals](#non-goals) before proposing a feature.

Good first contributions:

- Add your provider to [Tested providers](#tested-providers) with a config snippet that works.
- Improve the troubleshooting table with a failure you actually hit.
- Write a test for an edge case in the flow (see `handler_test.go` for the fake provider).

## License

MIT — see [LICENSE](LICENSE).
