# bb-auth

Minimal **auth gate**. It accepts an AWS **Cognito `id_token`** that a browser
already obtained and turns it into an HMAC-signed session cookie that a reverse
proxy (nginx `auth_request`) enforces on every request. It is
**service-agnostic** — it fronts any web service and is wired per-deployment
through `BB_AUTH_*` env vars.

## Why

Authorization-code OIDC proxies (e.g. oauth2-proxy) drive the login themselves:
they redirect the browser to the IdP's hosted login and exchange the returned
code. They **cannot accept a token the browser already obtained** — which is what
a "frictionless" browser-driven flow produces. bb-auth is built for that model: a
login page runs the Cognito `USER_AUTH` flow in the browser (which enables
sign-up and auto-login with no second OTP) and ends up holding an `id_token`.
bb-auth takes
that token, validates it, and issues the session cookie.

## Flow

```text
browser ── hits the protected service ──▶ nginx auth_request → GET /auth/validate
   │                                          └─ 401 (no/!valid cookie)
   ▼
nginx error_page 401 → 302  <login-page>/?rd=<original>
   │  (login page; talks to Cognito directly on the public client)
   │   • email exists  → InitiateAuth USER_AUTH / EMAIL_OTP → id_token
   │   • not found     → SignUp → ConfirmSignUp → InitiateAuth(Session) → id_token  (auto-login)
   ▼  top-level form POST  id_token=…&rd=…
<service>/auth/session  (bb-auth)
   • validate id_token (RS256 via JWKS, iss/aud/exp, token_use=id, email_verified)
   • email on allowlist?  → Set-Cookie (HMAC, ~30d) ; 302 → rd
   ▼
<service>  → nginx auth_request → /auth/validate → 204 → upstream app
```

## Endpoints

| Method | Path             | Who        | Purpose                                            |
|--------|------------------|------------|----------------------------------------------------|
| GET    | `/auth/validate` | nginx only | `auth_request`: 204 if the session cookie, an `Authorization: Bearer <id_token>`, or a static `Authorization: Bearer bbk_…` API key authorizes the request (allowlisted user, in path scope), else 401 |
| POST   | `/auth/session`  | browser    | validate posted `id_token`, set cookie, 302 → `rd` |
| GET    | `/auth/logout`   | browser    | clear cookie, 302 → login page                     |
| GET    | `/auth/healthz`  | local      | liveness                                           |

## Programmatic access (Bearer)

The cookie flow is for browsers. A programmatic client (e.g. an MCP client) sends
its credential on every request as a bearer, which `/auth/validate` checks **before**
the cookie. Two kinds are accepted; either way nothing is stored server-side and no
cookie is issued (a stateless per-request credential), and a failed bearer falls
through to the cookie check. The reverse proxy must forward the `Authorization`
header on the `auth_request` subrequest (`proxy_set_header Authorization
$http_authorization;`).

**1. Cognito `id_token`** — for a client that already holds one (a scripted
`USER_AUTH`/`USER_PASSWORD_AUTH` call, a device flow, a cached token):

```text
Authorization: Bearer <cognito_id_token>
```

Validated with the **same** checks as `/auth/session` (RS256 via JWKS, iss/aud/exp,
`token_use=id`, `email_verified`), then the email must be a user in the users file.
No flag needed: a valid id_token for an allowlisted email is exactly the credential
`/auth/session` already trusts to mint a 30-day cookie. Mint/refresh one with
[`tools/bb-token.py`](tools/bb-token.py) (dependency-free Python 3 stdlib; runs the
passwordless email-OTP login against Cognito's public API, caches + auto-refreshes):

```bash
python tools/bb-token.py login --email you@example.com      # once (emails you a code)
curl -H "$(python tools/bb-token.py header)" https://mcp.badbat75.com/mcp/foo/
```

**2. Static API key (`bbk_…`)** — a long-lived key that needs no Cognito round-trip:

```text
Authorization: Bearer bbk_<secret>
```

bb-auth looks it up by `sha256(bearer)` in the users file (only the hash is stored,
never the raw key), checks it is not past its `duration`, and enforces its path
scope. Mint one with [`tools/bb-apikey.py`](tools/bb-apikey.py) — it prints the raw
bearer **once** and a JSON entry to paste into the owning user's `api_keys`:

```bash
python tools/bb-apikey.py bob@badbat75.com --id laptop --duration 365d --paths /mcp/
# → Authorization: Bearer bbk_…  (give to the client)   +   { "id": "laptop", "key_hash": … }
```

**Path scoping.** Each user, and each key, may carry `enabled_paths` — request-path
prefixes it is allowed to reach (`[]` or `["*"]` = all; a key with none inherits its
user's scope). When set, bb-auth needs the original request path, so nginx must pass
it on the subrequest: `proxy_set_header X-Original-URI $uri;`. A scoped credential
with that header missing is denied (fail-closed), and a path containing `..` is
rejected. See the [users file](#users-file) below.

## Users file

The access gate is a single JSON file (`BB_AUTH_USERS_FILE`, installed as
`/opt/bb-auth/users.json`; see [`deploy/users.example.json`](deploy/users.example.json)).
It lists every allowlisted email and, optionally, per-user path scopes and static
API keys:

```json
{ "users": [
  { "email": "you@badbat75.com" },
  { "email": "bot@badbat75.com", "enabled_paths": ["/mcp/"],
    "api_keys": [
      { "id": "laptop", "key_hash": "<sha256 hex of the bbk_ bearer>",
        "released": "2026-07-08", "duration": "365d", "enabled_paths": ["/mcp/"] }
    ] }
] }
```

- **`email`** (required) — matched case-insensitively; its presence is the allowlist.
- **`enabled_paths`** — allowed request-path prefixes; omit / `[]` / `["*"]` = all.
- **`api_keys[]`** — static `bbk_` keys for that user (see [Programmatic access](#programmatic-access-bearer)):
  - **`key_hash`** — `sha256` of the bearer; the raw key is never stored (mint via `tools/bb-apikey.py`).
  - **`duration`** — `<n>d` / `<n>h` / `0` / `never`, counted from **`released`** (`YYYY-MM-DD`).
  - **`id`** — human label for logs/revocation. **`enabled_paths`** — omit to inherit the user's scope.
  - Unknown fields (e.g. `notes`) are ignored, so annotate freely.

It is the real access gate, re-checked on **every** `/validate`, hot-reloaded on
SIGHUP (`systemctl reload bb-auth`) — remove a user or a single key + reload to
de-authorize even a still-valid cookie. A reload that fails to parse keeps the live
table (never nuked). Keys are indexed by their hash, so a lookup is a single map hit
(and trivially a single indexed query if you ever move this to a database).

## Session cookie

`<cookie> = bb2.<keyid>.<exp>.<b64url(email)>.<b64url(HMAC_SHA256(...))>` — HttpOnly,
Secure, SameSite=Lax, host-only on the service host, ~30 days. The key id is
stamped in so the signing key can roll over with zero downtime (see "Key
rotation" below). Stateless: no server-side session store — any worker can
validate any cookie and a restart logs nobody out. Cookies signed under the
previous single-key scheme are still honoured:

```text
bb2.<keyid>.<exp>.<b64url(email)>.<b64url(HMAC_SHA256("bb2.<keyid>.<exp>.<b64url(email)>", key[keyid]))>   # active
bb1.<exp>.<b64url(email)>.<b64url(HMAC_SHA256("bb1.<exp>.<b64url(email)>"))>                                 # legacy (verify-only)
```

The users file is re-checked on every `/validate`, so de-authorizing someone is
just an edit (remove the user, or a single API key) + `systemctl reload bb-auth`
(SIGHUP). A restart works too.

## Build (cross-compile)

```bash
bash scripts/build.sh        # run on Linux (or WSL)
# → dist/bb-auth   (the build prints the max GLIBC symbol required, so you can
#                   match it to your target host's glibc)
```

`scripts/build.sh` cross-compiles to `aarch64-unknown-linux-gnu` by default; edit
it for a different target. Deps are pure-Rust or `ring`-based (`tiny_http`,
`ureq`+rustls, `jsonwebtoken`, `hmac`/`sha2`) — no system OpenSSL, so the cross
build needs only the matching GNU toolchain. Built blocking/threaded (no async
runtime) to keep the binary and resident memory small.

## Deploy

`scripts/deploy.sh` is the **on-host installer** (run as root, on the target):
it installs the binary/unit + staged `bb-auth.env` (generating the HMAC key on
first install, then preserving it forever), restarts the service, and runs a
**post-deploy verification** — service active, `GET /auth/healthz == ok`,
`GET /auth/validate` (no cookie) `== 401`, HMAC key present, users.json
integrity, clean journal startup — exiting non-zero if any check fails. Staging a
`users.json` is **optional**: if absent, the live one is preserved (or a legacy
`allowed_emails` is auto-migrated to `users.json` on first run), so a binary-only
redeploy can never lock anyone out.

`scripts/deploy.ps1` (**run from Windows**) orchestrates the whole thing for a
`user@host`:

```powershell
./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -Build          # build in WSL + redeploy (users.json + HMAC key kept)
./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -UsersFile .\deploy\users.json   # first install / replace access file
```

It verifies SSH + passwordless sudo + aarch64, stages the artifacts, runs
`deploy.sh` as root, pings healthz, and cleans up. By default it ships no
users.json and never regenerates the HMAC key, so redeploys are zero-downtime.

## Run

bb-auth is a single binary configured entirely from the environment. It expects
to run **as a non-privileged service, on loopback, behind a TLS-terminating
reverse proxy** that performs the `auth_request`. It needs two files: the env
file (holds the HMAC secret) and the users file (JSON access list). The included
`deploy/bb-auth.service` runs it as a dedicated system user with aggressive
systemd hardening; `scripts/deploy.sh` is an example installer (creates the
user, installs the binary/unit + staged `bb-auth.env`, generates the HMAC key
once and preserves it across redeploys). See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §"Running it".

## Config

All via env — see [`deploy/bb-auth.env.example`](deploy/bb-auth.env.example) for
every variable. The only secret is `BB_AUTH_HMAC_KEY` (`openssl rand -base64 48`);
keep it out of version control and off shared storage.

## Putting a service behind the gate

The binary is service-agnostic. To front a service at `app.example.com`:

1. **nginx** on the service host: add the `auth_request` wiring — an
   `/internal/auth-gate` location proxying to bb-auth's `/auth/validate`, an
   `error_page 401 → @bb_signin` that redirects to `<login-page>/?rd=…`, and
   `/auth/session` + `/auth/logout` proxied to bb-auth.
2. **Cross-service SSO vs per-service login** — pure configuration:
   - *SSO (one login across a domain):* set `BB_AUTH_COOKIE_DOMAIN=.example.com`
     so the session cookie is shared, and `BB_AUTH_RD_BASE_DOMAIN=example.com` so
     the `rd` open-redirect guard accepts any `*.example.com` sibling.
   - *Per-service login:* run a separate bb-auth instance per service (its own
     `BB_AUTH_SEARCH_URL` + host-only cookie).
3. **Login page**: it must POST the `id_token` to the *right* service's
   `/auth/session`. For multiple services, derive the target from the validated
   `rd` instead of a fixed base.

Step 3 is the only per-service behaviour change; the SSO scope in step 2 is now
just configuration (`BB_AUTH_COOKIE_DOMAIN` + `BB_AUTH_RD_BASE_DOMAIN`).

## Security notes

- A Cognito-signed `id_token` is unforgeable; possession of one for an
  allowlisted, verified email is the credential.
- Static `bbk_` API keys are stored only as a SHA-256 hash; a valid, unexpired key
  authorizes its user per request within its path scope. Revoke by removing the key
  (or the user) from the users file + reload. Keys bypass Cognito, so treat the raw
  bearer like a password and prefer scoping it to the paths it needs.
- `rd` is open-redirect-guarded to the service host (or `*.BB_AUTH_RD_BASE_DOMAIN`).
- Login-CSRF (an attacker POSTing *their* token to log a victim into the
  attacker's account) is possible in theory but low-impact for a read gate;
  accepted. Revisit with a state/nonce if the gate ever fronts something sensitive.

### Key rotation

The cookie is HMAC-signed under `BB_AUTH_HMAC_KEY`, addressed by
`BB_AUTH_HMAC_KEY_ID`. Rotation is **zero-downtime** because the key id is
stamped into every `bb2` cookie and multiple keys can be accepted for
verification at once. 3-step runbook (k1 → k2):

1. Generate the new key and publish it as verify-only, then reload:

   ```bash
   NEW=$(openssl rand -base64 48)
   # in the env file: BB_AUTH_HMAC_ACCEPTED_KEYS=k2:$NEW   (k1 stays the active key)
   systemctl reload bb-auth
   ```

2. Flip the active key + id and reload. New cookies are signed with k2; existing
   cookies (signed with k1) still verify because k1 is still in the accepted set:

   ```bash
   # in the env file: BB_AUTH_HMAC_KEY=$NEW  and  BB_AUTH_HMAC_KEY_ID=k2
   systemctl reload bb-auth
   ```

3. After ~30 d (one TTL), every surviving cookie is k2-signed. Drop k1 from
   `BB_AUTH_HMAC_ACCEPTED_KEYS` and reload.

Nobody is logged out at any step. The old `bb1` (single-key) cookies are also
still accepted — they verify against any key in the set — so the original
migration from `bb1` to `bb2` invalidated nobody.
