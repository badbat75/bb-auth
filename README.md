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
| GET    | `/auth/validate` | nginx only | `auth_request`: 204 if cookie valid + allowlisted, else 401 |
| POST   | `/auth/session`  | browser    | validate posted `id_token`, set cookie, 302 → `rd` |
| GET    | `/auth/logout`   | browser    | clear cookie, 302 → login page                     |
| GET    | `/auth/healthz`  | local      | liveness                                           |

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

The allowlist is re-checked on every `/validate`, so de-authorizing an email is
just an edit + `systemctl reload bb-auth` (SIGHUP). A restart works too.

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
`GET /auth/validate` (no cookie) `== 401`, HMAC key present, allowlist
integrity, clean journal startup — exiting non-zero if any check fails. Staging
an `allowed_emails` is **optional**: if absent, the live allowlist is preserved,
so a binary-only redeploy can never lock anyone out.

`scripts/deploy.ps1` (**run from Windows**) orchestrates the whole thing for a
`user@host`:

```powershell
./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -Build          # build in WSL + redeploy (allowlist + HMAC key kept)
./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -AllowlistFile .\deploy\emails.txt   # first install / replace allowlist
```

It verifies SSH + passwordless sudo + aarch64, stages the artifacts, runs
`deploy.sh` as root, pings healthz, and cleans up. By default it ships no
allowlist and never regenerates the HMAC key, so redeploys are zero-downtime.

## Run

bb-auth is a single binary configured entirely from the environment. It expects
to run **as a non-privileged service, on loopback, behind a TLS-terminating
reverse proxy** that performs the `auth_request`. It needs two files: the env
file (holds the HMAC secret) and the allowlist file. The included
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
2. **Cross-service SSO vs per-service login** — one design choice:
   - *SSO (one login across a domain):* set `BB_AUTH_COOKIE_DOMAIN=.example.com`
     so the session cookie is shared, and widen the `rd` open-redirect guard to
     accept any `*.example.com` host (today it pins to a single `BB_AUTH_SEARCH_URL`).
   - *Per-service login:* run a separate bb-auth instance per service (its own
     `BB_AUTH_SEARCH_URL` + host-only cookie).
3. **Login page**: it must POST the `id_token` to the *right* service's
   `/auth/session`. For multiple services, derive the target from the validated
   `rd` instead of a fixed base.

Steps 2–3 are the only code/behaviour changes; the gate logic itself is generic.

## Security notes

- A Cognito-signed `id_token` is unforgeable; possession of one for an
  allowlisted, verified email is the credential.
- `rd` is open-redirect-guarded to the service host.
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
