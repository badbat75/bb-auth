# bb-auth — Architecture

Minimal **auth gate**. It accepts a Cognito `id_token` that a browser-side login
page obtained and turns it into an HMAC-signed session cookie that nginx enforces
via `auth_request`. The service is generic — it fronts any web service and is
wired per-deployment through `BB_AUTH_*` env vars.

This document describes the **service**. The end-to-end login sequence (browser,
Cognito, nginx, bb-auth) is documented separately in
[`AUTHENTICATION_FLOW.md`](./AUTHENTICATION_FLOW.md).

---

## 1. Why it exists

Authorization-code OIDC proxies (e.g. oauth2-proxy) only speak the OIDC
**authorization-code** flow: they redirect the browser to the IdP's hosted login
and exchange the returned code themselves. They **cannot accept a token the
browser already obtained**.

bb-auth assumes the opposite: a login page drives the Cognito `USER_AUTH` flow
directly on the public client. The key UX this unlocks is **auto-login right
after registration, with no second OTP**: a new user is `SignUp` →
`ConfirmSignUp` → `InitiateAuth(Session)` in one flow and ends up holding an
`id_token`. bb-auth takes that client-obtained token, validates it, and issues
the session cookie that grants access to the protected service.

---

## 2. Component view

```text
                           ┌──────────────────────── service host ────────────────────────┐
                           │                                                               │
  browser ─── HTTPS ─────▶ │  nginx :443  (the protected service)                          │
                           │   │                                                           │
                           │   ├─ auth_request ─▶ /internal/auth-gate ─▶ 127.0.0.1:4181/auth/validate
                           │   │     (401 ─▶ 302 <login-page>/?rd=<original>)               │
                           │   │                                                           │
                           │   ├─ POST /auth/session  ─▶ bb-auth (validate id_token → Set-Cookie)
                           │   ├─ GET  /auth/logout   ─▶ bb-auth (clear cookie)             │
                           │   └─ everything else     ─▶ upstream app  (only if gate == 204)│
                           │                                                               │
                           │  bb-auth :4181  (loopback only)  ◀── this service             │
                           └───────────────────────────────────────────────────────────────┘
                                                    │
                                                    └─ HTTPS (JWKS fetch) ─▶ cognito-idp.<region>.amazonaws.com
```

Three actors outside bb-auth itself:

| Actor | Role |
|-------|------|
| **nginx** | Edge TLS terminator. Runs `auth_request` against bb-auth on every protected request; maps `401` to a redirect to the login page. |
| **Login page** | Browser-side email-first UI that performs the Cognito `USER_AUTH` flow and then top-level `POST`s the resulting `id_token` to `/auth/session`. |
| **AWS Cognito** | Issues and RS256-signs the `id_token`. bb-auth only reads its public JWKS — it holds no Cognito secret. |

---

## 3. Code structure

The service is a **single Rust file**, `src/main.rs` (~850 lines). No module
split — the whole gate is small enough to read top to bottom. Logical sections,
in file order:

| Section | Purpose |
|---------|---------|
| `Config` / `from_env` | All tunables from env vars; fatal-`exit`s on missing required values or a too-short HMAC key. |
| `State` / `JwksCache` | Shared state behind `Arc`: config, a `RwLock<HashSet>` allowlist, a `RwLock` JWKS cache, and a `Mutex` serializing JWKS refreshes. |
| `load_allowlist` / `read_allowlist` / `reload_allowlist` | Reads the allowlist file (one email/line, `#` comments), lowercased. `load_allowlist` aborts startup if unreadable (warns if empty); `reload_allowlist` swaps it live on `SIGHUP`, keeping the old set on error. |
| `fetch_jwks` / `refresh_jwks_if_due` / `decoding_key` | `GET {issuer}/.well-known/jwks.json` via `ureq`+rustls; cache keyed by `kid`, refreshed at most once per 60 s, deduped across workers by double-checked locking. |
| `validate_id_token` | Full JWT validation (see §6). Returns the verified, lowercased email. |
| `make_session` / `verify_session` | HMAC-SHA256 signed cookie (see §7). |
| HTTP helpers | Header/cookie parsing, cookie building, open-redirect `safe_rd`, response builders. |
| `handle_validate` / `handle_session` / `handle_logout` | The three real handlers (plus `/auth/healthz` inline). |
| `main` | Build config/state, prime JWKS, spawn the worker thread pool, route requests. |

---

## 4. Runtime model

- **No async runtime.** `tiny_http` is blocking + threaded. This keeps the binary
  small and resident memory low, so it runs comfortably on constrained hosts.
- **Thread pool:** `BB_AUTH_WORKERS` threads (default 4), each looping on
  `server.recv()` and dispatching on `(method, path)`. State is shared via
  `Arc<State>`; the JWKS cache and the allowlist are each behind a `RwLock`, and a
  `Mutex` serializes JWKS refreshers (double-checked locking — see §6).
- **Stateless sessions:** there is **no server-side session store**. The session
  is fully carried by the HMAC cookie, so any worker can validate any request and
  a restart does not log anyone out (cookies are time-bound, not server-bound).
- **Allowlist is hot-reloadable:** it lives in a `RwLock<HashSet>` and is re-read
  from disk on `SIGHUP` (`systemctl reload bb-auth`) — edit + reload applies
  changes live without dropping sessions. A restart still works too. The email is
  re-checked on every `/auth/validate`, so a removed address is denied
  immediately even for still-valid cookies.

---

## 5. Endpoints

| Method | Path | Caller | Behavior |
|--------|------|--------|----------|
| `GET` | `/auth/validate` | nginx only (`auth_request`) | `204` if the session cookie is signature-valid, unexpired, **and** its email is on the allowlist; otherwise `401`. |
| `POST` | `/auth/session` | browser | Body `application/x-www-form-urlencoded`: `id_token=…&rd=…`. Fully validates the id_token; on success sets the session cookie and `302`s to `rd` (open-redirect guarded). |
| `GET` | `/auth/logout` | browser | Sets an expired (Max-Age=0) cookie and `302` → login page. Cross-site requests (`Sec-Fetch-Site: cross-site`) are ignored (no cookie clear) to block CSRF-forced logout. |
| `GET` | `/auth/healthz` | local | `200 ok`. Liveness probe. |

`/auth/validate` is never exposed publicly; nginx reaches it over loopback
through the `internal` `/internal/auth-gate` location. `/auth/session` and
`/auth/logout` are the only public bb-auth routes.

---

## 6. id_token validation (`validate_id_token`)

A Cognito-signed `id_token` is the credential. bb-auth validates it fully before
ever issuing a cookie:

1. **Algorithm:** header `alg` must be `RS256` (rejects `none` / symmetric algs).
2. **Key lookup:** `kid` from header → JWKS cache; on a miss, refresh JWKS if the
   last refresh was > 60 s ago (handles IdP key rotation). Refreshes are
   deduped with double-checked locking (`Mutex`-guarded) so concurrent workers
   don't all fetch in parallel on a cold/stale cache.
3. **Signature + standard claims** via `jsonwebtoken`:
   - `exp` validated (60 s leeway), `iss == BB_AUTH_COGNITO_ISSUER`,
     `aud` ∈ accepted audiences (`BB_AUTH_CLIENT_ID` plus any `BB_AUTH_AUDIENCES`);
     `exp`/`aud`/`iss` are mandatory.
4. **Cognito-specific claims:** `token_use == "id"` (rejects access tokens) and
   `email_verified` truthy (accepts JSON `true` or the string `"true"`).
   - **Social-login exception** (off by default): when
     `BB_AUTH_ALLOW_UNVERIFIED_SOCIAL` is enabled, a token with
     `email_verified=false` is still accepted **iff** it carries a federated
     `identities` entry (a social login — Cognito often can't verify a social
     sign-up's email even though the IdP asserted it). `BB_AUTH_SOCIAL_PROVIDERS`
     can narrow this to specific `providerName`s. **Native** Cognito users (no
     `identities` claim) are never relaxed: self-signup is open, so an unverified
     native email is attacker-controlled. See `unverified_social_ok`.
5. Returns the `email` claim, lowercased.

Failure on any step → the session request is rejected with `401` (token
invalid/expired) or `403` (email not on the allowlist).

---

## 7. Session cookie

Two formats are accepted; both carry an `exp`, the base64url-encoded email, and a
base64url HMAC-SHA256 tag:

```text
bb2.<keyid>.<exp>.<b64url(email)>.<b64url(HMAC_SHA256("bb2.<keyid>.<exp>.<b64url(email)>", key[keyid]))>   # active (signed)
bb1.<exp>.<b64url(email)>.<b64url(HMAC_SHA256("bb1.<exp>.<b64url(email)>"))>                                 # legacy (verify-only)
```

- **`bb2`** — active format. The **key id** (`<keyid>`) is stamped in so the
  signing key can roll over with zero downtime: the verifier looks up the key by
  id in the accepted set (`BB_AUTH_HMAC_KEY` active + `BB_AUTH_HMAC_ACCEPTED_KEYS`).
- **`bb1`** — legacy single-key format from before the key-id scheme. It carries
  no key id, so verification tries every accepted key. Kept so the `bb1` → `bb2`
  rollout did not log anyone out.
- **`exp`** — Unix epoch seconds, `now + session_ttl`; rejected when `exp <= now`.
- **HMAC-SHA256** over the cookie prefix up to (but not including) the signature.
  Verification is constant-time (`Mac::verify_slice`).
- **Attributes:** `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, host-only on
  the service host (a `Domain` can be set via `BB_AUTH_COOKIE_DOMAIN` but is
  empty by default).
- **TTL:** ~30 days (`BB_AUTH_SESSION_TTL_SECS=2592000`).

Because the cookie is self-contained and key addressed, **key rotation
invalidates nobody**: the new key is added as verify-only, then flipped to
active, then the old one is dropped after a TTL. See README "Key rotation".
De-authorizing an email is separate from signatures: remove it from the
allowlist and reload/restart — the next `/auth/validate` for that cookie returns
`401` even though the cookie signature is still valid.

---

## 8. Configuration

All config is via environment variables (see `deploy/bb-auth.env.example`).
Required vars cause a fatal exit if missing.

| Variable | Required | Default | Notes |
|----------|:--------:|---------|-------|
| `BB_AUTH_HMAC_KEY` | yes | — | Active session-signing secret. **≥ 32 bytes.** Generated once at deploy time; the only secret in the system. |
| `BB_AUTH_HMAC_KEY_ID` | no | `default` | Key id stamped into new `bb2` cookies. Must match `[A-Za-z0-9_-]+` (no `.`). Bump on rotation so older keys can still verify. |
| `BB_AUTH_HMAC_ACCEPTED_KEYS` | no | empty | Comma-separated `id:key` entries accepted for verification during rotation (`key` = `openssl rand -base64 48`). Active key always verifies; this is for previous keys. |
| `BB_AUTH_COGNITO_ISSUER` | yes | — | The Cognito user-pool issuer URL, `https://cognito-idp.<region>.amazonaws.com/<user-pool-id>`. Trailing `/` stripped. JWKS URL is derived from this. |
| `BB_AUTH_CLIENT_ID` | yes | — | The public app client used by the login page; always an accepted `id_token.aud`. |
| `BB_AUTH_AUDIENCES` | no | empty | Comma-separated extra accepted `aud`s (Cognito app client ids), e.g. a separate social-login client. `BB_AUTH_CLIENT_ID` is always accepted; a token is valid if its `aud` matches any. Read at startup → needs `restart`, not `reload`. |
| `BB_AUTH_ALLOW_UNVERIFIED_SOCIAL` | no | `false` | Truthy (`1`/`true`/`yes`/`on`) accepts `email_verified=false` tokens **only** for federated/social logins (those carrying an `identities` claim); native Cognito users stay strict. Off = strict for everyone. |
| `BB_AUTH_SOCIAL_PROVIDERS` | no | empty → any | Comma-separated `providerName`s (case-insensitive, e.g. `Google,SignInWithApple`) the relaxation above applies to. Empty = any federated provider. No effect unless `BB_AUTH_ALLOW_UNVERIFIED_SOCIAL` is on. |
| `BB_AUTH_ALLOWLIST_FILE` | yes | — | Path to the allowlist file. Loaded at startup. |
| `BB_AUTH_LISTEN` | no | `127.0.0.1:4181` | Bind address. Loopback only — nginx fronts it. |
| `BB_AUTH_COOKIE_NAME` | no | `bb_session` | |
| `BB_AUTH_COOKIE_DOMAIN` | no | empty → host-only | Set to a parent domain for cross-service SSO. |
| `BB_AUTH_SESSION_TTL_SECS` | no | `2592000` (30 d) | |
| `BB_AUTH_SEARCH_URL` | no | built-in† | Canonical service base; `rd` guard and default post-login target. Set per deployment. |
| `BB_AUTH_LOGIN_URL` | no | built-in† | Where `401`/logout send the user (the login page). Set per deployment. |
| `BB_AUTH_WORKERS` | no | `4` | Thread pool size (min 1). |

† `BB_AUTH_SEARCH_URL` and `BB_AUTH_LOGIN_URL` have hard-coded fallback defaults in
`from_env` carried over from the original deployment — always set them explicitly.
(The `SEARCH_URL` name is legacy; it is just "the service base URL".)

---

## 9. Dependencies & build

The dependency set is deliberately **pure-Rust / `ring`-based** so the cross-compile
needs only the GNU toolchain — no system OpenSSL or cert store:

| Crate | Use |
|-------|-----|
| `tiny_http` | Blocking, threaded HTTP server. |
| `ureq` (+`tls`/rustls, bundled Mozilla roots) | JWKS fetch; no system cert store. |
| `jsonwebtoken` (`ring`) | RS256 id_token verification. |
| `hmac` / `sha2` | Session cookie signing. |
| `base64` | URL-safe encoding in the cookie. |
| `form_urlencoded` | Parsing the `/auth/session` POST body. |
| `serde` / `serde_json` | Claims + JWKS deserialization. |

**Release profile** (`Cargo.toml`): `opt-level="z"`, LTO, single codegen unit,
`panic="abort"`, stripped — optimized for binary size.

**Cross-compile** (`scripts/build.sh`, run on Linux or WSL): targets
`aarch64-unknown-linux-gnu` by default (edit for another target). The script
copies sources into a fast local filesystem, builds the stripped binary into
`dist/bb-auth`, and prints the max GLIBC symbol required — match that to the
target host's glibc.

---

## 10. Running it

bb-auth is one binary plus two files (env + allowlist). Its operational contract:

- **Runs as a non-privileged service** — a dedicated system user, no login, no home.
- **Loopback only**, behind a TLS-terminating reverse proxy that performs the
  `auth_request` and the `401 → login-page` redirect.
- **Env file** holds the config and the HMAC secret; keep it readable only by the
  service user (e.g. `0640 root:bb-auth`). The secret should be generated once and
  preserved across redeploys so existing cookies keep verifying.
- **Allowlist file** holds the access list; editable + `SIGHUP` to apply live.

A typical layout:

```text
<install-dir>/
├── bb-auth          # binary (read-only to the service)
├── bb-auth.env      # config + HMAC key (service-user readable only)
└── allowed_emails   # access allowlist
<systemd-unit-dir>/bb-auth.service
```

`scripts/deploy.sh` is an example installer (idempotent): it creates the
system user/group, installs the binary, allowlist (backing up the prior
allowlist) and the staged `bb-auth.env`, **generates `BB_AUTH_HMAC_KEY` on first
run if empty and never overwrites it**, installs the systemd unit,
`daemon-reload`s, enables + restarts, then probes `/auth/healthz`.

### systemd hardening

The unit (`deploy/bb-auth.service`) runs under a dedicated user with aggressive
restrictions:

`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, `ProtectClock/Hostname/KernelTunables/Modules/Logs`,
`ProtectControlGroups`, `RestrictNamespaces/Realtime/SUIDSGID`,
`LockPersonality`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_INET
AF_INET6 AF_UNIX AF_NETLINK` (loopback bind + outbound HTTPS to Cognito +
resolver), `SystemCallFilter=@system-service`, empty `CapabilityBoundingSet`,
`ReadOnlyPaths=<install-dir>`, `UMask=0077`.

---

## 11. Security model & notes

- **The id_token is the credential.** A Cognito-signed `id_token` is unforgeable;
  possession of one for an allowlisted, `email_verified` address is proof of
  identity. bb-auth holds no Cognito secret — it only reads public JWKS.
- **The allowlist is the real access gate.** Cognito self-signup is open by
  design (to enable frictionless registration). Anyone can get an `id_token`, but
  only allowlisted emails get a session cookie, and the check is repeated on
  every `/auth/validate`.
- **Why `email_verified` is mandatory for native users.** Self-signup being open,
  if an unverified native email were accepted, anyone could register
  `boss@company.com` without controlling it and inherit that email's allowlist
  entry. `BB_AUTH_ALLOW_UNVERIFIED_SOCIAL` relaxes this **only** for federated
  logins, where the email is asserted by the upstream IdP rather than self-claimed
  — and is best narrowed (via `BB_AUTH_SOCIAL_PROVIDERS`) to IdPs that actually
  verify the email (Google, Apple). Leaving it off keeps the strict invariant.
- **`rd` is open-redirect-guarded:** must start with the canonical service URL
  or be a same-host absolute path (no `//`, no `/\` — browsers normalise the
  latter to a scheme-relative off-host redirect). Any control byte (incl. CR/LF)
  is also rejected, so attacker-supplied bytes can never reach the `Location`
  header (no response splitting).
- **Body size** capped at 64 KiB (`MAX_BODY`) — id_tokens are 1–3 KB.
- **Login-CSRF** (an attacker POSTing *their* token to log a victim into the
  attacker's account) is theoretically possible but low-impact for a read gate;
  accepted. Revisit with a state/nonce if the gate ever fronts something
  sensitive.
- **No TLS in-process:** bb-auth speaks plain HTTP on loopback; the reverse proxy
  terminates TLS. It binds `127.0.0.1` only and is not exposed directly.
