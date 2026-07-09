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
| `State` / `JwksCache` | Shared state behind `Arc`: config, a `RwLock<Users>` users table, a `RwLock` JWKS cache, and a `Mutex` serializing JWKS refreshes. |
| `load_users` / `read_users` / `reload_users` | Parses the JSON users file (`BB_AUTH_USERS_FILE`) into two indices — allowlisted emails (`by_email`) and `bbk_` API keys (`by_key_hash`), each with a URL scope; emails lowercased. `load_users` aborts startup if unreadable (warns if empty); `reload_users` swaps the table live on `SIGHUP`, keeping the old table on error. See §12. |
| `glob_match` / `compile_pattern` / `UrlScope` | The `authorized_urls` matcher: validates + normalises patterns at load, then matches a request URL against them with `*` / `&` wildcards. See §12. |
| `check_users` | The `bb-auth --check-users <file>` mode: parse and exit `0`/`1`, no env and no network. Lets a deploy reject a users file before restarting onto it. |
| `fetch_jwks` / `refresh_jwks_if_due` / `decoding_key` | `GET {issuer}/.well-known/jwks.json` via `ureq`+rustls; cache keyed by `kid`, refreshed at most once per 60 s, deduped across workers by double-checked locking. |
| `validate_id_token` | Full JWT validation (see §6). Returns the verified, lowercased email. |
| `make_session` / `verify_session` | HMAC-SHA256 signed cookie (see §7). |
| HTTP helpers | Header/cookie parsing, cookie building, open-redirect `safe_rd`, response builders. |
| `handle_validate` / `handle_session` / `handle_logout` | The three real handlers (plus `/auth/healthz` inline). `/auth/validate` resolves a cookie or bearer credential and enforces the request-URL scope (`bearer_apikey_ok` / `user_scope_ok` / `original_url`). |
| `main` | Build config/state, prime JWKS, spawn the worker thread pool, route requests. |

---

## 4. Runtime model

- **No async runtime.** `tiny_http` is blocking + threaded. This keeps the binary
  small and resident memory low, so it runs comfortably on constrained hosts.
- **Thread pool:** `BB_AUTH_WORKERS` threads (default 4), each looping on
  `server.recv()` and dispatching on `(method, path)`. State is shared via
  `Arc<State>`; the JWKS cache and the users table are each behind a `RwLock`, and a
  `Mutex` serializes JWKS refreshers (double-checked locking — see §6).
- **Stateless sessions:** there is **no server-side session store**. The session
  is fully carried by the HMAC cookie, so any worker can validate any request and
  a restart does not log anyone out (cookies are time-bound, not server-bound).
- **Users table is hot-reloadable:** it lives in a `RwLock<Users>` and is re-read
  from disk on `SIGHUP` (`systemctl reload bb-auth`) — edit + reload applies
  changes live without dropping sessions. A restart still works too. Every
  credential is re-checked against the table on every `/auth/validate`, so removing
  a user (or one of their API keys) denies it immediately even for a still-valid
  cookie or unexpired key.

---

## 5. Endpoints

| Method | Path | Caller | Behavior |
|--------|------|--------|----------|
| `GET` | `/auth/validate` | nginx only (`auth_request`) | `204` if an accepted credential authorizes the request URL, otherwise `401`. Accepts (in order) an `Authorization: Bearer bbk_…` static API key, an `Authorization: Bearer <id_token>`, or the session cookie; each is additionally checked against the caller's `authorized_urls`. See §12. |
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
invalid/expired) or `403` (email not in the users table).

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
De-authorizing an email is separate from signatures: remove the user from the
users file and reload/restart — the next `/auth/validate` for that cookie returns
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
| `BB_AUTH_USERS_FILE` | yes | — | Path to the JSON users file (allowlisted emails plus their `bbk_` API keys and URL scopes; see §12). Loaded at startup, hot-reloaded on `SIGHUP`. |
| `BB_AUTH_ORIGINAL_URL_HEADER` | no | `X-Original-URL` | Request header carrying the original request URL (scheme + host + normalised path). Set by nginx on the `auth_request` subrequest (from a `$bb_url` captured in the gated location — **not** from `$uri`, see §12) **and** on `/auth/session` (there a plain `https://app.example.com$uri` is correct). Drives URL scoping, and on `/auth/session` tells bb-auth which host the login is on. Query/fragment are stripped; missing ⇒ fail closed. |
| `BB_AUTH_LISTEN` | no | `127.0.0.1:4181` | Bind address. Loopback only — nginx fronts it. |
| `BB_AUTH_COOKIE_NAME` | no | `bb_session` | |
| `BB_AUTH_COOKIE_DOMAIN` | no | empty → host-only | Set to a parent domain for cross-service SSO. |
| `BB_AUTH_SESSION_TTL_SECS` | no | `2592000` (30 d) | |
| `BB_AUTH_AUTHORIZED_HOSTS` | yes | — | Comma-separated host globs a post-login `rd` may land on, e.g. `example.com,*.example.com`. The sole authority for the `rd` guard (see §9a). `*.x.com` does not match the apex `x.com`. Replaces the pre-2.0 `BB_AUTH_SEARCH_URL` + `BB_AUTH_RD_BASE_DOMAIN`. |
| `BB_AUTH_LOGIN_URL` | yes | — | Where `401`/logout send the user (the login page), and where a rejected `rd` falls back to. |
| `BB_AUTH_WORKERS` | no | `4` | Thread pool size (min 1). |

### 9a. Where the post-login redirect may land (`safe_rd`)

There is no canonical service base URL: one gate fronts several hosts, and which one is
in play is decided by the caller. `safe_rd` therefore takes two inputs beyond the `rd`
itself — the **caller origin** (`scheme://host` of the `/auth/session` request, from
`BB_AUTH_ORIGINAL_URL_HEADER`) and **`BB_AUTH_AUTHORIZED_HOSTS`**, the only authority on
where a redirect may land.

| `rd` | resolves to |
|---|---|
| absent / empty | the caller's root, `https://<caller-host>/` |
| `/preferences` (absolute path) | `https://<caller-host>/preferences` |
| `https://sibling.example.com/x` | itself, if the host matches a pattern |
| anything else, or a rejected host | `BB_AUTH_LOGIN_URL` |

Every candidate — including one resolved against the caller — passes through the same
`rd_url_allowed` gate, so even a spoofed caller origin cannot produce an off-domain
redirect. The gate is https-only and rejects userinfo (`@`), backslashes, `//evil`,
`/\evil` and any control byte (CR/LF ⇒ no response splitting), stripping a `:port`
before matching the host with the same glob used by `authorized_urls`. Lookalikes such
as `evilexample.com` and `example.com.evil.com` do not match `*.example.com`, because
the pattern's literal dot must be present — and the apex `example.com` doesn't either,
so list it explicitly.

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

bb-auth is one binary plus two files (env + users file). Its operational contract:

- **Runs as a non-privileged service** — a dedicated system user, no login, no home.
- **Loopback only**, behind a TLS-terminating reverse proxy that performs the
  `auth_request` and the `401 → login-page` redirect.
- **Env file** holds the config and the HMAC secret; keep it readable only by the
  service user (e.g. `0640 root:bb-auth`). The secret should be generated once and
  preserved across redeploys so existing cookies keep verifying.
- **Users file** holds the access list — allowlisted emails plus their `bbk_` API
  keys and URL scopes (JSON); editable + `SIGHUP` to apply live.

The layout, separated by role:

```text
<install-dir>/
├── bin/bb-auth          # binary (read-only to the service)
├── etc/bb-auth.env      # config + HMAC key (service-user readable only)
└── var/lib/users.json   # access list: emails + API keys + URL scopes
<systemd-unit-dir>/bb-auth.service
```

Nothing under the tree is ever written by the service (sessions are stateless), so
the whole prefix stays read-only to it and no `StateDirectory` is needed despite the
`var/lib` name.

`scripts/deploy.sh` is an example installer (idempotent): it creates the
system user/group, installs the binary, users file (backing up the prior
`users.json`) and the staged `bb-auth.env`, **generates `BB_AUTH_HMAC_KEY` on first
run if empty and never overwrites it**, installs the systemd unit,
`daemon-reload`s, enables + restarts, then probes `/auth/healthz`. It relocates a
pre-2.0 flat layout into the tree — env file first, so the HMAC key is preserved
rather than regenerated — and validates the users file that is about to go live with
`bb-auth --check-users`, aborting before the restart if it is rejected.

### systemd hardening

The unit (`deploy/bb-auth.service`) runs under a dedicated user with aggressive
restrictions:

`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, `ProtectClock/Hostname/KernelTunables/Modules/Logs`,
`ProtectControlGroups`, `RestrictNamespaces/Realtime/SUIDSGID`,
`LockPersonality`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_INET
AF_INET6 AF_UNIX AF_NETLINK` (loopback bind + outbound HTTPS to Cognito +
resolver), `SystemCallFilter=@system-service`, empty `CapabilityBoundingSet`,
`ReadOnlyPaths=<install-dir>` (the whole tree), `UMask=0077`.

---

## 11. Security model & notes

- **The id_token is the credential.** A Cognito-signed `id_token` is unforgeable;
  possession of one for an allowlisted, `email_verified` address is proof of
  identity. bb-auth holds no Cognito secret — it only reads public JWKS.
- **The users file is the real access gate.** Cognito self-signup is open by
  design (to enable frictionless registration). Anyone can get an `id_token`, but
  only emails listed in the users file get a session cookie, and the check is
  repeated on every `/auth/validate` (see §12) — as is each `bbk_` API key and the
  request-URL scope.
- **Why `email_verified` is mandatory for native users.** Self-signup being open,
  if an unverified native email were accepted, anyone could register
  `boss@company.com` without controlling it and inherit that email's allowlist
  entry. `BB_AUTH_ALLOW_UNVERIFIED_SOCIAL` relaxes this **only** for federated
  logins, where the email is asserted by the upstream IdP rather than self-claimed
  — and is best narrowed (via `BB_AUTH_SOCIAL_PROVIDERS`) to IdPs that actually
  verify the email (Google, Apple). Leaving it off keeps the strict invariant.
- **`rd` is open-redirect-guarded:** it must resolve to an `https://` URL whose host
  matches `BB_AUTH_AUTHORIZED_HOSTS` — an absolute path resolves against the caller's
  host, and no `//` or `/\` counts as a path (browsers normalise the latter to a
  scheme-relative off-host redirect). Any control byte (incl. CR/LF) is also rejected,
  so attacker-supplied bytes can never reach the `Location` header (no response
  splitting). See §9a.
- **Body size** capped at 64 KiB (`MAX_BODY`) — id_tokens are 1–3 KB.
- **Login-CSRF** (an attacker POSTing *their* token to log a victim into the
  attacker's account) is theoretically possible but low-impact for a read gate;
  accepted. Revisit with a state/nonce if the gate ever fronts something
  sensitive.
- **No TLS in-process:** bb-auth speaks plain HTTP on loopback; the reverse proxy
  terminates TLS. It binds `127.0.0.1` only and is not exposed directly.

---

## 12. Users file, API keys & URL scoping

Access is described by a single JSON file (`BB_AUTH_USERS_FILE`, installed as
`/opt/bb-auth/var/lib/users.json`). It lists every user — each with an optional URL
scope and zero or more static API keys — loaded at startup and hot-reloaded on
`SIGHUP`. It is the real access gate (`read_users` / `Users`):

```json
{ "users": [
    { "email": "you@example.com", "authorized_urls": ["*://*/*"] },
    { "email": "bot@example.com",
      "authorized_urls": ["https://mcp.example.com/mcp", "https://mcp.example.com/mcp/*"],
      "api_keys": [
        { "id": "laptop", "key_hash": "<sha256 hex of the bbk_… bearer>",
          "released": "2026-07-08", "duration": "365d",
          "authorized_urls": ["https://mcp.example.com/mcp/*"] }
      ] }
] }
```

At load time the file is parsed into two in-memory indices behind `RwLock<Users>`:
`by_email` (lowercased email → `UserRecord`) and `by_key_hash` (`sha256(bearer)` hex
→ `ApiKeyRecord`). Structurally-invalid JSON is a hard error, so a bad reload keeps
the previous table; a single malformed key is warned about and skipped so one typo
can't drop everyone.

Scope errors, by contrast, are **fatal**, not skipped: a dropped `authorized_urls`
entry would silently narrow — or, if it was the only one, blank out — a grant someone
believed they had written. So a malformed pattern, and any residual pre-2.0
`enabled_paths` field, makes the whole load fail. At startup that is an exit; on
`SIGHUP` the live table survives. `bb-auth --check-users <file>` runs exactly this
parser and exits `0`/`1`, which is how `scripts/deploy.sh` refuses to restart the
service onto a file that would not boot.

### Static API keys (`bbk_`)

A programmatic client (e.g. an MCP client that can't run the browser cookie flow)
authenticates with `Authorization: Bearer bbk_<secret>`. Keys are minted out of band
(`tools/bb-apikey.py`) and only their **SHA-256 hex fingerprint** (`key_hash`) is
stored — the raw `bbk_…` bearer is shown once and never persisted. `/auth/validate`
looks a bearer up by `sha256(bearer)` in `by_key_hash`; the lookup itself is the
verification (forging a matching preimage of a high-entropy random key is infeasible,
so no constant-time compare is needed). A key is a self-contained grant tied to a
user — its `email` / `id` are for logging and revocation, not a second allowlist step
— and must be unexpired and in URL scope.

- **`key_hash`** — `sha256_hex("bbk_<secret>")`, 64 lowercase hex chars.
- **`released` / `duration`** — expiry = `released` (`YYYY-MM-DD`) + `duration`, where
  `duration` is `<n>d` (days), `<n>h` (hours), a bare `<n>` (days), or `0` / `never`
  (never expires).

### URL scoping

Both users and keys carry an `authorized_urls` list of full `<scheme>://<host>/<path>`
patterns; the request URL must match one of them. **Access is enumerated, never
assumed**: there is no "unrestricted" scope. Omitting the field, or `[]`, authorizes
*nothing* — a listed user with no patterns reaches no URL at all, which makes an empty
list a usable way to suspend someone. Blanket access is the explicit pattern `*://*/*`,
something an operator has to mean in order to write. On a key, omitting the field
inherits the owning user's scope.

Two wildcards, legal in every component:

- **`*`** — zero or more characters, never `/`, **except** as the pattern's final
  byte, where it matches the remainder of the URL including `/`.
- **`&`** — exactly one character, never `/`.

The match is anchored at both ends (`glob_match`). Since a non-final `*` cannot cross
`/`, and `://` holds two of them, no wildcard leaks between scheme, host and path —
which is why one matcher serves all three without special-casing them. `glob_match` is
a bottom-up DP over `(pattern suffix, input suffix)`, O(n·m); a recursive
star-backtracker would go exponential on a pattern with many `*`.

Patterns are validated and normalised once at load (`compile_pattern`): the authority
is lowercased (the path keeps its case), and an entry is rejected if it lacks `://`,
lacks a path, has an empty scheme or host, carries userinfo (`@`), contains `..`, or
holds a control byte. Ports never appear in a candidate URL (nginx's `$host` omits
them), so a pattern must not contain one.

`/auth/validate` reads the original request URL from the `BB_AUTH_ORIGINAL_URL_HEADER`
header (default `X-Original-URL`), strips query/fragment, lowercases the authority,
and checks it against the resolved scope. nginx must set it on the subrequest:

```nginx
location / {
    # Hardcode the host — it is this server block, and a literal cannot be spoofed
    # by a `Host:` header. $uri (not $request_uri): decoded, normalised, query-free.
    set $bb_url https://app.example.com$uri;
    auth_request /internal/auth-gate;
    …
}
location = /internal/auth-gate {
    internal;
    proxy_set_header X-Original-URL $bb_url;   # NOT $uri — see below
    …
}
```

The two-step is mandatory. Inside the `auth_request` subrequest `$uri` is the
*subrequest's* URI — the literal `/internal/auth-gate` — so writing `$uri` in the
gate would scope every request against that one path. `$request_uri` does survive
into the subrequest, which is why it is tempting, but it is wrong on two counts: it
carries the query string, and it is undecoded, so `/app/%2e%2e/admin` would match a
pattern for `/app/*` while nginx serves `/admin`. `$uri` is decoded and normalised,
i.e. the path nginx will actually route. A subrequest shares its parent's variable
array, so a `set` in the gated location — rewrite phase, which runs before the
access phase that fires `auth_request` — is visible in the gate. Put the `set` in
the *location*, never at `server` level: the subrequest re-runs the server rewrite
phase and would overwrite it with its own `$uri`. A gated location that omits the
`set` sends an empty header, which nginx drops entirely, and bb-auth denies.

Using `$scheme://$host$uri` instead of the literal host is acceptable **only** behind
a `default_server` that rejects unknown Hosts; otherwise a spoofed `Host:` picks which
scope is evaluated.

The header is **required**, not optional: since every credential is scoped, a
subrequest without it fails closed (`401`). A URL containing `..` is likewise rejected
outright. One caveat: nginx leaves `%2f` encoded in `$uri`, so the matcher sees three
literal bytes rather than a segment boundary — which also fails closed.

### Credential precedence at `/auth/validate`

`handle_validate` tries credentials in this order, each additionally URL-scoped:

1. **`Authorization: Bearer bbk_…`** — static API key: looked up by hash, checked for
   expiry and URL scope (`bearer_apikey_ok`).
2. **`Authorization: Bearer <id_token>`** — a Cognito id_token validated exactly as at
   `/auth/session` (§6); its email must be in `by_email` and the URL in the user's
   scope (`user_scope_ok`).
3. **Session cookie** — verified as in §7, then the same `by_email` + URL check.

A failed bearer falls through to the cookie check, so a stray `Authorization` header
never blocks an otherwise-valid cookie. Any authorized credential → `204`; otherwise
`401`.
