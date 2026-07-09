# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

bb-auth is a single-binary **auth gate**: it accepts an AWS Cognito `id_token` that a
browser-side login page already obtained, validates it (RS256 via JWKS), and issues an
HMAC-signed session cookie that nginx enforces on every request via `auth_request`. It also
accepts per-request bearer credentials — a Cognito `id_token` or a static `bbk_` API key —
and enforces per-user / per-key **URL scopes** (`authorized_urls`). The access list is a JSON
**users file** (`BB_AUTH_USERS_FILE`). It is service-agnostic — one binary fronts any web
service, wired per-deployment through `BB_AUTH_*` env vars. The whole gate is **one Rust
file**, [src/main.rs](src/main.rs) (~2000 lines incl. tests); there is no module split by
design — read it top to bottom.

The defining constraint vs. authorization-code OIDC proxies (oauth2-proxy): those drive the
login themselves and *cannot* accept a token the browser already holds. bb-auth is built for
the opposite — a login page runs Cognito `USER_AUTH` in the browser (enabling sign-up +
auto-login with no second OTP) and POSTs the resulting `id_token` to `/auth/session`.

Deep docs live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (the service internals) and
[docs/AUTHENTICATION_FLOW.md](docs/AUTHENTICATION_FLOW.md) (the end-to-end browser↔Cognito↔nginx
sequence). Read those before changing the request flow or cookie format.

## Commands

This repo is developed on Windows but the artifact is a Linux/aarch64 binary.

```powershell
# Tests — pure unit tests in src/main.rs, run on the host (no network needed)
cargo test
cargo test session_roundtrip_bb2      # a single test by name

# Validate a users file with the real parser (no env, no network). Same check the
# deploy runs before it restarts the service.
cargo run -- --check-users .\deploy\users.example.json

# Host build / typecheck (SIGHUP reload is cfg(unix), compiled out on Windows)
cargo check
cargo clippy
cargo fmt

# Release cross-compile for the target — run in WSL/Linux, NOT on Windows.
# Produces dist/bb-auth (aarch64) and prints the max GLIBC symbol required.
bash scripts/build.sh                 # target overridable via BB_AUTH_TARGET

# Deploy from Windows over SSH (build in WSL + ship + remote self-verify)
./scripts/deploy.ps1 user@host -Build
./scripts/deploy.ps1 user@host -UsersFile .\deploy\users.json   # first install / replace access file
```

`docs/*.md` are linted with markdownlint (`.markdownlint.jsonc`).

## Endpoints (all under `/auth/`, fronted by nginx on the protected host)

| Method | Path | Caller | Behavior |
|--------|------|--------|----------|
| GET | `/auth/validate` | nginx `auth_request` only (loopback) | 204 if a credential authorizes the request, else 401. Checked in order: `Authorization: Bearer bbk_…` (static API key, looked up by hash), `Authorization: Bearer <id_token>` (same `validate_id_token` as `/auth/session`), or the session cookie. Each must map to an allowlisted user **and** be in the request's URL scope (`X-Original-URL`). Bearers are stateless (no cookie issued) and fall through to the cookie on failure; the reverse proxy must forward `Authorization` (and `X-Original-URL` for URL scoping). |
| POST | `/auth/session` | browser | validate posted `id_token`, set cookie, 302 → `rd` |
| GET | `/auth/logout` | browser | clear cookie, 302 → login page |
| GET | `/auth/healthz` | local | 200 `ok` |

## Invariants — do not break these

- **The cookie is a versioned wire format with backward compat.** `bb2` is active
  (`bb2.<keyid>.<exp>.<b64url(email)>.<b64url(HMAC)>`); `bb1` is legacy verify-only. Changing
  the serialization or the signed-message string logs out **every** existing user. The keyid
  enables zero-downtime HMAC key rotation (active key signs, accepted keys still verify) — see
  README "Key rotation". `verify_session` / `make_session` and their tests pin this.
- **The users file is the real access gate**, re-checked on *every* `/auth/validate` (not just
  at login). `BB_AUTH_USERS_FILE` is JSON (`{ "users": [ { email, authorized_urls?, api_keys? } ] }`),
  parsed into `RwLock<Users>` with two indices (`by_email`, `by_key_hash`), hot-reloaded on SIGHUP
  (`systemctl reload bb-auth`) — a reload failure keeps the old table (never nuke the live one).
  Removing a user *or* a single API key + reload denies even still-valid cookies/keys next request.
  See `read_users`; keep it the access gate and keep the reload fail-soft.
- **Scope errors are fatal; key errors are skipped.** A malformed `authorized_urls` pattern — or a
  residual pre-2.0 `enabled_paths` field — makes `read_users` return `Err` (fatal at startup, old
  table retained on SIGHUP). A bad `key_hash`/`duration` is still warn+skip. The asymmetry is
  deliberate: skipping a scope entry silently changes who can reach what, and dropping *all* of a
  user's entries would read as unrestricted. `bb-auth --check-users <file>` runs this same parser
  and exits 0/1 — `scripts/deploy.sh` calls it on the file about to go live and aborts before
  restarting, so a rejected file can never become a `Restart=on-failure` boot loop.
- **Static API keys (`bbk_` namespace) are self-contained grants tied to a user.** A bearer
  starting `bbk_` is looked up by `sha256(bearer)` in `by_key_hash` — the raw key is never stored
  (only `key_hash`), and the hash lookup **is** the verification (high-entropy keys make a preimage
  infeasible, so no constant-time compare is needed). A key must be unexpired (`released` +
  `duration`) and in its URL scope. Mint with `tools/bb-apikey.py`. Don't index by anything the
  client sends in the clear and don't store the raw key.
- **URL scoping applies to every credential, and access is enumerated, never assumed.** A user/key
  carries `authorized_urls` — full `<scheme>://<host>/<path>` patterns — matched against the
  original request URL from `BB_AUTH_ORIGINAL_URL_HEADER` (default `X-Original-URL`, nginx must set
  it). **There is no "unrestricted" scope**: an absent or empty `authorized_urls` grants *nothing*
  (`UrlScope::deny_all`), and blanket access is the explicit pattern `*://*/*`. A key with no
  `authorized_urls` inherits its user's. Because everything is scoped, the header is **mandatory** —
  a request without it is denied. Wildcards, legal in every component: `*` = zero+ chars but never
  `/`, **except** as the pattern's last byte where it spans the rest incl. `/`; `&` = exactly one
  non-`/` char. Anchored both ends. That "non-final `*` can't cross `/`" rule is what stops a
  wildcard leaking across `://`, so one matcher serves scheme, host and path — don't split it into
  three. `glob_match` is a bottom-up DP, **not** recursive backtracking (which is exponential on
  many `*`); `glob_many_stars_terminates` pins that. A URL with `..` is rejected. Patterns are
  validated + authority-lowercased once at load (`compile_pattern`). See `UrlScope::allows`.
- **nginx must not let `Host:` pick the scope.** `X-Original-URL` should hardcode the host per
  server block; `$scheme://$host$uri` is only safe behind a `default_server` that rejects unknown
  Hosts. Use `$uri`, never `$request_uri` — the latter carries the query string and is undecoded,
  so `/app/%2e%2e/admin` would match a `/app/*` scope while nginx serves `/admin`.
- **The gate cannot read `$uri` itself.** Inside an `auth_request` subrequest `$uri` is the
  *subrequest's* URI (`/internal/auth-gate`). So each gated location does
  `set $bb_url https://app.example.com$uri;` (rewrite phase, before the access phase that fires
  `auth_request`) and the gate sends `proxy_set_header X-Original-URL $bb_url;` — subrequests share
  the parent's variable array. The `set` must live in the *location*, not at `server` level: the
  subrequest re-runs the server rewrite phase and would clobber it. A gated location that forgets
  the `set` sends no header and is denied — fail-closed, which is why this is survivable.
- **Sessions are stateless** — no server-side store. Any worker validates any cookie; a restart
  logs nobody out. Don't introduce per-session server state.
- **Dependencies stay pure-Rust / `ring`-based** (`ureq`+rustls with bundled Mozilla roots,
  `jsonwebtoken`, `hmac`/`sha2`). The point is a clean aarch64 cross-compile with **no system
  OpenSSL or cert store**. Do not add a dep that pulls in `openssl`/native-tls. No async runtime
  (`tiny_http` is blocking + threaded) — keeps the binary and resident memory small.
- **id_token validation** must keep all of: `alg==RS256`, `iss`/`aud`/`exp` enforced (`exp`
  required, 60s leeway), `token_use=="id"`, `email_verified` truthy. See `validate_id_token`.
  The **one** sanctioned exception: `BB_AUTH_ALLOW_UNVERIFIED_SOCIAL` accepts `email_verified=false`
  **only** for federated logins (token carries an `identities` claim), optionally narrowed by
  `BB_AUTH_SOCIAL_PROVIDERS` — never for native Cognito users, since self-signup is open and an
  unverified native email is attacker-controlled. Off by default. See `unverified_social_ok`.
- **There is no canonical service base URL.** One gate fronts several hosts and which one is in
  play is decided by the caller, so `/auth/session` learns it from `BB_AUTH_ORIGINAL_URL_HEADER`
  (`origin_of`) — nginx must set that header on the session location too, not just the auth-gate.
  `BB_AUTH_AUTHORIZED_HOSTS` (comma-separated host globs, required) is the *only* authority on
  redirect targets. Don't reintroduce a single base URL.
- **`safe_rd` guards the post-login redirect** against open-redirect + response-splitting. A
  relative `rd` resolves against the caller's origin, an absolute one is taken as-is, and no `rd`
  means the caller's root — then **every** candidate goes through the same `rd_url_allowed` gate,
  so a spoofed caller origin still can't escape. Rejected ⇒ fall back to `BB_AUTH_LOGIN_URL`. The
  gate is https-only and rejects `//`, `/\`, control bytes incl. CR/LF, userinfo `@`, backslashes,
  and lookalikes like `evilbadbat75.com` / `badbat75.com.evil.com` (a pattern's literal dot is what
  rules those out; `*.x.com` also does not match the apex `x.com`). Any new use of request-supplied
  data in a header/redirect must stay behind this guard.
- **Release profile is size-optimized** (`opt-level="z"`, LTO, `panic="abort"`, stripped). Leave
  it that way unless asked.

## Config & deploy notes

- All config is env vars (`Config::from_env`); missing required vars are a fatal exit. The only
  secret is `BB_AUTH_HMAC_KEY` (≥32 bytes). Full reference: [deploy/bb-auth.env.example](deploy/bb-auth.env.example)
  and `docs/ARCHITECTURE.md` §8.
- **Target layout is a tree**: `/opt/bb-auth/{bin/bb-auth, etc/bb-auth.env, var/lib/users.json}`,
  unit at `/etc/systemd/system/bb-auth.service`. The service writes nothing, so the whole prefix is
  `ReadOnlyPaths` and no `StateDirectory` is needed despite the `var/lib` name.
- `scripts/deploy.sh` is the on-host installer (root, idempotent, self-verifying). It is
  **lockout-safe by construction**: it generates the HMAC key once and preserves it forever, and
  preserves the live `users.json` unless a new one is explicitly staged. Two ordering rules keep
  that true and are easy to break: the env file must be relocated into `etc/` **before** the
  "does `$ENV_DEST` exist?" check (otherwise it mints a fresh HMAC key and logs out everyone), and
  the snapshots (`OLD_BIN_SHA`, `OLD_USERS_MD5`) must be taken from the **tree** paths, after that
  relocation, or every verify check compares against nothing. Any redeploy must never log anyone
  out; a rejected users file must never reach a restart.
- bb-auth runs as a hardened, non-privileged systemd service ([deploy/bb-auth.service](deploy/bb-auth.service))
  on loopback behind a TLS-terminating reverse proxy; it speaks plain HTTP and holds no Cognito secret.
