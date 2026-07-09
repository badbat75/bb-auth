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
file**, [src/main.rs](src/main.rs); there is no module split by design — read it top to bottom.

The defining constraint vs. authorization-code OIDC proxies (oauth2-proxy): those drive the
login themselves and *cannot* accept a token the browser already holds. bb-auth is built for
the opposite — a login page runs Cognito `USER_AUTH` in the browser (enabling sign-up +
auto-login with no second OTP) and POSTs the resulting `id_token` to `/auth/session`.

## Where documentation lives

This file holds the **rules**: what must not break, why, and the symbol that pins each one.
The **mechanism** lives in rustdoc next to the code (`cargo doc --no-deps --open`) — the
endpoint table and credential order on the crate root, the cookie wire format on
`COOKIE_VERSION`, the users-file schema on `UsersFile`, the wildcard grammar on `glob_match`,
the nginx snippets on `Config::original_url_header` and `IDENTITY_HEADER`. Don't copy one into
the other; when they disagree, the code wins. Rustdoc must stay warning-free — a broken
intra-doc link is the cheapest rot detector this repo has.

Deep docs: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (service internals) and
[docs/AUTHENTICATION_FLOW.md](docs/AUTHENTICATION_FLOW.md) (the end-to-end
browser↔Cognito↔nginx sequence). Read those before changing the request flow or cookie format.

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
cargo doc --no-deps                   # must emit zero warnings

# Release cross-compile for the target — run in WSL/Linux, NOT on Windows.
# Produces dist/bb-auth (aarch64) and prints the max GLIBC symbol required.
bash scripts/build.sh                 # target overridable via BB_AUTH_TARGET

# Deploy from Windows over SSH (build in WSL + ship + remote self-verify)
./scripts/deploy.ps1 user@host -Build
./scripts/deploy.ps1 user@host -UsersFile .\deploy\users.json   # first install / replace access file
```

`docs/*.md` are linted with markdownlint (`.markdownlint.jsonc`).

## Invariants — do not break these

- **The cookie is a versioned wire format with live clients.** Changing the serialization or the
  signed-message bytes logs out **every** existing user. `bb2` is active, `bb1` legacy verify-only;
  the keyid enables zero-downtime HMAC key rotation (README "Key rotation"). `make_session` /
  `verify_session` and their tests pin this.
- **The users file is the real access gate**, re-checked on *every* `/auth/validate` (not just at
  login). Parsed into `RwLock<Users>` with two indices, hot-reloaded on SIGHUP (`systemctl reload
  bb-auth`) — a reload failure keeps the old table (never nuke the live one). Removing a user *or* a
  single API key + reload denies even still-valid cookies/keys next request. See `read_users`; keep
  it the access gate and keep the reload fail-soft.
- **Scope errors are fatal; key errors are skipped.** A malformed `authorized_urls` pattern — or a
  residual pre-2.0 `enabled_paths` field — makes `read_users` return `Err` (fatal at startup, old
  table retained on SIGHUP). A bad `key_hash`/`duration` is still warn+skip. The asymmetry is
  deliberate: skipping a scope entry silently changes who can reach what, and dropping *all* of a
  user's entries would read as unrestricted. `bb-auth --check-users <file>` runs this same parser
  and exits 0/1 — `scripts/deploy.sh` calls it on the file about to go live and aborts before
  restarting, so a rejected file can never become a `Restart=on-failure` boot loop.
- **Static API keys (`bbk_` namespace) are self-contained grants tied to a user.** The raw key is
  never stored, and the `sha256(bearer)` lookup in `by_key_hash` **is** the verification. A key must
  be unexpired and in its URL scope. Don't index by anything the client sends in the clear, and don't
  store the raw key. Mint with `tools/bb-apikey.py`.
- **Access is enumerated, never assumed.** There is **no "unrestricted" scope**: an absent or empty
  `authorized_urls` grants *nothing* (`UrlScope::deny_all`), and blanket access is the explicit
  pattern `*://*/*`. A key with no `authorized_urls` inherits its user's. Because every credential is
  scoped, `BB_AUTH_ORIGINAL_URL_HEADER` is **mandatory** — a request without it is denied. See
  `UrlScope::allows`.
- **One matcher serves scheme, host and path.** A non-final `*` cannot cross `/`, and `://` holds two
  of them — that single rule is what stops a wildcard leaking across component boundaries, so don't
  split `glob_match` into three matchers. It is a bottom-up DP, **not** recursive backtracking (which
  is exponential on many `*`); `glob_many_stars_terminates` pins that. A URL with `..` is rejected;
  patterns are validated and authority-lowercased once at load (`compile_pattern`).
- **nginx builds `X-Original-URL`, and must not let `Host:` pick the scope.** Hardcode the host per
  server block (`$scheme://$host$uri` is only safe behind a `default_server` that rejects unknown
  Hosts), and use `$uri`, never `$request_uri` — the latter is undecoded and carries the query
  string, so `/app/%2e%2e/admin` would match an `/app/*` scope while nginx serves `/admin`. Inside an
  `auth_request` subrequest `$uri` is the *subrequest's* URI, so each gated **location** must
  `set $bb_url …$uri;` and the gate forwards `$bb_url`. The `set` must live in the location, not at
  `server` level: the subrequest re-runs the server rewrite phase and would clobber it. A gated
  location that forgets it sends no header and is denied — fail-closed, which is why this is
  survivable. nginx must also forward `Authorization`, and set the header on `/auth/session` too.
- **The gate names the user; nginx is what makes that trustworthy.** A `204` carries the
  authorized email in `IDENTITY_HEADER` (`X-Auth-Email`, a fixed constant — nginx renames it
  on the way through, so don't make it configurable). It is only safe because nginx sets or
  clears it on **every** gated location (`proxy_set_header` overrides just the names it lists)
  and the app is unreachable except through nginx. Emails must be printable ASCII, enforced
  once at load (`header_safe_email`, warn+skip like an empty email — dropping a user is
  fail-closed): a CR/LF would be a response-splitting gadget, and load time is the only point
  that also covers the API-key path, whose email never passes through a token claim. That guard
  is what lets `respond_authorized` call `h()` without a per-request check — `h()` panics on a
  non-ASCII value. The emitted email is always a `by_email` key: the token/cookie paths return
  the string that just matched one by exact lookup, so a case-insensitive lookup added later
  would break the chain (the `debug_assert!` there exists to catch exactly that). Applications
  must **not** decode the credential themselves — the cookie is not a JWT and a `bbk_` key has
  no token, and a valid id_token proves identity, never authorization.
- **Sessions are stateless** — no server-side store. Any worker validates any cookie; a restart
  logs nobody out. Don't introduce per-session server state.
- **Dependencies stay pure-Rust / `ring`-based** (`ureq`+rustls with bundled Mozilla roots,
  `jsonwebtoken`, `hmac`/`sha2`). The point is a clean aarch64 cross-compile with **no system
  OpenSSL or cert store**. Do not add a dep that pulls in `openssl`/native-tls. No async runtime
  (`tiny_http` is blocking + threaded) — keeps the binary and resident memory small.
- **id_token validation** must keep all of: `alg==RS256`, `iss`/`aud`/`exp` enforced (`exp`
  required, 60s leeway), `token_use=="id"`, `email_verified` truthy. The **one** sanctioned
  exception: `BB_AUTH_ALLOW_UNVERIFIED_SOCIAL` accepts `email_verified=false` **only** for federated
  logins, optionally narrowed by `BB_AUTH_SOCIAL_PROVIDERS` — never for native Cognito users, since
  self-signup is open and an unverified native email is attacker-controlled. Off by default. See
  `validate_id_token` / `unverified_social_ok`.
- **There is no canonical service base URL.** One gate fronts several hosts and which one is in
  play is decided by the caller, so `/auth/session` learns it from `BB_AUTH_ORIGINAL_URL_HEADER`
  (`origin_of`) — nginx must set that header on the session location too, not just the auth-gate.
  `BB_AUTH_AUTHORIZED_HOSTS` (comma-separated host globs, required) is the *only* authority on
  redirect targets. Don't reintroduce a single base URL.
- **`safe_rd` guards the post-login redirect** against open-redirect + response-splitting. **Every**
  candidate — relative, absolute, or the no-`rd` default — goes through the same `rd_url_allowed`
  gate, so a spoofed caller origin still can't escape. Rejected ⇒ fall back to `BB_AUTH_LOGIN_URL`.
  The gate is https-only and rejects `//`, `/\`, control bytes incl. CR/LF, userinfo `@`,
  backslashes, and lookalikes like `evilbadbat75.com` / `badbat75.com.evil.com` (a pattern's literal
  dot is what rules those out; `*.x.com` also does not match the apex `x.com`). Any new use of
  request-supplied data in a header/redirect must stay behind this guard.
- **Release profile is size-optimized** (`opt-level="z"`, LTO, `panic="abort"`, stripped). Leave
  it that way unless asked.

## Config & deploy notes

- All config is env vars (`Config::from_env`); missing required vars are a fatal exit. The only
  secret is `BB_AUTH_HMAC_KEY` (≥32 bytes). Full reference: [deploy/bb-auth.env.example](deploy/bb-auth.env.example)
  and `docs/ARCHITECTURE.md` §8.
- **Target layout is a tree**: `/opt/bb-auth/{bin/bb-auth, etc/bb-auth.env, var/lib/users.json}`,
  unit at `/etc/systemd/system/bb-auth.service`. The service writes nothing, so the whole prefix is
  `ReadOnlyPaths` and no `StateDirectory` is needed despite the `var/lib` name. It runs hardened and
  non-privileged on loopback behind a TLS-terminating reverse proxy, speaks plain HTTP, and holds no
  Cognito secret.
- `scripts/deploy.sh` is the on-host installer (root, idempotent, self-verifying). It is
  **lockout-safe by construction**: it generates the HMAC key once and preserves it forever, and
  preserves the live `users.json` unless a new one is explicitly staged. **The env file is
  operator-owned** — installed once, then never edited. So the deploy *validates* config rather
  than fixing it: a missing required var, or a `BB_AUTH_USERS_FILE` that doesn't point at the file
  this deploy installs, aborts **before** the restart. Both matter — a fatal startup under
  `Restart=on-failure` is a boot loop, and a mismatched path means `--check-users` vouched for a
  file nothing loads. Any redeploy must never log anyone out; a rejected users file must never
  reach a restart.
