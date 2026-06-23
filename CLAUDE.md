# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

bb-auth is a single-binary **auth gate**: it accepts an AWS Cognito `id_token` that a
browser-side login page already obtained, validates it (RS256 via JWKS), and issues an
HMAC-signed session cookie that nginx enforces on every request via `auth_request`. It is
service-agnostic — one binary fronts any web service, wired per-deployment through
`BB_AUTH_*` env vars. The whole gate is **one Rust file**, [src/main.rs](src/main.rs)
(~950 lines incl. tests); there is no module split by design — read it top to bottom.

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

# Host build / typecheck (SIGHUP reload is cfg(unix), compiled out on Windows)
cargo check
cargo clippy
cargo fmt

# Release cross-compile for the target — run in WSL/Linux, NOT on Windows.
# Produces dist/bb-auth (aarch64) and prints the max GLIBC symbol required.
bash scripts/build.sh                 # target overridable via BB_AUTH_TARGET

# Deploy from Windows over SSH (build in WSL + ship + remote self-verify)
./scripts/deploy.ps1 user@host -Build
./scripts/deploy.ps1 user@host -AllowlistFile .\deploy\emails.txt   # first install / replace allowlist
```

`docs/*.md` are linted with markdownlint (`.markdownlint.jsonc`).

## Endpoints (all under `/auth/`, fronted by nginx on the protected host)

| Method | Path | Caller | Behavior |
|--------|------|--------|----------|
| GET | `/auth/validate` | nginx `auth_request` only (loopback) | 204 if cookie valid **and** email allowlisted, else 401 |
| POST | `/auth/session` | browser | validate posted `id_token`, set cookie, 302 → `rd` |
| GET | `/auth/logout` | browser | clear cookie, 302 → login page |
| GET | `/auth/healthz` | local | 200 `ok` |

## Invariants — do not break these

- **The cookie is a versioned wire format with backward compat.** `bb2` is active
  (`bb2.<keyid>.<exp>.<b64url(email)>.<b64url(HMAC)>`); `bb1` is legacy verify-only. Changing
  the serialization or the signed-message string logs out **every** existing user. The keyid
  enables zero-downtime HMAC key rotation (active key signs, accepted keys still verify) — see
  README "Key rotation". `verify_session` / `make_session` and their tests pin this.
- **The allowlist is the real access gate**, re-checked on *every* `/auth/validate` (not just
  at login). It's an in-memory `RwLock<HashSet>` of lowercased emails, hot-reloaded on SIGHUP
  (`systemctl reload bb-auth`) — a reload failure keeps the old set (never nuke the live list).
  Removing an email + reload denies even still-valid cookies on the next request.
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
- **`safe_rd` guards the post-login redirect** against open-redirect + response-splitting (only
  the canonical service URL prefix or a same-host absolute path; rejects `//`, `/\`, and any
  control byte incl. CR/LF). Any new use of request-supplied data in a header/redirect must stay
  behind this guard.
- **Release profile is size-optimized** (`opt-level="z"`, LTO, `panic="abort"`, stripped). Leave
  it that way unless asked.

## Config & deploy notes

- All config is env vars (`Config::from_env`); missing required vars are a fatal exit. The only
  secret is `BB_AUTH_HMAC_KEY` (≥32 bytes). Full reference: [deploy/bb-auth.env.example](deploy/bb-auth.env.example)
  and `docs/ARCHITECTURE.md` §8.
- `scripts/deploy.sh` is the on-host installer (root, idempotent, self-verifying). It is
  **lockout-safe by construction**: it generates the HMAC key once and preserves it forever, and
  preserves the live allowlist unless a new one is explicitly staged. Preserve this property when
  editing the deploy path — a binary-only redeploy must never log anyone out.
- bb-auth runs as a hardened, non-privileged systemd service ([deploy/bb-auth.service](deploy/bb-auth.service))
  on loopback behind a TLS-terminating reverse proxy; it speaks plain HTTP and holds no Cognito secret.
