# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

bb-auth is a single-binary **auth gate**: it accepts an AWS Cognito `id_token` that a
browser-side login page already obtained, validates it (RS256 via JWKS), and issues an
HMAC-signed session cookie that nginx enforces on every request via `auth_request`. It also
accepts per-request bearer credentials — a Cognito `id_token` or a static `bbk_` API key —
and enforces per-user / per-key **URL scopes** (`authorized_urls`), plus **`sites`** that can
open a URL area to any authenticated identity. The access list is a JSON **access file**
(`BB_AUTH_USERS_FILE` — the var keeps its pre-`sites` name). It is service-agnostic — one
binary fronts any web service, wired per-deployment through `BB_AUTH_*` env vars.

One crate, three targets, and the split is load-bearing:

- **[src/lib.rs](src/lib.rs)** (`bb_auth_core`) — **the access file**: its schema, its
  parser, the URL matcher, and the grant model (`decide` / `decide_api_key`). Everything two
  programs must agree on, byte for byte.
- **[src/main.rs](src/main.rs)** — **the gate**, and everything the access file has no
  opinion about: HTTP, the session cookie, id_token validation, the nginx contract. Still
  **one file**, still read top to bottom.
- **[src/bin/bb-auth-adm.rs](src/bin/bb-auth-adm.rs)** — the access-file admin CLI: CRUD over
  `url_groups` / `sites` / `denied` / `users` / `api_keys`, key minting, and `can EMAIL URL`
  (would this credential get in?). It links the library, none of the gate.

The defining constraint vs. authorization-code OIDC proxies (oauth2-proxy): those drive the
login themselves and *cannot* accept a token the browser already holds. bb-auth is built for
the opposite — a login page runs Cognito `USER_AUTH` in the browser (enabling sign-up +
auto-login with no second OTP) and POSTs the resulting `id_token` to `/auth/session`.

## Where documentation lives

This file holds the **rules**: what must not break, why, and the symbol that pins each one.
The **mechanism** lives in rustdoc next to the code (`cargo doc --no-deps --open`) — the
endpoint table and credential order on `bb-auth`'s crate root, the cookie wire format on
`COOKIE_VERSION`, the access-file schema on `AccessFile`, the site-resolution rule on `Sites`,
the wildcard grammar on `glob_match`, the `@name` group grammar on `UrlGroups`, the grant
model on `Decision`, the reason for the
library split on `bb_auth_core`'s crate root, the claim→header derivation on `ProfileClaim`,
the nginx snippets on `Config::original_url_header` and `IDENTITY_HEADER`. Don't copy one into
the other; when they disagree, the code wins. Rustdoc must stay warning-free — a broken
intra-doc link is the cheapest rot detector this repo has, and it now spans two crates
(a gate doc pointing at a moved type must be re-pointed, not de-linked).

Deep docs: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (service internals) and
[docs/AUTHENTICATION_FLOW.md](docs/AUTHENTICATION_FLOW.md) (the end-to-end
browser↔Cognito↔nginx sequence). Read those before changing the request flow or cookie format.

## Commands

This repo is developed on Windows but the artifact is a Linux/aarch64 binary.

```powershell
# Tests — pure unit tests in src/lib.rs (the access file) and src/main.rs (the gate),
# run on the host, no network needed
cargo test
cargo test session_roundtrip_bb4      # a single test by name

# Validate an access file with the real parser (no env, no network). Same check the
# deploy runs before it restarts the service. Prints the public_auth sites, if any.
cargo run --bin bb-auth -- --check-users .\deploy\users.example.json

# Administer an access file (CRUD; every write is validated with the gate's own parser).
# `can` answers with the gate's own decision function — exit 0 = the request would pass.
cargo run --bin bb-auth-adm -- --help
cargo run --bin bb-auth-adm -- -f .\deploy\users.json show
cargo run --bin bb-auth-adm -- -f .\deploy\users.json user add bob@x.com --url 'https://app.x.com/*'
cargo run --bin bb-auth-adm -- -f .\deploy\users.json key add bob@x.com --id laptop --duration 365d
cargo run --bin bb-auth-adm -- -f .\deploy\users.json can bob@x.com https://app.x.com/reports

# Host build / typecheck (SIGHUP reload is cfg(unix), compiled out on Windows)
cargo check
cargo clippy --all-targets
cargo fmt
cargo doc --no-deps                   # must emit zero warnings, across all three targets

# Release cross-compile for the target — run in WSL/Linux, NOT on Windows.
# Produces dist/bb-auth (aarch64) and prints the max GLIBC symbol required.
bash scripts/build.sh                 # target overridable via BB_AUTH_TARGET

# Deploy from Windows over SSH (build in WSL + ship + remote self-verify)
./scripts/deploy.ps1 user@host -Build
./scripts/deploy.ps1 user@host -UsersFile .\deploy\users.json   # first install / replace access file
```

`docs/*.md` are linted with markdownlint (`.markdownlint.jsonc`).

## Invariants — do not break these

- **The library is the access file, and nothing else.** `bb_auth_core` exists because two
  programs must agree, byte for byte, on what an access file *means* — so there is exactly
  one parser (`compile_access`), one matcher (`glob_match`), one grant model (`decide`,
  `decide_api_key`), and both link it. That is the whole membership rule: a thing belongs
  in the library iff the access file has an opinion about it. HTTP, the cookie, the JWT,
  the env, the nginx contract are the **gate's**, and stay in `src/main.rs` — which is
  still one file, read top to bottom. Do not move gate code into the library to "share" it
  with the CLI; the CLI has no business with any of it. The two authorization functions in
  `main.rs` (`authorize`, `bearer_apikey_email`) are thin wrappers that add the log line
  and the wall clock to the library's decision — keep them thin, and keep the rule in the
  library, or `bb-auth-adm can` starts answering a different question from the gate.
- **`bb-auth-adm` must never write a file the gate would reject.** Every mutation is
  serialized, re-parsed, and run through `compile_access` — the gate's own parser, on the
  exact bytes about to land on disk — before the write. A rejected access file is a fatal
  startup, and under `Restart=on-failure` that is a boot loop; this tool and
  `--check-users` are the two places that can catch it in time. The write is atomic
  (temp + rename) and **preserves mode and owner**: the live file is `root:bb-auth 0640`,
  and a rewrite by root that left it `root:root` would lock the service out of its own
  access list — the chown failing is therefore a hard abort, not a warning.
- **The cookie is a versioned wire format, and exactly one version is accepted.** `bb4` is it;
  there is deliberately no verify-only arm for `bb1`/`bb2`/`bb3` any more. So changing the
  serialization or the signed-message bytes logs out **every** existing user — that is the
  accepted price, because a re-auth is one trip through the login page against a Cognito session
  the browser still holds, and carrying an arm per historical format is not worth it. Bump the tag
  when the bytes change (never reuse one), say so in the README's upgrade note, and don't ship it
  mid-something. What must *never* log anyone out is HMAC **key rotation**, which is a separate
  axis: the keyid in the cookie is what makes it zero-downtime (README "Key rotation").
  `make_session` / `verify_session` and their tests pin the format, and
  `pre_bb4_cookies_are_rejected` pins the absence of the legacy arms. The claims segment is a
  **self-describing JSON object**, and that is what keeps `BB_AUTH_PROFILE_CLAIMS` off this
  axis: positional segments would let a config edit reinterpret a live cookie's values under
  another claim's name, so editing the list must stay a no-logout change. Verify checks the
  signature over the segment **as received** and only then parses it — never parse and
  re-serialize to compare.
- **The access file is the real access gate**, re-checked on *every* `/auth/validate` (not just at
  login). Parsed into `RwLock<Access>` — sites, `denied`, and two indices — hot-reloaded on SIGHUP
  (`systemctl reload bb-auth`); a reload failure keeps the old table (never nuke the live one). See
  `read_access`; keep it the access gate and keep the reload fail-soft. Its four sections answer
  four questions: `url_groups` names a reusable set of URLs, `sites` describe URL areas, `denied`
  vetoes people, `users` is the roster.
- **Scope errors are fatal; key errors are skipped.** A malformed URL pattern (a user's, a key's, or
  a site's), an unknown field on a `SiteSpec`, or a residual pre-2.0 `enabled_paths` field makes
  `read_access` return `Err` (fatal at startup, old table retained on SIGHUP). So does anything
  wrong about a **`@group` reference** — an unknown one (the message names the referrer), a bad
  group name, a group entry that references another group (groups are flat, so there is no cycle
  to detect), or a malformed pattern in a group **nothing references**: a group that only breaks
  when someone first uses it is a trap `--check-users` never saw. Groups are pure abbreviation and
  expand **once, in `compile_access`** (`UrlScope::compile_with_groups`), so `Access`, `decide` and
  every consumer stay flat and know nothing about them — keep the expansion there. A bad
  `key_hash`/`duration` is still warn+skip. The asymmetry is deliberate: skipping a scope entry
  silently changes who can reach what, and dropping *all* of a user's entries would read as
  unrestricted. `deny_unknown_fields` on `SiteSpec` is the same reflex aimed forward — when
  `public_auth` grows a companion restriction, a typo in it must not silently leave `public_auth:
  true` standing alone, which fails *open*. `bb-auth --check-users <file>` runs this same parser
  and exits 0/1 — `scripts/deploy.sh` calls it on the file about to go live and aborts before
  restarting, so a rejected file can never become a `Restart=on-failure` boot loop.
- **Two grant sources, one veto.** A request is authorized when the credential resolves to an
  identity and either the user's `authorized_urls` or a `public_auth` site covers the URL
  (`authorize`). `denied` outranks both, on **every** credential — the id_token and cookie paths,
  the API-key path (its owner), and cookie issuance. A veto covering half the doors is worse than
  none. `denied` is not redundant with deleting the row: on a `public_auth` site `by_email` is never
  consulted, so for an un-enrolled identity it is the *only* denial there is; and for an enrolled one
  it suspends without destroying their scope and keys. Corollary an operator must know: removing a
  user does **not** keep them off a `public_auth` site, and neither does `authorized_urls: []`.
- **A site describes a place, never a person.** No field of a `SiteRecord` may name a user — grants
  to named users live in exactly one place, `users[].authorized_urls`. Expressing the same
  user↔URL relation twice would mean someone removed from the roster could still walk in through a
  site. Site fields are predicates over an anonymous identity, and may only modulate the grant that
  record itself makes. `Sites::resolve` is **first-match-wins in file order** — fixed now, while
  `public_auth` is the only property, because a second field makes "which record answers?" expensive
  to change; the doc on `Sites` records why the alternatives lose. Sites only ever *grant*: a URL
  with no site is not denied, just not open. They match through `UrlScope::allows`, which is where
  the missing-header and `..` denials live — do not give them a second matcher.
- **`public_auth` grants on identity alone**, to anyone Cognito vouches for, enrolled or not. Since
  self-signup is open that means anyone who can register; it is the right grant for an onboarding
  area and the wrong one for anything else. It reaches only the two Cognito-backed credentials — an
  unknown `bbk_` key stays unknown, because Cognito vouches for no key of ours and there would be no
  email to hand back. Note it multiplies with `BB_AUTH_ALLOW_UNVERIFIED_SOCIAL`.
- **Static API keys (`bbk_` namespace) are self-contained grants tied to a user.** The raw key is
  never stored, and the `sha256(bearer)` lookup in `by_key_hash` **is** the verification. A key must
  have a non-denied owner, be unexpired, and be in its URL scope. Don't index by anything the client
  sends in the clear, and don't store the raw key. Mint with `bb-auth-adm key add` (`mint_api_key`),
  which prints the bearer on stdout **once, and only after the file carrying its hash is safely on
  disk** — the other order hands out a credential that authorizes nothing if the write then fails,
  and the raw key exists nowhere else to retry from. `key rotate` is the answer to a leak.
- **Access is enumerated, never assumed** — from *either* grant source. There is **no "unrestricted"
  scope**: an absent or empty `authorized_urls` grants *nothing* (`UrlScope::deny_all`), a URL with
  no site is not open, and blanket access is the explicit pattern `*://*/*`. A key with no
  `authorized_urls` inherits its user's. Because every credential is scoped,
  `BB_AUTH_ORIGINAL_URL_HEADER` is **mandatory** — a request without it is denied. See
  `UrlScope::allows`.
- **One matcher serves scheme, host and path** — and users, keys and sites. A non-final `*` cannot
  cross `/`, and `://` holds two of them — that single rule is what stops a wildcard leaking across
  component boundaries, so don't split `glob_match` into three matchers. It is a bottom-up DP, **not**
  recursive backtracking (which is exponential on many `*`); `glob_many_stars_terminates` pins that.
  A URL with `..` is rejected; patterns are validated and authority-lowercased once at load
  (`compile_pattern`).
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
  and the app is unreachable except through nginx. Emails must be printable ASCII: a CR/LF would
  be a response-splitting gadget, and `h()` panics on a non-ASCII value, so `respond_authorized`
  emits without a per-request check. `header_safe_email` is therefore enforced at the **two**
  points an email enters, which between them cover all three credentials — keep both:
  - `read_access`, at load, for roster emails (warn+skip like an empty email — dropping a user is
    fail-closed). The only guard on the API-key path, whose email never passes a token claim.
  - `validate_id_token`, for emails lifted out of a claim. A `public_auth` site emits identities
    that are in no table, so load time cannot see them; and since that is the only way an email
    reaches `make_session`, the cookie inherits the property through the HMAC.

  The `debug_assert!` in `respond_authorized` pins both halves — it catches a case-insensitive
  `by_email` lookup added later (which would break the "returns the key it matched" chain) *and* a
  fourth credential that skips `validate_id_token`. Applications must **not** decode the credential
  themselves — the cookie is not a JWT and a `bbk_` key has no token, and a valid id_token proves
  identity, never authorization. On a `public_auth` site the email may name someone in no table at
  all; enrolling them is the application's business.
- **The profile claims are decoration, and the encoder is what makes them safe.** A `204` may also
  carry OIDC claims from the token — `BB_AUTH_PROFILE_CLAIMS`, empty by default. They are **not**
  identities: they authorize nothing, no field of the access file mentions them, and
  `authorize_identity` keeps them out of `decide` — otherwise `bb-auth-adm can` would stop
  answering the gate's question. Being self-asserted (any Cognito user edits their own profile,
  `email_verified` or not), nothing downstream may key on them. Three rules to keep: values go out
  **percent-encoded** (`pct_encode`, RFC 3986) and that construction — printable ASCII for *any*
  input — is the whole safety argument, so a value needs no `header_safe_email` (which would reject
  the spaces and accents real names have) and must never be emitted raw; an absent claim **omits the
  header** rather than sending it empty, because nginx cannot tell those apart; and values are
  **never logged** — the line already has the email (claim *names* are config, and the startup
  banner may list them). Capture hygiene (`clean_claim`) is about quality and cookie size, not
  safety: a bad value costs that claim, never the login, which is why `Claims::extra` holds
  `serde_json::Value`s.
- **The set of claims is config; the header name is code.** An operator names a *claim*, never a
  header: `derive_profile_header` maps it (`given_name` → `X-Auth-Given-Name`,
  `custom:department` → `X-Auth-Custom-Department`), so the two can never disagree and no header
  name is typo-reachable. Since a claim name is restricted to `[A-Za-z0-9_:-]`, a derived header is
  always a valid token — that, not a check, is why `h()` cannot panic on it. Keep three things.
  `compile_profile_claims` is **fatal on every bad entry** (bad charset, empty part around a
  separator, a header collision with `IDENTITY_HEADER`/`LOGIN_URL_HEADER` or another entry) —
  a silently skipped claim is a header an application waits for forever; the same reflex as a
  fatal scope error. It must keep rejecting `RESERVED_CLAIMS` (`email`, `email_verified`,
  `token_use`, `identities`), because `Claims` takes those into typed fields and
  `#[serde(flatten)]` never sees a key a typed field took — configuring one would propagate
  nothing, forever. And emission is **config-authoritative** (`profile_headers`): a cookie
  outlives an edit to the list, so what it carries is filtered against the *live* config, never
  emitted because the credential happened to have it.
- **`/auth/session` is not a gate.** It mints a cookie for any valid id_token whose email is not
  `denied` and has somewhere to go (roster entry, or any `public_auth` site exists). The 403 there is
  a courtesy so an un-enrolled user hears it at the login page instead of bouncing off a 401 later —
  it must not tighten into an authorization check, and it must not try to guess the destination from
  `rd` (which is the post-login target, not the URL that triggered the login, and `safe_rd` may have
  already replaced it).
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
  `validate_id_token` / `unverified_social_ok`. It multiplies with `public_auth`: together they mean
  "any social account, unverified email, no enrolment".
- **There is no canonical service base URL.** One gate fronts several hosts and which one is in
  play is decided by the caller, so `/auth/session` learns it from `BB_AUTH_ORIGINAL_URL_HEADER`
  (`origin_of`) — nginx must set that header on the session location too, not just the auth-gate.
  `BB_AUTH_AUTHORIZED_HOSTS` (comma-separated host globs, required) is the *only* authority on
  redirect targets. Don't reintroduce a single base URL.
- **The gate never redirects a gated request; nginx does.** A `401` carries this area's login page
  in `LOGIN_URL_HEADER` (`X-Auth-Login-URL`) — the site's `login_url`, else `BB_AUTH_LOGIN_URL`
  (`login_url_for`) — and nginx lifts it with `auth_request_set` into a request variable, which is
  what stops a later `proxy_pass` clobbering `$upstream_http_*`. (`auth_request_set` does read a
  `401` subrequest's headers — verified against nginx 1.26.) nginx must route it through a `map`
  with the global URL as the default arm: an unset variable makes `return 302 $bb_login?rd=…` emit a
  *relative* `Location: ?rd=…`, i.e. a redirect loop back onto the gated path. This works because a
  `401` happens *on* a gated URL, so the site resolves. **A logout does not**: `/auth/logout` is inside no site's
  `urls`, so there is no per-site logout landing page and adding one would be a field the gate can
  never reach. The logout link supplies `?rd=` instead, through `safe_rd`; with no `rd` the browser
  goes to the login page, *not* to `safe_rd`'s caller-root default. Both the global and every site's
  `login_url` pass `compile_login_url` at load (printable ASCII, absolute https, no `@`, no `\`) —
  that is what makes emitting them into a header, a `Location:` and a page safe with no per-use
  check. It is deliberately **not** checked against `BB_AUTH_AUTHORIZED_HOSTS`: `read_access` reads
  no env, which is what lets `--check-users` run with no config, and moving the check to startup
  would turn a typo into a boot loop that `--check-users` never saw.
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
- **Target layout is a tree**: `/opt/bb-auth/{bin/bb-auth, bin/bb-auth-adm, etc/bb-auth.env,
  var/lib/users.json}`, unit at `/etc/systemd/system/bb-auth.service`. The service writes nothing,
  so the whole prefix is `ReadOnlyPaths` and no `StateDirectory` is needed despite the `var/lib`
  name — `bb-auth-adm` writes that file from *outside* the unit's namespace, as root, and the
  hardening does not apply to it. It runs hardened and non-privileged on loopback behind a
  TLS-terminating reverse proxy, speaks plain HTTP, and holds no Cognito secret.
- **The live `users.json` is the copy that is current** — it is edited on the host (`sudo
  bb-auth-adm …; systemctl reload bb-auth`) and a repo copy drifts from it within a week. So
  `deploy.sh` preserves it unless one is explicitly staged, and `deploy.ps1 -UsersFile` **replaces**
  it wholesale: never stage a stale file. `bb-auth-adm` is installed to the host precisely so the
  edit can happen where the current file is. It is optional in the deploy (installed if staged), and
  must stay that way: the gate never calls it, and an older `dist/` must still deploy.
- `scripts/deploy.sh` is the on-host installer (root, idempotent, self-verifying). It is
  **lockout-safe by construction**: it generates the HMAC key once and preserves it forever, and
  preserves the live `users.json` unless a new one is explicitly staged. **The env file is
  operator-owned** — installed once, then never edited. So the deploy *validates* config rather
  than fixing it: a missing required var, or a `BB_AUTH_USERS_FILE` that doesn't point at the file
  this deploy installs, aborts **before** the restart. Both matter — a fatal startup under
  `Restart=on-failure` is a boot loop, and a mismatched path means `--check-users` vouched for a
  file nothing loads. A redeploy must never log anyone out *by accident* — that is what preserving
  the HMAC key buys, and it stays non-negotiable; the one sanctioned exception is a deliberate
  cookie-format bump, which does log everyone out and belongs in the release's upgrade note. A
  rejected users file must never reach a restart.
