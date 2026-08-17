# AGENTS.md

How to work in this repository: what it is, what to run, and the conventions to write in.
It is tool-agnostic on purpose, so any coding agent can start here.

**The invariants are not in this file.** What must never break, why, and the symbol that
pins each rule live in [CLAUDE.md](CLAUDE.md). Read them before changing behaviour: this is
an authentication gate, and most of its rules exist because breaking one locks somebody out
or lets somebody in.

## What this is

bb-auth is a single-binary **auth gate**: it accepts an AWS Cognito `id_token` that a
browser-side login page already obtained, validates it (RS256 via JWKS), and issues an
HMAC-signed session cookie that nginx enforces on every request via `auth_request`. It also
accepts per-request bearer credentials — a Cognito `id_token` or a static `bbk_` API key.

The access list is a JSON **access file** (`BB_AUTH_ACCESS_FILE`, default
`access.json`, and it says *access* rather than *users* because the roster is one section of
four, the smallest of them), and it is **application-centric**: an `applications` entry owns a
literal URL area and a list of named **scopes**; a scope owns URL patterns, one access
policy (`anonymous`, `authenticated`, `restricted`) and an `excluded` list that keeps named
people out of it ahead of that policy; a user is a **uuid** plus the emails
that resolve to it plus its API keys, and carries no URL at all. A grant is written once,
on the side of the place. It is service-agnostic — one binary fronts any web service, wired
per-deployment through `BB_AUTH_*` env vars **and a settings file** (`settings.json` beside
the access file): the six settings that must change without a restart live there, because a
process cannot re-read its own environment.

One crate, four targets, and the split is load-bearing:

- **[src/lib.rs](src/lib.rs)** (`bb_auth_core`): **the files the programs share**. The
  access file above all: its schema, its parser, the URL matcher, the two-level resolution
  (`Access::resolve`), the grant model (`decide` / `decide_api_key`), and how one is *edited
  and written* (`open_access_file`, `AccessWrite`, the document mutations). And
  **the settings file** beside it (`SettingsFile`, `compile_settings`, `SettingsWrite`, plus
  `compile_profile_claims` / `compile_identity_attrs`, which are here because all three
  programs validate them). Everything more than one program must agree on, byte for
  byte.
- **[src/bin/bb-auth.rs](src/bin/bb-auth.rs)** — **the gate**, and everything the access file has no
  opinion about: HTTP, the session cookie, id_token validation, the nginx contract. Still
  **one file**, still read top to bottom.
- **[src/bin/bb-auth-adm.rs](src/bin/bb-auth-adm.rs)** — the access-file admin CLI: CRUD over
  `applications` / `scopes` / `user_groups` / `denied` / `users` / `api_keys`, key minting,
  and `can EMAIL URL` (would this credential get in?). It links the library, none of the gate.
- **[src/bin/bb-auth-web.rs](src/bin/bb-auth-web.rs)** — the access-file admin GUI
  (server-rendered, `maud`): the same CRUD as the CLI, made **only** through the library's
  editing core, plus a **Settings** tab over the settings file. Five tabs, and none of them
  is `denied` or `user_groups`: those two are **sections of the users
  page**, groups above the roster, because a group only means anything in terms of the roster
  and both are about people. Settings is last because it is the only tab that is not about
  the access file at all. Every unordered list carries a filter and a pager, both living
  entirely in the query string (`Listing`, `list_controls`) since a page here must work with
  scripting off; each list namespaces its two parameters (`uq`/`up`, `gq`/`gp`, …) so several
  on one page do not steal each other's state. **Scopes are deliberately excluded from that**:
  their order is their meaning and the ↑/↓ buttons move them within the *file*, so a filtered
  view would show positions that are not the file's and a move that appears to do nothing.
  **No page may need JavaScript**, and the *only* thing standing on the far side of that
  rule is `SETTINGS_ONCHANGE`, one
  inline handler that applies a Settings list box the moment it is picked, with a
  `<noscript>` submit button behind it doing the same job one click later. There is no
  `<script>` tag anywhere and nothing else carries a handler of any kind; a page that stops
  working with scripting off is the thing that must never ship
  (`the_page_carries_one_handler_and_no_script`, and `nojs.js` runs the whole GUI with
  scripting disabled). A `GET` never mutates;
  every mutation is a `POST` guarded by a strict same-origin check (`Sec-Fetch-Site`, else
  `Origin`'s host vs `Host`'s — never the scheme, it speaks plain HTTP behind nginx) and by a
  hidden `rev` = sha256 of the file's exact bytes as the form was rendered, so a lost update
  against a `bb-auth-adm` over SSH is a 409 instead of a silent clobber. It links the library,
  none of the gate, and is **just another app bb-auth fronts**: loopback only, gated by nginx
  `auth_request`, identity read from the `X-Auth-Email` nginx injects and from nowhere else —
  a missing header is a 401, not an anonymous visitor. `web.admins` is its own
  allowlist on top of that, required and never empty, because an `authenticated` scope covering
  its URL would otherwise open the admin surface to any Cognito account.

The defining constraint vs. authorization-code OIDC proxies (oauth2-proxy): those drive the
login themselves and *cannot* accept a token the browser already holds. bb-auth is built for
the opposite — a login page runs Cognito `USER_AUTH` in the browser (enabling sign-up +
auto-login with no second OTP) and POSTs the resulting `id_token` to `/auth/session`.

## Where documentation lives

[CLAUDE.md](CLAUDE.md) holds the **rules**: what must not break, why, and the symbol that
pins each one.
The **mechanism** lives in rustdoc next to the code (`cargo doc --no-deps --open`) — the
endpoint table and credential order on `bb-auth`'s crate root, the cookie wire format on
`COOKIE_VERSION`, the access-file schema on `AccessFile`, the two-level resolution rule on
`Access::resolve` and `AppRecord`, the area-boundary rule on `base_covers`, the wildcard
grammar on `glob_match`, the `@name` group grammar on `AccessFile::user_groups`, the grant
model on `Decision` and `Subject`, the reason for the library split on `bb_auth_core`'s
crate root, the claim→header derivation on `ProfileClaim` and the attribute→header one on
`IdentityAttr`, the nginx snippets on `Config::original_url_header` and `IDENTITY_ATTRS`.
Don't copy one into the other; when they disagree, the code wins. Rustdoc must stay
warning-free — a broken intra-doc link is the cheapest rot detector this repo has, and it
now spans two crates (a gate doc pointing at a moved type must be re-pointed, not
de-linked).

Deep docs: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (service internals) and
[docs/AUTHENTICATION_FLOW.md](docs/AUTHENTICATION_FLOW.md) (the end-to-end
browser↔Cognito↔nginx sequence). Read those before changing the request flow or cookie format.
[scripts/README.md](scripts/README.md) maps the five build/deploy scripts: which machine each
one runs on, who calls whom, and which invariant each one is there to hold.

## Commands

This repo is developed on Windows but the artifact is a Linux/aarch64 binary.

```powershell
# Tests — pure unit tests in src/lib.rs (the access file) and src/bin/bb-auth.rs (the gate),
# run on the host, no network needed
cargo test
cargo test session_roundtrip          # a single test by name

# Validate an access file with the real parser (no env, no network). Same check the
# deploy runs before it restarts the service. Prints each application's area, and the
# scopes that grant without listing anybody (anonymous, authenticated).
cargo run --bin bb-auth -- --check-access .\deploy\access.example.json

# Validate a SETTINGS file with the parser all three programs use. Prints the derived
# header for every claim and attribute, and names the GUI's administrators.
cargo run --bin bb-auth -- --check-settings .\deploy\settings.example.json

# Administer an access file (CRUD; every write is validated with the gate's own parser).
# `can` answers with the gate's own decision function — exit 0 = the request would pass.
cargo run --bin bb-auth-adm -- --help
cargo run --bin bb-auth-adm -- -f .\deploy\access.json show
cargo run --bin bb-auth-adm -- -f .\deploy\access.json app add mpa --base 'https://app.x.com/mpa'
cargo run --bin bb-auth-adm -- -f .\deploy\access.json scope add mpa admin --url 'https://app.x.com/mpa/admin/*' --access restricted --user bob@x.com
cargo run --bin bb-auth-adm -- -f .\deploy\access.json user add bob@x.com
cargo run --bin bb-auth-adm -- -f .\deploy\access.json key add bob@x.com --id laptop --duration 365d
cargo run --bin bb-auth-adm -- -f .\deploy\access.json can bob@x.com https://app.x.com/mpa/admin/panel

# The settings file: the six values that take effect with no restart at all. `-s` names it;
# with no `-s` it is settings.json beside the access file, which is what the packages create.
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings show
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings set --claims given_name,family_name
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings admin add bob@x.com

# Browser E2E suite for bb-auth-web (Node + system Edge/Chrome; self-contained — builds,
# starts and kills its own server on a temp copy of the fixture; see e2e/README.md)
node e2e/run.js

# Host build / typecheck (SIGHUP reload is cfg(unix), compiled out on Windows)
cargo check
cargo clippy --all-targets
cargo fmt
cargo doc --no-deps                   # must emit zero warnings, across all four targets

# Release cross-compile for the target. It does NOT hand itself to WSL, so run it from a
# Linux/WSL shell: from Git Bash it stays on Windows and fails for want of a cross gcc.
# Produces dist/{bb-auth,bb-auth-adm,bb-auth-web} (aarch64) and the max GLIBC symbol.
bash scripts/build.sh                 # target overridable via BB_AUTH_TARGET

# .deb packages for the target: three of them, one per binary (cargo-deb; the metadata
# is [package.metadata.deb] in Cargo.toml). Builds through build.sh, so dist/ stays
# current for deploy.ps1 too. THIS one re-execs itself inside WSL when started from a
# Windows shell, which makes it the supported entry point for a release build.
# Output: dist/{bb-auth,bb-auth-adm,bb-auth-web}_<ver>-<rev>_<arch>.deb
bash scripts/package.sh               # arm64; --arch amd64, --no-build, --only, --revision

# Deploy from Windows over SSH: package in WSL, ship the .deb, dpkg -i, remote verify.
# It always builds; -NoBuild repackages the current dist/ instead.
./scripts/deploy.ps1 user@host
./scripts/deploy.ps1 user@host -Packages bb-auth                # gate only, no admin tools
./scripts/deploy.ps1 user@host -AccessFile .\deploy\access.json   # also replace the access file

# Health-check a host without deploying to it (also run at the end of every deploy)
ssh user@host 'sudo bash -s' < ./scripts/verify.sh
```

**Match the check to the change.** Every suite here is cheap to start and slow to finish, so
run what the edit can actually break, not the whole board. Re-running a check that already
passed, on code untouched since it passed, tells you nothing you did not already know.

| What changed | What to run |
| --- | --- |
| Only the `CSS` constant in `bb-auth-web.rs` | `cargo build --bin bb-auth-web` (it is a Rust string: it still has to compile) and `node e2e/shots.js <scene>` |
| `maud` markup, or a `K` translation key | the above, plus `cargo test` (several tests assert on rendered HTML) and `node e2e/run.js` |
| A signature, a handler, the gate, or the library | all of it, plus `cargo clippy --all-targets` |
| A dependency version | all of it, plus the cross-compile and the dependency check below |

`cargo doc --no-deps` earns its place when an intra-doc link could have moved, which is a
real risk when a type or a function is renamed and no risk at all when a border-radius
changes. `node e2e/shots.js` takes a scene-name filter for the same reason: the full walk is
124 screenshots across seven views, and a change to one page needs one of them.

Markdown is linted with markdownlint (`.markdownlint.jsonc`, which documents its own
invocation): `npx markdownlint-cli2 "**/*.md" "#target" "#dist"`.

## After a dependency change

The dependency rule (see CLAUDE.md) is about what the tree must *not* contain, so a bump is
only done when it has been checked rather than assumed:

```powershell
cargo tree | Select-String -Pattern "openssl|native-tls|aws-lc|schannel|security-framework"
cargo tree | Select-String -Pattern "webpki-roots"
```

The first must find nothing and the second must still find the roots: together they are what
says the aarch64 cross-compile still needs no system TLS library and no system cert store.
Then run `bash scripts/package.sh`, which is the only check that compiles for the real
target. Two things it prints are worth reading: the **max GLIBC symbol** (it must stay at or
below the `libc6 (>= …)` floor the packages declare in `Cargo.toml`) and the binary sizes,
because `[profile.release]` is size-optimised on purpose.

One gap to close by hand: **no unit test covers RS256 verification or the JWKS parse**, so a
change under `jsonwebtoken` or `ureq` can pass the whole suite and still break every login.
Start the gate against the real issuer instead: the initial JWKS fetch is fatal on failure,
so reaching the `listening on …` line proves the fetch, the parse and every
`DecodingKey::from_jwk`.

## Conventions

- **Write durable artifacts in English**: this file, `CLAUDE.md`, rustdoc, code comments,
  commit messages, `docs/*.md`. Conversation may be in another language; the repo is not.
- **Comments and docs explain *why*, not *what***, in full sentences. A comment that restates
  the line below it is noise; a comment that records the reason a rule exists is why this
  codebase can be changed safely a year later.
- **Do not introduce new em-dashes.** Existing prose uses them freely and is left alone, but
  anything written from now on uses `:` for an apposition, `;` between two independent
  clauses, `,` for an aside, or parentheses. The sanctioned exception is a `—` that is *data*
  rather than prose, such as a table cell meaning "not applicable".
- **A rule lives in exactly one place.** The invariants are in `CLAUDE.md`, the mechanism is
  in rustdoc, the operating manual is here. When two disagree, the code wins, and the loser
  gets fixed rather than both getting edited.
- **Commit messages are a sentence, not a label**: what changed and, above all, why, in the
  same register as the code comments. Work happens on `main`.
