# AGENTS.md

Everything that governs work in this repository: what it is, what to run, the conventions to
write in, and the rules that must not break. It is tool-agnostic on purpose, so any coding
agent can start here; `CLAUDE.md` is a one-line import of this file and holds nothing of its
own.

**Read [the invariants](#invariants--do-not-break-these) before changing behaviour.** This is
an authentication gate, and almost every rule in it exists because breaking that rule locks
somebody out or lets somebody in.

## What this is

bb-auth is a single-binary **auth gate**: it accepts an AWS Cognito `id_token` that a
browser-side login page already obtained, validates it (RS256 via JWKS), and issues an
HMAC-signed session cookie that nginx enforces on every request via `auth_request`. It also
accepts per-request bearer credentials — a Cognito `id_token` or a static `bbk_` API key.
**It serves that login page itself**, at `/auth/login` (and `/auth/callback` for a social
sign-in), which is not a widening of the job but a removal of three duplicated values: the
page needs the app-client id, the issuer's endpoint and the hosts a post-login `rd` may land
on, and the gate already holds all three as the values it validates against.

The access list is a JSON **access file** (`BB_AUTH_ACCESS_FILE`, default
`access.json`, and it says *access* rather than *users* because the roster is one section of
four, the smallest of them), and it is **application-centric**: an `applications` entry owns a
literal URL area and a list of named **scopes**; a scope owns URL patterns, one access
policy (`anonymous`, `authenticated`, `restricted`) and an `excluded` list that keeps named
people out of it ahead of that policy; a user is a **uuid** plus the emails
that resolve to it plus its API keys, and carries no URL at all. A grant is written once,
on the side of the place. It is service-agnostic — one binary fronts any web service, wired
per-deployment through `BB_AUTH_*` env vars **and a settings file** (`settings.json` beside
the access file): the settings that must change without a restart live there, because a
process cannot re-read its own environment.

One crate, four targets, and the split is load-bearing:

- **[src/lib.rs](src/lib.rs)** (`bb_auth_core`): **the files the programs share**. The
  access file above all: its schema, its parser, the URL matcher, the two-level resolution
  (`Access::resolve`), the grant model (`decide` / `decide_api_key`), and how one is *edited
  and written* (`open_access_file`, `AccessWrite`, the document mutations). And
  **the settings file** beside it (`SettingsFile`, `compile_settings`, `SettingsWrite`, plus
  `compile_profile_claims` / `compile_identity_attrs`, which are here because all three
  programs validate them). And **the presentation contract**: the palette
  (`THEME_CSS`, [src/assets/theme.css](src/assets/theme.css)), the components built out of it
  (`BASE_CSS`, [src/assets/base.css](src/assets/base.css)), and `UiTheme` / `stylesheet_link`
  / `html_escape` / `compile_asset_url` beside them. Same membership rule: two programs emit
  HTML, and they must agree byte for byte on what `--accent` names, on what a button and a
  field are made of, and on where an operator's stylesheet lands in the cascade, or the two
  surfaces drift apart one edit at a time and nobody working inside either file can see it.
  What is *not* there is either program's **arrangement** of those components. Everything
  more than one program must agree on, byte for byte.
- **[src/bin/bb-auth.rs](src/bin/bb-auth.rs)** — **the gate**, and everything the access file has no
  opinion about: HTTP, the session cookie, id_token validation, the nginx contract, and the
  three pages it serves ([src/assets/](src/assets/): the sign-in page, the social callback and
  the error page, each a template whose `__BB_*__` placeholders `render_page` fills). Still
  **one file**, still read top to bottom.
- **[src/bin/bb-auth-adm.rs](src/bin/bb-auth-adm.rs)** — the access-file admin CLI: CRUD over
  `applications` / `scopes` / `user_groups` / `denied` / `users` / `api_keys`, key minting,
  and `can EMAIL URL` (would this credential get in?). It links the library, none of the gate.
- **[src/bin/bb-auth-web.rs](src/bin/bb-auth-web.rs)** — the access-file admin GUI
  (server-rendered, `maud`): the same CRUD as the CLI, made **only** through the library's
  editing core, plus a **Settings** tab over the settings file, in that file's own three
  sections: what the gate answers with, who administers this, and how the pages look (the
  last one being the gate's pages too, which is why one save restyles both programs). Five
  tabs, and none of them
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
auto-login with no second OTP) and POSTs the resulting `id_token` to `/auth/session`. The gate
now ships that page, but the constraint is unchanged and so is the shape: the page is still a
browser-side client of Cognito that hands the gate a token it did not obtain, and pointing
`BB_AUTH_LOGIN_URL` at a page of your own instead still works.

## Where documentation lives

This file holds the **rules**: what must not break, why, and the symbol that pins each one.
The **mechanism** lives in rustdoc next to the code (`cargo doc --no-deps --open`) — the
endpoint table and credential order on `bb-auth`'s crate root, the cookie wire format on
`COOKIE_VERSION`, the access-file schema on `AccessFile`, the two-level resolution rule on
`Access::resolve` and `AppRecord`, the area-boundary rule on `base_covers`, the wildcard
grammar on `glob_match`, the `@name` group grammar on `AccessFile::user_groups`, the grant
model on `Decision` and `Subject`, the reason for the library split on `bb_auth_core`'s
crate root, the claim→header derivation on `ProfileClaim` and the attribute→header one on
`IdentityAttr`, the nginx snippets on `Config::original_url_header` and `IDENTITY_ATTRS`, the
Cognito flow the sign-in page runs on `LOGIN_HTML` and the OAuth leg on `CALLBACK_HTML`, and
the palette's four arms and what an override may redefine on `THEME_CSS` (the file itself,
[src/assets/theme.css](src/assets/theme.css)).
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
# header for every claim and attribute, names the GUI's administrators, and says how the
# pages will look (the stylesheet by name: whether it loads is the browser's business).
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

# The settings file: the values that take effect with no restart at all. `-s` names it;
# with no `-s` it is settings.json beside the access file, which is what the packages create.
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings show
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings set --claims given_name,family_name
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings admin add bob@x.com
# The `ui` four: the look of every page BOTH programs serve, so one stylesheet restyles the
# sign-in page and the admin GUI together. Pass an empty value to unset any of them.
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings set --brand 'BadBat75' --theme dark
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings set --stylesheet 'https://assets.x.com/css/theme.css'

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
| `src/assets/admin.css` alone | `cargo test --bin bb-auth-web` and `node e2e/shots.js <scene>` |
| `src/assets/theme.css` or `src/assets/base.css` | `cargo test` (the palette's four arms are pinned by `the_theme_defines_every_token_in_all_four_arms`, the sharing by `only_the_palette_names_a_colour` and `the_components_are_shared_and_the_layouts_only_arrange_them`) and `node e2e/shots.js config` **and a look at `/auth/login`**: both files are emitted by both programs, so a change to either repaints the admin interface and the sign-in page together, and half of that is invisible to the admin's own suite |
| `src/assets/auth.css` alone | `cargo test --bin bb-auth` and a look at the page in a browser |
| `src/assets/*.html` | `cargo test --bin bb-auth` (the page tests read the rendered document) and a look at the page in a browser: no test can tell you a login form is unusable |
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

The dependency invariant below is about what the tree must *not* contain, so a bump is only
done when it has been checked rather than assumed:

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

The gap that used to sit here is now half closed, and the half that remains is worth naming.
`rsa_signature_verification_works` covers the JWKS parse and a real RS256 verification against
a fixed offline key, both ways (a good signature must verify, a forged one must not), which is
what catches a `jsonwebtoken` change that breaks every login while the rest of the suite stays
green. It exists because that is not hypothetical: see the crypto-provider half of the
dependency invariant. What a unit test cannot cover is the **fetch** (`ureq`, rustls, and the
real issuer's document), so start the gate against that issuer as well: the initial JWKS fetch
is fatal on failure, so reaching the `listening on …` line proves the fetch, the parse and every
`DecodingKey::from_jwk`.

## Conventions

- **Write durable artifacts in English**: this file, rustdoc, code comments, commit messages,
  `docs/*.md`. Conversation may be in another language; the repo is not.
- **Comments and docs explain *why*, not *what***, in full sentences. A comment that restates
  the line below it is noise; a comment that records the reason a rule exists is why this
  codebase can be changed safely a year later.
- **Do not introduce new em-dashes.** Existing prose uses them freely and is left alone, but
  anything written from now on uses `:` for an apposition, `;` between two independent
  clauses, `,` for an aside, or parentheses. The sanctioned exception is a `—` that is *data*
  rather than prose, such as a table cell meaning "not applicable".
- **A rule lives in exactly one place.** The rules and the operating manual are in this file,
  the mechanism is in rustdoc beside the code. When two disagree, the code wins, and the
  loser gets fixed rather than both getting edited into agreement.
- **Commit messages are a sentence, not a label**: what changed and, above all, why, in the
  same register as the code comments. Work happens on `main`.

## Invariants — do not break these

- **The library is the shared files, and nothing else.** `bb_auth_core` exists because more
  than one program must agree, byte for byte, on what a shared file *means*, so there is
  exactly one parser (`compile_access`), one matcher (`glob_match`), one grant model
  (`decide`, `decide_api_key`), and all three link it. That is the whole membership rule: a
  thing belongs in the library iff a file more than one program reads has an opinion about
  it. The rule reaches **how a file
  is edited and written**, too — validate-before-write on the exact bytes, atomic replace,
  mode and owner preserved (`open_access_file`, `AccessWrite`, and the document mutations
  beside them), because `bb-auth-adm` and the web admin must agree on that byte
  for byte: the same argument that created the library. It is also what admits the
  **settings file** (`compile_settings`, `SettingsWrite`), and with it
  `compile_profile_claims` / `compile_identity_attrs`: the moment an editor must refuse to
  *write* a bad claim list, the rule that decides one is shared, however much it may look
  like the gate's business. `write_atomically` stays private and
  serves both writers. The same rule, one step further out, is what admits the
  **presentation contract** (`THEME_CSS`, `BASE_CSS`, `UiTheme`, `stylesheet_link`,
  `html_escape`, `compile_asset_url`): two programs emit HTML now, and a second answer to
  "what does `--accent` name" or "where does the operator's stylesheet land in the cascade"
  would mean `ui.stylesheet_url` restyles one surface and leaves the other standing in another
  palette. A stylesheet in a library needs that argument made out loud, and the argument is
  the library's own. **It reaches the components too**, and that half was learned by looking
  at the two surfaces side by side: a shared vocabulary of colours does not stop a button from
  being a rounded rectangle on one page and a lozenge on the other, or a field from being 12px
  tall here and 7px there. Each of those is somebody editing the file in front of them, which
  is drift invisible from inside either file, so a THING (a button, a field, a card, a tag, a
  message) is defined once in `BASE_CSS` and both programs emit it. Its limit is where a thing
  stops and an ARRANGEMENT of things starts: the admin's header, tables and phone stacking are
  the GUI's, the centred card and its steps are the gate's, and nothing requires those two to
  agree. What stays in a tool is what has an
  operator: flags, warnings, and the wording of a verdict. HTTP, the cookie, the JWT,
  the env, the nginx contract and the pages themselves are the **gate's**, and stay in
  `src/bin/bb-auth.rs` and `src/assets/` — which is still one file, read top to bottom, plus
  three templates it fills. Do not move gate code into the library to "share" it
  with the CLI; the CLI has no business with any of it. The two authorization functions in
  `bb-auth.rs` (`authorize`, `bearer_apikey_email`) are thin wrappers that add the log line
  and the wall clock to the library's decision — keep them thin, and keep the rule in the
  library, or `bb-auth-adm can` starts answering a different question from the gate.
- **No editor may write a file the gate would reject.** Every mutation is
  serialized, re-parsed, and run through `compile_access` — the gate's own parser, on the
  exact bytes about to land on disk — before the write. `AccessWrite` is that order made
  unskippable and is the only door: `prepare` compiles, `commit` writes what it compiled,
  and `write_atomically` is private to the library. `SettingsWrite` is the same type for the
  settings file, with the same three parts and the same single door. A rejected access file is a fatal
  startup, and under `Restart=on-failure` that is a boot loop; this tool and
  `--check-access` are the two places that can catch it in time. The write is atomic
  (temp + rename) and **preserves mode and owner**: the live file is `root:bb-auth 0640`
  — `bb-auth-web:bb-auth 0640` once the GUI is installed — and a rewrite that left it
  `root:root` would lock the service out of its own access list. The chown failing is
  therefore a hard abort, not a warning; it is also what makes the *unprivileged* writer
  work at all, so its owner and group are a deploy-time contract, not cosmetics.
- **The cookie is a versioned wire format, and exactly one version is accepted.** `bb1` is it,
  and there is deliberately no verify-only arm for any other tag. So changing the
  serialization or the signed-message bytes logs out **every** existing user: that is the
  accepted price, because a re-auth is one trip through the login page against a Cognito session
  the browser still holds, and carrying an arm per format is not worth it. Bump the tag
  when the bytes change (never reuse one), say so in the release notes, and don't ship it
  mid-something. What must *never* log anyone out is HMAC **key rotation**, which is a separate
  axis: the keyid in the cookie is what makes it zero-downtime (README "Key rotation").
  `make_session` / `verify_session` and their tests pin the format, and
  `foreign_cookie_versions_are_rejected` pins that a tag this binary did not write gets no arm at
  all. The claims segment is a
  **self-describing JSON object**, and that is what keeps `profile_claims` off this
  axis: positional segments would let a config edit reinterpret a live cookie's values under
  another claim's name, so editing the list must stay a no-logout change. Verify checks the
  signature over the segment **as received** and only then parses it — never parse and
  re-serialize to compare.
- **The access file is the real access gate**, re-checked on *every* `/auth/validate` (not just at
  login). Parsed into `RwLock<Access>` — the applications, `denied` in its two halves, and the
  roster indices — hot-reloaded on SIGHUP (`systemctl reload bb-auth`); a reload failure keeps the
  old table (never nuke the live one). See `read_access`; keep it the access gate and keep the
  reload fail-soft. Its four sections answer four questions: `applications` describe places and who
  reaches them, `user_groups` names a reusable set of people, `denied` vetoes people, `users` is the
  roster of identities. The file declares `"version": 1`, and a file that declares anything else,
  or nothing at all, is a **fatal, explanatory** load error rather than a type mismatch three
  levels down: a file written for another format could otherwise compile to an access table that
  grants differently, which is a lockout, or worse, reported as a successful load.
- **The settings file is what must change without a restart, and the rule for what goes in it
  is three-part.** A setting belongs there iff it is (1) read **per request**, (2) unable to
  lock the operator out when it is wrong, and (3) not a secret. Ten pass, in three sections:
  `gate.profile_claims`, `gate.identity_attrs`, `gate.allow_unverified_social`,
  `gate.social_providers`, `gate.session_ttl_secs`; `web.admins`; and the whole `ui` section
  (`stylesheet_url`, `logo_url`, `brand_name`, `theme`), which is the **look of every page
  either program serves** and the one section both of them read. The `ui` four pass the middle
  part precisely because the built-in stylesheet is complete: the worst a wrong value there
  achieves is an unstyled page, never a closed door. Everything else stays in
  `bb-auth.env`: the listener and the worker count (a rebind), the HMAC key (the secret), the
  Cognito trust roots and the cookie's name and domain (a change lets nobody in or logs
  everybody out), the `BB_AUTH_SOCIAL_*` group (a wrong client id or callback URL is a
  sign-in that cannot complete, which is the lockout wearing a GUI field's clothes), and
  `BB_AUTH_LOGIN_URL` / `BB_AUTH_AUTHORIZED_HOSTS` /
  `BB_AUTH_ORIGINAL_URL_HEADER`, which **are** the lockout. The `ui` section and the
  `BB_AUTH_SOCIAL_*` group sitting on opposite sides of that line, both of them about the same
  sign-in page, is the rule working rather than an inconsistency. It is a *file* for one
  mechanical reason, and not for tidiness: **a process cannot re-read its own environment**
  (systemd loads `EnvironmentFile=` once, at `ExecStart`), so an env var can never be hot. Do
  not add an eleventh setting because it would be convenient there; check it against the three
  parts first. It is held in `RwLock<Settings>`, reloaded by the same SIGHUP as the access file and
  **fail-soft in the same way** (a broken file keeps the live values), which is what makes it
  safe to hand to a GUI: the worst a bad save can do is leave the previous values in force.
  `bb-auth-web` reads it fresh per request instead, because it is the one service that edits
  its own half of it.
- **What changes who reaches what is fatal; what drops one credential is skipped.** Fatal
  (`read_access` returns `Err`: fatal at startup, old table retained on SIGHUP): a malformed URL
  pattern, an `access` that is absent or misspelled, `users`/`groups`/`credentials` on a scope that
  is not `restricted`, an unknown field anywhere in the application/scope tree, a base that is not
  literal or that overlaps another application's, a scope pattern outside its own application's
  base, a malformed uuid, two rows claiming one uuid or one identifier, a key restriction naming a
  scope that does not exist, and anything wrong about a
  **`@group` reference** (an unknown one, with the message naming the referrer; a bad group name; a
  group that references another group, since groups are flat and there is no cycle to detect; a
  malformed member in a group **nothing references**, because a group that only breaks when someone
  first uses it is a trap `--check-access` never saw). Warn and skip: a bad `key_hash`/`duration`, an
  identifier that is not `header_safe_email`, and a **dangling** reference (a well-formed uuid that
  matches no roster row), which fails closed and which both editors lint: making it fatal would mean
  removing a user could brick the gate on its next reload. Groups are pure abbreviation and expand
  **once, in `compile_access`**, so `Access`, `decide` and every consumer know nothing about them:
  keep the expansion there. `deny_unknown_fields` on `AppSpec` and `ScopeSpec` is the same reflex
  aimed forward: the day `access` grows a companion restriction, a typo in it must not be silently
  dropped and leave the field it was meant to narrow standing alone, which fails *open*.
  `bb-auth --check-access <file>` runs this same parser and exits 0/1, and `scripts/deploy.sh` calls
  it on the file about to go live and aborts before restarting, so a rejected file can never become
  a `Restart=on-failure` boot loop.
- **Two levels of resolution, and they answer differently on purpose.** Applications **partition**
  the URL space: every `base` is a literal prefix, no two overlap, and every scope pattern lies
  inside its own application's base, so at most one application can answer for a URL and their file
  order carries no meaning. Scopes inside one application are **first match wins, in file order**
  (`Access::resolve`). That asymmetry is the design: first-match is what makes a **carve-out**
  expressible (a narrower, stricter scope listed before a broad one), which a union of grants cannot
  express at all, and its dangerous half (a broad entry shadowing a narrow one) can only bite
  between scopes an operator sees together, on one screen, in one form. The literal base is what
  makes non-overlap a string comparison instead of a glob-intersection test, and `base_covers` is
  the one function both checks go through, so "does this application own that URL?" and "does this
  scope stay inside its own application?" can never drift apart. It compares at a **path boundary**,
  which is what stops the area `https://x.com/app` from swallowing `https://x.com/application`: the
  same trap as a `*` written with no `/` before it. An application on a wildcard host is therefore
  not expressible, and that is a deliberate cost.
- **A URL no application covers is reachable by nobody.** Since a user carries no URL of their
  own, this is the only fail-closed reading, and it is a posture worth saying out loud: a gated
  location outside every application is a `401` for everyone, including the person who wrote the
  file. `--check-access` prints each application's area so it can be compared with what nginx
  actually gates.
- **One veto, ahead of every grant, on every credential.** `denied` outranks everything
  (`decide`, `decide_api_key`, and the gate's `/auth/session`), and it holds two kinds of entry: a
  **uuid**, which vetoes the user and every identifier they have, and a bare **email**, which vetoes
  an identity the file has never heard of. The second is not decoration: an `authenticated` scope
  admits identities that are in no table, so for them it is the only denial there is. An email that
  *does* resolve is folded onto its uuid at load (`compile_access`), so denying one address of a
  user cannot leave another standing. The one place the veto does **not** reach is an `anonymous`
  scope, which grants before it (`decide`): that scope grants with no credential at all, so a vetoed
  client would simply omit theirs. A veto bypassed by sending *less* is not a veto, and offering it
  would be worse than not offering it, because an operator would believe it.
- **A scope's `excluded` is the same veto, one level down, and it is checked before the
  scope's own grant.** `denied` shuts somebody out everywhere; this shuts them out of *here*,
  and the two exist for different jobs rather than as a convenience. It is what makes a
  carve-out expressible in the other direction: a member of a `@group` can be kept out of one
  scope without the group being unpicked, and an `authenticated` scope — which lists nobody,
  so there is nobody to remove — can finally keep one identity out. It takes the same three
  spellings the file-level veto does (a uuid, a bare email for a stranger, plus `@group`), and
  an email that resolves is folded onto its uuid at load, so excluding one address of a user
  cannot leave another standing (`compile_access`, `ScopeRecord::excludes_identifier`). Order
  matters and is pinned: `denied` is reported **ahead** of it (`Decision::Vetoed` before
  `Decision::Excluded`), because an operator reading a log must be told the identity is out
  everywhere rather than only here. It is **fatal on `anonymous`** for exactly the reason the
  file-level veto does not reach that kind either: the scope grants with no credential at all,
  so an excluded client would simply send none, and a field that reads like a defence while
  defending nothing is worse than no field. Both editors resolve people to uuids and keep an
  unknown email as itself (`to_exclusions`, `parse_exclusions`), and `remove_user` and
  `user_group_refs` count an exclusion as a reference like any other — marked `(excluded)`,
  because a sweep that reported the two alike would read as if the user had been let in there.
- **A scope names people, and that is the only place a grant is written.** The rule is against
  **duplication**: a user removed from the roster must not still walk in through a place. Since
  the grant is written on the side of the place and nowhere else, that takes two halves.
  `ScopeRecord::members` are **references to roster rows**, so a reference to a row that does
  not exist grants nothing; and `remove_user` sweeps every scope and group that named the row it
  removes. Without both, a deleted user who re-registers on Cognito would walk back in
  through a dangling reference.
- **`anonymous` and `authenticated` grant without listing anybody**, which makes them the two
  things an operator most often did not mean to leave open, and why `--check-access` and the startup
  banner print them by name. `anonymous` needs no credential at all and the `204` names nobody.
  `authenticated` takes any identity Cognito vouches for, enrolled or not; since self-signup is open
  that means anyone who can register, which is the right grant for an onboarding area and the wrong
  one for anything else. It reaches only the two Cognito-backed credentials: an unknown `bbk_` key
  stays unknown, because Cognito vouches for no key of ours and there would be no identity to hand
  back. Note it multiplies with `allow_unverified_social`.
- **Static API keys (`bbk_` namespace) act as their user, and may only narrow.** The raw key is
  never stored, and the `sha256(bearer)` lookup in `by_key_hash` **is** the verification. A key must
  have a non-denied owner and be unexpired (`decide_api_key`), and then the scope that answers
  decides, exactly as it does for a browser login (`Subject::Key`). A key's own `scopes` list is a
  **restriction, never a grant**: it can only subtract from what its owner already reaches, which is
  what lets a machine credential carry less authority than the human who owns it while grants stay
  written in exactly one place. Don't index by anything the client sends in the clear, and don't
  store the raw key. Mint with `bb-auth-adm key add` (`add_api_key` -> `mint_api_key`), which prints
  the bearer on stdout **once, and only after the file carrying its hash is safely on disk**: the
  other order hands out a credential that authorizes nothing if the write then fails, and the raw
  key exists nowhere else to retry from. That order is the API's, not the caller's: a mint returns a
  `SealedKey`, and `reveal` takes the `Written` receipt of a completed write, so a dry run has no
  bearer to leak. `key rotate` is the answer to a leak.
- **Access is enumerated, never assumed.** A URL no application covers is open to nobody; a
  `restricted` scope that lists nobody admits nobody; an empty `credentials` list is a fatal error
  rather than a scope reachable by everything. Blanket coverage is the explicit pattern `*://*/*`,
  which an operator has to mean in order to write. Because every scope is defined by URL patterns,
  `BB_AUTH_ORIGINAL_URL_HEADER` is **mandatory**: a request without it resolves to no application
  and is denied. See `UrlScope::allows` and `sane_url`.
- **One matcher serves scheme, host and path.** A non-final `*` cannot cross `/`, and `://` holds
  two of them: that single rule is what stops a wildcard leaking across component boundaries, so
  don't split `glob_match` into three matchers. It is a bottom-up DP, **not** recursive backtracking
  (which is exponential on many `*`); `glob_many_stars_terminates` pins that. A URL with `..` is
  rejected at both levels of resolution, from one helper (`sane_url`), and patterns are validated
  and authority-lowercased once at load (`compile_pattern`).
- **nginx builds `X-Original-URL`, and must not let `Host:` pick the scope.** Hardcode the host per
  server block (`$scheme://$host$uri` is only safe behind a `default_server` that rejects unknown
  Hosts), and use `$uri`, never `$request_uri` — the latter is undecoded and carries the query
  string, so `/app/%2e%2e/admin` would match an `/app/*` scope while nginx serves `/admin`. Inside an
  `auth_request` subrequest `$uri` is the *subrequest's* URI, so each gated **location** must
  `set $bb_url …$uri;` and the gate forwards `$bb_url`. The `set` must live in the location, not at
  `server` level: the subrequest re-runs the server rewrite phase and would clobber it. A gated
  location that forgets it sends no header and is denied — fail-closed, which is why this is
  survivable. nginx must also forward `Authorization`, and set the header on `/auth/session` too.
- **The gate names the identity; nginx is what makes that trustworthy.** A `204` carries the
  authorized identity in headers derived from `identity_attrs` (`IdentityAttr`), default
  `email` and therefore `X-Auth-Email`, which is what every application behind this gate already
  reads. It is only safe because nginx sets or clears those names on **every** gated location
  (`proxy_set_header` overrides just the names it lists) and the app is unreachable except through
  nginx. Two consequences that must not be lost:
  - **nginx must clear every *possible* identity header, not the configured ones.** The set of
    possible names is finite and code-defined (`IDENTITY_ATTRS`), precisely so that it *can* be
    cleared; an attribute that is off must still be cleared, or a client can send it, and turning it
    on later then needs no nginx change at all.
  - **Multiple values of one attribute are joined with a space**, which is unambiguous by
    construction rather than by convention: every identifier passed `header_safe_email`, which
    requires printable ASCII, and a space is not printable ASCII. A comma would not do, because
    `well_formed_email` allows one in a local part. An attribute with no value **omits its header**
    rather than sending it empty, because nginx cannot tell those apart.

  Identifiers must be printable ASCII: a CR/LF would be a response-splitting gadget, and `h()`
  panics on a non-ASCII value, so `respond_authorized` emits without a per-request check.
  `header_safe_email` is therefore enforced at the **two** points an identifier enters, which
  between them cover all three credentials — keep both:
  - `compile_access`, at load, for every roster identifier (warn+skip: dropping one is fail-closed).
    The only guard on the API-key path, whose identity never passes a token claim.
  - `validate_id_token`, for identifiers lifted out of a claim. An `authenticated` scope emits
    identities that are in no table, so load time cannot see them; and since that is the only way an
    identifier reaches `make_session`, the cookie inherits the property through the HMAC.

  The `debug_assert!` in `respond_authorized` pins the lot: it is what stands between a fourth
  credential that skips both routes and a panicking worker thread. Applications must **not** decode
  the credential themselves — the cookie is not a JWT and a `bbk_` key has no token, and a valid
  id_token proves identity, never authorization. On an `authenticated` scope the identity may be in
  no table at all, and it then has no `uuid` to send; enrolling them is the application's business.
- **The profile claims are decoration, and the encoder is what makes them safe.** A `204` may also
  carry OIDC claims from the token — `profile_claims`, empty by default. They are **not**
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
- **The set is config; the header name is code.** This holds twice over, for the same reason and
  through the same function. An operator names a *claim* (`profile_claims`) or an
  *attribute* (`identity_attrs`), never a header: `derive_profile_header` maps both
  (`given_name` -> `X-Auth-Given-Name`, `custom:department` -> `X-Auth-Custom-Department`, `email`
  -> `X-Auth-Email`, `uuid` -> `X-Auth-Uuid`), so the two can never disagree and no header name is
  typo-reachable. Since a claim name is restricted to `[A-Za-z0-9_:-]`, a derived header is always a
  valid token: that, not a check, is why `h()` cannot panic on it. Keep four things.
  `compile_profile_claims` is **fatal on every bad entry** (bad charset, empty part around a
  separator, a collision with `LOGIN_URL_HEADER` or another entry) — a silently skipped claim is a
  header an application waits for forever, the same reflex as a fatal scope error. It must reserve
  **every possible identity header**, not the enabled ones, or turning an attribute on tomorrow
  collides with a claim configured yesterday and the discovery happens at runtime, on a header an
  application already trusts. It must keep rejecting `RESERVED_CLAIMS` (`email`, `email_verified`,
  `token_use`, `identities`), because `Claims` takes those into typed fields and
  `#[serde(flatten)]` never sees a key a typed field took, so configuring one would propagate
  nothing, forever. And `compile_identity_attrs` is **fatal on an empty list**: an authorized `204`
  that names nobody breaks every application behind the gate, in silence. Emission stays
  **config-authoritative** (`profile_headers`): a cookie outlives an edit to the list, so what it
  carries is filtered against the *live* config, never emitted because the credential happened to
  have it.
- **`/auth/session` is not a gate.** It mints a cookie for any valid id_token whose identifier is
  not `denied` and has somewhere to go (a roster row, or any `authenticated` scope exists at all).
  The 403 there is a courtesy so an un-enrolled user hears it at the login page instead of bouncing
  off a 401 later — it must not tighten into an authorization check, and it must not try to guess
  the destination from `rd` (which is the post-login target, not the URL that triggered the login,
  and `safe_rd` may have already replaced it).
- **Sessions are stateless** — no server-side store. Any worker validates any cookie; a restart
  logs nobody out. Don't introduce per-session server state.
- **Dependencies stay pure-Rust, on `ring` or RustCrypto** (`ureq`+rustls with bundled Mozilla
  roots via `webpki-roots`; `jsonwebtoken`, `hmac`/`sha2` on RustCrypto). The point is a clean
  aarch64 cross-compile with **no system
  OpenSSL or cert store**. Do not add a dep that pulls in `openssl`/native-tls, and do not let
  rustls or a JWT crate switch to `aws-lc-rs` or a platform verifier: both reintroduce exactly
  what this rule exists to keep out. Selecting **no** provider is not the safe middle, and it
  is the half of this rule that has actually broken production: `jsonwebtoken`'s crypto is the
  `rust_crypto` **feature**, not a default, and with neither feature it compiles happily and
  installs a verifier factory that is a `panic!`. The gate then starts clean (the JWKS fetch and
  `from_jwk` never reach the provider) and aborts on the first real login, which under
  `panic = "abort"` and `Restart=on-failure` is a restart loop rather than a failed request.
  `cargo tree` cannot catch that one, because there the wrong tree is the one with a crate
  **missing**; `rsa_signature_verification_works` is what catches it, and is why that test
  exists. After any dependency bump, check with
  `cargo tree | grep -iE "openssl|native-tls|aws-lc|schannel|security-framework"`, which must
  stay empty, and confirm `webpki-roots` is still there. No async runtime
  (`tiny_http` is blocking + threaded) — keeps the binary and resident memory small.
- **id_token validation** must keep all of: `alg==RS256`, `iss`/`aud`/`exp` enforced (`exp`
  required, 60s leeway), `token_use=="id"`, `email_verified` truthy. The **one** sanctioned
  exception: `allow_unverified_social` accepts `email_verified=false` **only** for federated
  logins, optionally narrowed by `social_providers` — never for native Cognito users, since
  self-signup is open and an unverified native email is attacker-controlled. Off by default. See
  `validate_id_token` / `unverified_social_ok`. It multiplies with `authenticated`: together they mean
  "any social account, unverified email, no enrolment".
- **There is no canonical service base URL.** One gate fronts several hosts and which one is in
  play is decided by the caller, so `/auth/session` learns it from `BB_AUTH_ORIGINAL_URL_HEADER`
  (`origin_of`) — nginx must set that header on the session location too, not just the auth-gate.
  `BB_AUTH_AUTHORIZED_HOSTS` (comma-separated host globs, required) is the *only* authority on
  redirect targets. Don't reintroduce a single base URL.
- **The gate never redirects a gated request; nginx does.** A `401` carries this area's login page
  in `LOGIN_URL_HEADER` (`X-Auth-Login-URL`) — the application's `login_url`, else `BB_AUTH_LOGIN_URL`
  (`login_url_for`) — and nginx lifts it with `auth_request_set` into a request variable, which is
  what stops a later `proxy_pass` clobbering `$upstream_http_*`. (`auth_request_set` does read a
  `401` subrequest's headers — verified against nginx 1.26.) nginx must route it through a `map`
  with the global URL as the default arm: an unset variable makes `return 302 $bb_login?rd=…` emit a
  *relative* `Location: ?rd=…`, i.e. a redirect loop back onto the gated path. This works because a
  `401` happens *on* a gated URL, so the application resolves, and it answers even when none of its
  scopes covers the URL: `login_url` says where this area's users sign in, not who may enter.
  **A logout does not**: `/auth/logout` is inside no application's area, so there is no per-area
  logout landing page and adding one would be a field the gate can never reach. The logout link supplies `?rd=` instead, through `safe_rd`; with no `rd` the browser
  goes to the login page, *not* to `safe_rd`'s caller-root default. Both the global and every application's
  `login_url` pass `compile_login_url` at load (printable ASCII, absolute https, no `@`, no `\`) —
  that is what makes emitting them into a header, a `Location:` and a page safe with no per-use
  check. It is deliberately **not** checked against `BB_AUTH_AUTHORIZED_HOSTS`: `read_access` reads
  no env, which is what lets `--check-access` run with no config, and moving the check to startup
  would turn a typo into a boot loop that `--check-access` never saw.
- **The pages the gate serves are complete on their own, and the operator's stylesheet is an
  addition to one.** `/auth/login`, `/auth/callback` and the error page carry their palette
  (`THEME_CSS`), the components built from it (`BASE_CSS`, the same bytes `bb-auth-web`
  emits), their own arrangement of them (`AUTH_CSS`), their script and their two languages
  **inline**:
  no font, no CDN, no second host. That is not frugality, it is the situation these pages
  exist for — somebody cannot get in, and a sign-in page that needs another host to be up has
  picked the worst possible moment to have a dependency. `ui.stylesheet_url` is emitted
  *after* the built-in one, so it wins by source order and a host that does not answer costs a
  page its palette and nothing else; `ui.logo_url` is the only other external reference and is
  equally optional. Keep `BASE_CSS` and both layouts free of literal colours (`THEME_CSS` is
  the only place one may appear, and `only_the_palette_names_a_colour` is what says so), or a
  token file stops being able to restyle what they paint. Substitution
  is `render_page` over `__BB_*__` placeholders, single-pass so a substituted value is never
  rescanned, and every value going in is either an `env_page_value` (printable ASCII, no
  quotes, fatal at startup otherwise) or HTML-escaped. Request data reaches a page in exactly
  one place, `data-rd` on the sign-in page's `<body>`, validated with the same
  `rd_url_allowed` `safe_rd` uses and emitted as an escaped attribute, never as JavaScript
  source. **nginx must leave both locations ungated** (`auth_request off`, exactly as for
  `/auth/session` and `/auth/logout`): a sign-in page behind the gate answers a signed-out
  visitor with itself, forever.
- **Social sign-in is all four env vars or none, fatally.** `BB_AUTH_OAUTH_DOMAIN`,
  `BB_AUTH_SOCIAL_CLIENT_ID`, `BB_AUTH_SOCIAL_CALLBACK_URL` and `BB_AUTH_SOCIAL_IDPS`
  (`SocialConfig::from_env`). Unset, the sign-in page has no social section at all — no
  divider, no button, nothing hinting at a way in this deployment does not have — and
  `/auth/callback` is a `404`, because there is no OAuth leg to finish. Half-configured is a
  refusal to start: a button that cannot work tells whoever clicks it `redirect_mismatch`, in
  Amazon's words, on Amazon's page. The social client id must also be an accepted audience,
  and that is checked at startup: without it every social login succeeds at Cognito and is
  then refused here, one redirect later, with nothing on the page to explain it. The callback
  URL must match the app client's registered `redirect_uri` byte for byte, which is the whole
  reason it is one value in one place.
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

- Config is env vars (`Config::from_env`; missing required vars are a fatal exit) **plus the
  settings file** (`compile_settings`) for the six that must be hot. The only secret is
  `BB_AUTH_HMAC_KEY` (≥32 bytes), and it is in the env file. Full reference:
  [deploy/bb-auth.env.example](deploy/bb-auth.env.example),
  [deploy/settings.example.json](deploy/settings.example.json) and `docs/ARCHITECTURE.md` §8/§8a.
- **Target layout is a tree**: `/opt/bb-auth/{bin/bb-auth, bin/bb-auth-adm, bin/bb-auth-web,
  etc/bb-auth.env, etc/bb-auth-web.env, share/*.example, var/lib/{access,settings}.json}`, units at
  `/usr/lib/systemd/system/{bb-auth.service, bb-auth-web.service, bb-auth-reload.{path,service}}`
  (where a **package** must put them; `/etc/systemd/system` is the admin's, and a copy there
  *overrides* the packaged one forever, which is why both postinsts and `verify.sh` report one
  rather than remove it).
  **The gate** writes nothing, so its whole prefix is `ReadOnlyPaths` and no `StateDirectory` is
  needed despite the `var/lib` name — `bb-auth-adm` writes that file from *outside* the unit's
  namespace, as root, and the hardening does not apply to it. It runs hardened and non-privileged
  on loopback behind a TLS-terminating reverse proxy, speaks plain HTTP, and holds no Cognito
  secret. **`bb-auth-web` is a second unit of the same shape** — the gate's hardening mirrored,
  its own `bb-auth-web` user, its own operator-owned env, an administrator list it reads from
  the settings file (required and never empty), and one hole in the read-only tree: `ReadWritePaths=/opt/bb-auth/var/lib`. The
  hole is the **directory**, because the write is a temp file renamed into place. Both admin
  tools are **optional in the deploy** (their own packages, `deploy.ps1 -Packages`), and must
  stay that way.
- **Installing `bb-auth-web` is what moves the access file (and the settings file) to
  `bb-auth-web:bb-auth 0640`**
  (its directory `bb-auth-web:bb-auth 0750`); a deploy without it changes no ownership at all,
  which is what lets a host run the gate alone. The gate keeps read access
  through the `bb-auth` group and its unit is the same either way. The owner has to move because the
  library's writer restores the replaced file's mode and owner before renaming, and an
  unprivileged process may only `chown` to the uid it already owns and a group it belongs to —
  hence `SupplementaryGroups=bb-auth` on the unit; without either, every GUI save aborts with
  `EPERM`. And because the writer *preserves* the owner rather than resetting it, `sudo
  bb-auth-adm` keeps working untouched and leaves the file `bb-auth-web:bb-auth` too — the two
  editors go on sharing one file, which is what the GUI's `rev` check exists for.
- **`bb-auth-reload.path` is what makes an edit live**, from either editor: it watches
  `access.json` **and `settings.json`** and runs `systemctl reload bb-auth`, so neither the GUI
  (unprivileged, and not the gate) nor the CLI operator needs the privilege to signal the
  service. One unit for both files, because the gate's SIGHUP re-reads both and each is
  fail-soft on its own, so there is nothing to route: a second unit would only be a second way
  to ask for the same reload. `PathChanged=`, not
  `PathModified=`: both editors end with a `rename(2)`, seen as `IN_MOVED_TO` on the watched
  directory, and `IN_MODIFY` would only add a reload on a half-written file. It ships with the
  GUI, so a CLI-only host still reloads by hand; a doubled reload costs nothing.
- **The access file's name is a config contract**, so `BB_AUTH_ACCESS_FILE` and the file it names
  are **state a package may not touch**: the file is the only current copy of the access list, and
  the env file is operator-owned precisely so a deploy can never rewrite it. The gate's `postinst`
  therefore checks that the variable names the file this install creates and aborts **before the
  restart** if it does not, because a mismatched path means `--check-access` vouched for a file
  nothing loads. A missing `BB_AUTH_ACCESS_FILE` is caught by the same required-var preflight.
- **The live `access.json` is the copy that is current** — it is edited on the host (`sudo
  bb-auth-adm …; systemctl reload bb-auth`) and a repo copy drifts from it within a week. So
  a redeploy preserves it and `deploy.ps1 -AccessFile` **replaces** it wholesale: never stage a
  stale file. `bb-auth-adm` is installed to the host precisely so the edit can happen where the
  current file is. It is its own package and optional, and must stay that way: the gate never
  calls it.
- **The deploy is `dpkg -i`, and the packages are where the install lives.** The binaries, the
  units, the service users, the env file, the HMAC key, the empty access file, and the order they
  must happen in all live in `deploy/debian/*/postinst`, and the arrangement is
  **lockout-safe by construction**:
  no state is packaged, so dpkg *cannot* clobber the HMAC key or the live `access.json`, because
  it cannot clobber a file it does not ship. That is also why they are **not** `conf-files`: a
  prompt one `--force-confnew` would lose is not the same guarantee. The env file stays
  operator-owned (created once from `share/*.example`, then never edited), so the install
  *validates* config rather than fixing it: a missing required var, or a `BB_AUTH_ACCESS_FILE`
  that does not name the file this install creates, fails the `postinst` **before** the restart
  and dpkg reports it. Both matter: a fatal startup under `Restart=on-failure` is a boot loop,
  and a mismatched path means `--check-access` vouched for a file nothing loads. A redeploy must
  never log anyone out *by accident*, and the one sanctioned exception is a deliberate
  cookie-format bump, which belongs in the release notes.
- **`scripts/deploy.sh` is what a package may not do**, and nothing else: `dpkg -i` in one
  transaction (not `apt install`, which declines to reinstall an equal version, so a rebuilt
  `1.0.0-1` would silently not deploy); installing a staged
  `access.json` after the gate's own parser has vouched for it, with the owner and mode the live
  file already had; and running `scripts/verify.sh`. It deliberately does **not** move aside a
  unit an admin put in `/etc/systemd/system`, which shadows the packaged one forever:
  that directory is the admin's, so the postinsts and `verify.sh` *report* the shadow and the
  admin decides, which is also what keeps `verify.sh` read-only. `deploy.ps1` builds the packages
  (`package.sh` first, always), ships them with those two scripts, and runs `deploy.sh` as root
  there. Keep the host-side logic in those files rather than in a string quoted through
  PowerShell into `ssh` into a remote shell, and keep `verify.sh` read-only so it stays runnable
  by hand on a host nobody is deploying to.
