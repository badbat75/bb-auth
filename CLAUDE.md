# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

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
  serves both writers. What stays in a tool is what has an
  operator: flags, warnings, and the wording of a verdict. HTTP, the cookie, the JWT,
  the env, the nginx contract are the **gate's**, and stay in `src/bin/bb-auth.rs` — which is
  still one file, read top to bottom. Do not move gate code into the library to "share" it
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
  lock the operator out when it is wrong, and (3) not a secret. Six pass:
  `gate.profile_claims`, `gate.identity_attrs`, `gate.allow_unverified_social`,
  `gate.social_providers`, `gate.session_ttl_secs`, and `web.admins`. Everything else stays in
  `bb-auth.env`: the listener and the worker count (a rebind), the HMAC key (the secret), the
  Cognito trust roots and the cookie's name and domain (a change lets nobody in or logs
  everybody out), and `BB_AUTH_LOGIN_URL` / `BB_AUTH_AUTHORIZED_HOSTS` /
  `BB_AUTH_ORIGINAL_URL_HEADER`, which **are** the lockout. It is a *file* for one mechanical
  reason, and not for tidiness: **a process cannot re-read its own environment** (systemd
  loads `EnvironmentFile=` once, at `ExecStart`), so an env var can never be hot. Do not add a
  seventh setting because it would be convenient there; check it against the three parts
  first. It is held in `RwLock<Settings>`, reloaded by the same SIGHUP as the access file and
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
  what this rule exists to keep out. After any dependency bump, check with
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
