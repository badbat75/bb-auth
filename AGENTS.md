# AGENTS.md

Everything that governs work in this repository: what it is, what to run, the conventions to
write in, and the rules that must not break. It is tool-agnostic on purpose, so any coding
agent can start here, and there is deliberately no tool-specific file beside it.

**Read [the invariants](#invariants--do-not-break-these) before changing behaviour.** This is
an authentication gate, and almost every rule in it exists because breaking that rule locks
somebody out or lets somebody in.

**Start here: read `PLAN.md`.** It holds the user's requirements, the Definition of Done, and what is
left to do, in order.

| | |
| --- | --- |
| [What this is](#what-this-is) | the four targets, and why the split is load-bearing |
| [Where documentation lives](#where-documentation-lives) | this file holds the rules, rustdoc holds the mechanism |
| [Commands](#commands) | what to run, and **which check matches which change** |
| [After a dependency change](#after-a-dependency-change) | the two `cargo tree` greps, and what they mean |
| [Conventions](#conventions) | English, why-not-what, no new em-dashes, one home per rule |
| [Invariants](#invariants--do-not-break-these) | **42 rules, in ten groups, indexed at the top of the section** |
| [Config & deploy notes](#config--deploy-notes) | the configuration reference (the deploy *rules* are invariants) |
| [Working from the plan](#working-from-the-plan) | `PLAN.md`, agent commands, skills and roles |

## What this is

bb-auth is a single-binary **auth gate**: it accepts an AWS Cognito `id_token` that a
browser-side login page already obtained, validates it (RS256 via JWKS), and issues an
HMAC-signed session cookie that nginx enforces on every request via `auth_request`. It also
accepts per-request bearer credentials — a Cognito `id_token` or a static `bbk_` API key.
**It serves that login page itself**, at `/auth/login` (and `/auth/callback` for a social
sign-in), which is not a widening of the job but a removal of three duplicated values: the
page needs the app-client id, the issuer's endpoint and the hosts a post-login `rd` may land
on, and the gate already holds all three as the values it validates against. It serves the
**refusal** page too, at `/auth/denied`, for the same kind of reason one page along: a `403`
has to land somewhere, that somewhere needs the palette and the brand the gate is already
configured with, and the alternative was nginx answering a refusal with the login page, which
is the redirect loop the `403` exists to end.

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
  programs validate them). And **the audit file** (`AuditEvent`, `AuditWriter`, `read_audit`),
  which is the same rule pointing the other way: the gate writes those lines and the GUI reads
  them, so a second answer to what one line means would be a reader showing something the
  writer never said. And **the presentation contract**: the palette
  (`THEME_CSS`, [src/assets/theme.css](src/assets/theme.css)), the components built out of it
  (`BASE_CSS`, [src/assets/base.css](src/assets/base.css)), and `UiTheme` / `stylesheet_link`
  / `html_escape` / `compile_asset_url` beside them. Same membership rule: two programs emit
  HTML, and they must agree byte for byte on what `--accent` names, on what a button and a
  field are made of, and on where an operator's stylesheet lands in the cascade, or the
  surfaces drift apart one edit at a time and nobody working inside either file can see it.
  What is *not* there is each program's **arrangement** of those components. Everything
  more than one program must agree on, byte for byte.
- **[src/bin/bb-auth.rs](src/bin/bb-auth.rs)** — **the gate**, and everything the access file has no
  opinion about: HTTP, the session cookie, id_token validation, the nginx contract, and the
  four pages it serves, and all four are templates in [src/assets/](src/assets/) whose
  `__BB_*__` placeholders `render_page` fills: the sign-in page, the social callback, the
  refusal page a `403` lands on and the error page a failed `/auth/session` lands on. A page
  is HTML, and HTML is edited, diffed and reviewed as HTML; the two small ones were built in a
  `format!` until somebody had to change one. Still **one file**
  (about 8,000 lines), still read top to bottom. The GUI is about 29,300 and is navigated by
  its section order rather than by that slogan.
- **[src/bin/bb-auth-adm.rs](src/bin/bb-auth-adm.rs)** — the access-file admin CLI: CRUD over
  `applications` / `scopes` / `user_groups` / `denied` / `users` / `api_keys`, key minting,
  and `can EMAIL URL` (would this credential get in?). It links the library, none of the gate.
- **[src/bin/bb-auth-web.rs](src/bin/bb-auth-web.rs)** — the access-file admin GUI
  (server-rendered, `maud`): the same CRUD as the CLI, made **only** through the library's
  editing core, plus a **System settings** page over the settings file, in that file's own four
  sections: what the gate answers with, what the audit records and for how long, who
  administers this, and how the pages look (the last one being the gate's pages and the
  self-service page too, which is why one save restyles both programs), each a group that
  folds to its heading with no script and that the page opens folded, and an **Audit** tab over
  the file the gate writes. The bar is **one row at every width** (`flex-wrap:nowrap`,
  §13.28): a ☰ navigation trigger (the console only, and shown only below the breakpoint), the
  operator's logo (`ui.logo_url`, and the console's `img-src` admits it, as the self-service
  page's already did), the brand, the deployment's name alone beside the logo and nothing else
  (the "Administration" tag is gone, and the brand is a `span` and not a link, the user's
  decision of 2026-11-26: the link led to the page the Dashboard tab already names, §13.34
  §10 §11), **five tabs** (Dashboard, Applications, Users, Audit and
  **Settings**, that one last) and one pill, the person's given name or else their first
  address, which opens the **account menu**. The brand's slot is **as wide as the bar allows**,
  never a length of a brand: its cap is the bar's own width less the room the rest of the row
  keeps, floored at `14rem` (plan step 19, 2026-11-27, §13.34 §12), because the fixed `14rem` cut
  "BadBat75 Operations Con…" at 1280 with 180px of empty bar standing beside it. From 884px the
  brand is the part of the row that never gives (`.brand{flex-shrink:0}`), which replaces 1.99.9's
  `nav.acct{flex-shrink:100}`: a shrink factor is a multiplier and not a budget, so that rule
  spent the name pill's room first, and the person's name went at 883 while the brand's words
  were being cut beside it. The slot never wraps, on the console or on `/account`, and the bar's
  **height** is asserted beside its row count: a wrapped brand made the `/account` bar 58px where
  it is 36 (§13.34 §12a, measured) while the row count kept reporting **one row**, because every
  child of a centred flex row keeps the same centre, and the page below loses 40px of it. At
  **640px and below** the bar keeps the mark and hides the brand's words, the words being the part
  a 320px row has no room for once the trigger and the sign-out pill are counted, and hides them
  visually only, by the clip pattern `base.css`'s `.vh` uses, because the mark's `alt` is empty and
  the words are the bar's only name for a screen reader: the user's reversal (2026-11-27, built)
  of the phone rule the coordinator had taken from §13.34 §12g's option (a). The cost is §12g's
  option (c), chosen with no script: a logo answering `404` leaves the phone's brand empty, which
  only a wrong `ui.logo_url` causes
  (`the_words_hide_with_a_logo_and_the_panel_rows_need_no_gap` pins that). What the budget does
  not buy, and §13.34 §12g accepts: a brand over about 28 characters with a logo is still cut on
  the console at 1280, because the cap assumes the Italian tabs and the longest given name, while
  `/account` and the `403`, which carry no tabs, show it whole. That menu is a `details`, so it
  opens with markup
  and closes when a row navigates away, and its rows are the caller's own things and nothing
  else: the caller's name and every address, then the one place ("Go to your account", on the
  console only), then Preferences nested and closed, then Sign out (§13.34 §3). At **883px and
  below** (the number re-measured when the brand lost its tag, §13.34 §10) the tabs ride in a
  navigation menu of their own, opened by that ☰ at the start of the
  bar and never in the account menu (the user's option B, 2026-11-26, replacing the compromise
  the user accepted on 2026-11-25 of riding them in the account panel): the two panels are one
  exclusive `details` group (`name="bar-menu"`), so opening one closes the other with no script,
  and the nested `details.prefs` carries no `name` for exactly that reason. The account menu is
  **one fixed width on both surfaces** (`.menu` is `width:20rem` capped at `calc(100vw - 32px)`,
  §13.34 §3, W13): the console's panel and the self-service page's are one box, that width
  holding the longest row of either in both languages. None of the tabs is `denied` or
  `user_groups`: those two are **sections of the users
  page**, groups above the roster, because a group only means anything in terms of the roster
  and both are about people. Audit comes after them because it is about the same people one
  step later: `users` says who may get in, the audit says who did. **Settings** is a tab, and last
  among them for the reason it read as the odd one out while it was one: it is the only thing here
  that is not about who reaches what, so it sits at the end of a list whose subject is who reaches
  what, and its URL is unchanged (`/config`). The tab's word is "Settings" / "Impostazioni"
  (`K::ConfigTab`), because the full label leaves the brand cut at every width (§13.34 §0), and
  the `h1` it opens spells the name out ("System settings" / "Impostazioni di sistema",
  `K::Config`).
  **Every tab is a noun**, a place that owns a section of a file, and
  that is what says where the **access check** goes: it is a verb, it owns nothing, and it was
  the odd item out for as long as it was a fifth tab. It is now a section of the application
  page and of the person page (`app_check`, `user_check`), which is where the question is
  actually asked, because each of those pages already holds half of it: on an application both
  fields, with `url` starting on that area's own `base` and the verdict naming which of the
  scopes numbered above it answered; on a person only `url`, since the identity is the page.
  An email left empty asks what a client with **no** credential reaches, which only the
  application side can ask, and a row with no email says it has nothing to check rather than
  quietly testing the empty subject. One `decide`, two arrangements: `verdict` and
  `verdict_panel` are shared, the forms are not. There is deliberately no `/can` route left,
  not even a redirect, because there is no single page a bookmark to it could honestly land on. Every unordered list carries a filter and a pager, both living
  entirely in the query string (`Listing`, `list_controls`) so a list works with
  scripting off; each list namespaces its two parameters (`uq`/`up`, `gq`/`gp`, …) so several
  on one page do not steal each other's state. The audit's three list boxes ride in the same
  form through `list_controls_with`, rather than in a second one beside it: two forms over one
  list are two Apply buttons, and an operator who set a period and typed a name would have to
  guess which one applies both. Its Refresh is that same URL as a link, which is all it can be
  when the page reads the file on every request and every filter is already in the address. **Scopes are deliberately excluded from that**:
  their order is their meaning and the ↑/↓ buttons move them within the *file*, so a filtered
  view would show positions that are not the file's and a move that appears to do nothing.
  **JavaScript is used sparingly** (the user's rule since 2026-11-25, replacing "no page may
  need JavaScript"). HTML and CSS come first, and a script is added only where it clearly
  improves an interaction that markup alone does badly; each one is small, inline, allowed by
  its response's CSP by hash or nonce, never loaded from another host, and no framework. What a
  page is for (reading it, submitting its form) should still work with scripting off wherever
  that costs little, which `nojs.js` checks by running the whole GUI with scripting disabled.
  Two scripts exist today. One is `SETTINGS_ONCHANGE`, one inline handler that applies one of
  the account menu's two Preferences list boxes (theme, language) the moment it is picked, with
  a `<noscript>` submit button behind it. The menu is one form (`prefs_form`), so that handler
  runs on the console **and** on the self-service page (plan step 13, 2026-11-26), and both
  policies admit it by the same hash (`page_script_src`). The
  other is `COPY_SCRIPT`, carried only by the page that reveals a freshly minted or rotated key
  and allowed only by that response's CSP, by its hash; it reveals a hidden copy button, and with
  scripting off no button shows and one click still selects the whole key.
  `no_page_but_the_reveal_carries_a_script` pins where scripts are, so adding one is a decision
  made on purpose and written down here, never a side effect. A `GET` never mutates;
  every mutation is a `POST` guarded by a strict same-origin check (`Sec-Fetch-Site`, else
  `Origin`'s host vs `Host`'s — never the scheme, it speaks plain HTTP behind nginx) and by a
  hidden `rev` = sha256 of the file's exact bytes as the form was rendered, so a lost update
  against a `bb-auth-adm` over SSH is a 409 instead of a silent clobber. It links the library,
  none of the gate, and is **just another app bb-auth fronts**: loopback only, gated by nginx
  `auth_request`, identity read from the `X-Auth-Email` nginx injects and from nowhere else —
  a missing header is a 401, not an anonymous visitor. Ahead of that header sits the **proxy
  secret**: every request, `GET` or `POST`, must carry `X-BB-Web-Secret` matching
  `BB_AUTH_WEB_PROXY_SECRET`, compared in constant time (`compile_proxy_secret`,
  `proxy_secret_matches`) before the identity header or the settings file is read, and a request
  that does not is a `403`. The reason: loopback is reachable by every user and every other
  service on the host, and each of them can write `X-Auth-Email`, so the secret is the only thing
  that says a request came through nginx (docs/ARCHITECTURE.md §13.3). `web.admins` is its own
  allowlist on top of that, required and never empty, because an `authenticated` scope covering
  its URL would otherwise open the admin surface to any Cognito account.
  **The self-service page** is the one part of this binary a person who is not an administrator
  reaches: the `/account` prefix (`BB_AUTH_WEB_ACCOUNT_PATH`, default `/account`,
  `Config::account_path`), what one signed-in person does to **their own** account, so that
  reading what they reach stops needing an administrator. It is the console's trust model with
  the privilege taken out: the proxy secret, the identity header and the settings file are read
  exactly as they are everywhere else, and `web.admins` is **not** read at all, because an
  administrator here is one more person acting on their own account. That is why the prefix is
  dispatched **ahead of** the allowlist, and why the two prefixes must be **siblings**:
  `compile_account_path` refuses at startup a page equal to, inside or containing the console's
  base, since a page nested in `/admin` would answer the administrator surface's URLs as the
  page, and a base that normalises to nothing is every path, leaving no sibling space to mount
  anything beside, which is what makes an empty `BB_AUTH_WEB_BASE_PATH` a fatal startup. The
  proxy secret is route-global and is not relaxed for this page, and a non-administrator's
  request to an admin route is a `403`, never a `404` that names which paths exist; that `403`
  names the caller in the bar as every other page does and ends in one action, a "Go to your
  account" pill to this page, because the console has no page that person may open and this one
  is theirs by design. What the page shows is one lede with the caller's addresses (every email
  of one roster row, space-joined, as the gate sends them) and, on the line below, the uuid they
  resolve to under the label "Account id". A caller with **no** roster row gets the addresses
  alone: that second line names an id, and with no id to name there is no line and no `br`,
  nothing standing in for a row the file does not have (plan step 13, 2026-11-26, which deleted
  the `K::AccountNoRow` sentence).
  Then four sections, in the order a person reads them, each with a sub-line saying what it is
  for and each empty state a sentence naming what is missing: *Profile* (each configured
  `gate.profile_claims` claim and the value nginx forwarded, percent-decoded, where a configured
  claim with nothing forwarded reads "not provided", and the **edit** of those claims, offered
  only on a request that carries `X-Auth-Native-Username`, because the edit acts on one Cognito
  user and the pool name is the only honest name for them: a session with no header, federated or
  minted before that header existed, sees the list and one sentence where the pill would be, never
  a disabled control), *API keys* (the console's own key
  table: each key's id, its expiry date or "never", and its restriction, never the hash or the
  bearer, each row ending in a rotate pill and a revoke icon that lead to a confirmation page),
  *Groups* (the `user_groups` naming the caller's uuid, under the page's own word
  for that section, "Groups", not the console's "User groups") and *Where you reach* (the
  applications and
  scope names `Access::scopes_reached` returns, as one flat `app/scope` list in the file's order,
  never a URL). The last two are **read-only**.
  The `denied` veto is answered with a `403` ahead of everything the page would otherwise say
  about the caller, and a stranger and an administrator with no roster row see the same page.
  It wears the `ui` section per request as the console does (brand name and logo, the operator's
  stylesheet, `ui.theme` as the default theme stamped as `data-theme`), on the console's own
  `main` column, one width for both surfaces with prose capped at 75ch (§13.26), under
  the console's own header (`top_bar`, one function for both surfaces): the operator's brand,
  mark and name, worn as a `span` and not a link, since this page is the only one its visitor
  came to the estate for, an empty tabs nav, and the console's one account menu with **no
  places** in it (this page offers no console page), so its panel is who
  the caller is in full, the Preferences box nested and closed, and Sign out. The person chooses
  only the theme (light, dark, "Auto (system)") and the language (English, Italian, auto) from
  that box, which is the console's own form: its two list boxes carry the console's one
  `SETTINGS_ONCHANGE` handler, so a choice applies the moment it is picked, and the Apply sits
  inside `<noscript>` as the way in for a browser running no code (plan step 13, 2026-11-26,
  which replaced the page's "no handler at all" and its always-present Apply). The form is a
  `GET` back to the page, and one submit answers one `302` that sets the `theme` and `lang`
  cookies, the same names the console writes, so a choice carries between the two surfaces on
  one host.
  Its Sign out is the console's `BB_AUTH_WEB_LOGOUT_URL` with its `rd` parameter dropped
  (`logout_without_rd`, derived once at startup into `Config::account_logout_url`), because that
  `rd` is the console's round trip and a person who is not an administrator following it lands on
  a `403` there: the link can only lose a parameter, never gain one, so it names no landing place
  the operator did not write.
  The keys' writes are there: mint, rotate and revoke of the caller's **own** keys, each a
  `POST` to a path under the account prefix (`/account/keys`, `/account/keys/rotate`,
  `/account/keys/remove`), each carrying the file's `rev` so a stale form is a `409` that writes
  nothing, and a mint or a rotate answers directly with the bearer shown once through the
  console's own reveal, copy icon included. The two row actions are asked first, as the console's
  are: a `GET` (`/account/keys/rotate?id=`, `/account/keys/remove?id=`) renders the console's
  `page_confirm` card and changes nothing, and only its `POST` writes, so a prefetch or a misclick
  cannot cost a credential; an id that is not on the caller's row is a `404` naming nothing, which
  keeps that step no oracle for other people's keys. Minting is a page of its own as well: "+ New
  key" is a `GET` to `/account/keys/new`, the same page with one table row more, a `td` holding the
  console's `form.edit`, and a refused mint keeps that row with the values as posted, because a
  person who typed a name and a restriction is not being asked to type them again. At ten keys the
  `+` is the sentence that says why there is none, not a disabled control, which the keyboard
  skips and which says nothing. The profile edit is there, and it acts on the session's own
  native user: the pool is asked by `USERNAME`, taken from `X-Auth-Native-Username` on **this**
  request and never from a posted field, and the IdToken Cognito returns is bound by
  `cognito:username`, so a challenge that answers for anybody else writes nothing and says so
  (§13.25). Account deletion is there too, as the account menu's last row (`K::AccountDelete`,
  after Sign out), and **only when `BB_AUTH_WEB_DELETE_INTAKE` names the owner's intake**: with it
  unset there is no row and `{account}/delete` is the `404` every unknown path under the prefix
  gets. The `GET` is the confirmation and changes nothing: it lists what goes (the bb-auth record
  and the named grants on it, the caller's API keys, their groups, and every sign-in account with
  each of the caller's addresses), says what the audit keeps and for how long, and asks the person
  to type one of those addresses. That field carries **no** `autocomplete` (the user's decision,
  2026-11-26: the confirmation is the person's own act, and this is the estate's one deliberate
  exception to WCAG 1.3.5), and no `autofocus`. The `POST` goes in the order that cannot leave a
  half: the same-origin door, then `rev` and the `uuid` behind it (a stale one is a `409` that
  writes nothing), then the typed address (one of the caller's, or a `400` that keeps what was
  typed), then the intake's `whoami` for **every** address before anything is touched (a protected
  address is a `403` and nothing is written, so the page is no oracle for somebody else's
  account). For a caller with a roster row the row is removed **first**, under the write lock
  through `remove_user` and `AccessWrite` with `rev` re-checked, so the keys and the named grants
  die before the pool is asked; then each address is queued at the intake, one call each, stopping
  at the first answer that is not `202`. A caller with no row is queued and the access file is
  untouched. The pages never say *deleted*, only **queued**, because this program cannot read the
  worker's outcome, and a partial run says what did happen and offers the retry. Where **every**
  address is queued and `BB_AUTH_WEB_LOGOUT_URL` is set, the `POST` answers no page at all: a
  `303` to that logout with `rd=/auth/login?notice=account-deleted`, so the gate clears the cookie
  (it is the only program that knows its name, its `Domain` and its `Path`, and a second builder
  of a clearing `Set-Cookie` is how a clear ends up doing nothing) and the person lands on the
  sign-in page's one fixed notice, whose words are the done page's, *queued* included (§13.32 §1,
  §13.33 §1). Only on full success: every partial outcome offers "Try again", and that retry is
  the walk over the header's addresses, which needs the session, so those pages keep their "Sign
  out" pill and their words. With no logout URL set the done page stays what it was. A deleted
  administrator stays in `web.admins` (the user's decision, 2026-11-26): this path edits the access
  file and never the settings file. The intake is reached at a loopback `http` origin over
  `X-Auth-Email`, and the optional shared secret `BB_AUTH_WEB_DELETE_SECRET` travels in
  `X-BB-Delete-Secret`. Its design is
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §13.

The defining constraint vs. authorization-code OIDC proxies (oauth2-proxy): those drive the
login themselves and *cannot* accept a token the browser already holds. bb-auth is built for
the opposite — a login page runs Cognito `USER_AUTH` in the browser (enabling sign-up +
auto-login with no second OTP) and POSTs the resulting `id_token` to `/auth/session`. The gate
now ships that page, but the constraint is unchanged and so is the shape: the page is still a
browser-side client of Cognito that hands the gate a token it did not obtain, and pointing
`gate.login_url` at a page of your own instead still works.

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
# Tests: unit tests in all four targets, run on the host, no network needed. The access
# file and the writers (src/lib.rs), the gate including its token verifier and its router
# over a real socket (src/bin/bb-auth.rs), the CLI's argument grammar (src/bin/bb-auth-adm.rs),
# and the GUI including the tests that drive it over a real socket, the console's and the
# self-service page's alike (src/bin/bb-auth-web.rs). A handful are
# cfg(unix) (the SIGHUP reload's fail-soft, the writer's mode preservation, the audit file's
# own mode) and therefore run on Linux, never on the development host (run them under WSL
# before a release).
cargo test
cargo test session_roundtrip          # a single test by name

# Can THIS binary verify a signature? No env, no config, no network: the offline RS256
# check a login performs, against a key compiled in. scripts/verify.sh runs it on the host
# after every deploy, which is the check that was missing when a provider-less build
# deployed green and failed every login.
cargo run --bin bb-auth -- --self-test

# Which build is this? `v<version>-g<commit>`, `-dirty` when the tree was not committed,
# and all three programs answer it.
cargo run --bin bb-auth -- --version

# Does an env file name everything the gate refuses to start without? The gate's postinst
# asks the binary this rather than keeping its own list of variables in shell. Run it
# against a REAL env file: the tracked example deliberately leaves BB_AUTH_HMAC_KEY blank
# (the install generates one), so it is expected to fail this check.
cargo run --bin bb-auth -- --check-env /opt/bb-auth/etc/bb-auth.env

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
# The two pages this area sends people to, and since an area names a host, this is also how
# one gate fronting several hosts gives each host its own sign-in and refusal page.
cargo run --bin bb-auth-adm -- -f .\deploy\access.json app set mpa --denied-url 'https://app.x.com/no-entry'
cargo run --bin bb-auth-adm -- -f .\deploy\access.json user add bob@x.com
cargo run --bin bb-auth-adm -- -f .\deploy\access.json key add bob@x.com --id laptop --duration 365d
cargo run --bin bb-auth-adm -- -f .\deploy\access.json can bob@x.com https://app.x.com/mpa/admin/panel

# The settings file: the values that take effect with no restart at all. `-s` names it;
# with no `-s` it is settings.json beside the access file, which is what the packages create.
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings show
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings set --claims given_name,family_name
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings admin add bob@x.com
# Where a sign-in lands when nothing named a place (no rd, no Referer). An empty value unsets it,
# which is the default and lands on the caller's root. The value must sit on a host
# gate.authorized_hosts covers, because safe_rd refuses a landing page outside them at every login.
cargo run --bin bb-auth-adm -- -s .\deploy\settings.json settings set --landing-url 'https://auth.x.com/account/'
# The `ui` four: the look of every page EVERY program serves, so one stylesheet restyles the
# sign-in page, the admin GUI and the self-service page together. Pass an empty value to unset
# any of them.
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
./scripts/deploy.ps1 user@host -AccessFile <your-access.json>  # also replace the access file

# Health-check a host without deploying to it (also run at the end of every deploy)
ssh user@host 'sudo bash -s' < ./scripts/verify.sh
```

**Match the check to the change.** Every suite here is cheap to start and slow to finish, so
run what the edit can actually break, not the whole board. Re-running a check that already
passed, on code untouched since it passed, tells you nothing you did not already know.

| What changed | What to run |
| --- | --- |
| `src/assets/admin.css` alone | `cargo test --bin bb-auth-web` and `node e2e/shots.js <scene>` |
| `src/assets/theme.css` or `src/assets/base.css` | `cargo test` (the palette's four arms are pinned by `the_theme_defines_every_token_in_all_four_arms`, the sharing by `only_the_palette_names_a_colour` and `the_components_are_shared_and_the_layouts_only_arrange_them`) and `node e2e/shots.js config` **and a look at `/auth/login`**: both files are emitted by both HTML programs, so a change to either repaints the admin interface, the sign-in page and the self-service page together, and most of that is invisible to the admin's own suite |
| `src/assets/auth.css` alone | `cargo test --bin bb-auth` and a look at the page in a browser |
| `src/assets/*.html` | `cargo test --bin bb-auth` (the page tests read the rendered document) and a look at the page in a browser: no test can tell you a login form is unusable, or that a refusal reads as an accusation. All four pages are here: `login.html`, `callback.html`, `denied.html`, `error.html` |
| `maud` markup, or a `K` translation key | the above, plus `cargo test` (several tests assert on rendered HTML) and `node e2e/run.js` |
| Anything about the audit (what is recorded, the schema, the page) | `cargo test` **and a look at the tab with a real file**: the suite can say a row round-trips, it cannot say a refusal reads as an explanation. `bb-auth --check-env` does not cover this one, since the audit is optional by design |
| A signature, a handler, the gate, or the library | all of it, plus `cargo clippy --all-targets` |
| A dependency version | all of it, plus the cross-compile and the dependency check below |

`cargo doc --no-deps` earns its place when an intra-doc link could have moved, which is a
real risk when a type or a function is renamed and no risk at all when a border-radius
changes. `node e2e/shots.js` takes a scene-name filter for the same reason: the full walk is
296 shots at most across seven views (71 scenes, plus the 13 interaction states in the two views
that run them; a scene that cannot run in a view is reported `SKIPPED`), and a change to one
page needs one of them.

Markdown is linted with markdownlint (`.markdownlint.jsonc`, which documents its own
invocation): `npx markdownlint-cli2 "**/*.md" "#target" "#dist" "#e2e/node_modules"`.

There is **no CI**: every check above is run by whoever is making the change, which is why
the table above says which one matches which edit. `scripts/package.sh` runs the test suite
itself before it builds, so the one check that must never be skipped before a release is not
left to memory.

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
because a jump there is the first sign a dependency grew.

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
  same register as the code comments. With no changelog before this one, no pull requests and
  no tracker, `git log` is the whole design narrative, and that is worth more than a tidy
  subject line. Going forward, put the claim in a **subject under 72 characters** and expand
  the same sentence as the body's first line: the current mean is 90, which `--oneline` wraps
  and GitHub truncates in the middle of the operative clause. Nothing is rewritten
  retroactively.
- **Work happens on `main`**, and there is no review step, so two things stand in for one.
  A change is not done until `cargo test`, `cargo clippy --all-targets` and `cargo fmt` are
  clean, and nothing runs them for you. And **check `git status` before you build**: this
  tree has had two sessions editing it at once, an uncommitted change is what
  `scripts/package.sh` now refuses to package by default (`--allow-dirty` to mean it), and a
  binary built from one reports a `-dirty` build string forever after.

## Invariants — do not break these

**The rules, in one place.** Forty-two of them, grouped. The lead sentence of each is
its whole claim; the prose under it is the reason, which is the part worth reading before
changing anything. Seven of these used to sit in "Config & deploy notes" below, so this
section under-read itself by a fifth, and two of the seven are lockout-class.

[**What lives where**](#what-lives-where)

- The library is the shared files, and nothing else.
- No editor may write a file the gate would reject.

[**The session cookie**](#the-session-cookie)

- The cookie is a versioned wire format, and exactly one version is accepted.

[**The two files, and what a bad one costs**](#the-two-files-and-what-a-bad-one-costs)

- The access file is the real access gate
- The settings file is what must change without a restart, and the rule for what goes in it is three-part.
- What changes who reaches what is fatal; what drops one credential is skipped.

[**The audit**](#the-audit)

- An event has exactly one home.
- The audit is bounded by construction, and can never cost a login.
- It records authentication, not traffic.
- It believes a header only when an operator has named it.

[**Resolving a URL**](#resolving-a-url)

- Two levels of resolution, and they answer differently on purpose.
- A URL no application covers is reachable by nobody.
- One matcher serves scheme, host and path.

[**Grants and vetoes**](#grants-and-vetoes)

- One veto, ahead of every grant, on every credential.
- A scope's `excluded` is the same veto, one level down, and it is checked before the scope's own grant.
- A scope names people, and that is the only place a grant is written.
- `anonymous` and `authenticated` grant without listing anybody
- Static API keys (`bbk_` namespace) act as their user, and may only narrow.
- Access is enumerated, never assumed.

[**What a 204 hands nginx**](#what-a-204-hands-nginx)

- nginx builds `X-Original-URL`, and must not let `Host:` pick the scope.
- The gate names the identity; nginx is what makes that trustworthy.
- The profile claims are decoration, and the encoder is what makes them safe.
- The set is config; the header name is code.

[**The endpoints, the pages and the redirects**](#the-endpoints-the-pages-and-the-redirects)

- `/auth/session` is not a gate.
- Sessions are stateless
- id_token validation
- There is no canonical service base URL.
- The gate never redirects a gated request; nginx does.
- A refusal a login cannot fix is a `403`, and nginx answers it with a page rather than a hop.
- The pages the gate serves are complete on their own, and the operator's stylesheet is an addition to one.
- Social sign-in is four settings that stand or fall together, and none of them is an env var.
- `safe_rd` guards the post-login redirect

[**Dependencies and the build**](#dependencies-and-the-build)

- Dependencies stay pure-Rust, on `ring` or RustCrypto
- Release profile is speed-optimized

[**Deploy and packaging**](#deploy-and-packaging)

- Target layout is a tree
- Installing `bb-auth-web` is what moves the access file (and the settings file) to `bb-auth-web:bb-auth 0640`
- `bb-auth-reload.path` is what makes an edit live
- The access file's name is a config contract
- The live `access.json` is the copy that is current
- The deploy is `dpkg -i`, and the packages are where the install lives.
- A release runs the tests and says which commit it is.
- `scripts/deploy.sh` is what a package may not do

### What lives where

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
  message) is defined once in `BASE_CSS` and both programs emit it. **It reaches the response
  too**, one step further out and by the same argument: two programs answer a browser with an
  HTML document, so "what headers does one carry" and "where did this `POST` come from" must
  not have two answers either. `PAGE_SECURITY_HEADERS`, `page_csp`, `csp_hash` and
  `request_site` are in the library for that reason, and the drift they end was real: the gate
  sent `X-Frame-Options` and no `nosniff`, the GUI sent `nosniff` and no `X-Frame-Options`,
  and the page that could be framed was the one whose forms delete users. What stays each
  program's own is the **policy**: `request_site` classifies, and the GUI refuses anything but
  `same-origin` while the gate also accepts `same-site`, because `gate.login_url` may name a
  sign-in page on a sibling host. Its limit is where a thing
  stops and an ARRANGEMENT of things starts: the admin's header, tables and phone stacking are
  the GUI's, the centred card and its steps are the gate's, and the account page wears the
  console's column rather than a card of its own (§13.26), and nothing
  requires those to agree. What stays in a tool is what has an
  operator: flags, warnings, and the wording of a verdict. HTTP, the cookie, the JWT,
  the env, the nginx contract and the pages themselves are the **gate's**, and stay in
  `src/bin/bb-auth.rs` and `src/assets/` — which is still one file, read top to bottom, plus
  the four templates it fills. Do not move gate code into the library to "share" it
  with the CLI; the CLI has no business with any of it. The two authorization functions in
  `bb-auth.rs` (`authorize`, `bearer_apikey`) are thin wrappers that add the log line
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

### The session cookie

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
  another claim's name, so editing the list must stay a no-logout change. The gate writes one
  key of its own into that same object, `native_username` (the pool name of a native sign-in,
  docs/ARCHITECTURE.md §13.25), and it lands on the same no-logout side of the axis for the
  same reason: a binary that never wrote that key verifies a cookie that carries it, and this
  binary names no username for a cookie minted before it existed. Verify checks the
  signature over the segment **as received** and only then parses it — never parse and
  re-serialize to compare.

### The two files, and what a bad one costs

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
  lock the operator out **irreversibly**, and (3) not a secret. Twenty-four pass, in four
  sections: `gate.issuer`, `gate.client_id`, `gate.login_url`, `gate.denied_url`,
  `gate.landing_url`, `gate.cookie_domain`,
  `gate.authorized_hosts`, `gate.profile_claims`, `gate.identity_attrs`,
  `gate.allow_unverified_social`, `gate.social_providers`, `gate.oauth_domain`,
  `gate.social_callback_url`, `gate.social_buttons`, `gate.session_ttl_secs`; the whole
  `audit` section (`client_ip_header`, `request_id_header`, `rotation`, `retention`);
  `web.admins`;
  and the whole `ui` section (`stylesheet_url`, `logo_url`, `brand_name`, `theme`), which is
  the **look of every page either program serves** and the one section both read. The
  `ui` four pass the middle part precisely because the built-in stylesheet is complete: the
  worst a wrong value there achieves is an unstyled page, never a closed door.

  **The nineteenth is `gate.denied_url`, and the argument is made out loud because this
  section demands it of the next one too.** It is read per request, on `/auth/denied`; it is
  no secret, since it is a `Location:` a browser follows; and it passes the middle part more
  cleanly than anything else here, because it is read **after** somebody has already been
  refused. It cannot close a door: the worst a wrong value achieves is that a person who was
  never getting in sees a broken link instead of a page. That is also why it is not a
  sixth guarded change, and why an application may override it in the access file
  (`denied_url_for`), which is what makes a refusal page per host.

  **The twenty-fourth is `gate.landing_url`, and it passes the middle part the same way, one
  page along.** It is read per request, on `/auth/session`; it is no secret, since it is a
  `Location:` a browser follows; and it is read **after** the token is verified and the cookie
  built, deciding only where a browser that is already signed in is sent. The worst a wrong
  value achieves is a landing on a `403` or a `404`, the cookie is set either way, and the
  editor still holds a session to undo it with, so it is not a sixth guarded change either. It
  carries one load-time cross-check: `compile_settings` refuses a value whose host
  `gate.authorized_hosts` does not cover, because `safe_rd` refuses it at every login and the
  sign-in falls back onto the sign-in page, which is the loop this setting exists to end with a
  setting standing beside it saying it is fixed. Empty, the default, is the caller's root
  exactly as before it existed, and an empty one is **never written**: `GateSettings` refuses
  unknown keys, so an older binary refuses a file that carries the key, and an editor that
  never set one leaves a rollback nothing to trip on. Where one is set, the order is deploy
  then set, and `settings set --landing-url ''` before any rollback.

  **The last four are the `audit` section, and they pass all three parts cleanly.** They are
  read whenever an event is recorded or the audit is maintained, which is per request or hourly
  and never once at startup; none can close a door, because the audit is written after the
  decision and can fail without costing a login; and none is a secret. They are a section of
  their own rather than more of `gate` because they answer a different question (not how a
  request is answered but what is written down about it, and for how long), and the choice has
  a useful side effect: an older binary keeps an unknown top-level key rather than refusing the
  file, so this section can be written before the binaries that read it have landed.
  The two headers are not **checkable**, and that is the thing to know about them: naming one
  is a promise that nginx overwrites that header on every location that reaches the gate, and
  no parser can see nginx. So both are empty in a fresh file, a package never names them, and
  the one refusal the file makes on them is the one that matters most: neither may name a
  credential header (`compile_audit_header`), because a request id is written down as it
  arrives. `rotation` and `retention` are refused in exactly one combination, the one that bounds
  no bytes, which the audit invariant below is about. None of the four is a guarded change: the
  worst a wrong one does is write a wrong address down, or keep less than somebody wanted.

  **Part 2 is not "cannot break a login", and saying so is what makes the list honest.**
  Several of these can. The test is whether the person who made the edit can still undo it,
  and nothing in this file invalidates a cookie: a bad save leaves every session already
  minted standing, including the one the editor is holding, and `bb-auth-adm` over SSH is the
  way back if not. That is the line the HMAC key falls on the wrong side of, since getting it
  wrong logs **everybody** out at once, including the person who could fix it.

  **The whole Cognito wiring is here, the pool included, and what that cost is stated rather
  than glossed.** `gate.client_id` and every `gate.social_buttons` audience *are* the accepted
  audiences (`Settings::audiences`, derived), which ended a real duplication: `BB_AUTH_AUDIENCES`
  and `BB_AUTH_SOCIAL_IDPS` were two lists that had to agree with a third by hand, and a list
  that has to agree with another by hand is the bug this repository keeps writing warnings
  about. What moved them was that all three programs have an opinion about them: an env var is
  readable only by the process that was started with it, so the GUI could have shown one only
  by being handed a second copy in its own env file, and a value written in two files drifts
  with nothing to catch it. For a while the safety argument was that the **pool** stayed in the
  environment, so the file could only choose among the app clients of an issuer the environment
  already trusted. `gate.issuer` retired that sentence, and the honest replacement is: **this
  file is trusted as much as the gate itself**, because whoever can write it can already write
  the access file beside it and the admin list inside it.

  **Three of them do not pass cleanly, and each is worth its own line.** `gate.issuer` fails
  part 1: it is read once, to fetch a JWKS, so a reload has to re-fetch and then swap keys and
  settings **together or neither** (`reload_settings_from`), because a gate holding half of that
  pair checks one pool's tokens against the other's keys. `gate.cookie_domain` fails part 2 in a
  way nothing else here does: it cannot log anybody out, it does something worse, which is
  orphan every cookie already issued so that `/auth/logout` stops clearing them (a browser
  matches a clearing `Set-Cookie` on `(name, Domain, Path)`: see `build_cookie`). And
  `gate.authorized_hosts` was the boundary that kept `gate.login_url` from being a redirect
  gadget. What the move buys, and what was not expressible while those two lived in different
  files, is that **`cookie_domain` must reach every host in `authorized_hosts` or the file is
  refused** (`cookie_domain_covers`): a host the cookie cannot reach is a login that lands,
  sends no cookie, gets a `401` and bounces back to the sign-in page for ever, with nothing
  anywhere saying why.

  **Five of them can stop people getting in, so both editors ask before writing one.**
  `issuer`, `client_id`, `login_url`, `cookie_domain`, and *removing* an `authorized_hosts`
  entry: `guarded_changes` is the one list, in the library, because two editors that disagreed
  about which fields those are would make the guard a property of which editor you happened to
  open. The wording is each program's own (`--yes` and a printed block on the CLI, a panel and
  a second `POST` in the GUI), because it is addressed to an operator. Asking is enough rather
  than refusing for the reason part 2 gives: no cookie is invalidated. **It is five and not
  fifteen on purpose** — a confirmation that fires on every save is a button people learn to
  click without reading, which is worse than no confirmation because it is also an alibi — and
  it fires on what is *taken away*, never on a value being set for the first time (an empty
  field being filled in can only be a deployment being finished), and never on *adding* a host.

  Empty is tolerated on all three of the new ones, and on `client_id`, because a package
  creates this file and cannot know any of them: the gate says so loudly at startup instead of
  refusing to start, which on a first install would be a boot loop. The GUI is stricter than
  the gate and refuses to *write* an empty `issuer`, `client_id` or `authorized_hosts`, which
  is not a contradiction but the same rule at a different distance: a form should not be able
  to express a deployment nobody can get into. A fresh install is therefore wired with
  `bb-auth-adm` over SSH, and it has to be, since `bb-auth-web` is itself behind the gate.
  `gate.login_url` empty means the gate's own `/auth/login`, which is a page it actually
  serves.

  Everything else stays in `bb-auth.env`: the listener and the worker count (a rebind), the
  HMAC key (the secret), the cookie's **name** (renaming it orphans every cookie already
  issued, and unlike the domain nobody has a reason to), `BB_AUTH_ACCESS_FILE` (the file this
  one is found beside, which cannot live inside it), and `BB_AUTH_ORIGINAL_URL_HEADER`, which
  **is** the lockout.

  It is a *file* for one mechanical reason, and not for tidiness: **a process cannot re-read
  its own environment** (systemd loads `EnvironmentFile=` once, at `ExecStart`), so an env var
  can never be hot. Do not add a twenty-fifth setting because it would be convenient there;
  check it against the three parts first, and say the argument out loud the way the ones above
  are, including the part it fails.
  It is held in `RwLock<Settings>`, reloaded by the same SIGHUP as the access file and
  **fail-soft in the same way** (a broken file keeps the live values), which is what makes it
  safe to hand to a GUI: the worst a bad save can do is leave the previous values in force.
  `bb-auth-web` reads it fresh per request instead, because it is the one service that edits
  its own half of it.

  The file declares `"version": 3`, and both older formats are refused with a **sentence**
  rather than a type error three levels down, for the reason the access file's own version
  check gives. Version 1 predates the app clients, and no parser can guess which client each
  of its bare-name buttons belonged to; version 2 predates the pool, and the three values it
  is missing were in an env file the gate can no longer read. Each refusal names the fields to
  move in and points at the CHANGELOG.

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

### The audit

The third file more than one program has an opinion about, and the only one that goes the
other way: the gate writes it, `bb-auth-web` reads it back on its Audit tab. It is off unless
`BB_AUTH_AUDIT_FILE` names something, and its default is `/var/log/bb-auth/audit.jsonl`, which
the unit creates through `LogsDirectory` precisely so that the gate's own prefix can stay
`ReadOnlyPaths`.

- **An event has exactly one home.** When the audit is on, the request-path lines that used to
  go to the journal go to the file **instead**; when it is off, the journal keeps saying what
  it always said. The same refusal in two artifacts is one an operator has to reconcile by
  eye, and reconciling by eye is what a schema is for: the journal is prose with a volume
  knob, this is a record with a schema and a retention, and each event belongs to one of them.
  `LogLevel::Debug` overrides both and prints regardless, because that level exists for the
  ten minutes when the repetition *is* the information. The exclusivity is not a promise the
  file gets to break: `Audit::on` reports false the moment a write has failed, and every
  caller records first and asks afterwards, so a broken audit hands its events straight back
  to the journal and a recovered one takes them back. What is **not** on this axis is startup,
  configuration, reloads and failures, which are the journal's alone: they are about the
  process and not about a person.
- **The audit is bounded by construction, and can never cost a login.** There are exactly two
  files, the live one and the one it last rotated onto (`.1`), and a rotation replaces the old
  `.1`. When the live file rotates and how much the pair keeps are `audit.rotation` and
  `audit.retention`, each an amount of time or of space (`AuditPolicy`), and **at least one of
  the two must be a size**: a time bounds how old the audit gets and not how big, so rotation and
  retention both in time is refused (`AuditPolicy::new`), which is what keeps
  `AuditPolicy::max_bytes` an answer however hard somebody hammers a gated URL. A retention in
  space works by rotating at half of it at the latest, so it never needs a rewrite; a retention
  in time drops every expired event from both files, and so does a rotation on age, in
  `AuditWriter::maintain`, which the gate runs hourly, at startup and on every reload. The
  hourly half is not optional: a deployment that records one event a month must still forget,
  on time, the address it said it would, which a rule applied only on write would not do. The
  default is `AUDIT_MAX_BYTES` and no retention, which is what the audit did before either was
  a setting. The size is deliberately the *only* bound on a flood: it is exactly the case an
  audit exists for, so it is kept and the disk is what gets protected, rather than the flood
  being filtered and the evidence lost. Write failures are
  fail-soft to the last line: `AuditWriter::record` returns the error, `Audit::record` says so
  **once** and carries on, and the decision is the access file's whatever the file system
  says. A full disk must not be able to refuse anybody, and must not be able to admit anybody
  either. The reader is bounded too: `read_audit` walks a file backwards in blocks
  (`RevLines`), so a rotation an operator set to a gibibyte costs the Audit tab one block of
  memory and not the file.
- **It records authentication, not traffic.** Sign-ins, sign-outs, refusals, and the one grant
  worth a line (an identity Cognito vouches for walking into an `authenticated` scope while
  being in no roster row). **Not** the ordinary allowed request: the gate answers an
  `auth_request` for every asset of every page, and a row for each is a file nobody reads and
  a write on the path that must never be slow. That log already exists and is nginx's, which
  has the URL, the status and the byte count of every request, and a row's `rid` is how it
  finds its line there. The second deliberate
  omission is the refusal carrying **no** credential, which is what every signed-out browser
  gets on its way to the login page: it is the ordinary case, it names nobody, and it is the
  only one an anonymous client could produce without limit. The two kinds that do fire per
  request are deduplicated by `first_audited` on its own five-minute window, keyed by who,
  where, why and from which address, but never by which URL, since a browser refused one asset
  is a browser refused forty, while one identity refused from a second address is a second fact
  and usually the interesting one; that window is **separate from the journal's**
  (`first_in_window`), because an audit
  whose contents depend on the journal's verbosity is not an audit. A `reason` is a **code**
  and never a sentence (`decision_reason` is the only place one is spelled, and it is the
  `Decision` variant's own name), so the wording belongs to whoever is reading: the GUI shows
  a refusal in the reader's language, in the same words its access check already uses for the
  same verdict. Profile claims are in neither home, for the reason they are in no log line.
- **It believes a header only when an operator has named it.** The gate listens on loopback
  and never sees a client, so a row's address (`ip`) and nginx's id for the request (`rid`)
  are only as true as the proxy that wrote them, and nginx hands a client's own headers through
  untouched unless a `proxy_set_header` overwrites them. An address the client chose is worse
  than none, because an audit that can be told a lie is an audit that tells one. So both are
  read only from the header `audit.client_ip_header` / `audit.request_id_header` names, both are
  empty until somebody who has wired nginx names them, and the recipe overwrites both on every
  location that reaches the gate (the `auth_request` target, `/auth/session`, `/auth/logout`).
  Of a list the **last** entry is taken, which is the one the nearest proxy appended, and never
  the first, which is the client's. Every value is narrowed on the way in rather than trusted
  to be what it says: the address is parsed and dropped if it is not one (`client_ip`), the id
  is letters, digits and `-` (`request_id`, a charset every credential this gate knows fails,
  so a misnamed header still cannot write one down), and the user agent, which needs no setting
  because it is the client's word and recorded as such, is cut at `AUDIT_UA_MAX`. It is stamped
  by `RequestAudit` rather than at each call site, so no event can be written without it. The
  account (`sub`) comes from a validated token and from nothing else, and it is in no cookie,
  by choice rather than by necessity: the login event already records what that login proved.
  (A new key in the cookie's claims object would not be a `COOKIE_VERSION` bump, which is how
  `native_username` travels; only a change to the signed bytes' layout is.) And an address
  is personal data kept for as long as the file's bytes last rather than for a number of days, which is worth saying on any page
  that tells people what this estate records about them.

### Resolving a URL

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

- **One matcher serves scheme, host and path.** A non-final `*` cannot cross `/`, and `://` holds
  two of them: that single rule is what stops a wildcard leaking across component boundaries, so
  don't split `glob_match` into three matchers. It is a bottom-up DP, **not** recursive backtracking
  (which is exponential on many `*`); `glob_many_stars_terminates` pins that. A URL with `..` is
  rejected at both levels of resolution, from one helper (`sane_url`), and patterns are validated
  and authority-lowercased once at load (`compile_pattern`).

### Grants and vetoes

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
  `user_group_refs` count an exclusion as a reference like any other, marked `(excluded)`.
  The mark is what lets the report tell the two apart, and they must be told apart: an
  exclusion is **not swept**, it is rewritten to the row's primary email, as `denied`
  already is, because dropping a veto lifts it and the same person re-registering on Cognito
  under that email walks back into the scope they were just shut out of. A row with no email
  has no stranger spelling to leave behind, so its entry is dropped as it always was, and a
  `@group` entry stays a group reference. `bb-auth-adm user rm` says "still kept out of
  APP/SCOPE by email EMAIL" where a grant says "also removed from" (`user_rm_report`); the
  GUI's removal goes through the same library call and says nothing about exclusions.

- **A scope names people, and that is the only place a grant is written.** The rule is against
  **duplication**: a user removed from the roster must not still walk in through a place. Since
  the grant is written on the side of the place and nowhere else, that takes two halves.
  `ScopeRecord::members` are **references to roster rows**, so a reference to a row that does
  not exist grants nothing; and `remove_user` sweeps every scope and group that named the row it
  removes. Without both, a deleted user who re-registers on Cognito would walk back in
  through a dangling reference.

- **`anonymous` and `authenticated` grant without listing anybody**, which makes them the two
  things an operator most often did not mean to leave open, and why `--check-access` and the startup
  banner print them by name. `anonymous` needs no credential at all, and a request that presents
  none is answered with a `204` that names nobody (one that presents a credential is still
  named, except a vetoed one: see `authorize_login`).
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
  rather than a scope that admits every credential there is. Blanket coverage is the explicit
  pattern `*://*/*`,
  which an operator has to mean in order to write. Because every scope is defined by URL patterns,
  `BB_AUTH_ORIGINAL_URL_HEADER` is **mandatory**: a request without it resolves to no application
  and is denied. See `UrlScope::allows` and `sane_url`.

### What a 204 hands nginx

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
  nginx. Three consequences that must not be lost:
  - **nginx must clear every *possible* identity header, not the configured ones.** The set of
    possible names is finite and code-defined (`IDENTITY_ATTRS`), precisely so that it *can* be
    cleared; an attribute that is off must still be cleared, or a client can send it, and turning it
    on later then needs no nginx change at all.
  - **The gate's own `X-Auth-Native-Username` is on that list too.** It names the Cognito username
    of the session, for a native sign-in only, and it is what the self-service page's profile edit
    acts on (§13.25), so it is forwarded by that one location and cleared by every other, the
    console included: a name the app (or the GUI) trusts has to be one only the gate wrote.
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
  `authorize_login` keeps them out of `decide`; otherwise `bb-auth-adm can` would stop
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
  separator, a collision with `LOGIN_URL_HEADER`, `NATIVE_USERNAME_HEADER` or another entry); a
  silently skipped claim is a header an application waits for forever, the same reflex as a fatal
  scope error. It must reserve **every possible identity header**, not the enabled ones, or
  turning an attribute on tomorrow collides with a claim configured yesterday and the discovery
  happens at runtime, on a header an application already trusts. It reserves the gate's own
  `X-Auth-Native-Username` for the same reason in the other direction: every spelling of
  `native_username` derives it, and a self-asserted claim arriving on the header the profile edit
  acts on would be a pool name an attacker typed. It must keep rejecting `RESERVED_CLAIMS`
  (`email`, `email_verified`,
  `token_use`, `identities`), because `Claims` takes those into typed fields and
  `#[serde(flatten)]` never sees a key a typed field took, so configuring one would propagate
  nothing, forever. And `compile_identity_attrs` is **fatal on an empty list**: an authorized `204`
  that names nobody breaks every application behind the gate, in silence. Emission stays
  **config-authoritative** (`profile_headers`): a cookie outlives an edit to the list, so what it
  carries is filtered against the *live* config, never emitted because the credential happened to
  have it.

### The endpoints, the pages and the redirects

- **`/auth/session` is not a gate, and it has exactly one door.** The door is
  `request_site`: a `cross-site` request, and a client that says nothing about where it came
  from, are refused before the body is read, because minting a session cookie for somebody
  else's form is login CSRF and `SameSite=Lax` says nothing about it (that attribute governs
  when a cookie is *sent*, never who may cause one to be *set*). `same-site` passes, since an
  operator's own sign-in page may sit on a sibling host and the cookie's `Domain` is the site
  anyway. Past the door it mints a cookie for any valid id_token whose identifier is
  not `denied` and has somewhere to go (a roster row, or any `authenticated` scope exists at all).
  The 403 there is a courtesy so an un-enrolled user hears it at the login page instead of bouncing
  off a 401 later — it must not tighten into an authorization check, and it must not try to guess
  the destination from `rd` (which is the post-login target, not the URL that triggered the login,
  and `safe_rd` may have already replaced it).

- **Sessions are stateless** — no server-side store. Any worker validates any cookie; a restart
  logs nobody out. Don't introduce per-session server state.

  The statelessness has one accepted cost, and it is stated here so nobody has to rediscover
  it: **a deletion does not end the sessions minted in the person's other browsers.** A cookie
  minted before a self-service deletion keeps verifying until it expires, `gate.session_ttl_secs`
  after it was minted, in every browser that holds one; the deleting browser is signed out by the
  deletion's own `303` (§13.32 §1). What that stale cookie reaches is narrow: a `restricted` scope
  admits nobody once the row is gone, every `denied` and `excluded` veto still matches the bare
  email, the API keys went with the row, and what is left is `anonymous` and `authenticated`,
  where the deleted person can register the same email again within a minute and walk into exactly
  the same scopes. That is why the gap is **accepted** (the user, 2026-11-26, who also kept the
  TTL at 30 days) and said on the sign-in page's notice: while self-signup is open it grants
  nothing a stranger cannot get in a minute. The premise is the thing to watch: if the pool
  becomes admin-create-only, or an `authenticated` scope starts to mean "people we once knew", the
  gap becomes real and the tombstone of §13.32 §2 (a time-bounded section of the access file, with
  an `iat` in the cookie's claims, which is no `COOKIE_VERSION` bump) is the design to build.
  Nothing here may close the gap with per-session server state, since that is this rule's own
  subject.

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
  `gate.authorized_hosts` (host globs in the settings file) is the *only* authority on
  redirect targets. Don't reintroduce a single base URL.

- **The gate never redirects a gated request; nginx does.** A `401` carries this area's login page
  in `LOGIN_URL_HEADER` (`X-Auth-Login-URL`) — the application's `login_url`, else
  `gate.login_url`, else this gate's own `/auth/login` (`login_url_for`, `global_login`) — and nginx lifts it with `auth_request_set` into a request variable, which is
  what stops a later `proxy_pass` clobbering `$upstream_http_*`. (`auth_request_set` does read a
  `401` subrequest's headers — verified against nginx 1.26.) nginx must route it through a `map`
  with the global URL as the default arm: an unset variable makes `return 302 $bb_login?rd=…` emit a
  *relative* `Location: ?rd=…`, i.e. a redirect loop back onto the gated path. This works because a
  `401` happens *on* a gated URL, so the application resolves, and it answers even when none of its
  scopes covers the URL: `login_url` says where this area's users sign in, not who may enter.
  **A logout does not**: `/auth/logout` is inside no application's area, so there is no per-area
  logout landing page and adding one would be a field the gate can never reach. The logout link supplies `?rd=` instead, through `safe_rd`; with no `rd` the browser
  goes to the login page, *not* to `safe_rd`'s caller-root default. **A link that says nothing falls
  back to `Referer` (`REFERER_HEADER`), on both browser endpoints and through one function**
  (`rd_candidate`, used by `logout_target` and `login_rd`). The order is who wrote each one: the
  `?rd=` for that link, and it means something specific; the `Referer` for nobody in particular,
  which is why it is **a backup and never the mechanism** (absent under
  `Referrer-Policy: no-referrer`, absent on a bookmark or a typed URL, trimmed to a bare origin
  cross-origin, and on a logout often naming a page the person may no longer see, which costs a
  `401` and one more hop). It is the only header of anyone else's the gate treats as a redirect
  target, so three rules keep it from being a new surface. It goes through the very gate that
  endpoint already applies to `rd` (`safe_rd` on the way out of a logout, `rd_url_allowed` before
  the sign-in page carries it, absolute-only there because that page resolves nothing against
  nginx), so a link from outside `gate.authorized_hosts` redirects nowhere. A rejected
  candidate is **discarded, not replaced**: whoever spoke first is answered on its own merits, or
  a crafted `?rd=` would get to choose which of the two is read. And an empty value counts as
  nothing said, which is what a template renders from an empty variable. Both the global and every application's
  `login_url` pass `compile_login_url` at load (printable ASCII, absolute https, no `@`, no `\`) —
  that is what makes emitting them into a header, a `Location:` and a page safe with no per-use
  check. It is deliberately **not** checked against `gate.authorized_hosts`: `read_access` reads
  no env, which is what lets `--check-access` run with no config, and moving the check to startup
  would turn a typo into a boot loop that `--check-access` never saw.

- **A refusal a login cannot fix is a `403`, and nginx answers it with a page rather than a
  hop.** `/auth/validate` has two refusals and the line between them is whether the gate
  **identified** the caller, never whether it authorized them: a `bbk_` key that resolved to a
  live row, an id_token that validated, or a session cookie whose signature held are all
  clients this gate knows, and a refusal after that is `403` (`respond_forbidden`, and the
  `identified` flag set where each credential is *verified*). Everything else is the `401`
  above. The reason is what nginx does with each. A `401` is a redirect to the login page, so
  answering one to somebody already signed in is a loop with no error in it anywhere: the
  login page hands back the cookie they already had, the gated URL refuses it again, and the
  deployment is working exactly as configured throughout. A `403` carries **no**
  `LOGIN_URL_HEADER`, and that omission is the rule rather than an oversight: there is nothing
  to redirect to, because signing in again cannot change the answer. An `anonymous` scope is
  still asked *before* either refusal, for the reason it outranks the `denied` veto: it grants
  with no credential at all, so a client refused there could simply have sent less. The gate
  serves the page itself at `/auth/denied` (`403`, so `error_page 403 = @bb_denied` keeps the
  status honest), and it must say no **without saying whether the URL exists**: a URL outside
  every application is refused exactly like one whose scope excludes this person, and telling
  a visitor which they hit is an enumeration oracle for anybody with any account at all. The
  operator's own page replaces it through `denied_url_for`, the application's `denied_url`
  before `gate.denied_url`, which is `login_url_for` one page along and is what makes a
  refusal page **per host**, since an area is an absolute prefix. That override is the one
  `302` this design does not push into nginx, and the reason is nginx: proxying to a host a
  file names would need a resolver and a second upstream, so the recipe stays a fixed
  `proxy_pass` to `/auth/denied` and the choice of page stays where every other hot value is.
  It cannot loop, because nothing gates the page it names.

- **The pages the gate serves are complete on their own, and the operator's stylesheet is an
  addition to one.** `/auth/login`, `/auth/callback`, the refusal page (`/auth/denied`) and
  the error page carry their palette
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
  source. The one other request value that page reads is its `notice` parameter, and it is a
  **closed set of one**: compared byte for byte against `LOGIN_NOTICE_ACCOUNT_DELETED`, a match
  swaps in two fixed `__BB_*__` strings (the deletion paragraph, and the attribute naming it as
  the email field's description) and any other value, or none, swaps in empty ones, so a code
  selects a fixed element and no byte of the query is reflected (§13.32 §1, §13.33 §2).
  **Every page carries a policy, and the policy is derived rather than written**:
  `PAGE_SECURITY_HEADERS` on every HTML response, and a `page_csp` of `default-src 'none'`
  plus exactly what that page uses, which is a per-response nonce (`csp_nonce`) on the two
  inline blocks, the origins the script talks to, the two `ui` URLs an operator may have
  set, and **`form-action`, which is the estate and not `'self'`**. That last one is derived
  too, from `gate.cookie_domain` through `estate_form_action`, and the reason it is worth a
  clause of its own is that the constant it replaced broke every Chromium login here for a
  day: these pages hand the id_token over with a real top-level form `POST`, the answer is a
  `302` onto another host, and Chromium checks the **redirect** against this directive and
  not just the URL the form names. The cookie domain is the right source rather than
  `gate.authorized_hosts` because `compile_settings` already refuses a file whose hosts it
  does not cover, so it is a superset by construction, and because a host pattern admits
  globs (`*bat75.com`) that no CSP source expression can express, which building the
  directive out of them would silently drop. It is not an authorization boundary and is not
  asked to be one: `safe_rd` still decides where a login may land. An empty domain keeps
  `'self'`, since a host-only cookie has no second host to survive to. The GUI stays `'self'`
  and must, because it only ever redirects to itself.
  This is the page in the estate most worth spending one on: its whole job is to hold a
  credential for a moment, and it is the one a GUI field can point at a third host. The
  practical cost is that an inline `style=` attribute or an `on…=` handler no longer applies
  on these pages, so arrangement goes in `AUTH_CSS` where it belonged anyway
  (`the_sign_in_page_carries_its_policy_and_the_nonce_it_names` pins the pairing, and
  `a_whole_login_lands_where_the_page_that_ran_it_permits` walks a whole login both ways in
  and requires the redirect the gate issues to be permitted by the page that submitted the
  form: every half of that was already tested separately and the login was broken anyway,
  which is what a suite of fixtures on one host could never see). **nginx must leave all three page locations ungated** (`auth_request off`, exactly as for
  `/auth/session` and `/auth/logout`): a sign-in page behind the gate answers a signed-out
  visitor with itself, forever, and a refusal page behind it is a refusal nobody can ever be
  shown. The refusal page and the error page go through one `respond_card`, which is
  `look_subs` plus that page's own values: the two differ by a template and three
  substitutions, and neither carries a script, so both get `script-src 'none'` rather than the
  nonce the other two need, and `form-action 'none'` rather than the estate, since each
  carries a link and a link is not a form submission.

- **Social sign-in is four settings that stand or fall together, and none of them is an env
  var.** `gate.oauth_domain` (the hosted UI, a bare host), `gate.social_callback_url` (the
  `redirect_uri`), and one `gate.social_buttons` entry per provider, each carrying its own
  `audience`: the app client that federates it. With none of them the sign-in page has no
  social section at all — no divider, no button, nothing hinting at a way in this deployment
  does not have — and `/auth/callback` is a `404`, because there is no OAuth leg to finish.
  **The app client is per button because Cognito federates per app client**: which identity
  providers a client offers is a property of that client, so two providers may live on two of
  them, and one value for all of them made that arrangement inexpressible. The price is that
  the login page must carry the client id on the button (`data-client-id`) and stash it in
  `sessionStorage` beside the PKCE verifier, because the callback is a second document and
  has to exchange its code with the same client the authorize call named.
  A **half-configured** file is refused by `compile_settings` rather than by the gate's
  startup: buttons with no domain or no callback URL, or a button with no app client, are
  errors on the way to disk, which is where an editor can still say so. What the file cannot
  check is whether Cognito agrees with it — that the callback URL is registered byte for byte
  on each of those clients, and that each client really federates its provider — and it does
  not try: whoever clicks a button that Amazon disagrees with is told `redirect_mismatch`, in
  Amazon's words, on Amazon's page.

- **`safe_rd` guards the post-login redirect** against open-redirect + response-splitting. **Every**
  candidate — relative, absolute, or the no-`rd` default — goes through the same `rd_url_allowed`
  gate, so a spoofed caller origin still can't escape. The no-`rd` default is `gate.landing_url`
  when one is set, else the caller's root, and `compile_settings` refuses a landing page whose
  host `gate.authorized_hosts` does not cover, so the load-time check and this one cannot
  disagree. Rejected ⇒ fall back to `gate.login_url` (or the gate's own page, which is what
  empty means).
  The gate is https-only and rejects `//`, `/\`, control bytes incl. CR/LF, userinfo `@`,
  backslashes, and lookalikes like `evilbadbat75.com` / `badbat75.com.evil.com` (a pattern's literal
  dot is what rules those out; `*.x.com` also does not match the apex `x.com`). Any new use of
  request-supplied data in a header/redirect must stay behind this guard.

### Dependencies and the build

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

- **Release profile is speed-optimized** (`opt-level=3`, LTO, `panic="abort"`, stripped). The user
  chose speed over size on 2026-11-23; leave it that way unless asked.

### Deploy and packaging

- **Target layout is a tree**: `/opt/bb-auth/{bin/bb-auth, bin/bb-auth-adm, bin/bb-auth-web,
  etc/bb-auth.env, etc/bb-auth-web.env, share/*.example, var/lib/{access,settings}.json}`, units at
  `/usr/lib/systemd/system/{bb-auth.service, bb-auth-web.service, bb-auth-reload.{path,service}}`
  (where a **package** must put them; `/etc/systemd/system` is the admin's, and a copy there
  *overrides* the packaged one forever, which is why both postinsts and `verify.sh` report one
  rather than remove it).
  **The gate** writes nothing *under its own prefix*, so that whole prefix is `ReadOnlyPaths` and
  no `StateDirectory` is needed despite the `var/lib` name — `bb-auth-adm` writes that file from
  *outside* the unit's namespace, as root, and the hardening does not apply to it. The one thing
  it does write is the audit, and it is `LogsDirectory=bb-auth` (`/var/log/bb-auth`, mode 0750,
  owned by the service user) rather than a second hole in `/opt/bb-auth` for exactly that reason:
  a gate that could write `var/lib` could rewrite the access list it enforces, which is a far
  larger hole than an audit is worth. The GUI reads that directory through the `bb-auth` group it
  already belongs to, and never writes it: an audit an administrator can edit is not an audit.
  It runs hardened and non-privileged
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
  stale file. The examples deliberately name `<your-access.json>` and not a path in this
  repository: `deploy/access.json` is gitignored, is whatever a past session left there, and
  on at least one checkout was a pre-1.0 document that parses as JSON and that the gate
  refuses outright. `deploy.ps1` now checks its `version` locally, and `deploy.sh` runs the
  gate's own parser on it before anything is installed, so a stale file costs a second rather
  than a red deploy on a mutated host. `bb-auth-adm` is installed to the host precisely so the edit can happen where the
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

- **A release runs the tests and says which commit it is.** `scripts/package.sh` runs
  `cargo test --locked` before it builds (`--skip-tests` to repackage bytes already tested)
  and refuses an uncommitted tree (`--allow-dirty` to mean it); both scripts export
  `BB_AUTH_BUILD` as the **commit alone** (`g0a8d129`, `-dirty` when the tree was not
  committed), which `bb_auth_core::BUILD` reads at compile time and `version_id()` joins to
  cargo's own version: `v1.99.1-g0a8d129`, what `--version` prints, both banners open with
  and the GUI's footer carries. Not `git describe`, which anchors on the last **tag** and so
  opened with `v1.0.0` on every untagged candidate. A plain `cargo build` sets nothing and
  reports `v<version>-unknown`, which is the honest answer for a binary nobody released. The reason is one incident: a `.deb`
  version reads `1.99.1-1` for a tagged release, a dirty checkout and a hand-patched
  experiment alike, and the test that catches a gate with no crypto provider was being run by
  a human remembering to. **`bb-auth --self-test`** is the other half: the offline RS256
  verification a login performs, with no env and no network, and `scripts/verify.sh` runs it
  on the host, because every other check that script has is green on exactly that build.
- **`scripts/deploy.sh` is what a package may not do**, and nothing else: validating a staged
  `access.json` with the gate's own parser **before** `dpkg -i`, out of the package about to be
  installed (it fails closed either way, but a check that runs afterwards means a red deploy on
  a host that has already been mutated); `dpkg -i` in one
  transaction (not `apt install`, which declines to reinstall an equal version, so a rebuilt
  `1.99.1-1` would silently not deploy); recording what it replaced under `share/previous/`,
  because dpkg keeps no archive and a rollback needs somewhere to start; installing the staged
  `access.json`, with the owner and mode the live
  file already had; and running `scripts/verify.sh`. It deliberately does **not** move aside a
  unit an admin put in `/etc/systemd/system`, which shadows the packaged one forever:
  that directory is the admin's, so the postinsts and `verify.sh` *report* the shadow and the
  admin decides, which is also what keeps `verify.sh` read-only. `deploy.ps1` builds the packages
  (`package.sh` first, always), ships them with those two scripts, and runs `deploy.sh` as root
  there. Keep the host-side logic in those files rather than in a string quoted through
  PowerShell into `ssh` into a remote shell, and keep `verify.sh` read-only so it stays runnable
  by hand on a host nobody is deploying to.

## Config & deploy notes

The rules that govern a deploy are **in the invariants above**, under
[Deploy and packaging](#deploy-and-packaging): a rule about what a package may not do is
as much an invariant as a rule about what a scope may not grant, and keeping them here
meant the file's own instruction to "read the invariants" pointed at four fifths of them.
What is left below is configuration, which is a reference rather than a rule.

- Config is env vars (`Config::from_env`; missing required vars are a fatal exit) **plus the
  settings file** (`compile_settings`) for the settings that must be hot. Which ones those
  are, and the three-part rule that decides it, is stated once in the invariants above and
  deliberately not counted again here: the two copies had already drifted to "ten" and
  "six". The only secret of the gate is `BB_AUTH_HMAC_KEY` (≥32 bytes), and it is in the env
  file; the GUI's env file holds one of its own, `BB_AUTH_WEB_PROXY_SECRET`, which the install
  generates and never prints (docs/ARCHITECTURE.md §13.3). That file also carries the
  restart-only `BB_AUTH_WEB_WORKERS` (default 8, accepted 1 to 64, anything else a fatal startup
  naming the variable): it bounds concurrent request handlers, not connections, so too few shows
  as latency for everybody, and the ruler for sizing it is how many slow handlers may be in
  flight while page views still get through, not the core count (docs/ARCHITECTURE.md §13.13).
  Full reference:
  [deploy/bb-auth.env.example](deploy/bb-auth.env.example),
  [deploy/bb-auth-web.env.example](deploy/bb-auth-web.env.example),
  [deploy/settings.example.json](deploy/settings.example.json) and `docs/ARCHITECTURE.md` §8/§8a.

## Working from the plan

- Take the first open step unless the user says otherwise. Split it if it is too big for one sitting.
- The plan can change. The coordinator or the user can change any part of it when needed: steps, order,
  requirements or Definition of Done. Other agents propose changes to the coordinator. The commit says
  why, and the coordinator tells the user whenever a requirement changes.
- If a requirement is added, make sure a step covers it.
- A step is done only when it meets the Definition of Done in `PLAN.md` as well as its own "Done when".
- Steps in `PLAN.md` are only open work. When a step is done, remove it, and update the requirements'
  "State" and "Where things stand" if they changed.
- Do this in the same commit as the work. The commit message says what was closed and how it was
  checked, so `git log` is the record of closed work. Do not keep a done list in the plan.
- New work that comes up goes in the plan, in its place in the order. A step that turns out wrong gets
  rewritten, not worked around.

## Agent commands

Agents run the checks the table under [Commands](#commands) matches to their change, plus:

```powershell
cargo clippy --all-targets
cargo fmt --check
```

The `tester` runs the whole board once, on `main` after the merge and before a release, when the
coordinator asks for it: `cargo test`,
`node e2e/run.js`, `cargo doc --no-deps`, and the cfg(unix) tests under WSL.

## Layout

See [What lives where](#what-lives-where) and [Where documentation lives](#where-documentation-lives).

## Rules

**Test first, always.** Write a failing test, run it and see it fail, then write the code. A change
without a test that failed first is not done. Tests never touch real systems or real data.

**Keep it simple.** Minimum that solves the problem, no speculative options or abstractions.

**Facts need a source.** Check commands, APIs and limits against official documentation or a real run.
In the docs, keep what was measured, read in a source and assumed apart. Mark guesses as guesses.

**Displayed text.** Text the admin GUI shows goes through the `K` translation table in
`src/bin/bb-auth-web.rs`, and the pages' text lives in `src/assets/*.html`, never inline in logic. Logic
must not depend on that text.

## Actions with real effects

- What counts here: a deploy (`scripts/deploy.ps1`, `scripts/verify.sh` on a host), a live host's access
  file, settings file or env file, the Cognito user pool, and any real `bbk_` key or HMAC key.
- Reading is fine. Anything that changes the real thing needs the user's go-ahead each time.
- Agents may be blocked from running some commands. Give the user the exact command to run, and say what
  it does, how long it takes and what result to expect.
- A command must undo what it changed by itself, wherever it can.

## Skills

Each role has a skill in `.agents/skills/` in the standard `SKILL.md` format; `.claude/skills` is a
symlink to that directory.

- A skill says how its role does the work in this project. Rules stay in this file. It has two sections:
  - "How to": commands that work, conventions, where things are, procedures. Written as instructions.
    Add to it when you find out how something is done here, and change it when that changes.
  - "Pitfalls": traps met so far that a careful agent would still fall into, one line each. Add one when
    something went wrong in a way that was not obvious.
- When a pitfall becomes a way of working, rewrite it as a step in "How to" (or as a rule in this file)
  and remove it from "Pitfalls".
- Only what is specific to this project or its tools. General good practice does not go in a skill.
- An agent can update its own skill. The coordinator can update any of them.
- Keep them short, and remove what stops being true. Say why in the commit, like any other change.

## Roles

Role definitions live in `.opencode/agents/`; `.claude/agents` is a symlink to that directory, so
OpenCode and Claude Code read the same files. Keep the frontmatter to the fields both accept (`name`,
`description`, `mode`), and write role limits in the body rather than in harness-specific tool lists.

- `coordinator`: plans and sequences the work, checks each result. The default agent for a session, set
  in `.claude/settings.json` and `.opencode/opencode.json`.
- `architect`: designs the software and infrastructure architecture, in `docs/ARCHITECTURE.md`. Writes no
  code.
- `designer`: the UX/UI expert. Designs the pages' interface (layout, interaction, wording,
  accessibility) to established usability practice, in `docs/ARCHITECTURE.md`, and reviews the
  screenshots of the result before a slice closes. Writes no code.
- `tester`: writes the failing tests.
- `coder`: makes them pass.
- `docs`: keeps the documentation true.

Cycle: coordinator takes the next step from `PLAN.md` and picks one small slice, architect designs
it when it changes the architecture, designer designs it when it changes what a person sees or does,
tester writes tests and shows them red, coder turns them green, coordinator reruns everything,
designer reviews the screenshots when the slice changed a page, docs updates what changed.
