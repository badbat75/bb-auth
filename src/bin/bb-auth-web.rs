//! bb-auth-web — a server-rendered admin GUI over a bb-auth **access file**
//! (`BB_AUTH_USERS_FILE`, a.k.a. users.json).
//!
//! What `bb-auth-adm` shows on a terminal, this shows in a browser: the roster, the url
//! groups and who references them, the sites in the order that decides which one answers,
//! the `denied` veto, every api key's expiry, and the `can EMAIL URL` tester — answered, as
//! there, by the gate's own [`decide`]. And what `bb-auth-adm` *edits*, this edits: full
//! CRUD over every section, through the library's editing core and through nothing else.
//!
//! **Deployment.** Its own hardened unit (`deploy/bb-auth-web.service`) under a dedicated
//! `bb-auth-web` user, its own operator-owned env (`deploy/bb-auth-web.env.example`), and
//! `deploy/bb-auth-reload.path`, which turns any rewrite of the access file — this one's or
//! a `bb-auth-adm` over SSH — into a `systemctl reload bb-auth`. Optional in the deploy just
//! like `bb-auth-adm`: installed iff it was staged. Installing it is also what moves the
//! access file to `bb-auth-web:bb-auth 0640`, because the writer restores the owner it finds
//! and an unprivileged one may only chown to a uid it already owns and a group it is a
//! member of. See the README and `scripts/deploy.sh`.
//!
//! # Trust model
//!
//! This is **just another application bb-auth fronts**, and it is protected exactly the way
//! any other one is:
//!
//! * it binds **loopback** (`BB_AUTH_WEB_LISTEN`, default `127.0.0.1:8091`) and speaks plain
//!   HTTP, so nothing reaches it except through the reverse proxy;
//! * nginx gates its URL with `auth_request` against the gate, and injects the authorized
//!   email with `auth_request_set` + `proxy_set_header X-Auth-Email` — the contract
//!   documented on `bb-auth`'s `IDENTITY_HEADER`, unchanged and unextended;
//! * this binary reads that header and nothing else. It validates no token, holds no secret
//!   and mints no cookie — there is no credential here to steal.
//!
//! Trusting the header is sound for one reason only: `proxy_set_header` overwrites whatever
//! the client sent, on **every** gated location, and the service is unreachable except
//! through nginx. Both halves are load-bearing. Exposing this port directly, or gating it
//! from a location that forgets the `proxy_set_header`, would let anyone name themselves —
//! so a missing header is a `401` here rather than an anonymous session, which turns a
//! broken deployment into an error page instead of a silent open door.
//!
//! And the header is not the last word: the email must also be on **`BB_AUTH_WEB_ADMINS`**.
//! That allowlist is deliberate defense in depth: a `public_auth` site covering the GUI's
//! URL would otherwise open the admin surface to any Cognito account. It is required, and
//! must be non-empty — empty must never mean "everyone".
//!
//! Both checks are **route-global** and run before the router: there is no path — not a
//! `404`, not a `POST`, not a broken access file — that answers anything to someone nginx
//! did not vouch for and `BB_AUTH_WEB_ADMINS` does not name.
//!
//! # Mutations
//!
//! Every write goes through [`AccessWrite`], the same door `bb-auth-adm` uses: `prepare`
//! compiles the exact bytes with the gate's own parser, `commit` writes the bytes it
//! compiled, and the raw writer is private to the library. So this binary *cannot* save a
//! file the gate would reject — a rejected access file is a fatal startup, and under
//! `Restart=on-failure` a boot loop. A refusal is shown **verbatim**, in the English the
//! library says it in, on the form that caused it and with the submitted values still in
//! the fields; nothing is written on any error path.
//!
//! Four rules hold on every mutating route, and between them they are the whole mechanism:
//!
//! * **A `GET` never mutates.** Every mutation is a `POST`, to the same path that renders
//!   its form. The only redirects a `GET` performs are the two preference ones (`?lang=`,
//!   `?theme=`), which set a display cookie and change nothing else.
//! * **Strict same-origin on every `POST`** ([`csrf_ok`]). If `Sec-Fetch-Site` is present it
//!   must say `same-origin`: the browser sets it, a page cannot, so where it exists it is
//!   the whole answer. Otherwise `Origin`'s **host** must equal the `Host:` header's —
//!   hosts, not schemes, because this binary speaks plain HTTP behind a TLS-terminating
//!   nginx and would have to compare its own `http` against the browser's `https`, failing
//!   every honest request. Neither header present ⇒ refused with a `403`: that is not a
//!   browser submitting a form. There is deliberately **no CSRF token** — one needs
//!   per-session server state, which this binary does not have and the gate does not have
//!   either, and which nothing else here would use.
//! * **Optimistic concurrency.** Every form carries a hidden `rev`: the sha256 of the exact
//!   bytes of the access file as it was read to render that form. The `POST` re-reads the
//!   file and compares; a mismatch is a `409` that writes nothing and says to reload. This
//!   is what turns the lost-update race between this GUI and a `bb-auth-adm` over SSH — the
//!   two are expected to be used on the same file, the CLI is installed on the host for
//!   exactly that — into a visible error instead of a silently discarded edit.
//! * **POST-redirect-GET.** A successful mutation answers `303` to the page it belongs to
//!   with `?msg=<key>`, so a reload cannot repeat it. Only *known* keys render ([`Msg`]);
//!   an unknown one is ignored, and no free text ever travels through the query string.
//!
//! **Minting is the one exception to the redirect**, and deliberately: `key add` and
//! `key rotate` render their result page directly, because it carries the `bbk_` bearer,
//! which is shown once and stored nowhere. The order is the library's — [`SealedKey`]
//! opens only against the [`Written`] receipt of a completed write — so a bearer cannot be
//! handed out for a file that never landed. It never reaches a log line or a URL. A
//! re-submitted mint form cannot double-mint either, and pleasantly it is the `rev` rule
//! that stops it: the first write changed the file, so the second `POST` carries a stale
//! fingerprint and is refused. That refusal gets a page of its own
//! ([`page_mint_conflict`]): the generic `409` would blame another writer and advise
//! redoing the change — which here would mint a second key — where the truth is that the
//! key was created and a lost bearer's remedy is `key rotate`.
//!
//! Destructive actions (`user rm`, `key rm`, `key rotate`, `site rm`, `url-group rm`,
//! `deny rm`) are a `GET` confirmation page whose `POST` does the deed — the no-JavaScript
//! form of "are you sure", and the only way to be sure a link never deletes anything.
//! Each successful mutation writes one audit line to stderr ([`audit`]): who, the verb as
//! `bb-auth-adm` spells it, and the target's name — never a bearer, never a hash, never a
//! submitted value beyond the name.
//!
//! An edit is not live until the gate re-reads the file: `systemctl reload bb-auth`. This
//! binary cannot send that signal (it is not the gate, and does not run in its namespace),
//! so every page says so in the footer.
//!
//! # Configuration
//!
//! | Var | Required | Default | Meaning |
//! |-----|----------|---------|---------|
//! | `BB_AUTH_USERS_FILE` | yes | — | the access file to render. Same name, same meaning as the gate's |
//! | `BB_AUTH_WEB_ADMINS` | yes | — | comma-separated emails allowed in. Empty is fatal |
//! | `BB_AUTH_WEB_LISTEN` | no | `127.0.0.1:8091` | bind address. Keep it on loopback |
//! | `BB_AUTH_WEB_BASE_PATH` | no | *(empty)* | URL prefix nginx mounts the GUI at, e.g. `/admin` |
//! | `BB_AUTH_WEB_DEFAULT_LANG` | no | `en` | `en` or `it`, when the request expresses no preference |
//!
//! Read once at startup, like the gate: a change needs a restart. A missing required var is
//! a fatal exit, in the same words and for the same reason — there is no safe default.
//!
//! # The file is read fresh on every request
//!
//! No cache, no watch, no server-side state: every page calls [`open_access_file`], renders,
//! and drops the result. The file is small, and always showing the live truth *is* the
//! feature — an edit made over SSH with `bb-auth-adm` a second ago is on the next page load,
//! with no reload signal and no coherency question between this binary and the gate. It also
//! keeps the process trivial: nothing here can go stale, and a restart loses nothing. The
//! `rev` fingerprint is what makes that safe for writing too: state a form needs about the
//! file travels in the form, not in the process.
//!
//! Two consequences worth knowing. Compiling is what emits the parser's warnings, so a file
//! that warns will warn once per request on this service's stderr — noisy, and the price of
//! having exactly one parser. And when the file does not compile at all, this GUI does not
//! die: it renders the library's message verbatim, which is the sentence an operator needs
//! ("the gate would reject this file as it stands"), on a page whose navigation still works.
//!
//! # Settings: the language and the theme
//!
//! The two live together in one **Settings** menu at the right of the header ([`shell`])
//! because they are the same kind of thing and the only two of it: preferences that change
//! how this GUI looks to one browser and touch neither the access file nor anybody else.
//! Anything that did touch the file would be a form on a page, not a menu in the chrome.
//!
//! The menu is a `<details>` disclosure, which is what a menu is when there is no
//! JavaScript to open one, holding a `GET` form with the two list boxes. Picking an option
//! applies it there and then, through the one handler this binary emits
//! ([`SETTINGS_ONCHANGE`]) — and with scripting off, through a `<noscript>` submit button
//! that costs one click and sets both preferences in the same trip. Either way the form
//! puts `?lang=` and `?theme=` on the current URL and the handler does with them what it
//! always did: turn each into a cookie ([`LANG_COOKIE`], [`THEME_COOKIE`]) and redirect the
//! parameter back out of the URL, so a bookmark or a reload does not carry a preference
//! around forever. The rest of the query goes back into the form as hidden fields, which is
//! what keeps a `can` result on screen across a preference change.
//!
//! **Language** is English and Italian, from a table compiled into the binary ([`t`]), plus
//! `Auto`: the choice to make no choice, which resolves per request against the browser's
//! `Accept-Language` and is what a session that never chose has always been getting (see
//! [`LangPref`]). Prose and labels are translated; the **file's vocabulary never is** —
//! `public_auth`, `authorized_urls`, `url_groups`, `sites`, `denied`, `bbk_`, an `@group`
//! reference, and every name, email and URL pattern read the same in both, because they are
//! what an operator will type into `bb-auth-adm` and into the file itself. Library error
//! messages render verbatim, in the English the gate and the CLI already say them in.
//!
//! **Theme** is light, dark or system, and [`Theme::System`] is the floor for the same
//! reason `Auto` is: an existing session's page does not change appearance until someone
//! chooses. One CSS attribute selector, and no script at all, is what repaints the page; see
//! [`CSS`] for the two-arm dark rule that makes an explicit choice win over the OS.

use bb_auth_core::{
    add_api_key, add_application, add_denied, add_scope, add_user, add_user_email, add_user_group,
    app_mut, app_pos, decide, edit_urls, format_date, group_ref, key_expiry, key_mut, move_scope,
    norm_email, now, open_access_file, remove_api_key, remove_application, remove_denied,
    remove_scope, remove_user, remove_user_email, remove_user_group, rename_application,
    rename_scope, request_url, rotate_api_key, scope_mut, scope_pos, sha256_hex, user_group_mut,
    user_group_refs, user_label, user_pos, user_refs, Access, AccessFile, AccessWrite, ApiKeySpec,
    AppSpec, Decision, ScopeSpec, SealedKey, Subject, UserSpec, Written,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use std::io::Read;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

/// Request header naming the authenticated user, injected by nginx after the gate
/// authorized the request. The other end of `bb-auth`'s `IDENTITY_HEADER` contract — a fixed
/// constant there, so a fixed constant here.
const IDENTITY_HEADER: &str = "X-Auth-Email";

/// Cookie remembering the language choice. It carries no identity and no capability: the
/// worst an attacker who reads or rewrites it achieves is a page in the other language.
/// That is why it is not `Secure` — this binary speaks plain HTTP on loopback and cannot
/// know the scheme the browser used, and a display preference is not worth a flag that
/// would be a lie about half the deployments.
const LANG_COOKIE: &str = "lang";

/// Cookie remembering the theme choice. Same reasoning as [`LANG_COOKIE`]: it carries no
/// identity and no capability, so the worst an attacker who reads or rewrites it achieves is
/// a page in the wrong palette. Not `Secure`, for the same reason too.
const THEME_COOKIE: &str = "theme";

/// A year. The preference is a preference, not a session. Shared by every preference cookie:
/// today [`LANG_COOKIE`] and [`THEME_COOKIE`], both set through [`respond_preference_redirect`].
const PREFERENCE_COOKIE_MAX_AGE: i64 = 31_536_000;

/// **The only JavaScript this GUI emits**, on the two Settings list boxes and nowhere else.
///
/// A `<select>` has no native way to say "I changed, act on it", so applying a preference the
/// moment it is picked needs a script — one expression of it. It is an *enhancement*: with
/// scripting off, the `<noscript>` submit button [`shell`] renders instead does exactly the
/// same thing, one click later, and that path sets **both** preferences in one trip where
/// this one sets whichever was just touched. Nothing on any page depends on it, and no other
/// element in this binary carries a handler of any kind (`the_page_carries_one_handler_and_no_script`
/// pins that, and `nojs.js` pins it in a real browser).
///
/// `this.form.submit()` and not `requestSubmit()`: the older method is universal, and it
/// submits without firing the submit event, which is exactly what is wanted here since there
/// is no handler for one. The one way to break it is a control named `submit` shadowing the
/// method on the form, which would need a query parameter literally called `submit` (see
/// [`preserved_query`]) — no link this GUI builds has one, and the failure mode is a menu
/// that stops applying on change, not a broken page.
const SETTINGS_ONCHANGE: &str = "this.form.submit()";

/// Blocking request threads. Fixed, and deliberately not an env var: this serves the
/// handful of people on `BB_AUTH_WEB_ADMINS`, not the public.
const WORKERS: usize = 2;

/// The whole stylesheet, inlined. No external request of any kind — no font, no script, no
/// image — so the page needs nothing beyond this constant on a laptop, on a phone, or on a
/// host with no route to the internet. Below 640px the layout adapts (a compact header, table
/// rows stacked into cards) but ships not one byte more to get there.
///
/// Light and dark come from `prefers-color-scheme` over a handful of custom properties, and
/// an explicit choice overrides it through a `data-theme` attribute [`shell`] puts on `html`
/// (see [`Theme::attr`]) and a selector that outranks the media query. There is still no
/// script on any page: not for a form, not for a confirmation, not for reordering a site,
/// not for opening the Settings menu, and not for the theme it sets either. The override is
/// CSS specificity, nothing more, which is why the dark token list below is written twice
/// and kept in sync by hand. (The one handler in the binary, [`SETTINGS_ONCHANGE`], saves a
/// click on a list box and paints nothing.)
const CSS: &str = r"
*,*::before,*::after{box-sizing:border-box}
:root{color-scheme:light dark;
  --bg:#f7f7fa;--panel:#fff;--fg:#1c1c21;--muted:#65656f;--line:#e2e2ea;
  --accent:#3350c8;--ok:#1c6b40;--warn:#8a5a00;--bad:#b3261e;--chip:#eeeef4;--on-accent:#fff;
  /* Shape and small-text tokens, not colour: a radius or a font-size does not change with
     the theme, so unlike every token above these are defined exactly once, here, and must
     never be copied into either dark block below. */
  --r-box:10px;--r-ctl:7px;--r-pill:999px;--fs-sm:.85rem}
/* An explicit light choice needs no different tokens (the block above already holds them),
   only color-scheme narrowed from the System default's `light dark` to plain `light`, so the
   browser's own scrollbars and form controls stop following a dark OS. */
:root[data-theme=light]{color-scheme:light}
/* Dark tokens, written twice on purpose: once here for System (data-theme absent, the only
   state an unvisited browser is ever in) so the OS still drives, and once below for an
   explicit dark choice on a light OS. `:not([data-theme=light])` is what lets an explicit
   light choice win over a dark OS instead of this arm re-applying dark anyway. Keep both
   lists in sync by hand; there is no third place to define them once without JavaScript to
   flip a class. */
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#16161b;--panel:#1e1e25;--fg:#e8e8ee;--muted:#9a9aa8;--line:#30303b;
  --accent:#8aa0ff;--ok:#5fd08a;--warn:#e3b341;--bad:#ff8a80;--chip:#292933;--on-accent:#16161b}}
/* Kept in sync with the media-query block above by hand; see its comment. This is the arm
   that wins on a light OS once the operator picks dark explicitly, and it narrows
   color-scheme the same way the light override above does, only to `dark`. */
:root[data-theme=dark]{
  --bg:#16161b;--panel:#1e1e25;--fg:#e8e8ee;--muted:#9a9aa8;--line:#30303b;
  --accent:#8aa0ff;--ok:#5fd08a;--warn:#e3b341;--bad:#ff8a80;--chip:#292933;--on-accent:#16161b;
  color-scheme:dark}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;font-size:.92em}
header.top{background:var(--panel);border-bottom:1px solid var(--line);padding:10px 16px}
/* The gap between the header's three parts (the brand, the tabs, the Settings menu). It has
   to beat the tabs' own 4px by enough to be read as a boundary: every control in the row
   looks the same on purpose, so space is the only thing left that says where one group ends,
   and separating them with a rule or a tint would put back exactly the differentiating trait
   the pill object exists to remove. */
.bar{max-width:1000px;margin:0 auto;display:flex;flex-wrap:wrap;gap:20px;align-items:center}
.brand{font-weight:600;letter-spacing:.02em}
a.brand{color:inherit;text-decoration:none}
a.brand:hover{text-decoration:underline}
.brand .v{color:var(--muted);font-weight:400;font-size:.85em;margin-left:6px}
nav{display:flex;flex-wrap:wrap;gap:4px;flex:1 1 auto}
main{max-width:1000px;margin:0 auto;padding:18px 16px 40px}
h1{font-size:1.25rem;margin:0 0 4px}
h2{font-size:1rem;margin:26px 0 8px}
/* A group's own heading, inside a .panel that already carries top padding: the panel's
   padding and this h2's own top margin would otherwise stack. */
h2.tight{margin-top:0}
p.lede{color:var(--muted);margin:0 0 18px}
/* A lede introducing a subsection (h2), not the page (h1): same voice, one size down so it
   doesn't compete with the page's own lede above it. */
p.lede.sub{font-size:.92em;margin:0 0 14px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--r-box);
  padding:14px 16px;margin:0 0 16px;overflow-x:auto}
/* Modifiers for a panel that is also a state, reusing .flash/.err's left-bar treatment
   (a 4px accent border over the plain 1px one) without duplicating panel's own box model.
   `color` is reset to `--fg` on purpose: `bad`/`warn`/`ok` are also bare utility classes
   below (`.bad{color:var(--bad)}` etc.) and a panel carries its state word as one of its
   two classes, so without this the inherited color would tint every word inside it, not
   just the border. */
.panel.ok{border-color:var(--ok);border-left:4px solid var(--ok);color:var(--fg)}
.panel.warn{border-color:var(--warn);border-left:4px solid var(--warn);color:var(--fg)}
.panel.bad{border-color:var(--bad);border-left:4px solid var(--bad);color:var(--fg)}
table{border-collapse:collapse;width:100%;min-width:420px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;font-size:var(--fs-sm);text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}
/* Was --chip: the same colour a hovered pill fills with, so a row action's hover was
   invisible on exactly the two pages that have rows (users, api_keys). --bg leaves --line
   free for the pill's own hover border below. */
tbody tr:hover{background:var(--bg)}
ul.plain{list-style:none;margin:0;padding:0}
ul.plain li{padding:2px 0}
ol.sites{margin:0;padding-left:22px}
ol.sites > li{margin:0 0 14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,160px));gap:10px;
  margin:0 0 18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r-box);
  padding:14px 16px}
a.card{display:block;color:inherit;text-decoration:none}
a.card:hover{border-color:var(--accent)}
.card .n{font-size:1.6rem;font-weight:600;line-height:1.1}
.card .l{color:var(--muted);font-size:var(--fs-sm)}
.tag{display:inline-block;padding:1px 7px;border-radius:var(--r-pill);background:var(--chip);
  font-size:var(--fs-sm);white-space:nowrap}
.tag.bad{background:var(--bad);color:var(--on-accent)}
.tag.warn{background:var(--warn);color:var(--on-accent)}
.tag.ok{background:var(--ok);color:var(--on-accent)}
.muted{color:var(--muted)}
.bad{color:var(--bad)}
form.can{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end}
form.can label{display:flex;flex-direction:column;gap:4px;flex:1 1 240px;font-size:var(--fs-sm);
  text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
/* One rule for both kinds of field, so the Settings menu's list boxes are the same object as
   every text field in the app: same border, same radius, same padding, same measure. A
   select still draws its own arrow, which is the browser's job and the one part of a control
   that must look native. */
input[type=text],select{font:inherit;padding:7px 9px;border:1px solid var(--line);
  border-radius:var(--r-ctl);background:var(--bg);color:var(--fg);width:100%}
/* Per-field measure, keyed off the wire field name text_field() stamps onto the input as
   `f-<name>` (see its doc comment): a short token stays narrow, an email/name/URL stays
   readable but never balloons to the panel's full width. Both still shrink below their
   measure on a narrow viewport because width:100% is left standing. */
input.f-id,input.f-duration{max-width:14ch}
input.f-email,input.f-name,input.f-login_url{max-width:40ch}
input::placeholder{color:var(--muted);font-style:italic}
/* The one field a refusal is attributed to (see Refusal): border only, so radius, padding
   and background stay exactly what the plain field has, and the focus ring above (which
   draws an outline, not a border) still shows plainly over it. */
input[type=text].invalid,textarea.invalid{border-color:var(--bad)}
/* The border is 1px solid var(--accent), invisible against the button's own fill, which is
   the point: it is what makes a filled submit and the outlined cancel pill beside it land on
   exactly the same footprint as .pill below (same border width, same radius, same padding
   step). A class selector already outranks this element selector regardless of source order,
   so the two reorder buttons on the sites page (plain buttons carrying class pill) take the
   pill shape either way; .pill still follows button here so the object reads as built on top
   of it. */
button{font:inherit;padding:6px 14px;border:1px solid var(--accent);border-radius:var(--r-pill);
  background:var(--accent);color:var(--on-accent);cursor:pointer}
button.danger{background:var(--bad);border-color:var(--bad)}
p.primary{margin:16px 0 20px}
.verdict{font-size:1.05rem;font-weight:600;margin:0 0 6px}
.verdict.yes{color:var(--ok)}
.verdict.no{color:var(--bad)}
footer{max-width:1000px;margin:0 auto;padding:0 16px 30px;color:var(--muted);font-size:var(--fs-sm);
  display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between}
form.edit label{display:block;margin:0 0 14px}
form.edit .lbl{display:block;font-size:var(--fs-sm);text-transform:uppercase;letter-spacing:.04em;
  color:var(--muted);margin:0 0 4px}
form.edit .hint{display:block;color:var(--muted);font-size:var(--fs-sm);margin:4px 0 0}
textarea{font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;font-size:.92em;
  padding:7px 9px;border:1px solid var(--line);border-radius:var(--r-ctl);background:var(--bg);
  color:var(--fg);width:100%;line-height:1.5}
form.edit .radio{display:flex;gap:8px;align-items:baseline;margin:0 0 6px}
form.edit .radio input{margin:0}
.actions{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin:18px 0 0}
/* The pill: one shape for every small control that used to style itself where it happened
   to be used: a nav tab, the Settings menu's own trigger, a row's edit/rotate/remove, the two
   site reorder buttons, a form's cancel. .pills is the group (the flex row that holds them);
   .pill is the member. Nothing at a call site is allowed to say how a pill looks any more,
   which is why no style= attribute survives anywhere in this file. Every pill looks the same
   at rest, on purpose: the only things allowed to change one are its state (selected, hovered,
   disabled) and the one case where the click's consequence differs in kind (rm). */
.pills{display:inline-flex;flex-wrap:wrap;gap:6px;align-items:center}
/* A table cell's action group must not wrap: wrapping is exactly what broke the api_keys
   row's three actions onto two ragged lines inside a narrow right-aligned cell. The panel
   already scrolls (overflow-x:auto) if a row's actions ever outgrow the column, so nowrap
   here costs nothing. */
td.pills{display:flex;flex-wrap:nowrap;justify-content:flex-end}
/* The resting box is currentColor, not --line: the old hairline measured about 1.3 to 1
   against the panel, which is why these did not read as controls at all before this pass.
   Every pill carries the box, with no exception, so a nav tab, a language or theme choice,
   a row action, a reorder button and cancel all look identical at rest. */
.pill{display:inline-flex;align-items:center;font:inherit;font-size:var(--fs-sm);
  line-height:1.45;padding:3px 10px;border:1px solid currentColor;border-radius:var(--r-pill);
  background:none;color:var(--accent);text-decoration:none;cursor:pointer;white-space:nowrap}
/* The one destructive member: quieter than the rest at rest (--muted, not --accent, and the
   border follows along since it is currentColor) and only turns --bad on hover, so the
   consequence is legible right before the click without making the row alarming at rest. */
.pill.rm{color:var(--muted)}
/* Has to read on every surface a pill can sit on: the plain panel, a hovered row now tinted
   --bg, a coloured .panel.ok/.bad/.warn state. --line is one step off all of them, and the
   accent border is the half none of those surfaces can cancel out; this is the rule that
   makes a row action's hover plainly visible again, which was the reported defect. */
.pill:hover{background:var(--line);border-color:var(--accent)}
.pill.rm:hover{color:var(--bad);border-color:var(--bad)}
.pill[disabled]{color:var(--muted);border-color:var(--line);background:none;cursor:default}
/* Selected state as a fill, never as a border: the top nav's own idiom before this pass, now
   the whole family's. Declared last so a selected pill always outranks a hovered one. */
.pill.on,.pill.on:hover{background:var(--accent);border-color:var(--accent);
  color:var(--on-accent);font-weight:600}
/* The size step: body-size pills for the nav, for a list page's one creating action, and for
   a form's way out (cancel), so each sits at the same footprint as the text or button beside
   it. A size, declared once here for three named contexts, not a call site restyling itself. */
nav .pill,p.primary .pill,.actions .pill{font-size:1rem;padding:6px 14px}
/* The Settings menu. `details` is the disclosure widget HTML has had all along: the summary
   is the trigger and takes the same pill as every other control in the bar, and .menu is the
   panel it opens, taken out of flow so opening it never reflows the header. What is inside
   the panel is not styled here at all: it is form.edit's labels and .actions' button, the
   same two objects every editing form on every page is built from. */
details.settings{position:relative;margin-left:auto}
/* Two ways of saying the same thing, because browsers disagree on which one they read: the
   pill's own display:inline-flex already drops the marker triangle in Chromium, list-style
   does it in Firefox, and the pseudo-element in WebKit. */
details.settings > summary{list-style:none}
details.settings > summary::-webkit-details-marker{display:none}
.menu{position:absolute;right:0;top:calc(100% + 8px);z-index:10;min-width:230px;
  background:var(--panel);border:1px solid var(--line);border-radius:var(--r-box);
  padding:14px 16px;box-shadow:0 8px 24px rgba(0,0,0,.25)}
/* The panel's own padding is the space below the last field, so the gap above the button is
   left to .actions and reads exactly as it does in any form on any page. */
.menu form.edit label:last-of-type{margin-bottom:0}
.flash{background:var(--panel);border:1px solid var(--ok);border-left:4px solid var(--ok);
  border-radius:var(--r-box);padding:14px 16px;margin:0 0 16px}
.err{background:var(--panel);border:1px solid var(--bad);border-left:4px solid var(--bad);
  border-radius:var(--r-box);padding:14px 16px;margin:0 0 16px;white-space:pre-wrap}
.secret{border:1px solid var(--warn);border-left:4px solid var(--warn);border-radius:var(--r-box);
  padding:14px 16px;margin:0 0 16px;background:var(--panel)}
/* The one string on the page that matters, so it must outrank the paragraph explaining it:
   bigger than body text (not just bigger than code's own .92em default), roomy padding and
   line-height, a border of its own so the box reads as a distinct object against .secret's
   panel background, and a pointer cursor as a visible cue for the user-select:all below. */
.secret code{display:block;margin:10px 0 0;padding:16px 18px;background:var(--chip);
  border:1px solid var(--line);border-radius:6px;font-size:1.15em;line-height:1.6;
  word-break:break-all;user-select:all;cursor:pointer}
.secret .hint{display:block;color:var(--muted);font-size:.82rem;margin:8px 0 0}

/* Phone layout: a compact single-row header, and every table row becomes a stacked card so
   no column is ever off-screen. Everything below is scoped to this query; nothing above it
   changes. */
@media (max-width:640px){
  header.top{padding:6px 10px}
  .bar{gap:6px 8px}
  .brand{order:1}
  /* The menu keeps the brand company on the first line, at the right edge, and the tabs get
     the whole second line to scroll along. One trigger instead of ten pills is what makes
     that first line fit on a phone at all. */
  .settings{order:2}
  .pill{padding:3px 8px}
  nav .pill,p.primary .pill,.actions .pill{font-size:var(--fs-sm);padding:4px 9px}
  nav{order:3;flex:1 1 100%;flex-wrap:nowrap;overflow-x:auto;gap:1px;padding-bottom:2px}
  table{min-width:0}
  table,thead,tbody,tr,td{display:block}
  thead{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;
    clip:rect(0,0,0,0);white-space:nowrap;border:0}
  tbody tr{border-bottom:1px solid var(--line);padding:8px 0;margin:0 0 2px}
  tbody tr:last-child{border-bottom:0}
  td{border-bottom:0;padding:3px 0}
  td[data-label]::before{content:attr(data-label);display:block;font-weight:600;font-size:.8rem;
    text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  td.pills{justify-content:flex-start;padding-top:6px}
}
";

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

/// The two languages the binary carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lang {
    En,
    It,
}

impl Lang {
    /// The `lang=` attribute, the cookie value, and the query parameter — one spelling.
    fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::It => "it",
        }
    }

    /// How the language names itself, for its option in the Settings menu. A language menu
    /// that translated its own entries would hide the one an operator is looking for behind
    /// the language they cannot read, which is the one case where translating is the bug.
    fn name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::It => "Italiano",
        }
    }
}

/// Parse a language name, from `BB_AUTH_WEB_DEFAULT_LANG` or, through [`parse_lang_pref`],
/// from the query and the cookie. `None` for anything else — an unknown value is simply not
/// a preference.
fn parse_lang(s: &str) -> Option<Lang> {
    match s.trim().to_ascii_lowercase().as_str() {
        "en" => Some(Lang::En),
        "it" => Some(Lang::It),
        _ => None,
    }
}

/// What the Settings menu offers, which is not the same set as [`Lang`]: `Auto` is the
/// choice to make no choice, and it resolves per request against the browser's
/// `Accept-Language` (see [`negotiate_lang`]).
///
/// It needs a type of its own because [`Lang`] has to stay the two the table actually holds:
/// every string on the page is looked up by one, so `Auto` could never travel that far. The
/// theme needs no such second type for exactly the mirror reason: [`Theme::System`] *is* a
/// value the renderer carries all the way to the page, as an absent attribute.
///
/// `Auto` is also the floor, not an extra state bolted on: a session that never expressed a
/// preference has always been served what `Auto` means, so naming the behaviour changes
/// nobody's page and only makes it choosable again after choosing something else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LangPref {
    Auto,
    Fixed(Lang),
}

impl LangPref {
    /// The cookie value and the query parameter value: one spelling, and for a fixed choice
    /// it is [`Lang::code`]'s own, so `?lang=it` still means exactly what it always meant.
    fn code(self) -> &'static str {
        match self {
            LangPref::Auto => "auto",
            LangPref::Fixed(l) => l.code(),
        }
    }

    /// The label its option in the Settings menu shows, rendered in `lang`. Only `Auto` is
    /// translated: the other two name themselves (see [`Lang::name`]).
    fn label(self, lang: Lang) -> &'static str {
        match self {
            LangPref::Auto => t(lang, K::LangAuto),
            LangPref::Fixed(l) => l.name(),
        }
    }
}

/// Parse a language preference, from the query or the cookie: the two language codes plus
/// `auto`. `None` for anything else, exactly as [`parse_lang`] does and for the same reason.
fn parse_lang_pref(s: &str) -> Option<LangPref> {
    match s.trim().to_ascii_lowercase().as_str() {
        "auto" => Some(LangPref::Auto),
        _ => parse_lang(s).map(LangPref::Fixed),
    }
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

/// The three appearances the GUI can render in. `System` is the default: it is what
/// [`negotiate_theme`] returns for a request that expressed no preference at all, so nobody's
/// page changes appearance until they choose one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Theme {
    Light,
    Dark,
    System,
}

impl Theme {
    /// The cookie value and the query parameter value: one spelling.
    fn code(self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
            Theme::System => "system",
        }
    }

    /// The `data-theme` attribute [`shell`] puts on `html`, for the CSS in [`CSS`] to key
    /// off. `None` for `System`: leaving the attribute off the page entirely is what lets the
    /// `prefers-color-scheme` media query keep deciding, instead of a third value it would
    /// have to special-case.
    fn attr(self) -> Option<&'static str> {
        match self {
            Theme::Light => Some("light"),
            Theme::Dark => Some("dark"),
            Theme::System => None,
        }
    }

    /// The label its option in the Settings menu shows. A [`K`] and not a string, unlike
    /// [`LangPref::label`]: an appearance is prose about the page, so it translates.
    fn label(self) -> K {
        match self {
            Theme::Light => K::ThemeLight,
            Theme::Dark => K::ThemeDark,
            Theme::System => K::ThemeSystem,
        }
    }
}

/// Parse a theme name, from the query or the cookie. `None` for anything else: an
/// unrecognised value is not an error, it just means no choice was expressed, and falls back
/// exactly as a missing cookie does.
fn parse_theme(s: &str) -> Option<Theme> {
    match s.trim().to_ascii_lowercase().as_str() {
        "light" => Some(Theme::Light),
        "dark" => Some(Theme::Dark),
        "system" => Some(Theme::System),
        _ => None,
    }
}

/// Every translatable string in the GUI, as a variant.
///
/// An enum rather than a string key so that [`t`]'s match is **exhaustive**: adding a key
/// without translating it does not fall back at runtime, it fails to compile. And because
/// each arm names both spellings on one line, no key can be half-translated either.
///
/// [`K::Dashboard`], [`K::Groups`], [`K::Apps`], [`K::Users`], [`K::Denied`] and [`K::Can`]
/// are the nav labels and page headings: descriptive prose *about* a section, not that
/// section's name. The name itself stays untranslated wherever it appears as itself,
/// namely `authorized_urls`, `public_auth`, `login_url`, `api_keys`, `released`, `duration`,
/// `notes`, `bbk_`, every `@group` reference, and the raw key shown in muted monospace
/// beside a heading; that is because it is what an operator types into the file and into
/// `bb-auth-adm`, and translating it would invent a second name for a thing that has one.
#[derive(Clone, Copy)]
enum K {
    Dashboard,
    Groups,
    Apps,
    Scopes,
    Users,
    Denied,
    Can,
    Back,
    None,
    Counts,
    KeyExpiry,
    ColOwner,
    ColExpiry,
    Expired,
    ExpiresSoon,
    NeverExpires,
    KeyInvalid,
    Expires,
    Warnings,
    NoWarnings,
    WarnNoScope,
    WarnEnrolledAndDenied,
    ReferencedBy,
    ReferencedByNothing,
    ReachesNothing,
    NoSuchUser,
    UsersIntro,
    GroupsIntro,
    AppsIntro,
    ScopesIntro,
    DeniedIntro,
    CanIntro,
    Submit,
    Authorized,
    VerdictDenied,
    // --- the ten decisions, in the order `Decision` declares them ---
    WhyAnonymousGrant,
    WhyGranted,
    WhyVetoed,
    WhyNoApplication,
    WhyNoScope,
    WhyUnauthenticated,
    WhyCredentialRefused,
    WhyNotEnrolled,
    WhyNotMember,
    WhyKeyOutOfScope,
    AppSees,
    NoIdentityTitle,
    NoIdentityBody,
    NotAdminTitle,
    NotAdminBody,
    NotFoundTitle,
    NotFoundBody,
    FileErrorTitle,
    FileErrorHint,
    SignedInAs,
    ReloadHint,
    // --- the settings menu ---
    Settings,
    SettingLanguage,
    SettingTheme,
    LangAuto,
    Apply,
    ThemeLight,
    ThemeDark,
    ThemeSystem,
    // --- actions, buttons, form furniture ---
    Add,
    Edit,
    Remove,
    Rotate,
    Save,
    Create,
    Cancel,
    MoveUp,
    MoveDown,
    KeyScopeInherit,
    KeyScopesHelp,
    ScopeUrlsHelp,
    AnonymousWarn,
    AuthenticatedWarn,
    GroupMembersHelp,
    GroupNoRename,
    NewName,
    // --- the words the application-centric file is made of ---
    Base,
    BaseHelp,
    LoginUrl,
    LoginUrlHelp,
    AccessWord,
    AccessAnonymous,
    AccessAuthenticated,
    AccessRestricted,
    AccessHelp,
    Credentials,
    CredentialsHelp,
    CredLogin,
    CredApiKey,
    Members,
    MembersHelp,
    Uuid,
    Emails,
    AddEmail,
    ConfirmEmailRm,
    NoScopes,
    InNoScope,
    WarnShadowed,
    WarnNoMembers,
    /// A scope's or a group's member that resolves to no roster row: a dangling uuid, shown
    /// for what it is rather than silently hidden.
    UnknownMember,
    // --- what a destructive page warns about ---
    ConfirmUserRm,
    ConfirmKeyRm,
    ConfirmKeyRotate,
    ConfirmAppRm,
    ConfirmScopeRm,
    ConfirmGroupRm,
    ConfirmDenyRm,
    // --- the minted bearer ---
    BearerHeading,
    BearerOnce,
    BearerClickHint,
    // --- refusals a form makes on its own ---
    EmailRequired,
    NameRequired,
    KeyIdRequired,
    BadKeyWindow,
    AlreadyDenied,
    NoSuchKey,
    NoSuchApp,
    NoSuchScope,
    NoSuchGroup,
    NoSuchDenied,
    // --- whole-request refusals ---
    ConflictTitle,
    ConflictBody,
    ConflictRecover,
    ConflictBack,
    MintConflictTitle,
    MintConflictBody,
    MintConflictLost,
    MintConflictRotate,
    CsrfTitle,
    CsrfBody,
    NotAllowedTitle,
    NotAllowedBody,
    // --- what a redirect says it did ---
    MsgUserAdded,
    MsgUserSaved,
    MsgUserRemoved,
    MsgKeySaved,
    MsgKeyRemoved,
    MsgAppAdded,
    MsgScopeAdded,
    MsgAppSaved,
    MsgScopeSaved,
    MsgAppRemoved,
    MsgScopeRemoved,
    MsgScopeMoved,
    MsgGroupAdded,
    MsgGroupSaved,
    MsgGroupRemoved,
    MsgDeniedAdded,
    MsgDeniedRemoved,
}

/// Pick one of a key's two spellings.
fn m(lang: Lang, en: &'static str, it: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::It => it,
    }
}

/// The translation table. See [`K`] for why it is a match and what is deliberately absent
/// from it.
fn t(lang: Lang, key: K) -> &'static str {
    match key {
        K::Dashboard => m(lang, "Dashboard", "Cruscotto"),
        K::Groups => m(lang, "User groups", "Gruppi di utenti"),
        K::Apps => m(lang, "Applications", "Applicazioni"),
        K::Scopes => m(lang, "Scopes", "Ambiti"),
        K::Users => m(lang, "Users", "Utenti"),
        K::Denied => m(lang, "Denied", "Bloccati"),
        K::Can => m(lang, "Access check", "Verifica accesso"),
        K::Back => m(lang, "back", "indietro"),
        K::None => m(lang, "none", "nessuno"),
        K::Counts => m(lang, "What is in the file", "Cosa c'è nel file"),
        K::KeyExpiry => m(lang, "Key expiry", "Scadenza delle chiavi"),
        K::ColOwner => m(lang, "owner", "proprietario"),
        K::ColExpiry => m(lang, "expiry", "scadenza"),
        K::Expired => m(lang, "expired", "scaduta"),
        K::ExpiresSoon => m(lang, "expires soon", "scade a breve"),
        K::NeverExpires => m(lang, "never expires", "non scade mai"),
        K::KeyInvalid => m(
            lang,
            "invalid released/duration — the gate skips this key",
            "released/duration non validi — il gate salta questa chiave",
        ),
        K::Expires => m(lang, "expires", "scade il"),
        K::Warnings => m(lang, "Warnings", "Avvisi"),
        K::NoWarnings => m(lang, "nothing to report", "nulla da segnalare"),
        K::WarnNoScope => m(
            lang,
            "reaches nothing: no scope lists them",
            "non raggiunge nulla: nessuno scope lo elenca",
        ),
        K::WarnEnrolledAndDenied => m(
            lang,
            "is in users and in denied — denied wins, on every credential",
            "è in users e in denied — vince denied, su ogni credenziale",
        ),
        K::ReferencedBy => m(lang, "referenced by", "referenziato da"),
        K::ReferencedByNothing => m(lang, "referenced by nothing", "referenziato da nulla"),
        K::Base => m(lang, "base", "base"),
        K::Members => m(lang, "members", "membri"),
        K::Uuid => m(lang, "uuid", "uuid"),
        K::Emails => m(lang, "emails", "email"),
        K::AccessWord => m(lang, "access", "accesso"),
        K::Credentials => m(lang, "credentials", "credenziali"),
        K::LoginUrl => m(lang, "login_url", "login_url"),
        K::CredLogin => m(lang, "login", "login"),
        K::CredApiKey => m(lang, "api_key", "api_key"),
        K::AccessAnonymous => m(lang, "anonymous", "anonimo"),
        K::AccessAuthenticated => m(lang, "authenticated", "autenticato"),
        K::AccessRestricted => m(lang, "restricted", "ristretto"),
        K::NoScopes => m(lang, "no scopes", "nessuno scope"),
        K::AddEmail => m(lang, "Add an email", "Aggiungi un\u{2019}email"),
        K::InNoScope => m(
            lang,
            "in no scope: this user reaches nothing",
            "in nessuno scope: questo utente non raggiunge nulla",
        ),
        K::ReachesNothing => m(lang, "reaches nothing", "non raggiunge nulla"),
        K::NoSuchUser => m(lang, "no such user", "utente inesistente"),
        K::UsersIntro => m(
            lang,
            "The roster: an identity, the emails that resolve to it, and its keys. What a \
             user reaches is written on the side of the place, in the scopes that list them.",
            "Il roster: un\u{2019}identità, le email che vi si risolvono e le sue chiavi. Ciò \
             che un utente raggiunge è scritto dalla parte del posto, negli scope che lo \
             elencano.",
        ),
        K::GroupsIntro => m(
            lang,
            "Named sets of people. A group is abbreviation, never a grant: defining one \
             authorizes nobody until a scope names it.",
            "Insiemi di persone con un nome. Un gruppo è un\u{2019}abbreviazione, mai una \
             concessione: definirne uno non autorizza nessuno finché uno scope non lo nomina.",
        ),
        K::AppsIntro => m(
            lang,
            "The places, and who reaches them. Every grant in the file is written here. \
             Applications partition the URL space: no two areas overlap, and a URL no \
             application covers is reachable by nobody.",
            "I posti, e chi li raggiunge. Ogni concessione del file è scritta qui. Le \
             applicazioni partizionano lo spazio degli URL: due aree non si sovrappongono \
             mai, e un URL che nessuna applicazione copre non è raggiungibile da nessuno.",
        ),
        K::ScopesIntro => m(
            lang,
            "In file order, and the order is the meaning: first match wins, so the first \
             scope whose urls cover a request answers for it, even if it grants nothing. \
             Put the narrow, stricter scope first.",
            "Nell\u{2019}ordine del file, e l\u{2019}ordine è il significato: vince la prima \
             corrispondenza, quindi risponde il primo scope le cui urls coprono la richiesta, \
             anche se non concede nulla. Lo scope stretto e severo va prima.",
        ),
        K::DeniedIntro => m(
            lang,
            "A veto. It outranks every grant, on every credential, and it is not the same as \
             deleting the user\u{2019}s row. An enrolled user is vetoed by uuid, so every \
             email they hold goes with it; a stranger is vetoed by the email itself.",
            "Un veto. Batte ogni concessione, su ogni credenziale, e non equivale a cancellare \
             la riga dell\u{2019}utente. Un utente iscritto si veta per uuid, quindi ci vanno \
             dietro tutte le sue email; uno sconosciuto si veta con l\u{2019}email stessa.",
        ),
        K::CanIntro => m(
            lang,
            "Would this credential reach this URL? Answered by the gate's own decision \
             function, on the file as it is on disk right now.",
            "Questa credenziale raggiungerebbe questo URL? Risponde la funzione di decisione \
             del gate, sul file così com'è su disco adesso.",
        ),
        K::Submit => m(lang, "Check", "Verifica"),
        K::Authorized => m(lang, "AUTHORIZED", "AUTORIZZATO"),
        K::VerdictDenied => m(lang, "DENIED", "NEGATO"),
        K::WhyAnonymousGrant => m(
            lang,
            "is anonymous: it grants with no credential at all, so this URL is open to \
             everyone and the 204 names nobody.",
            "è anonimo: concede senza alcuna credenziale, quindi questo URL è aperto a tutti \
             e il 204 non nomina nessuno.",
        ),
        K::WhyGranted => m(
            lang,
            "admits this credential.",
            "ammette questa credenziale.",
        ),
        K::WhyVetoed => m(
            lang,
            "is on the denied list, which outranks every grant.",
            "è nella lista denied, che batte ogni concessione.",
        ),
        K::WhyNoApplication => m(
            lang,
            "is inside no application\u{2019}s area, so nobody reaches it, with any credential.",
            "non è dentro l\u{2019}area di nessuna applicazione, quindi non lo raggiunge \
             nessuno, con nessuna credenziale.",
        ),
        K::WhyNoScope => m(
            lang,
            "owns this URL but has no scope covering it.",
            "possiede questo URL ma non ha uno scope che lo copra.",
        ),
        K::WhyUnauthenticated => m(
            lang,
            "wants an identity, and the request carried no credential.",
            "vuole un\u{2019}identità, e la richiesta non portava credenziali.",
        ),
        K::WhyCredentialRefused => m(
            lang,
            "does not admit this class of credential.",
            "non ammette questa classe di credenziale.",
        ),
        K::WhyNotEnrolled => m(
            lang,
            "is in no users entry, and this scope admits only the people it lists.",
            "non è in nessuna voce users, e questo scope ammette solo le persone che elenca.",
        ),
        K::WhyNotMember => m(
            lang,
            "does not list this user.",
            "non elenca questo utente.",
        ),
        K::WhyKeyOutOfScope => m(
            lang,
            "is not among the scopes this key restricted itself to.",
            "non è tra gli scope a cui questa chiave si è ristretta.",
        ),
        K::AppSees => m(lang, "the application sees", "l'applicazione vede"),
        K::NoIdentityTitle => m(lang, "No identity header", "Nessun header di identità"),
        K::NoIdentityBody => m(
            lang,
            "identity header missing — is nginx auth_request wiring in front of this service?",
            "header di identità mancante — c'è il wiring nginx auth_request davanti a questo \
             servizio?",
        ),
        K::NotAdminTitle => m(lang, "Not an administrator", "Non sei un amministratore"),
        K::NotAdminBody => m(
            lang,
            "is authenticated, but is not on BB_AUTH_WEB_ADMINS.",
            "è autenticato, ma non è in BB_AUTH_WEB_ADMINS.",
        ),
        K::NotFoundTitle => m(lang, "Not found", "Non trovato"),
        K::NotFoundBody => m(
            lang,
            "there is no page at this address.",
            "non c'è nessuna pagina a questo indirizzo.",
        ),
        K::FileErrorTitle => m(
            lang,
            "The access file cannot be read",
            "L'access file non è leggibile",
        ),
        K::FileErrorHint => m(
            lang,
            "Every page here re-reads the file on each request, so fixing it takes effect at \
             once — no restart, no reload.",
            "Ogni pagina qui rilegge il file a ogni richiesta, quindi correggerlo ha effetto \
             subito — senza riavvio né reload.",
        ),
        K::SignedInAs => m(lang, "signed in as", "accesso come"),
        K::ReloadHint => m(
            lang,
            "an edit is live when the gate re-reads the file:",
            "una modifica è attiva quando il gate rilegge il file:",
        ),

        K::Settings => m(lang, "Settings", "Impostazioni"),
        K::SettingLanguage => m(lang, "Language", "Lingua"),
        K::SettingTheme => m(lang, "Theme", "Tema"),
        // Named after what decides when nobody has: the browser. "Auto" alone would leave an
        // operator guessing what it follows, and this is the one option whose answer is not
        // written next to it in the list.
        K::LangAuto => m(lang, "Auto (browser)", "Auto (browser)"),
        K::Apply => m(lang, "Apply", "Applica"),
        K::ThemeLight => m(lang, "Light", "Chiaro"),
        K::ThemeDark => m(lang, "Dark", "Scuro"),
        K::ThemeSystem => m(lang, "System", "Sistema"),

        K::Add => m(lang, "add", "aggiungi"),
        K::Edit => m(lang, "edit", "modifica"),
        K::Remove => m(lang, "remove", "rimuovi"),
        K::Rotate => m(lang, "rotate", "rigenera"),
        K::Save => m(lang, "Save", "Salva"),
        K::Create => m(lang, "Create", "Crea"),
        K::Cancel => m(lang, "cancel", "annulla"),
        K::MoveUp => m(lang, "move up", "sposta su"),
        K::MoveDown => m(lang, "move down", "sposta giù"),
        K::KeyScopeInherit => m(
            lang,
            "everything its owner reaches",
            "tutto ciò che raggiunge il proprietario",
        ),
        K::KeyScopesHelp => m(
            lang,
            "One 'application/scope' per line, and a restriction rather than a grant: it can \
             only subtract from what the owner already reaches. Empty means all of them.",
            "Un 'applicazione/scope' per riga, ed è una restrizione, non una concessione: può \
             solo sottrarre a ciò che il proprietario già raggiunge. Vuoto vuol dire tutti.",
        ),
        K::ScopeUrlsHelp => m(
            lang,
            "One URL pattern per line. Every one of them must lie inside the application's \
             base, and first match wins, so a broad scope listed early silences the ones \
             below it.",
            "Un pattern di URL per riga. Ognuno deve stare dentro la base \
             dell\u{2019}applicazione, e vince la prima corrispondenza, quindi uno scope ampio \
             messo presto zittisce quelli sotto.",
        ),
        K::BaseHelp => m(
            lang,
            "One literal URL prefix per line, with no wildcards: this is the area the \
             application owns. No two applications may overlap, and every scope pattern must \
             lie inside one of these.",
            "Un prefisso di URL letterale per riga, senza wildcard: è l\u{2019}area che \
             l\u{2019}applicazione possiede. Due applicazioni non possono sovrapporsi, e ogni \
             pattern di scope deve stare dentro uno di questi.",
        ),
        K::LoginUrlHelp => m(
            lang,
            "The sign-in page for this whole area, overriding BB_AUTH_LOGIN_URL. Absolute \
             https. Empty uses the global one.",
            "La pagina di accesso per tutta quest\u{2019}area, che sostituisce \
             BB_AUTH_LOGIN_URL. Https assoluto. Vuoto usa quella globale.",
        ),
        K::AccessHelp => m(
            lang,
            "What this scope asks of an identity. It is required and has no default, because \
             it decides everything.",
            "Cosa chiede questo scope a un\u{2019}identità. È obbligatorio e non ha default, \
             perché decide tutto.",
        ),
        K::CredentialsHelp => m(
            lang,
            "Which classes of credential may exercise this grant. Neither ticked means both, \
             which is what an absent field says in the file.",
            "Quali classi di credenziale possono esercitare questa concessione. Nessuna delle \
             due spuntate vuol dire entrambe, che è ciò che dice un campo assente nel file.",
        ),
        K::MembersHelp => m(
            lang,
            "One per line: an email or a uuid for a person, '@name' for a group. An email is \
             resolved to the uuid the file stores.",
            "Uno per riga: un\u{2019}email o un uuid per una persona, '@nome' per un gruppo. \
             Un\u{2019}email viene risolta nell\u{2019}uuid che il file memorizza.",
        ),
        K::AnonymousWarn => m(
            lang,
            "no credential at all is asked for: these urls are open to everyone, and the 204 \
             names nobody. Note that denied does not reach here, because a vetoed client would \
             simply send nothing.",
            "non viene chiesta alcuna credenziale: questi urls sono aperti a tutti, e il 204 \
             non nomina nessuno. Nota che denied non arriva fin qui, perché un client vetato \
             basterebbe che non mandasse nulla.",
        ),
        K::AuthenticatedWarn => m(
            lang,
            "any identity Cognito vouches for reaches these urls, enrolled or not, and the \
             roster is not consulted. Self-signup is open, so that means anyone who can \
             register: the right grant for an onboarding area, the wrong one for anything else.",
            "ogni identità garantita da Cognito raggiunge questi urls, iscritta o no, e il \
             roster non viene consultato. La registrazione è aperta, quindi vuol dire chiunque \
             possa registrarsi: la concessione giusta per un\u{2019}area di onboarding, \
             sbagliata per tutto il resto.",
        ),
        K::WarnShadowed => m(
            lang,
            "unreachable: an earlier scope of this application already covers every url it \
             has",
            "irraggiungibile: uno scope precedente di questa applicazione copre già ogni url \
             che ha",
        ),
        K::WarnNoMembers => m(
            lang,
            "restricted and lists nobody: it admits no one",
            "ristretto e non elenca nessuno: non ammette nessuno",
        ),
        K::UnknownMember => m(
            lang,
            "matches no roster row",
            "non corrisponde a nessuna riga del roster",
        ),
        K::GroupMembersHelp => m(
            lang,
            "The people this name stands for, one per line, by email or uuid. A group cannot \
             reference another group.",
            "Le persone per cui sta questo nome, una per riga, per email o uuid. Un gruppo non \
             può referenziarne un altro.",
        ),
        K::GroupNoRename => m(
            lang,
            "There is deliberately no rename: a reference names a group by its exact \
             spelling. Add the new name, move the references, then remove the old one.",
            "La rinomina non esiste di proposito: un riferimento nomina il gruppo con la sua \
             esatta grafia. Aggiungi il nuovo nome, sposta i riferimenti, poi rimuovi il \
             vecchio.",
        ),
        K::NewName => m(lang, "name (rename)", "nome (rinomina)"),

        K::ConfirmUserRm => m(
            lang,
            "The roster row goes, and every api key it owns with it. It does NOT keep them \
             off a public_auth site — the roster is not consulted there; that is what denied \
             is for.",
            "Sparisce la riga del roster, e con essa ogni sua api key. NON li tiene fuori da \
             un site public_auth — lì il roster non viene consultato; per quello c'è denied.",
        ),
        K::ConfirmKeyRm => m(
            lang,
            "The bearer stops working the moment the gate reloads. It cannot be restored — \
             only a new key can be minted.",
            "Il bearer smette di funzionare appena il gate ricarica. Non è recuperabile — si \
             può solo generare una chiave nuova.",
        ),
        K::ConfirmKeyRotate => m(
            lang,
            "A new bearer is minted and shown once, here. The old one stops working at the \
             next reload — which is what makes this the answer to a leak.",
            "Viene generato un nuovo bearer, mostrato una volta sola, qui. Il vecchio smette \
             di funzionare al prossimo reload — ed è per questo che è la risposta a una fuga.",
        ),
        K::ConfirmScopeRm => m(
            lang,
            "Removing this scope takes away every grant it made, and the scope after it \
             starts answering for the urls it covered.",
            "Rimuovere questo scope toglie ogni concessione che faceva, e lo scope successivo \
             comincia a rispondere per gli urls che copriva.",
        ),
        K::ConfirmEmailRm => m(
            lang,
            "This address stops signing in as this user. The identity, its groups and its \
             keys stay exactly as they are.",
            "Questo indirizzo smette di accedere come questo utente. L\u{2019}identita, i suoi \
             gruppi e le sue chiavi restano esattamente come sono.",
        ),
        K::ConfirmAppRm => m(
            lang,
            "If it was public_auth, the identities it let in with no roster entry now reach \
             nothing.",
            "Se era public_auth, le identità che entravano senza riga nel roster ora non \
             raggiungono nulla.",
        ),
        K::ConfirmGroupRm => m(
            lang,
            "A group is abbreviation, not a grant. Removing one is refused while any list \
             still names it.",
            "Un gruppo è un'abbreviazione, non una concessione. Rimuoverlo viene rifiutato \
             finché una lista lo nomina.",
        ),
        K::ConfirmDenyRm => m(
            lang,
            "The veto is lifted. Whatever the roster and the sites grant them applies again.",
            "Il veto viene tolto. Torna a valere quanto gli concedono il roster e i site.",
        ),

        K::BearerHeading => m(
            lang,
            "The bearer — copy it now",
            "Il bearer — copialo adesso",
        ),
        K::BearerOnce => m(
            lang,
            "Shown once, here, and stored nowhere: the file keeps only its sha256, and that \
             lookup is the whole verification. It cannot be recovered — only replaced by a \
             rotation.",
            "Mostrato una volta sola, qui, e non memorizzato da nessuna parte: il file tiene \
             solo il suo sha256, e quel lookup è tutta la verifica. Non è recuperabile — si \
             può solo sostituire con una rotazione.",
        ),
        K::BearerClickHint => m(
            lang,
            "Click the credential to select it all, then copy.",
            "Fai clic sulla credenziale per selezionarla tutta, poi copiala.",
        ),

        K::EmailRequired => m(lang, "an email is required", "serve un'email"),
        K::NameRequired => m(lang, "a name is required", "serve un nome"),
        K::KeyIdRequired => m(
            lang,
            "a key needs an id — it is what names it in a log and in a rotation",
            "una chiave ha bisogno di un id — è ciò che la nomina in un log e in una rotazione",
        ),
        K::BadKeyWindow => m(
            lang,
            "released + duration is not a valid window: a date is YYYY-MM-DD, a duration is \
             <n>d, <n>h or never. The gate would skip this key.",
            "released + duration non sono una finestra valida: una data è YYYY-MM-DD, una \
             durata è <n>d, <n>h o never. Il gate salterebbe questa chiave.",
        ),
        K::AlreadyDenied => m(
            lang,
            "that email is already on denied",
            "quell'email è già in denied",
        ),
        K::NoSuchKey => m(lang, "no such api key", "api key inesistente"),
        K::NoSuchApp => m(lang, "no such application", "applicazione inesistente"),
        K::NoSuchScope => m(lang, "no such scope", "scope inesistente"),
        K::NoSuchGroup => m(lang, "no such url group", "url group inesistente"),
        K::NoSuchDenied => m(
            lang,
            "that email is not on denied",
            "quell'email non è in denied",
        ),

        K::ConflictTitle => m(lang, "The file changed", "Il file è cambiato"),
        K::ConflictBody => m(
            lang,
            "The access file was written by someone else after this form was loaded — a \
             bb-auth-adm over SSH, or another tab. Nothing was written here: reload the page \
             and make the change again, on what the file says now.",
            "L'access file è stato scritto da qualcun altro dopo il caricamento di questa \
             form — un bb-auth-adm via SSH, o un'altra scheda. Qui non è stato scritto \
             nulla: ricarica la pagina e rifai la modifica su ciò che il file dice adesso.",
        ),
        K::ConflictRecover => m(
            lang,
            "What you typed is not lost: the browser's Back button returns to the form as \
             you filled it in — copy the values from there onto the freshly reloaded form.",
            "Ciò che avevi digitato non è perso: il pulsante Indietro del browser riporta \
             alla form così come l'avevi compilata — copia da lì i valori sulla form appena \
             ricaricata.",
        ),
        K::ConflictBack => m(lang, "reload the page", "ricarica la pagina"),
        K::MintConflictTitle => m(
            lang,
            "This key was already created",
            "Questa chiave è già stata creata",
        ),
        K::MintConflictBody => m(
            lang,
            "The file already carries a key with this id for this user — most likely this \
             page is a reload of the one that showed the bearer, re-submitting the mint \
             form. Nothing was written now: the key exists exactly once.",
            "Il file contiene già una chiave con questo id per questo utente — con ogni \
             probabilità questa pagina è il ricaricamento di quella che mostrava il bearer, \
             e ha reinviato la form di creazione. Adesso non è stato scritto nulla: la \
             chiave esiste una volta sola.",
        ),
        K::MintConflictLost => m(
            lang,
            "The bearer was shown once, when the key was created, and cannot be recovered — \
             the file keeps only its hash. If it was not copied then, rotate the key: same \
             row, same scope, a new secret.",
            "Il bearer è stato mostrato una sola volta, alla creazione della chiave, e non \
             può essere recuperato — il file ne conserva solo l'hash. Se allora non è stato \
             copiato, rigenera la chiave: stessa riga, stesso scope, un nuovo segreto.",
        ),
        K::MintConflictRotate => m(lang, "rotate this key", "rigenera questa chiave"),
        K::CsrfTitle => m(lang, "Request refused", "Richiesta rifiutata"),
        K::CsrfBody => m(
            lang,
            "this POST did not come from a page of this site. Only a same-origin form \
             submission is accepted.",
            "questo POST non arriva da una pagina di questo sito. Si accetta solo l'invio di \
             una form dalla stessa origine.",
        ),
        K::NotAllowedTitle => m(lang, "Not allowed here", "Non ammesso qui"),
        K::NotAllowedBody => m(
            lang,
            "this address does not answer that method.",
            "questo indirizzo non risponde a quel metodo.",
        ),

        K::MsgUserAdded => m(lang, "user added", "utente aggiunto"),
        K::MsgUserSaved => m(lang, "user saved", "utente salvato"),
        K::MsgUserRemoved => m(lang, "user removed", "utente rimosso"),
        K::MsgKeySaved => m(lang, "api key saved", "api key salvata"),
        K::MsgKeyRemoved => m(lang, "api key removed", "api key rimossa"),
        K::MsgAppAdded => m(lang, "application added", "applicazione aggiunta"),
        K::MsgAppSaved => m(lang, "application saved", "applicazione salvata"),
        K::MsgAppRemoved => m(lang, "application removed", "applicazione rimossa"),
        K::MsgScopeAdded => m(lang, "scope added", "scope aggiunto"),
        K::MsgScopeSaved => m(lang, "scope saved", "scope salvato"),
        K::MsgScopeRemoved => m(lang, "scope removed", "scope rimosso"),
        K::MsgScopeMoved => m(lang, "scope moved", "scope spostato"),
        K::MsgGroupAdded => m(lang, "url group added", "url group aggiunto"),
        K::MsgGroupSaved => m(lang, "url group saved", "url group salvato"),
        K::MsgGroupRemoved => m(lang, "url group removed", "url group rimosso"),
        K::MsgDeniedAdded => m(lang, "email denied", "email negata"),
        K::MsgDeniedRemoved => m(lang, "veto lifted", "veto tolto"),
    }
}

/// What a successful mutation says on the page it redirects to.
///
/// A closed set, and that is the point: the `303` puts `?msg=<key>` in the URL, so what
/// comes back is request data. Only these keys render, through [`t`]; anything else is
/// dropped silently. No free text ever travels through the query string, which is what
/// keeps the banner from being a place to inject prose into an admin's page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Msg {
    UserAdded,
    UserSaved,
    UserRemoved,
    KeySaved,
    KeyRemoved,
    AppAdded,
    AppSaved,
    AppRemoved,
    ScopeAdded,
    ScopeSaved,
    ScopeRemoved,
    ScopeMoved,
    GroupAdded,
    GroupSaved,
    GroupRemoved,
    DeniedAdded,
    DeniedRemoved,
}

impl Msg {
    /// The spelling in the query string — printable ASCII, so it goes into a `Location:`
    /// with no encoding.
    fn key(self) -> &'static str {
        match self {
            Msg::UserAdded => "user-added",
            Msg::UserSaved => "user-saved",
            Msg::UserRemoved => "user-removed",
            Msg::KeySaved => "key-saved",
            Msg::KeyRemoved => "key-removed",
            Msg::AppAdded => "app-added",
            Msg::AppSaved => "app-saved",
            Msg::AppRemoved => "app-removed",
            Msg::ScopeAdded => "scope-added",
            Msg::ScopeSaved => "scope-saved",
            Msg::ScopeRemoved => "scope-removed",
            Msg::ScopeMoved => "scope-moved",
            Msg::GroupAdded => "group-added",
            Msg::GroupSaved => "group-saved",
            Msg::GroupRemoved => "group-removed",
            Msg::DeniedAdded => "denied-added",
            Msg::DeniedRemoved => "denied-removed",
        }
    }

    /// The inverse. `None` for anything this binary does not say itself.
    fn parse(s: &str) -> Option<Msg> {
        [
            Msg::UserAdded,
            Msg::UserSaved,
            Msg::UserRemoved,
            Msg::KeySaved,
            Msg::KeyRemoved,
            Msg::AppAdded,
            Msg::AppSaved,
            Msg::AppRemoved,
            Msg::ScopeAdded,
            Msg::ScopeSaved,
            Msg::ScopeRemoved,
            Msg::ScopeMoved,
            Msg::GroupAdded,
            Msg::GroupSaved,
            Msg::GroupRemoved,
            Msg::DeniedAdded,
            Msg::DeniedRemoved,
        ]
        .into_iter()
        .find(|m| m.key() == s)
    }

    fn text(self, lang: Lang) -> &'static str {
        t(
            lang,
            match self {
                Msg::UserAdded => K::MsgUserAdded,
                Msg::UserSaved => K::MsgUserSaved,
                Msg::UserRemoved => K::MsgUserRemoved,
                Msg::KeySaved => K::MsgKeySaved,
                Msg::KeyRemoved => K::MsgKeyRemoved,
                Msg::AppAdded => K::MsgAppAdded,
                Msg::AppSaved => K::MsgAppSaved,
                Msg::AppRemoved => K::MsgAppRemoved,
                Msg::ScopeAdded => K::MsgScopeAdded,
                Msg::ScopeSaved => K::MsgScopeSaved,
                Msg::ScopeRemoved => K::MsgScopeRemoved,
                Msg::ScopeMoved => K::MsgScopeMoved,
                Msg::GroupAdded => K::MsgGroupAdded,
                Msg::GroupSaved => K::MsgGroupSaved,
                Msg::GroupRemoved => K::MsgGroupRemoved,
                Msg::DeniedAdded => K::MsgDeniedAdded,
                Msg::DeniedRemoved => K::MsgDeniedRemoved,
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Runtime configuration, read once from the environment at startup. Mirrors the gate's
/// `Config::from_env`, down to the wording of a fatal exit: a missing required var has no
/// safe default, so the process refuses to start rather than guess.
struct Config {
    /// `BB_AUTH_WEB_LISTEN`. Loopback — see the trust model on the crate root.
    listen: String,
    /// `BB_AUTH_USERS_FILE`, the access file to render. The gate's variable name, on
    /// purpose: each service gets its own env file, and one name means one meaning.
    access_path: String,
    /// `BB_AUTH_WEB_ADMINS`, normalised with [`norm_email`] — the emails allowed in, and
    /// never empty ([`compile_admins`]).
    admins: Vec<String>,
    /// `BB_AUTH_WEB_BASE_PATH`, normalised by [`normalize_base_path`]: `""` or `/admin`.
    /// Every internal href carries it and the router strips it.
    base_path: String,
    /// `BB_AUTH_WEB_DEFAULT_LANG`, used when a request expresses no preference at all.
    default_lang: Lang,
}

/// Read an env var, falling back to `default` when unset.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read a required env var, or exit(1).
fn env_req(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        eprintln!("[bb-auth-web] FATAL: missing required env var {key}");
        std::process::exit(1);
    })
}

/// Compile `BB_AUTH_WEB_ADMINS` — comma-separated emails — into the allowlist. Entries are
/// trimmed, lowercased ([`norm_email`], so a login's capitalisation cannot matter) and
/// deduplicated; blank entries are dropped, which is what makes a trailing comma harmless.
///
/// **An empty result is an error**, never "everyone". This list is the only thing standing
/// between a `public_auth` site that happens to cover the GUI's URL and an admin surface
/// open to any Cognito account — and Cognito self-signup is open.
///
/// Pure and fallible so it can be tested; [`Config::from_env`] turns an `Err` into the usual
/// fatal exit.
fn compile_admins(spec: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for email in spec.split(',').map(norm_email).filter(|e| !e.is_empty()) {
        if !out.contains(&email) {
            out.push(email);
        }
    }
    if out.is_empty() {
        return Err("no admin emails — this must never mean 'everyone'".into());
    }
    Ok(out)
}

/// Normalise `BB_AUTH_WEB_BASE_PATH` — the prefix nginx mounts the GUI at.
///
/// Empty stays empty (mounted at the root). Otherwise a leading `/` is added if missing and
/// trailing ones are stripped, so `admin/` and `/admin` both become `/admin` and hrefs can
/// concatenate it with a route path without ever doubling a slash.
///
/// Rejects anything that is not printable ASCII, plus `?` and `#`: this string is prefixed
/// to every href *and* to the `Location:` of the language redirect, and that check at load
/// is what makes both emissions safe with no per-use escape — the same argument as the
/// gate's `compile_login_url`.
fn normalize_base_path(raw: &str) -> Result<String, String> {
    let p = raw.trim().trim_end_matches('/');
    if p.is_empty() {
        return Ok(String::new());
    }
    if !p.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "'{raw}': must be printable ASCII (no spaces, no control bytes)"
        ));
    }
    if p.contains('?') || p.contains('#') {
        return Err(format!("'{raw}': a path prefix cannot contain '?' or '#'"));
    }
    Ok(match p.strip_prefix('/') {
        Some(_) => p.to_string(),
        None => format!("/{p}"),
    })
}

impl Config {
    /// Build the config from the environment, exiting on the first fatal problem.
    fn from_env() -> Config {
        let admins = compile_admins(&env_req("BB_AUTH_WEB_ADMINS")).unwrap_or_else(|e| {
            eprintln!("[bb-auth-web] FATAL: BB_AUTH_WEB_ADMINS: {e}");
            std::process::exit(1);
        });
        let base_path =
            normalize_base_path(&env_or("BB_AUTH_WEB_BASE_PATH", "")).unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: BB_AUTH_WEB_BASE_PATH: {e}");
                std::process::exit(1);
            });
        let raw_lang = env_or("BB_AUTH_WEB_DEFAULT_LANG", "en");
        let default_lang = parse_lang(&raw_lang).unwrap_or_else(|| {
            eprintln!(
                "[bb-auth-web] FATAL: BB_AUTH_WEB_DEFAULT_LANG: '{raw_lang}' is not en or it"
            );
            std::process::exit(1);
        });
        Config {
            listen: env_or("BB_AUTH_WEB_LISTEN", "127.0.0.1:8091"),
            access_path: env_req("BB_AUTH_USERS_FILE"),
            admins,
            base_path,
            default_lang,
        }
    }

    /// Whether `email` (already [`norm_email`]-normalised) may use the GUI.
    fn is_admin(&self, email: &str) -> bool {
        self.admins.iter().any(|a| a == email)
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// A page. The four section routes are the access file's four sections, which is the whole
/// navigation: what the file has, the GUI has a tab for. Everything else is a form, a
/// confirmation, or the one `POST`-only route ([`Route::ScopeMove`]).
///
/// A route that mutates is reached by `POST` on **the same path** that renders its form by
/// `GET`, which is what makes "re-render this form with the library's refusal" a matter of
/// calling the same page function again. The names a route carries — an email, a key id, a
/// site or group name — are already percent-**decoded**.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Route {
    Dashboard,
    /// The applications, which is where every grant in the file is written.
    Apps,
    /// One application and its scopes, in file order.
    App(String),
    /// The user groups.
    Groups,
    Denied,
    Users,
    /// One roster row, addressed by its uuid: the identity is what the file references,
    /// and an email can be added or dropped without the page moving.
    User(String),
    Can,

    AppAdd,
    AppEdit(String),
    AppRm(String),
    /// A scope is named by its application and its own name, which is exactly how the file
    /// and both editors name it: `app/scope`.
    ScopeAdd(String),
    ScopeEdit(String, String),
    ScopeRm(String, String),
    /// `POST` only: a per-row button, so there is nothing to render on a `GET`.
    ScopeMove(String, String),

    UserAdd,
    UserEdit(String),
    UserRm(String),
    /// An identifier is added and dropped on its own, because that is what replaced a
    /// rename: the identity never changes.
    EmailAdd(String),
    EmailRm(String, String),
    KeyAdd(String),
    KeyEdit(String, String),
    KeyRotate(String, String),
    KeyRm(String, String),

    GroupAdd,
    GroupEdit(String),
    GroupRm(String),

    DenyAdd,
    DenyRm(String),
}

/// The segment that marks an action rather than a name, in a position where a name could
/// also appear (`/users/+add` vs `/users/bob@x.com`).
///
/// A `+` is what makes the two unambiguous, and by construction rather than by luck:
/// [`pct_encode_segment`] escapes everything outside the unreserved set, `+` included, so
/// no href this binary builds for a name can ever spell one — whatever the roster holds.
const ACTION_ADD: &str = "+add";

impl Route {
    /// This route's path below the base — the canonical spelling, which is also what every
    /// href, the language redirect and the post-mutation `Location:` are built from. Nothing
    /// a client sent survives into one: names are re-encoded by [`pct_encode_segment`], so
    /// the result is printable ASCII whatever the access file contains.
    fn path(&self) -> String {
        let seg = pct_encode_segment;
        match self {
            Route::Dashboard => "/".to_string(),
            Route::Apps => "/apps".to_string(),
            Route::App(a) => format!("/apps/{}", seg(a)),
            Route::Groups => "/groups".to_string(),
            Route::Denied => "/denied".to_string(),
            Route::Users => "/users".to_string(),
            Route::User(u) => format!("/users/{}", seg(u)),
            Route::Can => "/can".to_string(),

            Route::AppAdd => format!("/apps/{ACTION_ADD}"),
            Route::AppEdit(a) => format!("/apps/{}/edit", seg(a)),
            Route::AppRm(a) => format!("/apps/{}/rm", seg(a)),
            Route::ScopeAdd(a) => format!("/apps/{}/scopes/{ACTION_ADD}", seg(a)),
            Route::ScopeEdit(a, s) => format!("/apps/{}/scopes/{}/edit", seg(a), seg(s)),
            Route::ScopeRm(a, s) => format!("/apps/{}/scopes/{}/rm", seg(a), seg(s)),
            Route::ScopeMove(a, s) => format!("/apps/{}/scopes/{}/move", seg(a), seg(s)),

            Route::UserAdd => format!("/users/{ACTION_ADD}"),
            Route::UserEdit(u) => format!("/users/{}/edit", seg(u)),
            Route::UserRm(u) => format!("/users/{}/rm", seg(u)),
            Route::EmailAdd(u) => format!("/users/{}/emails/{ACTION_ADD}", seg(u)),
            Route::EmailRm(u, e) => format!("/users/{}/emails/{}/rm", seg(u), seg(e)),
            Route::KeyAdd(u) => format!("/users/{}/keys/{ACTION_ADD}", seg(u)),
            Route::KeyEdit(u, i) => format!("/users/{}/keys/{}/edit", seg(u), seg(i)),
            Route::KeyRotate(u, i) => format!("/users/{}/keys/{}/rotate", seg(u), seg(i)),
            Route::KeyRm(u, i) => format!("/users/{}/keys/{}/rm", seg(u), seg(i)),

            Route::GroupAdd => format!("/groups/{ACTION_ADD}"),
            Route::GroupEdit(n) => format!("/groups/{}/edit", seg(n)),
            Route::GroupRm(n) => format!("/groups/{}/rm", seg(n)),

            Route::DenyAdd => format!("/denied/{ACTION_ADD}"),
            Route::DenyRm(e) => format!("/denied/{}/rm", seg(e)),
        }
    }

    /// Which nav tab to mark current for this route: everything about a user belongs to
    /// the `users` tab, and so on down the sections. `denied` has no tab of its own: its
    /// page still lives at its own route, but the bar lights up `users` for it, since the
    /// two are the sections about people and [`page_users`] is where an operator now finds
    /// both.
    fn tab(&self) -> Route {
        match self {
            Route::User(_)
            | Route::UserAdd
            | Route::UserEdit(_)
            | Route::UserRm(_)
            | Route::EmailAdd(_)
            | Route::EmailRm(..)
            | Route::KeyAdd(_)
            | Route::KeyEdit(..)
            | Route::KeyRotate(..)
            | Route::KeyRm(..)
            | Route::Denied
            | Route::DenyAdd
            | Route::DenyRm(_) => Route::Users,
            Route::App(_)
            | Route::AppAdd
            | Route::AppEdit(_)
            | Route::AppRm(_)
            | Route::ScopeAdd(_)
            | Route::ScopeEdit(..)
            | Route::ScopeRm(..)
            | Route::ScopeMove(..) => Route::Apps,
            Route::GroupAdd | Route::GroupEdit(_) | Route::GroupRm(_) => Route::Groups,
            other => other.clone(),
        }
    }

    /// Where a form's `cancel` link goes, and where a `409` offers to send the browser
    /// back: the page this route was reached *from*.
    fn parent(&self) -> Route {
        match self {
            Route::UserEdit(u)
            | Route::UserRm(u)
            | Route::EmailAdd(u)
            | Route::EmailRm(u, _)
            | Route::KeyAdd(u)
            | Route::KeyEdit(u, _)
            | Route::KeyRotate(u, _)
            | Route::KeyRm(u, _) => Route::User(u.clone()),
            Route::UserAdd => Route::Users,
            // A scope's form was reached from its application's page, which is the only
            // place a scope is ever listed: order is meaning there, so it is where an
            // operator needs to land back.
            Route::ScopeAdd(a)
            | Route::ScopeEdit(a, _)
            | Route::ScopeRm(a, _)
            | Route::ScopeMove(a, _)
            | Route::AppEdit(a)
            | Route::AppRm(a) => Route::App(a.clone()),
            Route::AppAdd => Route::Apps,
            Route::GroupAdd | Route::GroupEdit(_) | Route::GroupRm(_) => Route::Groups,
            Route::DenyAdd | Route::DenyRm(_) => Route::Denied,
            other => other.clone(),
        }
    }

    /// The `<title>`: the section's own name, untranslated, because that is the word an
    /// operator types. Matched on `self` and not on [`Route::tab`]: `denied` now shares the
    /// `users` *tab*, but its `<title>` should still say which page this is, not which tab
    /// is lit.
    fn title(&self) -> &'static str {
        match self {
            Route::Denied | Route::DenyAdd | Route::DenyRm(_) => "denied",
            _ => match self.tab() {
                Route::Groups => "user_groups",
                Route::Apps => "applications",
                Route::Users => "users",
                Route::Can => "can",
                _ => "bb-auth-web",
            },
        }
    }
}

/// Resolve a request path to a page, or `None` for a 404.
///
/// `base` is [`normalize_base_path`]'s output. A request outside it is not this service's —
/// it 404s rather than falling through to the dashboard, so a misconfigured `location` in
/// nginx shows up as a missing page instead of a GUI that silently answers everywhere.
///
/// Segments are decoded one by one, so a name containing a `/` (a key id may) round-trips
/// through [`Route::path`] and back. Literal arms come before the ones that capture a name;
/// [`ACTION_ADD`] is why that is unambiguous rather than a precedence a future name could
/// steal.
fn route(path: &str, base: &str) -> Option<Route> {
    let rest = if base.is_empty() {
        path
    } else {
        match path.strip_prefix(base) {
            // `/admin` and `/admin/…` are ours; `/administrivia` is not.
            Some("") => "/",
            Some(r) if r.starts_with('/') => r,
            _ => return None,
        }
    };
    let decoded: Vec<String> = rest
        .trim_end_matches('/')
        .split('/')
        .skip(1)
        .map(pct_decode)
        .collect();
    let segs: Vec<&str> = decoded.iter().map(String::as_str).collect();
    let s = |x: &&str| x.to_string();
    match segs.as_slice() {
        [] | [""] => Some(Route::Dashboard),
        ["can"] => Some(Route::Can),

        ["users"] => Some(Route::Users),
        ["users", ACTION_ADD] => Some(Route::UserAdd),
        ["users", u] if !u.is_empty() => Some(Route::User(s(u))),
        ["users", u, "edit"] if !u.is_empty() => Some(Route::UserEdit(s(u))),
        ["users", u, "rm"] if !u.is_empty() => Some(Route::UserRm(s(u))),
        ["users", u, "emails", ACTION_ADD] if !u.is_empty() => Some(Route::EmailAdd(s(u))),
        ["users", u, "emails", e, "rm"] if !u.is_empty() => Some(Route::EmailRm(s(u), s(e))),
        ["users", u, "keys", ACTION_ADD] if !u.is_empty() => Some(Route::KeyAdd(s(u))),
        ["users", u, "keys", i, "edit"] if !u.is_empty() => Some(Route::KeyEdit(s(u), s(i))),
        ["users", u, "keys", i, "rotate"] if !u.is_empty() => Some(Route::KeyRotate(s(u), s(i))),
        ["users", u, "keys", i, "rm"] if !u.is_empty() => Some(Route::KeyRm(s(u), s(i))),

        ["apps"] => Some(Route::Apps),
        ["apps", ACTION_ADD] => Some(Route::AppAdd),
        ["apps", a] if !a.is_empty() => Some(Route::App(s(a))),
        ["apps", a, "edit"] if !a.is_empty() => Some(Route::AppEdit(s(a))),
        ["apps", a, "rm"] if !a.is_empty() => Some(Route::AppRm(s(a))),
        ["apps", a, "scopes", ACTION_ADD] if !a.is_empty() => Some(Route::ScopeAdd(s(a))),
        ["apps", a, "scopes", n, "edit"] if !a.is_empty() => Some(Route::ScopeEdit(s(a), s(n))),
        ["apps", a, "scopes", n, "rm"] if !a.is_empty() => Some(Route::ScopeRm(s(a), s(n))),
        ["apps", a, "scopes", n, "move"] if !a.is_empty() => Some(Route::ScopeMove(s(a), s(n))),

        ["groups"] => Some(Route::Groups),
        ["groups", ACTION_ADD] => Some(Route::GroupAdd),
        ["groups", n, "edit"] if !n.is_empty() => Some(Route::GroupEdit(s(n))),
        ["groups", n, "rm"] if !n.is_empty() => Some(Route::GroupRm(s(n))),

        ["denied"] => Some(Route::Denied),
        ["denied", ACTION_ADD] => Some(Route::DenyAdd),
        ["denied", e, "rm"] if !e.is_empty() => Some(Route::DenyRm(s(e))),

        _ => None,
    }
}

/// Percent-encode one path segment per RFC 3986: everything outside the unreserved set
/// becomes `%XX`.
///
/// Hand-rolled for the same reason the gate hand-rolls its own: `form_urlencoded` is the
/// wrong grammar here. It spells a space `+`, which would make `a+tag@x.com` — a perfectly
/// ordinary address — ambiguous with `a tag@x.com` in a path segment. Encoding and decoding
/// are exact inverses, and the output is printable ASCII for **any** input, which is what
/// lets a route path go into a `Location:` header unchecked.
fn pct_encode_segment(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// The inverse of [`pct_encode_segment`]: `%XX` decoded, every other byte literal — a `+`
/// is a `+`. Invalid UTF-8 is replaced rather than rejected; the result is only ever
/// compared against roster emails, and a mangled one simply matches nobody.
fn pct_decode(s: &str) -> String {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (
            b[i],
            b.get(i + 1).copied().and_then(hex),
            b.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(hi), Some(lo)) => {
                out.push(hi * 16 + lo);
                i += 3;
            }
            _ => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// First request header matching `name`, compared case-insensitively.
fn header_value<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

/// Pull one cookie's value out of a `Cookie:` header.
fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header
        .split(';')
        .filter_map(|p| p.trim().strip_prefix(name))
        .find_map(|rest| rest.strip_prefix('='))
}

/// The value of query parameter `name`. `form_urlencoded` **is** the right grammar here —
/// this is what a browser puts in the query string when it submits the `can` form.
fn query_param(query: &str, name: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Build a response header. Panics only on a caller-side bug; every call site passes a
/// constant or a value that is printable ASCII by construction.
fn h(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("valid header")
}

/// Is this `POST` a same-origin form submission?
///
/// Two questions, in the order the browser answers them best:
///
/// * **`Sec-Fetch-Site`** is set by the browser on every request and cannot be set by a
///   page, so where it exists it is the whole answer: `same-origin` passes, anything else
///   (`cross-site`, `same-site`, `none`) does not.
/// * **`Origin`** is the fallback, and only its **host** is compared — against the `Host:`
///   header's. Not the scheme: this binary speaks plain HTTP behind a TLS-terminating
///   nginx, so the browser's `https://…` origin can never equal a scheme reconstructed
///   here, and comparing one would refuse every honest request. The port travels with the
///   host in both headers, so comparing the authority as written is right in the
///   default-port case *and* the explicit-port one.
///
/// Neither header present ⇒ **refused**. That is not a browser submitting a form, and no
/// token in the page would help against a client that sends neither.
fn csrf_ok(sec_fetch_site: Option<&str>, origin: Option<&str>, host: Option<&str>) -> bool {
    if let Some(sfs) = sec_fetch_site {
        return sfs.trim().eq_ignore_ascii_case("same-origin");
    }
    match (origin, host) {
        (Some(o), Some(hst)) => {
            let authority = o
                .trim()
                .split_once("://")
                .map(|(_, rest)| rest.trim_end_matches('/'));
            authority.is_some_and(|a| !a.is_empty() && a.eq_ignore_ascii_case(hst.trim()))
        }
        _ => false,
    }
}

/// The most a form body may be. Every field here is an email, a name or a handful of URL
/// patterns; anything past this is not one of our forms, and reading it would be a way to
/// make a 2-thread server chew memory.
const MAX_BODY: usize = 256 * 1024;

/// Read a request body, capped. A truncated read is not distinguished from a short one on
/// purpose: what comes out is parsed as a form, and a form missing its `rev` is refused by
/// the concurrency check anyway.
fn read_body(req: &mut Request) -> String {
    let mut body = String::new();
    let _ = req
        .as_reader()
        .take(MAX_BODY as u64)
        .read_to_string(&mut body);
    body
}

/// A submitted form, parsed once. `form_urlencoded` is exactly the right grammar here: this
/// is what a browser sends for a `<form method="post">` with no `enctype`.
///
/// The content type is deliberately not checked. A body in another grammar simply does not
/// produce the fields a handler asks for — starting with `rev`, whose absence is a refusal —
/// so there is nothing a wrong `Content-Type` buys that the same-origin check does not
/// already deny.
struct Form(Vec<(String, String)>);

impl Form {
    fn parse(body: &str) -> Form {
        Form(
            form_urlencoded::parse(body.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
        )
    }

    /// The first value of `name`, or `""`. Nothing is trimmed here — a field that must be
    /// trimmed says so at its use.
    fn get(&self, name: &str) -> &str {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map_or("", |(_, v)| v.as_str())
    }

    /// A checkbox: present at all ⇒ ticked. Browsers omit an unticked box entirely.
    fn checked(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| k == name)
    }

    /// A textarea of URL patterns, one per line: trimmed, blanks dropped. `@refs` are left
    /// exactly as typed — the file's own spelling, which is what the library expands.
    fn lines(&self, name: &str) -> Vec<String> {
        self.get(name)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }
}

/// Send a rendered page.
///
/// `Response::from_data` rather than `from_string` because the latter installs its own
/// `Content-Type: text/plain` header that `with_header` would then *append* to rather than
/// replace, putting two of them on the wire.
///
/// Three headers on every response, and they are the same three every time: `no-store`
/// because a page is a snapshot of a file that changes under it, `nosniff` because a browser
/// guessing at a content type is a browser deciding something we already know, and the
/// charset because the roster is full of names that are not ASCII.
fn respond_page(req: Request, status: u16, page: Markup) {
    let resp = Response::from_data(page.into_string().into_bytes())
        .with_status_code(StatusCode(status))
        .with_header(h("Content-Type", "text/html; charset=utf-8"))
        .with_header(h("Cache-Control", "no-store"))
        .with_header(h("X-Content-Type-Options", "nosniff"));
    let _ = req.respond(resp);
}

/// `302` to `location`, setting one preference cookie to `value`. `location` is built from a
/// [`Route`] and re-encoded query parameters, so it is printable ASCII by construction and
/// [`h`] cannot panic on it; `value` is always one of a closed enum's own [`Lang::code`] or
/// [`Theme::code`], never request-supplied.
///
/// The one redirect both preferences use: see [`respond_lang_redirect`] and
/// [`respond_theme_redirect`].
fn respond_preference_redirect(req: Request, location: &str, cookie_name: &str, value: &str) {
    let cookie =
        format!("{cookie_name}={value}; Max-Age={PREFERENCE_COOKIE_MAX_AGE}; Path=/; HttpOnly; SameSite=Lax");
    let resp = Response::empty(StatusCode(302))
        .with_header(h("Location", location))
        .with_header(h("Set-Cookie", &cookie[..]))
        .with_header(h("Cache-Control", "no-store"));
    let _ = req.respond(resp);
}

/// [`respond_preference_redirect`] for a language choice. It takes the [`LangPref`] and not
/// the [`Lang`] it resolved to: `Auto` has to be storable, or choosing it would write the
/// language it happens to resolve to today and stop following the browser.
fn respond_lang_redirect(req: Request, location: &str, pref: LangPref) {
    respond_preference_redirect(req, location, LANG_COOKIE, pref.code());
}

/// [`respond_preference_redirect`] for a theme choice.
fn respond_theme_redirect(req: Request, location: &str, theme: Theme) {
    respond_preference_redirect(req, location, THEME_COOKIE, theme.code());
}

/// `303` to `location` — the redirect half of POST-redirect-GET, so a reload of the result
/// page cannot repeat the mutation.
///
/// `303` and not `302`: it is the status that tells every browser to follow with a `GET`,
/// which is the entire point. `location` is a [`Route::path`] under the base plus a
/// [`Msg::key`], both printable ASCII by construction, so [`h`] cannot panic on it — and
/// nothing request-supplied is in it.
fn respond_redirect(req: Request, location: &str) {
    let resp = Response::empty(StatusCode(303))
        .with_header(h("Location", location))
        .with_header(h("Cache-Control", "no-store"));
    let _ = req.respond(resp);
}

/// The preference in force and the language it renders as. Query, then cookie, then
/// `Accept-Language`, then the configured default — most explicit wins.
///
/// Both halves come back because the page needs both, and they are genuinely different
/// questions: the [`Lang`] looks every string up, while the [`LangPref`] is which option the
/// Settings menu must show as chosen, and `Auto` and `en` can render the identical page
/// while being different answers to that one. Returning the pair from a single function is
/// what keeps the rule stated once, where two negotiate calls could drift apart.
///
/// The `Accept-Language` check is deliberately crude: does the header start with `it`? A
/// full RFC 4647 negotiation over two languages would be more code than the question is
/// worth, and both wrong answers are one choice in the menu from being right (and then
/// remembered).
fn negotiate_lang(
    query: Option<&str>,
    cookie: Option<&str>,
    accept: Option<&str>,
    default: Lang,
) -> (LangPref, Lang) {
    let pref = query
        .and_then(parse_lang_pref)
        .or_else(|| cookie.and_then(parse_lang_pref))
        .unwrap_or(LangPref::Auto);
    let lang = match pref {
        LangPref::Fixed(l) => l,
        LangPref::Auto
            if accept.is_some_and(|a| a.trim().to_ascii_lowercase().starts_with("it")) =>
        {
            Lang::It
        }
        LangPref::Auto => default,
    };
    (pref, lang)
}

/// Which theme to render in. Query, then cookie, then `Theme::System`: most explicit wins,
/// and `System` is the floor rather than a configured default, since there is nothing to
/// configure; it is what every session already has until it chooses otherwise.
fn negotiate_theme(query: Option<&str>, cookie: Option<&str>) -> Theme {
    if let Some(t) = query.and_then(parse_theme) {
        return t;
    }
    if let Some(t) = cookie.and_then(parse_theme) {
        return t;
    }
    Theme::System
}

/// This request's URL with the `param` query parameter dropped: where a preference redirect
/// lands, once the choice that parameter carried has become a cookie. The rest of the query
/// survives, which is what keeps a `can` result on screen across a preference change.
///
/// One builder for both preferences, named by the cookie constant at the call site
/// (`LANG_COOKIE`, `THEME_COOKIE`): each doubles as its query parameter's name, so there is
/// one spelling per preference and no second place to keep in step. Every byte of the result
/// is a constant, a [`Route::path`] or a re-encoded query parameter — nothing the client sent
/// survives verbatim, which is what makes the string safe in a `Location:` header.
fn preference_href(cfg: &Config, at: &Route, query: &str, param: &str) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        if k != param {
            ser.append_pair(&k, &v);
        }
    }
    let q = ser.finish();
    let path = format!("{}{}", cfg.base_path, at.path());
    if q.is_empty() {
        path
    } else {
        format!("{path}?{q}")
    }
}

/// The query as received, minus the two parameters the Settings form sets itself, as hidden
/// fields for that form to put back.
///
/// A switch that was a link could rebuild the whole URL ([`preference_href`]); a `GET` form
/// sends its own fields and nothing else, so without this, changing the theme on a `can`
/// result page would throw the result away. `msg` is deliberately *not* dropped: the flash
/// belongs to the page the operator is looking at, and survived the old switch links too.
fn preserved_query(query: &str) -> Vec<(String, String)> {
    form_urlencoded::parse(query.as_bytes())
        .filter(|(k, _)| k != LANG_COOKIE && k != THEME_COOKIE)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

/// Everything the page shell needs that is not the page.
struct View<'a> {
    cfg: &'a Config,
    lang: Lang,
    /// Which option the Settings menu shows as the chosen language, which is not the same
    /// thing as `lang`: `Auto` renders as one of the two and must still come back as `Auto`
    /// (see [`LangPref`]). Both come from one [`negotiate_lang`] call.
    lang_pref: LangPref,
    /// Which appearance to render in; see [`Theme`]. `System` unless the visitor chose
    /// otherwise, in which case [`shell`] stamps the choice onto `html` as `data-theme`.
    /// It is its own chosen-option marker too, `System` included, which is why the theme
    /// needs no second field beside this one.
    theme: Theme,
    /// The signed-in administrator, when there is one. `None` suppresses the navigation:
    /// a visitor who got a `401` or a `403` has nowhere to go but the login page.
    admin: Option<&'a str>,
    /// The route being rendered, for the current tab and the language switch.
    at: Route,
    /// The query as received, so switching language keeps the `can` form filled in.
    query: &'a str,
    /// sha256 of the access file's exact bytes as this request read them. Every form on the
    /// page carries it, and the `POST` that comes back must still match — see [`mutate`].
    /// Empty when the file could not be read, in which case there is no form to render.
    rev: &'a str,
    /// What the redirect that landed here says it did, if this binary said it ([`Msg`]).
    msg: Option<Msg>,
}

impl View<'_> {
    fn t(&self, key: K) -> &'static str {
        t(self.lang, key)
    }

    /// An absolute href for one of our own routes.
    fn href(&self, at: &Route) -> String {
        format!("{}{}", self.cfg.base_path, at.path())
    }
}

/// The chrome around every page: the tabs, the Settings menu, the footer.
///
/// Five tabs, not the file's four sections plus the tester: `denied` shares the `users` tab
/// (see [`Route::tab`]) because both are about people, and the page itself moved to sit at
/// the bottom of [`page_users`] rather than stand on its own in the bar. What is left reads
/// left to right roughly as the file reads top to bottom, dashboard in front and the tester
/// at the end. Labels are translated, descriptive prose about a section ([`K::Groups`] and
/// friends), not the section's own name in the file; that name still appears, untranslated,
/// beside the heading each tab leads to.
fn shell(v: &View, title: &str, content: Markup) -> Markup {
    let tabs = [
        (Route::Dashboard, v.t(K::Dashboard)),
        (Route::Groups, v.t(K::Groups)),
        (Route::Apps, v.t(K::Apps)),
        (Route::Users, v.t(K::Users)),
        (Route::Can, v.t(K::Can)),
    ];
    let current = v.at.tab();
    // The two list boxes' options, each in the order they are offered. Both lead with the
    // choice that follows something outside this GUI (the browser, the OS), because that is
    // where every session starts and what the other options are departures from.
    let langs = [
        LangPref::Auto,
        LangPref::Fixed(Lang::En),
        LangPref::Fixed(Lang::It),
    ];
    let themes = [Theme::System, Theme::Light, Theme::Dark];
    html! {
        (DOCTYPE)
        // `data-theme=[v.theme.attr()]` is maud's optional-attribute form: `Theme::System`'s
        // `None` omits the attribute outright rather than emitting `data-theme=""`, which is
        // what leaves the `prefers-color-scheme` rule in `CSS` as the one deciding.
        html lang=(v.lang.code()) data-theme=[v.theme.attr()] {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { "bb-auth-web · " (title) }
                // The one deliberately raw emission on any page: a compile-time constant,
                // never request data and never anything read out of the access file.
                style { (PreEscaped(CSS)) }
            }
            body {
                header class="top" {
                    div class="bar" {
                        // The brand is the way home, but only when there is a home to go
                        // to: the 403 page has no nav for the same reason, so the brand
                        // stays the plain inert span it always was.
                        @if v.admin.is_some() {
                            a class="brand" href=(v.href(&Route::Dashboard)) {
                                "bb-auth-web"
                                span class="v" { "v" (env!("CARGO_PKG_VERSION")) }
                            }
                        } @else {
                            span class="brand" {
                                "bb-auth-web"
                                span class="v" { "v" (env!("CARGO_PKG_VERSION")) }
                            }
                        }
                        @if v.admin.is_some() {
                            nav {
                                @for (r, label) in &tabs {
                                    a class=@if *r == current { "pill on" } @else { "pill" }
                                      href=(v.href(r)) { (label) }
                                }
                            }
                        } @else {
                            nav {}
                        }
                        // The Settings menu: `details` is the disclosure widget HTML has had
                        // all along, so the menu opens with no script, and closes by itself
                        // on submit, because submitting reloads the page. The form is a
                        // plain `GET` back to this same route, which is exactly the URL the
                        // old switch links built by hand; the handler below turns each
                        // parameter into a cookie and redirects it back out.
                        details class="settings" {
                            summary class="pill" { (v.t(K::Settings)) }
                            div class="menu" {
                                // class=edit is not decoration here: it is the form
                                // furniture every other field in this GUI is dressed in, and
                                // a settings field that invented its own would be one more
                                // thing on the page that looks like nothing else.
                                form class="edit" method="get" action=(v.href(&v.at)) {
                                    @for (k, val) in preserved_query(v.query) {
                                        input type="hidden" name=(k) value=(val);
                                    }
                                    label {
                                        span class="lbl" { (v.t(K::SettingLanguage)) }
                                        select name=(LANG_COOKIE) onchange=(SETTINGS_ONCHANGE) {
                                            @for p in langs {
                                                option value=(p.code()) selected[p == v.lang_pref] {
                                                    (p.label(v.lang))
                                                }
                                            }
                                        }
                                    }
                                    label {
                                        span class="lbl" { (v.t(K::SettingTheme)) }
                                        select name=(THEME_COOKIE) onchange=(SETTINGS_ONCHANGE) {
                                            @for th in themes {
                                                option value=(th.code()) selected[th == v.theme] {
                                                    (v.t(th.label()))
                                                }
                                            }
                                        }
                                    }
                                    // The way in for a browser with scripting off, and the
                                    // only path that sets both preferences at once. With
                                    // scripting on the browser parses this as text, so the
                                    // button is not in the DOM at all and picking an option
                                    // is the whole interaction.
                                    noscript { div class="actions" { button { (v.t(K::Apply)) } } }
                                }
                            }
                        }
                    }
                }
                main {
                    // The one thing a redirect is allowed to say, from a closed set.
                    @if let Some(msg) = v.msg {
                        div class="flash" { (msg.text(v.lang)) }
                    }
                    (content)
                }
                footer {
                    span { (v.t(K::ReloadHint)) " " code { "systemctl reload bb-auth" } }
                    @if let Some(a) = v.admin {
                        span { (v.t(K::SignedInAs)) " " code { (a) } }
                    }
                }
            }
        }
    }
}

/// A rounded label — a `denied` badge, an expiry state, `public_auth`.
fn tag(class: &str, text: &str) -> Markup {
    html! { span class=(format!("tag {class}")) { (text) } }
}

/// A top-level section page's `h1`: the descriptive, translated label the nav now carries,
/// with the access file's own key for that section beside it in muted monospace. The label
/// is the headline; the key is what the docs, the CLI and the file itself all speak, so it
/// must not disappear, only stop being the first thing an operator reads.
fn section_heading(label: &str, key: &str) -> Markup {
    html! { (label) " " span class="muted mono" { (key) } }
}

/// A URL-pattern list as the file stores it. `@group` references are shown **raw, never
/// expanded**: the file is what an operator edits and what `bb-auth-adm` prints, so a page
/// that quietly substituted a group's patterns would be showing something nobody wrote.
fn url_list(lang: Lang, urls: Option<&Vec<String>>, absent: &str) -> Markup {
    html! {
        @match urls {
            None => span class="muted" { (absent) },
            Some(l) if l.is_empty() => span class="bad" { "[] — " (t(lang, K::ReachesNothing)) },
            Some(l) => ul class="plain mono" { @for u in l { li { (u) } } },
        }
    }
}

// ---------------------------------------------------------------------------
// Form furniture
// ---------------------------------------------------------------------------

/// A refused submission: the library's or a handler's own sentence, verbatim, and, only
/// when the failing step can be about exactly one field, the wire `name=` of that field.
///
/// Most refusals attribute nothing: a bare `String` converts into one via [`From`] with
/// `field: None`, so a `?` on a library call that cannot be pinned to one field costs a
/// handler nothing. [`Refusal::on`] is the deliberate exception, spelled out at each call
/// site [`mutate`] attributes; never guessed from the message text.
struct Refusal {
    msg: String,
    field: Option<&'static str>,
}

impl Refusal {
    /// Attribute this refusal to the field named `field` (its `name=` attribute, exactly).
    fn on(field: &'static str, msg: impl Into<String>) -> Self {
        Refusal {
            msg: msg.into(),
            field: Some(field),
        }
    }

    /// `true` when this refusal is attributed to the field named `name`: what
    /// [`text_field`] and [`urls_field`] ask to decide whether to render themselves invalid.
    fn is(&self, name: &str) -> bool {
        self.field == Some(name)
    }
}

impl From<String> for Refusal {
    /// The common case: a message with nothing to attribute it to.
    fn from(msg: String) -> Self {
        Refusal { msg, field: None }
    }
}

/// The id of a form's `div.err` block. The one field a [`Refusal`] is attributed to points
/// at it with `aria-describedby`, since the message itself lives above the form, not beside
/// the field.
const ERR_ID: &str = "form-error";

/// The scaffold every editing form shares: the `POST` back to the route that rendered it,
/// the `rev` the concurrency check reads, the refusal above the fields it is about, and a
/// way out that changes nothing.
///
/// The action is always [`View::at`] — a form posts to the path it was served from — which
/// is what makes a re-render after a refusal literally the same call with an error added.
fn form_shell(
    v: &View,
    err: Option<&Refusal>,
    fields: Markup,
    submit: &str,
    danger: bool,
) -> Markup {
    html! {
        form class="edit" method="post" action=(v.href(&v.at)) {
            // The library's words, verbatim: the sentence `bb-auth-adm` prints for the same
            // refusal, so an operator who has read one recognises the other. `id` is what
            // an attributed field's `aria-describedby` points at.
            @if let Some(e) = err { div class="err" id=(ERR_ID) { (e.msg) } }
            input type="hidden" name="rev" value=(v.rev);
            (fields)
            div class="actions" {
                button type="submit" class=@if danger { "danger" } @else { "" } { (submit) }
                a class="pill" href=(v.href(&v.at.parent())) { (v.t(K::Cancel)) }
            }
        }
    }
}

/// A one-line text field. The label is the file's own field name wherever there is one.
/// The input also carries an `f-<name>` class, keyed off that same wire name, so the
/// stylesheet can size each field to what it holds (an email wide, a `duration` narrow)
/// without this helper knowing anything about measures itself.
///
/// `invalid` marks this as the one field a [`Refusal`] is attributed to: it adds `.invalid`
/// (the `.f-<name>` class stays, so the width rule still applies) to colour the border
/// `--bad`, and sets `aria-invalid` plus `aria-describedby` so the association with the
/// message above the form is real for assistive tech, not just a colour.
fn text_field(
    label: &str,
    name: &str,
    value: &str,
    placeholder: &str,
    hint: Option<&str>,
    invalid: bool,
) -> Markup {
    html! {
        label {
            span class="lbl" { (label) }
            input type="text" name=(name) value=(value) placeholder=(placeholder)
                  class=(format!("f-{name}{}", if invalid { " invalid" } else { "" }))
                  autocapitalize="off" spellcheck="false"
                  aria-invalid=[invalid.then_some("true")]
                  aria-describedby=[invalid.then_some(ERR_ID)];
            @if let Some(h) = hint { span class="hint" { (h) } }
        }
    }
}

/// A URL-pattern list: one per line, `@refs` written literally. The same shape for a user's
/// scope, a key's, a site's `urls` and a group's patterns — one grammar, as in the file.
///
/// `invalid` is the same attribution [`text_field`] takes: see its doc comment.
fn urls_field(label: &str, name: &str, value: &str, hint: Markup, invalid: bool) -> Markup {
    html! {
        label {
            // An empty label is a field whose heading is already above it (the key form's
            // scope radios) — not a blank line to leave in the page.
            @if !label.is_empty() { span class="lbl" { (label) } }
            textarea name=(name) rows="6" spellcheck="false" autocapitalize="off"
                      class=[invalid.then_some("invalid")]
                      aria-invalid=[invalid.then_some("true")]
                      aria-describedby=[invalid.then_some(ERR_ID)] { (value) }
            span class="hint" { (hint) }
        }
    }
}

/// The lines of a pattern list, as a textarea's value.
fn urls_text(urls: Option<&Vec<String>>) -> String {
    urls.map(|l| l.join("\n")).unwrap_or_default()
}

/// A small `add` / `edit` / `remove` pill beside the thing it acts on.
fn act(v: &View, at: &Route, label: &str) -> Markup {
    html! { a class="pill" href=(v.href(at)) { (label) } }
}

/// Same as [`act`], marked as the destructive member of its `.pills` group (CSS `.pill.rm`):
/// the one action here that removes a row, not just changes it. `rotate` replaces a credential
/// rather than deleting anything, so it stays plain [`act`]; only an actual `Rm` route earns
/// this.
fn act_rm(v: &View, at: &Route, label: &str) -> Markup {
    html! { a class="pill rm" href=(v.href(at)) { (label) } }
}

/// A confirmation page: what is about to go, what that means, and a `POST` that does it.
/// The `GET` that renders this changes nothing, which is the whole reason destructive
/// actions are two steps and not a link.
fn page_confirm(
    v: &View,
    heading: Markup,
    what: Markup,
    why: &str,
    button: &str,
    err: Option<&Refusal>,
) -> Markup {
    html! {
        h1 { (heading) }
        p class="lede" { (why) }
        div class="panel bad" {
            (what)
            (form_shell(v, err, html! {}, button, true))
        }
    }
}

/// "no such user / api key / site / url group" — a `GET` for a name the file does not have.
fn page_missing(v: &View, what: &str, name: &str, back: &Route) -> Markup {
    html! {
        h1 { (what) }
        p class="lede" { code { (name) } }
        p { a href=(v.href(back)) { "← " (v.t(K::Back)) } }
    }
}

// ---------------------------------------------------------------------------
// Key expiry
// ---------------------------------------------------------------------------

/// A key's validity window, resolved against the wall clock — the library's [`key_expiry`]
/// plus the "is that in the past?" the gate applies on every request.
enum Expiry {
    /// `released`/`duration` do not parse: the gate skips this key entirely.
    Invalid,
    Never,
    /// Unix seconds, and the days from now (negative once past).
    At(u64, i64),
}

/// Anything closer than this is called out on the dashboard. A month is the window in which
/// re-minting a key is a chore rather than an incident.
const SOON_DAYS: i64 = 30;

fn expiry_of(k: &ApiKeySpec, now: u64) -> Expiry {
    match key_expiry(&k.released, &k.duration) {
        None => Expiry::Invalid,
        Some(None) => Expiry::Never,
        Some(Some(exp)) => Expiry::At(exp, (exp as i64 - now as i64) / 86_400),
    }
}

impl Expiry {
    /// Sort rank for the dashboard table: what expires soonest first, then the broken ones
    /// (which need attention but have no date to sort by), then the ones that never expire.
    fn rank(&self) -> (u8, i64) {
        match self {
            Expiry::At(_, days) => (0, *days),
            Expiry::Invalid => (1, 0),
            Expiry::Never => (2, 0),
        }
    }
}

fn expiry_markup(lang: Lang, e: &Expiry) -> Markup {
    html! {
        @match e {
            Expiry::Invalid => (tag("bad", t(lang, K::KeyInvalid))),
            Expiry::Never => (tag("", t(lang, K::NeverExpires))),
            Expiry::At(exp, days) if *days < 0 => {
                (tag("bad", t(lang, K::Expired)))
                " " span class="mono muted" { (format_date(*exp)) }
            }
            Expiry::At(exp, days) if *days <= SOON_DAYS => {
                (tag("warn", t(lang, K::ExpiresSoon)))
                " " span class="mono muted" { (format_date(*exp)) " (" (days) "d)" }
            }
            Expiry::At(exp, days) => {
                span class="muted" { (t(lang, K::Expires)) " " }
                span class="mono" { (format_date(*exp)) }
                span class="muted" { " (" (days) "d)" }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// The emails on `denied`, normalised — every page that marks one needs this set.
/// How a uuid appears to an operator wherever a members list is rendered, or wherever a
/// route's own uuid needs a friendly heading: the roster's own label if the row still
/// exists, else the uuid itself — a dangling reference is shown for what it is rather than
/// hidden.
fn label_of(doc: &AccessFile, key: &str) -> String {
    let key = key.trim().to_ascii_lowercase();
    match user_pos(doc, &key) {
        Some(i) => user_label(&doc.users[i]),
        None => key,
    }
}

/// `/` — the counts, what expires next, and everything the file says that an operator would
/// rather hear now than at 3am.
///
/// The warnings are computed from library data only: [`Access::scopes_for`], the compiled
/// scopes (for shadowing and empty-membership), [`user_group_refs`] and [`Access::denied_users`].
/// Shadowing is a heuristic an earlier version of this doc comment kept out of the GUI on
/// the grounds that it needed an operator to explain itself to; it earns its place here
/// because the alternative — a scope that answers for nothing and nobody notices — is worse.
fn page_dashboard(v: &View, doc: &AccessFile, access: &Access) -> Markup {
    let n = now();
    let scope_count: usize = doc.applications.iter().map(|a| a.scopes.len()).sum();
    let key_count: usize = doc.users.iter().map(|u| u.api_keys.len()).sum();

    // Every key in the file, soonest expiry first.
    let mut keys: Vec<(&UserSpec, &ApiKeySpec, Expiry)> = doc
        .users
        .iter()
        .flat_map(|u| u.api_keys.iter().map(move |k| (u, k, expiry_of(k, n))))
        .collect();
    keys.sort_by_key(|(_, _, e)| e.rank());

    let mut warnings: Vec<Markup> = Vec::new();
    for (ai, a) in doc.applications.iter().enumerate() {
        for (si, s) in a.scopes.iter().enumerate() {
            if scope_shadowed(access, ai, &s.urls, si) {
                warnings.push(html! {
                    code { (a.name.trim()) "/" (s.name.trim()) } " " (v.t(K::WarnShadowed))
                });
            }
        }
    }
    for a in &access.apps {
        for s in &a.scopes {
            if s.access == bb_auth_core::AccessKind::Restricted && s.members.is_empty() {
                warnings.push(html! {
                    code { (a.name) "/" (s.name) } " " (v.t(K::WarnNoMembers))
                });
            }
        }
    }
    for u in &doc.users {
        let uuid = u.uuid.trim().to_ascii_lowercase();
        if access.scopes_for(&uuid).is_empty() {
            warnings.push(html! { code { (user_label(u)) } " " (v.t(K::WarnNoScope)) });
        }
        if access.denied_users.contains(&uuid) {
            warnings.push(html! { code { (user_label(u)) } " " (v.t(K::WarnEnrolledAndDenied)) });
        }
    }
    for name in doc.user_groups.keys() {
        if user_group_refs(doc, name).is_empty() {
            warnings.push(html! { code { "@" (name) } " " (v.t(K::ReferencedByNothing)) });
        }
    }

    html! {
        h1 { (v.t(K::Dashboard)) }
        p class="lede" { code { (v.cfg.access_path) } }

        h2 { (v.t(K::Counts)) }
        div class="cards" {
            @for (label, count, route) in [
                ("applications", doc.applications.len(), Some(Route::Apps)),
                ("scopes", scope_count, None),
                ("users", doc.users.len(), Some(Route::Users)),
                ("api_keys", key_count, None),
                ("user_groups", doc.user_groups.len(), Some(Route::Groups)),
                ("denied", doc.denied.len(), Some(Route::Denied)),
            ] {
                @if let Some(r) = &route {
                    a class="card" href=(v.href(r)) {
                        div class="n" { (count) }
                        div class="l mono" { (label) }
                    }
                } @else {
                    div class="card" {
                        div class="n" { (count) }
                        div class="l mono" { (label) }
                    }
                }
            }
        }

        h2 { (v.t(K::KeyExpiry)) }
        div class="panel" {
            @if keys.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                table {
                    thead { tr {
                        th { (v.t(K::ColOwner)) }
                        th { "id" }
                        th { (v.t(K::ColExpiry)) }
                    } }
                    tbody {
                        @for (u, k, e) in &keys {
                            @let uuid = u.uuid.trim().to_ascii_lowercase();
                            tr {
                                td data-label=(v.t(K::ColOwner)) {
                                    a href=(v.href(&Route::User(uuid))) { (user_label(u)) }
                                }
                                td class="mono" data-label="id" { (k.id.trim()) }
                                td data-label=(v.t(K::ColExpiry)) { (expiry_markup(v.lang, e)) }
                            }
                        }
                    }
                }
            }
        }

        h2 { (v.t(K::Warnings)) }
        div class=@if warnings.is_empty() { "panel" } @else { "panel warn" } {
            @if warnings.is_empty() {
                span class="muted" { (v.t(K::NoWarnings)) }
            } @else {
                ul class="plain" { @for w in &warnings { li { (*w) } } }
            }
        }
    }
}

/// Does an earlier scope of the same application already cover every URL this one has?
///
/// A heuristic, not an enumeration of every possible request: each of this scope's own raw
/// patterns is asked of an earlier scope's *compiled* matcher, so `https://x.com/*` is
/// correctly seen to shadow `https://x.com/admin/*` even though the two strings differ. It
/// can miss a shadow built from several earlier scopes whose patterns only jointly cover
/// this one pattern-by-pattern rather than each covering it outright; that is the price of
/// staying a straight read of compiled data rather than a second matcher.
fn scope_shadowed(access: &Access, app_idx: usize, urls: &[String], scope_idx: usize) -> bool {
    let earlier = &access.apps[app_idx].scopes[..scope_idx];
    !urls.is_empty()
        && !earlier.is_empty()
        && urls
            .iter()
            .map(|u| u.trim())
            .filter(|u| !u.is_empty())
            .all(|u| earlier.iter().any(|s| s.urls.allows(Some(u))))
}

/// `/users` — the roster.
fn page_users(v: &View, doc: &AccessFile, access: &Access) -> Markup {
    html! {
        h1 { (section_heading(v.t(K::Users), "users")) }
        p class="lede" { (v.t(K::UsersIntro)) }
        p class="primary" { (act(v, &Route::UserAdd, &format!("+ {}", v.t(K::Add)))) }
        div class="panel" {
            @if doc.users.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                table {
                    thead { tr {
                        th { (v.t(K::Emails)) }
                        th { "api_keys" }
                        th {}
                    } }
                    tbody {
                        @for u in &doc.users {
                            @let uuid = u.uuid.trim().to_ascii_lowercase();
                            tr {
                                td data-label=(v.t(K::Emails)) {
                                    a href=(v.href(&Route::User(uuid.clone()))) { (user_label(u)) }
                                    @if access.denied_users.contains(&uuid) {
                                        " " (tag("bad", "denied"))
                                    }
                                }
                                td data-label="api_keys" { (u.api_keys.len()) }
                                td class="pills" {
                                    (act_rm(v, &Route::UserRm(uuid.clone()), v.t(K::Remove)))
                                }
                            }
                        }
                    }
                }
            }
        }

        // The `denied` veto, as a second section of this same page rather than a tab of
        // its own: the two sections are both about people, and an operator managing the
        // roster is the one most likely to also need the veto list. The route `/denied`
        // still exists on its own (see `page_denied`) for the add/remove PRG redirects and
        // for a direct link; `denied_list` is what keeps the two views of the same list
        // from ever drifting apart.
        h2 { (v.t(K::Denied)) }
        p class="lede sub" { (v.t(K::DeniedIntro)) }
        p class="primary" { (act(v, &Route::DenyAdd, &format!("+ {}", v.t(K::Add)))) }
        (denied_list(v, doc))
    }
}

/// `/users/{uuid}` — one roster row, as the file stores it, plus the scopes computed from
/// [`Access::scopes_for`]: membership only, so a user reached by an `anonymous` or
/// `authenticated` scope is not listed here even though they get in — that is a property of
/// the scope, not of them.
fn page_user(v: &View, doc: &AccessFile, access: &Access, key: &str) -> (u16, Markup) {
    let u: &UserSpec = match user_pos(doc, key).map(|i| &doc.users[i]) {
        Some(u) => u,
        None => return (404, page_missing(v, v.t(K::NoSuchUser), key, &Route::Users)),
    };
    let n = now();
    let uuid = u.uuid.trim().to_ascii_lowercase();
    let denied = access.denied_users.contains(&uuid);
    let notes = u.extra.get("notes").and_then(|n| n.as_str());
    let scopes = access.scopes_for(&uuid);

    (
        200,
        html! {
            h1 {
                (user_label(u))
                @if denied { " " (tag("bad", "denied")) }
            }
            p class="lede" {
                a href=(v.href(&Route::Users)) { "← " (v.t(K::Back)) }
            }
            p class="pills" {
                (act_rm(v, &Route::UserRm(uuid.clone()), v.t(K::Remove)))
            }

            @if let Some(notes) = notes {
                div class="panel" { span class="muted mono" { "notes " } (notes) }
            }

            h2 { (v.t(K::Uuid)) }
            div class="panel" { span class="mono" { (uuid) } }

            h2 { (v.t(K::Emails)) }
            p class="primary" {
                (act(v, &Route::EmailAdd(uuid.clone()), &format!("+ {}", v.t(K::AddEmail))))
            }
            div class="panel" {
                ul class="plain" {
                    @for e in &u.emails {
                        @let email = norm_email(e);
                        li class="pills" {
                            code { (email) }
                            (act_rm(v, &Route::EmailRm(uuid.clone(), email.clone()), v.t(K::Remove)))
                        }
                    }
                }
            }

            h2 { (section_heading(v.t(K::Scopes), "scopes")) }
            div class="panel" {
                @if scopes.is_empty() {
                    span class="bad" { (v.t(K::InNoScope)) }
                } @else {
                    ul class="plain" {
                        @for (a, s) in &scopes {
                            li {
                                a href=(v.href(&Route::App(a.name.clone()))) {
                                    code { (a.name) "/" (s.name) }
                                }
                            }
                        }
                    }
                }
            }

            h2 { "api_keys" }
            p class="primary" { (act(v, &Route::KeyAdd(uuid.clone()), &format!("+ {}", v.t(K::Add)))) }
            div class="panel" {
                @if u.api_keys.is_empty() {
                    span class="muted" { (v.t(K::None)) }
                } @else {
                    table {
                        thead { tr {
                            th { "id" }
                            th { "released" }
                            th { "duration" }
                            th { (v.t(K::ColExpiry)) }
                            th { (v.t(K::Scopes)) }
                            th {}
                        } }
                        tbody {
                            @for k in &u.api_keys {
                                @let id = k.id.trim().to_string();
                                tr {
                                    td class="mono" data-label="id" { (id) }
                                    td class="mono" data-label="released" { (k.released.trim()) }
                                    td class="mono" data-label="duration" { (k.duration.trim()) }
                                    td data-label=(v.t(K::ColExpiry)) {
                                        (expiry_markup(v.lang, &expiry_of(k, n)))
                                    }
                                    td data-label=(v.t(K::Scopes)) {
                                        (url_list(v.lang, k.scopes.as_ref(), t(v.lang, K::KeyScopeInherit)))
                                    }
                                    td class="pills" {
                                        (act(v, &Route::KeyEdit(uuid.clone(), id.clone()),
                                             v.t(K::Edit)))
                                        (act(v, &Route::KeyRotate(uuid.clone(), id.clone()),
                                             v.t(K::Rotate)))
                                        (act_rm(v, &Route::KeyRm(uuid.clone(), id.clone()),
                                             v.t(K::Remove)))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// `/groups` — each `user_groups` entry, who it references, and everything that names it.
/// Members are people now: an email where a roster row still resolves it, the raw uuid
/// where none does, and flagged when it matches nobody at all.
fn page_groups(v: &View, doc: &AccessFile) -> Markup {
    html! {
        h1 { (section_heading(v.t(K::Groups), "user_groups")) }
        p class="lede" { (v.t(K::GroupsIntro)) }
        p class="primary" { (act(v, &Route::GroupAdd, &format!("+ {}", v.t(K::Add)))) }
        @if doc.user_groups.is_empty() {
            div class="panel" { span class="muted" { (v.t(K::None)) } }
        } @else {
            @for (name, members) in &doc.user_groups {
                @let refs = user_group_refs(doc, name);
                div class="panel" {
                    h2 class="tight" {
                        code { "@" (name) }
                        " "
                        span class="pills" {
                            (act(v, &Route::GroupEdit(name.clone()), v.t(K::Edit)))
                            (act_rm(v, &Route::GroupRm(name.clone()), v.t(K::Remove)))
                        }
                    }
                    p class="muted" {
                        @if refs.is_empty() {
                            (v.t(K::ReferencedByNothing))
                        } @else {
                            (v.t(K::ReferencedBy)) " "
                            @for (i, r) in refs.iter().enumerate() {
                                @if i > 0 { ", " }
                                code { (r) }
                            }
                        }
                    }
                    p class="muted" { (v.t(K::Members)) }
                    @if members.is_empty() {
                        p class="muted" { (v.t(K::None)) }
                    } @else {
                        ul class="plain" {
                            @for m in members {
                                @let uuid = m.trim().to_ascii_lowercase();
                                li {
                                    @match user_pos(doc, &uuid) {
                                        Some(i) => {
                                            a href=(v.href(&Route::User(uuid.clone()))) {
                                                code { (user_label(&doc.users[i])) }
                                            }
                                        }
                                        None => {
                                            code class="bad" { (uuid) }
                                            " " (tag("bad", v.t(K::UnknownMember)))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// `/apps` — the applications, with their base and scope count.
fn page_apps(v: &View, doc: &AccessFile) -> Markup {
    html! {
        h1 { (section_heading(v.t(K::Apps), "applications")) }
        p class="lede" { (v.t(K::AppsIntro)) }
        p class="primary" { (act(v, &Route::AppAdd, &format!("+ {}", v.t(K::Add)))) }
        div class="panel" {
            @if doc.applications.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                table {
                    thead { tr {
                        th { "name" }
                        th { (v.t(K::Base)) }
                        th { (v.t(K::Scopes)) }
                        th {}
                    } }
                    tbody {
                        @for a in &doc.applications {
                            tr {
                                td data-label="name" {
                                    a href=(v.href(&Route::App(a.name.trim().to_string()))) {
                                        code { (a.name.trim()) }
                                    }
                                }
                                td data-label=(v.t(K::Base)) { (url_list(v.lang, Some(&a.base), "")) }
                                td data-label=(v.t(K::Scopes)) { (a.scopes.len()) }
                                td class="pills" {
                                    (act_rm(v, &Route::AppRm(a.name.trim().to_string()), v.t(K::Remove)))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// `/apps/{app}` — one application: its base, its login page, and its scopes **in file
/// order**, the number carrying the meaning first-match-wins gives it.
fn page_app(v: &View, doc: &AccessFile, name: &str) -> (u16, Markup) {
    let a = match app_pos(doc, name).map(|i| &doc.applications[i]) {
        Some(a) => a,
        None => return (404, page_missing(v, v.t(K::NoSuchApp), name, &Route::Apps)),
    };
    let last = a.scopes.len().saturating_sub(1);
    let app_name = a.name.trim().to_string();
    (
        200,
        html! {
            h1 { (app_name) }
            p class="lede" { a href=(v.href(&Route::Apps)) { "← " (v.t(K::Back)) } }
            p class="pills" {
                (act(v, &Route::AppEdit(app_name.clone()), v.t(K::Edit)))
                (act_rm(v, &Route::AppRm(app_name.clone()), v.t(K::Remove)))
            }

            @if let Some(notes) = &a.notes {
                div class="panel" { span class="muted mono" { "notes " } (notes) }
            }

            h2 { (v.t(K::Base)) }
            div class="panel" { (url_list(v.lang, Some(&a.base), "")) }
            @if let Some(l) = &a.login_url {
                p class="muted" { (v.t(K::LoginUrl)) " " span class="mono" { (l) } }
            }

            h2 { (section_heading(v.t(K::Scopes), "scopes")) }
            p class="lede sub" { (v.t(K::ScopesIntro)) }
            p class="primary" {
                (act(v, &Route::ScopeAdd(app_name.clone()), &format!("+ {}", v.t(K::Add))))
            }
            div class="panel" {
                @if a.scopes.is_empty() {
                    span class="muted" { (v.t(K::NoScopes)) }
                } @else {
                    ol class="sites" {
                        @for (i, s) in a.scopes.iter().enumerate() {
                            li { (scope_block(v, doc, &app_name, s, i, last)) }
                        }
                    }
                }
            }
        },
    )
}

/// One `POST` button that moves a scope one place inside its application. Order is meaning
/// — `AppRecord::scopes` is first-match-wins — so this is a mutation like any other: same
/// `rev`, same audit line, and a `303` back to this page. It is a button and not a link
/// because a `GET` never mutates, and it is per row because two buttons beat a position
/// field an operator has to count out.
fn move_button(
    v: &View,
    app: &str,
    scope: &str,
    dir: &str,
    label: &str,
    glyph: &str,
    disabled: bool,
) -> Markup {
    html! {
        form method="post" action=(v.href(&Route::ScopeMove(app.to_string(), scope.to_string()))) {
            input type="hidden" name="rev" value=(v.rev);
            input type="hidden" name="dir" value=(dir);
            button type="submit" class="pill" title=(label) disabled[disabled] { (glyph) }
        }
    }
}

/// One scope, as one item of the ordered list [`page_app`] renders: its access kind, its
/// urls, its members (people, resolved where the roster still can) and its move buttons.
fn scope_block(
    v: &View,
    doc: &AccessFile,
    app: &str,
    s: &ScopeSpec,
    i: usize,
    last: usize,
) -> Markup {
    let name = s.name.trim().to_string();
    let access = s.access.trim();
    let access_label = match access {
        "anonymous" => v.t(K::AccessAnonymous),
        "authenticated" => v.t(K::AccessAuthenticated),
        "restricted" => v.t(K::AccessRestricted),
        other => other,
    };
    html! {
        div {
            strong { (name) }
            " "
            (tag(if access == "restricted" { "" } else { "warn" }, access_label))
            " "
            span class="pills" {
                (act(v, &Route::ScopeEdit(app.to_string(), name.clone()), v.t(K::Edit)))
                (act_rm(v, &Route::ScopeRm(app.to_string(), name.clone()), v.t(K::Remove)))
                (move_button(v, app, &name, "up", v.t(K::MoveUp), "↑", i == 0))
                (move_button(v, app, &name, "down", v.t(K::MoveDown), "↓", i >= last))
            }
        }
        @if s.urls.is_empty() {
            div class="bad" { "urls: [] — " (v.t(K::ReachesNothing)) }
        } @else {
            ul class="plain mono" { @for u in &s.urls { li { (u) } } }
        }
        @match access {
            "anonymous" => div class="muted" { (v.t(K::AnonymousWarn)) },
            "authenticated" => div class="muted" { (v.t(K::AuthenticatedWarn)) },
            "restricted" => {
                @let members = scope_members_display(doc, s);
                div class="muted" {
                    (v.t(K::Members)) ": "
                    @if members.is_empty() {
                        span class="bad" { (v.t(K::WarnNoMembers)) }
                    } @else {
                        @for (i, m) in members.iter().enumerate() {
                            @if i > 0 { ", " }
                            code { (m) }
                        }
                    }
                }
                @if let Some(creds) = &s.credentials {
                    div class="muted" { (v.t(K::Credentials)) ": " (creds.join(", ")) }
                }
            }
            _ => {}
        }
    }
}

/// A scope's `users` (resolved to a label where the roster still can) and `groups` (`@name`,
/// shown exactly as the file spells it), for display only. See [`parse_members`] for the
/// inverse, on submit.
fn scope_members_display(doc: &AccessFile, s: &ScopeSpec) -> Vec<String> {
    let mut out: Vec<String> = s.users.iter().flatten().map(|u| label_of(doc, u)).collect();
    out.extend(s.groups.iter().flatten().map(|g| g.trim().to_string()));
    out
}

/// `/denied`: the veto list, standing on its own for a direct link and for the add/remove
/// PRG redirects. [`page_users`] also renders this same list, as its own second section; both
/// go through [`denied_list`] so the two views can never show two different lists.
fn page_denied(v: &View, doc: &AccessFile) -> Markup {
    html! {
        h1 { (section_heading(v.t(K::Denied), "denied")) }
        p class="lede" { (v.t(K::DeniedIntro)) }
        p class="primary" { (act(v, &Route::DenyAdd, &format!("+ {}", v.t(K::Add)))) }
        (denied_list(v, doc))
    }
}

/// The `denied` panel's body: the empty state, or the list itself, one row per vetoed
/// entry — a uuid names the user it vetoes, a bare email names a stranger. Factored out of
/// [`page_denied`] because [`page_users`] renders the identical panel as its own second
/// section, and the two must never be free to drift apart.
fn denied_list(v: &View, doc: &AccessFile) -> Markup {
    html! {
        div class="panel" {
            @if doc.denied.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                ul class="plain" {
                    @for d in &doc.denied {
                        @let raw = d.trim().to_ascii_lowercase();
                        li class="pills" {
                            @match user_pos(doc, &raw) {
                                Some(i) => {
                                    @let u = &doc.users[i];
                                    a href=(v.href(&Route::User(u.uuid.trim().to_ascii_lowercase()))) {
                                        code { (user_label(u)) }
                                    }
                                }
                                None => { code { (norm_email(&raw)) } }
                            }
                            (act_rm(v, &Route::DenyRm(raw.clone()), v.t(K::Remove)))
                        }
                    }
                }
            }
        }
    }
}

/// `/can` — the tester. A `GET` form, and the gate's own [`decide`] behind it.
///
/// An email left blank tests [`Subject::Anonymous`] rather than refusing to answer: that is
/// the only way to check what an `anonymous` scope actually opens. (`bb-auth-adm can --key
/// ID` also evaluates a `bbk_` key. It stays on the terminal for now: naming a key means
/// picking one, which is a second field and a listing, and a key's verdict is one
/// `bb-auth-adm` invocation away on the host that has the file.)
fn page_can(v: &View, access: &Access, query: &str) -> Markup {
    let email_in = query_param(query, "email").unwrap_or_default();
    let url_in = query_param(query, "url").unwrap_or_default();
    let asked = !url_in.trim().is_empty();
    let url = request_url(&url_in);

    html! {
        h1 { (section_heading(v.t(K::Can), "can")) }
        p class="lede" { (v.t(K::CanIntro)) }
        div class="panel" {
            form class="can" method="get" action=(v.href(&Route::Can)) {
                label {
                    "email"
                    input type="text" name="email" value=(email_in)
                          placeholder="bob@x.com" autocapitalize="off" spellcheck="false";
                }
                label {
                    "url"
                    input type="text" name="url" value=(url_in)
                          placeholder="https://app.x.com/reports" autocapitalize="off"
                          spellcheck="false";
                }
                // Keep the language across a submit: the form replaces the whole query.
                input type="hidden" name="lang" value=(v.lang.code());
                button type="submit" { (v.t(K::Submit)) }
            }
        }
        @if asked {
            @let (granted, verdict_markup) = verdict(v, access, &email_in, &url);
            div class=@if granted { "panel ok" } @else { "panel bad" } { (verdict_markup) }
        }
    }
}

/// One verdict, with the reason the gate would have. The wording follows `bb-auth-adm can`'s:
/// same decision, same explanation, so an operator who has read one recognises the other.
/// Returns whether the request was granted alongside the markup, so the caller can carry that
/// same boolean onto the panel wrapping it (an `ok` or `bad` left bar).
fn verdict(v: &View, access: &Access, email_in: &str, url: &str) -> (bool, Markup) {
    let email = norm_email(email_in);
    let subject = if email.is_empty() {
        Subject::Anonymous
    } else {
        Subject::Identifier(&email)
    };
    let decision = decide(access, &subject, Some(url));
    let granted = decision.granted();
    let at = |app: &str, scope: &str| html! { code { (app) "/" (scope) } };
    let markup = html! {
        p class=@if granted { "verdict yes" } @else { "verdict no" } {
            @if granted { (v.t(K::Authorized)) } @else { (v.t(K::VerdictDenied)) }
        }
        p {
            @match &decision {
                Decision::Anonymous { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyAnonymousGrant))
                }
                Decision::Granted { app, scope } => { (at(app, scope)) " " (v.t(K::WhyGranted)) }
                Decision::Vetoed => { code { (email) } " " (v.t(K::WhyVetoed)) }
                Decision::NoApplication => { code { (url) } " " (v.t(K::WhyNoApplication)) }
                Decision::NoScope { app } => { code { (app) } " " (v.t(K::WhyNoScope)) }
                Decision::Unauthenticated { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyUnauthenticated))
                }
                Decision::CredentialRefused { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyCredentialRefused))
                }
                Decision::NotEnrolled { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyNotEnrolled))
                }
                Decision::NotMember { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyNotMember))
                }
                Decision::KeyOutOfScope { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyKeyOutOfScope))
                }
            }
        }
        @if granted && !matches!(decision, Decision::Anonymous { .. }) {
            p class="muted" {
                (v.t(K::AppSees)) " " code { (IDENTITY_HEADER) ": " (email) }
            }
        }
    };
    (granted, markup)
}

// ---------------------------------------------------------------------------
// Editing pages
// ---------------------------------------------------------------------------
//
// One struct and one page function per form. The struct is what the fields hold, and it is
// filled from two places — the access file, when the form is first rendered, and the
// submitted body, when a refusal sends the same form back. That is what "the submitted
// values are preserved" is: the same page function, one error string later.

/// The `users` form: one email. Used both for `users · add` (the row's first identifier)
/// and for `/users/{uuid}/emails/+add` — the two places an email is ever typed in, now that
/// an identity carries no URL and its uuid never changes. `UserForm` gains nothing beyond
/// this: there is nothing else left on a [`UserSpec`] a form could usefully edit.
#[derive(Default)]
struct UserForm {
    email: String,
}

impl UserForm {
    fn read(f: &Form) -> UserForm {
        UserForm {
            email: f.get("email").to_string(),
        }
    }
}

/// `users · add`: mints a uuid and enrols the first email.
fn page_user_form(v: &View, f: &UserForm, err: Option<&Refusal>) -> Markup {
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (v.t(K::Users)) " · " (v.t(K::Add)) }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field("email", "email", &f.email, "bob@x.com", None, about("email")))
            }, v.t(K::Create), false))
        }
    }
}

/// `/users/{uuid}/emails/+add`: one more identifier for an existing row.
fn page_email_form(v: &View, owner: &str, f: &UserForm, err: Option<&Refusal>) -> Markup {
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (owner) " · " (v.t(K::AddEmail)) }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field("email", "email", &f.email, "bob@x.com", None, about("email")))
            }, v.t(K::Create), false))
        }
    }
}

/// The `api_keys` form: a label, a window, and the `application/scope` restriction. Empty
/// means every scope the owner reaches ([`K::KeyScopesHelp`]) — a restriction, never a
/// grant, so it can only subtract from what the owner already has.
#[derive(Default)]
struct KeyForm {
    id: String,
    duration: String,
    scopes: String,
}

impl KeyForm {
    fn of(k: &ApiKeySpec) -> KeyForm {
        KeyForm {
            id: k.id.trim().to_string(),
            duration: k.duration.trim().to_string(),
            scopes: urls_text(k.scopes.as_ref()),
        }
    }
    fn read(f: &Form) -> KeyForm {
        KeyForm {
            id: f.get("id").to_string(),
            duration: f.get("duration").to_string(),
            scopes: f.get("scopes").to_string(),
        }
    }
}

/// `api_keys · add` / `· edit`. `released` is not editable: on an add it is today, and on an
/// edit it is what the file says — a key's issue date is a fact about a secret that exists,
/// not a setting. (`bb-auth-adm key set --released` is there for a repair; a GUI that
/// offered it would mostly be a way to move an expiry by accident.)
fn page_key_form(
    v: &View,
    owner: &str,
    existing: Option<&str>,
    released: &str,
    f: &KeyForm,
    err: Option<&Refusal>,
) -> Markup {
    let editing = existing.is_some();
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (owner) " · api_keys · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(id) = existing { p class="lede" { code { (id) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                @if !editing {
                    (text_field("id", "id", &f.id, "laptop", None, about("id")))
                }
                (text_field("duration", "duration", &f.duration, "365d",
                            Some("<n>d · <n>h · never"), about("duration")))
                label {
                    span class="lbl" { "released" }
                    span class="mono" { (released) }
                }
                (urls_field("scopes", "scopes", &f.scopes, html! { (v.t(K::KeyScopesHelp)) },
                            about("scopes")))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// A free-text notes field: operator documentation, round-tripped untouched. Not a pattern
/// list, so it gets no per-line framing.
fn notes_field(value: &str) -> Markup {
    html! {
        label {
            span class="lbl" { "notes" }
            textarea name="notes" rows="3" spellcheck="true" { (value) }
        }
    }
}

/// The `applications` form: `name`, `base`, `login_url`, `notes`. There is no field here
/// that names a user, and there never may be one: an application describes a **place**, and
/// grants to named users live in a scope's `users`/`groups` alone.
#[derive(Default)]
struct AppForm {
    name: String,
    base: String,
    login_url: String,
    notes: String,
}

impl AppForm {
    fn of(a: &AppSpec) -> AppForm {
        AppForm {
            name: a.name.trim().to_string(),
            base: a.base.join("\n"),
            login_url: a.login_url.clone().unwrap_or_default(),
            notes: a.notes.clone().unwrap_or_default(),
        }
    }
    fn read(f: &Form) -> AppForm {
        AppForm {
            name: f.get("name").to_string(),
            base: f.get("base").to_string(),
            login_url: f.get("login_url").to_string(),
            notes: f.get("notes").to_string(),
        }
    }
}

fn page_app_form(v: &View, existing: Option<&str>, f: &AppForm, err: Option<&Refusal>) -> Markup {
    let editing = existing.is_some();
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (v.t(K::Apps)) " · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(n) = existing { p class="lede" { code { (n) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field(if editing { v.t(K::NewName) } else { "name" },
                            "name", &f.name, "app1", None, about("name")))
                (urls_field(v.t(K::Base), "base", &f.base, html! { (v.t(K::BaseHelp)) }, about("base")))
                (text_field(v.t(K::LoginUrl), "login_url", &f.login_url, "https://login.x.com/",
                            Some(v.t(K::LoginUrlHelp)), about("login_url")))
                (notes_field(&f.notes))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// The `scopes` form: `name`, `urls`, `access`, and — only meaningful under `restricted` —
/// `members` (people, one per line: an email or uuid resolved to a uuid, `@name` kept as a
/// group reference) and `credentials`.
#[derive(Default)]
struct ScopeForm {
    name: String,
    urls: String,
    access: String,
    members: String,
    cred_login: bool,
    cred_api_key: bool,
    notes: String,
}

impl ScopeForm {
    fn of(doc: &AccessFile, s: &ScopeSpec) -> ScopeForm {
        let (cred_login, cred_api_key) = match &s.credentials {
            None => (true, true),
            Some(list) => (
                list.iter().any(|c| c.trim() == "login"),
                list.iter().any(|c| c.trim() == "api_key"),
            ),
        };
        ScopeForm {
            name: s.name.trim().to_string(),
            urls: s.urls.join("\n"),
            access: s.access.trim().to_string(),
            members: scope_members_display(doc, s).join("\n"),
            cred_login,
            cred_api_key,
            notes: s.notes.clone().unwrap_or_default(),
        }
    }
    fn read(f: &Form) -> ScopeForm {
        ScopeForm {
            name: f.get("name").to_string(),
            urls: f.get("urls").to_string(),
            access: f.get("access").to_string(),
            members: f.get("members").to_string(),
            cred_login: f.checked("cred_login"),
            cred_api_key: f.checked("cred_api_key"),
            notes: f.get("notes").to_string(),
        }
    }
}

fn page_scope_form(
    v: &View,
    app: &str,
    existing: Option<&str>,
    f: &ScopeForm,
    err: Option<&Refusal>,
) -> Markup {
    let editing = existing.is_some();
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (app) " · " (v.t(K::Scopes)) " · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(n) = existing { p class="lede" { code { (n) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field(if editing { v.t(K::NewName) } else { "name" },
                            "name", &f.name, "admin", None, about("name")))
                (urls_field("urls", "urls", &f.urls, html! { (v.t(K::ScopeUrlsHelp)) }, about("urls")))
                div {
                    span class="lbl" { (v.t(K::AccessWord)) }
                    @for (val, label) in [
                        ("anonymous", v.t(K::AccessAnonymous)),
                        ("authenticated", v.t(K::AccessAuthenticated)),
                        ("restricted", v.t(K::AccessRestricted)),
                    ] {
                        label class="radio" {
                            input type="radio" name="access" value=(val) checked[f.access == val];
                            span { (label) }
                        }
                    }
                    span class="hint" { (v.t(K::AccessHelp)) }
                }
                (urls_field(v.t(K::Members), "members", &f.members, html! { (v.t(K::MembersHelp)) },
                            about("members")))
                div {
                    span class="lbl" { (v.t(K::Credentials)) }
                    label class="radio" {
                        input type="checkbox" name="cred_login" value="on" checked[f.cred_login];
                        span { (v.t(K::CredLogin)) }
                    }
                    label class="radio" {
                        input type="checkbox" name="cred_api_key" value="on" checked[f.cred_api_key];
                        span { (v.t(K::CredApiKey)) }
                    }
                    span class="hint" { (v.t(K::CredentialsHelp)) }
                }
                (notes_field(&f.notes))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// The `user_groups` form — a name and its members, people now rather than URL patterns.
#[derive(Default)]
struct GroupForm {
    name: String,
    members: String,
}

impl GroupForm {
    fn read(f: &Form) -> GroupForm {
        GroupForm {
            name: f.get("name").to_string(),
            members: f.get("members").to_string(),
        }
    }
}

fn page_group_form(
    v: &View,
    existing: Option<&str>,
    f: &GroupForm,
    err: Option<&Refusal>,
) -> Markup {
    let editing = existing.is_some();
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (v.t(K::Groups)) " · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(n) = existing { p class="lede" { code { "@" (n) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                // No rename: the library refuses to have one, and says why.
                @if editing {
                    p class="muted" { (v.t(K::GroupNoRename)) }
                } @else {
                    (text_field("name", "name", &f.name, "admins", None, about("name")))
                }
                (urls_field(v.t(K::Members), "members", &f.members, html! { (v.t(K::GroupMembersHelp)) },
                            about("members")))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// The `denied` form — one address, and the veto that outranks every grant.
#[derive(Default)]
struct DenyForm {
    email: String,
}

impl DenyForm {
    fn read(f: &Form) -> DenyForm {
        DenyForm {
            email: f.get("email").to_string(),
        }
    }
}

fn page_deny_form(v: &View, f: &DenyForm, err: Option<&Refusal>) -> Markup {
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (v.t(K::Denied)) " · " (v.t(K::Add)) }
        p class="lede" { (v.t(K::DeniedIntro)) }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field("email", "email", &f.email, "spammer@x.com", None, about("email")))
            }, v.t(K::Create), false))
        }
    }
}

/// The page a mint answers with — and the one place a `bbk_` bearer is ever rendered.
///
/// Rendered **directly**, not after a redirect: a `303` would put the result behind a fresh
/// `GET` that has no bearer to show, and the bearer exists nowhere else — the file keeps
/// only its sha256. It is not logged and never travels in a URL.
fn page_minted(v: &View, owner_uuid: &str, owner_label: &str, id: &str, bearer: &str) -> Markup {
    html! {
        h1 { (owner_label) " · api_keys · " (id) }
        div class="secret" {
            div { strong { (v.t(K::BearerHeading)) } }
            p { (v.t(K::BearerOnce)) }
            code { "Authorization: Bearer " (bearer) }
            p class="hint" { (v.t(K::BearerClickHint)) }
        }
        p { a href=(v.href(&Route::User(owner_uuid.to_string()))) { "← " (v.t(K::Back)) } }
    }
}

/// The `409`: the file moved under the form. Nothing was written, and the way out is a
/// fresh read of what the file says now — with a pointer at the browser's Back button,
/// which (no page here runs a script on load, so nothing disturbs the bfcache) still holds
/// the form exactly as it was filled in.
fn page_conflict(v: &View) -> Markup {
    // A `POST`-only route has no form to reload, so it goes back to its section.
    let back = match &v.at {
        Route::ScopeMove(..) => v.at.parent(),
        other => other.clone(),
    };
    html! {
        h1 { (v.t(K::ConflictTitle)) }
        div class="panel warn" {
            p { (v.t(K::ConflictBody)) }
            p { (v.t(K::ConflictRecover)) }
            p { a href=(v.href(&back)) { "← " (v.t(K::ConflictBack)) } }
        }
    }
}

/// The mint route's own `409`: the `rev` is stale **and** the requested key now exists —
/// which is what a reload of the reveal page looks like from here, the reveal being the
/// direct `POST` response ([`page_minted`]). The generic [`page_conflict`] would be wrong
/// twice on this path: the "someone else" who moved the file was this administrator's own
/// submit, and "make the change again" would mint a second key. What an administrator who
/// lost the bearer needs instead is a rotation, so the link to it is here — and there is
/// deliberately no Back-button hint, because the typed input is not worth recovering.
fn page_mint_conflict(v: &View, owner: &str, id: &str) -> Markup {
    let owner = norm_email(owner);
    html! {
        h1 { (v.t(K::MintConflictTitle)) }
        div class="panel warn" {
            p { code { (owner) } " · api_keys · " code { (id) } }
            p { (v.t(K::MintConflictBody)) }
            p { (v.t(K::MintConflictLost)) }
            p {
                a href=(v.href(&Route::KeyRotate(owner.clone(), id.to_string()))) {
                    (v.t(K::MintConflictRotate))
                }
                " · "
                a href=(v.href(&Route::User(owner.clone()))) { "← " (v.t(K::Back)) }
            }
        }
    }
}

/// A page that is only a message: the `401`, the `403`, the `404`, the `405` and the
/// broken-file page. Content only — the caller wraps it in [`shell`], as it does any page.
/// `kind` styles the panel the same way [`tag`] styles a label (`"bad"`, `"warn"`, `"ok"`,
/// or `""` for a neutral one); every call site today is a refusal, so every one passes
/// `"bad"`.
fn notice(kind: &str, title: &str, body: Markup) -> Markup {
    html! {
        h1 { (title) }
        div class=(format!("panel {kind}")) { (body) }
    }
}

/// The page for an access file the gate would refuse. The library's message goes out
/// **verbatim** — it is the same sentence `bb-auth --check-users` and a failed startup
/// print, and an operator who can match those three is an operator who can fix the file.
fn page_file_error(v: &View, err: &str) -> Markup {
    notice(
        "bad",
        v.t(K::FileErrorTitle),
        html! {
            p class="mono bad" { (err) }
            p class="muted" { (v.t(K::FileErrorHint)) }
        },
    )
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/// What a `POST` came to: either it happened, and the browser is sent to the page it
/// belongs to, or there is a page to render right here.
enum Outcome {
    /// POST-redirect-GET: `303` to this route with `?msg=`, so a reload cannot repeat it.
    Done(Route, Msg),
    /// A form re-rendered with a refusal, the `409`, or the one page that carries a freshly
    /// minted bearer and therefore cannot be behind a redirect.
    Page(u16, &'static str, Markup),
}

/// One line per successful mutation, on stderr, in the shape the gate logs in.
///
/// The acting administrator, the verb spelled as `bb-auth-adm` spells the equivalent
/// command, and the target's name. Never a bearer, never a `key_hash`, and no submitted
/// value beyond the name of the thing that changed — a scope full of URLs is in the file,
/// and the file keeps a `.bak` of what it was.
fn audit(admin: &str, verb: &str, target: &str) {
    eprintln!("[bb-auth-web] {admin}: {verb} {target}");
}

/// Check the edit with the gate's own parser, write it, and log the line.
///
/// [`AccessWrite`] is the only door: `prepare` compiles the exact bytes, `commit` writes the
/// bytes it compiled. An `Err` is the library's own sentence and means the file on disk was
/// not touched — which is what every error path in [`mutate`] relies on.
fn commit(v: &View, doc: &AccessFile, verb: &str, target: &str) -> Result<Written, String> {
    let written = AccessWrite::prepare(doc)?.commit(&v.cfg.access_path)?;
    audit(v.admin.unwrap_or("?"), verb, target);
    Ok(written)
}

/// Apply one `POST`.
///
/// Three things happen before any mutation is even looked at, and they are the load-bearing
/// order:
///
/// 1. the access file is re-read, and its sha256 must equal the `rev` the form carries —
///    otherwise the file moved under the form (a `bb-auth-adm` over SSH, another tab) and
///    this is a `409` that writes nothing;
/// 2. the document is opened with [`open_access_file`], which refuses to start from a file
///    the gate would reject — an edit must begin from a file that works;
/// 3. only then does the arm for this route run, and every one of them ends in [`commit`].
///
/// (1) and (2) are two reads of the same file, so a writer landing exactly between them is
/// still not seen — the same window `bb-auth-adm` has had all along, since nothing here
/// locks. What the `rev` removes is the interesting case, the one measured in minutes: a
/// form loaded, read, thought about, and submitted onto a file that has since moved.
///
/// A refusal — from a form's own check or from the library — re-renders the very form that
/// caused it, with the submitted values still in the fields and the message verbatim. On
/// every one of those paths nothing has been written: `prepare` fails before `commit`, and
/// `commit` is atomic.
///
/// The status for a refused submission is `400`, and a failed write is reported the same
/// way. From the browser's side the two say the same thing — nothing happened, here is the
/// sentence that says why — and the sentence itself is what distinguishes them.
fn mutate(v: &View, form: &Form) -> Outcome {
    let path = &v.cfg.access_path;
    let title = v.at.title();

    // (1) The file as it is right now, byte for byte.
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("read {path}: {e}");
            return Outcome::Page(500, title, page_file_error(v, &msg));
        }
    };
    if form.get("rev").trim() != sha256_hex(&raw) {
        // On the mint route, a stale rev is usually this administrator's own write: the
        // reveal page is the direct POST response (a bearer cannot survive a redirect), so
        // reloading it re-submits the mint. If the requested key now exists, say what
        // actually happened — the generic page's advice, "make the change again", would
        // mint a second key. A stale rev with no such key is a genuine concurrent edit,
        // and keeps the generic answer.
        if let Route::KeyAdd(owner) = &v.at {
            let id = form.get("id").trim();
            let minted = |d: &AccessFile| {
                user_pos(d, owner)
                    .is_some_and(|i| d.users[i].api_keys.iter().any(|k| k.id.trim() == id))
            };
            if !id.is_empty() && serde_json::from_str::<AccessFile>(&raw).is_ok_and(|d| minted(&d))
            {
                return Outcome::Page(409, title, page_mint_conflict(v, owner, id));
            }
        }
        return Outcome::Page(409, title, page_conflict(v));
    }

    // (2) And as the gate would read it. A file that does not compile is not a file to edit.
    let (mut doc, _) = match open_access_file(path) {
        Ok(pair) => pair,
        Err(e) => return Outcome::Page(500, title, page_file_error(v, &e)),
    };

    // (3) The mutation itself. Each arm: read the form, ask the library, write, say where
    // the browser goes — or hand the refusal back to the form it came from.
    match &v.at {
        Route::UserAdd => {
            let f = UserForm::read(form);
            let r = (|| -> Result<String, Refusal> {
                let email = norm_email(&f.email);
                if email.is_empty() {
                    return Err(Refusal::on("email", v.t(K::EmailRequired)));
                }
                add_user(
                    &mut doc,
                    UserSpec {
                        emails: vec![email.clone()],
                        ..Default::default()
                    },
                )
                .map_err(|e| Refusal::on("email", e))?;
                let uuid = user_pos(&doc, &email)
                    .map(|i| doc.users[i].uuid.trim().to_ascii_lowercase())
                    .unwrap_or_default();
                commit(v, &doc, "user add", &email)?;
                Ok(uuid)
            })();
            match r {
                Ok(uuid) => Outcome::Done(Route::User(uuid), Msg::UserAdded),
                Err(e) => Outcome::Page(400, title, page_user_form(v, &f, Some(&e))),
            }
        }

        Route::UserRm(target) => {
            let r = (|| -> Result<(), Refusal> {
                let (u, _swept) = remove_user(&mut doc, target)?;
                commit(v, &doc, "user rm", &user_label(&u))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Users, Msg::UserRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Users)) " · " (v.t(K::Remove)) },
                        html! { p { code { (target) } } },
                        v.t(K::ConfirmUserRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::EmailAdd(owner) => {
            let f = UserForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                let email = norm_email(&f.email);
                if email.is_empty() {
                    return Err(Refusal::on("email", v.t(K::EmailRequired)));
                }
                add_user_email(&mut doc, owner, &email).map_err(|e| Refusal::on("email", e))?;
                commit(
                    v,
                    &doc,
                    "user email add",
                    &format!("{}: +{email}", label_of(&doc, owner)),
                )?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::User(owner.clone()), Msg::UserSaved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_email_form(v, &label_of(&doc, owner), &f, Some(&e)),
                ),
            }
        }

        Route::EmailRm(owner, email) => {
            let r = (|| -> Result<(), Refusal> {
                remove_user_email(&mut doc, owner, email)?;
                commit(
                    v,
                    &doc,
                    "user email rm",
                    &format!("{}: -{}", label_of(&doc, owner), norm_email(email)),
                )?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::User(owner.clone()), Msg::UserSaved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Emails)) " · " (v.t(K::Remove)) },
                        html! { p { code { (norm_email(email)) } } },
                        v.t(K::ConfirmEmailRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::KeyAdd(owner) => {
            let f = KeyForm::read(form);
            // Today, and not a field: a key's issue date is a fact about a secret that is
            // being created right now.
            let released = format_date(now());
            let owner_label = label_of(&doc, owner);
            let r = (|| -> Result<(String, String), Refusal> {
                let id = f.id.trim().to_string();
                if id.is_empty() {
                    return Err(Refusal::on("id", v.t(K::KeyIdRequired)));
                }
                let duration = f.duration.trim().to_string();
                // Fail before minting: a key the file would reject is a secret handed out
                // for nothing.
                if key_expiry(&released, &duration).is_none() {
                    return Err(Refusal::on("duration", v.t(K::BadKeyWindow)));
                }
                let lines = form.lines("scopes");
                let scopes = if lines.is_empty() { None } else { Some(lines) };
                // Not attributed: besides a duplicate id, this can also fail on an owner
                // lookup or on entropy for the mint itself; neither is a field to blame.
                let sealed: SealedKey = add_api_key(
                    &mut doc,
                    owner,
                    ApiKeySpec {
                        id: id.clone(),
                        released: released.clone(),
                        duration,
                        scopes,
                        ..Default::default()
                    },
                )?;
                // The bearer opens only against the receipt of a completed write, so this
                // order is the library's and not a convention this file could get wrong.
                // The id and duration already passed; the scopes just submitted are the
                // only new, still-unvalidated content left for the compile to catch.
                let written = commit(v, &doc, "key add", &format!("{owner_label}/{id}"))
                    .map_err(|e| Refusal::on("scopes", e))?;
                Ok((id, sealed.reveal(&written)))
            })();
            match r {
                Ok((id, bearer)) => Outcome::Page(
                    200,
                    title,
                    page_minted(v, owner, &owner_label, &id, &bearer),
                ),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_key_form(v, &owner_label, None, &released, &f, Some(&e)),
                ),
            }
        }

        Route::KeyEdit(owner, id) => {
            let f = KeyForm::read(form);
            let owner_label = label_of(&doc, owner);
            let released = key_mut(&mut doc, owner, id)
                .map(|k| k.released.trim().to_string())
                .unwrap_or_default();
            let r = (|| -> Result<(), Refusal> {
                let k = key_mut(&mut doc, owner, id)?;
                k.duration = f.duration.trim().to_string();
                if key_expiry(&k.released, &k.duration).is_none() {
                    return Err(Refusal::on("duration", v.t(K::BadKeyWindow)));
                }
                // Empty collapses to absent, which is what "everything the owner reaches"
                // means: see `KeyScopesHelp`.
                let lines = form.lines("scopes");
                let clear = lines.is_empty();
                edit_urls(&mut k.scopes, lines, Vec::new(), Vec::new(), clear);
                commit(v, &doc, "key set", &format!("{owner_label}/{id}"))
                    .map_err(|e| Refusal::on("scopes", e))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::User(owner.clone()), Msg::KeySaved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_key_form(v, &owner_label, Some(id), &released, &f, Some(&e)),
                ),
            }
        }

        Route::KeyRotate(owner, id) => {
            let owner_label = label_of(&doc, owner);
            let r = (|| -> Result<String, Refusal> {
                let sealed = rotate_api_key(&mut doc, owner, id)?;
                let written = commit(v, &doc, "key rotate", &format!("{owner_label}/{id}"))?;
                Ok(sealed.reveal(&written))
            })();
            match r {
                Ok(bearer) => {
                    Outcome::Page(200, title, page_minted(v, owner, &owner_label, id, &bearer))
                }
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (owner_label) " · api_keys · " (v.t(K::Rotate)) },
                        html! { p { code { (id) } } },
                        v.t(K::ConfirmKeyRotate),
                        v.t(K::Rotate),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::KeyRm(owner, id) => {
            let owner_label = label_of(&doc, owner);
            let r = (|| -> Result<(), Refusal> {
                remove_api_key(&mut doc, owner, id)?;
                commit(v, &doc, "key rm", &format!("{owner_label}/{id}"))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::User(owner.clone()), Msg::KeyRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (owner_label) " · api_keys · " (v.t(K::Remove)) },
                        html! { p { code { (id) } } },
                        v.t(K::ConfirmKeyRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::AppAdd => {
            let f = AppForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                let name = f.name.trim().to_string();
                let base = form.lines("base");
                let login_url = match f.login_url.trim() {
                    "" => None,
                    l => Some(l.to_string()),
                };
                let notes = match f.notes.trim() {
                    "" => None,
                    n => Some(n.to_string()),
                };
                add_application(
                    &mut doc,
                    AppSpec {
                        name: name.clone(),
                        base,
                        login_url,
                        notes,
                        ..Default::default()
                    },
                )
                .map_err(|e| Refusal::on("name", e))?;
                // Not attributed: base and login_url are both still unvalidated at this
                // point, so a compile failure could be either.
                commit(v, &doc, "app add", &name)?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Apps, Msg::AppAdded),
                Err(e) => Outcome::Page(400, title, page_app_form(v, None, &f, Some(&e))),
            }
        }

        Route::AppEdit(target) => {
            let f = AppForm::read(form);
            let r = (|| -> Result<String, Refusal> {
                let name = f.name.trim().to_string();
                if name.is_empty() {
                    return Err(Refusal::on("name", v.t(K::NameRequired)));
                }
                rename_application(&mut doc, target, &name).map_err(|e| Refusal::on("name", e))?;
                let a = app_mut(&mut doc, &name)?;
                a.base = form.lines("base");
                a.login_url = match f.login_url.trim() {
                    "" => None,
                    l => Some(l.to_string()),
                };
                a.notes = match f.notes.trim() {
                    "" => None,
                    n => Some(n.to_string()),
                };
                commit(v, &doc, "app set", &name)?;
                Ok(name)
            })();
            match r {
                Ok(name) => Outcome::Done(Route::App(name), Msg::AppSaved),
                Err(e) => Outcome::Page(400, title, page_app_form(v, Some(target), &f, Some(&e))),
            }
        }

        Route::AppRm(target) => {
            let r = (|| -> Result<(), Refusal> {
                let a = remove_application(&mut doc, target)?;
                commit(v, &doc, "app rm", a.name.trim())?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Apps, Msg::AppRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Apps)) " · " (v.t(K::Remove)) },
                        html! { p { code { (target) } } },
                        v.t(K::ConfirmAppRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::ScopeAdd(app) => {
            let f = ScopeForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                let spec = scope_spec(&doc, &f, form.lines("urls"))
                    .map_err(|e| Refusal::on("members", e))?;
                add_scope(&mut doc, app, spec, None).map_err(|e| Refusal::on("name", e))?;
                commit(v, &doc, "scope add", &format!("{app}/{}", f.name.trim()))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::App(app.clone()), Msg::ScopeAdded),
                Err(e) => Outcome::Page(400, title, page_scope_form(v, app, None, &f, Some(&e))),
            }
        }

        Route::ScopeEdit(app, target) => {
            let f = ScopeForm::read(form);
            let r = (|| -> Result<String, Refusal> {
                let name = f.name.trim().to_string();
                if name.is_empty() {
                    return Err(Refusal::on("name", v.t(K::NameRequired)));
                }
                rename_scope(&mut doc, app, target, &name).map_err(|e| Refusal::on("name", e))?;
                let spec = scope_spec(&doc, &f, form.lines("urls"))
                    .map_err(|e| Refusal::on("members", e))?;
                *scope_mut(&mut doc, app, &name)? = spec;
                commit(v, &doc, "scope set", &format!("{app}/{name}"))?;
                Ok(name)
            })();
            match r {
                Ok(_) => Outcome::Done(Route::App(app.clone()), Msg::ScopeSaved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_scope_form(v, app, Some(target), &f, Some(&e)),
                ),
            }
        }

        Route::ScopeRm(app, target) => {
            let r = (|| -> Result<(), Refusal> {
                let s = remove_scope(&mut doc, app, target)?;
                commit(v, &doc, "scope rm", &format!("{app}/{}", s.name.trim()))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::App(app.clone()), Msg::ScopeRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Scopes)) " · " (v.t(K::Remove)) },
                        html! { p { code { (app) "/" (target) } } },
                        v.t(K::ConfirmScopeRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::ScopeMove(app, target) => {
            let r = (|| -> Result<(), String> {
                let ai =
                    app_pos(&doc, app).ok_or_else(|| format!("no application '{}'", app.trim()))?;
                let si = scope_pos(&doc.applications[ai], target)
                    .ok_or_else(|| format!("{app}/{}: no such scope", target.trim()))?;
                let to = match form.get("dir") {
                    "up" => si.checked_sub(1),
                    "down" => Some(si + 1).filter(|j| *j < doc.applications[ai].scopes.len()),
                    _ => None,
                };
                // A move off either end is not an error, it is a button that was already
                // disabled: nothing changes, and nothing is written.
                if let Some(to) = to {
                    move_scope(&mut doc, app, si, to)?;
                    commit(
                        v,
                        &doc,
                        "scope mv",
                        &format!("{app}/{} --at {to}", target.trim()),
                    )?;
                }
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::App(app.clone()), Msg::ScopeMoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    notice("bad", v.t(K::NotFoundTitle), html! { p { (e) } }),
                ),
            }
        }

        Route::GroupAdd => {
            let f = GroupForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                let name = f.name.trim().to_string();
                let members =
                    parse_group_members(&doc, &f.members).map_err(|e| Refusal::on("members", e))?;
                add_user_group(&mut doc, &name, members).map_err(|e| Refusal::on("name", e))?;
                commit(v, &doc, "group add", &format!("@{name}"))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Groups, Msg::GroupAdded),
                Err(e) => Outcome::Page(400, title, page_group_form(v, None, &f, Some(&e))),
            }
        }

        Route::GroupEdit(target) => {
            let f = GroupForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                // No rename: a reference names a group by its exact spelling, so the
                // library does not offer one and neither does this form.
                let members =
                    parse_group_members(&doc, &f.members).map_err(|e| Refusal::on("members", e))?;
                *user_group_mut(&mut doc, target)? = members;
                commit(v, &doc, "group set", &format!("@{}", target.trim()))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Groups, Msg::GroupSaved),
                Err(e) => Outcome::Page(400, title, page_group_form(v, Some(target), &f, Some(&e))),
            }
        }

        Route::GroupRm(target) => {
            let r = (|| -> Result<(), Refusal> {
                // The library refuses while anything still references the group, and its
                // refusal names every referrer — which is the list of places to go and fix.
                remove_user_group(&mut doc, target)?;
                commit(v, &doc, "group rm", &format!("@{}", target.trim()))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Groups, Msg::GroupRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Groups)) " · " (v.t(K::Remove)) },
                        html! { p { code { "@" (target) } } },
                        v.t(K::ConfirmGroupRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::DenyAdd => {
            let f = DenyForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                let email = norm_email(&f.email);
                if email.is_empty() {
                    return Err(Refusal::on("email", v.t(K::EmailRequired)));
                }
                if !add_denied(&mut doc, &email).map_err(|e| Refusal::on("email", e))? {
                    return Err(Refusal::on("email", v.t(K::AlreadyDenied)));
                }
                commit(v, &doc, "deny add", &email)?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Denied, Msg::DeniedAdded),
                Err(e) => Outcome::Page(400, title, page_deny_form(v, &f, Some(&e))),
            }
        }

        Route::DenyRm(target) => {
            let email = norm_email(target);
            let r = (|| -> Result<(), Refusal> {
                if remove_denied(&mut doc, std::slice::from_ref(&email)) == 0 {
                    return Err(Refusal::from(v.t(K::NoSuchDenied).to_string()));
                }
                commit(v, &doc, "deny rm", &email)?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Denied, Msg::DeniedRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Denied)) " · " (v.t(K::Remove)) },
                        html! { p { code { (email) } } },
                        v.t(K::ConfirmDenyRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        // Everything else is a page, and a page does not take a POST — `Route::UserEdit`
        // included: nothing is left on a `UserSpec` for a standalone edit to change (the
        // uuid is fixed, emails and keys have their own routes), so its `GET` just shows
        // the user and its `POST` falls here.
        _ => Outcome::Page(
            405,
            title,
            notice(
                "bad",
                v.t(K::NotAllowedTitle),
                html! { p { (v.t(K::NotAllowedBody)) } },
            ),
        ),
    }
}

/// Build a `ScopeSpec` from a submitted form: `urls` already split into lines by the
/// caller, `access` copied verbatim (the library is the judge of whether it is one of the
/// three words), and the membership fields populated only under `restricted` — present on
/// any other kind is fatal, so this is what keeps a stray tick from ever reaching the
/// compile.
fn scope_spec(doc: &AccessFile, f: &ScopeForm, urls: Vec<String>) -> Result<ScopeSpec, String> {
    let access = f.access.trim().to_string();
    let (users, groups, credentials) = if access == "restricted" {
        let (u, g) = parse_members(doc, &f.members)?;
        let credentials = if !f.cred_login && !f.cred_api_key {
            None
        } else {
            let mut list = Vec::new();
            if f.cred_login {
                list.push("login".to_string());
            }
            if f.cred_api_key {
                list.push("api_key".to_string());
            }
            Some(list)
        };
        (
            (!u.is_empty()).then_some(u),
            (!g.is_empty()).then_some(g),
            credentials,
        )
    } else {
        (None, None, None)
    };
    Ok(ScopeSpec {
        name: f.name.trim().to_string(),
        urls,
        access,
        users,
        groups,
        credentials,
        notes: match f.notes.trim() {
            "" => None,
            n => Some(n.to_string()),
        },
    })
}

/// Split a members textarea into `users` (each line resolved to a uuid, exactly as an
/// operator types it: email or uuid, through [`user_pos`]) and `groups` (`@name`, kept
/// exactly as written — the file's own spelling, and what `compile_access` expands).
fn parse_members(doc: &AccessFile, text: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let mut users = Vec::new();
    let mut groups = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if group_ref(line).is_some() {
            groups.push(line.to_string());
        } else {
            match user_pos(doc, line) {
                Some(i) => users.push(doc.users[i].uuid.trim().to_ascii_lowercase()),
                None => return Err(format!("no user '{line}' (add them with: user add {line})")),
            }
        }
    }
    Ok((users, groups))
}

/// [`parse_members`] for a `user_groups` member list, which may only ever hold uuids: a
/// group cannot reference another group, so an `@name` line is refused here rather than
/// silently dropped into a field nothing reads.
fn parse_group_members(doc: &AccessFile, text: &str) -> Result<Vec<String>, String> {
    let mut users = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(g) = group_ref(line) {
            return Err(format!("'@{g}': a group cannot reference another group"));
        }
        match user_pos(doc, line) {
            Some(i) => users.push(doc.users[i].uuid.trim().to_ascii_lowercase()),
            None => return Err(format!("no user '{line}' (add them with: user add {line})")),
        }
    }
    Ok(users)
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// Serve one request: identify, authorize, route, then either render or mutate.
///
/// The order is the point. Identity and the admin allowlist come **before** the router and
/// before the file is opened, so there is no path — not a 404, not a `POST`, not a broken
/// access file — that answers anything to someone nginx did not vouch for. The two guards
/// are route-global and method-blind by construction: they are here, above everything.
fn handle(mut req: Request, cfg: &Config) {
    let target = req.url().to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let posting = *req.method() == Method::Post;
    let (lang_pref, lang) = negotiate_lang(
        query_param(&query, LANG_COOKIE).as_deref(),
        header_value(&req, "Cookie").and_then(|c| cookie_value(c, LANG_COOKIE)),
        header_value(&req, "Accept-Language"),
        cfg.default_lang,
    );
    let theme = negotiate_theme(
        query_param(&query, THEME_COOKIE).as_deref(),
        header_value(&req, "Cookie").and_then(|c| cookie_value(c, THEME_COOKIE)),
    );
    // Nothing is routed yet, so the Settings menu on an error page submits to the root.
    let anon = |at: Route| View {
        cfg,
        lang,
        lang_pref,
        theme,
        admin: None,
        at,
        query: "",
        rev: "",
        msg: None,
    };

    // Identity comes from nginx and from nowhere else. A missing header is a broken
    // deployment, not an anonymous visitor — say so, and fail closed.
    let raw_email = match header_value(&req, IDENTITY_HEADER) {
        Some(e) if !e.trim().is_empty() => e.to_string(),
        _ => {
            let v = anon(Route::Dashboard);
            let page = notice(
                "bad",
                v.t(K::NoIdentityTitle),
                html! { p { (v.t(K::NoIdentityBody)) } },
            );
            respond_page(req, 401, shell(&v, v.t(K::NoIdentityTitle), page));
            return;
        }
    };
    let email = norm_email(&raw_email);
    if !cfg.is_admin(&email) {
        let v = anon(Route::Dashboard);
        let page = notice(
            "bad",
            v.t(K::NotAdminTitle),
            html! { p { code { (email) } " " (v.t(K::NotAdminBody)) } },
        );
        respond_page(req, 403, shell(&v, v.t(K::NotAdminTitle), page));
        return;
    }

    let at = match route(&path, &cfg.base_path) {
        Some(r) => r,
        None => {
            let v = View {
                cfg,
                lang,
                lang_pref,
                theme,
                admin: Some(&email),
                at: Route::Dashboard,
                query: "",
                rev: "",
                msg: None,
            };
            let page = notice(
                "bad",
                v.t(K::NotFoundTitle),
                html! { p { (v.t(K::NotFoundBody)) } },
            );
            respond_page(req, 404, shell(&v, v.t(K::NotFoundTitle), page));
            return;
        }
    };

    // ----- POST: the mutating half -----------------------------------------
    if posting {
        // Same-origin or nothing, and before the body is even read.
        let allowed = csrf_ok(
            header_value(&req, "Sec-Fetch-Site"),
            header_value(&req, "Origin"),
            header_value(&req, "Host"),
        );
        let v = View {
            cfg,
            lang,
            lang_pref,
            theme,
            admin: Some(&email),
            at: at.clone(),
            query: "",
            rev: "",
            msg: None,
        };
        if !allowed {
            let page = notice("bad", v.t(K::CsrfTitle), html! { p { (v.t(K::CsrfBody)) } });
            respond_page(req, 403, shell(&v, v.t(K::CsrfTitle), page));
            return;
        }
        let form = Form::parse(&read_body(&mut req));
        match mutate(&v, &form) {
            Outcome::Done(to, msg) => {
                let location = format!("{}{}?msg={}", cfg.base_path, to.path(), msg.key());
                respond_redirect(req, &location);
            }
            Outcome::Page(status, title, content) => {
                respond_page(req, status, shell(&v, title, content))
            }
        }
        return;
    }

    // ----- GET: the rendering half -----------------------------------------

    // An explicit `?lang=` or `?theme=` is a choice: remember it, then send the browser to
    // the same page without that parameter, so a bookmark or a reload does not carry it
    // around forever. The rest of the query survives, which is what keeps a `can` result on
    // screen. The two checks are independent and each returns on its own redirect, which is
    // what makes the Settings form's single submit work while setting both: the first pass
    // stores the language and leaves `?theme=` standing, the redirect comes straight back in
    // and the second pass stores the theme. Two round trips on loopback, and no coupling
    // between the two preferences anywhere in the code.
    if query_param(&query, LANG_COOKIE)
        .and_then(|l| parse_lang_pref(&l))
        .is_some()
    {
        respond_lang_redirect(
            req,
            &preference_href(cfg, &at, &query, LANG_COOKIE),
            lang_pref,
        );
        return;
    }
    if query_param(&query, THEME_COOKIE)
        .and_then(|t| parse_theme(&t))
        .is_some()
    {
        respond_theme_redirect(req, &preference_href(cfg, &at, &query, THEME_COOKIE), theme);
        return;
    }

    // Fresh off disk, every request, and hashed: `rev` is what every form on this page will
    // carry, and what the `POST` that comes back has to still match.
    let raw = std::fs::read_to_string(&cfg.access_path).unwrap_or_default();
    let rev = sha256_hex(&raw);
    let v = View {
        cfg,
        lang,
        lang_pref,
        theme,
        admin: Some(&email),
        at: at.clone(),
        query: &query,
        rev: &rev,
        msg: query_param(&query, "msg").as_deref().and_then(Msg::parse),
    };

    let (doc, access) = match open_access_file(&cfg.access_path) {
        Ok(pair) => pair,
        Err(e) => {
            respond_page(
                req,
                500,
                shell(&v, v.t(K::FileErrorTitle), page_file_error(&v, &e)),
            );
            return;
        }
    };

    let title = at.title();
    let (status, content, title) = match &at {
        Route::Dashboard => (200, page_dashboard(&v, &doc, &access), v.t(K::Dashboard)),
        Route::Groups => (200, page_groups(&v, &doc), title),
        Route::Apps => (200, page_apps(&v, &doc), title),
        Route::App(n) => {
            let (status, content) = page_app(&v, &doc, n);
            (status, content, title)
        }
        Route::Denied => (200, page_denied(&v, &doc), title),
        Route::Users => (200, page_users(&v, &doc, &access), title),
        // Nothing left on a `UserSpec` for a standalone edit to change, so `UserEdit`
        // simply shows the same page `User` does: the uuid is fixed, and emails and keys
        // manage themselves on their own routes.
        Route::User(e) | Route::UserEdit(e) => {
            let (status, content) = page_user(&v, &doc, &access, e);
            (status, content, title)
        }
        Route::Can => (200, page_can(&v, &access, &query), title),

        Route::UserAdd => (200, page_user_form(&v, &UserForm::default(), None), title),
        Route::UserRm(key) => match user_pos(&doc, key) {
            Some(i) => {
                let u = &doc.users[i];
                let keys = u.api_keys.len();
                (
                    200,
                    page_confirm(
                        &v,
                        html! { (v.t(K::Users)) " · " (v.t(K::Remove)) },
                        html! {
                            p { code { (user_label(u)) } }
                            @if keys > 0 {
                                p class="muted" { (keys) " api_keys" }
                            }
                            @let refs = user_refs(&doc, &u.uuid.trim().to_ascii_lowercase());
                            @if !refs.is_empty() {
                                p class="muted" {
                                    (v.t(K::ReferencedBy)) " "
                                    @for (i, r) in refs.iter().enumerate() {
                                        @if i > 0 { ", " }
                                        code { (r) }
                                    }
                                }
                            }
                        },
                        v.t(K::ConfirmUserRm),
                        v.t(K::Remove),
                        None,
                    ),
                    title,
                )
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchUser), key, &Route::Users),
                title,
            ),
        },
        Route::EmailAdd(uuid) => match user_pos(&doc, uuid) {
            Some(i) => (
                200,
                page_email_form(&v, &user_label(&doc.users[i]), &UserForm::default(), None),
                title,
            ),
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchUser), uuid, &Route::Users),
                title,
            ),
        },
        Route::EmailRm(uuid, e) => match user_pos(&doc, uuid) {
            Some(_)
                if doc.users[user_pos(&doc, uuid).unwrap()]
                    .emails
                    .iter()
                    .any(|x| norm_email(x) == norm_email(e)) =>
            {
                (
                    200,
                    page_confirm(
                        &v,
                        html! { (v.t(K::Emails)) " · " (v.t(K::Remove)) },
                        html! { p { code { (norm_email(e)) } } },
                        v.t(K::ConfirmEmailRm),
                        v.t(K::Remove),
                        None,
                    ),
                    title,
                )
            }
            _ => (
                404,
                page_missing(&v, v.t(K::NoSuchUser), e, &Route::User(uuid.clone())),
                title,
            ),
        },
        Route::KeyAdd(uuid) => match user_pos(&doc, uuid) {
            Some(i) => {
                let owner = user_label(&doc.users[i]);
                let f = KeyForm {
                    duration: "365d".to_string(),
                    ..Default::default()
                };
                (
                    200,
                    page_key_form(&v, &owner, None, &format_date(now()), &f, None),
                    title,
                )
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchUser), uuid, &Route::Users),
                title,
            ),
        },
        Route::KeyEdit(uuid, id) => match find_key(&doc, uuid, id) {
            Some((u, k)) => (
                200,
                page_key_form(
                    &v,
                    &user_label(u),
                    Some(id),
                    k.released.trim(),
                    &KeyForm::of(k),
                    None,
                ),
                title,
            ),
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchKey), id, &Route::User(uuid.clone())),
                title,
            ),
        },
        Route::KeyRotate(uuid, id) => match find_key(&doc, uuid, id) {
            Some((u, _)) => (
                200,
                page_confirm(
                    &v,
                    html! { (user_label(u)) " · api_keys · " (v.t(K::Rotate)) },
                    html! { p { code { (id) } } },
                    v.t(K::ConfirmKeyRotate),
                    v.t(K::Rotate),
                    None,
                ),
                title,
            ),
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchKey), id, &Route::User(uuid.clone())),
                title,
            ),
        },
        Route::KeyRm(uuid, id) => match find_key(&doc, uuid, id) {
            Some((u, _)) => (
                200,
                page_confirm(
                    &v,
                    html! { (user_label(u)) " · api_keys · " (v.t(K::Remove)) },
                    html! { p { code { (id) } } },
                    v.t(K::ConfirmKeyRm),
                    v.t(K::Remove),
                    None,
                ),
                title,
            ),
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchKey), id, &Route::User(uuid.clone())),
                title,
            ),
        },

        Route::AppAdd => (
            200,
            page_app_form(&v, None, &AppForm::default(), None),
            title,
        ),
        Route::AppEdit(n) => match app_pos(&doc, n) {
            Some(i) => {
                let f = AppForm::of(&doc.applications[i]);
                let name = doc.applications[i].name.trim().to_string();
                (200, page_app_form(&v, Some(&name), &f, None), title)
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchApp), n, &Route::Apps),
                title,
            ),
        },
        Route::AppRm(n) => match app_pos(&doc, n) {
            Some(i) => {
                let a = &doc.applications[i];
                (
                    200,
                    page_confirm(
                        &v,
                        html! { (v.t(K::Apps)) " · " (v.t(K::Remove)) },
                        html! {
                            p { code { (a.name.trim()) } }
                            @if !a.scopes.is_empty() {
                                p class="muted" { (a.scopes.len()) " " (v.t(K::Scopes)) }
                            }
                        },
                        v.t(K::ConfirmAppRm),
                        v.t(K::Remove),
                        None,
                    ),
                    title,
                )
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchApp), n, &Route::Apps),
                title,
            ),
        },
        Route::ScopeAdd(app) => match app_pos(&doc, app) {
            Some(_) => (
                200,
                page_scope_form(&v, app, None, &ScopeForm::default(), None),
                title,
            ),
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchApp), app, &Route::Apps),
                title,
            ),
        },
        Route::ScopeEdit(app, n) => match app_pos(&doc, app).and_then(|i| {
            scope_pos(&doc.applications[i], n).map(|j| &doc.applications[i].scopes[j])
        }) {
            Some(s) => {
                let f = ScopeForm::of(&doc, s);
                (200, page_scope_form(&v, app, Some(n), &f, None), title)
            }
            None => (
                404,
                page_missing(
                    &v,
                    v.t(K::NoSuchScope),
                    &format!("{app}/{n}"),
                    &Route::App(app.clone()),
                ),
                title,
            ),
        },
        Route::ScopeRm(app, n) => match app_pos(&doc, app).and_then(|i| {
            scope_pos(&doc.applications[i], n).map(|j| &doc.applications[i].scopes[j])
        }) {
            Some(_) => (
                200,
                page_confirm(
                    &v,
                    html! { (v.t(K::Scopes)) " · " (v.t(K::Remove)) },
                    html! { p { code { (app) "/" (n) } } },
                    v.t(K::ConfirmScopeRm),
                    v.t(K::Remove),
                    None,
                ),
                title,
            ),
            None => (
                404,
                page_missing(
                    &v,
                    v.t(K::NoSuchScope),
                    &format!("{app}/{n}"),
                    &Route::App(app.clone()),
                ),
                title,
            ),
        },
        // A button, not a page: there is nothing to render for it, and a GET must not move
        // a scope any more than it may delete a user.
        Route::ScopeMove(..) => (
            405,
            notice(
                "bad",
                v.t(K::NotAllowedTitle),
                html! { p { (v.t(K::NotAllowedBody)) } },
            ),
            title,
        ),

        Route::GroupAdd => (
            200,
            page_group_form(&v, None, &GroupForm::default(), None),
            title,
        ),
        Route::GroupEdit(n) => match doc.user_groups.get(n.trim()) {
            Some(members) => {
                let f = GroupForm {
                    name: n.trim().to_string(),
                    members: members
                        .iter()
                        .map(|m| label_of(&doc, m))
                        .collect::<Vec<_>>()
                        .join("\n"),
                };
                (200, page_group_form(&v, Some(n.trim()), &f, None), title)
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchGroup), n, &Route::Groups),
                title,
            ),
        },
        Route::GroupRm(n) => match doc.user_groups.get(n.trim()) {
            Some(_) => (
                200,
                page_confirm(
                    &v,
                    html! { (v.t(K::Groups)) " · " (v.t(K::Remove)) },
                    html! {
                        p { code { "@" (n.trim()) } }
                        @let refs = user_group_refs(&doc, n.trim());
                        @if !refs.is_empty() {
                            p class="muted" {
                                (v.t(K::ReferencedBy)) " "
                                @for (i, r) in refs.iter().enumerate() {
                                    @if i > 0 { ", " }
                                    code { (r) }
                                }
                            }
                        }
                    },
                    v.t(K::ConfirmGroupRm),
                    v.t(K::Remove),
                    None,
                ),
                title,
            ),
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchGroup), n, &Route::Groups),
                title,
            ),
        },

        Route::DenyAdd => (200, page_deny_form(&v, &DenyForm::default(), None), title),
        Route::DenyRm(e) => {
            let email = norm_email(e);
            if doc.denied.iter().any(|d| norm_email(d) == email) {
                (
                    200,
                    page_confirm(
                        &v,
                        html! { (v.t(K::Denied)) " · " (v.t(K::Remove)) },
                        html! { p { code { (email) } } },
                        v.t(K::ConfirmDenyRm),
                        v.t(K::Remove),
                        None,
                    ),
                    title,
                )
            } else {
                (
                    404,
                    page_missing(&v, v.t(K::NoSuchDenied), &email, &Route::Denied),
                    title,
                )
            }
        }
    };
    respond_page(req, status, shell(&v, title, content));
}

/// One user's key, by owner (uuid or email) and id — what a key form and its two
/// confirmations need before there is anything to render. The owner row comes back too, so
/// a caller can label it with [`user_label`] without a second lookup.
fn find_key<'a>(
    doc: &'a AccessFile,
    key: &str,
    id: &str,
) -> Option<(&'a UserSpec, &'a ApiKeySpec)> {
    let i = user_pos(doc, key)?;
    let u = &doc.users[i];
    let k = u.api_keys.iter().find(|k| k.id.trim() == id.trim())?;
    Some((u, k))
}

/// Read the config, bind, and serve forever on a fixed pool of blocking threads — the gate's
/// shape, minus everything the gate needs and this does not.
fn main() {
    let cfg = Config::from_env();

    // Read once at startup so a broken file is heard about immediately, and so the banner
    // can say what is in it. Not fatal: the GUI's job is to *show* a broken file.
    match open_access_file(&cfg.access_path) {
        Ok((doc, _)) => eprintln!(
            "[bb-auth-web] {}: {} users, {} applications, {} scopes, {} user_groups, {} denied",
            cfg.access_path,
            doc.users.len(),
            doc.applications.len(),
            doc.applications
                .iter()
                .map(|a| a.scopes.len())
                .sum::<usize>(),
            doc.user_groups.len(),
            doc.denied.len()
        ),
        Err(e) => eprintln!("[bb-auth-web] WARNING: {e}"),
    }

    let server = Server::http(&cfg.listen).unwrap_or_else(|e| {
        eprintln!("[bb-auth-web] FATAL: cannot bind {}: {e}", cfg.listen);
        std::process::exit(1);
    });
    let base = if cfg.base_path.is_empty() {
        "/".to_string()
    } else {
        cfg.base_path.clone()
    };
    eprintln!(
        "[bb-auth-web] listening on {} | file={} | admins={} | base={base} | lang={}",
        cfg.listen,
        cfg.access_path,
        cfg.admins.len(),
        cfg.default_lang.code()
    );
    eprintln!(
        "[bb-auth-web] identity comes from the {IDENTITY_HEADER} header — this port must be \
         reachable ONLY through nginx, behind bb-auth's own auth_request"
    );
    eprintln!(
        "[bb-auth-web] this instance WRITES {} — every edit is validated with the gate's own \
         parser first, and goes live on: systemctl reload bb-auth",
        cfg.access_path
    );

    let server = std::sync::Arc::new(server);
    let cfg = std::sync::Arc::new(cfg);
    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let server = std::sync::Arc::clone(&server);
        let cfg = std::sync::Arc::clone(&cfg);
        handles.push(std::thread::spawn(move || loop {
            match server.recv() {
                Ok(req) => handle(req, &cfg),
                Err(e) => eprintln!("[bb-auth-web] recv error: {e}"),
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Bob's uuid, fixed so a redirect target and a route path are things a test can name.
    const BOB: &str = "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b";
    /// A second user, enrolled but in no scope: what `WarnNoScope`/`InNoScope` are for.
    const NOWHERE: &str = "11111111-1111-1111-1111-111111111111";

    /// A file with one of everything, so a rendering test has something to render.
    const SAMPLE: &str = r#"{ "version": 3,
      "applications": [
        { "name": "mpa", "base": ["https://app.x.com/mpa"],
          "scopes": [
            { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"], "access": "restricted",
              "groups": ["@admins"], "notes": "the admin area" }
          ] }
      ],
      "user_groups": {
        "admins": ["8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b"],
        "unused": ["8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b"]
      },
      "denied": ["spammer@x.com"],
      "users": [
        { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b", "emails": ["Bob@X.com"], "notes": "the bot",
          "api_keys": [ { "id": "laptop",
            "key_hash": "1111111111111111111111111111111111111111111111111111111111111111",
            "released": "1970-01-01", "duration": "1d" } ] },
        { "uuid": "11111111-1111-1111-1111-111111111111", "emails": ["nowhere@x.com"] }
      ]
    }"#;

    /// Two scopes in one application, so a reorder has somewhere to go.
    const TWO_SCOPES: &str = r#"{ "version": 3,
      "applications": [
        { "name": "app1", "base": ["https://app.x.com"],
          "scopes": [
            { "name": "first", "urls": ["https://app.x.com/a/*"], "access": "anonymous" },
            { "name": "second", "urls": ["https://app.x.com/b/*"], "access": "anonymous" }
          ] }
      ],
      "users": [ { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b", "emails": ["bob@x.com"] } ]
    }"#;

    fn cfg_for(path: &str, base: &str) -> Config {
        Config {
            listen: String::new(),
            access_path: path.to_string(),
            admins: vec!["admin@x.com".to_string()],
            base_path: base.to_string(),
            default_lang: Lang::En,
        }
    }

    /// Write `json` to a uniquely-named temp file so tests can run in parallel.
    fn scratch(name: &str, json: &str) -> String {
        let p = std::env::temp_dir().join(format!("bb-auth-web-{name}.json"));
        std::fs::write(&p, json).unwrap();
        p.to_string_lossy().into_owned()
    }

    /// The scratch file and the backup a write leaves beside it.
    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.bak"));
    }

    fn read(path: &str) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    /// The fingerprint a form rendered from this file would carry.
    fn rev_of(path: &str) -> String {
        sha256_hex(&read(path))
    }

    fn body_of(fields: &[(&str, &str)]) -> String {
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for (k, v) in fields {
            ser.append_pair(k, v);
        }
        ser.finish()
    }

    /// What a `POST` came to, as a test wants to read it.
    #[derive(Debug)]
    enum Got {
        /// The `Location:` a `303` would carry, base path and `?msg=` included.
        Redirect(String),
        /// A status and the whole rendered page.
        Page(u16, String),
    }

    impl Got {
        fn page(&self) -> (u16, &str) {
            match self {
                Got::Page(s, h) => (*s, h.as_str()),
                Got::Redirect(l) => panic!("expected a page, got a redirect to {l}"),
            }
        }
        fn location(&self) -> &str {
            match self {
                Got::Redirect(l) => l.as_str(),
                Got::Page(s, _) => panic!("expected a redirect, got a {s} page"),
            }
        }
    }

    /// Drive one `POST` exactly as [`handle`] does, minus the HTTP: parse the body, build
    /// the view, call [`mutate`], and turn the outcome into what a browser would see.
    fn post(cfg: &Config, at: Route, fields: &[(&str, &str)]) -> Got {
        let v = view(cfg, at, "");
        let form = Form::parse(&body_of(fields));
        match mutate(&v, &form) {
            Outcome::Done(to, msg) => {
                Got::Redirect(format!("{}{}?msg={}", cfg.base_path, to.path(), msg.key()))
            }
            Outcome::Page(status, title, content) => {
                Got::Page(status, shell(&v, title, content).into_string())
            }
        }
    }

    /// The `rev` a rendered page's forms carry, lifted out the way a browser would.
    fn rev_in(html: &str) -> String {
        const NEEDLE: &str = "name=\"rev\" value=\"";
        let at = html.find(NEEDLE).expect("a form carrying a rev");
        html[at + NEEDLE.len()..]
            .split('"')
            .next()
            .unwrap()
            .to_string()
    }

    // --- config -------------------------------------------------------------

    #[test]
    fn compile_admins_trims_lowercases_and_dedupes() {
        assert_eq!(
            compile_admins("  Alice@X.com , bob@x.com ,, ALICE@x.com ,").unwrap(),
            vec!["alice@x.com".to_string(), "bob@x.com".to_string()]
        );
        assert_eq!(compile_admins("one@x.com").unwrap(), vec!["one@x.com"]);
    }

    #[test]
    fn compile_admins_rejects_an_empty_list() {
        // Empty must never mean "everyone" — it is the whole point of the allowlist.
        for spec in ["", "   ", ",", " , , "] {
            assert!(compile_admins(spec).is_err(), "{spec:?} must be rejected");
        }
    }

    #[test]
    fn normalize_base_path_normalizes_and_rejects() {
        assert_eq!(normalize_base_path("").unwrap(), "");
        assert_eq!(normalize_base_path("  ").unwrap(), "");
        assert_eq!(normalize_base_path("/").unwrap(), "");
        assert_eq!(normalize_base_path("/admin").unwrap(), "/admin");
        assert_eq!(normalize_base_path("admin").unwrap(), "/admin");
        assert_eq!(normalize_base_path("/admin/").unwrap(), "/admin");
        assert_eq!(normalize_base_path(" /a/b// ").unwrap(), "/a/b");
        // It reaches a Location: header, so the same reflex as compile_login_url.
        assert!(normalize_base_path("/a b").is_err());
        assert!(normalize_base_path("/a\r\nX: 1").is_err());
        assert!(normalize_base_path("/a?b").is_err());
        assert!(normalize_base_path("/a#b").is_err());
    }

    #[test]
    fn parse_lang_accepts_only_the_two() {
        assert_eq!(parse_lang("en"), Some(Lang::En));
        assert_eq!(parse_lang(" IT "), Some(Lang::It));
        assert_eq!(parse_lang("fr"), None);
        assert_eq!(parse_lang(""), None);
    }

    // --- routing ------------------------------------------------------------

    #[test]
    fn route_without_a_base_path() {
        assert_eq!(route("/", ""), Some(Route::Dashboard));
        assert_eq!(route("", ""), Some(Route::Dashboard));
        assert_eq!(route("/users", ""), Some(Route::Users));
        assert_eq!(route("/users/", ""), Some(Route::Users));
        assert_eq!(route("/groups", ""), Some(Route::Groups));
        assert_eq!(route("/apps", ""), Some(Route::Apps));
        assert_eq!(route("/denied", ""), Some(Route::Denied));
        assert_eq!(route("/can", ""), Some(Route::Can));
        assert_eq!(route("/nope", ""), None);
        assert_eq!(route("/users/a/b", ""), None);
    }

    #[test]
    fn route_strips_the_base_path_and_404s_outside_it() {
        assert_eq!(route("/admin", "/admin"), Some(Route::Dashboard));
        assert_eq!(route("/admin/", "/admin"), Some(Route::Dashboard));
        assert_eq!(route("/admin/users", "/admin"), Some(Route::Users));
        // Outside the prefix, and the near-misses that a plain `starts_with` would admit.
        assert_eq!(route("/users", "/admin"), None);
        assert_eq!(route("/administrivia", "/admin"), None);
        assert_eq!(route("/adminusers", "/admin"), None);
        assert_eq!(route("/", "/admin"), None);
    }

    #[test]
    fn route_decodes_the_email_segment() {
        assert_eq!(
            route("/users/a%2Btag%40x.com", ""),
            Some(Route::User("a+tag@x.com".to_string()))
        );
    }

    #[test]
    fn email_path_segment_round_trips() {
        // A `+` is a literal plus, not a space — which is why this is not form_urlencoded.
        for email in [
            "bob@x.com",
            "a+tag@sub.example.co.uk",
            "n.o'brien@x.com",
            "béatrice@x.com",
            "<script>alert(1)</script>@x.com",
            "a b@x.com",
        ] {
            let enc = pct_encode_segment(email);
            assert!(
                enc.bytes().all(|b| b.is_ascii_graphic()),
                "{enc} must be printable ASCII"
            );
            assert!(!enc.contains('/'), "{enc} must stay one path segment");
            assert_eq!(pct_decode(&enc), email);
            assert_eq!(
                route(&format!("/users/{enc}"), ""),
                Some(Route::User(email.to_string()))
            );
        }
    }

    #[test]
    fn route_path_is_the_href_and_survives_a_hostile_email() {
        let r = Route::User("<script>@x.com".to_string());
        assert_eq!(r.path(), "/users/%3Cscript%3E%40x.com");
        assert_eq!(r.tab(), Route::Users);
    }

    // --- language -----------------------------------------------------------

    #[test]
    fn negotiate_lang_prefers_query_then_cookie_then_header_then_default() {
        // query beats everything
        assert_eq!(
            negotiate_lang(Some("it"), Some("en"), Some("en-GB"), Lang::En).1,
            Lang::It
        );
        // cookie beats the header
        assert_eq!(
            negotiate_lang(None, Some("it"), Some("en-GB"), Lang::En).1,
            Lang::It
        );
        // header beats the default
        assert_eq!(
            negotiate_lang(None, None, Some("it-IT,it;q=0.9"), Lang::En).1,
            Lang::It
        );
        // and the default is the floor
        assert_eq!(
            negotiate_lang(None, None, Some("de-DE"), Lang::En).1,
            Lang::En
        );
        assert_eq!(negotiate_lang(None, None, None, Lang::It).1, Lang::It);
        // an unparseable preference is not a preference
        assert_eq!(
            negotiate_lang(Some("fr"), Some("it"), None, Lang::En).1,
            Lang::It
        );
    }

    #[test]
    fn parse_lang_pref_accepts_auto_and_the_two_codes() {
        assert_eq!(parse_lang_pref("auto"), Some(LangPref::Auto));
        assert_eq!(parse_lang_pref(" Auto "), Some(LangPref::Auto));
        assert_eq!(parse_lang_pref("en"), Some(LangPref::Fixed(Lang::En)));
        assert_eq!(parse_lang_pref("IT"), Some(LangPref::Fixed(Lang::It)));
        assert_eq!(parse_lang_pref("fr"), None);
        assert_eq!(parse_lang_pref(""), None);
        // The code a choice is stored under is the one it is read back from.
        for p in [
            LangPref::Auto,
            LangPref::Fixed(Lang::En),
            LangPref::Fixed(Lang::It),
        ] {
            assert_eq!(parse_lang_pref(p.code()), Some(p));
        }
    }

    #[test]
    fn auto_is_the_floor_and_is_choosable_back_out_of_a_fixed_choice() {
        // No preference expressed at all reads as Auto, which is what makes naming the
        // behaviour in the menu change nobody's page.
        assert_eq!(negotiate_lang(None, None, None, Lang::En).0, LangPref::Auto);
        // A stored `auto` beats no header and still follows one when there is one, so
        // choosing it undoes a fixed choice instead of freezing today's answer.
        assert_eq!(
            negotiate_lang(None, Some("auto"), Some("it-IT"), Lang::En),
            (LangPref::Auto, Lang::It)
        );
        assert_eq!(
            negotiate_lang(None, Some("auto"), Some("de-DE"), Lang::En),
            (LangPref::Auto, Lang::En)
        );
        // And an explicit `?lang=auto` outranks a fixed cookie: that is the submit that
        // switches the menu back to Auto.
        assert_eq!(
            negotiate_lang(Some("auto"), Some("it"), Some("de-DE"), Lang::En),
            (LangPref::Auto, Lang::En)
        );
        // A fixed choice reports itself, never the language it happens to agree with.
        assert_eq!(
            negotiate_lang(None, Some("en"), Some("en-GB"), Lang::En).0,
            LangPref::Fixed(Lang::En)
        );
    }

    #[test]
    fn preference_href_drops_the_parameter_and_keeps_the_rest() {
        let cfg = cfg_for("x.json", "/admin");
        assert_eq!(
            preference_href(&cfg, &Route::Can, "email=bob%40x.com&lang=en", LANG_COOKIE),
            "/admin/can?email=bob%40x.com"
        );
        // The other preference survives the first redirect, which is what lets one submit
        // set both: see the two checks in `handle`.
        assert_eq!(
            preference_href(&cfg, &Route::Can, "lang=en&theme=dark", LANG_COOKIE),
            "/admin/can?theme=dark"
        );
        assert_eq!(
            preference_href(&cfg, &Route::Can, "lang=en&theme=dark", THEME_COOKIE),
            "/admin/can?lang=en"
        );
        assert_eq!(
            preference_href(&cfg, &Route::Dashboard, "", LANG_COOKIE),
            "/admin/"
        );
    }

    #[test]
    fn preference_href_never_carries_client_bytes_verbatim() {
        // Everything a client sent is re-encoded, so this string is safe in a Location:.
        let cfg = cfg_for("x.json", "");
        for param in [LANG_COOKIE, THEME_COOKIE] {
            let href = preference_href(
                &cfg,
                &Route::Can,
                "url=https://x/%0d%0aX:+1&lang=it&theme=dark",
                param,
            );
            assert!(href.bytes().all(|b| b.is_ascii_graphic()), "{href}");
            assert!(!href.contains('\r') && !href.contains('\n'));
        }
    }

    #[test]
    fn preserved_query_keeps_everything_the_settings_form_does_not_set() {
        // The form sends its own fields and nothing else, so what it does not put back as a
        // hidden field is lost: a `can` result, and the flash the page is showing.
        let kept = preserved_query(
            "email=bob%40x.com&url=https%3A%2F%2Fx%2Fa&lang=en&theme=dark&msg=user-added",
        );
        assert_eq!(
            kept,
            vec![
                ("email".to_string(), "bob@x.com".to_string()),
                ("url".to_string(), "https://x/a".to_string()),
                ("msg".to_string(), "user-added".to_string()),
            ]
        );
        assert!(preserved_query("").is_empty());
    }

    #[test]
    fn cookie_value_parses_the_language_cookie() {
        assert_eq!(cookie_value("lang=it", LANG_COOKIE), Some("it"));
        assert_eq!(cookie_value("a=1; lang=en; b=2", LANG_COOKIE), Some("en"));
        assert_eq!(cookie_value("mylang=it", LANG_COOKIE), None);
        assert_eq!(cookie_value("a=1", LANG_COOKIE), None);
    }

    // --- theme ----------------------------------------------------------------

    #[test]
    fn parse_theme_accepts_the_three_spellings_and_nothing_else() {
        assert_eq!(parse_theme("light"), Some(Theme::Light));
        assert_eq!(parse_theme("Dark"), Some(Theme::Dark));
        assert_eq!(parse_theme(" system "), Some(Theme::System));
        // an unrecognised value is not an error, just no preference expressed
        assert_eq!(parse_theme("blue"), None);
        assert_eq!(parse_theme(""), None);
    }

    #[test]
    fn negotiate_theme_prefers_query_then_cookie_then_system() {
        // query beats the cookie
        assert_eq!(negotiate_theme(Some("dark"), Some("light")), Theme::Dark);
        // cookie beats the default
        assert_eq!(negotiate_theme(None, Some("light")), Theme::Light);
        // System is the floor, with nothing expressed
        assert_eq!(negotiate_theme(None, None), Theme::System);
        // an unparseable preference is not a preference, so the next source still applies
        assert_eq!(negotiate_theme(Some("blue"), Some("dark")), Theme::Dark);
        assert_eq!(negotiate_theme(None, Some("blue")), Theme::System);
    }

    #[test]
    fn cookie_value_parses_the_theme_cookie() {
        assert_eq!(cookie_value("theme=dark", THEME_COOKIE), Some("dark"));
        assert_eq!(
            cookie_value("a=1; theme=light; b=2", THEME_COOKIE),
            Some("light")
        );
        assert_eq!(cookie_value("mytheme=dark", THEME_COOKIE), None);
        assert_eq!(cookie_value("a=1", THEME_COOKIE), None);
    }

    #[test]
    fn theme_attr_is_none_only_for_system() {
        // `None` is what leaves `data-theme` off the page for System; an explicit choice
        // always carries its own spelling.
        assert_eq!(Theme::Light.attr(), Some("light"));
        assert_eq!(Theme::Dark.attr(), Some("dark"));
        assert_eq!(Theme::System.attr(), None);
    }

    #[test]
    fn shell_emits_data_theme_only_for_an_explicit_choice() {
        // The stylesheet itself mentions `data-theme` in its selectors, so the assertion has
        // to look at the `<html ...>` tag specifically, not the page as a whole.
        let cfg = cfg_for("x.json", "");
        let mut v = view(&cfg, Route::Dashboard, "REV");
        let html = shell(&v, "t", html! { "x" }).into_string();
        assert!(
            html.contains(r#"<html lang="en">"#),
            "System must render no data-theme attribute at all: {html}"
        );
        v.theme = Theme::Dark;
        let html = shell(&v, "t", html! { "x" }).into_string();
        assert!(
            html.contains(r#"<html lang="en" data-theme="dark">"#),
            "{html}"
        );
    }

    #[test]
    fn the_settings_menu_marks_the_chosen_option_in_both_list_boxes() {
        let cfg = cfg_for("x.json", "");
        let mut v = view(&cfg, Route::Dashboard, "REV");
        let html = shell(&v, "t", html! { "x" }).into_string();
        // The floor, and the reason it has to be a LangPref: `Auto` renders an English page
        // and must still come back as `Auto`, not as `en`.
        assert!(html.contains(r#"<option value="auto" selected>"#), "{html}");
        assert!(
            html.contains(r#"<option value="system" selected>"#),
            "{html}"
        );
        assert_eq!(html.matches(" selected>").count(), 2, "{html}");

        v.lang_pref = LangPref::Fixed(Lang::It);
        v.theme = Theme::Dark;
        let html = shell(&v, "t", html! { "x" }).into_string();
        assert!(html.contains(r#"<option value="it" selected>"#), "{html}");
        assert!(html.contains(r#"<option value="dark" selected>"#), "{html}");
        assert_eq!(html.matches(" selected>").count(), 2, "{html}");
    }

    #[test]
    fn the_page_carries_one_handler_and_no_script() {
        // The invariant that replaced "no JavaScript": no page may *need* a script. One
        // inline handler is allowed to save a click on the Settings list boxes; anything
        // else — a `<script>` tag, a second kind of handler, a `javascript:` href — would be
        // a page that stops working when scripting is off, which this GUI must never be.
        for html in [
            render("nojs-dash", Route::Dashboard),
            render("nojs-users", Route::Users),
            render("nojs-can", Route::Can),
        ] {
            assert!(!html.contains("<script"), "no page may carry a script tag");
            assert!(!html.contains("javascript:"), "{html}");
            // Two selects, two handlers, and no other `on…=` attribute anywhere.
            assert_eq!(
                html.matches(&format!("onchange=\"{SETTINGS_ONCHANGE}\""))
                    .count(),
                2,
                "{html}"
            );
            for handler in [
                " onclick=",
                " onload=",
                " onsubmit=",
                " oninput=",
                " onfocus=",
                " onerror=",
            ] {
                assert!(!html.contains(handler), "{handler} in {html}");
            }
            // And the way through without a script is on the page, inside <noscript>.
            assert!(
                html.contains("<noscript><div class=\"actions\"><button>"),
                "the no-script submit must be there, and inside noscript: {html}"
            );
        }
    }

    #[test]
    fn the_settings_menu_is_a_get_that_carries_the_rest_of_the_query() {
        // A GET, because it mutates nothing: every POST in this binary is a write to the
        // access file, guarded by the rev and the same-origin check, and a display
        // preference is neither.
        let cfg = cfg_for("x.json", "/admin");
        let mut v = view(&cfg, Route::Can, "REV");
        v.query = "email=bob%40x.com&lang=en&theme=dark";
        let html = shell(&v, "t", html! { "x" }).into_string();
        assert!(
            html.contains(r#"<form class="edit" method="get" action="/admin/can">"#),
            "{html}"
        );
        // The `can` result survives the round trip; the two parameters the form sets itself
        // do not come back as hidden fields, or the list boxes could never change them.
        assert!(
            html.contains(r#"<input type="hidden" name="email" value="bob@x.com">"#),
            "{html}"
        );
        assert!(!html.contains(r#"type="hidden" name="lang""#), "{html}");
        assert!(!html.contains(r#"type="hidden" name="theme""#), "{html}");
    }

    // --- rendering ----------------------------------------------------------

    /// A view over `cfg` at `at`, as a request would build one.
    fn view<'a>(cfg: &'a Config, at: Route, rev: &'a str) -> View<'a> {
        View {
            cfg,
            lang: Lang::En,
            lang_pref: LangPref::Auto,
            theme: Theme::System,
            admin: Some("admin@x.com"),
            at,
            query: "",
            rev,
            msg: None,
        }
    }

    /// Render one read-only page of `SAMPLE` and hand back the HTML.
    fn render(name: &str, at: Route) -> String {
        let path = scratch(name, SAMPLE);
        let cfg = cfg_for(&path, "");
        let (doc, access) = open_access_file(&cfg.access_path).unwrap();
        let v = view(&cfg, at.clone(), "REV");
        let content = match &at {
            Route::Dashboard => page_dashboard(&v, &doc, &access),
            Route::Groups => page_groups(&v, &doc),
            Route::Apps => page_apps(&v, &doc),
            Route::App(n) => page_app(&v, &doc, n).1,
            Route::Denied => page_denied(&v, &doc),
            Route::Users => page_users(&v, &doc, &access),
            Route::User(e) => page_user(&v, &doc, &access, e).1,
            Route::Can => page_can(
                &v,
                &access,
                "email=bob@x.com&url=https://app.x.com/mpa/admin/x",
            ),
            other => panic!("{other:?} is not a read-only page"),
        };
        let html = shell(&v, "t", content).into_string();
        let _ = std::fs::remove_file(&path);
        html
    }

    #[test]
    fn dashboard_counts_expiries_and_warnings() {
        let html = render("dash", Route::Dashboard);
        assert!(html.contains("user_groups"));
        // the 1970 key is long past
        assert!(html.contains("expired"), "{html}");
        // nowhere@x.com is in no scope, and @unused references nobody
        assert!(html.contains("reaches nothing"), "{html}");
        assert!(html.contains("@unused"));
        assert!(html.contains("referenced by nothing"));
    }

    #[test]
    fn user_page_shows_its_scopes_and_notes() {
        let html = render("user", Route::User(BOB.to_string()));
        assert!(
            html.contains("mpa/admin"),
            "the scope that lists this user is shown"
        );
        assert!(html.contains("the bot"), "notes come from extra");
        assert!(
            html.contains("everything its owner reaches"),
            "the sample key declares no scopes of its own"
        );
    }

    #[test]
    fn user_in_no_scope_gets_the_warning() {
        let html = render("nowhere", Route::User(NOWHERE.to_string()));
        assert!(html.contains("in no scope"), "{html}");
    }

    #[test]
    fn app_page_lists_its_scopes_in_file_order_with_raw_group_refs() {
        let html = render("app", Route::App("mpa".to_string()));
        assert!(
            html.contains("<ol"),
            "order is meaning, so it is an ordered list"
        );
        assert!(html.contains("admin") && html.contains("restricted"));
        // A `@group` reference is shown as the file spells it, never expanded to who it
        // resolves to today.
        assert!(html.contains("@admins"), "the reference is shown as stored");
    }

    #[test]
    fn apps_page_lists_applications_with_their_scope_count() {
        let html = render("apps", Route::Apps);
        assert!(html.contains("mpa"));
    }

    #[test]
    fn can_page_renders_the_gates_own_verdict() {
        let html = render("can", Route::Can);
        assert!(html.contains("AUTHORIZED"), "{html}");
        assert!(html.contains("X-Auth-Email"));
    }

    #[test]
    fn groups_page_names_who_references_a_group() {
        let html = render("groups", Route::Groups);
        assert!(html.contains("referenced by"));
        assert!(html.contains("mpa/admin"));
    }

    #[test]
    fn denied_page_shows_a_stranger_by_email() {
        let html = render("denied", Route::Denied);
        assert!(html.contains("spammer@x.com"));
    }

    #[test]
    fn hostile_values_from_the_file_come_out_escaped() {
        // The access file is operator-owned, but it is also a text file that anything with
        // root can write, and half of it ends up in a page. maud escapes on the way in;
        // this pins that it stays that way.
        let json = r#"{ "version": 3, "users": [
            { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b",
              "emails": ["<script>alert(1)</script>@x.com"], "notes": "<b>bold</b>" } ] }"#;
        let path = scratch("xss", json);
        let cfg = cfg_for(&path, "");
        let (doc, access) = open_access_file(&cfg.access_path).unwrap();
        let v = view(&cfg, Route::Users, "REV");
        for html in [
            shell(&v, "t", page_users(&v, &doc, &access)).into_string(),
            shell(&v, "t", page_user(&v, &doc, &access, BOB).1).into_string(),
        ] {
            assert!(
                html.contains("&lt;script&gt;alert(1)&lt;/script&gt;@x.com"),
                "{html}"
            );
            assert!(!html.contains("<script>alert(1)"), "{html}");
            assert!(!html.contains("<b>bold</b>"), "{html}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_broken_file_renders_the_librarys_message_verbatim() {
        let path = scratch(
            "broken",
            r#"{ "version": 3, "applications": [
                { "name": "a", "base": ["https://x.com/a"], "scopes": [
                    { "name": "s", "urls": ["https://x.com/a/*"], "access": "restricted",
                      "groups": ["@nope"] } ] } ] }"#,
        );
        let cfg = cfg_for(&path, "");
        // `Access` has no `Debug` on purpose (a table of live credentials), so no unwrap_err.
        let err = match open_access_file(&cfg.access_path) {
            Ok(_) => panic!("a dangling @group reference must be refused"),
            Err(e) => e,
        };
        let v = view(&cfg, Route::Dashboard, "REV");
        let html = page_file_error(&v, &err).into_string();
        assert!(
            html.contains("the gate would reject this file as it stands"),
            "{html}"
        );
        assert!(html.contains("unknown user group"), "{html}");
        let _ = std::fs::remove_file(&path);
    }

    // --- mutations ----------------------------------------------------------

    #[test]
    fn csrf_accepts_only_a_same_origin_submission() {
        // Sec-Fetch-Site is the whole answer where the browser sends it.
        assert!(csrf_ok(Some("same-origin"), None, None));
        assert!(csrf_ok(Some(" Same-Origin "), None, None));
        for bad in ["cross-site", "same-site", "none", ""] {
            assert!(!csrf_ok(Some(bad), None, None), "{bad:?} must be refused");
        }
        // A hostile Origin does not rescue a cross-site Sec-Fetch-Site.
        assert!(!csrf_ok(
            Some("cross-site"),
            Some("https://x.com"),
            Some("x.com")
        ));
        // Origin is the fallback, and only the host is compared — the scheme cannot be,
        // since this binary speaks http behind a TLS-terminating nginx.
        assert!(csrf_ok(
            None,
            Some("https://admin.x.com"),
            Some("admin.x.com")
        ));
        assert!(csrf_ok(
            None,
            Some("http://admin.x.com:8091"),
            Some("admin.x.com:8091")
        ));
        assert!(!csrf_ok(
            None,
            Some("https://evil.com"),
            Some("admin.x.com")
        ));
        assert!(!csrf_ok(None, Some("null"), Some("admin.x.com")));
        // Neither header is not a browser posting a form.
        assert!(!csrf_ok(None, None, Some("admin.x.com")));
        assert!(!csrf_ok(None, None, None));
    }

    #[test]
    fn a_user_add_mints_a_uuid_and_redirects_to_it() {
        let path = scratch("m-useradd", SAMPLE);
        let cfg = cfg_for(&path, "");
        let got = post(
            &cfg,
            Route::UserAdd,
            &[("rev", &rev_of(&path)), ("email", " New@X.com ")],
        );
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        let u = doc
            .users
            .iter()
            .find(|u| u.emails.iter().any(|e| e == "new@x.com"))
            .expect("the new row");
        assert_eq!(
            u.emails,
            ["new@x.com"],
            "the email is normalised on the way in"
        );
        assert_eq!(got.location(), format!("/users/{}?msg=user-added", u.uuid));
        cleanup(&path);
    }

    #[test]
    fn a_rev_mismatch_is_a_409_and_writes_nothing() {
        let path = scratch("m-rev", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::UserAdd,
            &[
                (
                    "rev",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ),
                ("email", "new@x.com"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 409);
        assert!(html.contains("The file changed"), "{html}");
        // The typed input is one Back-button press away, and the page says so.
        assert!(html.contains("Back button"), "{html}");
        assert_eq!(read(&path), before, "nothing may be written on a conflict");
        // A form with no rev at all is the same refusal, not a bypass.
        let got = post(&cfg, Route::UserAdd, &[("email", "new@x.com")]);
        assert_eq!(got.page().0, 409);
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn a_refused_scope_add_re_renders_the_form_with_the_librarys_words() {
        let path = scratch("m-refused", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::ScopeAdd("mpa".to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("name", "reports"),
                ("urls", "https://elsewhere.com/x"),
                ("access", "anonymous"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        // Verbatim, in the English the CLI says it in.
        assert!(html.contains("refusing to write"), "{html}");
        assert!(html.contains("outside this application's base"), "{html}");
        // And the submitted values are still in the fields.
        assert!(
            html.contains("https://elsewhere.com/x</textarea>"),
            "{html}"
        );
        assert!(html.contains("value=\"reports\""), "{html}");
        assert_eq!(read(&path), before, "a refusal writes nothing");
        cleanup(&path);
    }

    #[test]
    fn hostile_submitted_values_come_back_escaped() {
        let path = scratch("m-hostile", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::ScopeAdd("mpa".to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("name", "reports"),
                ("urls", "https://app.x.com/mpa/reports/*"),
                ("access", "restricted"),
                ("members", "\"><img src=x onerror=alert(1)>"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        assert!(!html.contains("<img src=x"), "{html}");
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn a_hostile_email_comes_back_escaped_in_the_user_form() {
        // The local part is deliberately unrestricted (`well_formed_email` only checks the
        // domain), so a script tag ahead of an ordinary `@x.com` is accepted; this uses a
        // `>` in the domain instead, which the label check does refuse.
        let path = scratch("m-hostile-email", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::UserAdd,
            &[
                ("rev", &rev_of(&path)),
                ("email", "<script>alert(1)</script>@evil>.com"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;@evil&gt;.com"),
            "{html}"
        );
        assert!(!html.contains("<script>alert(1)"), "{html}");
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn minting_shows_the_bearer_once_and_files_only_its_hash() {
        let path = scratch("m-mint", SAMPLE);
        let cfg = cfg_for(&path, "");
        let stale = rev_of(&path);
        let got = post(
            &cfg,
            Route::KeyAdd(BOB.to_string()),
            &[("rev", &stale), ("id", "ci"), ("duration", "365d")],
        );
        let (status, html) = got.page();
        assert_eq!(
            status, 200,
            "a mint renders its result, it does not redirect"
        );
        let bearer = html
            .split("Authorization: Bearer ")
            .nth(1)
            .and_then(|r| r.split('<').next())
            .expect("the bearer, once")
            .to_string();
        assert!(bearer.starts_with("bbk_"), "{bearer}");
        assert!(html.contains("stored nowhere"), "{html}");

        // The file carries the hash and never the bearer.
        let on_disk = read(&path);
        assert!(on_disk.contains(&sha256_hex(&bearer)), "the hash is filed");
        assert!(!on_disk.contains(&bearer), "the raw key is never stored");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        let k = &doc.users[0].api_keys;
        assert_eq!(k.len(), 2);
        assert!(
            k[1].scopes.is_none(),
            "an empty scopes field is the field being absent"
        );

        // A re-submitted form cannot double-mint: the write moved the file, so the rev the
        // browser still holds is stale.
        let replay = post(
            &cfg,
            Route::KeyAdd(BOB.to_string()),
            &[("rev", &stale), ("id", "ci2"), ("duration", "365d")],
        );
        assert_eq!(replay.page().0, 409);
        assert_eq!(read(&path), on_disk, "the replay wrote nothing");
        cleanup(&path);
    }

    #[test]
    fn a_reloaded_reveal_page_gets_the_mint_conflict_not_the_generic_409() {
        let path = scratch("m-mint-reload", SAMPLE);
        let cfg = cfg_for(&path, "");
        let stale = rev_of(&path);
        let fields = [("rev", stale.as_str()), ("id", "ci"), ("duration", "365d")];
        let first = post(&cfg, Route::KeyAdd("bob@x.com".to_string()), &fields);
        assert_eq!(first.page().0, 200, "the mint itself succeeds");
        let on_disk = read(&path);

        // The reveal page is the direct POST response, so reloading it re-submits these
        // exact bytes. The rev is stale — the mint's own write moved the file — and the
        // key exists, so the answer is the mint's own 409, not "someone else wrote".
        let replay = post(&cfg, Route::KeyAdd("bob@x.com".to_string()), &fields);
        let (status, html) = replay.page();
        assert_eq!(status, 409);
        assert!(html.contains("This key was already created"), "{html}");
        assert!(
            !html.contains("The file changed"),
            "the generic advice would mint a second key: {html}"
        );
        // A lost bearer's remedy is rotation, and the link is on the page.
        assert!(html.contains("/users/bob%40x.com/keys/ci/rotate"), "{html}");
        assert!(!html.contains("bbk_"), "no bearer on a replay: {html}");
        assert_eq!(read(&path), on_disk, "the replay wrote nothing");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        let ci = doc.users[0].api_keys.iter().filter(|k| k.id.trim() == "ci");
        assert_eq!(ci.count(), 1, "still exactly one key with this id");

        // A stale rev whose key does NOT exist is a genuine concurrent edit, and keeps
        // the generic page — nothing was created, redoing the change is the right advice.
        let other = post(
            &cfg,
            Route::KeyAdd("bob@x.com".to_string()),
            &[("rev", &stale), ("id", "other"), ("duration", "365d")],
        );
        let (status, html) = other.page();
        assert_eq!(status, 409);
        assert!(html.contains("The file changed"), "{html}");
        assert_eq!(read(&path), on_disk);
        cleanup(&path);
    }

    #[test]
    fn a_malformed_email_is_refused_on_the_form_it_came_from() {
        let path = scratch("m-bademail", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::UserAdd,
            &[("rev", &rev_of(&path)), ("email", "not an email")],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        // The library's refusal, verbatim, above the field that caused it.
        assert!(
            html.contains("does not look like an email address"),
            "{html}"
        );
        assert!(
            html.contains("value=\"not an email\""),
            "the typed value is still in the field: {html}"
        );
        assert_eq!(read(&path), before, "a refusal writes nothing");

        // The same door guards denied — a malformed veto would fail open.
        let got = post(
            &cfg,
            Route::DenyAdd,
            &[("rev", &rev_of(&path)), ("email", "bob@example,com")],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        assert!(
            html.contains("does not look like an email address"),
            "{html}"
        );
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn a_malformed_email_marks_the_email_field_invalid() {
        let path = scratch("m-bademail-attr", SAMPLE);
        let cfg = cfg_for(&path, "");
        let got = post(
            &cfg,
            Route::UserAdd,
            &[("rev", &rev_of(&path)), ("email", "not an email")],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        // The one field the refusal is about: an invalid border, and the two attributes
        // that tie it to the message above the form for assistive tech.
        assert!(
            html.contains("class=\"f-email invalid\""),
            "the email field carries the invalid state: {html}"
        );
        assert!(
            html.contains(&format!("aria-describedby=\"{ERR_ID}\"")),
            "{html}"
        );
        assert!(
            html.contains(&format!("id=\"{ERR_ID}\"")),
            "the error box carries the id aria-describedby points at: {html}"
        );
        assert_eq!(
            html.matches("aria-invalid=\"true\"").count(),
            1,
            "only the email field is marked: {html}"
        );
        cleanup(&path);
    }

    #[test]
    fn an_unattributable_refusal_marks_no_field_invalid() {
        // An application's `base` and `login_url` are both still-unvalidated when `commit`
        // runs, so a compile failure there cannot be pinned to either one with certainty,
        // unlike a malformed email, which always names `email` (see `mutate`'s
        // `Route::UserAdd` arm). A confidently wrong field is worse than none, so this
        // refusal marks nothing.
        let path = scratch("m-unattributed", SAMPLE);
        let cfg = cfg_for(&path, "");
        let got = post(
            &cfg,
            Route::AppAdd,
            &[
                ("rev", &rev_of(&path)),
                ("name", "app1"),
                ("base", "https://app.x.com/app1"),
                ("login_url", "http://login.x.com/"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        assert!(html.contains("must be an absolute https"), "{html}");
        assert!(!html.contains("aria-invalid=\"true\""), "{html}");
        assert!(
            !html.contains(&format!("aria-describedby=\"{ERR_ID}\"")),
            "{html}"
        );
        assert!(!html.contains("class=\"invalid\""), "{html}");
        assert!(!html.contains(" invalid\""), "{html}");
        cleanup(&path);
    }

    #[test]
    fn a_key_scopes_field_collapses_empty_to_inherit() {
        let path = scratch("m-keyscope", SAMPLE);
        let cfg = cfg_for(&path, "");
        let key = || Route::KeyEdit(BOB.to_string(), "laptop".to_string());
        let scopes = || {
            bb_auth_core::read_access_file(&path).unwrap().users[0].api_keys[0]
                .scopes
                .clone()
        };
        assert_eq!(scopes(), None, "the sample key inherits");

        let got = post(
            &cfg,
            key(),
            &[
                ("rev", &rev_of(&path)),
                ("duration", "1d"),
                ("scopes", "mpa/admin"),
            ],
        );
        assert_eq!(got.location(), format!("/users/{BOB}?msg=key-saved"));
        assert_eq!(scopes(), Some(vec!["mpa/admin".to_string()]));

        // And back: an empty textarea collapses to absent, "everything the owner reaches".
        let got = post(
            &cfg,
            key(),
            &[
                ("rev", &rev_of(&path)),
                ("duration", "1d"),
                ("scopes", "   \n  "),
            ],
        );
        assert_eq!(got.location(), format!("/users/{BOB}?msg=key-saved"));
        assert_eq!(scopes(), None, "an emptied textarea collapses to inherit");
        cleanup(&path);
    }

    #[test]
    fn a_bad_key_window_is_refused_before_anything_is_minted() {
        let path = scratch("m-window", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::KeyAdd(BOB.to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("id", "ci"),
                ("duration", "forever"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        assert!(html.contains("not a valid window"), "{html}");
        assert!(!html.contains("bbk_"), "no secret is handed out: {html}");
        assert_eq!(read(&path), before);
        // The same for a key with no id.
        let got = post(
            &cfg,
            Route::KeyAdd(BOB.to_string()),
            &[("rev", &rev_of(&path)), ("id", "  "), ("duration", "365d")],
        );
        assert!(got.page().1.contains("a key needs an id"));
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn removing_a_referenced_group_is_refused_with_its_referrers() {
        let path = scratch("m-grouprm", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::GroupRm("admins".to_string()),
            &[("rev", &rev_of(&path))],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        assert!(html.contains("is still referenced by"), "{html}");
        assert!(html.contains("mpa/admin"), "the referrer is named: {html}");
        assert_eq!(read(&path), before);

        // The unreferenced one goes.
        let got = post(
            &cfg,
            Route::GroupRm("unused".to_string()),
            &[("rev", &rev_of(&path))],
        );
        assert_eq!(got.location(), "/groups?msg=group-removed");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        assert!(!doc.user_groups.contains_key("unused"));
        assert!(doc.user_groups.contains_key("admins"));
        cleanup(&path);
    }

    #[test]
    fn a_scope_is_edited_and_reordered_by_its_buttons() {
        let path = scratch("m-scopes", TWO_SCOPES);
        let cfg = cfg_for(&path, "");
        let names = || {
            bb_auth_core::read_access_file(&path).unwrap().applications[0]
                .scopes
                .iter()
                .map(|s| s.name.clone())
                .collect::<Vec<_>>()
        };

        // Editing replaces the record wholesale: urls, access, members and credentials.
        let got = post(
            &cfg,
            Route::ScopeEdit("app1".to_string(), "second".to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("name", "second"),
                ("urls", "https://app.x.com/b\nhttps://app.x.com/b/*"),
                ("access", "restricted"),
                ("members", "bob@x.com"),
                ("cred_login", "on"),
                ("notes", "the vip area"),
            ],
        );
        assert_eq!(got.location(), "/apps/app1?msg=scope-saved");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        let second = &doc.applications[0].scopes[1];
        assert_eq!(second.urls.len(), 2);
        assert_eq!(second.access, "restricted");
        assert_eq!(second.users.as_deref(), Some(&[BOB.to_string()][..]));
        assert_eq!(
            second.credentials.as_deref(),
            Some(&["login".to_string()][..])
        );
        assert_eq!(second.notes.as_deref(), Some("the vip area"));

        // An access of "anonymous" with no members/credentials sent is not a stray field:
        // there is nothing to send, since this form never sends those fields blank-vs-set.
        let got = post(
            &cfg,
            Route::ScopeEdit("app1".to_string(), "second".to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("name", "second"),
                ("urls", "https://app.x.com/b/*"),
                ("access", "anonymous"),
            ],
        );
        assert_eq!(got.location(), "/apps/app1?msg=scope-saved");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        assert_eq!(doc.applications[0].scopes[1].access, "anonymous");
        assert!(doc.applications[0].scopes[1].users.is_none());

        // Order is meaning, so a move is a mutation like any other.
        assert_eq!(names(), ["first", "second"]);
        let got = post(
            &cfg,
            Route::ScopeMove("app1".to_string(), "second".to_string()),
            &[("rev", &rev_of(&path)), ("dir", "up")],
        );
        assert_eq!(got.location(), "/apps/app1?msg=scope-moved");
        assert_eq!(names(), ["second", "first"]);
        // And a move off the end changes nothing rather than erroring.
        let before = read(&path);
        post(
            &cfg,
            Route::ScopeMove("app1".to_string(), "second".to_string()),
            &[("rev", &rev_of(&path)), ("dir", "up")],
        );
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn a_denied_email_is_added_once_and_lifted() {
        let path = scratch("m-deny", TWO_SCOPES);
        let cfg = cfg_for(&path, "");
        let got = post(
            &cfg,
            Route::DenyAdd,
            &[("rev", &rev_of(&path)), ("email", " Bob@X.com ")],
        );
        assert_eq!(got.location(), "/denied?msg=denied-added");
        // An enrolled user is written down by uuid, so the veto covers every email they hold.
        assert_eq!(bb_auth_core::read_access_file(&path).unwrap().denied, [BOB]);
        // Twice is a refusal, not a second row.
        let got = post(
            &cfg,
            Route::DenyAdd,
            &[("rev", &rev_of(&path)), ("email", "bob@x.com")],
        );
        assert!(got.page().1.contains("already on denied"));
        // And the veto lifts.
        let got = post(
            &cfg,
            Route::DenyRm("bob@x.com".to_string()),
            &[("rev", &rev_of(&path))],
        );
        assert_eq!(got.location(), "/denied?msg=denied-removed");
        assert!(bb_auth_core::read_access_file(&path)
            .unwrap()
            .denied
            .is_empty());
        cleanup(&path);
    }

    #[test]
    fn a_page_route_does_not_take_a_post() {
        let path = scratch("m-405", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(&cfg, Route::Users, &[("rev", &rev_of(&path))]);
        assert_eq!(got.page().0, 405);
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn a_user_edit_route_has_nothing_to_post_and_falls_to_405() {
        // There is nothing left on a `UserSpec` for a standalone edit to change: the uuid
        // is fixed, and emails and keys manage themselves on their own routes.
        let path = scratch("m-useredit", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::UserEdit(BOB.to_string()),
            &[("rev", &rev_of(&path))],
        );
        assert_eq!(got.page().0, 405);
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn an_email_is_added_and_removed() {
        let path = scratch("m-email", SAMPLE);
        let cfg = cfg_for(&path, "");
        let got = post(
            &cfg,
            Route::EmailAdd(BOB.to_string()),
            &[("rev", &rev_of(&path)), ("email", " Second@X.com ")],
        );
        assert_eq!(got.location(), format!("/users/{BOB}?msg=user-saved"));
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        // The original email round-trips exactly as the file had it (case untouched); only
        // the freshly submitted one is normalised on the way in.
        assert_eq!(doc.users[0].emails, ["Bob@X.com", "second@x.com"]);

        let got = post(
            &cfg,
            Route::EmailRm(BOB.to_string(), "second@x.com".to_string()),
            &[("rev", &rev_of(&path))],
        );
        assert_eq!(got.location(), format!("/users/{BOB}?msg=user-saved"));
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        assert_eq!(doc.users[0].emails, ["Bob@X.com"]);

        // The last email is refused: a row nobody can sign in as is not a retirement, it
        // is a dead end.
        let got = post(
            &cfg,
            Route::EmailRm(BOB.to_string(), "bob@x.com".to_string()),
            &[("rev", &rev_of(&path))],
        );
        assert!(got.page().1.contains("only email"));
        cleanup(&path);
    }

    #[test]
    fn a_mutation_under_a_base_path_redirects_under_it() {
        let path = scratch("m-base", SAMPLE);
        let cfg = cfg_for(&path, "/admin");
        let got = post(
            &cfg,
            Route::UserAdd,
            &[("rev", &rev_of(&path)), ("email", "new@x.com")],
        );
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        let uuid = &doc
            .users
            .iter()
            .find(|u| u.emails.iter().any(|e| e == "new@x.com"))
            .unwrap()
            .uuid;
        assert_eq!(
            got.location(),
            format!("/admin/users/{uuid}?msg=user-added")
        );
        cleanup(&path);
    }

    #[test]
    fn a_known_msg_key_renders_and_an_unknown_one_is_dropped() {
        assert_eq!(Msg::parse("user-added"), Some(Msg::UserAdded));
        assert_eq!(Msg::parse("scope-moved"), Some(Msg::ScopeMoved));
        assert_eq!(Msg::parse("<script>"), None);
        assert_eq!(Msg::parse(""), None);
        assert_eq!(Msg::UserRemoved.text(Lang::It), "utente rimosso");
        // Every key round-trips, so a redirect can never name a banner that does not exist.
        for m in [
            Msg::UserAdded,
            Msg::KeySaved,
            Msg::AppAdded,
            Msg::ScopeAdded,
            Msg::GroupRemoved,
            Msg::DeniedAdded,
        ] {
            assert_eq!(Msg::parse(m.key()), Some(m));
        }
    }

    // --- the server ---------------------------------------------------------

    #[test]
    fn serving_enforces_the_identity_header_and_the_admin_allowlist() {
        let path = scratch("serve", SAMPLE);
        let cfg = cfg_for(&path, "");
        let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
        let port = server.server_addr().to_ip().expect("an ip address").port();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &cfg);
            }
        });
        let at = |p: &str| format!("http://127.0.0.1:{port}{p}");

        // No header at all: a broken deployment, not an anonymous visitor.
        match ureq::get(&at("/")).call() {
            Err(ureq::Error::Status(401, r)) => {
                assert!(r.into_string().unwrap().contains("auth_request"));
            }
            other => panic!("expected 401, got {other:?}"),
        }
        // Authenticated, but not on the allowlist.
        match ureq::get(&at("/"))
            .set(IDENTITY_HEADER, "someone@x.com")
            .call()
        {
            Err(ureq::Error::Status(403, r)) => {
                assert!(r.into_string().unwrap().contains("someone@x.com"));
            }
            other => panic!("expected 403, got {other:?}"),
        }
        // An administrator gets the dashboard, in the configured language.
        let body = ureq::get(&at("/"))
            .set(IDENTITY_HEADER, "Admin@X.com") // normalised, so capitalisation is fine
            .call()
            .expect("200")
            .into_string()
            .unwrap();
        assert!(
            body.contains("user_groups") && body.contains("Warnings"),
            "{body}"
        );
        // And an unknown path is a 404, not a fall-through to the dashboard.
        match ureq::get(&at("/nope"))
            .set(IDENTITY_HEADER, "admin@x.com")
            .call()
        {
            Err(ureq::Error::Status(404, _)) => {}
            other => panic!("expected 404, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The whole `POST` contract over real HTTP, under a base path: a confirmation page that
    /// changes nothing, the same-origin check, the `rev`, the `303`, and the replay that
    /// the `rev` turns into a `409`.
    #[test]
    fn serving_a_post_checks_the_origin_the_rev_and_then_redirects() {
        let path = scratch("serve-post", SAMPLE);
        let cfg = cfg_for(&path, "/admin");
        let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
        let port = server.server_addr().to_ip().expect("an ip address").port();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &cfg);
            }
        });
        let url = format!("http://127.0.0.1:{port}/admin/users/bob%40x.com/rm");
        // 303s must be visible, not followed.
        let agent = ureq::builder().redirects(0).build();
        let post = || agent.post(&url).set(IDENTITY_HEADER, "admin@x.com");

        // The confirmation page is a GET, and a GET changes nothing.
        let before = read(&path);
        let page = ureq::get(&url)
            .set(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("200")
            .into_string()
            .unwrap();
        assert!(
            page.contains("denied is for"),
            "the consequence is spelled out"
        );
        assert_eq!(read(&path), before, "a GET never mutates");
        let rev = rev_in(&page);
        assert_eq!(rev, rev_of(&path));

        // The identity header and the allowlist guard a POST exactly as they guard a GET:
        // they are above the router, so no method reaches a mutation without them.
        match agent
            .post(&url)
            .set("Sec-Fetch-Site", "same-origin")
            .send_form(&[("rev", &rev)])
        {
            Err(ureq::Error::Status(401, _)) => {}
            other => panic!("expected 401 with no identity header, got {other:?}"),
        }
        match agent
            .post(&url)
            .set(IDENTITY_HEADER, "someone@x.com")
            .set("Sec-Fetch-Site", "same-origin")
            .send_form(&[("rev", &rev)])
        {
            Err(ureq::Error::Status(403, r)) => {
                assert!(r.into_string().unwrap().contains("BB_AUTH_WEB_ADMINS"));
            }
            other => panic!("expected 403 for a non-admin POST, got {other:?}"),
        }
        assert_eq!(read(&path), before, "neither may have written anything");

        // No Sec-Fetch-Site and no Origin: not a browser posting a form.
        match post().send_form(&[("rev", &rev)]) {
            Err(ureq::Error::Status(403, r)) => {
                assert!(r.into_string().unwrap().contains("same-origin"));
            }
            other => panic!("expected 403, got {other:?}"),
        }
        assert_eq!(read(&path), before);

        // Cross-site is a refusal too, whatever the Origin claims.
        match post()
            .set("Sec-Fetch-Site", "cross-site")
            .set("Origin", &format!("http://127.0.0.1:{port}"))
            .send_form(&[("rev", &rev)])
        {
            Err(ureq::Error::Status(403, _)) => {}
            other => panic!("expected 403, got {other:?}"),
        }
        assert_eq!(read(&path), before);

        // Same-origin, current rev: it happens, and answers a 303 under the base path.
        let resp = post()
            .set("Sec-Fetch-Site", "same-origin")
            .send_form(&[("rev", &rev)])
            .expect("a 303 is not an error");
        assert_eq!(resp.status(), 303);
        assert_eq!(
            resp.header("Location"),
            Some("/admin/users?msg=user-removed")
        );
        let after = read(&path);
        assert!(!after.contains("Bob@X.com"), "bob is gone: {after}");

        // The browser still holds the old rev — a resubmission cannot repeat the deed.
        match post()
            .set("Sec-Fetch-Site", "same-origin")
            .send_form(&[("rev", &rev)])
        {
            Err(ureq::Error::Status(409, r)) => {
                assert!(r.into_string().unwrap().contains("The file changed"));
            }
            other => panic!("expected 409, got {other:?}"),
        }
        assert_eq!(read(&path), after);

        // And the redirect target renders the banner it was sent with.
        let landed = ureq::get(&format!(
            "http://127.0.0.1:{port}/admin/users?msg=user-removed"
        ))
        .set(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("200")
        .into_string()
        .unwrap();
        assert!(landed.contains("user removed"), "{landed}");
        cleanup(&path);
    }
}
