//! bb-auth-web — a server-rendered admin GUI over a bb-auth **access file**
//! (`BB_AUTH_ACCESS_FILE`, a.k.a. access.json).
//!
//! What `bb-auth-adm` shows on a terminal, this shows in a browser: the roster, the user
//! groups and who references them, each application's scopes in the order that decides which
//! one answers, the `denied` veto, every api key's expiry, and what `can EMAIL URL` answers,
//! here a section of the two pages that each hold half of that question (an application's and
//! a person's) rather than a page of its own, and answered, as there, by the gate's own
//! [`decide`]. And what `bb-auth-adm` *edits*, this
//! edits: full CRUD over every section, through the library's editing core and through
//! nothing else.
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
//! * nginx also sets [`PROXY_SECRET_HEADER`] on that location, from `BB_AUTH_WEB_PROXY_SECRET`,
//!   and this binary refuses any request that does not carry it. Loopback is reachable by every
//!   user and every other service on the host, and each of them can write `X-Auth-Email`, so the
//!   secret is the one thing that says "this came through the proxy": nginx sets it, and nothing
//!   else on the host knows it. It is compared on every request, in constant time
//!   ([`proxy_secret_matches`]), and the value is never printed, logged or rendered.
//!   `docs/ARCHITECTURE.md` §13.3.
//! * this binary reads that header and nothing else. It validates no token and mints no
//!   cookie: the only credential here is the proxy secret, which authorizes a *transport*,
//!   never a person, and buys nothing to anyone who cannot reach the port through nginx.
//!
//! Trusting the header is sound for one reason only: `proxy_set_header` overwrites whatever
//! the client sent, on **every** gated location, and the service is unreachable except
//! through nginx. Both halves are load-bearing. Exposing this port directly, or gating it
//! from a location that forgets the `proxy_set_header`, would let anyone name themselves —
//! so a missing header is a `401` here rather than an anonymous session, which turns a
//! broken deployment into an error page instead of a silent open door. The proxy secret is
//! what closes the other half: a process that reaches this port directly, having read nothing
//! it should not, is answered a `403` before its identity is looked at.
//!
//! And the header is not the last word: the email must also be on **`web.admins`** in the
//! settings file.
//! That allowlist is deliberate defense in depth: an `authenticated` scope covering the
//! GUI's URL would otherwise open the admin surface to any Cognito account. It is required,
//! and must be non-empty — empty must never mean "everyone".
//!
//! The first three checks are **route-global** and run before anything is routed, in that
//! order: there is no path (not a `404`, not a `POST`, not a broken access file) that answers
//! anything to a request the proxy did not send, or to someone nginx did not vouch for. The
//! fourth is not route-global, and that is the seam of this binary: the self-service page at
//! [`Config::account_path`] is dispatched **ahead of** the `web.admins` allowlist, because it
//! is the page a person who is not an administrator reads. Everything outside that prefix is
//! answered only to an administrator, and a non-administrator's request to it is a `403` and
//! never a `404` that names which paths exist.
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
//! Destructive actions (`user rm`, `key rm`, `key rotate`, `app rm`, `scope rm`,
//! `group rm`, `deny rm`) are a `GET` confirmation page whose `POST` does the deed — the
//! no-JavaScript form of "are you sure", and the only way to be sure a link never deletes
//! anything.
//! Each successful mutation writes one audit line to stderr ([`audit`]): who, the verb as
//! `bb-auth-adm` spells it, and the target's name — never a bearer, never a hash, never a
//! submitted value beyond the name.
//!
//! An edit is not live until the gate re-reads the file, and this binary cannot send that
//! signal: it is not the gate and does not run in its namespace. It does not have to.
//! `bb-auth-reload.path` watches the file and turns every save into a
//! `systemctl reload bb-auth`, so the footer says nothing about it — a standing instruction
//! to run a command nobody has to run is worse than no instruction.
//!
//! # Configuration
//!
//! | Var | Required | Default | Meaning |
//! |-----|----------|---------|---------|
//! | `BB_AUTH_ACCESS_FILE` | yes | — | the access file to render. Same name, same meaning as the gate's |
//! | `BB_AUTH_SETTINGS_FILE` | no | `settings.json` beside the access file | the settings file, read **and written** |
//! | `BB_AUTH_WEB_LISTEN` | no | `127.0.0.1:8091` | bind address. Keep it on loopback |
//! | `BB_AUTH_WEB_BASE_PATH` | no | *(empty)* | URL prefix nginx mounts the GUI at, e.g. `/admin` |
//! | `BB_AUTH_WEB_ACCOUNT_PATH` | no | `/account` | URL prefix of the self-service page. Must sit **beside** the base, never inside it: see [`compile_account_path`] |
//! | `BB_AUTH_WEB_DEFAULT_LANG` | no | `en` | `en` or `it`, when the request expresses no preference |
//! | `BB_AUTH_WEB_LOGOUT_URL` | no | *(empty)* | where the Sign out control points, or no control at all. See [`Config::logout_url`] |
//!
//! Read once at startup, like the gate: a change needs a restart. A missing required var is
//! a fatal exit, in the same words and for the same reason — there is no safe default.
//!
//! The administrator allowlist is deliberately **not** in this table. It is `web.admins` in
//! the settings file, read fresh on every request, and editable from the Settings tab: it is
//! the one setting this service both enforces and owns, so a change that needed a restart
//! would be a change this GUI could make and not see.
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
//! what keeps an access-check verdict on screen across a preference change.
//!
//! That handler is the only inline handler this binary emits, and the estate's rule is that no
//! page may **need** a script, not that no page carries one: the bearer reveal carries
//! [`COPY_SCRIPT`] for its copy button, and a browser running no code gets that page as it was
//! before, with no button (§13.14). `no_page_but_the_reveal_carries_a_script` pins the handler
//! list and the one script together, and `nojs.js` walks both in a real browser.
//!
//! **Language** is English and Italian, from a table compiled into the binary ([`t`]), plus
//! `Auto`: the choice to make no choice, which resolves per request against the browser's
//! `Accept-Language` and is what a session that never chose has always been getting (see
//! [`LangPref`]). Prose and labels are translated; the **file's vocabulary never is** —
//! `applications`, `scopes`, `user_groups`, `denied`, `anonymous`, `authenticated`,
//! `restricted`, `bbk_`, an `@group` reference, and every name, email and URL pattern read
//! the same in both, because they are what an operator will type into `bb-auth-adm` and into
//! the file itself. Library error messages render verbatim, in the English the gate and the
//! CLI already say them in.
//!
//! **Theme** is light, dark or system, and [`UiTheme::System`] is the floor for the same
//! reason `Auto` is: an existing session's page does not change appearance until someone
//! chooses. `System` then falls through to the deployment's own `ui.theme` ([`Look`]) before
//! the OS decides, so pinning one for a whole estate still leaves an administrator free to
//! work in the other. One CSS attribute selector, and no script at all, is what repaints the
//! page; the two-arm dark rule that makes an explicit choice win over the OS is in
//! [`THEME_CSS`], with the rest of the palette.
//!
//! **The time zone** is a third preference of the same kind, and the one that is not in the
//! menu: it changes one page, the audit, so it sits in that page's own filter row, and its
//! `Custom` choice needs a text box, which a menu of list boxes that apply on change has no
//! place for. It is remembered the same way ([`TZ_COOKIE`]) and redirected out of the URL the
//! same way. `Local` is the zone of the **host** this program runs on and not the browser's,
//! because no header carries a browser's zone and a page that may not need a script cannot
//! ask for it; the list box names the host's zone so nobody has to guess which one it is. The
//! zones come out of the host's own database ([`ZONEINFO_DIR`]), and none is compiled in.
//!
//! **How the Settings page opens** is the fourth, and the same shape again: its groups are
//! `details` that each fold on their own with no script, the page opens folded to its five
//! headings, and its two commands (expand all, collapse all) are links carrying `?groups=`,
//! which becomes [`GROUPS_COOKIE`] so that a page somebody opened stays open after the next
//! save. A refused field's group is open whatever the preference says.
//!
//! **The look is shared with the gate**, which is why neither the palette nor the controls
//! are in this file at all. Two reasons, and the second was learned by looking at the two
//! surfaces side by side: `ui.stylesheet_url` restyles this GUI and the gate's sign-in page
//! from one token file, which only works if both agree on what `--accent` names; and a shared
//! palette on its own does not stop a button from being a rounded rectangle on one page and a
//! lozenge on the other, because that is one author editing one file and no test and no
//! reader can see it from inside either. So the palette is [`THEME_CSS`], the objects a
//! person operates are [`BASE_CSS`], both come from the library and both programs emit the
//! same bytes; [`CSS`] is only this program's ARRANGEMENT of them, and it names no colour and
//! no control of its own.
//!
//! # The self-service page
//!
//! One page here is not an administrator's: the **self-service page** at
//! [`Config::account_path`] (by default `/account`), which is what one signed-in person does
//! to **their own** account, so that reading what they reach, and choosing a theme and a
//! language, stop needing an administrator. It is the console's trust model with the privilege
//! taken out: the proxy secret, the identity header and the settings file are read exactly as
//! they are everywhere else, and `web.admins` is **not** read at all, because an administrator
//! here is one more person acting on their own account. A stranger Cognito vouches for and a
//! roster user see the same page, and the `denied` veto is answered with a `403` ahead of
//! everything the page would otherwise say about them.
//!
//! Four read-only sections, as siblings: *Where you reach* (the applications and scope names
//! [`Access::scopes_reached`] returns, never a URL, since a URL is the gate's business and an
//! application's, not something to hand to a person), *Groups*, *API keys* (each key's id, its
//! expiry and its restriction, never the hash and never the bearer, which is printed once at
//! the moment it is minted and exists nowhere else) and *Profile* (each configured
//! `gate.profile_claims` claim and the value nginx forwarded, percent-decoded).
//!
//! The prefix is a **sibling** of [`Config::base_path`] and not a child of it, and
//! [`compile_account_path`] refuses a deployment where they overlap: the dispatch runs ahead of
//! the allowlist, so a page nested inside the console's URLs would answer `/admin/…` URLs as
//! the page. Its arrangement is the **console's column**: the console's header bar (`top_bar`)
//! with the operator's brand, an empty tabs `nav` and the one account menu, then a `main` of the
//! console's width, in [`CSS`] beside the console's tables, because the palette, the objects and
//! the layout are already shared (§13.26, §13.28). The menu's two list boxes carry the shell's
//! one handler, so a theme or a language applies the moment it is picked here as it does in the
//! console, with the Apply behind a `noscript` as the way in for a browser running no code
//! (step 13); the form is a `GET` back to the page, answered by one `302` that sets one cookie
//! per recognised choice and redirects back to the page with the parameters gone. The cookie
//! names are the console's own, so a choice carries between the two surfaces on one host.
//!
//! It is a **prefix of this binary**, not a settings-file value: it decides which code answers
//! a request, and the settings file is for what is read per request. `docs/ARCHITECTURE.md`
//! §13.2.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bb_auth_core::{
    add_api_key, add_application, add_denied, add_scope, add_user, add_user_email, add_user_group,
    app_mut, app_pos, compile_app_client_id, compile_asset_url, compile_audit_header,
    compile_cookie_domain, compile_issuer, csp_hash, decide, default_settings_path, edit_urls,
    email_verified_true, format_date, format_datetime, group_ref, guarded_changes, key_expiry,
    key_mut, move_scope, norm_email, now, open_access_file, open_settings_file, page_csp,
    parse_duration, parse_exclusion, read_audit, remove_api_key, remove_application, remove_denied,
    remove_scope, remove_user, remove_user_email, remove_user_group, rename_application,
    rename_scope, request_site, request_url, rotate_api_key, scope_mut, scope_pos, sha256_hex,
    shadowing_scope, social_idp_label, stylesheet_link, user_group_mut, user_group_refs,
    user_label, user_pos, user_refs, version_line, Access, AccessFile, AccessWrite, ApiKeySpec,
    AppSpec, AuditCredential, AuditEvent, AuditKind, AuditLimit, AuditPolicy, AuditUnit, Decision,
    Dur, GateSettings, GuardedSetting, HeaderFault, PrepareError, RequestSite, ScopeSpec,
    SealedKey, SettingKey, Settings, SettingsFile, SettingsRefusal, SettingsWrite,
    SocialButtonSpec, Subject, UiTheme, UrlFault, UserSpec, WiredButton, Written, BASE_CSS,
    DEFAULT_AUDIT_FILE, EXCLUDED_REF, IDENTITY_ATTRS, IDENTITY_HEADER, MAX_BRAND_NAME,
    MAX_SESSION_TTL, MIN_SESSION_TTL, PAGE_SECURITY_HEADERS, SOCIAL_IDPS, THEME_CSS,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

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

/// Cookie remembering which clock the audit is read in. A display preference exactly like the
/// two above and for the same reasons: it carries no identity and no capability, and the worst
/// a rewritten one achieves is a page read in another time zone.
const TZ_COOKIE: &str = "tz";

/// The audit form's text box for a zone of the operator's own, read only when the list box
/// beside it says `custom`. It is never a cookie itself: [`TZ_COOKIE`] stores the zone it named.
const TZ_CUSTOM_PARAM: &str = "tzc";

/// Cookie remembering whether the Settings page opens with its groups expanded or collapsed.
/// A display preference like the others, with their reasoning: the worst a rewritten one
/// achieves is a page folded the other way.
const GROUPS_COOKIE: &str = "groups";

/// Where the host keeps its zone database, which the tzdata package keeps current. Read on
/// demand and never bundled: see the `tz-rs` entry in `Cargo.toml`.
const ZONEINFO_DIR: &str = "/usr/share/zoneinfo";

/// The host's own zone, which is what `timedatectl set-timezone` points somewhere in
/// [`ZONEINFO_DIR`].
const LOCALTIME_FILE: &str = "/etc/localtime";

/// A year. The preference is a preference, not a session. Shared by every preference cookie:
/// [`LANG_COOKIE`], [`THEME_COOKIE`] and [`TZ_COOKIE`], all set through
/// [`respond_preference_redirect`].
const PREFERENCE_COOKIE_MAX_AGE: i64 = 31_536_000;

/// **The only inline handler this GUI emits**, on the two Preferences list boxes and nowhere else.
///
/// A `<select>` has no native way to say "I changed, act on it", so applying a preference the
/// moment it is picked needs a script — one expression of it. It is an *enhancement*: with
/// scripting off, the `<noscript>` submit button [`shell`] renders instead does exactly the
/// same thing, one click later, and that path sets **both** preferences in one trip where
/// this one sets whichever was just touched. Nothing on any page depends on it, and no other
/// element in this binary carries a handler of any kind. The binary's one `<script>` is
/// [`COPY_SCRIPT`], carried by the bearer reveal and by nothing else (§13.14): a script is not
/// a handler, so the handler allowlist stays exactly this one expression and `/account/`'s
/// policy needs no `'unsafe-hashes'` to run the reveal's button.
/// `no_page_but_the_reveal_carries_a_script` pins both halves, and `nojs.js` pins them in a
/// real browser.
///
/// `this.form.submit()` and not `requestSubmit()`: the older method is universal, and it
/// submits without firing the submit event, which is exactly what is wanted here since there
/// is no handler for one. The one way to break it is a control named `submit` shadowing the
/// method on the form, which would need a query parameter literally called `submit` (see
/// [`preserved_query`]) — no link this GUI builds has one, and the failure mode is a menu
/// that stops applying on change, not a broken page.
const SETTINGS_ONCHANGE: &str = "this.form.submit()";

/// The one `<script>` this program emits, on the bearer reveal and nowhere else (§13.14).
///
/// Copying to the clipboard needs scripting, and the estate's rule is that no page may *need* a
/// script, not that no page carries one. So the server renders the button `hidden` and this is
/// the only thing that shows it: a browser running no code, a browser that is not a secure
/// context, and a browser with no `navigator.clipboard` all get exactly the page as it was
/// before, the key selectable by hand and no control that does nothing.
///
/// `addEventListener` and not an `on…` attribute, so the handler allowlist
/// (`no_page_but_the_reveal_carries_a_script`) stays exactly the two Preferences list boxes, and
/// `/account`'s policy needs no `'unsafe-hashes'` to run it.
///
/// `Navigator.clipboard` and `Clipboard.writeText` are "available only in secure contexts
/// (HTTPS), in some or all supporting browsers", and `writeText` rejects with `NotAllowedError`
/// "if writing to the clipboard is not allowed" (MDN, Navigator/clipboard and
/// Clipboard/writeText). "Some or all" is why both `isSecureContext` and the property are
/// checked rather than either. There is no `document.execCommand("copy")` fallback: MDN marks it
/// deprecated and "not implemented consistently or fully by user agents", and the fallback this
/// page needs already exists, which is the selection the rejection path makes.
///
/// The key is read out of the DOM at click time, so it is in this constant nowhere: the script
/// is a compile-time constant, the reveal's own policy names its hash, and the bearer stays in
/// exactly one place in the response.
///
/// The word is set **on the click**, and a rejection replaces it, rather than the word following
/// the promise. `writeText` is a permission check and an IPC round trip, so a word that waits
/// for it leaves a clicked button saying nothing for a tick, which is exactly what a dead button
/// looks like, and this is the one control on the estate's most important page. The cost is that
/// a refused copy shows `data-done` for that same tick before `data-failed` replaces it.
///
/// The word goes to the **status span**, never into the button, and the button's own state is an
/// attribute (§13.15, §13.17): the control is an icon whose only text is its name, so a word
/// written into it would replace the glyph the person is looking at and take the name away from
/// the reader that speaks it. `data-state` is what the stylesheet swaps the glyph on, and a
/// refusal sets `failed`, which keeps the copy glyph and selects the key, since a copy that was
/// refused is one the person can still do by hand.
const COPY_SCRIPT: &str = r#"(function () {
  var code = document.getElementById("bearer");
  var btn = document.getElementById("bearer-copy");
  var status = document.getElementById("bearer-copy-status");
  if (!code || !btn || !status || !window.isSecureContext || !navigator.clipboard) { return; }
  btn.hidden = false;
  btn.addEventListener("click", function () {
    btn.setAttribute("data-state", "done");
    status.textContent = btn.getAttribute("data-done");
    navigator.clipboard.writeText(code.textContent).catch(function () {
      btn.setAttribute("data-state", "failed");
      window.getSelection().selectAllChildren(code);
      status.textContent = btn.getAttribute("data-failed");
    });
  });
})();"#;

/// The header that carries the proxy secret: `BB_AUTH_WEB_PROXY_SECRET` on this end, and the
/// one line of `/opt/bb-auth/etc/bb-auth-web.nginx` on nginx's (`proxy_set_header`, which
/// **overwrites** whatever the client sent under that name).
///
/// Deliberately not under `X-Auth-`: that prefix is where the gate derives a header from every
/// claim an operator can name (`derive_profile_header`), so a claim called `web_secret` would
/// be able to collide with this one.
const PROXY_SECRET_HEADER: &str = "X-BB-Web-Secret";

/// The default for `BB_AUTH_WEB_WORKERS`, the blocking request threads ([`compile_workers`],
/// [`Config::workers`], docs/ARCHITECTURE.md §13.13).
///
/// It is 8 and not the 2 this replaces, whose own comment says it was sized for the handful of
/// people on `web.admins`: `/account` opened the same process to every signed-in person. A
/// handler here **waits rather than computes** (a write queues on [`WRITE_LOCK`] and two
/// fsyncs, and from plan step 5 a Cognito call queues on the network), so the ruler is how many
/// slow handlers may be in flight while page views still get through, not the core count.
const DEFAULT_WORKERS: usize = 8;

/// The ceiling for `BB_AUTH_WEB_WORKERS` (docs/ARCHITECTURE.md §13.13). It is there to turn a
/// typo (`800`) into a refusal and not to forbid anything a real deployment needs: past this
/// many threads there is nothing left to do in parallel, since writes serialise on one lock and
/// a read is milliseconds.
const MAX_WORKERS: usize = 64;

/// One writer at a time inside this process. See [`mutate`], which is its only user.
static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// This GUI's layout, compiled in from `src/assets/admin.css`: **where things go**, and
/// nothing about what they look like. The palette is [`THEME_CSS`] and the controls are
/// [`BASE_CSS`], both of which [`shell`] emits immediately ahead of this, and both of which
/// the gate emits ahead of its own layout too. That split is the whole point of the
/// arrangement rather than tidiness: it is what makes this GUI and the sign-in page one
/// product by construction, so a change to a button's shape or a field's height reaches both
/// or neither, and what lets `ui.stylesheet_url` restyle them together from one token file
/// knowing nothing about either layout. A literal colour added here is a thing that file can
/// no longer restyle; a control's *appearance* added here is drift the sign-in page will
/// never hear about.
///
/// Still no external request of any kind by default — no font, no script, no image — so the
/// page needs nothing beyond these three constants on a laptop, on a phone, or on a host with
/// no route to the internet. An operator's stylesheet is an *addition* to a complete page
/// ([`Look`]), never a page that only works once it loads. Below 640px the layout adapts (a
/// compact header, table rows stacked into cards) but ships not one byte more to get there.
///
/// Light and dark come from `prefers-color-scheme`, and an explicit choice overrides it through
/// the `data-theme` attribute [`shell`] puts on `html`; both live in [`THEME_CSS`]. There is
/// still no script on any page that paints: not for a form, not for a confirmation, not for
/// reordering a scope, not for opening the Settings menu, and not for the theme it sets either.
/// The override is CSS specificity, nothing more. (The one handler in the binary,
/// [`SETTINGS_ONCHANGE`], saves a click on a list box and paints nothing, and the one script,
/// [`COPY_SCRIPT`], is the bearer reveal's copy button and paints nothing either.)
const CSS: &str = include_str!("../../assets/admin.css");

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// A view for a page that answers before this request is anybody: nothing is routed yet, so
/// the Settings menu on it submits to the root, and it names no administrator.
///
/// The **look is a parameter**, and that is the whole point of this signature. Two of the
/// pages built from it render *before* the settings file has been read and can only wear the
/// built-in look, because the file that would say otherwise is exactly what is missing or
/// broken. The other two render *after* a successful read, and there the deployment has said
/// how its pages look: a `403` in a different palette from every other page of the same
/// installation looks like a page belonging to a different service, which is the opposite of
/// what an operator set `ui.stylesheet_url` to get. Passing it in makes each call site say
/// which of the two it is.
///
/// A function rather than a closure because [`Look`] borrows the settings it came from, and a
/// closure cannot name that lifetime.
fn anon_view<'a>(
    cfg: &'a Config,
    lang: Lang,
    lang_pref: LangPref,
    theme: UiTheme,
    look: Look<'a>,
) -> View<'a> {
    View {
        cfg,
        lang,
        lang_pref,
        theme,
        // An error page shows no time, so it has no clock to be read in, no settings to fold
        // and no audit to cut.
        tz: TzPref::Utc,
        groups: GroupsPref::Open,
        audit: AuditPolicy::default(),
        look,
        admin: None,
        // Every caller is an error page, and an error page belongs to no tab.
        at: Route::Dashboard,
        query: "",
        rev: "",
        msg: None,
        identity: vec![IDENTITY_HEADER.to_string()],
    }
}

/// Serve one request: prove the proxy sent it, identify, authorize, route, then either render
/// or mutate.
///
/// The order is the point. The proxy secret, the identity and the admin allowlist come
/// **before** the router and before the file is opened, so there is no path (not a 404, not a
/// `POST`, not a broken access file) that answers anything to someone nginx did not vouch for,
/// reached from outside the proxy. The three guards are route-global and method-blind by
/// construction: they are here, above everything.
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
    // The cookie alone, unlike the two above: a `?tz=` never reaches a render, because the
    // redirect below turns it into this cookie first. A cookie this binary could not have set
    // is no preference at all, and UTC is what no preference means.
    let tz = header_value(&req, "Cookie")
        .and_then(|c| cookie_value(c, TZ_COOKIE))
        .and_then(parse_tz_pref)
        .unwrap_or_default();
    // The same, for how the Settings page opens.
    let groups = header_value(&req, "Cookie")
        .and_then(|c| cookie_value(c, GROUPS_COOKIE))
        .and_then(GroupsPref::parse)
        .unwrap_or_default();
    // The proxy secret, ahead of the identity header and of the settings file
    // (docs/ARCHITECTURE.md §13.3). This port answers on loopback, and loopback is reachable by
    // every user and every other service on the host, each of which can write `X-Auth-Email`:
    // the secret is what says "this request came through nginx", because nginx sets it on the
    // one location and nothing else on the host knows it. It is checked here, above everything,
    // so a forged administrator's name buys a `403` and not the dashboard, and it is checked on
    // a `GET` as much as on a `POST`: a read of the roster, the settings and the audit is the
    // personal data this exists to keep in. Everything above this line reads request headers
    // only, so nothing here has looked at an identity, a file or the settings yet.
    if !proxy_secret_matches(
        header_value(&req, PROXY_SECRET_HEADER).unwrap_or(""),
        &cfg.proxy_secret,
    ) {
        // The built-in look, like the two refusals below it: the settings file is the thing
        // this request has not been allowed to read, so it cannot be asked what the page
        // should look like. The page says the request did not come through the proxy, names no
        // header value, and is the same one for an absent secret and a wrong one.
        let v = anon_view(cfg, lang, lang_pref, theme, Look::default());
        let page = notice(
            "bad",
            v.t(K::NoProxyTitle),
            html! { p { (v.t(K::NoProxyBody)) } },
        );
        respond_page(
            req,
            403,
            shell(&v, v.t(K::NoProxyTitle), page),
            &v.look,
            None,
            false,
        );
        return;
    }
    // The self-service page, dispatched **ahead of the administrator allowlist** and of the
    // identity refusal below it (docs/ARCHITECTURE.md §13.2). It is the one page of this program a
    // person who is not on `web.admins` reaches, so an allowlist that ran first would answer them
    // a `403` about a console they were never meant to open. The prefix test is anchored at the
    // **start** of the path and made at a path boundary, so `/admin/account` stays the console's
    // and `/accounts` is not the page.
    if path == cfg.account_path || path.starts_with(&format!("{}/", cfg.account_path)) {
        handle_account(req, cfg, &path, &query, lang_pref, lang, theme);
        return;
    }
    // Identity comes from nginx and from nowhere else. A missing header is a broken
    // deployment, not an anonymous visitor — say so, and fail closed.
    let raw_email = match header_value(&req, IDENTITY_HEADER) {
        Some(e) if !e.trim().is_empty() => e.to_string(),
        _ => {
            // The built-in look, and here there is no other: the settings have not been
            // read yet, and a request with no identity at all is not going to reach them.
            let v = anon_view(cfg, lang, lang_pref, theme, Look::default());
            let page = notice(
                "bad",
                v.t(K::NoIdentityTitle),
                html! { p { (v.t(K::NoIdentityBody)) } },
            );
            respond_page(
                req,
                401,
                shell(&v, v.t(K::NoIdentityTitle), page),
                &v.look,
                None,
                false,
            );
            return;
        }
    };
    // The header is a list, not one address: the gate puts **every** email of the roster row
    // into it, joined by a single space (`identity_headers` in `bb-auth`, `who.emails.join(" ")`).
    // Comparing that whole string against `web.admins` would lock out the administrator who
    // happens to hold a second address, from the only interface that can edit that list.
    let identities: Vec<String> = raw_email.split_ascii_whitespace().map(norm_email).collect();
    // What nginx sent, as the refusal page has to show it: an operator debugging a lockout
    // needs the header as it arrived, not one address picked out of it.
    let who_header = identities.join(" ");

    // The allowlist, fresh off disk on every request, because this is the one service that
    // can edit it. Three outcomes, and they are deliberately different pages: a file that
    // does not compile is a `500` naming the parser's own sentence (nobody is an
    // administrator, but saying "you are not one" would be a lie); an empty list is a `500`
    // too, because "everyone" is the one thing it must never come to mean; and only a list
    // that simply does not name this identity is the `403`.
    let settings = match open_settings_file(&cfg.settings_path) {
        Ok((_, s)) => s,
        Err(e) => {
            // The built-in look: the file that would describe another one is the file this
            // page exists to report on.
            let v = anon_view(cfg, lang, lang_pref, theme, Look::default());
            respond_page(
                req,
                500,
                shell(&v, v.t(K::FileErrorTitle), page_file_error(&v, &e)),
                &v.look,
                None,
                false,
            );
            return;
        }
    };
    // The settings are readable from here down, so every page below wears what they say.
    // `web.admins` being empty or not naming this identity says nothing about the `ui`
    // section, and there is no reason for those two pages to look like a different product.
    let look = Look {
        theme: settings.theme,
        stylesheet: settings.stylesheet_url.as_deref(),
        brand: settings.brand_name.as_deref(),
    };
    // The mark the bar shows and the one `img-src` source the policy names, read from the
    // same settings as the rest of the look and handed to both the shell and the response
    // (§13.28 §6).
    let logo = settings.logo_url.as_deref();
    // The given name the header shows, and it exists only where the deployment configures the
    // claim: the settings say which header the proxy was told to fill, so a deployment that
    // does not name `given_name` forwards nothing and the bar says the address alone. Decoded
    // because the gate sends a profile value percent-encoded, and a bar reading
    // `Ada%20Admin · ada@x.com` is a bar showing an encoding nobody asked to see.
    let given = settings
        .profile_claims
        .iter()
        .find(|c| c.claim == "given_name")
        .and_then(|c| header_value(&req, &c.header))
        .map(pct_decode);
    if settings.admins.is_empty() {
        let v = anon_view(cfg, lang, lang_pref, theme, look);
        let e = format!("{}: {}", cfg.settings_path, v.t(K::AdminsNeverEmpty));
        respond_page(
            req,
            500,
            shell(&v, v.t(K::FileErrorTitle), page_file_error(&v, &e)),
            &v.look,
            logo,
            false,
        );
        return;
    }
    // Any one of the addresses the header carries is enough to be admitted, and the one this
    // request is answered under is the first of them that is an administrator: the audit line
    // and the Settings "cannot remove yourself" guard below name one identity, and the whole
    // header is not one.
    let email = match identities
        .iter()
        .find(|e| settings.is_admin(e.as_str()))
        .cloned()
    {
        Some(e) => e,
        None => {
            let v = anon_view(cfg, lang, lang_pref, theme, look);
            let page = html! {
                (notice(
                    "bad",
                    v.t(K::NotAdminTitle),
                    html! { p { code { (who_header) } " " (v.t(K::NotAdminBody)) } },
                ))
                // The way forward. This console has no page this person may open, but the
                // self-service page is theirs by design (§13.2), so the refusal ends in an
                // action and not in two icons (§13.17). A pill, because it is the one action
                // on the page.
                p class="primary" {
                    a class="pill" href=(format!("{}/", cfg.account_path)) {
                        (v.t(K::NotAdminToAccount))
                    }
                }
            };
            respond_page(
                req,
                403,
                shell_named(
                    &v,
                    Some(who(given.as_deref(), &who_header)),
                    logo,
                    v.t(K::NotAdminTitle),
                    page,
                ),
                &v.look,
                logo,
                false,
            );
            return;
        }
    };

    // From the same settings read the look came from, and for the same reason: what the
    // access check predicts and what admitted this request must come from one version of the
    // file. A save landing mid-request must not style a page from one version and admit it on
    // another.
    let identity: Vec<String> = settings
        .identity_attrs
        .iter()
        .map(|a| a.header.clone())
        .collect();

    let at = match route(&path, &cfg.base_path) {
        Some(r) => r,
        None => {
            let v = View {
                cfg,
                lang,
                lang_pref,
                theme,
                tz,
                groups,
                audit: settings.audit_policy,
                look,
                admin: Some(&email),
                at: Route::Dashboard,
                query: "",
                rev: "",
                msg: None,
                identity,
            };
            let page = notice(
                "bad",
                v.t(K::NotFoundTitle),
                html! { p { (v.t(K::NotFoundBody)) } },
            );
            respond_page(
                req,
                404,
                shell_as(
                    &v,
                    given.as_deref(),
                    &who_header,
                    logo,
                    v.t(K::NotFoundTitle),
                    page,
                ),
                &v.look,
                logo,
                false,
            );
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
        // The same fingerprint a `GET` renders, and for the same reason: whatever this POST
        // answers with is a form somebody may submit again. It used to be empty, which made
        // every page a POST produced a dead end: fix the field a refusal named, press Save,
        // and the answer was a 409 about a file nobody else had touched. Nothing here has
        // written yet, so these are the bytes the page about to be rendered was built from,
        // which is exactly what `rev` is defined to be.
        let raw = std::fs::read_to_string(edited_file(cfg, &at)).unwrap_or_default();
        let rev = sha256_hex(&raw);
        let v = View {
            cfg,
            lang,
            lang_pref,
            theme,
            tz: tz.clone(),
            groups,
            audit: settings.audit_policy,
            look,
            admin: Some(&email),
            at: at.clone(),
            query: "",
            rev: &rev,
            msg: None,
            identity: identity.clone(),
        };
        if !allowed {
            let page = notice("bad", v.t(K::CsrfTitle), html! { p { (v.t(K::CsrfBody)) } });
            respond_page(
                req,
                403,
                shell_as(
                    &v,
                    given.as_deref(),
                    &who_header,
                    logo,
                    v.t(K::CsrfTitle),
                    page,
                ),
                &v.look,
                logo,
                false,
            );
            return;
        }
        let form = Form::parse(&read_body(&mut req));
        match mutate(&v, &form) {
            Outcome::Done(to, msg) => {
                let location = format!("{}{}?msg={}", cfg.base_path, to.path(), msg.key());
                respond_redirect(req, &location);
            }
            Outcome::Page(status, title, content) => {
                // The bearer reveal is the only page this program runs a script on (§13.14),
                // and a `200` on one of these two routes can only be the reveal: every refusal
                // the mint and the rotate arms make is a `400`, a stale `rev` is a `409`, and a
                // route that mints nothing is not one of these two.
                let reveal =
                    status == 200 && matches!(v.at, Route::KeyAdd(_) | Route::KeyRotate(..));
                respond_page(
                    req,
                    status,
                    shell_as(&v, given.as_deref(), &who_header, logo, title, content),
                    &v.look,
                    logo,
                    reveal,
                )
            }
        }
        return;
    }

    // ----- GET: the rendering half -----------------------------------------

    // An explicit `?lang=` or `?theme=` is a choice: remember it, then send the browser to
    // the same page without that parameter, so a bookmark or a reload does not carry it
    // around forever. The rest of the query survives, which is what keeps an access-check
    // verdict on screen. The two checks are independent and each returns on its own redirect,
    // which is what makes the Settings form's single submit work while setting both: the first pass
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
    // The audit's clock, remembered the same way. It arrives as two fields rather than one,
    // because `custom` is a choice in a list box and the zone it means is typed in the box
    // beside it: the text box is read only when the list box says so. A zone nothing can read
    // sets nothing, and the browser comes back to the page in whatever clock it was already
    // in, with both parameters gone so no link on it carries them any further.
    if let Some(choice) = query_param(&query, TZ_COOKIE) {
        let chosen = match choice.trim() {
            "custom" => query_param(&query, TZ_CUSTOM_PARAM).and_then(|z| parse_tz_pref(&z)),
            other => parse_tz_pref(other),
        };
        let location = preference_href_without(cfg, &at, &query, &[TZ_COOKIE, TZ_CUSTOM_PARAM]);
        match chosen {
            Some(pref) => respond_preference_redirect(req, &location, TZ_COOKIE, pref.code()),
            // A `303`, the redirect this binary answers a form with: there is nothing to
            // remember, and a `GET` is exactly what the browser should follow it with.
            None => respond_redirect(req, &location),
        }
        return;
    }
    // How the Settings page opens, remembered the same way again: the two commands at its top
    // are links carrying this one parameter.
    if let Some(pref) = query_param(&query, GROUPS_COOKIE).and_then(|g| GroupsPref::parse(&g)) {
        respond_preference_redirect(
            req,
            &preference_href(cfg, &at, &query, GROUPS_COOKIE),
            GROUPS_COOKIE,
            pref.code(),
        );
        return;
    }

    // Fresh off disk, every request, and hashed: `rev` is what every form on this page will
    // carry, and what the `POST` that comes back has to still match. Which file it fingerprints
    // is the file this page *edits*, so the settings page guards the settings file and every
    // other page guards the access file, through one field and one check.
    let raw = std::fs::read_to_string(edited_file(cfg, &at)).unwrap_or_default();
    let rev = sha256_hex(&raw);
    let v = View {
        cfg,
        lang,
        lang_pref,
        theme,
        tz,
        groups,
        audit: settings.audit_policy,
        look,
        admin: Some(&email),
        at: at.clone(),
        query: &query,
        rev: &rev,
        msg: query_param(&query, "msg").as_deref().and_then(Msg::parse),
        identity,
    };

    // Answered before the access file is even opened, and deliberately: this page does not
    // read it, and a broken access file must not take away the one page where the
    // administrator list is fixed.
    if at == Route::Config {
        let content = match open_settings_file(&cfg.settings_path) {
            Ok((doc, _)) => page_config(&v, &ConfigForm::of(&doc), None, None),
            Err(e) => page_file_error(&v, &e),
        };
        respond_page(
            req,
            200,
            shell_as(
                &v,
                given.as_deref(),
                &who_header,
                logo,
                v.t(K::Config),
                content,
            ),
            &v.look,
            logo,
            false,
        );
        return;
    }

    let (doc, access) = match open_access_file(&cfg.access_path) {
        Ok(pair) => pair,
        Err(e) => {
            respond_page(
                req,
                500,
                shell_as(
                    &v,
                    given.as_deref(),
                    &who_header,
                    logo,
                    v.t(K::FileErrorTitle),
                    page_file_error(&v, &e),
                ),
                &v.look,
                logo,
                false,
            );
            return;
        }
    };

    let title = at.title();
    let (status, content, title) = match &at {
        Route::Dashboard => (200, page_dashboard(&v, &doc, &access), v.t(K::Dashboard)),
        Route::Apps => (200, page_apps(&v, &doc), title),
        Route::App(n) => {
            let (status, content) = page_app(&v, &doc, &access, n);
            (status, content, title)
        }
        Route::Denied => (200, page_denied(&v, &doc), title),
        Route::Users => (200, page_users(&v, &doc, &access), title),
        Route::Groups => (200, page_groups(&v, &doc), title),
        Route::Group(n) => {
            let (status, content) = page_group(&v, &doc, n);
            (status, content, title)
        }
        // It reads the access file for one thing only: what the roster calls a uuid an event
        // recorded. Every other page here is *about* that file; this one borrows a name from
        // it.
        Route::Audit => (200, page_audit(&v, &doc), title),
        // Nothing left on a `UserSpec` for a standalone edit to change, so `UserEdit`
        // simply shows the same page `User` does: the uuid is fixed, and emails and keys
        // manage themselves on their own routes.
        Route::User(e) | Route::UserEdit(e) => {
            let (status, content) = page_user(&v, &doc, &access, e);
            (status, content, title)
        }
        // Answered above, before the access file was opened: it is the one page that does
        // not read it.
        Route::Config => unreachable!("the settings page returns before this match"),

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
                page_missing(&v, v.t(K::NoSuchGroup), n, &Route::Users),
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
                page_missing(&v, v.t(K::NoSuchGroup), n, &Route::Users),
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
    respond_page(
        req,
        status,
        shell_as(&v, given.as_deref(), &who_header, logo, title, content),
        &v.look,
        logo,
        false,
    );
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
    // The same one-line answer the other two programs give, for the same reason: `dpkg-query`
    // reports 1.99.1-1 for a release and for a hand-built tree alike.
    if std::env::args().any(|a| a == "--version") {
        println!("{}", version_line("bb-auth-web"));
        return;
    }
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

    // A bind that is not loopback, refused before the socket exists.
    //
    // This service's ONLY credential is a request header nginx injects. Reachable directly,
    // it is an unauthenticated remote writer of the estate's access list: one header, and the
    // caller is whoever they say they are. `BB_AUTH_WEB_LISTEN=0.0.0.0:8091` is one edit away
    // from that, and nothing said so.
    //
    // Fatal here, where the gate only warns, and the asymmetry is deliberate: the gate
    // refusing to start is an outage for everyone, while this refusing to start costs an
    // administrator a GUI and leaves `bb-auth-adm` over SSH doing the same job. A deployment
    // that genuinely proxies from another host can say so, once, in the env file.
    if !listen_is_loopback(&cfg.listen) && !env_flag("BB_AUTH_WEB_ALLOW_NONLOOPBACK") {
        eprintln!(
            "[bb-auth-web] FATAL: BB_AUTH_WEB_LISTEN is {}, which is not loopback. This service \
             takes its identity from the {IDENTITY_HEADER} header nginx sets, so anything that \
             can reach the port can edit the access file. Put nginx in front of it, or set \
             BB_AUTH_WEB_ALLOW_NONLOOPBACK=1 to say you meant it.",
            cfg.listen
        );
        std::process::exit(1);
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
    // The administrator list is read per request, not here, so what the banner can honestly
    // report is where it will be read from. A file that is missing or does not compile is
    // said so now rather than discovered by the first visitor.
    let admins = match open_settings_file(&cfg.settings_path) {
        Ok((_, s)) => format!("{}", s.admins.len()),
        Err(e) => {
            eprintln!("[bb-auth-web] WARNING: {e}");
            "unreadable".to_string()
        }
    };
    eprintln!(
        "[bb-auth-web] {} listening on {} | file={} | settings={} | admins={admins} | base={base}          | lang={} | workers={}",
        version_line("bb-auth-web"),
        cfg.listen,
        cfg.access_path,
        cfg.settings_path,
        cfg.default_lang.code(),
        cfg.workers
    );
    eprintln!(
        "[bb-auth-web] identity comes from the {IDENTITY_HEADER} header — this port must be \
         reachable ONLY through nginx, behind bb-auth's own auth_request"
    );
    // Names the header and the file it comes from, never the value: a startup message goes to
    // the journal, and a secret that lands there once is a secret in the journal for as long as
    // the journal is kept.
    eprintln!(
        "[bb-auth-web] proxy secret: set. A request whose {PROXY_SECRET_HEADER} does not match \
         is a 403, so nginx must include /opt/bb-auth/etc/bb-auth-web.nginx in the GUI's location."
    );
    // The deletion intake, wired (§13.29 W2). The journal is where an operator checks what this
    // surface is joined to, so the origin and the bound on one call are both worth naming: the
    // bound is what stops a hung intake from holding a handler thread forever (§13.13), and
    // naming it here is what makes it a fact of this deployment rather than a constant nobody
    // can see. The secret is never named, for the proxy secret's reason.
    if let Some(origin) = cfg.delete_intake.as_deref() {
        eprintln!(
            "[bb-auth-web] deletion intake: {origin}, one call given {}s before this gives up.",
            cfg.intake_timeout.as_secs()
        );
        // The half-wired state, said once. The intake checks no secret today, so an operator who
        // wired the worker and not the secret has a menu row reaching a service that trusts any
        // local caller, and the journal is the only place that can say so.
        if cfg.delete_secret.is_none() {
            eprintln!(
                "[bb-auth-web] deletion intake: no BB_AUTH_WEB_DELETE_SECRET set: the intake \
                 trusts any caller that reaches it, until the same secret is written here and \
                 where the intake's unit reads it."
            );
        }
    }
    eprintln!(
        "[bb-auth-web] this instance WRITES {} — every edit is validated with the gate's own \
         parser first, and goes live on: systemctl reload bb-auth",
        cfg.access_path
    );

    let server = std::sync::Arc::new(server);
    let cfg = std::sync::Arc::new(cfg);
    let mut handles = Vec::new();
    for _ in 0..cfg.workers {
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

mod account;
mod account_delete;
mod account_keys;
mod account_profile;
mod apps;
mod audit_page;
mod check;
mod config;
mod dashboard;
mod edit;
mod forms;
mod i18n;
mod k_text;
mod layout;
mod routing;
mod settings_page;
mod users;
mod writes;

use account::*;
use account_delete::*;
use account_keys::*;
use account_profile::*;
use apps::*;
use audit_page::*;
use check::*;
use config::*;
use dashboard::*;
use edit::*;
use forms::*;
use i18n::*;
use k_text::*;
use layout::*;
use routing::*;
use settings_page::*;
use users::*;
use writes::*;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
