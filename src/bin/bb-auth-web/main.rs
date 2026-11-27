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
// Editing pages
// ---------------------------------------------------------------------------
//
// One struct and one page function per form. The struct is what the fields hold, and it is
// filled from two places — the access file, when the form is first rendered, and the
// submitted body, when a refusal sends the same form back. That is what "the submitted
// values are preserved" is: the same page function, one error string later.

/// The `users` form: one email. Used both for `users · add` (the row's first identifier)
/// and for `/users/{uuid}/emails/+add`: the two places an email is ever typed in, since an
/// identity carries no URL and its uuid never changes. `UserForm` gains nothing beyond
/// this: there is nothing else on a [`UserSpec`] a form could usefully edit.
#[derive(Default)]
struct UserForm {
    email: String,
}

impl UserForm {
    pub(crate) fn read(f: &Form) -> UserForm {
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
    days: String,
    scopes: String,
}

impl KeyForm {
    fn of(k: &ApiKeySpec) -> KeyForm {
        let (duration, days) = duration_of_stored(&k.duration);
        KeyForm {
            id: k.id.trim().to_string(),
            duration,
            days,
            scopes: urls_text(k.scopes.as_ref()),
        }
    }
    pub(crate) fn read(f: &Form) -> KeyForm {
        let (duration, days) = duration_of_posted(f.get("duration"), f.get("days"));
        KeyForm {
            id: f.get("id").to_string(),
            duration,
            days,
            scopes: f.get("scopes").to_string(),
        }
    }
}

/// The stored `duration`, read back into the control that spells it: a preset for a preset,
/// no expiry for **every** spelling of it (`never`, `0`, `-`, and the empty field
/// `parse_duration` reads as never), and the custom box filled with the file's own bytes for
/// anything the five cannot name. That last case is the one a form rewrite loses: `8760h` is
/// a real value in a real file, and a form that showed nothing picked for it would save
/// `365d` over it the moment the person pressed the button.
fn duration_of_stored(stored: &str) -> (String, String) {
    let stored = stored.trim();
    match stored {
        "365d" | "182d" | "91d" => (stored.to_string(), String::new()),
        _ => match parse_duration(stored) {
            Some(Dur::Never) => ("never".to_string(), String::new()),
            _ => ("custom".to_string(), stored.to_string()),
        },
    }
}

/// What a submission names, in the same shape, so the re-render after a refusal shows the
/// person what they posted. A hand-written client that posts `duration=30d` gets the custom
/// box filled with it, and a form that arrived with no `duration` at all opens on the add
/// form's default, which is what keeps the control carrying exactly one `selected`.
fn duration_of_posted(choice: &str, days: &str) -> (String, String) {
    let choice = choice.trim();
    match choice {
        "365d" | "182d" | "91d" | "custom" | "never" => {
            (choice.to_string(), days.trim().to_string())
        }
        "" => ("365d".to_string(), days.trim().to_string()),
        other => ("custom".to_string(), other.to_string()),
    }
}

/// The five choices, mapped onto the file's duration grammar, in **one** function for both
/// surfaces (§13.15): the console's mint, the console's edit and the self-service page mint
/// the same field, and a mapping written twice is two mappings.
///
/// The presets come back **verbatim** (`365d`, `182d`, `91d`, `never`), because they are not
/// codes to translate: they are the exact strings the file stores, so `bb-auth-adm show`, the
/// gate and every existing file see nothing new. A custom all-digit value gets the `d` the
/// grammar needs, so the file reads unambiguously; a custom value with a unit (`12h`) passes
/// through as typed, because the console's box has always taken the whole grammar and twelve
/// hours is a window a deployment genuinely wants. Anything else is passed through as typed,
/// so a hand-written `duration=30d` keeps working.
///
/// The refusals are the half worth reading. An empty or absent `duration` is refused and not
/// read as "no expiry": `parse_duration("")` is `Dur::Never`, so a form that lost its control
/// would mint a key that never dies, which is the one outcome the person did not ask for and
/// cannot undo from the page. A number typed while a preset is picked is a form that
/// contradicts itself, and guessing which half was meant is how a key outlives its reason.
pub(crate) fn duration_from_form(form: &Form) -> Result<String, K> {
    let choice = form.get("duration").trim();
    if choice.is_empty() {
        return Err(K::KeyDurationRequired);
    }
    let days = form.get("days").trim();
    if choice == "custom" {
        let stored = if days.is_empty() {
            String::new()
        } else if days.bytes().all(|b| b.is_ascii_digit()) {
            format!("{days}d")
        } else {
            days.to_string()
        };
        // A spelling of never has its own choice, and `parse_duration` reads `0`, `-` and
        // `never` as `Dur::Never`: taking one here would be a second way to spell one thing.
        if !matches!(parse_duration(&stored), Some(Dur::Secs(secs)) if secs > 0) {
            return Err(K::KeyDaysInvalid);
        }
        return Ok(stored);
    }
    if !days.is_empty() {
        return Err(K::KeyDaysWithoutCustom);
    }
    Ok(choice.to_string())
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
                (duration_choice(
                    v.lang,
                    "duration",
                    &f.duration,
                    &f.days,
                    // No placeholder: this box takes the whole grammar, and the hint says so.
                    None,
                    Some("<n>d · <n>h"),
                    about("duration"),
                ))
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

/// The `applications` form: `name`, `base`, `login_url`, `denied_url`, `notes`. There is no field here
/// that names a user, and there never may be one: an application describes a **place**, and
/// grants to named users live in a scope's `users`/`groups` alone.
#[derive(Default)]
struct AppForm {
    name: String,
    base: String,
    login_url: String,
    /// Where a refusal inside this area lands. Beside `login_url` because the pair is the
    /// same question twice: which page this area sends somebody to when they cannot pass.
    denied_url: String,
    notes: String,
}

impl AppForm {
    fn of(a: &AppSpec) -> AppForm {
        AppForm {
            name: a.name.trim().to_string(),
            base: a.base.join("\n"),
            login_url: a.login_url.clone().unwrap_or_default(),
            denied_url: a.denied_url.clone().unwrap_or_default(),
            notes: a.notes.clone().unwrap_or_default(),
        }
    }
    pub(crate) fn read(f: &Form) -> AppForm {
        AppForm {
            name: f.get("name").to_string(),
            base: f.get("base").to_string(),
            login_url: f.get("login_url").to_string(),
            denied_url: f.get("denied_url").to_string(),
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
                (text_field(v.t(K::DeniedUrl), "denied_url", &f.denied_url, "https://x.com/denied",
                            Some(v.t(K::DeniedUrlHelp)), about("denied_url")))
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
    /// The scope's own `excluded`, one per line: a person, a `@group`, or a stranger's
    /// email. Its own box and not a `-` prefix inside `members`, because the two lists say
    /// opposite things and a typo that turned one into the other would fail *open*.
    excluded: String,
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
            excluded: scope_excluded_display(doc, s).join("\n"),
            notes: s.notes.clone().unwrap_or_default(),
        }
    }
    pub(crate) fn read(f: &Form) -> ScopeForm {
        ScopeForm {
            name: f.get("name").to_string(),
            urls: f.get("urls").to_string(),
            access: f.get("access").to_string(),
            members: f.get("members").to_string(),
            cred_login: f.checked("cred_login"),
            cred_api_key: f.checked("cred_api_key"),
            excluded: f.get("excluded").to_string(),
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
                (urls_field(v.t(K::Excluded), "excluded", &f.excluded,
                            html! { (v.t(K::ExcludedHelp)) }, about("excluded")))
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

/// The `user_groups` form: a name and its members, who are people rather than URL patterns.
#[derive(Default)]
struct GroupForm {
    name: String,
    members: String,
}

impl GroupForm {
    pub(crate) fn read(f: &Form) -> GroupForm {
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

/// Which file a route edits, and therefore which one its `rev` fingerprints.
///
/// Two files, one optimistic-concurrency check. A settings form carrying the access file's
/// fingerprint would `409` on every unrelated roster edit, and, far worse, one carrying a
/// fingerprint of the wrong file would not notice a concurrent `bb-auth-adm settings set` at
/// all, which is the whole thing the check exists for.
fn edited_file<'a>(cfg: &'a Config, at: &Route) -> &'a str {
    match at.tab() {
        Route::Config => &cfg.settings_path,
        _ => &cfg.access_path,
    }
}

/// The settings form: the five the gate answers with, and the list of people this GUI opens
/// for.
///
/// One form, not five, and one `Save`: these are read together on every request and written
/// together in one file, so splitting them into a form each would only invent five chances to
/// hit a stale `rev`.
///
/// Nothing here is a secret and nothing here can lock anybody out, which is exactly the rule
/// that decided what the file holds; see `bb_auth_core::Settings`. What is *not* on this page
/// is the rest of the configuration: the listener, the HMAC key, the Cognito trust roots, the
/// login page and the authorized hosts stay in the env file on the host, where changing one
/// costs a restart and getting one wrong costs the service.
struct ConfigForm {
    claims: String,
    identity: String,
    ttl: String,
    social: bool,
    providers: String,
    /// The app client the email flow uses, `gate.client_id`. Empty is a deployment that
    /// cannot complete a login, which this form refuses to write.
    client_id: String,
    /// `gate.login_url`. Empty = the gate's own `/auth/login`.
    login_url: String,
    /// `gate.denied_url`. Empty = the gate's own `/auth/denied`. The one URL on this page
    /// that can close nothing: it is only what somebody already refused is shown.
    denied_url: String,
    /// `gate.landing_url`. Empty = the caller's root. It is refused off `gate.authorized_hosts`
    /// for the reason the help line gives: `safe_rd` refuses a landing page outside them at
    /// every login, so the setting would silently do nothing.
    landing_url: String,
    /// `gate.issuer`, the Cognito user pool. This form refuses to write an empty one, for the
    /// reason it refuses an empty `client_id`: both mean no login can complete.
    issuer: String,
    /// `gate.cookie_domain`. Empty = a host-only cookie.
    cookie_domain: String,
    /// `gate.authorized_hosts`, one per line.
    hosts: String,
    /// `gate.oauth_domain`, the hosted UI's bare host. Empty = no social sign-in.
    domain: String,
    /// `gate.social_callback_url`. Empty = no social sign-in.
    callback: String,
    /// The enabled social providers as `(identity_provider, app client)`. Pairs rather than
    /// names because Cognito federates per app client: see [`social_choices`].
    buttons: Vec<(String, String)>,
    /// `audit.client_ip_header`. Empty = the audit records no address.
    ip_header: String,
    /// `audit.request_id_header`. Empty = the audit records no request id.
    rid_header: String,
    /// `audit.rotation`, as the two controls it is edited in: an amount, and a unit's code.
    rotation_n: String,
    rotation_unit: String,
    /// `audit.retention` likewise. An empty unit is no retention, whatever the amount says.
    retention_n: String,
    retention_unit: String,
    admins: String,
    stylesheet: String,
    logo: String,
    brand: String,
    theme: String,
}

impl ConfigForm {
    /// The form as the file says it, which is what a `GET` renders.
    fn of(doc: &SettingsFile) -> ConfigForm {
        // Both parse, because a file that did not would not have been opened for editing: a
        // file the gate refuses is an error page, not this form.
        let rotation =
            AuditLimit::parse(&doc.audit.rotation).unwrap_or(AuditPolicy::default().rotation);
        let retention = AuditLimit::parse(&doc.audit.retention).ok();
        ConfigForm {
            claims: doc.gate.profile_claims.join("\n"),
            identity: doc.gate.identity_attrs.join("\n"),
            ttl: doc.gate.session_ttl_secs.to_string(),
            social: doc.gate.allow_unverified_social,
            providers: doc.gate.social_providers.join("\n"),
            client_id: doc.gate.client_id.clone(),
            login_url: doc.gate.login_url.clone(),
            denied_url: doc.gate.denied_url.clone(),
            landing_url: doc.gate.landing_url.clone(),
            issuer: doc.gate.issuer.clone(),
            cookie_domain: doc.gate.cookie_domain.clone(),
            hosts: doc.gate.authorized_hosts.join("\n"),
            domain: doc.gate.oauth_domain.clone(),
            callback: doc.gate.social_callback_url.clone(),
            // A bare-name entry is the pre-2 shape, which `compile_settings` refuses; it is
            // rendered as a row with no app client so the page can show what the file says
            // and the operator can fix it here rather than over SSH.
            buttons: doc
                .gate
                .social_buttons
                .iter()
                .map(|b| match b {
                    SocialButtonSpec::Wired(w) => (w.idp.clone(), w.audience.clone()),
                    SocialButtonSpec::Name(n) => (n.clone(), String::new()),
                })
                .collect(),
            ip_header: doc.audit.client_ip_header.clone(),
            rid_header: doc.audit.request_id_header.clone(),
            // The file's spelling split into the two controls. A rotation nobody wrote is the
            // default one, shown as what it is rather than as an empty box that means it.
            rotation_n: rotation.amount.to_string(),
            rotation_unit: rotation.unit.code().to_string(),
            retention_n: retention.map(|r| r.amount.to_string()).unwrap_or_default(),
            retention_unit: retention
                .map(|r| r.unit.code().to_string())
                .unwrap_or_default(),
            admins: doc.web.admins.join("\n"),
            stylesheet: doc.ui.stylesheet_url.clone(),
            logo: doc.ui.logo_url.clone(),
            brand: doc.ui.brand_name.clone(),
            // A file that says nothing renders the list box on `system`, which is what saying
            // nothing means. Writing it back as the word costs nothing and makes the file read
            // the way the page does.
            theme: UiTheme::parse(&doc.ui.theme)
                .unwrap_or_default()
                .code()
                .to_string(),
        }
    }

    pub(crate) fn read(f: &Form) -> ConfigForm {
        ConfigForm {
            claims: f.get("claims").to_string(),
            identity: f.get("identity").to_string(),
            ttl: f.get("ttl").to_string(),
            // An unchecked checkbox sends nothing at all, which is what makes its absence the
            // `false` rather than a value to parse.
            social: !f.get("social").is_empty(),
            providers: f.get("providers").to_string(),
            client_id: f.get("client_id").to_string(),
            login_url: f.get("login_url").to_string(),
            denied_url: f.get("denied_url").to_string(),
            landing_url: f.get("landing_url").to_string(),
            issuer: f.get("issuer").to_string(),
            cookie_domain: f.get("cookie_domain").to_string(),
            hosts: f.get("hosts").to_string(),
            domain: f.get("domain").to_string(),
            callback: f.get("callback").to_string(),
            // The page says which providers it drew a row for, and this keeps the ones whose
            // box came back ticked, with the app client typed beside it. Reading the offered
            // set off the form rather than re-deriving it here is what makes a provider this
            // build has never heard of survive a save: it was rendered, so it is named, so it
            // can be kept.
            buttons: f
                .get("idps")
                .split_whitespace()
                .filter(|idp| f.checked(&idp_field(idp)))
                .map(|idp| (idp.to_string(), f.get(&aud_field(idp)).trim().to_string()))
                .collect(),
            ip_header: f.get("client_ip_header").to_string(),
            rid_header: f.get("request_id_header").to_string(),
            rotation_n: f.get("audit_rotation").to_string(),
            rotation_unit: f.get("audit_rotation_unit").to_string(),
            retention_n: f.get("audit_retention").to_string(),
            retention_unit: f.get("audit_retention_unit").to_string(),
            admins: f.get("admins").to_string(),
            stylesheet: f.get("stylesheet").to_string(),
            logo: f.get("logo").to_string(),
            brand: f.get("brand").to_string(),
            theme: f.get("ui_theme").to_string(),
        }
    }

    /// One textarea's lines, trimmed, blanks dropped: the grammar every list field in this
    /// GUI already uses.
    fn lines(s: &str) -> Vec<String> {
        s.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Apply the form to the document. The refusals here are the ones the library cannot make
    /// on its own: it does not know who is signed in, and it does not parse a form. Every other
    /// check is `compile_settings`'s, made once on the way to disk, where its refusal is said in
    /// the reader's language on the field that can fix it (docs/ARCHITECTURE.md §13.31 §5).
    fn apply(&self, doc: &mut SettingsFile, admin: &str, lang: Lang) -> Result<(), Refusal> {
        // Every refusal here is said in the page's own register: the visible label of the
        // field, then what is allowed, through `fill` like the library's (§13.31 §10).
        let ttl: u64 = self.ttl.trim().parse().map_err(|_| {
            Refusal::on(
                "ttl",
                fill(t(lang, K::SessionTtlBad), &[t(lang, K::SessionTtl)]),
            )
        })?;
        let admins = Self::lines(&self.admins);
        if admins.is_empty() {
            return Err(Refusal::on(
                "admins",
                fill(t(lang, K::SetRefAdminsNone), &[t(lang, K::Admins)]),
            ));
        }
        // The guard that makes this page safe to hand an administrator: you may add anyone
        // and remove anyone but yourself. Removing the last administrator is refused above;
        // removing *this* one would leave a GUI nobody can open, and the way back is the SSH
        // this page exists to save people from. `bb-auth-adm` will still do it.
        if !admins.iter().any(|a| norm_email(a) == admin) {
            return Err(Refusal::on(
                "admins",
                fill(t(lang, K::SetRefAdminsSelf), &[t(lang, K::Admins)]),
            ));
        }
        // The four the GUI is stricter than the gate about on purpose: a deployment with an
        // empty one of these is one where no login can complete, and a form should not be able
        // to write that. A fresh install has none of them and no way to reach this page either,
        // so the first one is set with `bb-auth-adm` over SSH.
        let client_id = compile_app_client_id("client_id", &self.client_id)
            .unwrap_or(self.client_id.trim().to_string());
        if client_id.is_empty() {
            return Err(Refusal::on(
                "client_id",
                fill(t(lang, K::ClientIdNeeded), &[t(lang, K::SignInEmail)]),
            ));
        }
        let issuer = compile_issuer(&self.issuer).unwrap_or(self.issuer.trim().to_string());
        if issuer.is_empty() {
            return Err(Refusal::on(
                "issuer",
                fill(t(lang, K::IssuerNeeded), &[t(lang, K::Issuer)]),
            ));
        }
        let hosts = Self::lines(&self.hosts);
        if hosts.is_empty() {
            return Err(Refusal::on(
                "hosts",
                fill(
                    t(lang, K::AuthorizedHostsNeeded),
                    &[t(lang, K::AuthorizedHosts)],
                ),
            ));
        }
        for (idp, aud) in &self.buttons {
            if aud.trim().is_empty() {
                return Err(Refusal::on(
                    aud_field(idp),
                    fill(t(lang, K::AudienceNeeded), &[social_idp_label(idp)]),
                ));
            }
        }
        // A value this list box cannot produce, so a refusal here means the request was not
        // this form. It is still a refusal and not a silent `system`: see `UiTheme::parse`.
        // The field is `ui_theme`, the page's name for the box, as `settings_refusal` says:
        // `theme` is the file's key, and marks nothing on this page (§13.31 §10).
        let theme = UiTheme::parse(&self.theme).ok_or_else(|| {
            Refusal::on(
                "ui_theme",
                fill(t(lang, K::DefaultThemeBad), &[t(lang, K::DefaultTheme)]),
            )
        })?;
        // The validators stay where their `Ok` value is what the file stores: the issuer with
        // its trailing slash gone, the cookie domain lowercased, an app client and a header
        // trimmed, the two audit limits in the file's own spelling. The refusal does not stay:
        // `.unwrap_or` takes the trimmed input, so a value the library accepts is written byte
        // for byte as before and one it refuses reaches `prepare` and is answered there.
        let cookie_domain = compile_cookie_domain(&self.cookie_domain)
            .unwrap_or(self.cookie_domain.trim().to_string());
        let ip_header = compile_audit_header("client_ip_header", &self.ip_header)
            .unwrap_or(self.ip_header.trim().to_string());
        let rid_header = compile_audit_header("request_id_header", &self.rid_header)
            .unwrap_or(self.rid_header.trim().to_string());
        let rotation_raw = format!("{} {}", self.rotation_n.trim(), self.rotation_unit.trim());
        let rotation = AuditLimit::parse(&rotation_raw)
            .map(|r| r.spelled())
            .unwrap_or(rotation_raw);
        let retention = match self.retention_unit.trim() {
            "" => String::new(),
            unit => {
                let raw = format!("{} {unit}", self.retention_n.trim());
                AuditLimit::parse(&raw).map(|r| r.spelled()).unwrap_or(raw)
            }
        };

        doc.gate.profile_claims = Self::lines(&self.claims);
        doc.gate.identity_attrs = Self::lines(&self.identity);
        doc.gate.session_ttl_secs = ttl;
        doc.gate.allow_unverified_social = self.social;
        doc.gate.social_providers = Self::lines(&self.providers);
        doc.gate.client_id = client_id;
        doc.gate.login_url = self.login_url.trim().to_string();
        doc.gate.denied_url = self.denied_url.trim().to_string();
        doc.gate.landing_url = self.landing_url.trim().to_string();
        doc.gate.issuer = issuer;
        doc.gate.cookie_domain = cookie_domain;
        doc.gate.authorized_hosts = hosts;
        doc.gate.oauth_domain = self.domain.trim().to_string();
        doc.gate.social_callback_url = self.callback.trim().to_string();
        doc.gate.social_buttons = self
            .buttons
            .iter()
            .map(|(idp, aud)| {
                SocialButtonSpec::Wired(WiredButton {
                    idp: idp.clone(),
                    audience: aud.clone(),
                })
            })
            .collect();
        doc.audit.client_ip_header = ip_header;
        doc.audit.request_id_header = rid_header;
        doc.audit.rotation = rotation;
        doc.audit.retention = retention;
        doc.web.admins = admins;
        doc.ui.stylesheet_url = self.stylesheet.trim().to_string();
        doc.ui.logo_url = self.logo.trim().to_string();
        doc.ui.brand_name = self.brand.trim().to_string();
        doc.ui.theme = theme.code().to_string();
        Ok(())
    }
}

/// A save held for confirmation: the guarded settings this form would change, each with what
/// it is going from and to.
///
/// It is a type rather than a list of tuples because the page renders it AND the hidden field
/// is built from it, and those two have to be about the same values. A confirmation that
/// showed one thing and authorised another would be a worse guard than none at all.
struct Confirm {
    /// `(which, before, after)`, in [`guarded_changes`]'s order.
    changes: Vec<(GuardedSetting, String, String)>,
    /// What the hidden field carries and what the next `POST` is checked against: the sha256
    /// of the values being confirmed, rather than the values themselves. One field to check
    /// instead of five, and no list has to survive a round trip through an attribute.
    ///
    /// It binds a confirmation to exactly the change it was shown for: edit the field again
    /// on the confirmation page and the token no longer matches, so the page asks again about
    /// the new value instead of writing it on the strength of an answer about the old one.
    token: String,
}

impl Confirm {
    /// What `new` changes about `old` that is worth stopping for, or `None` for a save that
    /// takes nothing away.
    fn of(old: &GateSettings, new: &GateSettings) -> Option<Confirm> {
        let changes: Vec<(GuardedSetting, String, String)> = guarded_changes(old, new)
            .into_iter()
            .map(|c| (c, guarded_value(c, old), guarded_value(c, new)))
            .collect();
        if changes.is_empty() {
            return None;
        }
        let token = sha256_hex(
            &changes
                .iter()
                .map(|(c, _, after)| format!("{}={after}", c.field()))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        Some(Confirm { changes, token })
    }
}

/// One guarded setting's value, spelled the one way the page shows it and the token is built
/// from. Both come through here, so the two cannot disagree.
fn guarded_value(which: GuardedSetting, gate: &GateSettings) -> String {
    match which {
        GuardedSetting::Issuer => gate.issuer.trim().to_string(),
        GuardedSetting::ClientId => gate.client_id.trim().to_string(),
        GuardedSetting::LoginUrl => gate.login_url.trim().to_string(),
        GuardedSetting::CookieDomain => gate.cookie_domain.trim().to_string(),
        GuardedSetting::AuthorizedHosts => gate.authorized_hosts.join(" "),
    }
}

/// What each guarded setting costs when it is wrong, in the reader's language. The library
/// says *which* settings are guarded, because both editors have to agree on that; the
/// sentence is this program's, because it is addressed to whoever is looking at the form.
fn guarded_risk(which: GuardedSetting) -> K {
    match which {
        GuardedSetting::Issuer => K::RiskIssuer,
        GuardedSetting::ClientId => K::RiskClientId,
        GuardedSetting::LoginUrl => K::RiskLoginUrl,
        GuardedSetting::CookieDomain => K::RiskCookieDomain,
        GuardedSetting::AuthorizedHosts => K::RiskAuthorizedHosts,
    }
}

/// One group of the Settings page: a panel that folds to its heading.
///
/// A `details`, because that is how HTML has always opened and closed something with no
/// script behind it, and this GUI may have none. Its inputs are part of the form whether it is
/// open or not, so a folded group is saved exactly as a visible one is.
fn settings_group(id: &str, open: bool, heading: Markup, body: Markup) -> Markup {
    html! {
        details class="panel group" id=(format!("g-{id}")) open[open] {
            summary { h2 class="tight" { (heading) } }
            (body)
        }
    }
}

/// Which group of the Settings page a refused field is in, by its `name=`: the group that has
/// to be open whatever the reader asked for, since a refusal pointing at a folded field is a
/// refusal nobody can act on.
fn settings_group_of(field: &str) -> &'static str {
    match field {
        "social" | "providers" | "ttl" => "access",
        "identity" | "claims" => "handover",
        "client_ip_header" | "request_id_header" | "audit_rotation" | "audit_retention" => "audit",
        // The list box is `ui_theme`, the page's name for it; `theme` is the file's key, and a
        // refusal spelled that way opened no group at all (§13.31 §10).
        "admins" | "brand" | "stylesheet" | "logo" | "ui_theme" => "look",
        // Everything else on the page is the sign-in box's, including the table of ways in,
        // whose fields are named after the providers in the file (`aud-Google`).
        _ => "signin",
    }
}

fn page_config(
    v: &View,
    f: &ConfigForm,
    err: Option<&Refusal>,
    confirm: Option<&Confirm>,
) -> Markup {
    let about = |name| err.is_some_and(|e| e.is(name));
    let days = f.ttl.trim().parse::<u64>().unwrap_or(0) / 86_400;
    // Which groups are open: the reader's preference, then whatever the page has to show them.
    // A refusal opens its field's group, and one that names no field opens them all, since
    // the page cannot say where the problem is; a held save opens the sign-in group, which is
    // where every guarded setting lives.
    let refused = err.map(|e| e.field.as_deref().map(settings_group_of));
    let open = |id: &str| {
        v.groups == GroupsPref::Open
            || matches!(refused, Some(None))
            || refused.flatten() == Some(id)
            || (confirm.is_some() && id == "signin")
    };
    let groups_href =
        |pref: GroupsPref| format!("{}?{GROUPS_COOKIE}={}", v.href(&Route::Config), pref.code());
    html! {
        h1 { (v.t(K::Config)) }
        p class="lede" { (v.t(K::ConfigIntro)) }
        // The two commands. Links and not buttons, because they change nothing but how this
        // page opens: each is a `GET` the handler turns into a cookie and redirects back from,
        // exactly as a language or a theme is chosen.
        p class="primary" {
            a class="pill" href=(groups_href(GroupsPref::Open)) { "⊞ " (v.t(K::GroupsExpand)) }
            " "
            a class="pill" href=(groups_href(GroupsPref::Closed)) { "⊟ " (v.t(K::GroupsCollapse)) }
        }
        // A save that takes one of the five guarded settings away is SHOWN before it is
        // written, and the form below is re-rendered with the values that are waiting, so
        // the answer to "no, not that" is to edit the field rather than to start again.
        @if let Some(c) = confirm {
            div class="panel warn" {
                h2 class="tight" { (v.t(K::ConfirmTitle)) }
                p class="lede" { (v.t(K::ConfirmLede)) }
                table {
                    thead { tr {
                        th { (v.t(K::ColSetting)) }
                        th { (v.t(K::ColNow)) }
                        th { (v.t(K::ColAfter)) }
                    } }
                    tbody {
                        @for (which, before, after) in &c.changes {
                            tr {
                                td data-label=(v.t(K::ColSetting)) {
                                    div class="mono" { (which.field()) }
                                    span class="hint" { (v.t(guarded_risk(*which))) }
                                }
                                td class="mono" data-label=(v.t(K::ColNow)) {
                                    (if before.is_empty() { "\u{2014}" } else { before })
                                }
                                td class="mono" data-label=(v.t(K::ColAfter)) {
                                    (if after.is_empty() { "\u{2014}" } else { after })
                                }
                            }
                        }
                    }
                }
                p class="muted" { (v.t(K::ConfirmSafety)) }
            }
        }
        // FIVE GROUPS, ONE FORM. The grouping is by what a setting decides, not by which
        // section of the file it lands in: an operator asking "who gets in, and for how
        // long" should not have to read past what the application receives to find out, and
        // the two questions are answered by fields that happen to be neighbours in the file.
        // Each group still names the section it writes; where a group spans two, it names both.
        //
        // One form and one save, because the `rev` guard is over the whole file: five forms
        // would be five fingerprints and four chances to lose an edit somebody else made
        // between them. Folding a group does not take it out of the form.
        (form_shell(v, err, html! {
            (settings_group("access", open("access"), section_heading(v.t(K::ConfigAccess), "gate"), html! {
                // The scope form's own furniture, because a checkbox here is the same thing
                // it is there and inventing a second one would show.
                div {
                    label class="radio" {
                        input type="checkbox" name="social" value="on" checked[f.social];
                        span { (v.t(K::UnverifiedSocial)) }
                    }
                    span class="hint" { (v.t(K::UnverifiedSocialHelp)) }
                }
                (urls_field(v.t(K::SocialProviders), "providers", &f.providers,
                            html! { (v.t(K::SocialProvidersHelp)) }, about("providers")))
                // The hint carries both halves: what this value is in days, which is the
                // only way a number of seconds reads as a lifetime, and what changing it
                // does to sessions that already exist. The second half used to appear only
                // as the refusal on a typo, which is the one moment nobody is reading it.
                (text_field(v.t(K::SessionTtl), "ttl", &f.ttl, "2592000",
                            Some(&format!("{days} {}. {}", v.t(K::Days), v.t(K::SessionTtlHelp))),
                            about("ttl")))
            }))
            (settings_group("handover", open("handover"), section_heading(v.t(K::ConfigHandover), "gate"), html! {
                (urls_field(v.t(K::IdentityAttrs), "identity", &f.identity,
                            html! { (v.t(K::IdentityAttrsHelp)) }, about("identity")))
                (urls_field(v.t(K::ProfileClaims), "claims", &f.claims,
                            html! { (v.t(K::ProfileClaimsHelp)) }, about("claims")))
            }))
            // The headers that come IN, beside the ones that go out above: both are the
            // nginx contract, and an operator wiring one is looking at the other. Named by
            // the file's own keys, since both are typed into an nginx config next. Then how
            // long what they record is kept, which is the other half of the same decision.
            (settings_group("audit", open("audit"), section_heading(v.t(K::ConfigAudit), "audit"), html! {
                (text_field(v.t(K::ClientIpHeader), "client_ip_header", &f.ip_header,
                            "X-Real-IP", Some(v.t(K::ClientIpHeaderHelp)),
                            about("client_ip_header")))
                (text_field(v.t(K::RequestIdHeader), "request_id_header", &f.rid_header,
                            "X-Request-ID", Some(v.t(K::RequestIdHeaderHelp)),
                            about("request_id_header")))
                (limit_field(v, v.t(K::AuditRotation), "audit_rotation", &f.rotation_n,
                             &f.rotation_unit, false, v.t(K::AuditRotationHelp),
                             about("audit_rotation")))
                (limit_field(v, v.t(K::AuditRetention), "audit_retention", &f.retention_n,
                             &f.retention_unit, true, v.t(K::AuditRetentionHelp),
                             about("audit_retention")))
            }))
            (settings_group("signin", open("signin"), section_heading(v.t(K::ConfigSignIn), "gate"), html! {
                // Where people sign in at all, first: it is the page the two below only
                // add a way into.
                // The pool first: everything else in this box is a way into it.
                (text_field(v.t(K::Issuer), "issuer", &f.issuer,
                            "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_xxxxxxxxx",
                            Some(v.t(K::IssuerHelp)), about("issuer")))
                (text_field(v.t(K::GlobalLoginUrl), "login_url", &f.login_url,
                            "https://auth.example.com/auth/login",
                            Some(v.t(K::GlobalLoginUrlHelp)), about("login_url")))
                // The other page a browser is sent to, and the reason it sits beside the
                // sign-in page rather than under the look below: the two are one decision,
                // where this estate answers somebody it will not let through.
                (text_field(v.t(K::GlobalDeniedUrl), "denied_url", &f.denied_url,
                            "https://auth.example.com/auth/denied",
                            Some(v.t(K::GlobalDeniedUrlHelp)), about("denied_url")))
                // The third page of the trio, and the one that is not a refusal: where a
                // sign-in puts a person down when nothing named a place. It is checked against
                // the hosts below, which is why it sits directly above them.
                (text_field(v.t(K::GlobalLandingUrl), "landing_url", &f.landing_url,
                            "https://auth.example.com/account/",
                            Some(v.t(K::GlobalLandingUrlHelp)), about("landing_url")))
                // These two are neighbours because they are checked against each other: a
                // host the cookie cannot reach is refused, and an operator told so has to be
                // able to see both without scrolling.
                (text_field(v.t(K::CookieDomain), "cookie_domain", &f.cookie_domain,
                            ".example.com",
                            Some(v.t(K::CookieDomainHelp)), about("cookie_domain")))
                (urls_field(v.t(K::AuthorizedHosts), "hosts", &f.hosts,
                            html! { (v.t(K::AuthorizedHostsHelp)) }, about("hosts")))
                // Where the browser goes and where it comes back to, above the table of who
                // it goes as: both are one per deployment, and both are Amazon's to agree
                // with, so they read as the frame the rows sit in.
                (text_field(v.t(K::OauthDomain), "domain", &f.domain,
                            "pool.auth.eu-central-1.amazoncognito.com",
                            Some(v.t(K::OauthDomainHelp)), about("domain")))
                (text_field(v.t(K::SocialCallback), "callback", &f.callback,
                            "https://auth.example.com/auth/callback",
                            Some(v.t(K::SocialCallbackHelp)), about("callback")))
                // Every way in, and the app client each runs through. Switches and not a list
                // of names to type, because the answer is a choice among a handful of things
                // this project knows by name, and a free-text field invites a spelling
                // Cognito will not match (`Microsoft` for `MicrosoftPersonal`, say) with
                // nothing to catch it but a button that never appears.
                (social_choices(v, f, err))
            }))
            (settings_group("look", open("look"), section_heading(v.t(K::ConfigAdminLook), "web + ui"), html! {
                (urls_field(v.t(K::Admins), "admins", &f.admins,
                            html! { (v.t(K::AdminsHelp)) " (" (v.t(K::AdminsKeepYourself)) ")" },
                            about("admins")))
                (text_field(v.t(K::BrandName), "brand", &f.brand, "BadBat75",
                            Some(v.t(K::BrandNameHelp)), about("brand")))
                (text_field(v.t(K::StylesheetUrl), "stylesheet", &f.stylesheet,
                            "https://assets.example.com/css/theme.css",
                            Some(v.t(K::StylesheetUrlHelp)), about("stylesheet")))
                (text_field(v.t(K::LogoUrl), "logo", &f.logo,
                            "https://assets.example.com/img/logo.png",
                            Some(v.t(K::LogoUrlHelp)), about("logo")))
                // A list box and not three radios, because it is the same choice the Settings
                // menu in the header offers and it must be the same object: three named
                // values, one line, no invented furniture.
                //
                // `ui_theme` and not `theme`, which is the one field on this page whose wire
                // name is not the file's own. The header's menu is on every page including
                // this one, and its own control is `theme`, the cookie; two controls of that
                // name on one document is a page where "the theme" means two different
                // things depending on which form you are looking at.
                label {
                    span class="lbl" { (v.t(K::DefaultTheme)) }
                    select name="ui_theme" {
                        @for th in [UiTheme::System, UiTheme::Light, UiTheme::Dark] {
                            option value=(th.code()) selected[th.code() == f.theme] {
                                (v.t(theme_label(th)))
                            }
                        }
                    }
                    span class="hint" { (v.t(K::DefaultThemeHelp)) }
                }
            }))
            @if let Some(c) = confirm {
                input type="hidden" name="confirm" value=(c.token);
            }
        }, if confirm.is_some() { v.t(K::ConfirmSave) } else { v.t(K::Save) },
           confirm.is_some()))
        p class="muted" { (v.t(K::ConfigHot)) }
    }
}

/// The `denied` form — one address, and the veto that outranks every grant.
#[derive(Default)]
struct DenyForm {
    email: String,
}

impl DenyForm {
    pub(crate) fn read(f: &Form) -> DenyForm {
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

/// The block that reveals a freshly minted bearer, rendered by **both** surfaces: the console's
/// [`page_minted`] and the self-service page's [`page_account_minted`] (§13.14).
///
/// One function because the two must not drift. The key, the button and the script are the same
/// bytes on the console and on `/account/`; only the words around them are each page's own.
///
/// The `code id="bearer"` carries **the key and nothing else**, with no whitespace around it,
/// because that text is what a click selects (`user-select: all` in `admin.css`) and what the
/// button copies. The button is server-rendered `hidden`: a browser running no code must show no
/// control that does nothing, and [`COPY_SCRIPT`] is the only thing that shows it, so the script
/// goes last, after the three elements it looks up exist, and needs no load event. `type="button"`
/// because this block sits where a form may later be wrapped around it, and a button that submits
/// one is a mutation on a click.
///
/// The button is the estate's shared icon component, `pill ico` (§13.17), so its size, its
/// 24 by 24 target and the way a glyph is painted all live in `base.css` with every other icon
/// control, and this block keeps only the rule that is its own: the glyph swap on `data-state`.
/// Its name is a `span.vh` of translated words inside it, repeated as `title`, and **not** an
/// `aria-label`: one naming mechanism for every icon in the estate, because the header's
/// Preferences trigger is a `summary`, which carries no reliable `aria-label` while text content
/// is read by every reader. The two glyphs are inline geometry, `aria-hidden` and `focusable`
/// false, so the shape is out of the accessibility tree and out of the tab order, and they name
/// no colour, which keeps `THEME_CSS` the only place one is defined. The word a click writes goes
/// to the `role="status"` span beside the icon, empty as served, so the icon stays an icon and
/// the word is announced to a reader.
///
/// The bearer is in **exactly one place** in the response: the text of this `code`. The script is
/// a compile-time constant and reads the key from the DOM at click time, and the button's two
/// data attributes carry only translated text, so the key is in no script, no attribute, no URL
/// and no header. The hint below the panel spells the word `Bearer` in a `code` of its own: that
/// is a word somebody types, not the credential, and it is the reason the hint sits **outside**
/// the panel. Inside `.secret` a `code` is the key's block chip (`admin.css`), so a second one
/// there would render as a second box the size of the secret.
fn bearer_reveal(lang: Lang, bearer: &str) -> Markup {
    let name = t(lang, K::CopyKey);
    html! {
        div class="secret" {
            div { strong { (t(lang, K::BearerHeading)) } }
            p { (t(lang, K::BearerOnce)) }
            code id="bearer" { (bearer) }
            // `hidden="hidden"`: the serialised form of the boolean attribute, which is what
            // `admin.css`'s `.secret button[hidden]` pins shut against an operator stylesheet
            // that gives `button` a `display` of its own.
            button type="button" id="bearer-copy" class="pill ico" hidden="hidden" title=(name)
                data-done=(t(lang, K::CopyDone)) data-failed=(t(lang, K::CopyFailed)) {
                // Two overlapping rounded squares: the sheet in front, and the one behind it.
                svg class="i-copy" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                    rect x="9" y="9" width="12" height="12" rx="2" {}
                    path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" {}
                }
                // The check, shown by the state the click stamps on the button.
                svg class="i-done" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                    path d="M20 6 9 17l-5-5" {}
                }
                span class="vh" { (name) }
            }
            span id="bearer-copy-status" class="copy-status" role="status" {}
            script { (PreEscaped(COPY_SCRIPT)) }
        }
        // The word is an element, so the sentence is two translated halves around it, and the
        // word itself is not translated: it is what the person types.
        p class="hint" {
            (t(lang, K::BearerHintLead)) " " code { "Bearer" } (t(lang, K::BearerHintTail))
        }
    }
}

/// The page a mint answers with — and the one place a `bbk_` bearer is ever rendered.
///
/// Rendered **directly**, not after a redirect: a `303` would put the result behind a fresh
/// `GET` that has no bearer to show, and the bearer exists nowhere else — the file keeps
/// only its sha256. It is not logged and never travels in a URL.
///
/// The key itself, the copy button and the script are [`bearer_reveal`], shared with the
/// self-service page so the two surfaces cannot answer the same moment differently.
fn page_minted(v: &View, owner_uuid: &str, owner_label: &str, id: &str, bearer: &str) -> Markup {
    html! {
        h1 { (owner_label) " · api_keys · " (id) }
        (bearer_reveal(v.lang, bearer))
        p { (back(v, &Route::User(owner_uuid.to_string()))) }
    }
}

/// The `409`: the file moved under the form. Nothing was written, and the way out is a
/// fresh read of what the file says now — with a pointer at the browser's Back button,
/// which (no page here runs a script **on load**: the one script this program emits,
/// [`COPY_SCRIPT`], is the bearer reveal's copy button, wired to a click, so nothing
/// disturbs the bfcache) still holds the form exactly as it was filled in.
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

/// The `409` for the two routes that **reveal a bearer**: the `rev` is stale *and* the key in
/// question exists, which is what a reload of the reveal page looks like from here, the reveal
/// being the direct `POST` response ([`page_minted`]).
///
/// The generic [`page_conflict`] is wrong twice on these paths. The "someone else" who moved
/// the file was this administrator's own submit; and "make the change again" would mint a
/// second key, or, on a rotation, destroy the bearer that was just shown and produce this page
/// again, so each recovery attempt would undo the previous one.
///
/// `rotated` picks which of the two happened, because the difference matters to the person
/// reading it: after a mint the offer of a rotation is the answer to a lost bearer, and after
/// a rotation it is the thing not to do twice. There is deliberately no Back-button hint on
/// either: the typed input is not worth recovering.
fn page_mint_conflict(v: &View, owner: &str, id: &str, rotated: bool) -> Markup {
    let owner = norm_email(owner);
    let (title, body) = if rotated {
        (K::RotateConflictTitle, K::RotateConflictBody)
    } else {
        (K::MintConflictTitle, K::MintConflictBody)
    };
    html! {
        h1 { (v.t(title)) }
        div class="panel warn" {
            p { code { (owner) } " · api_keys · " code { (id) } }
            p { (v.t(body)) }
            p { (v.t(K::MintConflictLost)) }
            p class="pills" {
                @if !rotated {
                    a class="pill"
                      href=(v.href(&Route::KeyRotate(owner.clone(), id.to_string()))) {
                        (v.t(K::MintConflictRotate))
                    }
                }
                (back(v, &Route::User(owner.clone())))
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
/// **verbatim** — it is the same sentence `bb-auth --check-access` and a failed startup
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
/// still not seen. What the `rev` removes is the interesting case, the one measured in
/// minutes: a form loaded, read, thought about, and submitted onto a file that has since
/// moved.
///
/// **Within this process, the whole of it is serialized** by [`WRITE_LOCK`], and that half is
/// not something `rev` can do: two workers submitting at the same moment both read the same
/// bytes, both compute the same fingerprint, and both are entitled to write. There are two
/// workers, an administrator with two tabs is ordinary, and the loser's edit vanishing with a
/// success page is exactly the silent clobber the `rev` exists to prevent. The lock costs
/// nothing: this serves a handful of people and a save is a few milliseconds.
///
/// What it cannot cover is the other process. A concurrent `bb-auth-adm` over SSH is still
/// only guarded by the fingerprint, which is the window it has always had, and the write
/// itself is atomic on both sides.
///
/// A refusal — from a form's own check or from the library — re-renders the very form that
/// caused it, with the submitted values still in the fields and the message verbatim. On
/// every one of those paths nothing has been written: `prepare` fails before `commit`, and
/// `commit` is atomic.
///
/// The status for a refused submission is `400`, and a failed write is reported the same
/// way. From the browser's side the two say the same thing — nothing happened, here is the
/// sentence that says why — and the sentence itself is what distinguishes them.
pub(crate) fn mutate(v: &View, form: &Form) -> Outcome {
    // Held for the whole of the read-check-write, and released when this returns. A poisoned
    // lock is taken anyway: the panic it remembers happened in some other request's mutation,
    // and refusing every edit afterwards would be a worse answer than proceeding, since every
    // write is validated and atomic in its own right.
    let _writing = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Whichever file this route edits: the same `rev` field, checked against the file whose
    // fingerprint the form was given ([`edited_file`]).
    let path = edited_file(v.cfg, &v.at);
    // The settings page is titled with its own name, translated, on every response this route
    // gives: the settings file is a whole file in four sections, so `Route::title`'s
    // untranslated word ("settings") names no section an operator types, and a browser tab
    // that changes wording and language after a save is a page that seems to have moved
    // (§13.31 §10, WCAG 2.2 SC 2.4.2). The access-file pages keep the section word.
    let title = match &v.at {
        Route::Config => v.t(K::Config),
        _ => v.at.title(),
    };

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
        // Both routes that REVEAL a bearer, not just the mint: a rotate answers with a page
        // for the same reason a mint does (a bearer cannot survive a redirect), so reloading
        // it re-submits with a stale rev too. The generic page's advice, "make the change
        // again", is actively destructive there: rotating a second time invalidates the
        // bearer just copied, and lands on the same page offering the same advice.
        let reveal = match &v.at {
            Route::KeyAdd(owner) => Some((owner, false)),
            Route::KeyRotate(owner, id) => Some((owner, !id.is_empty())),
            _ => None,
        };
        if let Some((owner, rotated)) = reveal {
            let id = match &v.at {
                Route::KeyRotate(_, id) => id.clone(),
                _ => form.get("id").trim().to_string(),
            };
            let exists = |d: &AccessFile| {
                user_pos(d, owner)
                    .is_some_and(|i| d.users[i].api_keys.iter().any(|k| k.id.trim() == id))
            };
            if !id.is_empty() && serde_json::from_str::<AccessFile>(&raw).is_ok_and(|d| exists(&d))
            {
                return Outcome::Page(409, title, page_mint_conflict(v, owner, &id, rotated));
            }
        }
        return Outcome::Page(409, title, page_conflict(v));
    }

    // The settings file's own mutation, and the only one that never touches the access file.
    // It sits here, between the concurrency check and the access file's own parse, because it
    // needs the first and has no use for the second.
    if v.at == Route::Config {
        let f = ConfigForm::read(form);
        let r = (|| -> Result<Option<Confirm>, Refusal> {
            let (mut doc, _) = open_settings_file(path)?;
            // What the file says now, kept before the form touches it: the five guarded
            // settings are compared against this and not against whatever the form mentions.
            let before = doc.gate.clone();
            f.apply(&mut doc, v.admin.unwrap_or_default(), v.lang)?;
            // A save that takes one of the five away is shown and held rather than written,
            // until a `POST` comes back carrying the token the shown page named. It is not an
            // error, so it is not a 400: nothing is wrong with the form, it is a step.
            if let Some(c) = Confirm::of(&before, &doc.gate) {
                if form.get("confirm").trim() != c.token {
                    return Ok(Some(c));
                }
            }
            // The library is the only door here too: `prepare` compiles the exact bytes with
            // the parser the gate uses, `commit` writes the bytes it compiled. What it refuses
            // is a code, and this page says it in the reader's language and marks the box the
            // operator has to go back to (§13.31): the library names the setting, only this
            // page knows which field holds it.
            SettingsWrite::prepare(&doc)
                .map_err(|e| match &e {
                    PrepareError::Refused(r) => settings_refusal(v.lang, r),
                    // Not a settings refusal at all: serde on our own structs, never seen, and
                    // nothing on the page to blame.
                    _ => Refusal::from(e.to_string()),
                })?
                .commit(path)?;
            audit(v.admin.unwrap_or("?"), "settings set", path);
            Ok(None)
        })();
        return match r {
            Ok(None) => Outcome::Done(Route::Config, Msg::SettingsSaved),
            Ok(Some(c)) => Outcome::Page(200, title, page_config(v, &f, None, Some(&c))),
            Err(e) => Outcome::Page(400, title, page_config(v, &f, Some(&e), None)),
        };
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
                let duration =
                    duration_from_form(form).map_err(|k| Refusal::on("duration", v.t(k)))?;
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
                let duration =
                    duration_from_form(form).map_err(|e| Refusal::on("duration", v.t(e)))?;
                let k = key_mut(&mut doc, owner, id)?;
                k.duration = duration;
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
                let denied_url = match f.denied_url.trim() {
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
                        denied_url,
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
                a.denied_url = match f.denied_url.trim() {
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
                let spec = scope_spec(v, &doc, &f, form.lines("urls"))?;
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
                let spec = scope_spec(v, &doc, &f, form.lines("urls"))?;
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
            let r = (|| -> Result<String, Refusal> {
                let name = f.name.trim().to_string();
                let members =
                    parse_group_members(&doc, &f.members).map_err(|e| Refusal::on("members", e))?;
                add_user_group(&mut doc, &name, members).map_err(|e| Refusal::on("name", e))?;
                commit(v, &doc, "group add", &format!("@{name}"))?;
                Ok(name)
            })();
            match r {
                // The group's own page (§13.36 §1): the add form names the members, and the
                // page that shows them is where an operator checks what they typed.
                Ok(name) => Outcome::Done(Route::Group(name), Msg::GroupAdded),
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
                Ok(()) => Outcome::Done(Route::Group(target.trim().to_string()), Msg::GroupSaved),
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
fn scope_spec(
    v: &View,
    doc: &AccessFile,
    f: &ScopeForm,
    urls: Vec<String>,
) -> Result<ScopeSpec, Refusal> {
    let access = f.access.trim().to_string();
    let (users, groups, credentials) = if access == "restricted" {
        let (u, g) = parse_members(doc, &f.members).map_err(|e| Refusal::on("members", e))?;
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
    // Exclusions belong to `restricted` *and* to `authenticated` — that kind lists nobody,
    // so an exclusion is the only way to keep one person out of it. `anonymous` refuses
    // them, and refuses them out loud: silently dropping what an operator typed into a box
    // meant to keep somebody out is the worst of the three possible answers.
    let excluded = if access == "anonymous" {
        if !f.excluded.trim().is_empty() {
            return Err(Refusal::on("excluded", v.t(K::ExcludedNotAnon)));
        }
        None
    } else {
        let list = parse_exclusions(doc, &f.excluded).map_err(|e| Refusal::on("excluded", e))?;
        (!list.is_empty()).then_some(list)
    };
    Ok(ScopeSpec {
        name: f.name.trim().to_string(),
        urls,
        access,
        users,
        groups,
        credentials,
        excluded,
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

/// The inverse of [`scope_excluded_display`]: one textarea into a scope's `excluded`, one
/// line at a time through the library's [`parse_exclusion`].
///
/// The rule itself is not here, and that is the fix rather than a detail: this and the CLI's
/// `--exclude` had one implementation each and they had already come apart over what an
/// `@name` line has to satisfy. Unlike [`parse_members`] it accepts an email the roster has
/// never heard of, which is the whole point of the field on an `authenticated` scope.
fn parse_exclusions(doc: &AccessFile, text: &str) -> Result<Vec<String>, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| parse_exclusion(doc, l))
        .collect()
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
// The self-service page
// ---------------------------------------------------------------------------

/// The self-service page's look: the four `ui` values, all four of which it paints.
///
/// [`Look`] is the console's, and carries only what that shell paints out of it: a theme, a
/// stylesheet and the name its bar shows, because its header bar shows no logo. This page shows
/// a logo, and widening `Look` by a field the console paints nothing for is how a struct starts
/// lying about what it means.
///
/// `AccountLook::default()` is "nothing configured", and it is the honest answer on every page
/// rendered **before** the settings file has been read: the `401` happens above that read, and a
/// page that cannot know the operator's stylesheet shows the built-in one rather than guessing.
///
/// `theme` here is the **deployment's** default, kept beside the visitor's own choice rather than
/// folded into it: the two answer different questions and both have to survive to the page, since
/// the selector must show `System` as chosen while the page renders the dark the administrator
/// asked for.
#[derive(Clone, Copy, Default)]
struct AccountLook<'a> {
    /// `ui.theme`: which arm of the palette a page starts in when the visitor has expressed no
    /// preference of their own.
    theme: UiTheme,
    /// `ui.stylesheet_url`: an operator's own stylesheet, loaded after the built-in one.
    stylesheet: Option<&'a str>,
    /// `ui.logo_url`: needed for the policy as much as for the markup, since it is the one image
    /// this page may fetch.
    logo: Option<&'a str>,
    /// `ui.brand_name`: the name the page calls this deployment.
    brand: Option<&'a str>,
}

/// The name a page calls this deployment when `ui.brand_name` is empty: the self-service page's
/// brand slot and the console's bar both fall back to it, so a deployment nobody has branded
/// names itself the same on both. A package creates the settings file with that field empty, so
/// this is what a first install shows.
const DEFAULT_ACCOUNT_BRAND: &str = "bb-auth";

/// What the chrome needs that is not the page: this browser's two preferences, the language they
/// render as, the URL the selector form goes back to, and the two facts the header bar shows
/// beside it (§13.17).
///
/// A struct rather than four more arguments because every page under the prefix is answered
/// through [`respond_account`], and a preference that reached only some of them is a page whose
/// selector shows something other than what that page is rendered in. The bar's two facts are
/// here for the same reason: the identity and the Sign out target exist only once the identity
/// header and the settings have been read, and a bar that showed them on some pages and not
/// others is the drift this struct exists to stop.
struct AccountPrefs<'a> {
    /// The language every string on the page is looked up by.
    lang: Lang,
    /// Which option the selector shows as the chosen language, which is not the same thing as
    /// `lang`: `Auto` renders as one of the two and must still come back as `Auto`.
    lang_pref: LangPref,
    /// Which appearance **this browser** asked for, `System` included. It is not on its own what
    /// the page renders in: [`account_shell`] falls through to [`AccountLook::theme`] after it.
    theme: UiTheme,
    /// The prefix with a trailing slash: the form's `action` and the target of the preference
    /// redirect, both built from [`Config::account_path`].
    page: &'a str,
    /// Who the bar says is signed in, once the identity header has been read: the forwarded
    /// `given_name` and every address, or the addresses alone. `None` on the pages answered
    /// before any identity exists (the `401`), where there is nobody to name.
    who: Option<Who>,
    /// Where Sign out points: [`Config::account_logout_url`], the operator's link with its `rd`
    /// dropped, and no control at all when the operator named no destination. The console's own
    /// pill is the same setting unchanged (§13.17).
    logout: Option<&'a str>,
    /// The delete row's target: `{account}/delete`, and `None` when
    /// [`Config::delete_intake`] is unset (§13.29 W2, §13.30 §1).
    ///
    /// A field and not something the shell derives, because the row exists only where there is a
    /// worker behind the page: a deployment that never wired one must show nobody a door to
    /// nothing, and the page's `{account}/delete` stays the ordinary `404`.
    delete: Option<&'a str>,
    /// Whether **this page** carries its own `p.lede`, and the bar's menu therefore keeps the
    /// identity out.
    ///
    /// The menu's lede is the identity's second home for a page that has no lede of its own: the
    /// bar hides the name on a phone, and the menu opens with the answer. A step page whose lede
    /// is the sentence the person must read first (the code page names the address the code went
    /// to, an outcome page says why nothing was saved) is the case the design counts as *one*
    /// `p.lede` (§13.23 §3, §4): a second one above it in the document would put the identity
    /// ahead of the sentence that explains the page. The bar's own name is untouched.
    page_lede: bool,
}

/// This page's `Content-Security-Policy`.
///
/// The style hash is the **same** value [`admin_csp`] computes, because the `<style>` block is
/// the same bytes: the palette, the components and [`CSS`]. That is why the page's arrangement
/// lives in `src/assets/admin.css` and not beside this code: a second stylesheet is a second
/// hash, and a page whose policy is a list of hashes to keep in step is a page that breaks when
/// one of them is edited.
///
/// `script-src` is the console's, through [`page_script_src`]: the shared Preferences form
/// carries the shell's one handler on **both** surfaces, so picking a theme or a language
/// submits on this page exactly as it does in the console, and the `<noscript>` Apply is the
/// way in for a browser running no code. `reveal` adds the copy script's hash and nothing
/// else (§13.14): the bearer reveal is the one page under this prefix that carries a
/// `<script>`, and a policy that said `'none'` beside a hash would run nothing, so the sources
/// replace each other rather than joining.
///
/// `form-action` is `'self'`: the selector is a `GET` back to this same page, which is the whole
/// interaction.
///
/// `img-src` names the deployment's logo beside the `data:` that was already there, exactly as
/// [`admin_csp_logo`] does for the console: both surfaces show the mark in the bar, so both name
/// its source, and neither names a second one (§13.28 §6).
fn account_csp(look: &AccountLook, reveal: bool) -> String {
    let style = csp_hash(&format!("{THEME_CSS}{BASE_CSS}{CSS}"));
    page_csp(
        &page_script_src(reveal),
        &style,
        "'self'",
        look.stylesheet,
        look.logo,
        &[],
    )
}

/// The chrome every page under the prefix is wrapped in: the palette, the components built out of
/// it, the console's arrangement, then the operator's stylesheet, so an override wins by
/// source order and needs no `!important`.
///
/// The bar is the console's, from [`top_bar`], and the three slots say what the two surfaces are
/// for: the operator's brand where the console names the tool, an empty `nav` where the console's
/// four tabs are (this page is one page, so there is nothing to switch between), and the account
/// end with the identity, the Preferences menu and Sign out. The menu is the console's, worn
/// here exactly as it is worn there: the two list boxes carry the shell's one handler, so a
/// choice applies the moment it is picked, and the Apply sits behind a `noscript` as the way in
/// for a browser running no code (step 13, PLAN.md). The form is a plain `GET` back to the page,
/// so the existing `302` that sets the `theme` and `lang` cookies keeps working.
fn account_shell(prefs: &AccountPrefs, title: &str, content: Markup, look: AccountLook) -> Markup {
    // The two list boxes' options, each in the order they are offered, both leading with the
    // choice that follows something outside this page (the browser, the OS), because that is
    // where every session starts and what the other options are departures from.
    let brand_name = look.brand.unwrap_or(DEFAULT_ACCOUNT_BRAND);
    // The brand slot: the operator's mark and name, worn as the page showed them before the bar
    // existed, and now worn the same way on every surface, the console's bar included
    // (§13.34 §11).
    let brand = brand_block(brand_name, look.logo, "selfserve-brand");
    // The account end: one menu, built by the console's own function, so the two surfaces cannot
    // drift. No places: this page has no tabs to move and offers no console page (§13.28 §2), so
    // the panel is who the caller is, the Preferences box, and Sign out.
    let prefs_box = prefs_form(prefs.lang, prefs.lang_pref, prefs.theme, prefs.page, &[]);
    let acct = html! {
        nav class="acct" {
            (account_menu(
                prefs.lang,
                prefs.who.as_ref(),
                None,
                prefs_box,
                prefs.logout,
                prefs.delete,
                // Grouped: this page's bar has the account menu and no ☰, and the console's bar
                // beside it has both, so the name is the pair's, written the same on each half.
                true,
            ))
        }
    };
    page_document(
        prefs.lang,
        prefs.theme.attr().or(look.theme.attr()),
        &format!("{brand_name} · {title}"),
        look.stylesheet,
        html! {
            // No ☰ here (§13.34 §4), and the strip is the strip with its own name and empty:
            // the breakpoint rules hide the strip by name (`nav.tabs`), because with the ☰ in
            // the console's bar the old `nav:not(.acct)` would hide that too. A strip written
            // without the class is invisible to every one of those rules, and on a phone it
            // lands in front of the brand as an ordering item, which is what moves the brand
            // off the left edge the page's `h1` starts at.
            (top_bar(html! {}, brand, html! { nav class="tabs" {} }, acct))
            main {
                h1 { (title) }
                (content)
            }
        },
    )
}

/// One HTML page under the prefix, with the estate's shared headers and this page's own policy.
///
/// It does not go through [`respond_page`], because that answers with the console's [`Look`],
/// and this page's look is its own read of the `ui` section: it paints the operator's logo,
/// which the console's shell carries as a separate argument, and a page rendered above the
/// settings read has an `AccountLook::default()` of its own (§13.28 §6). What the two policies
/// **allow to run** is not one of the differences: both surfaces wear the same Preferences form,
/// so both admit the same handler through [`page_script_src`], and the only widening here is the
/// reveal's (§13.17).
fn respond_account(
    req: Request,
    status: u16,
    prefs: &AccountPrefs,
    title: &str,
    content: Markup,
    look: AccountLook,
    reveal: bool,
) {
    let page = account_shell(prefs, title, content, look);
    let mut resp = Response::from_data(page.into_string().into_bytes())
        .with_status_code(StatusCode(status))
        .with_header(h("Content-Type", "text/html; charset=utf-8"))
        .with_header(h("Content-Security-Policy", &account_csp(&look, reveal)));
    for (k, v) in PAGE_SECURITY_HEADERS {
        resp.add_header(h(k, v));
    }
    let _ = req.respond(resp);
}

/// `302` back to the page, setting **one cookie per preference this request named**.
///
/// One response for both, because the selector is a form with a submit button and no script: one
/// `GET` carries `theme` and `lang` together, and a program that answered one at a time would
/// leave the person watching the other half of their own submit revert on the next load. The
/// console gets away with one cookie per redirect only because its handler fires per list box.
///
/// A value nobody recognises sets nothing: storing it would write a cookie the page cannot show
/// as chosen, and would let a crafted link write a preference for somebody.
///
/// `location` is [`Config::account_path`] plus a slash, so it is printable ASCII by construction
/// and [`h`] cannot panic on it; the cookie values are one of a closed enum's own codes.
fn respond_account_preferences(
    req: Request,
    location: &str,
    theme: Option<UiTheme>,
    lang: Option<LangPref>,
) {
    let mut resp = Response::empty(StatusCode(302)).with_header(h("Location", location));
    if let Some(chosen) = theme {
        resp.add_header(h(
            "Set-Cookie",
            &format!(
                "{THEME_COOKIE}={}; Max-Age={PREFERENCE_COOKIE_MAX_AGE}; Path=/; HttpOnly; \
                 SameSite=Lax",
                chosen.code()
            ),
        ));
    }
    if let Some(chosen) = lang {
        resp.add_header(h(
            "Set-Cookie",
            &format!(
                "{LANG_COOKIE}={}; Max-Age={PREFERENCE_COOKIE_MAX_AGE}; Path=/; HttpOnly; \
                 SameSite=Lax",
                chosen.code()
            ),
        ));
    }
    resp.add_header(h("Cache-Control", "no-store"));
    let _ = req.respond(resp);
}

/// What the four sections show: most of it read out of the two files this request opened, and
/// the two facts that belong to the request itself (`native`, and the paths) beside them.
///
/// A struct because the page function takes the caller's identity separately (it comes from the
/// request, not from the files), and a page that took six loose arguments was a page whose
/// arguments could be swapped without a compiler noticing.
struct AccountOwn<'a> {
    /// Each application the caller reaches, with the scope names under it, in file order.
    reached: Vec<(&'a str, Vec<&'a str>)>,
    /// The `user_groups` that list the caller's uuid.
    groups: Vec<&'a str>,
    /// The keys on the caller's roster row, in the file's order.
    keys: Vec<&'a ApiKeySpec>,
    /// Each configured `gate.profile_claims` entry, with the value the proxy forwarded.
    claims: Vec<(&'a str, Option<String>)>,
    /// The scopes a key of the caller's may be narrowed to, from
    /// [`bb_auth_core::Access::key_scopes_for`]. Empty for a caller with no row, which is what
    /// takes the mint form out of the page.
    mintable: Vec<(&'a str, &'a str)>,
    /// The `POST` target of the mint form, and the fingerprint of the file as this page was
    /// rendered. Both belong to the request, not to the files, so they arrive beside the facts
    /// the files gave rather than as two more arguments to the page.
    keys_path: &'a str,
    rev: &'a str,
    /// The page's own URL: where every cancel link goes.
    page: &'a str,
    /// `<prefix>/profile`, the form's `POST` target and the Edit pill's href. Beside `keys_path`
    /// for the same reason: it belongs to the request, not to the files.
    profile_path: &'a str,
    /// Whether the edit can work here at all, which is what puts the Edit pill on the panel or
    /// takes it off (§13.22, "The client is `gate.client_id`").
    profile_edit: bool,
    /// Whether this session is a **native** Cognito sign-in, which is the gate's
    /// `X-Auth-Native-Username` speaking (§13.25). The edit acts on that one Cognito user, so a
    /// session the gate did not name gets no pill, no form and no code, and the sentence that
    /// says why. It is a `bool` and not the name because the page only asks whether to offer.
    native: bool,
}

/// The scopes a signed-in caller reaches, grouped by application in file order.
///
/// The grouping is [`bb_auth_core::Access::scopes_reached`] restated as pairs of names, because
/// the page shows an application and then its scopes, and a renderer that walked the raw list
/// would have to notice the application changed at every step.
fn account_reached<'a>(access: &'a Access, identifier: &str) -> Vec<(&'a str, Vec<&'a str>)> {
    let mut out: Vec<(&str, Vec<&str>)> = Vec::new();
    for (app, scope) in access.scopes_reached(identifier) {
        match out.last_mut() {
            Some((name, scopes)) if *name == app.name => scopes.push(scope.name.as_str()),
            _ => out.push((app.name.as_str(), vec![scope.name.as_str()])),
        }
    }
    out
}

/// The groups that list `uuid`.
///
/// The **document** is asked, not the table: `compile_access` expands a `@group` into each
/// scope's members and keeps no group names, and the question a person has is "under which named
/// set am I filed", which a scope's member list cannot answer (a `@group` lists none of them
/// directly). Members are compared the way the library compares them, with [`norm_email`]. A
/// caller with no roster row is in no group, because a group lists uuids.
fn account_groups<'a>(doc: &'a AccessFile, uuid: Option<&str>) -> Vec<&'a str> {
    let Some(want) = uuid else {
        return Vec::new();
    };
    let want = norm_email(want);
    doc.user_groups
        .iter()
        .filter(|(_, members)| members.iter().any(|m| norm_email(m) == want))
        .map(|(name, _)| name.as_str())
        .collect()
}

/// The keys on the caller's roster row, in the file's order.
///
/// Read off the **document**, not the compiled table: the table is a `HashMap` and has lost the
/// order, a page that reshuffled a person's keys between two reloads is a page nobody can compare
/// with the file they wrote, and the console's own table lists them in the file's order too. It
/// is also the row the ten-key bound counts, including a key whose hash the gate skipped, since a
/// person has to be able to see and revoke that one as well. The bearer is not on a roster row at
/// all, only its hash, and the hash is never shown: this list is free of the secret by the shape
/// of what the page reads from it.
fn account_keys<'a>(doc: &'a AccessFile, uuid: Option<&str>) -> Vec<&'a ApiKeySpec> {
    uuid.and_then(|u| user_pos(doc, u))
        .map_or_else(Vec::new, |i| doc.users[i].api_keys.iter().collect())
}

/// The Cognito user this session **is**, as the gate named it, or `None` when the gate named
/// nobody.
///
/// The gate sends [`bb_auth_core::NATIVE_USERNAME_HEADER`] (the token's `cognito:username`) only
/// for a sign-in that went straight to Cognito: a federated sign-in, an API key, an anonymous
/// grant, and a cookie minted before that header existed all send nothing. That is the whole
/// basis of the profile edit, because the edit acts on **one Cognito user** and the only honest
/// name for that user is the one the token carried. Reading it from anywhere else is the bug this
/// step exists for: the rpi-01 deployment has native accounts whose roster email is not their
/// Cognito username, so an edit aimed at an email resolves to a different user, or to nobody, and
/// the person's save silently lands somewhere else.
///
/// An empty value counts as no name: a header that names nothing cannot be sent as a `USERNAME`,
/// and offering the edit on it would end in a pool error the page cannot explain.
///
/// The value is never written to a log, the journal or the audit: it is a personal identifier, and
/// the only thing that reads it is the Cognito request that carries it.
fn native_user(req: &Request) -> Option<&str> {
    header_value(req, bb_auth_core::NATIVE_USERNAME_HEADER).filter(|v| !v.is_empty())
}

/// Everything the page shows, gathered from the two files this request opened. One function for
/// the page a `GET` renders and for the page a refused mint answers with, so the refusal cannot
/// show a different account from the one it refused.
#[allow(clippy::too_many_arguments)]
fn account_own<'a>(
    doc: &'a AccessFile,
    access: &'a Access,
    settings: &'a Settings,
    req: &Request,
    ids: &[String],
    uuid: Option<&str>,
    keys_path: &'a str,
    rev: &'a str,
    page: &'a str,
    profile_path: &'a str,
) -> AccountOwn<'a> {
    AccountOwn {
        reached: account_reached(access, &ids[0]),
        groups: account_groups(doc, uuid),
        keys: account_keys(doc, uuid),
        claims: account_claims(settings, req),
        mintable: match uuid {
            Some(u) => access
                .key_scopes_for(u)
                .iter()
                .map(|(a, s)| (a.name.as_str(), s.name.as_str()))
                .collect(),
            None => Vec::new(),
        },
        keys_path,
        rev,
        page,
        profile_path,
        profile_edit: profile_offered(settings),
        native: native_user(req).is_some(),
    }
}

/// Each configured claim, with the value this request actually carried for its derived header.
///
/// The claim names come from the settings and the values from the request, and keeping them in one
/// function is what makes "configured" and "forwarded" one list rather than two a renderer has to
/// line up by hand. `None` when no header arrived, and the page shows the name with the word for
/// none: a page that filled in a value nobody sent would be telling a person something the estate
/// never said.
fn account_claims<'a>(settings: &'a Settings, req: &Request) -> Vec<(&'a str, Option<String>)> {
    settings
        .profile_claims
        .iter()
        .map(|c| {
            (
                c.claim.as_str(),
                header_value(req, &c.header).map(pct_decode),
            )
        })
        .collect()
}

/// The most keys this page mints onto one roster row. The administrator's CLI has no such
/// bound, and does not need one: an operator typing `bb-auth-adm key add` over SSH is one
/// person doing a counted thing. This form is reachable by every signed-in identity on the
/// estate, and a row accumulating keys is a row whose credentials nobody can review.
const ACCOUNT_MAX_KEYS: usize = 10;

/// The shortest window a self-service mint may ask for, in seconds.
///
/// There is no longest. With "no expiry" among the five choices a ceiling protects nothing:
/// a key of 36500 days and a key that never expires are the same credential, and refusing the
/// first while offering the second is a rule with no reason, which is what the page's own
/// ceiling was. The grammar is the only limit, and it is a real one: `parse_duration` and
/// `key_expiry` use checked arithmetic and answer `None` on overflow. The floor stays, because
/// a key that expires in seconds is a key that does not work, and an `hours` value a
/// hand-written `POST` may bring is refused by it.
const ACCOUNT_KEY_MIN_SECS: u64 = 86_400;

/// Is `id` one this page will file? `[a-z0-9-]{1,32}`, which is the shape that stays readable
/// in a log line and in a `key rotate`, and is short enough to be the whole name of a thing.
fn account_key_id_ok(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Is `duration` a window this page will file? See [`ACCOUNT_KEY_MIN_SECS`]: the parse is the
/// library's, so `365d`, `8760h` and a bare `365` are all one year, and the floor is on the
/// seconds they mean, not on the spelling. No expiry passes too, because the page offers it.
fn account_key_window_ok(duration: &str) -> bool {
    match parse_duration(duration) {
        Some(Dur::Never) => true,
        Some(Dur::Secs(secs)) => secs >= ACCOUNT_KEY_MIN_SECS,
        None => false,
    }
}

/// The values the mint row shows. A fresh row opens on the one-year choice and "all scopes"; a
/// refused submission puts back exactly what was posted, so the person fixes the one thing wrong
/// instead of retyping the rest (WCAG 3.3.1 and 3.3.3).
struct NewKeyRow<'a> {
    id: &'a str,
    choice: &'a str,
    days: &'a str,
    /// The radio: `true` when "only these" is picked.
    some: bool,
    ticked: &'a [String],
    err: Option<&'a Refusal>,
}

impl NewKeyRow<'_> {
    /// The row as `GET <prefix>/keys/new` opens it.
    const OPEN: NewKeyRow<'static> = NewKeyRow {
        id: "",
        choice: "365d",
        days: "",
        some: false,
        ticked: &[],
        err: None,
    };
}

/// The mint row's name field: [`text_field_with`]'s markup, plus the browser's own constraints.
///
/// [`text_field_with`] is the one field both surfaces build from, and the console's key form puts
/// no constraint on its id: an operator typing `bb-auth-adm key add` over SSH is one person doing a
/// counted thing, and the library checks the grammar anyway. This form is reachable by every
/// signed-in identity on the estate, so the grammar goes on the field as well, and `autofocus`
/// puts the person in the field the `+` asked for. All four are the browser's constraint
/// validation and need no script, which is what keeps this page inside the estate's no-JavaScript
/// rule; the server checks every one of them again.
///
/// The hint is the shape, spelled out, and it is shown on the open row. It is **omitted the
/// moment the field carries the refusal**: the refusal is a sentence that already says what is
/// allowed, in the reader's language, so the hint under it is one rule in two registers, and the
/// one that is not the reason for the refusal is the one to drop.
fn account_key_id_field(lang: Lang, value: &str, invalid: bool) -> Markup {
    // The shape, spelled out, on the open row only: see the doc comment.
    let hints: Vec<&str> = if invalid {
        Vec::new()
    } else {
        vec![t(lang, K::AccountKeyIdHint)]
    };
    text_field_with(
        t(lang, K::KeyColName),
        "id",
        value,
        "laptop",
        &hints,
        invalid,
        FieldOpts {
            autofocus: true,
            required: true,
            maxlength: Some(32),
            pattern: Some("[a-z0-9-]{1,32}"),
            ..FieldOpts::default()
        },
    )
}

/// The mint row: the console's `form.edit` inside one cell that spans the table.
///
/// §13.16. A `form` may not wrap a table row, but it may sit inside a cell, so the row that mints
/// is in the table the person is looking at and no `form` attribute is needed anywhere.
///
/// Two of the console's fields are deliberately absent. There is no **owner** field: the owner is
/// the person asking, read from the identity header nginx wrote, and a field that chose the row
/// would let any signed-in person mint a credential on anybody's account. There is no `released`:
/// a key's issue date is a fact about a secret being created now, and the handler stamps it.
///
/// The checkboxes are [`bb_auth_core::Access::key_scopes_for`], so the pairs on offer are exactly
/// the pairs the handler accepts, and each checkbox's value is the `application/scope` pair the
/// file stores. A hand-written form can still name a pair that is not on the list, and the handler
/// answers that with a `400`: a pair the gate would refuse mints a key that fails on its very
/// first request. That list is **empty** for a caller whose scopes take `login` only, and then the
/// whole block is absent, a hidden `restrict=all` in its place: a lone checked radio beside a
/// "Scopes" heading is a choice of one, a control that can only be answered wrong, and
/// `restrict=some` with no pair writes a key narrowed to nothing.
///
/// No URL appears. The restriction is named by application and scope, never by the pattern behind
/// it (§13.6): a URL from the file is information about the estate, and this page is about the
/// person.
fn account_key_row(
    lang: Lang,
    keys_path: &str,
    rev: &str,
    cancel: &str,
    scopes: &[(&str, &str)],
    row: &NewKeyRow,
) -> Markup {
    let about = |name| row.err.is_some_and(|e| e.is(name));
    // Grouped by application, in the order `key_scopes_for` yields them, which is file order.
    let mut apps: Vec<(&str, Vec<&str>)> = Vec::new();
    for (app, scope) in scopes {
        match apps.iter_mut().find(|(name, _)| *name == *app) {
            Some((_, names)) => names.push(*scope),
            None => apps.push((*app, vec![*scope])),
        }
    }
    let fields = html! {
        (account_key_id_field(lang, row.id, about("id")))
        (duration_choice(
            lang,
            t(lang, K::KeyColExpires),
            row.choice,
            row.days,
            // This box takes a number and nothing else, so the placeholder can name the unit;
            // the console's takes `12h` too and keeps its hint line instead (§13.17).
            Some(t(lang, K::DurDaysHint)),
            None,
            about("duration"),
        ))
        @if apps.is_empty() {
            // Nothing to narrow to, so there is no choice to show, not even a checked radio
            // beside a "Scopes" heading: a choice of one is a control that can only be
            // answered wrong. The restriction the owner reaches is carried unseen, so the
            // handler is unchanged and still refuses a request that chose nothing.
            input type="hidden" name="restrict" value="all";
        } @else {
            div {
                span class="lbl" { (t(lang, K::Scopes)) }
                label class="radio" {
                    input type="radio" name="restrict" value="all" checked[!row.some];
                    span { (t(lang, K::KeyScopesAll)) }
                }
                // The narrowing choice, and only when there is something to narrow **to**.
                label class="radio" {
                    input type="radio" name="restrict" value="some" checked[row.some];
                    span { (t(lang, K::KeyScopesOnly)) ":" }
                }
                @for (app, names) in apps {
                    div {
                        span class="lbl" { code { (app) } }
                        @for name in names {
                            @let pair = format!("{app}/{name}");
                            label class="radio" {
                                input type="checkbox" name="scope" value=(pair)
                                      checked[row.ticked.contains(&pair)];
                                span { code { (name) } }
                            }
                        }
                    }
                }
            }
        }
    };
    html! {
        td colspan="4" {
            (form_shell_at(
                keys_path,
                rev,
                cancel,
                t(lang, K::Cancel),
                row.err,
                fields,
                t(lang, K::AccountKeyCreate),
                false,
            ))
        }
    }
}

/// A key's restriction cell, and its table row: [`url_list_marked`] and [`expiry_markup`], the
/// functions the console's person page calls, so the two surfaces answer "what does this key
/// reach" and "when does it die" from one place.
///
/// A pair the owner no longer reaches is still listed, because the key still carries it, and is
/// marked in words (WCAG 1.4.1): a key narrowed to a scope its owner was removed from is the case
/// where the person most needs to know it reaches less than it says.
///
/// The two row actions are the console's: [`act`]'s plain pill for a rotate and [`act_rm`]'s
/// destructive one for a revoke, each a link to a `GET` page that changes nothing, so a crawler
/// or a prefetch cannot rotate or revoke a credential. They are written out here rather than
/// called because those two take a console `View`. The name carries the id because ten links all
/// called "Revoke key" are ten identical entries in a reader's list of links (WCAG 2.4.6).
fn account_key_line(
    lang: Lang,
    k: &ApiKeySpec,
    mintable: &[(&str, &str)],
    keys_path: &str,
    n: u64,
) -> Markup {
    let id = k.id.trim();
    let query: String = form_urlencoded::byte_serialize(id.as_bytes()).collect();
    let remove = format!("{} {id}", t(lang, K::AccountKeyRemove));
    html! {
        tr {
            td class="mono" data-label=(t(lang, K::KeyColName)) { (id) }
            td data-label=(t(lang, K::Scopes)) {
                (url_list_marked(lang, k.scopes.as_ref(), t(lang, K::KeyScopesAll), |u| {
                    let reached = mintable.iter().any(|(a, s)| format!("{a}/{s}") == u);
                    (!reached).then(|| t(lang, K::KeyScopeGone))
                }))
            }
            td data-label=(t(lang, K::ColExpiry)) { (expiry_markup(lang, &expiry_of(k, n))) }
            td class="pills" {
                span class="pills" {
                    a class="pill" href=(format!("{keys_path}/rotate?id={query}"))
                      aria-label=(format!("{} {id}", t(lang, K::AccountKeyRotate))) {
                        (t(lang, K::Rotate))
                    }
                    " "
                    a class="pill rm ico" href=(format!("{keys_path}/remove?id={query}"))
                      title=(remove) {
                        svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                            path d="M6 6l12 12M18 6L6 18" {}
                        }
                        span class="vh" { (remove) }
                    }
                }
            }
        }
    }
}

/// The confirmation a row's rotate or revoke link opens: the console's [`confirm_card`] card
/// in this page's words, with the key's id in a hidden field because the two paths do not name
/// it. **No heading**: the shell's one `h1` carries the action word, which is why the caller
/// passes `op.title()` as the page title (§13.17).
///
/// A rotate is not marked destructive: it keeps the name and the restriction, and a red button on
/// it would teach the person to read the revoke's red as one more routine thing.
fn page_account_confirm(
    lang: Lang,
    page: &str,
    keys_path: &str,
    rev: &str,
    id: &str,
    op: AccountKeyOp,
) -> Markup {
    let (verb, word, warn, danger) = match op {
        AccountKeyOp::Rotate => (
            "rotate",
            K::AccountKeyRotate,
            K::AccountKeyRotateWarn,
            false,
        ),
        _ => ("remove", K::AccountKeyRemove, K::AccountKeyRemoveWarn, true),
    };
    confirm_card(
        &format!("{keys_path}/{verb}"),
        rev,
        page,
        t(lang, K::Cancel),
        html! { p { code { (id) } } },
        t(lang, warn),
        html! { input type="hidden" name="id" value=(id); },
        t(lang, word),
        None,
        danger,
    )
}

/// The delete confirmation page, in its two variants (§13.30 §2).
///
/// A `GET` renders it and does nothing else: it writes no byte of the access file and reaches the
/// intake in no way, because a prefetch of this URL is somebody who wanted to read, not somebody
/// who pressed (§13.29 W3). The facts are the two files' and the settings': what goes is the
/// roster row (the record, the keys, the groups) and the sign-in accounts, and a caller with no
/// row has only the accounts, which is why the stranger's variant is a page and not a refusal.
///
/// The audit sentence is the deployment's own bound, read from the compiled policy through the
/// console's own [`limit_text`] and [`size_text`], so the page cannot promise a retention an
/// operator did not set, and the unit word is the one the Settings page shows for that setting.
///
/// The typed address carries no `autocomplete`: the user removed it on 2026-11-26 (PLAN.md), so
/// the confirmation stays the person's own act, a deliberate exception to WCAG 1.3.5. Nothing on
/// the page is focused, because Enter must not be one keystroke from a deletion, and an empty
/// `required` field stops a stray Enter in the browser anyway.
///
/// `typed` and `err` are the `400` (§13.30 §2): the page that asked for the address is the page a
/// typo is answered on, with what was typed kept in the field, so a typo is seen and fixed rather
/// than retyped (forgiving input, WCAG 3.3.1 and 3.3.3). A `GET` renders the same page empty.
#[allow(clippy::too_many_arguments)]
fn page_account_delete(
    lang: Lang,
    action: &str,
    page: &str,
    rev: &str,
    uuid: Option<&str>,
    ids: &[String],
    own: &AccountOwn<'_>,
    audit: &AuditPolicy,
    typed: &str,
    err: Option<&Refusal>,
) -> Markup {
    // The one field this form has, so the refusal on it is what marks the field: the class,
    // `aria-invalid` and the link to the message box above the fields are one decision, made by
    // [`text_field_with`], and this page does not get to make it differently.
    let invalid = err.is_some_and(|e| e.is("confirm_email"));
    // Two addresses is the case that needs the hint, because the field asks for one of them and a
    // person with one has nothing to pick.
    let many = ids.len() > 1;
    let keys: Vec<&str> = own.keys.iter().map(|k| k.id.as_str()).collect();
    let addresses: Vec<&str> = ids.iter().map(String::as_str).collect();
    let hint = t(lang, K::AccountDeleteTypeHintMany);
    let hints: Vec<&str> = if many { vec![hint] } else { Vec::new() };
    let facts = html! {
        p class="lbl" { (t(lang, K::AccountDeleteGoes)) }
        ul class="plain" {
            @if uuid.is_some() {
                li { (t(lang, K::AccountDeleteRecord)) }
                @if !keys.is_empty() {
                    li { (t(lang, K::AccountDeleteKeysLead)) " " (code_list(&keys)) }
                }
                @if !own.groups.is_empty() {
                    li { (t(lang, K::AccountDeleteGroupsLead)) " " (code_list(&own.groups)) }
                }
            }
            // Last, because it is the one item that does not go at once (§13.30 §2).
            li {
                @if many {
                    (t(lang, K::AccountDeleteSignInMany))
                } @else {
                    (t(lang, K::AccountDeleteSignInOne))
                }
                " " (code_list(&addresses))
            }
        }
        p class="muted" { (t(lang, K::AccountDeleteLater)) }
        p class="muted" {
            @match audit.retention {
                Some(r) => {
                    (t(lang, K::AccountDeleteAuditKept)) " " (limit_text(lang, &r))
                    (t(lang, K::AccountDeleteAuditTail))
                },
                None => {
                    (t(lang, K::AccountDeleteAuditSize)) " " (size_text(audit.max_bytes())) "."
                },
            }
        }
    };
    confirm_card(
        action,
        rev,
        page,
        t(lang, K::Cancel),
        facts,
        t(lang, K::AccountDeleteLead),
        html! {
            // The subject of the press, as a hidden field and not in the path: the page is about
            // the caller, and the caller's uuid is what the `POST` re-checks against the header
            // (§13.29 W3 step 5). Empty for a stranger, and a stranger's deletion is the pool's
            // alone.
            input type="hidden" name="uuid" value=(uuid.unwrap_or(""));
            (text_field_with(
                t(lang, K::AccountDeleteTypeLabel),
                "confirm_email",
                typed,
                "",
                &hints,
                invalid,
                FieldOpts {
                    required: true,
                    inputmode: Some("email"),
                    class: Some("f-email"),
                    ..FieldOpts::default()
                },
            ))
        },
        t(lang, K::AccountDeleteConfirm),
        err,
        true,
    )
}

/// The most addresses one deletion request queues (§13.29 W3).
///
/// Named after the worker's own `MAX_PER_RUN`: it takes ten addresses per run and refuses the
/// **whole** run above that, so a caller with more is refused here, before anything is sent,
/// rather than leaving nine queued and the tenth not.
const DELETE_MAX_ADDRESSES: usize = 10;

/// The intake's two paths, hard-coded on **its** side (§13.29 W1), which is why
/// `BB_AUTH_WEB_DELETE_INTAKE` names only an origin: a path an operator can set is a path the
/// intake may not answer.
const INTAKE_WHOAMI_PATH: &str = "/account/whoami";
const INTAKE_DELETE_PATH: &str = "/account/delete";

/// The header the shared secret travels in (§13.29 W8 §1), on both calls and only where the
/// deployment set one.
const INTAKE_SECRET_HEADER: &str = "X-BB-Delete-Secret";

/// What one `GET /account/whoami` answered (§13.29 W3 step 4).
enum Whoami {
    /// The intake will take this address.
    Open,
    /// The intake will not (§13.29 W5). The protected list is its own, and this page never names
    /// it, the address that matched, or the intake's word for it (§13.30 §7).
    Protected,
    /// It gave no HTTP answer at all: the timeout, or a socket that will not carry the request.
    NoAnswer,
    /// It answered, in a way the contract does not read: not a `200`, not this address, no
    /// `protected` it is willing to state.
    Unusable,
}

/// What one `POST /account/delete` answered (§13.29 W3 step 6).
///
/// A run that stops on anything but [`Self::Accepted`] is a **partial** run for a caller whose
/// row went at step 5, and its page never says the account is deleted: the row going is a fact
/// this process did with its own hands, while the sign-in accounts sit in a queue this process
/// cannot read (§13.29 W6), so "deleted" would be a claim about the worker and "only partly
/// deleted" is the whole of what is known. The retry that page offers still works, and works as
/// a stranger: the row is gone, so the confirmation page the retry renders is the stranger's
/// variant, and the walk that follows runs over the addresses the session's own header names,
/// which is exactly the walk that queues what the first run did not.
enum Queued {
    /// `202` with `"ok": true`, the only acceptance the contract has (§13.29 W1).
    Accepted,
    /// An HTTP answer that is not an acceptance, with the status that said so. A `403` is the
    /// intake's protected list, and for a caller with no roster row that is the same page
    /// `whoami` would have given (§13.30 §4).
    Refused(u16),
    /// No HTTP answer at all, so the record may or may not be queued and the page says exactly
    /// that (§13.29 W6).
    NoAnswer,
}

/// The intake's HTTP client: the same three settings as [`cognito_post`], for the same reasons.
///
/// `timeout_global` is the bound the caller waits on (§13.29 W2), because `tiny_http` runs a
/// fixed pool of handler threads and a call that hangs forever is a worker that never serves
/// anybody again. `http_status_as_error(false)`, so a `403` and a `503` arrive as the answers
/// they are and not as errors. `max_redirects` **0**, because ureq's own default is 10 and a
/// `3xx` from the intake would hand the identity header, written here, to whatever host the
/// intake named.
fn intake_agent(cfg: &Config) -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(cfg.intake_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    )
}

/// Ask the intake whether one address may be deleted (§13.29 W3 step 4).
///
/// **One address per call**, as `X-Auth-Email`: the intake reads the whole header as one address,
/// so the gate's joined header (every email of one roster row) would queue an address no Cognito
/// user has and report it accepted. `X-Real-IP` is sent by nobody here: the intake records the
/// address of the socket that asked, and this client is not the proxy that knows the caller's.
///
/// The answer counts only from a `200` that echoes the address sent and states `protected` as a
/// boolean; anything else is [`Whoami::Unusable`]. Guessing "not protected" from an answer that
/// did not say so is the one guess this walk may not make, because the price of that guess is a
/// queued deletion.
fn intake_whoami(agent: &ureq::Agent, cfg: &Config, origin: &str, email: &str) -> Whoami {
    let mut request = agent
        .get(&format!("{origin}{INTAKE_WHOAMI_PATH}"))
        .header(IDENTITY_HEADER, email);
    if let Some(secret) = cfg.delete_secret.as_deref() {
        request = request.header(INTAKE_SECRET_HEADER, secret);
    }
    let response = match request.call() {
        Ok(r) => r,
        Err(ureq::Error::Timeout(_)) => return Whoami::NoAnswer,
        Err(_) => return Whoami::Unusable,
    };
    if response.status().as_u16() != 200 {
        return Whoami::Unusable;
    }
    let mut body = response.into_body();
    let text = body.read_to_string().unwrap_or_default();
    let value = serde_json::from_str::<serde_json::Value>(&text).unwrap_or_default();
    if value.get("email").and_then(|v| v.as_str()) != Some(email) {
        return Whoami::Unusable;
    }
    match value.get("protected").and_then(|v| v.as_bool()) {
        Some(true) => Whoami::Protected,
        Some(false) => Whoami::Open,
        None => Whoami::Unusable,
    }
}

/// Queue one address with the intake (§13.29 W3 step 6).
///
/// The body carries `confirm_email` equal to the header's address: the intake refuses a
/// `confirm_email` that differs from `X-Auth-Email` (`confirm_mismatch`), and the two are one
/// fact stated twice, so a request that means one address says it twice.
fn intake_delete(agent: &ureq::Agent, cfg: &Config, origin: &str, email: &str) -> Queued {
    let mut request = agent
        .post(&format!("{origin}{INTAKE_DELETE_PATH}"))
        .header(IDENTITY_HEADER, email);
    if let Some(secret) = cfg.delete_secret.as_deref() {
        request = request.header(INTAKE_SECRET_HEADER, secret);
    }
    let response = match request.send_form([("confirm_email", email)]) {
        Ok(r) => r,
        // A timeout and a socket that refuses the request are one fact to the person: the intake
        // did not say. "May or may not be queued" is the honest page for both, and the page's
        // own advice, try again, is safe in the case where it was queued.
        Err(_) => return Queued::NoAnswer,
    };
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let text = body.read_to_string().unwrap_or_default();
    let value = serde_json::from_str::<serde_json::Value>(&text).unwrap_or_default();
    if status == 202 && value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Queued::Accepted
    } else {
        Queued::Refused(status)
    }
}

/// The page a deletion request ends on (§13.30 §4): the profile outcome's shape, one `h1` that
/// states the result, one `p.lede`, one row of pills.
///
/// `muted` is the line the "some are queued" outcome adds: the addresses this walk cannot
/// confirm, which is a list of values for the administrator the person is sent to ask, not a
/// sentence of the lede (§13.30 §4). Every other outcome passes `None`.
///
/// The row's tag depends on how many pills it holds. maud writes no whitespace between
/// siblings, so pills written straight into one paragraph touch borders and read as one control
/// (WCAG 2.5.8, target spacing): a row of two rides in `div.actions`, which `admin.css` gives
/// `gap:12px` and the confirmation page's form already uses. `p.primary` stays for the single
/// pill, which needs no gap and is the shape the rest of the estate's pages have.
fn page_account_delete_outcome(lede: Markup, muted: Option<Markup>, pills: Vec<Markup>) -> Markup {
    html! {
        p class="lede" { (lede) }
        @if let Some(line) = muted {
            p class="muted" { (line) }
        }
        @if pills.len() > 1 {
            div class="actions" {
                @for pill in &pills { (pill) }
            }
        } @else if !pills.is_empty() {
            p class="primary" {
                @for pill in &pills { (pill) }
            }
        }
    }
}

/// The actions of an outcome page that says something **did** go: the retry, then the sign out
/// (§13.30 §4). The sign out is there because the cookie outlives the deletion and signing out is
/// the one action left that is true, and it is absent exactly where the operator named no
/// destination, which is the same rule the bar's row follows. The completed deletion answers no
/// page at all when a destination **is** named (§13.32 §1).
fn with_sign_out(prefs: &AccountPrefs, lang: Lang, retry: Markup) -> Vec<Markup> {
    let mut pills = vec![retry];
    if let Some(url) = prefs.logout {
        pills.push(pill_link(url, t(lang, K::SignOut)));
    }
    pills
}

/// Why the roster row did not go, and which page each answer is (§13.30 §4).
enum RowGone {
    /// The page is not the current one: its bytes moved under it, or the row it names is no
    /// longer in the file. The same page as the check at (2) answers this, because for the
    /// person each is "my account changed", and one page for both is also what stops the
    /// delete form being an oracle for which of the two checks fired.
    Changed,
    /// The write did not land, for a reason the filesystem or the parser gave. The library's
    /// sentence rides along for the journal, and the page says only that bb-auth could not
    /// save: the person has no use for an `EPERM`, and an operator reads it in the journal.
    Failed(String),
}

/// Answer the delete `POST` (§13.29 W3).
///
/// The order is W3's, and every step that can refuse refuses **before** the intake is asked,
/// because a `202` is the one answer this page cannot take back:
///
/// 1. the same-origin door, before the body is read, the door every `/account` `POST` goes
///    through;
/// 2. the page is the current one: the posted `uuid` is the live row's (`""` for a caller the
///    file has no row for) and the posted `rev` is the file's exact bytes. A person who opened
///    the page as a stranger and gained a row before pressing is refused, because the page they
///    hold says the file names nobody, and acting on that deletes a record they were never shown;
/// 3. the typed address is one of the caller's own, normalised as the header's are;
/// 4. no more than [`DELETE_MAX_ADDRESSES`] addresses;
/// 5. `whoami` for **every** address, ahead of any `POST`. The protected list is the intake's, and
///    a caller whose second address is protected must not leave a record queued behind the first,
///    which is why this is a loop of its own and not a check inside the write loop;
/// 6. for a caller the file has a row for: that row, removed under [`WRITE_LOCK`] through
///    [`remove_user`], ahead of the first `POST` (the reason is at the step);
/// 7. `POST` each address, stopping at the first that is not accepted;
/// 8. the journal lines (§13.29 W7), then the answer: where every address queued and the
///    operator named a logout URL, a `303` through the gate's logout (§13.32 §1); every other
///    outcome a page (§13.30 §4).
///
/// A caller with no row skips (6) and the access file is never opened for writing on that path,
/// which is the stranger's half of W3: the same walk, one effect short.
#[allow(clippy::too_many_arguments)]
fn account_delete_post(
    mut req: Request,
    cfg: &Config,
    prefs: &mut AccountPrefs,
    lang: Lang,
    look: AccountLook,
    ids: &[String],
    uuid: Option<&str>,
    own: &AccountOwn<'_>,
    settings: &Settings,
    intake: Option<&str>,
    delete_path: &str,
    page: &str,
    rev: &str,
) {
    // (1) The door, and the console's strict policy: `same-origin` and nothing else.
    if !csrf_ok(
        header_value(&req, "Sec-Fetch-Site"),
        header_value(&req, "Origin"),
        header_value(&req, "Host"),
    ) {
        respond_account(
            req,
            403,
            prefs,
            t(lang, K::CsrfTitle),
            html! { p { (t(lang, K::CsrfBody)) } },
            look,
            false,
        );
        return;
    }
    let form = Form::parse(&read_body(&mut req));
    // Every page below carries its own `p.lede`, as the confirmation page does (§13.23 §4).
    prefs.page_lede = true;
    let typed = norm_email(form.get("confirm_email").trim());
    // (2) The page is the current one. The `rev` alone is not the check: a page rendered after
    // the row landed carries the current `rev` and no uuid, and is refused by the uuid.
    if form.get("rev").trim() != rev || form.get("uuid").trim() != uuid.unwrap_or("") {
        respond_account(
            req,
            409,
            prefs,
            t(lang, K::AccountDeleteChangedTitle),
            page_account_delete_outcome(
                html! { (t(lang, K::AccountDeleteChanged)) },
                None,
                vec![
                    pill_link(delete_path, t(lang, K::AccountDeleteStartAgain)),
                    back_link(lang, page),
                ],
            ),
            look,
            false,
        );
        return;
    }
    // (3) The typed address **is** the confirmation, so a typo is refused here, with the page
    // that asked for it kept on screen and the typo kept in the field, and nothing sent.
    if !ids.contains(&typed) {
        let refusal = Refusal::on("confirm_email", t(lang, K::AccountDeleteTypedWrong));
        respond_account(
            req,
            400,
            prefs,
            t(lang, K::AccountDeleteTitle),
            page_account_delete(
                lang,
                delete_path,
                page,
                rev,
                uuid,
                ids,
                own,
                &settings.audit_policy,
                &typed,
                Some(&refusal),
            ),
            look,
            false,
        );
        return;
    }
    // (4) The worker's bound, checked before the first call: nine addresses queued and a tenth
    // refused is a half-deleted account, which is the one outcome this page cannot explain.
    if ids.len() > DELETE_MAX_ADDRESSES {
        respond_account(
            req,
            400,
            prefs,
            t(lang, K::AccountDeleteNotDoneTitle),
            page_account_delete_outcome(
                html! { (t(lang, K::AccountDeleteTooMany)) },
                None,
                vec![back_link(lang, page)],
            ),
            look,
            false,
        );
        return;
    }
    // The intake, and the walk starts here. The path is dispatched only where an intake is
    // wired (§13.29 W2), so this is the same fact the `404` above already answered.
    let Some(origin) = intake else {
        respond_account(
            req,
            404,
            prefs,
            t(lang, K::NotFoundTitle),
            html! { p { (t(lang, K::NotFoundBody)) } },
            look,
            false,
        );
        return;
    };
    let agent = intake_agent(cfg);
    // (5) Every address is asked before any is posted.
    for id in ids {
        match intake_whoami(&agent, cfg, origin, id) {
            Whoami::Open => {}
            Whoami::Protected => {
                audit(
                    &format!("{typed} (self)"),
                    "delete-request",
                    "refused protected",
                );
                respond_account(
                    req,
                    403,
                    prefs,
                    t(lang, K::AccountDeleteNotDoneTitle),
                    page_account_delete_outcome(
                        html! { (t(lang, K::AccountDeleteProtected)) },
                        None,
                        vec![back_link(lang, page)],
                    ),
                    look,
                    false,
                );
                return;
            }
            who => {
                // No answer is a 504 and an unusable answer a 502, and both say the same thing:
                // nothing was deleted, and the caller can still sign in. Try again is the way
                // forward, because the confirmation page this link renders is still true.
                let (status, journal) = match who {
                    Whoami::NoAnswer => (504, "no answer"),
                    _ => (502, "refused no check"),
                };
                audit(&format!("{typed} (self)"), "delete-request", journal);
                respond_account(
                    req,
                    status,
                    prefs,
                    t(lang, K::AccountDeleteNotDoneTitle),
                    page_account_delete_outcome(
                        html! { (t(lang, K::AccountDeleteNoCheck)) },
                        None,
                        vec![
                            pill_link(delete_path, t(lang, K::AccountDeleteRetry)),
                            back_link(lang, page),
                        ],
                    ),
                    look,
                    false,
                );
                return;
            }
        }
    }
    // (6) The row, ahead of the first `POST` (§13.29 W3 step 5).
    //
    // **Why the row goes first, and not after a `202`.** The worker runs `user show` and then
    // `user rm`, and a row that disappears between the two fails its whole run: the cursor is
    // kept, the owner is mailed, and every later deletion waits for the spool to change again
    // (W1). A row that is **already** gone when the record lands is the path its contract
    // tolerates: `show` finds nothing, the worker logs "not in the roster" and goes on. Removing
    // the row after the `202` races that by construction, however short our write is. The
    // person's half is the same fact seen from their side: the row goes with its keys and every
    // reference to it, so no credential that still works is left waiting on a queue nobody can
    // read, and `bb-auth-reload.path` hands the gate the new file as soon as this write lands.
    //
    // The lock ends at the commit, as every write in this program does (§13.13): what it owes is
    // that no other writer renames between this one's `rev` check and this one's rename, and the
    // intake walk that follows is a network call, which is the one thing never held across it.
    let mut row_gone = false;
    if let Some(uuid) = uuid {
        let writing = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let done = (|| -> Result<(), RowGone> {
            // `rev` **again**, under the lock. The check at (2) is a courtesy to a stale page:
            // between it and here a console save, an `bb-auth-adm` over SSH or this page's own
            // mint can land, and the bytes the person confirmed are the bytes this write replaces.
            let raw = std::fs::read_to_string(&cfg.access_path)
                .map_err(|e| RowGone::Failed(format!("read {}: {e}", cfg.access_path)))?;
            if form.get("rev").trim() != sha256_hex(&raw) {
                return Err(RowGone::Changed);
            }
            let (mut doc, _) = open_access_file(&cfg.access_path).map_err(RowGone::Failed)?;
            // The library's sweep, the same one `bb-auth-adm user rm` runs: the row, its keys,
            // every scope and group that named it, and an `excluded` entry **rewritten** to the
            // row's primary email rather than dropped, because dropping a veto lifts it and an
            // `authenticated` scope lets that identity walk straight back in.
            remove_user(&mut doc, uuid).map_err(|_| RowGone::Changed)?;
            AccessWrite::prepare(&doc)
                .map_err(RowGone::Failed)?
                .commit(&cfg.access_path)
                .map_err(RowGone::Failed)?;
            Ok(())
        })();
        drop(writing);
        match done {
            Ok(()) => {
                row_gone = true;
                audit(&format!("{typed} (self)"), "user rm", uuid);
            }
            Err(RowGone::Changed) => {
                // The page (2) renders, for the reason §13.30 §4 gives: to the person a file that
                // moved and a row an administrator took away are the same fact, "my account
                // changed", and one page for both is what keeps this form from reporting which
                // check fired. Nothing was written and nothing has been posted.
                respond_account(
                    req,
                    409,
                    prefs,
                    t(lang, K::AccountDeleteChangedTitle),
                    page_account_delete_outcome(
                        html! { (t(lang, K::AccountDeleteChanged)) },
                        None,
                        vec![
                            pill_link(delete_path, t(lang, K::AccountDeleteStartAgain)),
                            back_link(lang, page),
                        ],
                    ),
                    look,
                    false,
                );
                return;
            }
            Err(RowGone::Failed(msg)) => {
                // One journal line for the one effect that failed, carrying the library's sentence
                // (a path and an OS error, never a bearer), and a page that says only that the
                // save failed and signing in still works: the row stands, so that is true.
                audit(
                    &format!("{typed} (self)"),
                    "user rm",
                    &format!("failed: {msg}"),
                );
                respond_account(
                    req,
                    500,
                    prefs,
                    t(lang, K::AccountDeleteNotDoneTitle),
                    page_account_delete_outcome(
                        html! { (t(lang, K::AccountDeleteWriteFailed)) },
                        None,
                        vec![
                            pill_link(delete_path, t(lang, K::AccountDeleteStartAgain)),
                            back_link(lang, page),
                        ],
                    ),
                    look,
                    false,
                );
                return;
            }
        }
    }
    // (7) The records, one address per request, stopping at the first that is not accepted.
    //
    // A stop is one of three pages, and the two facts that choose it are what has already
    // **gone** and what has already been **queued** (§13.30 §4):
    //
    // - an address before this one was accepted: some of the sign-in accounts are queued, so
    //   the page says "some" and lists the addresses it cannot confirm, from this one on, for
    //   the administrator the person is sent to ask;
    // - the row went at (6): the keys and the named access are gone and these accounts are not
    //   queued, so the account is *only partly* deleted, and "your account was not deleted"
    //   would be false. The page leads with what did go (Nielsen 9);
    // - neither: nothing has gone, and a `403` here is the intake's protected list answering
    //   where `whoami` did not, which is the page §4 gives it.
    //
    // The actions are the same facts read as advice: a page that says something did go ends in
    // Sign out, because the cookie outlives the deletion and signing out is the one thing left
    // that is true; a page that says nothing went offers the retry and the way back. The retry
    // works for a caller whose row is gone because the confirmation page it renders is the
    // stranger's variant, and the walk over the header's addresses is the same walk.
    for (i, id) in ids.iter().enumerate() {
        let outcome = intake_delete(&agent, cfg, origin, id);
        if matches!(outcome, Queued::Accepted) {
            continue;
        }
        let refused = match outcome {
            Queued::Refused(status) => Some(status),
            _ => None,
        };
        // One journal line for the effect that stopped the walk: the status the intake gave,
        // and nothing of the credential this call carries (§13.29 W7).
        audit(
            &format!("{typed} (self)"),
            "delete-request",
            &match refused {
                Some(status) => format!("refused {status}"),
                None => "no answer".to_string(),
            },
        );
        let unanswered = refused.is_none();
        let retry = pill_link(delete_path, t(lang, K::AccountDeleteRetry));
        // The row went, so the account is only partly deleted, and a row that had two addresses
        // says so: the retry reaches the one this session signs in with, and the rest of what
        // the row held is an administrator's to take (§13.30 §4).
        if i > 0 {
            // Some are queued and this one is not, so the page cannot speak of the accounts as
            // a whole, and the addresses it cannot confirm are the fact the person has no way
            // to check. Not "not queued": an unanswered request may have been queued.
            let unconfirmed: Vec<&str> = ids[i..].iter().map(String::as_str).collect();
            respond_account(
                req,
                if unanswered { 504 } else { 502 },
                prefs,
                t(lang, K::AccountDeletePartialTitle),
                page_account_delete_outcome(
                    html! {
                        @if row_gone {
                            (t(lang, K::AccountDeleteNowGone)) " "
                        }
                        (t(lang, K::AccountDeleteSome)) " "
                        (t(lang, K::AccountDeleteRetryOneAddress))
                    },
                    Some(html! {
                        (t(lang, K::AccountDeleteUnconfirmedLead)) " " (code_list(&unconfirmed))
                    }),
                    with_sign_out(prefs, lang, retry),
                ),
                look,
                false,
            );
            return;
        }
        if row_gone {
            respond_account(
                req,
                if unanswered { 504 } else { 502 },
                prefs,
                t(
                    lang,
                    if unanswered {
                        K::AccountDeleteUnsureTitle
                    } else {
                        K::AccountDeletePartialTitle
                    },
                ),
                page_account_delete_outcome(
                    html! {
                        (t(lang, K::AccountDeleteNowGone)) " "
                        (t(lang, if unanswered {
                            K::AccountDeleteMaybeQueued
                        } else {
                            K::AccountDeleteNotQueued
                        }))
                        @if ids.len() > 1 {
                            " " (t(lang, K::AccountDeleteRetryOneAddress))
                        }
                    },
                    None,
                    with_sign_out(prefs, lang, retry),
                ),
                look,
                false,
            );
            return;
        }
        if refused == Some(403) {
            // Nothing has changed for a caller with no row, so the protected page is true, and
            // it names no list, no address and no rule (§13.30 §7).
            respond_account(
                req,
                403,
                prefs,
                t(lang, K::AccountDeleteNotDoneTitle),
                page_account_delete_outcome(
                    html! { (t(lang, K::AccountDeleteProtected)) },
                    None,
                    vec![back_link(lang, page)],
                ),
                look,
                false,
            );
            return;
        }
        // Nothing went, so the account stands, signing in still works, and the retry renders a
        // confirmation page that is still true.
        respond_account(
            req,
            if unanswered { 504 } else { 502 },
            prefs,
            t(
                lang,
                if unanswered {
                    K::AccountDeleteUnsureTitle
                } else {
                    K::AccountDeleteNotDoneTitle
                },
            ),
            page_account_delete_outcome(
                html! {
                    (t(lang, if unanswered {
                        K::AccountDeleteMaybeQueued
                    } else {
                        K::AccountDeleteNotQueued
                    }))
                },
                None,
                vec![retry, back_link(lang, page)],
            ),
            look,
            false,
        );
        // The walk stops at the answer: a `POST` after a refusal would queue an address behind
        // one the intake has just refused, which is the half-state §13.29 W3 exists to avoid.
        return;
    }
    // (8) Every address is queued, which is all this program knows (§13.29 W6): the worker's
    // outcome is not readable from here, so the answer says "being deleted" and never
    // "deleted". Where the operator named a logout URL this is also the one outcome that
    // signs the browser out, through the gate's logout (§13.32 §1): by the time a page is
    // drawn the person is signed out, so nothing here ever asks them to sign out. Every
    // partial outcome above keeps its page and its Sign out pill, because its "Try again"
    // is a walk over the header's addresses and that walk needs the session. With no logout
    // URL there is nowhere to send the browser, so the done page stays, and its last
    // sentence says what the person can do themselves.
    audit(
        &format!("{typed} (self)"),
        "delete-request",
        &format!("{} queued", ids.len()),
    );
    if let Some(url) = prefs.logout {
        respond_redirect(req, &delete_logout_location(url));
        return;
    }
    respond_account(
        req,
        200,
        prefs,
        t(lang, K::AccountDeleteQueuedTitle),
        page_account_delete_outcome(
            // The row's half first, and only where the row went: it is the part that is already
            // true, while the queue is a promise about a process this page cannot see (§13.30 §4).
            html! {
                @if row_gone {
                    (t(lang, K::AccountDeleteNowGone)) " "
                }
                (t(lang, K::AccountDeleteQueued)) " " (t(lang, K::AccountDeletedClose))
            },
            None,
            // No pill: the page's one action used to be the sign out, and §13.32 §1 moved
            // that action into the redirect this branch does not answer with. The bar's
            // account menu is the sign out that is left.
            vec![],
        ),
        look,
        false,
    );
}

/// The values one delete line names, each in `code` and joined by `", "`: an address, a key id, a
/// group name is a value, and a person reads a value in the same face they read it in everywhere
/// else in this estate (§13.30 §2).
fn code_list(values: &[&str]) -> Markup {
    html! {
        @for (i, v) in values.iter().enumerate() {
            @if i > 0 { ", " }
            code { (v) }
        }
    }
}

/// The page a mint or a rotate answers with, and the one place this page ever renders a bearer.
///
/// Rendered **directly**, for the console's reason ([`page_minted`]): a redirect would put the
/// result behind a `GET` that has no bearer to show, and the bearer exists nowhere else. The
/// block is [`bearer_reveal`], the console's own: the key, the copy button and the script are one
/// rendering, so a person who mints from the console and from `/account/` sees one page, and the
/// words are the console's three, because "shown once, copy it now" is one fact with one spelling
/// in this program, and a person who sees it in two places must not read two claims. A rotate
/// lands on the same page for the same reason: it mints a secret, and the old one is already dead
/// at the next reload.
fn page_account_minted(lang: Lang, page: &str, bearer: &str) -> Markup {
    html! {
        (bearer_reveal(lang, bearer))
        p { a href=(page) { "← " (t(lang, K::Back)) } }
    }
}

/// The page a caller gets: who they are, as the header carried it, their uuid when the access file
/// has a row for them, and the four sections about their own account.
///
/// A stranger is named too: the `authenticated` scope §13.4 chose for this URL admits any
/// identity Cognito vouches for, so "bb-auth knows nothing about you" is a page a real caller
/// reaches, not a defensive one. A stranger and an administrator with no roster row get the same
/// page, because `web.admins` is not read here. Where there is **no** row the lede says nothing
/// about it (the user, 2026-11-26, PLAN.md step 13): the line under the addresses exists to name
/// an account id, so with no id to name the line and its `br` go, and the page writes no sentence
/// standing in for a row it does not have.
///
/// The sections are siblings, each a `.panel` whose `h2 class="tight"` is followed by one
/// `p.lede.sub` saying what that section is for, and whose empty state is a `p.muted` naming what
/// is missing. The page's contract is the one that made this page few keys: **which fact belongs
/// in which section**, so a sub-line says what a section is for and never states a fact that
/// belongs to another one.
///
/// The order is what a person **does** first (§13.26 §1): the two sections you act in, profile
/// and keys, then the two you read, groups and reach. The ids do not move with it, so no link and
/// no selector changes. The heading carries `tight` because the page is the console's column now
/// and the console writes the same rule at each of its headings; a rule scoped to this page is
/// what used to say it, and that rule was one of the width rules §13.26 deleted.
fn page_account(
    lang: Lang,
    ids: &[String],
    uuid: Option<&str>,
    own: &AccountOwn,
    row: Option<&NewKeyRow>,
    profile: Option<&ProfileForm>,
) -> Markup {
    html! {
        // One paragraph says who this page is about: every address of the row (as the gate sends
        // them), and on the line below the account these addresses resolve to. The bar already
        // says who is signed in, so the body does not say it twice. A caller with no row gets the
        // addresses alone: the second line names an id, and with no id there is no line and no
        // `br` to stand under it (step 13).
        p class="lede" {
            @for id in ids {
                code { (id) } " "
            }
            @if let Some(u) = uuid {
                br;
                (t(lang, K::AccountIdLabel)) ": " code class="uid" { (u) }
            }
        }
        section id="profile" class="panel" {
            h2 class="tight" { (t(lang, K::AccountProfile)) }
            // The sub-line says what this section is doing: reading, or editing. The edit page
            // says what happens after the form (a code by email), because that is the fact a
            // person needs before they type anything (§13.23 §2).
            p class="lede sub" {
                (t(lang, if profile.is_some() { K::AccountProfileEditSub } else { K::AccountProfileSub }))
            }
            @if let Some(f) = profile {
                // The form, on this page alone (`<prefix>/profile`, the `keys/new` pattern): the
                // panel is the section, and the section is what a caller of `/account/profile`
                // came to.
                (profile_form(lang, f, own.profile_path, own.page))
            } @else {
                @if own.claims.is_empty() {
                    p class="muted" { (t(lang, K::AccountProfileNone)) }
                } @else {
                    ul class="plain" {
                        @for (claim, value) in &own.claims {
                            li {
                                // A claim the design names a word for is called by that word, in
                                // the same words the form labels it with, so the panel and the
                                // form never call one field by two names. The rest keep the
                                // claim's own name, in code: it is the file's vocabulary, and a
                                // name nobody translated is the honest answer.
                                @if let Some(word) = profile_label(lang, claim) {
                                    (word)
                                } @else {
                                    code { (claim) }
                                }
                                ": "
                                // The value is the person's name or department, which is prose. A
                                // claim the deployment configured and the proxy did not forward is
                                // a fact about the wiring, and says so in words: a bare colon after
                                // a name reads as "your name is empty", a statement nobody made.
                                @if let Some(v) = value {
                                    (v)
                                } @else {
                                    span class="muted" { (t(lang, K::AccountNotProvided)) }
                                }
                            }
                        }
                    }
                }
                // The way in, and only where the edit can work: a pool, a native client, at least
                // one editable claim, and a session the gate named a Cognito user for (§13.25).
                // A control that can only end in an error is a promise the page cannot keep, so it
                // is absent, not disabled, and the person is told the reason in the sentence that
                // stands where the pill would be. A deployment with no pool says nothing about
                // editing at all: there is nothing to sign out and back into.
                @if own.profile_edit {
                    @if own.native {
                        p class="primary" {
                            (pill_link(own.profile_path, t(lang, K::AccountProfileEdit)))
                        }
                    } @else {
                        p class="muted" { (t(lang, K::AccountProfileNotNative)) }
                    }
                }
            }
        }
        section id="keys" class="panel" {
            h2 class="tight" { (t(lang, K::AccountKeys)) }
            p class="lede sub" { (t(lang, K::AccountKeysSub)) }
            // Ten keys close the row (§13.16), counting every key on the row. A sentence and not
            // a disabled control: a disabled control is skipped by the keyboard and says nothing
            // about why.
            @let full = own.keys.len() >= ACCOUNT_MAX_KEYS;
            @let open = if full { None } else { row.filter(|_| uuid.is_some()) };
            @if own.keys.is_empty() && open.is_none() {
                p class="muted" { (t(lang, K::AccountKeysNone)) }
            } @else {
                table {
                    thead { tr {
                        th { (t(lang, K::KeyColName)) }
                        th { (t(lang, K::Scopes)) }
                        th { (t(lang, K::ColExpiry)) }
                        th {}
                    } }
                    tbody {
                        @for k in &own.keys {
                            (account_key_line(lang, k, &own.mintable, own.keys_path, now()))
                        }
                        @if let Some(r) = open {
                            tr { (account_key_row(lang, own.keys_path, own.rev, own.page, &own.mintable, r)) }
                        }
                    }
                }
            }
            // The mint control, and only for a caller the file has a row for: a key is filed
            // under a uuid, so a stranger has no account to mint into, and a control that would
            // be refused before it was read is a promise the page cannot keep.
            @if uuid.is_some() {
                @if full {
                    @if let Some(e) = row.and_then(|r| r.err) { div class="err" { (e.msg) } }
                    p class="muted" { (t(lang, K::AccountKeyFullRow)) }
                } @else if row.is_none() {
                    p class="primary" {
                        (pill_link(
                            &format!("{}/new", own.keys_path),
                            t(lang, K::AccountKeyNew),
                        ))
                    }
                }
            }
        }
        section id="groups" class="panel" {
            h2 class="tight" { (t(lang, K::AccountGroups)) }
            p class="lede sub" { (t(lang, K::AccountGroupsSub)) }
            @if own.groups.is_empty() {
                p class="muted" { (t(lang, K::AccountGroupsNone)) }
            } @else {
                ul class="plain" {
                    @for g in &own.groups {
                        li { code { (g) } }
                    }
                }
            }
        }
        section id="reach" class="panel" {
            h2 class="tight" { (t(lang, K::AccountReach)) }
            p class="lede sub" { (t(lang, K::AccountReachSub)) }
            @if own.reached.is_empty() {
                p class="muted" { (t(lang, K::AccountReachNone)) }
            } @else {
                // One flat list of `app/scope` pairs, in the file's order: the question is "where
                // can I go", and each answer is one place. The console's person page lists them
                // the same way.
                ul class="plain" {
                    @for (app, scopes) in &own.reached {
                        @for scope in scopes {
                            li { code { (app) "/" (scope) } }
                        }
                    }
                }
            }
        }
    }
}

/// The uuid every address in the header resolves to, or `None` when the file has no row for any of
/// them. `Err` when they do not all resolve to the same one.
///
/// A stranger is `Ok(None)`, and reaches the page: the `authenticated` scope admits identities the
/// file has never heard of, and "bb-auth knows nothing about you" is a fact about the caller that
/// the page is the right place to say.
fn account_uuid_of<'a>(access: &'a Access, ids: &[String]) -> Result<Option<&'a str>, ()> {
    let mut found: Option<&str> = None;
    for id in ids {
        if let Some(u) = access.uuid_of(id) {
            match found {
                // Two addresses of one row name one uuid, and that is the ordinary case.
                Some(seen) if seen == u => {}
                Some(_) => return Err(()),
                None => found = Some(u),
            }
        }
    }
    Ok(found)
}

/// Answer one request under the self-service prefix.
///
/// The order is the console's own, and for the console's own reasons: the proxy secret has already
/// been proved by the caller here, so the first thing this does is read the identity, and the
/// `denied` veto is checked **ahead** of the row resolution that decides `500` vs `200`. The gate
/// refuses a vetoed identity before it reaches this page, so this is the second lock for a file
/// edited mid-request, and a lock a caller escapes by sending *less* is not a lock.
///
/// `web.admins` is never read. An administrator here is one more person acting on their own
/// account, and a list in the settings file must not become a second, invisible way to be granted
/// something on a page whose whole subject is the access file.
fn handle_account(
    req: Request,
    cfg: &Config,
    path: &str,
    query: &str,
    lang_pref: LangPref,
    lang: Lang,
    theme: UiTheme,
) {
    // The page's own URL: the prefix plus a slash. The form's `action` and the target of a
    // preference redirect are both this, and the bare prefix is answered as the page too, so
    // `/account` and `/account/` are one page rather than a page and a redirect.
    let page = format!("{}/", cfg.account_path);
    // The delete row's target (§13.30 §1). The row exists only where an intake is wired, because
    // it is the door to the worker: a deployment that never wired one shows nobody a door to
    // nothing, and this path stays the ordinary `404` every unknown path under the prefix gets.
    let delete_path = cfg
        .delete_intake
        .as_ref()
        .map(|_| format!("{}/delete", cfg.account_path));
    // The keys prefix, and the mint's `POST` target. A path and not a query flag because a
    // mutation is a `POST` to a URL that names the mutation, exactly as every console route does,
    // and because the keys section's form has to name it in its `action`.
    let keys = format!("{}/keys", cfg.account_path);
    // The two mutations every key of the caller's carries, one path below the mint's, each
    // naming its own verb for the same reason every console route does.
    let rotate = format!("{keys}/rotate");
    let remove = format!("{keys}/remove");
    // The mint row is a page of its own (§13.16): the keys section with one more row.
    let new_key = format!("{keys}/new");
    // The profile edit (§13.22) and its interface (§13.23): the panel with fields instead of
    // text, the `POST` target of those fields, and the code step the code page posts to. Each is
    // a path because each is a mutation with its own verb, exactly as every console route is.
    let profile = format!("{}/profile", cfg.account_path);
    let code = format!("{profile}/code");
    let posting = *req.method() == Method::Post;
    // The bar's identity starts empty and is filled as the facts behind it are read: the
    // address once nginx has named somebody, the given name once the settings say which
    // header carries it. A page answered before any of that (the `404`, the `401`) shows no
    // name, because there is nobody to name.
    let mut prefs = AccountPrefs {
        lang,
        lang_pref,
        theme,
        page: &page,
        who: None,
        logout: cfg.account_logout_url.as_deref(),
        delete: delete_path.as_deref(),
        page_lede: false,
    };
    // Below the prefix, only the page, the profile edit, the three key mutations and the delete
    // confirmation exist. A path that is nothing is a `404` for every caller alike, administrator
    // included, because a page that answers a stranger `403` and an administrator `404` is a page
    // describing its own layout to whoever asks. The confirmation is on the list only where an
    // intake is wired, so a deployment that never wired one answers its URL as the ordinary
    // nothing (§13.29 W2).
    if path != cfg.account_path
        && path != page
        && path != keys
        && path != rotate
        && path != remove
        && path != new_key
        && path != profile
        && path != code
        && delete_path.as_deref() != Some(path)
    {
        respond_account(
            req,
            404,
            &prefs,
            t(lang, K::NotFoundTitle),
            html! { p { (t(lang, K::NotFoundBody)) } },
            AccountLook::default(),
            false,
        );
        return;
    }
    // Identity comes from nginx and from nowhere else, exactly as it does for the console: a
    // missing header is a broken deployment, not an anonymous visitor, and this page's whole
    // subject is a person, so there is nothing to render without one.
    let raw = match header_value(&req, IDENTITY_HEADER) {
        Some(e) if !e.trim().is_empty() => e.to_string(),
        _ => {
            // The built-in look, and here there is no other: the settings have not been read, and
            // a request with no identity at all is not going to reach them.
            respond_account(
                req,
                401,
                &prefs,
                t(lang, K::NoIdentityTitle),
                html! { p { (t(lang, K::NoIdentityBody)) } },
                AccountLook::default(),
                false,
            );
            return;
        }
    };
    // The header is a list, not one address: the gate puts **every** email of the roster row into
    // it, joined by a single space. Every one of them is shown, because the page is about the
    // identity the estate handed over, not about one address picked out of it.
    let ids: Vec<String> = raw.split_ascii_whitespace().map(norm_email).collect();
    // The bar can name this person now, the address alone: the given name needs the settings.
    prefs.who = Some(who(None, &raw));
    // A preference is applied before anything is rendered, so the page a person lands on after a
    // submit is in the language and the appearance they just picked. `None` for a value nobody
    // recognises, which is what makes an unrecognised value set no cookie and leave the page as it
    // was.
    let want_theme = query_param(query, THEME_COOKIE).and_then(|v| parse_theme(&v));
    let want_lang = query_param(query, LANG_COOKIE).and_then(|v| parse_lang_pref(&v));
    if want_theme.is_some() || want_lang.is_some() {
        respond_account_preferences(req, &page, want_theme, want_lang);
        return;
    }
    // The settings, fresh off disk, for the same reason the console reads them per request: the
    // `ui` section is what makes one save restyle every surface of the estate at once.
    let settings = match open_settings_file(&cfg.settings_path) {
        Ok((_, s)) => s,
        Err(e) => {
            respond_account(
                req,
                500,
                &prefs,
                t(lang, K::FileErrorTitle),
                html! { p { (e) } },
                AccountLook::default(),
                false,
            );
            return;
        }
    };
    // The given name the bar shows, by the console's rule: it exists only where the deployment
    // configures the claim, since the settings are what say which header the proxy was told to
    // fill, and it is percent-decoded because the gate sends a profile value encoded.
    let given = settings
        .profile_claims
        .iter()
        .find(|c| c.claim == "given_name")
        .and_then(|c| header_value(&req, &c.header))
        .map(pct_decode);
    prefs.who = Some(who(given.as_deref(), &raw));
    let look = AccountLook {
        theme: settings.theme,
        stylesheet: settings.stylesheet_url.as_deref(),
        logo: settings.logo_url.as_deref(),
        brand: settings.brand_name.as_deref(),
    };
    // `gate.identity_attrs` without `email` means nginx injects no `X-Auth-Email`, so there is no
    // identity for this page to act on. The page names the setting, because the operator reading it
    // is the only person who can fix it.
    if !settings.identity_attrs.iter().any(|a| a.attr == "email") {
        respond_account(
            req,
            500,
            &prefs,
            t(lang, K::AccountNoEmailTitle),
            html! { p { (t(lang, K::AccountNoEmailBody)) } },
            look,
            false,
        );
        return;
    }
    // The access file, fresh off disk too: this page answers "what may I do", and an answer cached
    // from an earlier request is an answer about a file that is not the one the gate is enforcing.
    let (doc, access) = match open_access_file(&cfg.access_path) {
        Ok(pair) => pair,
        Err(e) => {
            respond_account(
                req,
                500,
                &prefs,
                t(lang, K::FileErrorTitle),
                html! { p { (e) } },
                look,
                false,
            );
            return;
        }
    };
    // The veto, ahead of everything the file has to say about grants.
    if ids.iter().any(|e| access.vetoes_identifier(e)) {
        respond_account(
            req,
            403,
            &prefs,
            t(lang, K::AccountVetoTitle),
            html! { p { (t(lang, K::AccountVetoBody)) } },
            look,
            false,
        );
        return;
    }
    // Every address in the header has to resolve to the **same** row. The gate builds the header
    // out of one row's emails, so several values that resolve to different rows is nginx having
    // written one header for two people, and there is no page that is about both.
    let uuid = match account_uuid_of(&access, &ids) {
        Ok(u) => u,
        Err(()) => {
            respond_account(
                req,
                500,
                &prefs,
                t(lang, K::AccountAmbiguousTitle),
                html! { p { (t(lang, K::AccountAmbiguousBody)) } },
                look,
                false,
            );
            return;
        }
    };
    // The mint, the one mutation this page offers, and the reason the file's exact bytes are
    // kept: the form's `rev` is the fingerprint of the file as this page renders it, the same
    // lost-update guard every console form carries.
    let bytes = match std::fs::read_to_string(&cfg.access_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            let msg = format!("read {}: {e}", cfg.access_path);
            respond_account(
                req,
                500,
                &prefs,
                t(lang, K::FileErrorTitle),
                html! { p { (msg) } },
                look,
                false,
            );
            return;
        }
    };
    let rev = sha256_hex(&bytes);
    // The facts the page is built out of, for a `GET` and for a `POST` alike: the profile
    // submission answers with the page around its form, and the panel that holds the form is
    // part of that page, so it needs the same facts the `GET` showed.
    let own = account_own(
        &doc, &access, &settings, &req, &ids, uuid, &keys, &rev, &page, &profile,
    );
    // A `POST` to one of the key paths, or to the profile edit, is answered here: after the
    // proxy secret, the identity, the veto and the row resolution, because each of those is a
    // refusal this submission has to meet on the same terms as the `GET` that rendered its form.
    if posting {
        if path == code {
            account_profile_code_post(req, cfg, &mut prefs, lang, look, &settings, &profile, &page);
            return;
        }
        if path == profile {
            account_profile_post(
                req, cfg, &mut prefs, lang, look, &settings, &ids, uuid, &own, &profile, &page,
            );
            return;
        }
        // The delete `POST` is claimed here for the same reason the mint guard was: every path
        // this branch does not claim is the mint below, and a submission to the delete URL that
        // fell through would mint an API key on the page that asks to delete the row.
        if delete_path.as_deref() == Some(path) {
            account_delete_post(
                req,
                cfg,
                &mut prefs,
                lang,
                look,
                &ids,
                uuid,
                &own,
                &settings,
                cfg.delete_intake.as_deref(),
                path,
                &page,
                &rev,
            );
            return;
        }
        let op = if path == rotate {
            AccountKeyOp::Rotate
        } else if path == remove {
            AccountKeyOp::Remove
        } else {
            AccountKeyOp::Mint
        };
        account_key_post(
            req, cfg, &prefs, lang, look, uuid, op, &settings, &ids, &keys, &profile,
        );
        return;
    }
    // The three pages that are about one key or one row exist for a caller with a row, and a
    // stranger gets the page's own refusal for them, exactly as the mutations give it.
    let wants_row = path == new_key || path == rotate || path == remove;
    if wants_row && uuid.is_none() {
        respond_account(
            req,
            403,
            &prefs,
            t(lang, K::AccountNoRowTitle),
            html! { p { (t(lang, K::AccountNoRowBody)) } },
            look,
            false,
        );
        return;
    }
    if path == rotate || path == remove {
        // The caller's own row only, and every miss is one `404` that names nothing: an unknown
        // id, no id at all and a key filed under somebody else are the same answer, so the page
        // is not an oracle for which ids exist on the estate.
        let id = query_param(query, "id").unwrap_or_default();
        if !own.keys.iter().any(|k| k.id.trim() == id) {
            respond_account(
                req,
                404,
                &prefs,
                t(lang, K::NotFoundTitle),
                html! { p { (t(lang, K::NotFoundBody)) } },
                look,
                false,
            );
            return;
        }
        let op = if path == rotate {
            AccountKeyOp::Rotate
        } else {
            AccountKeyOp::Remove
        };
        respond_account(
            req,
            200,
            &prefs,
            // The action word as the page title, so the shell's one `h1` and the `<title>` both
            // name what is about to happen, as the console's confirmation does (§13.17).
            t(lang, op.title()),
            page_account_confirm(lang, &page, &keys, &rev, &id, op),
            look,
            false,
        );
        return;
    }
    // The delete confirmation (§13.30 §2). It answers a caller with no roster row too, because the
    // sign-in accounts are theirs and are what the worker deletes, so it is not on the list of
    // paths that need a row. The page writes nothing and calls nothing: the intake is asked on the
    // `POST`, after the typed address and the `rev` (§13.29 W3).
    if delete_path.as_deref() == Some(path) {
        // The page carries its own lede (the irreversibility statement), so the bar's menu keeps
        // the identity out: the design counts one `p.lede` per page (§13.23 §3, §4).
        prefs.page_lede = true;
        respond_account(
            req,
            200,
            &prefs,
            t(lang, K::AccountDeleteTitle),
            page_account_delete(
                lang,
                path,
                &page,
                &rev,
                uuid,
                &ids,
                &own,
                &settings.audit_policy,
                "",
                None,
            ),
            look,
            false,
        );
        return;
    }
    // The edit form rides on one page only: `<prefix>/profile` is the panel with fields, and
    // every other page under the prefix shows the panel as read-only text (§13.22). A session the
    // gate named no Cognito user for gets the read-only panel on that path too (§13.25): the form
    // acts on one Cognito user, and a page with no user to act on is not an edit page, so its
    // title says the same thing the panel says.
    let form = (path == profile && own.native).then(|| ProfileForm::open(&settings, &req));
    respond_account(
        req,
        200,
        &prefs,
        if form.is_some() {
            t(lang, K::AccountProfileEdit)
        } else {
            t(lang, K::AccountTitle)
        },
        page_account(
            lang,
            &ids,
            uuid,
            &own,
            (path == new_key).then_some(&NewKeyRow::OPEN),
            form.as_ref(),
        ),
        look,
        false,
    );
}

/// The longest value this page accepts for one claim, and the `maxlength` the field says.
///
/// One constant for both, because a field that lets a person type more than the server will
/// accept is a field that sets them up to be refused.
const PROFILE_VALUE_MAX: usize = 2048;

/// The longest code this page accepts, and the `maxlength` the field says. Cognito's email OTP is
/// 6 digits; the room is for a pool configured with a longer one, and the field's own bound is
/// what stops a paste of a whole email landing in the API call.
const PROFILE_CODE_MAX: usize = 32;

/// The code as the pool must receive it: `None` for anything that cannot be a code.
///
/// Whitespace goes first, because a pasted `123 456` is the same code typed twice (§13.23 §3), and
/// a browser `pattern` would refuse the space the server can simply drop. What is left must be
/// ASCII letters and digits, 1 to 16: a code is a short alphanumeric string, and a value that is
/// not one is a hand-made form, not a person with a code.
fn profile_code(code: &str) -> Option<String> {
    let clean: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() <= 16 && !clean.is_empty() && clean.chars().all(|c| c.is_ascii_alphanumeric()) {
        Some(clean)
    } else {
        None
    }
}

/// The claims the profile form puts a field for, in the order the OIDC profile document
/// lists them (§13.22).
///
/// These are the claims Cognito keeps as user-pool attributes, so the update step
/// (`UpdateUserAttributes`, slice 5c) accepts them; a claim outside this list is refused on
/// the way in, because a field the directory will not store is a field that cannot save, and a
/// field that cannot save is worse than no field at all. `preferred_username` is absent on
/// purpose: it is the sign-in name, and changing it changes who the person is, which is not
/// what this page is for.
const PROFILE_EDITABLE: [&str; 12] = [
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
];

/// The word a claim is shown under, and `None` when the design names no word for it.
///
/// One function for the form's label, the change summary's name and the read-only panel's
/// name, because the panel and the form must never call one field by two names: a person who
/// read "Given name" on the panel is entitled to read it on the field they type into. A claim
/// with no word keeps its own name, in `code`, which is the file's vocabulary and the honest
/// answer for a name nobody translated.
fn profile_label(lang: Lang, claim: &str) -> Option<String> {
    let key = match claim {
        "name" => K::AttrName,
        "given_name" => K::AttrGivenName,
        "family_name" => K::AttrFamilyName,
        "middle_name" => K::AttrMiddleName,
        "nickname" => K::AttrNickname,
        "profile" => K::AttrProfile,
        "picture" => K::AttrPicture,
        "website" => K::AttrWebsite,
        "gender" => K::AttrGender,
        "birthdate" => K::AttrBirthdate,
        "zoneinfo" => K::AttrZoneinfo,
        "locale" => K::AttrLocale,
        _ => return None,
    };
    Some(t(lang, key).to_string())
}

/// The configured claims that are editable, in the settings' own order.
///
/// The order is the settings', not the allowlist's, because the operator chose it:
/// `gate.profile_claims` is the list the deployment says it forwards, and the form is a
/// field-for-field version of the panel that shows that list.
fn profile_editable(settings: &Settings) -> Vec<String> {
    settings
        .profile_claims
        .iter()
        .map(|c| c.claim.as_str())
        .filter(|c| PROFILE_EDITABLE.contains(c))
        .map(str::to_string)
        .collect()
}

/// Whether the edit can work at all: a pool to call, a native app client to call it with, and
/// at least one claim worth a field.
///
/// All three, because a form that can only end in an error is a promise the page cannot keep.
/// The pill is absent rather than disabled: a disabled control is skipped by the keyboard and
/// says nothing, and the reason here is a setting, not the person's doing.
fn profile_offered(settings: &Settings) -> bool {
    !settings.issuer.trim().is_empty()
        && !settings.client_id.trim().is_empty()
        && !profile_editable(settings).is_empty()
}

/// The autofill token for a field, as WCAG 1.3.5 asks for one: a name, a birthday and a
/// nickname are values the browser already holds, and a person who has typed them once should
/// not have to type them again. A claim with no token in the HTML spec's vocabulary gets no
/// attribute at all, which leaves the browser guessing nothing.
fn autocomplete_of(claim: &str) -> Option<&'static str> {
    match claim {
        "name" => Some("name"),
        "given_name" => Some("given-name"),
        "family_name" => Some("family-name"),
        "middle_name" => Some("additional-name"),
        "nickname" => Some("nickname"),
        "picture" => Some("photo"),
        "gender" => Some("sex"),
        "birthdate" => Some("bday"),
        _ => None,
    }
}

/// The profile form as one render needs it: the fields, and the one sentence above the form,
/// which is an error, a warning, or nothing.
///
/// A struct and not six arguments because the page that renders it is the page that refused a
/// submission, and every one of these is what the person left on the page: the values they
/// typed, the field that was refused. Deriving that from the request at render time would be a
/// second answer to "what did they submit".
struct ProfileForm {
    /// Each editable claim, with the value its field shows.
    editable: Vec<(String, String)>,
    /// Each configured claim that is not editable, with the value the panel shows it by.
    other: Vec<(String, String)>,
    /// The claim a refusal is attributed to, and the sentence above the form. The sentence
    /// names the field by its visible label, because that is the word the person read.
    err: Option<(String, String)>,
    /// A sentence above the form that is not an error: the values changed nothing.
    warn: Option<String>,
}

impl ProfileForm {
    /// The form as the page shows it before anyone has typed anything: every editable claim
    /// prefilled with the value the proxy forwarded.
    fn open(settings: &Settings, req: &Request) -> ProfileForm {
        let (editable, other) = profile_split(settings, req, &profile_editable(settings), None);
        ProfileForm {
            editable,
            other,
            err: None,
            warn: None,
        }
    }

    /// The form as it comes back after a refusal: the values as posted, and the sentence. A
    /// person who typed a name is not being asked to type it again.
    fn again(
        settings: &Settings,
        req: &Request,
        form: &Form,
        err: Option<(String, String)>,
        warn: Option<String>,
    ) -> ProfileForm {
        let (editable, other) =
            profile_split(settings, req, &profile_editable(settings), Some(form));
        ProfileForm {
            editable,
            other,
            err,
            warn,
        }
    }
}

/// The two lists of claims the edit page shows, from the settings, the forwarded values and
/// (after a refusal) what was posted: the editable ones as fields, the rest as read-only text.
///
/// `posted` is the submission whose values the fields must show; `None` is the first render,
/// where every field holds what the proxy forwarded.
///
/// The two lists are a pair of `(claim, value)` vectors, which is exactly what the form and
/// the read-only list consume; naming that pair would say less than the tuple does, so
/// clippy's `type_complexity` is answered here rather than with an alias.
#[allow(clippy::type_complexity)]
fn profile_split(
    settings: &Settings,
    req: &Request,
    editable_claims: &[String],
    posted: Option<&Form>,
) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let mut editable = Vec::new();
    let mut other = Vec::new();
    for c in &settings.profile_claims {
        let value = forwarded_claim(req, &c.header);
        if editable_claims.iter().any(|e| e == &c.claim) {
            editable.push((
                c.claim.clone(),
                match posted {
                    Some(f) if f.0.iter().any(|(k, _)| k == &c.claim) => {
                        f.get(&c.claim).to_string()
                    }
                    _ => value,
                },
            ));
        } else {
            other.push((c.claim.clone(), value));
        }
    }
    (editable, other)
}

/// The value the proxy forwarded for one derived header, percent-decoded, `""` for none.
fn forwarded_claim(req: &Request, header: &str) -> String {
    header_value(req, header)
        .map(pct_decode)
        .unwrap_or_default()
}

/// The edit form (§13.23 §2). Every field is a `label` that wraps its input, so the name is
/// the click target too, and the value is prefilled, because a person correcting a name is
/// correcting one word and not retyping the rest.
///
/// Nothing here names an address (§13.26 §4). The code goes to the Cognito user the session
/// **is** (§13.25), which is a name the person did not type and cannot choose, so there is
/// nothing to pick: the "Send the code to" line, its `select` and its hidden `email` are gone,
/// and a posted `email` is refused as a non-editable name. What stays is the sentence that says
/// why the email is not a field, after the fields, where a person who is looking for it reads it.
fn profile_form(lang: Lang, f: &ProfileForm, action: &str, page: &str) -> Markup {
    // Each editable claim as the shared field, in **prose** mode (§13.26): a person's name
    // keeps the browser's capitalisation and its spell check, which the console's field drops
    // because a URL, a header name and a key id have neither.
    let mut fields: Vec<Markup> = Vec::new();
    for (claim, value) in &f.editable {
        let label = profile_label(lang, claim).unwrap_or_else(|| claim.clone());
        // Where there is something to remove, the page says so before the person finds it by
        // submitting: emptying a field is a removal, not a no-op.
        let mut hints: Vec<&str> = Vec::new();
        if !value.is_empty() {
            hints.push(t(lang, K::AccountProfileClearDeletes));
        }
        if claim == "birthdate" {
            hints.push(t(lang, K::AccountProfileDateHint));
        }
        fields.push(text_field_with(
            &label,
            claim,
            value,
            "",
            &hints,
            f.err.as_ref().is_some_and(|(c, _)| c == claim),
            FieldOpts {
                class: Some("f-profile"),
                maxlength: Some(PROFILE_VALUE_MAX),
                autocomplete: autocomplete_of(claim),
                // The first text field is the one the page focuses, and only it: two
                // `autofocus` on one page is no focus at all.
                autofocus: f.editable.first().is_some_and(|(c, _)| c == claim),
                prose: true,
                ..FieldOpts::default()
            },
        ));
    }
    html! {
        form class="edit" method="post" action=(action) {
            // The console's shape in this page's shell: the sentence above the form, and the
            // field it names marked for assistive tech and not only coloured. The box carries
            // [`ERR_ID`], the id every form's message box carries on both surfaces, so the
            // `aria-describedby` the shared field writes points at something here too.
            @if let Some((_, msg)) = &f.err {
                div class="err" id=(ERR_ID) { (msg) }
            }
            @if let Some(msg) = &f.warn {
                div class="msg warn" { (msg) }
            }
            @for field in &fields { (field) }
            // Configured and not editable: shown as the read-only panel shows them, so the page
            // a person is editing says everything the page they came from said.
            @if !f.other.is_empty() {
                ul class="plain" {
                    @for (claim, value) in &f.other {
                        li {
                            @if let Some(word) = profile_label(lang, claim) {
                                (word)
                            } @else {
                                code { (claim) }
                            }
                            ": "
                            @if value.is_empty() {
                                span class="muted" { (t(lang, K::AccountNotProvided)) }
                            } @else {
                                (value)
                            }
                        }
                    }
                }
            }
            // Said after the fields, because this is the page of the person who was looking for
            // an email field and did not find one: the address is how they sign in, so it is not
            // a field here, and the sentence that says so belongs where their eye lands.
            p class="muted" { (t(lang, K::AccountProfileEmailFixed)) }
            p class="actions" {
                button type="submit" { (t(lang, K::AccountProfileSendCode)) }
                (pill_link(page, t(lang, K::Cancel)))
            }
        }
    }
}

/// One line of the change summary: the claim, what it was, what it becomes. `after` is `None`
/// for a removal, which is the case that has to be a word and not an empty box.
struct ProfileChange {
    claim: String,
    before: Option<String>,
    after: Option<String>,
}

/// What the code page carries, and what its two forms post.
///
/// The two field lists are separate on purpose. `carry` is the code step's: the `Session` and one
/// entry per changed claim, which is everything the step needs to answer the challenge and write
/// the attributes. `resend` is the start's: the changed claims, **never** the `Session`, because
/// "send a new code" is starting over and a page holding two sessions would be two answers to
/// which code the field belongs to. Neither carries a username (§13.25 step 2): the code step
/// answers for the user of the request that arrives, named by the gate's header.
struct ProfileCode<'a> {
    /// The masked address Cognito said it sent to, as the challenge named it, and `None` when the
    /// pool did not name one. Shown only when [`code_destination`] accepts it.
    destination: Option<&'a str>,
    changes: &'a [ProfileChange],
    carry: &'a [(String, String)],
    resend: &'a [(String, String)],
    /// The sentence above the change list when the code just was not right, and the field it
    /// marks. Nothing on the page says why the code was wrong beyond this: Cognito's own words
    /// are a sentence written for an AWS console.
    err: Option<&'a str>,
}

/// The masked destination the pool named, when it is a value this page may put on a page.
///
/// It is the provider's word, not the person's, and it arrives in a response body: a value that
/// is not printable ASCII has no business in a document, and one with a space in it is not an
/// address-shaped mask (Cognito's own mask is `t***@e***`). The bound is the length a mask can
/// plausibly be, and a value over it is a provider saying something this page cannot lay out.
/// Anything rejected is simply not named: the generic sentence says everything the page knows,
/// and a page that shows a raw address it was handed would be a page leaking somebody's address
/// through a field meant to mask it.
fn code_destination(destination: Option<&str>) -> Option<&str> {
    destination
        .map(str::trim)
        .filter(|d| !d.is_empty() && d.chars().count() <= 254)
        .filter(|d| d.chars().all(|c| c.is_ascii_graphic()))
}

/// The page that asks for the code (§13.23 §3, §13.26 §4): the masked address it went to, the
/// clock as a number, the changes as they will be described back, the code field, and a way to
/// start over.
///
/// The `Session` rides in a hidden field and nowhere else: this is a form, not a server-side
/// transaction, and a person who opens two tabs holds two independent codes.
fn page_profile_code(
    lang: Lang,
    c: &ProfileCode,
    profile_path: &str,
    code_path: &str,
    page: &str,
) -> Markup {
    html! {
        p class="lede" {
            @if let Some(dest) = code_destination(c.destination) {
                (t(lang, K::AccountProfileCodeSent)) " "
                code { (dest) }
                "." " " (t(lang, K::AccountProfileCodeLasts))
            } @else {
                // The pool named no address, so the page says what it knows and no more: the code
                // went to the address the account signs in with. It invents nothing, because the
                // address the pool writes to is the pool's, and on a pool whose `email` and
                // `username` differ the address this page could invent is not the one used.
                (t(lang, K::AccountProfileCodeSentNoDest)) " "
                (t(lang, K::AccountProfileCodeLasts))
            }
        }
        // The card, as the confirmations wear theirs: the summary and the field are one act, and
        // the shell has already rendered the act's name as the page's one heading.
        div class="card" {
            @if let Some(msg) = c.err {
                // Inside the card and above the summary: the person is reading this page again,
                // and the first thing they need to know is that this attempt did not work.
                div class="err" id="err" { (msg) }
            }
            p class="lbl" { (t(lang, K::AccountProfileChanges)) }
            ul class="plain changes" {
                @for ch in c.changes {
                    li {
                        (profile_label(lang, &ch.claim).unwrap_or_else(|| ch.claim.clone())) ": "
                        @if let Some(after) = &ch.after {
                            strong { (after) }
                            // An attribute that had no value has no `was` part: there is nothing
                            // to say it was.
                            @if let Some(before) = &ch.before {
                                " " (t(lang, K::AccountProfileWas)) " " code { (before) }
                            }
                        } @else {
                            // A removal is a word, not strike-through: `s` is not announced by
                            // most screen readers, and this is the deletion the person must
                            // confirm before it happens. `warn` and not `bad`: it is what they
                            // asked for, so it is pointed out, not alarmed about.
                            span class="tag warn" { (t(lang, K::AccountProfileRemoved)) }
                            " " (t(lang, K::AccountProfileWas)) " "
                            code { (ch.before.clone().unwrap_or_default()) }
                        }
                    }
                }
            }
            form class="edit" method="post" action=(code_path) {
                @for (name, value) in c.carry {
                    input type="hidden" name=(name) value=(value);
                }
                label {
                    span class="lbl" { (t(lang, K::AccountProfileCodeLabel)) }
                    // A text field with `inputmode="numeric"`, not a `number` field: a code is
                    // digits, and a `number` field brings a spinner and a locale-dependent
                    // decimal separator to a value that is never a number. `one-time-code` is
                    // what lets the browser fill it from the message it arrived in. **No
                    // `pattern`**: a pasted `123 456` would be blocked by the browser for a
                    // space the server simply strips.
                    //
                    // The value is never put back: a code that was refused is not worth typing
                    // again, and a field holding one invites a submit of the same answer. The
                    // focus does not move here either, on a page that is being read again: it
                    // stays where the reader's eye is, which is the summary above.
                    input class="f-code" name="code" type="text" inputmode="numeric"
                          autocomplete="one-time-code" autocapitalize="off" spellcheck="false"
                          required maxlength=(PROFILE_CODE_MAX)
                          autofocus=[(c.err.is_none()).then(|| "true")]
                          aria-invalid=[c.err.is_some().then_some("true")]
                          aria-describedby=[c.err.is_some().then_some("err")];
                }
                div class="actions" {
                    button type="submit" { (t(lang, K::AccountProfileSave)) }
                    (pill_link(page, t(lang, K::Cancel)))
                }
            }
        }
        // Resend is starting over, and says so by being the start's own form: the changed values,
        // never the `Session`, posted back to the start.
        form class="edit" method="post" action=(profile_path) {
            @for (name, value) in c.resend {
                input type="hidden" name=(name) value=(value);
            }
            p class="muted" { (t(lang, K::AccountProfileNoCode)) }
            div class="actions" {
                button type="submit" class="pill" { (t(lang, K::AccountProfileSendNew)) }
            }
        }
    }
}

/// The page a save lands on (§13.23 §4): the `h1` says it worked, the lede names what changed in
/// the same words the form used, and says before the person sees it that the account page still
/// shows the old values.
///
/// The panel is drawn from what the proxy forwarded at sign-in, so "back" lands on the values
/// that were there before. Saying so here is the difference between a save that reads as a save
/// and one that reads as a failure.
fn page_profile_saved(lang: Lang, changes: &[ProfileChange], page: &str) -> Markup {
    let names: Vec<String> = changes
        .iter()
        .map(|c| profile_label(lang, &c.claim).unwrap_or_else(|| c.claim.clone()))
        .collect();
    html! {
        p class="lede" {
            (t(lang, K::AccountProfileSavedLead)) " " (names.join(", ")) ". "
            (t(lang, K::AccountProfileSavedBody))
        }
        p class="primary" {
            (back_link(lang, page))
        }
    }
}

/// The page a start that did not work ends on: the `h1` says the profile was not saved, the
/// lede says why, and a way back is the only action.
///
/// Cognito's own `message` is never on the page. It is a sentence written for an AWS console, it
/// repeats the address back, and for the cases that mean "this account cannot sign in this way"
/// it is a string the person has no vocabulary for. The status is the operator's diagnostic; the
/// words are the person's.
fn page_profile_outcome(
    lang: Lang,
    key: K,
    resend: Option<&[(String, String)]>,
    profile_path: &str,
    page: &str,
) -> Markup {
    html! {
        p class="lede" { (t(lang, key)) }
        @if let Some(fields) = resend {
            // Only the case that timed out offers a new code: the pool may have taken the
            // request, so the honest answer is "ask again", and asking again is the same start.
            // A refusal that named the account has nothing to resend. The button is the primary
            // action here, because on this page it is the way forward.
            form class="edit" method="post" action=(profile_path) {
                @for (name, value) in fields {
                    input type="hidden" name=(name) value=(value);
                }
                div class="actions" {
                    button type="submit" { (t(lang, K::AccountProfileSendNew)) }
                    (back_link(lang, page))
                }
            }
        } @else {
            p class="primary" {
                (back_link(lang, page))
            }
        }
    }
}

/// How a call to Cognito's API ended, when it did not produce a code.
enum CognitoError {
    /// The endpoint answered, and the answer is not a code. The key is which of §13.23 §4's
    /// sentences to show; the status is the operator's, and the line is whether the pool was
    /// reached: a refusal the pool means is a `502` (an upstream said no), a pool that never
    /// answered is a `504`.
    Refused(K, u16),
    /// No answer within the bound.
    NoAnswer,
}

/// Where this deployment's Cognito API lives: the endpoint a test named, else the origin of the
/// issuer the settings name.
///
/// The fake is a `Config` field and not an environment variable, and that is the whole
/// argument: an env var is a setting a deployment can point at a host of its choosing, and the
/// only thing a test needs is a host on loopback. `compile_issuer` is https-only, so the real
/// answer can only ever be an https origin, and a plain-HTTP loopback URL cannot be expressed as
/// a setting at all.
fn cognito_endpoint_of(cfg: &Config, settings: &Settings) -> String {
    match cfg.cognito_endpoint.as_deref() {
        Some(e) => e.to_string(),
        None => settings.cognito_endpoint(),
    }
}

/// What the pool's API answered when it answered at all.
enum CognitoReply {
    /// A status that means "done", and the JSON body it came with.
    Ok(serde_json::Value),
    /// A status that means "no". The body is kept, because the `Session` a rejected code comes
    /// back with is in it, and the code page needs that to stay the same page.
    Error(serde_json::Value),
}

/// The reason a refusal carries: `__type` is `"TooManyRequestsException"` or
/// `"com.amazonaws.cognito#UserNotFoundException"`, and the reason is after the last `#`.
fn cognito_error_name(body: &serde_json::Value) -> String {
    body.get("__type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .rsplit('#')
        .next()
        .unwrap_or("")
        .to_string()
}

/// One call to Cognito's API (§13.22): the JSON 1.1 envelope every operation of it uses, the
/// operation named in `X-Amz-Target`, and the endpoint this deployment's issuer names.
///
/// No `ClientSecret` and no `SECRET_HASH`: the client this flow uses is a public client, the
/// same one the browser's sign-in page uses, and a secret is exactly what a binary that ships to
/// a browser does not have.
///
/// One attempt, and the bound is the whole wait. `http_status_as_error(false)` because a `400`
/// from this API is a named reason, and the reason is what the person is told;
/// `max_redirects(0)` because a redirect from a managed API is not a step this code takes, and
/// following one would hand a code, an address and a session to a host the settings never named.
/// Nothing that comes back is logged: the response carries the `Session`, and where it answers
/// with an `AuthenticationResult` it carries tokens.
fn cognito_post(
    cfg: &Config,
    settings: &Settings,
    target: &str,
    payload: &serde_json::Value,
) -> Result<CognitoReply, CognitoError> {
    let endpoint = cognito_endpoint_of(cfg, settings);
    if endpoint.is_empty() {
        return Err(CognitoError::Refused(K::AccountProfileRefused, 502));
    }
    let agent = ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(cfg.cognito_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    );
    let response = match agent
        .post(&endpoint)
        .header("X-Amz-Target", target)
        .header("Content-Type", "application/x-amz-json-1.1")
        .send(payload.to_string())
    {
        Ok(r) => r,
        Err(ureq::Error::Timeout(_)) => return Err(CognitoError::NoAnswer),
        Err(_) => return Err(CognitoError::Refused(K::AccountProfileRefused, 502)),
    };
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let text = body.read_to_string().unwrap_or_default();
    // A body that is not JSON is an answer this code cannot read, and the two callers read a
    // refusal by name and a success by field: an empty object answers both as "no".
    let value =
        serde_json::from_str::<serde_json::Value>(&text).unwrap_or_else(|_| serde_json::json!({}));
    if (200..300).contains(&status) {
        Ok(CognitoReply::Ok(value))
    } else {
        Ok(CognitoReply::Error(value))
    }
}

/// Ask Cognito for an email code for **the session's own user** (§13.22's one call, §13.25
/// step 1): `USER_AUTH`, the native app client from the settings, and
/// `PREFERRED_CHALLENGE=EMAIL_OTP`.
///
/// `username` is the gate's `X-Auth-Native-Username`, never an address and never a posted field.
/// That is the whole point of the shape: the pool resolves a `USERNAME` to one of its users, and
/// the only name that is guaranteed to be *this* session's user is the one the session's own
/// token carried. An address is not that name, and on a pool whose users' `email` and
/// `username` differ it is a different user or nobody. The body carries no `SECRET_HASH` and no
/// `ClientSecret` for the same reason the login page carries none: this is a public native
/// client, and a secret here would be a secret shipped to a binary a browser can read.
///
/// The answer is the `Session` to answer with, the masked address the code went to
/// (`CODE_DELIVERY_DESTINATION`, shown on the code page), and the `USERNAME` the challenge named
/// (`ChallengeParameters.USERNAME`). The third is the pool saying which of its users it is
/// asking: a pool that names one **other** than the user it was asked about has answered for
/// somebody else, and that is a refusal here, at the start, before a code reaches anybody's
/// mailbox on someone's behalf.
fn cognito_call(
    cfg: &Config,
    settings: &Settings,
    username: &str,
) -> Result<(String, Option<String>, String), CognitoError> {
    let payload = serde_json::json!({
        "AuthFlow": "USER_AUTH",
        "ClientId": settings.client_id,
        "AuthParameters": {
            "USERNAME": username,
            "PREFERRED_CHALLENGE": "EMAIL_OTP",
        },
    });
    let value = match cognito_post(
        cfg,
        settings,
        "AWSCognitoIdentityProviderService.InitiateAuth",
        &payload,
    )? {
        CognitoReply::Error(body) => {
            return Err(match cognito_error_name(&body).as_str() {
                // The pool has no such user, or has one it will not sign in. Both mean the same
                // thing to the person: the account this session signed in with is not one the
                // pool will send a code to, and signing out and in again is the way to find out
                // what happened.
                "UserNotFoundException"
                | "UserNotConfirmedException"
                | "NotAuthorizedException"
                | "CodeDeliveryFailureException" => {
                    CognitoError::Refused(K::AccountProfileNoUser, 400)
                }
                "TooManyRequestsException" | "LimitExceededException" => {
                    CognitoError::Refused(K::AccountProfileTooMany, 502)
                }
                _ => CognitoError::Refused(K::AccountProfileRefused, 502),
            });
        }
        CognitoReply::Ok(value) => value,
    };
    // A pool that hands back tokens at once is a pool that did not do what was asked: the
    // request was for a code, and these are not this page's to keep. They are dropped here, and
    // they reach no page, no header and no log line.
    if value.get("AuthenticationResult").is_some() {
        return Err(CognitoError::Refused(K::AccountProfileRefused, 502));
    }
    if value.get("ChallengeName").and_then(|v| v.as_str()) != Some("EMAIL_OTP") {
        return Err(CognitoError::Refused(K::AccountProfileRefused, 502));
    }
    let params = value.get("ChallengeParameters");
    // The username the challenge names, when it names one. A pool that names none is answering
    // about the user it was asked about, which is the name this call already holds.
    let named = params
        .and_then(|p| p.get("USERNAME"))
        .and_then(|v| v.as_str())
        .filter(|u| !u.trim().is_empty())
        .map(|u| u.trim().to_string());
    if let Some(named) = &named {
        if named != username {
            // The pool answered for a different account. Nothing is sent on, and the other
            // account is not named on the page: this is a shared surface, and a refusal that
            // says which user the pool reached is an oracle for anybody with any account.
            return Err(CognitoError::Refused(K::AccountProfileNotYours, 403));
        }
    }
    match value.get("Session").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => Ok((
            s.to_string(),
            params
                .and_then(|p| p.get("CODE_DELIVERY_DESTINATION"))
                .and_then(|v| v.as_str())
                .filter(|d| !d.trim().is_empty())
                .map(|d| d.to_string()),
            named.unwrap_or_else(|| username.to_string()),
        )),
        _ => Err(CognitoError::Refused(K::AccountProfileRefused, 502)),
    }
}

/// Answer the `EMAIL_OTP` challenge with the code the person typed (§13.22's second call): the
/// `Session` the challenge carried, the `USERNAME` the challenge named, and the code.
///
/// The username is the pool's own, not the address the form chose: `ChallengeParameters` is the
/// pool telling this page which of its users it is asking, and answering with an address the
/// pool did not name is a request to sign in as somebody else.
///
/// On success the answer is the `AuthenticationResult`, which carries the access token the update
/// step needs. It is returned by value and never stored: no page, header, log line or file sees
/// it (§13.22).
fn cognito_answer(
    cfg: &Config,
    settings: &Settings,
    session: &str,
    username: &str,
    code: &str,
) -> Result<serde_json::Value, CognitoAnswer> {
    let payload = serde_json::json!({
        "ChallengeName": "EMAIL_OTP",
        "ClientId": settings.client_id,
        "Session": session,
        "ChallengeResponses": { "USERNAME": username, "EMAIL_OTP_CODE": code },
    });
    let reply = cognito_post(
        cfg,
        settings,
        "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
        &payload,
    )?;
    match reply {
        CognitoReply::Ok(value) => match value.get("AuthenticationResult") {
            Some(auth) => Ok(auth.clone()),
            None => Err(CognitoAnswer::Refused(K::AccountProfileRefused)),
        },
        CognitoReply::Error(body) => {
            let name = cognito_error_name(&body);
            Err(match name.as_str() {
                // The code the person typed, mistyped. The page that asked for it comes back,
                // with the `Session` this answer carried if it carried one.
                "CodeMismatchException" => CognitoAnswer::WrongCode(
                    body.get("Session")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| s.to_string()),
                ),
                // The code is gone, or the session with it: the only way forward is a new one,
                // which is the same start.
                "ExpiredCodeException"
                | "NotAuthorizedException"
                | "UserNotFoundException"
                | "UserNotConfirmedException" => CognitoAnswer::Expired,
                "TooManyRequestsException" | "LimitExceededException" => {
                    CognitoAnswer::Refused(K::AccountProfileTooMany)
                }
                _ => CognitoAnswer::Refused(K::AccountProfileRefused),
            })
        }
    }
}

/// How the code step ended, when it did not produce an `AuthenticationResult`.
enum CognitoAnswer {
    /// The code was not the one the pool sent. The `Session` to ask again with, when the answer
    /// named a new one.
    WrongCode(Option<String>),
    /// The code, or the session that carried it, is gone: start again.
    Expired,
    /// The page that says why, in §13.23 §4's words.
    Refused(K),
    /// No answer within the bound.
    NoAnswer,
}

/// A call that never reached the pool, or reached it and got nothing readable, is the same
/// refusal at the code step as at the start; only the status is the step's own, and each caller
/// names it.
impl From<CognitoError> for CognitoAnswer {
    fn from(e: CognitoError) -> Self {
        match e {
            CognitoError::NoAnswer => CognitoAnswer::NoAnswer,
            CognitoError::Refused(key, _) => CognitoAnswer::Refused(key),
        }
    }
}

/// Write the attributes the person changed (§13.22's third call): one `UpdateUserAttributes`
/// carries every change, a removal as a blank value, which is what keeps a mixed edit at two
/// calls in the code request rather than three.
///
/// The access token arrives by value from the step that verified the code, and is used here and
/// dropped: it is not this page's to keep, and it reaches no page, header, log line or file.
fn cognito_update(
    cfg: &Config,
    settings: &Settings,
    access: &str,
    changes: &[ProfileChange],
) -> Result<(), CognitoError> {
    let attrs: Vec<serde_json::Value> = changes
        .iter()
        .map(|c| {
            serde_json::json!({
                "Name": c.claim,
                // A blank value is how this API deletes an attribute (§13.22), which is what
                // makes an emptied field a removal in the same call as a changed one.
                "Value": c.after.clone().unwrap_or_default(),
            })
        })
        .collect();
    let payload = serde_json::json!({ "AccessToken": access, "UserAttributes": attrs });
    match cognito_post(
        cfg,
        settings,
        "AWSCognitoIdentityProviderService.UpdateUserAttributes",
        &payload,
    )? {
        CognitoReply::Ok(_) => Ok(()),
        CognitoReply::Error(body) => {
            // One of the values is not one the directory will store: the person can fix that, so
            // it is a `400` and not a `502`.
            let (key, status) = match cognito_error_name(&body).as_str() {
                "InvalidParameterException" | "InvalidUserTypeException" => {
                    (K::AccountProfileBadValue, 400)
                }
                _ => (K::AccountProfileRefused, 502),
            };
            Err(CognitoError::Refused(key, status))
        }
    }
}

/// The `cognito:username` of the ID token the code step just got back, and `None` for a token
/// that does not name a user this page can use.
///
/// The token is **not** verified, and that is the design's decision (§13.22): it arrives over the
/// same TLS call that asked for the code, from the endpoint the settings name, and the only thing
/// this page does with it is check that it names the user the code went to. A signature check
/// would need the pool's JWKS, which the gate holds and this process does not, and it would
/// change nothing: whoever can hand this process a token can hand it one that passes every claim
/// check below as well. What the checks are for is the accident, not the attacker: a pool that
/// answered the wrong user, and a token from another pool, from another app client, for an access
/// token, or out of its life, are all a token this page must not spend.
///
/// §13.25 step 3: the name compared is the **username**, not the `email`. The address is not the
/// identity here, and on a pool whose users' two names differ a token that names this user
/// carries an address nobody signed in with (the fixture's stranger signs in as
/// `sam@elsewhere.com` on a token whose `email` is `Sam@Elsewhere.COM`). A token with no
/// `cognito:username` is refused: a bind that cannot be satisfied is a bind that failed.
fn id_token_username(token: &str, settings: &Settings) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let text = |key: &str| claims.get(key).and_then(|v| v.as_str()).unwrap_or("");
    if text("token_use") != "id"
        || text("iss") != settings.issuer
        || text("aud") != settings.client_id
    {
        return None;
    }
    // A token whose life has run out is not this page's to spend. `exp` in the future is all
    // "not expired" can mean here: there is no clock of the pool's to compare against, and the
    // code step runs inside the code's own three minutes, so no leeway constant is worth one.
    claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .filter(|exp| *exp > now() as i64)?;
    if !email_verified_true(
        claims
            .get("email_verified")
            .unwrap_or(&serde_json::Value::Null),
    ) {
        return None;
    }
    claims
        .get("cognito:username")
        .and_then(|v| v.as_str())
        .filter(|u| !u.trim().is_empty())
        .map(|u| u.trim().to_string())
}

/// The profile edit's `POST` (§13.22, §13.23, §13.25): refuse everything that must be refused
/// without asking Cognito anything, then ask for a code for **this session's own Cognito user**
/// and show the page that names the address it went to.
///
/// The order is the console's, for the same reasons: the door (`Sec-Fetch-Site`) first, because
/// a cross-site form must not reach anybody's mailbox; then the user, because the pool acts on
/// one name and only the gate's header names the one this session is; then the field names,
/// because a claim outside the allowlist is a field that cannot save and a request cannot be
/// honoured in part; then the values. Every refusal writes nothing and calls nothing.
///
/// There is no `rev` here. This `POST` writes no access file: the write is Cognito's, and it
/// happens in slice 5c, behind the code.
#[allow(clippy::too_many_arguments)]
fn account_profile_post(
    mut req: Request,
    cfg: &Config,
    prefs: &mut AccountPrefs,
    lang: Lang,
    look: AccountLook,
    settings: &Settings,
    ids: &[String],
    uuid: Option<&str>,
    own: &AccountOwn,
    profile_path: &str,
    page: &str,
) {
    // (1) The door, and the console's strict policy: `same-origin` and nothing else.
    if !csrf_ok(
        header_value(&req, "Sec-Fetch-Site"),
        header_value(&req, "Origin"),
        header_value(&req, "Host"),
    ) {
        respond_account(
            req,
            403,
            prefs,
            t(lang, K::CsrfTitle),
            html! { p { (t(lang, K::CsrfBody)) } },
            look,
            false,
        );
        return;
    }
    let form = Form::parse(&read_body(&mut req));
    let editable = profile_editable(settings);
    // (2) The session must name the Cognito user the edit acts on. The gate sends that name for a
    // native sign-in and for nothing else, so a social session, an API key and a cookie from
    // before the header has no user this page can ask a pool about, and the sentence that says so
    // is the one the panel already shows. Refused before the body is looked at beyond the names,
    // and before any call: a code sent on a name nobody holds goes to a stranger's mailbox.
    let native = match native_user(&req) {
        Some(u) => u.to_string(),
        None => {
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountProfileNotSavedTitle),
                html! { p { (t(lang, K::AccountProfileNotNative)) } },
                look,
                false,
            );
            return;
        }
    };
    // (3) Every posted name is an editable claim, or the whole submission is refused. A name
    // that is not one is a hand-made form naming a claim Cognito will not accept, and honouring
    // the rest of it would tell the person their change was sent. `email` is one of those names
    // now (§13.26 §4): the address is not a field on this page, and a form that posts one is a
    // form trying to choose where the code goes.
    for (name, _) in &form.0 {
        if !editable.iter().any(|c| c == name) {
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountProfileNotSavedTitle),
                html! { p { (format!("{name}: {}", t(lang, K::AccountProfileCannotEdit))) } },
                look,
                false,
            );
            return;
        }
    }
    // (4) Each value: at most the length the field says, and no control character. A newline in
    // a name is not a name, and a value that reaches a directory with control bytes in it is a
    // value every later reader has to guess about. The refusal names the field by the word the
    // person read, marks it, and leaves the rest of the form standing.
    for (name, value) in &form.0 {
        if value.chars().count() > PROFILE_VALUE_MAX || value.chars().any(|c| c.is_control()) {
            let label = profile_label(lang, name).unwrap_or_else(|| name.clone());
            // The page is built before the response, because the page reads the request's
            // headers (the forwarded claims) and the response takes the request.
            let body = page_account(
                lang,
                ids,
                uuid,
                own,
                None,
                Some(&ProfileForm::again(
                    settings,
                    &req,
                    &form,
                    Some((
                        name.clone(),
                        format!("{label}: {}", t(lang, K::AccountProfileValueBad)),
                    )),
                    None,
                )),
            );
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountProfileEdit),
                body,
                look,
                false,
            );
            return;
        }
    }
    // (5) What would change, against what the proxy forwarded. A field the form did not post is
    // a field that is not being changed, which is what lets the code page's resend post only the
    // changed ones: an absent field means "leave it", an empty one means "remove it".
    let mut changes: Vec<ProfileChange> = Vec::new();
    let mut resend: Vec<(String, String)> = Vec::new();
    for (name, value) in &form.0 {
        let header = match settings
            .profile_claims
            .iter()
            .find(|c| &c.claim == name)
            .map(|c| c.header.clone())
        {
            Some(header) => header,
            None => continue,
        };
        let before = forwarded_claim(&req, &header).trim().to_string();
        let after = value.trim().to_string();
        if before == after {
            continue;
        }
        changes.push(ProfileChange {
            claim: name.clone(),
            before: (!before.is_empty()).then_some(before),
            after: (!after.is_empty()).then_some(after),
        });
        resend.push((name.clone(), value.clone()));
    }
    if changes.is_empty() {
        // Not an error: nothing was refused and nothing was sent. A warning, in the page the
        // person is already looking at, because the ordinary cause is a field they did not type
        // in.
        let body = page_account(
            lang,
            ids,
            uuid,
            own,
            None,
            Some(&ProfileForm::again(
                settings,
                &req,
                &form,
                None,
                Some(t(lang, K::AccountProfileNothingChanged).to_string()),
            )),
        );
        respond_account(
            req,
            200,
            prefs,
            t(lang, K::AccountProfileEdit),
            body,
            look,
            false,
        );
        return;
    }
    // Every page past this point carries its own lede (the address the code went to, or why
    // nothing was saved), so the bar's menu keeps the identity out: the design counts one
    // `p.lede` per page (§13.23 §3, §4).
    prefs.page_lede = true;
    match cognito_call(cfg, settings, &native) {
        Ok((session, destination, _)) => {
            // What the code step needs, as hidden fields: the `Session` to answer with, and one
            // entry per changed claim, an emptied one posted empty. The code page is a form and
            // not a session: everything the next request must send is on the page, and nothing
            // the person did not type is kept on the server (§13.22). The username is **not**
            // among them (§13.25 step 2): the code step answers for the user of the request that
            // arrives, and a username that rides in a form is a form that can be posted by
            // somebody else and answered for them.
            let mut carry: Vec<(String, String)> = vec![("Session".to_string(), session)];
            for ch in &changes {
                carry.push((ch.claim.clone(), ch.after.clone().unwrap_or_default()));
            }
            respond_account(
                req,
                200,
                prefs,
                t(lang, K::AccountProfileCodeTitle),
                page_profile_code(
                    lang,
                    &ProfileCode {
                        destination: destination.as_deref(),
                        changes: &changes,
                        carry: &carry,
                        resend: &resend,
                        err: None,
                    },
                    profile_path,
                    &format!("{profile_path}/code"),
                    page,
                ),
                look,
                false,
            )
        }
        Err(CognitoError::NoAnswer) => respond_account(
            req,
            504,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(
                lang,
                K::AccountProfileNoAnswer,
                Some(&resend),
                profile_path,
                page,
            ),
            look,
            false,
        ),
        Err(CognitoError::Refused(key, status)) => respond_account(
            req,
            status,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(lang, key, None, profile_path, page),
            look,
            false,
        ),
    }
}

/// The code step (§13.22, §13.25 step 2): answer the `EMAIL_OTP` challenge **for the user of the
/// request that arrived**, bind the token it returns to that same user, write the attributes, and
/// render the outcome.
///
/// Every check the start made is made **again** here, against the live files, because the two
/// steps are two requests and the files are edited between requests: the claim list, the roster
/// and the `denied` list are all re-read, and a form whose claim has left the settings is refused
/// rather than sent. The `Session` is not a credential and buys nothing: it names a challenge, and
/// the person answering it has already been proved by the proxy secret, the identity header and
/// the veto, which `handle_account` has just done for this request on the same terms as the `GET`.
///
/// The order of the calls is the design's: at most two, and the update only after the code has
/// been accepted **and** the token it returned names this session's user. A token for another
/// account is dropped unused, so no `UpdateUserAttributes` ever runs with an access token the pool
/// handed to somebody else.
#[allow(clippy::too_many_arguments)]
fn account_profile_code_post(
    mut req: Request,
    cfg: &Config,
    prefs: &mut AccountPrefs,
    lang: Lang,
    look: AccountLook,
    settings: &Settings,
    profile_path: &str,
    page: &str,
) {
    // (1) The door, and the console's strict policy: `same-origin` and nothing else.
    if !csrf_ok(
        header_value(&req, "Sec-Fetch-Site"),
        header_value(&req, "Origin"),
        header_value(&req, "Host"),
    ) {
        respond_account(
            req,
            403,
            prefs,
            t(lang, K::CsrfTitle),
            html! { p { (t(lang, K::CsrfBody)) } },
            look,
            false,
        );
        return;
    }
    let form = Form::parse(&read_body(&mut req));
    let editable = profile_editable(settings);
    // A refusal before any call: the page that says nothing was changed, the sentence, and the
    // same start offered, because starting over is always correct once the form is refused.
    let refused = |req: Request, prefs: &mut AccountPrefs, key: K, fields: &[(String, String)]| {
        respond_account(
            req,
            400,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(lang, key, Some(fields), profile_path, page),
            look,
            false,
        );
    };
    // (2) The user this request is, as the gate named it on **this** request (§13.25 step 2).
    // Not a field: a code step that answered the username its form carried would answer for the
    // user of whoever posted the form, and the person whose session minted it would be the one
    // whose attributes got written. A request the gate named nobody for answers nothing.
    let native = match native_user(&req) {
        Some(u) => u.to_string(),
        None => {
            refused(req, prefs, K::AccountProfileNotNative, &[]);
            return;
        }
    };
    // (3) Every posted name is the code, the `Session` the page carries, or an editable claim
    // **the settings still list**. A name that is not one is a hand-made form naming a claim the
    // directory will not accept, and honouring the rest of it would tell the person their change
    // was written. `email` and `username` are not names any more: a form that posts one of them
    // is a form from before this step, or a form choosing where a code goes.
    for (name, _) in &form.0 {
        let known = name == "code" || name == "Session" || editable.iter().any(|c| c == name);
        if !known {
            refused(req, prefs, K::AccountProfileCannotEdit, &[]);
            return;
        }
    }
    // (4) The values and the `Session`: bounded, and no control character. The last is the pool's
    // own string riding through a form, so it gets the same bound as anything else a hand-made
    // form can fill.
    for (name, value) in &form.0 {
        if name == "code" {
            continue;
        }
        if value.chars().count() > PROFILE_VALUE_MAX || value.chars().any(|c| c.is_control()) {
            let label = profile_label(lang, name).unwrap_or_else(|| name.clone());
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountProfileNotSavedTitle),
                html! { p class="lede" { (format!("{label}: {}", t(lang, K::AccountProfileValueBad))) } },
                look,
                false,
            );
            return;
        }
    }
    // (5) The code, and the session it belongs to. A missing `Session` is the challenge being
    // gone, which is what an expired code means, and the way forward is the same: a new one.
    let session = form.get("Session").trim().to_string();
    let code = match profile_code(form.get("code")) {
        Some(c) => c,
        None => {
            refused(req, prefs, K::AccountProfileWrongCode, &[]);
            return;
        }
    };
    if session.is_empty() {
        refused(req, prefs, K::AccountProfileExpired, &[]);
        return;
    }
    // (6) What the form says to write, recomputed against the claims the settings list **now**
    // and the values the proxy forwarded on this request. A claim that left the settings between
    // the two steps is not written, and a form left with nothing to write is refused rather than
    // answered with a save that changed nothing.
    let mut changes: Vec<ProfileChange> = Vec::new();
    for (name, value) in &form.0 {
        if name == "code" || name == "Session" {
            continue;
        }
        let header = match settings
            .profile_claims
            .iter()
            .find(|c| &c.claim == name)
            .map(|c| c.header.clone())
        {
            Some(header) => header,
            None => continue,
        };
        let before = forwarded_claim(&req, &header).trim().to_string();
        let after = value.trim().to_string();
        if before == after {
            continue;
        }
        changes.push(ProfileChange {
            claim: name.clone(),
            before: (!before.is_empty()).then_some(before),
            after: (!after.is_empty()).then_some(after),
        });
    }
    // What the code page and the start's form carry, rebuilt from this request so a refusal shows
    // the same summary the person was reading.
    let mut resend: Vec<(String, String)> = Vec::new();
    let mut carry: Vec<(String, String)> = vec![("Session".to_string(), session.clone())];
    for ch in &changes {
        let value = ch.after.clone().unwrap_or_default();
        resend.push((ch.claim.clone(), value.clone()));
        carry.push((ch.claim.clone(), value));
    }
    if changes.is_empty() {
        refused(req, prefs, K::AccountProfileNothingChanged, &resend);
        return;
    }
    // Every page past here carries its own lede, so the bar's menu keeps the identity out.
    prefs.page_lede = true;
    let code_path = format!("{profile_path}/code");
    match cognito_answer(cfg, settings, &session, &native, &code) {
        Ok(auth) => {
            // The token the challenge returned, bound to this session's user (§13.22, §13.25
            // step 3). It is decoded, not verified, and what the checks are for is the accident:
            // a pool that answered the wrong user, a token from another pool, from another app
            // client, an access token posing as an ID token, and a token out of its life are
            // each a token this page must not spend. `id_token_username` is that list, and the
            // name it returns is compared to the header, never to an address.
            let id = auth
                .get("IdToken")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if id_token_username(id, settings).as_deref() != Some(native.as_str()) {
                // The other user is not named on the page: this is a shared surface, and a
                // refusal that says which account the code belonged to is an oracle for anybody
                // with any account at all.
                respond_account(
                    req,
                    403,
                    prefs,
                    t(lang, K::AccountProfileNotSavedTitle),
                    page_profile_outcome(lang, K::AccountProfileNotYours, None, profile_path, page),
                    look,
                    false,
                );
                return;
            }
            let access = auth
                .get("AccessToken")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            match cognito_update(cfg, settings, access, &changes) {
                Ok(()) => respond_account(
                    req,
                    200,
                    prefs,
                    t(lang, K::AccountProfileSavedTitle),
                    page_profile_saved(lang, &changes, page),
                    look,
                    false,
                ),
                Err(CognitoError::NoAnswer) => respond_account(
                    req,
                    504,
                    prefs,
                    t(lang, K::AccountProfileUnsureTitle),
                    page_profile_outcome(
                        lang,
                        K::AccountProfileNoAnswerUnsure,
                        None,
                        profile_path,
                        page,
                    ),
                    look,
                    false,
                ),
                Err(CognitoError::Refused(key, status)) => respond_account(
                    req,
                    status,
                    prefs,
                    t(lang, K::AccountProfileNotSavedTitle),
                    page_profile_outcome(lang, key, None, profile_path, page),
                    look,
                    false,
                ),
            }
        }
        Err(CognitoAnswer::WrongCode(new_session)) => {
            // The code page again, the field emptied, and the `Session` this answer carried when
            // it carried one: the pool has moved the challenge on, and the old one is gone.
            let session = new_session.unwrap_or(session);
            carry[0] = ("Session".to_string(), session);
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountProfileCodeTitle),
                page_profile_code(
                    lang,
                    &ProfileCode {
                        // No destination on this page: the answer that refused the code names a
                        // new `Session`, not a new address, and the address the first code went to
                        // is not this page's to repeat.
                        destination: None,
                        changes: &changes,
                        carry: &carry,
                        resend: &resend,
                        err: Some(t(lang, K::AccountProfileWrongCode)),
                    },
                    profile_path,
                    &code_path,
                    page,
                ),
                look,
                false,
            )
        }
        Err(CognitoAnswer::Expired) => respond_account(
            req,
            400,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(
                lang,
                K::AccountProfileExpired,
                Some(&resend),
                profile_path,
                page,
            ),
            look,
            false,
        ),
        Err(CognitoAnswer::NoAnswer) => respond_account(
            req,
            504,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(
                lang,
                K::AccountProfileNoAnswer,
                Some(&resend),
                profile_path,
                page,
            ),
            look,
            false,
        ),
        Err(CognitoAnswer::Refused(key)) => respond_account(
            req,
            502,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(lang, key, None, profile_path, page),
            look,
            false,
        ),
    }
}

/// Which key mutation a `POST` under the keys prefix is asking for.
///
/// A closed set, because all three stand behind the **same** doors (the same-origin check, the
/// row the identity header resolves to, the write lock, the file's fingerprint) and differ only
/// in what the library is asked to do once those doors are open. Three handlers that each
/// re-checked the doors are three chances for one of them to be missing from one of them, and a
/// `remove` that skipped the fingerprint is a silent clobber of somebody else's edit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AccountKeyOp {
    Mint,
    Rotate,
    Remove,
}

impl AccountKeyOp {
    /// The word this operation is named by: the verb the form's own button used, so the page a
    /// refusal lands on is headed by the word the reader just clicked, and the confirmation a
    /// row's link opens is headed by the word the reader is about to click (§13.17).
    fn title(self) -> K {
        match self {
            AccountKeyOp::Mint => K::AccountKeyAdd,
            AccountKeyOp::Rotate => K::AccountKeyRotate,
            AccountKeyOp::Remove => K::AccountKeyRemove,
        }
    }
}

/// Answer a key mutation: `POST <prefix>/keys`, `…/keys/rotate` or `…/keys/remove`.
///
/// The order is the console's, for the console's reasons ([`mutate`]), and it is the order that
/// makes "nothing was written" a fact on every refusal path rather than a hope:
///
/// 1. the same-origin door, before the body is read, because a mint hands out a credential, a
///    rotate hands out a new one and a revoke destroys one, and a form on somebody else's page
///    doing any of those to a signed-in person is the exact attack this door exists for;
/// 2. the row, which the identity header resolves to and no form field may choose;
/// 3. [`WRITE_LOCK`], then the file's current bytes against the form's `rev`, then
///    [`open_access_file`], which refuses to start editing from bytes the gate would reject.
///    The guard **ends at the commit**, before anything is rendered or sent, as `mutate`'s does
///    (docs/ARCHITECTURE.md §13.13): what the lock owes is that no other writer in this process
///    renames between this one's `rev` check and this one's rename, and a response's send is
///    none of that;
/// 4. the mutation's own checks, before anything is written, because a secret created for a
///    refusal is a secret handed out for nothing;
/// 5. [`add_api_key`] / [`rotate_api_key`] / [`remove_api_key`] through [`AccessWrite`], the
///    library's own door, and for the two that mint, the bearer opened against the receipt of
///    the completed write.
///
/// The refusal pages are short: this page's caller has no administrator in the room, so each
/// message names what to write instead, and the way back is the page they came from.
#[allow(clippy::too_many_arguments)]
fn account_key_post(
    mut req: Request,
    cfg: &Config,
    prefs: &AccountPrefs,
    lang: Lang,
    look: AccountLook,
    uuid: Option<&str>,
    op: AccountKeyOp,
    settings: &Settings,
    ids: &[String],
    keys_path: &str,
    profile_path: &str,
) {
    // (1) The door, and the console's strict policy: `same-origin` and nothing else.
    if !csrf_ok(
        header_value(&req, "Sec-Fetch-Site"),
        header_value(&req, "Origin"),
        header_value(&req, "Host"),
    ) {
        respond_account(
            req,
            403,
            prefs,
            t(lang, K::CsrfTitle),
            html! { p { (t(lang, K::CsrfBody)) } },
            look,
            false,
        );
        return;
    }
    // (2) A key is filed under a uuid, so a caller the file has no row for has no account to
    // mint into. The page says the same thing to them (§13.6); a hand-crafted `POST` gets the
    // same answer, and the vetoed caller never reaches here: the veto is answered above.
    let Some(owner) = uuid else {
        respond_account(
            req,
            403,
            prefs,
            t(lang, K::AccountNoRowTitle),
            html! { p { (t(lang, K::AccountNoRowBody)) } },
            look,
            false,
        );
        return;
    };
    let form = Form::parse(&read_body(&mut req));
    // (3) Serialized against every other write in this process, exactly as the console's
    // `mutate` is: two workers, one person with two tabs, and a loser whose mint vanishes
    // behind a success page is the silent clobber the `rev` cannot see. The guard is named so
    // it can be **released at the commit** below, and every refusal path that returns from here
    // drops it on the way out, so the lock is never held across a response.
    let writing = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let raw = match std::fs::read_to_string(&cfg.access_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            let msg = format!("read {}: {e}", cfg.access_path);
            respond_account(
                req,
                500,
                prefs,
                t(lang, K::FileErrorTitle),
                html! { p { (msg) } },
                look,
                false,
            );
            return;
        }
    };
    if form.get("rev").trim() != sha256_hex(&raw) {
        // The console's `409` in this page's shell. The advice is the console's too, and it is
        // the honest one: nothing was written, and the file says something the form never saw.
        respond_account(
            req,
            409,
            prefs,
            t(lang, K::ConflictTitle),
            html! {
                p { (t(lang, K::ConflictBody)) }
                p { (t(lang, K::ConflictRecover)) }
                p { a href=(prefs.page) { "← " (t(lang, K::ConflictBack)) } }
            },
            look,
            false,
        );
        return;
    }
    let (mut doc, access) = match open_access_file(&cfg.access_path) {
        Ok(pair) => pair,
        Err(e) => {
            respond_account(
                req,
                500,
                prefs,
                t(lang, K::FileErrorTitle),
                html! { p { (e) } },
                look,
                false,
            );
            return;
        }
    };
    let id = form.get("id").trim().to_string();
    // (4) then (5), in one closure so that "every path out of here wrote nothing" is a fact
    // about the shape of the code: the only `Ok` is the one that has committed. The payload is
    // `Some(bearer)` for the two mutations that mint a secret and `None` for the one that only
    // takes one away.
    let done = (|| -> Result<Option<String>, Refusal> {
        if op == AccountKeyOp::Mint {
            let duration =
                duration_from_form(&form).map_err(|k| Refusal::on("duration", t(lang, k)))?;
            let restrict = form.get("restrict").trim().to_string();
            let pairs = form.all("scope");
            // Each refusal names the field it is about, because the row it re-renders marks that
            // field and not the other, and says one fact: the sentence a person reads has to be
            // the sentence about what they got wrong.
            if !account_key_id_ok(&id) {
                return Err(Refusal::on("id", t(lang, K::AccountKeyIdBad)));
            }
            if !account_key_window_ok(&duration) {
                return Err(Refusal::on("duration", t(lang, K::AccountKeyTooShort)));
            }
            // The row's keys, read off the **document**, not the compiled table: the bound is on
            // how many credentials one identity carries, and a key whose hash the gate skipped is
            // still a row a person has to review.
            let mine = user_pos(&doc, owner).map_or(&[][..], |i| &doc.users[i].api_keys);
            // The bound counts the administrator's keys too: it is a bound on the row, not on
            // how many mints this page handed out.
            if mine.len() >= ACCOUNT_MAX_KEYS {
                return Err(t(lang, K::AccountKeyFull).to_string().into());
            }
            // An id is how a key is named back (in the journal line, and in `bb-auth-adm key
            // rotate`), so two keys called `laptop` on one row is one name naming two secrets.
            if mine.iter().any(|k| k.id.trim() == id) {
                return Err(Refusal::on("id", t(lang, K::AccountKeyDup)));
            }
            // `all` writes **no** `scopes` field, which the gate reads as the owner's whole reach.
            // `some` writes the submitted pairs sorted: the submitted order is a browser's, and
            // one canonical spelling is what makes a restriction a comparison, not a string match.
            let scopes = match restrict.as_str() {
                // Ticks beside "all scopes" are a choice the person thinks they made: dropping
                // them would file the widest key the person did not ask for. No field is marked,
                // since the contradiction is between two controls and not inside one.
                "all" if !pairs.is_empty() => {
                    return Err(t(lang, K::KeyScopesWithoutOnly).to_string().into());
                }
                "all" => None,
                "some" => {
                    let allowed = access.key_scopes_for(owner);
                    for pair in &pairs {
                        if !allowed
                            .iter()
                            .any(|(a, s)| format!("{}/{}", a.name, s.name) == *pair)
                        {
                            return Err(t(lang, K::AccountKeyUnknownScope).to_string().into());
                        }
                    }
                    let mut sorted = pairs.clone();
                    sorted.sort();
                    Some(sorted)
                }
                // Neither of the two the form can send. Refused rather than read as `all`: a key
                // with no restriction is the widest credential this page mints, and a request
                // that did not choose it must not get it by default. No field is marked: the
                // request chose nothing, so the fix is to name the two it could choose.
                _ => return Err(t(lang, K::KeyScopesChoose).to_string().into()),
            };
            let sealed = add_api_key(
                &mut doc,
                owner,
                ApiKeySpec {
                    id: id.clone(),
                    // Today, and not a field: a key's issue date is a fact about a secret that is
                    // being created right now.
                    released: format_date(now()),
                    duration: duration.clone(),
                    scopes,
                    ..Default::default()
                },
            )?;
            let written = AccessWrite::prepare(&doc)?.commit(&cfg.access_path)?;
            // The acting identity, marked as acting for itself, and the key's id. No bearer and
            // no hash: the line says which credential exists, and the file says anything more.
            audit(&format!("{owner} (self)"), "key add", &id);
            Ok(Some(sealed.reveal(&written)))
        } else {
            // The two mutations that act on a key the caller already has. The id is **not**
            // validated against the mint's grammar: a rotate naming an id this row does not carry
            // is refused by the library's own lookup, and the page answers every miss with the
            // same sentence, so a probe for which ids exist on the estate gets one answer for all
            // of them. The library resolves the row from the caller's uuid, so a key filed under
            // another person is not found at all: that is the ownership check, and it is the
            // library's, so the console and this page cannot answer it differently.
            let sealed = match op {
                AccountKeyOp::Rotate => rotate_api_key(&mut doc, owner, &id)
                    .map(Some)
                    .map_err(|_| t(lang, K::AccountKeyNotYours).to_string())?,
                AccountKeyOp::Remove => remove_api_key(&mut doc, owner, &id)
                    .map(|_| None)
                    .map_err(|_| t(lang, K::AccountKeyNotYours).to_string())?,
                AccountKeyOp::Mint => None,
            };
            let written = AccessWrite::prepare(&doc)?.commit(&cfg.access_path)?;
            audit(
                &format!("{owner} (self)"),
                if op == AccountKeyOp::Rotate {
                    "key rotate"
                } else {
                    "key remove"
                },
                &id,
            );
            // A rotate mints a new secret, so it comes back sealed like a mint does and is opened
            // against this write's receipt; a revoke mints nothing, so there is nothing to reveal.
            Ok(sealed.map(|sealed| sealed.reveal(&written)))
        }
    })();
    // The lock ends here, at the commit, and not at the response (§13.13): what it owes is that
    // no other writer renames between this one's `rev` check and this one's rename, and the
    // reveal page's send is nothing to that. Holding it across the write to the socket couples
    // every other writer's wait to one response.
    drop(writing);
    // The key's id rides in the title, because the shell renders the title as the page's one
    // heading: "API keys · phone" says which secret this is, which is the fact a person with two
    // browser tabs open needs in front of them.
    match done {
        // A mint and a rotate answer `200` directly, and that is why they are the two mutations
        // here that are not POST-redirect-GET: the bearer cannot ride a redirect, because a
        // `Location:` is a URL and a URL is a credential in a proxy log. The page that shows it
        // once has to be the response to the `POST`, and a reload of that page re-sends the
        // `POST`: the same price the console's mint page pays, for the same reason. It is also
        // the one response under this prefix that carries a script (§13.14), so it is the one
        // that passes `reveal`: a `400` here mints nothing, and a `409` has no key to copy.
        Ok(Some(bearer)) => respond_account(
            req,
            200,
            prefs,
            &format!("{} · {}", t(lang, K::AccountKeys), id),
            page_account_minted(lang, prefs.page, &bearer),
            look,
            true,
        ),
        // A revoke mints nothing, so it follows the estate's rule and answers `303` to the page
        // it came from. No `?msg=`: the key is gone from the list, and that is the confirmation.
        Ok(None) => respond_redirect(req, prefs.page),
        // A refused mint answers with the page and its row still open: the values as posted,
        // the sentence in the console's error box, and the field it is about marked (§13.16).
        Err(refusal) if op == AccountKeyOp::Mint => {
            let rev = sha256_hex(&raw);
            let own = account_own(
                &doc,
                &access,
                settings,
                &req,
                ids,
                uuid,
                keys_path,
                &rev,
                prefs.page,
                profile_path,
            );
            let ticked = form.all("scope");
            let row = NewKeyRow {
                id: &id,
                choice: form.get("duration").trim(),
                days: form.get("days").trim(),
                some: form.get("restrict").trim() == "some",
                ticked: &ticked,
                err: Some(&refusal),
            };
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountTitle),
                page_account(lang, ids, uuid, &own, Some(&row), None),
                look,
                false,
            );
        }
        Err(refusal) => respond_account(
            req,
            400,
            prefs,
            t(lang, op.title()),
            html! {
                div class="err" { (refusal.msg) }
                p { a href=(prefs.page) { "← " (t(lang, K::Back)) } }
            },
            look,
            false,
        ),
    }
}

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

mod apps;
mod audit_page;
mod check;
mod config;
mod dashboard;
mod forms;
mod i18n;
mod k_text;
mod layout;
mod routing;
mod users;

use apps::*;
use audit_page::*;
use check::*;
use config::*;
use dashboard::*;
use forms::*;
use i18n::*;
use k_text::*;
use layout::*;
use routing::*;
use users::*;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
