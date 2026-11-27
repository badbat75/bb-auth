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
/// theme needs no such second type for exactly the mirror reason: [`UiTheme::System`] *is* a
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

/// The three appearances a page can render in are [`UiTheme`], the library's, and not a
/// second enum here saying the same three words.
///
/// That is the presentation contract's doing rather than convenience: the settings file names
/// a theme, both programs stamp it onto `html` as `data-theme`, and one selector in
/// [`THEME_CSS`] keys off it. Two enums would be two spellings of `dark` waiting to disagree.
/// What stays local is the only part that is this GUI's alone: the label an option shows, and
/// what a cookie value means, neither of which the gate has any use for.
///
/// The label is a [`K`] and not a string, unlike [`LangPref::label`]: an appearance is prose
/// about the page, so it translates.
fn theme_label(theme: UiTheme) -> K {
    match theme {
        UiTheme::Light => K::ThemeLight,
        UiTheme::Dark => K::ThemeDark,
        UiTheme::System => K::ThemeSystem,
    }
}

/// Parse a theme name out of the query or the cookie, where **empty means no choice** rather
/// than `System`, which is the one place this differs from [`UiTheme::parse`] and the reason
/// it is a function and not a call.
///
/// A settings file that leaves `theme` blank has said "no preference", and `System` is the
/// right reading of that. A cookie whose value is blank has not said anything at all, and must
/// fall back exactly as a missing cookie does, so that a deployment's own default still
/// applies. `None` for an unrecognised value, for the same reason.
fn parse_theme(s: &str) -> Option<UiTheme> {
    match s.trim() {
        "" => None,
        v => UiTheme::parse(v),
    }
}

/// How the Settings page opens: every group expanded, or every group folded to its heading.
///
/// A preference and not a parameter of the page, because the commands that set it are meant to
/// stick: an operator who opens everything to work through the page wants it open after the
/// next save too, and a save ends in a redirect that carries no query. Each group still opens
/// and closes on its own in the browser, with no script, since each one is a `details`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum GroupsPref {
    Open,
    /// Where every browser starts: the page reads as its five headings, which is its table of
    /// contents, and the one group somebody came to change is a click away. A page of every
    /// field at once is a page that has to be scrolled to find the one that matters.
    #[default]
    Closed,
}

impl GroupsPref {
    /// The cookie value and the query value: one spelling.
    fn code(self) -> &'static str {
        match self {
            GroupsPref::Open => "open",
            GroupsPref::Closed => "closed",
        }
    }

    fn parse(s: &str) -> Option<GroupsPref> {
        match s.trim() {
            "open" => Some(GroupsPref::Open),
            "closed" => Some(GroupsPref::Closed),
            _ => None,
        }
    }
}

/// Which clock the audit is read in: the third preference, and the only one that is not in the
/// Settings menu, because it changes one page and its `Custom` choice needs a text box.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum TzPref {
    /// What the file stores, and where every session starts until it chooses otherwise: the
    /// same floor `Auto` and `System` are for the other two, so a deployment that never
    /// chooses reads the page it always read.
    #[default]
    Utc,
    /// The zone of the **host** this program runs on, and not the browser's: no request header
    /// carries a browser's zone, and a page that may not need a script has no way to ask for it.
    Local,
    /// A zone the operator named: an IANA name out of the host's database, or a fixed offset,
    /// held in the spelling [`custom_zone`] gives it.
    Custom(String),
}

impl TzPref {
    /// The cookie value, which is also what [`parse_tz_pref`] reads back. A custom zone is its
    /// own spelling, which [`custom_zone`] has already held to a charset a cookie may carry.
    fn code(&self) -> &str {
        match self {
            TzPref::Utc => "utc",
            TzPref::Local => "local",
            TzPref::Custom(z) => z,
        }
    }

    /// Which option of the audit's list box this is.
    fn choice(&self) -> &'static str {
        match self {
            TzPref::Utc => "utc",
            TzPref::Local => "local",
            TzPref::Custom(_) => "custom",
        }
    }
}

/// Parse a zone preference out of the cookie or out of the audit's text box. `None` for
/// anything that is neither of the two words nor a zone [`custom_zone`] accepts, which leaves
/// whatever preference was already in force standing.
fn parse_tz_pref(s: &str) -> Option<TzPref> {
    let v = s.trim();
    if v.eq_ignore_ascii_case("utc") {
        Some(TzPref::Utc)
    } else if v.eq_ignore_ascii_case("local") {
        Some(TzPref::Local)
    } else {
        custom_zone(v).map(TzPref::Custom)
    }
}

/// A zone of the operator's own, in the spelling the cookie stores: a fixed offset as
/// `+HH:MM`, or an IANA name as typed. `None` for anything else.
///
/// A name is letters, digits, `_`, `+`, `-` and `/`, starting with a letter, which is every
/// name in the database and nothing that can leave it: there is no `.`, so there is no `..`,
/// so there is no path that climbs out of [`ZONEINFO_DIR`]. The same charset is what makes the
/// value safe in a `Set-Cookie`, which is where it goes next. Whether the host has a zone of
/// that name is a question for the page that reads it, which says so when it does not.
fn custom_zone(v: &str) -> Option<String> {
    let v = v.trim();
    if let Some(secs) = parse_offset(v) {
        return Some(format_offset(secs));
    }
    let named = !v.is_empty()
        && v.len() <= 64
        && v.starts_with(|c: char| c.is_ascii_alphabetic())
        && !v.ends_with('/')
        && !v.contains("//")
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-' | b'/'));
    named.then(|| v.to_string())
}

/// A fixed offset from UTC in seconds: `+2`, `+02`, `+0200` or `+02:00`, optionally after `UTC`
/// or `GMT`, with the sign meaning what it means on a clock: ahead of UTC.
///
/// The sign is why this exists rather than the string going to a POSIX `TZ` parser, which is
/// what the zone library would have done with it: POSIX spells two hours **ahead** of UTC as
/// `UTC-2`, the opposite of what anybody typing it into a box means, and a page that silently
/// read four hours out would be worse than one that refused. Up to fourteen hours either way,
/// which is every offset in use.
fn parse_offset(v: &str) -> Option<i32> {
    let up = v.trim().to_ascii_uppercase();
    let rest = up
        .strip_prefix("UTC")
        .or_else(|| up.strip_prefix("GMT"))
        .unwrap_or(&up);
    let (sign, digits) = match rest.as_bytes().first()? {
        b'+' => (1, &rest[1..]),
        b'-' => (-1, &rest[1..]),
        _ => return None,
    };
    let (h, m) = match digits.split_once(':') {
        Some(pair) => pair,
        None if digits.len() > 2 => digits.split_at(digits.len() - 2),
        None => (digits, "0"),
    };
    let two_digits = |s: &str| (1..=2).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    if !two_digits(h) || !two_digits(m) {
        return None;
    }
    let (h, m): (i32, i32) = (h.parse().ok()?, m.parse().ok()?);
    if m > 59 || h * 60 + m > 14 * 60 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60))
}

/// An offset in seconds as `+HH:MM`, which is how the heading names a fixed zone and how the
/// cookie stores one.
fn format_offset(secs: i32) -> String {
    let a = secs.unsigned_abs();
    let sign = if secs < 0 { '-' } else { '+' };
    format!("{sign}{:02}:{:02}", a / 3600, (a % 3600) / 60)
}

/// Every translatable string in the GUI, as a variant.
///
/// An enum rather than a string key so that [`t`]'s match is **exhaustive**: adding a key
/// without translating it does not fall back at runtime, it fails to compile. And because
/// each arm names both spellings on one line, no key can be half-translated either.
///
/// [`K::Dashboard`], [`K::Groups`], [`K::Apps`], [`K::Users`] and [`K::Denied`] are the nav
/// labels and page headings: descriptive prose *about* a section, not that
/// section's name. [`K::Can`] reads the same way and heads no section of the file at all:
/// the access check is not a place, it is a question, and it is asked on the two pages that
/// each already hold half of it. The name itself stays untranslated wherever it appears as itself,
/// namely `base`, `urls`, `access`, `login_url`, `api_keys`, `released`, `duration`,
/// `notes`, `bbk_`, every `@group` reference, and the raw key shown in muted monospace
/// beside a heading; that is because it is what an operator types into the file and into
/// `bb-auth-adm`, and translating it would invent a second name for a thing that has one.
#[derive(Clone, Copy)]
enum K {
    Dashboard,
    Groups,
    Apps,
    Scopes,
    /// The group page's members **section heading** (§13.36 §2 item 3, as the screenshot review
    /// of plan step 22 read it). Not `K::Members`: that is the Groups list's lowercase *column*
    /// word, and a heading borrowing it reads as a table label, in Italian by a capital alone.
    /// Title case like the `Scopes` heading above it, because every heading is the section's word.
    MembersHeading,
    Users,
    /// The users tab's People sub-page, and the word its section heading carries. The tab's
    /// own word is `K::Users`, and the roster's heading used to repeat it, so the heading said
    /// which tab it was under and not which list it headed (§13.36 §1).
    People,
    /// The Groups sub-tab's short word. Not `K::Groups` ("User groups"), for the bar's own
    /// reason (`K::ConfigTab` versus `K::Config`): the row has to fit a phone, and the
    /// section's `h2` spells the name out (§13.36 §1).
    GroupsTab,
    /// The name of the users tab's row of sub-tabs. The page carries four navigation landmarks
    /// with it, and the accessibility practice asks that more than one of a kind be named.
    UsersSections,
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
    /// The kind word that opens a dashboard warning (§13.35). The warnings list mixes scopes,
    /// people and groups in one list, and an identifier such as `@delete-test` does not say on
    /// its own which of the three it is. Capitalised because it opens the list item; the words
    /// are the console's own singular for that object, as its add/save messages use them.
    KindScope,
    KindUser,
    KindGroup,
    WarnNoScope,
    WarnEnrolledAndDenied,
    ReferencedBy,
    ReferencedByNothing,
    ReachesNothing,
    NoSuchUser,
    UsersIntro,
    GroupsIntro,
    /// The group page's pill that asks the roster for the group's members (§13.36 §2). It
    /// names the page it lands on, because the members are already on this one: the pill asks
    /// to see them **as roster rows**, which is the one thing this page cannot show.
    GroupInRoster,
    /// The roster's chip naming the group its rows are filtered to (§13.36 §3). `{0}` is the
    /// group's name, spelled as the file spells it, `@` included.
    GroupFilter,
    /// The chip's name for what its `×` does: the whole filter, not one row.
    GroupFilterClear,
    AppsIntro,
    ScopesIntro,
    DeniedIntro,
    CanIntroUser,
    CanAnyEmail,
    CanIntroApp,
    CanNoIdentifier,
    Submit,
    Authorized,
    VerdictDenied,
    // --- the eleven decisions, in the order `Decision` declares them ---
    WhyAnonymousGrant,
    WhyGranted,
    WhyVetoed,
    WhyExcluded,
    WhyNoApplication,
    WhyNoScope,
    WhyUnauthenticated,
    WhyCredentialRefused,
    WhyNotEnrolled,
    WhyNotMember,
    WhyKeyOutOfScope,
    // --- the refusals only the audit ever shows, since no access check can reach them ---
    WhyTokenInvalid,
    WhyCrossSite,
    WhyKeyUnknown,
    WhyKeyExpired,
    WhyKeyOwnerDenied,
    WhyUnEnrolledGrant,
    WhyUnknownReason,
    // --- the audit ---
    Audit,
    AuditIntro,
    AuditOff,
    AuditOffHelp,
    AuditRefresh,
    AuditWindow,
    AuditAll,
    AuditOutcome,
    AuditAny,
    AuditAllowed,
    AuditRefused,
    AuditCredential,
    AuditDamaged,
    AuditTruncated,
    AuditDeduped,
    ColWhen,
    ColEvent,
    ColWho,
    ColClient,
    ColWhere,
    ColWhy,
    AuditZone,
    TzLocal,
    TzCustom,
    TzCustomHint,
    TzUnknown,
    TzLocalMissing,
    KindLoginGranted,
    KindLoginRefused,
    KindLoginEnded,
    KindAccessGranted,
    KindAccessRefused,
    CredSocial,
    CredLocal,
    CredKey,
    CredSession,
    CredAnonymous,
    AppSees,
    NoProxyTitle,
    NoProxyBody,
    NoIdentityTitle,
    NoIdentityBody,
    NotAdminTitle,
    NotAdminBody,
    NotAdminToAccount,
    NotFoundTitle,
    NotFoundBody,
    FileErrorTitle,
    FileErrorHint,
    SignOut,
    // --- the settings menu ---
    Settings,
    // The word that turns the bar's name into a control's name: "Ada, account menu"
    // (§13.28 §1).
    AccountMenu,
    // §13.34 §4: the fifth tab's word. `Config` stays the page's own title ("System settings"),
    // because the heading and the `<title>` say what the page is and a tab has to fit the strip.
    ConfigTab,
    // §13.34 §2: the ☰'s accessible name. The control is an icon, so this string is its name.
    NavMenu,
    // The self-service menu's last row (§13.30 §1). The words say what the press costs, because
    // the worker's deletion is the one action on this estate nobody can undo.
    AccountDelete,
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
    // --- the filter and pager every list carries ---
    Filter,
    /// The roster's box, and the only one that says what it searches: the reach (every email,
    /// the uuid, every key id) was never readable off a box that said "filter" (§13.36 §4).
    FilterPeople,
    /// The group page's member box (§13.36 §4, one list along). Its list filters a member's
    /// label and uuid and nothing else, so it cannot borrow `K::FilterPeople`, whose sentence
    /// promises a key id this list holds no key in: a box promising a search that answers
    /// nothing is the failure mode §4 exists to close.
    FilterMembers,
    FilterClear,
    PagePrev,
    PageNext,
    /// "rows 26–50 of 1234": the first row shown, the last, and how many matched. The one
    /// sentence that replaced the "page 2/5" fragment and the bare "matched/total" span
    /// (§13.36 §4). The en dash is a range, so it is data and not prose.
    PagerRows,
    /// The same with the list's whole length, while a filter is set (§13.36 §4).
    PagerRowsFiltered,
    NoMatch,
    // --- the words the application-centric file is made of ---
    Base,
    BaseHelp,
    LoginUrl,
    LoginUrlHelp,
    DeniedUrl,
    DeniedUrlHelp,
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
    Excluded,
    ExcludedHelp,
    ExcludedNone,
    CredNoneNeeded,
    Uuid,
    Emails,
    /// The roster's groups column (§13.36 §3): the groups that name this person. Lowercase
    /// like the `emails` column beside it, because it names the file's `user_groups` section.
    ColGroups,
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
    /// The two halves of the click hint, with the word `Bearer` emitted between them as a
    /// `code` element. Split because a word the person has to type is markup, not prose: a
    /// backtick inside a translated sentence reaches the page as a backtick.
    BearerHintLead,
    BearerHintTail,
    CopyKey,
    CopyDone,
    CopyFailed,
    // --- refusals a form makes on its own ---
    ExcludedNotAnon,
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
    RotateConflictTitle,
    RotateConflictBody,
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
    MsgSettingsSaved,
    // --- the settings page ---
    // The word for that page, and for the panel's row to it (§13.28 §2, §8). It says "system"
    // because the page edits the deployment's settings, and the panel's own rows are a
    // person's preferences: two words for two places, since one row in a menu that holds both
    // is read as the menu's whole subject.
    Config,
    ConfigIntro,
    ConfigAccess,
    ConfigHandover,
    ConfigSignIn,
    ConfigAdminLook,
    ConfigAudit,
    ClientIpHeader,
    ClientIpHeaderHelp,
    RequestIdHeader,
    RequestIdHeaderHelp,
    AuditRotation,
    AuditRotationHelp,
    AuditRetention,
    AuditRetentionHelp,
    AuditOnDisk,
    LimitNone,
    UnitWeek,
    UnitWeeks,
    UnitMonth,
    UnitMonths,
    UnitYear,
    UnitYears,
    GroupsExpand,
    GroupsCollapse,
    ConfigHot,
    ProfileClaims,
    ProfileClaimsHelp,
    IdentityAttrs,
    IdentityAttrsHelp,
    SessionTtl,
    SessionTtlHelp,
    SessionTtlBad,
    UnverifiedSocial,
    UnverifiedSocialHelp,
    SocialWaysHelp,
    GlobalLoginUrl,
    GlobalLoginUrlHelp,
    GlobalDeniedUrl,
    GlobalDeniedUrlHelp,
    GlobalLandingUrl,
    GlobalLandingUrlHelp,
    OauthDomain,
    OauthDomainHelp,
    SocialCallback,
    SocialCallbackHelp,
    SignInWays,
    SignInEmail,
    ClientIdNeeded,
    AudienceNeeded,
    SocialWiringNeeded,
    ColShownAs,
    ColAudience,
    SocialProviders,
    SocialProvidersHelp,
    Issuer,
    IssuerHelp,
    IssuerNeeded,
    CookieDomain,
    CookieDomainHelp,
    AuthorizedHosts,
    AuthorizedHostsHelp,
    AuthorizedHostsNeeded,
    ConfirmTitle,
    ConfirmLede,
    ConfirmSafety,
    ConfirmSave,
    ColSetting,
    ColNow,
    ColAfter,
    RiskIssuer,
    RiskClientId,
    RiskLoginUrl,
    RiskCookieDomain,
    RiskAuthorizedHosts,
    Admins,
    AdminsHelp,
    AdminsKeepYourself,
    AdminsNeverEmpty,
    StylesheetUrl,
    StylesheetUrlHelp,
    LogoUrl,
    LogoUrlHelp,
    BrandName,
    BrandNameHelp,
    DefaultTheme,
    DefaultThemeHelp,
    DefaultThemeBad,
    // --- a settings-file refusal, in the reader's language (docs/ARCHITECTURE.md §13.31) ---
    //
    // One key per refusal the library answers with a code, so the page that refuses a save says
    // the same thing in Italian as it says in English. The `{0}` of each is the visible label of
    // the field it is marked on, which is why none of them spells a wire name: an operator reads
    // "Landing page", never `landing_url`. A typed value is quoted only where the refusal is
    // about one entry of a list (a claim, an attribute, a host) or about a header name, since
    // there the value is the thing to point at; a whole-field refusal quotes nothing, because the
    // field below already shows what was typed.
    //
    // The library's code list is the authority on how many there are: `settings_refusal` matches
    // on the variant with no wildcard arm, so a refusal added there stops this GUI compiling
    // until it is given a key here.
    SetRefFileOnly,
    SetRefClaimCharset,
    SetRefClaimEmptyPart,
    SetRefClaimConsumed,
    SetRefClaimHeaderReserved,
    SetRefClaimsCollide,
    SetRefAttrUnknown,
    SetRefAttrTwice,
    SetRefAttrNone,
    SetRefTtlBelowFloor,
    SetRefTtlAboveCeiling,
    SetRefAppClientId,
    SetRefUrlNotPrintable,
    SetRefUrlNotHttps,
    SetRefUrlEmptyHost,
    SetRefUrlUserinfo,
    SetRefUrlBackslash,
    SetRefUrlUserinfoOrBackslash,
    SetRefUrlQueryOrFragment,
    SetRefUrlQuote,
    SetRefUrlNotHttpsOrRooted,
    SetRefCallbackNotHttps,
    SetRefCookieDomainNotBare,
    SetRefCookieDomainSingleLabel,
    SetRefHostControlByte,
    SetRefHostNotBare,
    SetRefHostAtOrDotDot,
    SetRefHostsOutsideCookieDomain,
    SetRefLandingOffHosts,
    SetRefOauthDomainNotBare,
    SetRefHeaderNotAName,
    SetRefHeaderCredential,
    SetRefHeadersSame,
    SetRefLimitNotAmount,
    SetRefLimitZero,
    SetRefLimitTooMuch,
    SetRefAuditUnbounded,
    SetRefBrandControl,
    SetRefBrandTooLong,
    // The two the page raises itself, in the same register as the library's (`Admins:` then
    // what is needed), because the library cannot make them: it does not know who is signed
    // in. Their `Admins*` neighbours keep their own keys and words, since those read as a
    // shell message and as a bracketed help line, where a label in front would repeat the
    // label printed just above them (§13.31 §10).
    SetRefAdminsNone,
    SetRefAdminsSelf,
    Days,
    // --- the self-service page ---
    //
    // Deliberately few, because the page's contract is about which fact belongs in which
    // section: prose in one is a word a test about another could match by accident, and the
    // sections carry a heading, the names, and one short "none" line. The mint form's words are
    // the one place this page carries prose, and they are the shape of what it asks for and the
    // reason a submission was refused: the person reading them has no administrator in the room,
    // so each has to say what to write instead.
    AccountTitle,
    AccountIdLabel,
    AccountNoRowTitle,
    AccountNoRowBody,
    AccountReach,
    AccountReachSub,
    AccountReachNone,
    AccountGroups,
    AccountGroupsSub,
    AccountGroupsNone,
    AccountKeys,
    AccountKeysSub,
    AccountKeysNone,
    AccountProfile,
    AccountProfileSub,
    AccountProfileNone,
    AccountNotProvided,
    // The profile edit (§13.22) and its interface (§13.23). The words are the designer's, in one
    // table, and no logic reads any of them.
    AccountProfileEdit,
    AccountProfileEditSub,
    AccountProfileNotNative,
    AccountProfileEmailFixed,
    AccountProfileClearDeletes,
    AccountProfileDateHint,
    AccountProfileSendCode,
    AccountProfileNothingChanged,
    AccountProfileValueBad,
    AccountProfileCannotEdit,
    AccountProfileCodeTitle,
    AccountProfileCodeSent,
    AccountProfileCodeSentNoDest,
    AccountProfileCodeLasts,
    AccountProfileChanges,
    AccountProfileWas,
    AccountProfileRemoved,
    AccountProfileCodeLabel,
    AccountProfileSave,
    AccountProfileNoCode,
    AccountProfileSendNew,
    AccountProfileNotSavedTitle,
    AccountProfileNoAnswer,
    AccountProfileNoUser,
    AccountProfileTooMany,
    AccountProfileRefused,
    // The code step (§13.22, §13.23 §4): the three ways the code itself goes wrong, the page a
    // save lands on, and the one page that cannot say whether anything changed.
    AccountProfileWrongCode,
    AccountProfileExpired,
    AccountProfileNotYours,
    AccountProfileSavedTitle,
    AccountProfileSavedLead,
    AccountProfileSavedBody,
    AccountProfileUnsureTitle,
    AccountProfileNoAnswerUnsure,
    AccountProfileBadValue,
    // The twelve `oidc:profile` attributes in words (§13.23 §5). One key each, used as the form's
    // label, as the change summary's name and as the read-only panel's name, so the three can
    // never call one field by two names.
    AttrName,
    AttrGivenName,
    AttrFamilyName,
    AttrMiddleName,
    AttrNickname,
    AttrProfile,
    AttrPicture,
    AttrWebsite,
    AttrGender,
    AttrBirthdate,
    AttrZoneinfo,
    AttrLocale,
    AccountKeyAdd,
    AccountKeyCreate,
    AccountKeyIdHint,
    AccountKeyRotate,
    AccountKeyRemove,
    AccountKeyNotYours,
    // The mint form's refusals, one per fact (§13.17): the one that replaced
    // `AccountKeyBound` says which of the two fields is wrong, not both.
    AccountKeyIdBad,
    AccountKeyTooShort,
    AccountKeyFull,
    AccountKeyDup,
    AccountKeyUnknownScope,
    // The keys table and its `+ New key` row (§13.16). The two column words are the
    // table's headings **and** the mint form's field labels: a field and the column
    // that shows the same value must not answer that value's name from two entries.
    AccountKeyNew,
    AccountKeyFullRow,
    AccountKeyRotateWarn,
    AccountKeyRemoveWarn,
    KeyColName,
    KeyColExpires,
    KeyScopesAll,
    KeyScopesOnly,
    KeyScopeGone,
    KeyScopesWithoutOnly,
    KeyScopesChoose,
    // The five duration choices (§13.15), the custom box, and the three refusals
    // `duration_from_form` answers with.
    DurOneYear,
    DurSixMonths,
    DurThreeMonths,
    DurCustom,
    DurNever,
    DurDaysLabel,
    DurDaysHint,
    KeyDurationRequired,
    KeyDaysWithoutCustom,
    KeyDaysInvalid,
    AccountVetoTitle,
    AccountVetoBody,
    AccountAmbiguousTitle,
    AccountAmbiguousBody,
    AccountNoEmailTitle,
    AccountNoEmailBody,
    // The delete confirmation page (§13.30 §2), in its two variants. The words name what goes
    // and what is kept, because the one act this page asks for cannot be undone, and the design
    // names no euphemism for it: the sign-in accounts are "queued", never "deleted", since the
    // press does not delete them (§13.29 W3). The audit sentence is the deployment's own number,
    // read from the policy, so the page cannot promise a retention an operator did not set.
    AccountDeleteTitle,
    AccountDeleteLead,
    AccountDeleteGoes,
    AccountDeleteRecord,
    AccountDeleteKeysLead,
    AccountDeleteGroupsLead,
    AccountDeleteSignInOne,
    AccountDeleteSignInMany,
    AccountDeleteLater,
    AccountDeleteAuditKept,
    AccountDeleteAuditTail,
    AccountDeleteAuditSize,
    AccountDeleteTypeLabel,
    AccountDeleteTypeHintMany,
    AccountDeleteConfirm,
    // The pages a deletion request answers with (§13.30 §4). The words are here, never in a
    // handler: the handler picks a key, and the key's words are the reader's language's.
    AccountDeleteQueuedTitle,
    AccountDeleteNowGone,
    AccountDeleteQueued,
    AccountDeletedClose,
    AccountDeletePartialTitle,
    AccountDeleteNotQueued,
    AccountDeleteUnsureTitle,
    AccountDeleteMaybeQueued,
    AccountDeleteSome,
    AccountDeleteUnconfirmedLead,
    AccountDeleteRetryOneAddress,
    AccountDeleteNotDoneTitle,
    AccountDeleteProtected,
    AccountDeleteNoCheck,
    AccountDeleteRetry,
    AccountDeleteStartAgain,
    AccountDeleteWriteFailed,
    AccountDeleteChangedTitle,
    AccountDeleteChanged,
    AccountDeleteTypedWrong,
    AccountDeleteTooMany,
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
        K::Config => m(lang, "System settings", "Impostazioni di sistema"),
        K::ConfigTab => m(lang, "Settings", "Impostazioni"),
        K::NavMenu => m(lang, "Navigation menu", "Menu di navigazione"),
        K::ConfigIntro => m(
            lang,
            "The settings that take effect with no restart. Everything else bb-auth is configured with stays in its env file, on the host.",
            "Le impostazioni che hanno effetto senza riavvio. Tutto il resto della configurazione di bb-auth resta nel suo file di environment, sull'host.",
        ),
        K::ConfigAccess => m(lang, "Access policy", "Politica di accesso"),
        K::ConfigHandover => m(
            lang,
            "What the application receives",
            "Cosa riceve l'applicazione",
        ),
        K::ConfigSignIn => m(lang, "The sign-in page", "La pagina di accesso"),
        K::ConfigAdminLook => m(lang, "Administration and look", "Amministrazione e aspetto"),
        K::ConfigAudit => m(lang, "What the audit records", "Cosa registra l'audit"),
        K::ClientIpHeader => m(
            lang,
            "Client address header",
            "Header dell'indirizzo del client",
        ),
        K::ClientIpHeaderHelp => m(
            lang,
            "The request header the audit reads the client's address from, such as X-Real-IP. Empty records no address. Name it only once nginx overwrites this header on every location that reaches the gate: one it does not overwrite is the client's own, and the audit would write down whatever the client chose to say. A list such as X-Forwarded-For is read from its last entry, which is the one nginx added.",
            "L'header da cui l'audit legge l'indirizzo del client, per esempio X-Real-IP. Vuoto non registra alcun indirizzo. Indicalo solo quando nginx sovrascrive questo header su ogni location che arriva al gate: uno che non sovrascrive è quello del client, e l'audit scriverebbe qualunque cosa il client abbia scelto di dire. Di una lista come X-Forwarded-For si legge l'ultima voce, cioè quella aggiunta da nginx.",
        ),
        K::AuditRotation => m(lang, "Rotation", "Rotazione"),
        K::AuditRotationHelp => m(
            lang,
            "When the live file moves onto the previous one, which it replaces: only the last is kept. A size (MiB, GiB), or an age of the file's oldest event (weeks, months, years).",
            "Quando il file attivo passa al posto del precedente, che sostituisce: si conserva solo l'ultimo. Una dimensione (MiB, GiB), oppure l'età dell'evento più vecchio del file (settimane, mesi, anni).",
        ),
        K::AuditRetention => m(lang, "Retention", "Conservazione"),
        K::AuditRetentionHelp => m(
            lang,
            "The most the audit keeps, across both files. An age: no event older than it stays on disk, which is the one to use for personal data such as addresses. A size: the two files together never exceed it. At least one of rotation and retention must be a size, or a flood of refusals could fill the disk.",
            "Il massimo che l'audit conserva, sommando i due file. Un'età: nessun evento più vecchio resta su disco, ed è quella da usare per dati personali come gli indirizzi. Una dimensione: i due file insieme non la superano mai. Almeno una tra rotazione e conservazione deve essere una dimensione, altrimenti un'ondata di rifiuti potrebbe riempire il disco.",
        ),
        K::AuditOnDisk => m(lang, "At most on disk", "Al massimo su disco"),
        K::LimitNone => m(lang, "none", "nessuna"),
        K::UnitWeek => m(lang, "week", "settimana"),
        K::UnitWeeks => m(lang, "weeks", "settimane"),
        K::UnitMonth => m(lang, "month", "mese"),
        K::UnitMonths => m(lang, "months", "mesi"),
        K::UnitYear => m(lang, "year", "anno"),
        K::UnitYears => m(lang, "years", "anni"),
        K::GroupsExpand => m(lang, "Expand all", "Espandi tutto"),
        K::GroupsCollapse => m(lang, "Collapse all", "Comprimi tutto"),
        K::RequestIdHeader => m(lang, "Request id header", "Header dell'id della richiesta"),
        K::RequestIdHeaderHelp => m(
            lang,
            "The request header carrying nginx's own id for the request, such as X-Request-ID set from $request_id. Empty records none. With $request_id in nginx's log format as well, the id on an audit row finds that request's line in nginx's access log, which has everything the audit leaves out. The same rule holds: nginx must overwrite it.",
            "L'header con l'id che nginx assegna alla richiesta, per esempio X-Request-ID impostato da $request_id. Vuoto non registra nulla. Con $request_id anche nel log_format di nginx, l'id su una riga dell'audit ritrova la riga di quella richiesta nel log di accesso di nginx, che contiene tutto quello che l'audit tralascia. Vale la stessa regola: nginx deve sovrascriverlo.",
        ),
        K::ConfigHot => m(
            lang,
            "Saved here, live on the next request.",
            "Salvato qui, attivo dalla richiesta successiva.",
        ),
        K::ProfileClaims => m(lang, "Profile claims", "Claim di profilo"),
        K::ProfileClaimsHelp => m(
            lang,
            "OIDC claims to hand to the application, one per line. The header is derived from the name and is never configured: given_name becomes X-Auth-Given-Name. They are self-asserted decoration: they authorize nothing.",
            "Claim OIDC da passare all'applicazione, uno per riga. L'header è derivato dal nome e non si configura: given_name diventa X-Auth-Given-Name. Sono decorazione auto-dichiarata: non autorizzano nulla.",
        ),
        K::IdentityAttrs => m(lang, "Identity attributes", "Attributi di identità"),
        K::IdentityAttrsHelp => m(
            lang,
            "What a 204 names the authorized identity with, one per line: email, uuid. Never empty. nginx already clears both names, so turning one on needs no change there.",
            "Con cosa un 204 nomina l'identità autorizzata, uno per riga: email, uuid. Mai vuoto. nginx azzera già entrambi i nomi, quindi accenderne uno non richiede modifiche lì.",
        ),
        K::SessionTtl => m(lang, "Session lifetime", "Durata della sessione"),
        // The list box's own words, not the file's codes: the box shows "Light", "Dark" and
        // the system option in the reader's language, so `light, dark, system` were wire
        // words on a page (§13.31 §10). Only a request this form did not build carries
        // another value, which is what the sentence says.
        K::SessionTtlBad => m(
            lang,
            "{0}: must be a whole number of seconds, such as 2592000 for 30 days.",
            "{0}: deve essere un numero intero di secondi, come 2592000 per 30 giorni.",
        ),
        K::DefaultThemeBad => m(
            lang,
            "{0}: choose one of the options in the list; this request carried a value the \
             list does not offer.",
            "{0}: scegli una delle opzioni dell'elenco; questa richiesta portava un valore \
             che l'elenco non offre.",
        ),
        // A settings-file refusal, in the reader's language (§13.31). `{0}` is the visible label
        // of the field the refusal is marked on, filled by `settings_refusal` through `fill`.
        K::SetRefFileOnly => m(
            lang,
            "The settings file is refused for a reason this page cannot fix: correct it with bb-auth-adm over SSH. The gate says: {0}",
            "Il file delle impostazioni viene rifiutato per un motivo che questa pagina non può risolvere: correggilo con bb-auth-adm via SSH. Il gate dice: {0}",
        ),
        K::SetRefClaimCharset => m(
            lang,
            "{0}: '{1}' may contain only letters, digits, '_', ':' and '-'.",
            "{0}: '{1}' può contenere solo lettere, cifre, '_', ':' e '-'.",
        ),
        K::SetRefClaimEmptyPart => m(
            lang,
            "{0}: '{1}' starts or ends with '_', ':' or '-', or has two of them in a row; each one must sit between letters or digits.",
            "{0}: '{1}' inizia o finisce con '_', ':' o '-', oppure ne ha due di fila; ognuno deve stare tra lettere o cifre.",
        ),
        K::SetRefClaimConsumed => m(
            lang,
            "{0}: '{1}' is a claim the gate reads for itself, so it cannot be passed to the application.",
            "{0}: '{1}' è un claim che il gate legge per sé, quindi non può essere passato all'applicazione.",
        ),
        K::SetRefClaimHeaderReserved => m(
            lang,
            "{0}: '{1}' would become the header {2}, which the gate keeps for itself.",
            "{0}: '{1}' diventerebbe l'header {2}, che il gate riserva a sé.",
        ),
        K::SetRefClaimsCollide => m(
            lang,
            "{0}: '{1}' and '{2}' would both become the header {3}; keep only one of them.",
            "{0}: '{1}' e '{2}' diventerebbero entrambi l'header {3}; tienine solo uno.",
        ),
        K::SetRefAttrUnknown => m(
            lang,
            "{0}: '{1}' is not one of: {2}.",
            "{0}: '{1}' non è uno tra: {2}.",
        ),
        K::SetRefAttrTwice => m(
            lang,
            "{0}: '{1}' is listed twice.",
            "{0}: '{1}' compare due volte.",
        ),
        K::SetRefAttrNone => m(
            lang,
            "{0}: at least one is needed ({1}); without one, the applications behind the gate cannot tell who signed in.",
            "{0}: ne serve almeno uno ({1}); senza, le applicazioni dietro il gate non sanno chi è entrato.",
        ),
        K::SetRefTtlBelowFloor => m(
            lang,
            "{0}: must be at least {1} seconds; a session that expires as it is handed over sends everybody back to the sign-in page.",
            "{0}: servono almeno {1} secondi; una sessione che scade mentre viene consegnata rimanda tutti alla pagina di accesso.",
        ),
        K::SetRefTtlAboveCeiling => m(
            lang,
            "{0}: must be at most {1} seconds.",
            "{0}: può essere al massimo di {1} secondi.",
        ),
        K::SetRefAppClientId => m(
            lang,
            "App client for {0}: '{1}' may contain only letters, digits, '.', '_' and '-'.",
            "App client per {0}: '{1}' può contenere solo lettere, cifre, '.', '_' e '-'.",
        ),
        K::SetRefUrlNotPrintable => m(
            lang,
            "{0}: may contain only plain ASCII characters, with no spaces, accented letters or control characters.",
            "{0}: può contenere solo caratteri ASCII semplici, senza spazi, lettere accentate o caratteri di controllo.",
        ),
        K::SetRefUrlNotHttps => m(
            lang,
            "{0}: must be an absolute address starting with https://.",
            "{0}: deve essere un indirizzo assoluto che inizia con https://.",
        ),
        K::SetRefUrlEmptyHost => m(
            lang,
            "{0}: the address names no host after https://.",
            "{0}: l'indirizzo non indica alcun host dopo https://.",
        ),
        K::SetRefUrlUserinfo => m(
            lang,
            "{0}: a user name and '@' before the host are not allowed.",
            "{0}: un nome utente con '@' prima dell'host non è ammesso.",
        ),
        K::SetRefUrlBackslash => m(
            lang,
            "{0}: a backslash (\\) is not allowed.",
            "{0}: la barra rovesciata (\\) non è ammessa.",
        ),
        K::SetRefUrlUserinfoOrBackslash => m(
            lang,
            "{0}: neither a user name with '@' nor a backslash (\\) is allowed.",
            "{0}: non sono ammessi né un nome utente con '@' né la barra rovesciata (\\).",
        ),
        K::SetRefUrlQueryOrFragment => m(
            lang,
            "{0}: must be the issuer address alone, with no '?' query and no '#' fragment.",
            "{0}: deve essere solo l'indirizzo dell'issuer, senza query '?' né frammento '#'.",
        ),
        K::SetRefUrlQuote => m(
            lang,
            "{0}: quotes and angle brackets are not allowed.",
            "{0}: virgolette e parentesi angolari non sono ammesse.",
        ),
        K::SetRefUrlNotHttpsOrRooted => m(
            lang,
            "{0}: must be an absolute https:// address or a path starting with '/'.",
            "{0}: deve essere un indirizzo https:// assoluto o un percorso che inizia con '/'.",
        ),
        K::SetRefCallbackNotHttps => m(
            lang,
            "{0}: must be the absolute https:// address registered on the app clients, because Cognito compares it byte for byte.",
            "{0}: deve essere l'indirizzo https:// assoluto registrato sugli app client, perché Cognito lo confronta byte per byte.",
        ),
        K::SetRefCookieDomainNotBare => m(
            lang,
            "{0}: must be a bare domain such as .example.com: letters, digits, '.' and '-', with no scheme, port or path.",
            "{0}: deve essere un dominio puro come .example.com: lettere, cifre, '.' e '-', senza schema, porta o percorso.",
        ),
        K::SetRefCookieDomainSingleLabel => m(
            lang,
            "{0}: no browser keeps a cookie for a one-word domain; name the domain the services share, such as .example.com.",
            "{0}: nessun browser conserva un cookie per un dominio di una sola parola; indica il dominio che i servizi hanno in comune, come .example.com.",
        ),
        K::SetRefHostControlByte => m(
            lang,
            "{0}: '{1}' contains a control character, often left by a paste; type it again.",
            "{0}: '{1}' contiene un carattere di controllo, spesso lasciato da un copia e incolla; riscrivilo.",
        ),
        K::SetRefHostNotBare => m(
            lang,
            "{0}: '{1}' must be a bare host such as app.example.com, with no scheme, port or path.",
            "{0}: '{1}' deve essere un host puro come app.example.com, senza schema, porta o percorso.",
        ),
        K::SetRefHostAtOrDotDot => m(
            lang,
            "{0}: '{1}' must not contain '@' or '..'.",
            "{0}: '{1}' non deve contenere '@' o '..'.",
        ),
        K::SetRefHostsOutsideCookieDomain => m(
            lang,
            "{0}: the {2} '{3}' does not reach {1}, so a sign-in that lands there carries no session cookie and loops back to the sign-in page.",
            "{0}: il {2} '{3}' non raggiunge {1}, quindi un accesso che arriva lì non porta il cookie di sessione e torna in ciclo alla pagina di accesso.",
        ),
        K::SetRefLandingOffHosts => m(
            lang,
            "{0}: must be on one of the {1}, or every sign-in that names no page falls back to the sign-in page.",
            "{0}: deve stare su uno degli {1}, altrimenti ogni accesso che non indica una pagina ricade sulla pagina di accesso.",
        ),
        K::SetRefOauthDomainNotBare => m(
            lang,
            "{0}: must be a bare host: letters, digits, '.' and '-', with no scheme and no path.",
            "{0}: deve essere un host puro: lettere, cifre, '.' e '-', senza schema né percorso.",
        ),
        K::SetRefHeaderNotAName => m(
            lang,
            "{0}: '{1}' is not a header name: letters, digits and '-' only (nginx drops a header with an underscore in its name).",
            "{0}: '{1}' non è un nome di header: solo lettere, cifre e '-' (nginx scarta un header con un trattino basso nel nome).",
        ),
        K::SetRefHeaderCredential => m(
            lang,
            "{0}: '{1}' carries a credential, and the audit never writes one down.",
            "{0}: '{1}' contiene una credenziale, e l'audit non registra mai credenziali.",
        ),
        K::SetRefHeadersSame => m(
            lang,
            "{0}: '{1}' is already the {2}; one header cannot carry both an address and a request id.",
            "{0}: '{1}' è già l'{2}; un solo header non può portare sia un indirizzo sia un id di richiesta.",
        ),
        K::SetRefLimitNotAmount => m(
            lang,
            "{0}: the amount must be a whole number.",
            "{0}: la quantità deve essere un numero intero.",
        ),
        K::SetRefLimitZero => m(
            lang,
            "{0}: the amount must be more than 0.",
            "{0}: la quantità deve essere maggiore di 0.",
        ),
        K::SetRefLimitTooMuch => m(
            lang,
            "{0}: the most allowed is {1} {2}.",
            "{0}: il massimo ammesso è {1} {2}.",
        ),
        K::SetRefAuditUnbounded => m(
            lang,
            "{0} and {1}: at least one of the two must be a size (MiB, GiB), or a flood of refusals would grow the audit without limit.",
            "{0} e {1}: almeno una delle due deve essere una dimensione (MiB, GiB), altrimenti un'ondata di rifiuti farebbe crescere l'audit senza limite.",
        ),
        K::SetRefBrandControl => m(
            lang,
            "{0}: control characters are not allowed.",
            "{0}: i caratteri di controllo non sono ammessi.",
        ),
        K::SetRefBrandTooLong => m(
            lang,
            "{0}: {1} characters, and at most {2} are allowed.",
            "{0}: {1} caratteri, e ne sono ammessi al massimo {2}.",
        ),
        // The page's own two, in the same register: the label, then what is needed. The
        // library cannot raise them, because it does not know who is signed in.
        K::SetRefAdminsNone => m(
            lang,
            "{0}: at least one is needed; an empty list must never come to mean 'everyone'.",
            "{0}: ne serve almeno uno; una lista vuota non deve mai finire per significare \
             'chiunque'.",
        ),
        K::SetRefAdminsSelf => m(
            lang,
            "{0}: your own address must stay on the list; to remove yourself, use \
             bb-auth-adm over SSH.",
            "{0}: il tuo indirizzo deve restare nella lista; per rimuovere te stesso usa \
             bb-auth-adm via SSH.",
        ),
        K::SessionTtlHelp => m(
            lang,
            "Seconds. Applies to cookies minted from now on: nobody is logged out by changing it.",
            "Secondi. Vale per i cookie coniati da adesso: cambiarla non disconnette nessuno.",
        ),
        K::UnverifiedSocial => m(
            lang,
            "Accept unverified social emails",
            "Accetta email social non verificate",
        ),
        K::UnverifiedSocialHelp => m(
            lang,
            "Only for federated logins (Google, Apple…), never for native Cognito users, whose sign-up is open and whose unverified email is attacker-controlled.",
            "Solo per accessi federati (Google, Apple…), mai per utenti Cognito nativi: la loro registrazione è aperta e un'email non verificata è controllata da chi attacca.",
        ),

        K::GlobalLoginUrl => m(lang, "Sign-in page", "Pagina di accesso"),
        K::GlobalLoginUrlHelp => m(
            lang,
            "Where a 401 sends people, and where a rejected redirect lands. Empty means the gate's own /auth/login on the host the request arrived at, which is what a deployment that has not moved its sign-in page wants. An application can override it for its own area.",
            "Dove un 401 manda le persone, e dove finisce un redirect rifiutato. Vuoto significa la /auth/login del gate stesso sull'host da cui arriva la richiesta, che è quello che vuole un deployment che non ha spostato la propria pagina di accesso. Una applicazione può sovrascriverla per la propria area.",
        ),
        K::GlobalDeniedUrl => m(lang, "Refusal page", "Pagina di rifiuto"),
        K::GlobalDeniedUrlHelp => m(
            lang,
            "Where a 403 sends people: somebody who is signed in and is not admitted here. Empty means the gate's own /auth/denied, which it builds out of the look below. It cannot shut a door, only decide what the person already shut out is shown. An application can override it for its own area, which is how one gate gives each host its own page.",
            "Dove un 403 manda le persone: qualcuno che ha fatto l'accesso e qui non è ammesso. Vuoto significa la /auth/denied del gate stesso, costruita con l'aspetto qui sotto. Non può chiudere nessuna porta: decide solo cosa vede chi è già stato respinto. Una applicazione può sovrascriverla per la propria area, ed è così che un solo gate dà a ogni host la sua pagina.",
        ),
        K::GlobalLandingUrl => m(lang, "Landing page", "Pagina di arrivo"),
        K::GlobalLandingUrlHelp => m(
            lang,
            "Where a sign-in lands when nothing named a place. Empty means the caller's root. It must be on one of the authorized hosts, or every sign-in falls back to the sign-in page.",
            "Dove arriva un accesso quando nessuno ha indicato una pagina. Vuoto significa la radice del chiamante. Deve stare su uno degli host autorizzati, altrimenti ogni accesso ricade sulla pagina di accesso.",
        ),
        K::OauthDomain => m(lang, "Hosted UI domain", "Dominio della hosted UI"),
        K::OauthDomainHelp => m(
            lang,
            "Cognito's hosted UI for this pool, as a bare host: no scheme, no path. Empty means this deployment offers no social sign-in at all, whatever the table below says.",
            "La hosted UI Cognito di questo pool, come host puro: niente schema, niente percorso. Vuoto significa nessun accesso social, qualunque cosa dica la tabella sotto.",
        ),
        K::SocialCallback => m(lang, "Callback URL", "URL di callback"),
        K::SocialCallbackHelp => m(
            lang,
            "Where Cognito sends the browser back, normally /auth/callback on the host that serves the sign-in page. It must be registered byte for byte on every app client in the table, or Amazon answers redirect_mismatch on Amazon's page.",
            "Dove Cognito rimanda il browser, di norma /auth/callback sull'host che serve la pagina di accesso. Deve essere registrato byte per byte su ogni app client della tabella, altrimenti Amazon risponde redirect_mismatch sulla propria pagina.",
        ),
        K::SignInWays => m(lang, "Ways in", "Modi di accesso"),
        K::SignInEmail => m(lang, "Email and code", "Email e codice"),
        K::ClientIdNeeded => m(
            lang,
            "App client for {0}: cannot be empty; without one, no sign-in can complete. It \
             is the Cognito app client the sign-in page signs people in against.",
            "App client per {0}: non può essere vuoto; senza, nessun accesso può \
             concludersi. È l'app client Cognito con cui la pagina di accesso fa entrare le \
             persone.",
        ),
        K::AudienceNeeded => m(
            lang,
            "App client for {0}: this provider needs its own, because Cognito federates per \
             app client; name the one that offers this provider.",
            "App client per {0}: questo provider ha bisogno del proprio, perché Cognito \
             federa per app client; indica quello che offre questo provider.",
        ),
        K::SocialWiringNeeded => m(
            lang,
            "{0} and {1}: a social button needs both; without them there is nowhere to send \
             a visitor and nowhere for them to come back to.",
            "{0} e {1}: un pulsante social ha bisogno di entrambi; senza, non c'è dove \
             mandare chi entra né dove farlo tornare.",
        ),
        K::SocialWaysHelp => m(
            lang,
            "Every way into this deployment, and the Cognito app client it runs through. \
             Email and code is always offered and is the app client the sign-in page runs \
             USER_AUTH against; each social provider is offered only if it is ticked, and \
             carries its own app client, because Cognito federates per app client. These app \
             clients ARE the audiences the gate accepts: an id_token carries the client it \
             was minted for. They all belong to the User pool (issuer) above. Microsoft is \
             the personal account (outlook.com, hotmail.com), not a work or school one: an \
             Entra ID tenant is a separate provider on the pool.",
            "Ogni modo di entrare in questo deployment, e l'app client Cognito attraverso cui \
             passa. Email e codice è sempre offerto ed è l'app client con cui la pagina di \
             accesso esegue USER_AUTH; ogni provider social viene offerto solo se è spuntato \
             e porta il proprio app client, perché Cognito federa per app client. Questi app \
             client SONO le audience che il gate accetta: un id_token porta il client per cui \
             è stato emesso. Appartengono tutti allo User pool (issuer) qui sopra. Microsoft \
             è l'account personale (outlook.com, hotmail.com), non uno aziendale o \
             scolastico: un tenant Entra ID è un provider separato sul pool.",
        ),
        K::ColShownAs => m(lang, "shown as", "mostrato come"),
        K::ColAudience => m(lang, "app client (aud)", "app client (aud)"),
        K::SocialProviders => m(lang, "Providers", "Provider"),
        K::SocialProvidersHelp => m(
            lang,
            "One per line, matched against the token's providerName. Empty means any federated provider.",
            "Uno per riga, confrontati con il providerName del token. Vuoto significa qualsiasi provider federato.",
        ),
        K::Issuer => m(lang, "User pool (issuer)", "User pool (issuer)"),
        K::IssuerHelp => m(
            lang,
            "The Cognito user pool this deployment trusts: every id_token is checked against \
             its iss and signed by its keys. It is also the one pool the app clients below \
             can belong to.",
            "Lo user pool Cognito di cui questo deployment si fida: ogni id_token viene \
             verificato contro il suo iss ed è firmato dalle sue chiavi. È anche l'unico pool \
             a cui gli app client qui sotto possono appartenere.",
        ),
        K::IssuerNeeded => m(
            lang,
            "{0}: cannot be empty; without one, no token can be validated and no sign-in \
             can complete.",
            "{0}: non può essere vuoto; senza, nessun token può essere validato e nessun \
             accesso può concludersi.",
        ),
        K::CookieDomain => m(lang, "Cookie domain", "Dominio del cookie"),
        K::CookieDomainHelp => m(
            lang,
            "The domain the session cookie is sent to, such as .example.com, which is what \
             makes one login cover every service behind the gate. Empty binds the session to \
             a single host. Changing it does not sign anybody out: it does something worse, \
             so this page asks first.",
            "Il dominio a cui viene inviato il cookie di sessione, ad esempio .example.com, \
             che è ciò che fa valere un solo accesso per tutti i servizi dietro il gate. \
             Vuoto lega la sessione a un host solo. Cambiarlo non disconnette nessuno: fa \
             qualcosa di peggio, quindi questa pagina chiede prima.",
        ),
        K::AuthorizedHosts => m(lang, "Authorized hosts", "Host autorizzati"),
        K::AuthorizedHostsHelp => m(
            lang,
            "One host per line, the only places a browser may be sent after signing in. \
             Wildcards are allowed (*.example.com), and the apex has to be listed on its own \
             because *.example.com does not match example.com. Every one of them must be \
             reachable by the cookie domain above.",
            "Un host per riga, gli unici posti in cui un browser può essere mandato dopo \
             l'accesso. I wildcard sono ammessi (*.example.com) e il dominio nudo va elencato \
             a parte, perché *.example.com non corrisponde a example.com. Ognuno deve essere \
             raggiungibile dal dominio del cookie qui sopra.",
        ),
        K::AuthorizedHostsNeeded => m(
            lang,
            "{0}: at least one is needed; without one, every redirect after sign-in is \
             refused and everybody lands back on the sign-in page.",
            "{0}: ne serve almeno uno; senza, ogni redirect dopo l'accesso viene rifiutato e \
             tutti tornano alla pagina di accesso.",
        ),
        K::ConfirmTitle => m(
            lang,
            "This can stop people getting in",
            "Questa modifica può impedire l'accesso",
        ),
        K::ConfirmLede => m(
            lang,
            "Nothing has been saved. Read what each change costs, then confirm it, or go back \
             and edit the value below.",
            "Non è stato salvato niente. Leggi che cosa comporta ogni modifica, poi confermala \
             oppure torna sul campo qui sotto e correggilo.",
        ),
        K::ConfirmSafety => m(
            lang,
            "None of this invalidates a session cookie, so your own login survives the change \
             and you can put it back. If it does not, bb-auth-adm over SSH is the way back.",
            "Niente di tutto questo invalida un cookie di sessione, quindi il tuo accesso \
             sopravvive alla modifica e puoi rimetterla com'era. Se non bastasse, la via di \
             ritorno è bb-auth-adm via SSH.",
        ),
        K::ConfirmSave => m(lang, "Confirm and save", "Conferma e salva"),
        K::ColSetting => m(lang, "setting", "impostazione"),
        K::ColNow => m(lang, "now", "adesso"),
        K::ColAfter => m(lang, "after saving", "dopo il salvataggio"),
        K::RiskIssuer => m(
            lang,
            "Every id_token is checked against this pool's iss and its signing keys. Point it \
             at the wrong pool and no login completes. On reload the gate fetches the new \
             pool's keys first, and keeps the old pool if they do not answer.",
            "Ogni id_token viene verificato contro l'iss di questo pool e le sue chiavi di \
             firma. Puntalo al pool sbagliato e nessun accesso si conclude. Al reload il gate \
             scarica prima le chiavi del nuovo pool, e se non rispondono tiene il vecchio.",
        ),
        K::RiskClientId => m(
            lang,
            "The app client the email sign-in runs through, and one of the audiences a token \
             is accepted for. Wrong, and every id_token is refused for its aud.",
            "L'app client con cui gira l'accesso via email, e una delle audience per cui un \
             token viene accettato. Sbagliato, e ogni id_token viene rifiutato per il suo aud.",
        ),
        K::RiskLoginUrl => m(
            lang,
            "Where a 401 sends a browser. Wrong, and everybody who is not signed in lands on \
             a page that is not there.",
            "Dove un 401 manda il browser. Sbagliato, e chiunque non abbia una sessione \
             finisce su una pagina che non esiste.",
        ),
        K::RiskCookieDomain => m(
            lang,
            "This one does something worse than shut a door. Every session cookie already \
             issued keeps the OLD domain, so it stays valid until it expires and the logout \
             can no longer clear it: a logout that silently succeeds at nothing, for everybody \
             who signed in before this save. Putting the old value back makes those cookies \
             clearable again.",
            "Questa fa qualcosa di peggio che chiudere una porta. Ogni cookie di sessione già \
             emesso conserva il dominio VECCHIO, quindi resta valido fino alla scadenza e il \
             logout non riesce più a cancellarlo: un logout che riesce in silenzio senza fare \
             niente, per chiunque abbia fatto accesso prima di questo salvataggio. Rimettere \
             il valore di prima rende di nuovo cancellabili quei cookie.",
        ),
        K::RiskAuthorizedHosts => m(
            lang,
            "A host taken off this list can no longer be redirected to after a login, so \
             anyone signing in for it lands back on the sign-in page instead. Adding one is \
             not asked about; only removing is.",
            "Un host tolto da questa lista non può più essere la destinazione dopo un \
             accesso, quindi chi entra per quell'host torna alla pagina di accesso. \
             Aggiungerne uno non viene chiesto; solo toglierne.",
        ),
        K::Admins => m(lang, "Administrators", "Amministratori"),
        K::AdminsHelp => m(
            lang,
            "One email per line. These are the only people this interface opens for, on top of the gate that already stands in front of it.",
            "Un'email per riga. Sono le uniche persone per cui questa interfaccia si apre, oltre al gate che le sta già davanti.",
        ),
        K::AdminsKeepYourself => m(
            lang,
            "you cannot remove yourself here: do it from bb-auth-adm, over SSH",
            "non puoi rimuovere te stesso da qui: fallo da bb-auth-adm, via SSH",
        ),
        K::AdminsNeverEmpty => m(
            lang,
            "at least one administrator is required: an empty list must never come to mean 'everyone'",
            "serve almeno un amministratore: una lista vuota non deve mai finire per significare 'chiunque'",
        ),
        K::StylesheetUrl => m(lang, "Stylesheet", "Foglio di stile"),
        K::StylesheetUrlHelp => m(
            lang,
            "A stylesheet loaded after the built-in one, on this interface and on the gate's \
             own pages: an absolute https:// URL, or a path starting with / on this host. It \
             is expected to redefine the theme's custom properties and nothing else. Leave it \
             empty and the built-in look is the whole answer; a URL that does not answer costs \
             the page its palette and nothing more.",
            "Un foglio di stile caricato dopo quello incorporato, su questa interfaccia e \
             sulle pagine del gate: un URL https:// assoluto, oppure un percorso che inizia \
             con / su questo host. Deve ridefinire le custom property del tema e nient'altro. \
             Lascialo vuoto e vale l'aspetto incorporato; un URL che non risponde costa alla \
             pagina la sua palette e nulla di più.",
        ),
        K::LogoUrl => m(lang, "Logo", "Logo"),
        K::LogoUrlHelp => m(
            lang,
            "Shown on the gate's login page, above the name. Same two shapes as the \
             stylesheet. Empty means the name alone.",
            "Mostrato sulla pagina di accesso del gate, sopra il nome. Stesse due forme del \
             foglio di stile. Vuoto significa solo il nome.",
        ),
        K::BrandName => m(lang, "Name", "Nome"),
        K::BrandNameHelp => m(
            lang,
            "What the login page calls this deployment. Empty and each page falls back to its \
             own name.",
            "Come la pagina di accesso chiama questo deployment. Vuoto e ogni pagina ripiega \
             sul proprio nome.",
        ),
        K::DefaultTheme => m(lang, "Default appearance", "Aspetto predefinito"),
        K::DefaultThemeHelp => m(
            lang,
            "Which palette a page starts in for someone who has chosen nothing. The gate's \
             pages have nowhere to keep a choice, so for them this is the whole answer; here \
             it is only the default, and the Settings menu above still overrides it in your \
             own browser.",
            "Con quale palette parte una pagina per chi non ha scelto nulla. Le pagine del \
             gate non hanno dove tenere una scelta, quindi per loro è tutta la risposta; qui \
             è solo il valore predefinito, e il menu Impostazioni qui sopra continua a \
             prevalere nel tuo browser.",
        ),
        K::Days => m(lang, "days", "giorni"),
        K::MsgSettingsSaved => m(lang, "settings saved", "impostazioni salvate"),
        K::Groups => m(lang, "User groups", "Gruppi di utenti"),
        K::Apps => m(lang, "Applications", "Applicazioni"),
        K::Scopes => m(lang, "Scopes", "Ambiti"),
        K::MembersHeading => m(lang, "Members", "Membri"),
        K::Users => m(lang, "Users", "Utenti"),
        K::People => m(lang, "People", "Persone"),
        K::GroupsTab => m(lang, "Groups", "Gruppi"),
        K::UsersSections => m(lang, "Users sections", "Sezioni di Utenti"),
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
        K::KindScope => m(lang, "Scope", "Scope"),
        K::KindUser => m(lang, "User", "Utente"),
        K::KindGroup => m(lang, "User group", "Gruppo di utenti"),
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
        K::ColGroups => m(lang, "groups", "gruppi"),
        K::GroupInRoster => m(lang, "show them in People", "mostrali in Persone"),
        K::GroupFilter => m(lang, "group: {0}", "gruppo: {0}"),
        K::GroupFilterClear => m(lang, "show every group", "mostra tutti i gruppi"),
        K::AccessWord => m(lang, "access", "accesso"),
        K::Credentials => m(lang, "credentials", "credenziali"),
        K::LoginUrl => m(lang, "login_url", "login_url"),
        K::DeniedUrl => m(lang, "denied_url", "denied_url"),
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
        K::CanIntroUser => m(
            lang,
            "Would this person reach a URL? Answered by the gate's own decision function, on \
             the file as it is on disk right now.",
            "Questa persona raggiungerebbe un URL? Risponde la funzione di decisione del gate, \
             sul file così com'è su disco adesso.",
        ),
        // Only worth saying where there is more than one address to wonder about, which is why
        // it is a sentence of its own rather than part of the one above.
        K::CanAnyEmail => m(
            lang,
            "Any of the emails above gives the same answer: each one resolves to this row.",
            "Ognuna delle email qui sopra dà la stessa risposta: ciascuna risolve a questa \
             riga.",
        ),
        K::CanIntroApp => m(
            lang,
            "Would this credential reach this URL? Answered by the gate's own decision \
             function, on the file as it is on disk right now, and it names the scope that \
             answered. Leave the email empty to ask what a client with no credential at all \
             reaches.",
            "Questa credenziale raggiungerebbe questo URL? Risponde la funzione di decisione \
             del gate, sul file così com'è su disco adesso, e nomina lo scope che ha risposto. \
             Lascia l'email vuota per chiedere cosa raggiunge un client senza alcuna \
             credenziale.",
        ),
        K::CanNoIdentifier => m(
            lang,
            "This row has no email, so no credential can ever resolve to it and there is \
             nothing to check. Add one above.",
            "Questa riga non ha email, quindi nessuna credenziale può risolversi a essa e non \
             c'è nulla da verificare. Aggiungine una qui sopra.",
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
        K::WhyExcluded => m(
            lang,
            "is excluded by the scope that answered, ahead of its own grant. This is local: \
             another scope may still admit them.",
            "è escluso dallo scope che ha risposto, prima della sua stessa concessione. È \
             locale: un altro scope può comunque ammetterlo.",
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
        // The refusals that happen before any scope is consulted, or on a path the access
        // check cannot walk. They read as the continuation of a sentence the row starts, the
        // same way the eleven above do.
        K::WhyTokenInvalid => m(
            lang,
            "the token did not validate: wrong pool, wrong app client, expired, or an unverified email.",
            "il token non è stato validato: pool errato, app client errato, scaduto, o email non verificata.",
        ),
        K::WhyCrossSite => m(
            lang,
            "the sign-in did not come from a page of this estate.",
            "l'accesso non proveniva da una pagina di questo dominio.",
        ),
        K::WhyKeyUnknown => m(
            lang,
            "no key in the file has this value. The key itself is never recorded, so there is nothing to name.",
            "nessuna chiave nel file ha questo valore. La chiave non viene mai registrata, quindi non c'è nulla da nominare.",
        ),
        K::WhyKeyExpired => m(lang, "the key has expired.", "la chiave è scaduta."),
        K::WhyKeyOwnerDenied => m(
            lang,
            "the key is valid, and its owner is on the denied list.",
            "la chiave è valida, e il suo proprietario è nella lista dei negati.",
        ),
        K::WhyUnEnrolledGrant => m(
            lang,
            "let in by an authenticated scope, while being in no users entry.",
            "ammesso da uno scope authenticated, pur non essendo in nessuna voce users.",
        ),
        K::WhyUnknownReason => m(
            lang,
            "recorded by a newer version of bb-auth than this one.",
            "registrato da una versione di bb-auth più recente di questa.",
        ),
        // --- the audit ---
        K::Audit => m(lang, "Audit", "Audit"),
        K::AuditIntro => m(
            lang,
            "What the gate has answered: sign-ins, sign-outs and refusals, newest first. Ordinary allowed requests are not here and never were: they are nginx's access log, and one row per asset would bury everything on this page.",
            "Cosa ha risposto il gate: accessi, uscite e rifiuti, dal più recente. Le richieste ordinarie ammesse non ci sono e non ci sono mai state: sono nel log di nginx, e una riga per ogni asset seppellirebbe tutto il resto di questa pagina.",
        ),
        K::AuditOff => m(lang, "The audit is off", "L'audit è disattivato"),
        K::AuditOffHelp => m(
            lang,
            "BB_AUTH_AUDIT_FILE is empty in this service's env file, or names a file the gate does not write. With no file there is nothing to show: the events are in the journal instead, on the host.",
            "BB_AUTH_AUDIT_FILE è vuoto nel file di environment di questo servizio, oppure indica un file che il gate non scrive. Senza file non c'è nulla da mostrare: gli eventi sono nel journal, sull'host.",
        ),
        K::AuditRefresh => m(lang, "Refresh", "Aggiorna"),
        K::AuditWindow => m(lang, "Period", "Periodo"),
        K::AuditAll => m(lang, "Everything", "Tutto"),
        K::AuditOutcome => m(lang, "Outcome", "Esito"),
        K::AuditAny => m(lang, "Any", "Qualsiasi"),
        K::AuditAllowed => m(lang, "Allowed", "Ammesso"),
        K::AuditRefused => m(lang, "Refused", "Rifiutato"),
        K::AuditCredential => m(lang, "Credential", "Credenziale"),
        K::AuditDamaged => m(
            lang,
            "lines could not be read and were skipped.",
            "righe non sono leggibili e sono state saltate.",
        ),
        K::AuditTruncated => m(
            lang,
            "There are older events in this period than this page can hold. Narrow the period to see them.",
            "In questo periodo ci sono eventi più vecchi di quanti questa pagina possa contenerne. Restringi il periodo per vederli.",
        ),
        K::AuditDeduped => m(
            lang,
            "A refusal repeated within five minutes is recorded once: a browser refused one asset is a browser refused forty. Sign-ins and sign-outs are never collapsed.",
            "Un rifiuto ripetuto entro cinque minuti è registrato una volta sola: un browser a cui viene rifiutato un asset è un browser a cui ne vengono rifiutati quaranta. Accessi e uscite non vengono mai accorpati.",
        ),
        // The zone the times are in follows it in brackets, because it is the reader's choice
        // now and a heading that said "UTC" on its own would be wrong half the time.
        K::ColWhen => m(lang, "When", "Quando"),
        K::ColEvent => m(lang, "Event", "Evento"),
        K::ColWho => m(lang, "Who", "Chi"),
        K::ColClient => m(lang, "Client", "Client"),
        K::AuditZone => m(lang, "Time zone", "Fuso orario"),
        K::TzLocal => m(lang, "Local", "Locale"),
        K::TzCustom => m(lang, "Custom", "Personalizzato"),
        K::TzCustomHint => m(lang, "Europe/Rome or +02:00", "Europe/Rome o +02:00"),
        K::TzUnknown => m(
            lang,
            "is not a time zone this server knows, so the times below are in UTC.",
            "non è un fuso orario che questo server conosca: gli orari qui sotto sono in UTC.",
        ),
        K::TzLocalMissing => m(
            lang,
            "This server does not say which time zone it is in, so the times below are in UTC.",
            "Questo server non dice in quale fuso orario si trova: gli orari qui sotto sono in UTC.",
        ),
        K::ColWhere => m(lang, "Where", "Dove"),
        K::ColWhy => m(lang, "Why", "Perché"),
        K::KindLoginGranted => m(lang, "Signed in", "Accesso"),
        K::KindLoginRefused => m(lang, "Sign-in refused", "Accesso rifiutato"),
        K::KindLoginEnded => m(lang, "Signed out", "Uscita"),
        K::KindAccessGranted => m(lang, "Let in", "Ammesso"),
        K::KindAccessRefused => m(lang, "Refused", "Rifiutato"),
        K::CredSocial => m(lang, "Social", "Social"),
        K::CredLocal => m(lang, "Cognito account", "Account Cognito"),
        K::CredKey => m(lang, "API key", "Chiave API"),
        K::CredSession => m(lang, "Session", "Sessione"),
        K::CredAnonymous => m(lang, "None", "Nessuna"),
        K::AppSees => m(lang, "the application sees", "l'applicazione vede"),
        K::NoProxyTitle => m(
            lang,
            "Not through the proxy",
            "Non arriva dal proxy",
        ),
        K::NoProxyBody => m(
            lang,
            "this request did not carry the proxy secret, so it did not arrive through nginx. \
             The admin interface answers only through the proxy that sets it (README, \"The \
             admin GUI behind the gate\").",
            "questa richiesta non porta il secret del proxy, quindi non arriva da nginx. \
             L'interfaccia di amministrazione risponde solo attraverso il proxy che lo imposta \
             (README, \"The admin GUI behind the gate\").",
        ),
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
            "is authenticated, but is not an administrator of this interface.",
            "è autenticato, ma non è amministratore di questa interfaccia.",
        ),
        K::NotAdminToAccount => m(lang, "Go to your account", "Vai al tuo account"),
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
        K::SignOut => m(lang, "Sign out", "Esci"),
        K::Settings => m(lang, "Preferences", "Preferenze"),
        K::AccountMenu => m(lang, "account menu", "menu dell'account"),
        // The words §13.28 §5 reserved and §13.30 §1 pins, in both languages: the row names what
        // the press costs, since the worker's deletion is the one action here no administrator
        // can undo.
        K::AccountDelete => m(
            lang,
            "Delete account and all its data",
            "Elimina l'account e tutti i suoi dati",
        ),
        K::SettingLanguage => m(lang, "Language", "Lingua"),
        K::SettingTheme => m(lang, "Theme", "Tema"),
        // Named after what decides when nobody has: the browser. "Auto" alone would leave an
        // operator guessing what it follows, and this is the one option whose answer is not
        // written next to it in the list.
        K::LangAuto => m(lang, "Auto (browser)", "Auto (browser)"),
        K::Apply => m(lang, "Apply", "Applica"),
        K::ThemeLight => m(lang, "Light", "Chiaro"),
        K::ThemeDark => m(lang, "Dark", "Scuro"),
        K::ThemeSystem => m(lang, "Auto (system)", "Auto (sistema)"),

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
        K::DeniedUrlHelp => m(
            lang,
            "The page a refusal lands on for this whole area, overriding the global one. \
             Absolute https. Empty uses the global, which is itself empty for the gate\u{2019}s \
             own /auth/denied.",
            "La pagina su cui atterra un rifiuto per tutta quest\u{2019}area, che sostituisce \
             quella globale. Https assoluto. Vuoto usa quella globale, che a sua volta vuota \
             significa la /auth/denied del gate stesso.",
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

        K::Filter => m(lang, "filter", "filtro"),
        K::FilterPeople => m(lang, "email, uuid or key id", "email, uuid o id chiave"),
        K::FilterMembers => m(lang, "email or uuid", "email o uuid"),
        K::FilterClear => m(lang, "clear the filter", "azzera il filtro"),
        K::PagePrev => m(lang, "previous", "precedente"),
        K::PageNext => m(lang, "next", "successiva"),
        K::PagerRows => m(lang, "rows {0}–{1} of {2}", "righe {0}–{1} di {2}"),
        K::PagerRowsFiltered => m(
            lang,
            "rows {0}–{1} of {2} (filtered from {3})",
            "righe {0}–{1} di {2} (filtrate da {3})",
        ),
        K::NoMatch => m(
            lang,
            "nothing here matches that filter.",
            "niente qui corrisponde a quel filtro.",
        ),

        K::Excluded => m(lang, "excluded", "esclusi"),
        K::ExcludedHelp => m(
            lang,
            "Kept OUT of this scope, whatever else admits them: one per line, an email or a \
             uuid for a person, '@name' for a group. Checked before the grant, so it beats a \
             group membership and it beats 'authenticated'. An email nobody here owns is kept \
             as written \u{2014} that is how a stranger is excluded.",
            "Tenuti FUORI da questo scope, qualunque altra cosa li ammetta: uno per riga, \
             un\u{2019}email o un uuid per una persona, '@nome' per un gruppo. Controllato prima \
             della concessione, quindi batte l\u{2019}appartenenza a un gruppo e batte \
             \u{2018}authenticated\u{2019}. Un\u{2019}email che qui non è di nessuno resta com\u{2019}è \
             scritta: è così che si esclude un estraneo.",
        ),
        K::ExcludedNone => m(lang, "nobody", "nessuno"),
        K::CredNoneNeeded => m(lang, "none needed", "nessuna necessaria"),

        K::ConfirmUserRm => m(
            lang,
            "The roster row goes, and every api key it owns with it. It does NOT keep them \
             off an authenticated scope: the roster is not consulted there; that is what \
             denied is for.",
            "Sparisce la riga del roster, e con essa ogni sua api key. NON li tiene fuori da \
             uno scope authenticated: lì il roster non viene consultato; per quello c'è \
             denied.",
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
            "If any of its scopes was authenticated, the identities it let in with no roster \
             entry now reach nothing.",
            "Se uno dei suoi scope era authenticated, le identità che entravano senza riga nel \
             roster ora non raggiungono nulla.",
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
            "The veto is lifted. Whatever the roster and the scopes grant them applies again.",
            "Il veto viene tolto. Torna a valere quanto gli concedono il roster e gli scope.",
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
        K::BearerHintLead => m(
            lang,
            "Click the key to select it all, then copy. Send it as a bearer token: the word",
            "Fai clic sulla chiave per selezionarla tutta, poi copiala. Mandala come token \
             bearer: la parola",
        ),
        K::BearerHintTail => m(lang, ", a space, then the key.", ", uno spazio, poi la chiave."),
        K::CopyKey => m(lang, "Copy the key", "Copia la chiave"),
        K::CopyDone => m(lang, "Copied", "Copiata"),
        K::CopyFailed => m(
            lang,
            "Copy refused: the key is selected, copy it with the keyboard.",
            "Copia negata: la chiave è selezionata, copiala con la tastiera.",
        ),

        K::ExcludedNotAnon => m(
            lang,
            "an anonymous scope grants with no credential at all, so an excluded client would \
             simply send none. Make it authenticated, or narrow the urls",
            "uno scope anonymous concede senza alcuna credenziale, quindi un client escluso \
             semplicemente non ne manderebbe nessuna. Rendilo authenticated, o restringi le url",
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
        K::NoSuchGroup => m(lang, "no such user group", "gruppo di utenti inesistente"),
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
        K::RotateConflictTitle => m(
            lang,
            "This key was already rotated",
            "Questa chiave è già stata rigenerata",
        ),
        K::RotateConflictBody => m(
            lang,
            "Most likely this page is a reload of the one that showed the new bearer, \
             re-submitting the rotation. Nothing was written now, which matters here: \
             rotating again would invalidate the bearer that page showed, and leave you on \
             this same page.",
            "Con ogni probabilità questa pagina è il ricaricamento di quella che mostrava \
             il nuovo bearer, e ha reinviato la rigenerazione. Adesso non è stato scritto \
             nulla, il che qui conta: rigenerare di nuovo invaliderebbe il bearer che quella \
             pagina mostrava, e ti riporterebbe su questa stessa pagina.",
        ),
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
        K::MsgGroupAdded => m(lang, "user group added", "gruppo di utenti aggiunto"),
        K::MsgGroupSaved => m(lang, "user group saved", "gruppo di utenti salvato"),
        K::MsgGroupRemoved => m(lang, "user group removed", "gruppo di utenti rimosso"),
        K::MsgDeniedAdded => m(lang, "email denied", "email negata"),
        K::MsgDeniedRemoved => m(lang, "veto lifted", "veto tolto"),

        // --- the self-service page ---
        //
        // The headings are the prose, and the only prose: the names in each section are the
        // access file's vocabulary, which is never translated.
        K::AccountTitle => m(lang, "Your account", "Il tuo account"),
        K::AccountIdLabel => m(lang, "Account id", "Id dell'account"),
        // The refusal a mint gets from a caller with no row. It says what is missing rather
        // than blaming the request, because the person reading it is the one who has to ask
        // for the row.
        K::AccountNoRowTitle => m(
            lang,
            "There is no account to mint into",
            "Non c'è un account in cui creare la chiave",
        ),
        K::AccountNoRowBody => m(
            lang,
            "bb-auth has no roster row for this identity, so there is no account a key of \
             yours could belong to.",
            "bb-auth non ha una riga nella lista per questa identità, quindi non c'è un account \
             a cui una tua chiave possa appartenere.",
        ),
        K::AccountReach => m(lang, "Where you reach", "Dove puoi arrivare"),
        K::AccountReachSub => m(
            lang,
            "The applications your sign-in opens, and the areas inside each.",
            "Le applicazioni a cui il tuo accesso apre la porta, e le aree dentro ciascuna.",
        ),
        K::AccountReachNone => m(
            lang,
            "Your sign-in opens no application yet.",
            "Il tuo accesso non apre ancora nessuna applicazione.",
        ),
        // The page's own word for the file's `user_groups` section, not the console's `K::Groups`
        // ("User groups"), which names the file section an administrator edits.
        K::AccountGroups => m(lang, "Groups", "Gruppi"),
        K::AccountGroupsSub => m(
            lang,
            "Groups an administrator has put you in.",
            "I gruppi in cui ti ha messo un amministratore.",
        ),
        K::AccountGroupsNone => m(lang, "You are in no group.", "Non sei in nessun gruppo."),
        K::AccountKeys => m(lang, "API keys", "Chiavi API"),
        K::AccountKeysSub => m(
            lang,
            "A key lets a script or a tool sign in as you. It reaches at most what you reach.",
            "Una chiave permette a uno script o a uno strumento di accedere come te. Arriva al \
             massimo dove arrivi tu.",
        ),
        K::AccountProfile => m(lang, "Profile", "Profilo"),
        K::AccountProfileSub => m(
            lang,
            "What your sign-in tells your applications about you.",
            "Cosa il tuo accesso dice di te alle tue applicazioni.",
        ),
        K::AccountProfileNone => m(
            lang,
            "This deployment shares no profile details.",
            "Questa installazione non condivide dettagli del profilo.",
        ),
        // A claim the deployment configured and the proxy did not forward. Lowercase, because it
        // reads as the tail of the row's sentence, after the claim's name, not as a heading.
        K::AccountNotProvided => m(lang, "not provided", "non fornito"),
        // The profile edit (§13.23 §5). The wording is the designer's table, verbatim, and the
        // sentences around a value are split into separate keys (`CodeSent` / `CodeLasts`,
        // `Was` / `Removed`) because the table has no placeholders and a sentence built by
        // gluing a value into the middle of a string is a sentence that reads wrong in one of
        // the two languages.
        K::AccountProfileEdit => m(lang, "Edit profile", "Modifica il profilo"),
        K::AccountProfileEditSub => m(
            lang,
            "Change what you need, then confirm with a code we email you.",
            "Cambia ciò che ti serve, poi conferma con un codice che ti mandiamo per email.",
        ),
        K::AccountProfileClearDeletes => m(
            lang,
            "Empty it to remove it.",
            "Svuotalo per eliminarlo.",
        ),
        K::AccountProfileDateHint => m(lang, "YYYY-MM-DD", "AAAA-MM-GG"),
        // The one sentence the profile panel says to a person whose session is not a native
        // Cognito sign-in (§13.25): the profile of a federated account belongs to the provider,
        // and a session minted before the gate named the Cognito user has to sign in again to
        // reach the edit. It says what to do, not only what is wrong.
        K::AccountProfileNotNative => m(
            lang,
            "If you sign in with a social account such as Google, your profile comes from that \
             provider and cannot be changed here. If you sign in with your email address, sign \
             out and sign in again to edit it.",
            "Se accedi con un account social come Google, il tuo profilo viene da quel fornitore \
             e non si può cambiare qui. Se accedi con il tuo indirizzo email, esci e accedi di \
             nuovo per modificarlo.",
        ),
        K::AccountProfileEmailFixed => m(
            lang,
            "Your email address is how you sign in, so only an administrator can change it.",
            "Il tuo indirizzo email è il modo in cui accedi, quindi solo un amministratore può cambiarlo.",
        ),
        K::AccountProfileSendCode => m(lang, "Send code", "Invia il codice"),
        K::AccountProfileNothingChanged => m(
            lang,
            "Nothing to save: every field is as it was, so no code was sent.",
            "Niente da salvare: ogni campo è com'era, quindi non è stato inviato alcun codice.",
        ),
        K::AccountProfileValueBad => m(
            lang,
            "too long, or holds characters that cannot be saved.",
            "troppo lungo, o contiene caratteri che non si possono salvare.",
        ),
        K::AccountProfileCannotEdit => m(
            lang,
            "cannot be changed here.",
            "non si può cambiare qui.",
        ),
        K::AccountProfileCodeTitle => m(lang, "Enter the code", "Inserisci il codice"),
        K::AccountProfileCodeSent => m(
            lang,
            "We emailed a code to",
            "Abbiamo inviato un codice a",
        ),
        // The same sentence with no address in it, for the case the provider does not name one
        // (§13.25): the code went to the address the account signs in with, and the page may say
        // that much without inventing an address it was not given.
        K::AccountProfileCodeSentNoDest => m(
            lang,
            "We emailed a code to the address you sign in with.",
            "Abbiamo inviato un codice all'indirizzo con cui accedi.",
        ),
        K::AccountProfileCodeLasts => m(
            lang,
            "It works for 3 minutes.",
            "Vale per 3 minuti.",
        ),
        K::AccountProfileChanges => m(lang, "What will change", "Cosa cambierà"),
        K::AccountProfileWas => m(lang, "was", "prima:"),
        K::AccountProfileRemoved => m(lang, "removed", "eliminato"),
        K::AccountProfileCodeLabel => m(lang, "Code", "Codice"),
        K::AccountProfileSave => m(lang, "Save profile", "Salva il profilo"),
        K::AccountProfileNoCode => m(
            lang,
            "No email after a minute? Look in your spam folder, or send a new code.",
            "Nessuna email dopo un minuto? Guarda nello spam, o invia un nuovo codice.",
        ),
        K::AccountProfileSendNew => m(lang, "Send a new code", "Invia un nuovo codice"),
        K::AccountProfileNotSavedTitle => m(
            lang,
            "Your profile was not changed",
            "Il tuo profilo non è stato modificato",
        ),
        K::AccountProfileNoAnswer => m(
            lang,
            "The sign-in service did not answer within 5 seconds. Try again in a minute.",
            "Il servizio di accesso non ha risposto entro 5 secondi. Riprova tra un minuto.",
        ),
        // The account the session named is gone from the pool (`UserNotFoundException`,
        // `UserNotConfirmedException`), so there is nobody to send a code to. It says so in the
        // same breath as what to do about it, because the person's own sign-in is the thing that
        // has to be redone.
        K::AccountProfileNoUser => m(
            lang,
            "The sign-in service no longer has the account you signed in with, so no code was \
             sent. Sign out and sign in again.",
            "Il servizio di accesso non ha più l'account con cui hai effettuato l'accesso, \
             quindi non è stato inviato alcun codice. Esci e accedi di nuovo.",
        ),
        K::AccountProfileTooMany => m(
            lang,
            "Too many attempts. Wait a few minutes, then try again.",
            "Troppi tentativi. Aspetta qualche minuto, poi riprova.",
        ),
        K::AccountProfileRefused => m(
            lang,
            "The sign-in service refused the change.",
            "Il servizio di accesso ha rifiutato la modifica.",
        ),
        K::AccountProfileWrongCode => m(
            lang,
            "That code is not right. Use the code in the latest email, and type it again.",
            "Il codice non è corretto. Usa il codice dell'ultima email e scrivilo di nuovo.",
        ),
        K::AccountProfileExpired => m(
            lang,
            "The code has expired. Send a new one, and type it as soon as it arrives.",
            "Il codice è scaduto. Inviane uno nuovo e scrivilo appena arriva.",
        ),
        K::AccountProfileNotYours => m(
            lang,
            "The sign-in service answered for a different account, so nothing was changed.",
            "Il servizio di accesso ha risposto per un altro account, quindi non è cambiato nulla.",
        ),
        K::AccountProfileBadValue => m(
            lang,
            "The sign-in service did not accept one of the values. Check the date (YYYY-MM-DD) \
             and the web addresses, then try again.",
            "Il servizio di accesso non ha accettato uno dei valori. Controlla la data \
             (AAAA-MM-GG) e gli indirizzi web, poi riprova.",
        ),
        K::AccountProfileSavedTitle => m(lang, "Profile saved", "Profilo salvato"),
        K::AccountProfileSavedLead => m(lang, "Changed:", "Modificato:"),
        K::AccountProfileSavedBody => m(
            lang,
            "Your applications, and this page, show it from your next sign-in.",
            "Le tue applicazioni, e questa pagina, lo mostrano dal prossimo accesso.",
        ),
        K::AccountProfileUnsureTitle => m(
            lang,
            "Your profile may not have been saved",
            "Il tuo profilo potrebbe non essere stato salvato",
        ),
        K::AccountProfileNoAnswerUnsure => m(
            lang,
            "The sign-in service accepted the code, then did not answer within 5 seconds, so the \
             change may or may not have been made. Your next sign-in will show which.",
            "Il servizio di accesso ha accettato il codice, poi non ha risposto entro 5 secondi: \
             la modifica potrebbe essere stata fatta oppure no. Il prossimo accesso lo mostrerà.",
        ),
        K::AttrName => m(lang, "Full name", "Nome completo"),
        K::AttrGivenName => m(lang, "Given name", "Nome"),
        K::AttrFamilyName => m(lang, "Family name", "Cognome"),
        K::AttrMiddleName => m(lang, "Middle name", "Secondo nome"),
        K::AttrNickname => m(lang, "Nickname", "Soprannome"),
        K::AttrProfile => m(lang, "Profile page", "Pagina del profilo"),
        K::AttrPicture => m(
            lang,
            "Picture (web address)",
            "Immagine (indirizzo web)",
        ),
        K::AttrWebsite => m(lang, "Website", "Sito web"),
        K::AttrGender => m(lang, "Gender", "Genere"),
        K::AttrBirthdate => m(lang, "Date of birth", "Data di nascita"),
        K::AttrZoneinfo => m(lang, "Time zone", "Fuso orario"),
        K::AttrLocale => m(lang, "Language and region", "Lingua e regione"),
        // The keys' empty state names keys, in the feminine (*chiavi*): Italian agrees an
        // adjective with the noun it stands for, and the section's heading is the noun a reader
        // sees beside the sentence, so a borrowed pronoun reads as a slip in the page's own
        // language.
        K::AccountKeysNone => m(
            lang,
            "No API keys yet.",
            "Non ci sono ancora chiavi API.",
        ),
        // The mint form. `id` and `duration` are the file's own field names and stay as
        // written in it, exactly as the console's key form leaves them.
        K::AccountKeyAdd => m(lang, "Add a key", "Aggiungi una chiave"),
        K::AccountKeyCreate => m(lang, "Create key", "Crea la chiave"),
        K::AccountKeyIdHint => m(
            lang,
            "lowercase letters, digits and dashes, up to 32",
            "lettere minuscole, cifre e trattini, fino a 32",
        ),
        // The mint form's two field labels. The **field names** stay `id` and `duration`,
        // because the handler reads those and the file stores those; the label is the page's
        // word for the thing, and a label is displayed text. The Italian noun is the one this
        // page's own refusals use (`AccountKeyIdBad` says "Il nome di una chiave", `AccountKeyDup`
        // "quel nome"), so the form and the refusal name the field alike, and the file's word
        // `id` never appears on this page.
        // The two forms every key of the caller's carries. The verbs are this page's, not the
        // console's (`K::Rotate` / `K::Remove` are an operator's lowercase command words): a
        // person with no administrator in the room is clicking a button that says what it does.
        K::AccountKeyRotate => m(lang, "Rotate key", "Rigenera la chiave"),
        K::AccountKeyRemove => m(lang, "Revoke key", "Revoca la chiave"),
        // The refusals this form answers with. Each names what to write instead, because a
        // person with no administrator at hand has to fix it themselves, and each says **one**
        // fact: the `AccountKeyBound` these replaced named the id and the window in the same
        // sentence, so a person who typed `My Laptop` read about durations (WCAG 3.3.1 and
        // 3.3.3: identify the error in text, name the fix).
        K::AccountKeyIdBad => m(
            lang,
            "A key name is lowercase letters, digits and dashes, up to 32 characters, such as \
             laptop.",
            "Il nome di una chiave è fatto di lettere minuscole, cifre e trattini, fino a 32 \
             caratteri, per esempio laptop.",
        ),
        K::AccountKeyTooShort => m(
            lang,
            "A key must last at least a day; choose a longer duration.",
            "Una chiave deve durare almeno un giorno; scegli una durata più lunga.",
        ),
        K::AccountKeyFull => m(
            lang,
            "This account has ten keys, which is the most this page mints.",
            "Questo account ha dieci chiavi, il massimo che questa pagina crea.",
        ),
        K::AccountKeyDup => m(
            lang,
            "This account already has a key with that name.",
            "Questo account ha già una chiave con quel nome.",
        ),
        K::AccountKeyUnknownScope => m(
            lang,
            "A scope you picked is not one a key of yours can reach.",
            "Uno degli ambiti scelti non è uno che una tua chiave può raggiungere.",
        ),
        // The keys table and its `+ New key` row (§13.16). The two column words are the
        // table's headings **and** the mint form's field labels, so a field and the column
        // that shows the same value answer that value's name from one entry, and an Italian
        // page cannot carry a label in English.
        K::AccountKeyNew => m(lang, "+ New key", "+ Nuova chiave"),
        K::AccountKeyFullRow => m(
            lang,
            "An account holds at most 10 keys. Revoke one to add another.",
            "Un account ha al massimo 10 chiavi. Revocane una per aggiungerne un'altra.",
        ),
        // The last clause is the reason it is spelled out: a rotate stamps a new `released`,
        // so the window starts again, which is not what "rotate the secret" sounds like.
        K::AccountKeyRotateWarn => m(
            lang,
            "A new secret replaces this one. Anything still using the old one stops getting \
             in within seconds. The name and the scopes stay; the expiry starts again from \
             today.",
            "Un nuovo segreto sostituisce questo. Ciò che usa il vecchio smette di entrare in \
             pochi secondi. Il nome e gli ambiti restano; la scadenza riparte da oggi.",
        ),
        K::AccountKeyRemoveWarn => m(
            lang,
            "The key stops working within seconds. This cannot be undone: only a new key can \
             replace it.",
            "La chiave smette di funzionare in pochi secondi. Non si può annullare: solo una \
             nuova chiave può sostituirla.",
        ),
        K::KeyColName => m(lang, "Name", "Nome"),
        K::KeyColExpires => m(lang, "Expires", "Scade"),
        K::KeyScopesAll => m(lang, "all scopes", "tutti gli ambiti"),
        K::KeyScopesOnly => m(lang, "only these", "solo questi"),
        K::KeyScopeGone => m(lang, "no longer reached", "non più raggiungibile"),
        // The twin of the console's refusal for the same contradiction: the ticks say one
        // thing and the radio says another, and the person has to pick which one they meant.
        K::KeyScopesWithoutOnly => m(
            lang,
            "You ticked scopes; choose 'only these', or untick them.",
            "Hai spuntato degli ambiti; scegli 'solo questi', o togli la spunta.",
        ),
        // The answer to a `restrict` that is neither of the two the form sends, which only a
        // hand-written `POST` achieves. No field is marked: the request chose nothing, and the
        // honest fix names the two choices it could have chosen.
        K::KeyScopesChoose => m(
            lang,
            "Choose 'all scopes' or 'only these'.",
            "Scegli 'tutti gli ambiti' o 'solo questi'.",
        ),
        // The five duration choices (§13.15). The words are the person's; the values the
        // control posts are the file's (`365d`, `182d`, `91d`, `custom`, `never`), so the
        // stored string is the spelling `bb-auth-adm show` prints.
        K::DurOneYear => m(lang, "in 1 year", "tra 1 anno"),
        K::DurSixMonths => m(lang, "in 6 months", "tra 6 mesi"),
        K::DurThreeMonths => m(lang, "in 3 months", "tra 3 mesi"),
        K::DurCustom => m(lang, "after a number of days", "dopo un numero di giorni"),
        K::DurNever => m(lang, "never", "mai"),
        // The box's own name. It echoes the option the person picked ("after a number of
        // days") and contains the placeholder's word, where "Custom duration" named nothing
        // on screen (WCAG 2.5.3, label in name).
        K::DurDaysLabel => m(lang, "Number of days", "Numero di giorni"),
        K::DurDaysHint => m(lang, "days", "giorni"),
        // The three refusals `duration_from_form` answers with, each naming its own fix,
        // because the person reading them has no administrator in the room. They sit beside
        // `KeyDurationRequired`, already a sentence, in the same box.
        K::KeyDurationRequired => m(
            lang,
            "Choose how long the key lasts.",
            "Scegli per quanto tempo dura la chiave.",
        ),
        K::KeyDaysWithoutCustom => m(
            lang,
            "You typed a number of days; choose 'after a number of days', or clear it.",
            "Hai scritto un numero di giorni; scegli 'dopo un numero di giorni', o cancellalo.",
        ),
        K::KeyDaysInvalid => m(
            lang,
            "Write a whole number of days, at least 1.",
            "Scrivi un numero intero di giorni, almeno 1.",
        ),
        // One sentence for "no such key" and "that key belongs to somebody else", because a
        // page that answered the two differently is an enumeration oracle for anybody with an
        // account: it would say which ids exist on the estate.
        K::AccountKeyNotYours => m(
            lang,
            "that key is not one of yours, so this page cannot rotate it or revoke it.",
            "quella chiave non è una delle tue, quindi questa pagina non può rigenerarla né \
             revocarla.",
        ),
        K::AccountVetoTitle => m(lang, "You are refused", "Sei escluso"),
        K::AccountVetoBody => m(
            lang,
            "this deployment has a veto on your identity, so there is no account to show.",
            "questa installazione ha un veto sulla tua identità, quindi non c'è un account da \
             mostrare.",
        ),
        K::AccountAmbiguousTitle => m(
            lang,
            "The identity header names two accounts",
            "L'header di identità nomina due account",
        ),
        K::AccountAmbiguousBody => m(
            lang,
            "the identity header carries addresses that belong to different roster rows, and \
             there is no page about both of them.",
            "l'header di identità porta indirizzi di righe diverse della lista, e non c'è una \
             pagina che parli di entrambe.",
        ),
        K::AccountNoEmailTitle => m(
            lang,
            "No email identity is forwarded",
            "Nessuna identità email è inoltrata",
        ),
        // Names the setting, because the operator reading this is the only person who can fix
        // it, and a page that only said "no identity" would send them to the wrong file.
        K::AccountNoEmailBody => m(
            lang,
            "gate.identity_attrs names no email, so the proxy forwards no identity for this \
             page to act on.",
            "gate.identity_attrs non nomina l'email, quindi il proxy non inoltra nessuna \
             identità su cui questa pagina può agire.",
        ),
        // The delete confirmation page (§13.30 §2 §5). The English is the designer's table
        // verbatim, and the Italian keeps one fixed name per thing: "account di accesso" for a
        // sign-in account, "servizio di eliminazione" for the deletion service.
        K::AccountDeleteTitle => m(
            lang,
            "Delete your account",
            "Elimina il tuo account",
        ),
        K::AccountDeleteLead => m(
            lang,
            "This cannot be undone. To confirm, type your email address below and press Delete \
             my account.",
            "Non si può annullare. Per confermare, scrivi qui sotto il tuo indirizzo email e \
             premi Elimina il mio account.",
        ),
        K::AccountDeleteGoes => m(lang, "What is deleted", "Cosa viene eliminato"),
        K::AccountDeleteRecord => m(
            lang,
            "Your bb-auth record, and every access an administrator gave you by name.",
            "I tuoi dati in bb-auth, e ogni accesso che un amministratore ti ha dato per nome.",
        ),
        K::AccountDeleteKeysLead => m(
            lang,
            "Your API keys, which stop working within seconds:",
            "Le tue chiavi API, che smettono di funzionare in pochi secondi:",
        ),
        K::AccountDeleteGroupsLead => m(
            lang,
            "Your place in these groups:",
            "Il tuo posto in questi gruppi:",
        ),
        K::AccountDeleteSignInOne => m(
            lang,
            "Every sign-in account with this email address, whether you sign in with an emailed \
             code or with a provider such as Google:",
            "Ogni account di accesso con questo indirizzo email, sia che tu acceda con un codice \
             via email sia con un fornitore come Google:",
        ),
        K::AccountDeleteSignInMany => m(
            lang,
            "Every sign-in account with any of these email addresses, whether you sign in with \
             an emailed code or with a provider such as Google:",
            "Ogni account di accesso con uno di questi indirizzi email, sia che tu acceda con un \
             codice via email sia con un fornitore come Google:",
        ),
        K::AccountDeleteLater => m(
            lang,
            "The sign-in accounts are not deleted at once: they are queued for a separate \
             deletion service.",
            "Gli account di accesso non vengono eliminati subito: vengono messi in coda per un \
             servizio di eliminazione separato.",
        ),
        K::AccountDeleteAuditKept => m(
            lang,
            "The record of your sign-ins and refusals is kept for",
            "Il registro dei tuoi accessi e dei rifiuti è conservato per",
        ),
        K::AccountDeleteAuditTail => m(lang, ", then dropped.", ", poi viene eliminato."),
        K::AccountDeleteAuditSize => m(
            lang,
            "The record of your sign-ins and refusals is kept until newer entries replace it; \
             this deployment keeps at most",
            "Il registro dei tuoi accessi e dei rifiuti resta finché voci più recenti non lo \
             sostituiscono; questa installazione ne conserva al massimo",
        ),
        K::AccountDeleteTypeLabel => m(
            lang,
            "Type your email address to confirm",
            "Scrivi il tuo indirizzo email per confermare",
        ),
        K::AccountDeleteTypeHintMany => m(
            lang,
            "Any one of the addresses above.",
            "Uno qualsiasi degli indirizzi qui sopra.",
        ),
        K::AccountDeleteConfirm => m(
            lang,
            "Delete my account",
            "Elimina il mio account",
        ),
        // The words of every outcome a deletion request answers with, verbatim from §13.30 §5.
        // "Queued" and never "deleted": the page cannot read the worker's outcome (§13.29 W6).
        K::AccountDeleteQueuedTitle => m(
            lang,
            "Your account is being deleted",
            "Il tuo account è in fase di eliminazione",
        ),
        K::AccountDeleteNowGone => m(
            lang,
            "Your API keys and every access an administrator gave you by name are gone.",
            "Le tue chiavi API e ogni accesso che un amministratore ti ha dato per nome non ci \
             sono più.",
        ),
        K::AccountDeleteQueued => m(
            lang,
            "Your sign-in accounts are queued for deletion. This page cannot tell when that \
             happens; if you can still sign in later, tell an administrator.",
            "I tuoi account di accesso sono in coda per l'eliminazione. Questa pagina non può \
             dire quando avverrà; se più avanti riesci ancora ad accedere, avvisa un \
             amministratore.",
        ),
        K::AccountDeletedClose => m(
            lang,
            "This browser stays signed in until the session ends.",
            "Questo browser resta connesso finché la sessione non termina.",
        ),
        K::AccountDeletePartialTitle => m(
            lang,
            "Your account is only partly deleted",
            "Il tuo account è stato eliminato solo in parte",
        ),
        K::AccountDeleteNotQueued => m(
            lang,
            "Your sign-in accounts could not be queued for deletion, so they still exist. Try \
             again later; if it fails again, tell an administrator.",
            "Non è stato possibile mettere in coda l'eliminazione dei tuoi account di accesso, \
             che quindi esistono ancora. Riprova più tardi; se non funziona di nuovo, avvisa un \
             amministratore.",
        ),
        K::AccountDeleteUnsureTitle => m(
            lang,
            "Your account may not be fully deleted",
            "Il tuo account potrebbe non essere stato eliminato del tutto",
        ),
        K::AccountDeleteMaybeQueued => m(
            lang,
            "The deletion service did not answer, so your sign-in accounts may or may not be \
             queued for deletion. Trying again is safe, even if they were.",
            "Il servizio di eliminazione non ha risposto, quindi i tuoi account di accesso \
             potrebbero essere in coda per l'eliminazione oppure no. Riprovare non crea problemi, \
             anche se lo erano già.",
        ),
        K::AccountDeleteSome => m(
            lang,
            "The sign-in accounts of some of your addresses are queued for deletion; the others \
             may not be.",
            "Gli account di accesso di alcuni dei tuoi indirizzi sono in coda per l'eliminazione; \
             gli altri potrebbero non esserlo.",
        ),
        K::AccountDeleteUnconfirmedLead => m(
            lang,
            "Addresses not confirmed as queued:",
            "Indirizzi di cui non è confermata la messa in coda:",
        ),
        K::AccountDeleteRetryOneAddress => m(
            lang,
            "Trying again covers only the address you signed in with; for the others, tell an \
             administrator.",
            "Riprovare riguarda solo l'indirizzo con cui hai effettuato l'accesso; per gli altri, \
             avvisa un amministratore.",
        ),
        K::AccountDeleteNotDoneTitle => m(
            lang,
            "Your account was not deleted",
            "Il tuo account non è stato eliminato",
        ),
        K::AccountDeleteProtected => m(
            lang,
            "This account cannot be deleted from this page, and nothing was deleted. If you want \
             it deleted, ask an administrator.",
            "Questo account non può essere eliminato da questa pagina, e non è stato eliminato \
             nulla. Se vuoi eliminarlo, chiedi a un amministratore.",
        ),
        K::AccountDeleteNoCheck => m(
            lang,
            "The deletion service did not answer as expected, so nothing was deleted and you can \
             still sign in. Try again in a minute; if it fails again, tell an administrator.",
            "Il servizio di eliminazione non ha risposto come previsto, quindi non è stato \
             eliminato nulla e puoi ancora accedere. Riprova tra un minuto; se non funziona di \
             nuovo, avvisa un amministratore.",
        ),
        K::AccountDeleteRetry => m(lang, "Try again", "Riprova"),
        K::AccountDeleteStartAgain => m(lang, "Start again", "Ricomincia"),
        K::AccountDeleteWriteFailed => m(
            lang,
            "bb-auth could not save the change, so nothing was deleted and you can still sign \
             in. Try again in a minute; if it fails again, tell an administrator.",
            "bb-auth non è riuscito a salvare la modifica, quindi non è stato eliminato nulla e \
             puoi ancora accedere. Riprova tra un minuto; se non funziona di nuovo, avvisa un \
             amministratore.",
        ),
        K::AccountDeleteChangedTitle => m(
            lang,
            "Your account changed",
            "Il tuo account è cambiato",
        ),
        K::AccountDeleteChanged => m(
            lang,
            "Your account changed after you opened this page, so nothing was deleted. Start again \
             to see what would be deleted now.",
            "Il tuo account è cambiato dopo che hai aperto questa pagina, quindi non è stato \
             eliminato nulla. Ricomincia per vedere cosa verrebbe eliminato adesso.",
        ),
        K::AccountDeleteTypedWrong => m(
            lang,
            "The email address typed is not one of this account's, so nothing was deleted. Type \
             it as it is shown above.",
            "L'indirizzo email scritto non è uno di quelli di questo account, quindi non è stato \
             eliminato nulla. Scrivilo come appare qui sopra.",
        ),
        K::AccountDeleteTooMany => m(
            lang,
            "This account has more email addresses than this page can delete at once, so it \
             cannot be deleted here, and nothing was deleted. If you want it deleted, ask an \
             administrator.",
            "Questo account ha più indirizzi email di quanti questa pagina ne possa eliminare in \
             una volta, quindi non può essere eliminato qui, e non è stato eliminato nulla. Se \
             vuoi eliminarlo, chiedi a un amministratore.",
        ),
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
    SettingsSaved,
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
            Msg::SettingsSaved => "settings-saved",
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
            Msg::SettingsSaved,
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
                Msg::SettingsSaved => K::MsgSettingsSaved,
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
    /// `BB_AUTH_ACCESS_FILE`, the access file to render. The gate's variable name, on
    /// purpose: each service gets its own env file, and one name means one meaning.
    access_path: String,
    /// `BB_AUTH_SETTINGS_FILE`, the settings file this GUI reads **and writes**, defaulting
    /// to `settings.json` beside the access file exactly as the gate defaults it.
    ///
    /// Its `web.admins` is the administrator allowlist, and it is read **per request** rather
    /// than at startup: this is the one service that can edit it, and a change that needed a
    /// restart to take effect would be a change this GUI could make but not see.
    settings_path: String,
    /// `BB_AUTH_WEB_BASE_PATH`, normalised by [`normalize_base_path`]: `""` or `/admin`.
    /// Every internal href carries it and the router strips it.
    base_path: String,
    /// `BB_AUTH_WEB_DEFAULT_LANG`, used when a request expresses no preference at all.
    default_lang: Lang,
    /// `BB_AUTH_WEB_LOGOUT_URL`: where the Sign out control in the header points, or `None`
    /// for no control at all.
    ///
    /// **No control when it is unset**, rather than a guess. This GUI cannot know its own
    /// public URL: it speaks plain HTTP on loopback, so it knows neither the scheme nor the
    /// host, and the one thing it *is* handed, the `Host` header, is client-supplied and is
    /// exactly what the rest of this project refuses to let decide a redirect target. A
    /// button that logs an administrator out to an address an attacker chose would be a
    /// phishing gadget, so the address is the operator's to state.
    ///
    /// Normally the root-relative `/auth/logout`, which needs no hostname at all when the
    /// gate and this GUI are on one vhost, and an absolute `https://auth.example.com/auth/logout`
    /// when they are not.
    ///
    /// **It may carry the gate's `?rd=`**, and that is how "sign out, then sign back in, and
    /// be where you were" is expressed: the gate clears the cookie and redirects there, that
    /// address is gated, so the `401` sends the browser to the login page carrying it, and the
    /// login hands it back. Which makes the value the whole round trip, written once:
    ///
    /// ```text
    /// BB_AUTH_WEB_LOGOUT_URL=/auth/logout?rd=https%3A%2F%2Fauth.example.com%2Fadmin%2F
    /// ```
    ///
    /// The `rd` has to be **absolute**, and this is the reason rather than a preference: a
    /// relative one is resolved by the gate against the caller origin it reads from
    /// `BB_AUTH_ORIGINAL_URL_HEADER`, and the logout location is deliberately ungated, so
    /// nginx has no reason to set that header there and normally does not. Without it a
    /// relative `rd` falls back to the login page, which is fail-soft and silent, and silent
    /// is the bad half. It also stays the operator's to write for the same reason the address
    /// itself does: this GUI knows neither its scheme nor its host, and the one thing it is
    /// handed is a client-supplied `Host`.
    ///
    /// With no `rd` the browser lands on the login page and stops there, which is the honest
    /// destination for someone who just ended their session and is the right default for a
    /// deployment that has not said otherwise.
    logout_url: Option<String>,
    /// [`Self::logout_url`] with its `rd` query parameter removed, derived once at startup by
    /// [`logout_without_rd`] and `None` exactly when `logout_url` is. The self-service page's
    /// Sign out pill carries this (docs/ARCHITECTURE.md §13.17): the `rd` is the console's round
    /// trip to the administrator surface, and on `/account/` it would land a person who is not
    /// an administrator on a `403`. It is also the logout a completed deletion redirects
    /// through (§13.32 §1, [`delete_logout_location`]), which is why the value is derived once
    /// and never re-cut per request.
    account_logout_url: Option<String>,
    /// `BB_AUTH_AUDIT_FILE`, the authentication audit the gate appends to and this GUI reads.
    /// Default [`DEFAULT_AUDIT_FILE`], and **empty means there is no Audit tab at all**.
    ///
    /// The gate's variable name, on purpose, exactly as `BB_AUTH_ACCESS_FILE` is: each service
    /// has its own env file, one name means one thing, and unset on both sides means the same
    /// default on both sides. This end never writes it, and the unit that runs this end has no
    /// business being able to: an audit an administrator can edit is not one.
    audit_path: String,
    /// `BB_AUTH_WEB_PROXY_SECRET`: the shared secret nginx sets in `X-BB-Web-Secret` on every
    /// request it proxies here, and the only thing that tells this port "you came through the
    /// proxy" (docs/ARCHITECTURE.md §13.3).
    ///
    /// Required, and validated at startup by [`compile_proxy_secret`]. It is compared on every
    /// request, as the first check in [`handle`], through [`proxy_secret_matches`] and never
    /// with `==`; and it is never printed, logged or rendered, because a value that reaches
    /// the journal at boot is a secret for as long as the journal is kept.
    proxy_secret: String,
    /// `BB_AUTH_WEB_ACCOUNT_PATH`: the prefix the self-service page is mounted at
    /// (docs/ARCHITECTURE.md §13.2). Normalised and checked against `base_path` at startup by
    /// [`compile_account_path`], so a deployment where the two prefixes overlap is a refusal
    /// to start and not a page that answers the wrong half of its own URLs.
    account_path: String,
    /// `BB_AUTH_WEB_WORKERS`: the blocking request threads `main` spawns, validated at startup
    /// by [`compile_workers`] (docs/ARCHITECTURE.md §13.13).
    ///
    /// It bounds how many **handlers run at once**, not how many connections are open:
    /// `tiny_http` runs its own accept pool and pushes every parsed request onto one unbounded
    /// queue, so a request that finds every worker busy waits, it is not refused. Too few
    /// workers therefore shows up as latency for everybody, which is why the count is a
    /// deployment's to state and not a constant.
    workers: usize,
    /// The address the Cognito API calls go to, and set from the environment by nothing a
    /// deployment builds.
    ///
    /// `None` means "derive it from the settings file", which is what every real deployment does
    /// ([`Settings::cognito_endpoint`]). The field exists for the tests alone: `compile_issuer`
    /// is https-only, so a plain-HTTP fake pool cannot be named through `gate.issuer`, and a TLS
    /// fake would need a certificate authority the bundled Mozilla roots do not trust (the design
    /// of docs/ARCHITECTURE.md §13.22). No env var and no file sets it, so a host never points
    /// the sign-in flow at an address an operator wrote in a config. The one reader is the
    /// browser suite's harness, behind the `e2e-fake-cognito` feature and loopback only, through
    /// [`e2e_cognito_endpoint`]: a release that carries the feature does not compile
    /// (docs/ARCHITECTURE.md §13.24).
    cognito_endpoint: Option<String>,
    /// How long one Cognito call may take before this gives up and says so.
    ///
    /// [`COGNITO_TIMEOUT`] at startup, and the tests shorten it so the "pool that never answers"
    /// case is fast. It is a constant and not a setting because it is not a value an operator has
    /// a reason to tune per deployment, and because a setting that bounds a call nobody can
    /// reproduce is a setting nobody can debug.
    cognito_timeout: std::time::Duration,
    /// `BB_AUTH_WEB_DELETE_INTAKE`: the **origin** of the owner's deletion worker's intake, the
    /// service that queues a self-service account deletion (docs/ARCHITECTURE.md §13.29 W2).
    ///
    /// Validated at startup by [`compile_delete_intake`], which accepts only a plain-HTTP
    /// loopback origin. **Unset is the feature off**: no menu row, and the delete page is the
    /// `404` every unknown path gets, exactly as [`Self::logout_url`] unset already behaves. It
    /// is an env var and not a setting because it is read once and decides where an identity is
    /// sent: the settings file is editable from the console, and a field there would let a
    /// console session point every future deletion at another port.
    delete_intake: Option<String>,
    /// `BB_AUTH_WEB_DELETE_SECRET`: the value sent to the intake in `X-BB-Delete-Secret` on both
    /// of its calls, when one is set (docs/ARCHITECTURE.md §13.29 W2, W8 §1).
    ///
    /// **Optional for now**, and the reason is the intake's, not ours: today the intake checks no
    /// secret at all, so requiring one here would ship a half that enforces nothing while a
    /// missing one stops the GUI from starting. bb-auth ships its half once and the owner starts
    /// enforcing the header whenever they choose, with no release here. A **malformed** value is
    /// still fatal ([`compile_delete_secret`]): optional means "unset is allowed", never "a
    /// broken value is ignored". With the intake set and no secret the startup banner says so
    /// once, in the journal.
    ///
    /// Never printed, logged or rendered, for the proxy secret's reason: a value that reaches the
    /// journal at boot is a secret for as long as the journal is kept.
    delete_secret: Option<String>,
    /// How long one intake call may take before this gives up and says so (§13.29 W2).
    ///
    /// [`INTAKE_TIMEOUT`] at startup, and the tests shorten it as they do
    /// [`Self::cognito_timeout`], because the "intake that never answers" case has to be fast.
    /// It is a constant and not a setting for the same reason that one is. The startup banner
    /// names it beside the origin, so the bound a deployment runs with is something an operator
    /// can read out of the journal.
    intake_timeout: std::time::Duration,
}

/// The bound on one deletion-intake call, end to end (§13.29 W2).
///
/// The same wall as [`COGNITO_TIMEOUT`], for the same reason: `tiny_http` runs a fixed pool of
/// handler threads, so a call that hangs forever is a worker that never serves anybody again.
/// The intake answers from a spool append, so five seconds is generous, and the design promises
/// nothing longer.
const INTAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The bound on one Cognito call, end to end (§13.22).
///
/// It is a wall on the **worker**, not a hint: `tiny_http` runs a fixed pool of handler threads,
/// so a call that hangs forever is a worker that never serves anybody again. Five seconds is
/// generous against the ~1 s a real `InitiateAuth` takes from rpi-01, and short enough that the
/// worst case is a slow page and not a wedged service. There is no retry: a start is one call and
/// the code step is two, so the most a request can spend is twice this.
const COGNITO_TIMEOUT: Duration = Duration::from_secs(5);

/// The Cognito address the browser suite's harness points this process at, and the reason no
/// release build has one (docs/ARCHITECTURE.md §13.24).
///
/// One function with two bodies, so the default build has a rule to test: without the
/// `e2e-fake-cognito` feature this answers `Ok(None)` for whatever `lookup` answers, and the
/// variable's name appears in no source that is compiled. With the feature,
/// `BB_AUTH_WEB_E2E_COGNITO_ENDPOINT` names the address and the address must be
/// `http://127.0.0.1:<port>`, optionally with a trailing `/`: the harness's fake is a plain-HTTP
/// server on loopback, and `compile_issuer` is https-only, so no real endpoint is ever spelled
/// like this. Anything else is an `Err` naming the variable, because a switch that accepted
/// `https://cognito-idp.eu-central-1.amazonaws.com/` is a switch a host can be pointed at an
/// upstream of the caller's choosing with, which is the §13.22 rule this feature exists to keep
/// unreachable outside a test.
///
/// A value that is read is announced on stderr in a line containing `E2E BUILD`, and
/// `e2e/lib/server.js` refuses to run against a process that did not print it: a walk that
/// silently reached no fake would read as a scene full of refusals.
#[cfg(feature = "e2e-fake-cognito")]
fn e2e_cognito_endpoint(lookup: impl Fn(&str) -> Option<String>) -> Result<Option<String>, String> {
    const VAR: &str = "BB_AUTH_WEB_E2E_COGNITO_ENDPOINT";
    let Some(raw) = lookup(VAR) else {
        return Ok(None);
    };
    let refuse = || {
        format!(
            "{VAR} must be http://127.0.0.1:<port> (the e2e harness's fake Cognito); got '{raw}'"
        )
    };
    let Some(rest) = raw.strip_prefix("http://127.0.0.1:") else {
        return Err(refuse());
    };
    let port = rest.strip_suffix('/').unwrap_or(rest);
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refuse());
    }
    eprintln!("E2E BUILD: Cognito calls go to {raw}");
    Ok(Some(raw))
}

/// The same function with no switch: a build that does not carry `e2e-fake-cognito` reads
/// nothing, so the variable is inert on every host and its name is not in the binary. The
/// feature body above is the rule, and docs/ARCHITECTURE.md §13.24 is why it is behind one.
#[cfg(not(feature = "e2e-fake-cognito"))]
fn e2e_cognito_endpoint(
    _lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<String>, String> {
    Ok(None)
}

// The second lock of §13.24, on the source: the harness builds debug, so a release build that
// carries the feature does not compile at all, and the switch cannot meet a `.deb` (always
// `--release`) whatever flags somebody passes. The other two locks are the artifact check in
// scripts/package.sh and the harness's own `--target-dir target/e2e`, which keeps
// target/debug/bb-auth-web, the binary a developer copies by hand, free of the feature.
// (A `//` comment and not a doc comment: rustdoc documents no macro invocation, so `///` here
// is an unused-doc-comment warning.)
#[cfg(all(feature = "e2e-fake-cognito", not(debug_assertions)))]
compile_error!("e2e-fake-cognito is for the e2e harness's debug build only");

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

/// The rule both of this program's shared secrets follow, named by the variable that carries
/// `raw`: at least 32 characters, all of `[A-Za-z0-9_-]`, so the value survives a shell, an env
/// file, an nginx `proxy_set_header` line and a header value with nothing to quote.
///
/// `hint` is the one sentence each secret has of its own, because the two are installed
/// differently: one is generated by the install, the other has to reach a file outside this
/// repository with the same bytes.
///
/// Every refusal names the variable and **never the value**. A startup message goes to the
/// journal, and a secret printed once at boot is a secret in the journal for as long as the
/// journal is kept; the length is safe to say, the bytes are not.
fn compile_secret_value(var: &str, raw: &str, hint: &str) -> Result<String, String> {
    if raw.chars().count() < 32 {
        return Err(format!(
            "{var} must be at least 32 characters of [A-Za-z0-9_-] (this one is {}); {hint}",
            raw.chars().count()
        ));
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!(
            "{var} holds a character outside [A-Za-z0-9_-], which cannot go into an env file, a \
             shell, an nginx `proxy_set_header` line or a header value without quoting it"
        ));
    }
    Ok(raw.to_string())
}

/// Validate `BB_AUTH_WEB_PROXY_SECRET` (docs/ARCHITECTURE.md §13.3), on the rule both of this
/// program's secrets share ([`compile_secret_value`]).
///
/// Required, with no default: a deployment that starts without a secret is a deployment where
/// the check is not running, and a generated one is one line of the install.
///
/// It is the first check [`handle`] makes, ahead of the self-service page's dispatch, so the
/// page is not a way around it (docs/ARCHITECTURE.md §13.2).
fn compile_proxy_secret(raw: &str) -> Result<String, String> {
    compile_secret_value(
        "BB_AUTH_WEB_PROXY_SECRET",
        raw,
        "the install generates one, so an env file that predates it needs the line appended once",
    )
}

/// Validate `BB_AUTH_WEB_DELETE_SECRET` (docs/ARCHITECTURE.md §13.29 W2): the value this program
/// sends to the deletion intake in `X-BB-Delete-Secret`, on the rule both of this program's
/// secrets share ([`compile_secret_value`]), and `Ok(None)` when unset.
///
/// **Optional for now**, and the reason is the intake's: it checks no secret today, so a required
/// one here would ship a half that enforces nothing while a missing one stopped the GUI from
/// starting. The user's answer to §13.29 W12 question 3, 2026-11-26: bb-auth ships its half once
/// and the owner starts enforcing the header when they choose, with no release here. With the
/// intake set and no secret the GUI starts and its banner says once, in the journal, that the
/// intake trusts any local caller until a secret is set on both sides.
///
/// Optional means "unset is allowed". A **malformed** value is fatal, because an operator who
/// wrote a secret and did not get one sent is a deployment that believes it is protected. The
/// rules are the proxy secret's so the one value can be written to this env file and to the
/// owner's unit file with nothing to quote.
fn compile_delete_secret(raw: &str) -> Result<Option<String>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    compile_secret_value(
        "BB_AUTH_WEB_DELETE_SECRET",
        raw,
        "the operator generates one and writes the same value here and where the intake's unit \
         reads it, so the install does not generate it",
    )
    .map(Some)
}

/// Validate `BB_AUTH_WEB_DELETE_INTAKE` (docs/ARCHITECTURE.md §13.29 W2): the deletion intake's
/// **origin**, and nothing more than an origin. Accepted: `http`, a loopback IP literal
/// (`127.0.0.0/8` or `[::1]`), a port, and nothing else. Empty is `Ok(None)`, the feature off.
///
/// The accepted value is returned **as written**, because the caller appends the intake's two
/// hard-coded paths to it, and a re-serialized origin is a second answer to what the operator
/// typed.
///
/// **Loopback only**, and the reason is the request, not the port: every call carries an identity
/// in clear, in `X-Auth-Email`, to a service whose one check is that header. To any other host
/// that is an identity sent unencrypted to something that deletes accounts on it, which is why a
/// plain-HTTP origin is accepted here and nowhere else in this estate.
///
/// Each refusal is its own reason, and each names the variable, because that is the only thing
/// an operator can go and edit:
///
/// - a **name**, `localhost` included: a name resolves to whatever the resolver says, and
///   "loopback" has to be a fact about the bytes the operator typed, not a guess the startup
///   made for them;
/// - a **non-loopback address**: the identity would leave the host;
/// - **`https`** or any other scheme: the intake speaks plain HTTP on loopback, so an https
///   origin names a host the operator did not name;
/// - a **path**, a query or a fragment: the intake hard-codes its two paths, so a base carrying
///   one appends them somewhere else;
/// - **userinfo**: an `@` is credentials in an origin;
/// - **no port**: the intake *is* a port, and the default one is not where it listens.
fn compile_delete_intake(raw: &str) -> Result<Option<String>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let refuse = |why: &str| -> Result<Option<String>, String> {
        Err(format!(
            "BB_AUTH_WEB_DELETE_INTAKE must be the deletion intake's origin: `http`, a loopback \
             IP literal (127.0.0.0/8 or [::1]) and a port, with no path, no query, no fragment \
             and no userinfo (docs/ARCHITECTURE.md §13.29 W2); '{raw}' {why}"
        ))
    };
    let Some(rest) = raw.strip_prefix("http://") else {
        return refuse("is not an http:// origin");
    };
    // The authority runs to the first delimiter, and there is nothing to accept after it: the
    // intake's paths are the caller's to append, so a base that already carries one is a base
    // that appends them somewhere else.
    let authority = match rest.find(['/', '?', '#']) {
        Some(_) => return refuse("carries a path, a query or a fragment"),
        None => rest,
    };
    if authority.contains('@') {
        return refuse("carries userinfo");
    }
    // An IPv6 literal is bracketed, and the brackets are not part of the address.
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let Some(close) = bracketed.find(']') else {
                return refuse("has an IPv6 literal with no closing bracket");
            };
            (
                &bracketed[..close],
                bracketed[close + 1..].strip_prefix(':').unwrap_or_default(),
            )
        }
        None => match authority.rsplit_once(':') {
            Some((h, p)) => (h, p),
            None => return refuse("names no port"),
        },
    };
    if port.is_empty()
        || !port.bytes().all(|b| b.is_ascii_digit())
        || !port.parse::<u16>().is_ok_and(|p| p > 0)
    {
        return refuse("names no port");
    }
    // A literal, both families, and nothing that has to be resolved to be known.
    let loopback = host
        .parse::<std::net::Ipv4Addr>()
        .map(|a| a.is_loopback())
        .or_else(|_| host.parse::<std::net::Ipv6Addr>().map(|a| a.is_loopback()))
        .unwrap_or(false);
    if !loopback {
        return refuse("is not a loopback IP literal");
    }
    Ok(Some(raw.to_string()))
}

/// The self-service page's prefix: `BB_AUTH_WEB_ACCOUNT_PATH`, normalised, checked against the
/// console's own [`Config::base_path`] (docs/ARCHITECTURE.md §13.2). The `/account` default is
/// the caller's, not this function's: a variable **set to empty** is a refusal, because an
/// operator who typed `BB_AUTH_WEB_ACCOUNT_PATH=` in an env file meant to say something, and a
/// prefix of nothing is the whole host.
///
/// The two prefixes are **siblings**, and that is what the checks are for. The page is the one
/// part of this program a person who is not an administrator reaches, so it is dispatched
/// *before* the `web.admins` allowlist, and a prefix nested inside the console's would put
/// `/admin/account/` in front of the console's own routes: the dispatch would answer those URLs
/// as the self-service page, and a person with no roster row would be standing inside the
/// administrator surface's URL space. So a prefix equal to the base, inside it, or containing
/// it, is a refusal to start, and the message names both.
///
/// The base is normalised the same way here as at startup, because the comparison is between
/// two prefixes and one of them arrives from the env file: `/admin` and `/admin/` are the same
/// prefix, and a check that read them as two strings would wave an overlapping deployment
/// through. A base that normalises to nothing is refused as well: `/` is every path, so a
/// console mounted at the root has no sibling space left to mount anything beside.
///
/// The prefix is checked for the same reason the base is: it is emitted into a `Location:` and
/// into a form's `action`, so printable ASCII with no quote, no backslash and no `@` is what
/// makes that safe with no per-request check.
fn compile_account_path(account: &str, base: &str) -> Result<String, String> {
    // Normalised with the console's own rule, so the comparison below is between two prefixes
    // in one spelling and `/account` and `/account/` are one answer, not two.
    let account =
        normalize_base_path(account).map_err(|e| format!("BB_AUTH_WEB_ACCOUNT_PATH: {e}"))?;
    if account.is_empty() {
        return Err(
            "BB_AUTH_WEB_ACCOUNT_PATH is empty: a prefix of nothing is the whole host, so the \
             self-service page would be dispatched ahead of the administrator allowlist for \
             every URL this program answers. Name a prefix, such as /account."
                .to_string(),
        );
    }
    let base = normalize_base_path(base)
        .map_err(|e| format!("BB_AUTH_WEB_ACCOUNT_PATH cannot be placed: {e}"))?;
    if base.is_empty() {
        return Err(
            "BB_AUTH_WEB_ACCOUNT_PATH cannot be placed: BB_AUTH_WEB_BASE_PATH is `/`, which is \
             every path, so a console mounted at the root has no prefix left beside it to mount \
             the self-service page on. Mount the console under a prefix."
                .to_string(),
        );
    }
    // Does `outer`'s area contain `inner`'s? At a path boundary, which is the rule
    // `bb_auth_core::base_covers` states for an application's area: `/accounts` beside
    // `/account` shares no boundary and is a legal neighbour, while `/admin/account` under
    // `/admin` is not.
    let contains =
        |outer: &str, inner: &str| inner == outer || inner.starts_with(&format!("{outer}/"));
    if contains(&base, &account) {
        return Err(format!(
            "BB_AUTH_WEB_ACCOUNT_PATH ({account}) is the console's own prefix ({base}) or sits \
             inside it: the self-service page is dispatched before the administrator allowlist, \
             so a prefix nested in the console's answers the console's URLs as the page. Choose \
             a prefix beside {base}, such as /account."
        ));
    }
    if contains(&account, &base) {
        return Err(format!(
            "BB_AUTH_WEB_ACCOUNT_PATH ({account}) contains the console's own prefix ({base}): \
             every administrator URL would be dispatched to the self-service page instead."
        ));
    }
    for (pos, ch) in account.char_indices() {
        if matches!(ch, '"' | '\'' | '\\' | '@') {
            return Err(format!(
                "BB_AUTH_WEB_ACCOUNT_PATH has a {ch:?} at offset {pos}: the prefix is emitted \
                 into a Location: and into a form action, so it carries no quote, no backslash \
                 and no userinfo."
            ));
        }
    }
    Ok(account)
}

/// Validate `BB_AUTH_WEB_WORKERS` (docs/ARCHITECTURE.md §13.13, plan step 4e): unset is
/// [`DEFAULT_WORKERS`], an exact decimal from 1 to [`MAX_WORKERS`] is accepted, and anything
/// else is a refusal naming the variable and the accepted range.
///
/// **Fatal, and not the gate's silent `unwrap_or`**: a fallback turns `BB_AUTH_WEB_WORKERS=800`
/// into 8 with nothing anywhere saying so, which is the operator's intent lost without a trace,
/// and every other value this binary reads from its env is already fatal on a bad one. The
/// boot-loop argument that makes the gate careful does not carry over here: a GUI that refuses
/// to start locks nobody out of any application, and `bb-auth-adm` over SSH is untouched.
///
/// **Digits only**, so ` 8` and `+8` are refusals rather than numbers with decoration: this
/// number is how many threads `main` spawns, and a parser that accepted one spelling's noise
/// would be a second answer to what the env file says. Empty is refused rather than defaulted,
/// because an empty assignment is somebody meaning to say something ([`compile_account_path`]
/// reads it the same way), and `0` is refused rather than raised to one, because a service that
/// binds its port and never answers is the worst of both. A refusal is **returned**, never a
/// panic: a panic in a startup parser is a `Restart=on-failure` boot loop.
fn compile_workers(raw: Option<&str>) -> Result<usize, String> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_WORKERS);
    };
    let n = if raw.bytes().all(|b| b.is_ascii_digit()) {
        raw.parse::<usize>().ok()
    } else {
        None
    };
    match n {
        Some(n) if (1..=MAX_WORKERS).contains(&n) => Ok(n),
        Some(n) => Err(format!(
            "BB_AUTH_WEB_WORKERS is {n}: the accepted range is 1 to {MAX_WORKERS}. Zero would \
             bind the port and never answer, and a count above {MAX_WORKERS} has nothing to do \
             in parallel (writes serialise on one lock and a read is milliseconds), so it reads \
             as a typo. Unset is {DEFAULT_WORKERS}."
        )),
        None => Err(format!(
            "BB_AUTH_WEB_WORKERS is {raw:?}: it must be a plain decimal number of request \
             threads from 1 to {MAX_WORKERS}, with no spaces, sign or trailing text. Unset is \
             {DEFAULT_WORKERS}."
        )),
    }
}

/// Does the secret this request carries match the one this process was started with
/// (docs/ARCHITECTURE.md §13.3)?
///
/// Both sides are hashed first, so the two inputs are always the same 32 bytes and the fold
/// over XOR reads every one of them: a plain `==` on strings stops at the first differing
/// byte, and a secret whose prefix can be probed one byte at a time is a secret with a search
/// attached to it. `sha2` is already in the tree (the cookie's HMAC, the form's `rev`), so
/// this buys the property for no dependency.
///
/// An absent header arrives as the empty string and fails like any other value: the refusal
/// for "no secret" and "wrong secret" is the same page, because a difference between them is
/// a probe that tells a local process when it has found the port.
fn proxy_secret_matches(sent: &str, expected: &str) -> bool {
    let sent = Sha256::digest(sent.as_bytes());
    let expected = Sha256::digest(expected.as_bytes());
    sent.iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

impl Config {
    /// Build the config from the environment, exiting on the first fatal problem.
    fn from_env() -> Config {
        // The administrator allowlist is not read here: it lives in the settings file, where
        // this GUI can edit it and see the edit, and an empty or missing one is a refusal to
        // serve, per request, in `handle`.
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
        let access_path = env_req("BB_AUTH_ACCESS_FILE");
        let settings_path = std::env::var("BB_AUTH_SETTINGS_FILE")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .unwrap_or_else(|| default_settings_path(&access_path));
        // Validated with the library's own asset-URL rule, which is the right one here for
        // the same reason it is right for a stylesheet: the value is emitted into an `href`,
        // and it may be either absolute https or a path on this host. Fatal on a bad one,
        // not skipped: a Sign out control that quietly went missing is one an administrator
        // would go on believing they had configured.
        let logout_url = compile_asset_url(
            "BB_AUTH_WEB_LOGOUT_URL",
            &env_or("BB_AUTH_WEB_LOGOUT_URL", ""),
        )
        .unwrap_or_else(|e| {
            eprintln!("[bb-auth-web] FATAL: {e}");
            std::process::exit(1);
        });
        // The self-service page's Sign out: the same link with only its `rd` removed (§13.17),
        // derived once here beside the value it comes from, so no page parses the operator's
        // value per request and the two surfaces cannot disagree about what was cut.
        let account_logout_url = logout_url.as_deref().map(logout_without_rd);
        // Required, and fatal here: a GUI that starts with no secret is a GUI whose check is
        // not running, and the one thing it is asked to protect is the header it trusts.
        let proxy_secret = compile_proxy_secret(&env_or("BB_AUTH_WEB_PROXY_SECRET", ""))
            .unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: {e}");
                std::process::exit(1);
            });
        // The self-service page's prefix, checked against the console's own: two prefixes that
        // overlap are a page answering the administrator surface's URLs, which is a refusal to
        // start, not a page that works on most of its own URLs.
        let account_path =
            compile_account_path(&env_or("BB_AUTH_WEB_ACCOUNT_PATH", "/account"), &base_path)
                .unwrap_or_else(|e| {
                    eprintln!("[bb-auth-web] FATAL: {e}");
                    std::process::exit(1);
                });
        // The worker count, fatal on a bad value like every other value read here. Read with
        // `var` and not `env_or` so an **unset** variable reaches `compile_workers` as `None`
        // (the default) while `BB_AUTH_WEB_WORKERS=` arrives as an empty value and is refused.
        let workers = compile_workers(std::env::var("BB_AUTH_WEB_WORKERS").ok().as_deref())
            .unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: {e}");
                std::process::exit(1);
            });
        // The deletion intake (§13.29 W2). Unset is the feature off, and off is a deployment:
        // no menu row, and the delete page is the `404` every unknown path gets. A malformed
        // value is fatal, like every other value read here, because a half-wired intake is a
        // menu row that leads to a page that cannot reach the worker.
        let delete_intake = compile_delete_intake(&env_or("BB_AUTH_WEB_DELETE_INTAKE", ""))
            .unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: {e}");
                std::process::exit(1);
            });
        let delete_secret = compile_delete_secret(&env_or("BB_AUTH_WEB_DELETE_SECRET", ""))
            .unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: {e}");
                std::process::exit(1);
            });
        Config {
            listen: env_or("BB_AUTH_WEB_LISTEN", "127.0.0.1:8091"),
            access_path,
            settings_path,
            base_path,
            account_path,
            workers,
            default_lang,
            logout_url,
            account_logout_url,
            proxy_secret,
            audit_path: env_or("BB_AUTH_AUDIT_FILE", DEFAULT_AUDIT_FILE)
                .trim()
                .to_string(),
            // The e2e switch (§13.24): `None` in every build that does not carry the feature,
            // which is every build a host runs. The feature build reads a loopback-only address
            // and says so on stderr; a bad value is fatal here, like every other value read
            // above, because a process that thinks it is talking to a fake and is not would
            // spend its whole request budget on the real pool.
            cognito_endpoint: e2e_cognito_endpoint(|k| std::env::var(k).ok()).unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: {e}");
                std::process::exit(1);
            }),
            // The production bound is the constant; only the tests shorten it.
            cognito_timeout: COGNITO_TIMEOUT,
            delete_intake,
            delete_secret,
            intake_timeout: INTAKE_TIMEOUT,
        }
    }
}

/// The operator's logout URL with its `rd` query parameter removed, and everything else exactly
/// as written: scheme, host, port, path, the other parameters in their order, and the fragment.
///
/// The `rd` on `BB_AUTH_WEB_LOGOUT_URL` is the console's round trip, the page a signed out
/// administrator comes back to, and it is written for the administrator surface. On `/account/`
/// that destination is a `403` for anybody who is not an administrator, so the self-service page
/// renders the same link with only that parameter dropped (docs/ARCHITECTURE.md §13.17). The
/// link can therefore only lose a parameter, never gain one: it names no landing place the
/// operator did not already write, and the gate's `safe_rd` against `gate.authorized_hosts`
/// still decides where any logout may land.
///
/// Textual, and deliberately: this program knows neither its scheme nor its host (the reason the
/// variable exists), so the value is cut, never parsed. A parameter goes when its name is
/// exactly `rd`, so `ord` and `rdx` stay; a percent-encoded value goes whole, because splitting
/// on `&` sees an encoded `&` as `%26` and not as a separator; the fragment is split off first,
/// so a `#` inside a value, which must be encoded, cannot be read as one; and the `?` leaves
/// with the last parameter, since a URL ending in `?` is a URL with an empty query.
fn logout_without_rd(url: &str) -> String {
    let (url, fragment) = match url.find('#') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, ""),
    };
    let Some((head, query)) = url.split_once('?') else {
        return format!("{url}{fragment}");
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| pair.split('=').next().unwrap_or_default() != "rd")
        .collect();
    if kept.is_empty() {
        format!("{head}{fragment}")
    } else {
        format!("{head}?{}{fragment}", kept.join("&"))
    }
}

/// The `Location:` of the `303` §13.32 §1 answers a **completed** deletion with: the operator's
/// logout URL ([`Config::account_logout_url`], already without the console's `rd`) with our `rd`
/// **added** to its query, ahead of any fragment.
///
/// A redirect and not a page because the gate is the only program that knows the session
/// cookie's name and builds the clearing `Set-Cookie`: a second builder would clear on a
/// `Domain` or `Path` that differs from the mint's, which "silently succeeds at nothing"
/// (`build_cookie`'s rustdoc, §13.32 §1's rejected option (b)). The `303` rides on the full
/// success **only**: every partial outcome above ends on a page that offers "Try again", and
/// that retry is a walk over the header's addresses which the gate admits by the session
/// cookie, so signing the browser out there strands the person on the page that tells them
/// to retry. With no logout URL there is nowhere to send the browser, so the done page stays.
///
/// The `rd` names the gate's **own** sign-in page and is built from the library's two
/// constants, never from the request: only that page understands the notice (the code is a
/// closed set of one, §13.32 §1), it is a location every deployment already routes ungated,
/// and the constants are the bytes the gate compiles its own `OWN_LOGIN_PATH` from, so the
/// two programs cannot disagree on the landing page. Fixed bytes also mean no request byte
/// ever rides into a `Location:` through this door. The value is percent-encoded with
/// [`pct_encode_segment`] (RFC 3986 unreserved set), which is what lets the `?` and the `=`
/// of the landing URL sit inside one parameter, and the fragment is kept **last**: a URL
/// ending `…#f&rd=…` sends the browser to the fragment and drops the notice.
fn delete_logout_location(logout: &str) -> String {
    let rd = pct_encode_segment(&format!(
        "{}?notice={}",
        bb_auth_core::GATE_LOGIN_PATH,
        bb_auth_core::LOGIN_NOTICE_ACCOUNT_DELETED
    ));
    let (url, fragment) = match logout.find('#') {
        Some(i) => (&logout[..i], &logout[i..]),
        None => (logout, ""),
    };
    let join = if url.contains('?') { '&' } else { '?' };
    format!("{url}{join}rd={rd}{fragment}")
}

/// Is this listen address on the loopback interface? The gate has the same function and the
/// same reason for it; this one is what makes a stray `0.0.0.0` fatal rather than merely
/// mentioned.
///
/// Textual on purpose: the value is a `host:port` string handed to `Server::http`, and what
/// matters is what an operator wrote in the env file. An unresolvable name is not loopback as
/// far as this is concerned, which errs towards refusing.
fn listen_is_loopback(listen: &str) -> bool {
    let host = match listen.rsplit_once(':') {
        // `[::1]:8091`, the only shape where the last colon is not the port separator's.
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => listen,
    };
    let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// An env var read as a deliberate yes: `1`, `true`, `yes`, in any case. Anything else,
/// including the variable being absent, is no.
fn env_flag(key: &str) -> bool {
    matches!(
        env_or(key, "").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// A page. The four section routes are the access file's four sections, which is most of the
/// navigation: what the file has, the GUI has a tab for. [`Route::Config`] is the exception
/// and says so by being one: it edits the *other* file. Everything else is a form, a
/// confirmation, or the one `POST`-only route ([`Route::ScopeMove`]).
///
/// A route that mutates is reached by `POST` on **the same path** that renders its form by
/// `GET`, which is what makes "re-render this form with the library's refusal" a matter of
/// calling the same page function again. The names a route carries — an email, a key id, an
/// application, scope or group name — are already percent-**decoded**.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Route {
    Dashboard,
    /// The applications, which is where every grant in the file is written.
    Apps,
    /// One application and its scopes, in file order.
    App(String),
    Denied,
    Users,
    /// The `user_groups` list, the users tab's Groups sub-page. It has always had the URL;
    /// §13.36 §1 made it the page that URL shows, instead of the roster's page.
    Groups,
    /// One roster row, addressed by its uuid: the identity is what the file references,
    /// and an email can be added or dropped without the page moving.
    User(String),
    /// The audit: what the gate has actually answered, which is the one page here that reads
    /// neither file and edits nothing. It sits between the people and the settings because it
    /// is about the people, one step later: `users` says who *may* get in, this says who did.
    Audit,
    /// The settings file, which is not a section of the access file at all: the five values
    /// the gate reads per request, and the list of people this GUI opens for.
    Config,

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
    /// An identifier is added and dropped on its own, which is what stands in place of a
    /// rename: the identity never changes.
    EmailAdd(String),
    EmailRm(String, String),
    KeyAdd(String),
    KeyEdit(String, String),
    KeyRotate(String, String),
    KeyRm(String, String),

    GroupAdd,
    /// One group's own page at `/groups/{name}` (§13.36 §2): the scopes that name it first,
    /// then its members. Matched after the `+add` arm; a group name is `[A-Za-z0-9_-]`, so
    /// no name can spell `+add` and the two arms cannot trade a URL.
    Group(String),
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
            Route::Denied => "/denied".to_string(),
            Route::Users => "/users".to_string(),
            Route::Groups => "/groups".to_string(),
            Route::User(u) => format!("/users/{}", seg(u)),
            Route::Audit => "/audit".to_string(),
            Route::Config => "/config".to_string(),

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
            Route::Group(n) => format!("/groups/{}", seg(n)),
            Route::GroupEdit(n) => format!("/groups/{}/edit", seg(n)),
            Route::GroupRm(n) => format!("/groups/{}/rm", seg(n)),

            Route::DenyAdd => format!("/denied/{ACTION_ADD}"),
            Route::DenyRm(e) => format!("/denied/{}/rm", seg(e)),
        }
    }

    /// Which nav tab to mark current for this route: everything about a user belongs to
    /// the `users` tab, and so on down the sections. The group list and `denied` have no tab
    /// of their own: their pages live at their own routes, reached from the sub-tab row
    /// beneath [`page_users`]'s tab, because all three lists are about people, which is what
    /// the Users tab is for (§13.36 §1).
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
            | Route::DenyRm(_)
            | Route::Groups => Route::Users,
            Route::App(_)
            | Route::AppAdd
            | Route::AppEdit(_)
            | Route::AppRm(_)
            | Route::ScopeAdd(_)
            | Route::ScopeEdit(..)
            | Route::ScopeRm(..)
            | Route::ScopeMove(..) => Route::Apps,
            Route::Group(_) | Route::GroupAdd | Route::GroupEdit(_) | Route::GroupRm(_) => {
                Route::Users
            }
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
            // §13.36 §1's table: the add form cancels to the list, because the group it is
            // about to make did not exist when the form was opened. The edit and the removal
            // cancel to the group's own page, which is the page that shows the membership the
            // form is about to write, and the page a removal is about to take away.
            Route::Group(_) | Route::GroupAdd => Route::Groups,
            Route::GroupEdit(n) | Route::GroupRm(n) => Route::Group(n.clone()),
            Route::DenyAdd | Route::DenyRm(_) => Route::Denied,
            other => other.clone(),
        }
    }

    /// The `<title>`: the section's own name, untranslated, because that is the word an
    /// operator types. Matched on `self` and not on [`Route::tab`]: `denied` and
    /// `user_groups` share the `users` *tab*, but a form's `<title>` should still say
    /// which section it edits, not which tab is lit.
    fn title(&self) -> &'static str {
        match self {
            Route::Denied | Route::DenyAdd | Route::DenyRm(_) => "denied",
            Route::Groups
            | Route::Group(_)
            | Route::GroupAdd
            | Route::GroupEdit(_)
            | Route::GroupRm(_) => "user_groups",
            _ => match self.tab() {
                Route::Apps => "applications",
                Route::Users => "users",
                Route::Config => "settings",
                // The one title that names no section of either file, because this tab is
                // about neither: it is the file the gate writes.
                Route::Audit => "audit",
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
        ["config"] => Some(Route::Config),

        ["audit"] => Some(Route::Audit),

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

        // The group list is a page of its own, under the Users tab (§13.36 §1). It has
        // always had this URL; what changed is what the URL shows. One group is a page too
        // (§13.36 §2), matched **after** `+add`, which is what makes a name that spells the
        // action impossible: a group name is `[A-Za-z0-9_-]`, so it carries no `+`.
        ["groups"] => Some(Route::Groups),
        ["groups", ACTION_ADD] => Some(Route::GroupAdd),
        ["groups", n] if !n.is_empty() => Some(Route::Group(s(n))),
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
/// this is what a browser puts in the query string when it submits an access check.
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
/// The classification is the library's [`request_site`], which the gate's `/auth/session`
/// door now uses too; what is this program's own is the **policy**, and it is the strict one:
/// `same-origin` and nothing else. Every form here is rendered by this binary and submitted
/// to the same origin, so there is no legitimate `same-site` submission to allow, and each
/// form deletes a user or rewrites the access file. The gate is deliberately laxer, because a
/// sign-in page an operator serves themselves may sit on a sibling host.
///
/// Neither header present ⇒ **refused**. That is not a browser submitting a form, and no
/// token in the page would help against a client that sends neither.
fn csrf_ok(sec_fetch_site: Option<&str>, origin: Option<&str>, host: Option<&str>) -> bool {
    request_site(sec_fetch_site, origin, host) == RequestSite::SameOrigin
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

    /// Every value submitted under `name`, in the order the browser sent them. A group of
    /// checkboxes sharing one name is a list, not a textarea, so it is not [`Form::lines`]:
    /// a browser sends each ticked box as its own pair and sends nothing for an unticked one.
    fn all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect()
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
///
/// `logo` is the deployment's `ui.logo_url`, handed to the policy beside the [`Look`] that
/// builds the page: the bar's `<img>` and the policy's `img-src` are one value read once, and
/// a page that shows a mark its policy does not name is a broken image. The policy is built
/// from that same `Option`, so the widening is exactly as wide as the setting.
fn respond_page(
    req: Request,
    status: u16,
    page: Markup,
    look: &Look,
    logo: Option<&str>,
    reveal: bool,
) {
    // The mark is named in `img-src` on the page that shows it and on no other. Every page
    // rendered above the settings read has no logo to name, and so has a deployment that never
    // set one, and those take `admin_csp`, which is that policy.
    let csp = match logo {
        Some(src) => admin_csp_logo(look, Some(src), reveal),
        None => admin_csp(look, reveal),
    };
    let mut resp = Response::from_data(page.into_string().into_bytes())
        .with_status_code(StatusCode(status))
        .with_header(h("Content-Type", "text/html; charset=utf-8"))
        .with_header(h("Content-Security-Policy", &csp));
    for (k, v) in PAGE_SECURITY_HEADERS {
        resp.add_header(h(k, v));
    }
    let _ = req.respond(resp);
}

/// This GUI's `Content-Security-Policy`.
///
/// Hashes and not a nonce, because everything this program executes or styles is a
/// compile-time constant: the `<style>` block is [`THEME_CSS`] + [`BASE_CSS`] + [`CSS`], the
/// handler on the Preferences list boxes is [`SETTINGS_ONCHANGE`], and the one `<script>`, the
/// reveal's [`COPY_SCRIPT`], is a constant too. So the policy is derived from the same `&str`s
/// the page is, and the two cannot disagree.
///
/// `'unsafe-hashes'` is what an inline event handler needs: a nonce cannot be put on an
/// attribute, and the alternative to naming this one handler by its hash is `'unsafe-inline'`,
/// which would permit every handler anybody ever adds. The `<noscript>` button behind it means
/// a browser that refuses the handler still works, which makes this the rare case where the
/// strict policy has a fallback already built.
///
/// `img-src` is `data:` and nothing else: this is the policy of a page that shows **no** image,
/// which is every page rendered above the settings read (the file that would name a logo is the
/// file those pages exist to report on) and every page of a deployment that never set
/// `ui.logo_url`. [`admin_csp_logo`] is the same policy with the mark named beside it, and the
/// widening is exactly as wide as the setting (§13.28 §6).
///
/// `form-action` stays `'self'`, which is the one place this GUI is stricter than the gate and
/// is meant to be. Every form here posts to this program and is answered with a `302` back to
/// a page of this program, so nothing of the estate's wider boundary applies: a redirect off
/// this host would be a bug, and a policy that permitted one would be the wrong place to find
/// out.
///
/// `reveal` is the bearer reveal and nothing else (§13.14): the one page allowed a `<script>`,
/// so its policy names that script's hash beside the Settings handler's. The console's shell
/// carries the Preferences list boxes on every page including this one, so both hashes ride the
/// same `'unsafe-hashes'` source, and every other page's policy is byte for byte what it was.
fn admin_csp(look: &Look, reveal: bool) -> String {
    admin_csp_logo(look, None, reveal)
}

/// The `script-src` sources **both surfaces** allow: the hash of [`SETTINGS_ONCHANGE`], which
/// the two Preferences list boxes of the shared form carry, and beside it the hash of
/// [`COPY_SCRIPT`] on the bearer reveal and on nothing else (§13.14).
///
/// One function because a rule about what may run cannot have two answers on two surfaces:
/// step 13 (PLAN.md) gave the self-service page the console's handler, and its policy is
/// asserted against this one (`only_the_reveal_policy_names_the_copy_script`), so the two
/// policies cannot drift by one hash.
fn page_script_src(reveal: bool) -> String {
    if reveal {
        format!(
            "'unsafe-hashes' {} {}",
            csp_hash(SETTINGS_ONCHANGE),
            csp_hash(COPY_SCRIPT)
        )
    } else {
        format!("'unsafe-hashes' {}", csp_hash(SETTINGS_ONCHANGE))
    }
}

/// [`admin_csp`] with the deployment's logo named in `img-src`: the policy of a page that shows
/// it, which is every page served from a settings read that has one (§13.28 §6). The logo
/// arrives as its own argument and not inside [`Look`] because the two consumers of it (the
/// bar's `<img>` and this policy) are handed the same `Option` from one settings read, and a
/// policy that named a source the bar cannot show, or the reverse, is the drift an argument
/// shared by both cannot have.
fn admin_csp_logo(look: &Look, logo: Option<&str>, reveal: bool) -> String {
    let script = page_script_src(reveal);
    let style = csp_hash(&format!("{THEME_CSS}{BASE_CSS}{CSS}"));
    page_csp(&script, &style, "'self'", look.stylesheet, logo, &[])
}

/// `302` to `location`, setting one preference cookie to `value`. `location` is built from a
/// [`Route`] and re-encoded query parameters, so it is printable ASCII by construction and
/// [`h`] cannot panic on it; `value` is one of a closed enum's own [`Lang::code`] or
/// [`UiTheme::code`], or a [`TzPref::code`], whose one request-supplied spelling has passed
/// [`custom_zone`]'s charset, which holds no byte a cookie value may not carry.
///
/// The one redirect every preference uses: see [`respond_lang_redirect`] and
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
fn respond_theme_redirect(req: Request, location: &str, theme: UiTheme) {
    respond_preference_redirect(req, location, THEME_COOKIE, theme.code());
}

/// `303` to `location` — the redirect half of POST-redirect-GET, so a reload of the result
/// page cannot repeat the mutation.
///
/// `303` and not `302`: it is the status that tells every browser to follow with a `GET`,
/// which is the entire point. `location` is a [`Route::path`] under the base plus a
/// [`Msg::key`], both printable ASCII by construction, so [`h`] cannot panic on it — and
/// nothing request-supplied is in it.
///
/// Its other uses: a `GET` that carried nothing but a time zone nobody could read, which comes
/// back to its page with the zone dropped (that `location` is a [`preference_href`], so the
/// same argument holds: every client byte in it has been re-encoded); and the completed account
/// deletion, sent through the gate's logout (§13.32 §1, [`delete_logout_location`]), whose
/// `location` is operator config and library constants, no request byte.
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

/// Which theme to render in. Query, then cookie, then `UiTheme::System`: most explicit wins,
/// and `System` is the floor rather than a configured default, since there is nothing to
/// configure; it is what every session already has until it chooses otherwise.
fn negotiate_theme(query: Option<&str>, cookie: Option<&str>) -> UiTheme {
    if let Some(t) = query.and_then(parse_theme) {
        return t;
    }
    if let Some(t) = cookie.and_then(parse_theme) {
        return t;
    }
    UiTheme::System
}

/// This request's URL with the `param` query parameter dropped: where a preference redirect
/// lands, once the choice that parameter carried has become a cookie. The rest of the query
/// survives, which is what keeps an access-check verdict on screen across a preference change.
///
/// One builder for both preferences, named by the cookie constant at the call site
/// (`LANG_COOKIE`, `THEME_COOKIE`): each doubles as its query parameter's name, so there is
/// one spelling per preference and no second place to keep in step. Every byte of the result
/// is a constant, a [`Route::path`] or a re-encoded query parameter — nothing the client sent
/// survives verbatim, which is what makes the string safe in a `Location:` header.
fn preference_href(cfg: &Config, at: &Route, query: &str, param: &str) -> String {
    preference_href_without(cfg, at, query, &[param])
}

/// [`preference_href`] for a preference that arrives as more than one parameter, which today
/// is the audit's clock: a list box and the text box a `custom` choice reads.
fn preference_href_without(cfg: &Config, at: &Route, query: &str, params: &[&str]) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        if !params.contains(&k.as_ref()) {
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
/// The redirect that follows a pick rebuilds the whole URL ([`preference_href`]); a `GET`
/// form sends its own fields and nothing else, so without this, changing the theme on a page
/// showing an access-check verdict would throw the verdict away. `msg` is deliberately *not*
/// dropped: the flash belongs to the page the operator is looking at.
fn preserved_query(query: &str) -> Vec<(String, String)> {
    form_urlencoded::parse(query.as_bytes())
        .filter(|(k, _)| k != LANG_COOKIE && k != THEME_COOKIE)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

// ---------------------------------------------------------------------------
// Filtering and paging a list
// ---------------------------------------------------------------------------
//
// Both live entirely in the query string, which is the only place they *can* live: a page
// here must work with scripting off, and a `GET` never mutates, so a filter is a form that
// navigates and a page is a link. That also makes both bookmarkable and survivable across a
// language change for free — `preserved_query` already carries every parameter but the two
// preferences through the Settings form.
//
// Each list namespaces its two parameters with a prefix (`uq`/`up`, `gq`/`gp`, …) so that
// several lists can sit on one page (as users, groups and denied do) without stealing
// each other's state.
//
// Scopes are deliberately NOT in this scheme. They are first-match-wins, their position is
// their meaning, and the ↑/↓ buttons move a scope within the *file*: a filtered view would
// show positions that are not the file's and a move that appears to do nothing. A list whose
// order is data does not get to be reordered by a search box.

/// Rows of one list per page.
const PAGE_SIZE: usize = 25;

/// One list's filter and page, read out of the query string.
struct Listing {
    /// Namespaces this list's two parameters. `""` is legal and means the page has one list.
    prefix: &'static str,
    /// The filter as typed, lowercased once so [`Listing::keeps`] does not do it per row.
    q: String,
    /// 0-based, as requested. [`Listing::window`] is what clamps it to what exists.
    page: usize,
    /// Whether the list is narrowed by something **besides** the box: the roster's group chip
    /// (§13.36 §5), which is a filter no field of the panel shows. A filter no box shows is a
    /// filter no box clears, so it has to count for the sentence the pager prints, and the
    /// panel answers it with a chip of its own.
    filtered: bool,
}

impl Listing {
    fn read(prefix: &'static str, query: &str) -> Listing {
        let q = query_param(query, &format!("{prefix}q")).unwrap_or_default();
        let page = query_param(query, &format!("{prefix}p"))
            .and_then(|p| p.trim().parse::<usize>().ok())
            .unwrap_or(1);
        Listing {
            prefix,
            q: q.trim().to_lowercase(),
            // Pages are 1-based in the URL, where a human reads them, and 0-based here.
            page: page.saturating_sub(1),
            // A caller whose list is narrowed by something outside the box says so.
            filtered: false,
        }
    }

    /// Does this row survive the filter? A plain case-insensitive substring, over whatever
    /// the caller decided the row's searchable text is — no globs, because the box next to a
    /// list of URL patterns must not look like it takes one.
    fn keeps(&self, hay: &str) -> bool {
        self.q.is_empty() || hay.to_lowercase().contains(&self.q)
    }

    /// The visible slice of `matched` rows, and how many pages there are.
    ///
    /// The page is clamped rather than refused: a filter that shrinks the list under the
    /// page someone was on is an ordinary thing to do, and answering it with an empty table
    /// would read as "nothing matches" when plenty does.
    fn window(&self, matched: usize) -> (usize, usize, usize, usize) {
        let pages = matched.div_ceil(PAGE_SIZE).max(1);
        let page = self.page.min(pages - 1);
        let start = page * PAGE_SIZE;
        (start, (start + PAGE_SIZE).min(matched), page, pages)
    }

    /// This list's own two parameter names.
    fn q_name(&self) -> String {
        format!("{}q", self.prefix)
    }
    fn p_name(&self) -> String {
        format!("{}p", self.prefix)
    }
}

/// An href for this page with this list's parameters replaced by `set`, everything else
/// kept: `[("up", "3")]` pages, `[]` clears both the filter and the page.
///
/// Every byte is a constant, a [`Route::path`] or a re-encoded parameter, so the result is
/// safe in an `href` for the same reason [`preference_href`]'s is.
fn listing_href(v: &View, l: &Listing, set: &[(String, String)]) -> String {
    let (q_name, p_name) = (l.q_name(), l.p_name());
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, val) in form_urlencoded::parse(v.query.as_bytes()) {
        if k != q_name && k != p_name {
            ser.append_pair(&k, &val);
        }
    }
    for (k, val) in set {
        ser.append_pair(k, val);
    }
    let q = ser.finish();
    if q.is_empty() {
        v.href(&v.at)
    } else {
        format!("{}?{q}", v.href(&v.at))
    }
}

/// This list's page `page` (1-based), with its filter kept.
fn page_href(v: &View, l: &Listing, page: usize) -> String {
    let mut set = Vec::new();
    if !l.q.is_empty() {
        set.push((l.q_name(), l.q.clone()));
    }
    set.push((l.p_name(), page.to_string()));
    listing_href(v, l, &set)
}

/// The filter box and the pager for one list, rendered above it.
///
/// The form is a `GET` back to this same route, exactly like the Settings menu: submitting
/// it *is* the navigation. Every other parameter on the page rides along as a hidden input
/// so filtering one list does not reset another's page — except this list's own page, which
/// is dropped on purpose, because a new filter belongs at the top of its results.
fn list_controls(v: &View, l: &Listing, matched: usize, total: usize) -> Markup {
    list_controls_named(v, l, matched, total, K::Filter)
}

/// [`list_controls`] where the box names what it searches. Only the roster's does today
/// (`K::FilterPeople`), because only its reach is wider than the column beside it: the box
/// finds a uuid and a key id too, and a box that says "filter" says nobody can (§13.36 §4).
fn list_controls_named(v: &View, l: &Listing, matched: usize, total: usize, ph: K) -> Markup {
    list_controls_with(v, l, matched, total, &[], html! {}, ph)
}

/// [`list_controls`] with fields of its own in front of the filter box.
///
/// `extra` is rendered inside the same form, so one submit applies the whole row and there is
/// one Apply button rather than one per control. `owned` names the parameters `extra` renders
/// itself: they are then left out of the hidden inputs, or every one of them would be
/// submitted twice and the page would read whichever value came last.
///
/// This exists for the audit, which is the only list here filtered by anything but text, and
/// it stays a parameter of the shared control rather than a second control beside it: two
/// forms over one list are two Apply buttons, and an operator who set a period and typed a
/// name would have to guess which one applies both.
fn list_controls_with(
    v: &View,
    l: &Listing,
    matched: usize,
    total: usize,
    owned: &[&str],
    extra: Markup,
    ph: K,
) -> Markup {
    let (start, end, page, pages) = l.window(matched);
    let q_name = l.q_name();
    let p_name = l.p_name();
    // Anything narrowing this list, from the box or from a control that is not a field.
    let narrowed = !l.q.is_empty() || l.filtered;
    // One sentence says where in the list this page sits, in place of the "page 2/5" fragment
    // and the bare "matched/total" span (§13.36 §4): the first row shown, the last, how many
    // matched, and while anything narrows the list, the list's whole length beside it.
    let rows = if !narrowed {
        fill(
            t(v.lang, K::PagerRows),
            &[
                &(start + 1).to_string(),
                &end.to_string(),
                &matched.to_string(),
            ],
        )
    } else {
        fill(
            t(v.lang, K::PagerRowsFiltered),
            &[
                &(start + 1).to_string(),
                &end.to_string(),
                &matched.to_string(),
                &total.to_string(),
            ],
        )
    };
    html! {
        div class="listctl" {
            form method="get" action=(v.href(&v.at)) {
                @for (k, val) in preserved_query(v.query) {
                    @if k != q_name && k != p_name && !owned.contains(&k.as_str()) {
                        input type="hidden" name=(k) value=(val);
                    }
                }
                (extra)
                input type="search" name=(q_name) value=(l.q) placeholder=(v.t(ph))
                      aria-label=(v.t(ph));
                // The page a submit lands on, spelled out rather than left to the absence of
                // `p`: a new filter belongs at the top of its results, and a field carrying the
                // first page says that to whoever reads the form.
                input type="hidden" name=(p_name) value="1";
                button type="submit" class="pill" { (v.t(K::Apply)) }
                @if !l.q.is_empty() {
                    a class="pill" href=(listing_href(v, l, &[])) title=(v.t(K::FilterClear)) { "×" }
                }
            }
            @if matched > 0 && (pages > 1 || narrowed) {
                span class="pager" {
                    // The words first, the two controls after them. With the sentence standing
                    // between them it was squeezed into a column one word wide at 320px in
                    // Italian (§13.36 §4, measured).
                    span class="muted" { (rows) }
                    @if pages > 1 {
                        @if page > 0 {
                            a class="pill" href=(page_href(v, l, page)) { "← " (v.t(K::PagePrev)) }
                        } @else {
                            span class="pill off" { "← " (v.t(K::PagePrev)) }
                        }
                        @if page + 1 < pages {
                            a class="pill" href=(page_href(v, l, page + 2)) { (v.t(K::PageNext)) " →" }
                        } @else {
                            span class="pill off" { (v.t(K::PageNext)) " →" }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

/// How this deployment asks its pages to look: the `ui` section of the settings file, as far
/// as [`shell`] is concerned.
///
/// It is a type of its own, and carried beside the visitor's own preference rather than folded
/// into it, because the two answer different questions and both have to survive to the page.
/// `theme` here is the deployment's default and `View::theme` is what this browser chose, so
/// the Settings menu can still show `System` as selected while the page renders dark.
///
/// [`Look::default`] is "nothing configured", and it is the honest answer on every page
/// rendered *before* the settings file has been read: a 401 from a missing identity header and
/// a 500 from a file that will not compile both happen above that read, and a page that cannot
/// know the operator's stylesheet must show the built-in one rather than guess.
#[derive(Clone, Copy, Default)]
struct Look<'a> {
    /// `ui.theme`: which arm of the palette a page starts in when the visitor has expressed no
    /// preference of their own.
    theme: UiTheme,
    /// `ui.stylesheet_url`: an operator's own stylesheet, loaded after the built-in one.
    stylesheet: Option<&'a str>,
    /// `ui.brand_name`: the deployment's name in the bar, so one settings read per request
    /// feeds every part of the look.
    brand: Option<&'a str>,
}

/// Everything the page shell needs that is not the page.
struct View<'a> {
    cfg: &'a Config,
    lang: Lang,
    /// Which option the Settings menu shows as the chosen language, which is not the same
    /// thing as `lang`: `Auto` renders as one of the two and must still come back as `Auto`
    /// (see [`LangPref`]). Both come from one [`negotiate_lang`] call.
    lang_pref: LangPref,
    /// Which appearance **this browser** asked for; see [`UiTheme`]. `System` unless the
    /// visitor chose otherwise, and it is its own chosen-option marker in the Settings menu,
    /// `System` included, which is why the choice needs no second field beside this one.
    ///
    /// It is not, on its own, what the page renders in: `System` means "no choice", and
    /// [`shell`] then falls through to the deployment's own [`Look::theme`] before leaving the
    /// decision to the OS.
    theme: UiTheme,
    /// Which clock **this browser** reads the audit in; see [`TzPref`]. Only the audit page
    /// looks at it, and it is carried here with the other two preferences because it comes
    /// from the same place (a cookie) for the same reason (a preference outlives a page).
    tz: TzPref,
    /// Whether the Settings page opens folded; see [`GroupsPref`].
    groups: GroupsPref,
    /// The audit's rotation and retention, from the same settings read as everything else on
    /// the page: the Audit tab shows no event the retention says is gone, whether or not the
    /// gate's hourly maintenance has reached it yet.
    audit: AuditPolicy,
    /// How this deployment asks the page to look. See [`Look`].
    look: Look<'a>,
    /// The signed-in administrator, when there is one. `None` suppresses the navigation:
    /// a visitor who got a `401` or a `403` has nowhere to go but the login page.
    admin: Option<&'a str>,
    /// The route being rendered, for the current tab and the language switch.
    at: Route,
    /// The query as received, so switching language keeps an access check's fields filled in.
    query: &'a str,
    /// sha256 of the access file's exact bytes as this request read them. Every form on the
    /// page carries it, and the `POST` that comes back must still match — see [`mutate`].
    /// Empty when the file could not be read, in which case there is no form to render.
    rev: &'a str,
    /// What the redirect that landed here says it did, if this binary said it ([`Msg`]).
    msg: Option<Msg>,
    /// The header names an authorized `204` will actually carry, derived from
    /// `gate.identity_attrs` by the library exactly as the gate derives them.
    ///
    /// Here because the access check answers "what will the application receive?", and that
    /// is a question about *this* deployment's settings. It used to answer with the literal
    /// `X-Auth-Email`, two clicks from the Settings field that can make it `X-Auth-Uuid` and
    /// nothing else, so the one page whose whole job is to predict the gate's behaviour was
    /// the page describing a header that would never arrive.
    identity: Vec<String>,
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

/// Who the bar says is signed in, in the two pieces the account menu needs: the **one** string
/// the trigger shows, and **every** address of the identity header for the panel to print.
///
/// The header is a list and not one address: the gate puts **every** email of the roster row
/// into it, joined by a single space (see `handle`), and a row with three addresses is one
/// person. Naming all three in a bar that has a few characters of room would be a second
/// sentence about the same person, so the bar names the one the person signs in as and the
/// panel prints the rest.
///
/// The given name is decoration from a profile claim, and a deployment that does not configure
/// `given_name` forwards no header at all. The address alone is then the whole label, which is
/// why this takes an `Option` and answers the address alone for a name that is empty: a trigger
/// reading `· bot@example.com` is a trigger with a hole in it.
struct Who {
    /// The trigger's visible label: a name, else an address, never both and never a separator.
    label: String,
    /// Every address of `X-Auth-Email`, in the order the gate wrote them.
    emails: Vec<String>,
    /// The name alone, when there is one: the panel prints it in `strong` above the addresses,
    /// and `label` is the same word cut to one line. `None` is "no name", which is why the
    /// trigger shows an address.
    name: Option<String>,
}

/// [`Who`] from the two headers. See the struct.
fn who(given_name: Option<&str>, email_header: &str) -> Who {
    let emails: Vec<String> = email_header
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect();
    let name = given_name
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    let label = name
        .clone()
        .or_else(|| emails.first().cloned())
        .unwrap_or_default();
    Who {
        label,
        emails,
        name,
    }
}

/// The bar every page of this program wears, as four slots: the navigation menu, the brand,
/// the tabs, and the account end.
///
/// Factored out of [`shell`] because the self-service page wears the same bar (§13.17), and
/// two copies of one bar is how two surfaces drift a pixel at a time, each editor changing the
/// file in front of them. The slots are markup and not a type because that is all the two
/// surfaces differ on: the account page has no tabs to move and no ☰ to move them in. Every
/// class is `admin.css`'s already, so a slot that arrives with one of its own is the thing to
/// fix.
fn top_bar(navn: Markup, brand: Markup, tabs: Markup, acct: Markup) -> Markup {
    html! {
        header class="top" {
            div class="bar" {
                (navn)
                (brand)
                (tabs)
                (acct)
            }
        }
    }
}

/// The brand slot of both shells: the operator's mark and the name (§13.28 §6, §7, as §13.34
/// §10 and §11 end it). It is a `span` on **every** surface, with no `href`: `/account/` is the
/// only page of its surface and the `403` names a console the caller may not open, and the
/// console's Dashboard tab beside the slot is the way home, so a link there would name a page the
/// bar already names. `extra` carries the page's own class (`selfserve-brand`), which is
/// arrangement and not the slot's own shape.
///
/// One function because the mark and the name are one object on both surfaces: two call sites
/// drawing the same pair is how a logo arrives in one bar and not the other, which is the drift
/// this file keeps writing rules about. The `alt` is empty because the name beside the picture
/// already says what it is. At 640px and below the bar shows the **mark** and hides the words
/// (§13.34 §12g, the user's reversal of 2026-11-27, which is the phone arm as §13.28 §4 wrote
/// it), and the words are hidden visually only: `admin.css` clips them to a 1px box, so they
/// stay in the accessibility tree and a reader hears the deployment's name from them, once. An
/// `alt` naming the picture would say it twice to that reader.
fn brand_block(name: &str, logo: Option<&str>, extra: &str) -> Markup {
    let cls = if extra.is_empty() {
        "brand".to_string()
    } else {
        format!("brand {extra}")
    };
    html! {
        span class=(cls) {
            @if let Some(src) = logo {
                img src=(src) alt="";
            }
            span class="t" { (name) }
        }
    }
}

/// The Preferences form, shared by both shells (§13.28 §3, §7).
///
/// One function because the two surfaces have **one** form: step 13 (PLAN.md) gave the
/// self-service page the console's behaviour, so the two list boxes submit themselves through
/// [`SETTINGS_ONCHANGE`] on both, and Apply rides in a `noscript` on both as the way in for a
/// browser running no code. The flag that used to make the page's copy plain is gone, and with
/// it the second shape of the form: two copies is how one list box gains a third option on one
/// surface only, which is the drift this file keeps writing rules about. `action` is the page
/// the `GET` returns to, and `hidden` re-carries the query the page was read with, so choosing
/// a theme from a filtered list does not throw the filter away.
fn prefs_form(
    lang: Lang,
    lang_pref: LangPref,
    theme: UiTheme,
    action: &str,
    hidden: &[(String, String)],
) -> Markup {
    // Both lead with the choice that follows something outside this GUI (the browser, the OS),
    // because that is where every session starts and what the other options are departures from.
    let langs = [
        LangPref::Auto,
        LangPref::Fixed(Lang::En),
        LangPref::Fixed(Lang::It),
    ];
    let themes = [UiTheme::System, UiTheme::Light, UiTheme::Dark];
    html! {
        form class="edit" method="get" action=(action) {
            @for (k, val) in hidden {
                input type="hidden" name=(k) value=(val);
            }
            label {
                span class="lbl" { (t(lang, K::SettingLanguage)) }
                select name=(LANG_COOKIE) onchange=(SETTINGS_ONCHANGE) {
                    @for p in langs {
                        option value=(p.code()) selected[p == lang_pref] { (p.label(lang)) }
                    }
                }
            }
            label {
                span class="lbl" { (t(lang, K::SettingTheme)) }
                select name=(THEME_COOKIE) onchange=(SETTINGS_ONCHANGE) {
                    @for th in themes {
                        option value=(th.code()) selected[th == theme] {
                            (t(lang, theme_label(th)))
                        }
                    }
                }
            }
            // The way in for a browser with scripting off. The browser parses the `noscript`
            // block as text, so with scripting on the button is not in the DOM at all and
            // picking an option is the whole interaction.
            noscript { div class="actions" { button { (t(lang, K::Apply)) } } }
        }
    }
}

/// The account menu both shells wear (§13.28 §1, §2, §3): one trigger that opens one panel.
///
/// The trigger is the person's own name, because the bar has a few characters of room and a
/// name is what a person recognises in it; the word "account menu" rides along inside the
/// control, visually hidden, so a reader is told what the name **is** rather than left with a
/// word that reads as a heading. The panel says who they are in full, offers the places this
/// menu has (`places`: §13.34 leaves the console's one, the caller's own page, and the
/// self-service page has none), the nested Preferences box, and Sign out, and ends in the delete
/// row on the one surface that offers it.
///
/// The panel is a `details` for the reason §13.20 gave: it opens with no script, closes by
/// itself when a row navigates away, and its trigger keeps the light-dismiss cover the console
/// already has. The nested box gets no cover of its own, so it toggles only from its own row.
/// `logout` is `None` when the operator named no destination, and then there is no row.
///
/// `grouped` is whether the bar carries a ☰ beside this menu (§13.34 §2), and it is a parameter
/// because the answer is not this function's to read: the console's pages have one, `/account/`
/// has one, and the console's `403` has none, because a page with no tabs has no tab strip to
/// move. `name="bar-menu"` is the exclusive-open group, and it groups **two** boxes, so a page
/// with one menu names a group nothing else belongs to. A group of one is not a rule, it is a
/// claim about a control that is not on the page.
///
/// The panel's groups are divided by a rule on **both** surfaces (§13.34 §3): one ahead of
/// Preferences, one ahead of Sign out. A rule that appears only where the console has places is
/// how the two panels stopped being one object, which is what `the_account_menu_is_one_object`
/// reads as the ordered list of classes.
///
/// `delete` is the self-service page's last row (§13.30 §1), and `None` is the whole reason it
/// is a parameter rather than something read here: the console's panel never carries it, and the
/// page carries it only where an intake is wired.
fn account_menu(
    lang: Lang,
    who: Option<&Who>,
    places: Option<Markup>,
    prefs: Markup,
    logout: Option<&str>,
    delete: Option<&str>,
    grouped: bool,
) -> Markup {
    let label = who.map(|w| w.label.as_str()).unwrap_or("");
    let menu_word = format!(", {}", t(lang, K::AccountMenu));
    let group = grouped.then_some("bar-menu");
    html! {
        details class="settings" name=[group] {
            // The name, the caret, and the word that names the control. `title` carries the full
            // label because the ellipsis may cut it, and a tooltip is the one place a cut name is
            // still the whole name.
            summary class="pill who" title=(label) {
                span class="who-name" { (label) }
                span class="vh" { (menu_word) }
                svg class="i-caret" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                    path d="M6 9l6 6 6-6" {}
                }
            }
            div class="menu" {
                // Who the name is, in full: every address of the roster row, because a caller is
                // their whole row and not the one address the bar had room for. No uuid: the
                // panel is read by a person, and an id is what the account page names under its
                // own label.
                @if let Some(w) = who {
                    p class="who-full" {
                        @if let Some(n) = &w.name {
                            strong { (n) }
                        }
                        @for e in &w.emails {
                            span class="addr muted" { (e) }
                        }
                    }
                }
                // The console's places, and the rule that divides them from the rows below (§13.34
                // §3). A caller with no places gets no container and no rule at all, which is what
                // keeps the `403` from offering a page it has refused. The rule is an `hr` and not
                // the panel's `div.sep`, because the panel must stay **one object** across the two
                // surfaces: `the_account_menu_is_one_object` reads the ordered list of classes the
                // panel emits once its two surface-only blocks are out, and a classed rule that
                // only the console emits is exactly the difference that test is there to catch.
                // `hr` is the element for a thematic break, so the divider is semantics with no
                // class to drift, and it sits after the places block, not inside it: the block is
                // the places, and a rule closing it would divide the block from itself.
                @if let Some(p) = places {
                    div class="menu-places" {
                        (p)
                    }
                    hr;
                }
                details class="prefs" {
                    // The sliders, and the word "Preferences": the panel's rows are places to go
                    // and this one is not, and the row that opens the two display choices must
                    // not read as the System settings page beside it.
                    summary class="pill" {
                        svg class="i-sliders" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                            path d="M3 6h12" {}
                            circle cx="18" cy="6" r="2.5" {}
                            path d="M9 12h12" {}
                            circle cx="6" cy="12" r="2.5" {}
                            path d="M3 18h8" {}
                            circle cx="14" cy="18" r="2.5" {}
                        }
                        (t(lang, K::Settings))
                    }
                    (prefs)
                }
                // Sign out behind the last rule: it is the row that leaves the estate, and the
                // rule is what separates it from the rows that only change how the estate looks.
                @if let Some(u) = logout {
                    div class="sep" {}
                    a class="pill" href=(u) {
                        svg class="i-out" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                            path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" {}
                            path d="M16 17l5-5-5-5" {}
                            path d="M21 12H9" {}
                        }
                        (t(lang, K::SignOut))
                    }
                }
                // The delete row, last (§13.30 §1). It is a link to the page that asks, not a
                // submission: a `GET` never mutates, and a browser prefetches the last row of an
                // open menu, which must not cost a person their account. The words name what the
                // press costs, because the worker's deletion is the one action on this estate
                // nobody can undo, and the glyph is decoration behind `aria-hidden`, so the
                // visible word stays the accessible name. A trash can and not the keys table's
                // `×`: at the bottom of a panel an `×` reads as "close this".
                @if let Some(href) = delete {
                    div class="sep" {}
                    a class="pill rm" href=(href) {
                        svg class="i-trash" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                            path d="M3 6h18" {}
                            path d="M8 6V4h8v2" {}
                            path d="M6 6l1 14h10l1-14" {}
                        }
                        (t(lang, K::AccountDelete))
                    }
                }
            }
        }
    }
}

/// The document skeleton both HTML surfaces of this program wear: the doctype, `<html>` stamped
/// with the language and with the theme when one is chosen, the head, and `body` as the whole
/// contents of the `<body>` element.
///
/// One function for both surfaces, because the head is the part the estate's safety argument
/// rests on: a page's `Content-Security-Policy` carries the hash of the three inlined
/// stylesheets **as one string** (see [`admin_csp`] and [`account_csp`]), so a head that emitted
/// them in another order, or with whitespace between them, is a page whose own policy refuses
/// its own look. Two heads written by hand is two chances for that to drift, and the drift is
/// invisible from inside either one.
///
/// The three stylesheets are the deliberately raw emissions on any page, and all three are
/// compile-time constants: never request data and never anything read out of the access file.
/// Their order is the contract: the palette, the components built out of it (the same bytes the
/// gate's pages get), the layout that arranges them, then whatever the operator wants to say
/// over the top.
///
/// `theme_attr` is the resolved theme's spelling, and the caller resolves the fallback order
/// (this browser's choice, then the deployment's default, then nothing). It is optional in the
/// type as well as in the markup: `None` omits `data-theme` outright rather than emitting
/// `data-theme=""`, because an empty attribute is one the palette's `[data-theme=…]` selectors
/// do not match, and leaving it off is what lets the `prefers-color-scheme` rule in `THEME_CSS`
/// be the one deciding.
///
/// `title` is the **whole** `<title>` text, escaped, and this function adds no prefix of its
/// own: that is what lets the console say `bb-auth-web · …` and the self-service page say
/// `{brand} · …` from the one skeleton.
///
/// `stylesheet` is the operator's own stylesheet, linked **after** the `<style>` so an override
/// wins by source order and needs no `!important`; `None` links nothing at all, because the
/// built-in look is complete and a deployment that configured nothing fetches nothing (a host
/// that is down then costs a page its palette and nothing else). The link is raw because the
/// library builds a whole `<link>` element out of a URL that has already passed
/// `compile_asset_url`, and maud has no way to say "an element" except in maud.
fn page_document(
    lang: Lang,
    theme_attr: Option<&str>,
    title: &str,
    stylesheet: Option<&str>,
    body: Markup,
) -> Markup {
    html! {
        (DOCTYPE)
        html lang=(lang.code()) data-theme=[theme_attr] {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { (title) }
                style { (PreEscaped(THEME_CSS)) (PreEscaped(BASE_CSS)) (PreEscaped(CSS)) }
                (PreEscaped(stylesheet_link(stylesheet)))
            }
            body { (body) }
        }
    }
}

/// The chrome around every page: the tabs, the account menu, the footer.
///
/// [`shell_as`] with no given name, no identity header and no logo to show, which is the
/// honest answer for a page built from a [`View`] nobody made from a request: there is no
/// forwarded claim and no settings read on one, so the bar says the address alone and shows
/// no mark.
fn shell(v: &View, title: &str, content: Markup) -> Markup {
    shell_as(v, None, "", None, title, content)
}

/// [`shell`] for a page rendered out of a request, which is the only place the bar's two
/// facts exist: the given name the proxy forwarded for the `given_name` claim (`None` when
/// the deployment does not configure it), and the whole identity header, `emails`: the gate
/// puts **every** email of the roster row into it, and a caller admitted by their second
/// address reads a panel naming every address they have, which is the answer the account page
/// already gives (§13.28 §2). `logo` is the deployment's `ui.logo_url`, the same `Option` the
/// response's policy is built from. The name goes in the bar beside the session controls and
/// at the top of the Preferences menu, and nowhere else: the footer used to say it too, and
/// one fact in two places is one fact that starts disagreeing with itself.
fn shell_as(
    v: &View,
    given_name: Option<&str>,
    emails: &str,
    logo: Option<&str>,
    title: &str,
    content: Markup,
) -> Markup {
    let ident = if emails.trim().is_empty() {
        v.admin.unwrap_or_default()
    } else {
        emails
    };
    shell_named(
        v,
        v.admin.map(|_| who(given_name, ident)),
        logo,
        title,
        content,
    )
}

/// [`shell_as`] with the bar's identity **given** rather than read out of `v.admin`.
///
/// The console's `403` is the caller that needs it (§13.17). That page has to name the person
/// it is refusing, and `v.admin` is `None` there precisely because the allowlist said no, so
/// deriving the label from it leaves the bar empty on the one page where the reader most needs
/// to see who the sentence is about. The tabs and the brand stay keyed on `v.admin`, which is
/// what makes "an identity in the bar, no tabs" expressible: that pair *is* the refusal. The
/// identity arrives as a built [`Who`] because each caller builds it out of two headers. One
/// identity in and not two computed out of it: the bar and the panel render the same facts,
/// and on a phone the panel is the only one of the two left standing, because the bar would
/// wrap to a second line to hold the name.
fn shell_named(
    v: &View,
    who: Option<Who>,
    logo: Option<&str>,
    title: &str,
    content: Markup,
) -> Markup {
    // Five tabs, Settings last (§13.34 §1): it is the page the bar's own row has room for, and
    // the row a phone reaches last through the ☰. The word is `K::ConfigTab` and not
    // `K::Config`, because the strip has to fit the bar and the page's heading can say what the
    // page is; the two words are pinned apart by `aria_current_names_the_page`.
    let tabs = [
        (Route::Dashboard, v.t(K::Dashboard)),
        (Route::Apps, v.t(K::Apps)),
        (Route::Users, v.t(K::Users)),
        (Route::Audit, v.t(K::Audit)),
        (Route::Config, v.t(K::ConfigTab)),
    ];
    let current = v.at.tab();
    // The brand says the deployment's name, in one line, in one shape on every surface: no tag
    // under it (§13.34 §10) and no link on it (§13.34 §11, the user's decision). The name is
    // `ui.brand_name` so the console's bar and `/account/` name the same deployment (§13.18),
    // and the tag is gone because what it said is said by the five tabs, the page's `h1` and the
    // `<title>`, and on a 1280px screen it was the word being cut. A link would lead to the page
    // the Dashboard tab beside it already names, so the slot is a `span` here as it is on
    // `/account/` and on the `403`.
    let name = v
        .look
        .brand
        .map(str::to_string)
        .unwrap_or_else(|| DEFAULT_ACCOUNT_BRAND.to_string());
    let brand = brand_block(&name, logo, "");
    // The strip, and the same four rows inside the panel, from one loop (§13.28 §4): moving one
    // element between the bar and a closed `details` cannot be done in CSS, so the links are
    // emitted twice and exactly one copy is displayed. `aria-current="page"` is the word a
    // reader hears for "you are here", because `.on` is a colour and colour alone is not a
    // distinction WCAG 1.3.1 accepts.
    // The strip's links, and the ☰'s copy of them, from one loop (§13.28 §4, §13.34 §1): moving
    // an element between the bar and a closed `details` cannot be done in CSS, so the links are
    // emitted twice and exactly one copy is displayed, which is also why the panel's rows are
    // `.pill`s, so the copy that appears is the same object as the copy it replaces.
    // `aria-current="page"` is the word a reader hears for "you are here", because `.on` is a
    // colour and colour alone is not a distinction WCAG 1.3.1 accepts.
    let tab_links = html! {
        @for (r, label) in &tabs {
            a class=@if *r == current { "pill on" } @else { "pill" }
              href=(v.href(r)) aria-current=[(*r == current).then_some("page")] { (label) }
        }
    };
    // The strip is named `tabs` so the breakpoint rule can hide it by name: with the ☰ in the
    // bar, `nav:not(.acct)` would hide that too (§13.34 §2). A page with no places to move
    // carries an empty strip, which is what keeps the bar's slots one shape on both surfaces.
    let tab_nav = html! {
        @if v.admin.is_some() { nav class="tabs" { (tab_links) } } @else { nav class="tabs" {} }
    };
    // The bar's navigation menu (§13.34 §2): the phone's tab strip, and the tabs' only home at
    // and below the breakpoint. It is a `nav` because it is navigation, which also gives its
    // rows the quiet tab look of `nav .pill`. `name="bar-menu"` puts it in one exclusive group
    // with the account menu, so opening one shuts the other with no script; the nested
    // `details.prefs` stays out of that group, or opening Preferences would close the menu it
    // sits in. The trigger is the glyph plus `K::NavMenu` in `span.vh`: a `summary` has no ARIA
    // role, so the name is hidden text and not `aria-label`, and `title` is the tooltip for the
    // pointer. A `403` names no console page, so it gets no ☰ at all: a page with no tabs has
    // no tab strip to move.
    let nav_word = v.t(K::NavMenu);
    let navn = v
        .admin
        .map(|_| {
            html! {
                nav class="navm" {
                    details class="settings navmenu" name="bar-menu" {
                        summary class="pill ico" title=(nav_word) {
                            svg class="i-menu" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                                path d="M4 6h16" {}
                                path d="M4 12h16" {}
                                path d="M4 18h16" {}
                            }
                            span class="vh" { (nav_word) }
                        }
                        div class="menu" {
                            div class="menu-tabs" { (tab_links) }
                        }
                    }
                }
            }
        })
    .unwrap_or_default();
    // The console's places, in the account panel: one row, the caller's own page (§13.34 §3).
    // The tabs left it for the ☰ and the settings page left it for the strip, so a row to
    // either here would be two answers to one question, one of them a row a phone cannot reach.
    // `v.admin` is the gate: a caller the allowlist refused is offered no console page at all,
    // and gets no `div.menu-places` to be offered in.
    let account_word = v.t(K::NotAdminToAccount);
    let account_href = format!("{}/", v.cfg.account_path);
    let places = v.admin.map(|_| {
        html! {
            // The row wears a glyph as every other row of the panel does (§13.34 §3, the
            // review of 2026-11-26): bare text among drawn marks starts left of its
            // neighbours and reads as the odd row out of a list of places. The person
            // outline says what the row is the page of, and it is **decoration** behind
            // `aria-hidden`: the visible word stays the row's name, in a language the reader
            // cannot see a glyph in and to a screen reader.
            a class="pill" href=(account_href) {
                svg class="i-person" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                    circle cx="12" cy="8" r="4" {}
                    path d="M4 20a8 8 0 0 1 16 0" {}
                }
                (account_word)
            }
        }
    });
    let prefs = prefs_form(
        v.lang,
        v.lang_pref,
        v.theme,
        &v.href(&v.at),
        &preserved_query(v.query),
    );
    // The account end of the bar, and it is a `nav` for the same reason the tabs are: it makes
    // these controls flex items of a flex row, exactly as the tabs are. One menu, opened by the
    // person's own name, replaces the identity span, the sliders trigger and the Sign out icon
    // of §13.17 and the Preferences menu of §13.20.
    //
    // Sign out is rendered even without an administrator, unlike the places: the `403` page is
    // exactly where this is most useful, because the way out of "you are signed in as somebody
    // who may not use this" is to end that session and start another. It is a plain link and not
    // a form: the gate's `/auth/logout` is a `GET` that clears the cookie and redirects, guarded
    // there against cross-site navigation.
    let acct = html! {
        nav class="acct" {
            (account_menu(
                v.lang,
                who.as_ref(),
                places,
                prefs,
                v.cfg.logout_url.as_deref(),
                // No delete row here (§13.28 §5): this surface edits **other people's** accounts,
                // and a person deletes their own on the page under the account prefix.
                None,
                // The ☰ is in this bar exactly where it is, so the two menus are one group
                // exactly where there are two menus to group (§13.34 §2).
                v.admin.is_some(),
            ))
        }
    };
    page_document(
        v.lang,
        v.theme.attr().or(v.look.theme.attr()),
        &format!("bb-auth-web · {title}"),
        v.look.stylesheet,
        html! {
            (top_bar(navn, brand, tab_nav, acct))
            main {
                // The one thing a redirect is allowed to say, from a closed set.
                @if let Some(msg) = v.msg {
                    div class="flash" { (msg.text(v.lang)) }
                }
                (content)
            }
            footer {
                // No reload hint: `bb-auth-reload.path` watches the file and reloads the
                // gate on every save, so telling an administrator to run
                // `systemctl reload bb-auth` would describe work nobody has to do.
                //
                // And no "signed in as": the bar above says it, where the session controls
                // are, and a fact kept in two places is a fact that starts disagreeing
                // with itself one edit at a time.
                // What these bytes were built from, which the version in the bar cannot
                // say: a `.deb` reads 1.99.1-1 for a clean release and for a working tree
                // somebody built by hand, and this is the one place a person can see
                // which of the two is answering.
                span class="muted" { code { (version_line("bb-auth-web")) } }
            }
        },
    )
}

/// What an unordered list looks like when it has nothing to show, which is **three** states
/// and not two.
///
/// "The file holds none of these" and "your filter matched none of them" are different
/// sentences and lead to different next actions, and every list on this GUI has to make that
/// distinction. It was made four times, in four page functions, each spelling out the same
/// three-armed `@if` around its own table: four places to change when the wording moves, and
/// four chances for one of them to say the wrong thing to somebody staring at an empty page.
///
/// `body` is rendered by the caller and passed in, because the four bodies have nothing in
/// common (a table, another table, a list, a run of panels) and pretending otherwise would be
/// the wrong abstraction: what is shared is the emptiness, not the content.
fn list_panel(v: &View, total: usize, shown: usize, body: Markup) -> Markup {
    html! {
        div class="panel" {
            @if total == 0 {
                span class="muted" { (v.t(K::None)) }
            } @else if shown == 0 {
                span class="muted" { (v.t(K::NoMatch)) }
            } @else {
                (body)
            }
        }
    }
}

/// [`list_panel`] for a list whose rows are panels of their own, so the empty states get a
/// panel and the rows are emitted bare.
fn list_rows(v: &View, total: usize, shown: usize, rows: Markup) -> Markup {
    html! {
        @if total == 0 || shown == 0 {
            (list_panel(v, total, shown, html! {}))
        } @else {
            (rows)
        }
    }
}

/// Every way into this deployment, and the app client each one runs through: one table, one
/// row per way, and a hidden field naming the set the page drew.
///
/// **A table, because a way in is three facts and only one of them is a choice.** What a
/// visitor reads on the button, the `identity_provider` Cognito matches byte for byte, and
/// the app client the sign-in runs through are three different things that a stacked list of
/// checkboxes ran together: `Microsoft` is the word on the button and `MicrosoftPersonal` is
/// the name Amazon knows, and an operator comparing this page with the Cognito console has to
/// see which is which.
///
/// **The email row is in it and has no checkbox**, which is the honest shape: the email path
/// is not something a deployment turns off, and its app client is the same kind of value as
/// every other row's. Leaving it out would have made the table look like the whole answer
/// while the most important app client lived somewhere else on the page.
///
/// The provider rows are [`SOCIAL_IDPS`] plus anything already in the file that is not in it,
/// in that order. The second half is what keeps this page honest about a file it did not
/// write: `bb-auth-adm` accepts any well-formed `identity_provider` name, a user pool may
/// federate a SAML or OIDC provider under a name nobody here anticipated, and a page that
/// rendered only the two it knows would quietly drop the third on the next save. Rendered, it
/// is named in the hidden field, so [`ConfigForm::read`] can keep it.
///
/// The hidden field is what makes that work without this function and `read` having to agree
/// twice: the form states what it offered, and the reader believes the form.
fn social_choices(v: &View, f: &ConfigForm, err: Option<&Refusal>) -> Markup {
    let about = |name: &str| err.is_some_and(|e| e.is(name));
    let offered = known_and_configured(&f.buttons);
    html! {
        div {
            span class="lbl" { (v.t(K::SignInWays)) }
            input type="hidden" name="idps" value=(offered.join(" "));
            table {
                thead { tr {
                    th { (v.t(K::ColShownAs)) }
                    // Cognito's own field name, untranslated, because it is what has to match
                    // on Amazon's side and a translated column heading would suggest it does
                    // not.
                    th class="mono" { "identity_provider" }
                    th { (v.t(K::ColAudience)) }
                } }
                tbody {
                    tr {
                        td data-label=(v.t(K::ColShownAs)) { (v.t(K::SignInEmail)) }
                        // An em-dash as data rather than prose: the email path is not
                        // federated, so this cell has nothing to name.
                        td class="mono muted" data-label="identity_provider" { "—" }
                        td data-label=(v.t(K::ColAudience)) {
                            input type="text" name="client_id" value=(f.client_id)
                                  placeholder="1h2j3k4l5m6n7o8p9q0r1s2t3u"
                                  class=(format!("f-aud{}", if about("client_id") { " invalid" } else { "" }))
                                  autocapitalize="off" spellcheck="false"
                                  aria-invalid=[about("client_id").then_some("true")]
                                  aria-describedby=[about("client_id").then_some(ERR_ID)];
                        }
                    }
                    @for idp in &offered {
                        @let field = aud_field(idp);
                        tr {
                            td data-label=(v.t(K::ColShownAs)) {
                                label class="radio" {
                                    input type="checkbox" name=(idp_field(idp)) value="on"
                                          checked[f.buttons.iter().any(|(e, _)| e.eq_ignore_ascii_case(idp))];
                                    span { (social_idp_label(idp)) }
                                }
                            }
                            td class="mono" data-label="identity_provider" { (idp) }
                            td data-label=(v.t(K::ColAudience)) {
                                input type="text" name=(field) value=(audience_of(&f.buttons, idp))
                                      placeholder="1h2j3k4l5m6n7o8p9q0r1s2t3u"
                                      class=(format!("f-aud{}", if about(&field) { " invalid" } else { "" }))
                                      autocapitalize="off" spellcheck="false"
                                      aria-invalid=[about(&field).then_some("true")]
                                      aria-describedby=[about(&field).then_some(ERR_ID)];
                            }
                        }
                    }
                }
            }
            span class="hint" { (v.t(K::SocialWaysHelp)) }
        }
    }
}

/// The app client the form holds for `idp`, or the empty string: what a row renders in its
/// last cell, whether or not the row is ticked.
fn audience_of(buttons: &[(String, String)], idp: &str) -> String {
    buttons
        .iter()
        .find(|(e, _)| e.eq_ignore_ascii_case(idp))
        .map(|(_, aud)| aud.clone())
        .unwrap_or_default()
}

/// The providers to draw a switch for: the ones this project knows, then any others the file
/// already enables, each exactly once.
fn known_and_configured(enabled: &[(String, String)]) -> Vec<String> {
    let mut out: Vec<String> = SOCIAL_IDPS.iter().map(|(idp, _)| idp.to_string()).collect();
    for (idp, _) in enabled {
        if !out.iter().any(|k| k.eq_ignore_ascii_case(idp)) {
            out.push(idp.clone());
        }
    }
    out
}

/// The form field name for one provider's checkbox. One function, because the renderer and
/// the reader must spell it the same way and there is no third caller to keep them honest.
fn idp_field(idp: &str) -> String {
    format!("idp-{idp}")
}

/// The form field name for one provider's app client, and a [`Refusal`]'s field name for it:
/// a bad app client is attributed to the row that carries it, which is the only way a table
/// of them can say which one it means.
fn aud_field(idp: &str) -> String {
    format!("aud-{idp}")
}

/// A rounded label — a `denied` badge, an expiry state, a scope's `access`.
fn tag(class: &str, text: &str) -> Markup {
    html! { span class=(format!("tag {class}")) { (text) } }
}

/// A top-level section page's `h1`: the descriptive, translated label the nav carries,
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
    url_list_marked(lang, urls, absent, |_| None)
}

/// [`url_list`] where a line may carry a warning tag after it: `mark` answers, per line, the
/// words to put there (or `None`). The words are text beside the line and not a colour, so a
/// reader that does not see colour hears them too (WCAG 1.4.1).
fn url_list_marked(
    lang: Lang,
    urls: Option<&Vec<String>>,
    absent: &str,
    mark: impl Fn(&str) -> Option<&'static str>,
) -> Markup {
    html! {
        @match urls {
            None => span class="muted" { (absent) },
            Some(l) if l.is_empty() => span class="bad" { "[] — " (t(lang, K::ReachesNothing)) },
            Some(l) => ul class="plain mono" {
                @for u in l {
                    li {
                        (u)
                        @if let Some(words) = mark(u) { " " (tag("warn", words)) }
                    }
                }
            },
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
    /// The offending input's `name=`, owned rather than `&'static str`: a table of app
    /// clients names its fields after the providers in the file, so which field a refusal is
    /// about is not always a literal this binary contains.
    field: Option<String>,
}

impl Refusal {
    /// Attribute this refusal to the field named `field` (its `name=` attribute, exactly).
    fn on(field: impl Into<String>, msg: impl Into<String>) -> Self {
        Refusal {
            msg: msg.into(),
            field: Some(field.into()),
        }
    }

    /// `true` when this refusal is attributed to the field named `name`: what
    /// [`text_field`] and [`urls_field`] ask to decide whether to render themselves invalid.
    fn is(&self, name: &str) -> bool {
        self.field.as_deref() == Some(name)
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

/// Fill `{0}`, `{1}`, … in `template` from `args`, in one pass.
///
/// The single pass is the point, for the reason `render_page` (the gate's page filler) gives for
/// its own substitution:
/// every argument is something an operator typed, and rescanning what a placeholder expanded to
/// would let a claim named `{1}` ask for a second round of substitution inside the sentence
/// about it. A `{` that opens nothing (no closing `}`, or a body that is not a number) is left
/// as the text it is, and an index past the end of `args` fills the empty string: a message with
/// a hole in it is a bug in this file, and the test over every code is what catches it, not a
/// panic on a page an operator is reading.
fn fill(template: &str, args: &[&str]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(at) = rest.find('{') {
        out.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        match rest.find('}') {
            Some(end) if rest[..end].bytes().all(|b| b.is_ascii_digit()) => {
                let n = rest[..end].parse::<usize>().unwrap_or(usize::MAX);
                out.push_str(args.get(n).copied().unwrap_or(""));
                rest = &rest[end + 1..];
            }
            _ => out.push('{'),
        }
    }
    out.push_str(rest);
    out
}

/// The field a [`SettingKey`] is about on the Settings page: its `name=` and its visible label.
///
/// One helper for the pair because a translated refusal has to name the label in its message and
/// mark the input by its `name=`, and the two are the same fact said twice. A key the library
/// names is the library's; which box on this page holds it is this page's, and this is the one
/// place that knows both.
fn setting_field(key: SettingKey) -> (&'static str, K) {
    match key {
        SettingKey::LoginUrl => ("login_url", K::GlobalLoginUrl),
        SettingKey::DeniedUrl => ("denied_url", K::GlobalDeniedUrl),
        SettingKey::LandingUrl => ("landing_url", K::GlobalLandingUrl),
        SettingKey::Issuer => ("issuer", K::Issuer),
        SettingKey::SocialCallbackUrl => ("callback", K::SocialCallback),
        SettingKey::StylesheetUrl => ("stylesheet", K::StylesheetUrl),
        SettingKey::LogoUrl => ("logo", K::LogoUrl),
        SettingKey::ClientIpHeader => ("client_ip_header", K::ClientIpHeader),
        SettingKey::RequestIdHeader => ("request_id_header", K::RequestIdHeader),
        SettingKey::AuditRotation => ("audit_rotation", K::AuditRotation),
        SettingKey::AuditRetention => ("audit_retention", K::AuditRetention),
    }
}

/// A settings-file refusal as this page says it: in the reader's language, naming the visible
/// label of the field it is about, and marking that field `invalid` (docs/ARCHITECTURE.md
/// §13.31).
///
/// The match is exhaustive, with **no `_` arm on purpose**. `SettingsRefusal` is the library's
/// answer about a file three programs read, so a refusal added there must not be able to arrive
/// here and be shown in English on an Italian page, which is what a wildcard would do silently.
/// Without one, a new variant is a compile error until somebody decides what the page says about
/// it and writes the `K` key, which is the same reflex that makes [`SettingsRefusal::code`] an
/// exhaustive match.
///
/// `{0}` of every key is `t(lang, label)`, which is what "names the visible field label" means
/// mechanically. A typed value is quoted only where the field cannot show which part of it is
/// wrong: an entry of a list (a claim, an attribute, a host) or a header name. The five codes
/// this form can never produce (§13.31 §5) are the one place the library's English sentence is
/// shown, because the operator who meets them is at a shell, where that is exactly what
/// `bb-auth-adm --check-settings` says.
fn settings_refusal(lang: Lang, r: &SettingsRefusal) -> Refusal {
    // The attributes the field accepts, as its own help spells them: the library's list, joined,
    // so a fourth attribute added there is named here by the same edit.
    let known = IDENTITY_ATTRS.join(", ");
    match r {
        SettingsRefusal::Version { .. }
        | SettingsRefusal::ButtonBareName { .. }
        | SettingsRefusal::ButtonNoIdp
        | SettingsRefusal::ButtonIdpCharset { .. }
        | SettingsRefusal::ButtonTwice { .. } => {
            Refusal::from(fill(t(lang, K::SetRefFileOnly), &[&r.to_string()]))
        }
        SettingsRefusal::ClaimCharset { claim } => Refusal::on(
            "claims",
            fill(
                t(lang, K::SetRefClaimCharset),
                &[t(lang, K::ProfileClaims), claim],
            ),
        ),
        SettingsRefusal::ClaimEmptyPart { claim } => Refusal::on(
            "claims",
            fill(
                t(lang, K::SetRefClaimEmptyPart),
                &[t(lang, K::ProfileClaims), claim],
            ),
        ),
        SettingsRefusal::ClaimConsumed { claim } => Refusal::on(
            "claims",
            fill(
                t(lang, K::SetRefClaimConsumed),
                &[t(lang, K::ProfileClaims), claim],
            ),
        ),
        SettingsRefusal::ClaimHeaderReserved { claim, header } => Refusal::on(
            "claims",
            fill(
                t(lang, K::SetRefClaimHeaderReserved),
                &[t(lang, K::ProfileClaims), claim, header],
            ),
        ),
        SettingsRefusal::ClaimsCollide {
            first,
            second,
            header,
        } => Refusal::on(
            "claims",
            fill(
                t(lang, K::SetRefClaimsCollide),
                &[t(lang, K::ProfileClaims), first, second, header],
            ),
        ),
        SettingsRefusal::AttrUnknown { attr } => Refusal::on(
            "identity",
            fill(
                t(lang, K::SetRefAttrUnknown),
                &[t(lang, K::IdentityAttrs), attr, &known],
            ),
        ),
        SettingsRefusal::AttrTwice { attr } => Refusal::on(
            "identity",
            fill(
                t(lang, K::SetRefAttrTwice),
                &[t(lang, K::IdentityAttrs), attr],
            ),
        ),
        SettingsRefusal::AttrNone => Refusal::on(
            "identity",
            fill(
                t(lang, K::SetRefAttrNone),
                &[t(lang, K::IdentityAttrs), &known],
            ),
        ),
        SettingsRefusal::TtlBelowFloor { .. } => Refusal::on(
            "ttl",
            fill(
                t(lang, K::SetRefTtlBelowFloor),
                &[t(lang, K::SessionTtl), &MIN_SESSION_TTL.to_string()],
            ),
        ),
        SettingsRefusal::TtlAboveCeiling { .. } => Refusal::on(
            "ttl",
            fill(
                t(lang, K::SetRefTtlAboveCeiling),
                &[t(lang, K::SessionTtl), &MAX_SESSION_TTL.to_string()],
            ),
        ),
        // The app client of the email flow and the one of a button are the same grammar in two
        // rows of the "Ways in" table, so the row's own heading is what the message names.
        SettingsRefusal::AppClientId { button: None, id } => Refusal::on(
            "client_id",
            fill(
                t(lang, K::SetRefAppClientId),
                &[t(lang, K::SignInEmail), id],
            ),
        ),
        SettingsRefusal::AppClientId {
            button: Some(idp),
            id,
        } => Refusal::on(
            aud_field(idp),
            fill(t(lang, K::SetRefAppClientId), &[social_idp_label(idp), id]),
        ),
        SettingsRefusal::Url { key, fault, .. } => {
            let (field, label) = setting_field(*key);
            let key = match fault {
                UrlFault::NotPrintable => K::SetRefUrlNotPrintable,
                UrlFault::NotHttps => K::SetRefUrlNotHttps,
                UrlFault::EmptyHost => K::SetRefUrlEmptyHost,
                UrlFault::Userinfo => K::SetRefUrlUserinfo,
                UrlFault::Backslash => K::SetRefUrlBackslash,
                UrlFault::UserinfoOrBackslash => K::SetRefUrlUserinfoOrBackslash,
                UrlFault::QueryOrFragment => K::SetRefUrlQueryOrFragment,
                UrlFault::Quote => K::SetRefUrlQuote,
                UrlFault::NotHttpsOrRooted => K::SetRefUrlNotHttpsOrRooted,
            };
            Refusal::on(field, fill(t(lang, key), &[t(lang, label)]))
        }
        SettingsRefusal::CallbackNotHttps => {
            let (field, label) = setting_field(SettingKey::SocialCallbackUrl);
            Refusal::on(
                field,
                fill(t(lang, K::SetRefCallbackNotHttps), &[t(lang, label)]),
            )
        }
        SettingsRefusal::CookieDomainNotBare { .. } => Refusal::on(
            "cookie_domain",
            fill(
                t(lang, K::SetRefCookieDomainNotBare),
                &[t(lang, K::CookieDomain)],
            ),
        ),
        SettingsRefusal::CookieDomainSingleLabel { .. } => Refusal::on(
            "cookie_domain",
            fill(
                t(lang, K::SetRefCookieDomainSingleLabel),
                &[t(lang, K::CookieDomain)],
            ),
        ),
        SettingsRefusal::HostControlByte { raw } => Refusal::on(
            "hosts",
            fill(
                t(lang, K::SetRefHostControlByte),
                &[t(lang, K::AuthorizedHosts), raw],
            ),
        ),
        SettingsRefusal::HostNotBare { raw } => Refusal::on(
            "hosts",
            fill(
                t(lang, K::SetRefHostNotBare),
                &[t(lang, K::AuthorizedHosts), raw],
            ),
        ),
        SettingsRefusal::HostAtOrDotDot { raw } => Refusal::on(
            "hosts",
            fill(
                t(lang, K::SetRefHostAtOrDotDot),
                &[t(lang, K::AuthorizedHosts), raw],
            ),
        ),
        // Attributed to the hosts field, which is where the operator goes to fix it, and naming
        // the cookie domain by its label, because the two are checked against each other and sit
        // one above the other for exactly that reason.
        SettingsRefusal::HostsOutsideCookieDomain {
            hosts,
            cookie_domain,
        } => Refusal::on(
            "hosts",
            fill(
                t(lang, K::SetRefHostsOutsideCookieDomain),
                &[
                    t(lang, K::AuthorizedHosts),
                    &hosts.join(", "),
                    t(lang, K::CookieDomain),
                    cookie_domain,
                ],
            ),
        ),
        SettingsRefusal::LandingOffHosts => Refusal::on(
            "landing_url",
            fill(
                t(lang, K::SetRefLandingOffHosts),
                &[t(lang, K::GlobalLandingUrl), t(lang, K::AuthorizedHosts)],
            ),
        ),
        SettingsRefusal::OauthDomainNotBare { .. } => Refusal::on(
            "domain",
            fill(
                t(lang, K::SetRefOauthDomainNotBare),
                &[t(lang, K::OauthDomain)],
            ),
        ),
        // The two the form can produce and already says something about, in its own words, in
        // both languages: reused rather than rewritten, because the row says the same thing
        // before the save as after it.
        SettingsRefusal::ButtonNoAudience { idp } => Refusal::on(
            aud_field(idp),
            fill(t(lang, K::AudienceNeeded), &[social_idp_label(idp)]),
        ),
        SettingsRefusal::SocialHalfConfigured { .. } => Refusal::on(
            "domain",
            fill(
                t(lang, K::SocialWiringNeeded),
                &[t(lang, K::OauthDomain), t(lang, K::SocialCallback)],
            ),
        ),
        SettingsRefusal::AuditHeader { key, name, fault } => {
            let (field, label) = setting_field(*key);
            let key = match fault {
                HeaderFault::NotAName => K::SetRefHeaderNotAName,
                HeaderFault::Credential => K::SetRefHeaderCredential,
            };
            Refusal::on(field, fill(t(lang, key), &[t(lang, label), name]))
        }
        // The shared header is marked on the request id, and the message names the other field
        // by its label, which is the one the operator has to go and change.
        SettingsRefusal::AuditHeadersSame { name } => Refusal::on(
            "request_id_header",
            fill(
                t(lang, K::SetRefHeadersSame),
                &[
                    t(lang, K::RequestIdHeader),
                    name,
                    t(lang, K::ClientIpHeader),
                ],
            ),
        ),
        SettingsRefusal::AuditLimitNotAmount { key, .. } => {
            let (field, label) = setting_field(*key);
            Refusal::on(
                field,
                fill(t(lang, K::SetRefLimitNotAmount), &[t(lang, label)]),
            )
        }
        SettingsRefusal::AuditLimitZero { key, .. } => {
            let (field, label) = setting_field(*key);
            Refusal::on(field, fill(t(lang, K::SetRefLimitZero), &[t(lang, label)]))
        }
        SettingsRefusal::AuditLimitTooMuch { key, unit, .. } => {
            let (field, label) = setting_field(*key);
            let max = unit.max_amount();
            Refusal::on(
                field,
                fill(
                    t(lang, K::SetRefLimitTooMuch),
                    &[
                        t(lang, label),
                        &max.to_string(),
                        unit_label(lang, *unit, max),
                    ],
                ),
            )
        }
        // The pair, not one of them: the refusal is that neither of the two is a size, and the
        // retention is the box an operator is more likely to fill in.
        SettingsRefusal::AuditUnbounded { .. } => Refusal::on(
            "audit_retention",
            fill(
                t(lang, K::SetRefAuditUnbounded),
                &[t(lang, K::AuditRotation), t(lang, K::AuditRetention)],
            ),
        ),
        SettingsRefusal::BrandControl { .. } => Refusal::on(
            "brand",
            fill(t(lang, K::SetRefBrandControl), &[t(lang, K::BrandName)]),
        ),
        SettingsRefusal::BrandTooLong { chars } => Refusal::on(
            "brand",
            fill(
                t(lang, K::SetRefBrandTooLong),
                &[
                    t(lang, K::BrandName),
                    &chars.to_string(),
                    &MAX_BRAND_NAME.to_string(),
                ],
            ),
        ),
        // The field is `ui_theme` and not the file's `theme`: it is the page's own name for the
        // box, and the one the form posts (§13.31 §2).
        SettingsRefusal::ThemeUnknown { .. } => Refusal::on(
            "ui_theme",
            fill(t(lang, K::DefaultThemeBad), &[t(lang, K::DefaultTheme)]),
        ),
    }
}

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
    form_shell_at(
        &v.href(&v.at),
        v.rev,
        &v.href(&v.at.parent()),
        v.t(K::Cancel),
        err,
        fields,
        submit,
        danger,
    )
}

/// [`form_shell`] with the three things it takes from a console [`View`] given as values: where
/// the form posts, the `rev` it carries, and where its cancel link goes. The self-service page
/// has no `View` and renders the same form through this, so the two surfaces cannot drift.
#[allow(clippy::too_many_arguments)]
fn form_shell_at(
    action: &str,
    rev: &str,
    cancel: &str,
    cancel_label: &str,
    err: Option<&Refusal>,
    fields: Markup,
    submit: &str,
    danger: bool,
) -> Markup {
    html! {
        form class="edit" method="post" action=(action) {
            // The library's words, verbatim: the sentence `bb-auth-adm` prints for the same
            // refusal, so an operator who has read one recognises the other. `id` is what
            // an attributed field's `aria-describedby` points at.
            @if let Some(e) = err { div class="err" id=(ERR_ID) { (e.msg) } }
            input type="hidden" name="rev" value=(rev);
            (fields)
            div class="actions" {
                button type="submit" class=@if danger { "danger" } @else { "" } { (submit) }
                a class="pill" href=(cancel) { (cancel_label) }
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
/// `--error`, and sets `aria-invalid` plus `aria-describedby` so the association with the
/// message above the form is real for assistive tech, not just a colour.
fn text_field(
    label: &str,
    name: &str,
    value: &str,
    placeholder: &str,
    hint: Option<&str>,
    invalid: bool,
) -> Markup {
    text_field_with(
        label,
        name,
        value,
        placeholder,
        hint.as_slice(),
        invalid,
        FieldOpts::default(),
    )
}

/// The options a text field can be asked for beyond the console's plain one. They live here
/// rather than as more arguments because the console's field takes none of them and the
/// self-service page's fields take five of the eight: a positional list would put a
/// `pattern` behind six blanks at every console call site, and a field that reads
/// `text_field(label, name, v, "", "", true, true, None, …)` says nothing about what it asks
/// the browser to enforce.
///
/// `prose` is the one that is not a constraint. A field that holds a person's **name** must
/// not carry `autocapitalize="off"` and `spellcheck="false"`: those two are right for a URL,
/// a header name and a key id, where a capital or a wavy underline is a typo, and wrong for
/// `Ada Lovelace`, where the browser's own capitalisation is what a person expects to see.
/// So it is one flag naming the kind of content, not two flags for two attributes.
#[derive(Default)]
struct FieldOpts<'a> {
    /// Put the cursor in this field when the page opens. One per page.
    autofocus: bool,
    /// Refuse an empty submission in the browser as well as on the server.
    required: bool,
    /// The window the browser lets a person type into.
    maxlength: Option<usize>,
    /// The grammar the server enforces, spelled for the browser too.
    pattern: Option<&'a str>,
    /// An autofill token (WCAG 1.3.5).
    autocomplete: Option<&'a str>,
    /// The keyboard to offer, for a field that takes a shape and not prose.
    inputmode: Option<&'a str>,
    /// The width class, for a field that is not sized by its wire name.
    class: Option<&'a str>,
    /// The value is prose: keep the browser's capitalisation and spell check.
    prose: bool,
}

/// The **one** text field: every label, input, hint and invalid mark on both surfaces is
/// built here (§13.26 "One text field"). The console's [`text_field`] is this with no
/// options, and the self-service page's fields are this with the browser's constraints on
/// them, so a field on one surface cannot gain a border, a hint line, an `aria` pair or a
/// width class that the other does not know about. That drift is invisible from inside
/// either page, and it is the same argument that put the palette and the components in the
/// library.
///
/// `placeholder` is an attribute only when there is something to suggest: an empty
/// `placeholder=""` is an empty bubble in a Chromium field, and it says nothing. `hints` is
/// one line per entry, in the order the caller gives them, under the control. `invalid` is
/// the pair [`text_field`] describes, and it points at [`ERR_ID`], the id every form's
/// message box carries on both surfaces.
fn text_field_with(
    label: &str,
    name: &str,
    value: &str,
    placeholder: &str,
    hints: &[&str],
    invalid: bool,
    opts: FieldOpts<'_>,
) -> Markup {
    let sized = format!("f-{name}");
    let class = format!(
        "{}{}",
        opts.class.unwrap_or(&sized),
        if invalid { " invalid" } else { "" }
    );
    html! {
        label {
            span class="lbl" { (label) }
            input type="text" name=(name) value=(value)
                  placeholder=[(!placeholder.is_empty()).then_some(placeholder)]
                  class=(class)
                  autocapitalize=[(!opts.prose).then_some("off")]
                  spellcheck=[(!opts.prose).then_some("false")]
                  autofocus[opts.autofocus]
                  required[opts.required]
                  maxlength=[opts.maxlength]
                  pattern=[opts.pattern]
                  autocomplete=[opts.autocomplete]
                  inputmode=[opts.inputmode]
                  aria-invalid=[invalid.then_some("true")]
                  aria-describedby=[invalid.then_some(ERR_ID)];
            @for h in hints {
                span class="hint" { (h) }
            }
        }
    }
}

/// The key's duration, chosen from five: one `select` whose values are the strings the file
/// stores, and the custom box beside it (§13.15, as §13.16 amended its markup).
///
/// One component and not two, because the console's mint, the console's edit and the
/// self-service page all mint the same field, and a component rendered two ways is two
/// components that drift one edit at a time. One `select` and not five radios because on
/// `/account/` it lives in one cell of a table row, where five stacked rows would be the
/// tallest thing in it.
///
/// The box is a **text** field with `inputmode="numeric"`, not a `number` field, because the
/// console's custom value takes the whole grammar (`40`, `40d`, `12h`): a `number` field
/// cannot type `12h`, and the keyboard hint is what a numeric box was wanted for. It shares
/// the row with the choice it belongs to (`form.edit .limit`, the furniture `admin.css`
/// already has) and has no visible label of its own, so its name is written down as an
/// `aria-label` (WCAG 3.3.2).
///
/// `choice` is one of the five values, `days` what the box shows; [`duration_of_stored`] and
/// [`duration_of_posted`] are what put a file's bytes, or a person's submission, into that
/// shape, and they always name one of the five, so exactly one option is picked.
///
/// The box's two words are the surfaces' own, because the two boxes take different grammars.
/// `placeholder` is what the empty box says: `/account/` passes "days", since its box takes a
/// number and nothing else. The console passes nothing, because its box takes the whole
/// grammar (`12h` is a legal value there) and a placeholder of "days" would be a lie about it.
/// `hint` is the line under the row, and is `None` where the placeholder already says the
/// same thing: a bare word alone on the line below reads as a caption of the whole row. The
/// box keeps its own name as an `aria-label` either way, since a placeholder is not a label
/// (WCAG 3.3.2) and the wrapping `label` labels only its first labelable descendant, the
/// select.
fn duration_choice(
    lang: Lang,
    label: &str,
    choice: &str,
    days: &str,
    placeholder: Option<&str>,
    hint: Option<&str>,
    invalid: bool,
) -> Markup {
    html! {
        label {
            span class="lbl" { (label) }
            span class="limit" {
                select name="duration" aria-label=(label)
                      class=[invalid.then_some("invalid")]
                      aria-invalid=[invalid.then_some("true")]
                      aria-describedby=[invalid.then_some(ERR_ID)] {
                    // The longest bounded choice is the one an add form opens on, and `never`
                    // is never preselected: the widest credential has to be asked for.
                    option value="365d" selected[choice == "365d"] { (t(lang, K::DurOneYear)) }
                    option value="182d" selected[choice == "182d"] { (t(lang, K::DurSixMonths)) }
                    option value="91d" selected[choice == "91d"] { (t(lang, K::DurThreeMonths)) }
                    option value="custom" selected[choice == "custom"] { (t(lang, K::DurCustom)) }
                    option value="never" selected[choice == "never"] { (t(lang, K::DurNever)) }
                }
                input type="text" inputmode="numeric" name="days" size="6" value=(days)
                      class="f-days"
                      placeholder=[placeholder]
                      aria-label=(t(lang, K::DurDaysLabel));
            }
            @if let Some(hint) = hint {
                span class="hint" { (hint) }
            }
        }
    }
}

/// A URL-pattern list: one per line, `@refs` written literally. The same shape for an
/// application's `base`, a scope's `urls`, its members and its exclusions, a key's `scopes`
/// and a group's members — one grammar, as in the file.
///
/// `invalid` is the same attribution [`text_field`] takes: see its doc comment.
fn urls_field(label: &str, name: &str, value: &str, hint: Markup, invalid: bool) -> Markup {
    html! {
        label {
            // An empty label is a field whose heading is already above it (the key form's
            // scope radios) — not a blank line to leave in the page.
            @if !label.is_empty() { span class="lbl" { (label) } }
            // `f-{name}` as every other field carries: it is what lets a refusal's `name=` be
            // found in the page, and the layout's width rules are written on `input.f-…`, so a
            // textarea wearing its own name costs nothing.
            textarea name=(name) rows="6" spellcheck="false" autocapitalize="off"
                      class=(format!("f-{name}{}", if invalid { " invalid" } else { "" }))
                      aria-invalid=[invalid.then_some("true")]
                      aria-describedby=[invalid.then_some(ERR_ID)] { (value) }
            span class="hint" { (hint) }
        }
    }
}

/// A unit's name in the reader's language, singular for one of it and plural otherwise. The
/// two of space are the same word in every language, and are left as the file spells them.
///
/// It takes the language and not the [`View`], because a refusal translated outside the page's
/// own render has a language and no view (§13.31 §4).
fn unit_label(lang: Lang, unit: AuditUnit, amount: u64) -> &'static str {
    let one = amount == 1;
    match unit {
        AuditUnit::Weeks => t(lang, if one { K::UnitWeek } else { K::UnitWeeks }),
        AuditUnit::Months => t(lang, if one { K::UnitMonth } else { K::UnitMonths }),
        AuditUnit::Years => t(lang, if one { K::UnitYear } else { K::UnitYears }),
        AuditUnit::MiB => "MiB",
        AuditUnit::GiB => "GiB",
    }
}

/// An audit limit in the reader's words: `4 MiB`, `6 mesi`, `1 year`.
///
/// The language and not the [`View`], for the reason [`unit_label`] gives: the delete
/// confirmation page (§13.30 §2) has a language and no view, and a second spelling of
/// "6 months" there is one unit word the Settings page can drift from (§13.29 W10 7b).
fn limit_text(lang: Lang, l: &AuditLimit) -> String {
    format!("{} {}", l.amount, unit_label(lang, l.unit, l.amount))
}

/// An amount-and-unit field: a number and a list box of [`AuditUnit`]s, posted as `name` and
/// `name_unit`, which the form puts back together into the one string the file stores.
///
/// Two controls and not one text box because the unit is a choice among five, and a box that
/// took "4 MB" would be a box that accepted a number the file then refuses. `none` is offered
/// only where empty means something (a retention), and never where it would be an error.
#[allow(clippy::too_many_arguments)]
fn limit_field(
    v: &View,
    label: &str,
    name: &str,
    amount: &str,
    unit: &str,
    none: bool,
    hint: &str,
    invalid: bool,
) -> Markup {
    html! {
        label {
            span class="lbl" { (label) }
            span class="limit" {
                input type="number" min="1" step="1" name=(name) value=(amount)
                      class=(format!("f-{name}{}", if invalid { " invalid" } else { "" }))
                      aria-invalid=[invalid.then_some("true")]
                      aria-describedby=[invalid.then_some(ERR_ID)];
                select name=(format!("{name}_unit")) aria-label=(label) {
                    @if none {
                        option value="" selected[unit.is_empty()] { (v.t(K::LimitNone)) }
                    }
                    @for u in AuditUnit::ALL {
                        option value=(u.code()) selected[u.code() == unit] {
                            (unit_label(v.lang, u, 2))
                        }
                    }
                }
            }
            span class="hint" { (hint) }
        }
    }
}

/// The lines of a pattern list, as a textarea's value.
fn urls_text(urls: Option<&Vec<String>>) -> String {
    urls.map(|l| l.join("\n")).unwrap_or_default()
}

/// A pill: the estate's small control, as a link. Declared once because **nothing at a call
/// site is allowed to say how a pill looks**: the class list is what the stylesheets style, so
/// a call site that spelled one out would repaint that page and leave every other standing,
/// which is drift no file in front of an editor can show. A link and not a button, because it
/// navigates and changes nothing; a pill and not body prose, because it sits in the same row as
/// `edit` and `remove` and is the same kind of thing.
///
/// These three helpers are that one home, and they take an `href` and a label as values rather
/// than a [`View`] for the same reason [`confirm_card`] takes a heading and a `rev`: the pages
/// under `/account` have no `View` at all (no route, no `rev`, no bar), so they reach the
/// console's pill through them, and the console's [`act`], [`act_rm`] and [`back`] are wrappers
/// over them. A second pill spelled for the self-service page is the drift this ends.
fn pill_link(href: &str, label: &str) -> Markup {
    html! { a class="pill" href=(href) { (label) } }
}

/// A pill marked as the destructive member of its `.pills` group (CSS `.pill.rm`): the action
/// that removes a row, not one that just changes it. See [`pill_link`] for why the markup is
/// here and not at a call site.
fn pill_link_rm(href: &str, label: &str) -> Markup {
    html! { a class="pill rm" href=(href) { (label) } }
}

/// The way back out of a page, in the reader's language: an arrow and [`K::Back`] on the pill
/// every other small control wears. See [`pill_link`] for why the markup is here.
fn back_link(lang: Lang, href: &str) -> Markup {
    html! { a class="pill" href=(href) { "\u{2190} " (t(lang, K::Back)) } }
}

/// A small `add` / `edit` / `remove` pill beside the thing it acts on.
fn act(v: &View, at: &Route, label: &str) -> Markup {
    pill_link(&v.href(at), label)
}

/// The way back out of a detail page, taking its language and href from the view.
fn back(v: &View, to: &Route) -> Markup {
    back_link(v.lang, &v.href(to))
}

/// Same as [`act`], marked destructive. `rotate` replaces a credential rather than deleting
/// anything, so it stays plain [`act`]; only an actual `Rm` route earns this.
fn act_rm(v: &View, at: &Route, label: &str) -> Markup {
    pill_link_rm(&v.href(at), label)
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
    page_confirm_at(
        &v.href(&v.at),
        v.rev,
        &v.href(&v.at.parent()),
        v.t(K::Cancel),
        heading,
        what,
        why,
        html! {},
        button,
        err,
        true,
    )
}

/// [`page_confirm`] on values instead of a [`View`]: the console's heading above the
/// [`confirm_card`] the self-service page renders on its own. `fields` is what the form carries
/// besides the `rev`: nothing on the console, whose route names the key, and the key's id on
/// `/account/`, whose two paths do not.
#[allow(clippy::too_many_arguments)]
fn page_confirm_at(
    action: &str,
    rev: &str,
    cancel: &str,
    cancel_label: &str,
    heading: Markup,
    what: Markup,
    why: &str,
    fields: Markup,
    button: &str,
    err: Option<&Refusal>,
    danger: bool,
) -> Markup {
    html! {
        h1 { (heading) }
        (confirm_card(
            action, rev, cancel, cancel_label, what, why, fields, button, err, danger,
        ))
    }
}

/// The card a confirmation is made of: what is about to go, what that means, and the `POST`
/// that does it. Split out of [`page_confirm_at`] for the self-service page (§13.17), whose
/// shell already wears the action word as the page's one `h1`, so the card arrives with no
/// heading of its own and the confirmation reads the way the console's does: the bar says where
/// you are, the `h1` says what is about to happen.
#[allow(clippy::too_many_arguments)]
fn confirm_card(
    action: &str,
    rev: &str,
    cancel: &str,
    cancel_label: &str,
    what: Markup,
    why: &str,
    fields: Markup,
    button: &str,
    err: Option<&Refusal>,
    danger: bool,
) -> Markup {
    html! {
        p class="lede" { (why) }
        div class="panel bad" {
            (what)
            (form_shell_at(action, rev, cancel, cancel_label, err, fields, button, danger))
        }
    }
}

/// "no such user / api key / application / scope / group" — a `GET` for a name the file does
/// not have.
fn page_missing(v: &View, what: &str, name: &str, back_to: &Route) -> Markup {
    html! {
        h1 { (what) }
        p class="lede" { code { (name) } }
        p { (back(v, back_to)) }
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
/// Shadowing is a heuristic, and it needs an operator to explain itself to; it earns its
/// place here because the alternative (a scope that answers for nothing, with nobody
/// noticing) is worse.
///
/// Each warning reads kind, identifier, sentence (§13.35): one list mixes scopes, people and
/// groups, and `@delete-test` on its own does not say which of the three it is. The identifier
/// is a link wherever the object has a page of its own (a scope to its application, because a
/// shadowed scope is explained only by the scopes listed above it there; a person to their
/// page; a user group to its own page, §13.36 §2, where "nothing references me" is answered by
/// the scopes panel first under the head).
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
    for a in doc.applications.iter() {
        for (si, s) in a.scopes.iter().enumerate() {
            if shadowing_scope(&a.scopes[..si], &s.urls).is_some() {
                warnings.push(html! {
                    (v.t(K::KindScope)) " "
                    a href=(v.href(&Route::App(a.name.trim().to_string()))) {
                        code { (a.name.trim()) "/" (s.name.trim()) }
                    }
                    " " (v.t(K::WarnShadowed))
                });
            }
        }
    }
    for a in &access.apps {
        for s in &a.scopes {
            if s.access == bb_auth_core::AccessKind::Restricted && s.members.is_empty() {
                warnings.push(html! {
                    (v.t(K::KindScope)) " "
                    a href=(v.href(&Route::App(a.name.trim().to_string()))) {
                        code { (a.name) "/" (s.name) }
                    }
                    " " (v.t(K::WarnNoMembers))
                });
            }
        }
    }
    for u in &doc.users {
        let uuid = u.uuid.trim().to_ascii_lowercase();
        if access.scopes_for(&uuid).is_empty() {
            warnings.push(html! {
                (v.t(K::KindUser)) " "
                a href=(v.href(&Route::User(uuid.clone()))) { code { (user_label(u)) } }
                " " (v.t(K::WarnNoScope))
            });
        }
        if access.denied_users.contains(&uuid) {
            warnings.push(html! {
                (v.t(K::KindUser)) " "
                a href=(v.href(&Route::User(uuid))) { code { (user_label(u)) } }
                " " (v.t(K::WarnEnrolledAndDenied))
            });
        }
    }
    for name in doc.user_groups.keys() {
        if user_group_refs(doc, name).is_empty() {
            warnings.push(html! {
                (v.t(K::KindGroup)) " "
                a href=(v.href(&Route::Group(name.clone()))) { code { "@" (name) } }
                " " (v.t(K::ReferencedByNothing))
            });
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

/// The users tab's row of sub-tabs: People, Groups, Denied (§13.36 §1).
///
/// Three pages under one tab, because all three answer the same question from different
/// sides, and the tab's five-slot bar has no room for three more tabs. The row is a
/// navigation landmark of its own beside the bar's tabs and the account end, so it is named
/// (`K::UsersSections`): the practice asks that more than one landmark of a kind be named.
/// Each link carries the section's short word and its **whole file** count, never the
/// filtered one, so the row does not move under the operator's hands while they type. The
/// Groups and Denied links carry the `id`s the old `/users#user_groups` and `/users#denied`
/// bookmarks named, so a note an operator wrote years ago scrolls to the link that means it.
fn users_subnav(v: &View, doc: &AccessFile) -> Markup {
    /// One pill: the current one marked the bar's way, in the markup and not only to a
    /// reader, because `.on` is a colour, and colour alone is not a distinction WCAG 1.3.1
    /// accepts. The row lights the page a route was reached *from* (`parent()`), which is the
    /// bar's own rule one level down: a group's form lights Groups, a veto's form lights
    /// Denied, and the roster's pages, including a person's, light People.
    fn pill(v: &View, at: &Route, label: &str, id: Option<&'static str>, n: usize) -> Markup {
        let on = v.at.parent() == *at;
        html! {
            a class=(if on { "pill on" } else { "pill" }) href=(v.href(at)) id=[id]
              aria-current=[on.then_some("page")]
              { (label) " (" (n) ")" }
        }
    }
    html! {
        nav class="sub" aria-label=(v.t(K::UsersSections)) {
            (pill(v, &Route::Users, v.t(K::People), None, doc.users.len()))
            (pill(
                v,
                &Route::Groups,
                v.t(K::GroupsTab),
                Some("user_groups"),
                doc.user_groups.len(),
            ))
            (pill(
                v,
                &Route::Denied,
                v.t(K::Denied),
                Some("denied"),
                doc.denied.len(),
            ))
        }
    }
}

/// `/users`: the roster, the users tab's People sub-page (§13.36 §1).
///
/// It used to be one stacked page of three sections, and a long file opened on the list the
/// operator did not come for. The shared `h1` is the tab's word, so the page says which tab
/// it is under, and the `h2` is the sub-tab's, so the link a person followed and the heading
/// they landed on are the same word. The filter and the pager are namespaced (`u`), as on
/// the other two pages, because all three lists live in one query string.
///
/// A row carries the **groups naming it**, as links to each group's page (§13.36 §5): the
/// file writes membership on the side of the group, and a roster that shows only emails asks
/// "which of these is an administrator?" with no way to answer. Beside the box, the
/// `?ug=` chip answers "who is in this group?" from the other side, on the group's page.
fn page_users(v: &View, doc: &AccessFile, access: &Access) -> Markup {
    let mut lu = Listing::read("u", v.query);
    // The group filter: `ug` names one `user_groups` entry **exactly** (a group name is a
    // `[A-Za-z0-9_-]` word, so a substring test on a name would invent matches), and it is
    // ANDed with the box rather than replacing it. A name the file has not got narrows to
    // nobody, which is what the panel's `no matches for this filter` says; the page is not an
    // error, because the chip is a link and links rot.
    let group = query_param(v.query, "ug").unwrap_or_default();
    let group = group.trim().to_string();
    let members = doc
        .user_groups
        .get(&group)
        .map(|ms| ms.iter().map(|m| m.trim().to_ascii_lowercase()).collect())
        .or_else(|| (!group.is_empty()).then(Vec::new));
    lu.filtered = !group.is_empty();
    let rows: Vec<&UserSpec> = doc
        .users
        .iter()
        .filter(|u| l_keeps_user(&lu, u))
        .filter(|u| {
            members
                .as_ref()
                .is_none_or(|ms| ms.iter().any(|m| *m == u.uuid.trim().to_ascii_lowercase()))
        })
        .collect();
    let (start, end, _, _) = lu.window(rows.len());
    // The membership map, built **once per request** (§13.36 §3): walking the groups per row
    // would read the whole section once per row of the page. The names come out in the file's
    // order, which for a `BTreeMap` is alphabetical.
    let mut by_uuid: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (name, ms) in &doc.user_groups {
        for m in ms {
            by_uuid
                .entry(m.trim().to_ascii_lowercase())
                .or_default()
                .push(name.clone());
        }
    }
    // The chip: what the list is narrowed to, and the one control that clears it. It rides in
    // the same form as the box, so Apply keeps the group with the text, and the group is
    // `owned` so the form carries it once.
    let chip = if group.is_empty() {
        html! {}
    } else {
        html! {
            input type="hidden" name="ug" value=(group);
            a class="pill" href=(clear_group_href(v, &lu)) title=(v.t(K::GroupFilterClear)) {
                (fill(v.t(K::GroupFilter), &[format!("@{group}").as_str()])) " ×"
            }
        }
    };
    html! {
        h1 { (v.t(K::Users)) }
        (users_subnav(v, doc))

        h2 { (section_heading(v.t(K::People), "users")) }
        p class="lede sub" { (v.t(K::UsersIntro)) }
        p class="primary" { (act(v, &Route::UserAdd, &format!("+ {}", v.t(K::Add)))) }
        (list_controls_with(
            v,
            &lu,
            rows.len(),
            doc.users.len(),
            &["ug"],
            chip,
            K::FilterPeople,
        ))
        (list_panel(v, doc.users.len(), rows.len(), html! {
                table {
                    thead { tr {
                        th { (v.t(K::Emails)) }
                        th { (v.t(K::ColGroups)) }
                        th { "api_keys" }
                        th {}
                    } }
                    tbody {
                        @for u in &rows[start..end] {
                            @let uuid = u.uuid.trim().to_ascii_lowercase();
                            @let groups = by_uuid.get(&uuid).cloned().unwrap_or_default();
                            tr {
                                td data-label=(v.t(K::Emails)) {
                                    a href=(v.href(&Route::User(uuid.clone()))) { (user_label(u)) }
                                    @if access.denied_users.contains(&uuid) {
                                        " " (tag("bad", "denied"))
                                    }
                                }
                                td data-label=(v.t(K::ColGroups)) {
                                    @if groups.is_empty() {
                                        span class="muted" { (v.t(K::None)) }
                                    } @else {
                                        @for (at, g) in groups.iter().enumerate() {
                                            @if at > 0 { ", " }
                                            a href=(v.href(&Route::Group(g.clone()))) {
                                                code { "@" (g) }
                                            }
                                        }
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
        }))

    }
}

/// The roster's own URL with the **group** filter dropped and everything else kept, the
/// chip's href (§13.36 §5). [`listing_href`] cannot answer this one: it clears the box and
/// the page of its own list, and a chip that clears the text the operator typed would be a
/// control that destroys a filter nobody asked it to destroy.
fn clear_group_href(v: &View, l: &Listing) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, val) in form_urlencoded::parse(v.query.as_bytes()) {
        if k != "ug" && k != l.p_name() {
            ser.append_pair(&k, &val);
        }
    }
    let q = ser.finish();
    if q.is_empty() {
        v.href(&v.at)
    } else {
        format!("{}?{q}", v.href(&v.at))
    }
}

/// A roster row's searchable text: every identifier, the uuid, and each key's id — all of
/// what identifies the person, not just the label the table happens to show.
fn l_keeps_user(l: &Listing, u: &UserSpec) -> bool {
    let mut hay = u.uuid.trim().to_string();
    for e in &u.emails {
        hay.push(' ');
        hay.push_str(e.trim());
    }
    for k in &u.api_keys {
        hay.push(' ');
        hay.push_str(k.id.trim());
    }
    l.keeps(&hay)
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
            p class="lede" { (back(v, &Route::Users)) }
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

            (user_check(v, access, u, &uuid))

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

/// `/groups`: the `user_groups` list, the users tab's Groups sub-page (§13.36 §1).
///
/// **A table, one row per group** (§13.36 §3). The list used to be one panel per group, which
/// put a name, a count and a reference list into prose a row at a time and said nothing about
/// how big each group is; a column answers "how big is each?" at a glance, and the names are
/// links to the page each one is about (§13.36 §2). The filter keeps the old reach (`@name`
/// and each member's label), because "which group is bob in?" is still the question this list
/// is opened to answer.
fn page_groups(v: &View, doc: &AccessFile) -> Markup {
    let l = Listing::read("g", v.query);
    let rows: Vec<(&String, &Vec<String>)> = doc
        .user_groups
        .iter()
        .filter(|(name, members)| {
            let people: Vec<String> = members.iter().map(|m| label_of(doc, m)).collect();
            l.keeps(&format!("@{name} {}", people.join(" ")))
        })
        .collect();
    let (start, end, _, _) = l.window(rows.len());
    html! {
        h1 { (v.t(K::Users)) }
        (users_subnav(v, doc))

        // §13.36 §1 item 3: the section's heading spells the name out (`User groups`), which is
        // why the sub-tab above is `K::GroupsTab` and not this: the row must fit a phone.
        h2 { (section_heading(v.t(K::Groups), "user_groups")) }
        p class="lede sub" { (v.t(K::GroupsIntro)) }
        p class="primary" { (act(v, &Route::GroupAdd, &format!("+ {}", v.t(K::Add)))) }
        (list_controls(v, &l, rows.len(), doc.user_groups.len()))
        (list_panel(v, doc.user_groups.len(), rows.len(), html! {
            table {
                thead { tr {
                    // `name` is the file's word, as the applications table heads its first
                    // column with it: the group's name is a key of the document, not a label.
                    th { "name" }
                    th { (v.t(K::Members)) }
                    th { (v.t(K::Scopes)) }
                    th {}
                } }
                tbody {
                    @for (name, members) in &rows[start..end] {
                        @let refs = user_group_refs(doc, name);
                        tr {
                            td data-label="name" {
                                a href=(v.href(&Route::Group((*name).clone()))) {
                                    code { "@" (name) }
                                }
                            }
                            td data-label=(v.t(K::Members)) { (members.len()) }
                            td data-label=(v.t(K::Scopes)) {
                                @if refs.is_empty() {
                                    span class="muted" { (v.t(K::ReferencedByNothing)) }
                                } @else {
                                    @for r in refs.iter() {
                                        (scope_ref_link(v, r)) " "
                                    }
                                }
                            }
                            td class="pills" {
                                // The inner `span` is not decoration: `td.pills` is a table
                                // cell with no gap, and two pills straight in it touch.
                                span class="pills" {
                                    (act(v, &Route::GroupEdit((*name).clone()), v.t(K::Edit)))
                                    (act_rm(v, &Route::GroupRm((*name).clone()), v.t(K::Remove)))
                                }
                            }
                        }
                    }
                }
            }
        }))
    }
}

/// One entry of [`user_group_refs`] as a page shows it: the scope as a link to the application
/// that owns it (a scope has no page of its own, and an application lists its scopes), and a
/// scope that keeps the group **out** carrying the file's own word beside the link.
///
/// The words come from [`EXCLUDED_REF`], which is what `user_group_refs` appends, so this page
/// and the removal's refusal cannot disagree about which references they are listing; and they
/// are words and not a colour, so a reader who does not see colour hears them (WCAG 1.4.1).
fn scope_ref_link(v: &View, entry: &str) -> Markup {
    let marker = format!(" ({EXCLUDED_REF})");
    let (at, excluded) = match entry.strip_suffix(marker.as_str()) {
        Some(rest) => (rest, true),
        None => (entry, false),
    };
    let app = at.split('/').next().unwrap_or_default().trim().to_string();
    html! {
        a href=(v.href(&Route::App(app))) { code { (at.trim()) } }
        @if excluded {
            " " (tag("bad", EXCLUDED_REF))
        }
    }
}

/// `/groups/{name}`: one `user_groups` entry (§13.36 §2).
///
/// Scopes come **before** members: the scopes are why the group matters, and this is the page
/// the dashboard's "referenced by nothing" warning links to, so its answer is the first thing
/// under the head. The two writes are the **existing** forms, reached from here; only where
/// they return changed (§1).
fn page_group(v: &View, doc: &AccessFile, name: &str) -> (u16, Markup) {
    let Some(members) = doc.user_groups.get(name.trim()) else {
        return (
            404,
            page_missing(v, v.t(K::NoSuchGroup), name.trim(), &Route::Groups),
        );
    };
    let refs = user_group_refs(doc, name.trim());
    // The members behind a `Listing` of their own prefix, so a group of a thousand people is a
    // page and not a scroll, and the scopes panel above has no control row of its own.
    let lm = Listing::read("m", v.query);
    let shown: Vec<&String> = members
        .iter()
        .filter(|m| lm.keeps(&format!("{} {}", m.trim(), label_of(doc, m))))
        .collect();
    let (start, end, _, _) = lm.window(shown.len());
    (
        200,
        html! {
            h1 {
                code { "@" (name.trim()) }
                " "
                span class="muted mono" { "user_groups" }
            }
            // No Users sub-tab row (§13.36 §2, as the screenshot review of plan step 22 read
            // it): this is the person page's shape, and that page has none. The row's job is to
            // say which of the three lists is showing, and on a page about one object the `h1`
            // has already said it, while the row pushes the page's answer, the scopes that name
            // the group, down the screen. The bar above still lights the Users tab, and the
            // back link below is the one thing here naming the list this page is a row of.
            p class="lede" { (back(v, &Route::Groups)) }
            p class="pills" {
                (act(v, &Route::GroupEdit(name.trim().to_string()), v.t(K::Edit)))
                (act_rm(v, &Route::GroupRm(name.trim().to_string()), v.t(K::Remove)))
            }

            h2 { (section_heading(v.t(K::Scopes), "scopes")) }
            div class="panel" {
                @if refs.is_empty() {
                    span class="muted" { (v.t(K::ReferencedByNothing)) }
                } @else {
                    ul class="plain" {
                        @for r in refs.iter() {
                            li { (scope_ref_link(v, r)) }
                        }
                    }
                }
            }

            // The section's word, in title case like the `Scopes` heading above it, and not the
            // Groups list's lowercase column word `K::Members` this heading used to borrow: a
            // heading that reads as a table label is the screenshot review's finding (§13.36 §2
            // item 3). The list's column keeps the lowercase word, because a column label is
            // not a heading.
            h2 { (v.t(K::MembersHeading)) }
            p class="primary" {
                a class="pill" href=(format!("{}?ug={}", v.href(&Route::Users), name.trim())) {
                    (v.t(K::GroupInRoster))
                }
            }
            // The box says what *this* list searches, a member's label and uuid, and not the
            // roster's wider reach (§13.36 §4): a key id is not in this list to find.
            (list_controls_named(v, &lm, shown.len(), members.len(), K::FilterMembers))
            (list_panel(v, members.len(), shown.len(), html! {
                ul class="plain" {
                    @for m in &shown[start..end] {
                        @let uuid = m.trim().to_ascii_lowercase();
                        li {
                            @match user_pos(doc, &uuid) {
                                Some(i) => {
                                    a href=(v.href(&Route::User(uuid.clone()))) {
                                        (user_label(&doc.users[i]))
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
            }))
        },
    )
}

/// `/apps` — the applications, with their base, their scope count, and which credential
/// classes get in anywhere inside them ([`app_credentials`]).
fn page_apps(v: &View, doc: &AccessFile) -> Markup {
    let l = Listing::read("a", v.query);
    // Filtered on everything the row shows, so what an operator reads is what they can
    // search: the name, the area, and the credentials column.
    let rows: Vec<&AppSpec> = doc
        .applications
        .iter()
        .filter(|a| {
            let creds = match app_credentials(a) {
                None => "anonymous".to_string(),
                Some(list) => list.join(" "),
            };
            l.keeps(&format!("{} {} {creds}", a.name.trim(), a.base.join(" ")))
        })
        .collect();
    let (start, end, _, _) = l.window(rows.len());
    html! {
        h1 { (section_heading(v.t(K::Apps), "applications")) }
        p class="lede" { (v.t(K::AppsIntro)) }
        p class="primary" { (act(v, &Route::AppAdd, &format!("+ {}", v.t(K::Add)))) }
        (list_controls(v, &l, rows.len(), doc.applications.len()))
        (list_panel(v, doc.applications.len(), rows.len(), html! {
                table {
                    thead { tr {
                        th { "name" }
                        th { (v.t(K::Base)) }
                        th { (v.t(K::Scopes)) }
                        th { (v.t(K::Credentials)) }
                        th {}
                    } }
                    tbody {
                        @for a in &rows[start..end] {
                            tr {
                                td data-label="name" {
                                    a href=(v.href(&Route::App(a.name.trim().to_string()))) {
                                        code { (a.name.trim()) }
                                    }
                                }
                                td data-label=(v.t(K::Base)) { (url_list(v.lang, Some(&a.base), "")) }
                                td data-label=(v.t(K::Scopes)) { (a.scopes.len()) }
                                td data-label=(v.t(K::Credentials)) {
                                    @match app_credentials(a) {
                                        None => (tag("warn", v.t(K::CredNoneNeeded))),
                                        Some(list) if list.is_empty() => {
                                            span class="muted" { (v.t(K::None)) }
                                        }
                                        Some(list) => code { (list.join(", ")) }
                                    }
                                }
                                td class="pills" {
                                    (act_rm(v, &Route::AppRm(a.name.trim().to_string()), v.t(K::Remove)))
                                }
                            }
                        }
                    }
                }
        }))
    }
}

/// `/apps/{app}` — one application: its base, its login page, its scopes **in file
/// order**, the number carrying the meaning first-match-wins gives it, and the access check
/// over the area they divide up.
///
/// The check is last because it is the conclusion of the list above it: it names the scope
/// that answered, which is one of the numbered ones, so what the page shows and what the gate
/// decides can be read against each other without leaving the page. That is also why this
/// page needs the compiled [`Access`] and not only the document.
fn page_app(v: &View, doc: &AccessFile, access: &Access, name: &str) -> (u16, Markup) {
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
            p class="lede" { (back(v, &Route::Apps)) }
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
                    ol class="scopes" {
                        @for (i, s) in a.scopes.iter().enumerate() {
                            li { (scope_block(v, doc, &app_name, s, i, last)) }
                        }
                    }
                }
            }

            (app_check(v, access, a))
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
            }
            _ => {}
        }
        // Credentials, and the exclusions, on every kind rather than only where the file
        // carries a field. An absent `credentials` means BOTH, which is the one default in
        // this format an operator can misread as "none", and `anonymous`/`authenticated`
        // have an answer too even though they have no field: this line says what actually
        // gets in, which is what the question is.
        div class="muted" {
            (v.t(K::Credentials)) ": "
            @match scope_credentials(s) {
                None => span class="mono" { (v.t(K::CredNoneNeeded)) },
                Some(list) => code { (list.join(", ")) }
            }
        }
        @if access != "anonymous" {
            @let excluded = scope_excluded_display(doc, s);
            div class="muted" {
                (v.t(K::Excluded)) ": "
                @if excluded.is_empty() {
                    span { (v.t(K::ExcludedNone)) }
                } @else {
                    @for (i, e) in excluded.iter().enumerate() {
                        @if i > 0 { ", " }
                        code class="bad" { (e) }
                    }
                }
            }
        }
    }
}

/// Which credential classes actually get into this scope, as the file's own words.
///
/// `None` is not "nothing": it is an `anonymous` scope, which needs no credential at all.
/// `authenticated` is `login` alone, because Cognito vouches for no static key of ours, and
/// `restricted` with no `credentials` field is **both** — the default this exists to spell
/// out, since an absent field is exactly where a reader guesses wrong.
fn scope_credentials(s: &ScopeSpec) -> Option<Vec<&'static str>> {
    match s.access.trim() {
        "anonymous" => None,
        "authenticated" => Some(vec!["login"]),
        _ => match &s.credentials {
            None => Some(vec!["login", "api_key"]),
            Some(list) => {
                let mut out = Vec::new();
                if list.iter().any(|c| c.trim() == "login") {
                    out.push("login");
                }
                if list.iter().any(|c| c.trim() == "api_key") {
                    out.push("api_key");
                }
                Some(out)
            }
        },
    }
}

/// Every credential class that gets in **anywhere** in this application: the union of
/// [`scope_credentials`] over its scopes, for the one column [`page_apps`] has room for.
///
/// A `None` from any scope (an `anonymous` one) makes the whole application answerable
/// without a credential, and that outranks the rest of the union: it is the thing an
/// operator scanning the list most needs to see.
fn app_credentials(a: &AppSpec) -> Option<Vec<&'static str>> {
    let (mut login, mut api_key) = (false, false);
    for s in &a.scopes {
        let list = scope_credentials(s)?;
        login |= list.contains(&"login");
        api_key |= list.contains(&"api_key");
    }
    // Built in a fixed order rather than sorted, so the column reads the same way the scope
    // below it does and the two can be compared at a glance.
    let mut out = Vec::new();
    if login {
        out.push("login");
    }
    if api_key {
        out.push("api_key");
    }
    Some(out)
}

/// A scope's `users` (resolved to a label where the roster still can) and `groups` (`@name`,
/// shown exactly as the file spells it), for display only. See [`parse_members`] for the
/// inverse, on submit.
fn scope_members_display(doc: &AccessFile, s: &ScopeSpec) -> Vec<String> {
    let mut out: Vec<String> = s.users.iter().flatten().map(|u| label_of(doc, u)).collect();
    out.extend(s.groups.iter().flatten().map(|g| g.trim().to_string()));
    out
}

/// A scope's `excluded`, for display and for the form's textarea.
///
/// One flat list, because the field is one flat list: a `@group` stays as written, a uuid
/// the roster still resolves becomes the person, and anything else — a stranger's email —
/// stays exactly as the file spells it. [`parse_exclusions`] is the inverse, and the
/// round-trip through the form is what that pairing has to keep exact.
fn scope_excluded_display(doc: &AccessFile, s: &ScopeSpec) -> Vec<String> {
    s.excluded
        .iter()
        .flatten()
        .map(|e| {
            let e = e.trim();
            if e.starts_with('@') {
                e.to_string()
            } else {
                label_of(doc, e)
            }
        })
        .collect()
}

/// `/denied`: the veto, the users tab's Denied sub-page (§13.36 §1), and the page the
/// add/remove PRG redirects land on, which is why it has always had its own URL.
///
/// It shares the `h1` and the sub-tab row with the other two, so the page says which tab it
/// is under; the heading it used to carry as an `h1` is now its `h2`, where the sub-tab's
/// word and the heading it lands on are the same word.
fn page_denied(v: &View, doc: &AccessFile) -> Markup {
    html! {
        h1 { (v.t(K::Users)) }
        (users_subnav(v, doc))

        h2 { (section_heading(v.t(K::Denied), "denied")) }
        p class="lede sub" { (v.t(K::DeniedIntro)) }
        p class="primary" { (act(v, &Route::DenyAdd, &format!("+ {}", v.t(K::Add)))) }
        (denied_list(v, doc))
    }
}

/// The `denied` list: the empty state, or the list itself, one row per vetoed entry; a uuid
/// names the user it vetoes, a bare email names a stranger.
fn denied_list(v: &View, doc: &AccessFile) -> Markup {
    let l = Listing::read("d", v.query);
    // Filtered on what the row *shows*, which for an enrolled user is their label rather
    // than the uuid the file stores: searching for the email you can see must work.
    let rows: Vec<&String> = doc
        .denied
        .iter()
        .filter(|d| {
            let raw = d.trim().to_ascii_lowercase();
            l.keeps(&format!("{raw} {}", label_of(doc, &raw)))
        })
        .collect();
    let (start, end, _, _) = l.window(rows.len());
    html! {
        (list_controls(v, &l, rows.len(), doc.denied.len()))
        (list_panel(v, doc.denied.len(), rows.len(), html! {
                ul class="plain" {
                    @for d in &rows[start..end] {
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
        }))
    }
}

// ---------------------------------------------------------------------------
// The audit page
// ---------------------------------------------------------------------------
//
// The one tab that reads neither file and writes nothing. Everything else here is a view of
// what an operator wrote; this is a view of what the gate *did* with it, which is the only
// way to find out that a rule written months ago is refusing somebody today.

/// The periods the page offers, as `(query value, seconds back from now)`. "Everything" is the
/// absence of a period and so is not one of them.
const AUDIT_PERIODS: [(&str, u64); 4] = [
    ("1h", 3_600),
    ("24h", 86_400),
    ("7d", 7 * 86_400),
    ("30d", 30 * 86_400),
];

/// The period a page with no `aw=` shows.
///
/// A day and not everything, because the read stops at the far edge of the period: the default
/// view parses the last day of a file that may hold a year, which is what keeps this page cheap
/// on the hardware it runs on. It is also the answer to the question somebody opening this tab
/// usually has, which is what happened just now.
const AUDIT_DEFAULT_PERIOD: &str = "24h";

/// How many events one read may return before it says there are more.
///
/// Far more than a page shows, because the filters run *after* the read: a text filter over a
/// month has to see the month. Twenty pages of fifty rows either way.
const AUDIT_READ_CAP: usize = 5_000;

/// The credentials the filter offers, in the order they appear, as `(tag, label)`. The tags are
/// [`AuditCredential::tag`]'s, so a row and a filter can never disagree about what a key is.
fn audit_credentials(v: &View) -> [(&'static str, &'static str); 5] {
    [
        ("social", v.t(K::CredSocial)),
        ("local", v.t(K::CredLocal)),
        ("key", v.t(K::CredKey)),
        ("session", v.t(K::CredSession)),
        ("anonymous", v.t(K::CredAnonymous)),
    ]
}

/// One event's credential, in words: the kind, and what names this one instance of it.
fn audit_cred_markup(v: &View, cred: &AuditCredential) -> Markup {
    html! {
        @match cred {
            AuditCredential::Social { provider } => {
                (v.t(K::CredSocial)) " " span class="muted mono" { (provider) }
            }
            AuditCredential::Key { id } if !id.is_empty() => {
                (v.t(K::CredKey)) " " span class="muted mono" { (id) }
            }
            other => (v.t(match other {
                AuditCredential::Local => K::CredLocal,
                AuditCredential::Session => K::CredSession,
                AuditCredential::Key { .. } => K::CredKey,
                _ => K::CredAnonymous,
            })),
        }
    }
}

/// The sentence a refusal code stands for, in the reader's language.
///
/// The nine that a [`Decision`] can produce are the **same phrases the access check prints**,
/// deliberately: a page that explained `not_member` one way here and another way there would
/// be two explanations of one rule. A code this binary has never heard of is shown as itself
/// with a note, because an audit written by a newer gate is still worth reading.
fn audit_reason(v: &View, code: &str) -> Markup {
    let key = match code {
        "vetoed" => Some(K::WhyVetoed),
        "excluded" => Some(K::WhyExcluded),
        "no_application" => Some(K::WhyNoApplication),
        "no_scope" => Some(K::WhyNoScope),
        "unauthenticated" => Some(K::WhyUnauthenticated),
        "credential_refused" => Some(K::WhyCredentialRefused),
        "not_enrolled" => Some(K::WhyNotEnrolled),
        "not_member" => Some(K::WhyNotMember),
        "key_out_of_scope" => Some(K::WhyKeyOutOfScope),
        "token_invalid" => Some(K::WhyTokenInvalid),
        "cross_site" => Some(K::WhyCrossSite),
        "key_unknown" => Some(K::WhyKeyUnknown),
        "key_expired" => Some(K::WhyKeyExpired),
        "key_owner_denied" => Some(K::WhyKeyOwnerDenied),
        "un_enrolled" => Some(K::WhyUnEnrolledGrant),
        _ => None,
    };
    html! {
        @match key {
            Some(k) => (v.t(k)),
            None => {
                code { (code) } " " span class="muted" { (v.t(K::WhyUnknownReason)) }
            }
        }
    }
}

/// A zone the audit can be read in: what the page calls it, and the rules that turn a Unix time
/// into that zone's wall clock.
struct Zone {
    /// What the column heading and the list box say: `UTC`, a name out of the host's
    /// database, or an offset.
    label: String,
    rules: tz::TimeZone,
    /// Whether each row says which of the zone's clocks it was read on (`CET`, `CEST`). A zone
    /// that changes its clock needs it, or the hour either side of a change reads the same
    /// twice; a fixed offset does not, and the heading already says which one it is.
    per_row: bool,
}

/// UTC as a [`Zone`]: what the file stores, and what the page falls back to when the zone it
/// was asked for cannot be had.
fn utc_zone() -> Zone {
    Zone {
        label: "UTC".to_string(),
        rules: tz::TimeZone::utc(),
        per_row: false,
    }
}

/// Why the zone a preference names could not be had, which the page says above the table
/// rather than quietly showing UTC under a heading somebody would take at its word.
#[derive(Debug, PartialEq, Eq)]
enum ZoneMissing {
    /// The host's own zone is not readable, which is what a workstation without one looks like.
    Local,
    /// No zone of this name in the host's database.
    Custom(String),
}

/// The zone a preference names, read out of the host's database on every request.
///
/// On every request, like everything else this program shows: a zone file is two or three
/// kilobytes, a host whose clock is moved by `timedatectl` is read correctly on the next page
/// rather than after a restart, and there is no cache to be the stale half of anything.
fn resolve_zone(pref: &TzPref) -> Result<Zone, ZoneMissing> {
    let read = |path: &str| {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| tz::TimeZone::from_tz_data(&bytes).ok())
    };
    match pref {
        TzPref::Utc => Ok(utc_zone()),
        TzPref::Local => Ok(Zone {
            label: local_zone_name().unwrap_or_else(|| "localtime".to_string()),
            rules: read(LOCALTIME_FILE).ok_or(ZoneMissing::Local)?,
            per_row: true,
        }),
        TzPref::Custom(zone) => match parse_offset(zone) {
            Some(secs) => Ok(Zone {
                label: format_offset(secs),
                rules: tz::TimeZone::fixed(secs).map_err(|_| ZoneMissing::Custom(zone.clone()))?,
                per_row: false,
            }),
            // `custom_zone` held the name to a charset with no `.` in it before it could
            // become a preference, which is what makes this join unable to leave the directory.
            None => Ok(Zone {
                label: zone.clone(),
                rules: read(&format!("{ZONEINFO_DIR}/{zone}"))
                    .ok_or_else(|| ZoneMissing::Custom(zone.clone()))?,
                per_row: true,
            }),
        },
    }
}

/// The host's own zone by name, for the list box and the heading: where [`LOCALTIME_FILE`]
/// points, which is how systemd records it. `None` for a copy rather than a link, and the
/// name is held to [`custom_zone`]'s rule because a link can point anywhere.
fn local_zone_name() -> Option<String> {
    let target = std::fs::read_link(LOCALTIME_FILE).ok()?;
    let (_, name) = target.to_str()?.rsplit_once("zoneinfo/")?;
    custom_zone(name).filter(|n| parse_offset(n).is_none())
}

/// One Unix time on this zone's wall clock, and the name of the clock when the zone has more
/// than one. `format_datetime` stays the one formatter: this only moves the seconds first.
fn zoned(ts: u64, zone: &Zone) -> (String, Option<String>) {
    match zone.rules.find_local_time_type(ts as i64) {
        Ok(t) => (
            format_datetime(ts.saturating_add_signed(i64::from(t.ut_offset()))),
            zone.per_row
                .then(|| t.time_zone_designation().to_string())
                .filter(|d| !d.is_empty()),
        ),
        // A time outside what the rules describe, which a zone file with a rule for the
        // future never has. The one honest rendering left is the one that is stored.
        Err(_) => (format_datetime(ts), Some("UTC".to_string())),
    }
}

/// Where this row's request came from: the address, the user agent, and nginx's id for it.
///
/// The address first and never broken, because it is what a reader compares down the column
/// and half an address is no address. The user agent under it, in a hint's small type and at
/// most two lines, because it is the client's description of itself and must not read as
/// evidence. The id last, on one line cut short by the stylesheet: it exists to be copied into
/// a search of nginx's log, and a cut on screen is not a cut in the text, so a double click
/// still copies all of it (and the title shows it). Its label is the file's own `rid`,
/// untranslated like every other word the file is made of.
fn audit_origin(e: &AuditEvent) -> Markup {
    html! {
        @if let Some(ip) = &e.ip {
            div class="mono ip" { (ip) }
        }
        @if let Some(ua) = &e.ua {
            div class="hint ua" title=(ua) { (ua) }
        }
        @if let Some(rid) = &e.rid {
            div class="hint mono clip" title=(rid) { "rid " (rid) }
        }
        @if e.ip.is_none() && e.ua.is_none() && e.rid.is_none() {
            span class="muted" { "—" }
        }
    }
}

/// `/audit` — what the gate has answered, newest first, filtered and paged entirely in the
/// query string like every other list here.
///
/// It reads the file **on every request**, which is what makes Refresh a plain link to this
/// same URL rather than a control that has to do anything: there is no cache to bust, and a
/// page that reloaded itself would be a page that needs a script.
fn page_audit(v: &View, doc: &AccessFile) -> Markup {
    if v.cfg.audit_path.is_empty() {
        return html! {
            h1 { (v.t(K::Audit)) }
            p class="lede" { (v.t(K::AuditIntro)) }
            div class="panel warn" {
                p { strong { (v.t(K::AuditOff)) } }
                p class="muted" { (v.t(K::AuditOffHelp)) }
            }
        };
    }
    let period = query_param(v.query, "aw").unwrap_or_else(|| AUDIT_DEFAULT_PERIOD.to_string());
    let since = AUDIT_PERIODS
        .iter()
        .find(|(name, _)| *name == period)
        .map(|(_, secs)| now().saturating_sub(*secs));
    // A retention in time is a floor on every period, "everything" included: the gate prunes
    // hourly, and in the hour between, a page that showed what the settings say is gone would
    // be showing somebody's address the operator decided nobody keeps.
    let since = match (since, v.audit.keep_since(now())) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let read = read_audit(
        std::path::Path::new(&v.cfg.audit_path),
        since,
        AUDIT_READ_CAP,
    );
    // A file that will not open is worth saying plainly and in the operator's own terms: the
    // one that actually happens is a mode the gate wrote and this service cannot read, and
    // "permission denied" plus the path is the whole diagnosis.
    let read = match read {
        Ok(p) => p,
        Err(e) => {
            return html! {
                h1 { (v.t(K::Audit)) }
                div class="panel bad" {
                    p { (v.t(K::FileErrorTitle)) }
                    p class="mono" { (v.cfg.audit_path) ": " (e) }
                    p class="muted" { (v.t(K::FileErrorHint)) }
                }
            }
        }
    };

    let cred = query_param(v.query, "ac").unwrap_or_default();
    let outcome = query_param(v.query, "ao").unwrap_or_default();
    let l = Listing::read("a", v.query);
    let rows: Vec<&AuditEvent> = read
        .events
        .iter()
        .filter(|e| cred.is_empty() || e.cred.tag() == cred)
        .filter(|e| match outcome.as_str() {
            "ok" => e.kind.granted(),
            "no" => !e.kind.granted(),
            _ => true,
        })
        // The row's own fields, plus what the roster currently calls the uuid on it: a key
        // event names a row and not an address, and searching for the address you can see has
        // to find it.
        .filter(|e| {
            let who = e
                .uuid
                .as_deref()
                .map(|u| label_of(doc, u))
                .unwrap_or_default();
            l.keeps(&format!("{} {who}", e.haystack()))
        })
        .collect();
    let (start, end, _, _) = l.window(rows.len());
    // The clock the page is read in, and why it is not the one asked for when that could not
    // be had: a heading saying `Europe/Rome` over UTC times would be a page lying about the one
    // thing a reader of an audit compares across rows.
    let (zone, missing) = match resolve_zone(&v.tz) {
        Ok(z) => (z, None),
        Err(m) => (utc_zone(), Some(m)),
    };
    let local = local_zone_name();
    let custom = match &v.tz {
        TzPref::Custom(z) => z.as_str(),
        _ => "",
    };
    let selects = html! {
        select name="aw" aria-label=(v.t(K::AuditWindow)) {
            @for (name, _) in AUDIT_PERIODS {
                option value=(name) selected[name == period] { (name) }
            }
            option value="all" selected[!AUDIT_PERIODS.iter().any(|(n, _)| *n == period)] {
                (v.t(K::AuditAll))
            }
        }
        select name="ac" aria-label=(v.t(K::AuditCredential)) {
            option value="" selected[cred.is_empty()] { (v.t(K::AuditCredential)) ": " (v.t(K::AuditAny)) }
            @for (tag, label) in audit_credentials(v) {
                option value=(tag) selected[tag == cred] { (label) }
            }
        }
        select name="ao" aria-label=(v.t(K::AuditOutcome)) {
            option value="" selected[outcome.is_empty()] { (v.t(K::AuditOutcome)) ": " (v.t(K::AuditAny)) }
            option value="ok" selected[outcome == "ok"] { (v.t(K::AuditAllowed)) }
            option value="no" selected[outcome == "no"] { (v.t(K::AuditRefused)) }
        }
        // The clock, and for a zone of the operator's own the box to type it in. In the same
        // form as the filters, so one Apply sets it with them, and remembered as a cookie
        // rather than carried in the URL, because it is a preference and not a filter: the
        // same zone is wanted tomorrow, on a link that says nothing about it. The box is shown
        // only while `custom` is chosen, which the stylesheet decides, since no script may.
        span class="tzpick" {
            select name=(TZ_COOKIE) aria-label=(v.t(K::AuditZone)) {
                option value="utc" selected[v.tz.choice() == "utc"] { "UTC" }
                option value="local" selected[v.tz.choice() == "local"] {
                    (v.t(K::TzLocal))
                    @if let Some(name) = &local { " (" (name) ")" }
                }
                option value="custom" selected[v.tz.choice() == "custom"] { (v.t(K::TzCustom)) }
            }
            input type="text" class="tzc" name=(TZ_CUSTOM_PARAM) value=(custom)
                  placeholder=(v.t(K::TzCustomHint)) aria-label=(v.t(K::TzCustom));
        }
    };
    html! {
        h1 { (v.t(K::Audit)) }
        p class="lede" { (v.t(K::AuditIntro)) }
        p class="primary" {
            // Refresh is this same URL: every filter is in it, so re-reading the file with the
            // view intact is a link and nothing more.
            a class="pill" href=(listing_href(v, &l, &audit_kept(&l, &period, &cred, &outcome))) {
                "↻ " (v.t(K::AuditRefresh))
            }
        }
        (list_controls_with(
            v,
            &l,
            rows.len(),
            read.events.len(),
            &["aw", "ac", "ao", TZ_COOKIE, TZ_CUSTOM_PARAM],
            selects,
            K::Filter,
        ))
        @match &missing {
            Some(ZoneMissing::Local) => div class="msg warn" { (v.t(K::TzLocalMissing)) },
            Some(ZoneMissing::Custom(name)) => div class="msg warn" {
                code { (name) } " " (v.t(K::TzUnknown))
            },
            None => {}
        }
        @if read.more {
            p class="muted" { (v.t(K::AuditTruncated)) }
        }
        @if read.damaged > 0 {
            p class="muted" { (read.damaged) " " (v.t(K::AuditDamaged)) }
        }
        (list_rows(v, read.events.len(), rows.len(), html! {
            div class="panel" {
                table {
                    // Six columns, and the credential is under the event rather than in a
                    // seventh: a table this wide is already what squeezes the sentence in the
                    // last column, and "signed in, through Google" is one fact read together.
                    thead { tr {
                        th { (v.t(K::ColWhen)) " (" (zone.label) ")" }
                        th { (v.t(K::ColEvent)) }
                        th { (v.t(K::ColWho)) }
                        th class="client" { (v.t(K::ColClient)) }
                        th { (v.t(K::ColWhere)) }
                        th class="why" { (v.t(K::ColWhy)) }
                    } }
                    tbody {
                        @for e in &rows[start..end] {
                            // The outcome is the tag in the event column and nowhere else: a
                            // whole row in the error colour is a page of red on the deployment
                            // that has most to read here, which is the one being probed.
                            @let (wall, clock) = zoned(e.ts, &zone);
                            tr {
                                td class="mono when" data-label=(v.t(K::ColWhen)) {
                                    (wall)
                                    @if let Some(c) = clock { " " span class="muted" { (c) } }
                                }
                                td data-label=(v.t(K::ColEvent)) {
                                    (audit_kind(v, e.kind))
                                    // Nothing under a refusal that came before any credential
                                    // was read: the reason column already says why, and "None"
                                    // under the tag would read as a second answer to it.
                                    @if !matches!(e.cred, AuditCredential::Anonymous) {
                                        div class="hint" { (audit_cred_markup(v, &e.cred)) }
                                    }
                                }
                                td data-label=(v.t(K::ColWho)) { (audit_who(v, doc, e)) }
                                td class="client" data-label=(v.t(K::ColClient)) {
                                    (audit_origin(e))
                                }
                                td class="where" data-label=(v.t(K::ColWhere)) {
                                    (audit_where(e))
                                }
                                td class="why" data-label=(v.t(K::ColWhy)) {
                                    @match &e.reason {
                                        Some(r) => (audit_reason(v, r)),
                                        None => span class="muted" { "—" },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }))
        p class="muted" { (v.t(K::AuditDeduped)) }
        // How far back this page can reach at all, which is a question a reader of an audit
        // always has and the page is the only one who can answer without a shell.
        p class="muted" {
            (v.t(K::AuditRotation)) ": " (limit_text(v.lang, &v.audit.rotation))
            " · " (v.t(K::AuditRetention)) ": "
            (match v.audit.retention {
                Some(r) => limit_text(v.lang, &r),
                None => v.t(K::LimitNone).to_string(),
            })
            " · " (v.t(K::AuditOnDisk)) ": " (size_text(v.audit.max_bytes()))
        }
    }
}

/// A number of bytes the way the settings write them: whole GiB or MiB where it is one, a
/// tenth of a MiB where half a retention is not.
fn size_text(bytes: u64) -> String {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    if bytes >= GIB && bytes.is_multiple_of(GIB) {
        format!("{} GiB", bytes / GIB)
    } else if bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    }
}

/// This page's own parameters, for a link that must keep the whole view: [`listing_href`]
/// replaces only the listing's two, and these three are not its business.
fn audit_kept(l: &Listing, period: &str, cred: &str, outcome: &str) -> Vec<(String, String)> {
    let mut set = Vec::new();
    if !l.q.is_empty() {
        set.push((l.q_name(), l.q.clone()));
    }
    for (name, val) in [("aw", period), ("ac", cred), ("ao", outcome)] {
        if !val.is_empty() {
            set.push((name.to_string(), val.to_string()));
        }
    }
    set
}

/// What kind of thing this row is, in one phrase.
fn audit_kind(v: &View, kind: AuditKind) -> Markup {
    let (key, class) = match kind {
        AuditKind::LoginGranted => (K::KindLoginGranted, "tag ok"),
        AuditKind::LoginRefused => (K::KindLoginRefused, "tag bad"),
        AuditKind::LoginEnded => (K::KindLoginEnded, "tag"),
        AuditKind::AccessGranted => (K::KindAccessGranted, "tag ok"),
        AuditKind::AccessRefused => (K::KindAccessRefused, "tag bad"),
    };
    html! { span class=(class) { (v.t(key)) } }
}

/// Who this row is about: a link to their page when the roster still has them, the identifier
/// as recorded when it does not.
///
/// The two are not interchangeable and the difference is the point: an audit is history, and
/// resolving a uuid through the file as it is **now** is how a reader finds out that the person
/// refused last week is the person whose row was edited yesterday. A row that has been deleted
/// since keeps its uuid and simply stops being a link.
fn audit_who(v: &View, doc: &AccessFile, e: &AuditEvent) -> Markup {
    html! {
        @match (&e.uuid, &e.subject) {
            (Some(uuid), _) if user_pos(doc, uuid).is_some() => {
                a href=(v.href(&Route::User(uuid.clone()))) { (label_of(doc, uuid)) }
            }
            (_, Some(s)) => code { (s) }
            (Some(uuid), None) => code class="muted" { (uuid) }
            (None, None) => span class="muted" { "—" },
        }
        // The Cognito account under the name, where a token was validated: the line that tells
        // this month's owner of an address from last month's, once somebody has deleted an
        // account and registered the address again. Labelled with the claim's own name, and on
        // one line, since the first group of a UUID is what an eye compares.
        @if let Some(sub) = &e.sub {
            div class="hint mono clip" title=(sub) { "sub " (sub) }
        }
    }
}

/// Where this row happened: the scope that answered, and the URL that was being reached for.
fn audit_where(e: &AuditEvent) -> Markup {
    html! {
        @if let (Some(app), Some(scope)) = (&e.app, &e.scope) {
            code { (app) @if !scope.is_empty() { "/" (scope) } }
        }
        @if let Some(url) = &e.url {
            div class="muted mono" { (url) }
        }
        @if e.app.is_none() && e.url.is_none() {
            span class="muted" { "—" }
        }
    }
}

/// The access check's one text field, in whichever of the two forms is asking.
///
/// `fld` is base.css's field label, the same class the sign-in page puts over its own inputs:
/// the type comes from there and admin.css only says these sit side by side. Without it this
/// form would grow a second answer to what a label looks like, which is the whole thing
/// base.css exists to prevent.
///
/// Neither form carries a hidden `lang`, though both replace the whole query when they submit:
/// by the time a page renders, the language is a cookie (an explicit `?lang=` is redirected
/// into one first), so it survives a submit on its own, and re-sending it would turn a
/// [`LangPref::Auto`] preference into a fixed choice on the operator's first check.
fn check_field(name: &str, value: &str, placeholder: &str) -> Markup {
    html! {
        label class="fld" {
            (name)
            input type="text" name=(name) value=(value) placeholder=(placeholder)
                  autocapitalize="off" spellcheck="false";
        }
    }
}

/// The `ok`/`bad` panel one answer lands in, shared by the two pages that ask.
///
/// The wrapper is shared and not just [`verdict`], because the left bar's colour is part of
/// the answer: the one thing an operator scanning a page cannot afford is a verdict that
/// looks the same whether it granted or refused.
/// The id the access check's heading carries, and the fragment both check forms submit to.
///
/// A `GET` form lands on a fresh document at the top of the page, which on an application or
/// a person is several screens above the question that was just asked: the operator types a
/// URL, presses the button, and the answer arrives out of sight. The fragment on the form's
/// `action` survives submission (the browser replaces the query and keeps the fragment), so
/// the answer arrives where the question was asked, with no script anywhere near it.
const CHECK_ANCHOR: &str = "check";

fn verdict_panel(v: &View, access: &Access, email: &str, url_in: &str) -> Markup {
    let (granted, markup) = verdict(v, access, email, &request_url(url_in));
    html! {
        div class=@if granted { "panel ok" } @else { "panel bad" } { (markup) }
    }
}

/// The access check as a section of a person's page: one field, because this page is the
/// other half of the question.
///
/// It sits under `scopes` and above `api_keys` on purpose. `scopes` says what the file
/// *lists*; this says what [`decide`] *answers*, which is not the same thing the moment an
/// `excluded`, a `denied` or an `authenticated` scope is involved, and the two belong side by
/// side. Above `api_keys` because it does not speak for a key: that verdict is
/// [`bb_auth_core::decide_api_key`]'s, and `bb-auth-adm can --key ID` is where it stays
/// (naming a key means picking one, which is a second field and a listing, and it is one
/// invocation away on the host that has the file).
///
/// The subject is [`user_label`]'s identifier, which is also this page's `h1`, and any of the
/// row's emails would give the same answer: an identifier that resolves is folded onto its
/// uuid at load, so a veto or an exclusion written against one address is written against the
/// row. A row with no email at all can be asked nothing, and says so rather than quietly
/// testing a stranger.
fn user_check(v: &View, access: &Access, u: &UserSpec, uuid: &str) -> Markup {
    // The identifiers that can actually resolve, which is not the same as the rows in
    // `emails`: an empty or non-ASCII one is dropped at load, so a row can list two and be
    // reachable through one.
    let ids: Vec<String> = u
        .emails
        .iter()
        .map(|e| norm_email(e))
        .filter(|e| !e.is_empty())
        .collect();
    let url_in = query_param(v.query, "url").unwrap_or_default();
    html! {
        h2 id=(CHECK_ANCHOR) { (v.t(K::Can)) }
        @match ids.first() {
            None => div class="panel" { span class="muted" { (v.t(K::CanNoIdentifier)) } },
            Some(email) => {
                p class="lede sub" {
                    (v.t(K::CanIntroUser))
                    @if ids.len() > 1 { " " (v.t(K::CanAnyEmail)) }
                }
                div class="panel" {
                    // The canonical spelling of this row's own route: the page renders under
                    // an email too, and the answer is about the identity either way.
                    form class="can" method="get"
                         action=(format!("{}#{CHECK_ANCHOR}", v.href(&Route::User(uuid.to_string())))) {
                        (check_field("url", &url_in, "https://app.x.com/reports"))
                        button type="submit" { (v.t(K::Submit)) }
                    }
                }
                @if !url_in.trim().is_empty() {
                    (verdict_panel(v, access, email, &url_in))
                }
            }
        }
    }
}

/// The access check as a section of an application's page: both fields, and the answer names
/// the scope that gave it, which is one of the numbered scopes listed directly above.
///
/// An email left blank tests [`Subject::Anonymous`] rather than refusing to answer: that is
/// the only way to check what an `anonymous` scope actually opens, and this is the only one of
/// the two places that can ask it, since a person's page always has a person.
///
/// The url field starts on this area's own `base` rather than empty, so an operator appends a
/// path instead of retyping a host. It is a *starting point* and not a restriction: whatever
/// is submitted goes to [`decide`], which resolves it against the whole file, so a URL typed
/// outside this area is answered honestly and the verdict says which application answered.
fn app_check(v: &View, access: &Access, a: &AppSpec) -> Markup {
    let email_in = query_param(v.query, "email").unwrap_or_default();
    let url_in = query_param(v.query, "url").unwrap_or_default();
    let asked = !url_in.trim().is_empty();
    let url_value = if asked {
        url_in.clone()
    } else {
        a.base
            .first()
            .map(|b| b.trim().to_string())
            .unwrap_or_default()
    };
    html! {
        h2 id=(CHECK_ANCHOR) { (v.t(K::Can)) }
        p class="lede sub" { (v.t(K::CanIntroApp)) }
        div class="panel" {
            form class="can" method="get"
                 action=(format!("{}#{CHECK_ANCHOR}",
                                 v.href(&Route::App(a.name.trim().to_string())))) {
                (check_field("email", &email_in, "bob@x.com"))
                (check_field("url", &url_value, "https://app.x.com/reports"))
                button type="submit" { (v.t(K::Submit)) }
            }
        }
        @if asked {
            (verdict_panel(v, access, &email_in, &url_in))
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
                Decision::Excluded { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyExcluded))
                }
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
                (v.t(K::AppSees)) " "
                // Every header this deployment's `gate.identity_attrs` will actually send,
                // by the library's own derivation, not the literal one this page used to
                // name. On a `["uuid"]` deployment there is no `X-Auth-Email` at all, and
                // saying otherwise here is saying it on the page whose whole job is to
                // predict what the application receives.
                @for (i, h) in v.identity.iter().enumerate() {
                    @if i > 0 { ", " }
                    code { (h) ": " (email) }
                }
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
/// and for `/users/{uuid}/emails/+add`: the two places an email is ever typed in, since an
/// identity carries no URL and its uuid never changes. `UserForm` gains nothing beyond
/// this: there is nothing else on a [`UserSpec`] a form could usefully edit.
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
    fn read(f: &Form) -> KeyForm {
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
fn duration_from_form(form: &Form) -> Result<String, K> {
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
    fn read(f: &Form) -> AppForm {
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
    fn read(f: &Form) -> ScopeForm {
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

    fn read(f: &Form) -> ConfigForm {
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
fn mutate(v: &View, form: &Form) -> Outcome {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
