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
//! And the header is not the last word: the email must also be on **`web.admins`** in the
//! settings file.
//! That allowlist is deliberate defense in depth: an `authenticated` scope covering the
//! GUI's URL would otherwise open the admin surface to any Cognito account. It is required,
//! and must be non-empty — empty must never mean "everyone".
//!
//! Both checks are **route-global** and run before the router: there is no path — not a
//! `404`, not a `POST`, not a broken access file — that answers anything to someone nginx
//! did not vouch for and `web.admins` does not name.
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

use bb_auth_core::{
    add_api_key, add_application, add_denied, add_scope, add_user, add_user_email, add_user_group,
    app_mut, app_pos, compile_asset_url, compile_brand_name, csp_hash, decide,
    default_settings_path, edit_urls, format_date, group_ref, key_expiry, key_mut, move_scope,
    norm_email, now, open_access_file, open_settings_file, page_csp, parse_exclusion,
    remove_api_key, remove_application, remove_denied, remove_scope, remove_user,
    remove_user_email, remove_user_group, rename_application, rename_scope, request_site,
    request_url, rotate_api_key, scope_mut, scope_pos, sha256_hex, shadowing_scope,
    stylesheet_link, user_group_mut, user_group_refs, user_label, user_pos, user_refs,
    version_line, Access, AccessFile, AccessWrite, ApiKeySpec, AppSpec, Decision, RequestSite,
    ScopeSpec, SealedKey, SettingsFile, SettingsWrite, Subject, UiTheme, UserSpec, Written,
    BASE_CSS, IDENTITY_HEADER, PAGE_SECURITY_HEADERS, THEME_CSS,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use std::io::Read;
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
/// handful of people on `web.admins`, not the public.
const WORKERS: usize = 2;

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
/// still no script on any page: not for a form, not for a confirmation, not for reordering a
/// scope, not for opening the Settings menu, and not for the theme it sets either. The override
/// is CSS specificity, nothing more. (The one handler in the binary, [`SETTINGS_ONCHANGE`],
/// saves a click on a list box and paints nothing.)
const CSS: &str = include_str!("../assets/admin.css");

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
    SignOut,
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
    // --- the filter and pager every list carries ---
    Filter,
    FilterClear,
    Page,
    PagePrev,
    PageNext,
    NoMatch,
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
    Excluded,
    ExcludedHelp,
    ExcludedNone,
    CredNoneNeeded,
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
    Config,
    ConfigIntro,
    ConfigAccess,
    ConfigHandover,
    ConfigSignIn,
    ConfigAdminLook,
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
    SocialButtons,
    SocialButtonsHelp,
    SocialProviders,
    SocialProvidersHelp,
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
    Days,
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
        K::Config => m(lang, "Settings", "Impostazioni"),
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
        K::SessionTtlBad => m(
            lang,
            "must be a whole number of seconds",
            "deve essere un numero intero di secondi",
        ),
        K::DefaultThemeBad => m(
            lang,
            "must be one of: light, dark, system",
            "deve essere uno tra: light, dark, system",
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
        K::SocialButtons => m(lang, "Social sign-in buttons", "Pulsanti di accesso social"),
        K::SocialButtonsHelp => m(
            lang,
            "One Cognito identity_provider name per line, in the order they appear on the sign-in page. Empty offers none. A provider also has to be federated by the app client (BB_AUTH_SOCIAL_IDPS on the host), or no button is drawn for it.",
            "Un nome identity_provider di Cognito per riga, nell'ordine in cui appaiono nella pagina di accesso. Vuoto non ne offre nessuno. Il provider deve anche essere federato dall'app client (BB_AUTH_SOCIAL_IDPS sull'host), altrimenti il pulsante non viene disegnato.",
        ),
        K::SocialProviders => m(lang, "Providers", "Provider"),
        K::SocialProvidersHelp => m(
            lang,
            "One per line, matched against the token's providerName. Empty means any federated provider.",
            "Uno per riga, confrontati con il providerName del token. Vuoto significa qualsiasi provider federato.",
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
            "is authenticated, but is not an administrator of this interface.",
            "è autenticato, ma non è amministratore di questa interfaccia.",
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
        K::SignOut => m(lang, "Sign out", "Esci"),
        K::Settings => m(lang, "Preferences", "Preferenze"),
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

        K::Filter => m(lang, "filter", "filtro"),
        K::FilterClear => m(lang, "clear the filter", "azzera il filtro"),
        K::Page => m(lang, "page", "pagina"),
        K::PagePrev => m(lang, "previous", "precedente"),
        K::PageNext => m(lang, "next", "successiva"),
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
        K::BearerClickHint => m(
            lang,
            "Click the credential to select it all, then copy.",
            "Fai clic sulla credenziale per selezionarla tutta, poi copiala.",
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
        Config {
            listen: env_or("BB_AUTH_WEB_LISTEN", "127.0.0.1:8091"),
            access_path,
            settings_path,
            base_path,
            default_lang,
            logout_url,
        }
    }
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
    /// One roster row, addressed by its uuid: the identity is what the file references,
    /// and an email can be added or dropped without the page moving.
    User(String),
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
            Route::User(u) => format!("/users/{}", seg(u)),
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
            Route::GroupEdit(n) => format!("/groups/{}/edit", seg(n)),
            Route::GroupRm(n) => format!("/groups/{}/rm", seg(n)),

            Route::DenyAdd => format!("/denied/{ACTION_ADD}"),
            Route::DenyRm(e) => format!("/denied/{}/rm", seg(e)),
        }
    }

    /// Which nav tab to mark current for this route: everything about a user belongs to
    /// the `users` tab, and so on down the sections. `denied` has no tab of its own: its
    /// page lives at its own route, but the bar lights up `users` for it, since the
    /// two are the sections about people and [`page_users`] is where an operator finds
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
            Route::GroupAdd | Route::GroupEdit(_) | Route::GroupRm(_) => Route::Users,
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
            Route::GroupAdd | Route::GroupEdit(_) | Route::GroupRm(_) => Route::Users,
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
            Route::GroupAdd | Route::GroupEdit(_) | Route::GroupRm(_) => "user_groups",
            _ => match self.tab() {
                Route::Apps => "applications",
                Route::Users => "users",
                Route::Config => "settings",
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

        // `/groups` is a section of the users page rather than a page of its own, so the
        // bare path lands where the list actually is instead of on a 404.
        ["groups"] => Some(Route::Users),
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
fn respond_page(req: Request, status: u16, page: Markup, look: &Look) {
    let mut resp = Response::from_data(page.into_string().into_bytes())
        .with_status_code(StatusCode(status))
        .with_header(h("Content-Type", "text/html; charset=utf-8"))
        .with_header(h("Content-Security-Policy", &admin_csp(look)));
    for (k, v) in PAGE_SECURITY_HEADERS {
        resp.add_header(h(k, v));
    }
    let _ = req.respond(resp);
}

/// This GUI's `Content-Security-Policy`.
///
/// Hashes and not a nonce, because everything this program executes or styles is a
/// compile-time constant: the `<style>` block is [`THEME_CSS`] + [`BASE_CSS`] + [`CSS`] and
/// the only scripting on any page is [`SETTINGS_ONCHANGE`], one attribute on one list box.
/// So the policy is derived from the same `&str`s the page is, and the two cannot disagree.
///
/// `'unsafe-hashes'` is what an inline event handler needs: a nonce cannot be put on an
/// attribute, and the alternative to naming this one handler by its hash is `'unsafe-inline'`,
/// which would permit every handler anybody ever adds. The `<noscript>` button behind it means
/// a browser that refuses the handler still works, which makes this the rare case where the
/// strict policy has a fallback already built.
///
/// `img-src` is `'none'`: this interface shows no image at all, not even the deployment's
/// logo, so the honest policy says so.
fn admin_csp(look: &Look) -> String {
    let script = format!("'unsafe-hashes' {}", csp_hash(SETTINGS_ONCHANGE));
    let style = csp_hash(&format!("{THEME_CSS}{BASE_CSS}{CSS}"));
    page_csp(&script, &style, look.stylesheet, None, &[])
}

/// `302` to `location`, setting one preference cookie to `value`. `location` is built from a
/// [`Route`] and re-encoded query parameters, so it is printable ASCII by construction and
/// [`h`] cannot panic on it; `value` is always one of a closed enum's own [`Lang::code`] or
/// [`UiTheme::code`], never request-supplied.
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
    let (_, _, page, pages) = l.window(matched);
    let q_name = l.q_name();
    let p_name = l.p_name();
    html! {
        div class="listctl" {
            form method="get" action=(v.href(&v.at)) {
                @for (k, val) in preserved_query(v.query) {
                    @if k != q_name && k != p_name {
                        input type="hidden" name=(k) value=(val);
                    }
                }
                input type="search" name=(q_name) value=(l.q) placeholder=(v.t(K::Filter))
                      aria-label=(v.t(K::Filter));
                button type="submit" class="pill" { (v.t(K::Apply)) }
                @if !l.q.is_empty() {
                    a class="pill" href=(listing_href(v, l, &[])) title=(v.t(K::FilterClear)) { "×" }
                }
            }
            @if pages > 1 {
                span class="pager" {
                    @if page > 0 {
                        a class="pill" href=(page_href(v, l, page)) { "← " (v.t(K::PagePrev)) }
                    } @else {
                        span class="pill off" { "← " (v.t(K::PagePrev)) }
                    }
                    span class="muted" { (v.t(K::Page)) " " (page + 1) "/" (pages) }
                    @if page + 1 < pages {
                        a class="pill" href=(page_href(v, l, page + 2)) { (v.t(K::PageNext)) " →" }
                    } @else {
                        span class="pill off" { (v.t(K::PageNext)) " →" }
                    }
                }
            }
            @if !l.q.is_empty() {
                span class="muted" { (matched) "/" (total) }
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

/// The chrome around every page: the tabs, the Settings menu, the footer.
///
/// Four tabs, not the access file's four sections plus the dashboard and the settings:
/// `denied` shares the `users` tab (see [`Route::tab`]) because both are about
/// people, and the page itself sits at the bottom of [`page_users`] rather than
/// standing on its own in the bar. The bar reads left to right roughly as the file reads
/// top to bottom, dashboard in front, then the settings, which are last
/// because they are the *other* file, and the one tab not about who reaches what.
///
/// Every tab is a **noun**: a place that owns a section of a file. The access check used to
/// be a fifth one and was the odd item out for exactly that reason, being a verb that owns
/// nothing; it is now a section of [`page_user`] and [`page_app`], which is where its
/// question is actually asked, since each of those pages already answers half of it.
///
/// Labels are translated, descriptive prose about a section ([`K::Groups`] and
/// friends), not the section's own name in the file; that name still appears, untranslated,
/// beside the heading each tab leads to.
fn shell(v: &View, title: &str, content: Markup) -> Markup {
    let tabs = [
        (Route::Dashboard, v.t(K::Dashboard)),
        (Route::Apps, v.t(K::Apps)),
        (Route::Users, v.t(K::Users)),
        (Route::Config, v.t(K::Config)),
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
    let themes = [UiTheme::System, UiTheme::Light, UiTheme::Dark];
    html! {
        (DOCTYPE)
        // The theme, resolved here and in one expression, because the fallback order is the
        // rule: this browser's choice, then the deployment's default, then nothing at all.
        // `data-theme=[…]` is maud's optional-attribute form, so the `None` two `System`s
        // produce omits the attribute outright rather than emitting `data-theme=""` — which
        // is what leaves the `prefers-color-scheme` rule in `THEME_CSS` as the one deciding.
        html lang=(v.lang.code()) data-theme=[v.theme.attr().or(v.look.theme.attr())] {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { "bb-auth-web · " (title) }
                // The three deliberately raw emissions on any page, and all three are
                // compile-time constants: never request data and never anything read out of
                // the access file. The order is the contract — the palette, the components
                // that read it (the same bytes the gate's pages get), the layout that
                // arranges them, then (below) whatever the operator wants to say over the top.
                style { (PreEscaped(THEME_CSS)) (PreEscaped(BASE_CSS)) (PreEscaped(CSS)) }
                // The operator's own stylesheet, or nothing. Raw because the string is a
                // whole `<link>` element built by the library, from a URL that has already
                // passed `compile_asset_url` and is escaped again on the way out; there is
                // no way to say "an element" in maud without saying it in maud.
                (PreEscaped(stylesheet_link(v.look.stylesheet)))
            }
            body {
                header class="top" {
                    div class="bar" {
                        // The brand is the way home, but only when there is a home to go
                        // to: the 403 page has no nav for the same reason, so there the
                        // brand is a plain inert span.
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
                        // The account end of the bar, and it is a `nav` for the same reason
                        // the tabs are: it makes these two controls flex items of a flex row,
                        // exactly as the four tabs are. Before this they were a `details` and
                        // a bare link sitting directly in the bar, which is three different
                        // structures for one object, and an object whose box depends on which
                        // structure it happens to be in is not one object.
                        nav class="acct" {
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
                                                    (v.t(theme_label(th)))
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
                        // Sign out, when the operator has said where to: last in the bar, to
                        // the right of the preferences menu, which is where a session control
                        // is looked for. It is the same pill as every other control up here
                        // and at the same size, and it gets that for being INSIDE the bar
                        // (`CSS` selects `.bar .pill`) rather than for being named.
                        //
                        // Rendered even without an administrator, unlike the tabs: the `403`
                        // page is exactly where this is most useful, because the way out of
                        // "you are signed in as somebody who may not use this" is to end that
                        // session and start another. It is a plain link and not a form: the
                        // gate's `/auth/logout` is a `GET` that clears the cookie and
                        // redirects, guarded there against cross-site navigation.
                        @if let Some(u) = &v.cfg.logout_url {
                            a class="pill" href=(u) { (v.t(K::SignOut)) }
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
                    // No reload hint: `bb-auth-reload.path` watches the file and reloads the
                    // gate on every save, so telling an administrator to run
                    // `systemctl reload bb-auth` would describe work nobody has to do.
                    @if let Some(a) = v.admin {
                        span { (v.t(K::SignedInAs)) " " code { (a) } }
                    }
                    // What these bytes were built from, which the version in the bar cannot
                    // say: a `.deb` reads 1.1.0-1 for a clean release and for a working tree
                    // somebody built by hand, and this is the one place a person can see
                    // which of the two is answering.
                    span class="muted" { code { (version_line("bb-auth-web")) } }
                }
            }
        }
    }
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

/// The way back out of a detail page, as a pill like every other small control.
///
/// A link and not a button, because it navigates and changes nothing; a pill and not body
/// prose, because it sits in the same row as `edit` and `remove` and is the same kind of
/// thing. Declared once here for the same reason [`act`] is: nothing at a call site is
/// allowed to say how a pill looks.
fn back(v: &View, to: &Route) -> Markup {
    html! { a class="pill" href=(v.href(to)) { "\u{2190} " (v.t(K::Back)) } }
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
                ("user_groups", doc.user_groups.len(), Some(Route::Users)),
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

/// `/users` — everything the file says about people, in three sections: the groups, the
/// roster, and the veto.
///
/// One tab, because all three answer the same question from different sides, and an operator
/// editing one usually has to look at another. `user_groups` leads, above the roster,
/// because a group is what a scope names and the roster is what a group names: the page
/// reads outside-in. Each section carries its own filter and pager, namespaced (`g`, `u`,
/// `d`) so that searching one does not disturb the others; `/groups` and `/denied` still
/// resolve, to this page and to [`page_denied`], so no bookmark breaks.
fn page_users(v: &View, doc: &AccessFile, access: &Access) -> Markup {
    let lu = Listing::read("u", v.query);
    let rows: Vec<&UserSpec> = doc.users.iter().filter(|u| l_keeps_user(&lu, u)).collect();
    let (start, end, _, _) = lu.window(rows.len());
    html! {
        h1 { (v.t(K::Users)) }
        p class="lede" { (v.t(K::UsersIntro)) }

        (groups_section(v, doc))

        h2 { (section_heading(v.t(K::Users), "users")) }
        p class="primary" { (act(v, &Route::UserAdd, &format!("+ {}", v.t(K::Add)))) }
        (list_controls(v, &lu, rows.len(), doc.users.len()))
        (list_panel(v, doc.users.len(), rows.len(), html! {
                table {
                    thead { tr {
                        th { (v.t(K::Emails)) }
                        th { "api_keys" }
                        th {}
                    } }
                    tbody {
                        @for u in &rows[start..end] {
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
        }))

        // The `denied` veto, as the last section of this same page rather than a tab of
        // its own: all three sections are about people, and an operator managing the
        // roster is the one most likely to also need the veto list. The route `/denied`
        // still exists on its own (see `page_denied`) for the add/remove PRG redirects and
        // for a direct link; `denied_list` is what keeps the two views of the same list
        // from ever drifting apart.
        h2 { (section_heading(v.t(K::Denied), "denied")) }
        p class="lede sub" { (v.t(K::DeniedIntro)) }
        p class="primary" { (act(v, &Route::DenyAdd, &format!("+ {}", v.t(K::Add)))) }
        (denied_list(v, doc))
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

/// The `user_groups` section of [`page_users`]: each entry, who it references, and
/// everything that names it. Members are people: an email where a roster row still
/// resolves it, the raw uuid where none does, and flagged when it matches nobody at all.
///
/// A section rather than a page of its own: a group only ever means something in terms of
/// the roster below it, and a list that is usually three lines long does not earn a tab in
/// the nav bar.
fn groups_section(v: &View, doc: &AccessFile) -> Markup {
    let l = Listing::read("g", v.query);
    // A group is searchable by its own name and by who is in it, because "which group is
    // bob in?" is the question this list is usually opened to answer.
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
        h2 { (section_heading(v.t(K::Groups), "user_groups")) }
        p class="lede sub" { (v.t(K::GroupsIntro)) }
        p class="primary" { (act(v, &Route::GroupAdd, &format!("+ {}", v.t(K::Add)))) }
        (list_controls(v, &l, rows.len(), doc.user_groups.len()))
        (list_rows(v, doc.user_groups.len(), rows.len(), html! {
            @for (name, members) in &rows[start..end] {
                @let refs = user_group_refs(doc, name);
                div class="panel" {
                    h3 class="tight" {
                        code { "@" (name) }
                        " "
                        span class="pills" {
                            (act(v, &Route::GroupEdit((*name).clone()), v.t(K::Edit)))
                            (act_rm(v, &Route::GroupRm((*name).clone()), v.t(K::Remove)))
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
                            @for m in members.iter() {
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
        }))
    }
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
        match scope_credentials(s) {
            None => return None,
            Some(list) => {
                login |= list.contains(&"login");
                api_key |= list.contains(&"api_key");
            }
        }
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
        h2 { (v.t(K::Can)) }
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
                    form class="can" method="get" action=(v.href(&Route::User(uuid.to_string()))) {
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
        h2 { (v.t(K::Can)) }
        p class="lede sub" { (v.t(K::CanIntroApp)) }
        div class="panel" {
            form class="can" method="get" action=(v.href(&Route::App(a.name.trim().to_string()))) {
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
    buttons: String,
    admins: String,
    stylesheet: String,
    logo: String,
    brand: String,
    theme: String,
}

impl ConfigForm {
    /// The form as the file says it, which is what a `GET` renders.
    fn of(doc: &SettingsFile) -> ConfigForm {
        ConfigForm {
            claims: doc.gate.profile_claims.join("\n"),
            identity: doc.gate.identity_attrs.join("\n"),
            ttl: doc.gate.session_ttl_secs.to_string(),
            social: doc.gate.allow_unverified_social,
            providers: doc.gate.social_providers.join("\n"),
            buttons: doc.gate.social_buttons.join("\n"),
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
            buttons: f.get("buttons").to_string(),
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

    /// Apply the form to the document. The refusals here are the two the library cannot make
    /// on its own: it does not know who is signed in, and it does not parse a form.
    fn apply(&self, doc: &mut SettingsFile, admin: &str, lang: Lang) -> Result<(), Refusal> {
        let ttl: u64 = self
            .ttl
            .trim()
            .parse()
            .map_err(|_| Refusal::on("ttl", t(lang, K::SessionTtlBad)))?;
        let admins = Self::lines(&self.admins);
        if admins.is_empty() {
            return Err(Refusal::on("admins", t(lang, K::AdminsNeverEmpty)));
        }
        // The guard that makes this page safe to hand an administrator: you may add anyone
        // and remove anyone but yourself. Removing the last administrator is refused above;
        // removing *this* one would leave a GUI nobody can open, and the way back is the SSH
        // this page exists to save people from. `bb-auth-adm` will still do it.
        if !admins.iter().any(|a| norm_email(a) == admin) {
            return Err(Refusal::on("admins", t(lang, K::AdminsKeepYourself)));
        }
        // The `ui` fields are attributed to the field that carries them, which is the whole
        // reason they are checked here and not left to the write: the library's refusal names
        // the setting, but only this page knows which input the operator has to go back to.
        // Empty is not a refusal anywhere here; it is the setting being unset.
        compile_asset_url("stylesheet_url", &self.stylesheet)
            .map_err(|e| Refusal::on("stylesheet", &e))?;
        compile_asset_url("logo_url", &self.logo).map_err(|e| Refusal::on("logo", &e))?;
        compile_brand_name(&self.brand).map_err(|e| Refusal::on("brand", &e))?;
        // A value this list box cannot produce, so a refusal here means the request was not
        // this form. It is still a refusal and not a silent `system`: see `UiTheme::parse`.
        let theme = UiTheme::parse(&self.theme)
            .ok_or_else(|| Refusal::on("theme", t(lang, K::DefaultThemeBad)))?;

        doc.gate.profile_claims = Self::lines(&self.claims);
        doc.gate.identity_attrs = Self::lines(&self.identity);
        doc.gate.session_ttl_secs = ttl;
        doc.gate.allow_unverified_social = self.social;
        doc.gate.social_providers = Self::lines(&self.providers);
        doc.gate.social_buttons = Self::lines(&self.buttons);
        doc.web.admins = admins;
        doc.ui.stylesheet_url = self.stylesheet.trim().to_string();
        doc.ui.logo_url = self.logo.trim().to_string();
        doc.ui.brand_name = self.brand.trim().to_string();
        doc.ui.theme = theme.code().to_string();
        Ok(())
    }
}

fn page_config(v: &View, f: &ConfigForm, err: Option<&Refusal>) -> Markup {
    let about = |name| err.is_some_and(|e| e.is(name));
    let days = f.ttl.trim().parse::<u64>().unwrap_or(0) / 86_400;
    html! {
        h1 { (v.t(K::Config)) }
        p class="lede" { (v.t(K::ConfigIntro)) }
        // FOUR BOXES, ONE FORM. The grouping is by what a setting decides, not by which
        // section of the file it lands in: an operator asking "who gets in, and for how
        // long" should not have to read past what the application receives to find out, and
        // the two questions are answered by fields that happen to be neighbours in the file.
        // The file keeps its own three sections unchanged, so each box still names the key
        // it writes; where a box spans two, it names both.
        //
        // One form and one save, because the `rev` guard is over the whole file: four forms
        // would be four fingerprints and three chances to lose an edit somebody else made
        // between them.
        (form_shell(v, err, html! {
            div class="panel" {
                (section_heading(v.t(K::ConfigAccess), "gate"))
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
            }
            div class="panel" {
                (section_heading(v.t(K::ConfigHandover), "gate"))
                (urls_field(v.t(K::IdentityAttrs), "identity", &f.identity,
                            html! { (v.t(K::IdentityAttrsHelp)) }, about("identity")))
                (urls_field(v.t(K::ProfileClaims), "claims", &f.claims,
                            html! { (v.t(K::ProfileClaimsHelp)) }, about("claims")))
            }
            div class="panel" {
                (section_heading(v.t(K::ConfigSignIn), "gate"))
                // A different question from the provider list above: that one says whose
                // unverified email is accepted, this one says what a visitor is offered.
                (urls_field(v.t(K::SocialButtons), "buttons", &f.buttons,
                            html! { (v.t(K::SocialButtonsHelp)) }, about("buttons")))
            }
            div class="panel" {
                (section_heading(v.t(K::ConfigAdminLook), "web + ui"))
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
            }
        }, v.t(K::Save), false))
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
        p { (back(v, &Route::User(owner_uuid.to_string()))) }
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
        let r = (|| -> Result<(), Refusal> {
            let (mut doc, _) = open_settings_file(path)?;
            f.apply(&mut doc, v.admin.unwrap_or_default(), v.lang)?;
            // The library is the only door here too: `prepare` compiles the exact bytes with
            // the parser the gate uses, `commit` writes the bytes it compiled.
            SettingsWrite::prepare(&doc)?.commit(path)?;
            audit(v.admin.unwrap_or("?"), "settings set", path);
            Ok(())
        })();
        return match r {
            Ok(()) => Outcome::Done(Route::Config, Msg::SettingsSaved),
            Err(e) => Outcome::Page(400, title, page_config(v, &f, Some(&e))),
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
            let r = (|| -> Result<(), Refusal> {
                let name = f.name.trim().to_string();
                let members =
                    parse_group_members(&doc, &f.members).map_err(|e| Refusal::on("members", e))?;
                add_user_group(&mut doc, &name, members).map_err(|e| Refusal::on("name", e))?;
                commit(v, &doc, "group add", &format!("@{name}"))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Users, Msg::GroupAdded),
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
                Ok(()) => Outcome::Done(Route::Users, Msg::GroupSaved),
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
                Ok(()) => Outcome::Done(Route::Users, Msg::GroupRemoved),
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
            respond_page(req, 401, shell(&v, v.t(K::NoIdentityTitle), page), &v.look);
            return;
        }
    };
    let email = norm_email(&raw_email);

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
    };
    if settings.admins.is_empty() {
        let v = anon_view(cfg, lang, lang_pref, theme, look);
        let e = format!("{}: {}", cfg.settings_path, v.t(K::AdminsNeverEmpty));
        respond_page(
            req,
            500,
            shell(&v, v.t(K::FileErrorTitle), page_file_error(&v, &e)),
            &v.look,
        );
        return;
    }
    if !settings.is_admin(&email) {
        let v = anon_view(cfg, lang, lang_pref, theme, look);
        let page = notice(
            "bad",
            v.t(K::NotAdminTitle),
            html! { p { code { (email) } " " (v.t(K::NotAdminBody)) } },
        );
        respond_page(req, 403, shell(&v, v.t(K::NotAdminTitle), page), &v.look);
        return;
    }

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
            respond_page(req, 404, shell(&v, v.t(K::NotFoundTitle), page), &v.look);
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
            look,
            admin: Some(&email),
            at: at.clone(),
            query: "",
            rev: "",
            msg: None,
            identity: identity.clone(),
        };
        if !allowed {
            let page = notice("bad", v.t(K::CsrfTitle), html! { p { (v.t(K::CsrfBody)) } });
            respond_page(req, 403, shell(&v, v.t(K::CsrfTitle), page), &v.look);
            return;
        }
        let form = Form::parse(&read_body(&mut req));
        match mutate(&v, &form) {
            Outcome::Done(to, msg) => {
                let location = format!("{}{}?msg={}", cfg.base_path, to.path(), msg.key());
                respond_redirect(req, &location);
            }
            Outcome::Page(status, title, content) => {
                respond_page(req, status, shell(&v, title, content), &v.look)
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
            Ok((doc, _)) => page_config(&v, &ConfigForm::of(&doc), None),
            Err(e) => page_file_error(&v, &e),
        };
        respond_page(req, 200, shell(&v, v.t(K::Config), content), &v.look);
        return;
    }

    let (doc, access) = match open_access_file(&cfg.access_path) {
        Ok(pair) => pair,
        Err(e) => {
            respond_page(
                req,
                500,
                shell(&v, v.t(K::FileErrorTitle), page_file_error(&v, &e)),
                &v.look,
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
    respond_page(req, status, shell(&v, title, content), &v.look);
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
    // reports 1.1.0-1 for a release and for a hand-built tree alike.
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
        "[bb-auth-web] {} listening on {} | file={} | settings={} | admins={admins} | base={base}          | lang={}",
        version_line("bb-auth-web"),
        cfg.listen,
        cfg.access_path,
        cfg.settings_path,
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
    const SAMPLE: &str = r#"{ "version": 1,
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
    const TWO_SCOPES: &str = r#"{ "version": 1,
      "applications": [
        { "name": "app1", "base": ["https://app.x.com"],
          "scopes": [
            { "name": "first", "urls": ["https://app.x.com/a/*"], "access": "anonymous" },
            { "name": "second", "urls": ["https://app.x.com/b/*"], "access": "anonymous" }
          ] }
      ],
      "users": [ { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b", "emails": ["bob@x.com"] } ]
    }"#;

    /// The settings file a test runs against: one administrator, and the defaults.
    ///
    /// Written beside its access file under that file's own unique name rather than at the
    /// derived default, because the default is one `settings.json` per *directory* and every
    /// test here shares the temp directory. Tests run in parallel.
    const SETTINGS: &str = r#"{ "version": 1, "web": { "admins": ["admin@x.com"] } }"#;

    fn settings_path(access_path: &str) -> String {
        format!("{access_path}.settings")
    }

    /// Names the two files; creates neither. A rendering-only test passes a path that is not
    /// on disk at all, and this must leave it that way: a helper that wrote a file for every
    /// `Config` it built would litter the working tree from the tests that never touch one.
    fn cfg_for(path: &str, base: &str) -> Config {
        Config {
            listen: String::new(),
            access_path: path.to_string(),
            settings_path: settings_path(path),
            base_path: base.to_string(),
            default_lang: Lang::En,
            // Configured, so the control renders and the tests below see the shape a real
            // deployment has. The unset case is its own test.
            logout_url: Some("/auth/logout".to_string()),
        }
    }

    /// Write `json` to a uniquely-named temp file so tests can run in parallel, and the
    /// settings file beside it: the two are one fixture, and every test that has an access
    /// file on disk needs a settings file to be served at all.
    fn scratch(name: &str, json: &str) -> String {
        let p = std::env::temp_dir().join(format!("bb-auth-web-{name}.json"));
        std::fs::write(&p, json).unwrap();
        let path = p.to_string_lossy().into_owned();
        std::fs::write(settings_path(&path), SETTINGS).unwrap();
        path
    }

    /// The scratch file, the settings file beside it, and the backups a write leaves.
    fn cleanup(path: &str) {
        for p in [
            path.to_string(),
            format!("{path}.bak"),
            settings_path(path),
            format!("{}.bak", settings_path(path)),
        ] {
            let _ = std::fs::remove_file(p);
        }
    }

    fn read(path: &str) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    /// The HTTP client every over-the-wire test uses, and both of its settings are the
    /// point. A refusal here is asserted on by its **body**, not just its code (that the
    /// 403 names the identity, that the 409 says the file changed), and the client's own
    /// status error carries only the number, so a non-2xx has to arrive as a response.
    /// And a `303` is the thing under test rather than a step on the way to something,
    /// so redirects are never followed.
    fn client() -> ureq::Agent {
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .new_agent()
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

    // --- the settings page ---------------------------------------------------

    /// The fields the settings form posts, as a browser would, with one override applied.
    fn settings_fields<'a>(rev: &'a str, over: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
        let mut f: Vec<(&str, &str)> = vec![
            ("rev", rev),
            ("identity", "email"),
            ("claims", ""),
            ("ttl", "2592000"),
            ("providers", ""),
            ("buttons", ""),
            ("admins", "admin@x.com"),
        ];
        for (k, v) in over {
            match f.iter_mut().find(|(n, _)| n == k) {
                Some(slot) => slot.1 = v,
                None => f.push((k, v)),
            }
        }
        f
    }

    #[test]
    fn the_settings_page_writes_the_five_and_the_administrators() {
        let path = scratch("cfg-write", SAMPLE);
        let cfg = cfg_for(&path, "");
        let sp = cfg.settings_path.clone();
        let got = post(
            &cfg,
            Route::Config,
            &settings_fields(
                &rev_of(&sp),
                &[
                    ("identity", "email\nuuid"),
                    ("claims", " given_name \n\n family_name "),
                    ("ttl", "604800"),
                    ("social", "on"),
                    ("providers", "Google"),
                    ("admins", "admin@x.com\nAnother@X.com"),
                ],
            ),
        );
        assert_eq!(got.location(), "/config?msg=settings-saved");

        let (_, s) = open_settings_file(&sp).unwrap();
        assert_eq!(
            s.identity_attrs
                .iter()
                .map(|a| a.attr.as_str())
                .collect::<Vec<_>>(),
            vec!["email", "uuid"]
        );
        // Trimmed, blanks dropped, and the header derived rather than configured.
        assert_eq!(s.profile_claims[1].header, "X-Auth-Family-Name");
        assert_eq!(s.session_ttl, 604_800);
        assert!(s.allow_unverified_social);
        assert_eq!(s.social_providers, Some(vec!["Google".to_string()]));
        assert_eq!(s.admins.len(), 2);
        // The access file was not touched: this page edits the other one.
        assert_eq!(read(&path), SAMPLE);
        cleanup(&path);
    }

    #[test]
    fn the_settings_page_writes_the_look_and_refuses_one_it_cannot() {
        let path = scratch("cfg-look", SAMPLE);
        let cfg = cfg_for(&path, "");
        let sp = cfg.settings_path.clone();
        let got = post(
            &cfg,
            Route::Config,
            &settings_fields(
                &rev_of(&sp),
                &[
                    ("brand", "  BadBat75  "),
                    ("stylesheet", "https://assets.badbat75.com/css/theme.css"),
                    ("logo", "/img/logo.png"),
                    ("ui_theme", "dark"),
                ],
            ),
        );
        assert_eq!(got.location(), "/config?msg=settings-saved");
        let (_, s) = open_settings_file(&sp).unwrap();
        assert_eq!(s.brand_name.as_deref(), Some("BadBat75"), "trimmed");
        assert_eq!(
            s.stylesheet_url.as_deref(),
            Some("https://assets.badbat75.com/css/theme.css")
        );
        assert_eq!(s.logo_url.as_deref(), Some("/img/logo.png"));
        assert_eq!(s.theme, UiTheme::Dark);

        // A URL the library refuses is refused HERE, attributed to the field that carries it,
        // and nothing is written: the same shape every other refusal on this page has.
        let before = read(&sp);
        let got = post(
            &cfg,
            Route::Config,
            &settings_fields(&rev_of(&sp), &[("stylesheet", "javascript:alert(1)")]),
        );
        let (status, body) = got.page();
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("stylesheet_url"), "{body}");
        assert!(
            body.contains(r#"class="f-stylesheet invalid""#),
            "the refusal must point at the field: {body}"
        );
        assert_eq!(read(&sp), before, "nothing written");
        cleanup(&path);
    }

    #[test]
    fn the_look_is_the_palette_the_components_the_layout_then_the_operator() {
        let path = scratch("look-order", SAMPLE);
        let cfg = cfg_for(&path, "");
        let (doc, access) = open_access_file(&cfg.access_path).unwrap();
        let mut v = view(&cfg, Route::Dashboard, "REV");
        v.look = Look {
            theme: UiTheme::Dark,
            stylesheet: Some("https://assets.badbat75.com/css/theme.css"),
        };
        let html = shell(&v, "t", page_dashboard(&v, &doc, &access)).into_string();

        // Order is the contract, and it is four deep: the palette, the components that read
        // it, the layout that arranges them, then an override that wins by source order alone
        // and therefore needs no `!important` and no knowledge of what it is restyling. The
        // middle two are the same bytes the gate emits on its own pages.
        let tokens = html.find("--accent:").expect("the palette is inlined");
        let components = html.find(".pill{").expect("the components are inlined");
        let layout = html.find("header.top{").expect("the layout is inlined");
        let link = html.find("<link rel=\"stylesheet\"").expect("the override");
        assert!(
            tokens < components && components < layout && layout < link,
            "{html}"
        );
        // The deployment's default theme reaches the page when the visitor chose nothing.
        assert!(html.contains(r#"data-theme="dark""#), "{html}");
        // And the visitor's own choice still outranks it.
        v.theme = UiTheme::Light;
        let html = shell(&v, "t", html! {}).into_string();
        assert!(html.contains(r#"data-theme="light""#), "{html}");
        cleanup(&path);
    }

    #[test]
    fn with_no_stylesheet_configured_the_page_links_nothing_at_all() {
        // The property the whole arrangement rests on: the built-in look is complete, so a
        // deployment that configures nothing fetches nothing, and one whose asset host is
        // down still has a working page.
        let html = render("look-none", Route::Dashboard);
        assert!(!html.contains("<link"), "{html}");
        assert!(
            html.contains("--accent:"),
            "the palette must still be there"
        );
    }

    /// The social buttons are a settings field like any other, and the page is where an
    /// operator turns one on: the whole reason this is not the env var it used to be.
    #[test]
    fn the_settings_page_writes_which_social_buttons_are_offered() {
        let path = scratch("cfg-buttons", SAMPLE);
        let sp = settings_path(&path);
        let cfg = cfg_for(&path, "");

        // Two, in the order they were typed, which is the order the page will show them.
        let got = post(
            &cfg,
            Route::Config,
            &settings_fields(
                &rev_of(&sp),
                &[(
                    "buttons",
                    "Google
MicrosoftPersonal",
                )],
            ),
        );
        assert!(matches!(got, Got::Redirect(_)), "{got:?}");
        let (doc, s) = open_settings_file(&sp).unwrap();
        assert_eq!(doc.gate.social_buttons, ["Google", "MicrosoftPersonal"]);
        assert_eq!(s.social_buttons, ["Google", "MicrosoftPersonal"]);

        // And emptying the field takes the section off the sign-in page, which is a thing an
        // operator does deliberately and must not need the env file for.
        let got = post(
            &cfg,
            Route::Config,
            &settings_fields(&rev_of(&sp), &[("buttons", "")]),
        );
        assert!(matches!(got, Got::Redirect(_)), "{got:?}");
        assert!(open_settings_file(&sp).unwrap().1.social_buttons.is_empty());

        // A name that could never be a Cognito identity_provider is refused in context, with
        // nothing written: the same shape every other refusal on this page has.
        let before = read(&sp);
        let got = post(
            &cfg,
            Route::Config,
            &settings_fields(&rev_of(&sp), &[("buttons", "Google Inc")]),
        );
        let (status, body) = got.page();
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("social_buttons"), "{body}");
        assert_eq!(read(&sp), before, "nothing written");
        cleanup(&path);
    }

    #[test]
    fn the_settings_page_refuses_what_would_lock_the_administrator_out() {
        let path = scratch("cfg-lockout", SAMPLE);
        let cfg = cfg_for(&path, "");
        let sp = cfg.settings_path.clone();
        let before = read(&sp);

        // Removing yourself: refused here, and the message says where it can be done.
        let got = post(
            &cfg,
            Route::Config,
            &settings_fields(&rev_of(&sp), &[("admins", "someone@else.com")]),
        );
        let (status, page) = got.page();
        assert_eq!(status, 400);
        assert!(page.contains("cannot remove yourself"), "{page}");

        // Emptying the list: refused before the library ever sees it, because an empty list
        // must never come to mean "everyone".
        let got = post(
            &cfg,
            Route::Config,
            &settings_fields(&rev_of(&sp), &[("admins", "  \n ")]),
        );
        assert_eq!(got.page().0, 400);
        assert!(got.page().1.contains("at least one administrator"));

        // An identity list the gate would refuse never reaches the disk either.
        let got = post(
            &cfg,
            Route::Config,
            &settings_fields(&rev_of(&sp), &[("identity", "phone")]),
        );
        assert_eq!(got.page().0, 400);
        assert!(got.page().1.contains("unknown identity attribute"));

        assert_eq!(read(&sp), before, "nothing was written on any refusal");
        cleanup(&path);
    }

    #[test]
    fn the_settings_form_is_guarded_by_the_settings_file_own_fingerprint() {
        let path = scratch("cfg-rev", SAMPLE);
        let cfg = cfg_for(&path, "");
        let sp = cfg.settings_path.clone();

        // The form a `GET` renders carries the settings file's fingerprint, not the access
        // file's; otherwise every roster edit would 409 this page, and a concurrent
        // `bb-auth-adm settings set` would go unnoticed, which is the case the check is for.
        let rev = rev_of(&sp);
        let v = view(&cfg, Route::Config, &rev);
        let (doc, _) = open_settings_file(&sp).unwrap();
        let html =
            shell(&v, "settings", page_config(&v, &ConfigForm::of(&doc), None)).into_string();
        assert_eq!(rev_in(&html), rev_of(&sp));
        assert_ne!(rev_of(&sp), rev_of(&path));

        // And a stale one is a 409 that writes nothing.
        let got = post(
            &cfg,
            Route::Config,
            &settings_fields("stale", &[("ttl", "60")]),
        );
        assert_eq!(got.page().0, 409);
        assert_eq!(open_settings_file(&sp).unwrap().1.session_ttl, 2_592_000);
        cleanup(&path);
    }

    #[test]
    fn an_unreadable_settings_file_is_an_error_page_not_a_denial() {
        // Saying "you are not an administrator" when the file that would say so cannot be
        // read is a lie, and one that sends an operator looking in the wrong place.
        let path = scratch("cfg-broken", SAMPLE);
        let cfg = cfg_for(&path, "");
        std::fs::write(&cfg.settings_path, "{ not json").unwrap();

        let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
        let port = server.server_addr().to_ip().expect("an ip address").port();
        let served = cfg_for(&path, "");
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &served);
            }
        });
        let mut r = client()
            .get(format!("http://127.0.0.1:{port}/"))
            .header(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("a response");
        assert_eq!(r.status(), 500);
        let body = r.body_mut().read_to_string().unwrap();
        assert!(body.contains("settings"), "{body}");
        cleanup(&path);
    }

    // --- config -------------------------------------------------------------

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
        assert_eq!(route("/groups", ""), Some(Route::Users));
        assert_eq!(route("/apps", ""), Some(Route::Apps));
        assert_eq!(route("/denied", ""), Some(Route::Denied));
        // The access check is a section of the two pages that hold half of its question, and
        // no longer a page: it has no route to bookmark, and asking for its old one 404s
        // rather than landing anywhere that answers a different question.
        assert_eq!(route("/can", ""), None);
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
        // An application's page, because that is where a query worth keeping lives now: the
        // two fields of its access check.
        let app = Route::App("mpa".to_string());
        assert_eq!(
            preference_href(&cfg, &app, "email=bob%40x.com&lang=en", LANG_COOKIE),
            "/admin/apps/mpa?email=bob%40x.com"
        );
        // The other preference survives the first redirect, which is what lets one submit
        // set both: see the two checks in `handle`.
        assert_eq!(
            preference_href(&cfg, &app, "lang=en&theme=dark", LANG_COOKIE),
            "/admin/apps/mpa?theme=dark"
        );
        assert_eq!(
            preference_href(&cfg, &app, "lang=en&theme=dark", THEME_COOKIE),
            "/admin/apps/mpa?lang=en"
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
                &Route::App("mpa".to_string()),
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
        // hidden field is lost: an access-check verdict, and the flash the page is showing.
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
        assert_eq!(parse_theme("light"), Some(UiTheme::Light));
        assert_eq!(parse_theme("Dark"), Some(UiTheme::Dark));
        assert_eq!(parse_theme(" system "), Some(UiTheme::System));
        // an unrecognised value is not an error, just no preference expressed
        assert_eq!(parse_theme("blue"), None);
        assert_eq!(parse_theme(""), None);
    }

    #[test]
    fn negotiate_theme_prefers_query_then_cookie_then_system() {
        // query beats the cookie
        assert_eq!(negotiate_theme(Some("dark"), Some("light")), UiTheme::Dark);
        // cookie beats the default
        assert_eq!(negotiate_theme(None, Some("light")), UiTheme::Light);
        // System is the floor, with nothing expressed
        assert_eq!(negotiate_theme(None, None), UiTheme::System);
        // an unparseable preference is not a preference, so the next source still applies
        assert_eq!(negotiate_theme(Some("blue"), Some("dark")), UiTheme::Dark);
        assert_eq!(negotiate_theme(None, Some("blue")), UiTheme::System);
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
        assert_eq!(UiTheme::Light.attr(), Some("light"));
        assert_eq!(UiTheme::Dark.attr(), Some("dark"));
        assert_eq!(UiTheme::System.attr(), None);
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
        v.theme = UiTheme::Dark;
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
        v.theme = UiTheme::Dark;
        let html = shell(&v, "t", html! { "x" }).into_string();
        assert!(html.contains(r#"<option value="it" selected>"#), "{html}");
        assert!(html.contains(r#"<option value="dark" selected>"#), "{html}");
        assert_eq!(html.matches(" selected>").count(), 2, "{html}");
    }

    #[test]
    fn every_small_control_is_a_pill_of_the_same_family() {
        // The rule the CSS states in prose: nothing at a call site decides how a pill looks,
        // and every small control is in the family, the way back and the Settings trigger
        // included.
        let app = render("pill-app", Route::App("mpa".into()));
        assert!(
            app.contains(r#"<a class="pill" href="/apps">"#),
            "the way back is a pill, not prose: {app}"
        );
        // Three different structures sit in that bar (the nav's tabs, a `details`' summary,
        // and a bare child), and every one of them must be the same object with the same
        // click area. The size rule therefore selects the CONTAINER and not the three
        // structures: a list of them is a list that can miss one, which is what it did.
        assert!(
            CSS.contains(".bar .pill,"),
            "every pill in the header shares one size rule, named by the bar and not one by one"
        );
        assert!(
            !CSS.contains("details.settings>summary.pill,"),
            "and no rule may go back to naming them one at a time"
        );
        // Same size is only half of "the same object": the other half is the same STRUCTURE,
        // because a flex container blockifies its children and an inline-flex box left on a
        // text baseline answers a click over its line box rather than over the rectangle a
        // person can see. So every pill in the header is a flex item of a `nav` — the tabs in
        // theirs, Preferences and Sign out in `nav.acct`. The summary is the one that cannot
        // be moved (it must stay inside its `details`), so the CSS makes that `details` a
        // flex container instead, which blockifies it the same way.
        assert!(
            app.contains(r#"<nav class="acct">"#),
            "the account controls share one flex row: {app}"
        );
        assert!(
            CSS.contains("details.settings{display:flex"),
            "and the Settings trigger is blockified by its own details"
        );
        assert!(
            app.contains(r#"<summary class="pill">"#),
            "and carry the class that rule selects: {app}"
        );
        // The footer never tells anybody to reload: `bb-auth-reload.path` does it.
        assert!(!app.contains("systemctl reload"), "{app}");
    }

    #[test]
    fn sign_out_is_in_the_bar_when_configured_and_absent_when_not() {
        let html = render("signout", Route::Dashboard);
        assert!(
            html.contains(r#"<a class="pill" href="/auth/logout">Sign out</a>"#),
            "{html}"
        );
        // To the RIGHT of the preferences menu, and the same object as everything else in
        // the bar. Both are easy to get wrong and neither shows up in any other assertion:
        // the order is DOM order, and the size comes from the bar's own rule, which is why
        // that rule selects the bar rather than listing the shapes inside it.
        let (settings_at, signout_at) = (
            html.find("details class=\"settings\"")
                .or(html.find("<details class=\"settings\"")),
            html.find(r#"<a class="pill" href="/auth/logout">"#),
        );
        assert!(
            settings_at < signout_at,
            "Sign out must come after the menu: {html}"
        );
        assert!(
            CSS.contains(".bar .pill,"),
            "and share the header's size step, which reaches it for being IN the bar"
        );

        // A logout URL carrying the gate's `?rd=` reaches the href intact, which is the whole
        // of "sign out and come back here": the operator states the round trip in one value
        // and this GUI neither parses it nor adds to it. The `&` an rd with two parameters
        // would carry comes out escaped, because it is emitted as an attribute and maud
        // escapes attributes; that is why this asserts on the rendered string.
        let path = scratch("signout-rd", SAMPLE);
        let mut cfg = cfg_for(&path, "");
        cfg.logout_url =
            Some("/auth/logout?rd=https%3A%2F%2Fauth.example.com%2Fadmin%2F".to_string());
        let (doc, access) = open_access_file(&cfg.access_path).unwrap();
        let v = view(&cfg, Route::Dashboard, "REV");
        let html = shell(&v, "t", page_dashboard(&v, &doc, &access)).into_string();
        assert!(
            html.contains(r#"href="/auth/logout?rd=https%3A%2F%2Fauth.example.com%2Fadmin%2F""#),
            "{html}"
        );
        cleanup(&path);

        // Unset means no control at all, rather than a guess: this GUI speaks plain HTTP on
        // loopback and knows neither its scheme nor its host, and the one thing it is handed
        // is a client-supplied `Host`. A dead or attacker-chosen link is worse than none.
        let path = scratch("signout-off", SAMPLE);
        let mut cfg = cfg_for(&path, "");
        cfg.logout_url = None;
        let (doc, access) = open_access_file(&cfg.access_path).unwrap();
        let v = view(&cfg, Route::Dashboard, "REV");
        let html = shell(&v, "t", page_dashboard(&v, &doc, &access)).into_string();
        // The anchor, not the words: `CSS` is emitted inline on every page and its comments
        // name the control, so a text search finds it whether or not anything is rendered.
        assert!(!html.contains(r#"href="/auth/logout""#), "{html}");
        cleanup(&path);
    }

    /// The policy names the page's own bytes by hash, so the two have to *be* the same bytes.
    ///
    /// A nonce cannot be wrong: it is generated and emitted in one breath. A hash can, and
    /// silently: add a fourth constant to the `<style>` block, or a separator between the
    /// three, and the browser refuses to apply the whole stylesheet while every test that
    /// reads HTML goes on passing. This is what stands between that and a deployment
    /// discovering it as an unstyled admin interface.
    #[test]
    fn the_policy_hashes_the_bytes_the_page_actually_carries() {
        let html = render("csp-style", Route::Dashboard);
        let open = html.find("<style>").expect("the built-in stylesheet");
        let close = html.find("</style>").expect("a closed style element");
        let inline = &html[open + "<style>".len()..close];
        let csp = admin_csp(&Look::default());
        assert!(
            csp.contains(&csp_hash(inline)),
            "style-src must name the hash of the bytes in the page"
        );
        // And the one handler, by the hash the policy allows it under.
        assert!(csp.contains(&csp_hash(SETTINGS_ONCHANGE)), "{csp}");
        assert!(
            csp.contains("'unsafe-hashes'"),
            "an attribute handler needs it: {csp}"
        );
        // Nothing else may run, load or be framed.
        assert!(csp.starts_with("default-src 'none';"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(csp.contains("form-action 'self'"), "{csp}");
    }

    #[test]
    fn the_page_carries_one_handler_and_no_script() {
        // The invariant is not "no JavaScript": it is that no page may *need* a script. One
        // inline handler is allowed to save a click on the Settings list boxes; anything
        // else (a `<script>` tag, a second kind of handler, a `javascript:` href) would be a
        // page that stops working when scripting is off, which this GUI must never be.
        //
        // Every page shape, over a socket, and an allowlist rather than a blacklist. The
        // previous version rendered four read-only pages and looked for six named handlers,
        // which says nothing about `onmouseover` anywhere, `onchange` on a seventh element,
        // or any of the eighteen form pages it could not render at all: it could only find
        // the mistakes somebody had already thought of. The browser suite (`e2e/nojs.js`)
        // has enumerated attributes this way all along, and it runs on a machine with a
        // browser, which no automated run of this repository's has.
        let path = scratch("nojs-all", SAMPLE);
        let served = cfg_for(&path, "");
        let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
        let port = server.server_addr().to_ip().expect("an ip address").port();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &served);
            }
        });

        for at in every_route() {
            let mut r = client()
                .get(format!("http://127.0.0.1:{port}{}", at.path()))
                .header(IDENTITY_HEADER, "admin@x.com")
                .call()
                .expect("a response");
            assert_eq!(r.status(), 200, "{at:?}");
            let html = r.body_mut().read_to_string().unwrap();
            assert!(!html.contains("<script"), "a script tag on {at:?}");
            assert!(
                !html.contains("javascript:"),
                "a javascript: href on {at:?}"
            );

            for h in handlers_in(&html) {
                assert_eq!(
                    h,
                    format!("onchange=\"{SETTINGS_ONCHANGE}\""),
                    "the only handler this GUI may carry is the Settings list box's, and \
                     {at:?} carries {h}"
                );
            }
            // The two Settings list boxes carry it, and the way through without a script is
            // on the page, inside <noscript>.
            assert_eq!(handlers_in(&html).len(), 2, "on {at:?}");
            assert!(
                html.contains("<noscript><div class=\"actions\"><button>"),
                "the no-script submit must be there, and inside noscript: {at:?}"
            );
        }
        cleanup(&path);
    }

    /// Every `on…="…"` attribute in `html`, found by scanning rather than by name: an
    /// allowlist can only be checked against the attributes that are actually there.
    fn handlers_in(html: &str) -> Vec<String> {
        let bytes = html.as_bytes();
        let mut out = Vec::new();
        for (i, _) in html.match_indices(" on") {
            let rest = &html[i + 3..];
            let name_len = rest.bytes().take_while(|b| b.is_ascii_lowercase()).count();
            if name_len == 0 || bytes.get(i + 3 + name_len) != Some(&b'=') {
                continue; // " once", " only", prose: not an attribute
            }
            let value = rest[name_len + 1..]
                .strip_prefix('"')
                .and_then(|v| v.split('"').next())
                .unwrap_or("");
            out.push(format!("on{}=\"{value}\"", &rest[..name_len]));
        }
        out
    }

    /// Does [`every_route`] still name every page there is?
    ///
    /// The `match` is the check and the compiler is what runs it: it is exhaustive, so a new
    /// `Route` variant does not compile until somebody has looked at this list, and the
    /// count then says whether they added it to `every_route` as well. Without this, the
    /// no-script guarantee quietly stops covering the newest page, which is the page most
    /// likely to have reached for a script.
    #[test]
    fn every_route_covers_every_variant() {
        fn variant(at: &Route) -> usize {
            match at {
                Route::Dashboard => 0,
                Route::Apps => 1,
                Route::App(_) => 2,
                Route::Denied => 3,
                Route::Users => 4,
                Route::User(_) => 5,
                Route::Config => 6,
                Route::AppAdd => 7,
                Route::AppEdit(_) => 8,
                Route::AppRm(_) => 9,
                Route::ScopeAdd(_) => 10,
                Route::ScopeEdit(_, _) => 11,
                Route::ScopeRm(_, _) => 12,
                Route::ScopeMove(_, _) => 13,
                Route::UserAdd => 14,
                Route::UserEdit(_) => 15,
                Route::UserRm(_) => 16,
                Route::EmailAdd(_) => 17,
                Route::EmailRm(_, _) => 18,
                Route::KeyAdd(_) => 19,
                Route::KeyEdit(_, _) => 20,
                Route::KeyRotate(_, _) => 21,
                Route::KeyRm(_, _) => 22,
                Route::GroupAdd => 23,
                Route::GroupEdit(_) => 24,
                Route::GroupRm(_) => 25,
                Route::DenyAdd => 26,
                Route::DenyRm(_) => 27,
            }
        }
        let seen: std::collections::HashSet<usize> = every_route().iter().map(variant).collect();
        // All of them but `ScopeMove`, which has no page to render: it is POST only.
        let missing: Vec<usize> = (0..=27).filter(|i| !seen.contains(i)).collect();
        assert_eq!(missing, vec![13], "every_route must name every page");
    }

    /// One of every page shape this GUI serves, for the tests that must hold on all of them.
    ///
    /// Written out rather than derived, because `Route` carries names and a derived list
    /// would have to invent them; the pairing is kept honest by
    /// `every_route_covers_every_variant`, which fails the day a variant is added.
    fn every_route() -> Vec<Route> {
        let bob = BOB.to_string();
        vec![
            Route::Dashboard,
            Route::Apps,
            Route::App("mpa".to_string()),
            Route::Denied,
            Route::Users,
            Route::User(bob.clone()),
            Route::Config,
            Route::AppAdd,
            Route::AppEdit("mpa".to_string()),
            Route::AppRm("mpa".to_string()),
            Route::ScopeAdd("mpa".to_string()),
            Route::ScopeEdit("mpa".to_string(), "admin".to_string()),
            Route::ScopeRm("mpa".to_string(), "admin".to_string()),
            Route::UserAdd,
            Route::UserEdit(bob.clone()),
            Route::UserRm(bob.clone()),
            Route::EmailAdd(bob.clone()),
            Route::EmailRm(bob.clone(), "bob@x.com".to_string()),
            Route::KeyAdd(bob.clone()),
            Route::KeyEdit(bob.clone(), "laptop".to_string()),
            Route::KeyRotate(bob.clone(), "laptop".to_string()),
            Route::KeyRm(bob.clone(), "laptop".to_string()),
            Route::GroupAdd,
            Route::GroupEdit("admins".to_string()),
            Route::GroupRm("admins".to_string()),
            Route::DenyAdd,
            Route::DenyRm("spammer@x.com".to_string()),
            // `ScopeMove` is deliberately absent: it is the one route with no page at all,
            // POST only, and rendering it is not a thing that exists.
        ]
    }

    #[test]
    fn the_settings_menu_is_a_get_that_carries_the_rest_of_the_query() {
        // A GET, because it mutates nothing: every POST in this binary is a write to the
        // access file, guarded by the rev and the same-origin check, and a display
        // preference is neither.
        let cfg = cfg_for("x.json", "/admin");
        let mut v = view(&cfg, Route::App("mpa".to_string()), "REV");
        v.query = "email=bob%40x.com&lang=en&theme=dark";
        let html = shell(&v, "t", html! { "x" }).into_string();
        assert!(
            html.contains(r#"<form class="edit" method="get" action="/admin/apps/mpa">"#),
            "{html}"
        );
        // The access check's own fields survive the round trip; the two parameters the form
        // sets itself do not come back as hidden fields, or the list boxes could never
        // change them.
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
            theme: UiTheme::System,
            look: Look::default(),
            admin: Some("admin@x.com"),
            at,
            query: "",
            rev,
            msg: None,
            identity: vec![IDENTITY_HEADER.to_string()],
        }
    }

    /// Render one read-only page of `SAMPLE` and hand back the HTML.
    fn render(name: &str, at: Route) -> String {
        render_of(name, SAMPLE, at, "")
    }

    /// [`render`] with a query string and a fixture of its own: what a filter or a pager
    /// arrives as, since both live entirely in the URL.
    fn render_of(name: &str, fixture: &str, at: Route, query: &str) -> String {
        let path = scratch(name, fixture);
        let cfg = cfg_for(&path, "");
        let (doc, access) = open_access_file(&cfg.access_path).unwrap();
        let mut v = view(&cfg, at.clone(), "REV");
        v.query = query;
        let content = match &at {
            Route::Dashboard => page_dashboard(&v, &doc, &access),
            Route::Apps => page_apps(&v, &doc),
            Route::App(n) => page_app(&v, &doc, &access, n).1,
            Route::Denied => page_denied(&v, &doc),
            Route::Users => page_users(&v, &doc, &access),
            Route::User(e) => page_user(&v, &doc, &access, e).1,
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
    fn the_access_check_answers_on_both_pages_that_ask_it() {
        // A person's page asks with the identity fixed: one field, and the subject is the row
        // itself. The `mpa/admin` scope lists Bob through `@admins`, so the gate lets him in.
        let user = render_of(
            "check-user",
            SAMPLE,
            Route::User(BOB.to_string()),
            "url=https://app.x.com/mpa/admin/x",
        );
        assert!(user.contains("AUTHORIZED"), "{user}");
        assert!(user.contains("X-Auth-Email"), "{user}");
        assert!(
            !user.contains(r#"name="email""#),
            "the identity is the page, not a field: {user}"
        );

        // An application's page asks with both, and the same pair gets the same verdict: one
        // `decide`, two arrangements of the question.
        let app = render_of(
            "check-app",
            SAMPLE,
            Route::App("mpa".to_string()),
            "email=bob@x.com&url=https://app.x.com/mpa/admin/x",
        );
        assert!(app.contains("AUTHORIZED"), "{app}");
        assert!(app.contains(r#"name="email""#), "{app}");

        // And a refusal reads as one, on the page that can ask it: an anonymous client on a
        // restricted scope. The panel's own class is what carries that to the eye.
        let anon = render_of(
            "check-anon",
            SAMPLE,
            Route::App("mpa".to_string()),
            "url=https://app.x.com/mpa/admin/x",
        );
        assert!(anon.contains("DENIED"), "{anon}");
        assert!(anon.contains(r#"class="panel bad""#), "{anon}");
    }

    #[test]
    fn the_access_check_starts_on_the_area_it_is_asked_about() {
        // With nothing asked yet, the url field is prefilled with this application's own base:
        // an operator appends a path instead of retyping a host. And no verdict yet, because
        // nothing was asked.
        let html = render("check-empty", Route::App("mpa".to_string()));
        assert!(
            html.contains(r#"value="https://app.x.com/mpa""#),
            "the url field starts on the area: {html}"
        );
        assert!(
            !html.contains("AUTHORIZED") && !html.contains("DENIED"),
            "{html}"
        );
    }

    #[test]
    fn a_row_with_no_email_has_nothing_to_check() {
        // No identifier resolves to this row, so there is no question to ask: the section says
        // so instead of quietly testing the empty subject, which `decide` would read as
        // anonymous and answer about somebody else entirely.
        const NO_EMAIL: &str = r#"{ "version": 1,
          "applications": [],
          "users": [ { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b", "emails": [] } ]
        }"#;
        let html = render_of("check-noemail", NO_EMAIL, Route::User(BOB.to_string()), "");
        assert!(html.contains("no email"), "{html}");
        assert!(!html.contains(r#"name="url""#), "no form to submit: {html}");
    }

    #[test]
    fn the_users_page_leads_with_the_groups_section() {
        let html = render("groups", Route::Users);
        // The groups section is on the users page, and it is ABOVE the roster.
        let g = html.find("user_groups").expect("no user_groups section");
        let u = html.rfind(">users<").expect("no users section");
        assert!(g < u, "user_groups must come before users: {html}");
        assert!(html.contains("referenced by"));
        assert!(html.contains("mpa/admin"));
        // And it is not a tab of its own.
        assert!(
            !html.contains("href=\"/groups\""),
            "the nav must not offer a groups tab: {html}"
        );
    }

    /// A roster of `n` users, to have something worth paging.
    fn many_users(n: usize) -> String {
        let rows: Vec<String> = (0..n)
            .map(|i| {
                format!(
                    r#"{{ "uuid": "{i:08x}-0000-4000-8000-000000000000",
                          "emails": ["user{i:03}@x.com"] }}"#
                )
            })
            .collect();
        format!(
            r#"{{ "version": 1, "applications": [], "users": [{}] }}"#,
            rows.join(",")
        )
    }

    #[test]
    fn a_list_filters_and_pages_with_nothing_but_the_query_string() {
        let big = many_users(PAGE_SIZE + 5);

        // Page one: the first PAGE_SIZE rows, and a pager offering the second.
        let html = render_of("pg1", &big, Route::Users, "");
        assert!(html.contains("user000@x.com"), "{html}");
        assert!(
            !html.contains("user025@x.com"),
            "page 1 must stop at the size"
        );
        assert!(html.contains("up=2"), "a next-page link: {html}");

        // Page two, asked for the way a link asks: 1-based, in the URL.
        let html = render_of("pg2", &big, Route::Users, "up=2");
        assert!(html.contains("user025@x.com"), "{html}");
        assert!(!html.contains("user000@x.com"));

        // The filter narrows, and the pager goes away when one page is enough.
        let html = render_of("pg3", &big, Route::Users, "uq=user01");
        assert!(html.contains("user010@x.com"));
        assert!(!html.contains("user020@x.com"));
        assert!(!html.contains("up=2"), "10 rows need no pager: {html}");

        // A filter that matches nothing says so, rather than looking like an empty file.
        let html = render_of("pg4", &big, Route::Users, "uq=nobodyatall");
        assert!(html.contains("matches that filter"), "{html}");

        // And none of it needs scripting.
        assert!(!html.contains("<script"), "{html}");
    }

    #[test]
    fn each_list_on_the_users_page_filters_on_its_own() {
        // Three lists, three namespaces: filtering the roster must not touch the groups.
        let html = render_of("ns", SAMPLE, Route::Users, "uq=nowhere");
        // The per-row Remove action is what only the roster table renders, so it is what
        // distinguishes "in the table" from "mentioned elsewhere on the page".
        assert!(html.contains("/users/11111111-1111-1111-1111-111111111111/rm"));
        assert!(
            !html.contains("/users/8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b/rm"),
            "the roster row for bob is filtered out: {html}"
        );
        // Bob is still on the page, in the groups section, which this filter never touched.
        assert!(html.contains("@admins"), "the groups list is not: {html}");
        assert!(html.contains("bob@x.com"), "as a group member: {html}");
        assert!(html.contains("spammer@x.com"), "nor is denied: {html}");
    }

    #[test]
    fn the_apps_list_says_which_credentials_get_in() {
        let html = render("appcreds", Route::Apps);
        // mpa/admin is restricted with no `credentials` field, which means BOTH — the one
        // default a reader can get wrong, so the column spells it out.
        assert!(html.contains("login, api_key"), "{html}");
    }

    #[test]
    fn a_scope_shows_its_credentials_and_its_exclusions() {
        let fixture = SAMPLE.replace(
            r#""groups": ["@admins"], "notes": "the admin area""#,
            r#""groups": ["@admins"], "excluded": ["nowhere@x.com"], "notes": "the admin area""#,
        );
        let html = render_of("scopeblock", &fixture, Route::App("mpa".into()), "");
        assert!(html.contains("excluded"), "{html}");
        assert!(html.contains("nowhere@x.com"), "{html}");
        assert!(html.contains("login, api_key"), "{html}");
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
        let json = r#"{ "version": 1, "users": [
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
            r#"{ "version": 1, "applications": [
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
        // Back to the users page, which is where the group list lives.
        assert_eq!(got.location(), "/users?msg=group-removed");
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
    fn a_scope_form_writes_and_refuses_exclusions() {
        let path = scratch("m-excl", TWO_SCOPES);
        let cfg = cfg_for(&path, "");

        // An enrolled person becomes their uuid; a stranger stays their email, which is
        // the only exclusion an `authenticated` scope can have.
        let got = post(
            &cfg,
            Route::ScopeEdit("app1".to_string(), "second".to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("name", "second"),
                ("urls", "https://app.x.com/b/*"),
                ("access", "authenticated"),
                ("excluded", "bob@x.com\nstranger@x.com"),
            ],
        );
        assert_eq!(got.location(), "/apps/app1?msg=scope-saved");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        assert_eq!(
            doc.applications[0].scopes[1].excluded.as_deref(),
            Some(&[BOB.to_string(), "stranger@x.com".to_string()][..])
        );

        // And the form refuses the one kind that cannot mean anything, out loud, with the
        // field named so it renders invalid.
        let before = read(&path);
        let got = post(
            &cfg,
            Route::ScopeEdit("app1".to_string(), "second".to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("name", "second"),
                ("urls", "https://app.x.com/b/*"),
                ("access", "anonymous"),
                ("excluded", "bob@x.com"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        assert!(html.contains("no credential at all"), "{html}");
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

    /// Which pages wear the deployment's look, and which cannot.
    ///
    /// The refusals are pages of the same installation as every other, so an administrator's
    /// colleague who is not on `web.admins` must not be told so in a palette nobody
    /// recognises. The two that render *before* the settings are read are the exception, and
    /// not a lapse: the file that would describe another look is the file that is missing or
    /// broken, so the built-in one is the only honest answer they have.
    #[test]
    fn a_refusal_wears_the_deployment_look_once_the_settings_can_be_read() {
        let path = scratch("look-403", SAMPLE);
        // A settings file that names an administrator AND a stylesheet, which is what a
        // deployment that has configured its look looks like.
        std::fs::write(
            settings_path(&path),
            r#"{ "version": 1, "web": { "admins": ["admin@x.com"] },
                 "ui": { "stylesheet_url": "https://assets.example.com/tokens.css" } }"#,
        )
        .unwrap();
        let served = cfg_for(&path, "");
        let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
        let port = server.server_addr().to_ip().expect("an ip address").port();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &served);
            }
        });
        let at = |p: &str| format!("http://127.0.0.1:{port}{p}");
        const LINK: &str =
            r#"<link rel="stylesheet" href="https://assets.example.com/tokens.css">"#;

        // Authenticated, not an administrator: the settings were read to find that out, so
        // the page they are refused with is the one this deployment asked for.
        let mut r = client()
            .get(at("/"))
            .header(IDENTITY_HEADER, "someone@x.com")
            .call()
            .expect("a response");
        assert_eq!(r.status(), 403);
        let csp = r
            .headers()
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let body = r.body_mut().read_to_string().unwrap();
        assert!(
            body.contains(LINK),
            "the 403 must carry the operator's stylesheet"
        );
        assert!(
            csp.contains("https://assets.example.com"),
            "and the policy must admit it: {csp}"
        );

        // The administrator's own page, for contrast: same look, which is the point.
        let mut r = client()
            .get(at("/"))
            .header(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("a response");
        assert_eq!(r.status(), 200);
        assert!(r.body_mut().read_to_string().unwrap().contains(LINK));

        // And the one that cannot: no identity header at all is answered above the settings
        // read, so it wears the built-in look and links nothing.
        let mut r = client().get(at("/")).call().expect("a response");
        assert_eq!(r.status(), 401);
        assert!(
            !r.body_mut().read_to_string().unwrap().contains("<link"),
            "a page rendered before the settings are read may link nothing"
        );

        // Nor can the page that exists BECAUSE the settings are unreadable.
        std::fs::write(settings_path(&path), "{ not json").unwrap();
        let mut r = client()
            .get(at("/"))
            .header(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("a response");
        assert_eq!(r.status(), 500);
        assert!(!r.body_mut().read_to_string().unwrap().contains("<link"));
        cleanup(&path);
    }

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
        let mut r = client().get(at("/")).call().expect("a response");
        assert_eq!(r.status(), 401);
        assert!(r
            .body_mut()
            .read_to_string()
            .unwrap()
            .contains("auth_request"));

        // Authenticated, but not on the allowlist.
        let mut r = client()
            .get(at("/"))
            .header(IDENTITY_HEADER, "someone@x.com")
            .call()
            .expect("a response");
        assert_eq!(r.status(), 403);
        assert!(r
            .body_mut()
            .read_to_string()
            .unwrap()
            .contains("someone@x.com"));

        // An administrator gets the dashboard, in the configured language.
        let mut r = client()
            .get(at("/"))
            .header(IDENTITY_HEADER, "Admin@X.com") // normalised, so capitalisation is fine
            .call()
            .expect("a response");
        assert_eq!(r.status(), 200);
        let body = r.body_mut().read_to_string().unwrap();
        assert!(
            body.contains("user_groups") && body.contains("Warnings"),
            "{body}"
        );
        // And an unknown path is a 404, not a fall-through to the dashboard.
        let r = client()
            .get(at("/nope"))
            .header(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("a response");
        assert_eq!(r.status(), 404);
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
        let agent = client();
        let post = || agent.post(&url).header(IDENTITY_HEADER, "admin@x.com");

        // The confirmation page is a GET, and a GET changes nothing.
        let before = read(&path);
        let mut r = client()
            .get(&url)
            .header(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("a response");
        assert_eq!(r.status(), 200);
        let page = r.body_mut().read_to_string().unwrap();
        assert!(
            page.contains("denied is for"),
            "the consequence is spelled out"
        );
        assert_eq!(read(&path), before, "a GET never mutates");
        let rev = rev_in(&page);
        assert_eq!(rev, rev_of(&path));

        // The identity header and the allowlist guard a POST exactly as they guard a GET:
        // they are above the router, so no method reaches a mutation without them.
        let r = agent
            .post(&url)
            .header("Sec-Fetch-Site", "same-origin")
            .send_form([("rev", rev.as_str())])
            .expect("a response");
        assert_eq!(r.status(), 401, "no identity header");
        let mut r = agent
            .post(&url)
            .header(IDENTITY_HEADER, "someone@x.com")
            .header("Sec-Fetch-Site", "same-origin")
            .send_form([("rev", rev.as_str())])
            .expect("a response");
        assert_eq!(r.status(), 403, "a non-admin POST");
        assert!(r
            .body_mut()
            .read_to_string()
            .unwrap()
            .contains("someone@x.com"));
        assert_eq!(read(&path), before, "neither may have written anything");

        // No Sec-Fetch-Site and no Origin: not a browser posting a form.
        let mut r = post()
            .send_form([("rev", rev.as_str())])
            .expect("a response");
        assert_eq!(r.status(), 403);
        assert!(r
            .body_mut()
            .read_to_string()
            .unwrap()
            .contains("same-origin"));
        assert_eq!(read(&path), before);

        // Cross-site is a refusal too, whatever the Origin claims.
        let r = post()
            .header("Sec-Fetch-Site", "cross-site")
            .header("Origin", format!("http://127.0.0.1:{port}"))
            .send_form([("rev", rev.as_str())])
            .expect("a response");
        assert_eq!(r.status(), 403);
        assert_eq!(read(&path), before);

        // Same-origin, current rev: it happens, and answers a 303 under the base path.
        let resp = post()
            .header("Sec-Fetch-Site", "same-origin")
            .send_form([("rev", rev.as_str())])
            .expect("a response");
        assert_eq!(resp.status(), 303);
        assert_eq!(
            resp.headers().get("location").map(|v| v.to_str().unwrap()),
            Some("/admin/users?msg=user-removed")
        );
        let after = read(&path);
        assert!(!after.contains("Bob@X.com"), "bob is gone: {after}");

        // The browser still holds the old rev — a resubmission cannot repeat the deed.
        let mut r = post()
            .header("Sec-Fetch-Site", "same-origin")
            .send_form([("rev", rev.as_str())])
            .expect("a response");
        assert_eq!(r.status(), 409);
        assert!(r
            .body_mut()
            .read_to_string()
            .unwrap()
            .contains("The file changed"));
        assert_eq!(read(&path), after);

        // And the redirect target renders the banner it was sent with.
        let mut r = client()
            .get(format!(
                "http://127.0.0.1:{port}/admin/users?msg=user-removed"
            ))
            .header(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("a response");
        assert_eq!(r.status(), 200);
        let landed = r.body_mut().read_to_string().unwrap();
        assert!(landed.contains("user removed"), "{landed}");
        cleanup(&path);
    }
}
