//! bb-auth-me: the self-service page a signed-in person uses for **their own** account
//! (docs/ARCHITECTURE.md §13). It opens the two files the estate shares, works out who nginx is
//! vouching for, and answers that person with a page about their own account: where they reach,
//! the groups they are filed in, their API keys and the profile claims the proxy forwards. The
//! Cognito leg (editing a profile at the pool) is the next step, so what is here is **read
//! only**: the one form the page carries is a display preference, which writes a cookie and
//! nothing else, so there is no write and nothing that can lock anybody out.
//!
//! The trust model is `bb-auth-web`'s, unchanged: **just another application bb-auth fronts**.
//! It binds loopback, speaks plain HTTP behind a TLS-terminating nginx, and takes its identity
//! from the [`IDENTITY_HEADER`] header nginx injects and from nowhere else. It validates no
//! token, mints no cookie and holds no secret, so there is no credential here to steal.
//!
//! A missing header is a `401` and not an anonymous visitor: this location is gated, so a
//! header that is not there is a deployment that forgot its `proxy_set_header`, and a page
//! about "nobody" would turn that into a silent open door.
//!
//! `web.admins` is **not** read: an administrator is one more person here, and the access file
//! covers this URL with an `authenticated` scope, so a stranger Cognito vouches for is a real
//! caller rather than a defensive case (§13.4).

use bb_auth_core::{
    csp_hash, default_settings_path, format_date, norm_email, open_access_file, open_settings_file,
    page_csp, stylesheet_link, version_line, Access, AccessFile, ApiKeyRecord, AppRecord,
    ScopeRecord, Settings, UiTheme, BASE_CSS, IDENTITY_HEADER, PAGE_SECURITY_HEADERS, THEME_CSS,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use tiny_http::{Header, Request, Response, Server, StatusCode};

/// The request threads, mirroring `bb-auth-web`: `tiny_http` is blocking, so one thread per
/// in-flight request is what keeps a page that is reading two files from holding the port.
const WORKERS: usize = 2;

/// How long a preference cookie lives. Copied from `bb-auth-web`, and the same number there
/// matters: a person who chose dark in the admin console and reaches this page on the same
/// host gets dark, because both programs write the same cookie with the same life.
const PREFERENCE_COOKIE_MAX_AGE: i64 = 31_536_000;

/// Cookie remembering the language choice. Copied from `bb-auth-web`, name included: the
/// console writes this one, so a choice made there carries here without either program knowing
/// about the other. It carries no identity and no capability, so it is not `Secure`: this
/// binary speaks plain HTTP on loopback and cannot know the scheme the browser used, and a
/// display preference is not worth a flag that would be a lie about half the deployments.
const LANG_COOKIE: &str = "lang";

/// Cookie remembering the theme choice. Same reasoning as [`LANG_COOKIE`], and the same name as
/// the console's, for the same reason.
const THEME_COOKIE: &str = "theme";

/// `BB_AUTH_ME_LISTEN`, `BB_AUTH_ACCESS_FILE`, `BB_AUTH_SETTINGS_FILE`, `BB_AUTH_ME_BASE_PATH`.
struct Config {
    listen: String,
    access_path: String,
    settings_path: String,
    /// The prefix nginx mounts this at. Carried from the env file now because the env contract
    /// is fixed by §13.2. The startup banner prints it, and the page resolves its one URL
    /// against it: the preference form's `action` and the target of a preference redirect are
    /// both this plus `/`.
    base_path: String,
}

/// Read an env var, falling back to `default` when unset. A copy of `bb-auth-web`'s, which is
/// private there, and moving it is out of scope for this step.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Config {
    /// Build the config from the environment. Nothing here is fatal on a missing value: the
    /// defaults are the packaged ones, and a fatal startup under `Restart=on-failure` is a boot
    /// loop, which is why the settings path is derived rather than required.
    fn from_env() -> Config {
        let access_path = env_or("BB_AUTH_ACCESS_FILE", "access.json");
        let settings_path = std::env::var("BB_AUTH_SETTINGS_FILE")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .unwrap_or_else(|| default_settings_path(&access_path));
        Config {
            listen: env_or("BB_AUTH_ME_LISTEN", "127.0.0.1:8092"),
            access_path,
            settings_path,
            base_path: env_or("BB_AUTH_ME_BASE_PATH", ""),
        }
    }
}

/// Is this listen address on the loopback interface? A copy of `bb-auth-web`'s, which is
/// private there, and moving it is out of scope for this step.
///
/// Textual on purpose: the value is a `host:port` string handed to `Server::http`, and what
/// matters is what an operator wrote in the env file. An unresolvable name is not loopback as
/// far as this is concerned, which errs towards refusing.
fn listen_is_loopback(listen: &str) -> bool {
    let host = match listen.rsplit_once(':') {
        // `[::1]:8092`, the only shape where the last colon is not the port separator's.
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => listen,
    };
    let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// An env var read as a deliberate yes: `1`, `true`, `yes`, in any case. Anything else,
/// including the variable being absent, is no. A copy of `bb-auth-web`'s, which is private
/// there, and moving it is out of scope for this step.
fn env_flag(key: &str) -> bool {
    matches!(
        env_or(key, "").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

/// The languages this binary carries. Two, and the shape is `bb-auth-web`'s so that adding a
/// third is an arm in [`m`] and nothing else, and so that a key nobody translated is a compile
/// error rather than a fallback.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lang {
    En,
    It,
}

impl Lang {
    /// The `lang=` attribute, the cookie value and the query parameter value: one spelling.
    fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::It => "it",
        }
    }

    /// How the language names itself, for its option in the selector. A language menu that
    /// translated its own entries would hide the one a person is looking for behind the
    /// language they cannot read, which is the one case where translating is the bug. Copied
    /// from `bb-auth-web` for that reason, and not because the two lists must agree.
    fn name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::It => "Italiano",
        }
    }
}

/// Parse a language name, from the query or the cookie. `None` for anything else: an unknown
/// value is simply not a preference, and nothing is remembered for it. Copied from
/// `bb-auth-web`.
fn parse_lang(s: &str) -> Option<Lang> {
    match s.trim().to_ascii_lowercase().as_str() {
        "en" => Some(Lang::En),
        "it" => Some(Lang::It),
        _ => None,
    }
}

/// What the selector offers, which is not the same set as [`Lang`]: `Auto` is the choice to
/// make no choice, and it resolves per request against the browser's `Accept-Language` (see
/// [`negotiate_lang`]). Copied from `bb-auth-web`, with the reason it needs a type of its own:
/// [`Lang`] has to stay the two the table actually holds, because every string on the page is
/// looked up by one, so `Auto` could never travel that far.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LangPref {
    Auto,
    Fixed(Lang),
}

impl LangPref {
    /// The cookie value and the query parameter value: one spelling, and for a fixed choice it
    /// is [`Lang::code`]'s own, so `?lang=it` still means exactly what it always meant.
    fn code(self) -> &'static str {
        match self {
            LangPref::Auto => "auto",
            LangPref::Fixed(l) => l.code(),
        }
    }

    /// The label its option in the selector shows, rendered in `lang`. Only `Auto` is
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

/// The three appearances a page can render in are [`UiTheme`], the library's, and not a second
/// enum here saying the same three words: the settings file names a theme, this binary and the
/// console both stamp it onto `html` as `data-theme`, and one selector in [`THEME_CSS`] keys off
/// it. Copied from `bb-auth-web`, where the argument is made in full. What stays local is the
/// label an option shows, which is prose about the page and so translates.
fn theme_label(theme: UiTheme) -> K {
    match theme {
        UiTheme::Light => K::ThemeLight,
        UiTheme::Dark => K::ThemeDark,
        UiTheme::System => K::ThemeSystem,
    }
}

/// Parse a theme name out of the query or the cookie, where **empty means no choice** rather
/// than `System`, copied from `bb-auth-web`: a cookie whose value is blank has not said anything
/// at all, and must fall back exactly as a missing cookie does, so that a deployment's own
/// default still applies. `None` for an unrecognised value, for the same reason.
fn parse_theme(s: &str) -> Option<UiTheme> {
    match s.trim() {
        "" => None,
        v => UiTheme::parse(v),
    }
}

/// Which theme to render in. Query, then cookie, then `UiTheme::System`: most explicit wins,
/// and `System` is the floor rather than a configured default, since there is nothing to
/// configure; it is what every session already has until it chooses otherwise. Copied from
/// `bb-auth-web`, and [`shell`] is where it falls through to the deployment's own default.
fn negotiate_theme(query: Option<&str>, cookie: Option<&str>) -> UiTheme {
    if let Some(t) = query.and_then(parse_theme) {
        return t;
    }
    if let Some(t) = cookie.and_then(parse_theme) {
        return t;
    }
    UiTheme::System
}

/// The preference in force and the language it renders as. Query, then cookie, then
/// `Accept-Language`, then English: most explicit wins. Copied from `bb-auth-web`, and the
/// reason both halves come back is the reason it has there: the [`Lang`] looks every string up,
/// while the [`LangPref`] is which option the selector must show as chosen, and `Auto` and `en`
/// can render the identical page while being different answers to that one.
///
/// The `Accept-Language` check is deliberately crude: does the header start with `it`? A full
/// RFC 4647 negotiation over two languages would be more code than the question is worth, and
/// both wrong answers are one choice in the list from being right (and then remembered).
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

/// A string the page displays. An enum rather than a literal so [`t`]'s match is **exhaustive**:
/// a key added without its text does not fall back at runtime, it fails to compile.
///
/// What is deliberately absent is anything that is data rather than prose: an email, a uuid, a
/// header name, a setting name, and the library's own error sentences, which are shown verbatim
/// because the operator who can fix the file is the person reading them.
#[derive(Clone, Copy)]
enum K {
    Title,
    SignedInAs,
    Uuid,
    NoRow,
    NoIdentityTitle,
    NoIdentityBody,
    NoEmailTitle,
    NoEmailBody,
    DeniedTitle,
    DeniedBody,
    AmbiguousTitle,
    AmbiguousBody,
    SettingsTitle,
    AccessTitle,
    ReachTitle,
    GroupsTitle,
    KeysTitle,
    ProfileTitle,
    Nothing,
    KeyNever,
    KeyAllScopes,
    Language,
    Theme,
    LangAuto,
    Apply,
    ThemeLight,
    ThemeDark,
    ThemeSystem,
}

/// Pick one of a key's spellings. The match is what makes adding a language a compile-time
/// checklist, and every key carries both spellings: this is the page a person reaches when
/// something is already wrong, so the strings are compiled in and nothing is fetched.
fn m(lang: Lang, en: &'static str, it: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::It => it,
    }
}

/// The translation table. No logic reads these strings: they are what a person is told, and a
/// decision that depended on one would change with the language.
fn t(lang: Lang, key: K) -> &'static str {
    match key {
        K::Title => m(lang, "Your account", "Il tuo account"),
        K::SignedInAs => m(lang, "Signed in as", "Accesso come"),
        K::Uuid => m(lang, "Your account id", "Il tuo id account"),
        K::NoRow => m(
            lang,
            "bb-auth has no roster row for this identity.",
            "bb-auth non ha una riga nella rubrica per questa identità.",
        ),
        K::NoIdentityTitle => m(lang, "No identity", "Nessuna identità"),
        K::NoIdentityBody => m(
            lang,
            "The proxy gated this page but sent no X-Auth-Email, so there is nobody to show a page about.",
            "Il proxy ha protetto questa pagina ma non ha inviato X-Auth-Email, quindi non c'è nessuno di cui mostrare una pagina.",
        ),
        K::NoEmailTitle => m(lang, "No email identity", "Nessuna identità email"),
        K::NoEmailBody => m(
            lang,
            "gate.identity_attrs does not list email, so nginx injects no X-Auth-Email and this page has no identity to act on.",
            "gate.identity_attrs non include email, quindi nginx non invia X-Auth-Email e questa pagina non ha un'identità su cui agire.",
        ),
        K::DeniedTitle => m(lang, "Refused", "Rifiutato"),
        K::DeniedBody => m(
            lang,
            "This identity is denied.",
            "Questa identità è negata.",
        ),
        K::AmbiguousTitle => m(
            lang,
            "More than one account",
            "Più di un account",
        ),
        K::AmbiguousBody => m(
            lang,
            "The identity header names accounts that are not the same person, so this page cannot say who it is about.",
            "L'header di identità nomina account che non sono la stessa persona, quindi questa pagina non può dire di chi parla.",
        ),
        K::SettingsTitle => m(
            lang,
            "Cannot read the settings",
            "Impossibile leggere le impostazioni",
        ),
        K::AccessTitle => m(
            lang,
            "Cannot read the access file",
            "Impossibile leggere il file di accesso",
        ),
        // The four section headings. Each is a noun naming what the list under it is, because
        // the page is read by a person looking for one of those four things.
        K::ReachTitle => m(lang, "Where you reach", "Dove puoi arrivare"),
        K::GroupsTitle => m(lang, "Groups", "Gruppi"),
        K::KeysTitle => m(lang, "API keys", "Chiavi API"),
        K::ProfileTitle => m(lang, "Profile", "Profilo"),
        // One word for all four empty sections. It stays one word on purpose: the sections
        // carry no prose, so a sentence here would be the one thing a test about a *name*
        // could match by accident.
        K::Nothing => m(lang, "None.", "Nessuno."),
        K::KeyNever => m(lang, "never", "mai"),
        K::KeyAllScopes => m(lang, "all scopes", "tutti gli scope"),
        // The selector's two labels, its submit button, and the options that are prose. The
        // language names itself (see [`Lang::name`]), so only `Auto` is translated here.
        K::Language => m(lang, "Language", "Lingua"),
        K::Theme => m(lang, "Theme", "Tema"),
        // Named after what decides when nobody has: the browser. "Auto" alone would leave a
        // person guessing what it follows.
        K::LangAuto => m(lang, "Auto (browser)", "Auto (browser)"),
        K::Apply => m(lang, "Apply", "Applica"),
        K::ThemeLight => m(lang, "Light", "Chiaro"),
        K::ThemeDark => m(lang, "Dark", "Scuro"),
        K::ThemeSystem => m(lang, "System", "Sistema"),
    }
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// What the deployment's `ui` section says a page should wear. `Look::default()` is "nothing
/// configured", and it is the honest answer on every page rendered **before** the settings file
/// has been read: the `401` and the settings `500` both happen above that read, and a page that
/// cannot know the operator's stylesheet shows the built-in one rather than guessing.
///
/// `theme` here is the **deployment's** default, kept beside the visitor's own choice rather
/// than folded into it, in `bb-auth-web`'s shape: the two answer different questions and both
/// have to survive to the page, since the selector must show `System` as chosen while the page
/// renders the dark the administrator asked for.
#[derive(Clone, Copy, Default)]
struct Look<'a> {
    /// `ui.theme`: which arm of the palette a page starts in when the visitor has expressed no
    /// preference of their own.
    theme: UiTheme,
    /// `ui.stylesheet_url`: an operator's own stylesheet, loaded after the built-in one.
    stylesheet: Option<&'a str>,
    /// `ui.logo_url`: needed for the policy, since it is the one image a page may fetch.
    logo: Option<&'a str>,
    /// `ui.brand_name`: the name the page calls this deployment. `None` is the binary's own
    /// name, which is what makes an unconfigured deployment look unconfigured rather than
    /// borrow somebody's brand.
    brand: Option<&'a str>,
}

/// What the page calls itself when `ui.brand_name` says nothing. The binary's own name, copied
/// from `bb-auth`'s `DEFAULT_BRAND` for the same reason.
const DEFAULT_BRAND: &str = "bb-auth-me";

/// This binary's **arrangement**: one centred card with a gutter at the sides, the brand above
/// it, and the preference row at the bottom. Emitted after [`THEME_CSS`] (the palette) and
/// [`BASE_CSS`] (the components), so it only says where things go, never what they are made of,
/// and it defines no colour of its own: every value is a palette token, which is what keeps
/// `ui.stylesheet_url` able to restyle this page and the other two programs at once.
///
/// It is a `const` in this file rather than a sixth asset because it is the arrangement of one
/// program's pages, which is exactly the thing `BASE_CSS` says a layout keeps to itself. It is
/// part of the [`csp_hash`] input in [`respond`], since it is emitted inside the one `style`
/// block the policy names.
const CSS: &str = "
body{display:flex;justify-content:center;padding:24px 16px}
main.card{width:100%;max-width:620px;margin:auto}
.brand{text-align:center;margin-bottom:18px}
.brand img{width:64px;height:64px;object-fit:contain;filter:var(--logo-filter)}
.brand .name{display:block;color:var(--muted);font-size:.92rem}
.prefs{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;margin-top:26px}
.prefs label{flex:1 1 150px}
.prefs button{flex:0 0 auto}
";

/// What the chrome needs that is not the page: this browser's two preferences, the language they
/// render as, and the prefix the selector form goes back to.
///
/// A struct rather than four more arguments because every page of this binary is answered through
/// [`respond`], and a preference that reached only some of them is a page whose selector shows
/// something other than what that page is rendered in.
struct Prefs<'a> {
    /// The language every string on the page is looked up by.
    lang: Lang,
    /// Which option the selector shows as the chosen language, which is not the same thing as
    /// `lang`: `Auto` renders as one of the two and must still come back as `Auto`.
    lang_pref: LangPref,
    /// Which appearance **this browser** asked for, `System` included. It is not on its own what
    /// the page renders in: [`shell`] falls through to [`Look::theme`] after it.
    theme: UiTheme,
    /// `BB_AUTH_ME_BASE_PATH`, normalised to have no trailing slash. The form's `action` and the
    /// target of a preference redirect are both this plus `/`.
    base: &'a str,
}

/// The chrome every page of this binary is wrapped in: the palette, the components built out of
/// it, this file's arrangement, then the operator's stylesheet, so an override wins by source
/// order and needs no `!important`.
fn shell(prefs: &Prefs, title: &str, content: Markup, look: Look) -> Markup {
    // The two list boxes' options, each in the order they are offered, both leading with the
    // choice that follows something outside this page (the OS, the browser), because that is
    // where every session starts and what the other options are departures from.
    let langs = [
        LangPref::Auto,
        LangPref::Fixed(Lang::En),
        LangPref::Fixed(Lang::It),
    ];
    let themes = [UiTheme::System, UiTheme::Light, UiTheme::Dark];
    let action = format!("{}/", prefs.base);
    html! {
        (DOCTYPE)
        // The theme, resolved here and in one expression, because the fallback order is the
        // rule: this browser's choice, then the deployment's default, then nothing at all.
        // `data-theme=[…]` is maud's optional-attribute form, so the `None` two `System`s
        // produce omits the attribute outright rather than emitting `data-theme=""`, which is
        // what leaves the `prefers-color-scheme` rule in `THEME_CSS` as the one deciding.
        html lang=(prefs.lang.code()) data-theme=[prefs.theme.attr().or(look.theme.attr())] {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { "bb-auth-me · " (title) }
                // The three deliberately raw emissions on the page, all three compile-time
                // constants and never request data. The order is the contract: the palette, the
                // components that read it (the same bytes the gate's pages and `bb-auth-web`
                // emit), then this binary's arrangement of them.
                style { (PreEscaped(THEME_CSS)) (PreEscaped(BASE_CSS)) (PreEscaped(CSS)) }
                // Raw because the library builds a whole `<link>` element from a URL that has
                // already passed `compile_asset_url`, and maud has no way to say "an element".
                (PreEscaped(stylesheet_link(look.stylesheet)))
            }
            body {
                main class="card" {
                    // The brand, and the logo only when the administrator set one: nothing
                    // configured means the page fetches no image at all. The `alt` is empty on
                    // purpose, because the name beside it already says what the picture is.
                    header class="brand" {
                        @if let Some(logo) = look.logo {
                            img src=(logo) alt="";
                        }
                        span class="name" { (look.brand.unwrap_or(DEFAULT_BRAND)) }
                    }
                    h1 { (title) }
                    (content)
                    // The selector: theme, then language, then a visible submit. A plain `GET`
                    // back to this same page, so a bookmark and a reload cannot change anything,
                    // and the button is not decoration: this binary emits no script and no
                    // handler, so picking an option is only half an interaction without it.
                    form class="prefs" method="get" action=(action) {
                        label {
                            span class="lbl" { (t(prefs.lang, K::Theme)) }
                            select name=(THEME_COOKIE) {
                                @for th in themes {
                                    option value=(th.code()) selected[th == prefs.theme] {
                                        (t(prefs.lang, theme_label(th)))
                                    }
                                }
                            }
                        }
                        label {
                            span class="lbl" { (t(prefs.lang, K::Language)) }
                            select name=(LANG_COOKIE) {
                                @for p in langs {
                                    option value=(p.code()) selected[p == prefs.lang_pref] {
                                        (p.label(prefs.lang))
                                    }
                                }
                            }
                        }
                        button { (t(prefs.lang, K::Apply)) }
                    }
                }
            }
        }
    }
}

/// Build a response header. Panics only on a caller-side bug; every call site passes a constant
/// or a value that is printable ASCII by construction.
fn h(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("valid header")
}

/// First request header matching `name`, compared case-insensitively.
fn header_value<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

/// Pull one cookie's value out of a `Cookie:` header. Copied from `bb-auth-web`, and it has to
/// be its own parse here: a header is a list of `name=value` pairs and `strip_prefix` on the
/// name is what stops `xtheme=dark` answering for `theme`.
fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header
        .split(';')
        .filter_map(|p| p.trim().strip_prefix(name))
        .find_map(|rest| rest.strip_prefix('='))
}

/// The value of query parameter `name`. Copied from `bb-auth-web`, including the reason
/// `form_urlencoded` **is** the right grammar: this is what a browser puts in the query string
/// when it submits a form, percent-encoding and all.
fn query_param(query: &str, name: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// `302` to `location`, setting one preference cookie per `(name, value)` pair in `choices`.
/// Copied from `bb-auth-web`, cookie spelling included, and the shape is the point: the same
/// `Path=/` and the same `Max-Age` mean a choice made in the admin console is the same cookie
/// this page writes, so one pick carries across both programs on the host.
///
/// The list, rather than one pair, is what lets a single submit carry two choices: the selector
/// sends `theme` and `lang` in the same `GET`, and a response that remembered only one of them
/// would silently drop the other, since the redirect takes the whole query out of the URL.
///
/// The redirect, rather than a page, is what makes the choice a URL: the browser lands back on
/// the page with the parameters gone, so a bookmark or a reload does not re-apply a preference
/// the person has since changed. `location` is the base path plus `/`, printable ASCII by
/// construction, so [`h`] cannot panic on it, and every value is one of a closed enum's own
/// codes.
fn respond_preference_redirect(req: Request, location: &str, choices: &[(&str, &str)]) {
    let mut resp = Response::empty(StatusCode(302))
        .with_header(h("Location", location))
        .with_header(h("Cache-Control", "no-store"));
    for (cookie_name, value) in choices {
        let cookie =
            format!("{cookie_name}={value}; Max-Age={PREFERENCE_COOKIE_MAX_AGE}; Path=/; HttpOnly; SameSite=Lax");
        resp = resp.with_header(h("Set-Cookie", &cookie[..]));
    }
    let _ = req.respond(resp);
}

/// The inverse of the gate's `pct_encode`: `%XX` decoded, every other byte literal. A copy of
/// `bb-auth-web`'s private one, which is out of scope to move into the library.
///
/// It is needed here because the gate emits a profile claim percent-encoded, and that
/// construction is the whole header-safety argument: the page has to undo it to show a name a
/// person can read. Invalid UTF-8 is replaced rather than rejected, and maud escapes the
/// result, since it is the caller's own self-asserted text.
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

/// Send one rendered page.
///
/// `Response::from_data` rather than `from_string` because the latter installs its own
/// `Content-Type: text/plain` header that `with_header` would then *append* to rather than
/// replace, putting two of them on the wire.
///
/// The policy is **derived** from the same `&str`s the page is built out of, so the two cannot
/// disagree: `script-src 'none'` because this binary emits no script and no handler at all (a
/// page here works with scripting off), and `style-src` the [`csp_hash`] of the exact inline
/// block, which is [`THEME_CSS`] plus [`BASE_CSS`] plus [`CSS`] and nothing else. `form-action
/// 'self'` because the one form on the page is the preference selector, which goes back to this
/// same page and nowhere else.
fn respond(req: Request, status: u16, prefs: &Prefs, title: &str, content: Markup, look: Look) {
    let csp = page_csp(
        "'none'",
        &csp_hash(&format!("{THEME_CSS}{BASE_CSS}{CSS}")),
        "'self'",
        look.stylesheet,
        look.logo,
        &[],
    );
    let mut resp = Response::from_data(
        shell(prefs, title, content, look)
            .into_string()
            .into_bytes(),
    )
    .with_status_code(StatusCode(status))
    .with_header(h("Content-Type", "text/html; charset=utf-8"))
    .with_header(h("Content-Security-Policy", &csp));
    for (k, v) in PAGE_SECURITY_HEADERS {
        resp.add_header(h(k, v));
    }
    let _ = req.respond(resp);
}

/// The page's four sections, as facts, gathered in [`handle`] from the two files and the
/// request headers.
///
/// A struct rather than six arguments because `page_me` is **arrangement only**: every
/// question ("which groups am I in", "which keys are mine") is answered next to the read that
/// answers it, so the page cannot ask a file a slightly different question from the one the
/// gate asks, and the arrangement can be read without re-deriving any of it.
struct Own<'a> {
    /// Where the caller reaches: each application they reach, with the scope names under it,
    /// both in the order the file writes them. Names only, never a URL: this page is served to
    /// any identity Cognito vouches for, and which areas exist and which paths inside them are
    /// gated is exactly what such a caller must not learn.
    reached: Vec<(&'a str, Vec<&'a str>)>,
    /// The `user_groups` entries that list the caller's uuid.
    groups: Vec<&'a str>,
    /// The caller's own API keys, sorted by id.
    keys: Vec<&'a ApiKeyRecord>,
    /// Each configured profile claim, with the value the proxy forwarded, decoded, when one
    /// arrived.
    claims: Vec<(&'a str, Option<String>)>,
}

/// Group [`Access::scopes_reached`] by application, keeping the order it returned.
///
/// One pass is enough: applications partition the URL space and the library walks them in file
/// order, so every pair of one application is contiguous in that list.
fn group_reached<'a>(reached: &[(&'a AppRecord, &'a ScopeRecord)]) -> Vec<(&'a str, Vec<&'a str>)> {
    let mut out: Vec<(&str, Vec<&str>)> = Vec::new();
    for (app, scope) in reached {
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
/// scope's members and keeps no group names, and the question a person has is "under which
/// named set am I filed", which a scope's member list cannot answer (a `@group` lists none of
/// them directly). Members are compared the way the library compares them, with
/// [`norm_email`]. A caller with no roster row is in no group, because a group lists uuids.
fn groups_of<'a>(doc: &'a AccessFile, uuid: Option<&str>) -> Vec<&'a str> {
    let Some(u) = uuid else {
        return Vec::new();
    };
    let want = norm_email(u);
    doc.user_groups
        .iter()
        .filter(|(_, members)| members.iter().any(|m| norm_email(m) == want))
        .map(|(name, _)| name.as_str())
        .collect()
}

/// The keys whose owner is `uuid`, sorted by id.
///
/// Sorted because [`Access::by_key_hash`] is a `HashMap`, and a page that reshuffles a
/// person's keys between two reloads is a page nobody can compare with the file they wrote.
/// The bearer and its hash are not in an [`ApiKeyRecord`] at all, which is what keeps this
/// list free of the secret: the file stores only a hash, and the bearer exists nowhere after
/// minting.
fn keys_of<'a>(access: &'a Access, uuid: Option<&str>) -> Vec<&'a ApiKeyRecord> {
    let Some(u) = uuid else {
        return Vec::new();
    };
    let mut keys: Vec<&ApiKeyRecord> = access
        .by_key_hash
        .values()
        .filter(|k| k.uuid == u)
        .collect();
    keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    keys
}

/// Each configured claim, with the value the proxy forwarded for its derived header.
///
/// `None` when no header arrived, and the page shows the name with no value: a page that
/// filled in a value nobody sent would be telling a person something the estate never said.
fn claims_of<'a>(req: &Request, settings: &'a Settings) -> Vec<(&'a str, Option<String>)> {
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

/// A key's expiry as the file states it: the date it expires, or the word for "no expiry".
fn expiry(lang: Lang, key: &ApiKeyRecord) -> String {
    match key.expires {
        Some(e) => format_date(e),
        None => t(lang, K::KeyNever).to_string(),
    }
}

/// A key's own restriction: the `app/scope` names it carries, sorted, or the word for "the
/// owner's whole reach". A restriction is a subtraction, so an owner has to be able to see
/// that a key is narrower than they are.
fn restriction(lang: Lang, key: &ApiKeyRecord) -> String {
    match &key.scopes {
        None => t(lang, K::KeyAllScopes).to_string(),
        Some(scopes) => {
            let mut names: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
            names.sort_unstable();
            names.join(", ")
        }
    }
}

/// The page a caller gets: who they are, as the header carried it, their uuid when the access
/// file has a row for them, and the four sections about their own account.
///
/// A stranger is named too, and told there is no row: the `authenticated` scope §13.4 chose for
/// this URL admits any identity Cognito vouches for, so "bb-auth knows nothing about you" is a
/// page a real caller reaches, not a defensive one. A stranger and an administrator with no row
/// get the same page, because `web.admins` is not read here.
///
/// The sections are siblings and each carries only a heading, the names, and one short "none"
/// line: the page's contract is about **which fact belongs in which section**, and prose in one
/// is a word a test about another could match by accident.
fn page_me(lang: Lang, ids: &[String], uuid: Option<&str>, own: &Own) -> Markup {
    html! {
        p {
            (t(lang, K::SignedInAs)) ": "
            @for id in ids {
                code { (id) } " "
            }
        }
        @if let Some(u) = uuid {
            p { (t(lang, K::Uuid)) ": " code { (u) } }
        } @else {
            p class="muted" { (t(lang, K::NoRow)) }
        }
        section id="reach" {
            h2 { (t(lang, K::ReachTitle)) }
            @if own.reached.is_empty() {
                p class="muted" { (t(lang, K::Nothing)) }
            } @else {
                @for (app, scopes) in &own.reached {
                    p { code { (app) } }
                    ul {
                        @for scope in scopes {
                            li { code { (scope) } }
                        }
                    }
                }
            }
        }
        section id="groups" {
            h2 { (t(lang, K::GroupsTitle)) }
            @if own.groups.is_empty() {
                p class="muted" { (t(lang, K::Nothing)) }
            } @else {
                ul {
                    @for g in &own.groups {
                        li { code { (g) } }
                    }
                }
            }
        }
        section id="keys" {
            h2 { (t(lang, K::KeysTitle)) }
            @if own.keys.is_empty() {
                p class="muted" { (t(lang, K::Nothing)) }
            } @else {
                ul {
                    @for k in &own.keys {
                        li {
                            code { (k.key_id) }
                            ul {
                                li { code { (expiry(lang, k)) } }
                                li { code { (restriction(lang, k)) } }
                            }
                        }
                    }
                }
            }
        }
        section id="profile" {
            h2 { (t(lang, K::ProfileTitle)) }
            @if own.claims.is_empty() {
                p class="muted" { (t(lang, K::Nothing)) }
            } @else {
                ul {
                    @for (claim, value) in &own.claims {
                        li {
                            code { (claim) }
                            // The word for none, not an empty value: a claim the deployment
                            // configured and nginx did not forward is a fact about the wiring,
                            // and a person has to be able to see it is missing rather than
                            // squint at a blank after a colon.
                            @if let Some(v) = value {
                                ": " code { (v) }
                            } @else {
                                " " code { (t(lang, K::Nothing)) }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Answer one request.
///
/// Both files are read **fresh on every request**, never from a cached copy: this page's whole
/// subject is a file an operator edits from three places at once, and a page about a roster row
/// that is gone is a page about whoever that uuid belongs to next.
///
/// The order is §13.4's table, and the veto sits ahead of the row resolution that decides `500`
/// vs `200` for the estate's standing reason: a lock a caller escapes by sending *less* is not a
/// lock.
fn handle(req: Request, cfg: &Config) {
    // The query and the two headers the preferences come from, read once and up front: the
    // language decides the words on a `401` as much as the words on the page, so a refusal that
    // answers in English to a browser that asked in Italian is the same bug in a smaller shape.
    let query = match req.url().split_once('?') {
        Some((_, q)) => q.to_string(),
        None => String::new(),
    };
    let cookie = header_value(&req, "Cookie").unwrap_or("").to_string();
    let accept = header_value(&req, "Accept-Language").map(|a| a.to_string());
    let (lang_pref, lang) = negotiate_lang(
        query_param(&query, LANG_COOKIE).as_deref(),
        cookie_value(&cookie, LANG_COOKIE),
        accept.as_deref(),
        Lang::En,
    );
    let theme = negotiate_theme(
        query_param(&query, THEME_COOKIE).as_deref(),
        cookie_value(&cookie, THEME_COOKIE),
    );
    let prefs = Prefs {
        lang,
        lang_pref,
        theme,
        base: cfg.base_path.trim_end_matches('/'),
    };
    // Identity comes from nginx and from nowhere else. A header of spaces is the same broken
    // deployment as no header at all: nginx wrote it and put nobody in it.
    let raw = match header_value(&req, IDENTITY_HEADER) {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => {
            respond(
                req,
                401,
                &prefs,
                t(lang, K::NoIdentityTitle),
                html! { p { (t(lang, K::NoIdentityBody)) } },
                Look::default(),
            );
            return;
        }
    };
    // The header is a list, not one address: the gate puts **every** email of the roster row
    // into it, joined by a single space. Comparing the whole string would treat one person's
    // second address as a second person.
    let ids: Vec<String> = raw.split_ascii_whitespace().map(norm_email).collect();

    // The settings, fresh off disk. The `ui` section is read per request for the gate's own
    // reason: one save restyles this page and the admin GUI together.
    let settings = match open_settings_file(&cfg.settings_path) {
        Ok((_, s)) => s,
        Err(e) => {
            respond(
                req,
                500,
                &prefs,
                t(lang, K::SettingsTitle),
                html! { p { (e) } },
                Look::default(),
            );
            return;
        }
    };
    let look = Look {
        theme: settings.theme,
        stylesheet: settings.stylesheet_url.as_deref(),
        logo: settings.logo_url.as_deref(),
        brand: settings.brand_name.as_deref(),
    };
    // `gate.identity_attrs` without `email` means nginx injects no `X-Auth-Email`, so there is
    // no identity for this page to act on. The page names the setting, because the operator
    // reading it is the only person who can fix it.
    if !settings.identity_attrs.iter().any(|a| a.attr == "email") {
        respond(
            req,
            500,
            &prefs,
            t(lang, K::NoEmailTitle),
            html! { p { (t(lang, K::NoEmailBody)) } },
            look,
        );
        return;
    }
    // Both halves come from **one** read: the groups live in the document and the grants in the
    // compiled table, and two reads of a file an operator edits from three places at once is a
    // page whose two halves describe different bytes.
    let (doc, access) = match open_access_file(&cfg.access_path) {
        Ok(pair) => pair,
        Err(e) => {
            respond(
                req,
                500,
                &prefs,
                t(lang, K::AccessTitle),
                html! { p { (e) } },
                look,
            );
            return;
        }
    };
    // The veto, ahead of everything else, on **every** value the header carries. The gate
    // refuses a vetoed identity before it ever reaches this page, so this is the second lock,
    // for a file edited mid-request.
    if ids.iter().any(|id| access.vetoes_identifier(id)) {
        respond(
            req,
            403,
            &prefs,
            t(lang, K::DeniedTitle),
            html! { p { (t(lang, K::DeniedBody)) } },
            look,
        );
        return;
    }
    // An explicit `?theme=` or `?lang=` is a **choice**, not a page: it is remembered in the
    // cookie and the browser is sent back to this page without the parameters, so a bookmark or a
    // reload does not carry around a preference the person has since changed. Both parameters are
    // read from the same query and answered with **one** redirect carrying one `Set-Cookie` per
    // recognised choice, because the selector's single submit sends both in one `GET`: a redirect
    // of its own per parameter would take the whole query out of the URL, and the second choice
    // picked on the same form would never reach the cookie.
    //
    // It sits **after** the identity checks and the veto, so a stranger and a vetoed identity are
    // answered exactly as they are with no query at all: a preference is never a way to reach a
    // page. And an unrecognised value is not a choice, so it sets no cookie; a submit whose values
    // are all unrecognised is not a choice at all, and falls through to the page.
    let home = format!("{}/", prefs.base);
    let mut choices: Vec<(&str, &str)> = Vec::new();
    if let Some(t) = query_param(&query, THEME_COOKIE).and_then(|v| parse_theme(&v)) {
        choices.push((THEME_COOKIE, t.code()));
    }
    if let Some(p) = query_param(&query, LANG_COOKIE).and_then(|v| parse_lang_pref(&v)) {
        choices.push((LANG_COOKIE, p.code()));
    }
    if !choices.is_empty() {
        respond_preference_redirect(req, &home, &choices);
        return;
    }
    // Every value must resolve to the same row, or to no row at all. Two rows in one header is
    // nginx having built one header out of two people, and no page is about both; one address
    // enrolled and one not is the same fault in a shape that would otherwise be answered as if
    // it were one person.
    let uuids: Vec<Option<&str>> = ids.iter().map(|id| access.uuid_of(id)).collect();
    if !uuids.iter().all(|u| *u == uuids[0]) {
        respond(
            req,
            500,
            &prefs,
            t(lang, K::AmbiguousTitle),
            html! { p { (t(lang, K::AmbiguousBody)) } },
            look,
        );
        return;
    }
    // Past the ambiguity check every value names the same person, so the first is as good an
    // answer as any: `scopes_reached` takes an identifier precisely so that a stranger gets the
    // scopes that grant on identity alone, and an exclusion that would answer differently for
    // two addresses of one row is a scope excluding one address of a user, which the library
    // folds onto the uuid at load.
    let reached = access.scopes_reached(&ids[0]);
    let own = Own {
        reached: group_reached(&reached),
        groups: groups_of(&doc, uuids[0]),
        keys: keys_of(&access, uuids[0]),
        claims: claims_of(&req, &settings),
    };
    respond(
        req,
        200,
        &prefs,
        t(lang, K::Title),
        page_me(lang, &ids, uuids[0], &own),
        look,
    );
}

fn main() {
    // The same one-line answer the other three programs give, for the same reason: `dpkg-query`
    // reports 1.99.1-1 for a release and for a hand-built tree alike.
    if std::env::args().any(|a| a == "--version") {
        println!("{}", version_line("bb-auth-me"));
        return;
    }
    let cfg = Config::from_env();

    // A bind that is not loopback, refused before the socket exists, exactly as `bb-auth-web`
    // refuses one: this service's ONLY credential is a header nginx injects, so anything that
    // can reach the port is whoever it says it is. Fatal rather than a warning, for the same
    // reason the GUI's is: refusing to start costs a person a page, not the estate its traffic.
    if !listen_is_loopback(&cfg.listen) && !env_flag("BB_AUTH_ME_ALLOW_NONLOOPBACK") {
        eprintln!(
            "[bb-auth-me] FATAL: BB_AUTH_ME_LISTEN is {}, which is not loopback. This service \
             takes its identity from the {IDENTITY_HEADER} header nginx sets, so anything that \
             can reach the port is whoever it says it is. Put nginx in front of it, or set \
             BB_AUTH_ME_ALLOW_NONLOOPBACK=1 to say you meant it.",
            cfg.listen
        );
        std::process::exit(1);
    }
    let server = Server::http(&cfg.listen).unwrap_or_else(|e| {
        eprintln!("[bb-auth-me] FATAL: cannot bind {}: {e}", cfg.listen);
        std::process::exit(1);
    });
    eprintln!(
        "[bb-auth-me] {} listening on {} | file={} | settings={} | base={}",
        version_line("bb-auth-me"),
        cfg.listen,
        cfg.access_path,
        cfg.settings_path,
        cfg.base_path
    );
    eprintln!(
        "[bb-auth-me] identity comes from the {IDENTITY_HEADER} header: this port must be \
         reachable ONLY through nginx, behind bb-auth's own auth_request"
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
                Err(e) => eprintln!("[bb-auth-me] recv error: {e}"),
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bb_auth_core::{norm_email, sha256_hex, IDENTITY_HEADER, PAGE_SECURITY_HEADERS};
    use std::time::Duration;
    use tiny_http::Server;

    /// One application, one `authenticated` scope (the grant docs/ARCHITECTURE.md §13.4 chose
    /// for this page, so a stranger is a real caller), two roster rows, and the `denied` veto.
    const ACCESS: &str = r#"{ "version": 1,
      "applications": [
        { "name": "mpa", "base": ["https://app.x.com/mpa"],
          "scopes": [ { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
                        "access": "authenticated" } ] }
      ],
      "denied": ["spammer@x.com"],
      "users": [
        { "uuid": "11111111-1111-4111-8111-111111111111",
          "emails": ["bob@x.com", "bob@old.com"] },
        { "uuid": "22222222-2222-4222-8222-222222222222", "emails": ["carol@x.com"] }
      ] }"#;

    /// The deployment's settings: the pool, the hosts it may redirect to, and one
    /// administrator. `identity_attrs` is left at its default, which is `email`.
    const SETTINGS: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"] },
        "web": { "admins": ["admin@x.com"] } }"#;

    /// The same file with `gate.identity_attrs` narrowed to `uuid`: nginx then injects no
    /// `X-Auth-Email` at all, so there is no identity for this page to act on.
    const SETTINGS_NO_EMAIL: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"],
        "identity_attrs": ["uuid"] },
        "web": { "admins": ["admin@x.com"] } }"#;

    /// Every caller §13.4's table lists, in the header form each one arrives in. The page
    /// must name each of them, as the header carried it, normalised.
    const CALLERS: [&str; 5] = [
        "bob@x.com",
        "BOB@old.com bob@x.com",
        "carol@x.com",
        "admin@x.com",
        "stranger@elsewhere.com",
    ];

    // ---------------------------------------------------------------------------
    // The richer fixture: everything the page is supposed to show something about.
    //
    // `ACCESS` and `SETTINGS` above are left exactly as they are, because the identity tests
    // depend on them. This one is the shape `bb_auth_core`'s own `fixture()` uses: two
    // applications, every access kind, a `@group` grant, a key-only scope, a key narrower
    // than its owner, and a key that does expire.
    // ---------------------------------------------------------------------------

    const BOB: &str = "11111111-1111-4111-8111-111111111111";
    const CAROL: &str = "22222222-2222-4222-8222-222222222222";

    /// The two raw bearers whose hashes the fixture stores. The keys exist so a test can say
    /// the page carries **neither** the bearer nor its hash: a page that printed a hash is
    /// one step from printing the file's secret material.
    const BEARER_LAPTOP: &str = "bbk_testkeytestkeytestkey";
    const BEARER_CI: &str = "bbk_secondkeysecondkey00";

    /// Two applications, every access kind, and bob in all of them in a different way: `mpa`
    /// reaches him through `@admins` (`admin`), through `authenticated` (`onboarding`) and
    /// not at all (`healthz`, anonymous, which says nothing about a person); `mcp` reaches him
    /// through `logs` and not through `api`, whose credentials are `api_key` only, so a
    /// browser login never reaches it.
    const ACCESS_FULL: &str = r#"{ "version": 1,
  "applications": [
    { "name": "mpa", "base": ["https://app.x.com/mpa"],
      "scopes": [
        { "name": "healthz", "urls": ["https://app.x.com/mpa/healthz"], "access": "anonymous" },
        { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"], "access": "restricted",
          "groups": ["@admins"], "credentials": ["login"] },
        { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"], "access": "authenticated" } ] },
    { "name": "mcp", "base": ["https://ai.x.com/mcp"],
      "scopes": [
        { "name": "logs", "urls": ["https://ai.x.com/mcp/logs/*"], "access": "restricted",
          "users": ["__BOB__"] },
        { "name": "api", "urls": ["https://ai.x.com/mcp/*"], "access": "restricted",
          "users": ["__BOB__"], "credentials": ["api_key"] } ] } ],
  "user_groups": { "admins": ["__BOB__"] },
  "denied": ["spammer@x.com"],
  "users": [
    { "uuid": "__BOB__", "emails": ["bob@x.com", "bob@old.com"],
      "api_keys": [
        { "id": "laptop", "key_hash": "__LAPTOP_HASH__", "released": "2026-01-01",
          "duration": "never", "scopes": ["mcp/api"] },
        { "id": "ci", "key_hash": "__CI_HASH__", "released": "2026-01-01", "duration": "365d" } ] },
    { "uuid": "__CAROL__", "emails": ["carol@x.com"] } ] }"#;

    /// The fixture with its uuids and key hashes filled in, the hashes by the library's own
    /// fingerprint, so the hashes a test looks for and the hashes in the file are the same
    /// bytes by construction.
    fn access_full() -> String {
        ACCESS_FULL
            .replace("__BOB__", BOB)
            .replace("__CAROL__", CAROL)
            .replace("__LAPTOP_HASH__", &sha256_hex(BEARER_LAPTOP))
            .replace("__CI_HASH__", &sha256_hex(BEARER_CI))
    }

    /// The deployment's settings, plus `gate.profile_claims`: the page shows the claims the
    /// proxy forwards, and `given_name` is the one whose derived header (`X-Auth-Given-Name`)
    /// a test can put on the wire.
    const SETTINGS_FULL: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"],
        "profile_claims": ["given_name"] },
        "web": { "admins": ["admin@x.com"] } }"#;

    /// The access file and the settings file beside it, under a name unique to this test:
    /// tests run in parallel and share one temp directory.
    fn scratch(name: &str, settings: &str) -> String {
        let p = std::env::temp_dir().join(format!("bb-auth-me-{name}.json"));
        std::fs::write(&p, ACCESS).expect("write the access fixture");
        let path = p.to_string_lossy().into_owned();
        std::fs::write(format!("{path}.settings"), settings).expect("write the settings fixture");
        path
    }

    /// The richer fixture, written the same way and under its own name, for every test about
    /// **what the page shows** rather than about who reaches it at all.
    fn scratch_full(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("bb-auth-me-{name}.json"));
        std::fs::write(&p, access_full()).expect("write the full access fixture");
        let path = p.to_string_lossy().into_owned();
        std::fs::write(format!("{path}.settings"), SETTINGS_FULL)
            .expect("write the full settings fixture");
        path
    }

    fn cleanup(path: &str) {
        for p in [path.to_string(), format!("{path}.settings")] {
            let _ = std::fs::remove_file(p);
        }
    }

    fn cfg_for(path: &str) -> Config {
        Config {
            listen: String::new(),
            access_path: path.to_string(),
            settings_path: format!("{path}.settings"),
            base_path: String::new(),
        }
    }

    /// The handler, served on an ephemeral loopback port, over a real socket. The thread is
    /// never joined: the test process exits and the socket goes with it.
    fn serve(cfg: Config) -> String {
        let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
        let port = server.server_addr().to_ip().expect("an ip address").port();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &cfg);
            }
        });
        format!("http://127.0.0.1:{port}/")
    }

    /// The HTTP client every over-the-wire test uses. A refusal here is asserted on by its
    /// **body**, not only its code, so a non-2xx has to arrive as a response; a redirect is
    /// the thing under test rather than a step, so none are followed; and every wait has a
    /// deadline, so a handler that never answers fails the test instead of hanging it.
    fn client() -> ureq::Agent {
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .new_agent()
    }

    /// One response, read the way these tests read it.
    #[derive(Debug)]
    struct Got {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Got {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    /// `GET /` carrying the identity header nginx injects, or carrying no such header.
    fn call(base: &str, identity: Option<&str>) -> Got {
        call_with(base, identity, &[])
    }

    /// The same request, carrying extra request headers as well, so a test can put a profile
    /// header on the wire exactly as the gate emits it: percent-encoded, `X-Auth-Given-Name:
    /// Bob%20Smith`, because that is the construction the estate's safety argument rests on.
    fn call_with(base: &str, identity: Option<&str>, extra: &[(&str, &str)]) -> Got {
        let mut req = client().get(base);
        if let Some(v) = identity {
            req = req.header(IDENTITY_HEADER, v);
        }
        for &(k, v) in extra {
            req = req.header(k, v);
        }
        let mut r = req.call().expect("a response");
        let headers = r
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        Got {
            status: r.status().as_u16(),
            headers,
            body: r.body_mut().read_to_string().expect("a body"),
        }
    }

    /// Case-insensitive search for an inline event handler: a space, `on`, at least one ASCII
    /// letter, `=`. That is the shape of `onclick=` and of every other `on…=` attribute, and
    /// a page here may carry none: the estate's rule is that a page works with scripting off.
    fn carries_inline_handler(document: &str) -> bool {
        let lower = document.to_ascii_lowercase();
        let bytes = lower.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            if *b != b' ' || !bytes[i + 1..].starts_with(b"on") {
                continue;
            }
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            if j > i + 2 && bytes.get(j) == Some(&b'=') {
                return true;
            }
        }
        false
    }

    /// The page with its inline stylesheets collapsed to a marker. `THEME_CSS` and `BASE_CSS`
    /// are the bulk of every document this binary sends, and a failure that quotes the whole
    /// page buries the line that failed under forty kilobytes of palette.
    fn readable(body: &str) -> String {
        let mut out = String::new();
        let mut rest = body;
        while let Some(i) = rest.find("<style") {
            out.push_str(&rest[..i]);
            rest = &rest[i..];
            let end = rest
                .find("</style>")
                .map_or(rest.len(), |e| e + "</style>".len());
            out.push_str("[style omitted]");
            rest = &rest[end..];
        }
        out.push_str(rest);
        out
    }

    /// One section of the page: from `<section id="X"` to the next `</section>`. The page's
    /// four sections are siblings and never nested, so the first closing tag ends the section
    /// that started, and an assertion about `keys` cannot be satisfied by words that belong
    /// to `reach`. A page with no such section is the failure this contract is about, so it
    /// is reported as one.
    fn section(body: &str, id: &str) -> String {
        let open = format!("<section id=\"{id}\"");
        let start = body.find(&open).unwrap_or_else(|| {
            panic!(
                "the page must carry {}; it does not: {}",
                open,
                readable(body)
            )
        });
        let rest = &body[start..];
        let end = rest
            .find("</section>")
            .unwrap_or_else(|| panic!("{} is opened and never closed: {}", open, readable(body)));
        rest[..end].to_string()
    }

    /// A missing `X-Auth-Email` means nginx gated this location and forgot to inject the
    /// identity. That is a broken deployment, not an anonymous visitor, so the page refuses
    /// rather than rendering a page about nobody: an open door here is silent.
    #[test]
    fn a_request_with_no_identity_header_is_a_401() {
        let path = scratch("no-header", SETTINGS);
        let base = serve(cfg_for(&path));

        let g = call(&base, None);
        assert_eq!(
            g.status, 401,
            "a header nobody sent is not an anonymous visitor"
        );

        // A header set to spaces is the same broken deployment: nginx wrote the header and
        // put nobody in it, and an identity of spaces is not a person either.
        let g = call(&base, Some("   "));
        assert_eq!(g.status, 401, "a header of spaces names nobody: {g:?}");

        cleanup(&path);
    }

    /// `gate.identity_attrs` without `email` means nginx injects no `X-Auth-Email`, so this
    /// page has no identity to act on at all. That is a deployment fault, and the answer has
    /// to name the setting, because the operator reading it is the only person who can fix it.
    #[test]
    fn settings_without_the_email_attribute_are_a_500_naming_the_setting() {
        let path = scratch("no-email-attr", SETTINGS_NO_EMAIL);
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("bob@x.com"));
        assert_eq!(
            g.status, 500,
            "a deployment that injects no email has no caller to serve"
        );
        assert!(
            g.body.contains("identity_attrs"),
            "the page must name the setting to fix: {g:?}"
        );

        cleanup(&path);
    }

    /// `X-Auth-Email` carries every identifier of one row, space-joined, so several values
    /// that resolve to **different** rows is nginx having built one header out of two
    /// people. There is no page that is about both, so this is a fault, not a caller.
    #[test]
    fn values_from_two_different_rows_are_a_500() {
        let path = scratch("two-rows", SETTINGS);
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("bob@x.com carol@x.com"));
        assert_eq!(g.status, 500, "two rows in one header is not one person");

        cleanup(&path);
    }

    /// `denied` is checked **first**, ahead of the row resolution that decides 500 vs 200:
    /// the gate refuses a vetoed identity before it ever reaches this page, so this is the
    /// second lock for a file edited mid-request, and a lock that a caller escapes by
    /// sending *less* is not a lock.
    #[test]
    fn a_vetoed_identity_is_a_403_checked_before_the_rest() {
        let path = scratch("vetoed", SETTINGS);
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("spammer@x.com"));
        assert_eq!(
            g.status, 403,
            "a vetoed identity gets a refusal, not the page"
        );

        // A vetoed value joined to a live one is still a vetoed request, and it is a 403
        // rather than the 500 the two-rows rule would hand it: the veto outranks it.
        let g = call(&base, Some("bob@x.com spammer@x.com"));
        assert_eq!(g.status, 403, "the veto outranks the two-row 500: {g:?}");

        cleanup(&path);
    }

    /// Every caller in §13.4's table reaches the page, and the page names them: a roster
    /// user, a row whose two emails both arrived, an administrator (whose `web.admins` entry
    /// is **not** read here, so they are treated as any stranger), and a stranger no row
    /// knows, whom the `authenticated` scope lets in.
    #[test]
    fn a_signed_in_caller_gets_a_page_naming_them() {
        let path = scratch("callers", SETTINGS);
        let base = serve(cfg_for(&path));

        for who in CALLERS {
            let g = call(&base, Some(who));
            assert_eq!(g.status, 200, "{who} is signed in and reaches the page");
            for part in who.split_ascii_whitespace() {
                let id = norm_email(part);
                assert!(g.body.contains(&id), "the page must name {id}: {g:?}");
            }
        }

        cleanup(&path);
    }

    /// This page is one of the estate's HTML documents, so it carries the shared header set
    /// the library decides once, and a policy of its own; and it is a page a stranger reaches,
    /// so it carries no script and no inline handler at all.
    #[test]
    fn every_page_carries_the_shared_headers_and_no_script() {
        let path = scratch("headers", SETTINGS);
        let base = serve(cfg_for(&path));

        for who in CALLERS {
            let g = call(&base, Some(who));
            assert_eq!(g.status, 200, "{who}");
            for (k, v) in PAGE_SECURITY_HEADERS {
                assert_eq!(
                    g.header(k),
                    Some(v),
                    "{who}: the response must carry {k}: {v}"
                );
            }
            assert!(
                g.header("Content-Security-Policy").is_some(),
                "{who}: every HTML page carries a policy: {g:?}"
            );
            assert!(
                !g.body.to_ascii_lowercase().contains("<script"),
                "{who}: no script tag, the page works with scripting off"
            );
            assert!(
                !carries_inline_handler(&g.body),
                "{who}: no inline handler: {g:?}"
            );
        }

        cleanup(&path);
    }

    // ---------------------------------------------------------------------------
    // What the page shows (plan step 2b-2, docs/ARCHITECTURE.md §13.4).
    //
    // Every test here reads one `<section id="…">` of the page, because the contract is about
    // which fact belongs in which part of the page: a sentence about keys sitting in the
    // reach list must not be able to satisfy a test about keys.
    // ---------------------------------------------------------------------------

    /// The answer to "where can I go?" is a list of places, so the section names each
    /// application and then that application's scopes, in the order the file writes them: an
    /// operator comparing the page with the file they wrote should read them in the same
    /// order. `anonymous` is absent because it grants with no credential and so says nothing
    /// about this person, and a scope whose credentials are `api_key` only is absent because
    /// the caller reading this page is signed in with a browser, not with a key.
    #[test]
    fn the_reach_section_lists_every_app_and_scope_bob_reaches_in_file_order() {
        let path = scratch_full("reach-bob");
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("bob@x.com"));
        assert_eq!(g.status, 200, "bob is a roster user: {}", readable(&g.body));
        let s = section(&g.body, "reach");
        for name in ["mpa", "admin", "onboarding", "mcp", "logs"] {
            assert!(
                s.contains(name),
                "bob reaches {name}, so the reach section must list it: {s}"
            );
        }
        let at = |n: &str| s.find(n).unwrap_or_default();
        assert!(
            at("mpa") < at("admin") && at("admin") < at("onboarding"),
            "an application must be named before its own scopes, and its scopes in file order: {s}"
        );
        assert!(
            at("onboarding") < at("mcp") && at("mcp") < at("logs"),
            "the applications are listed in file order, each before the scopes it owns: {s}"
        );
        assert!(
            !s.contains("healthz"),
            "an anonymous scope is reached by everyone with no credential, so it says nothing \
             about bob and must not be listed: {s}"
        );
        assert!(
            !s.contains("api"),
            "mcp/api admits only an api_key, and a browser login never reaches it: {s}"
        );

        cleanup(&path);
    }

    /// A group is how an operator writes a reusable set of people, so the groups section
    /// answers the question a person actually has: not "which scopes list my uuid" (a
    /// `@group` lists none of them directly) but "under which named set am I filed".
    #[test]
    fn the_groups_section_names_the_groups_the_caller_belongs_to() {
        let path = scratch_full("groups-bob");
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("bob@x.com"));
        assert_eq!(g.status, 200, "bob is a roster user: {}", readable(&g.body));
        let s = section(&g.body, "groups");
        assert!(
            s.contains("admins"),
            "bob is a member of the admins group, so the page must name it: {s}"
        );

        cleanup(&path);
    }

    /// The keys section is where a person learns which machine credentials exist for them, so
    /// it shows the id, the expiry and the restriction, all of them facts the file states. The
    /// secret is the one thing that must never come back: the file stores only a hash, the
    /// bearer is shown once at minting, and a page that reprinted either would be a way to
    /// read a credential out of a page that is not its reveal.
    #[test]
    fn the_keys_section_shows_id_expiry_and_restriction_and_never_the_secret() {
        let path = scratch_full("keys-bob");
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("bob@x.com"));
        assert_eq!(g.status, 200, "bob is a roster user: {}", readable(&g.body));
        let s = section(&g.body, "keys");
        assert!(
            s.contains("laptop") && s.contains("ci"),
            "bob has two keys, so both ids must be listed: {s}"
        );
        assert!(
            s.contains("never"),
            "the laptop key's duration is `never`, and that is the fact a person acts on: {s}"
        );
        assert!(
            s.contains("2027-01-01"),
            "the ci key was released 2026-01-01 for 365 days, so it expires 2027-01-01: {s}"
        );
        assert!(
            s.contains("mcp/api"),
            "the laptop key is restricted to mcp/api, and an owner has to see that a key is \
             narrower than they are: {s}"
        );

        // Absence is asserted on the whole document, not on the section: a bearer printed
        // anywhere, in a comment or a data attribute, is the same leak.
        for secret in [
            BEARER_LAPTOP.to_string(),
            BEARER_CI.to_string(),
            sha256_hex(BEARER_LAPTOP),
            sha256_hex(BEARER_CI),
        ] {
            assert!(
                !g.body.contains(&secret),
                "the page must carry neither a raw key nor its hash, and it carries {secret}"
            );
        }

        cleanup(&path);
    }

    /// The profile section shows what the estate hands to the applications behind the gate:
    /// the claims the deployment configured, as the proxy forwarded them. The gate sends a
    /// claim value percent-encoded (that construction is the whole header-safety argument), so
    /// the page has to decode it: a name rendered as `Bob%20Smith` is a name nobody can read,
    /// and a claim shown with no name against it is not evidence of anything.
    #[test]
    fn the_profile_section_shows_a_forwarded_claim_by_name_and_decoded() {
        let path = scratch_full("profile-bob");
        let base = serve(cfg_for(&path));

        let g = call_with(
            &base,
            Some("bob@x.com"),
            &[("X-Auth-Given-Name", "Bob%20Smith")],
        );
        assert_eq!(g.status, 200, "bob is a roster user: {}", readable(&g.body));
        let s = section(&g.body, "profile");
        assert!(
            s.contains("given_name"),
            "the page must name the claim it is showing, since that is the name the deployment \
             configured: {s}"
        );
        assert!(
            s.contains("Bob Smith"),
            "the forwarded value is percent-encoded on the wire and must reach the page decoded: {s}"
        );

        // Nothing forwarded, nothing shown: a page that invented a value would be showing a
        // person a fact about them that the estate never said.
        let g = call(&base, Some("bob@x.com"));
        assert_eq!(g.status, 200, "bob is signed in with no claim forwarded");
        let s = section(&g.body, "profile");
        assert!(
            !s.contains("Bob"),
            "no header arrived, so the page may not show a given name: {s}"
        );

        cleanup(&path);
    }

    /// A stranger is a real caller, because the page's own scope is `authenticated`, and what
    /// they reach is exactly the scopes that grant on identity alone: no restricted scope
    /// lists them, they belong to no group, and a key needs a roster owner, so there are none
    /// to show.
    #[test]
    fn a_stranger_reaches_only_the_authenticated_scope_and_has_no_groups_or_keys() {
        let path = scratch_full("stranger");
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("stranger@elsewhere.com"));
        assert_eq!(
            g.status,
            200,
            "a stranger Cognito vouches for reaches this page: {}",
            readable(&g.body)
        );
        let s = section(&g.body, "reach");
        assert!(
            s.contains("mpa") && s.contains("onboarding"),
            "the authenticated scope is reached by everyone signed in, so the page must list \
             it under its application: {s}"
        );
        for name in ["admin", "logs", "mcp", "healthz", "api"] {
            assert!(
                !s.contains(name),
                "the stranger reaches no {name}, so the page must not name it: {s}"
            );
        }
        assert!(
            !section(&g.body, "groups").contains("admins"),
            "a stranger is in no group: {}",
            section(&g.body, "groups")
        );
        let k = section(&g.body, "keys");
        assert!(
            !k.contains("laptop") && !k.contains("ci"),
            "a key must have a roster owner, so a stranger has no keys to be shown: {k}"
        );

        cleanup(&path);
    }

    /// `web.admins` is not read here: an administrator with no roster row is one more person
    /// looking at their own account. So the page they get is the stranger's page, section for
    /// section. Anything else would make a list in the settings file a second, invisible way
    /// to be granted something on a page whose whole subject is the access file.
    #[test]
    fn an_administrator_with_no_row_is_answered_exactly_as_a_stranger() {
        let path = scratch_full("admin-is-a-stranger");
        let base = serve(cfg_for(&path));

        for id in ["reach", "groups", "keys"] {
            let stranger = section(&call(&base, Some("stranger@elsewhere.com")).body, id);
            let admin = section(&call(&base, Some("admin@x.com")).body, id);
            assert_eq!(
                stranger, admin,
                "the {id} section must say the same thing to an administrator with no roster \
                 row as to any other caller with no row"
            );
        }

        cleanup(&path);
    }

    /// This page is served to whoever nginx vouches for, a stranger included, so the access
    /// file's URLs are not information to hand out: which areas exist, and which paths inside
    /// them are gated, is exactly what somebody holding any account at all should not learn.
    /// Names of applications and scopes are fine, and are what §13.4 chose to show instead.
    #[test]
    fn no_page_shows_a_url_from_the_access_file() {
        let path = scratch_full("no-urls");
        let base = serve(cfg_for(&path));

        for who in ["bob@x.com", "carol@x.com", "stranger@elsewhere.com"] {
            let g = call(&base, Some(who));
            assert_eq!(
                g.status,
                200,
                "{who} reaches the page: {}",
                readable(&g.body)
            );
            for url in ["https://app.x.com", "https://ai.x.com", "/mpa/", "/mcp/"] {
                assert!(
                    !g.body.contains(url),
                    "{who}: the page must not leak {url} from the access file"
                );
            }
        }

        cleanup(&path);
    }

    /// `denied` removes everything, and that includes the list: the veto is answered with a
    /// refusal before the page is built, so a section of grants on a refusal page would be the
    /// page telling a person it is refusing them what it just said they can reach.
    #[test]
    fn a_denied_identity_gets_a_403_and_sees_no_list_at_all() {
        let path = scratch_full("denied-full");
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("spammer@x.com"));
        assert_eq!(
            g.status,
            403,
            "a vetoed identity gets a refusal, on the rich fixture too: {}",
            readable(&g.body)
        );
        assert!(
            !g.body.contains("<section id=\"reach\""),
            "a refusal carries no list of what the caller reaches: {}",
            readable(&g.body)
        );

        cleanup(&path);
    }

    /// The estate's rule is that a page works with scripting off, and the identity page has
    /// nothing to script. The rich page is the one that tempts a developer into a disclosure
    /// toggle, so it is the one worth pinning.
    #[test]
    fn the_rich_page_carries_no_script_and_no_inline_handler() {
        let path = scratch_full("nojs-full");
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("bob@x.com"));
        assert_eq!(g.status, 200, "bob is a roster user: {}", readable(&g.body));
        assert!(
            !g.body.to_ascii_lowercase().contains("<script"),
            "no script tag: the page works with scripting off"
        );
        assert!(
            !carries_inline_handler(&g.body),
            "no inline handler of any kind: {}",
            readable(&g.body)
        );

        cleanup(&path);
    }

    // ---------------------------------------------------------------------------
    // The look and the preferences (plan step 2b-3).
    //
    // The administrator sets the look in the settings file's `ui` section, the same section
    // that restyles the admin console and the gate's pages. The person may change two things
    // about their own view, the theme and the language, each remembered in a cookie whose name
    // and value are the console's, so a choice made in one program carries to the other on the
    // same host. One difference from the console: this binary emits no script and no handler at
    // all, so its selector form carries a visible submit button and no `onchange`.
    // ---------------------------------------------------------------------------

    /// The deployment's settings plus the administrator's default theme.
    const SETTINGS_THEME_DARK: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"] },
        "web": { "admins": ["admin@x.com"] },
        "ui": { "theme": "dark" } }"#;

    /// The deployment's settings plus the brand name and the logo an administrator set.
    const SETTINGS_BRAND: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"] },
        "web": { "admins": ["admin@x.com"] },
        "ui": { "brand_name": "BadBat75",
                "logo_url": "https://assets.badbat75.com/logo.png" } }"#;

    /// The request a preference test makes: signed in as `identity`, with the browser's
    /// `Cookie` header carrying the preferences it already chose and an `Accept-Language` when
    /// the caller has one. Both are assembled here so each test spells the preference it is
    /// about and nothing else.
    fn call_pref(
        base: &str,
        identity: Option<&str>,
        cookie: Option<&str>,
        accept: Option<&str>,
    ) -> Got {
        let mut extra: Vec<(&str, &str)> = Vec::new();
        if let Some(c) = cookie {
            extra.push(("Cookie", c));
        }
        if let Some(a) = accept {
            extra.push(("Accept-Language", a));
        }
        call_with(base, identity, &extra)
    }

    /// The `<html …>` start tag. `THEME_CSS` spells `data-theme` inside its own selectors, so
    /// an assertion about the attribute has to look at the tag and not at the page.
    fn html_tag(body: &str) -> String {
        let start = body
            .find("<html")
            .unwrap_or_else(|| panic!("the page has no <html tag: {}", readable(body)));
        let rest = &body[start..];
        let end = rest.find('>').unwrap_or(rest.len());
        rest[..=end].to_string()
    }

    /// The text of the first `<h1>` (or `<h2>`) in `haystack`. A translation test compares one
    /// heading, because a whole section also carries names, emails and ids, and those are the
    /// file's vocabulary, which is never translated.
    fn heading(haystack: &str, tag: &str) -> String {
        let open = format!("<{tag}>");
        let start = haystack
            .find(&open)
            .unwrap_or_else(|| panic!("the page has no <{tag}>: {}", readable(haystack)));
        let rest = &haystack[start + open.len()..];
        let end = rest.find(&format!("</{tag}>")).unwrap_or_else(|| {
            panic!("<{tag}> is opened and never closed: {}", readable(haystack))
        });
        rest[..end].to_string()
    }

    /// The administrator's `ui.theme` is the theme a page starts in, stamped on `<html>` as
    /// `data-theme` exactly as the admin console stamps it. A deployment that configured
    /// nothing gets no attribute at all, which is what leaves the browser and the OS deciding.
    #[test]
    fn the_administrators_default_theme_is_stamped_on_the_html_tag() {
        let path = scratch("theme-default", SETTINGS_THEME_DARK);
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("bob@x.com"));
        assert_eq!(g.status, 200, "bob reaches the page: {}", readable(&g.body));
        assert!(
            html_tag(&g.body).contains(r#"data-theme="dark""#),
            "ui.theme dark must reach the html tag: {}",
            html_tag(&g.body)
        );

        // No `ui` section at all: no attribute, so `prefers-color-scheme` is what paints.
        let plain = scratch("theme-none", SETTINGS);
        let plain_base = serve(cfg_for(&plain));
        let g = call(&plain_base, Some("bob@x.com"));
        assert_eq!(g.status, 200, "bob reaches the page: {}", readable(&g.body));
        assert!(
            !html_tag(&g.body).contains("data-theme"),
            "a deployment that set no theme must emit no data-theme at all: {}",
            html_tag(&g.body)
        );

        cleanup(&path);
        cleanup(&plain);
    }

    /// The person's own cookie outranks the administrator's default, and `system` is the choice
    /// to give the choice back: it falls through to the deployment's default rather than
    /// painting a third thing, so a session that un-chose ends up where it started.
    #[test]
    fn a_theme_cookie_outranks_the_administrators_default() {
        let path = scratch("theme-cookie", SETTINGS_THEME_DARK);
        let base = serve(cfg_for(&path));

        let g = call_pref(&base, Some("bob@x.com"), Some("theme=light"), None);
        assert_eq!(g.status, 200, "bob reaches the page: {}", readable(&g.body));
        assert!(
            html_tag(&g.body).contains(r#"data-theme="light""#),
            "the person's own choice must outrank the deployment's default: {}",
            html_tag(&g.body)
        );

        let g = call_pref(&base, Some("bob@x.com"), Some("theme=system"), None);
        assert_eq!(g.status, 200, "bob reaches the page: {}", readable(&g.body));
        assert!(
            html_tag(&g.body).contains(r#"data-theme="dark""#),
            "system falls through to the administrator's dark: {}",
            html_tag(&g.body)
        );

        cleanup(&path);
    }

    /// Choosing a preference is a `GET` with a parameter, answered by a cookie and a redirect
    /// that takes the parameter back out of the URL, so a bookmark does not carry a preference
    /// around forever. The cookie names and values are the console's, which is what makes a
    /// choice made in one program carry to the other on the same host.
    #[test]
    fn a_theme_or_language_choice_becomes_a_cookie_and_a_redirect_home() {
        let path = scratch("pref-redirect", SETTINGS);
        let base = serve(cfg_for(&path));

        let g = call(&format!("{base}?theme=dark"), Some("bob@x.com"));
        assert_eq!(
            g.status,
            302,
            "?theme=dark must be applied and redirected, not answered with a page: {}",
            readable(&g.body)
        );
        let cookie = g
            .header("Set-Cookie")
            .expect("the choice must be remembered in a cookie");
        assert!(
            cookie.starts_with("theme=dark;"),
            "the cookie must be the console's own theme cookie: {cookie}"
        );
        for part in ["Path=/", "HttpOnly", "SameSite=Lax"] {
            assert!(
                cookie.contains(part),
                "the preference cookie must carry {part}: {cookie}"
            );
        }
        assert_eq!(
            g.header("Location"),
            Some("/"),
            "the redirect goes back to this page with the parameter gone: {:?}",
            g.header("Location")
        );

        let g = call(&format!("{base}?lang=it"), Some("bob@x.com"));
        assert_eq!(
            g.status,
            302,
            "?lang=it must be applied and redirected: {}",
            readable(&g.body)
        );
        let cookie = g
            .header("Set-Cookie")
            .expect("the choice must be remembered in a cookie");
        assert!(
            cookie.starts_with("lang=it;"),
            "the cookie must be the console's own lang cookie: {cookie}"
        );
        assert_eq!(
            g.header("Location"),
            Some("/"),
            "the redirect goes back to this page with the parameter gone: {:?}",
            g.header("Location")
        );

        cleanup(&path);
    }

    /// The selector's one submit carries `theme` and `lang` in the same `GET`, so one request
    /// has to remember both. It cannot today: the theme check answers with a redirect of its
    /// own, and `Location: /` takes the whole query out of the URL, so the language picked on
    /// the same form is dropped on the way home. A preference that is never stored is a choice
    /// that did not happen, and the person watches their own pick revert on the next load.
    #[test]
    fn one_submit_of_the_selector_remembers_both_choices() {
        let path = scratch("pref-both", SETTINGS);
        let base = serve(cfg_for(&path));

        // Every `Set-Cookie` the response carries, counted. A single submit is one response, so
        // the count is the contract: a response that set one cookie is one choice remembered,
        // whatever the one header says.
        fn cookies(g: &Got) -> Vec<&str> {
            g.headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
                .map(|(_, v)| v.as_str())
                .collect()
        }

        let g = call(&format!("{base}?theme=light&lang=it"), Some("bob@x.com"));
        assert_eq!(
            g.status,
            302,
            "one submit of both preferences must be applied and redirected: {}",
            readable(&g.body)
        );
        assert_eq!(
            g.header("Location"),
            Some("/"),
            "the redirect goes back to this page with the parameters gone: {:?}",
            g.header("Location")
        );
        let set = cookies(&g);
        assert_eq!(
            set.len(),
            2,
            "one submit of two preferences must set two cookies in one response, and it set \
             {set:?} (all headers: {:?})",
            g.headers
        );
        assert!(
            set.iter().any(|c| c.starts_with("theme=light;")),
            "the theme picked on this submit must be remembered: {set:?}"
        );
        assert!(
            set.iter().any(|c| c.starts_with("lang=it;")),
            "the language picked on the same submit must be remembered too: {set:?}"
        );

        // One recognised value and one nobody recognises is one choice, not two: the
        // unrecognised value is not a preference and must set nothing, while the recognised
        // half still lands.
        let g = call(&format!("{base}?theme=light&lang=xx"), Some("bob@x.com"));
        assert_eq!(
            g.status,
            302,
            "the recognised half of a submit is still a choice: {}",
            readable(&g.body)
        );
        let set = cookies(&g);
        assert_eq!(
            set.len(),
            1,
            "a value nobody recognises must set no cookie, and the response set {set:?}"
        );
        assert!(
            set[0].starts_with("theme=light;"),
            "the recognised half must be the theme cookie: {set:?}"
        );

        cleanup(&path);
    }

    /// A value that is not one of the three themes, or one of the two languages plus `auto`, is
    /// not a preference at all: nothing is remembered and the page is served as it was.
    /// Storing a nonsense value would leave the person looking at a choice the page cannot show
    /// as chosen, and would let a crafted link write a cookie for them.
    #[test]
    fn a_preference_nobody_recognises_sets_no_cookie() {
        let path = scratch("pref-bogus", SETTINGS);
        let base = serve(cfg_for(&path));

        for q in ["theme=purple", "lang=xx"] {
            let g = call(&format!("{base}?{q}"), Some("bob@x.com"));
            assert_eq!(
                g.status,
                200,
                "{q} is not a choice, so the page is served as it was: {}",
                readable(&g.body)
            );
            assert!(
                g.header("Set-Cookie").is_none(),
                "{q} must set no cookie, and the response set {:?}",
                g.header("Set-Cookie")
            );
        }

        cleanup(&path);
    }

    /// The language is the person's cookie, failing that the browser's `Accept-Language`,
    /// failing that English: most explicit wins, and `auto` is the choice to keep letting the
    /// browser decide, which is what a session that never chose has always been getting.
    #[test]
    fn the_language_is_the_cookie_then_the_browser_header_then_english() {
        let path = scratch("lang", SETTINGS);
        let base = serve(cfg_for(&path));

        let cases: [(Option<&str>, Option<&str>, &str); 5] = [
            (Some("lang=it"), None, "it"),
            (None, Some("it-IT,it;q=0.9"), "it"),
            (None, Some("de-DE"), "en"),
            (Some("lang=en"), Some("it"), "en"),
            (Some("lang=auto"), Some("it"), "it"),
        ];
        for (cookie, accept, want) in cases {
            let g = call_pref(&base, Some("bob@x.com"), cookie, accept);
            assert_eq!(g.status, 200, "bob reaches the page: {}", readable(&g.body));
            assert!(
                html_tag(&g.body).contains(&format!(r#"lang="{want}""#)),
                "cookie {cookie:?} with Accept-Language {accept:?} must render lang=\"{want}\": {}",
                html_tag(&g.body)
            );
        }

        cleanup(&path);
    }

    /// The Italian strings are compiled into the binary, not fetched: this is the page a person
    /// reaches when something is already wrong, and a page that needs a translation host has
    /// picked the worst moment to have a dependency. The headings are the prose, so they are
    /// what proves the table is being read at all.
    #[test]
    fn the_italian_page_is_translated() {
        let path = scratch_full("lang-it");
        let base = serve(cfg_for(&path));

        let en = call_pref(&base, Some("bob@x.com"), Some("lang=en"), None);
        let it = call_pref(&base, Some("bob@x.com"), Some("lang=it"), None);
        assert_eq!(
            en.status,
            200,
            "bob reaches the page: {}",
            readable(&en.body)
        );
        assert_eq!(
            it.status,
            200,
            "bob reaches the page: {}",
            readable(&it.body)
        );

        let reach_h2 = |g: &Got| heading(&section(&g.body, "reach"), "h2");
        assert_ne!(
            reach_h2(&en),
            reach_h2(&it),
            "the reach heading must be translated, and both pages say the same thing in it"
        );
        assert_ne!(
            heading(&en.body, "h1"),
            heading(&it.body, "h1"),
            "the page's own title must be translated too"
        );

        cleanup(&path);
    }

    /// The selector is a plain `GET` form with a visible submit button. Unlike the admin console
    /// this binary emits no script and no handler at all, so there is no `onchange` to apply a
    /// pick on the fly, and a browser with scripting off is not a fallback here but the only
    /// browser there is.
    #[test]
    fn the_page_carries_a_theme_and_language_selector_with_a_submit_button() {
        let path = scratch("selector", SETTINGS);
        let base = serve(cfg_for(&path));

        let g = call_pref(&base, Some("bob@x.com"), Some("theme=dark"), None);
        assert_eq!(g.status, 200, "bob reaches the page: {}", readable(&g.body));
        let body = readable(&g.body);
        let form = body.find("<form").expect("the page must carry a form");
        let theme = body
            .find(r#"<select name="theme""#)
            .expect("the page must carry a theme list box");
        let lang = body
            .find(r#"<select name="lang""#)
            .expect("the page must carry a language list box");
        assert!(
            form < theme && theme < lang,
            "both list boxes sit inside one form: {body}"
        );
        assert!(
            body.contains(r#"method="get""#),
            "a preference is a GET, so a bookmark and a reload cannot change anything: {body}"
        );
        for value in ["light", "dark", "system"] {
            assert!(
                body.contains(&format!(r#"<option value="{value}""#)),
                "the theme list must offer {value}: {body}"
            );
        }
        for value in ["en", "it", "auto"] {
            assert!(
                body.contains(&format!(r#"<option value="{value}""#)),
                "the language list must offer {value}: {body}"
            );
        }
        assert!(
            body.contains("<button"),
            "the form needs a visible submit button, since no script applies a pick: {body}"
        );
        assert!(
            body.contains(r#"<option value="dark" selected>"#),
            "the option in force must be marked chosen: {body}"
        );

        cleanup(&path);
    }

    /// The brand and the logo come from the same `ui` section that restyles the admin console
    /// and the gate's pages, so one save signs every surface of the estate in one name. A
    /// deployment that configured neither shows no image and no brand: the built-in page is
    /// complete, and a page that needs an asset host to be up is a page that cannot get in.
    #[test]
    fn the_administrators_brand_and_logo_reach_the_page() {
        let path = scratch("brand", SETTINGS_BRAND);
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("bob@x.com"));
        assert_eq!(g.status, 200, "bob reaches the page: {}", readable(&g.body));
        assert!(
            g.body.contains("BadBat75"),
            "the brand the administrator set must name the page: {}",
            readable(&g.body)
        );
        assert!(
            g.body
                .contains(r#"<img src="https://assets.badbat75.com/logo.png""#),
            "the logo the administrator set must be shown: {}",
            readable(&g.body)
        );

        let plain = scratch("brand-none", SETTINGS);
        let plain_base = serve(cfg_for(&plain));
        let g = call(&plain_base, Some("bob@x.com"));
        assert_eq!(g.status, 200, "bob reaches the page: {}", readable(&g.body));
        assert!(
            !g.body.contains("<img"),
            "nothing configured, so the page fetches no image: {}",
            readable(&g.body)
        );
        assert!(
            !g.body.contains("BadBat75"),
            "nothing configured, so the page claims no brand: {}",
            readable(&g.body)
        );

        cleanup(&path);
        cleanup(&plain);
    }

    /// A claim the deployment configured and the proxy did not forward is a fact the estate
    /// never said, and the page has to say so in words: a name with nothing after it reads as
    /// "your name is empty", which is a statement about the person that nobody actually made.
    #[test]
    fn a_claim_nobody_forwarded_shows_the_word_for_none() {
        let path = scratch_full("claim-none");
        let base = serve(cfg_for(&path));

        let g = call(&base, Some("bob@x.com"));
        assert_eq!(g.status, 200, "bob reaches the page: {}", readable(&g.body));
        let s = section(&g.body, "profile");
        assert!(
            s.contains("given_name"),
            "the page must still name the claim it has nothing to show: {s}"
        );
        assert!(
            s.contains("None."),
            "a claim with no forwarded value shows the word for none, never an empty value: {s}"
        );
        assert!(
            !s.contains("given_name</code>:"),
            "the word for none replaces a value, it does not follow a bare colon: {s}"
        );

        cleanup(&path);
    }

    /// The estate's rule, on every page this step adds and on the refusals beside them: no
    /// script tag, no handler of any kind. The preference form is the first thing here that a
    /// script would be tempting to wire up, so the rule is walked across every variant.
    #[test]
    fn every_look_and_preference_page_carries_no_script_and_no_handler() {
        let path = scratch("nojs-look", SETTINGS_THEME_DARK);
        let base = serve(cfg_for(&path));
        let brand = scratch("nojs-brand", SETTINGS_BRAND);
        let brand_base = serve(cfg_for(&brand));

        // Only queries that are not a choice: a real one is answered with a `302` and no body.
        let pages: [(Option<&str>, Option<&str>, &str, u16); 7] = [
            (Some("bob@x.com"), None, "", 200),
            (Some("bob@x.com"), Some("theme=light"), "", 200),
            (Some("bob@x.com"), Some("lang=it"), "", 200),
            (Some("bob@x.com"), None, "?theme=purple", 200),
            (Some("bob@x.com"), None, "?lang=xx", 200),
            (None, None, "", 401),
            (Some("spammer@x.com"), None, "", 403),
        ];
        for root in [&base, &brand_base] {
            for (identity, cookie, query, want) in pages {
                let url = if query.is_empty() {
                    root.to_string()
                } else {
                    format!("{root}{query}")
                };
                let g = call_pref(&url, identity, cookie, Some("it"));
                assert_eq!(
                    g.status,
                    want,
                    "{identity:?} at {url} with cookie {cookie:?}: {}",
                    readable(&g.body)
                );
                assert!(
                    !g.body.to_ascii_lowercase().contains("<script"),
                    "{identity:?} at {url}: no script tag, the page works with scripting off: {}",
                    readable(&g.body)
                );
                assert!(
                    !carries_inline_handler(&g.body),
                    "{identity:?} at {url}: no inline handler, the selector uses a submit button: {}",
                    readable(&g.body)
                );
            }
        }

        cleanup(&path);
        cleanup(&brand);
    }
}
