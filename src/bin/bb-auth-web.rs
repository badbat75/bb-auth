//! bb-auth-web — a server-rendered admin GUI over a bb-auth **access file**
//! (`BB_AUTH_USERS_FILE`, a.k.a. users.json).
//!
//! What `bb-auth-adm` shows on a terminal, this shows in a browser: the roster, the url
//! groups and who references them, the sites in the order that decides which one answers,
//! the `denied` veto, every api key's expiry, and the `can EMAIL URL` tester — answered, as
//! there, by the gate's own [`decide`].
//!
//! **Phase 1 is strictly read-only.** Every route is a `GET`, there is no form but the
//! tester, and nothing here can write the file; the mutations live in [`bb_auth_core`]
//! already ([`bb_auth_core::AccessWrite`]) and a later phase wires them up. Until then this
//! binary opens the file, renders it, and forgets it.
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
//! keeps the process trivial: nothing here can go stale, and a restart loses nothing.
//!
//! Two consequences worth knowing. Compiling is what emits the parser's warnings, so a file
//! that warns will warn once per request on this service's stderr — noisy, and the price of
//! having exactly one parser. And when the file does not compile at all, this GUI does not
//! die: it renders the library's message verbatim, which is the sentence an operator needs
//! ("the gate would reject this file as it stands"), on a page whose navigation still works.
//!
//! # Language
//!
//! English and Italian, from a table compiled into the binary ([`t`]). Prose and labels are
//! translated; the **file's vocabulary never is** — `public_auth`, `authorized_urls`,
//! `url_groups`, `sites`, `denied`, `bbk_`, an `@group` reference, and every name, email and
//! URL pattern read the same in both, because they are what an operator will type into
//! `bb-auth-adm` and into the file itself. Library error messages render verbatim, in the
//! English the gate and the CLI already say them in.

use bb_auth_core::{
    decide, format_date, key_expiry, norm_email, now, open_access_file, request_url, site_name,
    url_group_refs, user_pos, Access, AccessFile, ApiKeySpec, Decision, SiteSpec, UserSpec,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use tiny_http::{Header, Request, Response, Server, StatusCode};

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

/// A year. The preference is a preference, not a session.
const LANG_COOKIE_MAX_AGE: i64 = 31_536_000;

/// Blocking request threads. Fixed, and deliberately not an env var: this serves the
/// handful of people on `BB_AUTH_WEB_ADMINS`, not the public.
const WORKERS: usize = 2;

/// The whole stylesheet, inlined. No external request of any kind — no font, no script, no
/// image — so the page renders identically on a laptop, on a phone, and on a host with no
/// route to the internet.
///
/// Light and dark come from `prefers-color-scheme` over a handful of custom properties;
/// there is no theme toggle, and no JavaScript on any page in this phase.
const CSS: &str = r"
*,*::before,*::after{box-sizing:border-box}
:root{color-scheme:light dark;
  --bg:#f7f7fa;--panel:#fff;--fg:#1c1c21;--muted:#65656f;--line:#e2e2ea;
  --accent:#3350c8;--ok:#1c6b40;--warn:#8a5a00;--bad:#b3261e;--chip:#eeeef4}
@media (prefers-color-scheme:dark){:root{
  --bg:#16161b;--panel:#1e1e25;--fg:#e8e8ee;--muted:#9a9aa8;--line:#30303b;
  --accent:#8aa0ff;--ok:#5fd08a;--warn:#e3b341;--bad:#ff8a80;--chip:#292933}}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;font-size:.92em}
header.top{background:var(--panel);border-bottom:1px solid var(--line);padding:10px 16px}
.bar{max-width:1000px;margin:0 auto;display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.brand{font-weight:600;letter-spacing:.02em}
.brand .v{color:var(--muted);font-weight:400;font-size:.85em;margin-left:6px}
nav{display:flex;flex-wrap:wrap;gap:4px;flex:1 1 auto}
nav a{padding:4px 10px;border-radius:6px;text-decoration:none;color:var(--fg)}
nav a:hover{background:var(--chip)}
nav a.on{background:var(--accent);color:#fff}
.lang{display:flex;gap:6px;align-items:center;color:var(--muted);font-size:.85em}
main{max-width:1000px;margin:0 auto;padding:18px 16px 40px}
h1{font-size:1.25rem;margin:0 0 4px}
h2{font-size:1rem;margin:26px 0 8px}
p.lede{color:var(--muted);margin:0 0 18px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:14px 16px;margin:0 0 16px;overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:420px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}
ul.plain{list-style:none;margin:0;padding:0}
ul.plain li{padding:2px 0}
ol.sites{margin:0;padding-left:22px}
ol.sites li{margin:0 0 14px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:12px 16px;min-width:110px;flex:1 1 110px}
.card .n{font-size:1.6rem;font-weight:600;line-height:1.1}
.card .l{color:var(--muted);font-size:.82rem}
.tag{display:inline-block;padding:1px 7px;border-radius:999px;background:var(--chip);
  font-size:.78rem;white-space:nowrap}
.tag.bad{background:var(--bad);color:#fff}
.tag.warn{background:var(--warn);color:#fff}
.tag.ok{background:var(--ok);color:#fff}
.muted{color:var(--muted)}
.bad{color:var(--bad)}
form.can{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end}
form.can label{display:flex;flex-direction:column;gap:4px;flex:1 1 240px;font-size:.82rem;
  text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
input[type=text]{font:inherit;padding:7px 9px;border:1px solid var(--line);border-radius:7px;
  background:var(--bg);color:var(--fg);width:100%}
button{font:inherit;padding:8px 18px;border:0;border-radius:7px;background:var(--accent);
  color:#fff;cursor:pointer}
.verdict{font-size:1.05rem;font-weight:600;margin:0 0 6px}
.verdict.yes{color:var(--ok)}
.verdict.no{color:var(--bad)}
footer{max-width:1000px;margin:0 auto;padding:0 16px 30px;color:var(--muted);font-size:.82rem;
  display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between}
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

    /// The one the switch in the header offers.
    fn other(self) -> Lang {
        match self {
            Lang::En => Lang::It,
            Lang::It => Lang::En,
        }
    }
}

/// Parse a language name, from the query, the cookie or `BB_AUTH_WEB_DEFAULT_LANG`.
/// `None` for anything else — an unknown value is simply not a preference.
fn parse_lang(s: &str) -> Option<Lang> {
    match s.trim().to_ascii_lowercase().as_str() {
        "en" => Some(Lang::En),
        "it" => Some(Lang::It),
        _ => None,
    }
}

/// Every translatable string in the GUI, as a variant.
///
/// An enum rather than a string key so that [`t`]'s match is **exhaustive**: adding a key
/// without translating it does not fall back at runtime, it fails to compile. And because
/// each arm names both spellings on one line, no key can be half-translated either.
///
/// What is *not* here is as deliberate as what is: `users`, `url_groups`, `sites`, `denied`,
/// `authorized_urls`, `public_auth`, `login_url`, `api_keys`, `released`, `duration`,
/// `notes`, `can`, `bbk_` and every `@group` reference are the access file's own vocabulary.
/// They stay in both languages because they are what an operator types into the file and
/// into `bb-auth-adm`; translating them would invent a second name for a thing that has one.
#[derive(Clone, Copy)]
enum K {
    Dashboard,
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
    Patterns,
    Inherits,
    ReachesNothing,
    NoSuchUser,
    UsersIntro,
    GroupsIntro,
    SitesIntro,
    DeniedIntro,
    AlsoEnrolled,
    CanIntro,
    Submit,
    Authorized,
    VerdictDenied,
    WhySiteGrant,
    WhyRosterGrant,
    WhyVetoed,
    WhyOutOfScope,
    WhyNotEnrolled,
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
    ReadOnly,
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
            "reaches nothing — no authorized_urls",
            "non raggiunge nulla — nessun authorized_urls",
        ),
        K::WarnEnrolledAndDenied => m(
            lang,
            "is in users and in denied — denied wins, on every credential",
            "è in users e in denied — vince denied, su ogni credenziale",
        ),
        K::ReferencedBy => m(lang, "referenced by", "referenziato da"),
        K::ReferencedByNothing => m(lang, "referenced by nothing", "referenziato da nulla"),
        K::Patterns => m(lang, "patterns", "pattern"),
        K::Inherits => m(lang, "inherits the user's", "eredita quello dell'utente"),
        K::ReachesNothing => m(lang, "reaches nothing", "non raggiunge nulla"),
        K::NoSuchUser => m(lang, "no such user", "utente inesistente"),
        K::UsersIntro => m(
            lang,
            "The roster: who is enrolled, and what they may reach.",
            "Il roster: chi è iscritto e cosa può raggiungere.",
        ),
        K::GroupsIntro => m(
            lang,
            "Named sets of URL patterns. A group is abbreviation, never a grant: defining \
             one authorizes nobody until some list names it.",
            "Insiemi di pattern di URL con un nome. Un gruppo è un'abbreviazione, mai una \
             concessione: definirne uno non autorizza nessuno finché una lista non lo nomina.",
        ),
        K::SitesIntro => m(
            lang,
            "URL areas, in file order. First match wins: the first site whose urls cover a \
             request answers for it, even if it grants nothing. Specific sites go first.",
            "Aree di URL, nell'ordine del file. Vince la prima corrispondenza: risponde il \
             primo site le cui urls coprono la richiesta, anche se non concede nulla. I \
             site specifici vanno prima.",
        ),
        K::DeniedIntro => m(
            lang,
            "A veto by email. It outranks every grant, on every credential — and it is not \
             the same as deleting the user's row.",
            "Un veto per email. Batte ogni concessione, su ogni credenziale — e non equivale \
             a cancellare la riga dell'utente.",
        ),
        K::AlsoEnrolled => m(lang, "also in users", "anche in users"),
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
        K::WhySiteGrant => m(
            lang,
            "is public_auth: any identity Cognito vouches for reaches this URL, enrolled or \
             not. The roster is not consulted.",
            "è public_auth: ogni identità garantita da Cognito raggiunge questo URL, iscritta \
             o no. Il roster non viene consultato.",
        ),
        K::WhyRosterGrant => m(
            lang,
            "is enrolled, and this URL is inside their authorized_urls.",
            "è iscritto e questo URL è dentro i suoi authorized_urls.",
        ),
        K::WhyVetoed => m(
            lang,
            "is on the denied list, which outranks every grant.",
            "è nella lista denied, che batte ogni concessione.",
        ),
        K::WhyOutOfScope => m(
            lang,
            "is outside their authorized_urls, and no public_auth site covers it.",
            "è fuori dai loro authorized_urls, e nessun site public_auth lo copre.",
        ),
        K::WhyNotEnrolled => m(
            lang,
            "is not in users, and no public_auth site covers this URL.",
            "non è in users, e nessun site public_auth copre questo URL.",
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
        K::ReadOnly => m(lang, "read-only preview", "anteprima in sola lettura"),
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
/// navigation: what the file has, the GUI has a tab for.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Route {
    Dashboard,
    Groups,
    Sites,
    Denied,
    Users,
    /// One roster row. Carries the email already percent-**decoded**.
    User(String),
    Can,
}

impl Route {
    /// This route's path below the base — the canonical spelling, which is also what every
    /// href and the language redirect are built from. Nothing a client sent survives into
    /// one: the email is re-encoded by [`pct_encode_segment`], so the result is printable
    /// ASCII whatever the roster contains.
    fn path(&self) -> String {
        match self {
            Route::Dashboard => "/".to_string(),
            Route::Groups => "/groups".to_string(),
            Route::Sites => "/sites".to_string(),
            Route::Denied => "/denied".to_string(),
            Route::Users => "/users".to_string(),
            Route::User(e) => format!("/users/{}", pct_encode_segment(e)),
            Route::Can => "/can".to_string(),
        }
    }

    /// Which nav tab to mark current for this route — a user's detail page belongs to the
    /// `users` tab.
    fn tab(&self) -> Route {
        match self {
            Route::User(_) => Route::Users,
            other => other.clone(),
        }
    }
}

/// Resolve a request path to a page, or `None` for a 404.
///
/// `base` is [`normalize_base_path`]'s output. A request outside it is not this service's —
/// it 404s rather than falling through to the dashboard, so a misconfigured `location` in
/// nginx shows up as a missing page instead of a GUI that silently answers everywhere.
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
    match rest.trim_end_matches('/') {
        "" => Some(Route::Dashboard),
        "/groups" => Some(Route::Groups),
        "/sites" => Some(Route::Sites),
        "/denied" => Some(Route::Denied),
        "/users" => Some(Route::Users),
        "/can" => Some(Route::Can),
        p => p
            .strip_prefix("/users/")
            .filter(|e| !e.is_empty() && !e.contains('/'))
            .map(|e| Route::User(pct_decode(e))),
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

/// `302` to `location`, setting the language cookie. `location` is built from a [`Route`]
/// and re-encoded query parameters, so it is printable ASCII by construction and [`h`]
/// cannot panic on it.
fn respond_lang_redirect(req: Request, location: &str, lang: Lang) {
    let cookie = format!(
        "{LANG_COOKIE}={}; Max-Age={LANG_COOKIE_MAX_AGE}; Path=/; HttpOnly; SameSite=Lax",
        lang.code()
    );
    let resp = Response::empty(StatusCode(302))
        .with_header(h("Location", location))
        .with_header(h("Set-Cookie", &cookie[..]))
        .with_header(h("Cache-Control", "no-store"));
    let _ = req.respond(resp);
}

/// Which language to render in. Query, then cookie, then `Accept-Language`, then the
/// configured default — most explicit wins.
///
/// The `Accept-Language` check is deliberately crude: does the header start with `it`? A
/// full RFC 4647 negotiation over two languages would be more code than the question is
/// worth, and both wrong answers are one click from being right (and then remembered).
fn negotiate_lang(
    query: Option<&str>,
    cookie: Option<&str>,
    accept: Option<&str>,
    default: Lang,
) -> Lang {
    if let Some(l) = query.and_then(parse_lang) {
        return l;
    }
    if let Some(l) = cookie.and_then(parse_lang) {
        return l;
    }
    if accept.is_some_and(|a| a.trim().to_ascii_lowercase().starts_with("it")) {
        return Lang::It;
    }
    default
}

/// This request's URL with the `lang` parameter dropped, or set to `to`.
///
/// Used for both the language switch link and the redirect that follows one. Every byte of
/// the result is a constant, a [`Route::path`] or a re-encoded query parameter — nothing the
/// client sent survives verbatim, which is what makes the same string safe in an `href` and
/// in a `Location:` header.
fn lang_href(cfg: &Config, at: &Route, query: &str, to: Option<Lang>) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        if k != "lang" {
            ser.append_pair(&k, &v);
        }
    }
    if let Some(l) = to {
        ser.append_pair("lang", l.code());
    }
    let q = ser.finish();
    let path = format!("{}{}", cfg.base_path, at.path());
    if q.is_empty() {
        path
    } else {
        format!("{path}?{q}")
    }
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

/// Everything the page shell needs that is not the page.
struct View<'a> {
    cfg: &'a Config,
    lang: Lang,
    /// The signed-in administrator, when there is one. `None` suppresses the navigation:
    /// a visitor who got a `401` or a `403` has nowhere to go but the login page.
    admin: Option<&'a str>,
    /// The route being rendered, for the current tab and the language switch.
    at: Route,
    /// The query as received, so switching language keeps the `can` form filled in.
    query: &'a str,
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

/// The chrome around every page: the tabs, the language switch, the footer.
///
/// The tabs are the access file's four sections **in file order** — `url_groups`, `sites`,
/// `denied`, `users` — with the dashboard in front and the tester at the end. Reading the
/// nav left to right is reading the file top to bottom, and the labels are the section names
/// themselves, untranslated, because those are the words an operator types.
fn shell(v: &View, title: &str, content: Markup) -> Markup {
    let tabs = [
        (Route::Dashboard, v.t(K::Dashboard)),
        (Route::Groups, "url_groups"),
        (Route::Sites, "sites"),
        (Route::Denied, "denied"),
        (Route::Users, "users"),
        (Route::Can, "can"),
    ];
    let current = v.at.tab();
    html! {
        (DOCTYPE)
        html lang=(v.lang.code()) {
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
                        span class="brand" {
                            "bb-auth-web"
                            span class="v" { "v" (env!("CARGO_PKG_VERSION")) }
                        }
                        @if v.admin.is_some() {
                            nav {
                                @for (r, label) in &tabs {
                                    a class=@if *r == current { "on" } @else { "" }
                                      href=(v.href(r)) { (label) }
                                }
                            }
                        } @else {
                            nav {}
                        }
                        span class="lang" {
                            span { (v.lang.code()) }
                            "·"
                            a href=(lang_href(v.cfg, &v.at, v.query, Some(v.lang.other()))) {
                                (v.lang.other().code())
                            }
                        }
                    }
                }
                main { (content) }
                footer {
                    span { (v.t(K::ReadOnly)) }
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
fn denied_set(doc: &AccessFile) -> Vec<String> {
    doc.denied.iter().map(|d| norm_email(d)).collect()
}

/// Whether a scope grants nothing: absent, empty, or nothing but blank entries (which
/// `compile_access` drops).
fn scope_is_empty(urls: Option<&Vec<String>>) -> bool {
    urls.is_none_or(|l| l.iter().all(|u| u.trim().is_empty()))
}

/// `/` — the counts, what expires next, and everything the file says that an operator would
/// rather hear now than at 3am.
///
/// The warnings are computed from library data only ([`url_group_refs`], the scopes, the
/// `denied` list). `bb-auth-adm check`'s site-shadowing lint deliberately stays in the CLI:
/// it is a heuristic with an operator to explain itself to, and duplicating it here would
/// mean two implementations of a judgement call.
fn page_dashboard(v: &View, doc: &AccessFile) -> Markup {
    let n = now();
    let key_count: usize = doc.users.iter().map(|u| u.api_keys.len()).sum();

    // Every key in the file, soonest expiry first.
    let mut keys: Vec<(String, &ApiKeySpec, Expiry)> = doc
        .users
        .iter()
        .flat_map(|u| {
            u.api_keys
                .iter()
                .map(move |k| (norm_email(&u.email), k, expiry_of(k, n)))
        })
        .collect();
    keys.sort_by_key(|(_, _, e)| e.rank());

    let denied = denied_set(doc);
    let mut warnings: Vec<Markup> = Vec::new();
    for u in &doc.users {
        if scope_is_empty(u.authorized_urls.as_ref()) {
            let email = norm_email(&u.email);
            warnings.push(html! { code { (email) } " " (v.t(K::WarnNoScope)) });
        }
    }
    for name in doc.url_groups.keys() {
        if url_group_refs(doc, name).is_empty() {
            warnings.push(html! { code { "@" (name) } " " (v.t(K::ReferencedByNothing)) });
        }
    }
    for u in &doc.users {
        let email = norm_email(&u.email);
        if denied.contains(&email) {
            warnings.push(html! { code { (email) } " " (v.t(K::WarnEnrolledAndDenied)) });
        }
    }

    html! {
        h1 { (v.t(K::Dashboard)) }
        p class="lede" { code { (v.cfg.access_path) } }

        h2 { (v.t(K::Counts)) }
        div class="cards" {
            @for (label, count) in [
                ("users", doc.users.len()),
                ("api_keys", key_count),
                ("sites", doc.sites.len()),
                ("url_groups", doc.url_groups.len()),
                ("denied", doc.denied.len()),
            ] {
                div class="card" {
                    div class="n" { (count) }
                    div class="l mono" { (label) }
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
                        @for (email, k, e) in &keys {
                            tr {
                                td { a href=(v.href(&Route::User(email.clone()))) { (email) } }
                                td class="mono" { (k.id.trim()) }
                                td { (expiry_markup(v.lang, e)) }
                            }
                        }
                    }
                }
            }
        }

        h2 { (v.t(K::Warnings)) }
        div class="panel" {
            @if warnings.is_empty() {
                span class="muted" { (v.t(K::NoWarnings)) }
            } @else {
                ul class="plain" { @for w in &warnings { li { (*w) } } }
            }
        }
    }
}

/// `/users` — the roster.
fn page_users(v: &View, doc: &AccessFile) -> Markup {
    let denied = denied_set(doc);
    html! {
        h1 { "users" }
        p class="lede" { (v.t(K::UsersIntro)) }
        div class="panel" {
            @if doc.users.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                table {
                    thead { tr {
                        th { "email" }
                        th { "authorized_urls" }
                        th { "api_keys" }
                    } }
                    tbody {
                        @for u in &doc.users {
                            @let email = norm_email(&u.email);
                            tr {
                                td {
                                    a href=(v.href(&Route::User(email.clone()))) { (email) }
                                    @if denied.contains(&email) {
                                        " " (tag("bad", "denied"))
                                    }
                                }
                                // Raw entries, so an `@group` reference counts as the one
                                // line it is in the file.
                                td {
                                    @if scope_is_empty(u.authorized_urls.as_ref()) {
                                        span class="bad" { (v.t(K::ReachesNothing)) }
                                    } @else {
                                        (u.authorized_urls.as_ref().map_or(0, Vec::len))
                                    }
                                }
                                td { (u.api_keys.len()) }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// `/users/{email}` — one roster row, as the file stores it.
fn page_user(v: &View, doc: &AccessFile, email: &str) -> (u16, Markup) {
    let u: &UserSpec = match user_pos(doc, email).map(|i| &doc.users[i]) {
        Some(u) => u,
        None => {
            return (
                404,
                html! {
                    h1 { (v.t(K::NoSuchUser)) }
                    p class="lede" { code { (email) } }
                    p { a href=(v.href(&Route::Users)) { "← " (v.t(K::Back)) } }
                },
            )
        }
    };
    let n = now();
    let normalised = norm_email(&u.email);
    let denied = denied_set(doc).contains(&normalised);
    let notes = u.extra.get("notes").and_then(|n| n.as_str());

    (
        200,
        html! {
            h1 {
                (normalised)
                @if denied { " " (tag("bad", "denied")) }
            }
            p class="lede" { a href=(v.href(&Route::Users)) { "← " (v.t(K::Back)) } }

            @if let Some(notes) = notes {
                div class="panel" { span class="muted mono" { "notes " } (notes) }
            }

            h2 { "authorized_urls" }
            div class="panel" {
                (url_list(v.lang, u.authorized_urls.as_ref(), t(v.lang, K::ReachesNothing)))
            }

            h2 { "api_keys" }
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
                            th { "authorized_urls" }
                        } }
                        tbody {
                            @for k in &u.api_keys {
                                tr {
                                    td class="mono" { (k.id.trim()) }
                                    td class="mono" { (k.released.trim()) }
                                    td class="mono" { (k.duration.trim()) }
                                    td { (expiry_markup(v.lang, &expiry_of(k, n))) }
                                    td {
                                        (url_list(
                                            v.lang,
                                            k.authorized_urls.as_ref(),
                                            t(v.lang, K::Inherits),
                                        ))
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

/// `/groups` — each `url_groups` entry and everything that names it.
fn page_groups(v: &View, doc: &AccessFile) -> Markup {
    html! {
        h1 { "url_groups" }
        p class="lede" { (v.t(K::GroupsIntro)) }
        @if doc.url_groups.is_empty() {
            div class="panel" { span class="muted" { (v.t(K::None)) } }
        } @else {
            @for (name, urls) in &doc.url_groups {
                @let refs = url_group_refs(doc, name);
                div class="panel" {
                    h2 style="margin-top:0" { code { "@" (name) } }
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
                    p class="muted" { (v.t(K::Patterns)) }
                    ul class="plain mono" { @for u in urls { li { (u) } } }
                }
            }
        }
    }
}

/// `/sites` — the site table, **numbered, in file order**.
///
/// An ordered list and not a grid, because the number *is* the meaning: `Sites::resolve` is
/// first-match-wins, so position 1 shadows position 2 for any URL both cover. A layout that
/// let the eye wander would be hiding the one property this section has.
fn page_sites(v: &View, doc: &AccessFile) -> Markup {
    html! {
        h1 { "sites" }
        p class="lede" { (v.t(K::SitesIntro)) }
        div class="panel" {
            @if doc.sites.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                ol class="sites" {
                    @for s in &doc.sites {
                        li { (site_block(v, s)) }
                    }
                }
            }
        }
    }
}

fn site_block(v: &View, s: &SiteSpec) -> Markup {
    html! {
        div {
            strong { (site_name(s)) }
            " "
            @if s.public_auth {
                (tag("warn", "public_auth"))
            } @else {
                (tag("", "public_auth: false"))
            }
        }
        @if let Some(l) = &s.login_url {
            div class="muted" { "login_url " span class="mono" { (l) } }
        }
        @if s.urls.is_empty() {
            div class="bad" { "urls: [] — " (v.t(K::ReachesNothing)) }
        } @else {
            ul class="plain mono" { @for u in &s.urls { li { (u) } } }
        }
    }
}

/// `/denied` — the veto list.
fn page_denied(v: &View, doc: &AccessFile) -> Markup {
    html! {
        h1 { "denied" }
        p class="lede" { (v.t(K::DeniedIntro)) }
        div class="panel" {
            @if doc.denied.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                ul class="plain" {
                    @for d in &doc.denied {
                        @let email = norm_email(d);
                        li {
                            code { (email) }
                            @if user_pos(doc, &email).is_some() {
                                " "
                                a href=(v.href(&Route::User(email.clone()))) {
                                    (tag("", t(v.lang, K::AlsoEnrolled)))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// `/can` — the tester. A `GET` form, and the gate's own [`decide`] behind it.
///
/// Only the two Cognito-backed credentials are asked about here: an id_token bearer and a
/// session cookie resolve to nothing but an email, which is exactly what the form collects.
/// (`bb-auth-adm can --key ID` also evaluates a `bbk_` key; that arm needs a key to name,
/// and belongs with the write phase that can mint one.)
fn page_can(v: &View, access: &Access, query: &str) -> Markup {
    let email_in = query_param(query, "email").unwrap_or_default();
    let url_in = query_param(query, "url").unwrap_or_default();
    let asked = !email_in.trim().is_empty() && !url_in.trim().is_empty();
    let email = norm_email(&email_in);
    let url = request_url(&url_in);

    html! {
        h1 { "can" }
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
            div class="panel" { (verdict(v, access, &email, &url)) }
        }
    }
}

/// One verdict, with the reason the gate would have. The wording follows `bb-auth-adm can`'s
/// — same decision, same explanation, so an operator who has read one recognises the other.
fn verdict(v: &View, access: &Access, email: &str, url: &str) -> Markup {
    let decision = decide(access, email, Some(url));
    html! {
        p class=@if decision.granted() { "verdict yes" } @else { "verdict no" } {
            @if decision.granted() { (v.t(K::Authorized)) } @else { (v.t(K::VerdictDenied)) }
        }
        p {
            @match &decision {
                Decision::SiteGrant(site) => {
                    "site " code { (site) } " " (v.t(K::WhySiteGrant))
                }
                Decision::RosterGrant => { code { (email) } " " (v.t(K::WhyRosterGrant)) }
                Decision::Vetoed => { code { (email) } " " (v.t(K::WhyVetoed)) }
                Decision::OutOfScope => { code { (url) } " " (v.t(K::WhyOutOfScope)) }
                Decision::NotEnrolled => { code { (email) } " " (v.t(K::WhyNotEnrolled)) }
            }
        }
        @if decision.granted() {
            p class="muted" {
                (v.t(K::AppSees)) " " code { (IDENTITY_HEADER) ": " (email) }
            }
        }
    }
}

/// A page that is only a message: the `401`, the `403`, the `404` and the broken-file page.
fn notice(v: &View, title: &str, body: Markup) -> Markup {
    shell(
        v,
        title,
        html! {
            h1 { (title) }
            div class="panel" { (body) }
        },
    )
}

/// The page for an access file the gate would refuse. The library's message goes out
/// **verbatim** — it is the same sentence `bb-auth --check-users` and a failed startup
/// print, and an operator who can match those three is an operator who can fix the file.
fn page_file_error(v: &View, err: &str) -> Markup {
    notice(
        v,
        v.t(K::FileErrorTitle),
        html! {
            p class="mono bad" { (err) }
            p class="muted" { (v.t(K::FileErrorHint)) }
        },
    )
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// Serve one request: identify, authorize, route, render.
///
/// The order is the point. Identity and the admin allowlist come **before** the router and
/// before the file is opened, so there is no path — not a 404, not a broken access file —
/// that renders anything about the roster to someone nginx did not vouch for.
fn handle(req: Request, cfg: &Config) {
    let target = req.url().to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let lang = negotiate_lang(
        query_param(&query, "lang").as_deref(),
        header_value(&req, "Cookie").and_then(|c| cookie_value(c, LANG_COOKIE)),
        header_value(&req, "Accept-Language"),
        cfg.default_lang,
    );
    // Nothing is routed yet, so the language switch on an error page points at the root.
    let anon = |at: Route| View {
        cfg,
        lang,
        admin: None,
        at,
        query: "",
    };

    // Identity comes from nginx and from nowhere else. A missing header is a broken
    // deployment, not an anonymous visitor — say so, and fail closed.
    let raw_email = match header_value(&req, IDENTITY_HEADER) {
        Some(e) if !e.trim().is_empty() => e.to_string(),
        _ => {
            let v = anon(Route::Dashboard);
            let page = notice(
                &v,
                v.t(K::NoIdentityTitle),
                html! { p { (v.t(K::NoIdentityBody)) } },
            );
            respond_page(req, 401, page);
            return;
        }
    };
    let email = norm_email(&raw_email);
    if !cfg.is_admin(&email) {
        let v = anon(Route::Dashboard);
        let page = notice(
            &v,
            v.t(K::NotAdminTitle),
            html! { p { code { (email) } " " (v.t(K::NotAdminBody)) } },
        );
        respond_page(req, 403, page);
        return;
    }

    let at = match route(&path, &cfg.base_path) {
        Some(r) => r,
        None => {
            let v = View {
                cfg,
                lang,
                admin: Some(&email),
                at: Route::Dashboard,
                query: "",
            };
            let page = notice(
                &v,
                v.t(K::NotFoundTitle),
                html! { p { (v.t(K::NotFoundBody)) } },
            );
            respond_page(req, 404, page);
            return;
        }
    };

    // An explicit `?lang=` is a choice: remember it, then send the browser to the same page
    // without the parameter, so a bookmark or a reload does not carry it around forever.
    // The rest of the query survives, which is what keeps a `can` result on screen.
    if query_param(&query, "lang")
        .and_then(|l| parse_lang(&l))
        .is_some()
    {
        respond_lang_redirect(req, &lang_href(cfg, &at, &query, None), lang);
        return;
    }

    let v = View {
        cfg,
        lang,
        admin: Some(&email),
        at: at.clone(),
        query: &query,
    };

    // Fresh off disk, every request. See the crate docs for why there is no cache.
    let (doc, access) = match open_access_file(&cfg.access_path) {
        Ok(pair) => pair,
        Err(e) => {
            respond_page(req, 500, page_file_error(&v, &e));
            return;
        }
    };

    let (status, content, title) = match &at {
        Route::Dashboard => (200, page_dashboard(&v, &doc), v.t(K::Dashboard)),
        Route::Groups => (200, page_groups(&v, &doc), "url_groups"),
        Route::Sites => (200, page_sites(&v, &doc), "sites"),
        Route::Denied => (200, page_denied(&v, &doc), "denied"),
        Route::Users => (200, page_users(&v, &doc), "users"),
        Route::User(email) => {
            let (status, content) = page_user(&v, &doc, email);
            (status, content, "users")
        }
        Route::Can => (200, page_can(&v, &access, &query), "can"),
    };
    respond_page(req, status, shell(&v, title, content));
}

/// Read the config, bind, and serve forever on a fixed pool of blocking threads — the gate's
/// shape, minus everything the gate needs and this does not.
fn main() {
    let cfg = Config::from_env();

    // Read once at startup so a broken file is heard about immediately, and so the banner
    // can say what is in it. Not fatal: the GUI's job is to *show* a broken file.
    match open_access_file(&cfg.access_path) {
        Ok((doc, _)) => eprintln!(
            "[bb-auth-web] {}: {} users, {} sites, {} url_groups, {} denied",
            cfg.access_path,
            doc.users.len(),
            doc.sites.len(),
            doc.url_groups.len(),
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
        "[bb-auth-web] listening on {} | file={} | admins={} | base={base} | lang={} | read-only",
        cfg.listen,
        cfg.access_path,
        cfg.admins.len(),
        cfg.default_lang.code()
    );
    eprintln!(
        "[bb-auth-web] identity comes from the {IDENTITY_HEADER} header — this port must be \
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

    /// A file with one of everything, so a rendering test has something to render.
    const SAMPLE: &str = r#"{
      "url_groups": { "mcp": ["https://mcp.x.com/mcp/*"], "unused": ["https://old.x.com/*"] },
      "sites": [
        { "name": "onboarding", "urls": ["https://app.x.com/hello/*"], "public_auth": true }
      ],
      "denied": ["spammer@x.com"],
      "users": [
        { "email": "Bob@X.com", "authorized_urls": ["@mcp"], "notes": "the bot",
          "api_keys": [ { "id": "laptop",
            "key_hash": "1111111111111111111111111111111111111111111111111111111111111111",
            "released": "1970-01-01", "duration": "1d" } ] },
        { "email": "nowhere@x.com" }
      ]
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
        assert_eq!(route("/sites", ""), Some(Route::Sites));
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
            negotiate_lang(Some("it"), Some("en"), Some("en-GB"), Lang::En),
            Lang::It
        );
        // cookie beats the header
        assert_eq!(
            negotiate_lang(None, Some("it"), Some("en-GB"), Lang::En),
            Lang::It
        );
        // header beats the default
        assert_eq!(
            negotiate_lang(None, None, Some("it-IT,it;q=0.9"), Lang::En),
            Lang::It
        );
        // and the default is the floor
        assert_eq!(
            negotiate_lang(None, None, Some("de-DE"), Lang::En),
            Lang::En
        );
        assert_eq!(negotiate_lang(None, None, None, Lang::It), Lang::It);
        // an unparseable preference is not a preference
        assert_eq!(
            negotiate_lang(Some("fr"), Some("it"), None, Lang::En),
            Lang::It
        );
    }

    #[test]
    fn lang_href_swaps_the_parameter_and_keeps_the_rest() {
        let cfg = cfg_for("x.json", "/admin");
        let q = "email=bob%40x.com&lang=en";
        assert_eq!(
            lang_href(&cfg, &Route::Can, q, Some(Lang::It)),
            "/admin/can?email=bob%40x.com&lang=it"
        );
        assert_eq!(
            lang_href(&cfg, &Route::Can, q, None),
            "/admin/can?email=bob%40x.com"
        );
        assert_eq!(lang_href(&cfg, &Route::Dashboard, "", None), "/admin/");
    }

    #[test]
    fn lang_href_never_carries_client_bytes_verbatim() {
        // Everything a client sent is re-encoded, so this string is safe in a Location:.
        let cfg = cfg_for("x.json", "");
        let href = lang_href(&cfg, &Route::Can, "url=https://x/%0d%0aX:+1&lang=it", None);
        assert!(href.bytes().all(|b| b.is_ascii_graphic()), "{href}");
        assert!(!href.contains('\r') && !href.contains('\n'));
    }

    #[test]
    fn cookie_value_parses_the_language_cookie() {
        assert_eq!(cookie_value("lang=it", LANG_COOKIE), Some("it"));
        assert_eq!(cookie_value("a=1; lang=en; b=2", LANG_COOKIE), Some("en"));
        assert_eq!(cookie_value("mylang=it", LANG_COOKIE), None);
        assert_eq!(cookie_value("a=1", LANG_COOKIE), None);
    }

    // --- rendering ----------------------------------------------------------

    /// Render one page of `SAMPLE` and hand back the HTML.
    fn render(name: &str, at: Route) -> String {
        let path = scratch(name, SAMPLE);
        let cfg = cfg_for(&path, "");
        let (doc, access) = open_access_file(&cfg.access_path).unwrap();
        let v = View {
            cfg: &cfg,
            lang: Lang::En,
            admin: Some("admin@x.com"),
            at: at.clone(),
            query: "",
        };
        let content = match &at {
            Route::Dashboard => page_dashboard(&v, &doc),
            Route::Groups => page_groups(&v, &doc),
            Route::Sites => page_sites(&v, &doc),
            Route::Denied => page_denied(&v, &doc),
            Route::Users => page_users(&v, &doc),
            Route::User(e) => page_user(&v, &doc, e).1,
            Route::Can => page_can(&v, &access, "email=bob@x.com&url=https://mcp.x.com/mcp/a"),
        };
        let html = shell(&v, "t", content).into_string();
        let _ = std::fs::remove_file(&path);
        html
    }

    #[test]
    fn dashboard_counts_expiries_and_warnings() {
        let html = render("dash", Route::Dashboard);
        assert!(html.contains("url_groups"));
        // the 1970 key is long past
        assert!(html.contains("expired"), "{html}");
        // a scope-less user, an unreferenced group
        assert!(html.contains("no authorized_urls"));
        assert!(html.contains("@unused"));
        assert!(html.contains("referenced by nothing"));
    }

    #[test]
    fn user_page_shows_group_refs_raw_and_never_expanded() {
        let html = render("user", Route::User("bob@x.com".to_string()));
        assert!(html.contains("@mcp"), "the reference is shown as stored");
        assert!(
            !html.contains("https://mcp.x.com/mcp/*"),
            "a group must never be expanded on the page"
        );
        assert!(html.contains("the bot"), "notes come from extra");
        assert!(
            html.contains("inherits the user's"),
            "the key declares no scope"
        );
    }

    #[test]
    fn sites_page_is_numbered_in_file_order() {
        let html = render("sites", Route::Sites);
        assert!(
            html.contains("<ol"),
            "order is meaning, so it is an ordered list"
        );
        assert!(html.contains("onboarding") && html.contains("public_auth"));
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
        assert!(html.contains("bob@x.com"));
    }

    #[test]
    fn denied_page_marks_the_enrolled() {
        let html = render("denied", Route::Denied);
        assert!(html.contains("spammer@x.com"));
    }

    #[test]
    fn hostile_values_from_the_file_come_out_escaped() {
        // The access file is operator-owned, but it is also a text file that anything with
        // root can write, and half of it ends up in a page. maud escapes on the way in;
        // this pins that it stays that way.
        let json = r#"{ "users": [ { "email": "<script>alert(1)</script>@x.com",
                          "authorized_urls": ["https://x.com/\"><img src=x onerror=alert(1)>/*"],
                          "notes": "<b>bold</b>" } ] }"#;
        let path = scratch("xss", json);
        let cfg = cfg_for(&path, "");
        let (doc, _) = open_access_file(&cfg.access_path).unwrap();
        let v = View {
            cfg: &cfg,
            lang: Lang::En,
            admin: Some("admin@x.com"),
            at: Route::Users,
            query: "",
        };
        let email = "<script>alert(1)</script>@x.com";
        for html in [
            shell(&v, "t", page_users(&v, &doc)).into_string(),
            shell(&v, "t", page_user(&v, &doc, email).1).into_string(),
        ] {
            assert!(
                html.contains("&lt;script&gt;alert(1)&lt;/script&gt;@x.com"),
                "{html}"
            );
            assert!(!html.contains("<script>alert(1)"), "{html}");
            assert!(!html.contains("<img src=x"), "{html}");
            assert!(!html.contains("<b>bold</b>"), "{html}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_broken_file_renders_the_librarys_message_verbatim() {
        let path = scratch(
            "broken",
            r#"{ "users": [ { "email": "b@x", "authorized_urls": ["@nope"] } ] }"#,
        );
        let cfg = cfg_for(&path, "");
        // `Access` has no `Debug` on purpose (a table of live credentials), so no unwrap_err.
        let err = match open_access_file(&cfg.access_path) {
            Ok(_) => panic!("a dangling @group reference must be refused"),
            Err(e) => e,
        };
        let v = View {
            cfg: &cfg,
            lang: Lang::En,
            admin: Some("admin@x.com"),
            at: Route::Dashboard,
            query: "",
        };
        let html = page_file_error(&v, &err).into_string();
        assert!(
            html.contains("the gate would reject this file as it stands"),
            "{html}"
        );
        assert!(html.contains("unknown url group"), "{html}");
        let _ = std::fs::remove_file(&path);
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
            body.contains("url_groups") && body.contains("Warnings"),
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
}
