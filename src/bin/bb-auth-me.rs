//! bb-auth-me: the self-service page a signed-in person uses for **their own** account
//! (docs/ARCHITECTURE.md §13). It opens the two files the estate shares, works out who nginx is
//! vouching for, and answers that person with a page about their own account: where they reach,
//! the groups they are filed in, their API keys and the profile claims the proxy forwards. The
//! Cognito leg (editing a profile at the pool) is the next step, so what is here is **read
//! only**: no form, no write, nothing that can lock anybody out.
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
    ScopeRecord, Settings, BASE_CSS, IDENTITY_HEADER, PAGE_SECURITY_HEADERS, THEME_CSS,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use tiny_http::{Header, Request, Response, Server, StatusCode};

/// The request threads, mirroring `bb-auth-web`: `tiny_http` is blocking, so one thread per
/// in-flight request is what keeps a page that is reading two files from holding the port.
const WORKERS: usize = 2;

/// `BB_AUTH_ME_LISTEN`, `BB_AUTH_ACCESS_FILE`, `BB_AUTH_SETTINGS_FILE`, `BB_AUTH_ME_BASE_PATH`.
struct Config {
    listen: String,
    access_path: String,
    settings_path: String,
    /// The prefix nginx mounts this at. Carried from the env file now because the env contract
    /// is fixed by §13.2. The startup banner prints it, and only the banner reads it: no page
    /// renders an href yet, so nothing resolves a URL against it.
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

/// The languages this binary carries. One for now; the shape is `bb-auth-web`'s so that adding
/// a second is an arm in [`m`] and nothing else, and so that a key nobody translated is a
/// compile error rather than a fallback.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lang {
    En,
}

impl Lang {
    /// The `lang=` attribute.
    fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
        }
    }
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
}

/// Pick one of a key's spellings. One arm today, and the match is what makes adding a language
/// a compile-time checklist.
fn m(lang: Lang, en: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
    }
}

/// The translation table. No logic reads these strings: they are what a person is told, and a
/// decision that depended on one would change with the language.
fn t(lang: Lang, key: K) -> &'static str {
    match key {
        K::Title => m(lang, "Your account"),
        K::SignedInAs => m(lang, "Signed in as"),
        K::Uuid => m(lang, "Your account id"),
        K::NoRow => m(lang, "bb-auth has no roster row for this identity."),
        K::NoIdentityTitle => m(lang, "No identity"),
        K::NoIdentityBody => m(
            lang,
            "The proxy gated this page but sent no X-Auth-Email, so there is nobody to show a page about.",
        ),
        K::NoEmailTitle => m(lang, "No email identity"),
        K::NoEmailBody => m(
            lang,
            "gate.identity_attrs does not list email, so nginx injects no X-Auth-Email and this page has no identity to act on.",
        ),
        K::DeniedTitle => m(lang, "Refused"),
        K::DeniedBody => m(lang, "This identity is denied."),
        K::AmbiguousTitle => m(lang, "More than one account"),
        K::AmbiguousBody => m(
            lang,
            "The identity header names accounts that are not the same person, so this page cannot say who it is about.",
        ),
        K::SettingsTitle => m(lang, "Cannot read the settings"),
        K::AccessTitle => m(lang, "Cannot read the access file"),
        // The four section headings. Each is a noun naming what the list under it is, because
        // the page is read by a person looking for one of those four things.
        K::ReachTitle => m(lang, "Where you reach"),
        K::GroupsTitle => m(lang, "Groups"),
        K::KeysTitle => m(lang, "API keys"),
        K::ProfileTitle => m(lang, "Profile"),
        // One word for all four empty sections. It stays one word on purpose: the sections
        // carry no prose, so a sentence here would be the one thing a test about a *name*
        // could match by accident.
        K::Nothing => m(lang, "None."),
        K::KeyNever => m(lang, "never"),
        K::KeyAllScopes => m(lang, "all scopes"),
    }
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// What the deployment's `ui` section says a page should wear. `Look::default()` is "nothing
/// configured", and it is the honest answer on every page rendered **before** the settings file
/// has been read: the `401` and the settings `500` both happen above that read, and a page that
/// cannot know the operator's stylesheet shows the built-in one rather than guessing.
#[derive(Clone, Copy, Default)]
struct Look<'a> {
    /// `ui.stylesheet_url`: an operator's own stylesheet, loaded after the built-in one.
    stylesheet: Option<&'a str>,
    /// `ui.logo_url`: needed for the policy, since it is the one image a page may fetch.
    logo: Option<&'a str>,
}

/// The chrome every page of this binary is wrapped in: the palette, the components built out of
/// it, then the operator's stylesheet, so an override wins by source order and needs no
/// `!important`. No layout of its own yet: `BASE_CSS` is the whole answer for now, which is the
/// point of sharing it, and the arrangement the next steps want is theirs to add.
fn shell(lang: Lang, title: &str, content: Markup, look: Look) -> Markup {
    html! {
        (DOCTYPE)
        html lang=(lang.code()) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { "bb-auth-me · " (title) }
                // The two raw emissions on the page, both compile-time constants and never
                // request data. The order is the contract: the palette, then the components
                // that read it, the same bytes the gate's pages and `bb-auth-web` emit.
                style { (PreEscaped(THEME_CSS)) (PreEscaped(BASE_CSS)) }
                // Raw because the library builds a whole `<link>` element from a URL that has
                // already passed `compile_asset_url`, and maud has no way to say "an element".
                (PreEscaped(stylesheet_link(look.stylesheet)))
            }
            body {
                main class="card" {
                    h1 { (title) }
                    (content)
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
/// block, which is [`THEME_CSS`] plus [`BASE_CSS`] and nothing else. `form-action 'self'`
/// because there is no form yet, and a page that posts nowhere cannot be permitted to land
/// anywhere.
fn respond(req: Request, status: u16, lang: Lang, title: &str, content: Markup, look: Look) {
    let csp = page_csp(
        "'none'",
        &csp_hash(&format!("{THEME_CSS}{BASE_CSS}")),
        "'self'",
        look.stylesheet,
        look.logo,
        &[],
    );
    let mut resp =
        Response::from_data(shell(lang, title, content, look).into_string().into_bytes())
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
                            @if let Some(v) = value {
                                ": " code { (v) }
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
    let lang = Lang::En;
    // Identity comes from nginx and from nowhere else. A header of spaces is the same broken
    // deployment as no header at all: nginx wrote it and put nobody in it.
    let raw = match header_value(&req, IDENTITY_HEADER) {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => {
            respond(
                req,
                401,
                lang,
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
                lang,
                t(lang, K::SettingsTitle),
                html! { p { (e) } },
                Look::default(),
            );
            return;
        }
    };
    let look = Look {
        stylesheet: settings.stylesheet_url.as_deref(),
        logo: settings.logo_url.as_deref(),
    };
    // `gate.identity_attrs` without `email` means nginx injects no `X-Auth-Email`, so there is
    // no identity for this page to act on. The page names the setting, because the operator
    // reading it is the only person who can fix it.
    if !settings.identity_attrs.iter().any(|a| a.attr == "email") {
        respond(
            req,
            500,
            lang,
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
                lang,
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
            lang,
            t(lang, K::DeniedTitle),
            html! { p { (t(lang, K::DeniedBody)) } },
            look,
        );
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
            lang,
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
        lang,
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
}
