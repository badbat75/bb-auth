//! bb-auth-me: the self-service page a signed-in person uses for **their own** account
//! (docs/ARCHITECTURE.md §13). Plan step 2b-1 is the identity half of it: open the two files
//! the estate shares, work out who nginx is vouching for, and answer that person with a page
//! that names them. Their keys, their profile and the Cognito leg are the next steps, so what
//! is here is the shape those steps fill in, and nothing beyond it.
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
    csp_hash, default_settings_path, norm_email, open_settings_file, page_csp, read_access,
    stylesheet_link, version_line, BASE_CSS, IDENTITY_HEADER, PAGE_SECURITY_HEADERS, THEME_CSS,
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

/// The page a caller gets: who they are, as the header carried it, and their uuid when the access
/// file has a row for them.
///
/// A stranger is named too, and told there is no row: the `authenticated` scope §13.4 chose for
/// this URL admits any identity Cognito vouches for, so "bb-auth knows nothing about you" is a
/// page a real caller reaches, not a defensive one.
fn page_me(lang: Lang, ids: &[String], uuid: Option<&str>) -> Markup {
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
    let access = match read_access(&cfg.access_path) {
        Ok(a) => a,
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
    respond(
        req,
        200,
        lang,
        t(lang, K::Title),
        page_me(lang, &ids, uuids[0]),
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
    use bb_auth_core::{norm_email, IDENTITY_HEADER, PAGE_SECURITY_HEADERS};
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

    /// The access file and the settings file beside it, under a name unique to this test:
    /// tests run in parallel and share one temp directory.
    fn scratch(name: &str, settings: &str) -> String {
        let p = std::env::temp_dir().join(format!("bb-auth-me-{name}.json"));
        std::fs::write(&p, ACCESS).expect("write the access fixture");
        let path = p.to_string_lossy().into_owned();
        std::fs::write(format!("{path}.settings"), settings).expect("write the settings fixture");
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
        let mut req = client().get(base);
        if let Some(v) = identity {
            req = req.header(IDENTITY_HEADER, v);
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
}
