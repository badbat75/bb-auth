use super::*;

mod account;
mod account_boundary;
mod account_delete;
mod account_delete_partial;
mod account_delete_row;
mod account_delete_signout;
mod account_delete_stranger;
mod account_keys;
mod account_profile;
mod account_profile_code;
mod account_ui;
mod account_ui_confirm;
mod bar;
mod config;
mod document;
mod mutations;
mod prefs;
mod rendering;
mod server;
mod settings;
mod users_tab;

/// The header the gate names a native session's Cognito user in (§13.25). The web binary
/// reads it from 5g on; the tests name it here so a spelling change is one edit.
use bb_auth_core::NATIVE_USERNAME_HEADER;

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
/// The pool the fixture deployment belongs to. A constant because the fixture file and
/// every form post have to name the SAME one: a test that changed it by accident would be
/// answered by the confirmation page rather than by a save, which is correct behaviour and
/// a baffling test failure.
const TEST_ISSUER: &str = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST";
const TEST_HOSTS: &str = "badbat75.com
*.badbat75.com";
const SETTINGS: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"] },
        "web": { "admins": ["admin@x.com"] } }"#;

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
        // The self-service prefix, fixed for every fixture in this module, so the console
        // and the page have the two prefixes the design gives them (`/admin` and
        // `/account`) in every test, including the ones that never ask for the page.
        account_path: "/account".into(),
        default_lang: Lang::En,
        // Configured, so the control renders and the tests below see the shape a real
        // deployment has. The unset case is its own test.
        logout_url: Some("/auth/logout".to_string()),
        // What startup derives from the line above: with no `rd` in it, the same value.
        account_logout_url: Some("/auth/logout".to_string()),
        // Beside the access file, so a test that wants an audit writes one there and a
        // test that does not gets an empty page rather than another test's rows.
        audit_path: format!("{path}.audit"),
        // The fixture's proxy secret, so every over-the-wire test that goes through
        // [`get_with_secret`] / [`post_with_secret`] is a request the proxy would have
        // made, and the refusals below are about the secret and nothing else.
        proxy_secret: TEST_SECRET.to_string(),
        // The startup default, because no fixture here is about the worker count: the
        // handlers a test drives are reached over a socket, and the one test that needs
        // more than one thread builds its own server (`account_serve_with_workers`).
        workers: DEFAULT_WORKERS,
        // The production values: no fake endpoint (the settings file's issuer names the
        // address) and the real bound. The profile tests build their own `Config` to
        // point at a fake (`profile_boot`).
        cognito_endpoint: None,
        cognito_timeout: COGNITO_TIMEOUT,
        // The feature off, which is the startup default and what every fixture in this
        // module is: a deployment that never wired the owner's worker. The tests that want
        // it on set the fields on a copy (`account_port_intake`).
        delete_intake: None,
        delete_secret: None,
        intake_timeout: COGNITO_TIMEOUT,
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

/// The header nginx will set with the proxy secret, and the fixture's secret
/// (docs/ARCHITECTURE.md §13.3). The value is 38 characters of `[A-Za-z0-9_-]`, so it
/// passes the startup rule the moment that rule is implemented, and it is long enough that
/// a prefix of it is a meaningful "wrong secret" to send.
const SECRET_HEADER: &str = "X-BB-Web-Secret";
const TEST_SECRET: &str = "test_web_proxy_secret_0123456789ABCDEF";

/// A `GET` carrying the fixture's proxy secret. Every over-the-wire test uses this,
/// because the secret check sits **above** the identity check: a request that does not
/// send it is a `403` whatever else it carries, and a test about the allowlist, the `rev`
/// or the language cookie has to be a request the proxy would have made. A test that wants
/// the refusal builds its request with [`client`] and no secret.
fn get_with_secret<T>(url: T) -> ureq::RequestBuilder<ureq::typestate::WithoutBody>
where
    ureq::http::Uri: TryFrom<T>,
    <ureq::http::Uri as TryFrom<T>>::Error: Into<ureq::http::Error>,
{
    client().get(url).header(SECRET_HEADER, TEST_SECRET)
}

/// The `POST` half of [`get_with_secret`].
fn post_with_secret<T>(url: T) -> ureq::RequestBuilder<ureq::typestate::WithBody>
where
    ureq::http::Uri: TryFrom<T>,
    <ureq::http::Uri as TryFrom<T>>::Error: Into<ureq::http::Error>,
{
    client().post(url).header(SECRET_HEADER, TEST_SECRET)
}

/// Every header value and the body of a response, as one string, for a test that has to
/// prove a value appears **nowhere** in what came back. A non-UTF-8 header contributes
/// nothing: it cannot carry an ASCII secret anyway.
fn everything_in(mut r: ureq::http::Response<ureq::Body>) -> String {
    let mut all = String::new();
    for (name, value) in r.headers().iter() {
        all.push_str(&format!("{name}: {}\n", value.to_str().unwrap_or("")));
    }
    all.push_str(&r.body_mut().read_to_string().unwrap());
    all
}

/// Serve the GUI over a real socket on an ephemeral port, from a fixture on disk, and
/// return the port. The tests below need the socket because the check under test is on the
/// request path, above the router.
fn serve(path: &str, base: &str) -> u16 {
    let cfg = cfg_for(path, base);
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &cfg);
        }
    });
    port
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
/// The token a held save renders into its hidden field, or `None` if this page is not
/// one. Read out of the HTML rather than recomputed, because that is what a browser does
/// and a test that recomputed it would agree with the code by construction.
fn confirm_token(html: &str) -> Option<String> {
    const NEEDLE: &str = r#"name="confirm" value=""#;
    let rest = &html[html.find(NEEDLE)? + NEEDLE.len()..];
    Some(rest[..rest.find('"')?].to_string())
}

/// Save a settings form the way a person does: post it, and when the page comes back
/// asking about a guarded change, read its token and post again.
///
/// Every settings test that writes goes through here, because that second post IS what
/// saving means on this page now. A test that skipped it would be exercising a save this
/// GUI does not have.
fn post_settings(cfg: &Config, sp: &str, over: &[(&str, &str)]) -> Got {
    let first = post(cfg, Route::Config, &settings_fields(&rev_of(sp), over));
    let held = match &first {
        Got::Page(200, html) => confirm_token(html),
        _ => None,
    };
    let Some(token) = held else { return first };
    let rev = rev_of(sp);
    let mut fields = settings_fields(&rev, over);
    fields.push(("confirm", &token));
    post(cfg, Route::Config, &fields)
}

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

/// One application, one `authenticated` scope (the grant docs/ARCHITECTURE.md §13.4 chose
/// for this page, so a stranger is a real caller), two roster rows, and the `denied` veto.
const ACCOUNT_ACCESS: &str = r#"{ "version": 1,
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

fn account_access_keys() -> String {
    ACCOUNT_ACCESS_KEYS
        .replace("__BOB__", ACCOUNT_BOB)
        .replace("__CAROL__", ACCOUNT_CAROL)
        .replace("__LAPTOP_HASH__", &sha256_hex(ACCOUNT_BEARER_LAPTOP))
        .replace("__CI_HASH__", &sha256_hex(ACCOUNT_BEARER_CI))
        .replace("__PHONE_HASH__", &sha256_hex(ACCOUNT_BEARER_PHONE))
}

fn account_access_mint() -> String {
    ACCOUNT_ACCESS_MINT
        .replace("__BOB__", ACCOUNT_BOB)
        .replace("__CAROL__", ACCOUNT_CAROL)
}

const ACCOUNT_ACCESS_NO_NARROW: &str = r#"{ "version": 1,
  "applications": [
    { "name": "mpa", "base": ["https://app.x.com/mpa"],
      "scopes": [
        { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"], "access": "restricted",
          "users": ["__DAVE__"], "credentials": ["login"] },
        { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"], "access": "authenticated" } ] } ],
  "users": [ { "uuid": "__DAVE__", "emails": ["dave@x.com"] } ] }"#;

/// The full roster fixture with one fact added: the `authenticated` onboarding scope keeps
/// bob **out**. An `excluded` entry is the one reference `remove_user` must not simply
/// drop (dropping a veto lifts it), and the fixture the other tests share has none.
fn account_access_roster() -> String {
    ACCOUNT_ACCESS_FULL
        .replace(
            r#""access": "authenticated" } ] },"#,
            r#""access": "authenticated", "excluded": ["__BOB__"] } ] },"#,
        )
        .replace("__BOB__", ACCOUNT_BOB)
        .replace("__CAROL__", ACCOUNT_CAROL)
        .replace("__LAPTOP_HASH__", &sha256_hex(ACCOUNT_BEARER_LAPTOP))
        .replace("__CI_HASH__", &sha256_hex(ACCOUNT_BEARER_CI))
}

/// The mint fixture with bob's row already holding ten keys: the bound is
/// ten per row counting every key, the administrator's included, so the
/// fixture's own two keys are not enough to reach it and these ten are
/// indistinguishable from keys an administrator minted.
fn account_access_ten_keys() -> String {
    let keys = (1..=10)
        .map(|i| {
            format!(
                "{{ \"id\": \"key{i}\", \"key_hash\": \"{:064x}\", \"released\": \"2026-01-01\", \
                     \"duration\": \"365d\" }}",
                i
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    ACCOUNT_ACCESS_MINT
            .replace(
                r#""uuid": "__BOB__", "emails": ["bob@x.com", "bob@old.com"] },"#,
                &format!(
                    r#""uuid": "__BOB__", "emails": ["bob@x.com", "bob@old.com"], "api_keys": [{keys}] }},"#
                ),
            )
            .replace("__BOB__", ACCOUNT_BOB)
            .replace("__CAROL__", ACCOUNT_CAROL)
}

/// The minted bearer as the page shows it: the one `bbk_` token in the
/// document, read to the end of the base64url run the library's mint
/// produces. A page that shows two is showing somebody's mint twice.
fn account_bearer_in(body: &str) -> String {
    let i = body.find("bbk_").unwrap_or_else(|| {
        panic!(
            "the mint page must show the bearer: {}",
            account_readable(body)
        )
    });
    let rest = &body[i..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

/// The two raw bearers whose hashes the fixture stores. The keys exist so a test can say
/// the page carries **neither** the bearer nor its hash: a page that printed a hash is
/// one step from printing the file's secret material.
const ACCOUNT_BEARER_LAPTOP: &str = "bbk_testkeytestkeytestkey";

const ACCOUNT_BOB: &str = "11111111-1111-4111-8111-111111111111";

/// `GET /account/` carrying the identity header nginx injects, and the proxy secret this
/// deployment answers on, or carrying no identity at all.
fn account_call(url: &str, identity: Option<&str>) -> AccountGot {
    account_call_with(url, identity, &[])
}

/// The request a preference test makes: signed in as `identity`, with the browser's
/// `Cookie` header carrying the preferences it already chose and an `Accept-Language` when
/// the caller has one. Both are assembled here so each test spells the preference it is
/// about and nothing else.
fn account_call_pref(
    url: &str,
    identity: Option<&str>,
    cookie: Option<&str>,
    accept: Option<&str>,
) -> AccountGot {
    let mut extra: Vec<(&str, &str)> = Vec::new();
    if let Some(c) = cookie {
        extra.push(("Cookie", c));
    }
    if let Some(a) = accept {
        extra.push(("Accept-Language", a));
    }
    account_call_with(url, identity, &extra)
}

/// The same request, carrying extra request headers as well, so a test can put a profile
/// header on the wire exactly as the gate emits it: percent-encoded, `X-Auth-Given-Name:
/// Bob%20Smith`, because that is the construction the estate's safety argument rests on.
fn account_call_with(url: &str, identity: Option<&str>, extra: &[(&str, &str)]) -> AccountGot {
    let mut req = account_client()
        .get(url)
        .header(SECRET_HEADER, TEST_SECRET)
        .header("Sec-Fetch-Site", "same-origin");
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
    AccountGot {
        status: r.status().as_u16(),
        headers,
        body: r.body_mut().read_to_string().expect("a body"),
    }
}

const ACCOUNT_CAROL: &str = "22222222-2222-4222-8222-222222222222";

/// The client for these requests. Same two settings as [`client`] (a refusal is asserted
/// on by its **body**, and a redirect is the thing under test rather than a step), plus a
/// deadline, so a handler that never answers fails the test instead of hanging it.
fn account_client() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(std::time::Duration::from_secs(ACCOUNT_DEADLINE_SECS)))
        .build()
        .new_agent()
}

/// A roster user whose keys can be narrowed to **no** scope at all: dave is a
/// member of a `restricted` scope whose credentials are `login` only, and the
/// only other scope is `authenticated`, which a static key never reaches
/// (`Access::key_scopes_for` returns the empty vector for exactly that pair).
/// He has a row, so the mint form renders, and the form must not offer the
/// narrowing option, because a form offering a choice with nothing to choose
/// is a control that can only be answered wrong.
const ACCOUNT_DAVE: &str = "33333333-3333-4333-8333-333333333333";

/// The inline event handlers on a self-service page **beyond the one the estate allows**.
///
/// The estate allowed none here until 2026-11-26, when the user asked for the Preferences
/// list boxes to apply on selection on this page too (PLAN.md step 13), which is the
/// console's [`SETTINGS_ONCHANGE`] and nothing else. So this is an allowlist, not a
/// detector: the handler's *value* is compared, because an `onchange` that reads like the
/// allowed one and does something else is a second script. Everything the page does beyond
/// that stays a link or a form, because the rule this surface keeps is that it works with
/// scripting off, through the `<noscript>` Apply the same form renders.
fn account_extra_handlers(document: &str) -> Vec<String> {
    let allowed = format!("onchange=\"{SETTINGS_ONCHANGE}\"");
    handlers_in(document)
        .into_iter()
        .filter(|h| *h != allowed)
        .collect()
}

/// The `<form …>` blocks inside `haystack`, in document order. The keys
/// section carries several forms with nothing between them, and an assertion
/// about **this** key's rotate form must not be satisfied by that key's
/// remove form, so each block is cut out and judged on its own.
fn account_forms(haystack: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = haystack;
    while let Some(i) = rest.find("<form") {
        let tail = &rest[i..];
        let end = tail.find("</form>").unwrap_or_else(|| {
            panic!(
                "a form is opened and never closed: {}",
                account_readable(haystack)
            )
        });
        out.push(tail[..end].to_string());
        rest = &tail[end + "</form>".len()..];
    }
    out
}

/// One response, read the way these tests read it: every header, because a preference
/// test counts the `Set-Cookie` headers a single response carries.
#[derive(Debug)]
struct AccountGot {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl AccountGot {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    /// Every `Set-Cookie` value, in the order they arrived. One submit of the preference
    /// form is one response, so the count is the contract.
    fn cookies(&self) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// The text of the first `<h1>` (or `<h2>`) in `haystack`. A translation test compares one
/// heading, because a whole section also carries names, emails and ids, and those are the
/// file's vocabulary, which is never translated.
fn account_heading(haystack: &str, tag: &str) -> String {
    // The tag **name**, not the bare `<h2>`: an account section's heading carries
    // `class="tight"` (§13.26 §2), and a search for the closed bracket loses every heading
    // that has an attribute. The character after the name is what says one tag name is not
    // the prefix of another.
    let open = format!("<{tag}");
    let mut from = 0;
    let start = loop {
        let at = from
            + haystack[from..].find(&open).unwrap_or_else(|| {
                panic!("the page has no <{tag}…>: {}", account_readable(haystack))
            });
        if matches!(
            haystack[at + open.len()..].chars().next(),
            Some('>') | Some(' ') | Some('\n') | Some('\t')
        ) {
            break at;
        }
        from = at + open.len();
    };
    let rest = &haystack[start + open.len()..];
    let open_end = rest
        .find('>')
        .unwrap_or_else(|| panic!("<{tag} is never opened: {haystack}"));
    let rest = &rest[open_end + 1..];
    let end = rest.find(&format!("</{tag}>")).unwrap_or_else(|| {
        panic!(
            "<{tag}> is opened and never closed: {}",
            account_readable(haystack)
        )
    });
    rest[..end].to_string()
}

/// The `<html …>` start tag. `THEME_CSS` spells `data-theme` inside its own selectors, so
/// an assertion about the attribute has to look at the tag and not at the page.
fn account_html_tag(body: &str) -> String {
    let start = body
        .find("<html")
        .unwrap_or_else(|| panic!("the page has no <html tag: {}", account_readable(body)));
    let rest = &body[start..];
    let end = rest.find('>').unwrap_or(rest.len());
    rest[..=end].to_string()
}

/// One key as the file wrote it: `row` is the user row's index, `id` the key's
/// id. A `serde_json::Value`, because the writer rewrites the whole document,
/// so "unchanged" is a fact about the value the file carries, not about the
/// bytes around it.
fn account_key_json(file: &str, row: usize, id: &str) -> serde_json::Value {
    let doc: serde_json::Value = serde_json::from_str(file).expect("the written file parses");
    doc["users"][row]["api_keys"]
        .as_array()
        .and_then(|ks| ks.iter().find(|k| k["id"] == id))
        .cloned()
        .unwrap_or_else(|| panic!("the file has no key `{id}` under users[{row}]: {file}"))
}

/// The page's old words for a caller with no roster row, spelled here in both languages.
///
/// They were `K::AccountNoRow`. Step 13 (PLAN.md) took the sentence out of the page, so the
/// key has no caller left and is the coder's to delete, and the assertions that the page says
/// **nothing** about a missing row still need the words to look for: a test that compared with
/// a key would stop compiling, and one that dropped the comparison would quietly become an
/// English-only check of a page that is translated. Verbatim from the table, so a paraphrase
/// here is caught by the same assert as a paraphrase there.
const ACCOUNT_NO_ROW_EN: &str = "bb-auth has no roster row for you.";

const ACCOUNT_NO_ROW_IT: &str = "bb-auth non ha una tua riga nella lista.";

/// The page as §13.2 spells it, with the trailing slash: the URL a request asks for, and
/// the `Location:` a preference submit answers with.
const ACCOUNT_PAGE: &str = "/account/";

/// The self-service prefix, and the value [`cfg_for`] puts in `Config::account_path` for
/// every fixture in this module (`BB_AUTH_WEB_ACCOUNT_PATH`, default `/account`).
const ACCOUNT_PATH: &str = "/account";

/// The whole GUI served over a real socket on an ephemeral loopback port: console at
/// [`ADMIN_BASE`], page at [`ACCOUNT_PATH`]. The thread is never joined: the test process
/// exits and the socket goes with it.
fn account_port(path: &str) -> u16 {
    serve(path, ADMIN_BASE)
}

/// The GUI served with `BB_AUTH_WEB_DELETE_INTAKE` set, so the menu row exists (§13.29 W2).
/// The address is a port nothing listens on: 7a makes **no call** to the intake, so all this
/// fixture has to be is set, and a fixture pointing at a live intake would be a test that
/// could reach a real worker, which the rules here forbid.
fn account_port_intake(path: &str) -> u16 {
    let mut cfg = cfg_for(path, ADMIN_BASE);
    cfg.delete_intake = Some("http://127.0.0.1:1".to_string());
    cfg.delete_secret = Some(TEST_SECRET.to_string());
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &cfg);
        }
    });
    port
}

/// The GUI served with the intake pointing at a **live** listener, so a request the page
/// sends is a request a test can count. 7c's `FakeIntake` is the full version of this; 7b
/// needs only "did the page send anything", and a page that sends nothing is proved by a
/// listener that saw nothing.
fn account_port_intake_at(path: &str, intake: &str) -> u16 {
    let mut cfg = cfg_for(path, ADMIN_BASE);
    cfg.delete_intake = Some(intake.to_string());
    cfg.delete_secret = Some(TEST_SECRET.to_string());
    cfg.intake_timeout = TEST_INTAKE_TIMEOUT;
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &cfg);
        }
    });
    port
}

/// The GUI served with the intake pointing at a live listener **and** the logout URL given.
/// The done page's two variants (§13.32 §1: a `303` through the gate's logout, or the page
/// that says what the person can do themselves) are the same walk on two configs.
///
/// `account_logout_url` is derived by [`logout_without_rd`], exactly as startup derives it
/// from the same value (see the field's comment in [`cfg_for`]): the pair a deletion's
/// redirect is built from is the operator's URL **with the console's `rd` cut**, so a fixture
/// that handed the raw value over would make every assertion about that redirect red for a
/// reason no deployment can produce.
fn account_port_intake_logout(path: &str, intake: &str, logout: Option<&str>) -> u16 {
    let mut cfg = cfg_for(path, ADMIN_BASE);
    cfg.delete_intake = Some(intake.to_string());
    cfg.delete_secret = Some(TEST_SECRET.to_string());
    cfg.logout_url = logout.map(str::to_string);
    cfg.account_logout_url = logout.map(logout_without_rd);
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &cfg);
        }
    });
    port
}

/// A `POST` under the prefix, as the proxy-and-browser pair sends one: the
/// secret, the identity header, the same-origin marker, and a form body.
fn account_post(url: &str, identity: Option<&str>, fields: &[(&str, &str)]) -> AccountGot {
    account_post_as(url, identity, fields, "same-origin", true)
}

/// The same `POST` with the two things that gate it spelled out: the
/// `Sec-Fetch-Site` the browser writes, and whether the proxy secret is on
/// the request at all.
fn account_post_as(
    url: &str,
    identity: Option<&str>,
    fields: &[(&str, &str)],
    sec_fetch: &str,
    with_secret: bool,
) -> AccountGot {
    let mut req = account_client()
        .post(url)
        .header("Sec-Fetch-Site", sec_fetch);
    if with_secret {
        req = req.header(SECRET_HEADER, TEST_SECRET);
    }
    if let Some(v) = identity {
        req = req.header(IDENTITY_HEADER, v);
    }
    // Held across the request: see [`WRITE_PERMIT`].
    let _permit = WRITE_PERMIT.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = req
        .send_form(fields.iter().copied())
        .expect("a POST response");
    let headers = r
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    AccountGot {
        status: r.status().as_u16(),
        headers,
        body: r.body_mut().read_to_string().expect("a body"),
    }
}

/// The delete `POST` in a chosen language: the same request [`account_post`] sends, plus
/// the `lang` cookie the page negotiates its words from.
///
/// It asserts the `<html lang>` it got, because every caller of it compares the page's
/// words against one language's strings. A cookie the page ignored would make each of
/// those assertions fail on the Italian side, and the failure would read as a wrong
/// translation rather than as the request that never asked.
///
/// That assertion is about a **page**, and the completed deletion answers a `303` that
/// renders none (§13.32 §1), so it runs on the responses that carry a document: every
/// redirect this program sends is empty-bodied, so on one there is nothing to be in the
/// wrong language.
fn account_post_lang(url: &str, identity: &str, fields: &[(&str, &str)], lang: Lang) -> AccountGot {
    let req = account_client()
        .post(url)
        .header("Sec-Fetch-Site", "same-origin")
        .header(SECRET_HEADER, TEST_SECRET)
        .header(IDENTITY_HEADER, identity)
        .header("Cookie", format!("{LANG_COOKIE}={}", lang.code()));
    // Held across the request: see [`WRITE_PERMIT`].
    let _permit = WRITE_PERMIT.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = req
        .send_form(fields.iter().copied())
        .expect("a POST response");
    let out = AccountGot {
        status: r.status().as_u16(),
        headers: r
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        body: r.body_mut().read_to_string().expect("a body"),
    };
    // The language assertion is about a **page**. A `303` (§13.32 §1) carries no body,
    // so there is no `<html>` to read and nothing to be in the wrong language: the check
    // runs on a response that renders a document, which is every case that reads words.
    if !out.body.is_empty() {
        assert!(
            account_html_tag(&out.body).contains(&format!("lang=\"{}\"", lang.code())),
            "the request asked for {} and the page is not in it: {}",
            lang.code(),
            account_html_tag(&out.body)
        );
    }
    out
}

/// The page with its inline stylesheets collapsed to a marker. `THEME_CSS` and `BASE_CSS`
/// are the bulk of every document this binary sends, and a failure that quotes the whole
/// page buries the line that failed under forty kilobytes of palette.
fn account_readable(body: &str) -> String {
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

/// The access file and the settings file beside it, under a name unique to this test:
/// tests run in parallel and share one temp directory. The `account-` in the file name
/// keeps this suite's fixtures from colliding with the console's.
fn account_scratch(name: &str, settings: &str) -> String {
    let p = std::env::temp_dir().join(format!("bb-auth-web-account-{name}.json"));
    std::fs::write(&p, ACCOUNT_ACCESS).expect("write the access fixture");
    let path = p.to_string_lossy().into_owned();
    std::fs::write(settings_path(&path), settings).expect("write the settings fixture");
    path
}

/// A fixture written from given access text, with the full settings beside
/// it: the mint tests run over their own two variants of the roster.
fn account_scratch_access(name: &str, access: &str) -> String {
    let p = std::env::temp_dir().join(format!("bb-auth-web-account-{name}.json"));
    std::fs::write(&p, access).expect("write the access fixture");
    let path = p.to_string_lossy().into_owned();
    std::fs::write(settings_path(&path), ACCOUNT_SETTINGS_FULL)
        .expect("write the settings fixture");
    path
}

/// The richer fixture, written the same way and under its own name, for every test about
/// **what the page shows** rather than about who reaches it at all.
fn account_scratch_full(name: &str) -> String {
    let p = std::env::temp_dir().join(format!("bb-auth-web-account-{name}.json"));
    std::fs::write(&p, account_access_full()).expect("write the full access fixture");
    let path = p.to_string_lossy().into_owned();
    std::fs::write(settings_path(&path), ACCOUNT_SETTINGS_FULL)
        .expect("write the full settings fixture");
    path
}

/// The full roster with settings given: the audit sentence is the one fact on this page that
/// comes from the settings file rather than the access file.
fn account_scratch_full_settings(name: &str, settings: &str) -> String {
    let p = std::env::temp_dir().join(format!("bb-auth-web-account-{name}.json"));
    std::fs::write(&p, account_access_full()).expect("write the full access fixture");
    let path = p.to_string_lossy().into_owned();
    std::fs::write(settings_path(&path), settings).expect("write the settings fixture");
    path
}

/// The roster fixture on disk, with the deployment's settings beside it.
fn account_scratch_roster(name: &str) -> String {
    account_scratch_access(name, &account_access_roster())
}

/// One section of the page: from `<section id="X"` to the next `</section>`. The page's
/// sections are siblings and never nested, so the first closing tag ends the section that
/// started, and an assertion about `keys` cannot be satisfied by words that belong to
/// `reach`. A page with no such section is the failure this contract is about, so it is
/// reported as one.
fn account_section(body: &str, id: &str) -> String {
    let open = format!("<section id=\"{id}\"");
    let start = body.find(&open).unwrap_or_else(|| {
        panic!(
            "the page must carry {}; it does not: {}",
            open,
            account_readable(body)
        )
    });
    let rest = &body[start..];
    let end = rest.find("</section>").unwrap_or_else(|| {
        panic!(
            "{} is opened and never closed: {}",
            open,
            account_readable(body)
        )
    });
    rest[..end].to_string()
}

/// The page's own URL, `GET /account/`, on that server. A test that asks for a different
/// shape under the prefix builds its URL from [`ACCOUNT_PATH`] and says so.
fn account_serve(path: &str) -> String {
    format!("http://127.0.0.1:{}{ACCOUNT_PATH}/", account_port(path))
}

/// The deployment's settings: the pool, the hosts it may redirect to, and one
/// administrator who is **not** any of the callers. `identity_attrs` is left at its
/// default, which is `email`.
const ACCOUNT_SETTINGS: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"] },
        "web": { "admins": ["admin@x.com"] } }"#;

/// The deployment's settings plus the brand name and the logo an administrator set.
const ACCOUNT_SETTINGS_BRAND: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"] },
        "web": { "admins": ["admin@x.com"] },
        "ui": { "brand_name": "BadBat75",
                "logo_url": "https://assets.badbat75.com/logo.png" } }"#;

/// The deployment's settings, plus `gate.profile_claims`: the page shows the claims the
/// proxy forwards, and `given_name` is the one whose derived header (`X-Auth-Given-Name`)
/// a test can put on the wire.
const ACCOUNT_SETTINGS_FULL: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"],
        "profile_claims": ["given_name"] },
        "web": { "admins": ["admin@x.com"] } }"#;

/// The admin base these fixtures mount the console at. Never empty: a GUI mounted at the
/// root covers every path, so it has no room beside it for a self-service prefix, and
/// `compile_account_path` refuses that combination at startup. `/admin` is what the
/// packaged env example and rpi-01 both set.
const ADMIN_BASE: &str = "/admin";

/// The same links as **whole elements**, `<a …>…</a>`, for a claim about what is
/// *inside* one. [`links_to`] stops at the opening tag's `>`, which is the right
/// reach for an attribute and blind to the content: §13.17 names an icon control
/// with text inside it, so a test that reads that name from an open tag reads
/// nothing and passes on an unnamed icon.
fn anchors_to(html: &str, needle: &str) -> Vec<String> {
    elements(html, "<a ", "</a>")
        .into_iter()
        .filter(|a| a.contains(needle))
        .collect()
}

/// The rule §13.15 gives the duration control, as amended by §13.16, checked
/// against one rendered form: one `select name="duration"` with five options in
/// the file's own order, exactly one of them picked, and the custom box sharing
/// the form's existing `.limit` row with it.
///
/// One `select` and not five radios is asserted because §13.16 moved the control
/// into one cell of a table row on `/account/`, where five stacked rows would be
/// the tallest thing in it, and a component rendered two ways on the two
/// surfaces is two components that drift. The order is asserted because the five
/// are a list a person reads top down, longest to shortest, with no expiry last.
/// The single `selected` is asserted because a form with nothing picked is a form
/// that mints on the first click with no duration named, and one with two picks
/// whichever the browser feels like. The box shares the row because that is the
/// furniture `admin.css` already has (`form.edit .limit`), and a number box
/// orphaned below the choice it belongs to reads as a field of its own.
///
/// `mint` says which form this is, because §13.15 gives the two of them different
/// answers for `never`. A **mint** form preselects `365d` and must never preselect
/// `never`: the widest credential has to be asked for. An **edit** form reads the
/// key back (§13.16: "the edit form marks the stored choice `selected`"), and a key
/// stored as `never`, `0` or `-` *is* a key with no expiry, so `never` picked there
/// is the form telling the truth about the file.
fn assert_duration_choices(body: &str, selected: &str, label: &str, mint: bool) {
    assert_eq!(
        body.matches("name=\"duration\"").count(),
        1,
        "{label}: exactly one control is named `duration`, so the two surfaces render \
             one component and a hand-written client has one field to post"
    );
    let sel = element_containing(body, "name=\"duration\"", "</select>");
    assert!(
        sel.starts_with("<select"),
        "{label}: the five choices are a select: {sel}"
    );

    let opts = duration_options(&sel);
    assert_eq!(opts.len(), 5, "{label}: five choices, no more and no fewer");
    let values: Vec<String> = opts.iter().map(|o| o.0.clone()).collect();
    assert_eq!(
        values,
        vec!["365d", "182d", "91d", "custom", "never"],
        "{label}: the five values, longest to shortest, then no expiry, each spelled \
             as the file spells it"
    );

    let words: Vec<&str> = opts.iter().map(|o| o.1.as_str()).collect();
    assert!(
        words[0].contains("year"),
        "{label}: the first choice says a year in words: {words:?}"
    );
    assert!(
        words[1].contains('6') && words[1].contains("month"),
        "{label}: the second says six months in words: {words:?}"
    );
    assert!(
        words[2].contains('3') && words[2].contains("month"),
        "{label}: the third says three months in words: {words:?}"
    );
    assert!(
        words[3].contains("day"),
        "{label}: the fourth says the person names a number of days: {words:?}"
    );
    assert!(
        words[4].contains("never") || words[4].contains("expiry"),
        "{label}: the last says the key does not expire: {words:?}"
    );

    let picked: Vec<&(String, String, bool)> = opts.iter().filter(|o| o.2).collect();
    assert_eq!(
        picked.len(),
        1,
        "{label}: exactly one choice is picked, so the first click cannot mint a key \
             with no duration named"
    );
    assert_eq!(
        picked[0].0, selected,
        "{label}: the picked choice is `{selected}`"
    );
    if mint {
        assert_ne!(
            selected, "never",
            "{label}: no mint form preselects no expiry, because the widest credential \
                 has to be asked for"
        );
    }

    // The field is labelled, in the form's own label class, before the control.
    let at = body.find("name=\"duration\"").expect("the select is there");
    let head = &body[..at];
    let lbl = head.rfind("class=\"lbl\"").unwrap_or_else(|| {
        panic!("{label}: the duration field carries the form's own label: {head}")
    });
    assert!(
        !visible_text(&body[lbl..at]).is_empty(),
        "{label}: the label names the field: {}",
        &body[lbl..at.min(lbl + 120)]
    );

    // The custom box: a text field that brings up a numeric keyboard, named for
    // a screen reader because it has no visible label of its own, sitting in the
    // same `.limit` row as the select and after it.
    let box_tag = tag_containing(body, "name=\"days\"");
    assert!(
        box_tag.starts_with("<input")
            && box_tag.contains("type=\"text\"")
            && box_tag.contains("inputmode=\"numeric\""),
        "{label}: the custom box is a text field that brings up a numeric keyboard: \
             {box_tag}"
    );
    assert!(
        box_tag.contains("aria-label="),
        "{label}: the box has no visible label of its own, so its name has to be \
             written down: {box_tag}"
    );
    let days_at = body.find("name=\"days\"").expect("the box is there");
    assert!(
        at < days_at,
        "{label}: the box follows the choice it belongs to"
    );
    let limit = body[..days_at].rfind("class=\"limit\"").unwrap_or_else(|| {
        panic!("{label}: the select and the box share the form's existing .limit row")
    });
    let tail = &body[limit..];
    let row = &tail[..tail.find("</span>").unwrap_or(tail.len())];
    assert!(
        row.contains("name=\"duration\""),
        "{label}: the number box shares the `.limit` row with the choice, so it reads \
             as that row's companion and not as a field of its own: {row}"
    );
}

/// The value of `name="…"` in a tag, if the tag carries one.
fn attr(tag: &str, name: &str) -> Option<String> {
    let at = tag.find(&format!("{name}=\""))?;
    let rest = &tag[at + name.len() + 2..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The back pill's words. [`back_link`] puts an arrow in front of the key, so the pill's
/// text is not the key alone, and an assertion that compared `t(lang, K::Back)` would be
/// comparing a string the page never shows.
fn back_words(lang: Lang) -> String {
    format!("\u{2190} {}", t(lang, K::Back))
}

/// A **bare** attribute on a tag: the word is there with no `="value"` behind it, which
/// is how HTML spells `autofocus` and `required`.
///
/// `attr` reads `name="value"` and answers `None` for a bare one, so a test that asked
/// `attr(..).is_none()` about `autofocus` would pass on a field carrying neither, and a
/// test that asked `tag.contains("autofocus")` cannot tell the bare attribute from the
/// `autofocus="true"` the profile form used to write. The tag is split into its
/// attribute tokens, so only the bare spelling matches.
fn bare_attr(tag: &str, name: &str) -> bool {
    tag.split_whitespace()
        .any(|t| t == name || t == format!("{name}>"))
}

const CALL_PREFIX: &str = "AWSCognitoIdentityProviderService.";

/// The 5c flow's answer: the challenge names this session's own user, and carries no
/// masked address, which is the case the code page's generic sentence is for.
fn challenge_for_username() -> Reply {
    email_otp(FAKE_USERNAME, None)
}

/// The header's glyphs, asserted the same way on both surfaces (§13.28 §2-§3).
///
/// §13.17's rule was "a glyph is named by hidden text", because the glyph was the whole
/// control. §13.28 puts a word beside every header glyph, so the rule that applies is the
/// other half of the same pair: the glyph is **out** of the accessibility tree and the
/// control's name is the visible word, in the reader's language. A glyph that kept a name of
/// its own would make the row say "Sign out" twice to a reader.
fn check_header_glyphs(html: &str, lang: Lang, at: &str) {
    let nav = the_account_nav(html, at);
    let glyphs = elements(&nav, "<svg", "</svg>");
    assert!(!glyphs.is_empty(), "{at}: the header carries glyphs: {nav}");
    for g in &glyphs {
        assert!(
            g.contains("aria-hidden=\"true\"") && g.contains("focusable=\"false\""),
            "{at}: a header glyph is decoration: {g}"
        );
        assert!(
            !g.contains("fill=") && !g.contains("stroke=") && !g.contains("style="),
            "{at}: a glyph names no colour: {g}"
        );
    }
    // The trigger's name is the label plus the menu word, and the word is the table's.
    let hidden = controls_with_class(&nav, "summary", "who");
    assert_eq!(hidden.len(), 1, "{at}: one trigger: {nav}");
    let vh = controls_with_class(&hidden[0], "span", "vh");
    assert_eq!(vh.len(), 1, "{at}: one span of hidden words: {}", hidden[0]);
    assert_eq!(
        visible_text(&vh[0]),
        format!(", {}", t(lang, K::AccountMenu)),
        "{at}: the hidden words name the control, in the reader's language: {}",
        vh[0]
    );
    // The panel's rows say what they do, visibly, in the reader's language.
    let panel = the_panel(html, at);
    let prefs = controls_with_class(&panel, "summary", "pill");
    assert_eq!(prefs.len(), 1, "{at}: the Preferences row: {panel}");
    assert_eq!(
        visible_text(&prefs[0]),
        t(lang, K::Settings),
        "{at}: {}",
        prefs[0]
    );
    let outs: Vec<String> = controls_with_class(&panel, "a", "pill")
        .into_iter()
        .filter(|el| el.contains("/auth/logout"))
        .collect();
    assert_eq!(outs.len(), 1, "{at}: the Sign out row: {panel}");
    assert_eq!(
        visible_text(&outs[0]),
        t(lang, K::SignOut),
        "{at}: {}",
        outs[0]
    );
    // No System settings row here: §13.34 §3 moved it out of the account menu and §1 made the
    // settings page the fifth tab, so a tab is named by the strip, not by this panel (and the
    // strip is pinned by `the_bar_has_five_tabs`).
}

/// Every `class="…"` value inside `markup`, in document order. Two surfaces built from one
/// function have the same list; a slot that arrives with a class of its own shows up here.
fn class_values(markup: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = markup;
    while let Some(i) = rest.find(" class=\"") {
        let tail = &rest[i + 8..];
        let end = tail.find('"').expect("a closed attribute");
        out.push(tail[..end].to_string());
        rest = &tail[end..];
    }
    out
}

/// What the browser posts from the code page: its hidden fields, and the code typed.
fn code_fields(g: &AccountGot, code: &str) -> Vec<(String, String)> {
    let form = form_posting_to(&g.body, "/account/profile/code");
    let mut f = hidden_fields(&form);
    f.push(("code".to_string(), code.to_string()));
    f
}

/// The text of `<code id="{id}">…</code>`, exactly as the page wrote it, with nothing
/// trimmed. What a click selects (`user-select: all`) and what the copy button copies is
/// that text, so whitespace around it is a key that does not paste.
fn code_text(html: &str, id: &str) -> String {
    let open = format!("<code id=\"{id}\">");
    let at = html.find(&open).unwrap_or_else(|| {
        panic!(
            "the reveal must carry {open}: {}",
            &html[..html.len().min(600)]
        )
    });
    let rest = &html[at + open.len()..];
    let close = rest.find("</code>").expect("a closed code element");
    rest[..close].to_string()
}

/// What the fake recorded for one request: the `X-Amz-Target` it carried, its content type
/// and its JSON body.
#[derive(Debug, Clone)]
struct CognitoCall {
    target: String,
    content_type: String,
    body: serde_json::Value,
}

/// A console `GET` at an arbitrary path, as the proxy sends one.
fn console_at(port: u16, identity: &str, path: &str, cookie: &str) -> AccountGot {
    let url = format!("http://127.0.0.1:{port}{ADMIN_BASE}{path}");
    let r = get_with_secret(url)
        .header(IDENTITY_HEADER, identity)
        .header("Cookie", cookie)
        .call()
        .expect("a response");
    got_of(r)
}

/// A console `GET` over the socket, as the proxy sends one: the secret, the identity
/// header, and whatever extra headers the test wants on the wire.
fn console_get(port: u16, identity: &str, extra: &[(&str, &str)]) -> AccountGot {
    let url = format!(
        "http://127.0.0.1:{port}{ADMIN_BASE}{}",
        Route::Dashboard.path()
    );
    let mut req = account_client()
        .get(&url)
        .header(SECRET_HEADER, TEST_SECRET)
        .header("Sec-Fetch-Site", "same-origin")
        .header(IDENTITY_HEADER, identity);
    for &(k, v) in extra {
        req = req.header(k, v);
    }
    got_of(req.call().expect("a response"))
}

/// A console `POST` over the socket, read whole. The in-process [`post`] helper cannot
/// serve these tests: it calls [`mutate`] and renders the shell itself, so it has no
/// response and no `Content-Security-Policy` to assert on, and the pairing of a page with
/// the policy of *that response* is exactly what is under test.
fn console_post(port: u16, at: &Route, fields: &[(&str, &str)]) -> AccountGot {
    let url = format!("http://127.0.0.1:{port}{ADMIN_BASE}{}", at.path());
    // The same client-side serialization the account helpers use: one fsync per in-flight
    // write, so a slow disk costs latency and never a deadline.
    let _permit = WRITE_PERMIT.lock().unwrap_or_else(|e| e.into_inner());
    let r = post_with_secret(&url)
        .header(IDENTITY_HEADER, "admin@x.com")
        .header("Sec-Fetch-Site", "same-origin")
        .send_form(fields.iter().copied())
        .expect("a POST response");
    got_of(r)
}

/// Every element that opens with `<tag …>` whose class list contains `class`, as the
/// opening tag through its closing tag.
///
/// The class is the component's name (§13.17), so this finds every icon control in a
/// document without naming which control it is, and a control added later is covered
/// without editing the test. None of these controls nests inside another of the same tag,
/// so the first close tag is the right one.
fn controls_with_class(html: &str, tag: &str, class: &str) -> Vec<String> {
    let mut out = Vec::new();
    let open = format!("<{tag} ");
    let close = format!("</{tag}>");
    let mut at = 0;
    while let Some(i) = html[at..].find(&open) {
        let start = at + i;
        let gt = match html[start..].find('>') {
            Some(j) => start + j,
            None => break,
        };
        let end = match html[gt..].find(&close) {
            Some(j) => gt + j + close.len(),
            None => {
                at = gt + 1;
                continue;
            }
        };
        if attr(&html[start..gt], "class")
            .is_some_and(|c| c.split_whitespace().any(|word| word == class))
        {
            out.push(html[start..end].to_string());
        }
        at = end;
    }
    out
}

/// What `prop` is set to in a rule's declarations, if it is.
fn css_decl(body: &str, prop: &str) -> Option<String> {
    body.split(';')
        .filter_map(|d| d.split_once(':'))
        .find(|(n, _)| *n == prop)
        .map(|(_, v)| v.to_string())
}

/// `admin.css` as `(at-rule, selector, declarations)` triples: every rule tagged with the
/// at-rule it sits inside (`@media(max-width:800px)`) or `""` at the top level.
///
/// [`css_rules`] cannot serve here: it loses the selector of a rule nested in an at-rule
/// (the selector is read into the at-rule's *body*, and an at-rule's body is discarded),
/// which is why [`phone_rules`] exists. This one keeps the nesting, which is the whole point
/// of §13.28 §4: the design is a new `@media (max-width:800px)` block beside the existing
/// 640 one, and a test that cannot tell a rule inside a media block from one outside it
/// cannot say which breakpoint a declaration answers to.
fn css_scoped(css: &str) -> Vec<(String, String, String)> {
    let mut bare = String::new();
    let mut rest = css;
    while let Some(i) = rest.find("/*") {
        bare.push_str(&rest[..i]);
        rest = rest[i..].find("*/").map_or("", |j| &rest[i + j + 2..]);
    }
    bare.push_str(rest);
    let mut out = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut head = String::new();
    let mut body = String::new();
    // Inside an at-rule's block the next thing read is a *selector*; inside a rule, a body.
    let mut in_body = false;
    // Whitespace is not all noise. A **selector** keeps its spaces, collapsed to one each,
    // because `.brand img` and `.brandimg` are two different statements and the design names
    // the first; a **declaration body** loses them, because `css_decl` compares a property
    // name against the exact text before its colon. An at-rule's prelude loses them too, so
    // `@media (max-width:800px)` and `@media(max-width:800px)` are one key.
    for c in bare.chars() {
        match c {
            '{' => {
                let raw = std::mem::take(&mut head);
                // The head carries the whitespace that came before the selector, so the
                // at-rule test runs on the trimmed text: an untrimmed one reads " @media…"
                // as a selector, and every rule inside the block is then tagged with the
                // prelude **with its space**, which no caller's key matches.
                let at_rule = raw.trim_start().starts_with('@');
                let sel = if at_rule {
                    raw.chars().filter(|c| !c.is_whitespace()).collect()
                } else {
                    raw.split_whitespace().collect::<Vec<_>>().join(" ")
                };
                in_body = !at_rule;
                stack.push(sel);
            }
            '}' => {
                let sel = stack.pop().unwrap_or_default();
                if !body.is_empty() {
                    let at = stack.last().cloned().unwrap_or_default();
                    out.push((at, sel, std::mem::take(&mut body)));
                }
                head.clear();
                in_body = false;
            }
            ';' if in_body => body.push(';'),
            c if in_body => {
                if !c.is_whitespace() {
                    body.push(c);
                }
            }
            c => head.push(if c.is_whitespace() { ' ' } else { c }),
        }
    }
    out
}

/// The intake accepted the record. A `202` with `"ok":true` is the **only** acceptance
/// (§13.29 W2), which is why the accepted case is worth naming.
fn delete_accepted() -> Reply {
    reply(202, r#"{"ok":true,"status":"accepted"}"#)
}

const DELETE_CHANGED_EN: &str = "Your account changed after you opened this page, so nothing \
                                     was deleted. Start again to see what would be deleted now.";

const DELETE_CHANGED_IT: &str = "Il tuo account è cambiato dopo che hai aperto questa \
                                     pagina, quindi non è stato eliminato nulla. Ricomincia per \
                                     vedere cosa verrebbe eliminato adesso.";

const DELETE_CHANGED_TITLE_EN: &str = "Your account changed";

const DELETE_CHANGED_TITLE_IT: &str = "Il tuo account è cambiato";

const DELETE_CLOSE_EN: &str = "This browser stays signed in until the session ends.";

const DELETE_CLOSE_IT: &str = "Questo browser resta connesso finché la sessione non termina.";

/// The `Location:` §13.32 §1 and §4 pin for a deletion whose every address was queued, on
/// this suite's logout URL (`BB_AUTH_WEB_LOGOUT_URL`, `/auth/logout`): the gate's logout, and
/// its **own sign-in page** as the round trip, carrying the deletion's one notice code.
///
/// Spelled in full rather than rebuilt from `bb_auth_core::GATE_LOGIN_PATH` and
/// `bb_auth_core::LOGIN_NOTICE_ACCOUNT_DELETED`, because the encoded bytes are the fact: the
/// two constants are what the programs must agree on, and a builder that escaped the `?` and
/// the `=` wrongly would satisfy a test that re-encoded them the same way. This is also the
/// `rd` the gate's own pin decodes
/// (`a_logout_with_the_deletion_rd_clears_and_lands_on_the_notice`, `src/bin/bb-auth/tests.rs`), so
/// the two tests meet in the middle of the wire.
const DELETE_LOGOUT_LOCATION: &str = "/auth/logout?rd=%2Fauth%2Flogin%3Fnotice%3Daccount-deleted";

const DELETE_NO_CHECK_EN: &str = "The deletion service did not answer as expected, so \
                                      nothing was deleted and you can still sign in. Try again \
                                      in a minute; if it fails again, tell an administrator.";

const DELETE_NOT_DONE_EN: &str = "Your account was not deleted";

const DELETE_NOT_DONE_IT: &str = "Il tuo account non è stato eliminato";

const DELETE_NOW_GONE_EN: &str = "Your API keys and every access an administrator gave you \
                                      by name are gone.";

const DELETE_NOW_GONE_IT: &str = "Le tue chiavi API e ogni accesso che un amministratore ti \
                                      ha dato per nome non ci sono più.";

const DELETE_PATH: &str = "POST /account/delete";

const DELETE_PROTECTED_EN: &str = "This account cannot be deleted from this page, and \
                                       nothing was deleted. If you want it deleted, ask an \
                                       administrator.";

const DELETE_PROTECTED_IT: &str = "Questo account non può essere eliminato da questa \
                                       pagina, e non è stato eliminato nulla. Se vuoi \
                                       eliminarlo, chiedi a un amministratore.";

const DELETE_QUEUED_EN: &str = "Your sign-in accounts are queued for deletion. This page \
                                    cannot tell when that happens; if you can still sign in \
                                    later, tell an administrator.";

const DELETE_QUEUED_IT: &str = "I tuoi account di accesso sono in coda per l'eliminazione. \
                                    Questa pagina non può dire quando avverrà; se più avanti \
                                    riesci ancora ad accedere, avvisa un amministratore.";

const DELETE_QUEUED_TITLE_EN: &str = "Your account is being deleted";

const DELETE_QUEUED_TITLE_IT: &str = "Il tuo account è in fase di eliminazione";

/// The intake refused the record: any status that is not a `202` with `"ok":true` (§13.29
/// W2). `503` is the case the design names, the spool not writable, and the page's answer
/// to it is the same as to any other refusal; `403` is the protected list answering where
/// `whoami` did not, which is the one status with a page of its own for a stranger.
fn delete_refused(status: u16) -> Reply {
    reply(status, r#"{"ok":false,"status":"unavailable"}"#)
}

const DELETE_RETRY_EN: &str = "Try again";

const DELETE_START_EN: &str = "Start again";

const DELETE_START_IT: &str = "Ricomincia";

const DELETE_TITLE_EN: &str = "Delete your account";

const DELETE_TITLE_IT: &str = "Elimina il tuo account";

const DELETE_TOO_MANY_EN: &str = "This account has more email addresses than this page can \
                                      delete at once, so it cannot be deleted here, and nothing \
                                      was deleted. If you want it deleted, ask an administrator.";

/// The whole element that opens with the tag containing `needle`, up to and
/// including its close. [`tag_containing`] stops at that tag's own `>`, which
/// is right for an attribute and useless for "what is inside this button".
fn element_containing(html: &str, needle: &str, close: &str) -> String {
    let tag = tag_containing(html, needle);
    let start = html.find(&tag).expect("the tag is in the page");
    let tail = &html[start..];
    let end = tail
        .find(close)
        .unwrap_or_else(|| panic!("no {close} after {tag}"));
    tail[..end + close.len()].to_string()
}

/// Every element that opens with `open` through its first `close`, as strings.
fn elements(html: &str, open: &str, close: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find(open) {
        let tail = &rest[i..];
        let end = match tail.find(close) {
            Some(j) => j + close.len(),
            None => break,
        };
        out.push(tail[..end].to_string());
        rest = &tail[end..];
    }
    out
}

/// The answer a pool gives `USER_AUTH` with `PREFERRED_CHALLENGE=EMAIL_OTP`. §13.25: the
/// answer names the user it is answering for (`ChallengeParameters.USERNAME`), and a pool
/// that sends one names the masked address the code goes to
/// (`CODE_DELIVERY_DESTINATION`, documented as a masked address such as `t***@e***`).
fn email_otp(username: &str, destination: Option<&str>) -> Reply {
    let mut params = serde_json::Map::new();
    params.insert("USERNAME".to_string(), serde_json::json!(username));
    if let Some(d) = destination {
        params.insert(
            "CODE_DELIVERY_DESTINATION".to_string(),
            serde_json::json!(d),
        );
    }
    reply(
        200,
        &serde_json::json!({
            "ChallengeName": "EMAIL_OTP",
            "ChallengeParameters": params,
            "Session": FAKE_SESSION,
        })
        .to_string(),
    )
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
        Route::Groups,
        Route::User(bob.clone()),
        Route::Audit,
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

const FAKE_ACCESS: &str = "FAKEACCESS.0123456789.abcdefghij";

/// The fake endpoint: a `tiny_http` server on an ephemeral loopback port that records every
/// request and answers each action from the script, or holds the socket and never answers
/// (`silent`). An action nobody scripted is a `400` that names no known error.
struct FakeCognito {
    port: u16,
    calls: std::sync::Arc<std::sync::Mutex<Vec<CognitoCall>>>,
    // Silent mode keeps the accepted sockets open, so the caller waits on a live connection
    // rather than being refused.
    _held: std::sync::Arc<std::sync::Mutex<Vec<std::net::TcpStream>>>,
}

impl FakeCognito {
    fn answering(script: Vec<(&'static str, Reply)>) -> FakeCognito {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let server = Server::http("127.0.0.1:0").expect("bind the fake");
        let port = server.server_addr().to_ip().expect("an ip address").port();
        let seen = std::sync::Arc::clone(&calls);
        std::thread::spawn(move || {
            // A reply with status 0 is a request the fake takes and never answers, for the
            // one action a test wants to time out while the others work.
            let mut parked = Vec::new();
            for mut req in server.incoming_requests() {
                let header = |n: &str| {
                    req.headers()
                        .iter()
                        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(n))
                        .map(|h| h.value.as_str().to_string())
                        .unwrap_or_default()
                };
                let target = header("X-Amz-Target");
                let content_type = header("Content-Type");
                let mut raw = String::new();
                let _ = req.as_reader().read_to_string(&mut raw);
                let body = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
                seen.lock().unwrap().push(CognitoCall {
                    target: target.clone(),
                    content_type,
                    body,
                });
                let action = target.rsplit('.').next().unwrap_or("").to_string();
                let (status, body, location) = script
                    .iter()
                    .find(|(a, _)| *a == action)
                    .map(|(_, r)| (r.status, r.body.clone(), r.location.clone()))
                    .unwrap_or((
                        400,
                        r#"{"__type":"ResourceNotFoundException"}"#.into(),
                        None,
                    ));
                if status == 0 {
                    parked.push(req);
                    continue;
                }
                let mut resp = Response::from_string(body)
                    .with_status_code(StatusCode(status))
                    .with_header(
                        Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"application/x-amz-json-1.1"[..],
                        )
                        .unwrap(),
                    );
                if let Some(l) = location {
                    resp = resp
                        .with_header(Header::from_bytes(&b"Location"[..], l.as_bytes()).unwrap());
                }
                let _ = req.respond(resp);
            }
        });
        FakeCognito {
            port,
            calls,
            _held: Default::default(),
        }
    }

    /// A listener that accepts and says nothing, ever.
    fn silent() -> FakeCognito {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the silent fake");
        let port = listener.local_addr().unwrap().port();
        let held: std::sync::Arc<std::sync::Mutex<Vec<std::net::TcpStream>>> = Default::default();
        let keep = std::sync::Arc::clone(&held);
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                keep.lock().unwrap().push(s);
            }
        });
        FakeCognito {
            port,
            calls: Default::default(),
            _held: held,
        }
    }

    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    fn calls(&self) -> Vec<CognitoCall> {
        self.calls.lock().unwrap().clone()
    }

    /// The action names, in order: `InitiateAuth`, not the whole target.
    fn actions(&self) -> Vec<String> {
        self.calls()
            .iter()
            .map(|c| c.target.rsplit('.').next().unwrap_or("").to_string())
            .collect()
    }
}

struct FakeIntake {
    port: u16,
    calls: std::sync::Arc<std::sync::Mutex<Vec<IntakeCall>>>,
    watched: std::sync::Arc<std::sync::Mutex<Option<(String, String)>>>,
    // 7e: the answers one path gives **in order**, one per request. The partial outcomes are
    // a walk where the same path answers twice and differently (the first `POST` accepted,
    // the second refused), which a script keyed by path cannot say.
    sequences: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Scripted>>>,
    // Silent mode keeps the accepted sockets open, so the caller waits on a live connection
    // rather than being refused.
    _held: std::sync::Arc<std::sync::Mutex<Vec<std::net::TcpStream>>>,
}

impl FakeIntake {
    fn answering(script: Vec<(&'static str, Reply)>) -> FakeIntake {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let server = Server::http("127.0.0.1:0").expect("bind the fake intake");
        let port = server.server_addr().to_ip().expect("an ip address").port();
        let seen = std::sync::Arc::clone(&calls);
        // The file a test wants watched, as `(path, needle)`: see [`FakeIntake::watch`].
        let watched: std::sync::Arc<std::sync::Mutex<Option<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let file = std::sync::Arc::clone(&watched);
        // The in-order answers, keyed by `METHOD path`: see [`FakeIntake::in_order`].
        let sequences: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<String, Scripted>>,
        > = Default::default();
        let seq = std::sync::Arc::clone(&sequences);
        std::thread::spawn(move || {
            // A reply with status 0 is a request the fake takes and never answers, for the
            // one path a test wants to time out while the others work.
            let mut parked = Vec::new();
            for mut req in server.incoming_requests() {
                let header = |n: &str| {
                    req.headers()
                        .iter()
                        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(n))
                        .map(|h| h.value.as_str().to_string())
                };
                // Every header is read before the body: the closure borrows the request,
                // and `as_reader` needs it to itself.
                // Upper-cased: `tiny_http`'s `Debug` for its method is the Rust variant
                // name (`Get`), and the contract's paths are spelled the HTTP way.
                let method = fmt_method(req.method()).to_uppercase();
                let path = req.url().to_string();
                let email = header("X-Auth-Email");
                let secret = header("X-BB-Delete-Secret");
                let real_ip = header("X-Real-IP");
                let mut raw = String::new();
                let _ = req.as_reader().read_to_string(&mut raw);
                let confirm = form_urlencoded::parse(raw.as_bytes())
                    .find(|(k, _)| k == "confirm_email")
                    .map(|(_, v)| v.into_owned());
                // The watched file, read **now**: this is the only moment that can say
                // whether the row was still there when this request landed.
                let row_present = {
                    let w = file.lock().unwrap();
                    w.as_ref().map(|(p, needle)| {
                        std::fs::read_to_string(p)
                            .map(|s| s.contains(needle.as_str()))
                            .unwrap_or(false)
                    })
                };
                seen.lock().unwrap().push(IntakeCall {
                    method: method.clone(),
                    path: path.clone(),
                    email: email.clone(),
                    secret,
                    real_ip,
                    confirm_email: confirm,
                    row_present,
                });
                let at = format!("{method} {path}");
                // The in-order answers win over the flat script, and the **last** entry
                // repeats for every request after it, so a test that scripts two answers for
                // a three-address walk says "accepted, accepted, refused" without naming the
                // third. The count is taken from the recording, which is why the push above
                // comes first: this request is the `n`th, not the `n+1`th.
                let n = seen
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|c| format!("{} {}", c.method, c.path) == at)
                    .count()
                    - 1;
                let (status, body, location) = {
                    let seq = seq.lock().unwrap();
                    match seq.get(&at) {
                        Some(v) if !v.is_empty() => v[n.min(v.len() - 1)].clone(),
                        _ => script
                            .iter()
                            .find(|(p, _)| *p == at)
                            .map(|(_, r)| (r.status, r.body.clone(), r.location.clone()))
                            .unwrap_or((400, r#"{"error":"not_scripted"}"#.into(), None)),
                    }
                };
                if status == 0 {
                    parked.push(req);
                    continue;
                }
                let body = match &email {
                    Some(e) => body.replace("__EMAIL__", e),
                    None => body,
                };
                let mut resp = Response::from_string(body).with_status_code(StatusCode(status));
                if let Some(l) = location {
                    resp = resp
                        .with_header(Header::from_bytes(&b"Location"[..], l.as_bytes()).unwrap());
                }
                let _ = req.respond(resp);
            }
        });
        FakeIntake {
            port,
            calls,
            watched,
            sequences,
            _held: Default::default(),
        }
    }

    /// A listener that accepts and says nothing, ever.
    fn silent() -> FakeIntake {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind the silent fake intake");
        let port = listener.local_addr().unwrap().port();
        let held: std::sync::Arc<std::sync::Mutex<Vec<std::net::TcpStream>>> = Default::default();
        let keep = std::sync::Arc::clone(&held);
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                keep.lock().unwrap().push(s);
            }
        });
        FakeIntake {
            port,
            calls: Default::default(),
            watched: Default::default(),
            sequences: Default::default(),
            _held: held,
        }
    }

    /// The **origin** and nothing more: the intake's paths are its own, which is why
    /// `compile_delete_intake` refuses a value that carries one (§13.29 W2).
    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn calls(&self) -> Vec<IntakeCall> {
        self.calls.lock().unwrap().clone()
    }

    /// Each request as `METHOD path`, in the order they arrived: the order is part of the
    /// contract (every `whoami` before the first `POST`), so it is what a test compares.
    fn at(&self) -> Vec<String> {
        self.calls()
            .iter()
            .map(|c| format!("{} {}", c.method, c.path))
            .collect()
    }

    /// The recording from `seen` on, spelled as [`FakeIntake::at`]. The fake keeps every
    /// request it has ever been sent, so a test that drives it more than once (one request
    /// in two languages) asserts on what one drive added, not on the whole journal.
    fn at_since(&self, seen: usize) -> Vec<String> {
        self.at()[seen..].to_vec()
    }

    /// Watch `path` for `needle`, answering each request with whether the file held it at
    /// the moment the request arrived. The order of a write and a `POST` is a fact about
    /// two effects, and the response of neither can show it: the row has to be looked for
    /// in the file, from inside the request that is supposed to follow the write.
    fn watch(&self, path: &str, needle: &str) {
        *self.watched.lock().unwrap() = Some((path.to_string(), needle.to_string()));
    }

    /// What each call saw, in the order it arrived: `Some(true)` where the watched file
    /// held the needle when that request landed, `Some(false)` where it did not, `None`
    /// where nothing was watched.
    fn rows_since(&self, seen: usize) -> Vec<Option<bool>> {
        self.calls.lock().unwrap()[seen..]
            .iter()
            .map(|c| c.row_present)
            .collect()
    }

    /// The answers `at` gives **in order**, one per request, the last repeating for every
    /// request after it. The flat script of [`FakeIntake::answering`] is keyed by path, so it
    /// answers one path one way; the partial outcomes are a walk where the same path is
    /// asked twice and must answer differently the second time (the first address accepted,
    /// the second refused), and a page that cannot tell those two apart cannot tell a
    /// half-deleted account from a whole one.
    fn in_order(&self, at: &str, replies: Vec<Reply>) {
        *self
            .sequences
            .lock()
            .unwrap()
            .entry(at.to_string())
            .or_default() = replies
            .into_iter()
            .map(|r| (r.status, r.body, r.location))
            .collect();
    }
}

const FAKE_REFRESH: &str = "FAKEREFRESH.0123456789.abcdefghij";

/// A `Session` is 20 to 4096 characters (RespondToAuthChallenge's documentation).
const FAKE_SESSION: &str = "FAKESESSION0123456789abcdefghijklmnop";

const FAKE_USERNAME: &str = "cog-bob-0001";

/// The markup tag that carries `name="…"`: the input, textarea or list box a refusal
/// marks. Asserted on as one tag, because a body-wide search for `invalid` passes on any
/// other field's marking (§13.31 §10a).
fn field_tag(html: &str, name: &str) -> String {
    let needle = format!("name=\"{name}\"");
    let at = html
        .find(&needle)
        .unwrap_or_else(|| panic!("the page carries no field {name:?}"));
    let start = html[..at].rfind('<').expect("a name inside a tag");
    let end = at + html[at..].find('>').expect("a closed tag") + 1;
    html[start..end].to_string()
}

fn flow(name: &str) -> Flow {
    flow_with(name, signed_in(&good_id_token("bob@x.com")), ok_empty())
}

struct Flow {
    fake: FakeCognito,
    path: String,
    base: String,
}

impl Flow {
    fn start_url(&self) -> String {
        format!("{}profile", self.base)
    }
    fn code_url(&self) -> String {
        format!("{}profile/code", self.base)
    }
}

fn flow_with(name: &str, rtac: Reply, update: Reply) -> Flow {
    let fake = FakeCognito::answering(vec![
        ("InitiateAuth", challenge_for_username()),
        ("RespondToAuthChallenge", rtac),
        ("UpdateUserAttributes", update),
    ]);
    let (path, base) = profile_serve(name, &fake);
    Flow { fake, path, base }
}

/// The form whose `action` is exactly `action`.
fn form_posting_to(body: &str, action: &str) -> String {
    elements(body, "<form", "</form>")
        .into_iter()
        .find(|f| attr(f, "action").as_deref() == Some(action))
        .unwrap_or_else(|| panic!("no form posts to {action}: {}", account_readable(body)))
}

/// A token for `email` that names **this session's** Cognito user, so the bind of §13.25
/// (3) is satisfied and the flow reaches the update.
fn good_id_token(email: &str) -> String {
    token_from(email, FAKE_USERNAME)
}

/// A response read whole: status, every header, the body.
fn got_of(mut r: ureq::http::Response<ureq::Body>) -> AccountGot {
    let headers = r
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    AccountGot {
        status: r.status().as_u16(),
        headers,
        body: r.body_mut().read_to_string().expect("a body"),
    }
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

/// The hidden inputs of a form, `(name, value)`.
fn hidden_fields(form: &str) -> Vec<(String, String)> {
    elements(form, "<input", ">")
        .into_iter()
        .filter(|i| attr(i, "type").as_deref() == Some("hidden"))
        .map(|i| {
            (
                attr(&i, "name").unwrap_or_default(),
                attr(&i, "value")
                    .unwrap_or_default()
                    .replace("&quot;", "\"")
                    .replace("&#39;", "'")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&amp;", "&"),
            )
        })
        .collect()
}

/// The `value` of a form's hidden input named `name`.
fn hidden_value(form: &str, name: &str) -> Option<String> {
    elements(form, "<input", ">")
        .into_iter()
        .find(|i| {
            attr(i, "type").as_deref() == Some("hidden") && attr(i, "name").as_deref() == Some(name)
        })
        .and_then(|i| attr(&i, "value"))
}

/// An ID token the way the pool mints one: `header.payload.signature`, unsigned here
/// because the design does not verify it (§13.22). `exp_in` is seconds from now.
///
/// §13.25: the payload carries `cognito:username`, the pool's own name for the user, which
/// is what the code step binds the returned token by.
#[allow(clippy::too_many_arguments)]
fn id_token(
    email: &str,
    aud: &str,
    iss: &str,
    token_use: &str,
    exp_in: i64,
    verified: serde_json::Value,
    username: &str,
) -> String {
    use base64::Engine;
    let enc = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut payload = serde_json::json!({
        "iss": iss, "aud": aud, "sub": "sub-1", "token_use": token_use,
        "exp": now + exp_in, "email": email, "email_verified": verified,
    });
    if !username.is_empty() {
        payload["cognito:username"] = serde_json::json!(username);
    }
    format!(
        "{}.{}.x",
        enc(serde_json::json!({ "alg": "RS256", "kid": "k" })),
        enc(payload)
    )
}

/// The input tag named `name` in `html`.
fn input_named(html: &str, name: &str) -> String {
    elements(html, "<input", ">")
        .into_iter()
        .find(|i| attr(i, "name").as_deref() == Some(name))
        .unwrap_or_else(|| panic!("no input named {name}: {html}"))
}

/// A listener on loopback that records each request as `METHOD path` and answers `200`. It
/// is the intake, so it is a socket on this host and never a real worker: the rules here
/// forbid a test reaching one.
fn intake_listener() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let server = Server::http("127.0.0.1:0").expect("bind the fake intake");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    let keep = std::sync::Arc::clone(&seen);
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            keep.lock()
                .unwrap()
                .push(format!("{} {}", fmt_method(req.method()), req.url()));
            let _ = req.respond(Response::from_string("{}").with_status_code(StatusCode(200)));
        }
    });
    (port, seen)
}

const KIND_GROUP: &str = "User group";

fn lede_of(g: &AccountGot) -> String {
    visible_text(&element_containing(&g.body, "class=\"lede\"", "</p>"))
}

/// Every `<a …>` open tag whose own markup contains `needle` (an `href` substring
/// is how a test finds "the links that go to the remove page").
fn links_to(html: &str, needle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("<a ") {
        let tail = &rest[i..];
        let end = tail.find('>').unwrap_or(tail.len());
        let tag = tail[..end + 1].to_string();
        if tag.contains(needle) {
            out.push(tag);
        }
        rest = &tail[end..];
    }
    out
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

/// The element that opens with `open` through its **matching** close tag, counting nesting.
///
/// [`elements`] stops at the first close tag of the name, which is the wrong end for a block
/// that holds the same tag inside it. The account menu's panel is exactly that: it holds a
/// `div` (its tab rows) and a `details` (its preferences), so a panel read with `elements` is
/// the panel up to its first nested `div`, and every assertion about what comes after that
/// div reads a truncated document.
fn nested_block(html: &str, open: &str, tag: &str) -> String {
    let start = html
        .find(open)
        .unwrap_or_else(|| panic!("no {open} on the page"));
    let open_tag = format!("<{tag}");
    let close_tag = format!("</{tag}>");
    let mut depth = 1usize;
    let mut at = start + open.len();
    loop {
        let next_open = html[at..].find(&open_tag).map(|i| at + i);
        let next_close = html[at..].find(&close_tag).map(|i| at + i);
        match (next_open, next_close) {
            (Some(i), c) if c.is_none_or(|j| i < j) => {
                // `<div` is a prefix of `<divx`, which is not a div.
                if matches!(
                    html.as_bytes().get(i + open_tag.len()).copied(),
                    Some(b' ') | Some(b'>')
                ) {
                    depth += 1;
                }
                at = i + open_tag.len();
            }
            (_, Some(j)) => {
                depth -= 1;
                if depth == 0 {
                    return html[start..j + close_tag.len()].to_string();
                }
                at = j + close_tag.len();
            }
            _ => panic!("no closing {tag} for {open}"),
        }
    }
}

const NOT_YOURS: &str = "The sign-in service answered for a different account, so nothing \
                            was changed.";

fn ok_empty() -> Reply {
    reply(200, "{}")
}

/// The opening tag of an element string, up to and including its `>`.
fn open_tag(el: &str) -> &str {
    &el[..el.find('>').expect("an element opens") + 1]
}

fn post_code(f: &Flow, who: &str, fields: &[(String, String)]) -> AccountGot {
    post_code_with(f, who, fields, &PROFILE_HEADERS)
}

/// The code step as a request that arrives with `headers`: §13.25 (3) answers the challenge
/// with the username the **header** names on this request, so a test changes the header
/// between the two steps and watches which one the call carries.
fn post_code_with(
    f: &Flow,
    who: &str,
    fields: &[(String, String)],
    headers: &[(&'static str, &'static str)],
) -> AccountGot {
    let borrowed: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    profile_post_headers(
        &f.code_url(),
        Some(who),
        &borrowed,
        "same-origin",
        true,
        headers,
        &[],
    )
}

/// The GUI over a socket with its Cognito calls aimed at `endpoint`, `workers` threads and
/// the given bound; returns the fixture path and the page's URL (`/account/`).
fn profile_boot(
    name: &str,
    settings: &str,
    endpoint: Option<String>,
    timeout_ms: Option<u64>,
    workers: usize,
) -> (String, String) {
    let path = account_scratch(name, settings);
    let mut cfg = cfg_for(&path, ADMIN_BASE);
    cfg.cognito_endpoint = endpoint;
    if let Some(ms) = timeout_ms {
        cfg.cognito_timeout = std::time::Duration::from_millis(ms);
    }
    let cfg = std::sync::Arc::new(cfg);
    let server = std::sync::Arc::new(Server::http("127.0.0.1:0").expect("bind an ephemeral port"));
    let port = server.server_addr().to_ip().expect("an ip address").port();
    for _ in 0..workers {
        let server = std::sync::Arc::clone(&server);
        let cfg = std::sync::Arc::clone(&cfg);
        std::thread::spawn(move || loop {
            if let Ok(req) = server.recv() {
                handle(req, &cfg);
            }
        });
    }
    (path, format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/"))
}

const PROFILE_CLAIMS: &str = r#""given_name", "family_name", "birthdate", "zoneinfo",
        "phone_number", "preferred_username", "address", "custom:department""#;

/// What nginx forwards for bob on every request: the claims, percent-encoded as the gate
/// sends them. `zoneinfo` is deliberately not forwarded, so one editable field is empty.
///
/// §13.25 adds the seventh: `X-Auth-Native-Username`, the Cognito user this session *is*,
/// which is the only user the edit may act on. bob's is a pool-style UUID-shaped username.
const PROFILE_HEADERS: [(&str, &str); 7] = [
    ("X-Auth-Given-Name", "Bob"),
    ("X-Auth-Family-Name", "Smith%20Jr"),
    ("X-Auth-Birthdate", "1990-01-02"),
    ("X-Auth-Phone-Number", "%2B390000"),
    ("X-Auth-Preferred-Username", "bobby"),
    ("X-Auth-Custom-Department", "Sales"),
    (NATIVE_USERNAME_HEADER, FAKE_USERNAME),
];

/// The same headers with no `X-Auth-Native-Username`: what a federated session arrives with,
/// and what a cookie minted before §13.25's gate change arrives with (§13.25 step 1).
fn profile_headers_no_native() -> Vec<(&'static str, &'static str)> {
    PROFILE_HEADERS
        .iter()
        .filter(|(k, _)| *k != NATIVE_USERNAME_HEADER)
        .copied()
        .collect()
}

const PROFILE_POOL: &str = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST";

fn profile_post(url: &str, who: &str, fields: &[(&str, &str)]) -> AccountGot {
    profile_post_as(url, Some(who), fields, "same-origin", true, &[])
}

/// A `POST` the way the browser makes it from the form: the profile headers nginx adds, the
/// identity, the secret, and `Sec-Fetch-Site`.
fn profile_post_as(
    url: &str,
    who: Option<&str>,
    fields: &[(&str, &str)],
    sec_fetch: &str,
    with_secret: bool,
    extra: &[(&str, &str)],
) -> AccountGot {
    profile_post_headers(
        url,
        who,
        fields,
        sec_fetch,
        with_secret,
        &PROFILE_HEADERS,
        extra,
    )
}

fn profile_post_headers(
    url: &str,
    who: Option<&str>,
    fields: &[(&str, &str)],
    sec_fetch: &str,
    with_secret: bool,
    req_headers: &[(&str, &str)],
    extra: &[(&str, &str)],
) -> AccountGot {
    let mut req = account_client()
        .post(url)
        .header("Sec-Fetch-Site", sec_fetch);
    if with_secret {
        req = req.header(SECRET_HEADER, TEST_SECRET);
    }
    if let Some(v) = who {
        req = req.header(IDENTITY_HEADER, v);
    }
    for (k, v) in req_headers.iter().chain(extra.iter()) {
        req = req.header(*k, *v);
    }
    let mut r = req
        .send_form(fields.iter().copied())
        .expect("a POST response");
    let headers = r
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    AccountGot {
        status: r.status().as_u16(),
        headers,
        body: r.body_mut().read_to_string().expect("a body"),
    }
}

/// The form exactly as bob's page renders it, nothing edited. The field names are the claim
/// names, and nothing else: §13.25 removed the address choice, so there is no `email` field.
fn profile_same() -> Vec<(&'static str, &'static str)> {
    vec![
        ("given_name", "Bob"),
        ("family_name", "Smith Jr"),
        ("birthdate", "1990-01-02"),
        ("zoneinfo", ""),
    ]
}

/// The usual boot: the wired settings and the given fake, one worker is enough.
fn profile_serve(name: &str, fake: &FakeCognito) -> (String, String) {
    profile_boot(name, &profile_wired(), Some(fake.endpoint()), None, 2)
}

/// The settings of a deployment that can run the edit: the pool, the native client, and
/// eight claims, four of them editable (`given_name`, `family_name`, `birthdate`,
/// `zoneinfo`) and four never (`phone_number`, `preferred_username`, `address`, and a
/// `custom:` one). `email` cannot be configured as a claim at all.
fn profile_settings(client_id: &str, issuer: &str, claims: &str) -> String {
    format!(
        r#"{{ "version": 3, "gate": {{ "client_id": "{client_id}", "issuer": "{issuer}",
            "authorized_hosts": ["badbat75.com", "*.badbat75.com"],
            "profile_claims": [{claims}] }},
            "web": {{ "admins": ["admin@x.com"] }} }}"#
    )
}

fn profile_wired() -> String {
    profile_settings("email-client", PROFILE_POOL, PROFILE_CLAIMS)
}

fn profile_with(
    mut f: Vec<(&'static str, &'static str)>,
    key: &'static str,
    value: &'static str,
) -> Vec<(&'static str, &'static str)> {
    match f.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => f.push((key, value)),
    }
    f
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
        Route::Audit => page_audit(&v, &doc),
        other => panic!("{other:?} is not a read-only page"),
    };
    let html = shell(&v, "t", content).into_string();
    let _ = std::fs::remove_file(&path);
    html
}

fn reply(status: u16, body: &str) -> Reply {
    Reply {
        status,
        body: body.to_string(),
        location: None,
    }
}

/// One scripted answer of the fake. `location` makes it a redirect.
struct Reply {
    status: u16,
    body: String,
    location: Option<String>,
}

/// The four responses that reveal a freshly minted bearer, driven over real sockets: the
/// console's mint and rotate `POST`s, and the self-service page's mint and rotate.
///
/// One helper, because the rule under test is that the console and the self-service page
/// **cannot drift** (13.14: one `bearer_reveal`, two callers). A test that walked one of
/// the four is a test that lets the other three change. Each case is named by what made
/// it, so a failure says which of the four, and the fixtures are handed back for the
/// caller to clean.
///
/// The console's two ride one fixture and one server, re-reading the `rev` between them:
/// the mint's own write moves the file, and a rotate posted with the mint's `rev` is a
/// `409`, which is the thing the third test wants and not the reveal.
fn reveal_cases(name: &str) -> (Vec<(String, AccountGot)>, Vec<String>) {
    let mut cases: Vec<(String, AccountGot)> = Vec::new();
    let mut paths: Vec<String> = Vec::new();

    // --- the console: mint, then rotate, over one fixture and one server --------------
    let path = scratch(&format!("{name}-console"), SAMPLE);
    let served = cfg_for(&path, ADMIN_BASE);
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &served);
        }
    });
    let rev = rev_of(&path);
    cases.push((
        "console mint".to_string(),
        console_post(
            port,
            &Route::KeyAdd(BOB.to_string()),
            &[("rev", &rev), ("id", "reveal"), ("duration", "365d")],
        ),
    ));
    let rev = rev_of(&path);
    cases.push((
        "console rotate".to_string(),
        console_post(
            port,
            &Route::KeyRotate(BOB.to_string(), "laptop".to_string()),
            &[("rev", &rev)],
        ),
    ));
    paths.push(path);

    // --- the self-service page: mint, then rotate, over its own two fixtures ----------
    let path = account_scratch_access(&format!("{name}-account-mint"), &account_access_mint());
    let base = account_serve(&path);
    let rev = sha256_hex(&read(&path));
    cases.push((
        "account mint".to_string(),
        account_post(
            &format!("{base}keys"),
            Some("bob@x.com"),
            &[
                ("rev", rev.as_str()),
                ("id", "phone"),
                ("duration", "30d"),
                ("restrict", "all"),
            ],
        ),
    ));
    paths.push(path);

    let path = account_scratch_access(&format!("{name}-account-rotate"), &account_access_keys());
    let base = account_serve(&path);
    let rev = sha256_hex(&read(&path));
    cases.push((
        "account rotate".to_string(),
        account_post(
            &format!("{base}keys/rotate"),
            Some("bob@x.com"),
            &[("rev", rev.as_str()), ("id", "laptop")],
        ),
    ));
    paths.push(path);

    (cases, paths)
}

/// The declarations of the rule inside at-rule `at` (`""` for the top level) whose selector
/// list carries `sel` as one of its comma-parts, with a panic that says what is missing.
///
/// A rule is written by its **whole** selector list, and this stylesheet spells a shared
/// declaration as one rule with two names (`.bar .who svg,.menu svg`,
/// `p.primary .pill,.actions .pill`). A reader that demanded the list equal one of those names
/// goes red on the spelling the design asked for, so every lookup the §13.28 glyph and bar
/// rules make matches a comma-part.
fn rule_named(scoped: &[(String, String, String)], at: &str, sel: &str) -> String {
    scoped
        .iter()
        .find(|(a, s, _)| a == at && s.split(',').any(|part| part.trim() == sel))
        .unwrap_or_else(|| panic!("admin.css has no rule naming {sel} inside {at:?}"))
        .2
        .clone()
}

/// The rules of `scoped` inside at-rule `at` that set `prop` to `want`, as `(selector, body)`.
///
/// A design that names a selector ("the bar's tab `nav` gets `display:none`") states a
/// **role**, and more than one selector fills it (`nav.tabs`, `nav:not(.acct)`). A test that
/// pins one spelling fails a correct implementation for a reason nobody can see on the page,
/// so the roles checked here are matched by their declarations, not by their spelling.
fn rules_setting<'a>(
    scoped: &'a [(String, String, String)],
    at: &str,
    prop: &str,
    want: &str,
) -> Vec<(&'a str, &'a str)> {
    scoped
        .iter()
        .filter(|(a, _, body)| a == at && css_decl(body, prop).as_deref() == Some(want))
        .map(|(_, sel, body)| (sel.as_str(), body.as_str()))
        .collect()
}

/// The fields the settings form posts, as a browser would, with one override applied.
fn settings_fields<'a>(rev: &'a str, over: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut f: Vec<(&str, &str)> = vec![
        ("rev", rev),
        ("identity", "email"),
        ("claims", ""),
        ("ttl", "2592000"),
        ("providers", ""),
        // The app client the email flow uses. Every save carries it, because a
        // deployment with none is one where no login can complete and this form refuses
        // to write that.
        ("client_id", "email-client"),
        // The pool and the estate: guarded settings, so every save carries them
        // unchanged and the confirmation step stays out of the way of tests that are
        // about something else. `the_settings_page_asks_before_it_can_lock_anybody_out`
        // is the one that changes them on purpose.
        ("issuer", TEST_ISSUER),
        ("cookie_domain", ""),
        ("hosts", TEST_HOSTS),
        ("domain", ""),
        ("callback", ""),
        // The set the page says it drew a row for; a test that ticks one adds its own
        // `idp-<name>` and `aud-<name>` beside it, exactly as a browser would.
        ("idps", ""),
        // The audit's rotation as the page renders it for a file that names none, and no
        // retention: what a browser sends back from a form nobody touched.
        ("audit_rotation", "4"),
        ("audit_rotation_unit", "MiB"),
        ("audit_retention", ""),
        ("audit_retention_unit", ""),
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

fn signed_in(id: &str) -> Reply {
    reply(
        200,
        &serde_json::json!({ "AuthenticationResult": {
                "AccessToken": FAKE_ACCESS, "IdToken": id, "RefreshToken": FAKE_REFRESH,
                "ExpiresIn": 3600, "TokenType": "Bearer" } })
        .to_string(),
    )
}

/// Bob starts an edit (given name to Robert unless told otherwise) and gets the code page.
fn start_as(f: &Flow, who: &str, fields: &[(&str, &str)]) -> AccountGot {
    let g = profile_post(&f.start_url(), who, fields);
    assert_eq!(g.status, 200, "the start: {}", account_readable(&g.body));
    g
}

fn start_bob(f: &Flow) -> AccountGot {
    start_as(
        f,
        "bob@x.com",
        &profile_with(profile_same(), "given_name", "Robert"),
    )
}

fn strings(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// The sub-tab row of a rendered page: its `nav` and the links inside it, in document order.
fn sub_tabs(html: &str) -> (String, Vec<String>) {
    let navs = elements(html, r#"<nav class="sub""#, "</nav>");
    assert_eq!(
        navs.len(),
        1,
        "a users sub-page carries exactly one row of sub-tabs"
    );
    let nav = navs[0].clone();
    let links = elements(&nav, "<a ", "</a>");
    (nav, links)
}

/// The rows of the keys table, as `<tr>` elements, in document order. The console's table
/// and the account page's table are the same markup (§13.16), so one reader serves both.
fn table_rows(html: &str) -> Vec<String> {
    elements(html, "<tr", "</tr>")
}

/// The whole tag `needle` sits in, from its `<` to its `>`, so an assertion about an
/// attribute cannot be satisfied by the same word in prose beside it.
fn tag_containing(html: &str, needle: &str) -> String {
    let at = html
        .find(needle)
        .unwrap_or_else(|| panic!("the page must carry a tag with {needle}"));
    let start = html[..at].rfind('<').unwrap_or(at);
    let end = html[at..]
        .find('>')
        .map(|i| at + i + 1)
        .unwrap_or(html.len());
    html[start..end].to_string()
}

/// The intake bound for every server built by [`account_port_intake_at`]. The fake intakes
/// here answer at once or park forever, so the production 5 s bound bought nothing and made
/// every writer queue behind a parked call on `WRITE_PERMIT` (plan step 23, §13.38: four
/// tests of the 37 s run were five seconds each). 500 ms is generous for a loopback answer
/// and cheap for a park. The production 5 s stays pinned by
/// `delete_intake_without_a_secret_starts_and_sends_no_secret_header` on a plain `cfg_for`
/// config, and the bound test multiplies this constant, so shortening it here is what makes
/// that test fail a caller still bound at 5 s.
const TEST_INTAKE_TIMEOUT: Duration = Duration::from_millis(500);

/// The `nav.acct` of a page: the account end of the bar, and the only place the menu is.
fn the_account_nav(html: &str, label: &str) -> String {
    let all = elements(html, "<nav class=\"acct\"", "</nav>");
    assert_eq!(all.len(), 1, "{label}: exactly one nav.acct: {html}");
    all.into_iter().next().unwrap()
}

/// The pills of the page's actions, in document order.
fn the_action_pills(body: &str) -> Vec<String> {
    the_page_actions(body)
        .iter()
        .flat_map(|a| controls_with_class(a, "a", "pill"))
        .collect()
}

/// The bar's content box, with its nested `div`s kept whole.
fn the_bar(html: &str, label: &str) -> String {
    nested_block(&the_header_bar(html, label), "<div class=\"bar\">", "div")
}

/// The bar's brand slot, as one shape for **every** surface (§13.34 §10 as §11 overruled
/// it): a `span.brand`, no `href`, no link inside it, no tag line under the name.
///
/// The span is the user's decision, and it holds on the console too: the brand leads to the
/// page the Dashboard tab beside it already names, so it adds no destination, and the two
/// reasons `/account/` and the `403` had it that way (a link to the page already open, a
/// link to a page the caller may not open) apply to the same bar. Reading it as one reader
/// is the point: a bar whose console half is checked as a link and whose account half as a
/// span is a suite that passes on two shapes of one function.
///
/// Returns the element, so the caller reads the name out of it.
fn the_brand(top: &str, label: &str) -> String {
    let brands = controls_with_class(top, "span", "brand");
    assert_eq!(brands.len(), 1, "{label}: one span.brand in the bar: {top}");
    assert!(
        controls_with_class(top, "a", "brand").is_empty(),
        "{label}: the brand is not a link on any surface: {top}"
    );
    let brand = brands.into_iter().next().unwrap();
    assert!(
        attr(open_tag(&brand), "href").is_none(),
        "{label}: and carries no href of its own: {brand}"
    );
    assert!(
        !brand.contains("<a "),
        "{label}: nothing inside the brand is a link: {brand}"
    );
    assert!(
        controls_with_class(&brand, "span", "v").is_empty(),
        "{label}: the bar carries no tag line under the name: {brand}"
    );
    brand
}

/// The delete form: the one posting to `{account}/delete` and carrying this caller's hidden
/// `uuid` (`""` for a caller with no row). Both are asserted in the one lookup, because a
/// form that posts to the right place for the wrong subject is the bug.
fn the_delete_form(body: &str, uuid: &str, at: &str) -> String {
    let action = format!("{ACCOUNT_PATH}/delete");
    account_forms(body)
            .into_iter()
            .find(|f| {
                attr(open_tag(f), "action").as_deref() == Some(action.as_str())
                    && hidden_value(f, "uuid").as_deref() == Some(uuid)
            })
            .unwrap_or_else(|| {
                let seen: Vec<String> = account_forms(body)
                    .iter()
                    .map(|f| {
                        format!(
                            "action={:?} uuid={:?}",
                            attr(open_tag(f), "action"),
                            hidden_value(f, "uuid")
                        )
                    })
                    .collect();
                panic!("{at}: a form posting to {action} carrying a hidden uuid {uuid:?}; the page posts {seen:?}")
            })
}

/// The `header.top` element of a page, and a failure that says so when there is not exactly
/// one: a page with two bars, or none, is the drift 8b exists to end.
fn the_header_bar(html: &str, label: &str) -> String {
    let all = elements(html, "<header class=\"top\"", "</header>");
    assert_eq!(
        all.len(),
        1,
        "{label}: exactly one `header.top`: {}",
        account_readable(html)
    );
    all.into_iter().next().unwrap()
}

/// The page's own column: `<main>`, with the bar cut out. The bar's account menu names the
/// caller in full and carries its own Sign out row, so a "this page says no X" or a "one
/// action only" assertion has to look at the page, not at the chrome around it.
fn the_main(body: &str) -> String {
    nested_block(&account_readable(body), "<main>", "main")
}

/// The bar's navigation menu (§13.34): the `nav.navm` that carries the phone's copy of the
/// tabs. Its box is the one the bar measures, so it is found by the class the design names.
fn the_nav_menu(html: &str, label: &str) -> String {
    let bar = the_bar(html, label);
    let navs = elements(&bar, "<nav class=\"navm\"", "</nav>");
    assert_eq!(
        navs.len(),
        1,
        "{label}: the bar has one navigation menu: {bar}"
    );
    navs.into_iter().next().unwrap()
}

/// The panel of the bar's navigation menu: the `div.menu` inside `details.settings.navmenu`
/// (§13.34). It is a panel of the same family as [`the_panel`], and the two are asked the
/// same question, so they are read the same way.
fn the_nav_panel(html: &str, label: &str) -> String {
    let nav = the_nav_menu(html, label);
    nested_block(&nav, "<div class=\"menu\">", "div")
}

/// The outcome page's one `p.lede` (§13.23 §4's shape, which §13.30 §4 reuses).
fn the_page_lede(body: &str) -> String {
    let ledes = controls_with_class(&the_main(body), "p", "lede");
    assert_eq!(
        ledes.len(),
        1,
        "the outcome page is one heading and one lede: {}",
        account_readable(body)
    );
    visible_text(&ledes[0])
}

/// The words a person reads on the page itself.
fn the_page_words(body: &str) -> String {
    visible_text(&the_main(body))
}

/// The panel of a page: the `div.menu` inside `details.settings`.
fn the_panel(html: &str, label: &str) -> String {
    let nav = the_account_nav(html, label);
    nested_block(&nav, "<div class=\"menu\">", "div")
}

/// The declarations of one rule out of a stylesheet **compiled into the binary**, by its
/// exact selector, or `None` when there is no such rule.
///
/// [`css_block`] panics on a missing rule, which is right for a rule a test expects and
/// wrong for a rule a test expects to be **gone** (the sizing rules §13.17 deletes). The
/// walk steps over a `@media` block's own selector, so the phone overrides inside it are
/// reachable, and reads the bytes that ship rather than `src/assets/*.css` on disk.
fn the_rule(css: &str, selector: &str) -> Option<String> {
    // A comment sits between two rules and would otherwise be read as part of the next
    // selector; its commas alone are enough to hide an exact match.
    let mut bare = String::new();
    let mut rest = css;
    while let Some(i) = rest.find("/*") {
        bare.push_str(&rest[..i]);
        rest = rest[i..].find("*/").map_or("", |j| &rest[i + j + 2..]);
    }
    bare.push_str(rest);
    let css = bare.as_str();
    let mut at = 0;
    while let Some(i) = css[at..].find('{') {
        let sel = css[at..at + i].trim();
        let end = {
            let j = css[at + i..].find('}')?;
            at + i + j
        };
        if sel.split(',').any(|s| s.trim() == selector) {
            return Some(css[at + i + 1..end].trim().to_string());
        }
        at = end + 1;
    }
    None
}

/// The bar's tab `nav`: the strip, named by its class. It used to be "the first `nav` in
/// the bar", and §13.34 put a `nav` in front of it: the navigation menu. A test that takes
/// the first one now reads the menu and asserts a menu against a menu, which passes on a
/// page with no tabs at all, so the strip is found by the class the design names.
fn the_tab_nav(html: &str, label: &str) -> String {
    let bar = the_bar(html, label);
    let navs = elements(&bar, "<nav class=\"tabs\"", "</nav>");
    assert_eq!(navs.len(), 1, "{label}: the bar has one tab strip: {bar}");
    navs.into_iter().next().unwrap()
}

/// The one `<tbody>` inside `html`, with a message that says what is missing.
///
/// Indexing `[0]` on an empty list is the right failure ("this section has no
/// body row group") and prints as `index out of bounds`, which tells the next
/// reader nothing about which page they are looking at.
fn the_tbody(html: &str, label: &str) -> String {
    elements(html, "<tbody>", "</tbody>")
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{label}: the section carries no <tbody>: {html}"))
}

/// The text between `<title>` and `</title>`, spelled as the document spells it (escaped).
/// The parity test reads the title **out of** the page it is checking, because the prefix
/// is the caller's (`bb-auth-web · …` on the console, `{brand} · …` on the page) and a test
/// that hardcoded the wording would be a translation test in disguise.
fn title_of(doc: &str) -> String {
    let rest = &doc[doc.find("<title>").unwrap_or_else(|| {
        panic!("the document has no <title>: {}", account_readable(doc));
    })..];
    let inner = &rest["<title>".len()..];
    inner[..inner
        .find("</title>")
        .expect("the document has no </title>")]
        .to_string()
}

/// A token that names `username` as its Cognito user, everything else good. An empty
/// `username` omits the claim, which is what a token from a pool that does not send one
/// looks like.
fn token_from(email: &str, username: &str) -> String {
    id_token(
        email,
        "email-client",
        PROFILE_POOL,
        "id",
        3600,
        serde_json::json!(true),
        username,
    )
}

/// The declarations of the **top-level** rule for `sel`, with a panic that says which file
/// has no such rule.
fn top_rule(scoped: &[(String, String, String)], sel: &str) -> String {
    scoped
        .iter()
        .find(|(at, s, _)| at.is_empty() && s == sel)
        .unwrap_or_else(|| panic!("admin.css has no top-level rule for {sel}"))
        .2
        .clone()
}

/// The one rule inside at-rule `at` that caps the trigger at `want`, with a panic that names
/// what is missing. The trigger is `details.settings`'s `summary`, so its selector names one
/// of those two words; a cap on anything else is a cap on the wrong box.
fn trigger_cap<'a>(
    scoped: &'a [(String, String, String)],
    at: &str,
    want: &str,
) -> (&'a str, &'a str) {
    let hits = rules_setting(scoped, at, "max-width", want);
    assert_eq!(
        hits.len(),
        1,
        "{at}: exactly one rule caps the trigger at {want}, found {hits:?}"
    );
    let (sel, body) = hits[0];
    assert!(
        sel.split(',').any(|p| {
            let last = p.rsplit(['>', '+', '~', ' ']).next().unwrap_or(p);
            last.contains("who") || last.contains("summary")
        }),
        "{at}: the {want} cap is on the trigger, not on {sel}"
    );
    (sel, body)
}

/// A view over `cfg` at `at`, as a request would build one.
fn view<'a>(cfg: &'a Config, at: Route, rev: &'a str) -> View<'a> {
    View {
        cfg,
        lang: Lang::En,
        lang_pref: LangPref::Auto,
        theme: UiTheme::System,
        tz: TzPref::Utc,
        groups: GroupsPref::Open,
        audit: AuditPolicy::default(),
        look: Look::default(),
        admin: Some("admin@x.com"),
        at,
        query: "",
        rev,
        msg: None,
        identity: vec![IDENTITY_HEADER.to_string()],
    }
}

/// The text a block of markup shows a person: everything outside a tag, with
/// the markup's own line breaks collapsed. The tests that assert a control
/// carries **no** words need this, because "no words" about a list of tags is
/// a statement about the text between them.
fn visible_text(markup: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in markup.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The answer a healthy intake gives `whoami` for the address it was sent: not protected.
/// `__EMAIL__` is the fake's echo (see [`FakeIntake::answering`]), because the contract
/// reads a `whoami` only when its `email` is the address the request carried, and a script
/// that named one address could not answer a walk over two.
fn whoami_ok() -> Reply {
    reply(200, r#"{"ok":true,"email":"__EMAIL__","protected":false}"#)
}

/// The intake's two paths, hard-coded by the worker's contract (§13.29 W1), so a script
/// names them and nothing else, and the config value names only the origin.
const WHOAMI_PATH: &str = "GET /account/whoami";

/// The same, for an address on the intake's protected list (§13.29 W5).
fn whoami_protected() -> Reply {
    reply(200, r#"{"ok":true,"email":"__EMAIL__","protected":true}"#)
}

/// One in-flight account `POST` at a time, for the whole test process. The same shape as
/// the production [`WRITE_LOCK`], on the client side of the socket.
///
/// That lock is **process wide**, so per-test fixtures cannot dodge it: the suite's 11
/// write tests are a queue ~11 writes deep at any moment, and one request's latency is the
/// sum of the fsyncs ahead of it. Measured at load 7-10: `p90` 1.2-20.4 s and `max` 20.9 s
/// unthrottled, versus `max` 0.6-2.4 s with the permit, and the suite's own wall time fell
/// from 3.9-35.8 s to 2.3-9.0 s, because that queueing was only ever wasted clock.
///
/// This cannot mask a hang: a handler that deadlocks keeps its request open until the
/// deadline, and every writer behind it acquires the permit and fails at its own deadline
/// too. What it stops measuring is aggregate write throughput, which no test here asserts
/// on. A lock poisoned by a panicking test is taken anyway, for the reason [`mutate`]
/// gives for the same choice: failing every writer after one test's panic is the worse
/// answer.
static WRITE_PERMIT: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The fixture with its uuids and key hashes filled in, the hashes by the library's own
/// fingerprint, so the hashes a test looks for and the hashes in the file are the same
/// bytes by construction.
fn account_access_full() -> String {
    ACCOUNT_ACCESS_FULL
        .replace("__BOB__", ACCOUNT_BOB)
        .replace("__CAROL__", ACCOUNT_CAROL)
        .replace("__LAPTOP_HASH__", &sha256_hex(ACCOUNT_BEARER_LAPTOP))
        .replace("__CI_HASH__", &sha256_hex(ACCOUNT_BEARER_CI))
}

/// Two applications, every access kind, and bob in all of them in a different way: `mpa`
/// reaches him through `@admins` (`admin`), through `authenticated` (`onboarding`) and
/// not at all (`healthz`, anonymous, which says nothing about a person); `mcp` reaches him
/// through `logs` and not through `api`, whose credentials are `api_key` only, so a
/// browser login never reaches it.
const ACCOUNT_ACCESS_FULL: &str = r#"{ "version": 1,
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

/// The mint fixture with keys on **both** rows: bob's two, one narrowed to
/// `mcp/api` by an administrator and one unrestricted with a window, and
/// carol's one. The narrowed key is the one a rotate is asserted on, because
/// `rotate_api_key` changes only `key_hash` and `released` and a
/// implementation that rebuilt the row would drop the restriction; its
/// `duration` is `never`, which this page refuses to *mint*, so a rotate
/// that rewrote the window cannot hide behind a fixture value the page
/// itself would never have written. Carol's key is what makes "an id the
/// caller does not own" a real id in a real row rather than a typo.
const ACCOUNT_ACCESS_KEYS: &str = r#"{ "version": 1,
  "applications": [
    { "name": "mpa", "base": ["https://app.x.com/mpa"],
      "scopes": [
        { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"], "access": "restricted",
          "groups": ["@admins"], "credentials": ["login"] },
        { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"], "access": "authenticated" } ] },
    { "name": "mcp", "base": ["https://ai.x.com/mcp"],
      "scopes": [
        { "name": "logs", "urls": ["https://ai.x.com/mcp/logs/*"], "access": "restricted",
          "users": ["__BOB__"] },
        { "name": "api", "urls": ["https://ai.x.com/mcp/*"], "access": "restricted",
          "users": ["__BOB__"], "credentials": ["api_key"] },
        { "name": "vault", "urls": ["https://ai.x.com/mcp/vault/*"], "access": "restricted",
          "users": ["__CAROL__"] } ] } ],
  "user_groups": { "admins": ["__BOB__"] },
  "denied": ["spammer@x.com"],
  "users": [
    { "uuid": "__BOB__", "emails": ["bob@x.com", "bob@old.com"],
      "api_keys": [
        { "id": "laptop", "key_hash": "__LAPTOP_HASH__", "released": "2026-01-01",
          "duration": "never", "scopes": ["mcp/api"] },
        { "id": "ci", "key_hash": "__CI_HASH__", "released": "2026-01-01", "duration": "365d" } ] },
    { "uuid": "__CAROL__", "emails": ["carol@x.com"],
      "api_keys": [ { "id": "phone", "key_hash": "__PHONE_HASH__", "released": "2026-01-01",
                      "duration": "30d" } ] } ] }"#;

/// The full fixture plus a scope that **only carol** reaches, and bob with
/// no keys at all. The mint tests need a pair that sits outside bob's
/// `key_scopes_for` set for a reason other than naming nothing, and a file
/// whose bytes start clean, so "the file is unchanged" is a fact about
/// this request and not about a fixture's prehistoric keys.
const ACCOUNT_ACCESS_MINT: &str = r#"{ "version": 1,
  "applications": [
    { "name": "mpa", "base": ["https://app.x.com/mpa"],
      "scopes": [
        { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"], "access": "restricted",
          "groups": ["@admins"], "credentials": ["login"] },
        { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"], "access": "authenticated" } ] },
    { "name": "mcp", "base": ["https://ai.x.com/mcp"],
      "scopes": [
        { "name": "logs", "urls": ["https://ai.x.com/mcp/logs/*"], "access": "restricted",
          "users": ["__BOB__"] },
        { "name": "api", "urls": ["https://ai.x.com/mcp/*"], "access": "restricted",
          "users": ["__BOB__"], "credentials": ["api_key"] },
        { "name": "vault", "urls": ["https://ai.x.com/mcp/vault/*"], "access": "restricted",
          "users": ["__CAROL__"] } ] } ],
  "user_groups": { "admins": ["__BOB__"] },
  "denied": ["spammer@x.com"],
  "users": [
    { "uuid": "__BOB__", "emails": ["bob@x.com", "bob@old.com"] },
    { "uuid": "__CAROL__", "emails": ["carol@x.com"] } ] }"#;

const ACCOUNT_BEARER_CI: &str = "bbk_secondkeysecondkey00";

/// The third raw bearer, the one whose hash sits on carol's key: a test that
/// rotates bob's key must leave carol's secret working, and "working" is a
/// fact about the hash the file carries.
const ACCOUNT_BEARER_PHONE: &str = "bbk_thirdkeythirdkey0000";

/// The deadline every over-the-wire account request carries, in seconds.
///
/// It is a **deadlock detector, not a latency budget**, and the number is measured. A
/// mutation `POST` is answered only after [`mutate`] has taken the process-wide
/// [`WRITE_LOCK`] and `write_atomically` has fsynced the temp file and the directory, so
/// its latency is that write's fsync latency. Measured on this machine: 2-400 ms for the
/// suite's 39 mutation `POST`s run one at a time; the same write+fsync+rename+dir-fsync
/// sequence probed on a disk busy with another project's builds, 40 ms to **4.2 s**. Left
/// to run at large, the 11 write tests queue behind one lock, and the tail of that queue
/// measured **20.9 s** at load 10, against the 5 s this file used to allow: 5-11
/// `Timeout(Global)` failures per full parallel run, 150/150 under `--test-threads=1`.
/// That is queueing, and the tests assert status codes and file bytes, never how long a
/// save took.
///
/// So the harness serializes its own writers ([`WRITE_PERMIT`]), which bounds one
/// request's wait at one write (measured: max 2.4 s at load 7, 6.6 s at load 12), and this
/// sits about nine times above the worst request ever measured here. A handler that never
/// answers, a lock taken twice, a request the router drops, still fails, in this many
/// seconds, instead of hanging.
const ACCOUNT_DEADLINE_SECS: u64 = 60;

/// The `option`s of a `select`, as `(value, words, picked)`, in document order.
fn duration_options(select: &str) -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    let mut rest = select;
    while let Some(i) = rest.find("<option") {
        let tail = &rest[i..];
        let open_end = tail
            .find('>')
            .unwrap_or_else(|| panic!("an option opens and never closes: {tail}"));
        let open = &tail[..open_end + 1];
        let close = tail
            .find("</option>")
            .unwrap_or_else(|| panic!("an option is never closed: {tail}"));
        let at = open
            .find("value=\"")
            .unwrap_or_else(|| panic!("an option carries the value it posts: {open}"));
        let v = &open[at + 7..];
        out.push((
            v[..v.find('"').expect("a closed value")].to_string(),
            visible_text(&tail[..close]),
            open.contains("selected"),
        ));
        rest = &tail[close + "</option>".len()..];
    }
    out
}

/// `tiny_http`'s `Method` as the word a test names it by.
fn fmt_method(method: &Method) -> String {
    format!("{method:?}")
}

/// What the fake intake recorded for one request: the two headers the contract is about,
/// the body's `confirm_email`, and the `X-Real-IP` it must **never** see (§13.29 W2:
/// bb-auth-web vouches for no client address, so an address in the owner's record would be
/// one this gate copied out of a request header).
#[derive(Debug, Clone)]
struct IntakeCall {
    method: String,
    path: String,
    email: Option<String>,
    secret: Option<String>,
    real_ip: Option<String>,
    confirm_email: Option<String>,
    // 7d: the access file as it stood the moment this request arrived, answered for the
    // uuid the test asked the fake to watch. The order of a write and a `POST` is a fact
    // about two effects, and the response of either cannot show it: only the file, read
    // from inside the request, can say which came first.
    row_present: Option<bool>,
}

/// The fake intake: a `tiny_http` server on an ephemeral loopback port, shaped as
/// [`FakeCognito`]. It records each request's method, path, `X-Auth-Email`,
/// `X-BB-Delete-Secret`, `X-Real-IP` and `confirm_email`, answers each path from a script,
/// and in `silent` mode holds the accepted sockets so the caller waits out its timeout on a
/// live connection rather than being refused. A path nobody scripted answers `400`, which
/// the page reads as "not accepted": a test that forgot to script a path fails as a
/// refusal, and never as a hang.
/// One path's answers **in order**, as `(status, body, location)`. A name because the field
/// it feeds is an `Arc<Mutex<HashMap<…>>>` of tuples, and the alias is what keeps both the
/// field and the thread that reads it readable.
type Scripted = Vec<(u16, String, Option<String>)>;

/// The page's rows of actions: `p.primary` on an outcome page, `div.actions` inside a form.
/// Both, because §13.30 §4 names the row and not the tag.
fn the_page_actions(body: &str) -> Vec<String> {
    let main = the_main(body);
    let mut out = controls_with_class(&main, "p", "primary");
    out.extend(controls_with_class(&main, "div", "actions"));
    out
}
