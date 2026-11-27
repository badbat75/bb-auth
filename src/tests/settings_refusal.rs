use super::*;

// -----------------------------------------------------------------
// Settings refusals as golden strings (plan step 12, slice S0,
// docs/ARCHITECTURE.md §13.31 §6).
//
// These are characterization tests: green by design on the day they land. They pin the
// exact sentence every refusal prints today, copied from the source literal in this file
// (not from the design doc), so that when §3 turns `compile_settings`' `String` into the
// `SettingsRefusal` enum the CLI (`bb-auth-adm`, which prints `From<PrepareError> for
// String`) and the gate (`--check-settings`, which prints `read_settings`' `{path}: {e}`)
// keep printing byte-for-byte the same words. Every later slice keeps these green
// unedited; that is the byte-identity guarantee. `format!("{}", …)` compiles against both
// today's `String` and the future enum, so the test is not edited when the type changes.
// -----------------------------------------------------------------

/// The refusal `compile_settings` prints for a document, formatted the way the CLI and the
/// gate print it. `format!("{}", …)` is the whole point: it compiles against the `String`
/// of today and the `SettingsRefusal` of the later slices alike.
#[allow(clippy::useless_format)]
fn golden_settings(json: &str) -> String {
    let f: SettingsFile = serde_json::from_str(json).expect("fixture parses");
    format!("{}", compile_settings(&f).expect_err("refused"))
}

/// The refusal a `String` leaf wrapper prints, formatted the same way. The leaves keep
/// `Result<_, String>` through every slice (§3), so this stays valid.
#[allow(clippy::useless_format)]
fn golden_leaf<T>(r: Result<T, String>) -> String {
    format!("{}", r.err().expect("refused"))
}

/// One bad `SettingsFile` per refusal `compile_settings` can produce, each built by
/// mutating a valid `{ "version": 3 }` document, asserting the printed sentence equals the
/// source literal exactly. The §2 table's 46 codes, plus the doubled `login_url:` prefix
/// the leaf's own name keeps.
#[test]
fn settings_refusals_read_as_they_always_have() {
    let brand_too_long = "a".repeat(65);
    let cases: Vec<(&str, String, &str)> = vec![
            (
                "version 1",
                r#"{ "version": 1 }"#.into(),
                "\"version\": 1 was written before the app clients moved into this file (expected 3). Set gate.client_id, gate.oauth_domain and gate.social_callback_url, give every gate.social_buttons entry its own audience, and bump the version; see the CHANGELOG",
            ),
            (
                "version 2",
                r#"{ "version": 2 }"#.into(),
                "\"version\": 2 was written before the pool, the cookie domain and the authorized hosts moved into this file (expected 3). Copy BB_AUTH_COGNITO_ISSUER into gate.issuer, BB_AUTH_COOKIE_DOMAIN into gate.cookie_domain and BB_AUTH_AUTHORIZED_HOSTS into gate.authorized_hosts (as a list), bump the version, and take all three out of bb-auth.env; see the CHANGELOG",
            ),
            (
                "version 99",
                r#"{ "version": 99 }"#.into(),
                "\"version\": 99 is not this format (expected 3)",
            ),
            (
                "claim charset",
                r#"{ "version": 3, "gate": { "profile_claims": ["a b"] } }"#.into(),
                "profile_claims: claim 'a b' must be non-empty and contain only [A-Za-z0-9_:-]",
            ),
            (
                "claim empty part",
                r#"{ "version": 3, "gate": { "profile_claims": ["a::b"] } }"#.into(),
                "profile_claims: claim 'a::b' has an empty part around a '_', ':' or '-'",
            ),
            (
                "claim consumed",
                r#"{ "version": 3, "gate": { "profile_claims": ["email"] } }"#.into(),
                "profile_claims: claim 'email' is consumed by the gate itself and cannot be propagated",
            ),
            (
                "claim header reserved",
                r#"{ "version": 3, "gate": { "profile_claims": ["native_username"] } }"#.into(),
                "profile_claims: claim 'native_username' derives 'X-Auth-Native-Username', which is reserved",
            ),
            (
                "claims collide",
                r#"{ "version": 3, "gate": { "profile_claims": ["a_b", "a:b"] } }"#.into(),
                "profile_claims: claims 'a_b' and 'a:b' both derive 'X-Auth-A-B'",
            ),
            (
                "attr unknown",
                r#"{ "version": 3, "gate": { "identity_attrs": ["nope"] } }"#.into(),
                "identity_attrs: unknown identity attribute 'nope' (known: uuid, email)",
            ),
            (
                "attr twice",
                r#"{ "version": 3, "gate": { "identity_attrs": ["email", "email"] } }"#.into(),
                "identity_attrs: identity attribute 'email' is listed twice",
            ),
            (
                "attr none",
                r#"{ "version": 3, "gate": { "identity_attrs": [] } }"#.into(),
                "identity_attrs: at least one identity attribute is required (known: uuid, email); a 204 that names nobody breaks every application behind this gate, in silence",
            ),
            (
                "ttl below floor",
                r#"{ "version": 3, "gate": { "session_ttl_secs": 30 } }"#.into(),
                "session_ttl_secs: 30 is below the 60s floor; a session that expires as it is handed over is a login loop, not a short login",
            ),
            (
                "ttl above ceiling",
                r#"{ "version": 3, "gate": { "session_ttl_secs": 3153600001 } }"#.into(),
                "session_ttl_secs: 3153600001 is past the 3153600000s ceiling; a lifetime that does not fit the arithmetic mints a cookie that is already expired",
            ),
            (
                "app client id (gate)",
                r#"{ "version": 3, "gate": { "client_id": "bad id" } }"#.into(),
                "client_id: 'bad id' is not an app client id, which is letters, digits, '.', '_' and '-'",
            ),
            (
                "app client id (button)",
                r#"{ "version": 3, "gate": { "oauth_domain": "auth.x.com", "social_callback_url": "https://auth.x.com/cb", "social_buttons": [ { "idp": "Google", "audience": "bad id" } ] } }"#.into(),
                "social_buttons 'Google': audience: 'bad id' is not an app client id, which is letters, digits, '.', '_' and '-'",
            ),
            (
                "url not printable",
                r#"{ "version": 3, "gate": { "denied_url": "https://x.com/a b" } }"#.into(),
                "denied_url 'https://x.com/a b': must be printable ASCII (no spaces, no control bytes)",
            ),
            (
                "url not https",
                r#"{ "version": 3, "gate": { "denied_url": "http://x.com" } }"#.into(),
                "denied_url 'http://x.com': must be an absolute https:// URL",
            ),
            (
                "url empty host",
                r#"{ "version": 3, "gate": { "denied_url": "https://" } }"#.into(),
                "denied_url 'https://': empty host",
            ),
            (
                "url userinfo",
                r#"{ "version": 3, "gate": { "denied_url": "https://a@x.com" } }"#.into(),
                "denied_url 'https://a@x.com': userinfo '@' is not allowed in the host",
            ),
            (
                "url backslash",
                r#"{ "version": 3, "gate": { "denied_url": "https://x.com\\a" } }"#.into(),
                "denied_url 'https://x.com\\a': backslash is not allowed",
            ),
            (
                "login url keeps its doubled prefix",
                r#"{ "version": 3, "gate": { "login_url": "http://x.com" } }"#.into(),
                "login_url: login_url 'http://x.com': must be an absolute https:// URL",
            ),
            (
                "issuer userinfo and backslash",
                r#"{ "version": 3, "gate": { "issuer": "https://a@x.com" } }"#.into(),
                "issuer 'https://a@x.com': userinfo '@' and backslashes are not allowed",
            ),
            (
                "issuer query or fragment",
                r#"{ "version": 3, "gate": { "issuer": "https://x.com?q" } }"#.into(),
                "issuer 'https://x.com?q': must be the bare issuer URL: no query, no fragment",
            ),
            (
                "asset quote",
                r#"{ "version": 3, "ui": { "stylesheet_url": "https://x.com/\"a\"" } }"#.into(),
                "stylesheet_url 'https://x.com/\"a\"': must not contain a quote or an angle bracket",
            ),
            (
                "asset not https or rooted",
                r#"{ "version": 3, "ui": { "logo_url": "ftp://x.com" } }"#.into(),
                "logo_url 'ftp://x.com': must be an absolute https:// URL or a root-relative path starting with '/'",
            ),
            (
                "callback not https",
                r#"{ "version": 3, "gate": { "social_callback_url": "/cb" } }"#.into(),
                "social_callback_url: must be the absolute https:// URL registered on the app client, because Cognito compares it byte for byte",
            ),
            (
                "cookie domain not bare",
                r#"{ "version": 3, "gate": { "cookie_domain": "https://x.com" } }"#.into(),
                "cookie_domain 'https://x.com': is not a bare domain: letters, digits, '.' and '-', an optional leading dot, and no scheme, port or path",
            ),
            (
                "cookie domain single label",
                r#"{ "version": 3, "gate": { "cookie_domain": "example" } }"#.into(),
                "cookie_domain 'example': is a single label, which a browser stores for nothing: name the registrable domain the services share, such as '.example.com'",
            ),
            (
                "host control byte",
                r#"{ "version": 3, "gate": { "authorized_hosts": ["ho\tst"] } }"#.into(),
                "authorized_hosts: host pattern 'ho\tst': contains a control byte",
            ),
            (
                "host not bare",
                r#"{ "version": 3, "gate": { "authorized_hosts": ["https://x.com"] } }"#.into(),
                "authorized_hosts: host pattern 'https://x.com': must be a bare host — no scheme, port or path",
            ),
            (
                "host at or dot dot",
                r#"{ "version": 3, "gate": { "authorized_hosts": ["a..b"] } }"#.into(),
                "authorized_hosts: host pattern 'a..b': must not contain '@' or '..'",
            ),
            (
                "hosts outside cookie domain",
                r#"{ "version": 3, "gate": { "cookie_domain": ".example.com", "authorized_hosts": ["other.com"] } }"#.into(),
                "authorized_hosts: other.com outside cookie_domain '.example.com', so a login would redirect there and the browser would send no session cookie: a 401, a bounce back to the sign-in page, and a loop",
            ),
            (
                "landing off hosts",
                r#"{ "version": 3, "gate": { "landing_url": "https://nowhere.example/x" } }"#.into(),
                "landing_url: its host is not covered by authorized_hosts, so every sign-in with no rd would fall back to the sign-in page",
            ),
            (
                "oauth domain not bare",
                r#"{ "version": 3, "gate": { "oauth_domain": "https://x.com" } }"#.into(),
                "oauth_domain: 'https://x.com' is not a bare host, which is letters, digits, '.' and '-' with no scheme and no path",
            ),
            (
                "button bare name",
                r#"{ "version": 3, "gate": { "social_buttons": ["Google"] } }"#.into(),
                "social_buttons: 'Google' is a bare provider name, which was the shape before each button carried its own app client. Write it as { \"idp\": \"Google\", \"audience\": \"<app client id>\" }",
            ),
            (
                "button no idp",
                r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "", "audience": "abc" } ] } }"#.into(),
                "social_buttons: an entry names no identity_provider",
            ),
            (
                "button idp charset",
                r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "a b", "audience": "abc" } ] } }"#.into(),
                "social_buttons 'a b': a Cognito identity_provider name is letters, digits, '.', '_' and '-'",
            ),
            (
                "button twice",
                r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "Google", "audience": "abc" }, { "idp": "Google", "audience": "def" } ] } }"#.into(),
                "social_buttons: 'Google' is listed twice",
            ),
            (
                "button no audience",
                r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "Google", "audience": "" } ] } }"#.into(),
                "social_buttons 'Google': names no app client, so no button could be drawn for it. Cognito federates per app client, so this is the one that offers Google",
            ),
            (
                "social half configured",
                r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "Google", "audience": "abc123" } ] } }"#.into(),
                "social_buttons: 1 button(s) configured, but oauth_domain or social_callback_url is empty, so there is nowhere to send a visitor and nowhere for them to come back to",
            ),
            (
                "audit header not a name",
                r#"{ "version": 3, "audit": { "client_ip_header": "X_Real_IP" } }"#.into(),
                "audit.client_ip_header: 'X_Real_IP' is not a header name, which is letters, digits and '-' (nginx drops a request header with an underscore in its name)",
            ),
            (
                "audit header credential",
                r#"{ "version": 3, "audit": { "request_id_header": "Authorization" } }"#.into(),
                "audit.request_id_header: 'Authorization' carries a credential, and the audit never writes one down",
            ),
            (
                "audit headers same",
                r#"{ "version": 3, "audit": { "client_ip_header": "X-Real-IP", "request_id_header": "x-real-ip" } }"#.into(),
                "audit.client_ip_header and audit.request_id_header both name 'X-Real-IP'; one header cannot carry an address and a request id at once",
            ),
            (
                "audit limit not an amount",
                r#"{ "version": 3, "audit": { "rotation": "4" } }"#.into(),
                "audit.rotation: '4' is not an amount and a unit: write it as, say, '4 MiB', '1 GiB', '26 weeks', '6 months' or '1 year'",
            ),
            (
                "audit limit zero",
                r#"{ "version": 3, "audit": { "rotation": "0 MiB" } }"#.into(),
                "audit.rotation: '0 MiB': an amount of nothing is not a limit",
            ),
            (
                "audit limit too much",
                r#"{ "version": 3, "audit": { "rotation": "2048 GiB" } }"#.into(),
                "audit.rotation: '2048 GiB': at most 1024 GiB, which is already more than any disk or any audit needs",
            ),
            (
                "audit unbounded with retention",
                r#"{ "version": 3, "audit": { "rotation": "1 year", "retention": "2 years" } }"#.into(),
                "audit: rotation '1 year' with retention '2 years' bounds how old the audit gets and not how big: a flood of refusals would grow the live file without limit. Rotate on a size (MiB, GiB) or give the retention one",
            ),
            (
                "audit unbounded no retention",
                r#"{ "version": 3, "audit": { "rotation": "1 year" } }"#.into(),
                "audit: rotation '1 year' with no retention bounds how old the audit gets and not how big: a flood of refusals would grow the live file without limit. Rotate on a size (MiB, GiB) or give the retention one",
            ),
            (
                "brand control",
                r#"{ "version": 3, "ui": { "brand_name": "Bad\u0007Bat" } }"#.into(),
                "brand_name 'Bad\u{7}Bat': contains a control character",
            ),
            (
                "brand too long",
                format!(r#"{{ "version": 3, "ui": {{ "brand_name": "{brand_too_long}" }} }}"#),
                "brand_name: 65 characters is longer than the 64 allowed",
            ),
            (
                "theme unknown",
                r#"{ "version": 3, "ui": { "theme": "sepia" } }"#.into(),
                "theme: 'sepia' is not one of system, light, dark",
            ),
        ];
    for (label, json, want) in cases {
        assert_eq!(golden_settings(&json), want, "{label}");
    }
}

/// Each `String` leaf wrapper, called with the CLI's own flag names (the names
/// `bb-auth-adm` passes), printing each of its faults exactly. This includes the two
/// `empty` sentences `compile_settings` can never produce (a blank value is skipped before
/// the leaf is called), which is why they live in the wrappers and not the enum.
#[test]
fn settings_leaf_refusals_read_as_they_always_have() {
    // compile_page_url, the field the CLI names "denied_url", every fault incl. `empty`.
    assert_eq!(
        golden_leaf(compile_page_url("denied_url", "")),
        "denied_url '': empty"
    );
    assert_eq!(
        golden_leaf(compile_page_url("denied_url", "https://x.com/a b")),
        "denied_url 'https://x.com/a b': must be printable ASCII (no spaces, no control bytes)"
    );
    assert_eq!(
        golden_leaf(compile_page_url("denied_url", "http://x.com")),
        "denied_url 'http://x.com': must be an absolute https:// URL"
    );
    assert_eq!(
        golden_leaf(compile_page_url("denied_url", "https://")),
        "denied_url 'https://': empty host"
    );
    assert_eq!(
        golden_leaf(compile_page_url("denied_url", "https://a@x.com")),
        "denied_url 'https://a@x.com': userinfo '@' is not allowed in the host"
    );
    assert_eq!(
        golden_leaf(compile_page_url("denied_url", "https://x.com\\a")),
        "denied_url 'https://x.com\\a': backslash is not allowed"
    );
    // compile_login_url is compile_page_url under its own field name.
    assert_eq!(
        golden_leaf(compile_login_url("http://x.com")),
        "login_url 'http://x.com': must be an absolute https:// URL"
    );
    // compile_issuer, every fault.
    assert_eq!(
        golden_leaf(compile_issuer("https://x.com/a b")),
        "issuer 'https://x.com/a b': must be printable ASCII (no spaces, no control bytes)"
    );
    assert_eq!(
        golden_leaf(compile_issuer("http://x.com")),
        "issuer 'http://x.com': must be an absolute https:// URL"
    );
    // "https://" trims its trailing slashes to "https:", so it fails the https-prefix
    // check, not the empty-host check. The empty host is reached by "https:///nohost".
    assert_eq!(
        golden_leaf(compile_issuer("https://")),
        "issuer 'https://': must be an absolute https:// URL"
    );
    assert_eq!(
        golden_leaf(compile_issuer("https:///nohost")),
        "issuer 'https:///nohost': empty host"
    );
    assert_eq!(
        golden_leaf(compile_issuer("https://x.com\\p")),
        "issuer 'https://x.com\\p': userinfo '@' and backslashes are not allowed"
    );
    assert_eq!(
        golden_leaf(compile_issuer("https://x.com#frag")),
        "issuer 'https://x.com#frag': must be the bare issuer URL: no query, no fragment"
    );
    // compile_asset_url, the field the CLI names "--stylesheet", every fault.
    assert_eq!(
        golden_leaf(compile_asset_url("--stylesheet", "https://x.com/a b")),
        "--stylesheet 'https://x.com/a b': must be printable ASCII (no spaces, no control bytes)"
    );
    assert_eq!(
        golden_leaf(compile_asset_url("--stylesheet", "https://x.com/<a>")),
        "--stylesheet 'https://x.com/<a>': must not contain a quote or an angle bracket"
    );
    assert_eq!(
        golden_leaf(compile_asset_url("--stylesheet", "https://x.com\\p")),
        "--stylesheet 'https://x.com\\p': backslash is not allowed"
    );
    assert_eq!(
        golden_leaf(compile_asset_url("--stylesheet", "https://")),
        "--stylesheet 'https://': empty host"
    );
    assert_eq!(
        golden_leaf(compile_asset_url("--stylesheet", "https://a@x.com")),
        "--stylesheet 'https://a@x.com': userinfo '@' is not allowed in the host"
    );
    assert_eq!(
            golden_leaf(compile_asset_url("--stylesheet", "ftp://x.com")),
            "--stylesheet 'ftp://x.com': must be an absolute https:// URL or a root-relative path starting with '/'"
        );
    // compile_app_client_id, the CLI's flag.
    assert_eq!(
        golden_leaf(compile_app_client_id("--client-id", "bad id")),
        "--client-id: 'bad id' is not an app client id, which is letters, digits, '.', '_' and '-'"
    );
    // compile_audit_header, both CLI flags and both faults.
    assert_eq!(
            golden_leaf(compile_audit_header("--client-ip-header", "X_Real_IP")),
            "--client-ip-header: 'X_Real_IP' is not a header name, which is letters, digits and '-' (nginx drops a request header with an underscore in its name)"
        );
    assert_eq!(
        golden_leaf(compile_audit_header("--request-id-header", "Cookie")),
        "--request-id-header: 'Cookie' carries a credential, and the audit never writes one down"
    );
    // compile_cookie_domain, both faults.
    assert_eq!(
            golden_leaf(compile_cookie_domain("https://x.com")),
            "cookie_domain 'https://x.com': is not a bare domain: letters, digits, '.' and '-', an optional leading dot, and no scheme, port or path"
        );
    assert_eq!(
            golden_leaf(compile_cookie_domain("example")),
            "cookie_domain 'example': is a single label, which a browser stores for nothing: name the registrable domain the services share, such as '.example.com'"
        );
    // compile_oauth_domain.
    assert_eq!(
            golden_leaf(compile_oauth_domain("https://x.com")),
            "oauth_domain: 'https://x.com' is not a bare host, which is letters, digits, '.' and '-' with no scheme and no path"
        );
    // compile_brand_name, both faults.
    assert_eq!(
        golden_leaf(compile_brand_name("Bad\u{7}Bat")),
        "brand_name 'Bad\u{7}Bat': contains a control character"
    );
    assert_eq!(
        golden_leaf(compile_brand_name(&"a".repeat(65))),
        "brand_name: 65 characters is longer than the 64 allowed"
    );
    // compile_host_pattern, every fault incl. `empty`.
    assert_eq!(
        golden_leaf(compile_host_pattern("")),
        "host pattern '': empty"
    );
    assert_eq!(
        golden_leaf(compile_host_pattern("ho\tst")),
        "host pattern 'ho\tst': contains a control byte"
    );
    assert_eq!(
        golden_leaf(compile_host_pattern("https://x.com")),
        "host pattern 'https://x.com': must be a bare host — no scheme, port or path"
    );
    assert_eq!(
        golden_leaf(compile_host_pattern("a..b")),
        "host pattern 'a..b': must not contain '@' or '..'"
    );
    // AuditLimit::parse, every fault.
    assert_eq!(
            golden_leaf(AuditLimit::parse("4")),
            "'4' is not an amount and a unit: write it as, say, '4 MiB', '1 GiB', '26 weeks', '6 months' or '1 year'"
        );
    assert_eq!(
        golden_leaf(AuditLimit::parse("0 MiB")),
        "'0 MiB': an amount of nothing is not a limit"
    );
    assert_eq!(
        golden_leaf(AuditLimit::parse("2048 GiB")),
        "'2048 GiB': at most 1024 GiB, which is already more than any disk or any audit needs"
    );
    // AuditPolicy::new, the unbounded pair, both arms.
    assert_eq!(
            golden_leaf(AuditPolicy::new(
                AuditLimit::parse("1 year").unwrap(),
                Some(AuditLimit::parse("2 years").unwrap())
            )),
            "rotation '1 year' with retention '2 years' bounds how old the audit gets and not how big: a flood of refusals would grow the live file without limit. Rotate on a size (MiB, GiB) or give the retention one"
        );
    assert_eq!(
            golden_leaf(AuditPolicy::new(
                AuditLimit::parse("1 year").unwrap(),
                None
            )),
            "rotation '1 year' with no retention bounds how old the audit gets and not how big: a flood of refusals would grow the live file without limit. Rotate on a size (MiB, GiB) or give the retention one"
        );
    // compile_profile_claims, every fault.
    assert_eq!(
        golden_leaf(compile_profile_claims(&claims("a b"))),
        "claim 'a b' must be non-empty and contain only [A-Za-z0-9_:-]"
    );
    assert_eq!(
        golden_leaf(compile_profile_claims(&claims("a::b"))),
        "claim 'a::b' has an empty part around a '_', ':' or '-'"
    );
    assert_eq!(
        golden_leaf(compile_profile_claims(&claims("email"))),
        "claim 'email' is consumed by the gate itself and cannot be propagated"
    );
    assert_eq!(
        golden_leaf(compile_profile_claims(&claims("native_username"))),
        "claim 'native_username' derives 'X-Auth-Native-Username', which is reserved"
    );
    assert_eq!(
        golden_leaf(compile_profile_claims(&claims("a_b,a:b"))),
        "claims 'a_b' and 'a:b' both derive 'X-Auth-A-B'"
    );
    // compile_identity_attrs, every fault.
    assert_eq!(
        golden_leaf(compile_identity_attrs(&claims("nope"))),
        "unknown identity attribute 'nope' (known: uuid, email)"
    );
    assert_eq!(
        golden_leaf(compile_identity_attrs(&claims("email,email"))),
        "identity attribute 'email' is listed twice"
    );
    assert_eq!(
            golden_leaf(compile_identity_attrs(&claims(""))),
            "at least one identity attribute is required (known: uuid, email); a 204 that names nobody breaks every application behind this gate, in silence"
        );
}

/// `SettingsWrite::prepare` prefixes a compile refusal with `refusing to write:` and a
/// space, and the CLI prints exactly that string, so the bytes are the operator's contract.
#[test]
#[allow(clippy::useless_format)]
fn a_refused_write_reads_as_it_always_has() {
    let doc: SettingsFile = serde_json::from_str(
        r#"{ "version": 3, "gate": { "landing_url": "https://nowhere.example/x" } }"#,
    )
    .expect("fixture parses");
    let got = format!("{}", SettingsWrite::prepare(&doc).expect_err("refused"));
    assert!(got.starts_with("refusing to write: "), "{got}");
    assert_eq!(
            got,
            "refusing to write: landing_url: its host is not covered by authorized_hosts, so every sign-in with no rd would fall back to the sign-in page"
        );
}

/// A document `compile_settings` refuses, as the refusal it answers with (§13.31 §3).
/// `expect_err` asks for `Debug` on the `Ok` side, which `Settings` has.
fn settings_refusal_of(json: &str) -> SettingsRefusal {
    let f: SettingsFile = serde_json::from_str(json).expect("fixture parses");
    compile_settings(&f).expect_err("refused")
}

/// S1: `compile_settings` answers with the variant, not the sentence, and every variant
/// carries the stable code §2 lists. The matcher pins the variant (a `code()` that answered
/// the right string off the wrong arm would pass the code assert alone), and the code pins
/// the name S8 maps to a `K` key in the GUI. Each fixture is the one the S0 golden uses for
/// that sentence, so the refusal is known reachable and reaches the arm under test rather
/// than an earlier check. The last case is the brand name, the leaf S1 left as the temporary
/// `Other` and S7 converted: it is pinned here as well as in S7's own test because it is the
/// one case that shows the sequence working, a refusal that travelled as a sentence through
/// S1 to S6 and arrives as a variant with the same bytes.
#[test]
fn compile_settings_names_its_refusal() {
    type Row<'a> = (&'a str, &'a str, &'a str, fn(&SettingsRefusal) -> bool);
    let cases: Vec<Row> = vec![
        ("version", r#"{ "version": 1 }"#, "version", |r| {
            matches!(r, SettingsRefusal::Version { .. })
        }),
        (
            "ttl below floor",
            r#"{ "version": 3, "gate": { "session_ttl_secs": 30 } }"#,
            "ttl_below_floor",
            |r| matches!(r, SettingsRefusal::TtlBelowFloor { .. }),
        ),
        (
            "ttl above ceiling",
            r#"{ "version": 3, "gate": { "session_ttl_secs": 3153600001 } }"#,
            "ttl_above_ceiling",
            |r| matches!(r, SettingsRefusal::TtlAboveCeiling { .. }),
        ),
        (
            "hosts outside cookie domain",
            r#"{ "version": 3, "gate": { "cookie_domain": ".example.com", "authorized_hosts": ["other.com"] } }"#,
            "hosts_outside_cookie_domain",
            |r| matches!(r, SettingsRefusal::HostsOutsideCookieDomain { .. }),
        ),
        (
            "landing off hosts",
            r#"{ "version": 3, "gate": { "landing_url": "https://nowhere.example/x" } }"#,
            "landing_off_hosts",
            |r| matches!(r, SettingsRefusal::LandingOffHosts),
        ),
        (
            "callback not https",
            r#"{ "version": 3, "gate": { "social_callback_url": "/cb" } }"#,
            "callback_not_https",
            |r| matches!(r, SettingsRefusal::CallbackNotHttps),
        ),
        (
            "social half configured",
            r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "Google", "audience": "abc123" } ] } }"#,
            "social_half_configured",
            |r| matches!(r, SettingsRefusal::SocialHalfConfigured { .. }),
        ),
        (
            "audit headers same",
            r#"{ "version": 3, "audit": { "client_ip_header": "X-Real-IP", "request_id_header": "x-real-ip" } }"#,
            "audit_headers_same",
            |r| matches!(r, SettingsRefusal::AuditHeadersSame { .. }),
        ),
        (
            "theme unknown",
            r#"{ "version": 3, "ui": { "theme": "sepia" } }"#,
            "theme_unknown",
            |r| matches!(r, SettingsRefusal::ThemeUnknown { .. }),
        ),
    ];
    for (label, json, code, is_variant) in cases {
        let r = settings_refusal_of(json);
        assert!(is_variant(&r), "{label}: got {r:?}");
        assert_eq!(r.code(), code, "{label}: {r}");
    }
    // The leaf S1 left as the temporary `Other`, pinned here as the survivor of the sequence:
    // it kept today's sentence byte for byte through S1 to S6, and S7 made it a variant. The
    // bytes are the S0 golden's, so the conversion is visible as a code, not as a rewording.
    let r = settings_refusal_of(r#"{ "version": 3, "ui": { "brand_name": "Bad\u0007Bat" } }"#);
    assert!(
        matches!(&r, SettingsRefusal::BrandControl { name } if name == "Bad\u{7}Bat"),
        "{r:?}"
    );
    assert_eq!(r.code(), "brand_control");
    assert_eq!(
        r.to_string(),
        "brand_name 'Bad\u{7}Bat': contains a control character"
    );
}

/// S2 (§13.31 §2, §3, §7): the eight claim and attribute refusals are variants of
/// `SettingsRefusal`, not sentences riding in `Other`. Each row is the S0 golden's own
/// fixture for that sentence, so the refusal is known reachable and reaches the arm under
/// test, and each row asserts four things: the variant carries the §2 arguments; `code()` is
/// the §2 `snake_case` name S8 maps to a `K` key; the private `prefix()`/`sentence()` pair
/// splits today's sentence the way §3 says, the prefix being the key `compile_settings` used
/// to add and the sentence the leaf's own words; and `Display` joins them with ": ", which is
/// what the CLI and the gate print (the S0 golden pins those joined bytes, this pins the
/// join). The block after the table pins the two `String` wrappers as thin: each returns
/// exactly its variant's `sentence()`, so the access file's parser and the CLI's pre-checks
/// keep their bytes and each sentence has exactly one home.
#[test]
fn claim_and_attribute_refusals_are_codes() {
    type Row<'a> = (
        &'a str,
        &'a str,
        &'a str,
        &'a str,
        &'a str,
        fn(&SettingsRefusal) -> bool,
    );
    let cases: Vec<Row> = vec![
            (
                "claim charset",
                r#"{ "version": 3, "gate": { "profile_claims": ["a b"] } }"#,
                "claim_charset",
                "profile_claims",
                "claim 'a b' must be non-empty and contain only [A-Za-z0-9_:-]",
                |r| {
                    matches!(r, SettingsRefusal::ClaimCharset { claim } if claim == "a b")
                },
            ),
            (
                "claim empty part",
                r#"{ "version": 3, "gate": { "profile_claims": ["a::b"] } }"#,
                "claim_empty_part",
                "profile_claims",
                "claim 'a::b' has an empty part around a '_', ':' or '-'",
                |r| {
                    matches!(r, SettingsRefusal::ClaimEmptyPart { claim } if claim == "a::b")
                },
            ),
            (
                "claim consumed",
                r#"{ "version": 3, "gate": { "profile_claims": ["email"] } }"#,
                "claim_consumed",
                "profile_claims",
                "claim 'email' is consumed by the gate itself and cannot be propagated",
                |r| {
                    matches!(r, SettingsRefusal::ClaimConsumed { claim } if claim == "email")
                },
            ),
            (
                "claim header reserved",
                r#"{ "version": 3, "gate": { "profile_claims": ["native_username"] } }"#,
                "claim_header_reserved",
                "profile_claims",
                "claim 'native_username' derives 'X-Auth-Native-Username', which is reserved",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::ClaimHeaderReserved {
                            claim,
                            header
                        } if claim == "native_username" && header == "X-Auth-Native-Username"
                    )
                },
            ),
            (
                "claims collide",
                r#"{ "version": 3, "gate": { "profile_claims": ["a_b", "a:b"] } }"#,
                "claims_collide",
                "profile_claims",
                "claims 'a_b' and 'a:b' both derive 'X-Auth-A-B'",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::ClaimsCollide {
                            first,
                            second,
                            header
                        } if first == "a_b" && second == "a:b" && header == "X-Auth-A-B"
                    )
                },
            ),
            (
                // The known list is `IDENTITY_ATTRS` joined, in the file's order.
                "attr unknown",
                r#"{ "version": 3, "gate": { "identity_attrs": ["nope"] } }"#,
                "attr_unknown",
                "identity_attrs",
                "unknown identity attribute 'nope' (known: uuid, email)",
                |r| matches!(r, SettingsRefusal::AttrUnknown { attr } if attr == "nope"),
            ),
            (
                "attr twice",
                r#"{ "version": 3, "gate": { "identity_attrs": ["email", "email"] } }"#,
                "attr_twice",
                "identity_attrs",
                "identity attribute 'email' is listed twice",
                |r| matches!(r, SettingsRefusal::AttrTwice { attr } if attr == "email"),
            ),
            (
                "attr none",
                r#"{ "version": 3, "gate": { "identity_attrs": [] } }"#,
                "attr_none",
                "identity_attrs",
                "at least one identity attribute is required (known: uuid, email); a 204 that names nobody breaks every application behind this gate, in silence",
                |r| matches!(r, SettingsRefusal::AttrNone),
            ),
        ];
    for row in cases.iter() {
        let (label, json, code, prefix, sentence, is_variant) = *row;
        let r = settings_refusal_of(json);
        assert!(is_variant(&r), "{label}: got {r:?}");
        assert_eq!(r.code(), code, "{label}: {r:?}");
        assert_eq!(r.prefix(), Some(prefix), "{label}: {r:?}");
        assert_eq!(r.sentence(), sentence, "{label}: {r:?}");
        assert_eq!(
            r.to_string(),
            format!("{prefix}: {sentence}"),
            "{label}: Display is not prefix + \": \" + sentence"
        );
    }
    // The wrappers, called the way the access file's parser and the CLI's pre-checks call
    // them, each answering its variant's own sentence.
    let leaves: Vec<(&str, String)> = vec![
        (
            "claim charset",
            refusal(compile_profile_claims(&claims("a b"))),
        ),
        (
            "claim empty part",
            refusal(compile_profile_claims(&claims("a::b"))),
        ),
        (
            "claim consumed",
            refusal(compile_profile_claims(&claims("email"))),
        ),
        (
            "claim header reserved",
            refusal(compile_profile_claims(&claims("native_username"))),
        ),
        (
            "claims collide",
            refusal(compile_profile_claims(&claims("a_b,a:b"))),
        ),
        (
            "attr unknown",
            refusal(compile_identity_attrs(&claims("nope"))),
        ),
        (
            "attr twice",
            refusal(compile_identity_attrs(&claims("email,email"))),
        ),
        ("attr none", refusal(compile_identity_attrs(&claims("")))),
    ];
    for (label, leaf) in leaves {
        let json = cases
            .iter()
            .find(|c| c.0 == label)
            .map(|c| c.1)
            .expect("the label is one of the rows above");
        assert_eq!(
            leaf,
            settings_refusal_of(json).sentence(),
            "{label}: the String wrapper's sentence is not the variant's"
        );
    }
}

/// S3 (§13.31 §2, §3, §7): a URL refusal is one `Url` variant carrying which setting
/// (`SettingKey`), the text today's sentence quotes (`raw`) and which of the nine faults
/// (`UrlFault`), not a sentence riding in `Other`. Each row is the S0 golden's own fixture
/// for that sentence, so the refusal is known reachable and reaches the arm under test, and
/// each row asserts five things: the variant's three arguments; `code()` is §2's
/// `url_<fault>` name, which is what S8 maps to a `K` key; `prefix()` is `login_url` for the
/// sign-in page and nothing for the rest, which is how today's doubled
/// `login_url: login_url '…': …` is kept while the other six settings stay single;
/// `sentence()` is the setting's name, the quoted text and the fault's tail, which is what
/// the leaf's `String` wrapper answers under the caller's field name; and `Display` is
/// today's bytes, prefix joined with ": ". Every fixture carries no surrounding whitespace,
/// so the trimmed and untrimmed readings of `raw` (§2 notes the three leaves differ) cannot
/// differ here, and the row pins the value the sentence quotes, not one of the two readings.
/// The blocks after the table pin the shared parts: the nine tails, the eleven setting names,
/// and that each `String` wrapper is thin, formatting the caller's field name with the same
/// tail the variant carries, so the access file's parser and the CLI's flag-named pre-checks
/// keep their bytes and every tail has exactly one home.
#[test]
fn url_refusals_name_the_setting_and_the_fault() {
    type Row<'a> = (
        &'a str,               // label
        &'a str,               // the fixture, the S0 golden's own
        SettingKey,            // which setting the variant names
        &'a str,               // the text the sentence quotes
        UrlFault,              // which of the nine faults
        &'a str,               // code()
        Option<&'a str>,       // prefix()
        &'a str,               // Display: today's bytes, byte for byte
        fn(&'a str) -> String, // the String wrapper, under the setting's own name
    );
    let cases: Vec<Row> = vec![
        (
            "sign-in page not https",
            r#"{ "version": 3, "gate": { "login_url": "http://x.com" } }"#,
            SettingKey::LoginUrl,
            "http://x.com",
            UrlFault::NotHttps,
            "url_not_https",
            Some("login_url"),
            "login_url: login_url 'http://x.com': must be an absolute https:// URL",
            |raw| refusal(compile_login_url(raw)),
        ),
        (
            "landing page not https",
            r#"{ "version": 3, "gate": { "landing_url": "http://x.com" } }"#,
            SettingKey::LandingUrl,
            "http://x.com",
            UrlFault::NotHttps,
            "url_not_https",
            None,
            "landing_url 'http://x.com': must be an absolute https:// URL",
            |raw| refusal(compile_page_url("landing_url", raw)),
        ),
        (
            "issuer with a query",
            r#"{ "version": 3, "gate": { "issuer": "https://x.com?q" } }"#,
            SettingKey::Issuer,
            "https://x.com?q",
            UrlFault::QueryOrFragment,
            "url_query_or_fragment",
            None,
            "issuer 'https://x.com?q': must be the bare issuer URL: no query, no fragment",
            |raw| refusal(compile_issuer(raw)),
        ),
        (
            // The callback is an asset URL, so a scheme that is not https and is not a
            // root-relative path is the asset fault; the bare `/cb` that passes this leaf is
            // the separate `CallbackNotHttps` (S1), which is why this row is `ftp://`.
            "callback not https and not rooted",
            r#"{ "version": 3, "gate": { "social_callback_url": "ftp://x.com" } }"#,
            SettingKey::SocialCallbackUrl,
            "ftp://x.com",
            UrlFault::NotHttpsOrRooted,
            "url_not_https_or_rooted",
            None,
            "social_callback_url 'ftp://x.com': must be an absolute https:// URL or a \
                 root-relative path starting with '/'",
            |raw| refusal(compile_asset_url("social_callback_url", raw)),
        ),
        (
            "logo with a quote",
            r#"{ "version": 3, "ui": { "logo_url": "https://x.com/\"a\"" } }"#,
            SettingKey::LogoUrl,
            "https://x.com/\"a\"",
            UrlFault::Quote,
            "url_quote",
            None,
            "logo_url 'https://x.com/\"a\"': must not contain a quote or an angle bracket",
            |raw| refusal(compile_asset_url("logo_url", raw)),
        ),
    ];
    for row in cases.iter() {
        let (label, json, key, raw, fault, code, prefix, display, leaf) = *row;
        let r = settings_refusal_of(json);
        let (got_key, got_raw, got_fault) = match &r {
            SettingsRefusal::Url {
                key: k,
                raw: w,
                fault: f,
            } => (*k, w.clone(), *f),
            other => panic!("{label}: expected SettingsRefusal::Url, got {other:?}"),
        };
        assert_eq!(got_key, key, "{label}: which setting the refusal names");
        assert_eq!(got_raw, raw, "{label}: the text the sentence quotes");
        assert_eq!(got_fault, fault, "{label}: which fault");
        assert_eq!(r.code(), code, "{label}: {r:?}");
        assert_eq!(r.prefix(), prefix, "{label}: {r:?}");
        assert_eq!(
            r.sentence(),
            format!("{} '{raw}': {fault}", key.name()),
            "{label}: the sentence is the setting's name, the quoted text and the fault's tail"
        );
        assert_eq!(
            r.to_string(),
            display,
            "{label}: Display is not prefix + \": \" + sentence"
        );
        assert_eq!(
            leaf(raw),
            r.sentence(),
            "{label}: the String wrapper is not the variant's sentence under the setting's \
                 own name"
        );
    }
    // The nine tails, byte for byte from today's leaf sentences. `UrlFault`'s `Display` is
    // the one home of each: the wrapper formats `{field} '{raw}': {fault}` with the caller's
    // field and the enum's `sentence()` formats it with the setting's name, and both print
    // this tail unchanged (§3), which is the whole reason `Url` is nested.
    let tails: Vec<(UrlFault, &str)> = vec![
        (
            UrlFault::NotPrintable,
            "must be printable ASCII (no spaces, no control bytes)",
        ),
        (UrlFault::NotHttps, "must be an absolute https:// URL"),
        (UrlFault::EmptyHost, "empty host"),
        (
            UrlFault::Userinfo,
            "userinfo '@' is not allowed in the host",
        ),
        (UrlFault::Backslash, "backslash is not allowed"),
        (
            UrlFault::UserinfoOrBackslash,
            "userinfo '@' and backslashes are not allowed",
        ),
        (
            UrlFault::QueryOrFragment,
            "must be the bare issuer URL: no query, no fragment",
        ),
        (
            UrlFault::Quote,
            "must not contain a quote or an angle bracket",
        ),
        (
            UrlFault::NotHttpsOrRooted,
            "must be an absolute https:// URL or a root-relative path starting with '/'",
        ),
    ];
    for (fault, tail) in tails {
        assert_eq!(fault.to_string(), tail, "{fault:?}");
    }
    // Which name each setting is quoted by: a gate key bare, an audit key with its section,
    // which is what today's sentences spell (§3). The audit four are named here because
    // `SettingKey` arrives with this slice and S6 is the slice that uses them: a name spelled
    // for the audit's own sentence is pinned the day the type exists, not the day it is read.
    let names: Vec<(SettingKey, &str)> = vec![
        (SettingKey::LoginUrl, "login_url"),
        (SettingKey::DeniedUrl, "denied_url"),
        (SettingKey::LandingUrl, "landing_url"),
        (SettingKey::Issuer, "issuer"),
        (SettingKey::SocialCallbackUrl, "social_callback_url"),
        (SettingKey::StylesheetUrl, "stylesheet_url"),
        (SettingKey::LogoUrl, "logo_url"),
        (SettingKey::ClientIpHeader, "audit.client_ip_header"),
        (SettingKey::RequestIdHeader, "audit.request_id_header"),
        (SettingKey::AuditRotation, "audit.rotation"),
        (SettingKey::AuditRetention, "audit.retention"),
    ];
    for (key, name) in names {
        assert_eq!(key.name(), name, "{key:?}");
    }
    // The two callers whose field name is not a settings key, through the same core: the
    // tail is the shared one, the field is the caller's. The bytes are the S0 leaf golden's;
    // this pins that they come out of the typed core and not out of a second copy of a
    // sentence, which is what the access file's parser and `bb-auth-adm` depend on.
    assert_eq!(
        refusal(compile_asset_url("--stylesheet", "ftp://x.com")),
        format!("--stylesheet 'ftp://x.com': {}", UrlFault::NotHttpsOrRooted),
        "the CLI's flag-named asset refusal does not carry the shared tail"
    );
    assert_eq!(
        refusal(compile_page_url("denied_url", "https://x.com/a b")),
        format!("denied_url 'https://x.com/a b': {}", UrlFault::NotPrintable),
        "the access file's field-named page refusal does not carry the shared tail"
    );
}

/// S4 (§13.31 §2, §3, §7): the app client id, the cookie domain, the host pattern and the
/// OAuth domain refusals are variants of `SettingsRefusal`, not sentences riding in `Other`.
/// Each row is the S0 golden's own fixture for that sentence, so the refusal is known
/// reachable and reaches the arm under test, and each row asserts four things: the variant
/// carries the §2 arguments; `code()` is the §2 `snake_case` name S8 maps to a `K` key; the
/// private `prefix()`/`sentence()` pair splits today's sentence the way §3 says, the prefix
/// being `authorized_hosts` for the three host faults (the leaf's sentence starts
/// `host pattern '…'`, and `compile_settings` used to add the key) and nothing for the rest,
/// whose sentence names its key itself; and `Display` joins the two with ": ", which is what
/// the CLI and the gate print (the S0 golden pins those joined bytes, this pins the join).
/// The `HostNotBare` sentence carries today's em-dash: it is data, kept byte for byte. The
/// blocks after the table pin the four `String` wrappers as thin, each returning exactly its
/// variant's `sentence()` under the setting's own name, so the CLI's pre-checks keep their
/// bytes and each sentence has exactly one home, and pin the CLI's flag-named app client
/// refusal (`bb-auth-adm` calls `compile_app_client_id("--client-id", …)`) as the same tail
/// under the caller's name. The last block pins the button arm of `AppClientId`, which
/// `compile_settings` cannot produce until S5 converts `compile_social_buttons`: the variant
/// is built directly, and its `Display` is the S0 golden's button literal.
#[test]
fn domain_host_and_client_refusals_are_codes() {
    type Row<'a> = (
        &'a str,
        &'a str,
        &'a str,
        Option<&'a str>,
        &'a str,
        fn(&SettingsRefusal) -> bool,
    );
    let cases: Vec<Row> = vec![
            (
                "app client id",
                r#"{ "version": 3, "gate": { "client_id": "bad id" } }"#,
                "app_client_id",
                None,
                "client_id: 'bad id' is not an app client id, which is letters, digits, '.', '_' and '-'",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::AppClientId { button, id }
                            if button.is_none() && id == "bad id"
                    )
                },
            ),
            (
                "cookie domain not bare",
                r#"{ "version": 3, "gate": { "cookie_domain": "https://x.com" } }"#,
                "cookie_domain_not_bare",
                None,
                "cookie_domain 'https://x.com': is not a bare domain: letters, digits, '.' and '-', an optional leading dot, and no scheme, port or path",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::CookieDomainNotBare { raw } if raw == "https://x.com"
                    )
                },
            ),
            (
                "cookie domain single label",
                r#"{ "version": 3, "gate": { "cookie_domain": "example" } }"#,
                "cookie_domain_single_label",
                None,
                "cookie_domain 'example': is a single label, which a browser stores for nothing: name the registrable domain the services share, such as '.example.com'",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::CookieDomainSingleLabel { raw } if raw == "example"
                    )
                },
            ),
            (
                "host control byte",
                r#"{ "version": 3, "gate": { "authorized_hosts": ["ho\tst"] } }"#,
                "host_control_byte",
                Some("authorized_hosts"),
                "host pattern 'ho\tst': contains a control byte",
                |r| matches!(r, SettingsRefusal::HostControlByte { raw } if raw == "ho\tst"),
            ),
            (
                "host not bare",
                r#"{ "version": 3, "gate": { "authorized_hosts": ["https://x.com"] } }"#,
                "host_not_bare",
                Some("authorized_hosts"),
                "host pattern 'https://x.com': must be a bare host — no scheme, port or path",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::HostNotBare { raw } if raw == "https://x.com"
                    )
                },
            ),
            (
                "host at or dot dot",
                r#"{ "version": 3, "gate": { "authorized_hosts": ["a..b"] } }"#,
                "host_at_or_dot_dot",
                Some("authorized_hosts"),
                "host pattern 'a..b': must not contain '@' or '..'",
                |r| matches!(r, SettingsRefusal::HostAtOrDotDot { raw } if raw == "a..b"),
            ),
            (
                "oauth domain not bare",
                r#"{ "version": 3, "gate": { "oauth_domain": "https://x.com" } }"#,
                "oauth_domain_not_bare",
                None,
                "oauth_domain: 'https://x.com' is not a bare host, which is letters, digits, '.' and '-' with no scheme and no path",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::OauthDomainNotBare { raw } if raw == "https://x.com"
                    )
                },
            ),
        ];
    for row in cases.iter() {
        let (label, json, code, prefix, sentence, is_variant) = *row;
        let r = settings_refusal_of(json);
        assert!(is_variant(&r), "{label}: got {r:?}");
        assert_eq!(r.code(), code, "{label}: {r:?}");
        assert_eq!(r.prefix(), prefix, "{label}: {r:?}");
        assert_eq!(r.sentence(), sentence, "{label}: {r:?}");
        let display = match prefix {
            Some(p) => format!("{p}: {sentence}"),
            None => sentence.to_string(),
        };
        assert_eq!(
            r.to_string(),
            display,
            "{label}: Display is not prefix + \": \" + sentence"
        );
    }
    // The four wrappers, called the way `compile_settings` and the CLI's pre-checks call
    // them, each answering its variant's own sentence: the app client leaf spells the
    // setting's name from the caller's field, the cookie domain and OAuth leaves spell their
    // key inside the sentence, and the host leaf's sentence is the tail the settings function
    // prefixes with `authorized_hosts`. The bytes are the S0 leaf golden's; this pins that
    // they come out of the typed cores and not out of a second copy of a sentence.
    let leaves: Vec<(&str, String)> = vec![
        (
            "app client id",
            refusal(compile_app_client_id("client_id", "bad id")),
        ),
        (
            "cookie domain not bare",
            refusal(compile_cookie_domain("https://x.com")),
        ),
        (
            "cookie domain single label",
            refusal(compile_cookie_domain("example")),
        ),
        ("host control byte", refusal(compile_host_pattern("ho\tst"))),
        (
            "host not bare",
            refusal(compile_host_pattern("https://x.com")),
        ),
        ("host at or dot dot", refusal(compile_host_pattern("a..b"))),
        (
            "oauth domain not bare",
            refusal(compile_oauth_domain("https://x.com")),
        ),
    ];
    for (label, leaf) in leaves {
        let json = cases
            .iter()
            .find(|c| c.0 == label)
            .map(|c| c.1)
            .expect("the label is one of the rows above");
        assert_eq!(
            leaf,
            settings_refusal_of(json).sentence(),
            "{label}: the String wrapper's sentence is not the variant's"
        );
    }
    // The CLI's flag-named app client refusal: the same tail, under the caller's name, which
    // is what `bb-auth-adm settings set --client-id` prints today.
    assert_eq!(
        refusal(compile_app_client_id("--client-id", "bad id")),
        "--client-id: 'bad id' is not an app client id, which is letters, digits, '.', '_' and '-'",
        "the CLI's flag-named app client refusal is not the shared tail under its own name"
    );
    // The button arm, built directly: `compile_settings` reaches it only when S5 converts
    // `compile_social_buttons`, and the S0 golden's fixture for this sentence still answers
    // `Other` today. The shape is §2's, and the bytes are the golden's.
    let button = SettingsRefusal::AppClientId {
        button: Some("Google".to_string()),
        id: "bad id".to_string(),
    };
    assert_eq!(button.code(), "app_client_id");
    assert_eq!(button.prefix(), None);
    assert_eq!(
            button.to_string(),
            "social_buttons 'Google': audience: 'bad id' is not an app client id, which is letters, digits, '.', '_' and '-'"
        );
}

/// A `gate.social_buttons` array, as the settings file spells it.
fn social_specs(json: &str) -> Vec<SocialButtonSpec> {
    serde_json::from_str(json).expect("button fixture parses")
}

/// S5 (§13.31 §2, §3, §7): the five refusals a `gate.social_buttons` entry can raise are
/// variants of `SettingsRefusal`, not sentences riding in `Other`, and
/// `compile_social_buttons` answers that typed refusal itself: its only caller is
/// `compile_settings` (§3), so it keeps no `String` wrapper, and the refusal the leaf builds
/// is the refusal the file is refused with, variant for variant. Each row is the S0 golden's
/// own fixture for that sentence, so the refusal is known reachable and reaches the arm under
/// test, and each row asserts five things: the variant carries the §2 arguments; `code()` is
/// the §2 `snake_case` name S8 maps to `SetRefFileOnly`; `prefix()` is nothing, because each
/// of these sentences names `social_buttons` itself, which is why today's bytes carry no
/// doubled key; `sentence()` is today's bytes; and `Display` is those same bytes, which is
/// what `--check-settings` and `bb-auth-adm` print (the golden pins the bytes, this pins the
/// shape). The fixture is built from the row's own button array, so the leaf and
/// `compile_settings` are fed the same document, and the last assert of each row requires the
/// two refusals to be the same variant: one home for each sentence, and no re-wrapping on the
/// way out of the leaf. The blocks after the table pin the three things the table cannot: that
/// the name reaching the variant is the **trimmed** one today's sentence quoted, that a
/// duplicate is reported under the spelling of the entry that tripped it (the comparison is
/// case-insensitive, so the stored name is not the one being refused), and that a well-formed
/// button still compiles to the pair it always compiled to, which is what keeps this slice a
/// change of error type and not a change of what is accepted. The last block pins a button's
/// bad audience as S4's `AppClientId` with the button's name, reached through
/// `compile_settings` for the first time in this slice.
#[test]
fn social_button_refusals_are_codes() {
    type Row<'a> = (
        &'a str,
        &'a str,
        &'a str,
        Option<&'a str>,
        &'a str,
        fn(&SettingsRefusal) -> bool,
    );
    let cases: Vec<Row> = vec![
            (
                "button bare name",
                r#"["Google"]"#,
                "button_bare_name",
                None,
                "social_buttons: 'Google' is a bare provider name, which was the shape before each button carried its own app client. Write it as { \"idp\": \"Google\", \"audience\": \"<app client id>\" }",
                |r| {
                    matches!(r, SettingsRefusal::ButtonBareName { name } if name == "Google")
                },
            ),
            (
                "button no idp",
                r#"[ { "idp": "", "audience": "abc" } ]"#,
                "button_no_idp",
                None,
                "social_buttons: an entry names no identity_provider",
                |r| matches!(r, SettingsRefusal::ButtonNoIdp),
            ),
            (
                "button idp charset",
                r#"[ { "idp": "a b", "audience": "abc" } ]"#,
                "button_idp_charset",
                None,
                "social_buttons 'a b': a Cognito identity_provider name is letters, digits, '.', '_' and '-'",
                |r| {
                    matches!(r, SettingsRefusal::ButtonIdpCharset { idp } if idp == "a b")
                },
            ),
            (
                "button twice",
                r#"[ { "idp": "Google", "audience": "abc" }, { "idp": "Google", "audience": "def" } ]"#,
                "button_twice",
                None,
                "social_buttons: 'Google' is listed twice",
                |r| matches!(r, SettingsRefusal::ButtonTwice { idp } if idp == "Google"),
            ),
            (
                "button no audience",
                r#"[ { "idp": "Google", "audience": "" } ]"#,
                "button_no_audience",
                None,
                "social_buttons 'Google': names no app client, so no button could be drawn for it. Cognito federates per app client, so this is the one that offers Google",
                |r| {
                    matches!(r, SettingsRefusal::ButtonNoAudience { idp } if idp == "Google")
                },
            ),
        ];
    for row in cases.iter() {
        let (label, spec, code, prefix, sentence, is_variant) = *row;
        let json = format!(r#"{{ "version": 3, "gate": {{ "social_buttons": {spec} }} }}"#);
        let r = settings_refusal_of(&json);
        assert!(is_variant(&r), "{label}: got {r:?}");
        assert_eq!(r.code(), code, "{label}: {r:?}");
        assert_eq!(r.prefix(), prefix, "{label}: {r:?}");
        assert_eq!(r.sentence(), sentence, "{label}: {r:?}");
        let display = match prefix {
            Some(p) => format!("{p}: {sentence}"),
            None => sentence.to_string(),
        };
        assert_eq!(
            r.to_string(),
            display,
            "{label}: Display is not prefix + \": \" + sentence"
        );
        assert_eq!(
            compile_social_buttons(&social_specs(spec)).expect_err("the leaf refuses too"),
            r,
            "{label}: the leaf's refusal is not the refusal compile_settings shows"
        );
    }
    // The name the variant carries is the **trimmed** one, which is the text today's sentence
    // quoted: the leaf trims before it checks the charset, so a padded name is refused under
    // the spelling the file means rather than the one that was typed.
    let padded = social_specs(r#"[ { "idp": "  a b  ", "audience": "abc" } ]"#);
    let r = compile_social_buttons(&padded).expect_err("refused");
    assert!(
        matches!(&r, SettingsRefusal::ButtonIdpCharset { idp } if idp == "a b"),
        "{r:?}"
    );
    assert_eq!(
            r.sentence(),
            "social_buttons 'a b': a Cognito identity_provider name is letters, digits, '.', '_' and '-'",
            "{r:?}"
        );
    // A duplicate is found case-insensitively and reported under the spelling of the entry
    // that tripped the check, which is the line the operator has to fix: reporting the stored
    // name would name the first entry, the one nobody wrote wrong.
    let twice = social_specs(
        r#"[ { "idp": "Google", "audience": "abc" }, { "idp": "google", "audience": "def" } ]"#,
    );
    let r = compile_social_buttons(&twice).expect_err("refused");
    assert!(
        matches!(&r, SettingsRefusal::ButtonTwice { idp } if idp == "google"),
        "{r:?}"
    );
    assert_eq!(r.code(), "button_twice", "{r:?}");
    assert_eq!(
        r.to_string(),
        "social_buttons: 'google' is listed twice",
        "{r:?}"
    );
    // The accept path is unchanged by this slice: a well-formed button compiles to the pair
    // it always compiled to, provider name trimmed. Without this, a leaf that refused
    // everything would leave every row above green.
    let ok = compile_social_buttons(&social_specs(
            r#"[ { "idp": " Google ", "audience": "abc123" }, { "idp": "Amazon", "audience": "xyz789" } ]"#,
        ))
        .expect("a well-formed button compiles");
    assert_eq!(
        ok,
        vec![
            SocialButton {
                idp: "Google".to_string(),
                audience: "abc123".to_string(),
            },
            SocialButton {
                idp: "Amazon".to_string(),
                audience: "xyz789".to_string(),
            },
        ]
    );
    // A button's bad audience is §2 row 12, the S4 variant with the button's name, reached
    // through `compile_settings` for the first time in this slice: the leaf calls the app
    // client core with the button's spelling, and the fixture and the bytes are the S0
    // golden's own, which answer `Other` today.
    let json = r#"{ "version": 3, "gate": { "oauth_domain": "auth.x.com", "social_callback_url": "https://auth.x.com/cb", "social_buttons": [ { "idp": "Google", "audience": "bad id" } ] } }"#;
    let r = settings_refusal_of(json);
    assert!(
        matches!(
            &r,
            SettingsRefusal::AppClientId { button, id }
                if button.as_deref() == Some("Google") && id == "bad id"
        ),
        "{r:?}"
    );
    assert_eq!(r.code(), "app_client_id", "{r:?}");
    assert_eq!(r.prefix(), None, "{r:?}");
    assert_eq!(
            r.to_string(),
            "social_buttons 'Google': audience: 'bad id' is not an app client id, which is letters, digits, '.', '_' and '-'"
        );
    assert_eq!(
        compile_social_buttons(&social_specs(
            r#"[ { "idp": "Google", "audience": "bad id" } ]"#,
        ))
        .expect_err("the leaf refuses too"),
        r,
        "the button audience refusal is not the one the leaf builds"
    );
}

/// S6 (§13.31 §2, §3, §7): the six audit refusals are variants of `SettingsRefusal`, not
/// sentences riding in `Other`. Each row is the S0 golden's own fixture for that sentence, so
/// the refusal is known reachable and reaches the arm under test, and each row asserts four
/// things: the variant carries the §2 arguments (which of the two header settings, which of
/// the two `HeaderFault`s, which of the two limit settings, which unit, and the retention arm
/// of the unbounded pair); `code()` is the §2 `snake_case` name S8 maps to a `K` key, the two
/// header faults spelled `audit_header_<fault>` the way `UrlFault`'s are `url_<fault>`;
/// `prefix()` is the key `compile_settings` used to write in front of the leaf's sentence,
/// which is `audit.rotation` / `audit.retention` for a limit (the leaf's sentence is the tail,
/// as the host leaf's is) and `audit` for the unbounded pair (the settings function prefixed
/// `AuditPolicy::new`'s sentence with `audit:`, which is what the CLI's
/// `.replace("audit:", …)` swaps), and nothing for a header refusal, whose sentence names its
/// own key; and `Display` joins the two with ": ", which is what the CLI and the gate print
/// (the golden pins those joined bytes, this pins the join). The blocks after the table pin
/// what the table cannot: that the name a header refusal carries is the **trimmed** one
/// today's sentence quoted, that a credential is matched case-insensitively and reported
/// under the spelling typed (the comparison is against `CREDENTIAL_HEADERS`, so naming the
/// stored spelling would blame the constant rather than the line the operator wrote), that a
/// name past the length bound is the charset fault and not a fault of its own, that the
/// unbounded pair carries the **spelled** limit and not the raw text (`'1 weeks'` is refused
/// as `'1 week'`, which is today's byte), and that the three `String` wrappers are thin:
/// `compile_audit_header` prints the shared tail under the CLI's flag name, `AuditLimit::parse`
/// prints a limit refusal's sentence with no key prefix (the CLI prefixes its own flag),
/// `AuditPolicy::new` prints the pair's sentence with no `audit:` prefix (the settings function
/// adds it), and `compile_audit_policy` keeps both prefixes byte for byte, which is why it
/// stays a `String` for the CLI's `.replace`. The last block pins the accept path unchanged: a
/// good header, a good limit and a bounded pair still compile to the values they always
/// compiled to, so a wrapper that refused everything would not leave every row above green.
#[test]
fn audit_refusals_are_codes() {
    type Row<'a> = (
        &'a str,
        &'a str,
        &'a str,
        Option<&'a str>,
        &'a str,
        fn(&SettingsRefusal) -> bool,
    );
    let cases: Vec<Row> = vec![
            (
                "audit header not a name",
                r#"{ "version": 3, "audit": { "client_ip_header": "X_Real_IP" } }"#,
                "audit_header_not_a_name",
                None,
                "audit.client_ip_header: 'X_Real_IP' is not a header name, which is letters, digits and '-' (nginx drops a request header with an underscore in its name)",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::AuditHeader { key, name, fault }
                            if *key == SettingKey::ClientIpHeader
                                && name == "X_Real_IP"
                                && *fault == HeaderFault::NotAName
                    )
                },
            ),
            (
                "audit header credential",
                r#"{ "version": 3, "audit": { "request_id_header": "Authorization" } }"#,
                "audit_header_credential",
                None,
                "audit.request_id_header: 'Authorization' carries a credential, and the audit never writes one down",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::AuditHeader { key, name, fault }
                            if *key == SettingKey::RequestIdHeader
                                && name == "Authorization"
                                && *fault == HeaderFault::Credential
                    )
                },
            ),
            (
                "audit limit not an amount",
                r#"{ "version": 3, "audit": { "rotation": "4" } }"#,
                "audit_limit_not_amount",
                Some("audit.rotation"),
                "'4' is not an amount and a unit: write it as, say, '4 MiB', '1 GiB', '26 weeks', '6 months' or '1 year'",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::AuditLimitNotAmount { key, raw }
                            if *key == SettingKey::AuditRotation && raw == "4"
                    )
                },
            ),
            (
                "audit limit zero",
                r#"{ "version": 3, "audit": { "rotation": "0 MiB" } }"#,
                "audit_limit_zero",
                Some("audit.rotation"),
                "'0 MiB': an amount of nothing is not a limit",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::AuditLimitZero { key, raw }
                            if *key == SettingKey::AuditRotation && raw == "0 MiB"
                    )
                },
            ),
            (
                // The same fault on the other setting: the `key` argument is what tells an
                // operator which box to fix, and the golden's fixtures only ever name the
                // rotation, so the table needs a row of its own for the retention.
                "audit limit zero on the retention",
                r#"{ "version": 3, "audit": { "rotation": "4 MiB", "retention": "0 GiB" } }"#,
                "audit_limit_zero",
                Some("audit.retention"),
                "'0 GiB': an amount of nothing is not a limit",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::AuditLimitZero { key, raw }
                            if *key == SettingKey::AuditRetention && raw == "0 GiB"
                    )
                },
            ),
            (
                "audit limit too much",
                r#"{ "version": 3, "audit": { "rotation": "2048 GiB" } }"#,
                "audit_limit_too_much",
                Some("audit.rotation"),
                "'2048 GiB': at most 1024 GiB, which is already more than any disk or any audit needs",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::AuditLimitTooMuch { key, raw, unit }
                            if *key == SettingKey::AuditRotation
                                && raw == "2048 GiB"
                                && *unit == AuditUnit::GiB
                    )
                },
            ),
            (
                // The second unit's arm: the sentence names the ceiling **of the unit written**,
                // so a refusal that hardcoded one ceiling would pass the row above alone.
                "audit limit too much in MiB",
                r#"{ "version": 3, "audit": { "rotation": "1048577 MiB" } }"#,
                "audit_limit_too_much",
                Some("audit.rotation"),
                "'1048577 MiB': at most 1048576 MiB, which is already more than any disk or any audit needs",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::AuditLimitTooMuch { key, raw, unit }
                            if *key == SettingKey::AuditRotation
                                && raw == "1048577 MiB"
                                && *unit == AuditUnit::MiB
                    )
                },
            ),
            (
                "audit unbounded with retention",
                r#"{ "version": 3, "audit": { "rotation": "1 year", "retention": "2 years" } }"#,
                "audit_unbounded",
                Some("audit"),
                "rotation '1 year' with retention '2 years' bounds how old the audit gets and not how big: a flood of refusals would grow the live file without limit. Rotate on a size (MiB, GiB) or give the retention one",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::AuditUnbounded { rotation, retention }
                            if rotation == "1 year" && retention.as_deref() == Some("2 years")
                    )
                },
            ),
            (
                // The other arm of the same sentence: today's bytes say `with no retention` when
                // the retention is empty, and the variant carries an `Option` for exactly that.
                "audit unbounded no retention",
                r#"{ "version": 3, "audit": { "rotation": "1 year" } }"#,
                "audit_unbounded",
                Some("audit"),
                "rotation '1 year' with no retention bounds how old the audit gets and not how big: a flood of refusals would grow the live file without limit. Rotate on a size (MiB, GiB) or give the retention one",
                |r| {
                    matches!(
                        r,
                        SettingsRefusal::AuditUnbounded { rotation, retention }
                            if rotation == "1 year" && retention.is_none()
                    )
                },
            ),
        ];
    for row in cases.iter() {
        let (label, json, code, prefix, sentence, is_variant) = *row;
        let r = settings_refusal_of(json);
        assert!(is_variant(&r), "{label}: got {r:?}");
        assert_eq!(r.code(), code, "{label}: {r:?}");
        assert_eq!(r.prefix(), prefix, "{label}: {r:?}");
        assert_eq!(r.sentence(), sentence, "{label}: {r:?}");
        let display = match prefix {
            Some(p) => format!("{p}: {sentence}"),
            None => sentence.to_string(),
        };
        assert_eq!(
            r.to_string(),
            display,
            "{label}: Display is not prefix + \": \" + sentence"
        );
    }
    // The name the variant carries is the **trimmed** one, which is the text today's sentence
    // quoted: the leaf trims before it checks anything, so a padded header is refused under
    // the spelling the file means rather than the one that was typed.
    let padded = settings_refusal_of(
        r#"{ "version": 3, "audit": { "client_ip_header": "  X_Real_IP  " } }"#,
    );
    assert!(
        matches!(
            &padded,
            SettingsRefusal::AuditHeader { name, fault, .. }
                if name == "X_Real_IP" && *fault == HeaderFault::NotAName
        ),
        "{padded:?}"
    );
    assert_eq!(
            padded.to_string(),
            "audit.client_ip_header: 'X_Real_IP' is not a header name, which is letters, digits and '-' (nginx drops a request header with an underscore in its name)",
            "{padded:?}"
        );
    // A credential is matched case-insensitively (header names are) and reported under the
    // spelling typed: naming the constant's spelling would blame `Cookie` on a file that
    // wrote `cookie`, which is the line the operator has to fix.
    let lowered =
        settings_refusal_of(r#"{ "version": 3, "audit": { "request_id_header": "cookie" } }"#);
    assert!(
        matches!(
            &lowered,
            SettingsRefusal::AuditHeader { name, fault, .. }
                if name == "cookie" && *fault == HeaderFault::Credential
        ),
        "{lowered:?}"
    );
    assert_eq!(
            lowered.to_string(),
            "audit.request_id_header: 'cookie' carries a credential, and the audit never writes one down",
            "{lowered:?}"
        );
    // A name past the length bound is the charset fault, not a fault of its own: today's leaf
    // refuses both with one sentence, and §2 lists one code, so a new fault here would be a
    // code the GUI has no key for.
    let long = "X".repeat(65);
    let r = settings_refusal_of(&format!(
        r#"{{ "version": 3, "audit": {{ "client_ip_header": "{long}" }} }}"#
    ));
    assert!(
        matches!(
            &r,
            SettingsRefusal::AuditHeader { name, fault, .. }
                if name == &long && *fault == HeaderFault::NotAName
        ),
        "{r:?}"
    );
    assert_eq!(r.code(), "audit_header_not_a_name", "{r:?}");
    // The unbounded pair carries the **spelled** limit, not the raw text: the sentence today
    // prints is built from `AuditLimit::spelled`, so `'1 weeks'` is refused as `'1 week'`.
    // Keeping the raw text would be a refusal quoting a spelling the file does not accept.
    let spelled = settings_refusal_of(r#"{ "version": 3, "audit": { "rotation": "1 weeks" } }"#);
    assert!(
        matches!(
            &spelled,
            SettingsRefusal::AuditUnbounded { rotation, retention }
                if rotation == "1 week" && retention.is_none()
        ),
        "{spelled:?}"
    );
    assert_eq!(
            spelled.to_string(),
            "audit: rotation '1 week' with no retention bounds how old the audit gets and not how big: a flood of refusals would grow the live file without limit. Rotate on a size (MiB, GiB) or give the retention one",
            "{spelled:?}"
        );
    // The header wrapper, called the way `bb-auth-adm` calls it, and the tail's one home: the
    // CLI's bytes are the variant's sentence with the setting's name swapped for the flag's,
    // and nothing else moves. The literals are the S0 leaf golden's.
    for (flag, key, fault, raw, tail) in [
            (
                "--client-ip-header",
                SettingKey::ClientIpHeader,
                HeaderFault::NotAName,
                "X_Real_IP",
                "is not a header name, which is letters, digits and '-' (nginx drops a request header with an underscore in its name)",
            ),
            (
                "--request-id-header",
                SettingKey::RequestIdHeader,
                HeaderFault::Credential,
                "Cookie",
                "carries a credential, and the audit never writes one down",
            ),
        ] {
            let v = SettingsRefusal::AuditHeader {
                key,
                name: raw.to_string(),
                fault,
            };
            assert_eq!(
                refusal(compile_audit_header(flag, raw)),
                format!("{flag}: '{raw}' {tail}"),
                "{flag}: the wrapper's bytes moved"
            );
            assert_eq!(
                v.sentence(),
                format!("{}: '{raw}' {tail}", key.name()),
                "{flag}: the variant's sentence is not the same tail under the setting's name"
            );
            assert_eq!(v.prefix(), None, "{flag}: {v:?}");
        }
    // The limit wrapper: exactly the variant's sentence, with no key prefix, because the CLI
    // prefixes its own flag name (`--audit-rotation: {e}`) and `compile_settings` prefixes the
    // setting's. One tail, three callers, no second copy of the sentence.
    for (raw, json) in [
        ("4", r#"{ "version": 3, "audit": { "rotation": "4" } }"#),
        (
            "0 MiB",
            r#"{ "version": 3, "audit": { "rotation": "0 MiB" } }"#,
        ),
        (
            "2048 GiB",
            r#"{ "version": 3, "audit": { "rotation": "2048 GiB" } }"#,
        ),
    ] {
        assert_eq!(
            refusal(AuditLimit::parse(raw)),
            settings_refusal_of(json).sentence(),
            "'{raw}': AuditLimit::parse is not the variant's sentence"
        );
    }
    // The pair: `AuditPolicy::new` answers the sentence and no prefix (the settings function
    // adds `audit:`, which is the prefix the CLI swaps), and `compile_audit_policy` keeps both
    // prefixes byte for byte, which is why it stays a `String` for that `.replace`.
    let pair = settings_refusal_of(
        r#"{ "version": 3, "audit": { "rotation": "1 year", "retention": "2 years" } }"#,
    );
    assert_eq!(
        refusal(AuditPolicy::new(
            AuditLimit::new(1, AuditUnit::Years),
            Some(AuditLimit::new(2, AuditUnit::Years))
        )),
        pair.sentence(),
        "AuditPolicy::new is not the variant's sentence"
    );
    assert_eq!(
        refusal(compile_audit_policy("1 year", "2 years")),
        pair.to_string(),
        "compile_audit_policy's bytes moved"
    );
    assert_eq!(
            refusal(compile_audit_policy("1 year", "2 years"))
                .replace("audit:", "--audit-rotation / --audit-retention:"),
            "--audit-rotation / --audit-retention: rotation '1 year' with retention '2 years' bounds how old the audit gets and not how big: a flood of refusals would grow the live file without limit. Rotate on a size (MiB, GiB) or give the retention one",
            "the CLI's flag-named pair refusal is not what it prints today"
        );
    assert_eq!(
        refusal(compile_audit_policy("4", "")),
        settings_refusal_of(r#"{ "version": 3, "audit": { "rotation": "4" } }"#).to_string(),
        "compile_audit_policy no longer prefixes a limit refusal with the setting's name"
    );
    // The accept path is unchanged by this slice: a good header, a good limit and a bounded
    // pair compile to the values they always compiled to, and a whole audit section still
    // compiles through `compile_settings`. Without this, a wrapper that refused everything
    // would leave every row above green.
    assert_eq!(
        compile_audit_header("--client-ip-header", " X-Real-IP ").expect("a good header compiles"),
        "X-Real-IP"
    );
    assert_eq!(
        AuditLimit::parse("4 MiB").expect("a good limit compiles"),
        AuditLimit::new(4, AuditUnit::MiB)
    );
    assert_eq!(
        compile_audit_policy("4 MiB", "6 months").expect("a bounded pair compiles"),
        AuditPolicy {
            rotation: AuditLimit::new(4, AuditUnit::MiB),
            retention: Some(AuditLimit::new(6, AuditUnit::Months)),
        }
    );
    assert_eq!(
        compile_audit_policy("", "").expect("empty is a default, not a refusal"),
        AuditPolicy::default()
    );
    let ok: SettingsFile = serde_json::from_str(
            r#"{ "version": 3, "audit": { "client_ip_header": "X-Real-IP", "request_id_header": "X-Request-Id", "rotation": "8 MiB", "retention": "6 months" } }"#,
        )
        .expect("fixture parses");
    assert_eq!(
        compile_settings(&ok)
            .expect("a well-formed audit section compiles")
            .audit_policy,
        AuditPolicy {
            rotation: AuditLimit::new(8, AuditUnit::MiB),
            retention: Some(AuditLimit::new(6, AuditUnit::Months)),
        }
    );
}

/// S7 (§13.31 §2 rows 44 and 45, §3, §7): the two brand-name refusals are variants of
/// `SettingsRefusal`, the last two refusals that travelled as a sentence in the temporary
/// `Other`. `compile_brand_name` keeps its `String` signature as a thin wrapper, because
/// `bb-auth-adm settings set --brand` and the GUI's own pre-check call it with their own
/// field names. Each row is the S0 golden's own fixture for that sentence, so the refusal is
/// known reachable and reaches the arm under test, and each row asserts four things: the
/// variant carries the §2 argument; `code()` is the §2 `snake_case` name S8 maps to a `K`
/// key; `prefix()` is nothing, because `compile_settings` added no prefix to this leaf (its
/// sentence names `brand_name` itself, which is why the golden's bytes start there); and
/// `Display` is the golden's bytes. The blocks after the table pin what the table cannot:
/// that the name the control refusal carries is the **trimmed** value (the leaf trims before
/// it checks anything, so a padded brand is refused under the spelling the file means, and
/// the argument is the text the sentence quotes, as §2 says); that the length is a count of
/// **characters** and not of bytes (an accented name 65 characters long is 130 bytes, so a
/// refusal printing the byte count blames a name the layout does fit); and that the `String`
/// wrapper is thin, answering exactly its variant's `sentence()`, so the CLI's `--brand`
/// refusal and the GUI's pre-check keep their bytes and each sentence has one home.
#[test]
fn brand_refusals_are_codes() {
    let long = "a".repeat(65);
    let accented = "è".repeat(65);
    type Row = (
        &'static str,
        String,
        &'static str,
        Option<&'static str>,
        &'static str,
        fn(&SettingsRefusal) -> bool,
    );
    let cases: Vec<Row> = vec![
        (
            "brand control",
            r#"{ "version": 3, "ui": { "brand_name": "Bad\u0007Bat" } }"#.into(),
            "brand_control",
            None,
            "brand_name 'Bad\u{7}Bat': contains a control character",
            |r| matches!(r, SettingsRefusal::BrandControl { name } if name == "Bad\u{7}Bat"),
        ),
        (
            // The padded spelling: the leaf trims first, so the refusal names the brand the
            // file means, and the argument is the trimmed text the sentence quotes (§2).
            "brand control padded",
            r#"{ "version": 3, "ui": { "brand_name": "  Bad\u0007Bat  " } }"#.into(),
            "brand_control",
            None,
            "brand_name 'Bad\u{7}Bat': contains a control character",
            |r| matches!(r, SettingsRefusal::BrandControl { name } if name == "Bad\u{7}Bat"),
        ),
        (
            "brand too long",
            format!(r#"{{ "version": 3, "ui": {{ "brand_name": "{long}" }} }}"#),
            "brand_too_long",
            None,
            "brand_name: 65 characters is longer than the 64 allowed",
            |r| matches!(r, SettingsRefusal::BrandTooLong { chars: 65 }),
        ),
        (
            // 65 characters, 130 bytes: the sentence counts characters, because the bound is
            // on what the page lays out, not on what the file stores.
            "brand too long in accented characters",
            format!(r#"{{ "version": 3, "ui": {{ "brand_name": "{accented}" }} }}"#),
            "brand_too_long",
            None,
            "brand_name: 65 characters is longer than the 64 allowed",
            |r| matches!(r, SettingsRefusal::BrandTooLong { chars: 65 }),
        ),
    ];
    for row in cases.iter() {
        let (label, code, prefix, sentence, is_variant) = (row.0, row.2, row.3, row.4, row.5);
        let r = settings_refusal_of(&row.1);
        assert!(is_variant(&r), "{label}: got {r:?}");
        assert_eq!(r.code(), code, "{label}: {r:?}");
        assert_eq!(r.prefix(), prefix, "{label}: {r:?}");
        assert_eq!(r.sentence(), sentence, "{label}: {r:?}");
        let display = match prefix {
            Some(p) => format!("{p}: {sentence}"),
            None => sentence.to_string(),
        };
        assert_eq!(
            r.to_string(),
            display,
            "{label}: Display is not prefix + \": \" + sentence"
        );
    }
    // The wrapper, called the way the CLI's `--brand` and the GUI's pre-check call it.
    let leaves: Vec<(&str, String)> = vec![
        ("brand control", refusal(compile_brand_name("Bad\u{7}Bat"))),
        ("brand too long", refusal(compile_brand_name(&long))),
    ];
    for (label, leaf) in leaves {
        let json = cases
            .iter()
            .find(|c| c.0 == label)
            .map(|c| &c.1)
            .expect("the label is one of the rows above");
        assert_eq!(
            leaf,
            settings_refusal_of(json).sentence(),
            "{label}: the String wrapper's sentence is not the variant's"
        );
    }
}

/// S7 (§13.31 §2, §3, §6, §7): every code has a name, a sample and a sentence, checked off
/// one list. `SETTINGS_REFUSAL_CODES` is §2's list in §2's order, and the literal below
/// spells that list out here, so a code that arrives with a new spelling, or out of order,
/// is caught by the test rather than by whoever reads the file next.
/// `settings_refusal_samples()` is one refusal per code, built in the library so the GUI's
/// test can walk the codes across the crate boundary (a `cfg(test)` item is invisible to
/// another crate). The test then asserts the two line up in both directions and exactly
/// once: a code with no sample is a refusal the GUI's exhaustive match has to invent
/// arguments for, and a sample whose code is not listed is a refusal no page can name. Every
/// sample prints a non-empty sentence, which is what the CLI and the gate print and what the
/// GUI wraps verbatim for the five file-only codes (§5), and every code is `snake_case`,
/// which is the shape §2 fixes.
#[test]
fn every_refusal_has_a_code_a_sample_and_a_sentence() {
    const EXPECTED: [&str; 46] = [
        "version",
        "claim_charset",
        "claim_empty_part",
        "claim_consumed",
        "claim_header_reserved",
        "claims_collide",
        "attr_unknown",
        "attr_twice",
        "attr_none",
        "ttl_below_floor",
        "ttl_above_ceiling",
        "app_client_id",
        "url_not_printable",
        "url_not_https",
        "url_empty_host",
        "url_userinfo",
        "url_backslash",
        "url_userinfo_or_backslash",
        "url_query_or_fragment",
        "url_quote",
        "url_not_https_or_rooted",
        "callback_not_https",
        "cookie_domain_not_bare",
        "cookie_domain_single_label",
        "host_control_byte",
        "host_not_bare",
        "host_at_or_dot_dot",
        "hosts_outside_cookie_domain",
        "landing_off_hosts",
        "oauth_domain_not_bare",
        "button_bare_name",
        "button_no_idp",
        "button_idp_charset",
        "button_twice",
        "button_no_audience",
        "social_half_configured",
        "audit_header_not_a_name",
        "audit_header_credential",
        "audit_headers_same",
        "audit_limit_not_amount",
        "audit_limit_zero",
        "audit_limit_too_much",
        "audit_unbounded",
        "brand_control",
        "brand_too_long",
        "theme_unknown",
    ];
    let listed: Vec<&str> = SETTINGS_REFUSAL_CODES.to_vec();
    assert_eq!(
        listed,
        EXPECTED.to_vec(),
        "SETTINGS_REFUSAL_CODES is not §2's 46 codes, spelled and ordered as §2 lists them"
    );
    let samples = settings_refusal_samples();
    let mut got: Vec<&str> = samples.iter().map(|r| r.code()).collect();
    got.sort_unstable();
    let mut want = listed.clone();
    want.sort_unstable();
    assert_eq!(
        got, want,
        "the samples' codes are not exactly SETTINGS_REFUSAL_CODES, each exactly once"
    );
    for r in samples.iter() {
        assert!(!r.code().is_empty(), "{r:?}: a refusal with no code");
        assert!(
            r.code()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "{r:?}: the code '{}' is not snake_case",
            r.code()
        );
        assert!(
            !r.to_string().trim().is_empty(),
            "{r:?}: a refusal that prints an empty sentence"
        );
    }
}

/// S7 (§13.31 §6, §7): every code is reached by a real settings document, not only by a
/// hand-built sample. The fixtures below are the S0 golden's, copied verbatim: the golden
/// owns the **sentences** (its literals are never edited, which is the byte-identity
/// guarantee for `bb-auth-adm` and `--check-settings`), and this test owns the **codes**, so
/// a variant no file can produce goes red here while the goldens stay untouched. A new
/// variant therefore arrives with a fixture of its own, and a code that stops being
/// reachable (a check deleted, a leaf reordered behind another) fails loudly rather than
/// leaving the GUI with a `K` key for a sentence nobody can ever meet. The 51 fixtures cover
/// 46 codes, because `version` has three fixtures for the one variant, and `app_client_id`,
/// `url_not_https` and `audit_unbounded` each have one per spelling.
#[test]
fn the_golden_fixtures_reach_every_code() {
    let brand_too_long = "a".repeat(65);
    let fixtures: Vec<String> = vec![
            r#"{ "version": 1 }"#.into(),
            r#"{ "version": 2 }"#.into(),
            r#"{ "version": 99 }"#.into(),
            r#"{ "version": 3, "gate": { "profile_claims": ["a b"] } }"#.into(),
            r#"{ "version": 3, "gate": { "profile_claims": ["a::b"] } }"#.into(),
            r#"{ "version": 3, "gate": { "profile_claims": ["email"] } }"#.into(),
            r#"{ "version": 3, "gate": { "profile_claims": ["native_username"] } }"#.into(),
            r#"{ "version": 3, "gate": { "profile_claims": ["a_b", "a:b"] } }"#.into(),
            r#"{ "version": 3, "gate": { "identity_attrs": ["nope"] } }"#.into(),
            r#"{ "version": 3, "gate": { "identity_attrs": ["email", "email"] } }"#.into(),
            r#"{ "version": 3, "gate": { "identity_attrs": [] } }"#.into(),
            r#"{ "version": 3, "gate": { "session_ttl_secs": 30 } }"#.into(),
            r#"{ "version": 3, "gate": { "session_ttl_secs": 3153600001 } }"#.into(),
            r#"{ "version": 3, "gate": { "client_id": "bad id" } }"#.into(),
            r#"{ "version": 3, "gate": { "oauth_domain": "auth.x.com", "social_callback_url": "https://auth.x.com/cb", "social_buttons": [ { "idp": "Google", "audience": "bad id" } ] } }"#.into(),
            r#"{ "version": 3, "gate": { "denied_url": "https://x.com/a b" } }"#.into(),
            r#"{ "version": 3, "gate": { "denied_url": "http://x.com" } }"#.into(),
            r#"{ "version": 3, "gate": { "denied_url": "https://" } }"#.into(),
            r#"{ "version": 3, "gate": { "denied_url": "https://a@x.com" } }"#.into(),
            r#"{ "version": 3, "gate": { "denied_url": "https://x.com\\a" } }"#.into(),
            r#"{ "version": 3, "gate": { "login_url": "http://x.com" } }"#.into(),
            r#"{ "version": 3, "gate": { "issuer": "https://a@x.com" } }"#.into(),
            r#"{ "version": 3, "gate": { "issuer": "https://x.com?q" } }"#.into(),
            r#"{ "version": 3, "ui": { "stylesheet_url": "https://x.com/\"a\"" } }"#.into(),
            r#"{ "version": 3, "ui": { "logo_url": "ftp://x.com" } }"#.into(),
            r#"{ "version": 3, "gate": { "social_callback_url": "/cb" } }"#.into(),
            r#"{ "version": 3, "gate": { "cookie_domain": "https://x.com" } }"#.into(),
            r#"{ "version": 3, "gate": { "cookie_domain": "example" } }"#.into(),
            r#"{ "version": 3, "gate": { "authorized_hosts": ["ho\tst"] } }"#.into(),
            r#"{ "version": 3, "gate": { "authorized_hosts": ["https://x.com"] } }"#.into(),
            r#"{ "version": 3, "gate": { "authorized_hosts": ["a..b"] } }"#.into(),
            r#"{ "version": 3, "gate": { "cookie_domain": ".example.com", "authorized_hosts": ["other.com"] } }"#.into(),
            r#"{ "version": 3, "gate": { "landing_url": "https://nowhere.example/x" } }"#.into(),
            r#"{ "version": 3, "gate": { "oauth_domain": "https://x.com" } }"#.into(),
            r#"{ "version": 3, "gate": { "social_buttons": ["Google"] } }"#.into(),
            r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "", "audience": "abc" } ] } }"#.into(),
            r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "a b", "audience": "abc" } ] } }"#.into(),
            r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "Google", "audience": "abc" }, { "idp": "Google", "audience": "def" } ] } }"#.into(),
            r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "Google", "audience": "" } ] } }"#.into(),
            r#"{ "version": 3, "gate": { "social_buttons": [ { "idp": "Google", "audience": "abc123" } ] } }"#.into(),
            r#"{ "version": 3, "audit": { "client_ip_header": "X_Real_IP" } }"#.into(),
            r#"{ "version": 3, "audit": { "request_id_header": "Authorization" } }"#.into(),
            r#"{ "version": 3, "audit": { "client_ip_header": "X-Real-IP", "request_id_header": "x-real-ip" } }"#.into(),
            r#"{ "version": 3, "audit": { "rotation": "4" } }"#.into(),
            r#"{ "version": 3, "audit": { "rotation": "0 MiB" } }"#.into(),
            r#"{ "version": 3, "audit": { "rotation": "2048 GiB" } }"#.into(),
            r#"{ "version": 3, "audit": { "rotation": "1 year", "retention": "2 years" } }"#.into(),
            r#"{ "version": 3, "audit": { "rotation": "1 year" } }"#.into(),
            r#"{ "version": 3, "ui": { "brand_name": "Bad\u0007Bat" } }"#.into(),
            format!(r#"{{ "version": 3, "ui": {{ "brand_name": "{brand_too_long}" }} }}"#),
            r#"{ "version": 3, "ui": { "theme": "sepia" } }"#.into(),
        ];
    let mut got: Vec<&str> = fixtures
        .iter()
        .map(|json| settings_refusal_of(json).code())
        .collect();
    got.sort_unstable();
    got.dedup();
    let mut want: Vec<&str> = SETTINGS_REFUSAL_CODES.to_vec();
    want.sort_unstable();
    assert_eq!(
        got, want,
        "the codes these fixtures produce are not SETTINGS_REFUSAL_CODES: a code no settings \
             file reaches, or a fixture reaching a code §2 does not list"
    );
}

/// S1: `From<PrepareError> for String` is the one thing that lets `bb-auth-adm` print these
/// refusals without changing a line, so it is pinned to be exactly `refusing to write: `, a
/// space, and the refusal's own `Display`, and to that sentence's bytes (the S0 golden's
/// literal), not merely to whatever `Display` says today. The two serde arms of
/// `PrepareError` (`cannot serialize:`, `serialized to invalid JSON:`) are unreachable from
/// a document, so they are not asserted here.
#[test]
fn prepare_error_becomes_the_same_string() {
    let doc: SettingsFile = serde_json::from_str(
        r#"{ "version": 3, "gate": { "landing_url": "https://nowhere.example/x" } }"#,
    )
    .expect("fixture parses");
    let err = SettingsWrite::prepare(&doc).expect_err("refused");
    let shown = match &err {
        PrepareError::Refused(r) => r.to_string(),
        _ => panic!("expected a settings refusal, not a serialize failure"),
    };
    let s = String::from(err);
    assert_eq!(s, format!("refusing to write: {shown}"));
    assert_eq!(
        s,
        "refusing to write: landing_url: its host is not covered by authorized_hosts, so \
             every sign-in with no rd would fall back to the sign-in page"
    );
}

/// §13.32 §1: the sign-in path and the deletion notice's code live in the library because
/// **two programs write one URL**. `bb-auth-web` builds the logout's `rd` out of both, and
/// the gate's sign-in page reads the code back out of the query string it lands in. A
/// constant in each program is two strings that have to agree by eye, and the way they
/// disagree is silent: every browser is sent to a page that shows no notice, and the
/// deletion flow's only explanation of itself never appears. So the pair is pinned to the
/// exact bytes §13.32 spells, and the gate's test module reads them from here.
#[test]
fn the_gate_login_path_and_the_notice_code_are_the_librarys() {
    assert_eq!(GATE_LOGIN_PATH, "/auth/login");
    assert_eq!(LOGIN_NOTICE_ACCOUNT_DELETED, "account-deleted");
}
