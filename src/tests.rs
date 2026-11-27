use super::*;

#[test]
fn sha256_hex_known_vector() {
    // canonical SHA-256("abc")
    assert_eq!(
        sha256_hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn mint_api_key_is_namespaced_and_hashed() {
    let (raw, hash) = mint_api_key().unwrap();
    assert!(raw.starts_with(API_KEY_PREFIX));
    assert_eq!(hash, sha256_hex(&raw)); // the file stores only this half
    assert_eq!(hash.len(), 64);
    // A bearer must survive a header, a shell and a JSON string untouched.
    assert!(raw.bytes().all(|b| b.is_ascii_graphic()));
    assert!(!raw.contains(':') && !raw.contains('='));
    // 256 bits of entropy: two mints never collide.
    assert_ne!(raw, mint_api_key().unwrap().0);
}

#[test]
fn parse_date_epoch_basic() {
    assert_eq!(parse_date_epoch("1970-01-01"), Some(0));
    assert_eq!(parse_date_epoch("1970-01-02"), Some(86_400));
    assert_eq!(parse_date_epoch("1972-01-01"), Some(730 * 86_400)); // 1970+1971 = 365*2
    assert!(parse_date_epoch("2026-07-08").is_some());
    assert_eq!(parse_date_epoch("2026-13-01"), None); // bad month
    assert_eq!(parse_date_epoch("2026-07-40"), None); // bad day
    assert_eq!(parse_date_epoch("notadate"), None);
    assert_eq!(parse_date_epoch("1969-12-31"), None); // before epoch
}

#[test]
fn format_date_inverts_parse_date_epoch() {
    for d in ["1970-01-01", "2000-02-29", "2026-07-14", "2099-12-31"] {
        assert_eq!(format_date(parse_date_epoch(d).unwrap()), d);
    }
    // mid-day epochs floor to their date
    assert_eq!(format_date(86_400 + 3_600), "1970-01-02");
}

#[test]
fn parse_duration_variants() {
    assert!(matches!(parse_duration("never"), Some(Dur::Never)));
    assert!(matches!(parse_duration("0"), Some(Dur::Never)));
    assert!(matches!(parse_duration("-"), Some(Dur::Never)));
    assert!(matches!(parse_duration(""), Some(Dur::Never)));
    assert!(matches!(parse_duration("365d"), Some(Dur::Secs(s)) if s == 365 * 86_400));
    assert!(matches!(parse_duration("24h"), Some(Dur::Secs(s)) if s == 24 * 3_600));
    assert!(matches!(parse_duration("7"), Some(Dur::Secs(s)) if s == 7 * 86_400)); // bare = days
    assert!(parse_duration("abc").is_none());
    assert!(parse_duration("10x").is_none());
}

#[test]
fn key_expiry_computes() {
    assert_eq!(key_expiry("2026-01-01", "never"), Some(None));
    assert_eq!(key_expiry("1970-01-01", "1d"), Some(Some(86_400)));
    assert_eq!(key_expiry("1970-01-01", "0"), Some(None)); // 0 = never (date ignored)
    assert_eq!(key_expiry("bad", "1d"), None); // bad date with finite duration
    assert_eq!(key_expiry("2026-01-01", "xyz"), None); // bad duration
}

/// Compile one pattern and match `url` against it.
fn m(pat: &str, url: &str) -> bool {
    compile_pattern(pat).expect("pattern compiles").matches(url)
}

#[test]
fn glob_terminal_star_includes_slash() {
    // `https://pippo/path1/*` => everything under path1, at any depth …
    assert!(m("https://pippo/path1/*", "https://pippo/path1/"));
    assert!(m("https://pippo/path1/*", "https://pippo/path1/a"));
    assert!(m("https://pippo/path1/*", "https://pippo/path1/a/b/c.png"));
    // … but not the bare parent, and not a sibling
    assert!(!m("https://pippo/path1/*", "https://pippo/path1"));
    assert!(!m("https://pippo/path1/*", "https://pippo/path2/a"));
    // the classic prefix footgun, now closed: /mcp/* does not match /mcpEVIL
    assert!(!m("https://pippo/mcp/*", "https://pippo/mcpEVIL"));
}

#[test]
fn glob_nonterminal_star_no_slash() {
    // `…/path1/*/` => exactly one level below path1, trailing slash required
    assert!(m("https://pippo/path1/*/", "https://pippo/path1/a/"));
    assert!(m("https://pippo/path1/*/", "https://pippo/path1/ab/"));
    assert!(!m("https://pippo/path1/*/", "https://pippo/path1/a"));
    assert!(!m("https://pippo/path1/*/", "https://pippo/path1/a/b/"));
}

#[test]
fn glob_middle_star_segment() {
    // one wildcard level, then a fixed subtree, then anything
    let p = "https://pippo/path1/*/images/*";
    assert!(m(p, "https://pippo/path1/a/images/x.png"));
    assert!(m(p, "https://pippo/path1/a/images/sub/y.png"));
    assert!(!m(p, "https://pippo/path1/a/b/images/x.png")); // star can't cross '/'
    assert!(!m(p, "https://pippo/path1/a/other/x.png"));
}

#[test]
fn glob_single_char_amp() {
    assert!(m("https://pippo/v&/*", "https://pippo/v1/x"));
    assert!(m("https://pippo/v&/*", "https://pippo/v9/x"));
    assert!(!m("https://pippo/v&/*", "https://pippo/v10/x")); // one char, not two
    assert!(!m("https://pippo/v&/*", "https://pippo/v/x")); // one char, not zero
}

#[test]
fn glob_wildcard_in_scheme_and_host() {
    // scheme wildcard
    assert!(m("*://mcp.x.com/mcp/*", "https://mcp.x.com/mcp/a"));
    assert!(m("*://mcp.x.com/mcp/*", "http://mcp.x.com/mcp/a"));
    // host wildcard: `*` stops at '/', so it can never spill into the path
    assert!(m("https://*/mcp/*", "https://anything.x.com/mcp/a"));
    assert!(!m("https://*/mcp/*", "https://x.com/other/a"));
    // subdomain wildcard — note `*` crosses dots, so it also spans two labels
    assert!(m("https://*.x.com/*", "https://mcp.x.com/a"));
    assert!(m("https://*.x.com/*", "https://a.b.x.com/a"));
    // suffix lookalikes do not match
    assert!(!m("https://*.x.com/*", "https://evil-x.com/a"));
    assert!(!m("https://*.x.com/*", "https://x.com.evil.net/a"));
    // single-char host wildcard
    assert!(m("https://v&.x.com/*", "https://v1.x.com/a"));
    assert!(!m("https://v&.x.com/*", "https://v10.x.com/a"));
}

#[test]
fn glob_authority_case_insensitive_path_sensitive() {
    let p = compile_pattern("HTTPS://MCP.X.COM/Mcp/*").unwrap();
    // authority lowercased at compile time and at request time
    assert!(p.matches("https://mcp.x.com/Mcp/a"));
    // the path keeps its case on both sides
    assert!(!p.matches("https://mcp.x.com/mcp/a"));
    assert_eq!(
        lower_authority("HTTPS://Host.COM/Path/A"),
        "https://host.com/Path/A"
    );
    assert_eq!(lower_authority("HTTPS://Host.COM"), "https://host.com");
}

#[test]
fn compile_pattern_rejects_malformed() {
    assert!(compile_pattern("mcp.x.com/mcp").is_err()); // no scheme
    assert!(compile_pattern("https://mcp.x.com").is_err()); // no path
    assert!(compile_pattern("https:///mcp").is_err()); // empty host
    assert!(compile_pattern("://mcp.x.com/a").is_err()); // empty scheme
    assert!(compile_pattern("https://u@mcp.x.com/a").is_err()); // userinfo
    assert!(compile_pattern("https://mcp.x.com/../a").is_err()); // traversal
    assert!(compile_pattern("https://mcp.x.com/a\rb").is_err()); // control byte
    assert!(compile_pattern("https://mcp.x.com/*").is_ok());
}

#[test]
fn glob_many_stars_terminates() {
    // The classic exponential case for a recursive star-backtracker: many stars,
    // a long input, and a final byte that can never match. The DP is O(n*m).
    let pat = format!("https://h/{}", "*a".repeat(24));
    let url = format!("https://h/{}b", "a".repeat(400));
    let p = compile_pattern(&pat).unwrap();
    let t = std::time::Instant::now();
    assert!(!p.matches(&url)); // pattern ends in 'a', input in 'b'
                               // The assertion above is not the test: a backtracker would *also* return false here,
                               // eventually, and "eventually" is the regression. Without a clock, a return to
                               // exponential matching is a `cargo test` that hangs, which reads as a broken machine
                               // rather than a broken matcher. The DP does this in microseconds, so a second is
                               // three orders of magnitude of headroom and is not a timing-sensitive test.
    assert!(
        t.elapsed() < std::time::Duration::from_secs(1),
        "matching took {:?}: the matcher is backtracking again",
        t.elapsed()
    );
}

#[test]
fn url_scope_empty_denies_everything() {
    // No patterns => no access. Both the absent list and an explicit `[]`.
    for s in [UrlScope::deny_all(), UrlScope::compile(&[]).unwrap()] {
        assert!(s.is_empty());
        assert!(!s.allows(Some("https://x/a")));
        assert!(!s.allows(None));
    }
    // whitespace-only entries are dropped, and drop to deny-all
    assert!(UrlScope::compile(&["  ".to_string()]).unwrap().is_empty());
}

#[test]
fn url_scope_star_pattern_grants_everything() {
    // Blanket access is spelled out, never implied.
    let s = UrlScope::compile(&["*://*/*".to_string()]).unwrap();
    assert!(s.allows(Some("https://anything.example.com/at/all")));
    assert!(s.allows(Some("http://h/")));
    assert!(s.allows(Some("https://h/a/b/c.png")));
    assert!(!s.allows(None)); // the header is still mandatory
    assert!(!s.allows(Some("https://h/../etc"))); // and `..` still denied

    // A bare "*" is NOT a sentinel: it is a malformed pattern, and the error points
    // at the spelling that works.
    let err = match compile_pattern("*") {
        Ok(_) => panic!("a bare '*' must not compile"),
        Err(e) => e,
    };
    assert!(err.contains("*://*/*"), "{err}");
}

#[test]
fn url_scope_matching() {
    let s = UrlScope::compile(&[
        "https://mcp.x.com/mcp".to_string(),
        "https://mcp.x.com/mcp/*".to_string(),
    ])
    .unwrap();
    assert!(s.allows(Some("https://mcp.x.com/mcp")));
    assert!(s.allows(Some("https://mcp.x.com/mcp/tools")));
    assert!(!s.allows(Some("https://mcp.x.com/mcpEVIL")));
    assert!(!s.allows(Some("https://search.x.com/mcp/tools"))); // wrong host
    assert!(!s.allows(Some("http://mcp.x.com/mcp"))); // wrong scheme
    assert!(!s.allows(None)); // restricted + missing header => fail closed
    assert!(!s.allows(Some("https://mcp.x.com/mcp/../etc"))); // traversal rejected
}

#[test]
fn compile_host_pattern_rejects_non_hosts() {
    assert!(compile_host_pattern("").is_err());
    assert!(compile_host_pattern("https://x.com").is_err()); // scheme
    assert!(compile_host_pattern("x.com/path").is_err()); // path
    assert!(compile_host_pattern("x.com:8443").is_err()); // port
    assert!(compile_host_pattern("u@x.com").is_err()); // userinfo
    assert!(compile_host_pattern("a..b").is_err());
    assert!(compile_host_pattern("*.badbat75.com").is_ok());
    assert!(compile_host_pattern("v&.badbat75.com").is_ok());
    // normalised to lowercase
    assert_eq!(compile_host_pattern("X.COM").unwrap().as_bytes(), b"x.com");
}

#[test]
fn compile_login_url_rejects_unsafe_targets() {
    assert!(compile_login_url("https://login.x.com/").is_ok());
    assert_eq!(
        compile_login_url("  https://login.x.com/?a=1  ").unwrap(),
        "https://login.x.com/?a=1" // trimmed
    );

    assert!(compile_login_url("").is_err());
    assert!(compile_login_url("http://login.x.com/").is_err()); // https only
    assert!(compile_login_url("/relative").is_err());
    assert!(compile_login_url("https://").is_err()); // empty host
    assert!(compile_login_url("https:///nohost").is_err());
    assert!(compile_login_url("https://user@evil.com/").is_err()); // userinfo
    assert!(compile_login_url("https://login.x.com\\@evil.com/").is_err()); // backslash
                                                                            // these are the reason the check exists: they reach a header and a redirect
    assert!(compile_login_url("https://x.com/\r\nSet-Cookie: a=1").is_err());
    assert!(compile_login_url("https://x.com/ b").is_err()); // space
    assert!(compile_login_url("https://xé.com/").is_err()); // non-ascii => h() would panic
}

#[test]
fn header_safe_email_rejects_injection_and_non_ascii() {
    assert!(header_safe_email("alice@example.com"));
    assert!(header_safe_email("a+tag@sub.example.co.uk"));

    assert!(!header_safe_email("")); // respond_authorized asserts on this
    assert!(!header_safe_email("bad\r\nX-Admin: 1@x.com")); // response splitting
    assert!(!header_safe_email("nul\0@x.com"));
    assert!(!header_safe_email("has space@x.com"));
    // to_ascii_lowercase() leaves these bytes intact, so the load-time guard is the
    // only thing keeping them out of a header value.
    assert!(!header_safe_email("béatrice@x.com"));
}

// --- the access file ----------------------------------------------------

/// Write `json` to a uniquely-named temp file so tests can run in parallel.
pub(crate) fn users_tmp(name: &str, json: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("bb-auth-core-{name}.json"));
    std::fs::write(&p, json).unwrap();
    p
}

/// Parse `json` as an access file, through the real parser and a real temp file.
fn access_of(name: &str, json: &str) -> Access {
    let tmp = users_tmp(name, json);
    let a = read_access(tmp.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_file(&tmp);
    a
}

/// The message the gate would refuse `json` with. Matched rather than unwrapped,
/// because [`Access`] has no `Debug` on purpose.
fn access_err(name: &str, json: &str) -> String {
    let tmp = users_tmp(name, json);
    let r = read_access(tmp.to_str().unwrap());
    let _ = std::fs::remove_file(&tmp);
    match r {
        Ok(_) => panic!("{name}: expected the gate to refuse this file"),
        Err(e) => e,
    }
}

fn doc_of(json: &str) -> AccessFile {
    serde_json::from_str(json).expect("fixture parses")
}

fn err_of<T>(r: Result<T, String>) -> String {
    match r {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    }
}

const BOB: &str = "11111111-1111-4111-8111-111111111111";
const CAROL: &str = "22222222-2222-4222-8222-222222222222";
const BEARER: &str = "bbk_testkeytestkeytestkey";

/// Two applications, every access kind, a carve-out that only works because scopes
/// are first match wins, and a key narrower than its owner.
fn fixture() -> String {
    r#"{
          "version": 1,
          "applications": [
            { "name": "mpa",
              "base": ["https://app.x.com/mpa"],
              "login_url": "https://signup.x.com/",
              "denied_url": "https://app.x.com/mpa-denied",
              "scopes": [
                { "name": "healthz", "urls": ["https://app.x.com/mpa/healthz"],
                  "access": "anonymous" },
                { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"],
                  "access": "restricted", "groups": ["@admins"], "credentials": ["login"] },
                { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
                  "access": "authenticated" } ] },
            { "name": "mcp",
              "base": ["https://ai.x.com/mcp"],
              "scopes": [
                { "name": "logs", "urls": ["https://ai.x.com/mcp/logs/*"],
                  "access": "restricted", "users": ["BOBUUID"] },
                { "name": "api", "urls": ["https://ai.x.com/mcp/*"],
                  "access": "restricted", "users": ["BOBUUID"],
                  "credentials": ["api_key"] } ] } ],
          "user_groups": { "admins": ["BOBUUID"] },
          "denied": ["spammer@x.com"],
          "users": [
            { "uuid": "BOBUUID", "emails": ["bob@x.com", "bob@old.com"],
              "api_keys": [ { "id": "laptop", "key_hash": "KEYHASH",
                              "released": "2026-01-01", "duration": "never",
                              "scopes": ["mcp/api"] } ] },
            { "uuid": "CAROLUUID", "emails": ["carol@x.com"] } ] }"#
        .replace("BOBUUID", BOB)
        .replace("CAROLUUID", CAROL)
        .replace("KEYHASH", &sha256_hex(BEARER))
}

fn fixture_key(a: &Access) -> &ApiKeyRecord {
    match decide_api_key(a, &sha256_hex(BEARER), 1_000) {
        KeyDecision::Granted(r) => r,
        _ => panic!("the fixture key must resolve"),
    }
}

// --- the URL partition --------------------------------------------------

#[test]
fn base_covers_stops_at_a_path_boundary() {
    assert!(base_covers("https://x.com/app", "https://x.com/app"));
    assert!(base_covers(
        "https://x.com/app",
        "https://x.com/app/deep/er"
    ));
    // The whole reason this is not a `starts_with`: two different areas.
    assert!(!base_covers(
        "https://x.com/app",
        "https://x.com/application"
    ));
    assert!(!base_covers("https://x.com/app", "https://x.com/ap"));
    // A base already ending in `/` needs no boundary of its own.
    assert!(base_covers("https://x.com/", "https://x.com/anything"));
    // Host boundaries are the same rule.
    assert!(!base_covers("https://x.com", "https://x.commerce.com/"));
}

#[test]
fn application_areas_may_not_overlap() {
    let e = access_err(
        "overlap",
        r#"{ "version": 1, "applications": [
                 { "name": "a", "base": ["https://x.com/app"], "scopes": [] },
                 { "name": "b", "base": ["https://x.com/app/inner"], "scopes": [] } ] }"#,
    );
    assert!(e.contains("overlaps"), "{e}");
    assert!(
        e.contains("'a'"),
        "the message must name the other application: {e}"
    );

    // Neighbours that merely share a prefix are fine, which is the boundary rule
    // doing its job.
    let a = access_of(
        "no-overlap",
        r#"{ "version": 1, "applications": [
                 { "name": "a", "base": ["https://x.com/app"], "scopes": [] },
                 { "name": "b", "base": ["https://x.com/application"], "scopes": [] } ] }"#,
    );
    assert_eq!(a.apps.len(), 2);
}

#[test]
fn a_base_must_be_literal() {
    for bad in [
        "https://*.x.com/",
        "https://x.com/a&b",
        "https://x.com/../etc",
        "x.com/app",
    ] {
        let json = format!(
            r#"{{ "version": 1, "applications": [
                     {{ "name": "a", "base": ["{bad}"], "scopes": [] }} ] }}"#
        );
        let e = access_err("bad-base", &json);
        assert!(e.contains("base"), "{bad}: {e}");
    }
}

#[test]
fn a_scope_may_not_reach_outside_its_application() {
    let e = access_err(
        "outside",
        r#"{ "version": 1, "applications": [
                 { "name": "a", "base": ["https://x.com/app"],
                   "scopes": [ { "name": "s", "urls": ["https://x.com/other/*"],
                                 "access": "authenticated" } ] } ] }"#,
    );
    assert!(e.contains("outside this application's base"), "{e}");
    assert!(e.contains("a/s"), "the message must name the scope: {e}");
}

#[test]
fn an_application_needs_a_base() {
    let e = access_err(
        "no-base",
        r#"{ "version": 1, "applications": [ { "name": "a", "scopes": [] } ] }"#,
    );
    assert!(e.contains("no base"), "{e}");
}

// --- resolution ---------------------------------------------------------

#[test]
fn scopes_resolve_first_match_wins() {
    let a = access_of("first-match", &fixture());
    // The carve-out answers, even though the broad scope after it also covers this.
    let (app, s) = a.resolve(Some("https://ai.x.com/mcp/logs/today")).unwrap();
    assert_eq!((app.name.as_str(), s.name.as_str()), ("mcp", "logs"));
    let (_, s) = a.resolve(Some("https://ai.x.com/mcp/tool")).unwrap();
    assert_eq!(s.name, "api");
}

#[test]
fn reordering_scopes_changes_who_answers() {
    // The same two scopes, broad one first: the carve-out is now unreachable. Order
    // is meaning, which is why an editor lints it and offers a move.
    let a = access_of(
        "shadowed",
        r#"{ "version": 1, "applications": [
                 { "name": "mcp", "base": ["https://ai.x.com/mcp"], "scopes": [
                   { "name": "api", "urls": ["https://ai.x.com/mcp/*"],
                     "access": "authenticated" },
                   { "name": "logs", "urls": ["https://ai.x.com/mcp/logs/*"],
                     "access": "anonymous" } ] } ] }"#,
    );
    let (_, s) = a.resolve(Some("https://ai.x.com/mcp/logs/today")).unwrap();
    assert_eq!(s.name, "api", "the broad scope listed first answers");
}

#[test]
fn resolution_rejects_a_missing_url_and_traversal() {
    let a = access_of("traversal", &fixture());
    assert!(a.resolve(None).is_none());
    assert!(a.app_for(None).is_none());
    assert!(a
        .resolve(Some("https://app.x.com/mpa/../mpa/healthz"))
        .is_none());
    assert_eq!(
        decide(&a, &Subject::Anonymous, None),
        Decision::NoApplication
    );
}

// --- the ten decisions --------------------------------------------------

#[test]
fn anonymous_scope_grants_with_no_credential() {
    let a = access_of("anon", &fixture());
    let d = decide(
        &a,
        &Subject::Anonymous,
        Some("https://app.x.com/mpa/healthz"),
    );
    assert_eq!(
        d,
        Decision::Anonymous {
            app: "mpa".into(),
            scope: "healthz".into()
        }
    );
    assert!(d.granted());
}

#[test]
fn anonymous_grants_ahead_of_the_veto() {
    // Not an oversight: the scope grants with no credential at all, so a vetoed
    // client would simply omit theirs. A veto bypassed by sending less is not a veto.
    let a = access_of("anon-veto", &fixture());
    let d = decide(
        &a,
        &Subject::Identifier("spammer@x.com"),
        Some("https://app.x.com/mpa/healthz"),
    );
    assert!(d.granted(), "{d:?}");
}

#[test]
fn authenticated_scope_grants_an_unenrolled_identity() {
    let a = access_of("authn", &fixture());
    assert!(a.uuid_of("newcomer@x.com").is_none());
    let d = decide(
        &a,
        &Subject::Identifier("newcomer@x.com"),
        Some("https://app.x.com/mpa/welcome"),
    );
    assert_eq!(
        d,
        Decision::Granted {
            app: "mpa".into(),
            scope: "onboarding".into()
        }
    );
}

#[test]
fn authenticated_scope_never_admits_a_key() {
    let a = access_of("authn-key", &fixture());
    let k = fixture_key(&a);
    let d = decide(&a, &Subject::Key(k), Some("https://app.x.com/mpa/welcome"));
    assert!(matches!(d, Decision::CredentialRefused { .. }), "{d:?}");
}

#[test]
fn restricted_scope_grants_a_member_and_refuses_everyone_else() {
    let a = access_of("restricted", &fixture());
    let url = Some("https://app.x.com/mpa/admin/panel");
    assert!(decide(&a, &Subject::Identifier("bob@x.com"), url).granted());
    // Carol is enrolled but not in @admins.
    assert!(matches!(
        decide(&a, &Subject::Identifier("carol@x.com"), url),
        Decision::NotMember { .. }
    ));
    // A stranger is in no roster row at all.
    assert!(matches!(
        decide(&a, &Subject::Identifier("nobody@x.com"), url),
        Decision::NotEnrolled { .. }
    ));
    // And no credential means no identity to check.
    assert!(matches!(
        decide(&a, &Subject::Anonymous, url),
        Decision::Unauthenticated { .. }
    ));
}

#[test]
fn the_credential_class_is_a_property_of_the_place() {
    let a = access_of("classes", &fixture());
    let k = fixture_key(&a);
    // mcp/api admits api_key only, mpa/admin admits login only. The same member, both
    // times, and the scope is what differs.
    assert!(matches!(
        decide(
            &a,
            &Subject::Identifier("bob@x.com"),
            Some("https://ai.x.com/mcp/tool")
        ),
        Decision::CredentialRefused { .. }
    ));
    assert!(decide(&a, &Subject::Key(k), Some("https://ai.x.com/mcp/tool")).granted());
    assert!(matches!(
        decide(
            &a,
            &Subject::Key(k),
            Some("https://app.x.com/mpa/admin/panel")
        ),
        Decision::CredentialRefused { .. }
    ));
}

#[test]
fn a_key_restriction_subtracts_from_its_owner() {
    let a = access_of("key-scope", &fixture());
    let k = fixture_key(&a);
    // Bob reaches mcp/logs; his key does not, because it named only mcp/api.
    assert!(decide(
        &a,
        &Subject::Identifier("bob@x.com"),
        Some("https://ai.x.com/mcp/logs/x")
    )
    .granted());
    assert!(matches!(
        decide(&a, &Subject::Key(k), Some("https://ai.x.com/mcp/logs/x")),
        Decision::KeyOutOfScope { .. }
    ));
}

#[test]
fn a_key_with_no_restriction_reaches_what_its_owner_reaches() {
    let json = fixture().replace(r#""scopes": ["mcp/api"]"#, r#""notes": "unrestricted""#);
    let a = access_of("key-unrestricted", &json);
    let k = fixture_key(&a);
    assert!(decide(&a, &Subject::Key(k), Some("https://ai.x.com/mcp/logs/x")).granted());
}

#[test]
fn nothing_outside_an_application_is_reachable() {
    let a = access_of("no-app", &fixture());
    for url in [
        "https://elsewhere.com/",
        // Boundary again: a neighbouring path is not inside the area.
        "https://app.x.com/mpa-extra/thing",
    ] {
        assert_eq!(
            decide(&a, &Subject::Identifier("bob@x.com"), Some(url)),
            Decision::NoApplication,
            "{url}"
        );
    }
}

#[test]
fn an_application_with_no_scope_for_the_url_says_so() {
    let a = access_of("no-scope", &fixture());
    // Inside mpa's area, but /mpa/* does not match the bare /mpa.
    assert_eq!(
        decide(
            &a,
            &Subject::Identifier("bob@x.com"),
            Some("https://app.x.com/mpa")
        ),
        Decision::NoScope { app: "mpa".into() }
    );
}

// --- the veto -----------------------------------------------------------

#[test]
fn denied_vetoes_a_stranger_by_email() {
    let a = access_of("veto-stranger", &fixture());
    assert!(a.denied_identifiers.contains("spammer@x.com"));
    assert_eq!(
        decide(
            &a,
            &Subject::Identifier("spammer@x.com"),
            Some("https://app.x.com/mpa/welcome")
        ),
        Decision::Vetoed
    );
}

#[test]
fn denying_one_email_vetoes_the_whole_user() {
    // Written as an email, folded onto the uuid at load: the other identifier, the
    // group membership and the key all go with it.
    let a = access_of(
        "veto-fold",
        &fixture().replace(
            r#""denied": ["spammer@x.com"]"#,
            r#""denied": ["bob@old.com"]"#,
        ),
    );
    assert!(a.denied_users.contains(BOB));
    for url in [
        "https://app.x.com/mpa/admin/panel",
        "https://ai.x.com/mcp/logs/x",
    ] {
        assert_eq!(
            decide(&a, &Subject::Identifier("bob@x.com"), Some(url)),
            Decision::Vetoed,
            "{url}"
        );
    }
    // And the key it owns, on the path that never sees a token.
    assert!(matches!(
        decide_api_key(&a, &sha256_hex(BEARER), 1_000),
        KeyDecision::OwnerDenied(_)
    ));
}

#[test]
fn a_denied_entry_must_be_a_uuid_or_an_email() {
    let e = access_err(
        "veto-junk",
        r#"{ "version": 1, "denied": ["11111111-1111-4111-8111-11111111111"] }"#,
    );
    assert!(e.contains("not a uuid and not an email"), "{e}");
}

// --- the scope's own veto ------------------------------------------------

/// The fixture with `excluded` on the scopes named, so each test below says only what
/// it is about.
fn with_exclusion(scope_urls: &str, excluded: &str) -> String {
    fixture().replace(
        &format!(r#""urls": ["{scope_urls}"],"#),
        &format!(r#""urls": ["{scope_urls}"], "excluded": [{excluded}],"#),
    )
}

#[test]
fn an_exclusion_beats_the_group_that_admits() {
    // bob reaches mpa/admin only through @admins. Excluded by uuid, the scope refuses
    // him without the group being touched — which is the whole reason the field exists.
    let a = access_of(
        "excl-group",
        &with_exclusion("https://app.x.com/mpa/admin/*", &format!("\"{BOB}\"")),
    );
    assert_eq!(
        decide(
            &a,
            &Subject::Identifier("bob@x.com"),
            Some("https://app.x.com/mpa/admin/panel")
        ),
        Decision::Excluded {
            app: "mpa".into(),
            scope: "admin".into()
        }
    );
    // Local, not global: the next application still admits him.
    assert!(decide(
        &a,
        &Subject::Identifier("bob@x.com"),
        Some("https://ai.x.com/mcp/logs/x")
    )
    .granted());
}

#[test]
fn an_exclusion_beats_authenticated_and_reaches_a_stranger() {
    // The kind that lists nobody, so there is nobody to remove: an exclusion is the
    // only way to keep one identity out, and a stranger is named by email because the
    // roster has never heard of them.
    let a = access_of(
        "excl-auth",
        &with_exclusion("https://app.x.com/mpa/*", "\"newcomer@x.com\""),
    );
    assert_eq!(
        decide(
            &a,
            &Subject::Identifier("newcomer@x.com"),
            Some("https://app.x.com/mpa/welcome")
        ),
        Decision::Excluded {
            app: "mpa".into(),
            scope: "onboarding".into()
        }
    );
    // Anybody else Cognito vouches for still walks in.
    assert!(decide(
        &a,
        &Subject::Identifier("someone@x.com"),
        Some("https://app.x.com/mpa/welcome")
    )
    .granted());
}

#[test]
fn excluding_one_email_excludes_the_whole_user() {
    // Folded onto the uuid at load, exactly as `denied` is: excluding one address of a
    // user cannot leave another standing.
    let a = access_of(
        "excl-fold",
        &with_exclusion("https://app.x.com/mpa/*", "\"bob@old.com\""),
    );
    assert!(a.apps[0].scopes[2].excluded_users.contains(BOB));
    assert_eq!(
        decide(
            &a,
            &Subject::Identifier("bob@x.com"),
            Some("https://app.x.com/mpa/welcome")
        ),
        Decision::Excluded {
            app: "mpa".into(),
            scope: "onboarding".into()
        }
    );
}

#[test]
fn an_exclusion_stops_a_key_through_its_owner() {
    // A key acts as its owner, so it is kept out by what keeps its owner out.
    let a = access_of(
        "excl-key",
        &with_exclusion("https://ai.x.com/mcp/*", &format!("\"{BOB}\"")),
    );
    let key = fixture_key(&a);
    assert_eq!(
        decide(&a, &Subject::Key(key), Some("https://ai.x.com/mcp/tool")),
        Decision::Excluded {
            app: "mcp".into(),
            scope: "api".into()
        }
    );
}

#[test]
fn a_group_may_be_excluded() {
    let a = access_of(
        "excl-groupref",
        &with_exclusion("https://app.x.com/mpa/*", "\"@admins\""),
    );
    assert!(a.apps[0].scopes[2].excluded_users.contains(BOB));
}

#[test]
fn denied_outranks_an_exclusion() {
    // Both would refuse, and the file-level veto is what must be reported: an operator
    // reading a log has to be told the identity is out everywhere, not just here.
    let a = access_of(
        "excl-vs-denied",
        &with_exclusion("https://app.x.com/mpa/*", "\"spammer@x.com\""),
    );
    assert_eq!(
        decide(
            &a,
            &Subject::Identifier("spammer@x.com"),
            Some("https://app.x.com/mpa/welcome")
        ),
        Decision::Vetoed
    );
}

#[test]
fn an_anonymous_scope_refuses_an_exclusion() {
    let e = access_err(
        "excl-anon",
        &with_exclusion("https://app.x.com/mpa/healthz", "\"bob@x.com\""),
    );
    assert!(e.contains("'excluded' means nothing"), "{e}");
    assert!(
        e.contains("no credential at all"),
        "the message must say WHY: {e}"
    );
}

#[test]
fn an_exclusion_must_be_a_uuid_a_group_or_an_email() {
    let e = access_err(
        "excl-junk",
        &with_exclusion("https://app.x.com/mpa/*", "\"nonsense\""),
    );
    assert!(
        e.contains("not a uuid, not '@group' and not an email"),
        "{e}"
    );

    // An unknown group is fatal here for the same reason it is in `groups`: it is a
    // typo that would silently protect nothing.
    let e = access_err(
        "excl-badgroup",
        &with_exclusion("https://app.x.com/mpa/*", "\"@nope\""),
    );
    assert!(e.contains("unknown user group '@nope'"), "{e}");
}

// --- keys ---------------------------------------------------------------

#[test]
fn an_unknown_key_is_nobody() {
    let a = access_of("key-unknown", &fixture());
    assert!(matches!(
        decide_api_key(&a, &sha256_hex("bbk_nope"), 1_000),
        KeyDecision::Unknown
    ));
}

#[test]
fn an_expired_key_is_refused_before_any_url() {
    let a = access_of(
        "key-expired",
        &fixture().replace(r#""duration": "never""#, r#""duration": "1d""#),
    );
    let released = parse_date_epoch("2026-01-01").unwrap();
    assert!(matches!(
        decide_api_key(&a, &sha256_hex(BEARER), released + 86_401),
        KeyDecision::Expired(_)
    ));
    assert!(decide_api_key(&a, &sha256_hex(BEARER), released + 3_600).granted());
}

#[test]
fn a_key_restriction_naming_no_scope_is_fatal() {
    let e = access_err(
        "key-bad-scope",
        &fixture().replace(r#""scopes": ["mcp/api"]"#, r#""scopes": ["mcp/apy"]"#),
    );
    assert!(e.contains("names no scope"), "{e}");
}

#[test]
fn a_bad_key_hash_only_skips_that_key() {
    let a = access_of(
        "key-bad-hash",
        &fixture().replace(&sha256_hex(BEARER), "not-a-hash"),
    );
    assert!(a.by_key_hash.is_empty());
    // The roster it hangs off is untouched: one bad key must not drop a user.
    assert!(a.by_uuid.contains_key(BOB));
}

// --- the roster ---------------------------------------------------------

#[test]
fn identifiers_resolve_many_to_one() {
    let a = access_of("identifiers", &fixture());
    assert_eq!(a.uuid_of("bob@x.com"), Some(BOB));
    assert_eq!(
        a.uuid_of("BOB@OLD.COM"),
        Some(BOB),
        "matched case-insensitively"
    );
    assert_eq!(a.by_uuid[BOB].emails, vec!["bob@x.com", "bob@old.com"]);
}

#[test]
fn two_users_may_not_share_an_identifier() {
    let e = access_err(
        "dup-email",
        &fixture().replace(r#""emails": ["carol@x.com"]"#, r#""emails": ["bob@x.com"]"#),
    );
    assert!(e.contains("declared by two users"), "{e}");
}

#[test]
fn two_users_may_not_share_a_uuid() {
    let e = access_err("dup-uuid", &fixture().replace(CAROL, BOB));
    assert!(e.contains("declared by two users entries"), "{e}");
}

#[test]
fn a_malformed_uuid_is_fatal_wherever_it_appears() {
    for (what, json) in [
        (
            "roster",
            r#"{ "version": 1, "users": [ { "uuid": "nope", "emails": ["a@x.com"] } ] }"#,
        ),
        (
            "group",
            r#"{ "version": 1, "user_groups": { "g": ["nope"] } }"#,
        ),
        (
            "scope",
            r#"{ "version": 1, "applications": [ { "name": "a",
                     "base": ["https://x.com/a"], "scopes": [ { "name": "s",
                       "urls": ["https://x.com/a/*"], "access": "restricted",
                       "users": ["nope"] } ] } ] }"#,
        ),
    ] {
        let e = access_err("bad-uuid", json);
        assert!(e.contains("not a uuid"), "{what}: {e}");
    }
}

#[test]
fn an_email_that_could_not_be_a_header_is_skipped_not_fatal() {
    let a = access_of(
        "unsafe-email",
        &fixture().replace(r#""carol@x.com""#, r#""carol@x.com\r\nX-Admin: yes""#),
    );
    assert!(a.uuid_of("carol@x.com").is_none());
    assert!(a.by_uuid.contains_key(CAROL), "the row survives");
}

// --- user groups --------------------------------------------------------

#[test]
fn a_group_expands_once_and_nothing_downstream_sees_it() {
    let a = access_of("groups", &fixture());
    let (_, admin) = a.resolve(Some("https://app.x.com/mpa/admin/x")).unwrap();
    assert!(admin.members.contains(BOB));
}

#[test]
fn an_unknown_group_is_fatal_and_names_the_referrer() {
    let e = access_err("group-unknown", &fixture().replace("@admins", "@nope"));
    assert!(e.contains("unknown user group '@nope'"), "{e}");
    assert!(e.contains("mpa/admin"), "{e}");
}

#[test]
fn a_group_may_not_reference_a_group() {
    let e = access_err(
        "group-nested",
        r#"{ "version": 1, "user_groups": { "a": ["@b"], "b": [] } }"#,
    );
    assert!(e.contains("cannot reference another group"), "{e}");
}

#[test]
fn a_group_is_validated_even_when_nothing_references_it() {
    // A group that only breaks the day someone first uses it is a trap
    // `--check-access` never saw.
    let e = access_err(
        "group-unused",
        r#"{ "version": 1, "user_groups": { "unused": ["not-a-uuid"] } }"#,
    );
    assert!(e.contains("not a uuid"), "{e}");
}

#[test]
fn a_dangling_reference_grants_nothing() {
    let a = access_of(
        "dangling",
        r#"{ "version": 1,
                 "applications": [ { "name": "a", "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"], "access": "restricted",
                     "users": ["33333333-3333-4333-8333-333333333333"] } ] } ],
                 "users": [ { "uuid": "11111111-1111-4111-8111-111111111111",
                              "emails": ["bob@x.com"] } ] }"#,
    );
    assert!(matches!(
        decide(
            &a,
            &Subject::Identifier("bob@x.com"),
            Some("https://x.com/a/thing")
        ),
        Decision::NotMember { .. }
    ));
}

// --- the access word ----------------------------------------------------

#[test]
fn access_is_required_and_has_no_default() {
    let e = access_err(
        "no-access",
        r#"{ "version": 1, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"] } ] } ] }"#,
    );
    assert!(e.contains("'access' is required"), "{e}");

    let e = access_err(
        "bad-access",
        r#"{ "version": 1, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"],
                     "access": "anonimous" } ] } ] }"#,
    );
    assert!(e.contains("unknown access 'anonimous'"), "{e}");
}

#[test]
fn membership_fields_belong_only_to_restricted() {
    for field in [
        r#""users": []"#,
        r#""groups": []"#,
        r#""credentials": ["login"]"#,
    ] {
        let json = format!(
            r#"{{ "version": 1, "applications": [ {{ "name": "a",
                     "base": ["https://x.com/a"], "scopes": [
                       {{ "name": "s", "urls": ["https://x.com/a/*"],
                          "access": "authenticated", {field} }} ] }} ] }}"#
        );
        let e = access_err("stray-field", &json);
        assert!(e.contains("belongs to \"restricted\""), "{field}: {e}");
    }
}

#[test]
fn an_empty_credentials_list_is_fatal() {
    let e = access_err(
        "no-creds",
        r#"{ "version": 1, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"],
                     "access": "restricted", "credentials": [] } ] } ] }"#,
    );
    assert!(e.contains("unreachable"), "{e}");
}

#[test]
fn an_unknown_field_in_a_scope_is_fatal() {
    // The one place a typo could fail open, so it is the one place extras are refused.
    let e = access_err(
        "unknown-field",
        r#"{ "version": 1, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"],
                     "access": "restricted", "anonymous_ok": true } ] } ] }"#,
    );
    assert!(e.contains("anonymous_ok"), "{e}");
}

// --- the format version -------------------------------------------------

#[test]
fn the_version_must_be_the_one_this_binary_reads() {
    // The two arms say different things: nobody declared a format, versus a format
    // this binary does not have.
    let e = access_err("no-version", r#"{}"#);
    assert!(e.contains("no 'version'"), "{e}");
    let e = access_err("future", r#"{ "version": 5 }"#);
    assert!(e.contains("declares version 5"), "{e}");
}

// --- the login page -----------------------------------------------------

#[test]
fn login_url_falls_back_through_the_application_then_the_global() {
    let a = access_of("login-url", &fixture());
    let g = "https://global.example/";
    // Inside mpa, even on a URL no scope covers: a 401 there still wants mpa's page.
    assert_eq!(
        login_url_for(&a, g, Some("https://app.x.com/mpa")),
        "https://signup.x.com/"
    );
    // mcp declares none, and nothing at all is outside every application.
    assert_eq!(login_url_for(&a, g, Some("https://ai.x.com/mcp/tool")), g);
    assert_eq!(login_url_for(&a, g, None), g);
}

#[test]
fn the_refusal_page_falls_back_the_same_way_the_login_page_does() {
    let a = access_of("denied-url", &fixture());
    let g = "https://denied.example/";
    // An area's own page, which is what makes a refusal per-host: the area names a host.
    assert_eq!(
        denied_url_for(&a, g, Some("https://app.x.com/mpa/admin/x")),
        "https://app.x.com/mpa-denied"
    );
    // An application that declares none, and a request nginx sent no URL for, both fall
    // through to the global; empty there is the gate's own page, which only the gate can
    // name, so this returns it empty rather than guessing a path.
    assert_eq!(denied_url_for(&a, g, Some("https://ai.x.com/mcp/tool")), g);
    assert_eq!(denied_url_for(&a, g, None), g);
    assert_eq!(denied_url_for(&a, "", None), "");
}

#[test]
fn a_malformed_denied_url_is_fatal() {
    // Same guard as the login page, and fatal for the same reason: it lands in a
    // `Location:` header, so a value that is not printable ASCII is a splitting gadget
    // and one that is not https is a downgrade.
    let e = access_err(
        "bad-denied",
        &fixture().replace(
            "https://app.x.com/mpa-denied",
            "http://app.x.com/mpa-denied",
        ),
    );
    assert!(e.contains("absolute https"), "{e}");
    assert!(e.contains("denied_url"), "{e}");
}

#[test]
fn a_malformed_login_url_is_fatal() {
    let e = access_err(
        "bad-login",
        &fixture().replace("https://signup.x.com/", "http://signup.x.com/"),
    );
    assert!(e.contains("absolute https"), "{e}");
}

// --- the round trip -----------------------------------------------------

#[test]
fn the_document_round_trips_and_preserves_operator_notes() {
    let json = fixture();
    let doc = doc_of(&json);
    let out = render_access_file(&doc).unwrap();
    let back = doc_of(&out);
    assert_eq!(back.version, ACCESS_FILE_VERSION);
    assert_eq!(back.applications.len(), 2);
    assert_eq!(back.users.len(), 2);
    assert_eq!(
        back.applications[0].scopes[1].groups.as_deref(),
        Some(&["@admins".to_string()][..])
    );
    assert!(out.ends_with('\n'));
    // An absent optional field is left out rather than written as null, which the
    // parser would take for a value.
    assert!(!out.contains("null"), "{out}");
}

#[test]
fn operator_notes_on_a_user_survive_an_edit() {
    let json = fixture().replace(
        r#""emails": ["carol@x.com"]"#,
        r#""emails": ["carol@x.com"], "notes": "on leave""#,
    );
    let doc = doc_of(&json);
    let out = render_access_file(&doc).unwrap();
    assert!(out.contains("on leave"), "{out}");
}

// --- uuids --------------------------------------------------------------

#[test]
fn well_formed_uuid_is_strict_about_one_spelling() {
    const MIXED: &str = "b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d";
    assert!(well_formed_uuid(BOB));
    assert!(well_formed_uuid(MIXED));
    // One spelling only: two strings naming the same identity that do not compare
    // equal would be a dangling reference that looks right in a diff.
    assert!(!well_formed_uuid(&MIXED.to_ascii_uppercase()));
    assert!(!well_formed_uuid(&BOB.replace('-', "")));
    assert!(!well_formed_uuid(""));
    assert!(!well_formed_uuid("11111111-1111-4111-8111-11111111111g"));
}

#[test]
fn mint_uuid_makes_one_this_file_accepts() {
    let a = mint_uuid().unwrap();
    let b = mint_uuid().unwrap();
    assert!(well_formed_uuid(&a), "{a}");
    assert_ne!(a, b);
    assert_eq!(&a[14..15], "4", "version 4");
}

// --- editing the document -----------------------------------------------

#[test]
fn removing_a_user_rewrites_the_exclusions_that_named_them_to_their_email() {
    let mut doc = doc_of(&with_exclusion(
        "https://app.x.com/mpa/*",
        &format!("\"{BOB}\""),
    ));
    let refs = user_refs(&doc, BOB);
    assert!(
        refs.iter().any(|r| r == "mpa/onboarding (excluded)"),
        "an exclusion is a reference, and marked as one: {refs:?}"
    );
    let (_, swept) = remove_user(&mut doc, "bob@x.com").unwrap();
    assert!(swept.iter().any(|r| r.contains("excluded")), "{swept:?}");
    // The exclusion is a veto, so dropping it would lift it: it becomes the primary
    // email, the spelling an exclusion uses for an identity the roster does not know.
    assert_eq!(
        doc.applications[0].scopes[2].excluded.as_deref(),
        Some(&["bob@x.com".to_string()][..])
    );
    // The file that comes out compiles, and keeps the person out as a stranger.
    let w = AccessWrite::prepare(&doc).unwrap();
    assert_eq!(
        decide(
            w.access(),
            &Subject::Identifier("bob@x.com"),
            Some("https://app.x.com/mpa/anything")
        ),
        Decision::Excluded {
            app: "mpa".into(),
            scope: "onboarding".into()
        }
    );
}

#[test]
fn removing_a_user_with_no_email_leaves_nothing_behind_in_excluded() {
    let mut doc = doc_of(&with_exclusion(
        "https://app.x.com/mpa/*",
        &format!("\"{BOB}\""),
    ));
    doc.users[0].emails.clear();
    remove_user(&mut doc, BOB).unwrap();
    let left = doc.applications[0].scopes[2].excluded.clone();
    assert!(
        left.iter()
            .flatten()
            .all(|e| e.trim().is_empty() || norm_email(e) != BOB),
        "{left:?}"
    );
    assert!(
        left.iter().flatten().all(|e| !e.trim().is_empty()),
        "no blank entry either: {left:?}"
    );
}

#[test]
fn a_uuid_excluded_in_several_scopes_is_rewritten_in_each() {
    let mut doc = doc_of(&with_exclusion(
        "https://app.x.com/mpa/*",
        &format!("\"{BOB}\""),
    ));
    doc.applications[1].scopes[0].excluded = Some(vec![BOB.to_string()]);
    doc.applications[0].scopes[1].excluded = Some(vec![BOB.to_string()]);
    remove_user(&mut doc, "bob@x.com").unwrap();
    for (a, s) in [(0, 1), (0, 2), (1, 0)] {
        assert_eq!(
            doc.applications[a].scopes[s].excluded.as_deref(),
            Some(&["bob@x.com".to_string()][..]),
            "scope {a}/{s}"
        );
    }
    AccessWrite::prepare(&doc).unwrap();
}

#[test]
fn an_exclusion_through_a_group_stays_a_group_reference() {
    let mut doc = doc_of(&with_exclusion("https://app.x.com/mpa/*", "\"@admins\""));
    remove_user(&mut doc, "bob@x.com").unwrap();
    // The group is swept as it always was, and the scope still names the group: the
    // rewrite is for uuids only, so no email is added behind the group's back.
    assert!(doc.user_groups["admins"]
        .iter()
        .all(|m| norm_email(m) != BOB));
    assert_eq!(
        doc.applications[0].scopes[2].excluded.as_deref(),
        Some(&["@admins".to_string()][..])
    );
    AccessWrite::prepare(&doc).unwrap();
}

#[test]
fn a_group_only_an_exclusion_names_still_cannot_be_removed() {
    // `compile_access` refuses an unknown group in `excluded` too, so removing this one
    // would produce a file the gate rejects. The refusal names where to go and fix it.
    let mut doc = doc_of(&fixture().replace(
        r#"{ "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
                  "access": "authenticated" }"#,
        r#"{ "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
                  "access": "authenticated", "excluded": ["@admins"] }"#,
    ));
    // The membership reference goes first, so only the exclusion is left holding it.
    doc.applications[0].scopes[1].groups = None;
    doc.applications[0].scopes[1].users = Some(vec![BOB.to_string()]);
    let e = err_of(remove_user_group(&mut doc, "admins"));
    assert!(e.contains("still referenced by"), "{e}");
    assert!(e.contains("mpa/onboarding (excluded)"), "{e}");
}

#[test]
fn add_user_mints_a_uuid_and_refuses_a_taken_email() {
    let mut doc = doc_of(&fixture());
    add_user(
        &mut doc,
        UserSpec {
            emails: vec!["dave@x.com".into()],
            ..Default::default()
        },
    )
    .unwrap();
    let dave = &doc.users[2];
    assert!(well_formed_uuid(&dave.uuid));

    let e = err_of(add_user(
        &mut doc,
        UserSpec {
            emails: vec!["BOB@x.com".into()],
            ..Default::default()
        },
    ));
    assert!(e.contains("already belongs to another user"), "{e}");
}

#[test]
fn add_user_refuses_a_value_that_could_never_be_an_email() {
    let mut doc = doc_of(&fixture());
    let e = err_of(add_user(
        &mut doc,
        UserSpec {
            emails: vec!["not an email".into()],
            ..Default::default()
        },
    ));
    assert!(e.contains("does not look like an email"), "{e}");
}

#[test]
fn a_user_is_found_by_uuid_or_by_any_of_their_emails() {
    let doc = doc_of(&fixture());
    assert_eq!(user_pos(&doc, BOB), Some(0));
    assert_eq!(user_pos(&doc, "bob@old.com"), Some(0));
    assert_eq!(user_pos(&doc, "carol@x.com"), Some(1));
    assert_eq!(user_pos(&doc, "nobody@x.com"), None);
}

#[test]
fn identifiers_are_added_and_dropped_but_never_all_of_them() {
    let mut doc = doc_of(&fixture());
    assert!(add_user_email(&mut doc, BOB, "bob@new.com").unwrap());
    assert!(
        !add_user_email(&mut doc, BOB, "BOB@NEW.COM").unwrap(),
        "idempotent"
    );
    let e = err_of(add_user_email(&mut doc, CAROL, "bob@new.com"));
    assert!(e.contains("already belongs"), "{e}");

    assert!(remove_user_email(&mut doc, BOB, "bob@new.com").unwrap());
    let e = err_of(remove_user_email(&mut doc, CAROL, "carol@x.com"));
    assert!(e.contains("only email"), "{e}");
}

#[test]
fn remove_user_sweeps_every_reference_to_them() {
    let mut doc = doc_of(&fixture());
    let (gone, swept) = remove_user(&mut doc, "bob@x.com").unwrap();
    assert_eq!(gone.uuid, BOB);
    assert!(swept.contains(&"mcp/logs".to_string()), "{swept:?}");
    assert!(swept.contains(&"@admins".to_string()), "{swept:?}");
    // And the file that comes out has no dangling reference left in it.
    assert!(user_refs(&doc, BOB).is_empty());
    let rendered = render_access_file(&doc).unwrap();
    assert!(!rendered.contains(BOB), "{rendered}");
}

#[test]
fn renaming_an_application_repoints_the_keys_that_named_it() {
    let mut doc = doc_of(&fixture());
    rename_application(&mut doc, "mcp", "gateway").unwrap();
    assert_eq!(
        doc.users[0].api_keys[0].scopes.as_deref(),
        Some(&["gateway/api".to_string()][..])
    );
    // And the result still compiles, which is what the re-pointing is for.
    AccessWrite::prepare(&doc).unwrap();
}

#[test]
fn renaming_a_scope_repoints_the_keys_that_named_it() {
    let mut doc = doc_of(&fixture());
    rename_scope(&mut doc, "mcp", "api", "tools").unwrap();
    assert_eq!(
        doc.users[0].api_keys[0].scopes.as_deref(),
        Some(&["mcp/tools".to_string()][..])
    );
    AccessWrite::prepare(&doc).unwrap();
}

#[test]
fn moving_a_scope_changes_who_answers_without_changing_a_field() {
    let mut doc = doc_of(&fixture());
    move_scope(&mut doc, "mcp", 0, 1).unwrap();
    let a = AccessWrite::prepare(&doc).unwrap();
    let (_, s) = a
        .access()
        .resolve(Some("https://ai.x.com/mcp/logs/x"))
        .unwrap();
    assert_eq!(s.name, "api", "the broad scope now answers first");
}

#[test]
fn scope_and_application_names_must_be_free() {
    let mut doc = doc_of(&fixture());
    let e = err_of(add_application(
        &mut doc,
        AppSpec {
            name: "mpa".into(),
            ..Default::default()
        },
    ));
    assert!(e.contains("already exists"), "{e}");
    let e = err_of(add_scope(
        &mut doc,
        "mpa",
        ScopeSpec {
            name: "admin".into(),
            ..Default::default()
        },
        None,
    ));
    assert!(e.contains("already exists"), "{e}");
}

#[test]
fn a_group_cannot_be_removed_while_a_scope_names_it() {
    let mut doc = doc_of(&fixture());
    let e = err_of(remove_user_group(&mut doc, "admins"));
    assert!(e.contains("mpa/admin"), "{e}");
    // Drop the reference and it goes.
    doc.applications[0].scopes[1].groups = None;
    assert_eq!(remove_user_group(&mut doc, "admins").unwrap(), vec![BOB]);
}

#[test]
fn denying_an_enrolled_user_writes_their_uuid() {
    let mut doc = doc_of(&fixture());
    assert!(add_denied(&mut doc, "bob@old.com").unwrap());
    assert!(doc.denied.contains(&BOB.to_string()), "{:?}", doc.denied);
    assert!(
        !add_denied(&mut doc, BOB).unwrap(),
        "already vetoed, by either name"
    );
    assert_eq!(remove_denied(&mut doc, &["bob@x.com".to_string()]), 1);
}

#[test]
fn denying_a_stranger_keeps_the_email() {
    let mut doc = doc_of(&fixture());
    assert!(add_denied(&mut doc, "Nuisance@X.com").unwrap());
    assert!(doc.denied.contains(&"nuisance@x.com".to_string()));
    let e = err_of(add_denied(&mut doc, "not an email"));
    assert!(e.contains("does not look like an email"), "{e}");
}

// --- the write order ----------------------------------------------------

#[test]
fn access_write_refuses_a_document_the_gate_would_reject() {
    let mut doc = doc_of(&fixture());
    doc.applications[0].scopes[0].access = "anonimous".into();
    let e = err_of(AccessWrite::prepare(&doc));
    assert!(e.contains("refusing to write"), "{e}");
}

#[test]
fn access_write_commits_exactly_the_bytes_it_compiled() {
    let path = users_tmp("commit", &fixture());
    let mut doc = doc_of(&fixture());
    add_user(
        &mut doc,
        UserSpec {
            emails: vec!["dave@x.com".into()],
            ..Default::default()
        },
    )
    .unwrap();
    let w = AccessWrite::prepare(&doc).unwrap();
    let expected = w.json().to_string();
    let receipt = w.commit(path.to_str().unwrap()).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
    assert!(receipt.backup.exists());
    let _ = std::fs::remove_file(&receipt.backup);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn open_access_file_refuses_a_file_the_gate_would_reject() {
    let path = users_tmp("open-bad", r#"{ "version": 1, "denied": ["nope"] }"#);
    let e = err_of(open_access_file(path.to_str().unwrap()));
    assert!(e.contains("the gate would reject this file"), "{e}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn add_api_key_seals_the_bearer_until_the_file_carries_its_hash() {
    let path = users_tmp("seal", &fixture());
    let mut doc = doc_of(&fixture());
    let sealed = add_api_key(
        &mut doc,
        "carol@x.com",
        ApiKeySpec {
            id: "ci".into(),
            released: "2026-08-17".into(),
            duration: "30d".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let w = AccessWrite::prepare(&doc).unwrap();
    let receipt = w.commit(path.to_str().unwrap()).unwrap();
    // The receipt is what unseals it: a dry run has no bearer to leak.
    let bearer = sealed.reveal(&receipt);
    assert!(bearer.starts_with(API_KEY_PREFIX));
    let a = read_access(path.to_str().unwrap()).unwrap();
    assert!(a.by_key_hash.contains_key(&sha256_hex(&bearer)));
    let _ = std::fs::remove_file(&receipt.backup);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn add_api_key_refuses_a_duplicate_id() {
    let mut doc = doc_of(&fixture());
    let e = err_of(add_api_key(
        &mut doc,
        BOB,
        ApiKeySpec {
            id: "laptop".into(),
            ..Default::default()
        },
    ));
    assert!(e.contains("already has a key 'laptop'"), "{e}");
}

#[test]
fn rotate_api_key_replaces_the_hash_and_redates_the_row() {
    let mut doc = doc_of(&fixture());
    let before = doc.users[0].api_keys[0].key_hash.clone();
    let _sealed = rotate_api_key(&mut doc, "bob@x.com", "laptop").unwrap();
    assert_ne!(doc.users[0].api_keys[0].key_hash, before);
    assert_eq!(doc.users[0].api_keys[0].released, format_date(now()));
}

#[test]
fn scopes_for_lists_where_a_user_is_named() {
    let a = access_of("scopes-for", &fixture());
    let mine: Vec<String> = a
        .scopes_for(BOB)
        .iter()
        .map(|(app, s)| format!("{}/{}", app.name, s.name))
        .collect();
    assert_eq!(mine, vec!["mpa/admin", "mcp/logs", "mcp/api"]);
    assert!(a.scopes_for(CAROL).is_empty());
}

#[test]
fn any_authenticated_scope_is_what_session_asks() {
    let a = access_of("any-authn", &fixture());
    assert!(a.any_authenticated_scope());
    let b = access_of(
        "no-authn",
        r#"{ "version": 1, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"],
                     "access": "restricted" } ] } ] }"#,
    );
    assert!(!b.any_authenticated_scope());
}

// --- what an identity reaches -------------------------------------------

/// The pairs as `app/scope` strings, in the order the function returns them, so each
/// assertion below reads as the list the user page will show and pins file order too.
fn reached(a: &Access, identifier: &str) -> Vec<String> {
    a.scopes_reached(identifier)
        .iter()
        .map(|(app, s)| format!("{}/{}", app.name, s.name))
        .collect()
}

/// One URL per non-anonymous scope of the fixture, chosen so that **that** scope answers
/// it: scopes are first match wins, so `mpa/onboarding` answers `/mpa/welcome` and never
/// `/mpa/admin/panel`, and `mcp/api` answers `/mcp/other` and never `/mcp/logs/today`.
/// The agreement test checks this table against `resolve` before trusting it.
const PROBES: &[(&str, &str)] = &[
    ("mpa/admin", "https://app.x.com/mpa/admin/panel"),
    ("mpa/onboarding", "https://app.x.com/mpa/welcome"),
    ("mcp/logs", "https://ai.x.com/mcp/logs/today"),
    ("mcp/api", "https://ai.x.com/mcp/other"),
];

/// The set is the page's promise about a signed-in person, so every kind has to be right
/// in it: bob reaches mpa/admin only through `@admins`, mcp/logs directly, and
/// mpa/onboarding because that grant admits any signed-in identity. mpa/healthz is
/// anonymous, so it says nothing about him, and mcp/api's credentials admit a key and
/// refuse a login, so a browser never reaches it.
#[test]
fn scopes_reached_lists_a_roster_user_in_file_order() {
    let a = access_of("reached-bob", &fixture());
    assert_eq!(
        reached(&a, "bob@x.com"),
        vec!["mpa/admin", "mpa/onboarding", "mcp/logs"]
    );
}

/// The identifier is an email and the answer comes from the roster row, so an old
/// address, or the same address in another case, must not show a shorter list than the
/// one the person signs in with.
#[test]
fn scopes_reached_answers_the_same_for_every_email_of_a_user() {
    let a = access_of("reached-emails", &fixture());
    assert_eq!(reached(&a, "BOB@old.com"), reached(&a, "bob@x.com"));
    assert_eq!(
        reached(&a, " BOB@OLD.COM "),
        vec!["mpa/admin", "mpa/onboarding", "mcp/logs"]
    );
}

/// A stranger has no uuid, so no restricted scope can name them, and `authenticated`
/// exists precisely to admit a signed-in identity the file has never heard of. This is
/// why the function takes an email and not a uuid.
#[test]
fn scopes_reached_gives_a_stranger_only_the_authenticated_scope() {
    let a = access_of("reached-stranger", &fixture());
    assert_eq!(
        reached(&a, "stranger@elsewhere.com"),
        vec!["mpa/onboarding"]
    );
}

/// carol is in the roster and named by no scope: a `restricted` scope reads membership,
/// not enrolment, so being a user buys a person no access on its own.
#[test]
fn scopes_reached_gives_an_enrolled_non_member_only_the_authenticated_scope() {
    let a = access_of("reached-carol", &fixture());
    assert_eq!(reached(&a, "carol@x.com"), vec!["mpa/onboarding"]);
}

/// `denied` outranks every grant, so a vetoed identity is shown no list at all: the page
/// that would show it is a 403. This one asserts absence, so it is green against the
/// stub and must be rerun once the code exists.
#[test]
fn scopes_reached_is_empty_for_an_identity_the_file_denies() {
    let a = access_of("reached-denied", &fixture());
    assert!(a.vetoes_identifier("spammer@x.com"));
    assert!(reached(&a, "spammer@x.com").is_empty());
}

/// The scope's own veto is local, unlike `denied`: bob is kept out of mpa/admin without
/// unpicking `@admins`, so the rest of his list stands.
#[test]
fn scopes_reached_drops_a_scope_that_excludes_the_identity_by_uuid() {
    let a = access_of(
        "reached-excl-uuid",
        &with_exclusion("https://app.x.com/mpa/admin/*", &format!("\"{BOB}\"")),
    );
    assert_eq!(reached(&a, "bob@x.com"), vec!["mpa/onboarding", "mcp/logs"]);
}

/// An `authenticated` scope lists nobody, so an email is the only way to keep a stranger
/// out of one, and in this fixture it is the only scope they reached at all. This one
/// asserts absence, so it is green against the stub and must be rerun once the code
/// exists.
#[test]
fn scopes_reached_is_empty_for_a_stranger_excluded_from_the_only_scope() {
    let a = access_of(
        "reached-excl-stranger",
        &with_exclusion("https://app.x.com/mpa/*", "\"stranger@elsewhere.com\""),
    );
    assert!(reached(&a, "stranger@elsewhere.com").is_empty());
}

/// The page's list and the gate's answer are the same rule written twice, and two copies
/// of a grant rule drift. So for every identifier, every non-anonymous scope of the
/// fixture must be listed exactly when `decide` grants on a URL that scope itself
/// answers: the whole set, both directions, on one fixture.
#[test]
fn scopes_reached_agrees_with_decide_on_every_scope() {
    let a = access_of("reached-agree", &fixture());

    // The probe table is the whole file: a scope added to the fixture has to be probed.
    let probed: Vec<String> = PROBES.iter().map(|(name, _)| name.to_string()).collect();
    let non_anonymous: Vec<String> = a
        .apps
        .iter()
        .flat_map(|app| {
            app.scopes
                .iter()
                .filter(|s| s.access != AccessKind::Anonymous)
                .map(|s| format!("{}/{}", app.name, s.name))
        })
        .collect();
    assert_eq!(
        probed, non_anonymous,
        "the probe table must cover every non-anonymous scope"
    );

    for id in [
        "bob@x.com",
        "BOB@old.com",
        "carol@x.com",
        "stranger@elsewhere.com",
        "spammer@x.com",
    ] {
        let listed = reached(&a, id);
        for (name, url) in PROBES {
            let (app, scope) = a.resolve(Some(url)).expect("every probe url resolves");
            assert_eq!(
                (app.name.as_str(), scope.name.as_str()),
                name.split_once('/').unwrap(),
                "{url} must be answered by {name}, not by a scope that shadows it"
            );
            let granted = decide(&a, &Subject::Identifier(id), Some(url)).granted();
            let shows = listed.iter().any(|s| s == name);
            assert_eq!(
                granted, shows,
                "{id} at {url}: decide granted {granted}, scopes_reached listed {shows} \
                     (list: {listed:?})"
            );
        }
    }
}

// --- what a key reaches -------------------------------------------------

const DAVE: &str = "33333333-3333-4333-8333-333333333333";
const NOBODY: &str = "99999999-9999-4999-8999-999999999999";
const BOB_BEARER: &str = "bbk_keytestbob000000000000000000000";
const CAROL_BEARER: &str = "bbk_keytestcarol00000000000000000000";
const DAVE_BEARER: &str = "bbk_keytestdave00000000000000000000";

/// The estate of [`fixture`] arranged for the key rule, so every arm that rule has is in
/// one file: bob's key carries **no** `scopes` restriction, which is the spelling the
/// binding rule is stated for ("at most what the owner reaches"), so nothing has
/// subtracted from the answer. `mpa/reports` names bob directly and spells out both
/// credential classes; `mpa/admin` admits a login only, so a key is refused there even
/// though `@admins` names him; `mcp/logs` names bob and excludes him by uuid; `mcp/keys`
/// reaches him through `@machines`; `mcp/other` is carol's alone and leaves `credentials`
/// unset, which means both classes; `mcp/api` names bob and dave and admits a key only.
/// dave is `denied` by uuid, and `mpa/reports` sits first in the file so the expected
/// order is the reverse of the alphabetical one.
fn key_fixture() -> String {
    r#"{
          "version": 1,
          "applications": [
            { "name": "mpa",
              "base": ["https://app.x.com/mpa"],
              "scopes": [
                { "name": "reports", "urls": ["https://app.x.com/mpa/reports/*"],
                  "access": "restricted", "users": ["BOBUUID"],
                  "credentials": ["login", "api_key"] },
                { "name": "healthz", "urls": ["https://app.x.com/mpa/healthz"],
                  "access": "anonymous" },
                { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"],
                  "access": "restricted", "groups": ["@admins"],
                  "credentials": ["login"] },
                { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
                  "access": "authenticated" } ] },
            { "name": "mcp",
              "base": ["https://ai.x.com/mcp"],
              "scopes": [
                { "name": "logs", "urls": ["https://ai.x.com/mcp/logs/*"],
                  "access": "restricted", "users": ["BOBUUID"],
                  "excluded": ["BOBUUID"] },
                { "name": "keys", "urls": ["https://ai.x.com/mcp/keys/*"],
                  "access": "restricted", "groups": ["@machines"],
                  "credentials": ["login", "api_key"] },
                { "name": "other", "urls": ["https://ai.x.com/mcp/other/*"],
                  "access": "restricted", "users": ["CAROLUUID"] },
                { "name": "api", "urls": ["https://ai.x.com/mcp/*"],
                  "access": "restricted", "users": ["BOBUUID", "DAVEUUID"],
                  "credentials": ["api_key"] } ] } ],
          "user_groups": { "admins": ["BOBUUID"], "machines": ["BOBUUID", "DAVEUUID"] },
          "denied": ["spammer@x.com", "DAVEUUID"],
          "users": [
            { "uuid": "BOBUUID", "emails": ["bob@x.com"],
              "api_keys": [ { "id": "laptop", "key_hash": "BOBHASH",
                              "released": "2026-01-01", "duration": "never" } ] },
            { "uuid": "CAROLUUID", "emails": ["carol@x.com"],
              "api_keys": [ { "id": "desk", "key_hash": "CAROLHASH",
                              "released": "2026-01-01", "duration": "never" } ] },
            { "uuid": "DAVEUUID", "emails": ["dave@x.com"],
              "api_keys": [ { "id": "old", "key_hash": "DAVEHASH",
                              "released": "2026-01-01", "duration": "never" } ] } ] }"#
        .replace("BOBUUID", BOB)
        .replace("CAROLUUID", CAROL)
        .replace("DAVEUUID", DAVE)
        .replace("BOBHASH", &sha256_hex(BOB_BEARER))
        .replace("CAROLHASH", &sha256_hex(CAROL_BEARER))
        .replace("DAVEHASH", &sha256_hex(DAVE_BEARER))
}

/// The pairs as `app/scope` strings, in the order the function returns them, so each
/// assertion below reads as the list the key form will show and pins file order too.
fn key_scopes(a: &Access, uuid: &str) -> Vec<String> {
    a.key_scopes_for(uuid)
        .iter()
        .map(|(app, s)| format!("{}/{}", app.name, s.name))
        .collect()
}

/// The key, resolved the way the gate resolves a bearer: by its hash, through
/// [`decide_api_key`]. A denied owner's key does not get through that door, so the test
/// that needs one takes the record from [`Access::by_key_hash`] instead.
fn owner_key<'a>(a: &'a Access, bearer: &str) -> &'a ApiKeyRecord {
    match decide_api_key(a, &sha256_hex(bearer), 1_000) {
        KeyDecision::Granted(r) => r,
        KeyDecision::Unknown => panic!("the fixture key is not in the file"),
        KeyDecision::OwnerDenied(_) => panic!("the fixture key's owner is denied"),
        KeyDecision::Expired(_) => panic!("the fixture key is expired"),
    }
}

/// One URL per non-anonymous scope of [`key_fixture`], chosen so that **that** scope
/// answers it: scopes are first match wins, so `mpa/onboarding` answers `/mpa/welcome` and
/// never `/mpa/reports/q1`, and `mcp/api` answers `/mcp/plain` and never
/// `/mcp/keys/report`. The agreement test checks this table against `resolve` before
/// trusting it.
const KEY_PROBES: &[(&str, &str)] = &[
    ("mpa/reports", "https://app.x.com/mpa/reports/q1"),
    ("mpa/admin", "https://app.x.com/mpa/admin/panel"),
    ("mpa/onboarding", "https://app.x.com/mpa/welcome"),
    ("mcp/logs", "https://ai.x.com/mcp/logs/today"),
    ("mcp/keys", "https://ai.x.com/mcp/keys/report"),
    ("mcp/other", "https://ai.x.com/mcp/other/today"),
    ("mcp/api", "https://ai.x.com/mcp/plain"),
];

/// The list is the set of scopes a key of this owner may be narrowed to, so it has to be
/// exactly what such a key reaches: `mpa/reports` (named directly, both classes),
/// `mcp/keys` (through `@machines`, both classes) and `mcp/api` (named directly, key
/// only). Everything else is out for a reason the tests below take one each: `mpa/admin`
/// refuses the credential class, `mpa/onboarding` is `authenticated`, `mcp/logs` excludes
/// him, `mcp/other` does not name him, `mpa/healthz` is anonymous.
#[test]
fn key_scopes_for_lists_the_scopes_an_unrestricted_key_of_the_owner_reaches() {
    let a = access_of("key-scopes-bob", &key_fixture());
    assert_eq!(
        key_scopes(&a, BOB),
        vec!["mpa/reports", "mcp/keys", "mcp/api"]
    );
}

/// A key acts as its owner and not as anybody else, so carol's list is her own scopes and
/// none of bob's: `mcp/other` names her and leaves `credentials` unset, which restricts
/// nothing, so a key of hers reaches it.
#[test]
fn key_scopes_for_lists_only_what_a_key_of_that_owner_reaches() {
    let a = access_of("key-scopes-carol", &key_fixture());
    assert_eq!(key_scopes(&a, CAROL), vec!["mcp/other"]);
}

/// The list is what the **owner** reaches, never what one existing key of theirs is
/// narrowed to: [`fixture`]'s `laptop` key names only `mcp/api`, and a form that offered
/// only that could never widen the key back, which is the whole point of showing the
/// owner's reach.
#[test]
fn key_scopes_for_answers_for_the_owner_and_not_for_one_narrowed_key() {
    let a = access_of("key-scopes-owner", &fixture());
    assert_eq!(
        fixture_key(&a).scopes.as_ref().map(|s| s.len()),
        Some(1),
        "the fixture key must be narrowed to one scope for this to mean anything"
    );
    assert_eq!(key_scopes(&a, BOB), vec!["mcp/logs", "mcp/api"]);
}

/// A scope whose `credentials` admit a login only refuses a key, and bob is a member of
/// one, through `@admins`: membership alone must not put `mpa/admin` in the form, because
/// the form would then mint a key the gate refuses on its very first request.
#[test]
fn key_scopes_for_skips_a_scope_whose_credentials_admit_only_a_login() {
    let a = access_of("key-scopes-login-only", &key_fixture());
    assert!(
        a.scopes_for(BOB).iter().any(|(_, s)| s.name == "admin"),
        "bob must be a member of mpa/admin for the refusal to be about the class"
    );
    assert!(!key_scopes(&a, BOB).iter().any(|s| s == "mpa/admin"));
}

/// Groups are expanded at load and `credentials` is a statement about the place, so a
/// scope that reaches bob through `@machines` and spells out both classes is in his list
/// exactly as one that names him.
#[test]
fn key_scopes_for_lists_a_scope_reached_through_a_group_that_admits_both_classes() {
    let a = access_of("key-scopes-group", &key_fixture());
    assert!(key_scopes(&a, BOB).iter().any(|s| s == "mcp/keys"));
}

/// The scope's own veto is a key's veto too: `mcp/logs` names bob and excludes him, so
/// the form must not offer a scope the gate answers with `excluded`.
#[test]
fn key_scopes_for_drops_a_scope_that_excludes_the_uuid() {
    let a = access_of("key-scopes-excluded", &key_fixture());
    let logs = a
        .resolve(Some("https://ai.x.com/mcp/logs/today"))
        .expect("the probe url resolves")
        .1;
    assert!(logs.members.contains(BOB), "the fixture excludes a member");
    assert!(logs.excluded_users.contains(BOB));
    assert!(!key_scopes(&a, BOB).iter().any(|s| s == "mcp/logs"));
}

/// `denied` outranks every grant on every credential and a key is one of them, so a
/// vetoed owner is offered nothing at all: the page that would offer it is a 403. The
/// scopes are there to be reached, which is what makes the emptiness the veto's doing
/// rather than the file's.
#[test]
fn key_scopes_for_is_empty_for_a_uuid_the_file_denies() {
    let a = access_of("key-scopes-denied", &key_fixture());
    assert!(a.denied_users.iter().any(|u| u == DAVE));
    assert!(
        a.scopes_for(DAVE).iter().any(|(_, s)| s.name == "api"),
        "dave is named by mcp/api, so only the veto can empty his list"
    );
    assert!(key_scopes(&a, DAVE).is_empty());
}

/// A uuid the file has never heard of has no key, no membership and no grant, so the page
/// for it must offer no checkbox. This one asserts only absence, so it is green against
/// anything that returns an empty list and must be re-read once the code exists.
#[test]
fn key_scopes_for_is_empty_for_a_uuid_the_file_has_never_heard_of() {
    let a = access_of("key-scopes-unknown", &key_fixture());
    assert!(!a.by_uuid.contains_key(NOBODY));
    assert!(key_scopes(&a, NOBODY).is_empty());
}

/// `decide` answers an [`AccessKind::Anonymous`] scope **before** it looks at the
/// credential, so a key is granted there, and a denied owner's key is granted there too.
/// That is why the agreement test compares only non-anonymous scopes, and it is why the
/// design's word "restricted" is the right contract for this list: an anonymous scope says
/// nothing about whose key it is, so offering it as a restriction would be a checkbox that
/// changes nothing.
#[test]
fn key_scopes_for_omits_the_anonymous_scope_that_decide_grants_to_a_key_anyway() {
    let a = access_of("key-scopes-anon", &key_fixture());
    let url = "https://app.x.com/mpa/healthz";
    assert_eq!(
        decide(&a, &Subject::Key(owner_key(&a, BOB_BEARER)), Some(url)),
        Decision::Anonymous {
            app: "mpa".into(),
            scope: "healthz".into()
        }
    );
    let dead = a
        .by_key_hash
        .get(&sha256_hex(DAVE_BEARER))
        .expect("the fixture key is in the file");
    assert!(
        decide(&a, &Subject::Key(dead), Some(url)).granted(),
        "the veto sits after an anonymous grant, which is the reason for the exception"
    );
    assert!(!key_scopes(&a, BOB).iter().any(|s| s == "mpa/healthz"));
    assert!(!key_scopes(&a, DAVE).iter().any(|s| s == "mpa/healthz"));
}

/// The list the key form offers and the gate's answer are the same rule written twice, and
/// two copies of a grant rule drift. So for every owner of an unrestricted key, every
/// non-anonymous scope of the fixture must be listed exactly when `decide` grants that key
/// on a URL that scope itself answers: the whole set, both directions, on one fixture.
#[test]
fn key_scopes_for_agrees_with_decide_for_a_key_with_no_restriction() {
    let a = access_of("key-scopes-agree", &key_fixture());

    // The probe table is the whole file: a scope added to the fixture has to be probed.
    let probed: Vec<String> = KEY_PROBES
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    let non_anonymous: Vec<String> = a
        .apps
        .iter()
        .flat_map(|app| {
            app.scopes
                .iter()
                .filter(|s| s.access != AccessKind::Anonymous)
                .map(|s| format!("{}/{}", app.name, s.name))
        })
        .collect();
    assert_eq!(
        probed, non_anonymous,
        "the probe table must cover every non-anonymous scope"
    );

    for (uuid, bearer) in [(BOB, BOB_BEARER), (CAROL, CAROL_BEARER)] {
        let key = owner_key(&a, bearer);
        assert_eq!(key.uuid, uuid, "the fixture key must belong to {uuid}");
        assert!(
            key.scopes.is_none(),
            "the agreement is stated for a key with no restriction"
        );
        let listed = key_scopes(&a, uuid);
        for (name, url) in KEY_PROBES {
            let (app, scope) = a.resolve(Some(url)).expect("every probe url resolves");
            assert_eq!(
                (app.name.as_str(), scope.name.as_str()),
                name.split_once('/').unwrap(),
                "{url} must be answered by {name}, not by a scope that shadows it"
            );
            let granted = decide(&a, &Subject::Key(key), Some(url)).granted();
            let shows = listed.iter().any(|s| s == name);
            assert_eq!(
                granted, shows,
                "{uuid} at {url}: decide granted {granted}, key_scopes_for listed {shows} \
                     (list: {listed:?})"
            );
        }
    }

    // The vetoed owner: `decide_api_key` refuses the bearer at the first door, so the
    // record comes from the hash index, and `decide` vetoes it on every scope. The list
    // has to be empty for the same reason the gate refuses.
    let dead = a
        .by_key_hash
        .get(&sha256_hex(DAVE_BEARER))
        .expect("the fixture key is in the file");
    assert!(a.denied_users.iter().any(|u| u == &dead.uuid));
    let listed = key_scopes(&a, &dead.uuid);
    assert!(
        listed.is_empty(),
        "a denied owner is offered nothing: {listed:?}"
    );
    for (name, url) in KEY_PROBES {
        assert!(
            !decide(&a, &Subject::Key(dead), Some(url)).granted(),
            "{name} must not grant a denied owner's key"
        );
    }
}

/// The list is the file's order, not an alphabetical one: the form groups its checkboxes
/// under their application in the order the operator reads the file, and a list sorted by
/// name moves a scope the operator has just read. In this fixture the file's order starts
/// with `mpa/reports`, which is the exact reverse of the alphabetical one, so the
/// assertion below cannot be satisfied by a sort.
#[test]
fn key_scopes_for_returns_the_scopes_in_file_order() {
    let a = access_of("key-scopes-order", &key_fixture());
    let listed = key_scopes(&a, BOB);
    assert_eq!(listed, vec!["mpa/reports", "mcp/keys", "mcp/api"]);
    let mut sorted = listed.clone();
    sorted.sort();
    assert_ne!(
        listed, sorted,
        "the order pinned above is the file's, which is not alphabetical: {sorted:?}"
    );
}

// --- the settings file ---------------------------------------------------

/// A claim list from the comma-separated spelling, which is how these cases read best.
fn claims(spec: &str) -> Vec<String> {
    spec.split(',').map(str::to_string).collect()
}

/// The refusal, without asking the `Ok` side for a `Debug` it need not have. Generic over
/// the error because §13.31 changes it in mid-flight: the `String` leaf wrappers stay
/// `String`, while `compile_settings` answers `SettingsRefusal` and `prepare` answers
/// `PrepareError`. All three print the same sentence, so reading the sentence through
/// `Display` keeps every caller in this file compiling across every slice.
fn refusal<T, E: std::fmt::Display>(r: Result<T, E>) -> String {
    match r {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn compile_profile_claims_default_is_empty() {
    // Profile propagation is opt-in: an absent list and a list of blanks both mean
    // "emit nothing".
    for spec in ["", "   ", ",", " , ,"] {
        assert!(
            compile_profile_claims(&claims(spec)).unwrap().is_empty(),
            "should be empty: {spec:?}"
        );
    }
    assert!(compile_profile_claims(&[]).unwrap().is_empty());
}

#[test]
fn compile_profile_claims_derives_each_header_in_order() {
    // The header name is code and the claim name is config, so the derivation is
    // pinned byte for byte; the order out is the order the operator wrote.
    let c = compile_profile_claims(&claims("given_name,family_name")).unwrap();
    let got: Vec<(&str, &str)> = c
        .iter()
        .map(|p| (p.claim.as_str(), p.header.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("given_name", "X-Auth-Given-Name"),
            ("family_name", "X-Auth-Family-Name"),
        ]
    );
}

#[test]
fn compile_profile_claims_derivation_and_trimming() {
    let c = compile_profile_claims(&claims(
        " nickname , custom:department ,phone_number,ZoneInfo",
    ))
    .unwrap();
    let got: Vec<(&str, &str)> = c
        .iter()
        .map(|p| (p.claim.as_str(), p.header.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            // Entries are trimmed, and the claim keeps its own spelling: only the header
            // is normalised.
            ("nickname", "X-Auth-Nickname"),
            ("custom:department", "X-Auth-Custom-Department"),
            ("phone_number", "X-Auth-Phone-Number"),
            ("ZoneInfo", "X-Auth-Zoneinfo"),
        ]
    );
}

#[test]
fn compile_profile_claims_rejects_bad_names() {
    for spec in [
        "full name",  // space
        "naïve",      // non-ASCII
        "a.b",        // a dot would be ambiguous in a header token
        "given/name", // slash
        ":dept",      // empty leading part …
        "dept:",      // … trailing …
        "a--b",       // … and interior: all would derive an empty component
    ] {
        assert!(
            compile_profile_claims(&claims(spec)).is_err(),
            "should reject: {spec:?}"
        );
    }
}

#[test]
fn compile_profile_claims_rejects_claims_the_gate_consumes() {
    // The gate's `Claims` takes these into typed fields, so `flatten` never sees them:
    // configuring one would propagate nothing, silently and forever. Refused instead.
    for claim in RESERVED_CLAIMS {
        assert!(
            compile_profile_claims(&claims(claim)).is_err(),
            "should reject: {claim}"
        );
    }
}

#[test]
fn compile_profile_claims_rejects_header_collisions() {
    // Reserved headers the gate emits itself.
    assert!(compile_profile_claims(&claims("login_url")).is_err()); // -> X-Auth-Login-Url
    assert!(compile_profile_claims(&claims("login-URL")).is_err());
    // A repeated claim, and spellings that differ only in case or separator, all derive
    // the same header: one value would silently win.
    assert!(compile_profile_claims(&claims("nickname,nickname")).is_err());
    assert!(compile_profile_claims(&claims("given_name,given-name")).is_err());
    assert!(compile_profile_claims(&claims("nickname,NickName")).is_err());
    // Distinct headers are fine.
    assert_eq!(
        compile_profile_claims(&claims("nickname,locale"))
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn the_native_username_header_is_spelled_once_and_reserved() {
    // The gate emits it, `bb-auth-web` reads it and this compiler reserves it: three uses
    // and one spelling, pinned where `IDENTITY_HEADER`'s is (section 13.25).
    assert_eq!(NATIVE_USERNAME_HEADER, "X-Auth-Native-Username");
    // Every spelling of the claim derives that header, and none may be configured: the
    // value is a fact of the credential, not decoration an operator can switch.
    for claim in ["native_username", "native:username", "native-username"] {
        assert_eq!(derive_profile_header(claim), NATIVE_USERNAME_HEADER);
        let err = compile_profile_claims(&claims(claim)).unwrap_err();
        assert!(
            err.contains(NATIVE_USERNAME_HEADER),
            "{claim}: the refusal names the header: {err}"
        );
    }
    // And a claim that merely resembles it stays legal.
    assert!(compile_profile_claims(&claims("native_name")).is_ok());
}

#[test]
fn a_profile_claim_may_not_collide_with_an_identity_header_even_a_disabled_one() {
    // `uuid` is off by default, and that is exactly why the collision has to be refused
    // now: turning it on later would otherwise silently overwrite a claim an application
    // already trusts.
    for claim in IDENTITY_ATTRS {
        assert!(
            compile_profile_claims(&claims(claim)).is_err(),
            "{claim} must be refused"
        );
    }
}

#[test]
fn compile_identity_attrs_defaults_to_email_and_derives_its_header() {
    let a = compile_identity_attrs(&claims("email")).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].header, IDENTITY_HEADER);
    // The derivation is the profile claims' own, so the two can never disagree.
    assert_eq!(
        compile_identity_attrs(&claims("uuid,email")).unwrap()[0].header,
        "X-Auth-Uuid"
    );
}

#[test]
fn compile_identity_attrs_refuses_the_unknown_the_repeated_and_the_empty() {
    for spec in ["", "  ", ",,"] {
        let e = refusal(compile_identity_attrs(&claims(spec)));
        assert!(e.contains("at least one"), "{spec:?}: {e}");
    }
    assert!(refusal(compile_identity_attrs(&[])).contains("at least one"));
    assert!(
        refusal(compile_identity_attrs(&claims("phone"))).contains("unknown identity attribute")
    );
    assert!(refusal(compile_identity_attrs(&claims("email,email"))).contains("listed twice"));
}

/// A settings document through the real parser. The error stays the printed sentence:
/// §13.31 turns `compile_settings`' error type into `SettingsRefusal`, whose `Display` is
/// today's sentence byte for byte, so every caller here keeps reading the same text.
fn settings(json: &str) -> Result<Settings, String> {
    let f: SettingsFile = serde_json::from_str(json).map_err(|e| e.to_string())?;
    compile_settings(&f).map_err(|e| e.to_string())
}

#[test]
fn a_minimal_settings_file_is_the_behaviour_every_earlier_version_had() {
    // Both sections absent. What comes out has to be exactly what the gate did before
    // there was a settings file, or an upgrade would change behaviour by omission.
    let s = settings(r#"{ "version": 3 }"#).unwrap();
    assert!(s.profile_claims.is_empty());
    // No app client either, which is the state a package's fresh file is in: tolerated,
    // and it compiles to a gate that accepts no token rather than to a refusal.
    assert!(s.client_id.is_empty());
    assert!(s.audiences.is_empty());
    assert_eq!(s.identity_attrs.len(), 1);
    assert_eq!(s.identity_attrs[0].header, IDENTITY_HEADER);
    assert!(!s.allow_unverified_social);
    assert_eq!(s.social_providers, None);
    assert_eq!(s.session_ttl, 2_592_000);
    assert!(s.admins.is_empty());
    // The audit records nothing about where a request came from until somebody who has
    // wired nginx says which headers to believe, and it rotates and keeps exactly what it
    // did before either was a setting.
    assert_eq!(s.client_ip_header, None);
    assert_eq!(s.request_id_header, None);
    assert_eq!(s.audit_policy, AuditPolicy::default());
    assert_eq!(s.audit_policy.max_bytes(), 2 * AUDIT_MAX_BYTES);
}

/// Both audit headers are off until named, and neither may name a credential.
///
/// The credential refusal is the one that matters, and it is pinned for the request id's
/// sake: an id is written down as it arrives, so a setting that could name `Cookie` could
/// put every session cookie on the estate into a file an administrator reads.
#[test]
fn the_audit_headers_are_off_until_named_and_never_a_credential() {
    let s = settings(
        r#"{ "version": 3, "audit": { "client_ip_header": " X-Real-IP ",
                                           "request_id_header": "X-Request-ID" } }"#,
    )
    .unwrap();
    assert_eq!(s.client_ip_header.as_deref(), Some("X-Real-IP"));
    assert_eq!(s.request_id_header.as_deref(), Some("X-Request-ID"));

    for (field, name, says) in [
        ("client_ip_header", "Authorization", "credential"),
        ("request_id_header", "cookie", "credential"),
        ("request_id_header", "Proxy-Authorization", "credential"),
        // nginx drops a request header with an underscore in its name by default, so this
        // would be a setting that reads nothing, in silence.
        ("client_ip_header", "X_Real_IP", "underscore"),
        ("request_id_header", "X-Request ID", "header name"),
    ] {
        let e = refusal(settings(&format!(
            r#"{{ "version": 3, "audit": {{ "{field}": "{name}" }} }}"#
        )));
        assert!(e.contains(field) && e.contains(says), "{field}={name}: {e}");
    }

    // One header for both is a slip, and one of the two would record nothing.
    let e = refusal(settings(
        r#"{ "version": 3, "audit": { "client_ip_header": "X-Real-IP",
                                           "request_id_header": "x-real-ip" } }"#,
    ));
    assert!(e.contains("at once"), "{e}");
}

#[test]
fn an_audit_limit_is_an_amount_and_a_unit_of_time_or_space() {
    for (typed, amount, unit, spelled) in [
        ("4 MiB", 4, AuditUnit::MiB, "4 MiB"),
        ("4MiB", 4, AuditUnit::MiB, "4 MiB"),
        (" 1 gib ", 1, AuditUnit::GiB, "1 GiB"),
        ("1 year", 1, AuditUnit::Years, "1 year"),
        ("2 Years", 2, AuditUnit::Years, "2 years"),
        ("6 months", 6, AuditUnit::Months, "6 months"),
        ("1 month", 1, AuditUnit::Months, "1 month"),
        ("26 weeks", 26, AuditUnit::Weeks, "26 weeks"),
    ] {
        let l = AuditLimit::parse(typed).unwrap();
        assert_eq!((l.amount, l.unit), (amount, unit), "{typed}");
        assert_eq!(l.spelled(), spelled);
        // What the file is written with reads back as the same limit.
        assert_eq!(AuditLimit::parse(&l.spelled()).unwrap(), l);
    }
    assert_eq!(AuditLimit::parse("2 MiB").unwrap().bytes(), Some(2 << 20));
    assert_eq!(
        AuditLimit::parse("1 week").unwrap().seconds(),
        Some(604_800)
    );
    assert_eq!(AuditLimit::parse("1 GiB").unwrap().seconds(), None);
    // A decimal megabyte is a different number, and a day is finer than a log is kept in.
    for junk in [
        "",
        "4",
        "MiB",
        "0 MiB",
        "-1 years",
        "1.5 GiB",
        "4 MB",
        "4 KiB",
        "1 day",
        "101 years",
        "2000 GiB",
    ] {
        assert!(AuditLimit::parse(junk).is_err(), "{junk:?}");
    }
}

/// The arithmetic between rotation and retention, and the one combination refused: nothing
/// in space anywhere, which leaves a flood free to fill the disk.
#[test]
fn a_policy_is_bounded_in_bytes_whatever_else_it_says() {
    let l = |s: &str| AuditLimit::parse(s).unwrap();
    // A size rotation alone: the default shape.
    let p = AuditPolicy::new(l("4 MiB"), None).unwrap();
    assert_eq!(p.rotate_at_bytes(), 4 << 20);
    assert_eq!(p.max_bytes(), 8 << 20);
    assert_eq!(p.keep_since(1_000_000), None);
    // A retention in space pulls the rotation down to half of it, so the pair fits.
    let p = AuditPolicy::new(l("4 MiB"), Some(l("2 MiB"))).unwrap();
    assert_eq!(p.rotate_at_bytes(), 1 << 20);
    assert_eq!(p.max_bytes(), 2 << 20);
    // A rotation in time needs its bound from the retention.
    let p = AuditPolicy::new(l("1 month"), Some(l("64 MiB"))).unwrap();
    assert_eq!(p.rotate_at_age(), Some(2_629_746));
    assert_eq!(p.max_bytes(), 64 << 20);
    // A retention in time says how old, and the rotation still says how big.
    let p = AuditPolicy::new(l("4 MiB"), Some(l("1 week"))).unwrap();
    assert_eq!(p.keep_since(1_000_000), Some(1_000_000 - 604_800));
    assert_eq!(p.max_bytes(), 8 << 20);
    // Nothing in space: refused, with the way out in the sentence.
    for retention in [None, Some(l("1 year"))] {
        let e = AuditPolicy::new(l("1 month"), retention).unwrap_err();
        assert!(e.contains("without limit") && e.contains("MiB"), "{e}");
    }
    // And through the settings file, where each refusal names its setting.
    let e = refusal(settings(
        r#"{ "version": 3, "audit": { "rotation": "1 month" } }"#,
    ));
    assert!(e.contains("audit"), "{e}");
    let e = refusal(settings(
        r#"{ "version": 3, "audit": { "retention": "1 fortnight" } }"#,
    ));
    assert!(e.contains("audit.retention"), "{e}");
    let s =
        settings(r#"{ "version": 3, "audit": { "rotation": "1 GiB", "retention": "6 months" } }"#)
            .unwrap();
    assert_eq!(s.audit_policy.rotation, l("1 GiB"));
    assert_eq!(s.audit_policy.retention, Some(l("6 months")));
}

#[test]
fn the_refusal_page_is_optional_and_held_to_the_login_page_guard() {
    // Absent is the gate's own /auth/denied, and the gate is where that default lives,
    // because only it knows the path it serves.
    assert!(settings(r#"{ "version": 3 }"#)
        .unwrap()
        .denied_url
        .is_empty());
    let s = settings(r#"{ "version": 3, "gate": { "denied_url": "https://x.com/no" } }"#).unwrap();
    assert_eq!(s.denied_url, "https://x.com/no");
    // The same guard as the sign-in page: it ends up in a `Location:`, so anything that
    // could split a header or downgrade the scheme is refused on the way in, and the
    // message names the field the operator typed rather than the one it shares code with.
    let e = refusal(settings(
        r#"{ "version": 3, "gate": { "denied_url": "http://x.com/no" } }"#,
    ));
    assert!(
        e.contains("denied_url") && e.contains("absolute https"),
        "{e}"
    );
}

fn landing_settings(landing: &str, hosts: &str) -> Result<Settings, String> {
    settings(&format!(
        r#"{{ "version": 3, "gate": {{ "landing_url": "{landing}", "authorized_hosts": [{hosts}] }} }}"#
    ))
}

#[test]
fn a_landing_url_is_absolute_https_on_an_authorized_host() {
    // Unset is the caller's root, which is what the gate did before the setting existed.
    assert!(settings(r#"{ "version": 3 }"#)
        .unwrap()
        .landing_url
        .is_empty());
    let s = landing_settings("https://auth.x.com/account/", r#""auth.x.com""#).unwrap();
    assert_eq!(s.landing_url, "https://auth.x.com/account/");
    // A wildcard pattern covers it too, through the same matcher `safe_rd` uses.
    assert!(landing_settings("https://auth.x.com/account/", r#""*.x.com""#).is_ok());

    // Each refusal names the field the operator typed.
    for bad in [
        "http://auth.x.com/account/",
        "/account/",
        "https://bob@auth.x.com/account/",
        r"https://auth.x.com\account",
    ] {
        let e = refusal(landing_settings(
            bad.replace('\\', "\\\\").as_str(),
            r#""auth.x.com""#,
        ));
        assert!(e.contains("landing_url"), "{bad}: {e}");
    }
    // A host the patterns do not cover would be refused by `safe_rd` at every login and
    // fall back to the login page, so the file refuses it on the way to disk.
    let e = refusal(landing_settings(
        "https://evil.com/account/",
        r#""auth.x.com""#,
    ));
    assert!(
        e.contains("landing_url") && e.contains("authorized_hosts"),
        "{e}"
    );
    // No hosts at all covers nothing.
    let e = refusal(landing_settings("https://auth.x.com/account/", ""));
    assert!(e.contains("landing_url"), "{e}");
}

#[test]
fn an_unset_landing_url_is_never_written() {
    // A host that never used the setting must be able to roll back to an older binary,
    // which refuses an unknown key in this section.
    let doc: SettingsFile =
        serde_json::from_str(r#"{ "version": 3, "gate": { "authorized_hosts": ["auth.x.com"] } }"#)
            .unwrap();
    let out = render_settings_file(&doc).unwrap();
    assert!(!out.contains("landing_url"), "{out}");
    let back: SettingsFile = serde_json::from_str(&out).unwrap();
    assert_eq!(back.gate, doc.gate);

    // Set, it is written and survives the round trip.
    let mut doc = doc;
    doc.gate.landing_url = "https://auth.x.com/account/".to_string();
    let out = render_settings_file(&doc).unwrap();
    assert!(
        out.contains(r#""landing_url": "https://auth.x.com/account/""#),
        "{out}"
    );
    let back: SettingsFile = serde_json::from_str(&out).unwrap();
    assert_eq!(back.gate, doc.gate);
}

#[test]
fn removing_the_host_a_landing_url_needs_is_refused() {
    let mut doc: SettingsFile = serde_json::from_str(
        r#"{ "version": 3, "gate": { "authorized_hosts": ["auth.x.com", "app.x.com"],
                 "landing_url": "https://auth.x.com/account/" } }"#,
    )
    .unwrap();
    assert!(SettingsWrite::prepare(&doc).is_ok());
    // Removing an unrelated host is fine.
    doc.gate.authorized_hosts = vec!["auth.x.com".to_string()];
    assert!(SettingsWrite::prepare(&doc).is_ok());
    // Removing the one the landing page is on is the silent loop, refused with the
    // landing_url sentence, and nothing becomes bytes.
    doc.gate.authorized_hosts = vec!["app.x.com".to_string()];
    let e = refusal(SettingsWrite::prepare(&doc));
    assert!(e.contains("landing_url"), "{e}");
}

#[test]
fn the_landing_url_is_not_a_guarded_change() {
    let live = GateSettings {
        authorized_hosts: vec!["auth.x.com".to_string()],
        landing_url: "https://auth.x.com/account/".to_string(),
        ..Default::default()
    };
    for new in ["https://auth.x.com/other/", ""] {
        let changed = GateSettings {
            landing_url: new.to_string(),
            ..live.clone()
        };
        assert!(guarded_changes(&live, &changed).is_empty(), "{new:?}");
    }
    let fresh = GateSettings {
        landing_url: String::new(),
        ..live.clone()
    };
    assert!(guarded_changes(&fresh, &live).is_empty());
}

#[test]
fn rd_url_allowed_lives_in_the_library_and_judges_host_only() {
    let h = vec![compile_host_pattern("*.x.com").unwrap()];
    assert!(rd_url_allowed("https://a.x.com/p?q=1", &h));
    assert!(rd_url_allowed("https://A.X.com:8443/p", &h));
    assert!(!rd_url_allowed("https://x.com/", &h)); // the apex is not implied
    assert!(!rd_url_allowed("http://a.x.com/", &h));
    assert!(!rd_url_allowed("https://evil.com/a.x.com", &h));
    assert!(!rd_url_allowed("https://a.x.com.evil.com/", &h));
    assert!(!rd_url_allowed("https://u@a.x.com/", &h));
    assert!(!rd_url_allowed("https://a.x.com/\r\nSet-Cookie: x=1", &h));
}

#[test]
fn the_version_is_checked_the_way_the_access_file_checks_its_own() {
    // No version at all deserializes to 0, which is not this format either.
    for json in [r#"{}"#, r#"{ "version": 4 }"#] {
        assert!(refusal(settings(json)).contains("version"), "{json}");
    }
    // The two older formats get a sentence rather than a number, because both exist in
    // the wild and what each needs is not "try again" but a named list of fields to move
    // in. Version 1 predates the app clients; version 2 predates the pool.
    let one = refusal(settings(r#"{ "version": 1 }"#));
    assert!(
        one.contains("client_id") && one.contains("CHANGELOG"),
        "{one}"
    );
    let two = refusal(settings(r#"{ "version": 2 }"#));
    assert!(
        two.contains("gate.issuer")
            && two.contains("gate.cookie_domain")
            && two.contains("gate.authorized_hosts"),
        "{two}"
    );
}

/// The check that only became possible once these two stopped living in two files, and
/// the reason the move was worth its cost. The failure it prevents has no error anywhere:
/// the login works, the redirect lands, the browser sends no cookie, and the person is
/// back on the sign-in page they just came from.
#[test]
fn a_cookie_domain_must_reach_every_authorized_host() {
    let f = |domain: &str, hosts: &str| {
        settings(&format!(
            r#"{{ "version": 3, "gate": {{ "cookie_domain": "{domain}",
                     "authorized_hosts": [{hosts}] }} }}"#
        ))
    };
    // The apex and the wildcard are both under `.badbat75.com`, dot and all.
    assert!(f(".badbat75.com", r#""badbat75.com", "*.badbat75.com""#).is_ok());
    // With or without the leading dot: RFC 6265 ignores it, so this file must too.
    assert!(f("badbat75.com", r#""*.badbat75.com""#).is_ok());
    // A second estate the cookie is never sent to.
    let e = refusal(f(".badbat75.com", r#""badbat75.com", "app.other.com""#));
    assert!(
        e.contains("app.other.com") && e.contains("cookie_domain"),
        "{e}"
    );
    // The lookalike the dot exists to catch: `*badbat75.com` matches `evilbadbat75.com`,
    // which no cookie on badbat75.com reaches.
    assert!(f(".badbat75.com", r#""*badbat75.com""#).is_err());
    // A host-only cookie says nothing about where a redirect may land, so there is
    // nothing to check and the check does not invent one.
    assert!(f("", r#""app.other.com""#).is_ok());
}

#[test]
fn a_cookie_domain_is_a_domain_and_an_issuer_is_an_absolute_url() {
    for bad in [
        "https://x.com", // a URL, not a domain
        "x.com:443",     // a port
        "x.com/path",    // a path
        "com",           // a single label a browser stores for nothing
        ".",             // and its degenerate spelling
        "-x.com",
        "x..com",
    ] {
        assert!(compile_cookie_domain(bad).is_err(), "{bad}");
    }
    // Kept as written, lowercased, because those bytes go into the header.
    assert_eq!(
        compile_cookie_domain(" .BadBat75.com ").unwrap(),
        ".badbat75.com"
    );
    assert_eq!(compile_cookie_domain("").unwrap(), "");

    for bad in [
        "cognito-idp.eu-central-1.amazonaws.com/pool", // no scheme
        "http://x.com/pool",                           // not https
        "https://user@x.com/pool",                     // userinfo
        "https://x.com/pool?a=1",                      // a query
        "https://x.com/pool#f",                        // a fragment
        "https://x.com/po ol",                         // a space
    ] {
        assert!(compile_issuer(bad).is_err(), "{bad}");
    }
    // The trailing slash is dropped, because `iss` is compared byte for byte.
    assert_eq!(
        compile_issuer("https://x.com/pool/").unwrap(),
        "https://x.com/pool"
    );
}

/// A confirmation is about what is taken away. The rule is small enough to state and
/// exactly the sort of thing that rots into "ask about everything", which is a button
/// people learn to click without reading.
#[test]
fn a_guarded_setting_asks_about_a_change_and_never_about_a_first_value() {
    let g = |issuer: &str, client: &str, domain: &str, hosts: &[&str]| GateSettings {
        issuer: issuer.to_string(),
        client_id: client.to_string(),
        cookie_domain: domain.to_string(),
        authorized_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        ..Default::default()
    };
    let live = g("https://iss/p", "cid", ".x.com", &["x.com", "*.x.com"]);

    // Nothing to confirm: the same values, and the spellings that mean the same values.
    assert!(guarded_changes(&live, &live).is_empty());
    let same = g("https://iss/p/", "cid", "X.com", &[" *.X.COM ", "x.com"]);
    assert!(
        guarded_changes(&live, &same).is_empty(),
        "{:?}",
        guarded_changes(&live, &same)
    );

    // An empty deployment being filled in is not a risk, whatever it is filled with.
    let fresh = GateSettings::default();
    assert!(guarded_changes(&fresh, &live).is_empty());

    // Each of the four scalars, one at a time.
    for (new, want) in [
        (
            g("https://other/p", "cid", ".x.com", &["x.com", "*.x.com"]),
            GuardedSetting::Issuer,
        ),
        (
            g("https://iss/p", "other", ".x.com", &["x.com", "*.x.com"]),
            GuardedSetting::ClientId,
        ),
        (
            g("https://iss/p", "cid", ".y.com", &["x.com", "*.x.com"]),
            GuardedSetting::CookieDomain,
        ),
        (
            g("https://iss/p", "cid", ".x.com", &["x.com"]),
            GuardedSetting::AuthorizedHosts,
        ),
    ] {
        assert_eq!(guarded_changes(&live, &new), vec![want], "{:?}", want);
    }

    // Adding a host cannot stop a login, so it is not on this list; removing one can.
    let wider = g(
        "https://iss/p",
        "cid",
        ".x.com",
        &["x.com", "*.x.com", "z.com"],
    );
    assert!(guarded_changes(&live, &wider).is_empty());

    // Emptying a value that had one is the most dangerous shape of all, and is caught by
    // the same rule rather than by a case of its own.
    let gone = g("", "", "", &[]);
    assert_eq!(guarded_changes(&live, &gone).len(), 4);
}

#[test]
fn an_unknown_key_inside_a_section_is_refused_and_one_at_the_top_is_kept() {
    // The same split the access file makes: strict where a typo would drop a setting
    // that narrows behaviour, permissive where `_comment` lives.
    assert!(settings(r#"{ "version": 3, "gate": { "profil_claims": [] } }"#).is_err());
    assert!(settings(r#"{ "version": 3, "web": { "admin": [] } }"#).is_err());

    let doc: SettingsFile = serde_json::from_str(r#"{ "version": 1, "_comment": "hi" }"#).unwrap();
    let round = render_settings_file(&doc).unwrap();
    assert!(
        round.contains("_comment"),
        "an edit must not eat it: {round}"
    );
}

#[test]
fn an_app_client_id_is_letters_digits_and_three_punctuation_marks() {
    assert_eq!(
        compile_app_client_id("client_id", "  4h9dq7k2m1n0p3r5s7t9v1w3  ").unwrap(),
        "4h9dq7k2m1n0p3r5s7t9v1w3"
    );
    // Empty is not a refusal here: whether an absent app client is a warning or an error
    // is the caller's question, and the two callers answer it differently.
    assert_eq!(compile_app_client_id("client_id", "   ").unwrap(), "");
    // The two shapes that would matter, and the reason the charset is this narrow: the
    // value is substituted into a JavaScript string literal on the sign-in page, into an
    // HTML attribute on a button, and into a query string on the way to Cognito.
    assert!(compile_app_client_id("client_id", "a\";alert(1);\"").is_err());
    assert!(compile_app_client_id("client_id", "two words").is_err());
    // The message names the setting the caller was talking about, because a table of app
    // clients has more than one and "app client id" alone would not say which.
    let e = compile_app_client_id("social_buttons 'Google': audience", "two words").unwrap_err();
    assert!(e.starts_with("social_buttons 'Google': audience"), "{e}");
}

#[test]
fn a_session_ttl_that_is_a_login_loop_is_refused() {
    for ttl in [0, 1, MIN_SESSION_TTL - 1] {
        let json = format!(r#"{{ "version": 3, "gate": {{ "session_ttl_secs": {ttl} }} }}"#);
        assert!(refusal(settings(&json)).contains("floor"), "{ttl}");
    }
    // The floor itself is fine, and so is a year.
    assert!(settings(r#"{ "version": 3, "gate": { "session_ttl_secs": 60 } }"#).is_ok());
    assert!(settings(r#"{ "version": 3, "gate": { "session_ttl_secs": 31536000 } }"#).is_ok());
}

#[test]
fn an_empty_provider_list_means_any_provider() {
    let s = settings(
        r#"{ "version": 3, "gate": { "allow_unverified_social": true,
                 "social_providers": [] } }"#,
    )
    .unwrap();
    assert!(s.allow_unverified_social);
    assert_eq!(
        s.social_providers, None,
        "empty must mean 'any', not 'none'"
    );

    let s = settings(
        r#"{ "version": 3, "gate": { "allow_unverified_social": true,
                 "social_providers": ["Google", " SignInWithApple "] } }"#,
    )
    .unwrap();
    assert_eq!(
        s.social_providers,
        Some(vec!["Google".to_string(), "SignInWithApple".to_string()])
    );
}

#[test]
fn an_admin_that_could_never_match_is_skipped_not_fatal() {
    // Fail-closed, the roster identifiers' own rule: one administrator fewer is the safe
    // direction to be wrong in, and a gate that refused to start over a list it never
    // reads would be a lockout caused by the GUI's half of the file.
    let s = settings(
        r#"{ "version": 3, "web": { "admins": ["Bob@X.com", "not an email", "",
                 "bob@x.com"] } }"#,
    )
    .unwrap();
    assert_eq!(
        s.admins,
        vec!["bob@x.com".to_string()],
        "normalised, deduped"
    );
    assert!(s.is_admin("bob@x.com"));
    assert!(!s.is_admin("eve@x.com"));
}

#[test]
fn the_ui_section_defaults_to_the_built_in_look() {
    // A file that says nothing about the look is the common case, and it must compile to
    // "no override anywhere": each page is complete on its own, and nothing is fetched.
    let s = settings(r#"{ "version": 3 }"#).unwrap();
    assert_eq!(s.stylesheet_url, None);
    assert_eq!(s.logo_url, None);
    assert_eq!(s.brand_name, None);
    assert_eq!(s.theme, UiTheme::System);
    assert_eq!(
        stylesheet_link(None),
        "",
        "nothing configured, nothing linked"
    );
}

#[test]
fn an_asset_url_is_absolute_https_or_root_relative_and_nothing_else() {
    let ok = |u: &str| compile_asset_url("stylesheet_url", u).unwrap();
    assert_eq!(ok(""), None, "empty is unset, not an error");
    assert_eq!(ok("   "), None);
    assert_eq!(
        ok("https://assets.x.com/css/theme.css"),
        Some("https://assets.x.com/css/theme.css".to_string())
    );
    assert_eq!(
        ok("/css/theme.css"),
        Some("/css/theme.css".to_string()),
        "same-vhost, which needs no hostname and no cross-origin CSP"
    );

    let bad = |u: &str| compile_asset_url("stylesheet_url", u).unwrap_err();
    // http: the page it lands on is https, so this is a mixed-content block at best.
    assert!(bad("http://assets.x.com/t.css").contains("absolute https"));
    // Protocol-relative: an absolute URL wearing a relative one's clothes.
    assert!(bad("//assets.x.com/t.css").contains("absolute https"));
    assert!(bad("theme.css").contains("absolute https"));
    assert!(bad("https:///t.css").contains("empty host"));
    assert!(bad("https://user@evil.x.com/t.css").contains("userinfo"));
    // The three that could break out of the attribute this value is emitted into.
    assert!(bad("https://x.com/a\"onload=alert(1)").contains("quote"));
    assert!(bad("https://x.com/a'b").contains("quote"));
    assert!(bad("https://x.com/<script>").contains("angle bracket"));
    assert!(bad("https://x.com/a\\b").contains("backslash"));
    assert!(bad("https://x.com/a b").contains("printable ASCII"));
    assert!(bad("https://x.com/a\nb").contains("printable ASCII"));
}

#[test]
fn a_link_is_escaped_even_though_the_url_was_already_validated() {
    // Belt and braces on purpose: "already validated" is a property of today's callers,
    // and escaping is a property of the emission.
    assert_eq!(
        stylesheet_link(Some("https://x.com/t.css?a=1&b=2")),
        r#"<link rel="stylesheet" href="https://x.com/t.css?a=1&amp;b=2">"#
    );
}

#[test]
fn a_brand_name_is_prose_with_a_bound() {
    assert_eq!(
        compile_brand_name("  BadBat75  ").unwrap(),
        Some("BadBat75".to_string())
    );
    assert_eq!(compile_brand_name("").unwrap(), None);
    // Accents and spaces are exactly what a real name has: this is not an identifier.
    assert_eq!(
        compile_brand_name("Società X").unwrap(),
        Some("Società X".to_string())
    );
    assert!(compile_brand_name("a\nb").unwrap_err().contains("control"));
    let long = "x".repeat(MAX_BRAND_NAME + 1);
    assert!(compile_brand_name(&long).unwrap_err().contains("longer"));
}

#[test]
fn a_misspelled_theme_is_refused_rather_than_quietly_system() {
    assert_eq!(UiTheme::parse("dark"), Some(UiTheme::Dark));
    assert_eq!(UiTheme::parse(" LIGHT "), Some(UiTheme::Light));
    // Blank in the FILE means "no preference", which is what System is.
    assert_eq!(UiTheme::parse(""), Some(UiTheme::System));
    assert_eq!(UiTheme::parse("darkk"), None);
    assert!(refusal(compile_settings(
        &serde_json::from_str(r#"{ "version": 3, "ui": { "theme": "darkk" } }"#).unwrap()
    ))
    .contains("not one of system, light, dark"));
    // System is the absence of a choice, and says so by emitting no attribute at all.
    assert_eq!(UiTheme::System.attr(), None);
    assert_eq!(UiTheme::Dark.attr(), Some("dark"));
}

#[test]
fn a_bad_look_refuses_the_file_rather_than_being_skipped() {
    // The claim list's reflex, for the same reason: a setting silently dropped is a
    // deployment that goes on looking wrong with nothing anywhere saying why. It cannot
    // lock anybody out, which is what earns it a place in this file; that is not the same
    // as being allowed to be wrong in silence.
    let e = refusal(settings(
        r#"{ "version": 3, "ui": { "stylesheet_url": "javascript:alert(1)" } }"#,
    ));
    assert!(e.contains("stylesheet_url"), "{e}");

    let s = settings(
        r#"{ "version": 3, "ui": { "stylesheet_url": "https://a.x.com/t.css",
                 "logo_url": "/img/l.png", "brand_name": "X", "theme": "dark" } }"#,
    )
    .unwrap();
    assert_eq!(s.stylesheet_url.as_deref(), Some("https://a.x.com/t.css"));
    assert_eq!(s.logo_url.as_deref(), Some("/img/l.png"));
    assert_eq!(s.brand_name.as_deref(), Some("X"));
    assert_eq!(s.theme, UiTheme::Dark);

    // An unknown key inside the section is refused, exactly as it is in the other two.
    assert!(settings(r#"{ "version": 3, "ui": { "stylesheet": "x" } }"#).is_err());
}

/// The hash a policy names has to be the hash a *browser* computes, and the difference
/// between the two is invisible from inside this crate.
///
/// An HTML parser normalises the document's newlines before the CSP check ever runs, so a
/// browser hashes the block with every CRLF already collapsed. This repository is
/// developed on a CRLF checkout (`core.autocrlf=true`), `include_str!` embeds the
/// stylesheets exactly as they sit on disk, and the release is cross-compiled from that
/// same tree: hashing the raw bytes ships a binary whose every page carries a policy that
/// refuses its own stylesheet, with nothing in any log and nothing in a test that only
/// compares this function against itself. Hence the literal below rather than a
/// round trip.
#[test]
fn a_hash_names_the_newlines_a_browser_sees_and_not_the_ones_on_disk() {
    let crlf = "a{color:red}\r\nb{color:blue}\r\n";
    let lf = "a{color:red}\nb{color:blue}\n";
    assert_eq!(csp_hash(crlf), csp_hash(lf));
    assert_eq!(
        csp_hash(lf),
        "'sha256-S20dnUqfVjBZxb8Zswwd1Uxqocz3m5nEgSQSEQdyC7w='"
    );
}

#[test]
fn the_theme_defines_every_token_in_all_four_arms() {
    // The dark list is written twice on purpose (see theme.css), and the two copies have
    // to stay in step by hand. This is what notices when one of them does not.
    let arms: Vec<&str> = THEME_CSS.split("--bg:").collect();
    assert_eq!(arms.len(), 4, "one light arm and two dark ones define --bg");
    for token in [
        // `--bg-grad:` does not contain `--bg:`, so the split above does not see it and it
        // has to be listed here like any other. It is in the list at all because the ground
        // is now a gradient in both arms: a dark arm that forgot it would paint the light
        // theme's gradient over the dark theme's fill.
        "--bg-grad:",
        "--card:",
        "--card-border:",
        "--text:",
        "--muted:",
        "--input-bg:",
        "--input-border:",
        "--accent:",
        "--accent-hover:",
        "--accent-weak:",
        "--on-accent:",
        "--ok:",
        "--ok-bg:",
        "--warn:",
        "--warn-bg:",
        "--error:",
        "--error-bg:",
        "--on-state:",
        "--chip:",
        "--logo-filter:",
        "--shadow-lg:",
        "--shadow-md:",
    ] {
        assert_eq!(
            THEME_CSS.matches(token).count(),
            3,
            "{token} must be defined in the light arm and in both dark arms"
        );
    }
    // Shape and typography are theme-independent and defined exactly once, in the light
    // arm: a radius does not change with the palette.
    for token in [
        "--r-box:",
        "--r-ctl:",
        "--r-pill:",
        "--fs-sm:",
        "--font-ui:",
        "--font-mono:",
    ] {
        assert_eq!(
            THEME_CSS.matches(token).count(),
            1,
            "{token} is not a colour"
        );
    }
    // The selectors that make an explicit choice outrank the OS.
    assert!(THEME_CSS.contains(":root[data-theme=dark]"));
    assert!(THEME_CSS.contains(":root[data-theme=light]"));
    assert!(THEME_CSS.contains("@media (prefers-color-scheme:dark){:root:not([data-theme=light])"));
}

/// Everything a CSS comment says, removed. The prose in all four stylesheets talks about
/// colours by name and by hex on purpose, so a scan that did not strip comments would be
/// a scan of the documentation.
#[cfg(test)]
fn without_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(open) = rest.find("/*") {
        out.push_str(&rest[..open]);
        match rest[open..].find("*/") {
            Some(close) => rest = &rest[open + close + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Every rule of a stylesheet as `(selector, declarations)`, comments and all whitespace
/// removed. A rule inside an at-rule reports its own selector. Good enough for this
/// project's flat stylesheets, which is all it is used on.
#[cfg(test)]
fn flat_rules(css: &str) -> Vec<(String, String)> {
    let code: String = without_comments(css)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut rules = Vec::new();
    for chunk in code.split('}') {
        let parts: Vec<&str> = chunk.split('{').collect();
        if parts.len() >= 2 {
            rules.push((
                parts[parts.len() - 2].to_string(),
                parts[parts.len() - 1].to_string(),
            ));
        }
    }
    rules
}

/// The four arms of `THEME_CSS`, each as the declarations between its braces:
/// light (`:root`), the dark media arm, and the explicit `data-theme` dark arm.
/// The explicit light arm only sets `color-scheme` and is not an arm of values.
#[cfg(test)]
fn theme_arms() -> Vec<(&'static str, String)> {
    let code = without_comments(THEME_CSS);
    let light_start = code.find(":root{").expect("light arm");
    let light_end = code[light_start..].find("\n}").expect("light end") + light_start;
    let media = code
        .find("@media (prefers-color-scheme:dark)")
        .expect("media arm");
    let media_end = code[media..].find("}}").expect("media end") + media;
    let dark = code.find(":root[data-theme=dark]{").expect("dark arm");
    let dark_end = code[dark..].find("\n}").expect("dark end") + dark;
    vec![
        ("light", code[light_start..light_end].to_string()),
        ("dark (media)", code[media..media_end].to_string()),
        ("dark (explicit)", code[dark..dark_end].to_string()),
    ]
}

/// The value a custom property takes inside one arm's text.
#[cfg(test)]
fn arm_value(arm: &str, token: &str) -> String {
    let needle = format!("{token}:");
    let at = arm
        .find(&needle)
        .unwrap_or_else(|| panic!("{token} missing in arm"));
    let rest = &arm[at + needle.len()..];
    rest[..rest.find(';').unwrap()].trim().to_string()
}

#[cfg(test)]
fn hex_luminance(hex: &str) -> f64 {
    let h = hex.trim().trim_start_matches('#');
    assert_eq!(h.len(), 6, "expected #rrggbb, got {hex}");
    let ch = |i: usize| {
        let v = f64::from(u8::from_str_radix(&h[i..i + 2], 16).unwrap()) / 255.0;
        if v <= 0.03928 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * ch(0) + 0.7152 * ch(2) + 0.0722 * ch(4)
}

#[cfg(test)]
fn contrast(a: &str, b: &str) -> f64 {
    let (la, lb) = (hex_luminance(a), hex_luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// The theme contract of slice 8d: the set of custom properties `THEME_CSS` defines is
/// fixed, so an operator's token file written against today's names keeps working. A
/// rename or a removal is red; so is a new name, which would be a contract change that
/// needs the design's say-so first. Green today and meant to stay green.
#[test]
fn the_token_set_is_the_contract() {
    let code = without_comments(THEME_CSS);
    let mut found: std::collections::BTreeSet<String> = Default::default();
    let bytes = code.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if &bytes[i..i + 2] == b"--" && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let rest = &code[i..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .unwrap();
            if rest[end..].starts_with(':') {
                found.insert(rest[..end].to_string());
            }
            i += end.max(2);
        } else {
            i += 1;
        }
    }
    let expected: std::collections::BTreeSet<String> = [
        "--bg",
        "--bg-grad",
        "--card",
        "--card-border",
        "--text",
        "--muted",
        "--input-bg",
        "--input-border",
        "--accent",
        "--accent-hover",
        "--accent-weak",
        "--on-accent",
        "--ok",
        "--ok-bg",
        "--warn",
        "--warn-bg",
        "--error",
        "--error-bg",
        "--on-state",
        "--chip",
        "--logo-filter",
        "--shadow-lg",
        "--shadow-md",
        "--r-box",
        "--r-ctl",
        "--r-pill",
        "--fs-sm",
        "--font-ui",
        "--font-mono",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(expected.len(), 29);
    assert_eq!(
        found, expected,
        "THEME_CSS must define exactly the 29 contract tokens"
    );
}

/// WCAG 2.2 SC 1.4.11: the boundary of a field must be 3:1 against what it sits on, which
/// is the card (or the page) around it and its own fill. All four arms are read, because
/// the dark list is written twice and an edit to one copy is easy to miss.
#[test]
fn fields_have_a_three_to_one_border_in_every_arm() {
    let arms = theme_arms();
    assert_eq!(
        arms.len(),
        3,
        "light, dark media, dark explicit (the 4th sets no values)"
    );
    for (name, arm) in &arms {
        let border = arm_value(arm, "--input-border");
        for neighbour in ["--card", "--input-bg", "--bg"] {
            let other = arm_value(arm, neighbour);
            let ratio = contrast(&border, &other);
            // The page behind a light field is only the outer neighbour, so it is
            // held to the same bar as the card the field normally sits on.
            assert!(
                ratio >= 3.0,
                "{name}: --input-border {border} on {neighbour} {other} is {ratio:.2}:1, needs 3:1"
            );
        }
    }
}

/// The glow behind a page is painted once at the top. Without `no-repeat` it starts again
/// one viewport down, a hard band across any page longer than the window.
#[test]
fn the_ground_is_painted_once() {
    let body = flat_rules(BASE_CSS)
        .into_iter()
        .find(|(sel, _)| sel == "body")
        .expect("base.css has a body rule");
    assert!(
        body.1
            .contains("background:var(--bg-grad)no-repeat,var(--bg)"),
        "body background must read `var(--bg-grad) no-repeat,var(--bg)`, got {}",
        body.1
    );
}

/// A shadow says "this floats above the page". The surfaces in normal flow carry none; the
/// sign-in card and the preferences menu, which do float, name theirs.
#[test]
fn only_floating_surfaces_cast_a_shadow() {
    let surface = ".card,.panel,.msg,.flash,.err,.secret";
    let base = flat_rules(BASE_CSS);
    let rule = base
        .iter()
        .find(|(sel, _)| sel == surface)
        .expect("the shared surface rule");
    assert!(
        rule.1.contains("box-shadow:none"),
        "surface rule: {}",
        rule.1
    );

    let auth = include_str!("assets/auth.css");
    let admin = include_str!("assets/admin.css");
    for (file, css) in [
        ("base.css", BASE_CSS),
        ("auth.css", auth),
        ("admin.css", admin),
    ] {
        for (sel, decls) in flat_rules(css) {
            for token in ["var(--shadow-lg)", "var(--shadow-md)"] {
                if decls.contains(token) {
                    let allowed = (file == "auth.css"
                        && sel == ".card"
                        && token == "var(--shadow-lg)")
                        || (file == "admin.css" && sel == ".menu" && token == "var(--shadow-md)");
                    assert!(allowed, "{file}: `{sel}` casts {token}; only auth .card (lg) and admin .menu (md) may");
                }
            }
        }
    }
    assert!(flat_rules(auth)
        .iter()
        .any(|(s, d)| s == ".card" && d.contains("box-shadow:var(--shadow-lg)")));
    assert!(flat_rules(admin)
        .iter()
        .any(|(s, d)| s == ".menu" && d.contains("box-shadow:var(--shadow-md)")));
}

/// The declarations of every rule whose selector list names `selector` (whitespace-free,
/// as [`flat_rules`] spells it), in file order. A rule inside a `@media` block counts.
#[cfg(test)]
fn rules_named(css: &str, selector: &str) -> Vec<String> {
    flat_rules(css)
        .into_iter()
        .filter(|(sel, _)| sel.split(',').any(|s| s == selector))
        .map(|(_, d)| d)
        .collect()
}

/// §13.18 (8e): the type scale. `h1` 1.5rem / 1.25 / 650 / -.01em, `h2` 1.0625rem / 600,
/// with the margins the section gives (`flat_rules` strips whitespace, hence `margin:006px`).
#[test]
fn the_headings_follow_the_type_scale() {
    let h1 = rules_named(BASE_CSS, "h1");
    assert_eq!(h1.len(), 1, "one `h1` rule");
    for want in [
        "font-size:1.5rem",
        "line-height:1.25",
        "font-weight:650",
        "letter-spacing:-.01em",
        "margin:006px",
    ] {
        assert!(h1[0].contains(want), "h1 lacks {want}: {}", h1[0]);
    }
    let h2 = rules_named(BASE_CSS, "h2");
    assert_eq!(h2.len(), 1, "one `h2` rule");
    for want in ["font-size:1.0625rem", "font-weight:600", "margin:28px010px"] {
        assert!(h2[0].contains(want), "h2 lacks {want}: {}", h2[0]);
    }
}

/// §13.18 (8d-2): the secondary pill is neutral. Text `--text`, a 3:1 `--input-border` box,
/// and the accent fill belongs to `.pill.on` alone.
#[test]
fn the_secondary_pill_is_neutral() {
    let pill = rules_named(BASE_CSS, ".pill");
    assert_eq!(pill.len(), 1, "one `.pill` rule");
    assert!(pill[0].contains("color:var(--text)"), "text: {}", pill[0]);
    assert!(
        pill[0].contains("var(--input-border)"),
        "border: {}",
        pill[0]
    );
    assert!(!pill[0].contains("currentColor"), "border: {}", pill[0]);
    assert!(
        !pill[0].contains("color:var(--accent)"),
        "text: {}",
        pill[0]
    );
    for (sel, decls) in flat_rules(BASE_CSS) {
        if sel.contains(".pill") && decls.contains("background:var(--accent)") {
            assert_eq!(sel, ".pill.on,.pill.on:hover", "only .pill.on fills accent");
        }
    }
    let hover = rules_named(BASE_CSS, ".pill:hover");
    assert!(
        hover.iter().any(|d| d.contains("background:var(--chip)")
            && d.contains("border-color:var(--accent)")
            && d.contains("color:var(--accent)")),
        "hover: {hover:?}"
    );
}

/// §13.18 (8d-2): a pill in a `nav` is a tab, with no visible box at rest.
#[test]
fn a_pill_in_a_nav_is_a_tab() {
    let tab = rules_named(BASE_CSS, "nav.pill");
    assert_eq!(tab.len(), 1, "a `nav .pill` rule in BASE_CSS");
    assert!(tab[0].contains("var(--card)"), "box: {}", tab[0]);
    assert!(!tab[0].contains("var(--card-border)"), "box: {}", tab[0]);
    assert!(tab[0].contains("color:var(--muted)"), "text: {}", tab[0]);
    let hover = rules_named(BASE_CSS, "nav.pill:hover");
    assert!(
        hover.iter().any(|d| d.contains("background:var(--chip)")),
        "hover: {hover:?}"
    );
}

/// §13.18 (8d-2): links in a table cell or a list item are plain at rest and underlined
/// on hover.
#[test]
fn table_links_underline_on_hover() {
    for at_rest in ["tda", "lia"] {
        let rest = rules_named(BASE_CSS, at_rest);
        assert!(
            rest.iter().any(|d| d.contains("text-decoration:none")),
            "`{at_rest}` has no text-decoration:none rule"
        );
        let hover = rules_named(BASE_CSS, &format!("{at_rest}:hover"));
        assert!(
            hover
                .iter()
                .any(|d| d.contains("text-decoration:underline")),
            "`{at_rest}:hover` has no underline rule"
        );
    }
}

/// §13.18 (8d-2), `admin.css`: the bar shares `main`'s column, the header's pills are
/// tabs and not buttons, a pill beside a button has the button's measure, and the tiles
/// fill one row.
///
/// §13.26 (5g): the account page is the console's width, so the bar shares *one* column and
/// nothing narrows it for one surface. The `.selfserve` width rules are gone, and the
/// reading measure that replaces them (`main p.lede` at 75ch, a profile field at 40ch) is
/// asserted here because it is the rule that keeps a 1000px column readable on both pages.
///
/// §13.26 ("F. The flat ground"): the body override that painted this page's ground flat is
/// gone too, so the bare `body:has(.selfserve)` rule joins the forbidden list. The account
/// page wears the estate's ground, and `rules_named` matches one part of a selector list
/// exactly (whitespace-free), so the rule is named by its own spelling.
#[test]
fn the_header_shares_the_content_column() {
    let admin = include_str!("assets/admin.css");
    let has = |sel: &str, want: &str| {
        let rules = rules_named(admin, sel);
        assert!(
            rules.iter().any(|d| d.contains(want)),
            "`{sel}` lacks `{want}` (rules: {rules:?})"
        );
    };
    has("header.top", "padding:10px0");
    has("header.top", "padding:6px0");
    has(".bar", "padding:016px");
    for gone in [
        ".selfserve",
        "body:has(.selfserve)",
        "body:has(.selfserve).bar",
        ".selfserve.panelh2",
    ] {
        assert!(
            rules_named(admin, gone).is_empty(),
            "`{gone}` must be gone: the account page is the console's column and wears the \
                 estate's ground, and a rule naming `.selfserve` alone is the drift §13.26 \
                 deletes ({:?})",
            rules_named(admin, gone)
        );
    }
    // `rules_named` matches one part of a selector list at a time, so each arm of the
    // measure is looked up on its own, and both must land on the same one rule (that is
    // the point of one rule for both surfaces).
    for arm in ["mainp.lede", "mainp.muted"] {
        let rules = rules_named(admin, arm);
        assert_eq!(rules.len(), 1, "`{arm}` needs exactly one rule: {rules:?}");
        assert!(
            rules[0].contains("max-width:75ch"),
            "`{arm}` lacks the reading measure: {}",
            rules[0]
        );
    }
    has("input.f-profile", "max-width:40ch");
    // §13.23: the profile code field is a short numeric token, so it wears the short-id
    // measure and not the 40ch one above it: a full-width box reads as "type a sentence".
    has("input.f-code", "max-width:14ch");
    has(".bar.pill", "font-size:.95rem");
    has(".bar.pill", "padding:6px12px");
    has(".bar.pill.ico", "padding:6px");
    has("p.primary.pill", "font-size:inherit");
    has("p.primary.pill", "line-height:1.55");
    has("p.primary.pill", "padding:9px16px");
    has(".actions.pill", "line-height:1.55");
    has(".actions.pill", "padding:9px16px");
    has(".cards", "repeat(auto-fill,minmax(140px,1fr))");
}

/// A surface owns its padding, so its first child's top margin and its last child's bottom
/// margin do not add an empty band inside it.
#[test]
fn a_surface_owns_its_padding() {
    let rules = flat_rules(BASE_CSS);
    for (child, decl) in [
        (":first-child", "margin-top:0"),
        (":last-child", "margin-bottom:0"),
    ] {
        let found = rules.iter().any(|(sel, decls)| {
            [".card", ".panel", ".msg", ".flash", ".err", ".secret"]
                .iter()
                .all(|s| sel.split(',').any(|part| part == format!("{s}>{child}")))
                && decls.contains(decl)
        });
        assert!(
            found,
            "base.css needs one rule over all six surfaces: `>{child}{{{decl}}}`"
        );
    }
}

/// §13.21 (3): a ticked radio or checkbox wears the palette's accent, not the engine's
/// own blue.
#[test]
fn ticks_wear_the_accent() {
    // `rules_named` matches one selector of a list at a time, so each kind is looked up
    // on its own and must find the same single rule.
    for kind in ["input[type=radio]", "input[type=checkbox]"] {
        let rules = rules_named(BASE_CSS, kind);
        assert_eq!(rules.len(), 1, "one rule tints `{kind}`");
        assert!(
            rules[0].contains("accent-color:var(--accent)"),
            "the tint of `{kind}` is the accent token: {}",
            rules[0]
        );
    }
}

#[test]
fn only_the_palette_names_a_colour() {
    // The contract that makes `ui.stylesheet_url` a TOKEN file: a deployment restyles both
    // programs by redefining custom properties, which only works while every other
    // stylesheet reads them and states none of its own. One literal in a layout and that
    // stops being true for whatever it paints, silently and only in one of the two
    // surfaces — the exact failure this is here to catch.
    //
    // Both layouts are checked here, in the library, and not each in its own binary,
    // because the rule is not "this layout is tidy": it is that the shared files are the
    // ONLY answer to what a colour is worth, which is a statement about all of them at
    // once and belongs where the shared files live.
    for (name, css) in [
        ("base.css", BASE_CSS),
        (
            "auth.css (the gate's layout)",
            include_str!("assets/auth.css"),
        ),
        (
            "admin.css (bb-auth-web's layout)",
            include_str!("assets/admin.css"),
        ),
    ] {
        let code = without_comments(css);
        assert!(
            !code.contains('#'),
            "{name} names a colour by hex; it may only read one from theme.css"
        );
        // Every other way CSS has of writing a colour, not just `rgb`. The scan used to
        // be `#` and `rgb`, which let `hsl()`, `oklch()`, `color-mix()` and the 148 named
        // colours through: a rule that only catches the spelling somebody happened to
        // think of is a rule that stops holding the first time somebody writes it
        // differently.
        for how in [
            "rgb(",
            "rgba(",
            "hsl(",
            "hsla(",
            "hwb(",
            "lab(",
            "lch(",
            "oklab(",
            "oklch(",
            "color(",
            "color-mix(",
            "light-dark(",
        ] {
            assert!(
                !code.contains(how),
                "{name} names a colour with {how}; it may only read one from theme.css"
            );
        }
        // The named colours worth naming: the ones somebody actually reaches for, and
        // `transparent` and `currentColor` deliberately not among them (neither is a
        // colour a token file could have supplied instead).
        for named in [
            ":white", ":black", ":red", ":green", ":blue", ":gray", ":grey", ":silver", ":orange",
            ":yellow", ":purple", ":pink", ":brown", ":navy", ":teal", ":lime", ":aqua", ":cyan",
            ":magenta", ":gold", ":crimson",
        ] {
            assert!(
                !code.replace(' ', "").contains(named),
                "{name} names the colour {named}; it may only read one from theme.css"
            );
        }
    }
}

#[test]
fn the_components_are_shared_and_the_layouts_only_arrange_them() {
    // What "one product" means mechanically: the objects a person operates are defined
    // once, in the file both programs emit, so a change to a button's shape or a field's
    // height cannot reach one surface and miss the other. The four below are the ones that
    // had actually drifted when this was written — the sign-in page's rectangles against
    // the admin's lozenges, its 12px fields against the admin's 7px ones.
    for object in ["button{", ".pill{", ".tag{", ".card,.panel,"] {
        assert!(
            BASE_CSS.contains(object),
            "{object} belongs to the shared component layer"
        );
    }
    // And the negative half, which is the one that rots: a layout that starts redefining a
    // control has taken it back, and only its own program will ever see the change.
    //
    // A TOP-LEVEL rule is what that looks like: a selector at column zero. An indented one
    // is inside a media query, where a layout adjusting a control's padding at a
    // breakpoint is arrangement and is allowed (`admin.css` does exactly that, on
    // purpose). The whitespace before the brace is normalised, because `button {` and
    // `button{` are the same rule and the previous scan for `"\nbutton{"` saw only the
    // second: a rule a reformat can switch off is not a rule.
    for (name, css) in [
        ("admin.css", include_str!("assets/admin.css")),
        ("auth.css", include_str!("assets/auth.css")),
    ] {
        for line in without_comments(css).lines() {
            if line.starts_with(char::is_whitespace) {
                continue;
            }
            let flat: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            for selector in ["button{", ".pill{", ".tag{"] {
                assert!(
                    !flat.starts_with(selector),
                    "{name} redefines {selector} at the top level: a layout may arrange \
                         the shared controls, never redefine one"
                );
            }
        }
    }
}

/// The two settings a deployment can point at another host, and the policy that has to
/// let them through.
///
/// This is the pairing with something to get wrong. `ui.stylesheet_url` and
/// `ui.logo_url` are the only external references either program emits, and the same
/// two values feed the `<link>`/`<img>` and the policy that decides whether the browser
/// will fetch them. Derive the policy from anything but those values and a deployment
/// with a logo gets a page that renders without one, with nothing in the response to say
/// why: the header is present, the element is present, and the browser refuses.
///
/// Three shapes each, because [`compile_asset_url`] admits exactly three: an absolute
/// `https://` URL (its origin joins the policy), a root-relative path (`'self'` does),
/// and unset (nothing does, and the built-in stylesheet stands alone).
#[test]
fn the_policy_admits_exactly_the_asset_hosts_the_settings_name() {
    let csp = |style: Option<&str>, logo: Option<&str>| {
        page_csp("'nonce-N'", "'nonce-N'", "'self'", style, logo, &[])
    };

    // Neither set: nothing external may load, and an image may still be a data: URI,
    // which cannot script and is the one way a logo travels inside the page.
    let none = csp(None, None);
    assert!(none.contains("style-src 'nonce-N';"), "{none}");
    assert!(none.contains("img-src data:;"), "{none}");
    // No font at all: the built-in CSS names system faces and fetches nothing.
    assert!(none.contains("font-src 'none';"), "{none}");

    // Both on another host: that origin, and only that origin, joins the two lists.
    let both = csp(
        Some("https://assets.badbat75.com/css/theme.css"),
        Some("https://assets.badbat75.com/img/logo.svg"),
    );
    assert!(
        both.contains("style-src 'nonce-N' https://assets.badbat75.com;"),
        "the stylesheet's origin must be in style-src: {both}"
    );
    assert!(
        both.contains("img-src https://assets.badbat75.com data:;"),
        "the logo's origin must be in img-src: {both}"
    );
    // A stylesheet may bring its own @font-face, from where it came from and nowhere
    // else. Here that is the same host as the logo, so the mixed case below is the one
    // that pins which of the two settings font-src actually follows.
    assert!(
        both.contains("font-src https://assets.badbat75.com data:;"),
        "the stylesheet's origin must be in font-src: {both}"
    );
    // The path is NOT in the policy: a source expression is an origin, and carrying the
    // path would stop the next file on that host from loading.
    assert!(!both.contains("/css/theme.css"), "{both}");
    assert!(!both.contains("/img/logo.svg"), "{both}");

    // Root-relative, which is the better answer when the same vhost serves them: the
    // page's own origin, spelled the way a policy spells it.
    let own = csp(Some("/css/theme.css"), Some("/img/logo.svg"));
    assert!(own.contains("style-src 'nonce-N' 'self';"), "{own}");
    assert!(own.contains("img-src 'self' data:;"), "{own}");

    // One of each, which is an ordinary deployment: a shared asset host for the
    // stylesheet, the logo served beside the page.
    let mixed = csp(Some("https://cdn.example.com/t.css"), Some("/logo.png"));
    assert!(
        mixed.contains("style-src 'nonce-N' https://cdn.example.com;"),
        "{mixed}"
    );
    assert!(mixed.contains("img-src 'self' data:;"), "{mixed}");
    // font-src follows the STYLESHEET and not the logo: the typeface travels with the
    // file that asks for it.
    assert!(
        mixed.contains("font-src https://cdn.example.com data:;"),
        "{mixed}"
    );

    // A logo but no stylesheet: an image host, and still no font anywhere.
    let logo_only = csp(None, Some("https://assets.badbat75.com/logo.svg"));
    assert!(logo_only.contains("font-src 'none';"), "{logo_only}");

    // A host with a port keeps it, since an origin is scheme, host AND port.
    let port = csp(Some("https://assets.internal:8443/t.css"), None);
    assert!(
        port.contains("style-src 'nonce-N' https://assets.internal:8443;"),
        "{port}"
    );
}

/// Where a form may end up, which is a different question from where it posts, and the
/// one a hardcoded `'self'` got wrong for every Chromium login in this estate.
///
/// The two spellings of a cookie domain must give one answer: RFC 6265 ignores the
/// leading dot, so a file that writes it and a file that does not describe the same set of
/// hosts, and a directive that disagreed with the cookie would let a login land somewhere
/// the session does not reach (or, as it did, stop one landing where it does).
#[test]
fn the_form_action_is_the_estate_the_cookie_already_covers() {
    // The dot is the operator's spelling and not a source expression: what goes into the
    // policy is the domain and a wildcard for what is under it.
    let dotted = estate_form_action(Some(".badbat75.com"));
    assert_eq!(
        dotted, "'self' https://badbat75.com https://*.badbat75.com",
        "a leading dot must not reach the policy"
    );
    assert_eq!(estate_form_action(Some("badbat75.com")), dotted);

    // The apex is listed beside the wildcard because a CSP `*.x.com` does not match
    // `x.com`, exactly as `compile_host_pattern` does not: the gate's own host is often
    // the apex, and a login that lands there would be the same failure again.
    assert!(dotted.contains("https://badbat75.com "), "{dotted}");

    // No domain at all is a host-only cookie, so there is no second host a session could
    // survive to and nothing here worth permitting.
    assert_eq!(estate_form_action(None), "'self'");
    assert_eq!(estate_form_action(Some("")), "'self'");

    // And it reaches the emitted policy rather than only the helper, which is the half a
    // unit test of the helper alone would leave unproven.
    let live = page_csp(
        "'none'",
        "'none'",
        &estate_form_action(Some(".badbat75.com")),
        None,
        None,
        &[],
    );
    assert!(
        live.contains("form-action 'self' https://badbat75.com https://*.badbat75.com;"),
        "{live}"
    );
}

/// Every symbol the operating manual pins a rule to still exists.
///
/// `cargo doc` catches a broken intra-doc link, which the manual calls the cheapest rot
/// detector this repository has; Markdown is exactly where it cannot look. Three names
/// in `AGENTS.md` had already stopped existing (`bearer_apikey_email`,
/// `authorize_identity` twice), and each of them was a rule pointing at a function
/// nobody could find, in the file that is supposed to be the single source of the rules.
///
/// The scan is deliberately narrow: a backticked token that looks like a Rust identifier
/// (`snake_case` with an underscore, or `CamelCase`), inside the Invariants section and
/// the deploy notes that follow it, which is where the rules live. A word that is not a
/// symbol is not one of those shapes, and a symbol that is genuinely gone shows up as a
/// name that appears nowhere in `src/`.
#[test]
fn every_symbol_the_manual_names_still_exists() {
    const MANUAL: &str = include_str!("../AGENTS.md");
    // The sources, plus the two files that hold the other things the manual pins a
    // rule to: a cargo feature (`rust_crypto`) and the unit directives the hardening
    // argument is made of (`ReadOnlyPaths`, `ReadWritePaths`, `SupplementaryGroups`).
    // Those are as real as a function, and as able to stop existing.
    let src = format!(
        "{}{}{}{}{}{}{}{}{}{}",
        include_str!("lib.rs"),
        include_str!("tests.rs"),
        include_str!("bin/bb-auth/main.rs"),
        include_str!("bin/bb-auth/tests.rs"),
        include_str!("bin/bb-auth-adm/main.rs"),
        include_str!("bin/bb-auth-adm/tests.rs"),
        include_str!("bin/bb-auth-web.rs"),
        include_str!("../Cargo.toml"),
        include_str!("../deploy/bb-auth.service"),
        include_str!("../deploy/bb-auth-web.service"),
    );
    let rules = MANUAL
        .split_once("## Invariants")
        .expect("the manual has an Invariants section")
        .1;

    let is_snake = |t: &str| {
        t.contains('_')
            && t.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && t.starts_with(|c: char| c.is_ascii_lowercase())
    };
    let is_camel = |t: &str| {
        t.len() > 3
            && t.starts_with(|c: char| c.is_ascii_uppercase())
            && t.bytes().all(|b| b.is_ascii_alphanumeric())
            && t.bytes().any(|b| b.is_ascii_lowercase())
            && t.bytes().skip(1).any(|b| b.is_ascii_uppercase())
    };

    let mut missing: Vec<&str> = Vec::new();
    for (i, chunk) in rules.split('`').enumerate() {
        // Odd indices are the insides of a backtick pair.
        if i % 2 == 0 {
            continue;
        }
        // A call or a path in the prose: `decide_api_key(…)`, `Access::resolve`.
        let token = chunk
            .split(['(', ':', '.', '/', ' ', '<', '['])
            .next()
            .unwrap_or("");
        if !(is_snake(token) || is_camel(token)) {
            continue;
        }
        // Somebody else's vocabulary, named in the manual because the rule is about
        // their configuration: nginx's, here. The list is short on purpose, and a name
        // joins it only when the thing it names is genuinely not ours.
        if ["default_server", "StateDirectory"].contains(&token) {
            continue;
        }
        // Env vars and file names are not symbols; neither is a JSON field, but those
        // appear in `src/` as string literals anyway, so they cost nothing.
        if !src.contains(token) {
            missing.push(token);
        }
    }
    missing.sort_unstable();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "AGENTS.md names symbols that no longer exist in src/: {missing:?}"
    );
}

/// The half of the writer that a wrong answer locks the service out over.
///
/// The live access file is `bb-auth-web:bb-auth 0640` (or `root:bb-auth` on a host with
/// no GUI), and the gate reads it as a group member. A rewrite that reset the mode would
/// leave the gate unable to read its own access list, which is a fatal startup and, under
/// `Restart=on-failure`, a boot loop. The manual calls that out twice and nothing
/// exercised it.
///
/// Unix only, because a mode is what is being asserted. The owner half cannot be tested
/// without two uids to move between, so what is pinned here is the mode and the fact that
/// a *failed* write leaves the original byte-identical.
#[cfg(unix)]
#[test]
fn a_write_preserves_the_mode_it_replaces() {
    use std::os::unix::fs::PermissionsExt;
    let p = std::env::temp_dir().join("bb-auth-mode-test.json");
    let path = p.to_str().unwrap().to_string();
    let doc = AccessFile {
        version: ACCESS_FILE_VERSION,
        ..Default::default()
    };
    std::fs::write(&p, "{}").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();

    assert!(AccessWrite::prepare(&doc).unwrap().commit(&path).is_ok());
    let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640, "the replacement must inherit the mode");

    // A mode nobody would choose, to prove it is inherited rather than defaulted.
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(AccessWrite::prepare(&doc).unwrap().commit(&path).is_ok());
    let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{path}.bak"));
}

/// A write to a path that cannot be written leaves the original untouched, which is what
/// "nothing is renamed, and the old file stays intact" means in practice.
#[test]
fn a_failed_write_leaves_the_original_byte_identical() {
    let dir = std::env::temp_dir().join("bb-auth-nowhere-at-all");
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("access.json").to_str().unwrap().to_string();
    let doc = AccessFile {
        version: ACCESS_FILE_VERSION,
        ..Default::default()
    };
    // The directory does not exist, so the `stat` of the file to replace fails first.
    let e = match AccessWrite::prepare(&doc).unwrap().commit(&path) {
        Ok(_) => panic!("a write into a directory that does not exist must fail"),
        Err(e) => e,
    };
    assert!(e.contains("stat"), "{e}");
}

/// `create` is the only way a first file is written, and it refuses to touch one that is
/// already there: the two `init` commands used to do that with an `exists()` check of
/// their own, one line before a truncating write.
#[test]
fn create_refuses_a_file_that_already_exists() {
    let p = std::env::temp_dir().join("bb-auth-create-test.json");
    let path = p.to_str().unwrap().to_string();
    let _ = std::fs::remove_file(&p);
    let doc = AccessFile {
        version: ACCESS_FILE_VERSION,
        ..Default::default()
    };
    let w = AccessWrite::prepare(&doc).unwrap();
    w.create(&path).expect("the first create makes the file");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), w.json());
    let e = w.create(&path).unwrap_err();
    assert!(e.contains("already exists"), "{e}");
    // And it is still the file the first call wrote.
    assert_eq!(std::fs::read_to_string(&p).unwrap(), w.json());
    let _ = std::fs::remove_file(&p);
}

#[test]
fn settings_write_compiles_the_exact_bytes_it_would_write() {
    // The access file's rule, for the other file: what is checked is the byte string that
    // lands on disk, not the document it came from.
    let mut doc = SettingsFile {
        version: SETTINGS_VERSION,
        ..Default::default()
    };
    doc.gate.profile_claims = claims("given_name");
    let w = SettingsWrite::prepare(&doc).unwrap();
    assert!(w.json().ends_with("}\n"), "one trailing newline");
    assert_eq!(w.settings().profile_claims[0].header, "X-Auth-Given-Name");
    // And the round trip is exact.
    let back: SettingsFile = serde_json::from_str(w.json()).unwrap();
    assert_eq!(back.gate, doc.gate);

    // A document the gate would refuse never becomes bytes.
    doc.gate.identity_attrs = Vec::new();
    assert!(refusal(SettingsWrite::prepare(&doc)).contains("at least one"));
}

#[test]
fn the_settings_file_sits_beside_the_access_file() {
    assert_eq!(
        default_settings_path("/opt/bb-auth/var/lib/access.json"),
        "/opt/bb-auth/var/lib/settings.json"
    );
    // A bare name has no directory to inherit, and must not grow one.
    assert_eq!(default_settings_path("access.json"), "settings.json");
    // The separator the operator wrote is the separator that comes back.
    assert_eq!(
        default_settings_path(r"C:\tmp\access.json"),
        r"C:\tmp\settings.json"
    );
}

// --- the audit file -----------------------------------------------------

/// A fresh audit path of its own, so these tests run in parallel like the rest.
fn audit_tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("bb-auth-audit-{name}.jsonl"));
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(audit_previous(&p));
    p
}

fn login(ts: u64, who: &str) -> AuditEvent {
    AuditEvent::new(ts, AuditKind::LoginGranted, AuditCredential::Local).by(who, None)
}

/// Append under the policy a settings file that says nothing gets.
fn put(w: &AuditWriter, ev: AuditEvent) {
    w.record(&ev, &AuditPolicy::default()).unwrap();
}

#[test]
fn the_audit_reads_back_newest_first() {
    let p = audit_tmp("order");
    let w = AuditWriter::new(&p);
    for (i, who) in ["a@x.com", "b@x.com", "c@x.com"].iter().enumerate() {
        put(&w, login(100 + i as u64, who));
    }
    let page = read_audit(&p, None, 100).unwrap();
    let seen: Vec<&str> = page
        .events
        .iter()
        .map(|e| e.subject.as_deref().unwrap())
        .collect();
    assert_eq!(seen, ["c@x.com", "b@x.com", "a@x.com"]);
    assert!(!page.more);
    assert_eq!(page.damaged, 0);
    assert_eq!(page.events[0].v, AUDIT_SCHEMA);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn the_audit_stops_at_the_window_and_at_the_cap() {
    let p = audit_tmp("window");
    let w = AuditWriter::new(&p);
    for ts in 100..110 {
        put(&w, login(ts, "a@x.com"));
    }
    // The window is a floor on `ts`, and the file being time-ordered is what lets the
    // read stop there rather than parse the rest.
    assert_eq!(read_audit(&p, Some(105), 100).unwrap().events.len(), 5);
    // The cap says so instead of trimming in silence.
    let page = read_audit(&p, None, 3).unwrap();
    assert_eq!(page.events.len(), 3);
    assert!(page.more);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_torn_line_is_counted_and_the_rest_is_read() {
    let p = audit_tmp("torn");
    let w = AuditWriter::new(&p);
    put(&w, login(100, "a@x.com"));
    // What a power cut mid-append leaves behind.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"ts\":101,\"kin\n").unwrap();
    }
    put(&w, login(102, "b@x.com"));
    let page = read_audit(&p, None, 100).unwrap();
    assert_eq!(page.events.len(), 2, "the whole lines are still readable");
    assert_eq!(page.damaged, 1, "and the broken one is reported");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_rotation_keeps_the_window_whole() {
    let p = audit_tmp("rotate");
    let w = AuditWriter::new(&p);
    put(&w, login(100, "old@x.com"));
    // Rotate by hand rather than by writing four megabytes: what is under test is that a
    // read spans both files, not that `metadata` can measure one.
    std::fs::rename(&p, audit_previous(&p)).unwrap();
    put(&w, login(101, "new@x.com"));
    let page = read_audit(&p, None, 100).unwrap();
    let seen: Vec<&str> = page
        .events
        .iter()
        .map(|e| e.subject.as_deref().unwrap())
        .collect();
    assert_eq!(seen, ["new@x.com", "old@x.com"]);
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(audit_previous(&p));
}

/// Lines of an audit file, as the writer would have left them, oldest first.
fn lines_of(stamps: &[u64]) -> String {
    stamps
        .iter()
        .map(|ts| {
            format!(
                "{}\n",
                serde_json::to_string(&login(*ts, "a@x.com")).unwrap()
            )
        })
        .collect()
}

fn stamps(p: &std::path::Path) -> Vec<u64> {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| line_ts(l.as_bytes()))
        .collect()
}

fn cleanup_audit(p: &std::path::Path) {
    let _ = std::fs::remove_file(p);
    let _ = std::fs::remove_file(audit_previous(p));
}

/// The live file rotates before the line that would take it past its size, not after, so
/// the pair never holds more than the policy says: the bound is exact, not exact give or
/// take a line.
#[test]
fn the_live_file_rotates_before_it_would_pass_its_size() {
    let p = audit_tmp("rotate-size");
    // A retention of 2 MiB rotates the live file at 1 MiB.
    let policy = AuditPolicy::new(
        AuditLimit::new(4, AuditUnit::MiB),
        Some(AuditLimit::new(2, AuditUnit::MiB)),
    )
    .unwrap();
    let limit = policy.rotate_at_bytes();
    let one = lines_of(&[100]);
    let mut fill = String::new();
    let mut ts = 100;
    while fill.len() + one.len() <= limit as usize {
        fill.push_str(&lines_of(&[ts]));
        ts += 1;
    }
    std::fs::write(&p, &fill).unwrap();
    let w = AuditWriter::new(&p);
    w.record(&login(ts, "next@x.com"), &policy).unwrap();
    assert_eq!(
        stamps(&p),
        [ts],
        "the live file starts again with the new event"
    );
    assert_eq!(
        std::fs::read_to_string(audit_previous(&p)).unwrap(),
        fill,
        "and the one before it is what the live file was, whole"
    );
    assert!(std::fs::metadata(audit_previous(&p)).unwrap().len() <= limit);
    cleanup_audit(&p);
}

/// Maintenance is what makes a time mean something on a deployment that writes nothing
/// for a month: a live file whose oldest event is past the rotation age moves on, and
/// every event past a retention in time goes, whichever file it is in.
#[test]
fn maintenance_rotates_on_age_and_drops_what_the_retention_expired() {
    let now = 10_000_000;
    let week = 604_800;

    // Rotation on age: the oldest event is two weeks old, the rotation is one week.
    let p = audit_tmp("maintain-age");
    std::fs::write(&p, lines_of(&[now - 2 * week, now - 10])).unwrap();
    let rotate_weekly = AuditPolicy::new(
        AuditLimit::new(1, AuditUnit::Weeks),
        Some(AuditLimit::new(64, AuditUnit::MiB)),
    )
    .unwrap();
    AuditWriter::new(&p).maintain(&rotate_weekly, now).unwrap();
    assert!(!p.exists(), "rotated away");
    assert_eq!(stamps(&audit_previous(&p)), [now - 2 * week, now - 10]);
    cleanup_audit(&p);

    // Retention in time: `.1` entirely expired, the live file half.
    let p = audit_tmp("maintain-retention");
    std::fs::write(audit_previous(&p), lines_of(&[1_000, 1_001])).unwrap();
    let mut live = lines_of(&[5_000, now - 2 * week]);
    live.push_str("{\"ts\":42,\"kin\n"); // a torn line among the expired ones
    live.push_str(&lines_of(&[now - 3_600, now - 60]));
    std::fs::write(&p, live).unwrap();
    let keep_a_week = AuditPolicy::new(
        AuditLimit::new(4, AuditUnit::MiB),
        Some(AuditLimit::new(1, AuditUnit::Weeks)),
    )
    .unwrap();
    AuditWriter::new(&p).maintain(&keep_a_week, now).unwrap();
    assert!(
        !audit_previous(&p).exists(),
        "a file with nothing left in it goes"
    );
    assert_eq!(stamps(&p), [now - 3_600, now - 60]);
    assert_eq!(
        read_audit(&p, None, 100).unwrap().damaged,
        0,
        "and the torn line went with the expired events around it"
    );
    // Run again, nothing changes: a retention already met costs no rewrite.
    let before = std::fs::read(&p).unwrap();
    AuditWriter::new(&p).maintain(&keep_a_week, now).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), before);
    cleanup_audit(&p);
}

/// A stricter policy takes effect at the next maintenance, which the gate runs on every
/// reload: a `.1` written under a looser one is cut down to its newest events, at a line
/// boundary, rather than standing too big until the next rotation.
#[test]
fn a_stricter_size_cuts_a_file_written_under_a_looser_one() {
    let p = audit_tmp("maintain-size");
    let old: Vec<u64> = (0..40_000).collect();
    std::fs::write(audit_previous(&p), lines_of(&old)).unwrap();
    std::fs::write(&p, lines_of(&[50_000])).unwrap();
    let tight = AuditPolicy::new(
        AuditLimit::new(4, AuditUnit::MiB),
        Some(AuditLimit::new(2, AuditUnit::MiB)),
    )
    .unwrap();
    AuditWriter::new(&p).maintain(&tight, 60_000).unwrap();
    let prev = audit_previous(&p);
    assert!(std::fs::metadata(&prev).unwrap().len() <= tight.rotate_at_bytes());
    let kept = stamps(&prev);
    assert_eq!(
        kept.last(),
        Some(&39_999),
        "the newest events are the ones kept"
    );
    assert!(kept.len() < old.len());
    assert_eq!(
        read_audit(&p, None, 100_000).unwrap().damaged,
        0,
        "cut at a line"
    );
    cleanup_audit(&p);
}

/// Backwards through a file in blocks far smaller than its lines: every line comes out
/// whole, last first, blank ones skipped, with or without a final newline.
#[test]
fn a_file_is_read_backwards_in_blocks_and_every_line_comes_out_whole() {
    let p = audit_tmp("revlines");
    for body in [
        "alpha\nbravo-is-a-much-longer-line\n\ncharlie\n",
        "alpha\nbravo-is-a-much-longer-line\n\ncharlie",
        "",
        "\n\n",
        "only",
    ] {
        std::fs::write(&p, body).unwrap();
        let expect: Vec<&str> = body.lines().filter(|l| !l.is_empty()).rev().collect();
        for block in [1, 3, 7, 64 * 1024] {
            let mut r = RevLines::with_block(&p, block).unwrap();
            let mut got = Vec::new();
            while let Some(l) = r.next_line().unwrap() {
                got.push(String::from_utf8(l).unwrap());
            }
            assert_eq!(got, expect, "{body:?} in blocks of {block}");
        }
    }
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_missing_audit_is_an_empty_page_and_not_a_fault() {
    // What a gate that has never refused anybody looks like. It must not read as an
    // error, or the page would report a fault on a healthy deployment.
    let p = audit_tmp("absent");
    let page = read_audit(&p, None, 100).unwrap();
    assert!(page.events.is_empty());
    assert_eq!(page.damaged, 0);
}

#[test]
fn an_event_serializes_to_one_line_of_only_what_it_has() {
    let ev = AuditEvent::new(
        1_700_000_000,
        AuditKind::AccessRefused,
        AuditCredential::Key {
            id: "laptop".into(),
        },
    )
    .of("11111111-2222-3333-4444-555555555555")
    .at(Some(("ai", "root")))
    .on(Some("https://ai.x.com/mcp"))
    .because(decision_reason(&Decision::KeyOutOfScope {
        app: "ai".into(),
        scope: "root".into(),
    }));
    let line = serde_json::to_string(&ev).unwrap();
    assert!(!line.contains('\n'), "one event is one line");
    // An absent field is absent, not null: the file is read by a program and written on
    // a card, and half these fields are absent on any given event.
    assert!(!line.contains("subject"));
    assert!(line.contains(r#""reason":"key_out_of_scope""#));
    assert!(line.contains(r#""cred":{"type":"key","id":"laptop"}"#));
    assert_eq!(serde_json::from_str::<AuditEvent>(&line).unwrap(), ev);
    // The filter matches on the key's id, the scope and the reason alike.
    let hay = ev.haystack();
    for part in ["laptop", "ai", "root", "key_out_of_scope", "ai.x.com"] {
        assert!(hay.contains(part), "{part} is filterable");
    }
}

#[test]
fn where_a_request_came_from_rides_on_the_event_and_is_filterable() {
    let client = AuditClient {
        ip: Some("203.0.113.7".into()),
        ua: Some("Mozilla/5.0 (X11; Linux aarch64)".into()),
        rid: Some("5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f".into()),
    };
    let ev = login(1_700_000_000, "a@x.com")
        .account(Some("9d8e7f60-1a2b-4c3d-8e9f-0a1b2c3d4e5f"))
        .from(&client);
    assert_eq!(ev.ip, client.ip);
    assert_eq!(ev.ua, client.ua);
    assert_eq!(ev.rid, client.rid);
    let line = serde_json::to_string(&ev).unwrap();
    assert!(line.contains(r#""ip":"203.0.113.7""#), "{line}");
    assert!(line.contains(r#""sub":"9d8e7f60-"#), "{line}");
    assert_eq!(serde_json::from_str::<AuditEvent>(&line).unwrap(), ev);

    // Pasting an address from a firewall's log, or an id from nginx's, is how a reader
    // arrives at this page, so both have to find the row.
    let hay = ev.haystack();
    for part in ["203.0.113.7", "5f1c0a9e", "9d8e7f60", "aarch64"] {
        assert!(hay.contains(part), "{part} is filterable");
    }

    // A client that said nothing leaves nothing behind, not three nulls.
    let bare = login(1_700_000_000, "a@x.com").from(&AuditClient::default());
    let line = serde_json::to_string(&bare).unwrap();
    for absent in ["\"ip\"", "\"ua\"", "\"rid\"", "\"sub\""] {
        assert!(!line.contains(absent), "{absent} in {line}");
    }
}

/// The schema is additive, and a line an older gate wrote is still read. That is the whole
/// reason `AUDIT_SCHEMA` did not move when four fields arrived: nobody holds a line of this
/// file, so tolerating one without them costs nothing.
#[test]
fn a_line_from_before_the_client_fields_still_reads() {
    let old = r#"{"v":1,"ts":1700000000,"kind":"login_granted","cred":{"type":"local"},"subject":"a@x.com"}"#;
    let ev: AuditEvent = serde_json::from_str(old).unwrap();
    assert_eq!(ev.subject.as_deref(), Some("a@x.com"));
    assert_eq!((ev.ip, ev.ua, ev.rid, ev.sub), (None, None, None, None));
}

/// The audit is created group-readable, and that is a deployment contract rather than a
/// detail: the gate writes this file under `UMask=0077`, and `bb-auth-web` reads it
/// through the `bb-auth` group it already belongs to. At 0600 the Audit tab is a
/// permission error on a deployment where everything else is correct, and the only sign
/// of it is a page nobody looks at until they need it.
#[cfg(unix)]
#[test]
fn the_audit_is_readable_by_the_group_that_has_to_read_it() {
    use std::os::unix::fs::PermissionsExt;
    let p = audit_tmp("mode");
    put(&AuditWriter::new(&p), login(100, "a@x.com"));
    let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o640,
        "owner writes, the gate's group reads, nobody else"
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn the_credential_tag_is_the_kind_and_not_the_instance() {
    // The filter offers five words; a key's id must not be one of them, or filtering by
    // credential would mean filtering by which key.
    assert_eq!(
        AuditCredential::Key {
            id: "laptop".into()
        }
        .tag(),
        AuditCredential::Key { id: "phone".into() }.tag()
    );
    assert_eq!(
        AuditCredential::Social {
            provider: "Google".into()
        }
        .tag(),
        "social"
    );
    assert!(AuditKind::LoginGranted.granted());
    assert!(!AuditKind::AccessRefused.granted());
}

#[test]
fn the_cognito_endpoint_is_the_issuers_origin() {
    // The pool id is the only part of an issuer URL that is not the API's address.
    let s = settings(
        r#"{ "version": 3, "gate": { "issuer":
                "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TESTPOOL" } }"#,
    )
    .unwrap();
    assert_eq!(
        s.cognito_endpoint(),
        "https://cognito-idp.eu-central-1.amazonaws.com/"
    );
    // A port belongs to the origin, the path does not.
    let s =
        settings(r#"{ "version": 3, "gate": { "issuer": "https://idp.example.com:8443/pool" } }"#)
            .unwrap();
    assert_eq!(s.cognito_endpoint(), "https://idp.example.com:8443/");
    // No issuer, no endpoint: empty, never a bare "/" a page would then post to.
    let s = settings(r#"{ "version": 3 }"#).unwrap();
    assert_eq!(s.cognito_endpoint(), "");
}

#[test]
fn email_verified_is_true_or_the_string_true() {
    assert!(email_verified_true(&serde_json::json!(true)));
    assert!(email_verified_true(&serde_json::json!("true")));
    assert!(email_verified_true(&serde_json::json!("TRUE")));
    assert!(!email_verified_true(&serde_json::json!(false)));
    assert!(!email_verified_true(&serde_json::json!("false")));
    assert!(!email_verified_true(&serde_json::json!("1")));
    assert!(!email_verified_true(&serde_json::json!(1)));
    assert!(!email_verified_true(&serde_json::json!(null)));
}

/// The GUI's unit lets the process reach Cognito (docs/ARCHITECTURE.md §13.22, slice 5b):
/// `IPAddressDeny=any` would drop every packet the profile edit sends, so the directive
/// pair is gone, while the two things that keep egress from coming with the HMAC key stay.
#[test]
fn the_gui_unit_lets_cognito_out() {
    let unit = include_str!("../deploy/bb-auth-web.service");
    let directives: Vec<&str> = unit
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    assert!(
        !directives.iter().any(|l| l.starts_with("IPAddress")),
        "the unit must carry no IPAddressDeny/IPAddressAllow line: {directives:?}"
    );
    assert!(
        directives.contains(&"InaccessiblePaths=/opt/bb-auth/etc"),
        "the HMAC key stays unreachable: {directives:?}"
    );
    assert!(
        directives
            .iter()
            .any(|l| l.starts_with("RestrictAddressFamilies=")),
        "the address families stay restricted: {directives:?}"
    );
}

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
