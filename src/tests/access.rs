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
