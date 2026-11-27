use super::*;

// --- the settings file ---------------------------------------------------

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

/// Every .rs file under `dir`, read at run time and concatenated into one string: the
/// whole source tree, as the thing to search.
///
/// A walk, not a list, because plan step 25 adds a file per module. §13.39 §6 measured
/// the cost of the fixed `include_str!` list this replaces: it stayed green with
/// `src/audit.rs` left off it, only because the tests named `RevLines` as well, and went
/// red once those moved to `src/tests/audit.rs`. A list that fails for reasons that have
/// nothing to do with a move is a list somebody deletes the first time it is in the way.
/// The walk runs when the check runs, so it reads the tree that is on disk, which is the
/// tree the manual describes, and a new file needs no edit here.
fn rust_sources(dir: &std::path::Path) -> String {
    let mut out = String::new();
    for entry in
        std::fs::read_dir(dir).expect("the source tree is readable at CARGO_MANIFEST_DIR/src")
    {
        let path = entry
            .expect("an entry of the source tree is readable")
            .path();
        if path.is_dir() {
            out.push_str(&rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push_str(
                &std::fs::read_to_string(&path).expect("a source file under src/ is readable"),
            );
        }
    }
    out
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
    const MANUAL: &str = include_str!("../../AGENTS.md");
    // The sources: every .rs under src/, found by walking the tree (see rust_sources),
    // so a module move needs no edit to this list. Plus the three files beside them that
    // hold the other things the manual pins a rule to: a cargo feature (`rust_crypto`)
    // and the unit directives the hardening argument is made of (`ReadOnlyPaths`,
    // `ReadWritePaths`, `SupplementaryGroups`). Those are as real as a function, and as
    // able to stop existing.
    let mut src = rust_sources(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src"
    )));
    src.push_str(include_str!("../../Cargo.toml"));
    src.push_str(include_str!("../../deploy/bb-auth.service"));
    src.push_str(include_str!("../../deploy/bb-auth-web.service"));
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
