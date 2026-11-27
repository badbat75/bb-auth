use super::*;

fn keys_one() -> HmacKeys {
    let mut by_id = HashMap::new();
    by_id.insert("k1".to_string(), vec![0x42u8; 32]);
    HmacKeys {
        by_id,
        active_id: "k1".to_string(),
    }
}
fn keys_two() -> HmacKeys {
    let mut by_id = HashMap::new();
    by_id.insert("k1".to_string(), vec![0x11u8; 32]);
    by_id.insert("k2".to_string(), vec![0x22u8; 32]);
    HmacKeys {
        by_id,
        active_id: "k1".to_string(),
    }
}

/// An identity with no claims: every login under the default (empty)
/// the settings file's `profile_claims`.
fn ident(email: &str) -> UserIdentity {
    UserIdentity {
        email: email.to_string(),
        claims: BTreeMap::new(),
        cred: AuditCredential::Local,
        sub: None,
        native_username: None,
    }
}
/// An identity carrying an arbitrary claim set.
fn ident_claims(email: &str, claims: &[(&str, &str)]) -> UserIdentity {
    UserIdentity {
        email: email.to_string(),
        claims: claims
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        cred: AuditCredential::Local,
        sub: None,
        native_username: None,
    }
}
/// An identity carrying the two claims a display name is usually built from.
fn ident_full(email: &str, given: &str, family: &str) -> UserIdentity {
    ident_claims(email, &[("given_name", given), ("family_name", family)])
}

/// What a verified cookie hands back: the identity that went in, minus how it was proved
/// and minus which Cognito account proved it.
///
/// Its own helper rather than a weaker assertion, because that difference **is** the rule:
/// the cookie carries an identity and its claims and says nothing about the credential
/// behind them ([`AuditCredential::Session`]). A round trip that compared loosely would let
/// a future edit stamp the provider or the `sub` into the cookie with nothing noticing, and
/// that edit is a [`COOKIE_VERSION`] bump that logs every session out.
fn from_cookie(mut i: UserIdentity) -> UserIdentity {
    i.cred = AuditCredential::Session;
    i.sub = None;
    i
}

/// An audit that records nothing, in a `static` so the [`RequestAudit`] borrowed from it
/// outlives the statement it is made in.
static QUIET: Audit = Audit::off();

/// A request that says nothing about where it came from, on the audit that records nothing.
fn quiet() -> RequestAudit<'static> {
    QUIET.for_request(AuditClient::default(), AuditPolicy::default())
}

// The two authorization entry points with the audit off, which is what a test of the
// *decision* wants: these deliberately shadow the glob import above (a local item beats a
// `use super::*`), so a test reads as the question it is asking and nothing in this suite
// races for one file on disk. A test of the record itself calls `super::` and says so.
fn authorize_login(access: &Access, ident: UserIdentity, url: Option<&str>) -> Option<Granted> {
    super::authorize_login(access, ident, url, &quiet())
}
fn bearer_apikey<'a>(access: &'a Access, token: &str) -> Option<&'a ApiKeyRecord> {
    super::bearer_apikey(access, token, None, &quiet())
}
/// A compiled claim list, written comma-separated for brevity. The compiler itself, and
/// everything it refuses, is the library's and is tested there; what these tests need is
/// a list to emit from.
fn claims(spec: &str) -> Vec<ProfileClaim> {
    let list: Vec<String> = spec.split(',').map(str::to_string).collect();
    bb_auth_core::compile_profile_claims(&list).unwrap()
}

/// The claim set behind a first-and-last-name greeting, which is what most deployments
/// configure and therefore the size the cookie budget is judged against.
fn claims_cfg() -> Vec<ProfileClaim> {
    claims("given_name,family_name")
}

/// The JWKS parse and the RS256 verification, which every login runs and which nothing
/// else here covers: the rest of the suite starts from a [`UserIdentity`] that already
/// exists. The `Validation` is built exactly as [`validate_id_token`] builds it, so this
/// exercises the gate's own configuration and not a lenient one.
///
/// It exists because that coverage gap has already cost a production outage.
/// `jsonwebtoken` selects its crypto provider from a **feature**, and compiles happily
/// with none: it then installs a provider whose verifier factory is a `panic!`. Nothing
/// says so until the first signature is checked, and under `panic = "abort"` that is not
/// a failed login but a dead process, which `Restart=on-failure` turns into a restart
/// loop. A test that only built a `DecodingKey` would have missed it, because the JWKS
/// fetch and `from_jwk` never reach the provider; the verification is the whole point.
#[test]
fn rsa_signature_verification_works() {
    let set: JwkSet = serde_json::from_str(SELF_TEST_JWKS).expect("the JWKS must parse");
    let key = DecodingKey::from_jwk(&set.keys[0]).expect("the JWK must become a key");
    let v = self_test_validation();

    let data = decode::<Claims>(SELF_TEST_TOKEN, &key, &v).expect("a valid RS256 token verifies");
    assert_eq!(data.claims.email.as_deref(), Some("rs256@example.com"));
    assert_eq!(data.claims.token_use.as_deref(), Some("id"));
    // The profile claim rides in `extra`, which is what proves `flatten` still collects
    // what no typed field above took.
    assert_eq!(
        data.claims.extra.get("given_name").and_then(|v| v.as_str()),
        Some("Ada")
    );

    // The other half, and the one that says this is a signature check rather than a
    // decoder: one flipped base64 digit in the signature, the signed message untouched.
    let (msg, sig) = SELF_TEST_TOKEN
        .rsplit_once('.')
        .expect("a JWT has three segments");
    assert!(sig.starts_with('E'), "fixture drifted: {sig}");
    let forged = format!("{msg}.F{}", &sig[1..]);
    assert!(
        decode::<Claims>(&forged, &key, &v).is_err(),
        "a forged signature must not verify"
    );
}

#[test]
fn worst_case_cookie_bytes_grows_and_trips_the_warning() {
    let none = worst_case_cookie_bytes(&[]);
    let two = worst_case_cookie_bytes(&claims_cfg());
    assert!(two > none, "a claim must cost something");
    // The threshold `main` warns at. A couple of claims is comfortable; a handful of
    // max-length ones is not, which is the whole point of warning.
    assert!(two <= 3072, "the usual pair must not warn: {two}");
    let many = claims("a,b,c,d,e,f,g,h");
    assert!(
        worst_case_cookie_bytes(&many) > 3072,
        "eight claims must warn"
    );
}

#[test]
fn session_roundtrip() {
    let k = keys_one();
    // Non-ASCII and an apostrophe: the cookie is binary-safe (base64) where the header
    // is not, so this is the roundtrip that has to survive untouched.
    let c = make_session(
        &ident_full("Foo@Bar.com", "Niccolò", "de' Medici"),
        3600,
        &k,
    );
    assert!(c.starts_with("bb1.k1."));
    // The email lowercases; the claim values do not — their case is the user's.
    assert_eq!(
        verify_session(&c, &k),
        Some(from_cookie(ident_full(
            "foo@bar.com",
            "Niccolò",
            "de' Medici"
        )))
    );
}

#[test]
fn session_roundtrip_no_claims() {
    let k = keys_one();
    let c = make_session(&ident("a@b.com"), 3600, &k);
    // No claims is the empty segment, not a missing field and not "{}": the count
    // never varies, and the default config costs no cookie bytes.
    assert_eq!(c.split('.').count(), 6, "field count is fixed: {c}");
    assert_eq!(
        c.split('.').nth(4),
        Some(""),
        "empty segment, never {{}}: {c}"
    );
    assert_eq!(verify_session(&c, &k), Some(from_cookie(ident("a@b.com"))));
}

#[test]
fn session_roundtrip_json_special_chars() {
    // The blob is JSON, so a value containing a quote or a backslash goes through
    // escaping and must come back byte-identical.
    let k = keys_one();
    let id = ident_claims("a@b.com", &[("nickname", r#"a"b\c/d"#)]);
    let c = make_session(&id, 3600, &k);
    assert_eq!(verify_session(&c, &k), Some(from_cookie(id)));
}

#[test]
fn session_claims_are_signed() {
    let k = keys_one();
    let c = make_session(&ident_full("a@b.com", "Ada", "Byron"), 3600, &k);
    let p: Vec<&str> = c.split('.').collect();
    // Substitute a well-formed claims blob, keep the signature: the blob is inside the
    // signed bytes, so this must not verify.
    let forged = URL_SAFE_NO_PAD.encode(r#"{"given_name":"Eve"}"#);
    let cookie = format!("{}.{}.{}.{}.{forged}.{}", p[0], p[1], p[2], p[3], p[5]);
    assert_eq!(verify_session(&cookie, &k), None);
    // Dropping the blob entirely is no better.
    let stripped = format!("{}.{}.{}.{}..{}", p[0], p[1], p[2], p[3], p[5]);
    assert_eq!(verify_session(&stripped, &k), None);
}

#[test]
fn session_bad_claims_segment_fails_closed() {
    let k = keys_one();
    let exp = now() + 3600;
    let eb = URL_SAFE_NO_PAD.encode(b"a@b.com");
    let b64 = |s: &str| URL_SAFE_NO_PAD.encode(s.as_bytes());
    let over = "x".repeat(MAX_CLAIM_VALUE_BYTES + 1);
    // Every one of these is *correctly signed*. We could never have minted it, so it is
    // a bug or a compromised key — either way reject the cookie, not just the claim.
    for seg in [
        "!!!".to_string(),                    // not base64url
        URL_SAFE_NO_PAD.encode([0xff, 0xfe]), // not UTF-8
        b64("[]"),                            // not an object
        b64("\"x\""),                         // ditto
        b64("{}"),                            // we mint the empty segment
        b64(r#"{"a":1}"#),                    // value not a string
        b64(r#"{"a":null}"#),                 // ditto
        b64(r#"{"a":""}"#),                   // would emit an empty header
        b64(&format!(r#"{{"a":"{over}"}}"#)), // over the value cap
        b64(r#"{"a":"one\ntwo"}"#),           // control character
        b64(r#"{"a":" Ada"}"#),               // not trim-stable
        b64(r#"{"bad key!":"Ada"}"#),         // key no config could produce
    ] {
        let msg = format!("bb1.k1.{exp}.{eb}.{seg}");
        let sig = sign(&k.by_id["k1"], &msg);
        assert_eq!(
            verify_session(&format!("{msg}.{sig}"), &k),
            None,
            "should reject: {seg}"
        );
    }
}

#[test]
fn session_tampered_sig_rejected() {
    let k = keys_one();
    let mut c = make_session(&ident("a@b.com"), 3600, &k);
    let last = c.len() - 1;
    let alt = if c.as_bytes()[last] == b'A' { 'B' } else { 'A' };
    c.replace_range(last.., &alt.to_string());
    assert_eq!(verify_session(&c, &k), None);
}

#[test]
fn session_expired_rejected() {
    let k = keys_one();
    let c = make_session(&ident("a@b.com"), 0, &k); // exp == now
    assert_eq!(verify_session(&c, &k), None);
}

#[test]
fn session_unknown_keyid_rejected() {
    let k = keys_one(); // only k1
    let exp = now() + 3600;
    let eb = URL_SAFE_NO_PAD.encode(b"a@b.com");
    let msg = format!("bb1.k9.{exp}.{eb}.");
    let sig = sign(&k.by_id["k1"], &msg);
    let c = format!("{msg}.{sig}");
    assert_eq!(verify_session(&c, &k), None);
}

#[test]
fn session_routes_to_accepted_key() {
    let k = keys_two(); // k1 active, k2 accepted
    let exp = now() + 3600;
    let eb = URL_SAFE_NO_PAD.encode(b"x@y.com");
    let cb = URL_SAFE_NO_PAD.encode(r#"{"given_name":"Ada"}"#);
    let msg = format!("bb1.k2.{exp}.{eb}.{cb}");
    let sig = sign(&k.by_id["k2"], &msg);
    let c = format!("{msg}.{sig}");
    assert_eq!(
        verify_session(&c, &k),
        Some(from_cookie(ident_claims(
            "x@y.com",
            &[("given_name", "Ada")]
        )))
    );
}

#[test]
fn foreign_cookie_versions_are_rejected() {
    // The tag is inside the signed bytes and exactly one value of it has an arm, so a
    // live key signing the cookie is not enough: the tag has to be ours. That is what
    // makes a future format bump a clean break rather than an ambiguity, and it is the
    // contract, so it is pinned.
    let k = keys_one();
    let exp = now() + 3600;
    let eb = URL_SAFE_NO_PAD.encode(b"a@b.com");
    let cb = URL_SAFE_NO_PAD.encode(r#"{"given_name":"Ada"}"#);
    for msg in [
        format!("bb2.k1.{exp}.{eb}.{cb}"), // our shape, a tag we never mint
        format!("bb9.k1.{exp}.{eb}."),     // ditto, with no claims
        format!("xx1.k1.{exp}.{eb}.{cb}"), // another namespace entirely
        format!("bb1.{exp}.{eb}"),         // our tag, too few fields
        format!("bb1.k1.{exp}.{eb}.{cb}.x"), // our tag, one field too many
    ] {
        let sig = sign(&k.by_id["k1"], &msg);
        let c = format!("{msg}.{sig}");
        assert_eq!(verify_session(&c, &k), None, "should reject: {c}");
    }
}

#[test]
fn malformed_cookies_rejected() {
    let k = keys_one();
    for bad in [
        "",
        "bb1",
        "bb1.k1",
        "bb1.k1.9.aa",             // too few fields
        "bb1.k1.99999.!!!.AAAA",   // five: one short
        "bb1.k1.9.aa.bb.cc.dd",    // seven: the extra folds into sig, which then fails
        "bb1.k1.notanum.aa.bb.cc", // right shape, exp is not a number
        "bb1.k1.99999.!!!.bb.cc",  // right shape, the email is not base64url
        "zzz.a.b.c",               // no arm matches a tag we do not mint
        "bb9.k1.9.aa.bb.cc",       // ditto, even wearing our shape
    ] {
        assert_eq!(verify_session(bad, &k), None, "should reject: {bad:?}");
    }
}

#[test]
fn profile_headers_follow_the_live_config() {
    let cfg = claims_cfg();
    // A cookie minted under a wider config: `nickname` is no longer configured, so it
    // emits nothing — the live config is the authority, not the credential.
    let stale = ident_claims(
        "a@b.com",
        &[("given_name", "Ada"), ("nickname", "The Countess")],
    );
    assert_eq!(
        profile_headers(&cfg, &stale.claims),
        vec![("X-Auth-Given-Name", "Ada".to_string())]
    );
    // A configured claim the identity lacks omits its header rather than sending it
    // empty; order follows the config, not the map.
    assert_eq!(
        profile_headers(&cfg, &ident_full("a@b.com", "Ada", "Byron").claims),
        vec![
            ("X-Auth-Given-Name", "Ada".to_string()),
            ("X-Auth-Family-Name", "Byron".to_string()),
        ]
    );
    // No config, nothing emitted, whatever the identity carries.
    assert!(profile_headers(&[], &stale.claims).is_empty());
    // And the value goes out percent-encoded.
    assert_eq!(
        profile_headers(&cfg, &ident_full("a@b.com", "Niccolò", "de' Medici").claims),
        vec![
            ("X-Auth-Given-Name", "Niccol%C3%B2".to_string()),
            ("X-Auth-Family-Name", "de%27%20Medici".to_string()),
        ]
    );
}

#[test]
fn pct_encode_unreserved_untouched() {
    // RFC 3986's unreserved set passes through byte for byte, which is what keeps a
    // plain "Rossi" readable in a log.
    assert_eq!(pct_encode("AZaz09-._~Rossi"), "AZaz09-._~Rossi".to_string());
}

#[test]
fn pct_encode_space_utf8_and_symbols() {
    assert_eq!(pct_encode("Mary Jane"), "Mary%20Jane"); // %20, never '+'
    assert_eq!(pct_encode("Niccolò"), "Niccol%C3%B2"); // per UTF-8 byte
    assert_eq!(pct_encode("%"), "%25"); // the escape escapes itself
    assert_eq!(pct_encode("+"), "%2B"); // so '+' can only mean a literal plus
    assert_eq!(pct_encode("de' Medici"), "de%27%20Medici");
    assert_eq!(pct_encode("a\r\nb"), "a%0D%0Ab"); // no response splitting
    assert_eq!(pct_encode(""), "");
}

#[test]
fn pct_encode_output_always_ascii_graphic() {
    // The property `respond_authorized` leans on instead of a per-request check: for
    // *any* input — control bytes, DEL, multibyte — the output is printable ASCII, so
    // `h()` cannot panic.
    let mut s: String = (0u8..=0x7f).map(|b| b as char).collect();
    s.push_str("Niccolò Ægir 日本語 🙂");
    let enc = pct_encode(&s);
    assert!(
        enc.bytes().all(|b| b.is_ascii_graphic()),
        "not header-safe: {enc:?}"
    );
}

#[test]
fn clean_claim_hygiene() {
    use serde_json::json;
    // captured, trimmed, case and UTF-8 preserved
    assert_eq!(
        clean_claim(&json!("  Niccolò  ")).as_deref(),
        Some("Niccolò")
    );
    assert_eq!(
        clean_claim(&json!("de' Medici")).as_deref(),
        Some("de' Medici")
    );
    // nothing worth a header
    assert_eq!(clean_claim(&json!("")), None);
    assert_eq!(clean_claim(&json!("   ")), None);
    assert_eq!(clean_claim(&json!("Ada\rByron")), None); // control char
                                                         // dropped, not truncated, at the byte cap
    let max = "x".repeat(MAX_CLAIM_VALUE_BYTES);
    assert_eq!(clean_claim(&json!(max)).as_deref(), Some(max.as_str()));
    assert_eq!(
        clean_claim(&json!("x".repeat(MAX_CLAIM_VALUE_BYTES + 1))),
        None
    );
    // a non-string claim costs the claim, never the token
    for v in [
        json!(42),
        json!(true),
        json!(null),
        json!(["Ada"]),
        json!({}),
    ] {
        assert_eq!(clean_claim(&v), None, "should ignore: {v}");
    }
}

#[test]
fn claim_value_ok_is_what_a_cookie_may_carry() {
    // The predicate verification shares with capture — where the trim test, vacuous on
    // capture, is what rejects a value we could not have minted.
    assert!(claim_value_ok("Ada"));
    assert!(claim_value_ok("de' Medici"));
    assert!(!claim_value_ok(""));
    assert!(!claim_value_ok(" Ada"));
    assert!(!claim_value_ok("Ada "));
    assert!(!claim_value_ok("Ada\nByron"));
    assert!(claim_value_ok(&"x".repeat(MAX_CLAIM_VALUE_BYTES)));
    assert!(!claim_value_ok(&"x".repeat(MAX_CLAIM_VALUE_BYTES + 1)));
}

#[test]
fn claims_parse_profile_claims_present_absent_and_mistyped() {
    let parse = |s: &str| serde_json::from_str::<Claims>(s).expect("claims must parse");

    let c = parse(r#"{"email":"a@b.com","given_name":"Ada","family_name":"Byron"}"#);
    assert_eq!(
        c.extra.get("given_name").and_then(clean_claim).as_deref(),
        Some("Ada")
    );
    assert_eq!(
        c.extra.get("family_name").and_then(clean_claim).as_deref(),
        Some("Byron")
    );

    let c = parse(r#"{"email":"a@b.com"}"#);
    assert!(c.extra.get("given_name").is_none());

    // The reason `extra` holds `Value`s and not `String`s: a badly mapped IdP attribute
    // must cost the user that claim, not their login. `parse` not panicking *is* the
    // assertion.
    let c = parse(r#"{"email":"a@b.com","given_name":42,"family_name":["Byron"]}"#);
    assert_eq!(c.extra.get("given_name").and_then(clean_claim), None);
    assert_eq!(c.extra.get("family_name").and_then(clean_claim), None);
}

#[test]
fn claims_the_gate_consumes_never_reach_extra() {
    // Why `RESERVED_CLAIMS` exists: `flatten` never sees a key a typed field took, so
    // configuring one of these would look up a claim that can never be there.
    let c = serde_json::from_str::<Claims>(
        r#"{"email":"a@b.com","email_verified":true,"token_use":"id","identities":[]}"#,
    )
    .expect("claims must parse");
    for reserved in bb_auth_core::RESERVED_CLAIMS {
        assert!(
            c.extra.get(reserved).is_none(),
            "{reserved} must not be in extra"
        );
    }
}

#[test]
fn email_verified_truthy_variants() {
    assert!(email_verified_true(&serde_json::json!(true)));
    assert!(email_verified_true(&serde_json::json!("true")));
    assert!(email_verified_true(&serde_json::json!("TRUE")));
    assert!(!email_verified_true(&serde_json::json!(false)));
    assert!(!email_verified_true(&serde_json::json!("false")));
    assert!(!email_verified_true(&serde_json::json!("1")));
    assert!(!email_verified_true(&serde_json::json!(null)));
}

fn idents(names: &[&str]) -> Vec<Identity> {
    names
        .iter()
        .map(|n| Identity {
            provider_name: Some((*n).to_string()),
        })
        .collect()
}

#[test]
fn unverified_social_off_by_default() {
    // Feature disabled: never relax, even for a clear social identity.
    assert!(!unverified_social_ok(false, &None, &idents(&["Google"])));
}

#[test]
fn unverified_social_native_user_never_relaxed() {
    // No `identities` claim => native Cognito user => always strict.
    assert!(!unverified_social_ok(true, &None, &[]));
}

#[test]
fn unverified_social_any_provider_when_unrestricted() {
    assert!(unverified_social_ok(true, &None, &idents(&["Google"])));
    assert!(unverified_social_ok(true, &None, &idents(&["Facebook"])));
}

#[test]
fn unverified_social_provider_allowlist_enforced() {
    let allowed = Some(vec!["Google".to_string(), "SignInWithApple".to_string()]);
    assert!(unverified_social_ok(true, &allowed, &idents(&["Google"])));
    // Case-insensitive match against providerName.
    assert!(unverified_social_ok(true, &allowed, &idents(&["google"])));
    assert!(unverified_social_ok(
        true,
        &allowed,
        &idents(&["SignInWithApple"])
    ));
    // A provider not on the list is rejected.
    assert!(!unverified_social_ok(
        true,
        &allowed,
        &idents(&["Facebook"])
    ));
    // Any matching entry in a multi-identity token suffices.
    assert!(unverified_social_ok(
        true,
        &allowed,
        &idents(&["Facebook", "Google"])
    ));
}

#[test]
fn social_provider_names_joins() {
    assert_eq!(
        social_provider_names(&idents(&["Google", "Facebook"])),
        "Google,Facebook"
    );
    assert_eq!(
        social_provider_names(&[Identity {
            provider_name: None
        }]),
        "?"
    );
}

#[test]
fn claims_parse_identities_present_and_absent() {
    // Federated token carries `identities`; native token omits it.
    let social: Claims = serde_json::from_value(serde_json::json!({
        "email": "u@x.com",
        "email_verified": false,
        "token_use": "id",
        "identities": [{"providerName": "Google", "userId": "1", "primary": "true"}]
    }))
    .unwrap();
    assert_eq!(social.identities.len(), 1);
    assert_eq!(
        social.identities[0].provider_name.as_deref(),
        Some("Google")
    );

    let native: Claims = serde_json::from_value(serde_json::json!({
        "email": "u@x.com",
        "email_verified": true,
        "token_use": "id"
    }))
    .unwrap();
    assert!(native.identities.is_empty());
}

#[test]
fn cookie_value_parses_named() {
    let h = "a=1; bb_session=bb1.k1.1.aaa...bbb; c=2";
    assert_eq!(cookie_value(h, "bb_session"), Some("bb1.k1.1.aaa...bbb"));
    assert_eq!(cookie_value("bb_session_extra=x", "bb_session"), None);
    assert_eq!(cookie_value("", "bb_session"), None);
}

/// Only the cookie's name matters to `build_cookie` now; the rest are placeholders so
/// the literal compiles. Its *domain* is in the settings beside it: see `cookie_settings`.
fn cookie_cfg() -> Config {
    Config {
        listen: "127.0.0.1:4181".to_string(),
        hmac_keys: keys_one(),
        cookie_name: "bb_session".to_string(),
        original_url_header: "X-Original-URL".to_string(),
        // Off, which is what every test that is not about the audit wants: a suite that
        // wrote to a real path would have every test racing for one file.
        audit_file: String::new(),
        workers: 1,
    }
}

/// Compiled settings carrying just a cookie domain, which is the other half of what
/// `build_cookie` reads.
fn cookie_settings(domain: Option<&str>) -> Settings {
    bb_auth_core::compile_settings(&bb_auth_core::SettingsFile {
        version: bb_auth_core::SETTINGS_VERSION,
        gate: bb_auth_core::GateSettings {
            cookie_domain: domain.unwrap_or_default().to_string(),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap()
}

/// The line a single, estate-wide logout endpoint stands on: a browser matches a
/// `Set-Cookie` against what it stored by `(name, Domain, Path)`, so the expiring cookie
/// must name the same triple the minted one did. Make the clear host-only while the mint
/// is domain-wide and it misses in silence — the browser keeps the domain cookie, the
/// logout reports success, and every other host stays signed in.
#[test]
fn clearing_a_cookie_targets_the_same_cookie_it_minted() {
    let cfg = cookie_cfg();
    let st = cookie_settings(Some(".badbat75.com"));
    let minted = build_cookie(&cfg, &st, "bb1.k1.9999999999.ZWI.", 2_592_000);
    let cleared = build_cookie(&cfg, &st, "", 0);
    for attr in [
        "bb_session=",
        "Path=/",
        "Domain=.badbat75.com",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
    ] {
        assert!(minted.contains(attr), "mint lost {attr}: {minted}");
        assert!(cleared.contains(attr), "clear lost {attr}: {cleared}");
    }
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert!(!minted.contains("Max-Age=0"), "{minted}");

    // Host-only deployment (no cookie domain): neither carries a Domain, so the two
    // still address one cookie. What must never happen is one of them carrying it.
    let host_only = cookie_settings(None);
    assert!(!build_cookie(&cfg, &host_only, "v", 60).contains("Domain"));
    assert!(!build_cookie(&cfg, &host_only, "", 0).contains("Domain"));
}

#[test]
fn parse_bearer_extracts_token() {
    assert_eq!(parse_bearer("Bearer abc.def.ghi"), Some("abc.def.ghi"));
    assert_eq!(parse_bearer("bearer abc"), Some("abc")); // scheme case-insensitive
    assert_eq!(parse_bearer("BEARER   abc  "), Some("abc")); // token trimmed
    assert_eq!(parse_bearer("Basic abc"), None); // wrong scheme
    assert_eq!(parse_bearer("Bearer"), None); // no token
    assert_eq!(parse_bearer("Bearer "), None); // empty token
    assert_eq!(parse_bearer("Bearertoken"), None); // needs a space separator
    assert_eq!(parse_bearer(""), None);
}

#[test]
fn query_param_decodes_rd() {
    assert_eq!(
        query_param("/auth/logout?rd=%2Fapp1%2Fbye", "rd").as_deref(),
        Some("/app1/bye")
    );
    assert_eq!(
        query_param("/auth/logout?a=1&rd=https%3A%2F%2Fx.com%2Fz&b=2", "rd").as_deref(),
        Some("https://x.com/z")
    );
    assert_eq!(query_param("/auth/logout?rd=", "rd").as_deref(), Some(""));
    assert_eq!(query_param("/auth/logout?a=1", "rd"), None);
    assert_eq!(query_param("/auth/logout", "rd"), None);
}

/// The usual deployment: the apex plus every subdomain, enumerated.
/// The estate these tests are set on. One list, because the hosts are a setting now and
/// a fixture that compiled them separately from the one it writes into a settings file
/// would be testing two estates that happen to agree.
const BB_HOSTS: [&str; 2] = ["badbat75.com", "*.badbat75.com"];
fn bb_hosts() -> Vec<UrlPattern> {
    BB_HOSTS
        .iter()
        .map(|h| bb_auth_core::compile_host_pattern(h).unwrap())
        .collect()
}
/// The pool the fixture token was minted by, and therefore the only issuer that can
/// validate it. A setting now, so every fixture that reaches a token or renders a page
/// carries it.
const TEST_ISSUER: &str = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TESTPOOL";
const LOGIN: &str = "https://login.badbat75.com/";
/// The two OAuth endpoints `social_settings`'s domain derives, spelled out where a page
/// test needs them without a settings file in hand.
const TOKEN_URL: &str = "https://pool.auth.eu-central-1.amazoncognito.com/oauth2/token";
const CALLBACK_URL: &str = "https://auth.badbat75.com/auth/callback";
const CALLER: &str = "https://search.badbat75.com";

// --- the gate's own pages -----------------------------------------------

/// Compiled settings that enable the given social buttons, which is what decides whether
/// the sign-in page offers any: the env group only says what the pool federates.
fn settings_with_buttons(buttons: &[(&str, &str)]) -> Settings {
    social_settings("pool.auth.eu-central-1.amazoncognito.com", buttons)
}

/// Compiled settings for a deployment whose social sign-in is wired to `domain`, with one
/// button per `(identity_provider, app client)` pair. An empty `domain` is a deployment
/// with no social sign-in at all, which the compiler only accepts with no buttons.
fn social_settings(domain: &str, buttons: &[(&str, &str)]) -> Settings {
    bb_auth_core::compile_settings(&bb_auth_core::SettingsFile {
        version: bb_auth_core::SETTINGS_VERSION,
        gate: bb_auth_core::GateSettings {
            issuer: TEST_ISSUER.to_string(),
            client_id: "email-client".to_string(),
            oauth_domain: domain.to_string(),
            social_callback_url: if domain.is_empty() {
                String::new()
            } else {
                "https://auth.badbat75.com/auth/callback".to_string()
            },
            social_buttons: buttons
                .iter()
                .map(|(idp, aud)| {
                    bb_auth_core::SocialButtonSpec::Wired(bb_auth_core::WiredButton {
                        idp: idp.to_string(),
                        audience: aud.to_string(),
                    })
                })
                .collect(),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap()
}

/// Compiled settings with only the `ui` section set, which is all these pages read of
/// their own, plus the pool: the endpoint the page's script talks to is derived from it,
/// so a page fixture without one renders a page that can reach nothing.
fn ui_settings(ui: bb_auth_core::UiSettings) -> Settings {
    bb_auth_core::compile_settings(&bb_auth_core::SettingsFile {
        version: bb_auth_core::SETTINGS_VERSION,
        gate: bb_auth_core::GateSettings {
            issuer: TEST_ISSUER.to_string(),
            ..Default::default()
        },
        ui,
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn render_page_substitutes_once_and_leaves_an_unknown_placeholder_standing() {
    let subs = [
        ("__BB_A__", "<b>".to_string()),
        // A value that contains another placeholder: it must land as text, never be
        // substituted a second time, or a brand name could rewrite the page around it.
        ("__BB_B__", "__BB_A__".to_string()),
    ];
    assert_eq!(render_page("x __BB_A__ y", &subs), "x <b> y");
    assert_eq!(render_page("__BB_B__", &subs), "__BB_A__");
    // Unknown placeholders survive verbatim: a template that lost a substitution says so
    // on the page instead of quietly rendering a gap.
    assert_eq!(render_page("__BB_NOPE__", &subs), "__BB_NOPE__");
    assert_eq!(render_page("no placeholders", &subs), "no placeholders");
}

#[test]
fn the_login_page_is_whole_self_contained_and_escapes_its_one_request_value() {
    let page = login_page(
        &settings_with_buttons(&[("Google", "google-client"), ("Okta", "okta-client")]),
        "https://search.badbat75.com/?q=a\"b",
        "",
        "n0nce",
    );
    // Every placeholder was answered.
    assert!(!page.contains("__BB_"), "unsubstituted placeholder left");
    // The palette and the layout are IN the page: no stylesheet, script or font is
    // fetched from anywhere, which is the property this page exists to have.
    assert!(page.contains("--accent:"), "the palette is not inlined");
    assert!(page.contains(".card{"), "the layout is not inlined");
    assert!(
        !page.contains("<link"),
        "unconfigured, so nothing may be linked"
    );
    assert!(!page.contains("src=\"http"), "no external script or image");
    // The one request-supplied value is an escaped attribute, never JavaScript source.
    assert!(
        page.contains(r#"data-rd="https://search.badbat75.com/?q=a&quot;b""#),
        "{page}"
    );
    // The client id is the one the gate validates as an audience, by construction.
    assert!(
        page.contains(r#"var CLIENT_ID = "email-client";"#),
        "{page}"
    );
    assert!(page.contains(r#"var ENDPOINT = "https://cognito-idp.eu-central-1.amazonaws.com/";"#));
    // A known provider gets its icon, an unknown one gets a button anyway.
    assert!(page.contains(r#"data-idp="Google""#), "{page}");
    assert!(page.contains(r#"data-idp="Okta""#), "{page}");
    assert!(
        page.contains("data-i18n-arg=\"Okta\">Continue with Okta<"),
        "{page}"
    );
}

/// A provider is offered because somebody enabled it, and for no other reason.
///
/// The env group says what this deployment's app client federates and the settings say
/// what the page offers today, so a button needs both. The middle case below is the one
/// most worth a test: enabling something the pool does not federate must not draw a
/// button, because that button leads to Cognito explaining the mistake in Amazon's words
/// on Amazon's page, one redirect from somebody who was only trying to sign in.
#[test]
fn every_button_carries_its_own_app_client() {
    // Two providers, two app clients: the arrangement a single client id could not
    // express, and the reason the audience sits on the row rather than on the file.
    let page = login_page(
        &settings_with_buttons(&[("Google", "google-client"), ("Okta", "okta-client")]),
        "",
        "",
        "n0nce",
    );
    assert!(
        page.contains(r#"data-idp="Google" data-client-id="google-client""#),
        "{page}"
    );
    assert!(
        page.contains(r#"data-idp="Okta" data-client-id="okta-client""#),
        "{page}"
    );
    assert!(page.contains(r#"class="divider""#), "the section is there");
    // The email flow's own app client is the page's, and it is a different value.
    assert!(
        page.contains(r#"var CLIENT_ID = "email-client";"#),
        "{page}"
    );

    // File order is display order, because it is the operator's order.
    let both = login_page(
        &settings_with_buttons(&[("Okta", "okta-client"), ("Google", "google-client")]),
        "",
        "",
        "n0nce",
    );
    let okta = both.find(r#"data-idp="Okta""#).expect("okta");
    let google = both.find(r#"data-idp="Google""#).expect("google");
    assert!(okta < google, "the settings order is the display order");
}

#[test]
fn with_no_social_wiring_the_page_has_no_social_markup_at_all() {
    // No hosted-UI domain, which is the only way a file can say "no social sign-in":
    // `compile_settings` refuses buttons without one, so there is one such state and not
    // two that look different.
    let page = login_page(&social_settings("", &[]), "", "", "n0nce");
    assert!(!page.contains("data-idp="), "{page}");
    assert!(!page.contains(r#"class="divider""#), "{page}");
    assert!(page.contains(r#"var AUTHORIZE_URL = "";"#), "{page}");
    assert!(page.contains(r#"var CALLBACK_URL = "";"#), "{page}");
}

// --- the registration step's duplicate-account notice (docs §13.27) ------

/// The notice's two sentences, spelled exactly as `docs/ARCHITECTURE.md` §13.27 spells
/// them. Pinned verbatim rather than paraphrased: a paraphrase is red after the words
/// land and reads like a broken implementation, and the Italian is the half a stub gets
/// away with paraphrasing when only the English is asserted.
const DUP_EN: &str = "Do you usually sign in with one of the buttons below? Use it instead: signing up with a code creates a second, separate account.";
const DUP_IT: &str = "Di solito accedi con uno dei pulsanti qui sotto? Usa quello: registrarti con un codice crea un secondo account, separato.";

/// The two providers the design's fixture names, built as the compiled type, for the
/// tests that call `social_block` directly rather than through a page. Same order as
/// `login_with_buttons`, so a page assertion can compare against this block's bytes.
fn two_buttons() -> Vec<bb_auth_core::SocialButton> {
    vec![
        bb_auth_core::SocialButton {
            idp: "Google".to_string(),
            audience: "google-client".to_string(),
        },
        bb_auth_core::SocialButton {
            idp: "Okta".to_string(),
            audience: "okta-client".to_string(),
        },
    ]
}

/// The markup of one sign-in step: the region from the element carrying `id="FROM"` up to
/// the element carrying `id="TO"`. The three steps are siblings in file order and the
/// script's `getElementById` calls sit after all three forms, so the first match of each
/// id is the markup and the region is the step.
fn step_of<'a>(page: &'a str, from: &str, to: &str) -> &'a str {
    let at = page
        .find(&format!("id=\"{from}\""))
        .unwrap_or_else(|| panic!("no element with id={from}"));
    let open = page[..at].rfind('<').expect("an opening tag");
    let next = at
        + page[at..]
            .find(&format!("id=\"{to}\""))
            .expect("the next step");
    let close = open + page[open..next].rfind('<').expect("an opening tag");
    &page[open..close]
}

/// The opening tag of the element carrying `id="ID"`, `None` when there is none.
///
/// Read as a tag, not as a string search, because the notice is an element: the `I18N`
/// table carries the word `dup_note` and the English sentence on **every** deployment,
/// including the one with no buttons, so a string search cannot tell a panel from a
/// dictionary entry and an absence test written with one proves nothing.
fn open_tag(page: &str, id: &str) -> Option<String> {
    let at = page.find(&format!("id=\"{id}\""))?;
    let open = page[..at].rfind('<')?;
    let close = at + page[at..].find('>')? + 1;
    Some(page[open..close].to_string())
}

/// The text between the opening tag of `id="ID"` and the next `close`, trimmed.
fn element_text(page: &str, id: &str, close: &str) -> String {
    let tag = open_tag(page, id).expect("the element");
    let at = page.find(&tag).expect("the element");
    let rest = &page[at + tag.len()..];
    rest[..rest.find(close).expect("the closing tag")]
        .trim()
        .to_string()
}

/// Every `<button …>…</button>` inside the region's `div.social`, byte for byte. The
/// buttons are what the two steps must share; the wrapper's indentation is each block's
/// own, so the comparison is of the buttons and not of the markup around them.
fn social_buttons(region: &str) -> Vec<String> {
    let Some(at) = region.find("<div class=\"social\">") else {
        return Vec::new();
    };
    let end = at + region[at..].find("</div>").expect("the social div closes") + "</div>".len();
    region[at..end]
        .split("<button")
        .skip(1)
        .map(|b| {
            let close = b.find("</button>").expect("a closed button") + "</button>".len();
            format!("<button{}", &b[..close])
        })
        .collect()
}

/// The document with every `<script …>…</script>` and `<style …>…</style>` element
/// removed, so a scan of the markup sees attributes and not the page's own source: the
/// script's body is full of `on…` sequences (`addEventListener`) that are not handlers.
fn markup_only(page: &str) -> String {
    let mut out = page.to_string();
    for tag in ["script", "style"] {
        let open = format!("<{tag}");
        let close = format!("</{tag}>");
        while let Some(at) = out.find(&open) {
            match out[at..].find(&close) {
                Some(j) => out.replace_range(at..at + j + close.len(), ""),
                None => out.replace_range(at.., ""),
            }
        }
    }
    out
}

/// The event handler attributes in a document, with the script and style bodies out of it.
fn handler_attributes(page: &str) -> Vec<String> {
    let markup = markup_only(page);
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(off) = markup[at..].find(" on") {
        let name = at + off + 3;
        let mut end = name;
        while end < markup.len() && markup.as_bytes()[end].is_ascii_alphabetic() {
            end += 1;
        }
        if end < markup.len() && markup.as_bytes()[end] == b'=' {
            found.push(markup[name..end].to_string());
        }
        at = name;
    }
    found
}

/// The sign-in page of a deployment with the design's two buttons.
fn login_with_buttons() -> String {
    login_page(
        &settings_with_buttons(&[("Google", "google-client"), ("Okta", "okta-client")]),
        "",
        "",
        "n0nce",
    )
}

#[test]
fn the_registration_step_warns_before_a_duplicate_account() {
    let page = login_with_buttons();
    let tag = open_tag(&page, "dup-note").expect("the notice panel");
    // `.panel` and `.warn` are BASE_CSS's surface and state: no new class, no CSS change.
    assert!(tag.contains(r#"class="panel warn""#), "a warn panel: {tag}");
    // The script translates it, so it needs the attribute every translated element has.
    assert!(tag.contains(r#"data-i18n="dup_note""#), "{tag}");
    // Its static text is the English sentence, so the step reads correctly before the
    // script runs at all.
    assert_eq!(element_text(&page, "dup-note", "</p>"), DUP_EN);
    // The step's order: intro, notice, buttons, divider, fields. The notice sits between
    // the intro and the fields, and the buttons follow the panel in the same column, so
    // "the buttons below" is true at every width.
    let reg = step_of(&page, "register-form", "code-form");
    let note = reg
        .find(r#"id="dup-note""#)
        .expect("the notice is on the registration step");
    let social = reg
        .find("<div class=\"social\">")
        .expect("the buttons are on the registration step");
    let divider = social
        + reg[social..]
            .find(r#"class="divider""#)
            .expect("a divider follows");
    let given = reg.find(r#"id="given_name""#).expect("the name fields");
    assert!(
        note < social && social < divider && divider < given,
        "intro, notice, buttons, divider, fields: {reg}"
    );
}

#[test]
fn the_registration_step_repeats_the_email_step_buttons() {
    let page = login_with_buttons();
    let email = step_of(&page, "email-form", "register-form");
    let reg = step_of(&page, "register-form", "code-form");
    // The email step's buttons are hidden on this step (`.step{display:none}`), so the
    // notice's "use your provider" needs a way to do it on the step that says it.
    assert_eq!(
        page.matches(r#"data-idp="Google""#).count(),
        2,
        "one per step, no more: {page}"
    );
    assert!(!social_buttons(email).is_empty(), "step 1 has buttons");
    assert_eq!(
        social_buttons(reg),
        social_buttons(email),
        "the same buttons, not a second copy that drifted"
    );
    // The divider is the existing one, carrying its own translated word.
    assert!(reg.contains(r#"class="divider""#), "{reg}");
    assert!(reg.contains(r#"data-i18n="or""#), "{reg}");
}

#[test]
fn the_notice_words_are_pinned_in_both_languages() {
    // Both dictionaries carry the sentence on **every** deployment: the words are data in
    // the page's script, and the panel is what comes and goes.
    for page in [
        login_with_buttons(),
        login_page(&social_settings("", &[]), "", "", "n0nce"),
    ] {
        assert!(
            page.contains(&format!("dup_note: \"{DUP_EN}\"")),
            "the English dictionary: {page}"
        );
        assert!(
            page.contains(&format!("dup_note: \"{DUP_IT}\"")),
            "the Italian dictionary: {page}"
        );
    }
    assert_eq!(
        login_with_buttons().matches("dup_note:").count(),
        2,
        "one entry per dictionary"
    );
}

#[test]
fn the_notice_is_absent_where_there_are_no_social_buttons() {
    // Two shapes of "no buttons": no social wiring at all, and a hosted UI with an empty
    // button list. Both must produce the plain registration step, because a notice that
    // says "use one of the buttons below" above no buttons is worse than no notice.
    for settings in [
        social_settings("", &[]),
        social_settings("pool.auth.eu-central-1.amazoncognito.com", &[]),
    ] {
        let page = login_page(&settings, "", "", "n0nce");
        assert!(open_tag(&page, "dup-note").is_none(), "{page}");
        assert!(!page.contains(r#"data-i18n="dup_note""#), "{page}");
        assert!(!page.contains("data-idp="), "{page}");
        assert!(
            !page.contains(r#"class="divider""#),
            "no stray divider: {page}"
        );
        // The template's new placeholder is answered even when there is nothing to put
        // in it: an unfilled one is visible on the page.
        assert!(!page.contains("__BB_"), "unfilled placeholder: {page}");
    }
}

#[test]
fn the_name_field_is_described_by_the_intro_and_the_notice() {
    // The script moves focus to `#given_name` when the step opens, so a screen-reader
    // user lands after the notice and never hears it unless the field points at it. On a
    // deployment with no buttons `dup-note` is no element, and an IDREF that matches
    // nothing is ignored when the description is computed, so one template serves both.
    for page in [
        login_with_buttons(),
        login_page(&social_settings("", &[]), "", "", "n0nce"),
    ] {
        let tag = open_tag(&page, "given_name").expect("the name field");
        assert!(
            tag.contains(r#"aria-describedby="register-intro dup-note""#),
            "{tag}"
        );
    }
}

#[test]
fn the_email_step_is_unchanged_by_the_notice() {
    let page = login_with_buttons();
    let email = step_of(&page, "email-form", "register-form");
    let divider = email
        .find(r#"class="divider""#)
        .expect("the email step's divider");
    let first_button = email
        .find("data-idp=")
        .expect("the email step's first button");
    assert!(
        divider < first_button,
        "the divider precedes the buttons: {email}"
    );
    // File order is still display order, on the step that has always shown them.
    let both = login_page(
        &settings_with_buttons(&[("Okta", "okta-client"), ("Google", "google-client")]),
        "",
        "",
        "n0nce",
    );
    assert!(
        both.find(r#"data-idp="Okta""#) < both.find(r#"data-idp="Google""#),
        "{both}"
    );
    // The step is built by `social_block`, whose output the factoring must leave alone.
    assert!(
        page.contains(&social_block(&two_buttons())),
        "the email step carries social_block's bytes: {page}"
    );
}

#[test]
fn social_blocks_bytes_are_unchanged_by_the_factoring() {
    // §13.27 factors the per-button loop out of `social_block` and promises its output
    // stays byte for byte the same. This is that promise: the exact bytes for two
    // providers, one with an icon and one without, including the whitespace the empty
    // icon leaves behind. A moved byte here is a diff in the page the script binds.
    let icon = IDP_ICONS
        .iter()
        .find(|(name, _)| *name == "Google")
        .map(|(_, svg)| *svg)
        .expect("the fixture provider has an icon");
    let want = [
            r#"      <div class="divider"><span data-i18n="or">or</span></div>"#,
            r#"      <div class="social">"#,
            r#"        <button type="button" class="social-btn" data-idp="Google" data-client-id="google-client">"#,
            &format!("          {icon}"),
            r#"          <span data-i18n="btn_social" data-i18n-arg="Google">Continue with Google</span>"#,
            "        </button>",
            r#"        <button type="button" class="social-btn" data-idp="Okta" data-client-id="okta-client">"#,
            // The provider with no icon still gets its line: the empty icon is an empty
            // string, and the indentation around it is part of the bytes.
            r#"          "#,
            r#"          <span data-i18n="btn_social" data-i18n-arg="Okta">Continue with Okta</span>"#,
            "        </button>",
            "      </div>",
        ]
        .join("\n");
    assert_eq!(social_block(&two_buttons()), want);
    // And the empty list is still the empty string: one way for the section to be absent.
    assert_eq!(social_block(&[]), "");
}

#[test]
fn the_notice_adds_no_script_and_the_policy_still_names_one() {
    // The notice is markup and two dictionary strings. No new script element, no handler,
    // and the nonce policy that covers the page's one inline script is unchanged: a
    // second script, or a source added to `script-src` to make one run, is the widening
    // this pins out.
    let base = serve(token_state(gate_settings(&format!(
        r#"{{ "oauth_domain": "pool.auth.eu-central-1.amazoncognito.com",
                  "social_callback_url": "{CALLBACK_URL}",
                  "social_buttons": [{{ "idp": "Google", "audience": "social-client" }}] }}"#
    ))));
    let mut r = agent().get(format!("{base}/auth/login")).call().unwrap();
    assert_eq!(r.status(), 200);
    let csp = r
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let body = r.body_mut().read_to_string().unwrap();
    // The page under test is the one carrying the notice.
    assert!(body.contains(r#"id="dup-note""#), "{body}");
    assert_eq!(body.matches("<script").count(), 1, "one script element");
    assert_eq!(body.matches("<style").count(), 1, "one style element");
    assert!(handler_attributes(&body).is_empty(), "no handler attribute");
    let nonce = csp
        .split("'nonce-")
        .nth(1)
        .and_then(|t| t.split('\'').next())
        .expect("a nonce in the policy")
        .to_string();
    assert!(
        body.contains(&format!("<script nonce=\"{nonce}\">")),
        "the script carries the policy's nonce"
    );
    assert!(
        body.contains(&format!("<style nonce=\"{nonce}\">")),
        "the stylesheet carries the policy's nonce"
    );
    // The semicolon is part of the assertion: it says nothing was added beside the nonce.
    assert!(
        csp.contains(&format!("script-src 'nonce-{nonce}';")),
        "{csp}"
    );
    assert!(!csp.contains("unsafe-inline"), "{csp}");
}

// --- the deletion notice on the sign-in page (docs §13.33) ----------------

/// The notice's sentences, spelled exactly as `docs/ARCHITECTURE.md` §13.33 §1 spells
/// them, in both languages. Pinned verbatim and not paraphrased: a paraphrase is red
/// after the words land and reads like a broken implementation, and the Italian is the
/// half a stub gets away with paraphrasing when only the English is asserted. The words
/// say `queued` and never `deleted`, because that is all this estate can claim (§13.29
/// W6), and the last sentence is the accepted gap of §13.32 §2. The middle sentence is
/// the slice 14e narrowing (2026-11-26): signing in again *does* create an account here,
/// so only an email-code sign-in that skips registration is the failure an administrator
/// must hear of, and a Google or Microsoft sign-in recreates the user at once.
const NOTICE_EN: &str = "Your account is being deleted: this browser is signed out, and your sign-in accounts are queued for deletion. Signing in again later creates a new account; if you use an email code and are not asked to sign up first, tell an administrator. Other browsers where you signed in stay signed in until you sign out there or the session ends.";
const NOTICE_IT: &str = "Il tuo account è in fase di eliminazione: questo browser è disconnesso e i tuoi account di accesso sono in coda per l'eliminazione. Se accedi di nuovo più avanti viene creato un nuovo account; se usi un codice via email e non ti viene chiesto prima di registrarti, avvisa un amministratore. Gli altri browser in cui avevi effettuato l'accesso restano connessi finché non esci da lì o la sessione non termina.";

/// The clause slice 14e retired, in both languages: "If you can still sign in later
/// without signing up again, tell an administrator". It is false for a federated account,
/// which is recreated on the fly, so it blamed the deletion service for a normal
/// sign-in (§13.33 §1). Pinned as an absence, one spelling per language, so a page that
/// moved the element's text but left the old sentence in a dictionary arm is red.
const NOTICE_RETIRED: [(&str, &str); 2] = [
    ("en", "without signing up again"),
    ("it", "senza registrarti di nuovo"),
];

/// The dictionary key the element names. One key for both arms, since the notice cannot
/// tell a roster caller from a stranger (§13.32 §3): one code, one key, one sentence.
const NOTICE_KEY: &str = "notice_account_deleted";

/// The sign-in page as it is served to a browser arriving at
/// `/auth/login?notice=CODE`. A deployment with no social sign-in: the notice's presence
/// must not depend on any other section of the page.
fn login_page_notice(notice: &str) -> String {
    login_page(&social_settings("", &[]), "", notice, "n0nce")
}

/// One arm of the page's `I18N` dictionary: the region from `NAME: {` to the next arm
/// (`en` is the last, so the region runs to the script's first statement after the
/// dictionary). A check that reads the page as a whole cannot tell a translation from the
/// *other* arm, and both arms have to carry the key: `applyLang` sets the text of every
/// `[data-i18n]` element from the arm it is showing, so a key in one arm only is an
/// English sentence sitting in an Italian page.
fn i18n_arm(page: &str, arm: &str) -> String {
    let at = page
        .find(&format!("{arm}: {{"))
        .unwrap_or_else(|| panic!("the page's dictionary has no `{arm}` arm"));
    let end = match arm {
        "it" => at + page[at..].find("en: {").expect("the `en` arm follows `it`"),
        _ => {
            at + page[at..]
                .find("var msgEl")
                .expect("the dictionary ends where the script's next statement begins")
        }
    };
    page[at..end].to_string()
}

/// The line of `dict` that carries `KEY:`, for a failure message. Printing the whole arm
/// is 80 lines of other people's translations, which hides the one line that moved.
fn dict_entry(dict: &str, key: &str) -> String {
    match dict
        .lines()
        .find(|l| l.trim_start().starts_with(&format!("{key}:")))
    {
        Some(l) => l.trim().to_string(),
        None => format!("no `{key}:` entry at all"),
    }
}

/// Every rule of a stylesheet, in file order, as `(selector, declarations)`, with comments
/// removed. These stylesheets are flat, and their prose names selectors and declarations
/// as data on purpose, so a scan that kept the comments would read the documentation as
/// rules.
fn css_rules(css: &str) -> Vec<(String, String)> {
    let mut code = String::new();
    let mut rest = css;
    while let Some(open) = rest.find("/*") {
        code.push_str(&rest[..open]);
        match rest[open..].find("*/") {
            Some(close) => rest = &rest[open + close + 2..],
            None => break,
        }
    }
    code.push_str(rest);
    let mut rules = Vec::new();
    let mut rest = code.as_str();
    while let Some(open) = rest.find('{') {
        let head = rest[..open].trim().trim_matches('}').trim().to_string();
        let Some(close) = rest[open..].find('}') else {
            break;
        };
        rules.push((head, rest[open + 1..open + close].trim().to_string()));
        rest = &rest[open + close + 1..];
    }
    rules
}

#[test]
fn the_sign_in_page_shows_the_deletion_notice_only_for_its_code() {
    // The code is the library's, not this test's: §13.32 §1 puts it in `bb_auth_core`
    // because `bb-auth-web` writes it into the logout's `rd` and this page reads it back.
    let shown = login_page_notice(bb_auth_core::LOGIN_NOTICE_ACCOUNT_DELETED);
    let tag = open_tag(&shown, "notice").expect("the notice element");
    assert!(
        !tag.contains("hidden"),
        "the code matches, so it shows: {tag}"
    );
    // The markup §13.33 §2 chose: the box the page already has for a message, in its
    // success arm, a status region (not `role="alert"`: nothing went wrong), and the key
    // the page's own script translates it by.
    assert!(tag.contains(r#"class="msg ok show""#), "{tag}");
    assert!(tag.contains(r#"role="status""#), "{tag}");
    assert!(
        tag.contains(&format!(r#"data-i18n="{NOTICE_KEY}""#)),
        "{tag}"
    );
    // Between the brand and the form's message box, and never inside it: the script
    // empties `#msg` on every step, so a notice in there is erased by the first click.
    let brand = shown.find(r#"class="brand""#).expect("the brand block");
    let at = shown.find(r#"id="notice""#).expect("the notice");
    let msg = shown.find(r#"id="msg""#).expect("the message box");
    assert!(
        brand < at && at < msg,
        "brand, notice, message box: {brand} {at} {msg}"
    );
    // The email field has `autofocus`, so focus lands below the notice and a
    // screen-reader user starts past it. With the code present the field names the
    // notice, and it is read when the field takes focus.
    let email = open_tag(&shown, "email").expect("the email input");
    assert!(
        email.contains(r#"aria-describedby="notice""#),
        "the field must carry the notice it lands under: {email}"
    );

    // Every other request shows nothing. `""` is both "no `notice`" and `notice=`; the
    // mixed-case value is the one a case-insensitive compare would let in, and the
    // design's closed set is exactly one value.
    for notice in [
        "",
        "other",
        "ACCOUNT-DELETED",
        "Account-Deleted",
        "account-deleted-x",
        "x-account-deleted",
        "<script>x</script>",
    ] {
        let page = login_page_notice(notice);
        // The element is in the page on every deployment: it is a template element with
        // the `hidden` attribute, not markup that comes and goes, which is what keeps the
        // `aria-describedby` a plain IDREF and the page's byte size fixed.
        let tag = open_tag(&page, "notice").expect("the notice element");
        assert!(
            tag.contains("hidden"),
            "`notice={notice}` must not show the notice: {tag}"
        );
        // And the field must not point at it: a `hidden` element named by
        // `aria-describedby` is still read (ACCNAME 1.2 step 2A), so an unconditional
        // attribute reads a sentence about a deletion to every visitor.
        let email = open_tag(&page, "email").expect("the email input");
        assert!(
            !email.contains("aria-describedby"),
            "`notice={notice}` must leave the field alone: {email}"
        );
        // No byte of the query reaches the page, in either spelling a reflection would
        // take. The page carries a `<script>` of its own, so the whole value is searched.
        assert!(
            !page.contains("<script>x</script>"),
            "`notice=<script>x</script>` is on the page as markup: the value is echoed"
        );
        assert!(
            !page.contains("&lt;script&gt;x&lt;/script&gt;"),
            "`notice=<script>x</script>` is on the page escaped: the value is echoed"
        );
    }
    // Including the code that does show it: a code selects an element, it is never
    // reflected into the page that holds it. The dictionary key is spelled with
    // underscores, so the hyphenated code is the one that must be absent.
    assert!(
        !shown.contains(bb_auth_core::LOGIN_NOTICE_ACCOUNT_DELETED),
        "the code selects the notice and appears nowhere in the page"
    );
}

#[test]
fn the_deletion_notice_speaks_both_languages() {
    let page = login_page_notice(bb_auth_core::LOGIN_NOTICE_ACCOUNT_DELETED);
    // The element's own text is the English sentence, so the page reads correctly in the
    // half-second before its script runs, and on a browser running no script at all.
    assert_eq!(element_text(&page, "notice", "</p>"), NOTICE_EN);
    // Each arm carries §13.33 §1's sentence for its own language, verbatim, and both arms
    // have to carry it: `applyLang` sets the text of every `[data-i18n]` element from the
    // arm it is showing, so a key in one arm only is an English sentence sitting in an
    // Italian page, and a key in neither is an **empty** notice, the script clearing the
    // text of an element it cannot translate. The English one is pinned twice over: what
    // the person reads is the element's text, and what the script writes back on an
    // English page must be the same bytes.
    for (arm, words) in [("en", NOTICE_EN), ("it", NOTICE_IT)] {
        let dict = i18n_arm(&page, arm);
        assert!(
            dict.contains(&format!(r#"{NOTICE_KEY}: "{words}""#)),
            "the `{arm}` arm must carry the §13.33 sentence verbatim, and it says: {}",
            dict_entry(&dict, NOTICE_KEY)
        );
    }
    // Slice 14e: the retired clause is gone from the two texts and from every byte of
    // the served page. The const check keeps a paste of the old wording out of this
    // test, where it would make each assert above vacuous; the page check is the one
    // that bites, because the sentence lives in three places (the element's text and
    // both dictionary arms) and an edit of one leaves the others standing.
    for (arm, retired) in NOTICE_RETIRED {
        assert!(
            !NOTICE_EN.contains(retired) && !NOTICE_IT.contains(retired),
            "the §13.33 §1 texts must not carry the retired {arm} clause {retired:?}"
        );
        assert!(
            !page.contains(retired),
            "the page served for the deletion notice still carries the retired {arm} \
                 clause {retired:?}"
        );
    }
    // One entry per dictionary, as the page's one other translated notice is pinned: a
    // second key is a second sentence to keep true for no new decision (§13.32 §3).
    assert_eq!(
        page.matches(&format!("{NOTICE_KEY}:")).count(),
        2,
        "one entry per arm, and the element's key is not a dictionary entry"
    );
}

#[test]
fn the_auth_css_hides_a_hidden_message() {
    // §13.33 §2: the notice is `class="msg ok show"` and is hidden with the `hidden`
    // attribute. A bare `[hidden]{display:none}` does not hide it, because `.msg.show`
    // (two classes) outranks one attribute selector. The two rules have the same
    // specificity (0,2,0), so the one that wins is the one that comes **later**, and a
    // rule written above `.msg.show` is a notice shown to every visitor.
    let rules = css_rules(AUTH_CSS);
    let show = rules
        .iter()
        .position(|(s, _)| s == ".msg.show")
        .expect("`.msg.show` is the rule the notice needs to beat");
    let hidden = rules
        .iter()
        .position(|(s, _)| s == ".msg[hidden]")
        .expect("`.msg[hidden]`: §13.33 §2 adds it, and nothing else hides a `.show` box");
    assert!(
        hidden > show,
        "`.msg[hidden]` must come after `.msg.show`: they are equal on specificity, so \
             order is the whole tie-break and above it the box never closes"
    );
    // Each rule says the thing the order is about: `show` opens the box, `[hidden]`
    // closes it. A rule that closes a box it never opened proves nothing.
    assert!(
        rules[show].1.replace(' ', "").contains("display:block"),
        "`.msg.show` must show it: {:?}",
        rules[show]
    );
    assert!(
        rules[hidden].1.replace(' ', "").contains("display:none"),
        "`.msg[hidden]` must hide it: {:?}",
        rules[hidden]
    );
    // And the box is hidden by default, which is why `show` is on the notice statically:
    // an empty message box must never occupy space above the form.
    let bare = rules
        .iter()
        .find(|(s, _)| s == ".msg")
        .expect("the bare `.msg` rule");
    assert!(
        bare.1.replace(' ', "").contains("display:none"),
        "the box is hidden until it has something to say: {:?}",
        bare
    );
}

#[test]
fn the_audiences_are_the_app_clients_the_file_names() {
    // Nothing else in the system says which app clients this gate is part of, so the
    // list is derived rather than kept in step by hand: the email flow's, then each
    // button's, deduplicated and in file order.
    let s = settings_with_buttons(&[("Google", "google-client"), ("Okta", "okta-client")]);
    assert_eq!(
        s.audiences,
        ["email-client", "google-client", "okta-client"]
    );

    // Two buttons through one app client name it once.
    let shared = settings_with_buttons(&[("Google", "one-client"), ("Okta", "one-client")]);
    assert_eq!(shared.audiences, ["email-client", "one-client"]);
}

#[test]
fn a_rejected_rd_is_dropped_rather_than_carried_to_the_page() {
    // `handle_login` filters with the same `rd_url_allowed` `safe_rd` uses; this pins the
    // pairing that makes the two agree.
    let hosts = bb_hosts();
    assert!(rd_url_allowed("https://search.badbat75.com/x", &hosts));
    assert!(!rd_url_allowed("https://evil.example.com/", &hosts));
    let page = login_page(
        &ui_settings(bb_auth_core::UiSettings::default()),
        "",
        "",
        "n0nce",
    );
    assert!(page.contains(r#"data-rd=""#), "{page}");
}

#[test]
fn the_operator_stylesheet_is_linked_after_the_built_in_one_on_every_page() {
    let ui = bb_auth_core::UiSettings {
        stylesheet_url: "https://assets.badbat75.com/css/theme.css".to_string(),
        logo_url: "/img/logo.png".to_string(),
        brand_name: "BadBat75".to_string(),
        theme: "dark".to_string(),
    };
    let settings = ui_settings(ui);
    for page in [
        login_page(&settings, "", "", "n0nce"),
        callback_page(TOKEN_URL, CALLBACK_URL, &settings, "n0nce"),
    ] {
        let style = page.find("<style ").expect("the built-in stylesheet");
        let tokens = page.find("--accent:").expect("the palette");
        let components = page.find(".pill{").expect("the shared components");
        let layout = page
            .find(".lang-toggle{")
            .expect("this page's own arrangement");
        let link = page.find("<link rel=\"stylesheet\"").expect("the override");
        // Order is the contract, and it is four deep: the palette, the components that
        // read it, this page's arrangement of them, then the override, which wins by
        // source order and therefore needs no `!important` and no knowledge of what it is
        // overriding. The first two are the same bytes bb-auth-web emits, which is what
        // makes the sign-in page and the admin interface one product rather than two that
        // were once made to match.
        assert!(
            style < tokens && tokens < components && components < layout && layout < link,
            "the override must come after the built-in one"
        );
        assert!(page.contains(r#"data-theme="dark""#), "{page}");
        assert!(page.contains("<h1>BadBat75</h1>"), "{page}");
        assert!(
            page.contains(r#"<img src="/img/logo.png" alt="">"#),
            "{page}"
        );
    }
}

#[test]
fn the_callback_page_names_the_registered_redirect_uri_and_no_app_client() {
    let page = callback_page(
        TOKEN_URL,
        CALLBACK_URL,
        &ui_settings(bb_auth_core::UiSettings::default()),
        "n0nce",
    );
    assert!(!page.contains("__BB_"), "unsubstituted placeholder left");
    // The value Cognito compares byte for byte with the client's registered callback.
    assert!(page.contains(r#"var CALLBACK_URL = "https://auth.badbat75.com/auth/callback";"#));
    // And no app client of its own: it exchanges with whichever one the button that
    // started this leg named, which only sessionStorage knows.
    assert!(page.contains(r#"var SOCIAL_CLIENT_ID = "";"#), "{page}");
    assert!(
        page.contains(r#"sessionStorage.getItem("bb_social_client")"#),
        "{page}"
    );
}

#[test]
fn origin_of_extracts_scheme_and_host() {
    assert_eq!(
        origin_of("https://app.example.com/auth/session").as_deref(),
        Some("https://app.example.com")
    );
    assert_eq!(
        origin_of("https://app.example.com").as_deref(),
        Some("https://app.example.com")
    );
    assert_eq!(origin_of("/just/a/path"), None);
    assert_eq!(origin_of("https:///nohost"), None);
}

#[test]
fn safe_rd_resolves_relative_against_the_caller() {
    let h = bb_hosts();
    // a relative rd lands on whichever host the login happened on …
    assert_eq!(
        safe_rd(Some("/preferences"), Some(CALLER), &h, LOGIN, ""),
        "https://search.badbat75.com/preferences"
    );
    assert_eq!(
        safe_rd(
            Some("/q?x=1"),
            Some("https://mcp.badbat75.com"),
            &h,
            LOGIN,
            ""
        ),
        "https://mcp.badbat75.com/q?x=1"
    );
    // … and with no rd at all, on that host's root
    assert_eq!(
        safe_rd(None, Some(CALLER), &h, LOGIN, ""),
        "https://search.badbat75.com/"
    );
    assert_eq!(
        safe_rd(Some(""), Some(CALLER), &h, LOGIN, ""),
        "https://search.badbat75.com/"
    );
    // no caller origin (nginx didn't send the header) => the login page
    assert_eq!(safe_rd(Some("/preferences"), None, &h, LOGIN, ""), LOGIN);
    assert_eq!(safe_rd(None, None, &h, LOGIN, ""), LOGIN);
}

#[test]
fn safe_rd_allows_authorized_hosts() {
    let h = bb_hosts();
    for rd in [
        "https://mcp.badbat75.com/mcp/foo",
        "https://search.badbat75.com/q?x=1",
        "https://badbat75.com/", // the apex, listed explicitly
    ] {
        assert_eq!(
            safe_rd(Some(rd), Some(CALLER), &h, LOGIN, ""),
            rd,
            "rd={rd}"
        );
    }
}

#[test]
fn safe_rd_blocks_open_redirect_and_splitting() {
    let h = bb_hosts();
    let f = |rd: &str| safe_rd(Some(rd), Some(CALLER), &h, LOGIN, "");
    // scheme-relative + backslash variant (browsers normalise `/\` -> `//`)
    assert_eq!(f("//evil.com"), LOGIN);
    assert_eq!(f("/\\evil.com"), LOGIN);
    // response splitting via CRLF / control bytes
    assert_eq!(f("/\r\nSet-Cookie: x=1"), LOGIN);
    assert_eq!(f("/x\x00y"), LOGIN);
    assert_eq!(f("/q\x7f"), LOGIN);
    // off-host absolute URL
    assert_eq!(f("https://evil.com/"), LOGIN);
}

#[test]
fn safe_rd_rejects_lookalikes_and_tricks() {
    let h = bb_hosts();
    let f = |rd: &str| safe_rd(Some(rd), Some(CALLER), &h, LOGIN, "");
    assert_eq!(f("https://evilbadbat75.com/"), LOGIN); // suffix without the dot
    assert_eq!(f("https://badbat75.com.evil.com/"), LOGIN); // base as a left label
    assert_eq!(f("https://mcp.badbat75.com@evil.com/"), LOGIN); // userinfo: real host is evil.com
    assert_eq!(f("https://mcp.badbat75.com\\@evil.com/"), LOGIN); // backslash in authority
    assert_eq!(f("http://mcp.badbat75.com/"), LOGIN); // non-https
    assert_eq!(f("//mcp.badbat75.com/"), LOGIN); // scheme-relative

    // A spoofed caller origin cannot smuggle a redirect either: the resolved
    // candidate goes through the same host gate.
    assert_eq!(
        safe_rd(Some("/x"), Some("https://evil.com"), &h, LOGIN, ""),
        LOGIN
    );
}

#[test]
fn rd_candidate_is_the_link_then_the_browser() {
    let (rd, refr) = (Some("rd"), Some("refr"));
    assert_eq!(rd_candidate(rd, refr), Some("rd"));
    assert_eq!(rd_candidate(None, refr), Some("refr"));
    assert_eq!(rd_candidate(rd, None), Some("rd"));
    assert_eq!(rd_candidate(None, None), None);
    // An empty value is what a template renders from an empty variable, so it counts as
    // nothing said and the Referer answers.
    assert_eq!(rd_candidate(Some(""), refr), Some("refr"));
    assert_eq!(rd_candidate(Some(""), Some("")), None);
}

#[test]
fn login_rd_falls_back_to_the_referer() {
    let h = bb_hosts();
    let f = |rd: Option<&str>, r: Option<&str>| login_rd(rd, r, &h);
    let came_from = "https://search.badbat75.com/q";
    // The link's own rd wins; the Referer answers when there is none, or an empty one.
    assert_eq!(
        f(Some("https://mcp.badbat75.com/x"), Some(came_from)),
        "https://mcp.badbat75.com/x"
    );
    assert_eq!(f(None, Some(came_from)), came_from);
    assert_eq!(f(Some(""), Some(came_from)), came_from);
    assert_eq!(f(None, None), "");
    // Same gate as an rd, and a rejected candidate leaves the page with no rd at all
    // rather than sending the person away: they came here to sign in.
    assert_eq!(f(None, Some("https://evil.com/")), ""); // a link from anywhere
    assert_eq!(f(None, Some("http://mcp.badbat75.com/")), "");
    assert_eq!(f(None, Some("/relative")), ""); // absolute URLs only, on this page
                                                // Whoever spoke first is answered on its own merits: a rejected rd does not promote
                                                // the Referer, or a crafted link would choose which of the two is read.
    assert_eq!(f(Some("https://evil.com/"), Some(came_from)), "");
}

#[test]
fn logout_target_prefers_the_link_then_the_referer() {
    let h = bb_hosts();
    let f = |rd: Option<&str>, r: Option<&str>| logout_target(rd, r, Some(CALLER), &h, LOGIN);
    let came_from = "https://search.badbat75.com/q";
    // The rd was written for this link, so it wins over the browser's account of where
    // the person came from.
    assert_eq!(
        f(Some("/bye"), Some(came_from)),
        "https://search.badbat75.com/bye"
    );
    assert_eq!(f(None, Some(came_from)), came_from);
    assert_eq!(f(Some(""), Some(came_from)), came_from);
    // A relative candidate resolves against the caller, exactly as a relative rd does.
    assert_eq!(f(None, Some("/bye")), "https://search.badbat75.com/bye");
    // Neither: the login page, never safe_rd's caller-root default, which would send the
    // browser back into the area it was just signed out of.
    assert_eq!(f(None, None), LOGIN);
    assert_eq!(f(Some(""), Some("")), LOGIN);
    assert_eq!(logout_target(None, None, None, &h, LOGIN), LOGIN);
}

#[test]
fn logout_target_guards_the_referer_like_an_rd() {
    let h = bb_hosts();
    let f = |r: &str| logout_target(None, Some(r), Some(CALLER), &h, LOGIN);
    assert_eq!(f("https://evil.com/"), LOGIN); // off-host: a link from anywhere
    assert_eq!(f("//evil.com"), LOGIN); // scheme-relative
    assert_eq!(f("http://mcp.badbat75.com/"), LOGIN); // not https
    assert_eq!(f("https://mcp.badbat75.com@evil.com/"), LOGIN); // userinfo
    assert_eq!(f("/\r\nSet-Cookie: x=1"), LOGIN); // response splitting
}

const LANDING: &str = "https://auth.badbat75.com/account/";

/// `gate.landing_url` is the no-`rd` arm and nothing else: a present `rd` wins, a rejected
/// one is still an attack or a mistake and still goes to the sign-in page, and the landing
/// page itself goes through `rd_url_allowed` at use time, because the settings file may
/// have been edited since it was compiled.
#[test]
fn safe_rd_with_no_rd_lands_on_the_landing_url() {
    let h = bb_hosts();
    // Nothing said, or an empty rd: the landing page, ahead of the caller's root.
    for rd in [None, Some("")] {
        assert_eq!(
            safe_rd(rd, Some(CALLER), &h, LOGIN, LANDING),
            LANDING,
            "{rd:?}"
        );
        // With no caller origin the arm used to fall back to the login page.
        assert_eq!(safe_rd(rd, None, &h, LOGIN, LANDING), LANDING, "{rd:?}");
        // No landing configured: the caller's root, exactly as before.
        assert_eq!(
            safe_rd(rd, Some(CALLER), &h, LOGIN, ""),
            "https://search.badbat75.com/"
        );
    }
    // A present, valid rd (relative or absolute) still wins.
    assert_eq!(
        safe_rd(Some("/preferences"), Some(CALLER), &h, LOGIN, LANDING),
        "https://search.badbat75.com/preferences"
    );
    assert_eq!(
        safe_rd(
            Some("https://mcp.badbat75.com/x"),
            Some(CALLER),
            &h,
            LOGIN,
            LANDING
        ),
        "https://mcp.badbat75.com/x"
    );
    // A rejected rd is not promoted to the landing page.
    for bad in [
        "https://evil.com/",
        "//evil.com",
        "/\\evil.com",
        "/a\r\nX: y",
    ] {
        assert_eq!(
            safe_rd(Some(bad), Some(CALLER), &h, LOGIN, LANDING),
            LOGIN,
            "{bad}"
        );
    }
    // The landing page is checked when used: one off the estate, or not https, is refused
    // and the login page answers.
    for bad in ["https://evil.com/account/", "http://auth.badbat75.com/"] {
        assert_eq!(safe_rd(None, Some(CALLER), &h, LOGIN, bad), LOGIN, "{bad}");
    }
}

/// A logout with nothing said ends at the sign-in page even when a landing page is set:
/// `logout_target` is deliberately unchanged, and the sign-in it leads to lands there.
#[test]
fn logout_with_nothing_said_still_ends_at_the_login_page() {
    let base = serve(token_state(gate_settings(&format!(
        r#"{{ "landing_url": "{LANDING}" }}"#
    ))));
    let r = agent().get(format!("{base}/auth/logout")).call().unwrap();
    assert_eq!(r.status(), 302);
    assert_eq!(r.headers().get("Location").unwrap(), LOGIN);
    // An empty rd is nothing said as well.
    let r = agent()
        .get(format!("{base}/auth/logout?rd="))
        .call()
        .unwrap();
    assert_eq!(r.headers().get("Location").unwrap(), LOGIN);
}

#[test]
fn a_session_with_no_rd_redirects_to_the_landing_url() {
    let go = |gate: &str, fields: &[(&str, &str)], caller: Option<&str>| {
        let base = serve(token_state(gate_settings(gate)));
        let mut req = agent()
            .post(format!("{base}/auth/session"))
            .header("Sec-Fetch-Site", "same-origin");
        if let Some(c) = caller {
            req = req.header("X-Original-URL", c);
        }
        let mut form = vec![("id_token", IT_TOKEN_OK)];
        form.extend_from_slice(fields);
        let r = req.send_form(form).unwrap();
        assert_eq!(r.status(), 302);
        assert!(r.headers().get("Set-Cookie").is_some());
        r.headers()
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    };
    let set = format!(r#"{{ "landing_url": "{LANDING}" }}"#);
    // No rd, an empty rd, and with or without a caller origin: the landing page.
    assert_eq!(go(&set, &[], None), LANDING);
    assert_eq!(go(&set, &[("rd", "")], None), LANDING);
    assert_eq!(
        go(&set, &[], Some("https://search.badbat75.com/x")),
        LANDING
    );
    // A given rd still wins.
    assert_eq!(
        go(&set, &[("rd", "https://search.badbat75.com/x")], None),
        "https://search.badbat75.com/x"
    );
    // A rejected rd goes to the sign-in page, not the landing page.
    assert_eq!(go(&set, &[("rd", "https://evil.com/")], None), LOGIN);
    // No landing configured: today's behaviour, the caller's root.
    assert_eq!(
        go("{}", &[], Some("https://search.badbat75.com/x")),
        "https://search.badbat75.com/"
    );
}

/// `--check-settings` names the landing page, and says what an empty one means, because an
/// operator reading it should not have to know that "nothing" is the caller's root.
#[test]
fn check_settings_names_the_landing_page() {
    let report = |gate: &str| settings_report("s.json", &gate_settings(gate));
    let set = report(&format!(r#"{{ "landing_url": "{LANDING}" }}"#));
    let line = set
        .lines()
        .find(|l| l.contains("landing"))
        .unwrap_or_else(|| panic!("no landing line: {set}"));
    assert!(line.contains(LANDING), "{line}");
    let unset = report("{}");
    let line = unset
        .lines()
        .find(|l| l.contains("landing"))
        .unwrap_or_else(|| panic!("no landing line: {unset}"));
    assert!(line.contains("(none"), "{line}");
    assert!(!line.contains("https://"), "{line}");
}

/// The refusal page's sign-out, which is the one link in this repository that is read
/// under a vhost the gate is not mounted on. Relative, it resolved against that vhost and
/// hit its catch-all; absolute on the login page's origin, it reaches the one endpoint
/// that serves every vhost, and the `?rd=` is what saves the extra `401` the browser's
/// `Referer` would otherwise buy.
#[test]
fn the_refusal_page_signs_out_on_the_login_page_origin() {
    assert_eq!(
        logout_link("https://login.badbat75.com/"),
        "https://login.badbat75.com/auth/logout?rd=https%3A%2F%2Flogin.badbat75.com%2F"
    );
    // An area may sign its people in on a page of its own, path and query included, and
    // the origin is all this takes from it.
    assert_eq!(
        logout_link("https://in.badbat75.com/x?a=1"),
        "https://in.badbat75.com/auth/logout?rd=https%3A%2F%2Fin.badbat75.com%2Fx%3Fa%3D1"
    );
    // The gate's own page, which is only reachable when the gate is mounted on the vhost
    // being read from, and then the endpoint beside it is too.
    assert_eq!(
        logout_link(OWN_LOGIN_PATH),
        "/auth/logout?rd=%2Fauth%2Flogin"
    );
}

#[test]
fn rd_url_allowed_matches_host_only() {
    let h = bb_hosts();
    assert!(rd_url_allowed("https://mcp.badbat75.com/x", &h));
    assert!(rd_url_allowed("https://badbat75.com", &h));
    assert!(rd_url_allowed("https://a.b.badbat75.com/x?y=1", &h)); // `*` crosses dots
    assert!(rd_url_allowed("https://mcp.badbat75.com:8443/x", &h)); // port stripped
    assert!(rd_url_allowed("https://MCP.BadBat75.com/x", &h)); // case-insensitive
                                                               // path/query containing the base must NOT count
    assert!(!rd_url_allowed("https://evil.com/.badbat75.com", &h));
    assert!(!rd_url_allowed("https://evil.com/?x=badbat75.com", &h));
    assert!(!rd_url_allowed("http://mcp.badbat75.com/", &h));
    assert!(!rd_url_allowed("https://badbat75.com.evil.com/", &h));

    // The apex is NOT implied by the wildcard — it has to be listed.
    let only_sub = vec![bb_auth_core::compile_host_pattern("*.badbat75.com").unwrap()];
    assert!(rd_url_allowed("https://mcp.badbat75.com/", &only_sub));
    assert!(!rd_url_allowed("https://badbat75.com/", &only_sub));
}

#[test]
fn html_escape_escapes_special_chars() {
    assert_eq!(html_escape("plain"), "plain");
    assert_eq!(html_escape("a<b>&c\"'d"), "a&lt;b&gt;&amp;c&quot;&#39;d");
    // attribute-context safety: a crafted login url can't break out
    assert_eq!(
        html_escape("https://x/\" onmouseover=\"alert(1)"),
        "https://x/&quot; onmouseover=&quot;alert(1)"
    );
}

// --- the two wrappers over the grant model ------------------------------
//
// The rule itself (`decide` / `decide_api_key`, applications, `denied`, scopes, expiry) is
// pinned in bb_auth_core's tests. What is the gate's own is the mapping to what a
// response needs — and one property those tests cannot see: that the identity handed
// back is the very string that came in, which is what `respond_authorized`'s
// debug_assert stands on.

/// A live access table, via a real temp file and the real parser.
fn access_of(name: &str, json: &str) -> Access {
    // Unique per call, not per `name`: several tests ask for the same fixture and the
    // suite runs them on different threads, so a shared filename is one test writing the
    // file another is reading.
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("bb-auth-gate-{name}-{n}.json"));
    std::fs::write(&p, json).unwrap();
    let a = read_access(p.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_file(&p);
    a
}

const BOB: &str = "11111111-1111-4111-8111-111111111111";

/// One `authenticated` area, one `restricted` area, one veto, one key.
fn gate_access(name: &str) -> Access {
    let key_hash = sha256_hex("bbk_secret");
    access_of(
        name,
        &format!(
            r#"{{ "version": 1,
                     "applications": [
                       {{ "name": "app1", "base": ["https://app.x.com/app1"], "scopes": [
                          {{ "name": "open", "urls": ["https://app.x.com/app1/*"],
                             "access": "authenticated" }} ] }},
                       {{ "name": "other", "base": ["https://app.x.com/other"],
                          "denied_url": "https://denied.x.com/other", "scopes": [
                          {{ "name": "team", "urls": ["https://app.x.com/other/*"],
                             "access": "restricted", "users": ["{BOB}"] }} ] }},
                       {{ "name": "pub", "base": ["https://app.x.com/pub"], "scopes": [
                          {{ "name": "health", "urls": ["https://app.x.com/pub/*"],
                             "access": "anonymous" }} ] }} ],
                     "denied": ["spammer@x.com"],
                     "users": [ {{ "uuid": "{BOB}", "emails": ["bob@x.com", "bob@old.com"],
                        "api_keys": [ {{ "id": "laptop", "key_hash": "{key_hash}",
                                         "released": "2026-01-01", "duration": "never" }} ] }} ] }}"#
        ),
    )
}

#[test]
fn authorize_login_resolves_the_identity_it_hands_downstream() {
    let a = gate_access("authorize");
    let other = Some("https://app.x.com/other/x");
    let app1 = Some("https://app.x.com/app1/x");

    // Enrolled: the identity carries the uuid and every identifier the row has, not
    // just the one that signed in. That is what makes `X-Auth-Email` stable.
    let got = authorize_login(&a, ident("bob@old.com"), other).unwrap();
    match got {
        Granted::Identity(who) => {
            assert_eq!(who.uuid.as_deref(), Some(BOB));
            assert_eq!(who.emails, vec!["bob@x.com", "bob@old.com"]);
            assert!(who.emails.iter().all(|e| header_safe_email(e)));
        }
        Granted::Anonymous => panic!("a credential must not resolve to an anonymous grant"),
    }

    // An `authenticated` scope: nobody in any table, so no uuid, and the only email
    // there is is the one the token vouched for. Header-safe because
    // `validate_id_token` checked it there.
    let got = authorize_login(&a, ident("newcomer@x.com"), app1).unwrap();
    match got {
        Granted::Identity(who) => {
            assert_eq!(who.uuid, None);
            assert_eq!(who.emails, vec!["newcomer@x.com"]);
        }
        Granted::Anonymous => panic!("a credential must not resolve to an anonymous grant"),
    }

    // And the denials. The veto comes first, then membership, then the missing header.
    assert!(authorize_login(&a, ident("spammer@x.com"), app1).is_none());
    assert!(authorize_login(&a, ident("newcomer@x.com"), other).is_none());
    assert!(authorize_login(&a, ident("bob@x.com"), None).is_none());
    // Nothing outside every application is reachable, by anyone.
    assert!(authorize_login(&a, ident("bob@x.com"), Some("https://app.x.com/elsewhere")).is_none());
}

#[test]
fn authorize_login_passes_claims_through_untouched() {
    // The profile claims must survive the grant decision without influencing it: the
    // access file has no opinion about them, and `bb-auth-adm can` has to keep
    // answering the same question the gate does.
    let a = gate_access("authorize-claims");
    let carried = |g: Option<Granted>| match g {
        Some(Granted::Identity(who)) => who.claims,
        _ => panic!("expected a granted identity"),
    };
    assert_eq!(
        carried(authorize_login(
            &a,
            ident_full("bob@x.com", "Bob", "Rossi"),
            Some("https://app.x.com/other/x")
        )),
        ident_full("bob@x.com", "Bob", "Rossi").claims
    );
    // The same, where the identity is in no table at all.
    assert_eq!(
        carried(authorize_login(
            &a,
            ident_full("new@x.com", "Niccolò", "de' Medici"),
            Some("https://app.x.com/app1/x")
        )),
        ident_full("new@x.com", "Niccolò", "de' Medici").claims
    );
    // And a claim never rescues a denial.
    assert!(authorize_login(
        &a,
        ident_full("spammer@x.com", "S", "P"),
        Some("https://app.x.com/app1/x")
    )
    .is_none());
}

/// A client as nginx describes one: an address, a browser, and nginx's own id.
fn client_at(ip: &str) -> AuditClient {
    AuditClient {
        ip: Some(ip.to_string()),
        ua: Some("Mozilla/5.0 (X11; Linux aarch64)".to_string()),
        rid: Some("5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f".to_string()),
    }
}

#[test]
fn a_refusal_reaches_the_audit_with_who_where_and_why() {
    let a = gate_access("audit-refusal");
    let p = std::env::temp_dir().join("bb-auth-audit-refusal.jsonl");
    let _ = std::fs::remove_file(&p);
    let audit = Audit::to(p.to_str().unwrap());
    let home = audit.for_request(client_at("203.0.113.7"), AuditPolicy::default());

    // A member of nothing, on a restricted scope. The identity is unique to this test
    // because the dedupe window is process-wide and the suite runs in parallel.
    let refused = super::authorize_login(
        &a,
        ident("audit-refusal@x.com"),
        Some("https://app.x.com/other/x"),
        &home,
    );
    assert!(
        refused.is_none(),
        "the decision is unchanged by recording it"
    );

    let page = bb_auth_core::read_audit(&p, None, 10).unwrap();
    assert_eq!(page.events.len(), 1);
    let ev = &page.events[0];
    assert_eq!(ev.kind, AuditKind::AccessRefused);
    assert_eq!(ev.subject.as_deref(), Some("audit-refusal@x.com"));
    assert_eq!(ev.uuid, None, "nobody's row: this identity is in none");
    assert_eq!(ev.app.as_deref(), Some("other"));
    assert_eq!(ev.reason.as_deref(), Some("not_enrolled"));
    assert_eq!(ev.url.as_deref(), Some("https://app.x.com/other/x"));
    assert_eq!(ev.cred, AuditCredential::Local);
    // Where it came from, stamped by the request and not by any call site.
    assert_eq!(ev.ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(ev.rid.as_deref(), Some("5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f"));
    assert!(ev.ua.as_deref().is_some_and(|u| u.contains("aarch64")));

    // The same refusal again inside the window is the same sentence, so it is not a
    // second row: a browser refused one asset is a browser refused forty.
    super::authorize_login(
        &a,
        ident("audit-refusal@x.com"),
        Some("https://app.x.com/other/y"),
        &home,
    );
    assert_eq!(
        bb_auth_core::read_audit(&p, None, 10).unwrap().events.len(),
        1
    );

    // The same refusal from another address is not the same sentence: one identity
    // refused on two machines is two facts, and the second is the one worth reading.
    super::authorize_login(
        &a,
        ident("audit-refusal@x.com"),
        Some("https://app.x.com/other/z"),
        &audit.for_request(client_at("198.51.100.23"), AuditPolicy::default()),
    );
    let page = bb_auth_core::read_audit(&p, None, 10).unwrap();
    assert_eq!(page.events.len(), 2);
    assert_eq!(page.events[0].ip.as_deref(), Some("198.51.100.23"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn an_audit_that_cannot_be_written_costs_the_record_and_never_the_login() {
    // The rule the whole sink is built around: a full disk, a missing directory or a mode
    // nobody fixed must not be able to refuse anybody, and must not be able to admit
    // anybody either. The decision is the access file's, whatever the file system says.
    let a = gate_access("audit-broken");
    let nowhere = std::env::temp_dir().join("bb-auth-no-such-dir-at-all/audit.jsonl");
    let audit = Audit::to(nowhere.to_str().unwrap());
    assert!(audit.on(), "on until a write has actually failed");
    let request = audit.for_request(AuditClient::default(), AuditPolicy::default());

    let granted = super::authorize_login(
        &a,
        ident("bob@x.com"),
        Some("https://app.x.com/other/x"),
        &request,
    );
    assert!(granted.is_some(), "the grant stands");
    let refused = super::authorize_login(
        &a,
        ident("audit-broken@x.com"),
        Some("https://app.x.com/other/x"),
        &request,
    );
    assert!(refused.is_none(), "and so does the refusal");
    // And the events fall back to the journal, which is what `on()` reporting false means
    // to every caller that asks after recording.
    assert!(
        !audit.on(),
        "a failed write hands the events back to the journal"
    );
}

#[test]
fn a_client_address_is_the_last_entry_and_an_address_or_nothing() {
    assert_eq!(client_ip("203.0.113.7").as_deref(), Some("203.0.113.7"));
    // `$proxy_add_x_forwarded_for`: the client's claims first, nginx's own entry last.
    assert_eq!(
        client_ip("10.9.8.7, 1.1.1.1 , 203.0.113.7").as_deref(),
        Some("203.0.113.7")
    );
    // An IPv4 client of a dual-stack socket reads as the IPv4 address it is.
    assert_eq!(
        client_ip("::ffff:203.0.113.7").as_deref(),
        Some("203.0.113.7")
    );
    assert_eq!(client_ip("2001:DB8::1").as_deref(), Some("2001:db8::1"));
    // Anything that is not an address costs the row its address, and nothing else.
    for junk in [
        "",
        "unknown",
        "203.0.113.7:4431",
        "a@x.com",
        "203.0.113.7, ",
    ] {
        assert_eq!(client_ip(junk), None, "{junk:?}");
    }
}

#[test]
fn a_user_agent_is_kept_short_and_printable() {
    assert_eq!(user_agent("  curl/8.9.1 ").as_deref(), Some("curl/8.9.1"));
    assert_eq!(user_agent("a\u{7}b\u{1b}c").as_deref(), Some("abc"));
    assert_eq!(user_agent("   "), None);
    // Cut on a character boundary, however the length falls.
    let long = "é".repeat(AUDIT_UA_MAX);
    let kept = user_agent(&long).unwrap();
    assert!(kept.len() <= AUDIT_UA_MAX && kept.chars().all(|c| c == 'é'));
}

/// A request id is written down as it arrives, so its charset is the last line of defence
/// between a misnamed header and a credential in a file an administrator reads: every
/// credential this gate knows has a character it refuses.
#[test]
fn a_request_id_can_never_be_a_credential() {
    assert_eq!(
        request_id("5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f").as_deref(),
        Some("5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f")
    );
    assert!(request_id("9d8e7f60-1a2b-4c3d-8e9f-0a1b2c3d4e5f").is_some());
    let cookie = make_session(&ident("bob@x.com"), 3600, &keys_one());
    for credential in ["bbk_secret", IT_TOKEN_OK, cookie.as_str(), "Bearer abc"] {
        assert_eq!(request_id(credential), None, "{credential}");
    }
    assert_eq!(request_id(&"a".repeat(AUDIT_RID_MAX + 1)), None);
    assert_eq!(request_id(""), None);
}

#[test]
fn an_account_is_a_short_printable_string_or_nothing() {
    let sub = serde_json::json!("9d8e7f60-1a2b-4c3d-8e9f-0a1b2c3d4e5f");
    assert_eq!(
        account_sub(Some(&sub)).as_deref(),
        Some("9d8e7f60-1a2b-4c3d-8e9f-0a1b2c3d4e5f")
    );
    for bad in [
        serde_json::json!(42),
        serde_json::json!("has a space"),
        serde_json::json!("x".repeat(AUDIT_SUB_MAX + 1)),
        serde_json::json!(""),
    ] {
        assert_eq!(account_sub(Some(&bad)), None, "{bad}");
    }
    assert_eq!(account_sub(None), None);
}

/// The whole path, over a socket: the address and the request id reach the file from the
/// headers the settings name and from nowhere else, and the user agent always does.
///
/// The second half is the one that matters. A client that sends its own `X-Real-IP` to a
/// gate whose settings name no header must not get it written down, because on that
/// deployment nobody has promised that nginx overwrites it.
#[test]
fn where_a_request_came_from_is_read_only_from_the_headers_named() {
    let validate = |base: &str, email: &str, ip: &str| {
        let cookie = make_session(&ident(email), 3600, &keys_one());
        agent()
            .get(format!("{base}/auth/validate"))
            .header("X-Original-URL", "https://app.x.com/other/x")
            .header("Cookie", format!("bb_session={cookie}"))
            .header("X-Real-IP", ip)
            .header("X-Request-ID", "5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f")
            .header("User-Agent", "Mozilla/5.0 (X11; Linux aarch64)")
            .call()
            .unwrap()
    };
    let read = |p: &std::path::Path| bb_auth_core::read_audit(p, None, 10).unwrap().events;

    // Named: both headers are believed, and the refusal (a stranger on bob's scope)
    // carries them.
    let named = std::env::temp_dir().join("bb-auth-audit-client-named.jsonl");
    let _ = std::fs::remove_file(&named);
    // The two headers are the `audit` section's, which the compiled settings carry beside
    // the gate's own; set them there rather than teach the fixture a second section.
    let mut named_settings = gate_settings("{}");
    named_settings.client_ip_header = Some("X-Real-IP".to_string());
    named_settings.request_id_header = Some("X-Request-ID".to_string());
    let mut st = token_state(named_settings);
    st.audit = Audit::to(named.to_str().unwrap());
    let base = serve(st);
    assert_eq!(
        validate(&base, "client-named@x.com", "203.0.113.41").status(),
        403
    );
    let events = read(&named);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].ip.as_deref(), Some("203.0.113.41"));
    assert_eq!(
        events[0].rid.as_deref(),
        Some("5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f")
    );
    assert_eq!(
        events[0].ua.as_deref(),
        Some("Mozilla/5.0 (X11; Linux aarch64)")
    );

    // Not named: the same headers arrive and neither is written down. The user agent
    // still is, since it never pretended to be anything but the client's word.
    let unnamed = std::env::temp_dir().join("bb-auth-audit-client-unnamed.jsonl");
    let _ = std::fs::remove_file(&unnamed);
    let mut st = token_state(gate_settings("{}"));
    st.audit = Audit::to(unnamed.to_str().unwrap());
    let base = serve(st);
    assert_eq!(
        validate(&base, "client-unnamed@x.com", "203.0.113.42").status(),
        403
    );
    let events = read(&unnamed);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].ip, None);
    assert_eq!(events[0].rid, None);
    assert!(events[0].ua.is_some());

    let _ = std::fs::remove_file(&named);
    let _ = std::fs::remove_file(&unnamed);
}

#[test]
fn bearer_apikey_resolves_to_its_owner() {
    // The gate hashes the bearer; the file holds only the hash. A key acts as its
    // user, so the identity handed back is the owner's row: the one identity on this
    // path that never passed through a token claim, and so is guarded at load instead.
    let a = gate_access("apikey");
    let rec = bearer_apikey(&a, "bbk_secret").unwrap();
    assert_eq!(rec.uuid, BOB);

    let who = key_identity(&a, rec);
    assert_eq!(who.uuid.as_deref(), Some(BOB));
    assert_eq!(who.emails, vec!["bob@x.com", "bob@old.com"]);
    // A key has no token, so it can never carry a profile claim.
    assert!(who.claims.is_empty());

    assert!(bearer_apikey(&a, "bbk_nope").is_none());
}

#[test]
fn a_key_is_refused_where_the_scope_admits_only_a_login() {
    let a = access_of(
        "key-class",
        &format!(
            r#"{{ "version": 1,
                     "applications": [ {{ "name": "app", "base": ["https://x.com/a"],
                       "scopes": [ {{ "name": "s", "urls": ["https://x.com/a/*"],
                         "access": "restricted", "users": ["{BOB}"],
                         "credentials": ["login"] }} ] }} ],
                     "users": [ {{ "uuid": "{BOB}", "emails": ["bob@x.com"],
                       "api_keys": [ {{ "id": "k", "key_hash": "{}",
                                        "released": "2026-01-01", "duration": "never" }} ] }} ] }}"#,
            sha256_hex("bbk_secret")
        ),
    );
    let url = Some("https://x.com/a/thing");
    let rec = bearer_apikey(&a, "bbk_secret").unwrap();
    assert!(!authorize(
        &a,
        &Subject::Key(rec),
        url,
        &Caller::key(rec),
        &quiet()
    ));
    // The same person, through a browser login, is admitted.
    assert!(authorize_login(&a, ident("bob@x.com"), url).is_some());
}

#[test]
fn an_anonymous_scope_grants_with_no_credential_at_all() {
    let a = gate_access("anon");
    let url = Some("https://app.x.com/pub/healthz");
    assert!(decide(&a, &Subject::Anonymous, url).granted());
    // And it grants ahead of the veto, because a vetoed client would simply send
    // nothing and be granted anyway.
    assert!(decide(&a, &Subject::Identifier("spammer@x.com"), url).granted());
    // Elsewhere, no credential is no entry.
    assert!(!decide(&a, &Subject::Anonymous, Some("https://app.x.com/app1/x")).granted());
}

// --- the identity headers ------------------------------------------------

fn attrs(spec: &str) -> Vec<IdentityAttr> {
    let list: Vec<String> = spec.split(',').map(str::to_string).collect();
    bb_auth_core::compile_identity_attrs(&list).unwrap()
}

#[test]
fn identity_headers_join_with_a_space_and_omit_what_is_absent() {
    let who = Authorized {
        uuid: Some(BOB.to_string()),
        emails: vec!["bob@x.com".into(), "bob@old.com".into()],
        claims: BTreeMap::new(),
        native_username: None,
    };
    assert_eq!(
        identity_headers(&attrs("uuid,email"), &who),
        vec![
            ("X-Auth-Uuid", BOB.to_string()),
            (IDENTITY_HEADER, "bob@x.com bob@old.com".to_string()),
        ]
    );
    // A space can never appear inside an identifier, which is what makes the join
    // unambiguous; a comma could, so it is not used.
    assert!(who.emails.iter().all(|e| header_safe_email(e)));

    // An identity granted by an `authenticated` scope has no uuid: the header is
    // omitted, never sent empty, because nginx cannot tell those apart.
    let stranger = Authorized {
        uuid: None,
        emails: vec!["new@x.com".into()],
        claims: BTreeMap::new(),
        native_username: None,
    };
    assert_eq!(
        identity_headers(&attrs("uuid,email"), &stranger),
        vec![(IDENTITY_HEADER, "new@x.com".to_string())]
    );
    // Order follows the configuration, not the struct.
    assert_eq!(
        identity_headers(&attrs("email,uuid"), &who)[0].0,
        IDENTITY_HEADER
    );
}
// --- the token verifier, over real signatures ---------------------------
//
// A second offline RSA key, generated once and thrown away, and a token per branch of
// `validate_id_token`. `SELF_TEST_TOKEN` proves a signature verifies at all; these prove
// what the gate does with a token whose signature is *fine* and whose claims are not,
// which is every check between the verifier and the identity. Before this, the whole
// group of them (`alg`, a missing `kid`, `token_use`, `exp`, `aud`, the email's shape)
// was reachable only through a live Cognito.

// Two keys, as a real pool's JWKS has: the second was minted later, for
// `IT_TOKEN_COGNITO_2026`, and is just as thrown away as the first.
const IT_JWKS: &str = r#"{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"bb-auth-it","e":"AQAB","n":"rugOpI1NhVG8CKJbf8LFMFjw-Goe26G5YJLb7-VTWg3VLG_-Qy2kQEW-aPIX_RgDZ9VcoU06LT6ZAAa142TGZYarzE8RsGqTgDVS6uiJEeeCy_mztxMcKXUoE45enGhbESY1-j9VZPvNMb-7Oearl-EqKeprpJYV2-SxYY9QRtJFJR4rKxberyssan4PkN2hlS128Z5Kd4TepQLU5RlIm6tPTZaP81fKF_rB6YNvHDyAofEVcK0s3YH6a5CI1FDPWbK9VssTmDnlzPVoSdd56Haq4kH2NbxrybK3OOStROluoS_Q0Ejzsg_JTcqjofuNKRiLd8itgYti2FMstsKkbQ"},{"kty":"RSA","alg":"RS256","use":"sig","kid":"bb-auth-it-2026","e":"AQAB","n":"iuMCQrIgQh9ZpX39V3RbM2xcHq6l5n5MCAPnIToeAJfUZn-z5908qgi7VVAI_jSGGL2aa2OWBhmGshL67j1wvu2_xtY9ykJy2QXF5s_8OistMIDx7wOttMKDVA0VFPnfABXW_dwgLipx5aXj7Ow_CJYqwIQlJLsy2sW4fokbG09Vxa1gteA9Oyr6QgeGrMxuH5kDzTJF5EPg4z12RZYc8_sh4zoOFa_RVf9q4MdmQdEQPtlPxUCGatgwWTG03080RW9qwXznstrPhfn7t3C5y_e5ER6zoeBewiSz4pkBkUWxKOWUnuEoW6BBp6vTaOVFxUMqa4Yk88oywNe69yev0Q"}]}"#;
/// The token Cognito issues from November 2026: `IT_TOKEN_OK`'s claims plus a `sub`, a
/// string `acr` and an array `amr` (`"acr":"urn:cognito:loa:4","amr":["pwd","otp","mfa"]`),
/// the additive change AWS announced for every user pool.
const IT_TOKEN_COGNITO_2026: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQtMjAyNiJ9.eyJzdWIiOiJhMWIyYzNkNC01Njc4LTkwYWItY2RlZi0wMDAwMDAwMDAwMDEiLCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJnaXZlbl9uYW1lIjoiQWRhIiwiZmFtaWx5X25hbWUiOiJMb3ZlbGFjZSIsImFjciI6InVybjpjb2duaXRvOmxvYTo0IiwiYW1yIjpbInB3ZCIsIm90cCIsIm1mYSJdfQ.Ukd5cODjm6wYkOsK68WwRs5HfpuSQ0Aeo32NVmVR6OBnvBd4fbU6R1fxmO9xM-WeYLFX-361nbj_jf0SEnNkR8TcA5jwvIvI67Wr1fXtTJTOPOr3Xiu4945IyznaRmjvYc56F_eAaEGa_blDz4a-1r08xwoYizMifg1pAuJB_1MMvXAfoXWWNV2JUH-Fa0aoQuK__Qe3lUouaKLO65lhws2pmXSQpjMZHV6yMU-LOhDNNOULEEIjMb3h2HadJT0o9TXrwvhtlcmCuCQybTvWVegR_-S57KpzV3-x_d3Ttenw2FAkQWu-uTKUiCOc7jjl3-e8gFEUXUUv7nNNF5v8xA";
const IT_TOKEN_OK: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJnaXZlbl9uYW1lIjoiQWRhIiwiZmFtaWx5X25hbWUiOiJMb3ZlbGFjZSJ9.AsSpalg5hcJwwVL5Nh03f98i0xsz-Th4NJM5aFk9Wv7yRbBUq1zuYq6ZNZdOtpgKa19j3zTR3NsRETnHhWVZhGLRvSCluY_zyEGzgwO_D1cBwtDjc5XGqehOux-torQKaXryxWlhd2um3RyJt5KuBIUaCTuZsnRb4ghQBdYVBg7nmRwfXnFTCB-HWYwh_VaklGKpe0kaHfvv1ttp3oWdt37CCFT3CRXPQi2UNMxW53SeIk6UPrhEX2d9gNjRBMidno2ALMXxA6L4ku5G1bPEfj9HbkqArSNCJHCPtQMhH1WUB2iqZrMA6q78imDaFjI31uc5uzdIpt4FUda35NeQxA";
const IT_TOKEN_ACCESS: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MTAwMDAwMDAwMCwiZW1haWwiOiJhZGFAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UifQ.BcXSfueCjbuy0ICSd9mXlm3vwI1ywkym7x2KdABO5aYYeP2l9_2A7WCmNOFDpPeDcDUD-8rT3hpBsKeckfl0-CgxwyIQ8UClRhC3GbGjKFEuA_65ieaxz1CfruCEItlpFpE-zb3YUc89Yk6-dVbGI45k-0UhWK6I91Hn-R5hliZoauYgq2CCIxDfRRE2-bOKJvsBVgc3xrYDQts8Wq8M8lsmQn-OfycFWAtG3shOw8ujrr4nLGvycy2A9hffOsXJyV-sPtC_Oj_jtufHv_nW1KnVVxzcQj6QQFO3_s0BMyTyfTZSRD7I7_7OqNZ-N0GfCjMeza6uxWcQQ7Y4KDh0NA";
const IT_TOKEN_UNVERIFIED: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UifQ.owL1LWxaPNuK4do4S1T23b9Zywk7Fhfq178Nx9f0MO4R3qZKhtG10Z_E1bOqBK6hjy1T5hmbtUdg8FIwHg10OVWjbnW_m8Fzk7v-MWLnOgd5kLVwnsyWX8NgIAmo1dSb0-P3xV6C2HpCtFnZPhR98fGxXJUIf5HLr31Hi86VNJNG8-nMU3F2Iqy1vdeMBwcrSkMhlmZZO4n1rE0cR9DvUY9ixfEfr81sR9vTc4mpnXIwT-aViOP-s9Ovrq4gJCNz5os4IYJQkEwNVH8xO9tuXcx5zL-S2Rwfoqg6kv4Azk7gD4x4PCWbff2NsjTtS1fGxCwICQDhEmr46T2sitee8Q";
const IT_TOKEN_SOCIAL: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UiLCJpZGVudGl0aWVzIjpbeyJwcm92aWRlck5hbWUiOiJHb29nbGUiLCJ1c2VySWQiOiIxIn1dfQ.f2CwAFGvK0AfVpkTQytWw-4mpt8i8Z5hbuO75hAbyKqTjlsvQBBIhcErgD_tRwJube7S9TN459arezyk79QX85Pa0lBA5fnzF-k83GYkDjA7HXF0f7P7HhAWBuw2AuiRYC7qWnlusVlCC2SGDVDlLcCb0tw_2Oou5XQBkHkQjxeIK9rCIZXOHqaPyflIQulDr1w0ptSy3DL1LElmMW9XpnoMd4wxqll494UvMwxh8sBFfQdgQs2ifPk6lrMT_TCgGS9BsYIL-GaryRn3aTe4_F0YWybfZ9LYB7S_4-F4fj1nSrt52aHz_F2umidLs7tP57qVE40Pg6JJwB__0gkh5g";
const IT_TOKEN_SOCIAL_APPLE: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UiLCJpZGVudGl0aWVzIjpbeyJwcm92aWRlck5hbWUiOiJTaWduSW5XaXRoQXBwbGUiLCJ1c2VySWQiOiIxIn1dfQ.ZlwHhtX6ywtueOn8mDVKWufBPGGfIe5mViVVLw6mAYjX7_D-ghN-PZ7tRfrtebas5EMO8rQPVfk0hXxnt-9Eho9yWYTMtBz5kjX8eNBu409oC20gH-44-K2KPyl56vfJHbaCATzVArO6fJcSnbX_Z9T1doU1FuLMr89NhHtnnpTaoIZDsvTZCp-cMQsdlRicTtzhieuARyNFCH50quBsTzIy071BqClgYSCQ7a3z_f7o8-ZU2bKDWVM-XuwQFvc6JovnS9MF3Ds8W0zRXamh7oCz1zgEekmE6CpB172xTKa8DO6bIcgPzpFSyZzJlwF34-Udse-gm0VpxiUe2eKZGg";
const IT_TOKEN_BAD_EMAIL: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYVxyXG5YLUF1dGgtQWRtaW46IDFAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UifQ.AbRKWpldAZsycR7s2aSyFo237MRDl10rRwDiCQ0JKvlBhIv4Uu31aal9pF8x0nDBAEKhcf0Djo1w2mCdoxhah3jOmKzYL9GL-N6gHzblS2uitZ-JkWKk0Azio9weNKp6_s5Ss_KsOwbHHsvOdYySnnbtI_PkRj9-wFwFtjX60NmP1G5YVl2CP5gXfuk_enAPFTbuyDcrJtFs5-8emWhVIkzZYO80OZhXRW3yJVtnrfVaJxkd3mfPYooBVEIt4O0UVIMlVFgGD4BTlejVbr7Zw-f0rjWCYvlE5MYziiCGFiEfN7VO7KQfSsmFpL8VBbcpHKfdhv6_VnpQrRc_OYRe6A";
const IT_TOKEN_EXPIRED: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6MTAwMDAwMDA2MCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJnaXZlbl9uYW1lIjoiQWRhIiwiZmFtaWx5X25hbWUiOiJMb3ZlbGFjZSJ9.k5DFscI5iwnSuBjW_9Uw9QhjS4PJHcrgn7MdlQjGGTfSkIg3XqvUEcSNMHlegVOryhEHavcSxwmsXxxdRGADTEQwa6xxyY9hKtG7J2rDM9cbbghk4sxF_PIAjC5g6xgyYVf731YVt-qHPzMmhRE0P_A7DaLtGaVcvHjT07txbN8B_9SBcP7zU3KJfRJVU9KiQb0zjTS7TgUfddQQPz9fk8DHFlsOA-oFvPtmsDFwUnEhZQ5aJ62Q6d9ak2RnJbYYGVor_Q77MTxdGkkSHMM9L0gm0veh6vW9J6C3jQQ9CuseimBZqiHvM5wL7WgP88_P1TDBzb2JostBwIJv6Mn2DQ";
const IT_TOKEN_WRONG_AUD: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InNvbWVvbmUtZWxzZSIsInRva2VuX3VzZSI6ImlkIiwiZXhwIjo0MTAyNDQ0ODAwLCJpYXQiOjEwMDAwMDAwMDAsImVtYWlsIjoiYWRhQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImdpdmVuX25hbWUiOiJBZGEiLCJmYW1pbHlfbmFtZSI6IkxvdmVsYWNlIn0.ivJ9pHR_DS5aXQ_NB5zTUy4hKQ8yZYtEwf6dOjYVcU0wXHiUS5rygH4ENPwEZ45WHnr-KLMl8v9FRRMLTCl_hvCPwGwZtgc5y61W9Qn4WIkZKAH3gpCgbtAh3KbK1CZh0PsaGMhPWqBSJexKPvH72aceE60ZySeJyGf3vI6X16vzcaOCO9RUxHm7-X8_yps9a8heJWc2UJU8KVjJQAbK6z-hN2SjqzT8eMgQF-DgbXSM_CFUo1QFg_niZDcp6FZOP5KaFKtZXRVVfB-QfBrn17K3foIIYfuqFOorHuUfxMjPeHs6arZrzpxHrlSWTlfzMP5cAlZPSQ39vCUeFrzyvA";
const IT_TOKEN_NO_EMAIL: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UifQ.HQg4OhQXErFEdSM8IQqXuW4PPsIBUTY_YClLP103dfL_8jVBWSBAqXLgPkXT_WdbGKGasf06o4coaU4zIzCEY734mGjJomQpU8x5NxDWUcw-skODFHXh8Xeadglx7aKaZ1HF70uBHwO8gIG-es1zcxPmcM7DWCsBiBJeTa-d6hVVYpGEYmxhuvEKbNSebMhxzeD9m6I-lZB_vSS7PcHjRvPE8492jUwCVjVXFFGjOQRuNylOChNkC9b-o6AXO9d6L3Sp2wqIPdscW7Qn0nenx7vieMp5_rXl4XvePxncsEa-ViOSNyKLmDgLrzplv0HUt5SJKJFEyMmhFSnEhcyj2w";

/// A state whose JWKS already holds the fixture key, so nothing here touches the
/// network. `last_refresh` is *now* on purpose: an unknown `kid` must not become a
/// fetch, and this is what keeps these tests offline.
fn token_state(settings: Settings) -> State {
    let set: JwkSet = serde_json::from_str(IT_JWKS).expect("fixture JWKS parses");
    let keys: HashMap<String, DecodingKey> = set
        .keys
        .iter()
        .map(|jwk| {
            (
                jwk.common
                    .key_id
                    .clone()
                    .expect("every fixture JWK has a kid"),
                DecodingKey::from_jwk(jwk).expect("fixture JWK becomes a key"),
            )
        })
        .collect();
    // The issuer these keys belong to is the settings', so the cache is seeded with
    // whatever the fixture settings name: a cache that disagreed with them would trigger
    // a refetch against a pool no test has a server for.
    let issuer = settings.issuer.clone();
    State {
        cfg: cookie_cfg(),
        audit: Audit::off(),
        access: RwLock::new(gate_access("token")),
        settings: RwLock::new(settings),
        #[cfg(unix)]
        access_path: String::new(),
        #[cfg(unix)]
        settings_path: String::new(),
        jwks: RwLock::new(JwksCache {
            keys,
            last_refresh: Instant::now(),
            issuer,
        }),
        jwks_refresh: Mutex::new(()),
    }
}

/// Compiled settings from a gate section written as JSON, which is how an operator
/// writes them and therefore what these tests should be exercising.
fn gate_settings(gate: &str) -> Settings {
    let mut file: bb_auth_core::SettingsFile = serde_json::from_str(&format!(
        r#"{{ "version": {}, "gate": {gate} }}"#,
        bb_auth_core::SETTINGS_VERSION
    ))
    .unwrap();
    // The app client the fixture token was minted for, and therefore the only audience
    // these tests accept. It is a setting now, so a gate section that does not mention it
    // gets the fixture's rather than an empty audience list and a token nobody accepts.
    if file.gate.client_id.is_empty() {
        file.gate.client_id = "testclient".to_string();
    }
    // Where people sign in is a setting too now, and every test that reads a 401 or a
    // logout expects the configured page rather than the gate's own default.
    if file.gate.login_url.is_empty() {
        file.gate.login_url = LOGIN.to_string();
    }
    // And so are the pool and the estate, which between them decide whether a token
    // validates at all and whether a login may land anywhere but the sign-in page.
    if file.gate.issuer.is_empty() {
        file.gate.issuer = TEST_ISSUER.to_string();
    }
    if file.gate.authorized_hosts.is_empty() {
        file.gate.authorized_hosts = BB_HOSTS.iter().map(|h| h.to_string()).collect();
    }
    bb_auth_core::compile_settings(&file).unwrap()
}

/// Swap the *header* of a signed token, which is what a client attacking a verifier's
/// algorithm agility does. The signature is left over the original message, so anything
/// that reaches the signature check refuses it anyway; what this exercises is that it
/// never gets that far.
fn with_header(token: &str, header_json: &str) -> String {
    let rest: Vec<&str> = token.split('.').skip(1).collect();
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header_json.as_bytes()),
        rest.join(".")
    )
}

#[test]
fn a_good_token_yields_the_identity_and_only_the_configured_claims() {
    let st = token_state(gate_settings(r#"{ "profile_claims": ["given_name"] }"#));
    let id = validate_id_token(IT_TOKEN_OK, &st).expect("a valid token verifies");
    assert_eq!(id.email, "ada@example.com");
    assert_eq!(id.claims.get("given_name").map(String::as_str), Some("Ada"));
    // `family_name` is in the token and is not configured, so it is not captured: the
    // cookie carries what the operator asked for and nothing else.
    assert_eq!(id.claims.len(), 1);
}

#[test]
fn a_token_with_acr_and_an_array_amr_still_signs_in() {
    // AWS adds `acr` and `amr` to every Cognito token from November 2026, `amr` always an
    // array. Unknown claims land in `Claims::extra` as raw values, so the login must
    // survive them, and a struct that grew `deny_unknown_fields` or a `String` `amr`
    // would fail here before it failed every new login in production.
    let st = token_state(gate_settings(
        r#"{ "profile_claims": ["given_name", "acr", "amr"] }"#,
    ));
    let id = validate_id_token(IT_TOKEN_COGNITO_2026, &st).expect("the new claims are additive");
    assert_eq!(id.email, "ada@example.com");
    assert_eq!(
        id.sub.as_deref(),
        Some("a1b2c3d4-5678-90ab-cdef-000000000001")
    );
    // A string claim is captured like any other; an array one costs that claim and
    // nothing else, which is what `clean_claim` promises for a non-string value.
    assert_eq!(
        id.claims.get("acr").map(String::as_str),
        Some("urn:cognito:loa:4")
    );
    assert!(!id.claims.contains_key("amr"));
    assert_eq!(id.claims.get("given_name").map(String::as_str), Some("Ada"));
}

#[test]
fn each_token_check_refuses_on_its_own() {
    let st = token_state(gate_settings("{}"));
    let why = |t: &str| validate_id_token(t, &st).unwrap_err();

    // alg: refused before the signature is even looked up, which is the point of
    // checking it at all.
    assert!(why(&with_header(
        IT_TOKEN_OK,
        r#"{"alg":"HS256","kid":"bb-auth-it"}"#
    ))
    .contains("unexpected alg"));
    // A missing kid, and an unknown one. Neither may reach the network here: the cache
    // was just refreshed, so `refresh_jwks_if_due` returns without a fetch.
    assert!(why(&with_header(IT_TOKEN_OK, r#"{"alg":"RS256"}"#)).contains("no kid"));
    assert!(
        why(&with_header(IT_TOKEN_OK, r#"{"alg":"RS256","kid":"nope"}"#))
            .contains("unknown signing key")
    );
    // token_use is the single check between an access_token and a session cookie.
    assert!(why(IT_TOKEN_ACCESS).contains("token_use"));
    // exp and aud are `jsonwebtoken`'s, through the `Validation` this gate builds.
    assert!(why(IT_TOKEN_EXPIRED).contains("token invalid"));
    assert!(why(IT_TOKEN_WRONG_AUD).contains("token invalid"));
    // The identity must be header-safe: this one carries a CR/LF, which downstream
    // would be a response-splitting gadget.
    assert!(why(IT_TOKEN_BAD_EMAIL).contains("printable ASCII"));
    assert!(why(IT_TOKEN_NO_EMAIL).contains("no email"));
    // And the default posture on an unverified email, with no relaxation configured.
    assert!(why(IT_TOKEN_UNVERIFIED).contains("not verified"));
}

#[test]
fn the_unverified_relaxation_reaches_social_logins_only_and_narrows_by_provider() {
    // Off: even a federated token is refused, which is the default every deployment
    // starts on.
    let st = token_state(gate_settings("{}"));
    assert!(validate_id_token(IT_TOKEN_SOCIAL, &st).is_err());

    // On, unrestricted: any federated provider, but still never a native user.
    let st = token_state(gate_settings(r#"{ "allow_unverified_social": true }"#));
    assert_eq!(
        validate_id_token(IT_TOKEN_SOCIAL, &st).unwrap().email,
        "ada@example.com"
    );
    assert!(validate_id_token(IT_TOKEN_UNVERIFIED, &st).is_err());

    // On, narrowed: the provider list is the whole of it.
    let st = token_state(gate_settings(
        r#"{ "allow_unverified_social": true, "social_providers": ["Google"] }"#,
    ));
    assert!(validate_id_token(IT_TOKEN_SOCIAL, &st).is_ok());
    assert!(validate_id_token(IT_TOKEN_SOCIAL_APPLE, &st).is_err());
}

// --- the router, over a real socket -------------------------------------
//
// What a handler puts on the wire is not what its inner half returns, and the wire is
// what nginx and a browser read. These bind a port, run one worker of `route`, and speak
// HTTP to it, which is the harness `bb-auth-web`'s tests have always had and the gate's
// have not.

/// Start the router on a loopback port and return its base URL. The thread is left
/// running: the test process exits soon enough, and a shutdown protocol would be more
/// code than the thing it guards.
fn serve(state: State) -> String {
    let server = Server::http("127.0.0.1:0").expect("a loopback port");
    let base = format!("http://{}", server.server_addr());
    let state = Arc::new(state);
    std::thread::spawn(move || {
        while let Ok(req) = server.recv() {
            route(req, &state);
        }
    });
    base
}

/// The client half: no redirect following (the redirects *are* the assertion) and a
/// short timeout, so a hung handler fails one test instead of the suite.
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .new_agent()
}

#[test]
fn the_router_answers_every_documented_endpoint() {
    let base = serve(token_state(gate_settings("{}")));
    let a = agent();

    // healthz, which is what `verify.sh` reads.
    let mut r = a.get(format!("{base}/auth/healthz")).call().unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.body_mut().read_to_string().unwrap(), "ok");

    // An unknown path is a 404 and never a page.
    assert_eq!(a.get(format!("{base}/nope")).call().unwrap().status(), 404);

    // A gated request with no credential: 401 naming this area's login page, which is
    // the header nginx lifts with `auth_request_set`.
    let r = a
        .get(format!("{base}/auth/validate"))
        .header("X-Original-URL", "https://app.x.com/other/x")
        .call()
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers().get(LOGIN_URL_HEADER).unwrap(), LOGIN);

    // An `anonymous` scope: 204, and it names nobody.
    let r = a
        .get(format!("{base}/auth/validate"))
        .header("X-Original-URL", "https://app.x.com/pub/health")
        .call()
        .unwrap();
    assert_eq!(r.status(), 204);
    assert!(r.headers().get(IDENTITY_HEADER).is_none());

    // A cookie this gate minted, on the area its owner is listed in: 204 naming them.
    let cookie = make_session(&ident("bob@x.com"), 3600, &keys_one());
    let r = a
        .get(format!("{base}/auth/validate"))
        .header("X-Original-URL", "https://app.x.com/other/x")
        .header("Cookie", format!("bb_session={cookie}"))
        .call()
        .unwrap();
    assert_eq!(r.status(), 204);
    // Every identifier on the row, space-joined: the header names the person, not the
    // address they happened to sign in with.
    assert_eq!(
        r.headers().get(IDENTITY_HEADER).unwrap(),
        "bob@x.com bob@old.com"
    );

    // A `bbk_` key, which is the third credential and the one no token backs.
    let r = a
        .get(format!("{base}/auth/validate"))
        .header("X-Original-URL", "https://app.x.com/other/x")
        .header("Authorization", "Bearer bbk_secret")
        .call()
        .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(
        r.headers().get(IDENTITY_HEADER).unwrap(),
        "bob@x.com bob@old.com"
    );

    // A gated request with no `X-Original-URL` resolves to no application at all, which
    // is the fail-closed posture the whole nginx contract rests on.
    let r = a.get(format!("{base}/auth/validate")).call().unwrap();
    assert_eq!(r.status(), 401);

    // The page a 403 lands on, which nginx reaches with a fixed `proxy_pass`. It answers
    // 403 itself, so `error_page 403 = @bb_denied` keeps the status honest.
    let mut r = a.get(format!("{base}/auth/denied")).call().unwrap();
    assert_eq!(r.status(), 403);
    let page = r.body_mut().read_to_string().unwrap();
    assert!(page.contains("Access denied"), "{page}");
    // It offers the only move it honestly can, and never a link *to* the login page:
    // signing in as the same person lands right back here, which is the loop this whole
    // page is about. The sign-out is absolute on the login page's origin, because the
    // browser is reading this document under the gated vhost's address and a relative
    // path would resolve against a host that does not mount the gate.
    assert!(
        page.contains(&format!(
            r#"href="{}auth/logout?rd={}""#,
            LOGIN,
            pct_encode(LOGIN)
        )),
        "{page}"
    );
    assert!(!page.contains(&format!(r#"href="{LOGIN}""#)), "{page}");
    // Rendered, not served raw: a placeholder left standing is a page missing its
    // stylesheet, which is exactly what nobody looks at on an error page.
    assert!(!page.contains("__BB_"), "{page}");
}

/// The two refusals, told apart. A `401` sends a browser to the login page, so answering
/// one to somebody who is already signed in is a loop with no error in it anywhere:
/// login, cookie, back, refused, login. Every credential this gate accepts has to reach a
/// `403` instead, and every one it does not has to keep reaching the `401`.
#[test]
fn a_credential_the_gate_accepts_is_refused_with_403_and_no_login_page() {
    let base = serve(token_state(gate_settings("{}")));
    let a = agent();
    // `other` is restricted to bob, `app1` is `authenticated`, `pub` is `anonymous`.
    let validate = |url: &str, header: (&str, &str)| {
        a.get(format!("{base}/auth/validate"))
            .header("X-Original-URL", url)
            .header(header.0, header.1)
            .call()
            .unwrap()
    };
    let cookie = |email: &str| {
        format!(
            "bb_session={}",
            make_session(&ident(email), 3600, &keys_one())
        )
    };

    // A session this gate minted, on an area that lists somebody else. The person is
    // signed in: there is nothing a login page could do for them.
    let r = validate(
        "https://app.x.com/other/x",
        ("Cookie", &cookie("stranger@x.com")),
    );
    assert_eq!(r.status(), 403);
    assert!(r.headers().get(LOGIN_URL_HEADER).is_none());

    // The `denied` veto is the same answer: a vetoed identity is refused everywhere, and
    // signing in again is exactly what it may not fix.
    let r = validate(
        "https://app.x.com/other/x",
        ("Cookie", &cookie("spammer@x.com")),
    );
    assert_eq!(r.status(), 403);

    // A `bbk_` key the file knows, on a scope that admits no key at all. A key cannot
    // sign in either, so a 401 would be the same nonsense one credential along.
    let r = validate(
        "https://app.x.com/app1/x",
        ("Authorization", "Bearer bbk_secret"),
    );
    assert_eq!(r.status(), 403);

    // And what a 401 is still for. An expired cookie, a forged one and no cookie at all
    // are the same request as far as this gate is concerned: it does not know who this
    // is, and the login page is the answer.
    let r = validate(
        "https://app.x.com/other/x",
        (
            "Cookie",
            &format!(
                "bb_session={}",
                make_session(&ident("bob@x.com"), 0, &keys_one())
            ),
        ),
    );
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers().get(LOGIN_URL_HEADER).unwrap(), LOGIN);
    let r = validate(
        "https://app.x.com/other/x",
        ("Cookie", "bb_session=bb1.k1.nonsense"),
    );
    assert_eq!(r.status(), 401);
    // An unknown key is not a credential this gate accepts, so it is a 401 as well: there
    // is no identity behind it to refuse.
    let r = validate(
        "https://app.x.com/other/x",
        ("Authorization", "Bearer bbk_nope"),
    );
    assert_eq!(r.status(), 401);

    // An `anonymous` scope grants before either refusal, to anybody, which is what it is
    // for: a client refused there could simply have sent less.
    let r = validate(
        "https://app.x.com/pub/health",
        ("Cookie", &cookie("stranger@x.com")),
    );
    assert_eq!(r.status(), 204);
}

/// The refusal page, and the two ways an operator replaces it. Per application means per
/// **host**, since an area is an absolute prefix, which is the only axis this file has for
/// "this host answers differently".
#[test]
fn the_refusal_page_gives_way_to_the_area_and_then_to_the_settings() {
    let a = agent();
    // No page configured anywhere: the gate's own, on the calling host.
    let base = serve(token_state(gate_settings("{}")));
    let r = a.get(format!("{base}/auth/denied")).call().unwrap();
    assert_eq!(r.status(), 403);

    // The area that refused, if nginx said which one. This is a per-host page: the
    // application owns an absolute prefix, so its host is in its area.
    let r = a
        .get(format!("{base}/auth/denied"))
        .header("X-Original-URL", "https://app.x.com/other/x")
        .call()
        .unwrap();
    assert_eq!(r.status(), 302);
    assert_eq!(
        r.headers().get("Location").unwrap(),
        "https://denied.x.com/other"
    );

    // An area that names none falls back to the settings file, and a deployment whose
    // nginx forwards no URL at all falls back to it too: a refusal styled for the wrong
    // area still says no, where a failure to render says nothing.
    let base = serve(token_state(gate_settings(
        r#"{ "denied_url": "https://denied.x.com/all" }"#,
    )));
    for url in ["https://app.x.com/app1/x", ""] {
        let mut req = a.get(format!("{base}/auth/denied"));
        if !url.is_empty() {
            req = req.header("X-Original-URL", url);
        }
        let r = req.call().unwrap();
        assert_eq!(r.status(), 302);
        assert_eq!(
            r.headers().get("Location").unwrap(),
            "https://denied.x.com/all"
        );
    }
}

#[test]
fn a_session_post_from_another_site_is_refused_before_the_token_is_read() {
    let base = serve(token_state(gate_settings("{}")));
    let a = agent();
    let post = |site: Option<&str>| {
        let mut req = a.post(format!("{base}/auth/session"));
        if let Some(s) = site {
            req = req.header("Sec-Fetch-Site", s);
        }
        req.send_form([("id_token", IT_TOKEN_OK)]).unwrap()
    };
    // The attack: an attacker's own valid token, auto-submitted from their page. The
    // victim would otherwise browse the whole cookie domain as them.
    let r = post(Some("cross-site"));
    assert_eq!(r.status(), 403);
    assert!(r.headers().get("Set-Cookie").is_none());
    // A client that says nothing about where it came from is not a browser submitting
    // one of our forms.
    let r = post(None);
    assert_eq!(r.status(), 403);
    assert!(r.headers().get("Set-Cookie").is_none());
    // Same-site passes the door: `BB_AUTH_LOGIN_URL` may name a page an operator serves
    // on a sibling host, and that page has always been able to post here.
    assert_ne!(post(Some("same-site")).status(), 403);
}

#[test]
fn the_session_endpoint_mints_a_cookie_and_lands_on_the_rd() {
    let base = serve(token_state(gate_settings("{}")));
    let r = agent()
        .post(format!("{base}/auth/session"))
        .header("Sec-Fetch-Site", "same-origin")
        .send_form([
            ("id_token", IT_TOKEN_OK),
            ("rd", "https://search.badbat75.com/x"),
        ])
        .unwrap();
    assert_eq!(r.status(), 302);
    assert_eq!(
        r.headers().get("Location").unwrap(),
        "https://search.badbat75.com/x"
    );
    // The cookie itself, and the header that keeps the response carrying it out of a
    // cache.
    let sc = r.headers().get("Set-Cookie").unwrap().to_str().unwrap();
    assert!(sc.starts_with("bb_session=bb1."), "{sc}");
    assert!(sc.contains("HttpOnly") && sc.contains("Secure"), "{sc}");
    assert_eq!(r.headers().get("Cache-Control").unwrap(), "no-store");

    // A token that does not validate gets no cookie and an error page, not a redirect.
    let mut r = agent()
        .post(format!("{base}/auth/session"))
        .header("Sec-Fetch-Site", "same-origin")
        .send_form([("id_token", IT_TOKEN_BAD_EMAIL)])
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.headers().get("Set-Cookie").is_none());
    // And it is a rendered page: the way back to the sign-in page it came from, with
    // every placeholder filled. A template that lost a substitution shows the raw
    // `__BB_` on the one page nobody is reading carefully.
    let page = r.body_mut().read_to_string().unwrap();
    assert!(page.contains(LOGIN), "{page}");
    assert!(!page.contains("__BB_"), "{page}");

    // And a body that carries no token at all is a 400, which is the shape a broken
    // sign-in page produces.
    let r = agent()
        .post(format!("{base}/auth/session"))
        .header("Sec-Fetch-Site", "same-origin")
        .send_form([("rd", "https://search.badbat75.com/x")])
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[test]
fn the_sign_in_page_carries_its_policy_and_the_nonce_it_names() {
    let base = serve(token_state(gate_settings("{}")));
    let mut r = agent().get(format!("{base}/auth/login")).call().unwrap();
    assert_eq!(r.status(), 200);
    for (k, v) in PAGE_SECURITY_HEADERS {
        assert_eq!(r.headers().get(k).unwrap(), v, "missing {k}");
    }
    let csp = r
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let body = r.body_mut().read_to_string().unwrap();
    // The policy is only a policy if the page's own two blocks carry the nonce it names,
    // and if nothing else can execute.
    let nonce = csp
        .split("'nonce-")
        .nth(1)
        .and_then(|t| t.split('\'').next())
        .expect("a nonce in the policy")
        .to_string();
    assert!(csp.starts_with("default-src 'none';"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    // These fixture settings name no cookie domain, so the estate is a single host and
    // `'self'` is the whole answer. The semicolon is part of the assertion: it is what
    // says nothing has been quietly added beside it.
    assert!(csp.contains("form-action 'self';"), "{csp}");
    assert!(
        body.contains(&format!("<script nonce=\"{nonce}\">")),
        "the script must carry the policy's nonce"
    );
    assert!(
        body.contains(&format!("<style nonce=\"{nonce}\">")),
        "the stylesheet must carry the policy's nonce"
    );
    // A second response must not be able to reuse the first one's nonce.
    let mut r2 = agent().get(format!("{base}/auth/login")).call().unwrap();
    assert!(!r2.body_mut().read_to_string().unwrap().contains(&nonce));

    // `HEAD`, which nginx answered on the file this URL replaced.
    assert_eq!(
        agent()
            .head(format!("{base}/auth/login"))
            .call()
            .unwrap()
            .status(),
        200
    );
}

/// A whole login, both ways in, checked against the policy of the page that ran it.
///
/// **Every piece of this was already tested and the login was still broken**, which is
/// the argument for this test rather than an argument against the ones it joins.
/// `/auth/login` and `/auth/callback` had their policy asserted; `/auth/session` had its
/// `302`, its `Location` and its cookie asserted; and nothing anywhere compared the two.
/// `form-action` is a claim the page makes about where its form may **end up**, the
/// `Location` is where the gate then sends it, and Chromium is what refuses the pair when
/// they disagree: the `POST` is same-origin and passes, the session is minted, the cookie
/// is set, the journal records `session granted`, and the browser silently drops the
/// navigation. The person is signed in and is looking at a spinner that will never finish.
///
/// So this walks the login end to end and asserts the **relationship** rather than a
/// string: it reads the `form-action` off the page, follows the same `POST` a browser
/// would, and requires the redirect the gate issues to be permitted by the page that
/// issued the form. A literal assertion would have to be rewritten by whoever broke it;
/// this one only passes when a login actually works.
///
/// **Both ways in, because they are two documents.** The email flow POSTs from
/// `/auth/login`; a social sign-in comes back through `/auth/callback`, which POSTs the
/// token it has just exchanged. The last hop is the same for both and the page carrying
/// the policy is not, which is exactly the kind of difference "it is the same function"
/// hides: that was true of the broken version too. What is out of reach here is the middle
/// of the social leg, the code-for-token exchange, because that is Amazon's endpoint and
/// this suite is offline; the page that performs it and the `POST` that follows it are
/// both here.
///
/// The one thing no test in this language can do is **enforce** a CSP, which only a
/// browser does. What it can do is stop the two halves drifting apart again, and that
/// drift is the whole of what went wrong. It went unseen because every fixture deployment
/// in this suite was a single host, where `'self'` is the right answer and the bug does
/// not exist; this one names a cookie domain, which is what a real deployment has.
#[test]
fn a_whole_login_lands_where_the_page_that_ran_it_permits() {
    let base = serve(token_state(gate_settings(&format!(
        r#"{{ "cookie_domain": ".badbat75.com",
                  "oauth_domain": "pool.auth.eu-central-1.amazoncognito.com",
                  "social_callback_url": "{CALLBACK_URL}",
                  "social_buttons": [{{ "idp": "Google", "audience": "social-client" }}] }}"#
    ))));

    /// What a browser does with a `form-action` source list, near enough to assert on:
    /// the redirect's origin must be the page's own (`'self'`), an origin named
    /// literally, or a subdomain of a `https://*.d` source. A wildcard does not match
    /// the domain it is a wildcard of, which is why the apex has to be listed beside it
    /// and why this is worth modelling rather than string-matching.
    fn permits(directive: &str, url: &str, own: &str) -> bool {
        let origin: String = url.split('/').take(3).collect::<Vec<_>>().join("/");
        directive.split(' ').any(|src| match src {
            "'self'" => origin == own,
            _ => match src.strip_prefix("https://*.") {
                Some(d) => origin
                    .strip_prefix("https://")
                    .is_some_and(|h| h.ends_with(&format!(".{d}"))),
                None => src == origin,
            },
        })
    }

    // A subdomain and the apex: the two arms of the directive, and both are ordinary
    // landing places here. The apex is not decoration, since a CSP wildcard no more
    // matches it than a host pattern does.
    for target in ["https://ai.badbat75.com/llm/", "https://badbat75.com/"] {
        for page in ["/auth/login", "/auth/callback"] {
            let r = agent().get(format!("{base}{page}")).call().unwrap();
            assert_eq!(r.status(), 200, "{page}");
            let csp = r
                .headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let form_action = csp
                .split("; ")
                .find_map(|d| d.strip_prefix("form-action "))
                .expect("every page carries a form-action");

            // The form POST that page makes, which is same-origin and always was: this
            // is the hop that has never been in doubt.
            let r = agent()
                .post(format!("{base}/auth/session"))
                .header("Sec-Fetch-Site", "same-origin")
                .send_form([("id_token", IT_TOKEN_OK), ("rd", target)])
                .unwrap();
            assert_eq!(r.status(), 302, "{page} -> {target}");
            let sc = r.headers().get("Set-Cookie").unwrap().to_str().unwrap();
            assert!(sc.starts_with("bb_session=bb1."), "{sc}");
            let location = r.headers().get("Location").unwrap().to_str().unwrap();
            assert_eq!(location, target, "{page}");

            // And the assertion the outage was: the login has succeeded, and this is
            // whether the browser will be allowed to finish it.
            assert!(
                permits(form_action, location, &base),
                "a login from {page} is minted and then cancelled: \
                     form-action {form_action} does not permit {location}"
            );
        }
    }

    // The other direction, which says what this directive is not. `safe_rd` refuses a
    // target outside `gate.authorized_hosts` and falls back to the sign-in page, so the
    // authorization boundary is still the settings file's and not the policy's; and the
    // page it falls back to is itself inside what the policy permits, or a refused `rd`
    // would strand the visitor exactly as the bug did.
    let r = agent()
        .post(format!("{base}/auth/session"))
        .header("Sec-Fetch-Site", "same-origin")
        .send_form([("id_token", IT_TOKEN_OK), ("rd", "https://evil.example/x")])
        .unwrap();
    assert_eq!(r.status(), 302);
    let fallback = r.headers().get("Location").unwrap().to_str().unwrap();
    assert_eq!(fallback, LOGIN);
    let csp = agent()
        .get(format!("{base}/auth/login"))
        .call()
        .unwrap()
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let form_action = csp
        .split("; ")
        .find_map(|d| d.strip_prefix("form-action "))
        .unwrap();
    assert!(permits(form_action, fallback, &base), "{form_action}");
}

/// A deployment that sets the two `ui` URLs: the page asks for them and the policy lets
/// them through, which only holds if both are derived from the same two settings.
///
/// The failure this exists for is silent from every angle: the header is there, the
/// `<link>` and the `<img>` are there, the asset host is up, and the browser fetches
/// neither, because the policy names a different host or none. Nothing in the response
/// says so; the operator sees a login page rendered as bare HTML and no logo, which is
/// what an unreachable asset host looks like too.
#[test]
fn a_configured_stylesheet_and_logo_are_in_the_page_and_in_the_policy() {
    let ui = bb_auth_core::UiSettings {
        stylesheet_url: "https://assets.badbat75.com/css/theme.css".to_string(),
        logo_url: "https://assets.badbat75.com/img/logo.svg".to_string(),
        brand_name: "BadBat75".to_string(),
        theme: "dark".to_string(),
    };
    let base = serve(token_state(ui_settings(ui)));
    let mut r = agent().get(format!("{base}/auth/login")).call().unwrap();
    assert_eq!(r.status(), 200);
    let csp = r
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let body = r.body_mut().read_to_string().unwrap();

    // The page asks for both, by their full URL.
    assert!(
        body.contains(
            r#"<link rel="stylesheet" href="https://assets.badbat75.com/css/theme.css">"#
        ),
        "the operator's stylesheet must be linked: {body}"
    );
    assert!(
        body.contains(r#"<img src="https://assets.badbat75.com/img/logo.svg" alt="">"#),
        "the operator's logo must be in the page"
    );
    // And the policy admits that host for both, by origin and not by path.
    assert!(
        csp.contains("https://assets.badbat75.com;")
            || csp.contains("https://assets.badbat75.com "),
        "{csp}"
    );
    for directive in ["style-src", "img-src"] {
        let d = csp
            .split(';')
            .map(str::trim)
            .find(|d| d.starts_with(directive))
            .unwrap_or_else(|| panic!("{directive} in {csp}"));
        assert!(
            d.contains("https://assets.badbat75.com"),
            "{directive} must admit the host the page asks: {d}"
        );
    }
    // The inline blocks are still nonce-covered, so adding an external host does not
    // quietly relax what the page itself may run.
    assert!(csp.contains("script-src 'nonce-"), "{csp}");
    assert!(!csp.contains("unsafe-inline"), "{csp}");
}

#[test]
fn with_no_login_url_configured_the_gate_names_its_own_page() {
    // The default that makes the setting optional: since the gate serves the sign-in page
    // itself, naming one is how an operator points somewhere ELSE. A path and not a URL,
    // because this process knows neither its own scheme nor its own host.
    let mut file: bb_auth_core::SettingsFile = serde_json::from_str(&format!(
        r#"{{ "version": {}, "gate": {{ "client_id": "testclient" }} }}"#,
        bb_auth_core::SETTINGS_VERSION
    ))
    .unwrap();
    file.gate.login_url = String::new();
    let settings = bb_auth_core::compile_settings(&file).unwrap();
    assert_eq!(global_login(&settings), "/auth/login");

    let base = serve(token_state(settings));
    let r = agent().get(format!("{base}/auth/logout")).call().unwrap();
    assert_eq!(r.headers().get("Location").unwrap(), "/auth/login");
}

/// The same default, pinned to the **library's** constant and not to a literal. The gate
/// answers a logout, a `401` and an empty `gate.login_url` with this path, and
/// `bb-auth-web` writes it into the logout `rd` of the deletion flow (§13.32 §1). Two
/// programs naming the same page is a shared fact, which is the library's membership rule,
/// so the byte is asserted once here and read from there. A rename of the gate's own page
/// that updates one program and not the other sends every signed-out browser to a `404`.
#[test]
fn the_login_path_is_the_librarys() {
    assert_eq!("/auth/login", bb_auth_core::GATE_LOGIN_PATH);
    let mut file: bb_auth_core::SettingsFile = serde_json::from_str(&format!(
        r#"{{ "version": {}, "gate": {{ "client_id": "testclient" }} }}"#,
        bb_auth_core::SETTINGS_VERSION
    ))
    .unwrap();
    file.gate.login_url = String::new();
    let settings = bb_auth_core::compile_settings(&file).unwrap();
    assert_eq!(global_login(&settings), bb_auth_core::GATE_LOGIN_PATH);
}

#[test]
fn a_logout_clears_the_cookie_and_only_refuses_a_cross_site_one() {
    let base = serve(token_state(gate_settings("{}")));
    let r = agent().get(format!("{base}/auth/logout")).call().unwrap();
    assert_eq!(r.status(), 302);
    // No `rd`, no `Referer`: the login page, never `safe_rd`'s caller-root default.
    assert_eq!(r.headers().get("Location").unwrap(), LOGIN);
    let sc = r.headers().get("Set-Cookie").unwrap().to_str().unwrap();
    assert!(sc.starts_with("bb_session=;"), "{sc}");
    assert!(sc.contains("Max-Age=0"), "{sc}");

    // Cross-site: still a redirect, deliberately, but nothing is cleared.
    let r = agent()
        .get(format!("{base}/auth/logout"))
        .header("Sec-Fetch-Site", "cross-site")
        .call()
        .unwrap();
    assert_eq!(r.status(), 302);
    assert!(r.headers().get("Set-Cookie").is_none());
}

/// The last hop of the deletion flow, as the account page issues it (docs §13.32 §4).
///
/// Nothing new runs here, and that is the point: §13.32 §1 puts no code in the gate for
/// this step, because the notice is a query string on a URL the logout already lands on.
/// So this is a **pin**, and it is green before the page grows a notice: the pair that has
/// to keep working is that a signed-out browser is sent *through* the sign-in page with
/// the code attached, and the code arrives intact through `safe_rd`, which is the guard
/// that has every right to reject a value carrying a query. A change to the logout's
/// landing logic, to `safe_rd`, or to how the gate answers an `X-Original-URL` of nothing,
/// and the person whose account is being deleted sees the sign-in page with no explanation
/// of what happened to them.
#[test]
fn a_logout_with_the_deletion_rd_clears_and_lands_on_the_notice() {
    // A cookie domain, because the expiring cookie has to carry the one the session was
    // set with, and the notice is worthless to a person whose browser is still signed in.
    let base = serve(token_state(gate_settings(
        r#"{ "cookie_domain": ".badbat75.com" }"#,
    )));
    // The `rd` the account page writes, percent-encoded as a link writes it. The gate's
    // own sign-in path and the library's notice code, not this test's: a rename of either
    // moves every browser and silently lands this person on the sign-in page with the
    // notice hidden.
    let rd = format!(
        "/{}?notice={}",
        bb_auth_core::GATE_LOGIN_PATH.trim_start_matches('/'),
        bb_auth_core::LOGIN_NOTICE_ACCOUNT_DELETED
    );
    let url = format!("{base}/auth/logout?rd={}", pct_encode(&rd));
    let r = agent()
        .get(&url)
        .header("X-Original-URL", LANDING)
        .header("Sec-Fetch-Site", "same-origin")
        .call()
        .unwrap();
    assert_eq!(r.status(), 302);
    // The `rd` survives: same-origin path, resolved against the caller's host, and the
    // notice's query is not stripped on the way through `safe_rd`.
    let want = format!(
        "https://auth.badbat75.com{}?notice={}",
        bb_auth_core::GATE_LOGIN_PATH,
        bb_auth_core::LOGIN_NOTICE_ACCOUNT_DELETED
    );
    assert_eq!(
        r.headers().get("Location").unwrap(),
        &want,
        "the signed-out browser must land on the sign-in page carrying the code"
    );
    let sc = r.headers().get("Set-Cookie").unwrap().to_str().unwrap();
    assert!(sc.starts_with("bb_session=;"), "{sc}");
    assert!(sc.contains("Max-Age=0"), "{sc}");
    assert!(sc.contains("Domain=.badbat75.com"), "{sc}");
    assert!(sc.contains("Path=/"), "{sc}");

    // No `X-Original-URL`: the gate knows nothing about which host asked, and the logout
    // must still clear the session and still reach a sign-in page. A person mid-deletion
    // whose deployment has not wired the header is not left holding a live cookie.
    let r = agent()
        .get(&url)
        .header("Sec-Fetch-Site", "same-origin")
        .call()
        .unwrap();
    assert_eq!(r.status(), 302);
    assert_eq!(r.headers().get("Location").unwrap(), LOGIN, "{rd}");
    let sc = r.headers().get("Set-Cookie").unwrap().to_str().unwrap();
    assert!(sc.contains("Max-Age=0"), "{sc}");
}

/// The list `--check-env` answers with, against the calls that actually make a variable
/// required. `deploy/debian/bb-auth/postinst` used to keep a second copy of this in
/// shell; it now asks the binary, and this is what keeps the binary honest.
#[test]
fn the_required_env_list_matches_the_code() {
    let src = include_str!("main.rs");
    let called: std::collections::BTreeSet<&str> = src
        .match_indices("env_req(\"")
        .map(|(i, m)| {
            let rest = &src[i + m.len()..];
            &rest[..rest.find('"').expect("a closed string literal")]
        })
        .collect();
    let listed: std::collections::BTreeSet<&str> = REQUIRED_ENV.iter().copied().collect();
    assert_eq!(
        called, listed,
        "REQUIRED_ENV and the env_req call sites have drifted"
    );
}

/// The fail-soft promise, which is what makes it safe to let a GUI edit a live file:
/// a reload that cannot parse the file keeps what is already in memory.
///
/// Unix only, because SIGHUP is; that is also why this went untested for so long, since
/// the development host is Windows and the code is not even compiled there. Run it under
/// WSL (`wsl -e bash -lc 'cd /mnt/c/... && cargo test'`) before a release.
#[cfg(unix)]
#[test]
fn a_reload_that_cannot_parse_keeps_what_is_live() {
    let st = token_state(gate_settings("{}"));
    let before = st.access.read().unwrap().apps.len();
    assert!(before > 0, "the fixture has applications");

    let dir = std::env::temp_dir();
    let bad = dir.join("bb-auth-reload-bad.json");
    std::fs::write(&bad, "{ not json at all").unwrap();
    reload_access_from(&st, bad.to_str().unwrap());
    assert_eq!(
        st.access.read().unwrap().apps.len(),
        before,
        "a broken file must not empty the live table"
    );

    // A file the parser refuses for a rule reason, not a syntax one: same answer.
    std::fs::write(&bad, r#"{ "version": 99 }"#).unwrap();
    reload_access_from(&st, bad.to_str().unwrap());
    assert_eq!(st.access.read().unwrap().apps.len(), before);

    // And a good file does land.
    let good = dir.join("bb-auth-reload-good.json");
    std::fs::write(
            &good,
            r#"{ "version": 1, "applications": [
                 { "name": "only", "base": ["https://x.com/only"], "scopes": [
                   { "name": "all", "urls": ["https://x.com/only/*"], "access": "anonymous" } ] } ] }"#,
        )
        .unwrap();
    reload_access_from(&st, good.to_str().unwrap());
    assert_eq!(st.access.read().unwrap().apps.len(), 1);

    // The settings file, by the same rule.
    let ttl = st.settings.read().unwrap().session_ttl;
    let bad_s = dir.join("bb-auth-reload-bad-settings.json");
    std::fs::write(
        &bad_s,
        r#"{ "version": 1, "gate": { "identity_attrs": [] } }"#,
    )
    .unwrap();
    reload_settings_from(&st, bad_s.to_str().unwrap());
    assert_eq!(
        st.settings.read().unwrap().session_ttl,
        ttl,
        "a settings file the gate refuses must leave the live values alone"
    );

    for f in [bad, good, bad_s] {
        let _ = std::fs::remove_file(f);
    }
}

#[test]
fn a_listen_address_is_recognised_as_loopback_or_not() {
    for ok in [
        "127.0.0.1:4181",
        "localhost:4181",
        "[::1]:4181",
        "127.0.0.1",
    ] {
        assert!(listen_is_loopback(ok), "{ok}");
    }
    for no in [
        "0.0.0.0:4181",
        "10.0.0.5:4181",
        "auth.badbat75.com:80",
        "[::]:80",
    ] {
        assert!(!listen_is_loopback(no), "{no}");
    }
}

// --- section 13.25: the session's own Cognito user ------------------------------------
//
// A third offline RSA key (kid `bb-auth-un`), generated once and thrown away, signs the
// tokens below: the older fixtures carry no `cognito:username`. Every token has the claims
// of `IT_TOKEN_OK` (so it validates and lands in the `authenticated` scope `app1`) plus,
// per token, `cognito:username` and `identities` as the name says.
use bb_auth_core::NATIVE_USERNAME_HEADER;

const UN_JWKS: &str = r#"{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"bb-auth-un","e":"AQAB","n":"s-hoHHdqYKUEzHY3XeKpTYBFs6yRIwqDqDJKb9VRYN0woK8ynxd14XSboU_UuSBcej2cJegSbExrIqywG6XJu0djOBP4Od6FS_MKZaAteYRMOunZWJL5ycV9Xq9ylqrOzlA3KzLuYjGdUFXEJ3AKGjLPesNAjQZIF_IvAdnwaeN6jRTsyVUX3absp4p17A6P_lkTPx-B5Du-MFyMzZqZDwjXHsVD5zGIEvuOS0USP6CSI46sGBXGOmS29Ul_3EEOm1snZJP8ZV1N9r59PnGFSfUNJ3GutAFR5qDHMZWtijChJMn-PdqUbHmENdul4_r_iWYbqCb4txnRarLLwPt8Hw"}]}"#;
/// Native user: `"cognito:username":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"`, no `identities`.
const UN_NATIVE: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtdW4ifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjb2duaXRvOnVzZXJuYW1lIjoiMGExYjJjM2QtNGU1Zi00YTZiLThjN2QtOWUwZjFhMmIzYzRkIn0.RZUlzYkqvsSsdHOw5hsu21PC8MOi8gWT0PuDPRX2_wDudcZERozBUHC8KO265QpL5oEsg4O2mXCaErMCq20W2wMIveZr4-X6ohuniYuywB04KZqiUJJnlRxsA9BwjjX82aZGo7l-yHUGX_gB-S1eSzBWy430SoLvR2a6_BbbyQTO13X1Dms2gVI0QV9cSFTsLolV9tM9B0R-NECJX6hnvZSlz6RdpGKJ0ARMCVaIAhylmTWfN2tKWNlm2yfvY7vPwc6TMD1oIOMqfS4ZnHVESLO6J81fkkJ-hrzMDkWU8I7nPTcYZ22yvVbVXZs1QdjtiNZLcsXjS_dRYzVQ-pCFtQ";
const UN_NATIVE_NAME: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
/// Federated user: `"cognito:username":"Google_1234567890"` and a Google `identities` entry.
const UN_FEDERATED: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtdW4ifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjb2duaXRvOnVzZXJuYW1lIjoiR29vZ2xlXzEyMzQ1Njc4OTAiLCJpZGVudGl0aWVzIjpbeyJwcm92aWRlck5hbWUiOiJHb29nbGUiLCJ1c2VySWQiOiIxMjM0NTY3ODkwIn1dfQ.ogE2na2omfwksp1DYBAvvYTXbLCHd1CDJKV3nciuyWB2Z1PCNcMiOY-h2uU1DB_tvmg87QKwCXbbSEukathOZaaAkLlySQ0aJXqI6x8xMuHAP_O5tqX1OiiFudGQHopwmqrb5Vp_c4oqwmtvrvd0gymKrQw9mUrYlUvJ9O6FuyjLBowPrbzCambndOOspcR8S-3ZqWhaAbtLuYyLSe1M7Hque2RSg8fGlh1tKmTGvHe9cZ1wWHMrwRKN5ze0rOimXLLvfxJe_tjqZ08qOQSBxQbFmoz1jgbNvuePjxVrpGOVgtAc_ohubBcVO2CDb5o0pqlM6X3WgSGqg14Ul_boBg";
/// A native-looking token with no `cognito:username` at all.
const UN_NO_USERNAME: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtdW4ifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfQ.Hka5-mfbq11skaG_BZxGkhb386R5Sl43gTZrJ0xoMclR7cjNuDvirQOhMA4ovRxLe-4nyFWVKxj90dWfhUwGL2B_e_3YQfzPWPYah7KJ31tekQ_jo5579yUFWfiFWgv6xIEXpwscsfry8OfVrJh7UHX0PWruX5U0bqYwXvGlYC7UFG4cvUJBKzAPjt7Y1l2yhIjTCggGho_O3Cr98pBc56heIXHxKEsL2UwZY5Ob_B4M1rEbo2EsIs7t4-G4OgKj0ruftQ7YX_ezMgNp8tkuePYSMlYqfRN1Wvjq0AQ7nmmnEuYN67kn7UQrazlrM2h8-Vcvgcu_YZzo5v42DejQCg";
/// `"cognito:username":"bad name"` (a space), no `identities`.
const UN_SPACE: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtdW4ifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjb2duaXRvOnVzZXJuYW1lIjoiYmFkIG5hbWUifQ.jR2zgo4jf8GOEkVC5_PQk69UQbLPYEc9Top9hX59kQCoewqeklin0qMejKjAdiFL1Lwt_TbaBE7t3KQ1yZgn79TINHoIJX2AWUGkJ1_yuB28ZkS1oEJ3GX2S199KmETHeLCS5KKrcxxJDwcDZ0Hso8dGs3L1ead9j-smPE4xpOCoLcPTUpkfXSxf5amXr3hf5sLPVI4Z6ENtmqfPjsI-f_pjZYa39e1TkCxMMfOlKVWhvq7mang2oHQy_UaHrpoKnvMsCVREoaHLbLDxH59ugzyA1SR7WalnczujVSrPGIQIsufE3kpfKyW0ESdlqQdr2try-6FsleIB8dnuBQwX4Q";
/// `"cognito:username":"us\u00e9r"` (non-ASCII), no `identities`.
const UN_NON_ASCII: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtdW4ifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjb2duaXRvOnVzZXJuYW1lIjoidXNcdTAwZTlyIn0.Mcz5-evw8Xu-iaAxC0wbsMlHYmrxQDhYXEoZ7KwzJBqKujvUCEmRaIhbcuPoL2cgnQYafCs_nqD97ySMqgvIAcN-nHNQORbGDU79nB4v7iwJjTY7sGv8w1TxPIAlIVT2eFgKdDzUadnmA1Ee-aSoQOb1ZMxifBj1SmhHH_jYSTk7EK4e1SqZUgDb0UpBohaYg_hOe4ji0ayoQ0oYuE9qG10UAqM4YD1G-03eM7HqWsUHHUuxZDpCE0hSHWheBKQPwdpeuWT8jzVe32gsEB1IC5LNkZWRhBFrffSN47bvuXuqTrs04MxjiCGBChoJ4neVLsNYWN7qAQEnv3Ok4-1r0w";

/// The fixture state plus the third key, so nothing here touches the network.
fn username_state(settings: Settings) -> State {
    let st = token_state(settings);
    let set: JwkSet = serde_json::from_str(UN_JWKS).expect("fixture JWKS parses");
    for jwk in &set.keys {
        st.jwks.write().unwrap().keys.insert(
            jwk.common.key_id.clone().unwrap(),
            DecodingKey::from_jwk(jwk).expect("fixture JWK becomes a key"),
        );
    }
    st
}

const APP1_URL: &str = "https://app.x.com/app1/x";

fn native_ident(email: &str, username: Option<&str>) -> UserIdentity {
    UserIdentity {
        native_username: username.map(str::to_string),
        ..ident(email)
    }
}

/// `GET /auth/validate` on the `authenticated` area, with one credential header.
fn validate_with(
    base: &str,
    name: &str,
    value: &str,
    url: &str,
) -> ureq::http::Response<ureq::Body> {
    agent()
        .get(format!("{base}/auth/validate"))
        .header("X-Original-URL", url)
        .header(name, value)
        .call()
        .unwrap()
}

fn native_header(r: &ureq::http::Response<ureq::Body>) -> Option<String> {
    r.headers()
        .get(NATIVE_USERNAME_HEADER)
        .map(|v| v.to_str().unwrap().to_string())
}

/// The cookie value `/auth/session` sets for `token`.
fn session_cookie_for(base: &str, token: &str) -> String {
    let r = agent()
        .post(format!("{base}/auth/session"))
        .header("Sec-Fetch-Site", "same-origin")
        .send_form([("id_token", token), ("rd", "https://search.badbat75.com/x")])
        .unwrap();
    assert_eq!(r.status(), 302);
    let sc = r.headers().get("Set-Cookie").unwrap().to_str().unwrap();
    sc.split(';').next().unwrap().to_string()
}

#[test]
fn validate_id_token_captures_the_username_only_for_a_native_token() {
    let st = username_state(gate_settings("{}"));
    let native = validate_id_token(UN_NATIVE, &st).expect("a native token verifies");
    assert_eq!(native.native_username.as_deref(), Some(UN_NATIVE_NAME));
    // It is never a profile claim: nothing was configured, and it must not leak into the map.
    assert!(native.claims.is_empty(), "{:?}", native.claims);

    // A federated token carries `cognito:username` too (`Google_...`), and it is NOT the
    // session's Cognito user for editing: `identities` present means no capture at all.
    let fed = validate_id_token(UN_FEDERATED, &st).expect("a federated token still signs in");
    assert_eq!(fed.native_username, None);

    // No claim, no capture; the login itself is untouched.
    let none = validate_id_token(UN_NO_USERNAME, &st).expect("it still signs in");
    assert_eq!(none.native_username, None);
    assert_eq!(none.email, "ada@example.com");
}

/// A `bb1` cookie for `ada@example.com`, signed by hand with the test key and carrying
/// `claims` as its claims segment. `make_session` is not the only way bytes reach the
/// verifier, and a test of what the verifier does with a value it did not mint has to
/// sign it the way an attacker with the key would.
fn hand_signed(claims: &str) -> String {
    let keys = keys_one();
    let exp = now() + 3600;
    let b64 = |s: &str| URL_SAFE_NO_PAD.encode(s.as_bytes());
    let msg = format!(
        "{COOKIE_VERSION}.{}.{exp}.{}.{}",
        keys.active_id,
        b64("ada@example.com"),
        b64(claims)
    );
    format!("{msg}.{}", sign(keys.active(), &msg))
}

#[test]
fn an_unsafe_username_is_omitted_not_emitted() {
    let st = username_state(gate_settings("{}"));
    // The token still signs in (cost the edit, never the login) and captures nothing.
    for tok in [UN_SPACE, UN_NON_ASCII] {
        let id = validate_id_token(tok, &st).expect("the login itself is unaffected");
        assert_eq!(id.native_username, None, "kept an unsafe username");
    }
    // A cookie that carries one anyway (a bug elsewhere, a key compromise) is still
    // granted and still emits no header: the run-time guard the identity headers have,
    // applied on the way out rather than only on the way in.
    let base = serve(username_state(gate_settings("{}")));
    for bad in ["bad name", "us\u{e9}r"] {
        let cookie = format!(
            "bb_session={}",
            hand_signed(&format!(r#"{{"native_username":"{bad}"}}"#))
        );
        let r = validate_with(&base, "Cookie", &cookie, APP1_URL);
        assert_eq!(
            r.status(),
            204,
            "{bad:?}: the request itself is still granted"
        );
        assert_eq!(native_header(&r), None, "{bad:?} must not be emitted");
    }
    // A control byte and an empty value are not claim values at all, so the
    // claims-segment grammar owns them: the whole cookie fails, which is what that
    // grammar has always done for a claim value it could not have minted.
    for claims in [
        r#"{"native_username":""}"#,
        r#"{"native_username":"x\r\nX-Auth-Admin: 1"}"#,
    ] {
        let r = validate_with(
            &base,
            "Cookie",
            &format!("bb_session={}", hand_signed(claims)),
            APP1_URL,
        );
        assert_eq!(r.status(), 401, "{claims} fails the cookie, not the header");
    }
}

#[test]
fn a_native_token_names_its_username_on_the_204() {
    let base = serve(username_state(gate_settings("{}")));
    let r = validate_with(
        &base,
        "Authorization",
        &format!("Bearer {UN_NATIVE}"),
        APP1_URL,
    );
    assert_eq!(r.status(), 204);
    assert_eq!(native_header(&r).as_deref(), Some(UN_NATIVE_NAME));
    // The identity header is still what it was.
    assert_eq!(r.headers().get(IDENTITY_HEADER).unwrap(), "ada@example.com");
}

#[test]
fn a_federated_token_names_no_native_username() {
    let base = serve(username_state(gate_settings("{}")));
    let r = validate_with(
        &base,
        "Authorization",
        &format!("Bearer {UN_FEDERATED}"),
        APP1_URL,
    );
    // The sign-in is fine, the header is simply not there.
    assert_eq!(r.status(), 204);
    assert_eq!(r.headers().get(IDENTITY_HEADER).unwrap(), "ada@example.com");
    assert_eq!(native_header(&r), None);
    // And so is a token with no username to name.
    let r = validate_with(
        &base,
        "Authorization",
        &format!("Bearer {UN_NO_USERNAME}"),
        APP1_URL,
    );
    assert_eq!(r.status(), 204);
    assert_eq!(native_header(&r), None);
}

#[test]
fn the_cookie_carries_the_native_username_and_gives_it_back() {
    let base = serve(username_state(gate_settings("{}")));
    let cookie = session_cookie_for(&base, UN_NATIVE);
    let r = validate_with(&base, "Cookie", &cookie, APP1_URL);
    assert_eq!(r.status(), 204);
    assert_eq!(native_header(&r).as_deref(), Some(UN_NATIVE_NAME));

    // A federated sign-in mints a cookie that names none.
    let cookie = session_cookie_for(&base, UN_FEDERATED);
    let r = validate_with(&base, "Cookie", &cookie, APP1_URL);
    assert_eq!(r.status(), 204);
    assert_eq!(native_header(&r), None);
}

#[test]
fn the_new_claims_segment_passes_the_old_grammar_and_the_version_is_unchanged() {
    let base = serve(username_state(gate_settings("{}")));
    let cookie = session_cookie_for(&base, UN_NATIVE);
    let value = cookie.strip_prefix("bb_session=").unwrap();
    // No bump: same tag, same six segments.
    assert!(value.starts_with(&format!("{COOKIE_VERSION}.")), "{value}");
    assert_eq!(COOKIE_VERSION, "bb1");
    let parts: Vec<&str> = value.splitn(6, '.').collect();
    assert_eq!(parts.len(), 6);
    // The username rides in the self-describing claims object, under a gate-owned key.
    let raw = URL_SAFE_NO_PAD.decode(parts[4]).unwrap();
    let map: BTreeMap<String, String> = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        map.get("native_username").map(String::as_str),
        Some(UN_NATIVE_NAME)
    );
    // What a rollback binary checks, restated: every key a claim name, every value a
    // claim value. A cookie that fails this would log the rollback's users out.
    assert!(map
        .iter()
        .all(|(k, v)| claim_name_ok(k) && claim_value_ok(v)));
    // And the current verifier hands the username back as its own field, never as a claim.
    let id = verify_session(value, &keys_one()).unwrap();
    assert_eq!(id.native_username.as_deref(), Some(UN_NATIVE_NAME));
    assert!(
        !id.claims.contains_key("native_username"),
        "{:?}",
        id.claims
    );
}

#[test]
fn a_native_username_survives_a_cookie_round_trip_beside_profile_claims() {
    let mut who = ident_claims("ada@example.com", &[("given_name", "Ada")]);
    who.native_username = Some(UN_NATIVE_NAME.to_string());
    let back = verify_session(&make_session(&who, 3600, &keys_one()), &keys_one()).unwrap();
    assert_eq!(back, from_cookie(who));
    // Without one, the segment is byte for byte what it was before this change.
    let plain = ident_claims("ada@example.com", &[("given_name", "Ada")]);
    let cookie = make_session(&plain, 3600, &keys_one());
    let seg = cookie.split('.').nth(4).unwrap();
    assert_eq!(
        String::from_utf8(URL_SAFE_NO_PAD.decode(seg).unwrap()).unwrap(),
        r#"{"given_name":"Ada"}"#
    );
    // And a native identity with no claims at all still gets a segment, not an empty one.
    let only = native_ident("ada@example.com", Some(UN_NATIVE_NAME));
    let cookie = make_session(&only, 3600, &keys_one());
    let seg = cookie.split('.').nth(4).unwrap();
    assert_eq!(
        String::from_utf8(URL_SAFE_NO_PAD.decode(seg).unwrap()).unwrap(),
        format!(r#"{{"native_username":"{UN_NATIVE_NAME}"}}"#)
    );
}

#[test]
fn a_cookie_without_it_still_verifies_and_names_none() {
    // The "no bump" test: a `bb1` cookie of the shape every gate minted before this
    // change, signed by hand rather than by `make_session`, which is what is changing.
    let keys = keys_one();
    let cookie = hand_signed(r#"{"given_name":"Ada"}"#);
    let id = verify_session(&cookie, &keys).expect("an old cookie still verifies");
    assert_eq!(id.native_username, None);
    assert_eq!(id.claims.get("given_name").map(String::as_str), Some("Ada"));

    let base = serve(username_state(gate_settings("{}")));
    let r = validate_with(&base, "Cookie", &format!("bb_session={cookie}"), APP1_URL);
    assert_eq!(r.status(), 204);
    assert_eq!(native_header(&r), None, "an old cookie fails closed");
}

#[test]
fn an_api_key_names_no_native_username() {
    let base = serve(username_state(gate_settings("{}")));
    let r = validate_with(
        &base,
        "Authorization",
        "Bearer bbk_secret",
        "https://app.x.com/other/x",
    );
    assert_eq!(r.status(), 204);
    assert_eq!(native_header(&r), None);
}

#[test]
fn the_native_username_is_never_a_profile_header() {
    // With profile claims configured, a native session emits the configured claim and the
    // one reserved header, once, and nothing else of that name.
    let base = serve(username_state(gate_settings(
        r#"{ "profile_claims": ["given_name"] }"#,
    )));
    let mut who = ident_claims("ada@example.com", &[("given_name", "Ada")]);
    who.native_username = Some(UN_NATIVE_NAME.to_string());
    let cookie = format!("bb_session={}", make_session(&who, 3600, &keys_one()));
    let r = validate_with(&base, "Cookie", &cookie, APP1_URL);
    assert_eq!(r.status(), 204);
    assert_eq!(r.headers().get("X-Auth-Given-Name").unwrap(), "Ada");
    assert_eq!(native_header(&r).as_deref(), Some(UN_NATIVE_NAME));
    assert_eq!(
        r.headers().get_all(NATIVE_USERNAME_HEADER).iter().count(),
        1
    );

    // A cookie an older binary configured with a `native_username` claim could carry that
    // key as a *claim value* only if it is also the reserved one: whichever, the live
    // config cannot name it, so no second header appears.
    let names: Vec<String> = r
        .headers()
        .keys()
        .map(|k| k.as_str().to_ascii_lowercase())
        .filter(|k| k.contains("native"))
        .collect();
    assert_eq!(names, vec!["x-auth-native-username".to_string()]);
}
