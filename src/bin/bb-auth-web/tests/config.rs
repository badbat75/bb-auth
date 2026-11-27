use super::*;

// --- config -------------------------------------------------------------

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

/// The startup rule for `BB_AUTH_WEB_PROXY_SECRET` (docs/ARCHITECTURE.md §13.3): required,
/// at least 32 characters, and only `[A-Za-z0-9_-]`, so the value survives a shell, an env
/// file and an nginx `proxy_set_header` line with nothing to quote. Every refusal names the
/// variable, because a journal line that says only "bad secret" is a search; and no refusal
/// contains the value, because a secret printed at boot is a secret in the journal for ever.
#[test]
fn the_startup_refuses_a_missing_short_or_unsafe_proxy_secret_naming_the_variable() {
    let refused = |raw: &str| {
        let e = compile_proxy_secret(raw).expect_err("refused at startup");
        assert!(
            e.contains("BB_AUTH_WEB_PROXY_SECRET"),
            "the message must name the variable: {e}"
        );
        e
    };

    // Absent: `from_env` hands the empty string to this, and an unset variable has no safe
    // default, so the process refuses to start.
    refused("");

    // One character short of the floor.
    let short = "a".repeat(31);
    let e = refused(&short);
    assert!(
        !e.contains(&short),
        "the message must not echo the value: {e}"
    );

    // Long enough, and one character outside the charset.
    let spaced = format!("{} x", "a".repeat(30));
    assert_eq!(spaced.chars().count(), 32);
    let e = refused(&spaced);
    assert!(
        !e.contains(&spaced),
        "the message must not echo the value: {e}"
    );

    // A value that meets the rule is accepted unchanged, and that includes the fixture's,
    // so every over-the-wire test here is a deployment that could start.
    let ok = format!("{}-_ab", "a".repeat(28));
    assert_eq!(ok.chars().count(), 32);
    assert_eq!(compile_proxy_secret(&ok).expect("accepted"), ok);
    assert_eq!(
        compile_proxy_secret(TEST_SECRET).expect("accepted"),
        TEST_SECRET
    );
}

/// The startup rule for `BB_AUTH_WEB_WORKERS` (docs/ARCHITECTURE.md §13.13, plan step 4e):
/// unset is 8, the accepted range is 1 to 64, and every other value is a refusal naming the
/// variable. Tested on the parser alone and never by setting the environment: `std::env` is
/// process-global and this suite's tests run in parallel, so a test that wrote
/// `BB_AUTH_WEB_WORKERS` would race every other test in the binary, and the value `main`
/// reads is read once at startup anyway.
///
/// The default is 8 because a handler here waits rather than computes (a write queues on
/// [`WRITE_LOCK`] and two fsyncs, and from plan step 5 a Cognito call queues on the
/// network), so the ruler is how many slow handlers may be in flight while page views still
/// get through, not the core count. It is not 2, which is the constant this replaces and
/// whose own comment says it was sized for the handful of people on `web.admins`, before
/// `/account` opened the same process to every signed-in person.
#[test]
fn workers_unset_is_the_default_of_eight() {
    assert_eq!(
        compile_workers(None),
        Ok(8),
        "an unset variable is the default and not a refusal, because a package creates the \
             env file and cannot know this value"
    );
}

/// Both ends of the accepted range are accepted as the numbers they spell: `1` is a
/// deployment that wants the old fixed count, and 64 is the ceiling, accepted rather than
/// refused, so the ceiling refuses a typo (`800`) and not a deployment.
#[test]
fn workers_one_and_the_ceiling_are_accepted() {
    assert_eq!(
        compile_workers(Some("1")),
        Ok(1),
        "one worker is a legal deployment"
    );
    assert_eq!(
        compile_workers(Some("64")),
        Ok(64),
        "the ceiling is inside the range"
    );
}

/// Every value outside 1 to 64 is refused, and every refusal names `BB_AUTH_WEB_WORKERS`.
/// Fatal and not the gate's silent `unwrap_or`: a fallback turns `BB_AUTH_WEB_WORKERS=800`
/// into 8 with nothing anywhere saying so, which is the operator's intent lost without a
/// trace, and every other value this binary reads from its env is already fatal on a bad
/// one. Empty is refused rather than defaulted, because an empty assignment is somebody
/// meaning to say something (`BB_AUTH_WEB_ACCOUNT_PATH` reads it the same way), and `0` is
/// refused rather than raised to one, because a service that binds its port and never
/// answers is the worst of both. A refusal is **returned**, never a panic: a panic in a
/// startup parser is a `Restart=on-failure` boot loop, and this loop is what shows each of
/// these values comes back as an `Err` rather than taking the process down.
#[test]
fn workers_every_value_outside_one_to_sixty_four_is_refused_naming_the_variable() {
    for raw in ["0", "65", "-1", "", " 8", "8x", "eight"] {
        let e = compile_workers(Some(raw)).unwrap_err();
        assert!(
            e.contains("BB_AUTH_WEB_WORKERS"),
            "the refusal of {raw:?} must name the variable, since that is the only thing \
                 an operator can go and edit: {e}"
        );
    }
}

/// The startup rule for `BB_AUTH_WEB_DELETE_INTAKE` (docs/ARCHITECTURE.md §13.29 W2): the
/// intake's **origin**, `http`, a loopback IP literal, a port, and nothing else. Loopback
/// only, and the reason is the request, not the port: it carries an identity in clear to a
/// service whose one check is that header, so to any other host it is an identity sent
/// unencrypted to something that deletes accounts on it. Unset is the feature off
/// (`Ok(None)`), which is how `BB_AUTH_WEB_LOGOUT_URL` unset already behaves, and the
/// accepted value is kept as written, because the caller appends the intake's two
/// hard-coded paths to it and a re-serialized origin is a second answer to what the
/// operator typed.
///
/// Red until the coder adds `fn compile_delete_intake(raw: &str) -> Result<Option<String>,
/// String>` and the three fields §13.29 W10 7a names (`Config::{delete_intake,
/// delete_secret, intake_timeout}`).
#[test]
fn delete_intake_accepts_a_loopback_http_origin() {
    // The address the intake listens on today (§13.29 W1, rpi-01).
    assert_eq!(
        compile_delete_intake("http://127.0.0.1:8480"),
        Ok(Some("http://127.0.0.1:8480".to_string())),
        "the answer is the origin as written, so the caller appends its own paths to it \
             rather than to a re-serialized origin"
    );
    // All of 127.0.0.0/8 is loopback, and so is the IPv6 literal.
    for ok in [
        "http://127.0.0.42:1",
        "http://127.255.255.254:65535",
        "http://[::1]:8480",
    ] {
        assert_eq!(
            compile_delete_intake(ok),
            Ok(Some(ok.to_string())),
            "{ok} is a loopback origin"
        );
    }
    // Unset is the feature off, not a refusal: a deployment that never wired the worker
    // starts, shows no menu row, and answers the delete page as the 404 every unknown path
    // gets.
    assert_eq!(
        compile_delete_intake(""),
        Ok(None),
        "an unset variable is a deployment, not a boot loop"
    );
}

/// Every spelling that is **not** a loopback `http` origin is a fatal startup naming
/// `BB_AUTH_WEB_DELETE_INTAKE` (§13.29 W2). Each case is its own reason: `https` (the
/// intake speaks plain HTTP, so an https origin names a host the operator did not name);
/// a **name** (a name resolves to whatever the resolver says, and "loopback" has to be a
/// fact about the bytes, not a guess the startup made for the operator); a non-loopback
/// address (the identity would leave the host); a path (the intake hard-codes its two
/// paths, so a base carrying one appends them somewhere else, and the design says "nothing
/// else"); a query and a fragment for the same reason; userinfo (an `@` is credentials in
/// an origin); and no port, because the intake is a port, not a name on the default one.
#[test]
fn delete_intake_refuses_a_non_loopback_host_a_name_https_a_path_or_userinfo() {
    for raw in [
        "https://127.0.0.1:8480",
        "ftp://127.0.0.1:8480",
        "//127.0.0.1:8480",
        "127.0.0.1:8480",
        "http://localhost:8480",
        "http://intake.internal:8480",
        "http://127.0.0.1.evil.example:8480",
        "http://10.0.0.5:8480",
        "http://127.0.0.1:8480/account/whoami",
        "http://127.0.0.1:8480?q=1",
        "http://127.0.0.1:8480#x",
        "http://user@127.0.0.1:8480",
        "http://127.0.0.1",
        "not a url",
    ] {
        let e = compile_delete_intake(raw).expect_err("not a loopback origin");
        assert!(
            e.contains("BB_AUTH_WEB_DELETE_INTAKE"),
            "the refusal of {raw:?} must name the variable, since that is the only thing \
                 an operator can go and edit: {e}"
        );
    }
}

/// `BB_AUTH_WEB_DELETE_SECRET` is **optional** (§13.29 W2 as amended on 2026-11-26, the
/// user's answer to question 3): unset is allowed, the GUI starts, and the startup banner
/// says once in the journal that the intake trusts any local caller until a secret is set
/// on both sides. This test is the 7a half of its name: a deployment with no secret is
/// accepted (`Ok(None)`), and the fixture's `Config` holds `None` for both new fields, so
/// every test in this module is a deployment that could start with the feature off. The
/// "sends no secret header" half is 7c's
/// `each_request_carries_one_address_and_the_secret_never_the_joined_header`: 7a makes no
/// call to the intake at all, so there is no header on the wire to look for yet.
///
/// The bound on one intake call is asserted here because 7a is the slice that adds it:
/// §13.29 W2 says 5 s, the same wall `cognito_timeout` carries, and the tests shorten it
/// the same way.
#[test]
fn delete_intake_without_a_secret_starts_and_sends_no_secret_header() {
    assert_eq!(
        compile_delete_secret(""),
        Ok(None),
        "unset is the feature off, not a fatal startup: bb-auth ships its half once and \
             the owner starts enforcing the header when they choose, with no release here"
    );
    let cfg = cfg_for("delete-secret-unset", ADMIN_BASE);
    assert_eq!(
        cfg.delete_secret, None,
        "a Config with no delete secret is the fixture's shape, so the startup default is \
             off and not a guess"
    );
    assert_eq!(
        cfg.delete_intake, None,
        "and no intake either: the row, the page and the call all follow that one field"
    );
    assert_eq!(
        cfg.intake_timeout,
        std::time::Duration::from_secs(5),
        "the production bound is §13.29 W2's 5 s, and only the tests shorten it"
    );
}

/// A **malformed** delete secret is fatal (§13.29 W2): optional means "unset is allowed",
/// it never means "a broken value is ignored". The rules are `compile_proxy_secret`'s,
/// because the same value has to reach the owner's unit file and this env file with
/// nothing to quote: 32 characters of `[A-Za-z0-9_-]` at least. Every refusal names
/// `BB_AUTH_WEB_DELETE_SECRET` and none echoes the value, for the proxy secret's reason:
/// a startup message goes to the journal, and a secret printed once at boot is a secret
/// for as long as the journal is kept.
#[test]
fn a_malformed_delete_secret_is_fatal_and_names_the_variable() {
    let refused = |raw: &str| {
        let e = compile_delete_secret(raw).expect_err("a malformed secret is fatal");
        assert!(
            e.contains("BB_AUTH_WEB_DELETE_SECRET"),
            "the refusal must name the variable, since that is the only thing an operator \
                 can go and edit: {e}"
        );
        e
    };

    // One character short of the floor.
    let short = "a".repeat(31);
    let e = refused(&short);
    assert!(
        !e.contains(&short),
        "the message must not echo the value: {e}"
    );

    // Long enough, and one character outside the charset.
    let spaced = format!("{} x", "a".repeat(30));
    assert_eq!(spaced.chars().count(), 32);
    let e = refused(&spaced);
    assert!(
        !e.contains(&spaced),
        "the message must not echo the value: {e}"
    );

    // A value that meets the rule is accepted unchanged, and wrapped in `Some`: the field
    // is an `Option`, and the difference between "no secret" and "this secret" is the
    // difference between the banner's sentence and silence.
    let ok = format!("{}-_ab", "a".repeat(28));
    assert_eq!(ok.chars().count(), 32);
    assert_eq!(compile_delete_secret(&ok), Ok(Some(ok)));
    assert_eq!(
        compile_delete_secret(TEST_SECRET),
        Ok(Some(TEST_SECRET.to_string())),
        "the fixture's secret passes the rule, so 7c's request record is a deployment \
             that could start"
    );
}

// --- routing ------------------------------------------------------------

#[test]
fn route_without_a_base_path() {
    assert_eq!(route("/", ""), Some(Route::Dashboard));
    assert_eq!(route("", ""), Some(Route::Dashboard));
    assert_eq!(route("/users", ""), Some(Route::Users));
    assert_eq!(route("/users/", ""), Some(Route::Users));
    // §13.36 §1: the group list is a page of its own now, so `/groups` stops landing on the
    // users page. Read through `path()` in `route_maps_the_three_sub_pages` rather than
    // named here: while the variant does not exist, naming it is a compile error for the
    // whole target, which is a red that says nothing about the route.
    assert_ne!(
        route("/groups", ""),
        Some(Route::Users),
        "the group list is a page of its own now, not the users page wearing its URL"
    );
    assert_eq!(route("/apps", ""), Some(Route::Apps));
    assert_eq!(route("/denied", ""), Some(Route::Denied));
    // The access check is a section of the two pages that hold half of its question, and
    // no longer a page: it has no route to bookmark, and asking for its old one 404s
    // rather than landing anywhere that answers a different question.
    assert_eq!(route("/can", ""), None);
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
