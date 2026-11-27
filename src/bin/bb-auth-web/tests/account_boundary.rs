use super::*;

// ---------------------------------------------------------------------
// The boundary the move has to create (plan step 3c, docs/ARCHITECTURE.md §13.2).
//
// `/account/` is the one page of this program a person who is not an administrator reaches,
// and it is the only one: the console's routes stay behind `web.admins`, and the self-service
// page sits in front of them at a prefix of its own. These tests are the seam, so they are
// all about status codes and none about the page's contents, which the tests above pin.
//
// The shape they pin is §13.2's: the prefix test runs **before** the allowlist, so a path
// outside the prefix is a `403` for a non-administrator and never a `404` that tells them
// which paths exist, while a path inside it is answered identically to every caller.
// ---------------------------------------------------------------------

/// One of every route this GUI answers, with whether reaching it writes. Written out
/// variant by variant because `Route` carries names a derived list would have to invent;
/// `a_self_service_caller_is_refused_every_admin_route` keeps the list honest by matching
/// every variant of the enum, so a route added tomorrow fails that test until it is here.
fn account_every_route() -> Vec<(Route, bool)> {
    let bob = ACCOUNT_BOB.to_string();
    let mpa = || "mpa".to_string();
    let admin = || "admin".to_string();
    let laptop = || "laptop".to_string();
    vec![
        (Route::Dashboard, false),
        (Route::Apps, false),
        (Route::App(mpa()), false),
        (Route::Denied, false),
        (Route::Users, false),
        (Route::Groups, false),
        (Route::User(bob.clone()), false),
        (Route::Audit, false),
        (Route::Config, false),
        (Route::AppAdd, true),
        (Route::AppEdit(mpa()), true),
        (Route::AppRm(mpa()), true),
        (Route::ScopeAdd(mpa()), true),
        (Route::ScopeEdit(mpa(), admin()), true),
        (Route::ScopeRm(mpa(), admin()), true),
        (Route::ScopeMove(mpa(), admin()), true),
        (Route::UserAdd, true),
        (Route::UserEdit(bob.clone()), true),
        (Route::UserRm(bob.clone()), true),
        (Route::EmailAdd(bob.clone()), true),
        (Route::EmailRm(bob.clone(), "bob@old.com".to_string()), true),
        (Route::KeyAdd(bob.clone()), true),
        (Route::KeyEdit(bob.clone(), laptop()), true),
        (Route::KeyRotate(bob.clone(), laptop()), true),
        (Route::KeyRm(bob.clone(), laptop()), true),
        (Route::GroupAdd, true),
        (Route::GroupEdit("admins".to_string()), true),
        (Route::GroupRm("admins".to_string()), true),
        (Route::DenyAdd, true),
        (Route::DenyRm("spammer@x.com".to_string()), true),
    ]
}

/// A roster user who is on no `web.admins` reaches `/account/`, with or without the trailing
/// slash. This is the whole point of the move: the self-service page exists so that a person
/// who cannot open the console can mint their own key and read their own profile, so a
/// caller the allowlist does not name has to be answered with the page and not with the
/// console's `403`. The bare `/account` is the same page: nginx answers it with a `301` from
/// `location = /account`, so the binary only sees it when an operator gated the bare path
/// instead, and §13.2 says it is the page then, exactly as `/admin` is the dashboard.
#[test]
fn a_roster_user_who_is_no_administrator_reaches_the_self_service_page() {
    let path = account_scratch_full("boundary-account-200");
    let port = account_port(&path);

    for url in [
        format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/"),
        format!("http://127.0.0.1:{port}{ACCOUNT_PATH}"),
    ] {
        let mut r = get_with_secret(&url)
            .header(IDENTITY_HEADER, "bob@x.com")
            .call()
            .expect("a response");
        assert_eq!(
            r.status(),
            200,
            "{url}: bob is on the roster, and the account prefix is not the admin surface"
        );
        let body = r.body_mut().read_to_string().unwrap();
        assert!(
            body.contains("bob@x.com"),
            "the page names its caller: {}",
            account_readable(&body)
        );
        // And it is not the console wearing a different hat: no tab, no section of the file.
        assert!(
            !body.contains("user_groups"),
            "the self-service page must not be the console's users page: {}",
            account_readable(&body)
        );
    }

    cleanup(&path);
}

/// Every other route of this program stays behind `web.admins` for that caller. The check
/// is walked across the whole `Route` enum rather than over a handful of paths, because the
/// danger of the move is the route nobody thought about: an `/account/` arm that answers
/// everything below it, or a console page that starts rendering for a caller the allowlist
/// does not name. A `POST` is included, with a `rev` read from the file so it is a request
/// that would genuinely write, and the file's bytes are the final word: a `403` that wrote
/// something is not a refusal.
#[test]
fn a_self_service_caller_is_refused_every_admin_route() {
    let path = account_scratch_full("boundary-admin-403");
    let port = account_port(&path);
    let before = read(&path);
    let rev = rev_of(&path);

    // The list is complete, and the exhaustive match is what says so: a `Route` variant
    // added tomorrow stops this test compiling until it is listed above.
    fn variant(at: &Route) -> usize {
        match at {
            Route::Dashboard => 0,
            Route::Apps => 1,
            Route::App(_) => 2,
            Route::Denied => 3,
            Route::Users => 4,
            Route::User(_) => 5,
            Route::Audit => 6,
            Route::Config => 7,
            Route::AppAdd => 8,
            Route::AppEdit(_) => 9,
            Route::AppRm(_) => 10,
            Route::ScopeAdd(_) => 11,
            Route::ScopeEdit(_, _) => 12,
            Route::ScopeRm(_, _) => 13,
            Route::ScopeMove(_, _) => 14,
            Route::UserAdd => 15,
            Route::UserEdit(_) => 16,
            Route::UserRm(_) => 17,
            Route::EmailAdd(_) => 18,
            Route::EmailRm(_, _) => 19,
            Route::KeyAdd(_) => 20,
            Route::KeyEdit(_, _) => 21,
            Route::KeyRotate(_, _) => 22,
            Route::KeyRm(_, _) => 23,
            Route::GroupAdd => 24,
            Route::GroupEdit(_) => 25,
            Route::GroupRm(_) => 26,
            Route::DenyAdd => 27,
            Route::DenyRm(_) => 28,
            Route::Groups => 29,
            Route::Group(_) => 30,
        }
    }
    let routes = account_every_route();
    let seen: std::collections::HashSet<usize> = routes.iter().map(|(r, _)| variant(r)).collect();
    let missing: Vec<usize> = (0..=29).filter(|i| !seen.contains(i)).collect();
    assert!(
        missing.is_empty(),
        "account_every_route must name every Route variant, and it is missing {missing:?}"
    );

    for (at, mutating) in routes {
        let url = format!("http://127.0.0.1:{port}{ADMIN_BASE}{}", at.path());

        let r = get_with_secret(&url)
            .header(IDENTITY_HEADER, "bob@x.com")
            .call()
            .expect("a GET response");
        assert_eq!(
            r.status(),
            403,
            "GET {} is the administrator's page, not a roster user's",
            at.path()
        );

        if !mutating {
            continue;
        }
        // A POST that carries everything a browser would send: the origin, the identity,
        // and the fingerprint of the file as it stands. Only the allowlist is missing.
        let r = post_with_secret(&url)
            .header(IDENTITY_HEADER, "bob@x.com")
            .header("Sec-Fetch-Site", "same-origin")
            .send_form([("rev", rev.as_str())])
            .expect("a POST response");
        assert_eq!(
            r.status(),
            403,
            "POST {} by a caller the allowlist does not name",
            at.path()
        );
    }

    assert_eq!(
        read(&path),
        before,
        "a refusal may not write: the access file is byte for byte what it was"
    );

    cleanup(&path);
}

/// A URL that is not the self-service page and not a console page is a `403` for this
/// caller, not a `404`. The `404` is the answer the program gives an **administrator**, and
/// handing it to a stranger makes the refusal a probe: which paths exist, and which do not,
/// is exactly the enumeration the estate refuses to offer a caller holding any account at
/// all. The refusal is the same page for both, so the status carries no information.
///
/// `/admin` is in the list because the dashboard is a route, and a route is not an open
/// door; `/admin/account` is in it because the prefix test is anchored at the **start** of
/// the path, and a prefix that matched anywhere in it would hand the page to a URL the
/// console owns.
#[test]
fn a_url_outside_the_self_service_page_is_a_403_for_a_non_administrator() {
    let path = account_scratch_full("boundary-nope-403");
    let port = account_port(&path);

    for url in [
        "/admin",
        "/admin/",
        "/admin/nope",
        "/admin/apps/mpa",
        "/admin/account",
        "/nope",
        "/",
    ] {
        let r = get_with_secret(format!("http://127.0.0.1:{port}{url}"))
            .header(IDENTITY_HEADER, "bob@x.com")
            .call()
            .expect("a response");
        assert_eq!(
            r.status(),
            403,
            "{url} must be refused, and a 404 there says the path does not exist"
        );
    }

    cleanup(&path);
}

/// Below `/account/` the opposite: a path that is nothing is a `404`, for the administrator
/// and for the roster user alike. The self-service page is one page, so there is nothing
/// under it to discover, and the two callers must get the identical answer, because a page
/// that answers a stranger `403` and an administrator `404` is a page describing its own
/// layout to whoever asks.
#[test]
fn a_path_under_the_self_service_page_that_is_nothing_is_a_404() {
    let path = account_scratch_full("boundary-account-nope-404");
    let port = account_port(&path);

    for who in ["bob@x.com", "admin@x.com"] {
        for url in [
            format!("{ACCOUNT_PATH}/nope"),
            format!("{ACCOUNT_PATH}/nope/deeper"),
        ] {
            let r = get_with_secret(format!("http://127.0.0.1:{port}{url}"))
                .header(IDENTITY_HEADER, who)
                .call()
                .expect("a response");
            assert_eq!(
                r.status(),
                404,
                "{who}: `{url}` is nothing, and the answer must not depend on who is asking"
            );
        }
    }

    cleanup(&path);
}

/// The proxy secret is route-global and it is not relaxed for the one page a
/// non-administrator reaches: a request that did not come through nginx is a `403` at
/// `/account/` exactly as it is at `/admin/`, because the identity header it carries is
/// worth nothing until nginx vouches for the request, and `/account/` reads that header as
/// its subject.
#[test]
fn the_self_service_page_still_needs_the_proxy_secret() {
    let path = account_scratch_full("boundary-account-secret");
    let port = account_port(&path);

    for url in [
        format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/"),
        format!("http://127.0.0.1:{port}{ADMIN_BASE}/"),
    ] {
        let mut r = client()
            .get(&url)
            .header(IDENTITY_HEADER, "bob@x.com")
            .call()
            .expect("a response");
        assert_eq!(r.status(), 403, "{url}: a forged identity and no secret");
        let body = r.body_mut().read_to_string().unwrap();
        assert!(
            !body.contains("bob@x.com"),
            "{url}: the refusal must not be the self-service page naming its caller: {}",
            account_readable(&body)
        );
    }

    cleanup(&path);
}

/// `/accounts` is not the page. The prefix test is a test at a **path boundary**, not
/// `starts_with`, and the difference is a deployment that has an application under
/// `/accounts` being served this page by a prefix meant to stop at `/account`. For the
/// non-administrator it is the ordinary refusal; for an administrator it is the ordinary
/// `404`, because it is not a console route either. The startup rule refuses the same
/// overlap in the other direction, and says so in `compile_account_path`.
#[test]
fn a_neighbour_of_the_account_prefix_is_not_the_page() {
    let path = account_scratch_full("boundary-accounts");
    let port = account_port(&path);

    let r = get_with_secret(format!("http://127.0.0.1:{port}/accounts"))
        .header(IDENTITY_HEADER, "bob@x.com")
        .call()
        .expect("a response");
    assert_eq!(
        r.status(),
        403,
        "`/accounts` is not the page, so a caller the allowlist does not name is refused it"
    );

    let r = get_with_secret(format!("http://127.0.0.1:{port}/accounts"))
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(
        r.status(),
        404,
        "`/accounts` is no console route either, and an administrator is the one caller \
             who is told that"
    );

    cleanup(&path);
}

/// `BB_AUTH_WEB_ACCOUNT_PATH` is checked against `BB_AUTH_WEB_BASE_PATH` at startup, by the
/// rule `base_covers` applies to an application's area: neither prefix may contain the other
/// **at a path boundary**, in either direction, because nginx locations nest the same way
/// and a `location /admin/` would otherwise own the page. An empty admin base covers every
/// path, so it is refused too, which is the breaking change for a GUI mounted at the root
/// that plan step 3c says goes in the CHANGELOG.
///
/// The name `compile_account_path` is the tester's, taken from the design's own suggestion
/// (docs/ARCHITECTURE.md §13.2); the coder keeps whatever the code lands on.
#[test]
fn the_account_prefix_is_validated_against_the_admin_base_at_startup() {
    // Accepted: the default, a trailing slash normalised away, a deeper admin base, and the
    // neighbour that only looks nested (`/accounts` beside `/account` shares no boundary).
    for (account, base, want) in [
        ("/account", "/admin", "/account"),
        ("/account/", "/admin", "/account"),
        ("/account", "/admin/x", "/account"),
        ("/accounts", "/account", "/accounts"),
    ] {
        assert_eq!(
            compile_account_path(account, base).as_deref(),
            Ok(want),
            "`{account}` beside base `{base}` is a legal pair"
        );
    }

    // Refused, and every refusal names the variable, because the operator reading a failed
    // start is the only person who can edit the env file, and a message that names the
    // value is a message about a string they already have.
    for (account, base, why) in [
        (
            "",
            "/admin",
            "an empty prefix is the whole host, and swallows the console",
        ),
        (
            "/admin",
            "/admin",
            "equal to the admin base: one path, two answers",
        ),
        (
            "/admin/account",
            "/admin",
            "inside the admin base: nginx's location owns the page",
        ),
        (
            "/admin",
            "/admin/x",
            "containing the admin base: this prefix would own that console",
        ),
        ("/account", "", "an empty admin base covers every path"),
        (
            "/account",
            "/",
            "a base of `/` is the same root, normalised",
        ),
    ] {
        let e = compile_account_path(account, base)
            .err()
            .unwrap_or_else(|| panic!("`{account}` beside base `{base}` must be refused: {why}"));
        assert!(
            e.contains("BB_AUTH_WEB_ACCOUNT_PATH"),
            "the refusal must name the variable to fix: `{account}` / `{base}` said {e}"
        );
    }
}
