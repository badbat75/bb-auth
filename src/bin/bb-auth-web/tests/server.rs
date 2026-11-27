use super::*;

// --- the server ---------------------------------------------------------

/// Which pages wear the deployment's look, and which cannot.
///
/// The refusals are pages of the same installation as every other, so an administrator's
/// colleague who is not on `web.admins` must not be told so in a palette nobody
/// recognises. The two that render *before* the settings are read are the exception, and
/// not a lapse: the file that would describe another look is the file that is missing or
/// broken, so the built-in one is the only honest answer they have.
#[test]
fn a_refusal_wears_the_deployment_look_once_the_settings_can_be_read() {
    let path = scratch("look-403", SAMPLE);
    // A settings file that names an administrator AND a stylesheet, which is what a
    // deployment that has configured its look looks like.
    std::fs::write(
        settings_path(&path),
        r#"{ "version": 3, "gate": { "client_id": "email-client" },
                 "web": { "admins": ["admin@x.com"] },
                 "ui": { "stylesheet_url": "https://assets.example.com/tokens.css" } }"#,
    )
    .unwrap();
    let served = cfg_for(&path, "");
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &served);
        }
    });
    let at = |p: &str| format!("http://127.0.0.1:{port}{p}");
    const LINK: &str = r#"<link rel="stylesheet" href="https://assets.example.com/tokens.css">"#;

    // Authenticated, not an administrator: the settings were read to find that out, so
    // the page they are refused with is the one this deployment asked for.
    let mut r = get_with_secret(at("/"))
        .header(IDENTITY_HEADER, "someone@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 403);
    let csp = r
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let body = r.body_mut().read_to_string().unwrap();
    assert!(
        body.contains(LINK),
        "the 403 must carry the operator's stylesheet"
    );
    assert!(
        csp.contains("https://assets.example.com"),
        "and the policy must admit it: {csp}"
    );

    // The administrator's own page, for contrast: same look, which is the point.
    let mut r = get_with_secret(at("/"))
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 200);
    assert!(r.body_mut().read_to_string().unwrap().contains(LINK));

    // And the one that cannot: no identity header at all is answered above the settings
    // read, so it wears the built-in look and links nothing.
    let mut r = get_with_secret(at("/")).call().expect("a response");
    assert_eq!(r.status(), 401);
    assert!(
        !r.body_mut().read_to_string().unwrap().contains("<link"),
        "a page rendered before the settings are read may link nothing"
    );

    // Nor can the page that exists BECAUSE the settings are unreadable.
    std::fs::write(settings_path(&path), "{ not json").unwrap();
    let mut r = get_with_secret(at("/"))
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 500);
    assert!(!r.body_mut().read_to_string().unwrap().contains("<link"));
    cleanup(&path);
}

#[test]
fn serving_enforces_the_identity_header_and_the_admin_allowlist() {
    let path = scratch("serve", SAMPLE);
    let cfg = cfg_for(&path, "");
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &cfg);
        }
    });
    let at = |p: &str| format!("http://127.0.0.1:{port}{p}");

    // No header at all: a broken deployment, not an anonymous visitor.
    let mut r = get_with_secret(at("/")).call().expect("a response");
    assert_eq!(r.status(), 401);
    assert!(r
        .body_mut()
        .read_to_string()
        .unwrap()
        .contains("auth_request"));

    // Authenticated, but not on the allowlist.
    let mut r = get_with_secret(at("/"))
        .header(IDENTITY_HEADER, "someone@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 403);
    assert!(r
        .body_mut()
        .read_to_string()
        .unwrap()
        .contains("someone@x.com"));

    // An administrator gets the dashboard, in the configured language.
    let mut r = get_with_secret(at("/"))
        .header(IDENTITY_HEADER, "Admin@X.com") // normalised, so capitalisation is fine
        .call()
        .expect("a response");
    assert_eq!(r.status(), 200);
    let body = r.body_mut().read_to_string().unwrap();
    assert!(
        body.contains("user_groups") && body.contains("Warnings"),
        "{body}"
    );
    // And an unknown path is a 404, not a fall-through to the dashboard.
    let r = get_with_secret(at("/nope"))
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 404);
    let _ = std::fs::remove_file(&path);
}

/// The gate puts **every** email of a roster row into one `X-Auth-Email`, joined by a
/// single space (`identity_headers` in `bb-auth`: `who.emails.join(" ")`), so an
/// administrator with a second address arrives as `admin@x.com other@x.com`. Comparing
/// that whole string against `web.admins` locks out the one person who can edit
/// `web.admins`, and the only way back in is a hand edit over SSH, so the header has to
/// be read as the list of identities it is.
#[test]
fn serving_admits_an_administrator_whose_row_carries_several_emails() {
    let path = scratch("serve-multi-email", SAMPLE);
    let cfg = cfg_for(&path, "");
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &cfg);
        }
    });
    let at = |p: &str| format!("http://127.0.0.1:{port}{p}");

    // The administrator's address first, and second: the gate's join follows the roster's
    // order, which is nobody's contract, so a match that depended on the position of one
    // address was never a match.
    for header in ["Admin@X.com other@x.com", "other@x.com admin@x.com"] {
        let mut r = get_with_secret(at("/"))
            .header(IDENTITY_HEADER, header)
            .call()
            .expect("a response");
        assert_eq!(r.status(), 200, "{header} names an administrator");
        let body = r.body_mut().read_to_string().unwrap();
        assert!(
            body.contains("user_groups") && body.contains("Warnings"),
            "{header} must land on the dashboard a single-email admin sees: {body}"
        );
    }

    // Several addresses and not one of them an administrator: still the 403, and it
    // still names the caller, because an operator debugging a lockout has to be able to
    // see what nginx actually sent.
    let mut r = get_with_secret(at("/"))
        .header(IDENTITY_HEADER, "someone@x.com nobody@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 403);
    let body = r.body_mut().read_to_string().unwrap();
    assert!(
        body.contains("someone@x.com"),
        "the refusal must name the caller: {body}"
    );

    // A header that says nothing is a broken deployment and not a stranger, so it is
    // answered by the page that explains nginx, not by a 403 naming an empty identity.
    let mut r = get_with_secret(at("/"))
        .header(IDENTITY_HEADER, "   ")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 401);
    assert!(r
        .body_mut()
        .read_to_string()
        .unwrap()
        .contains("auth_request"));

    cleanup(&path);
}

/// A request that reaches this port without the secret nginx sets did not come through the
/// proxy (docs/ARCHITECTURE.md §13.3), so the `X-Auth-Email` it carries is worth nothing:
/// any local process can write that header. The check sits above the identity header and
/// above the settings read, so an administrator's name buys a `403` here, not the dashboard.
#[test]
fn a_request_with_no_proxy_secret_is_refused_before_the_identity_is_read() {
    let path = scratch("secret-absent", SAMPLE);
    let port = serve(&path, "");
    let mut r = client()
        .get(format!("http://127.0.0.1:{port}/"))
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 403, "a forged identity and no secret");
    let body = r.body_mut().read_to_string().unwrap();
    assert!(
        !body.contains("Dashboard"),
        "the refusal must not be the admin dashboard: {body}"
    );
    cleanup(&path);
}

/// The right length and the right charset are not the right value. What is sent here is the
/// fixture's secret with its last character changed, so a comparison that stops at the
/// first difference and one that reads the whole string give the same answer.
#[test]
fn a_request_with_the_wrong_proxy_secret_is_refused() {
    let path = scratch("secret-wrong", SAMPLE);
    let port = serve(&path, "");
    let wrong = format!("{}z", &TEST_SECRET[..TEST_SECRET.len() - 1]);
    let mut r = client()
        .get(format!("http://127.0.0.1:{port}/"))
        .header(SECRET_HEADER, wrong)
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 403, "a secret this deployment did not set");
    let body = r.body_mut().read_to_string().unwrap();
    assert!(
        !body.contains("Dashboard"),
        "the refusal must not be the admin dashboard: {body}"
    );
    cleanup(&path);
}

/// The proxy's own request, and nothing else about it moves: the secret is one header
/// nginx adds, so an administrator who arrives through nginx still sees the dashboard.
#[test]
fn a_request_with_the_right_proxy_secret_is_served() {
    let path = scratch("secret-right", SAMPLE);
    let port = serve(&path, "");
    let mut r = get_with_secret(format!("http://127.0.0.1:{port}/"))
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 200, "the secret the proxy sends");
    let body = r.body_mut().read_to_string().unwrap();
    assert!(body.contains("Dashboard"), "the dashboard: {body}");
    cleanup(&path);
}

/// A mutation is the case this exists to close, and it is refused by the same check as a
/// read, so a `POST` that is otherwise perfect (same-origin, an administrator's identity,
/// a current `rev`) still writes nothing without the secret.
#[test]
fn a_post_with_no_proxy_secret_is_refused_and_writes_nothing() {
    let path = scratch("secret-post", SAMPLE);
    let port = serve(&path, "/admin");
    let url = format!("http://127.0.0.1:{port}/admin/users/bob%40x.com/rm");
    let before = read(&path);
    let rev = rev_of(&path);
    let r = client()
        .post(&url)
        .header(IDENTITY_HEADER, "admin@x.com")
        .header("Sec-Fetch-Site", "same-origin")
        .send_form([("rev", rev.as_str())])
        .expect("a response");
    assert_eq!(r.status(), 403, "a mutation with no secret");
    assert_eq!(read(&path), before, "the access file untouched");
    cleanup(&path);
}

/// The secret is a gate in front of the existing checks, not a replacement for them: once it
/// is satisfied, a request that names nobody is still the `401` that explains nginx, which is
/// the answer an operator needs when the proxy is wired but the identity is not.
#[test]
fn the_right_proxy_secret_still_leaves_a_missing_identity_a_401() {
    let path = scratch("secret-no-identity", SAMPLE);
    let port = serve(&path, "");
    let mut r = get_with_secret(format!("http://127.0.0.1:{port}/"))
        .call()
        .expect("a response");
    assert_eq!(
        r.status(),
        401,
        "the secret passes, the identity is missing"
    );
    assert!(r
        .body_mut()
        .read_to_string()
        .unwrap()
        .contains("auth_request"));
    cleanup(&path);
}

/// The secret is a secret, so it is in no response: not in the page that refuses a request
/// that did not carry it (echoing the header a client guessed would confirm the guess), and
/// not in the page served to an administrator (a value in a document is a value in every
/// browser extension, cache and proxy log between here and the operator).
#[test]
fn the_proxy_secret_appears_in_no_response() {
    let path = scratch("secret-unrendered", SAMPLE);
    let port = serve(&path, "");
    let at = |p: &str| format!("http://127.0.0.1:{port}{p}");

    let r = client()
        .get(at("/"))
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 403, "the refusal this test is about");
    let refused = everything_in(r);
    assert!(
        !refused.contains(TEST_SECRET),
        "no header and no body of the 403 may carry the secret: {refused}"
    );

    let r = get_with_secret(at("/"))
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 200, "the page an administrator sees");
    let served = everything_in(r);
    assert!(
        !served.contains(TEST_SECRET),
        "no header and no body of the 200 may carry the secret: {}",
        &served[..served.len().min(400)]
    );
    cleanup(&path);
}

/// The whole `POST` contract over real HTTP, under a base path: a confirmation page that
/// changes nothing, the same-origin check, the `rev`, the `303`, and the replay that
/// the `rev` turns into a `409`.
#[test]
fn serving_a_post_checks_the_origin_the_rev_and_then_redirects() {
    let path = scratch("serve-post", SAMPLE);
    let cfg = cfg_for(&path, "/admin");
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &cfg);
        }
    });
    let url = format!("http://127.0.0.1:{port}/admin/users/bob%40x.com/rm");
    let post = || post_with_secret(&url).header(IDENTITY_HEADER, "admin@x.com");

    // The confirmation page is a GET, and a GET changes nothing.
    let before = read(&path);
    let mut r = get_with_secret(&url)
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 200);
    let page = r.body_mut().read_to_string().unwrap();
    assert!(
        page.contains("denied is for"),
        "the consequence is spelled out"
    );
    assert_eq!(read(&path), before, "a GET never mutates");
    let rev = rev_in(&page);
    assert_eq!(rev, rev_of(&path));

    // The proxy secret, the identity header and the allowlist guard a `POST` exactly as
    // they guard a GET: they are above the router, so no method reaches a mutation without
    // them.
    let r = post_with_secret(&url)
        .header("Sec-Fetch-Site", "same-origin")
        .send_form([("rev", rev.as_str())])
        .expect("a response");
    assert_eq!(r.status(), 401, "no identity header");
    let mut r = post_with_secret(&url)
        .header(IDENTITY_HEADER, "someone@x.com")
        .header("Sec-Fetch-Site", "same-origin")
        .send_form([("rev", rev.as_str())])
        .expect("a response");
    assert_eq!(r.status(), 403, "a non-admin POST");
    assert!(r
        .body_mut()
        .read_to_string()
        .unwrap()
        .contains("someone@x.com"));
    assert_eq!(read(&path), before, "neither may have written anything");

    // No Sec-Fetch-Site and no Origin: not a browser posting a form.
    let mut r = post()
        .send_form([("rev", rev.as_str())])
        .expect("a response");
    assert_eq!(r.status(), 403);
    assert!(r
        .body_mut()
        .read_to_string()
        .unwrap()
        .contains("same-origin"));
    assert_eq!(read(&path), before);

    // Cross-site is a refusal too, whatever the Origin claims.
    let r = post()
        .header("Sec-Fetch-Site", "cross-site")
        .header("Origin", format!("http://127.0.0.1:{port}"))
        .send_form([("rev", rev.as_str())])
        .expect("a response");
    assert_eq!(r.status(), 403);
    assert_eq!(read(&path), before);

    // Same-origin, current rev: it happens, and answers a 303 under the base path.
    let resp = post()
        .header("Sec-Fetch-Site", "same-origin")
        .send_form([("rev", rev.as_str())])
        .expect("a response");
    assert_eq!(resp.status(), 303);
    assert_eq!(
        resp.headers().get("location").map(|v| v.to_str().unwrap()),
        Some("/admin/users?msg=user-removed")
    );
    let after = read(&path);
    assert!(!after.contains("Bob@X.com"), "bob is gone: {after}");

    // The browser still holds the old rev — a resubmission cannot repeat the deed.
    let mut r = post()
        .header("Sec-Fetch-Site", "same-origin")
        .send_form([("rev", rev.as_str())])
        .expect("a response");
    assert_eq!(r.status(), 409);
    assert!(r
        .body_mut()
        .read_to_string()
        .unwrap()
        .contains("The file changed"));
    assert_eq!(read(&path), after);

    // And the redirect target renders the banner it was sent with.
    let mut r = get_with_secret(format!(
        "http://127.0.0.1:{port}/admin/users?msg=user-removed"
    ))
    .header(IDENTITY_HEADER, "admin@x.com")
    .call()
    .expect("a response");
    assert_eq!(r.status(), 200);
    let landed = r.body_mut().read_to_string().unwrap();
    assert!(landed.contains("user removed"), "{landed}");
    cleanup(&path);
}
