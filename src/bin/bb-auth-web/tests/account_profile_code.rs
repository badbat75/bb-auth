use super::*;

// ---------------------------------------------------------------------
// Slice 5c (§13.22, §13.23): the code step. The English texts of the keys 5c adds are
// written as literals here, because the `K` variants do not exist yet and this module may
// not add them; once they do, a rename to the keys is mechanical.
//
// Assumed field names of the code form's hidden inputs (§13.22 names the data, not the
// names): `Session`, `username` (the challenge's USERNAME), `email`, and one input per
// changed claim under the claim's own name, an emptied one posted with an empty value.
// The code input is `code`. Assumed update shape: ONE `UpdateUserAttributes` carries every
// changed name, a removal as `{"Name": n, "Value": ""}` (§13.22: "a blank value deletes the
// attribute"), which is what keeps a mixed edit at two calls.
// ---------------------------------------------------------------------

fn error_reply(status: u16, name: &str) -> Reply {
    reply(
        status,
        &serde_json::json!({ "__type": name, "message": "text that must never be shown" })
            .to_string(),
    )
}

fn set_field(f: &mut Vec<(String, String)>, key: &str, value: &str) {
    match f.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value.to_string(),
        None => f.push((key.to_string(), value.to_string())),
    }
}

/// The code page names what it will send: only the changed claims and the `Session`. No
/// address and no username ride in the form (§13.25 step 3): the username comes from the
/// header of the request that posts it.
#[test]
fn the_code_page_carries_what_the_code_step_needs() {
    let f = flow("c5-hidden");
    let g = start_bob(&f);
    let form = form_posting_to(&g.body, "/account/profile/code");
    let mut hidden = hidden_fields(&form);
    hidden.sort();
    let want = vec![
        ("Session".to_string(), FAKE_SESSION.to_string()),
        ("given_name".to_string(), "Robert".to_string()),
    ];
    assert_eq!(hidden, want, "{form}");
    cleanup(&f.path);
}

/// A right code: one `RespondToAuthChallenge` with the session and the username the
/// challenge named, then one `UpdateUserAttributes` with the access token and only the
/// changed attribute; the saved page names it in words and says when it shows.
#[test]
fn a_right_code_updates_exactly_the_changed_attributes() {
    let f = flow("c5-right");
    let g = start_bob(&f);
    let g = post_code(&f, "bob@x.com", &code_fields(&g, "123456"));
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    assert_eq!(
        f.fake.actions(),
        [
            "InitiateAuth",
            "RespondToAuthChallenge",
            "UpdateUserAttributes"
        ]
    );
    let calls = f.fake.calls();
    assert_eq!(
        calls[1].target,
        format!("{CALL_PREFIX}RespondToAuthChallenge")
    );
    assert_eq!(calls[1].content_type, "application/x-amz-json-1.1");
    assert_eq!(calls[1].body["ChallengeName"], "EMAIL_OTP");
    assert_eq!(calls[1].body["ClientId"], "email-client");
    assert_eq!(calls[1].body["Session"], FAKE_SESSION);
    assert_eq!(
        calls[1].body["ChallengeResponses"],
        serde_json::json!({ "USERNAME": FAKE_USERNAME, "EMAIL_OTP_CODE": "123456" })
    );
    assert_eq!(
        calls[2].target,
        format!("{CALL_PREFIX}UpdateUserAttributes")
    );
    assert_eq!(calls[2].content_type, "application/x-amz-json-1.1");
    assert_eq!(calls[2].body["AccessToken"], FAKE_ACCESS);
    assert_eq!(
        calls[2].body["UserAttributes"],
        serde_json::json!([{ "Name": "given_name", "Value": "Robert" }]),
        "exactly the changed attribute, nothing else"
    );
    assert_eq!(
        account_heading(&g.body, "h1"),
        "Profile saved",
        "{}",
        account_readable(&g.body)
    );
    let lede = lede_of(&g);
    assert!(lede.contains("Given name"), "the change in words: {lede}");
    assert!(!lede.contains("Family name"), "{lede}");
    assert!(
        lede.contains("Your applications, and this page, show it from your next sign-in."),
        "the panel shows old values until then, and says so: {lede}"
    );
    assert!(g.body.contains("href=\"/account/\""), "a way back");
    assert!(!g.body.contains(FAKE_SESSION), "the Session ends here");
    cleanup(&f.path);
}

/// A pasted `123 456` is accepted: the server strips the space (§13.23 §3).
#[test]
fn a_code_with_spaces_is_accepted() {
    let f = flow("c5-spaces");
    let g = start_bob(&f);
    let g = post_code(&f, "bob@x.com", &code_fields(&g, " 123 456 "));
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    assert_eq!(
        f.fake.calls()[1].body["ChallengeResponses"]["EMAIL_OTP_CODE"],
        "123456"
    );
    cleanup(&f.path);
}

/// A stranger (no roster row) completes the edit on their own Cognito user (user decision),
/// and the bind is the username, not the address: the token the pool returns names the
/// header's user, and the address it carries is not compared at all.
#[test]
fn a_stranger_completes_the_edit_on_their_own_user() {
    let sam = "cog-sam-0002";
    let f = flow_with(
        "c5-stranger",
        signed_in(&token_from("Sam@Elsewhere.COM", sam)),
        ok_empty(),
    );
    let g = start_as(
        &f,
        "sam@elsewhere.com",
        &profile_with(profile_same(), "given_name", "Samuel"),
    );
    let g = post_code_with(
        &f,
        "sam@elsewhere.com",
        &code_fields(&g, "123456"),
        &[(NATIVE_USERNAME_HEADER, sam)],
    );
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    assert_eq!(f.fake.actions().len(), 3);
    assert_eq!(
        f.fake.calls()[1].body["ChallengeResponses"]["USERNAME"],
        sam,
        "the code step answers for the header's user"
    );
    cleanup(&f.path);
}

/// An emptied field is sent as a blank value in the one update, beside a changed one: two
/// calls in the code request, never three.
#[test]
fn an_emptied_field_deletes_the_attribute() {
    let f = flow("c5-delete");
    let g = start_as(
        &f,
        "bob@x.com",
        &profile_with(
            profile_with(profile_same(), "family_name", ""),
            "given_name",
            "Robert",
        ),
    );
    let g = post_code(&f, "bob@x.com", &code_fields(&g, "123456"));
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    assert_eq!(
        f.fake.actions(),
        [
            "InitiateAuth",
            "RespondToAuthChallenge",
            "UpdateUserAttributes"
        ],
        "one update carries the change and the removal"
    );
    let mut attrs: Vec<(String, String)> = f.fake.calls()[2].body["UserAttributes"]
        .as_array()
        .expect("UserAttributes")
        .iter()
        .map(|a| {
            (
                a["Name"].as_str().unwrap().to_string(),
                a["Value"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    attrs.sort();
    assert_eq!(
        attrs,
        [
            ("family_name".to_string(), String::new()),
            ("given_name".to_string(), "Robert".to_string())
        ]
    );
    assert!(lede_of(&g).contains("Family name"), "{}", lede_of(&g));
    cleanup(&f.path);
}

/// A wrong code shows the code page again with the field marked, changes nothing, and
/// reuses the answer's new `Session` when it carried one, the old one otherwise.
#[test]
fn a_wrong_code_changes_nothing() {
    for (name, body, session) in [
        (
            "c5-wrong-same",
            serde_json::json!({ "__type": "CodeMismatchException", "message": "m" }),
            FAKE_SESSION,
        ),
        (
            "c5-wrong-new",
            serde_json::json!({ "__type": "CodeMismatchException", "message": "m",
                    "Session": "NEWSESSION0123456789abcdefghijklmnop" }),
            "NEWSESSION0123456789abcdefghijklmnop",
        ),
    ] {
        let f = flow_with(name, reply(400, &body.to_string()), ok_empty());
        let g = start_bob(&f);
        let g = post_code(&f, "bob@x.com", &code_fields(&g, "000000"));
        assert_eq!(g.status, 400, "{name}: {}", account_readable(&g.body));
        assert_eq!(
            f.fake.actions(),
            ["InitiateAuth", "RespondToAuthChallenge"],
            "{name}: nothing is updated"
        );
        let wrong = "That code is not right. Use the code in the latest email, and type it again.";
        let err = element_containing(&g.body, "id=\"err\"", "</div>");
        assert!(visible_text(&err).contains(wrong), "{name}: {err}");
        let at = |needle: &str| g.body.find(needle).unwrap_or(usize::MAX);
        assert!(
            at("class=\"card\"") < at("id=\"err\"")
                && at("id=\"err\"") < at(t(Lang::En, K::AccountProfileChanges)),
            "{name}: the refusal is inside the card, above the change list"
        );
        let input = input_named(&g.body, "code");
        assert_ne!(
            attr(&input, "value").unwrap_or_default(),
            "000000",
            "{name}: the field is emptied"
        );
        assert_eq!(
            attr(&input, "aria-invalid").as_deref(),
            Some("true"),
            "{name}"
        );
        assert_eq!(attr(&input, "aria-describedby").as_deref(), Some("err"));
        assert!(
            !input.contains("autofocus"),
            "{name}: focus stays on the summary"
        );
        assert!(
            visible_text(&element_containing(&g.body, "changes", "</ul>")).contains("Robert"),
            "{name}: the change list is still there"
        );
        let again = hidden_fields(&form_posting_to(&g.body, "/account/profile/code"));
        assert!(
            again.contains(&("Session".to_string(), session.to_string())),
            "{name}: {again:?}"
        );
        assert!(
            again.iter().all(|(k, _)| k != "username" && k != "email"),
            "{name}: no username and no address ride in the form: {again:?}"
        );
        cleanup(&f.path);
    }
}

/// An expired code, and a session Cognito no longer knows, both ask to start again.
#[test]
fn an_expired_code_starts_again() {
    for (name, kind) in [
        ("c5-expired", "ExpiredCodeException"),
        ("c5-expired-session", "NotAuthorizedException"),
    ] {
        let f = flow_with(name, error_reply(400, kind), ok_empty());
        let g = start_bob(&f);
        let g = post_code(&f, "bob@x.com", &code_fields(&g, "123456"));
        assert_eq!(g.status, 400, "{kind}: {}", account_readable(&g.body));
        assert_eq!(
            account_heading(&g.body, "h1"),
            "Your profile was not changed"
        );
        assert!(
            lede_of(&g).starts_with("The code has expired."),
            "{kind}: {}",
            lede_of(&g)
        );
        assert_eq!(f.fake.actions().len(), 2, "{kind}: no update");
        let resend = hidden_fields(&form_posting_to(&g.body, "/account/profile"));
        assert!(resend.contains(&("given_name".to_string(), "Robert".to_string())));
        assert!(resend.iter().all(|(k, _)| k != "Session"), "{resend:?}");
        assert!(!g.body.contains("text that must never be shown"));
        cleanup(&f.path);
    }
}

/// An `IdToken` that does not name the session's own Cognito user is never used: `403`, the
/// sentence, and the fake never sees an update. Both shapes of it: a token for another user,
/// and a token that names no user at all, since a bind that cannot be satisfied is a bind
/// that failed (§13.25 step 3).
#[test]
fn a_token_that_does_not_name_this_user_is_never_used() {
    let other = "0f8fad5b-d9cb-469f-a165-70867728950e";
    for (name, id) in [
        ("other-username", token_from("bob@x.com", other)),
        ("no-username-claim", token_from("bob@x.com", "")),
    ] {
        let f = flow_with(&format!("c5-{name}"), signed_in(&id), ok_empty());
        let g = start_bob(&f);
        let g = post_code(&f, "bob@x.com", &code_fields(&g, "123456"));
        assert_eq!(g.status, 403, "{name}: {}", account_readable(&g.body));
        assert_eq!(
            f.fake.actions(),
            ["InitiateAuth", "RespondToAuthChallenge"],
            "{name}: the access token is dropped unused"
        );
        assert!(lede_of(&g).contains(NOT_YOURS), "{name}: {}", lede_of(&g));
        assert!(
            !g.body.contains(other),
            "{name}: the other user is not named"
        );
        cleanup(&f.path);
    }
}

/// One case each: audience, issuer, `token_use`, expired, unverified, no email verified
/// claim, a token that is not a token, and no `IdToken` at all.
#[test]
fn a_token_of_the_wrong_audience_issuer_or_use_is_never_used() {
    let iss = PROFILE_POOL;
    let good = |aud: &str, iss: &str, tu: &str, exp: i64, v: serde_json::Value| {
        signed_in(&id_token("bob@x.com", aud, iss, tu, exp, v, FAKE_USERNAME))
    };
    let t = serde_json::json!(true);
    let cases: Vec<(&str, Reply)> = vec![
        ("audience", good("other-client", iss, "id", 3600, t.clone())),
        (
            "issuer",
            good(
                "email-client",
                "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_OTHER",
                "id",
                3600,
                t.clone(),
            ),
        ),
        ("use", good("email-client", iss, "access", 3600, t.clone())),
        ("expired", good("email-client", iss, "id", -3600, t.clone())),
        (
            "unverified",
            good("email-client", iss, "id", 3600, serde_json::json!(false)),
        ),
        (
            "garbage",
            reply(
                200,
                &serde_json::json!({ "AuthenticationResult": {
                        "AccessToken": FAKE_ACCESS, "IdToken": "not-a-token" } })
                .to_string(),
            ),
        ),
        (
            "no id token",
            reply(
                200,
                &serde_json::json!({ "AuthenticationResult": {
                        "AccessToken": FAKE_ACCESS } })
                .to_string(),
            ),
        ),
    ];
    for (i, (what, rtac)) in cases.into_iter().enumerate() {
        let f = flow_with(&format!("c5-badtoken-{i}"), rtac, ok_empty());
        let g = start_bob(&f);
        let g = post_code(&f, "bob@x.com", &code_fields(&g, "123456"));
        assert_eq!(g.status, 403, "{what}: {}", account_readable(&g.body));
        assert_eq!(
            f.fake.actions(),
            ["InitiateAuth", "RespondToAuthChallenge"],
            "{what}: the access token is dropped unused"
        );
        cleanup(&f.path);
    }
}

/// Every field the code step carries back is checked again, against the live files, before
/// any call: the status, and the fake saw only the start. The username is not one of them:
/// it is the header of this request, so a form posted by a second person binds against
/// *their* user and the write fails closed.
#[test]
fn the_code_step_rechecks_everything() {
    let f = flow("c5-recheck");
    let one_call = |what: &str, g: &AccountGot, status: u16| {
        assert_eq!(g.status, status, "{what}: {}", account_readable(&g.body));
        assert_eq!(
            f.fake.actions(),
            ["InitiateAuth"],
            "{what}: the code step called nothing"
        );
    };
    let fresh = || {
        let g = start_bob(&f);
        let n = f.fake.actions().len();
        // Forget the start between cases so each asserts on the code step alone.
        f.fake.calls.lock().unwrap().clear();
        f.fake.calls.lock().unwrap().push(CognitoCall {
            target: format!("{CALL_PREFIX}InitiateAuth"),
            content_type: String::new(),
            body: serde_json::Value::Null,
        });
        assert!(n >= 1);
        g
    };

    // The request arrives with no `X-Auth-Native-Username`: nothing to answer with.
    let g = fresh();
    one_call(
        "no native header",
        &profile_post_headers(
            &f.code_url(),
            Some("bob@x.com"),
            &code_fields(&g, "123456")
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>(),
            "same-origin",
            true,
            &profile_headers_no_native(),
            &[],
        ),
        400,
    );
    // Somebody else posting bob's form: the code step answers for *their* user, the fake
    // returns bob's token, and the bind refuses. One call, and no write.
    let g = fresh();
    let carol = "1a79a4d6-60df-4c01-9f83-7f8f8b8c1a2b";
    let g = post_code_with(
        &f,
        "carol@x.com",
        &code_fields(&g, "123456"),
        &[(NATIVE_USERNAME_HEADER, carol)],
    );
    assert_eq!(g.status, 403, "{}", account_readable(&g.body));
    assert_eq!(
        f.fake.actions(),
        ["InitiateAuth", "RespondToAuthChallenge"],
        "the stolen form is answered, and the bind is what stops it"
    );
    assert_eq!(
        f.fake.calls()[1].body["ChallengeResponses"]["USERNAME"],
        carol,
        "the code step answers the caller's own user, not the form's"
    );
    // A claim that is not editable, and a value too long.
    for (what, key, value) in [
        ("not editable", "phone_number", "+391"),
        ("overlong", "given_name", &"x".repeat(2049)),
        ("control", "given_name", "Ro\u{7}bert"),
    ] {
        let g = fresh();
        let mut fields = code_fields(&g, "123456");
        set_field(&mut fields, key, value);
        one_call(what, &post_code(&f, "bob@x.com", &fields), 400);
    }
    // A missing Session, and codes that cannot be a code.
    let g = fresh();
    let mut fields = code_fields(&g, "123456");
    fields.retain(|(k, _)| k != "Session");
    one_call("no session", &post_code(&f, "bob@x.com", &fields), 400);
    for code in ["", "   ", "12-34", "12345678901234567"] {
        let g = fresh();
        one_call(
            &format!("code {code:?}"),
            &post_code(&f, "bob@x.com", &code_fields(&g, code)),
            400,
        );
    }
    // The door, and the proxy secret.
    let g = fresh();
    let fields = code_fields(&g, "123456");
    let borrowed: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let cross = profile_post_as(
        &f.code_url(),
        Some("bob@x.com"),
        &borrowed,
        "cross-site",
        true,
        &[],
    );
    one_call("cross-site", &cross, 403);
    let secretless = profile_post_as(
        &f.code_url(),
        Some("bob@x.com"),
        &borrowed,
        "same-origin",
        false,
        &[],
    );
    one_call("no secret", &secretless, 403);

    // The claim is dropped from the settings between the two steps.
    let g = fresh();
    std::fs::write(
        settings_path(&f.path),
        profile_settings(
            "email-client",
            PROFILE_POOL,
            r#""family_name", "birthdate""#,
        ),
    )
    .unwrap();
    one_call(
        "claim dropped",
        &post_code(&f, "bob@x.com", &code_fields(&g, "123456")),
        400,
    );
    std::fs::write(settings_path(&f.path), profile_wired()).unwrap();

    // The caller is added to `denied` between the two steps.
    let g = fresh();
    std::fs::write(
        &f.path,
        ACCOUNT_ACCESS.replace(
            r#""denied": ["spammer@x.com"]"#,
            r#""denied": ["spammer@x.com", "bob@x.com"]"#,
        ),
    )
    .unwrap();
    one_call(
        "denied meanwhile",
        &post_code(&f, "bob@x.com", &code_fields(&g, "123456")),
        403,
    );
    cleanup(&f.path);
}

/// The update is refused: `502` or `400`, in words, and the pool's own message is never
/// shown.
#[test]
fn a_refused_update_says_so() {
    for (name, status, kind, sentence, code) in [
        (
            "c5-upd-na",
            400,
            "NotAuthorizedException",
            "The sign-in service refused the change.",
            502,
        ),
        (
            "c5-upd-ip",
            400,
            "InvalidParameterException",
            "The sign-in service did not accept one of the values.",
            400,
        ),
        (
            "c5-upd-other",
            400,
            "InternalErrorException",
            "The sign-in service refused the change.",
            502,
        ),
    ] {
        let f = flow_with(
            name,
            signed_in(&good_id_token("bob@x.com")),
            error_reply(status, kind),
        );
        let g = start_bob(&f);
        let g = post_code(&f, "bob@x.com", &code_fields(&g, "123456"));
        assert_eq!(g.status, code, "{kind}: {}", account_readable(&g.body));
        assert_eq!(
            account_heading(&g.body, "h1"),
            "Your profile was not changed"
        );
        assert!(lede_of(&g).starts_with(sentence), "{kind}: {}", lede_of(&g));
        assert!(!g.body.contains("text that must never be shown"));
        assert_eq!(f.fake.actions().len(), 3);
        cleanup(&f.path);
    }
}

/// Too many attempts at the code step is its own sentence.
#[test]
fn too_many_code_attempts_is_told() {
    let f = flow_with(
        "c5-toomany",
        error_reply(400, "TooManyRequestsException"),
        ok_empty(),
    );
    let g = start_bob(&f);
    let g = post_code(&f, "bob@x.com", &code_fields(&g, "123456"));
    assert_eq!(g.status, 502, "{}", account_readable(&g.body));
    assert!(
        lede_of(&g).starts_with("Too many attempts."),
        "{}",
        lede_of(&g)
    );
    cleanup(&f.path);
}

/// A timeout at `UpdateUserAttributes` may have been applied, so the page says so; a
/// timeout at `RespondToAuthChallenge` happened before any write and says nothing changed.
#[test]
fn a_timeout_at_the_update_does_not_claim_nothing_changed() {
    for (name, hold, unsure) in [
        ("c5-hold-update", "UpdateUserAttributes", true),
        ("c5-hold-respond", "RespondToAuthChallenge", false),
    ] {
        let fake = FakeCognito::answering(vec![
            ("InitiateAuth", challenge_for_username()),
            (
                "RespondToAuthChallenge",
                if hold == "RespondToAuthChallenge" {
                    reply(0, "")
                } else {
                    signed_in(&good_id_token("bob@x.com"))
                },
            ),
            (
                "UpdateUserAttributes",
                if hold == "UpdateUserAttributes" {
                    reply(0, "")
                } else {
                    ok_empty()
                },
            ),
        ]);
        let (path, base) =
            profile_boot(name, &profile_wired(), Some(fake.endpoint()), Some(300), 2);
        let f = Flow { fake, path, base };
        let g = start_bob(&f);
        let began = std::time::Instant::now();
        let g = post_code(&f, "bob@x.com", &code_fields(&g, "123456"));
        assert!(began.elapsed() < std::time::Duration::from_secs(3));
        assert_eq!(g.status, 504, "{hold}: {}", account_readable(&g.body));
        let h1 = account_heading(&g.body, "h1");
        if unsure {
            assert_eq!(h1, "Your profile may not have been saved");
            assert!(
                lede_of(&g).contains("may or may not have been made"),
                "{}",
                lede_of(&g)
            );
            assert!(!g.body.contains("Your profile was not changed"));
        } else {
            assert_eq!(h1, "Your profile was not changed");
            assert!(lede_of(&g).starts_with("The sign-in service did not answer within 5 seconds."));
            assert!(
                form_posting_to(&g.body, "/account/profile").contains("Send a new code"),
                "a new code is offered"
            );
        }
        cleanup(&f.path);
    }
}

/// No token, no refresh token and no `Session` in any body or header of any outcome of the
/// flow. (A log line cannot be read over this socket, §13.15's note: that half is made by
/// type, in the code, and is the untested half.)
#[test]
fn no_token_reaches_any_response() {
    let id = good_id_token("bob@x.com");
    let other = good_id_token("carol@x.com");
    let mut secrets = vec![
        FAKE_ACCESS.to_string(),
        FAKE_REFRESH.to_string(),
        id.clone(),
        other.clone(),
    ];
    let outcomes: Vec<(&str, Reply, Reply)> = vec![
        ("c5-leak-ok", signed_in(&id), ok_empty()),
        ("c5-leak-other", signed_in(&other), ok_empty()),
        (
            "c5-leak-refused",
            signed_in(&id),
            error_reply(400, "NotAuthorizedException"),
        ),
        (
            "c5-leak-wrong",
            error_reply(400, "CodeMismatchException"),
            ok_empty(),
        ),
    ];
    secrets.dedup();
    for (name, rtac, update) in outcomes {
        let f = flow_with(name, rtac, update);
        let started = start_bob(&f);
        let g = post_code(&f, "bob@x.com", &code_fields(&started, "123456"));
        for (what, r) in [("start", &started), ("code", &g)] {
            for s in &secrets {
                assert!(
                    !r.body.contains(s.as_str()),
                    "{name} {what}: a token is in the body"
                );
                for (k, v) in &r.headers {
                    assert!(!v.contains(s.as_str()), "{name} {what}: a token is in {k}");
                }
            }
        }
        // Past the code step the Session has no business on the page (a wrong code keeps
        // the form, and so keeps the Session, on purpose).
        if g.status != 400 {
            assert!(
                !g.body.contains(FAKE_SESSION),
                "{name}: the Session is on the outcome"
            );
        }
        cleanup(&f.path);
    }
}

/// The cap: the start makes one call, the code step at most two, in every outcome.
#[test]
fn at_most_two_cognito_calls_per_request() {
    let outcomes: Vec<(&str, Reply, Reply, usize)> = vec![
        (
            "c5-two-ok",
            signed_in(&good_id_token("bob@x.com")),
            ok_empty(),
            2,
        ),
        (
            "c5-two-wrong",
            error_reply(400, "CodeMismatchException"),
            ok_empty(),
            1,
        ),
        (
            "c5-two-other",
            signed_in(&token_from(
                "bob@x.com",
                "0f8fad5b-d9cb-469f-a165-70867728950e",
            )),
            ok_empty(),
            1,
        ),
        (
            "c5-two-refused",
            signed_in(&good_id_token("bob@x.com")),
            error_reply(400, "NotAuthorizedException"),
            2,
        ),
    ];
    for (name, rtac, update, want) in outcomes {
        let f = flow_with(name, rtac, update);
        let g = start_as(
            &f,
            "bob@x.com",
            &profile_with(
                profile_with(profile_same(), "family_name", ""),
                "given_name",
                "Robert",
            ),
        );
        assert_eq!(f.fake.calls().len(), 1, "{name}: the start is one call");
        post_code(&f, "bob@x.com", &code_fields(&g, "123456"));
        assert_eq!(
            f.fake.calls().len() - 1,
            want,
            "{name}: {:?}",
            f.fake.actions()
        );
        cleanup(&f.path);
    }
}

// ---------------------------------------------------------------------
// The e2e switch (docs/ARCHITECTURE.md §13.24): the one way a process is pointed at a
// Cognito that is not the pool. Default builds must never read the variable.
// ---------------------------------------------------------------------

#[cfg(feature = "e2e-fake-cognito")]
const E2E_ENDPOINT_VAR: &str = "BB_AUTH_WEB_E2E_COGNITO_ENDPOINT";

#[cfg(not(feature = "e2e-fake-cognito"))]
#[test]
fn the_e2e_endpoint_is_not_read_without_the_feature() {
    // The lookup answers a perfectly good loopback URL for every name: a default build must
    // still say nothing, because a binary that honours it is a binary a host can be pointed
    // at a Cognito of somebody's choosing with.
    let answers = |_: &str| Some("http://127.0.0.1:9/".to_string());
    assert_eq!(e2e_cognito_endpoint(answers), Ok(None));
    let hostile = |_: &str| Some("https://evil.example.org/".to_string());
    assert_eq!(e2e_cognito_endpoint(hostile), Ok(None));
}

#[cfg(feature = "e2e-fake-cognito")]
#[test]
fn the_e2e_endpoint_reads_only_its_own_variable() {
    let seen = std::cell::RefCell::new(Vec::new());
    let lookup = |k: &str| {
        seen.borrow_mut().push(k.to_string());
        None
    };
    assert_eq!(e2e_cognito_endpoint(lookup), Ok(None));
    assert_eq!(seen.into_inner(), vec![E2E_ENDPOINT_VAR.to_string()]);
}

#[cfg(feature = "e2e-fake-cognito")]
#[test]
fn a_loopback_e2e_endpoint_is_read() {
    let lookup = |k: &str| (k == E2E_ENDPOINT_VAR).then(|| "http://127.0.0.1:43210/".to_string());
    assert_eq!(
        e2e_cognito_endpoint(lookup),
        Ok(Some("http://127.0.0.1:43210/".to_string()))
    );
}

#[cfg(feature = "e2e-fake-cognito")]
#[test]
fn a_non_loopback_or_lookalike_e2e_endpoint_is_a_fatal_naming_the_variable() {
    for bad in [
        "https://cognito-idp.eu-central-1.amazonaws.com/",
        "http://10.0.0.1:80/",
        "http://127.0.0.1.evil.com:9/",
        "http://127.0.0.1.evil.com/",
        "http://localhost:9/",
        "https://127.0.0.1:9/",
    ] {
        let lookup = |k: &str| (k == E2E_ENDPOINT_VAR).then(|| bad.to_string());
        let got = e2e_cognito_endpoint(lookup);
        match got {
            Err(m) => assert!(m.contains(E2E_ENDPOINT_VAR), "{bad:?}: {m}"),
            other => panic!("{bad:?} must be refused, got {other:?}"),
        }
    }
}
