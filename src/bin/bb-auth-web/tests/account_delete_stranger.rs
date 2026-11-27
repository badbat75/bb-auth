use super::*;

// ---------------------------------------------------------------------
// The stranger's deletion, slice 7c (docs/ARCHITECTURE.md §13.29 W10, §13.30 §4 §5):
// `account_delete_post`'s steps 1 to 4 and 6, `intake_whoami`, `intake_delete`, and the
// done page. W3's step 5, the roster write, is 7d's, so every caller here is one the page
// writes nothing for, and the access file's bytes are the proof of that.
//
// Everything talks to `FakeIntake`, a socket on this host. No test reaches the real worker,
// and none starts `FakeCognito`: this path touches Cognito not at all (§13.29 W11).
// ---------------------------------------------------------------------

// The words §13.30 §5 pins for this slice, verbatim, in both languages. They are consts
// and not `K` keys because the keys do not exist yet: a test that wrote `t(lang,
// K::AccountDeleteQueued)` would not compile, and the red this slice wants is the missing
// behaviour, not a missing symbol.
const DELETE_TYPED_EN: &str = "The email address typed is not one of this account's, so \
                                   nothing was deleted. Type it as it is shown above.";
const DELETE_TYPED_IT: &str = "L'indirizzo email scritto non è uno di quelli di questo \
                                   account, quindi non è stato eliminato nulla. Scrivilo come \
                                   appare qui sopra.";
const DELETE_TOO_MANY_IT: &str = "Questo account ha più indirizzi email di quanti questa \
                                      pagina ne possa eliminare in una volta, quindi non può \
                                      essere eliminato qui, e non è stato eliminato nulla. Se \
                                      vuoi eliminarlo, chiedi a un amministratore.";
const DELETE_NO_CHECK_IT: &str = "Il servizio di eliminazione non ha risposto come previsto, \
                                      quindi non è stato eliminato nulla e puoi ancora accedere. \
                                      Riprova tra un minuto; se non funziona di nuovo, avvisa un \
                                      amministratore.";
// The done page's last sentence, for the page that **stays**: the one a deployment gets when
// the operator named no logout URL, so there is nowhere to send the browser (§13.32 §1). Its
// words are §13.33 §3's, which replaced "close your browser to end it": the cookie carries
// `Max-Age` (`build_cookie`), so it outlives a closed browser and the old sentence was false.
const DELETE_RETRY_IT: &str = "Riprova";

/// §13.29 W3 steps 4 and 6: a caller with no roster row is asked, then posted, and the
/// access file's bytes are the proof that this slice writes nothing. The order is the
/// contract: `whoami` for every address **before** the first `POST`, so a protected address
/// never has a record queued behind it.
#[test]
fn a_strangers_deletion_posts_each_address_and_leaves_the_file_unchanged() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_full("delete-7c-walk");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    let settings = read(&settings_path(&path));

    let rev = rev_of(&path);
    let fields = [
        ("rev", rev.as_str()),
        ("uuid", ""),
        ("confirm_email", "stranger@elsewhere.com"),
    ];
    let g = account_post(&url, Some("stranger@elsewhere.com"), &fields);
    assert_eq!(
        g.status,
        303,
        "a stranger's walk, queued, is answered by the logout redirect (§13.32 §1): {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.header("Location"),
        Some(DELETE_LOGOUT_LOCATION),
        "and the walk is the same walk: the redirect replaces the page, not the work"
    );
    assert_eq!(
        intake.at(),
        vec![WHOAMI_PATH.to_string(), DELETE_PATH.to_string()],
        "asked first, then posted, once each"
    );
    assert_eq!(
        read(&path),
        before,
        "no row, so nothing to write: the file's bytes are the file's"
    );
    assert_eq!(
        read(&settings_path(&path)),
        settings,
        "and the settings file beside it is untouched"
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W3 "Which addresses": `X-Auth-Email` is every address of the caller joined by a
/// space, and the intake reads the **whole** header as one address, so a joined header sent
/// as is queues an address no Cognito user has and says it was accepted. Each request
/// carries exactly one, as `X-Auth-Email` and as `confirm_email` (the intake's
/// `confirm_mismatch` check is the same rule from the other side); the secret is on every
/// one, and `X-Real-IP` is on none.
#[test]
fn each_request_carries_one_address_and_the_secret_never_the_joined_header() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_full("delete-7c-two");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");

    // Two addresses, and no roster row: the plural is the header's, and 7c writes nothing
    // for this caller, so the walk is the stranger's.
    let identity = "one@x.com two@x.com";
    let rev = rev_of(&path);
    let fields = [
        ("rev", rev.as_str()),
        ("uuid", ""),
        ("confirm_email", "one@x.com"),
    ];
    let g = account_post(&url, Some(identity), &fields);
    assert_eq!(
        g.status,
        303,
        "a two-address walk, queued, is answered by the logout redirect (§13.32 §1): {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.header("Location"),
        Some(DELETE_LOGOUT_LOCATION),
        "the caller's own addresses change nothing about the answer"
    );
    assert_eq!(
        intake.at(),
        vec![
            WHOAMI_PATH.to_string(),
            WHOAMI_PATH.to_string(),
            DELETE_PATH.to_string(),
            DELETE_PATH.to_string()
        ],
        "every address is asked before any is posted"
    );
    let calls = intake.calls();
    for c in &calls {
        assert!(
            matches!(c.email.as_deref(), Some("one@x.com") | Some("two@x.com")),
            "one address per request, never the joined header: {c:?}"
        );
        assert_eq!(
            c.secret.as_deref(),
            Some(TEST_SECRET),
            "the deployment set a secret, so every call carries it: {c:?}"
        );
        assert_eq!(c.real_ip, None, "no client address is invented: {c:?}");
    }
    for c in calls.iter().filter(|c| c.method == "POST") {
        assert_eq!(
            c.confirm_email.as_deref(),
            c.email.as_deref(),
            "the confirmation names this request's own address: {c:?}"
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.30 §2 §4: the typed address **is** the confirmation, so a typo is refused before
/// anything is sent, and the page is the same page with the typo kept in the field
/// (forgiving input, WCAG 3.3.1 and 3.3.3). An empty submission is the same refusal.
#[test]
fn a_typed_address_that_is_not_the_callers_sends_nothing() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_full("delete-7c-typo");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    let rev = rev_of(&path);

    for typed in ["someone@elsewhere.com", ""] {
        for lang in [Lang::En, Lang::It] {
            let at = format!("{} typed {typed:?}", lang.code());
            let fields = [
                ("rev", rev.as_str()),
                ("uuid", ""),
                ("confirm_email", typed),
            ];
            let g = account_post_lang(&url, "stranger@elsewhere.com", &fields, lang);
            assert_eq!(g.status, 400, "{at}: {}", account_readable(&g.body));
            assert_eq!(
                account_heading(&g.body, "h1"),
                m(lang, DELETE_TITLE_EN, DELETE_TITLE_IT),
                "{at}: the confirmation page again, not an outcome page"
            );
            let form = the_delete_form(&g.body, "", &at);
            let errs = elements(
                &form,
                &format!("<div class=\"err\" id=\"{ERR_ID}\">"),
                "</div>",
            );
            assert_eq!(
                errs.len(),
                1,
                "{at}: the refusal sits above the fields it is about: {form}"
            );
            assert_eq!(
                visible_text(&errs[0]),
                m(lang, DELETE_TYPED_EN, DELETE_TYPED_IT),
                "{at}: the words are a fact about the address, never about the person: {form}"
            );
            let i = input_named(&form, "confirm_email");
            assert_eq!(
                attr(&i, "value").as_deref(),
                Some(typed),
                "{at}: what was typed is kept, so a typo is seen and fixed rather than \
                     retyped: {i}"
            );
            assert!(
                attr(&i, "class").is_some_and(|c| c.split_whitespace().any(|w| w == "invalid")),
                "{at}: the field is marked in the class as well as the colour: {i}"
            );
            assert_eq!(
                attr(&i, "aria-invalid").as_deref(),
                Some("true"),
                "{at}: {i}"
            );
            assert_eq!(
                attr(&i, "aria-describedby").as_deref(),
                Some(ERR_ID),
                "{at}: the message is this field's description: {i}"
            );
            assert!(
                !i.contains("autofocus"),
                "{at}: Enter must not be one keystroke from a deletion: {i}"
            );
        }
    }
    assert!(
        intake.calls().is_empty(),
        "a refusal at the typed address sends nothing at all: {:?}",
        intake.calls()
    );
    assert_eq!(read(&path), before, "and it writes nothing");
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W5: the protected list is the intake's, and `whoami` is asked for every address
/// **before** anything is posted, so a protected caller leaves nothing anywhere. The page
/// says what cannot happen here, and never names a list, the address that matched, or the
/// intake's own word for it (§13.30 §7).
#[test]
fn a_protected_address_is_refused_before_anything_is_posted() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_protected()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_full("delete-7c-protected");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    let rev = rev_of(&path);
    let fields = [
        ("rev", rev.as_str()),
        ("uuid", ""),
        ("confirm_email", "stranger@elsewhere.com"),
    ];

    for lang in [Lang::En, Lang::It] {
        // The fake records every request it is sent, so each language is measured on what
        // that language added: the recording as it stood before this request is the baseline.
        let seen = intake.calls().len();
        let g = account_post_lang(&url, "stranger@elsewhere.com", &fields, lang);
        assert_eq!(
            g.status,
            403,
            "{}: a protected address is refused: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_NOT_DONE_EN, DELETE_NOT_DONE_IT),
            "{}: the heading states the result, in the reader's words",
            lang.code()
        );
        assert_eq!(
            the_page_lede(&g.body),
            m(lang, DELETE_PROTECTED_EN, DELETE_PROTECTED_IT),
            "{}: the lede",
            lang.code()
        );
        let pills = the_action_pills(&g.body);
        assert_eq!(
            pills.len(),
            1,
            "{}: back is the only action, there is nothing here to retry: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            visible_text(&pills[0]),
            back_words(lang),
            "{}: {}",
            lang.code(),
            pills[0]
        );
        assert_eq!(
            attr(open_tag(&pills[0]), "href").as_deref(),
            Some(ACCOUNT_PAGE),
            "{}: back goes to the account page: {}",
            lang.code(),
            pills[0]
        );
        let words = the_page_words(&g.body);
        assert!(
            !words.to_lowercase().contains("protected"),
            "{}: the intake's word is not the page's, and no list is named: {words}",
            lang.code()
        );
        assert!(
            !words.contains("stranger@elsewhere.com"),
            "{}: the address that matched is not named: {words}",
            lang.code()
        );
        // One `whoami` for this language's request, and no `POST`: the refusal happens
        // before anything is sent, so a protected caller leaves nothing anywhere.
        let asked = intake.at_since(seen);
        assert_eq!(
            asked,
            vec![WHOAMI_PATH.to_string()],
            "{}: asked, refused, posted nothing: {asked:?}",
            lang.code()
        );
    }
    assert_eq!(read(&path), before, "and wrote nothing");
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W3 step 4, §13.30 §4: an intake that does not answer, or answers in a way the
/// contract does not read, is "not accepted" and never a guess. Nothing has been touched, so
/// the page says so and offers Try again, and the caller is not left waiting on a socket
/// that will never answer: the client's timeout is the bound.
#[test]
fn whoami_with_no_answer_changes_nothing_within_the_bound() {
    // --- no answer at all: the fake takes the connection and says nothing --------------
    let silent = FakeIntake::silent();
    let path = account_scratch_full("delete-7c-silent");
    let port = account_port_intake_at(&path, &silent.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    let rev = rev_of(&path);
    let fields = [
        ("rev", rev.as_str()),
        ("uuid", ""),
        ("confirm_email", "stranger@elsewhere.com"),
    ];
    let started = std::time::Instant::now();
    let g = account_post(&url, Some("stranger@elsewhere.com"), &fields);
    let took = started.elapsed();
    assert_eq!(
        g.status,
        504,
        "an intake that never answers is a 504: {}",
        account_readable(&g.body)
    );
    // The pair `a_silent_cognito_answers_within_the_bound_and_frees_the_worker` spells:
    // it waited for the bound, and not past it. The bound is `TEST_INTAKE_TIMEOUT` (500 ms)
    // and the cap is 8 of them, so a caller still honouring the production 5 s would fail
    // this: the assertion is sensitive to the configured bound, not just to a hang.
    assert!(
        took >= std::time::Duration::from_millis(400),
        "it waited for the bound, it did not answer early: {took:?}"
    );
    assert!(
        took < 8 * TEST_INTAKE_TIMEOUT,
        "the bound is the client's timeout, not the socket's: {took:?}"
    );
    assert_eq!(
        account_heading(&g.body, "h1"),
        DELETE_NOT_DONE_EN,
        "the heading: {}",
        account_readable(&g.body)
    );
    assert_eq!(the_page_lede(&g.body), DELETE_NO_CHECK_EN, "the lede");
    let pills = the_action_pills(&g.body);
    let texts: Vec<String> = pills.iter().map(|p| visible_text(p)).collect();
    assert_eq!(
        texts,
        vec![DELETE_RETRY_EN.to_string(), back_words(Lang::En)],
        "try again, then back: {pills:?}"
    );
    assert!(
        pills
            .iter()
            .any(|p| attr(open_tag(p), "href").as_deref()
                == Some(&format!("{ACCOUNT_PATH}/delete")[..])),
        "Try again is the confirmation page, which after the write is the stranger's: \
             {pills:?}"
    );
    assert_eq!(
        read(&path),
        before,
        "nothing was changed while the intake was silent"
    );
    let _ = std::fs::remove_file(&path);

    // --- an answer the contract does not read: a 200 whose `email` is not the address sent
    let odd = FakeIntake::answering(vec![
        (
            WHOAMI_PATH,
            reply(
                200,
                r#"{"ok":true,"email":"other@x.com","protected":false}"#,
            ),
        ),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_full("delete-7c-odd");
    let port = account_port_intake_at(&path, &odd.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    let rev = rev_of(&path);
    let fields = [
        ("rev", rev.as_str()),
        ("uuid", ""),
        ("confirm_email", "stranger@elsewhere.com"),
    ];
    for lang in [Lang::En, Lang::It] {
        let g = account_post_lang(&url, "stranger@elsewhere.com", &fields, lang);
        assert_eq!(
            g.status,
            502,
            "{}: an answer that is not the one asked for is not accepted: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_NOT_DONE_EN, DELETE_NOT_DONE_IT),
            "{}: the heading: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            the_page_lede(&g.body),
            m(lang, DELETE_NO_CHECK_EN, DELETE_NO_CHECK_IT),
            "{}: the lede says nothing was deleted and that signing in still works",
            lang.code()
        );
        let pills = the_action_pills(&g.body);
        let texts: Vec<String> = pills.iter().map(|p| visible_text(p)).collect();
        assert_eq!(
            texts,
            vec![
                m(lang, DELETE_RETRY_EN, DELETE_RETRY_IT).to_string(),
                back_words(lang)
            ],
            "{}: try again, then back: {pills:?}",
            lang.code()
        );
        assert!(
            pills.iter().any(|p| attr(open_tag(p), "href").as_deref()
                == Some(&format!("{ACCOUNT_PATH}/delete")[..])),
            "{}: Try again goes back to the confirmation, which is still the person's: \
                 {pills:?}",
            lang.code()
        );
    }
    assert_eq!(
        odd.at(),
        vec![WHOAMI_PATH.to_string(); 2],
        "the unusable answer stops the walk before the first POST, every time: {:?}",
        odd.calls()
    );
    assert_eq!(read(&path), before, "and nothing was written");
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W1: ureq follows redirects by default (`max_redirects: 10` in its own defaults),
/// so an intake that answered `3xx` would be handed the identity header, by the client's own
/// code, to wherever it pointed. The client sets 0, and a redirect is "not accepted".
#[test]
fn a_redirect_from_the_intake_is_not_followed() {
    let (trap, seen) = intake_listener();
    let intake = FakeIntake::answering(vec![
        (
            WHOAMI_PATH,
            Reply {
                status: 302,
                body: String::new(),
                location: Some(format!("http://127.0.0.1:{trap}/carried")),
            },
        ),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_full("delete-7c-redirect");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    let rev = rev_of(&path);
    let fields = [
        ("rev", rev.as_str()),
        ("uuid", ""),
        ("confirm_email", "stranger@elsewhere.com"),
    ];
    let g = account_post(&url, Some("stranger@elsewhere.com"), &fields);
    assert_eq!(
        g.status,
        502,
        "a 3xx is not a 202, and is not a guess: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        account_heading(&g.body, "h1"),
        DELETE_NOT_DONE_EN,
        "the heading: {}",
        account_readable(&g.body)
    );
    assert_eq!(the_page_lede(&g.body), DELETE_NO_CHECK_EN, "the lede");
    assert_eq!(
        intake.at(),
        vec![WHOAMI_PATH.to_string()],
        "the walk stops at the redirect: {:?}",
        intake.calls()
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "the identity header went nowhere else: {seen:?}"
    );
    assert_eq!(read(&path), before, "and nothing was written");
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W3: the worker takes ten addresses per run and refuses the **whole** run above
/// that, so a caller with more is refused before anything is sent. Prevention before the
/// message (Nielsen 5): the `GET` offers no form (§13.30 §2), and this is the same refusal
/// on the way in, so a client that posts anyway is refused too.
#[test]
fn more_addresses_than_one_worker_run_takes_are_refused() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_full("delete-7c-many");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    let rev = rev_of(&path);

    let many: Vec<String> = (0..11).map(|i| format!("person{i}@x.com")).collect();
    let identity = many.join(" ");
    for lang in [Lang::En, Lang::It] {
        let fields = [
            ("rev", rev.as_str()),
            ("uuid", ""),
            ("confirm_email", many[0].as_str()),
        ];
        let g = account_post_lang(&url, &identity, &fields, lang);
        assert_eq!(
            g.status,
            400,
            "{}: eleven addresses are refused: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_NOT_DONE_EN, DELETE_NOT_DONE_IT),
            "{}: the heading states the result",
            lang.code()
        );
        assert_eq!(
            the_page_lede(&g.body),
            m(lang, DELETE_TOO_MANY_EN, DELETE_TOO_MANY_IT),
            "{}: the lede says why, and who to ask",
            lang.code()
        );
        let pills = the_action_pills(&g.body);
        assert_eq!(
            pills.len(),
            1,
            "{}: back is the only action: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            visible_text(&pills[0]),
            back_words(lang),
            "{}: {}",
            lang.code(),
            pills[0]
        );
        assert!(
            !the_main(&g.body).contains("<form"),
            "{}: a form whose every submission is refused is not offered: {}",
            lang.code(),
            account_readable(&g.body)
        );
    }
    assert!(
        intake.calls().is_empty(),
        "the count is checked before the first call: {:?}",
        intake.calls()
    );
    assert_eq!(read(&path), before, "and the refusal wrote nothing");
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W3 step 1: the door every `/account` `POST` goes through, unchanged by this
/// route. A form on another site pressing Delete is the same login CSRF the mint and the
/// revoke tests name, and a client that says nothing about where it came from is refused
/// with it.
#[test]
fn a_cross_site_delete_is_refused() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_full("delete-7c-csrf");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    let rev = rev_of(&path);
    let fields = [
        ("rev", rev.as_str()),
        ("uuid", ""),
        ("confirm_email", "stranger@elsewhere.com"),
    ];

    for site in ["cross-site", "none", ""] {
        let g = account_post_as(&url, Some("stranger@elsewhere.com"), &fields, site, true);
        assert_eq!(
            g.status,
            403,
            "a {site:?} delete is not this estate's form: {}",
            account_readable(&g.body)
        );
    }
    assert!(
        intake.calls().is_empty(),
        "the door closes before the intake is asked: {:?}",
        intake.calls()
    );
    assert_eq!(read(&path), before, "and the door's refusal wrote nothing");
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W3 step 2: the posted `uuid` is the live row's, both empty for a caller with no
/// row. A person who opened the page as a stranger and gained a row before pressing Delete
/// is the case that check exists for: the page they hold says the file names nobody, and
/// acting on that would delete a record they were never shown. `409`, the changed page, and
/// nothing posted.
#[test]
fn a_stranger_who_gained_a_row_between_steps_is_refused() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch("delete-7c-grew", ACCOUNT_SETTINGS);
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");

    let g = account_call(&url, Some("stranger@elsewhere.com"));
    assert_eq!(
        g.status,
        200,
        "the page opens as the stranger's: {}",
        account_readable(&g.body)
    );
    let form = the_delete_form(&g.body, "", "the stranger's page");
    let rev = hidden_value(&form, "rev").expect("the form carries the rev");

    // The row arrives, as an administrator's `bb-auth-adm user add` leaves it.
    let grew = read(&path).replace(
        "\"emails\": [\"carol@x.com\"] }",
        "\"emails\": [\"carol@x.com\"] }, { \"uuid\": \
             \"33333333-3333-4333-8333-333333333333\", \"emails\": [\"stranger@elsewhere.com\"] }",
    );
    assert_ne!(
        grew,
        read(&path),
        "the fixture has the row this test adds beside"
    );
    std::fs::write(&path, &grew).expect("add the row");

    for lang in [Lang::En, Lang::It] {
        // The page's own rev and the page's own empty uuid: the walk the person takes.
        let fields = [
            ("rev", rev.as_str()),
            ("uuid", ""),
            ("confirm_email", "stranger@elsewhere.com"),
        ];
        let g = account_post_lang(&url, "stranger@elsewhere.com", &fields, lang);
        assert_eq!(
            g.status,
            409,
            "{}: the page is stale: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_CHANGED_TITLE_EN, DELETE_CHANGED_TITLE_IT),
            "{}: the heading says the account changed, not that it was deleted",
            lang.code()
        );
        assert_eq!(
            the_page_lede(&g.body),
            m(lang, DELETE_CHANGED_EN, DELETE_CHANGED_IT),
            "{}: the lede",
            lang.code()
        );
        let pills = the_action_pills(&g.body);
        let texts: Vec<String> = pills.iter().map(|p| visible_text(p)).collect();
        assert_eq!(
            texts,
            vec![
                m(lang, DELETE_START_EN, DELETE_START_IT).to_string(),
                back_words(lang)
            ],
            "{}: start again, then back: {pills:?}",
            lang.code()
        );
        assert!(
            pills.iter().any(|p| attr(open_tag(p), "href").as_deref()
                == Some(&format!("{ACCOUNT_PATH}/delete")[..])),
            "{}: Start again re-renders the confirmation, which now shows the row: \
                 {pills:?}",
            lang.code()
        );
        assert!(
            !the_page_words(&g.body).contains(t(lang, K::ConflictBody)),
            "{}: the console's conflict sentence is not this page's: {}",
            lang.code(),
            the_page_words(&g.body)
        );
    }

    // The rev alone is not the check. A page rendered from the file **after** the row
    // landed, still carrying no uuid, is refused by the uuid.
    let rev_now = rev_of(&path);
    let fields = [
        ("rev", rev_now.as_str()),
        ("uuid", ""),
        ("confirm_email", "stranger@elsewhere.com"),
    ];
    let g = account_post(&url, Some("stranger@elsewhere.com"), &fields);
    assert_eq!(
        g.status,
        409,
        "a matching rev does not make an empty uuid current: {}",
        account_readable(&g.body)
    );

    assert!(
        intake.calls().is_empty(),
        "a 409 sends nothing: {:?}",
        intake.calls()
    );
    assert_eq!(read(&path), grew, "and the 409 wrote nothing");
    let _ = std::fs::remove_file(&path);
}
