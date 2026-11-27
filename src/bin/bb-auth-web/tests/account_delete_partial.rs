use super::*;

// ---------------------------------------------------------------------
// The partial outcomes, slice 7e (docs/ARCHITECTURE.md §13.29 W10, §13.30 §4 §5 §7):
// W3 step 7's two unhappy answers, for a caller whose row is already gone and for a
// stranger. A `POST` the intake refused (any status that is not a `202` with `"ok":true`)
// and a `POST` that never got an answer are the two ways a deletion stops half done, and
// for a roster user they stop it **after** the row went: the keys and the named access are
// gone and the sign-in accounts are not queued. So the page says which of the two happened,
// never "deleted", and offers the retry the person reaches as a stranger (the row is gone,
// so the confirmation page the retry renders is the stranger's variant).
//
// `whoami` unanswered is 7c's, a `503` from the intake is phrased as the service being
// unavailable, and the browser walk is 7f.
// ---------------------------------------------------------------------

// The four §13.30 §5 keys this slice needs that the table does not carry yet, verbatim, in
// both languages. Consts and not `t(lang, K::…)` for the reason 7c gives: the red this
// slice wants is the missing behaviour, not a missing symbol.
const DELETE_PARTIAL_TITLE_EN: &str = "Your account is only partly deleted";
const DELETE_PARTIAL_TITLE_IT: &str = "Il tuo account è stato eliminato solo in parte";
const DELETE_SOME_EN: &str = "The sign-in accounts of some of your addresses are queued for \
                                  deletion; the others may not be.";
const DELETE_SOME_IT: &str = "Gli account di accesso di alcuni dei tuoi indirizzi sono in \
                                  coda per l'eliminazione; gli altri potrebbero non esserlo.";
const DELETE_UNCONFIRMED_LEAD_EN: &str = "Addresses not confirmed as queued:";
const DELETE_UNCONFIRMED_LEAD_IT: &str = "Indirizzi di cui non è confermata la messa in coda:";
const DELETE_RETRY_ONE_EN: &str = "Trying again covers only the address you signed in with; \
                                       for the others, tell an administrator.";
const DELETE_RETRY_ONE_IT: &str = "Riprovare riguarda solo l'indirizzo con cui hai effettuato \
                                       l'accesso; per gli altri, avvisa un amministratore.";

/// The intake says nothing to the `POST`: the request is parked, so the caller waits out
/// `intake_timeout` on a live connection. `whoami` answers, so this is "the record did not
/// get through" and not "the service is not there": the page cannot tell whether the
/// record landed, which is the whole content of the unsure page.
fn delete_silent() -> Reply {
    reply(0, "")
}

/// One outcome page, read the way §13.30 §4 spells a row of its table: the status, the `h1`
/// that states the result, the lede's sentences **in order**, and exactly the actions that
/// row names. `pills` are the pill words in the order the page shows them, the arrow pill
/// included, because its text is not a key's text alone (see [`back_words`]).
///
/// The two pills that name a destination are checked against it, because §4 says "Try again
/// and Start again are `pill_link({account}/delete, …)`" and "Sign out is
/// `pill_link(account_logout_url, …)`": a pill with the right words and the wrong `href` is
/// a page that offers an action it does not perform.
///
/// The row that holds them is checked too ([`assert_action_row`]), because §4 says "one row
/// of pills" and says nothing about the tag: the spacing rule is the designer's, and every
/// row of this table is a row of one, two or zero pills, so the table is where both halves
/// of that rule get exercised.
fn assert_outcome(
    who: &str,
    g: &AccountGot,
    lang: Lang,
    status: u16,
    h1: &str,
    lede: &[&str],
    pills: &[&str],
) {
    let page = account_readable(&g.body);
    assert_eq!(g.status, status, "{who}: status: {page}");
    assert_eq!(
        account_heading(&g.body, "h1"),
        h1,
        "{who}: the heading states what happened: {page}"
    );
    assert_eq!(
        the_page_lede(&g.body),
        lede.join(" "),
        "{who}: the lede, in the order §4 writes it: {page}"
    );
    let got: Vec<String> = the_action_pills(&g.body)
        .iter()
        .map(|p| visible_text(p))
        .collect();
    let want: Vec<String> = pills.iter().map(|p| p.to_string()).collect();
    assert_eq!(got, want, "{who}: exactly the actions §4 names: {page}");
    let delete_url = format!("{ACCOUNT_PATH}/delete");
    for p in the_action_pills(&g.body) {
        let words = visible_text(&p);
        if words == t(lang, K::AccountDeleteRetry) || words == t(lang, K::AccountDeleteStartAgain) {
            assert_eq!(
                attr(open_tag(&p), "href").as_deref(),
                Some(delete_url.as_str()),
                "{who}: {words} renders the confirmation page: {p}"
            );
        }
        if words == t(lang, K::SignOut) {
            assert_eq!(
                attr(open_tag(&p), "href").as_deref(),
                Some("/auth/logout"),
                "{who}: the sign-out pill is the config's URL, `rd` dropped: {p}"
            );
        }
    }
    assert_action_row(who, &g.body, pills.len());
}

/// The two rows of §13.30 §4 that used to be pages, as §13.33 §3's table replaces them: a
/// completed deletion on a deployment with a logout URL answers a `303` to the gate's logout
/// and renders nothing, so there is no `h1`, no lede and no pill to read. The row of the
/// table that says "which page is this case" is therefore answered by the `Location:`, and
/// the words moved to the sign-in page's notice.
fn assert_done_redirect(who: &str, g: &AccountGot) {
    assert_eq!(
        g.status,
        303,
        "{who}: the row is a redirect, not a page: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.header("Location"),
        Some(DELETE_LOGOUT_LOCATION),
        "{who}: to the gate's logout, with the gate's sign-in page as the round trip"
    );
    assert!(
        g.body.is_empty(),
        "{who}: a redirect renders no page: {:?}",
        g.body
    );
}

/// §13.30 §7: one case per row of §4's table that ends on an outcome page, each asserting
/// the status, the `h1` key, the lede keys in order, and exactly the actions that row names.
/// The two rows §4 leaves blank are the door's and the typed address's, and they are 7c's
/// (`a_cross_site_delete_is_refused`, `a_typed_address_that_is_not_the_callers_sends_nothing`);
/// the write failure is 7d's `a_failed_write_posts_nothing`, which is `cfg(unix)` and owns a
/// read-only directory of its own.
///
/// Each case also asserts the **shape of the row** its actions sit in ([`assert_action_row`]),
/// because the table is where both halves of that rule land: the protected and too-many rows
/// are one pill and keep `p.primary`, while the changed, whoami, partial and
/// some rows are two and have to sit in `div.actions` to be two targets. The two completed
/// rows are here as [`assert_done_redirect`], a `303` with no page (§13.32 §1, §13.33 §3):
/// they are the table's rows, and a table that left them out would read as a case nobody
/// answered.
///
/// English only: the words of every new page are pinned in both languages by the tests below
/// and by 7c's and 7d's, and this table's subject is which page each case is.
#[test]
fn each_delete_outcome_states_its_result_in_the_h1() {
    let lang = Lang::En;
    let bob = "bob@x.com bob@old.com";
    let at = |port: u16| format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");

    // The page is not the current one: 409, "your account changed", Start again and back.
    {
        let intake = FakeIntake::answering(vec![
            (WHOAMI_PATH, whoami_ok()),
            (DELETE_PATH, delete_accepted()),
        ]);
        let path = account_scratch_roster("delete-7e-h1-changed");
        let port = account_port_intake_at(&path, &intake.endpoint());
        let stale = "0".repeat(64);
        let g = account_post_lang(
            &at(port),
            bob,
            &[
                ("rev", stale.as_str()),
                ("uuid", ACCOUNT_BOB),
                ("confirm_email", "bob@x.com"),
            ],
            lang,
        );
        assert_outcome(
            "the stale page",
            &g,
            lang,
            409,
            DELETE_CHANGED_TITLE_EN,
            &[DELETE_CHANGED_EN],
            &[DELETE_START_EN, back_words(lang).as_str()],
        );
        let _ = std::fs::remove_file(&path);
    }

    // More addresses than one run takes: 400, the too-many sentence, and one way back.
    {
        // Eleven addresses, one more than a run takes. An escaped string, not a raw one:
        // a raw string whose content ends in `]` carries no `"#` terminator, and the lexer
        // reads on to the next one in the file.
        let mut emails = String::from("\"emails\": [\"bob@x.com\"");
        let mut ids = String::from("bob@x.com");
        for n in 2..=DELETE_MAX_ADDRESSES + 1 {
            emails.push_str(&format!(", \"b{n}@x.com\""));
            ids.push_str(&format!(" b{n}@x.com"));
        }
        emails.push(']');
        let access =
            account_access_full().replace("\"emails\": [\"bob@x.com\", \"bob@old.com\"]", &emails);
        let intake = FakeIntake::answering(vec![
            (WHOAMI_PATH, whoami_ok()),
            (DELETE_PATH, delete_accepted()),
        ]);
        let path = account_scratch_access("delete-7e-h1-many", &access);
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
            &ids,
            &[
                ("rev", rev.as_str()),
                ("uuid", ACCOUNT_BOB),
                ("confirm_email", "bob@x.com"),
            ],
            lang,
        );
        assert_outcome(
            "eleven addresses",
            &g,
            lang,
            400,
            DELETE_NOT_DONE_EN,
            &[DELETE_TOO_MANY_EN],
            &[back_words(lang).as_str()],
        );
        assert!(
            intake.calls().is_empty(),
            "eleven addresses asks the intake nothing at all: {:?}",
            intake.at()
        );
        let _ = std::fs::remove_file(&path);
    }

    // An address on the intake's protected list: 403, the protected sentence, one way back.
    {
        let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_protected())]);
        let path = account_scratch_roster("delete-7e-h1-protected");
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
            bob,
            &[
                ("rev", rev.as_str()),
                ("uuid", ACCOUNT_BOB),
                ("confirm_email", "bob@x.com"),
            ],
            lang,
        );
        assert_outcome(
            "a protected address",
            &g,
            lang,
            403,
            DELETE_NOT_DONE_EN,
            &[DELETE_PROTECTED_EN],
            &[back_words(lang).as_str()],
        );
        let _ = std::fs::remove_file(&path);
    }

    // `whoami` unanswered (504) and unusable (502): the same page, "nothing was deleted".
    for (who, status, script) in [
        ("whoami never answers", 504u16, None),
        (
            "whoami answers for another address",
            502,
            Some(reply(
                200,
                r#"{"ok":true,"email":"someone-else@x.com","protected":false}"#,
            )),
        ),
    ] {
        let intake = FakeIntake::answering(vec![
            (WHOAMI_PATH, whoami_ok()),
            (DELETE_PATH, delete_accepted()),
        ]);
        if let Some(r) = script {
            intake.in_order(WHOAMI_PATH, vec![r]);
        } else {
            intake.in_order(WHOAMI_PATH, vec![delete_silent()]);
        }
        let path = account_scratch_roster(&format!("delete-7e-h1-whoami-{status}"));
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
            bob,
            &[
                ("rev", rev.as_str()),
                ("uuid", ACCOUNT_BOB),
                ("confirm_email", "bob@x.com"),
            ],
            lang,
        );
        assert_outcome(
            who,
            &g,
            lang,
            status,
            DELETE_NOT_DONE_EN,
            &[DELETE_NO_CHECK_EN],
            &[DELETE_RETRY_EN, back_words(lang).as_str()],
        );
        assert!(
            intake.at().iter().all(|c| c == WHOAMI_PATH),
            "{who}: a check that did not pass posts nothing: {:?}",
            intake.at()
        );
        let _ = std::fs::remove_file(&path);
    }

    // Every `POST` accepted: §13.32 §1 took these two rows off the table of pages. They
    // stay here so the table names every case, and are asserted as the redirect they are.
    {
        let intake = FakeIntake::answering(vec![
            (WHOAMI_PATH, whoami_ok()),
            (DELETE_PATH, delete_accepted()),
        ]);
        let path = account_scratch_roster("delete-7e-h1-done-roster");
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
            bob,
            &[
                ("rev", rev.as_str()),
                ("uuid", ACCOUNT_BOB),
                ("confirm_email", "bob@x.com"),
            ],
            lang,
        );
        assert_done_redirect("the roster's completed deletion", &g);
        let _ = std::fs::remove_file(&path);
    }
    {
        let intake = FakeIntake::answering(vec![
            (WHOAMI_PATH, whoami_ok()),
            (DELETE_PATH, delete_accepted()),
        ]);
        let path = account_scratch_full("delete-7e-h1-done-stranger");
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
            "stranger@elsewhere.com",
            &[
                ("rev", rev.as_str()),
                ("uuid", ""),
                ("confirm_email", "stranger@elsewhere.com"),
            ],
            lang,
        );
        assert_done_redirect("the stranger's completed deletion", &g);
        let _ = std::fs::remove_file(&path);
    }

    // The four partial rows. The roster's two carry `RetryOneAddress`, because the row had
    // two addresses and the retry reaches the one the person signed in with; the stranger's
    // two do not, because a stranger has exactly one address and the retry reaches it.
    {
        let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
        intake.in_order(DELETE_PATH, vec![delete_refused(503)]);
        let path = account_scratch_roster("delete-7e-h1-refused-roster");
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
            bob,
            &[
                ("rev", rev.as_str()),
                ("uuid", ACCOUNT_BOB),
                ("confirm_email", "bob@x.com"),
            ],
            lang,
        );
        assert_outcome(
            "the first POST refused, roster",
            &g,
            lang,
            502,
            DELETE_PARTIAL_TITLE_EN,
            &[
                DELETE_NOW_GONE_EN,
                t(lang, K::AccountDeleteNotQueued),
                DELETE_RETRY_ONE_EN,
            ],
            &[DELETE_RETRY_EN, t(lang, K::SignOut)],
        );
        let _ = std::fs::remove_file(&path);
    }
    {
        let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
        intake.in_order(DELETE_PATH, vec![delete_silent()]);
        let path = account_scratch_roster("delete-7e-h1-silent-roster");
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
            bob,
            &[
                ("rev", rev.as_str()),
                ("uuid", ACCOUNT_BOB),
                ("confirm_email", "bob@x.com"),
            ],
            lang,
        );
        assert_outcome(
            "the first POST unanswered, roster",
            &g,
            lang,
            504,
            t(lang, K::AccountDeleteUnsureTitle),
            &[
                DELETE_NOW_GONE_EN,
                t(lang, K::AccountDeleteMaybeQueued),
                DELETE_RETRY_ONE_EN,
            ],
            &[DELETE_RETRY_EN, t(lang, K::SignOut)],
        );
        let _ = std::fs::remove_file(&path);
    }
    {
        let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
        intake.in_order(DELETE_PATH, vec![delete_refused(503)]);
        let path = account_scratch_full("delete-7e-h1-refused-stranger");
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
            "stranger@elsewhere.com",
            &[
                ("rev", rev.as_str()),
                ("uuid", ""),
                ("confirm_email", "stranger@elsewhere.com"),
            ],
            lang,
        );
        assert_outcome(
            "the first POST refused, stranger",
            &g,
            lang,
            502,
            DELETE_NOT_DONE_EN,
            &[t(lang, K::AccountDeleteNotQueued)],
            &[DELETE_RETRY_EN, back_words(lang).as_str()],
        );
        let _ = std::fs::remove_file(&path);
    }
    {
        let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
        intake.in_order(DELETE_PATH, vec![delete_silent()]);
        let path = account_scratch_full("delete-7e-h1-silent-stranger");
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
            "stranger@elsewhere.com",
            &[
                ("rev", rev.as_str()),
                ("uuid", ""),
                ("confirm_email", "stranger@elsewhere.com"),
            ],
            lang,
        );
        assert_outcome(
            "the first POST unanswered, stranger",
            &g,
            lang,
            504,
            t(lang, K::AccountDeleteUnsureTitle),
            &[t(lang, K::AccountDeleteMaybeQueued)],
            &[DELETE_RETRY_EN, back_words(lang).as_str()],
        );
        let _ = std::fs::remove_file(&path);
    }

    // A **later** `POST` refused, then unanswered: the "some" page, which is the roster's
    // multi case, and the muted line naming the addresses not confirmed is asserted in full
    // by `a_second_address_refused_says_some_are_queued`.
    for (who, status, last) in [
        ("a later POST refused", 502u16, delete_refused(503)),
        ("a later POST unanswered", 504, delete_silent()),
    ] {
        let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
        intake.in_order(DELETE_PATH, vec![delete_accepted(), last]);
        let path = account_scratch_roster(&format!("delete-7e-h1-some-{status}"));
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
            bob,
            &[
                ("rev", rev.as_str()),
                ("uuid", ACCOUNT_BOB),
                ("confirm_email", "bob@x.com"),
            ],
            lang,
        );
        assert_outcome(
            who,
            &g,
            lang,
            status,
            DELETE_PARTIAL_TITLE_EN,
            &[DELETE_NOW_GONE_EN, DELETE_SOME_EN, DELETE_RETRY_ONE_EN],
            &[DELETE_RETRY_EN, t(lang, K::SignOut)],
        );
        let _ = std::fs::remove_file(&path);
    }
}

/// §13.30 §4, the row that exists because the row is already gone: the intake answers the
/// first `POST` with `503`, so the keys and the named access are gone and the sign-in
/// accounts were never queued. The page says both, in that order, never says the account is
/// deleted, and offers the retry, which the person reaches as a stranger.
#[test]
fn a_refused_post_after_the_row_says_partly_and_offers_the_retry() {
    for lang in [Lang::En, Lang::It] {
        let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
        // Refused once, then accepted: `in_order` repeats its last reply, so a script of one
        // entry refuses the retry's POSTs as well and the retry can never answer 200. The
        // walk this case describes is one refusal, then a pool that took the next two.
        intake.in_order(DELETE_PATH, vec![delete_refused(503), delete_accepted()]);
        let path = account_scratch_roster(&format!("delete-7e-partial-{}", lang.code()));
        let port = account_port_intake_at(&path, &intake.endpoint());
        let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
        let rev = rev_of(&path);
        let fields = [
            ("rev", rev.as_str()),
            ("uuid", ACCOUNT_BOB),
            ("confirm_email", "bob@x.com"),
        ];

        let g = account_post_lang(&url, "bob@x.com bob@old.com", &fields, lang);
        assert_outcome(
            "the first POST refused",
            &g,
            lang,
            502,
            m(lang, DELETE_PARTIAL_TITLE_EN, DELETE_PARTIAL_TITLE_IT),
            &[
                m(lang, DELETE_NOW_GONE_EN, DELETE_NOW_GONE_IT),
                t(lang, K::AccountDeleteNotQueued),
                m(lang, DELETE_RETRY_ONE_EN, DELETE_RETRY_ONE_IT),
            ],
            &[t(lang, K::AccountDeleteRetry), t(lang, K::SignOut)],
        );
        // The row really went, which is what makes "not deleted" a lie and "partly" true.
        let text = read(&path);
        assert!(
            !text.contains(ACCOUNT_BOB),
            "{}: the row is out of the file, so the keys and the named access are gone: \
                 {text}",
            lang.code()
        );
        // It never says the account is deleted, and never names the protected list: the
        // first is untrue here, the second is a list this page has no business showing.
        let words = the_page_words(&g.body);
        for forbidden in [
            m(lang, DELETE_QUEUED_TITLE_EN, DELETE_QUEUED_TITLE_IT),
            t(lang, K::AccountDeleteQueued),
            t(lang, K::AccountDeleteProtected),
        ] {
            assert!(
                !words.contains(forbidden),
                "{}: a half-deleted account is not a queued one and not a protected one: \
                     {words}",
                lang.code()
            );
        }
        // The intake's secret is the owner's credential. It reaches the intake's header and
        // nowhere else: not a page, not a link, not a comment.
        assert!(
            !g.body.contains(TEST_SECRET),
            "{}: the intake's secret reaches no response: {}",
            lang.code(),
            account_readable(&g.body)
        );

        // The retry, followed. The row is gone, so the confirmation page it renders is the
        // stranger's: no keys, no groups, no record, and a form carrying an empty uuid.
        let pills = the_action_pills(&g.body);
        let retry = pills
            .iter()
            .find(|p| visible_text(p) == t(lang, K::AccountDeleteRetry))
            .expect("the partial page offers the retry");
        let href = attr(open_tag(retry), "href").expect("the retry is a link");
        assert_eq!(
            href,
            format!("{ACCOUNT_PATH}/delete"),
            "{}: the retry is the confirmation page, not a destination the page invented",
            lang.code()
        );
        let g = account_call(
            &format!("http://127.0.0.1:{port}{href}"),
            Some("bob@x.com bob@old.com"),
        );
        assert_eq!(
            g.status,
            200,
            "{}: the retry renders the confirmation page: {}",
            lang.code(),
            account_readable(&g.body)
        );
        let form = the_delete_form(&g.body, "", "the retry's page");
        assert_eq!(
            hidden_value(&form, "uuid").as_deref(),
            Some(""),
            "{}: the row is gone, so the page the retry offers names no row: {form}",
            lang.code()
        );
        let words = the_page_words(&g.body);
        assert!(
            !words.contains(t(lang, K::AccountDeleteKeysLead)),
            "{}: the page after the write has no keys to list: {words}",
            lang.code()
        );
        // And pressing it works: the walk runs again, as a stranger, over the addresses the
        // header names, and the file has nothing left to take. Because the retry queues
        // **every** address, §13.32 §1 takes its answer off the page table too: a completed
        // deletion with a logout URL configured is the `303` through the gate's logout, the
        // same answer the first-class success rows give, not the retired done page.
        let before = read(&path);
        let seen = intake.calls().len();
        let rev = rev_of(&path);
        let g = account_post_lang(
            &url,
            "bob@x.com bob@old.com",
            &[
                ("rev", rev.as_str()),
                ("uuid", ""),
                ("confirm_email", "bob@x.com"),
            ],
            lang,
        );
        assert_done_redirect("the retry, pressed, queues both addresses", &g);
        assert_eq!(
            intake.at_since(seen),
            vec![
                WHOAMI_PATH.to_string(),
                WHOAMI_PATH.to_string(),
                DELETE_PATH.to_string(),
                DELETE_PATH.to_string()
            ],
            "{}: the retry is the whole walk again, one address per POST: {:?}",
            lang.code(),
            intake.at_since(seen)
        );
        assert_eq!(
            read(&path),
            before,
            "{}: a stranger's walk writes nothing: the row is already gone",
            lang.code()
        );
        let _ = std::fs::remove_file(&path);
    }
}

/// §13.30 §4's refinement: a `403` from the **first** `POST` is not one page. For a caller
/// with no row nothing has changed, so the protected page is true (7c's
/// `a_protected_address_is_refused_before_anything_is_posted`); for a roster user the row is
/// already gone, so "nothing was deleted" would be false and this is the partial page. The
/// protected list is named on neither.
#[test]
fn a_roster_first_post_403_is_the_partial_page_not_the_protected_one() {
    let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
    intake.in_order(DELETE_PATH, vec![delete_refused(403)]);
    let path = account_scratch_roster("delete-7e-403-partial");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let rev = rev_of(&path);
    let g = account_post(
        &url,
        Some("bob@x.com bob@old.com"),
        &[
            ("rev", rev.as_str()),
            ("uuid", ACCOUNT_BOB),
            ("confirm_email", "bob@x.com"),
        ],
    );
    assert_eq!(
        g.status,
        502,
        "a 403 after the row went is the partial page, not the 403 that says nothing \
             happened: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        account_heading(&g.body, "h1"),
        DELETE_PARTIAL_TITLE_EN,
        "the heading says partly, which is what happened: {}",
        account_readable(&g.body)
    );
    let words = the_page_words(&g.body);
    assert!(
        words.contains(t(Lang::En, K::AccountDeleteNotQueued)),
        "the page says the sign-in accounts were not queued: {words}"
    );
    assert!(
        words.contains(DELETE_NOW_GONE_EN),
        "and it says what did go: {words}"
    );
    assert!(
        !words.contains(t(Lang::En, K::AccountDeleteProtected)),
        "the protected list is never named on either page: {words}"
    );
    assert!(
        !read(&path).contains(ACCOUNT_BOB),
        "the row went before the refusal, which is the whole reason this is a different page"
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.30 §4 and §7: the walk stops at the first `POST` that is not accepted, so the
/// addresses after it are unknown territory. The page says "some are queued", and the muted
/// line lists the refused address and every one after it, each in `code`, for the
/// administrator the person is sent to ask. Not the first: that one is confirmed.
#[test]
fn a_second_address_refused_says_some_are_queued() {
    for (lang, lead, some) in [
        (Lang::En, DELETE_UNCONFIRMED_LEAD_EN, DELETE_SOME_EN),
        (Lang::It, DELETE_UNCONFIRMED_LEAD_IT, DELETE_SOME_IT),
    ] {
        let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
        intake.in_order(DELETE_PATH, vec![delete_accepted(), delete_refused(503)]);
        let path = account_scratch_roster(&format!("delete-7e-some-{}", lang.code()));
        let port = account_port_intake_at(&path, &intake.endpoint());
        let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
        let rev = rev_of(&path);
        let g = account_post_lang(
            &url,
            "bob@x.com bob@old.com",
            &[
                ("rev", rev.as_str()),
                ("uuid", ACCOUNT_BOB),
                ("confirm_email", "bob@x.com"),
            ],
            lang,
        );
        assert_eq!(
            g.status,
            502,
            "{}: the first address was queued and the second refused: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_PARTIAL_TITLE_EN, DELETE_PARTIAL_TITLE_IT),
            "{}: partly, and the page says so in the heading: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            the_page_lede(&g.body),
            format!(
                "{} {} {}",
                m(lang, DELETE_NOW_GONE_EN, DELETE_NOW_GONE_IT),
                some,
                m(lang, DELETE_RETRY_ONE_EN, DELETE_RETRY_ONE_IT)
            ),
            "{}: gone, then some, then the retry's limit, in that order: {}",
            lang.code(),
            account_readable(&g.body)
        );
        // The muted line: the lead, then the addresses from the one that failed on.
        let muted = controls_with_class(&the_main(&g.body), "p", "muted");
        assert_eq!(
            muted.len(),
            1,
            "{}: one line names the addresses not confirmed: {}",
            lang.code(),
            account_readable(&g.body)
        );
        let codes: Vec<String> = elements(&muted[0], "<code>", "</code>")
            .iter()
            .map(|c| visible_text(c))
            .collect();
        assert_eq!(
            codes,
            vec!["bob@old.com".to_string()],
            "{}: the refused address and every one after it, and not the confirmed one: {}",
            lang.code(),
            muted[0]
        );
        assert_eq!(
            visible_text(&muted[0]),
            format!("{lead} bob@old.com"),
            "{}: the line says what the list is: {}",
            lang.code(),
            muted[0]
        );
        assert_eq!(
            intake.at(),
            vec![
                WHOAMI_PATH.to_string(),
                WHOAMI_PATH.to_string(),
                DELETE_PATH.to_string(),
                DELETE_PATH.to_string()
            ],
            "{}: the walk stops at the refusal, so the second is the last POST: {:?}",
            lang.code(),
            intake.at()
        );
        let _ = std::fs::remove_file(&path);
    }
}

/// The same walk with the second `POST` unanswered: the page cannot say whether that
/// address is queued, so it says "may not be" and the muted line says "not confirmed",
/// never "not queued". A `504`, and the same actions.
#[test]
fn a_second_address_unanswered_says_some_may_be_queued() {
    let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
    intake.in_order(DELETE_PATH, vec![delete_accepted(), delete_silent()]);
    let path = account_scratch_roster("delete-7e-some-silent");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let rev = rev_of(&path);
    let g = account_post(
        &url,
        Some("bob@x.com bob@old.com"),
        &[
            ("rev", rev.as_str()),
            ("uuid", ACCOUNT_BOB),
            ("confirm_email", "bob@x.com"),
        ],
    );
    assert_eq!(
        g.status,
        504,
        "an unanswered POST is the gateway's own timeout: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        account_heading(&g.body, "h1"),
        DELETE_PARTIAL_TITLE_EN,
        "the row is gone, so the account is partly deleted whatever the intake did: {}",
        account_readable(&g.body)
    );
    let words = the_page_words(&g.body);
    assert!(
        words.contains(DELETE_SOME_EN),
        "some are queued, the others may not be: {words}"
    );
    assert!(
        !words.contains(t(Lang::En, K::AccountDeleteNotQueued)),
        "an unanswered request is not a refusal, so the page cannot say the accounts \
             \"could not be queued\": {words}"
    );
    let muted = controls_with_class(&the_main(&g.body), "p", "muted");
    assert_eq!(
        elements(&muted[0], "<code>", "</code>")
            .iter()
            .map(|c| visible_text(c))
            .collect::<Vec<_>>(),
        vec!["bob@old.com".to_string()],
        "the unconfirmed address is listed, because the person cannot know it: {}",
        account_readable(&g.body)
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.30 §6, "Scripting off: every step is a `GET` link or a `POST` form; nothing in the
/// flow carries a script". The console's version of this
/// (`no_page_but_the_reveal_carries_a_script`) walks `every_route()`, which is the console's
/// `Route` enum: it never reaches a `/account/delete` outcome, so the deletion's pages were
/// unpinned. Every page of §2 and §4 is walked here.
///
/// Step 13 (PLAN.md) moved the handler rule: these pages wear the account menu, so they carry
/// the menu's two `onchange` list boxes like every other page under the prefix. The script
/// rule is untouched, and the handler rule is the page's own allowlist
/// (`account_extra_handlers`), so a step of the flow that gains a script of its own is still
/// red here.
#[test]
fn the_delete_flow_carries_no_script() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_roster("delete-7e-nojs");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let rev = rev_of(&path);
    let roster = [
        ("rev", rev.as_str()),
        ("uuid", ACCOUNT_BOB),
        ("confirm_email", "bob@x.com"),
    ];
    let typed_wrong = [
        ("rev", rev.as_str()),
        ("uuid", ACCOUNT_BOB),
        ("confirm_email", "someone@elsewhere.com"),
    ];

    let mut pages: Vec<(&str, AccountGot)> = Vec::new();
    // The confirmation page, and the typed refusal, which is the same page again.
    pages.push((
        "the confirmation page",
        account_call(&url, Some("bob@x.com bob@old.com")),
    ));
    pages.push((
        "the typed refusal",
        account_post(&url, Some("bob@x.com bob@old.com"), &typed_wrong),
    ));
    // The completed deletion: a `303` with no body (§13.32 §1). It is in this list because
    // an empty answer is the cheapest page to smuggle a script into.
    pages.push((
        "the done redirect",
        account_post(&url, Some("bob@x.com bob@old.com"), &roster),
    ));
    // The 409, on bytes the page never saw.
    let stale = "0".repeat(64);
    pages.push((
        "the 409",
        account_post(
            &url,
            Some("bob@x.com bob@old.com"),
            &[
                ("rev", stale.as_str()),
                ("uuid", ACCOUNT_BOB),
                ("confirm_email", "bob@x.com"),
            ],
        ),
    ));
    // The partial, the unsure, and the "some" page, each on a scripted sequence of its own.
    for (label, replies) in [
        ("the partial page", vec![delete_refused(503)]),
        ("the unsure page", vec![delete_silent()]),
        (
            "the some page",
            vec![delete_accepted(), delete_refused(503)],
        ),
    ] {
        let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
        intake.in_order(DELETE_PATH, replies);
        let path = account_scratch_roster(&format!("delete-7e-nojs-{}", label.replace(' ', "-")));
        let port = account_port_intake_at(&path, &intake.endpoint());
        let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
        let rev = rev_of(&path);
        pages.push((
            label,
            account_post(
                &url,
                Some("bob@x.com bob@old.com"),
                &[
                    ("rev", rev.as_str()),
                    ("uuid", ACCOUNT_BOB),
                    ("confirm_email", "bob@x.com"),
                ],
            ),
        ));
        let _ = std::fs::remove_file(&path);
    }
    // The protected page.
    {
        let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_protected())]);
        let path = account_scratch_roster("delete-7e-nojs-protected");
        let port = account_port_intake_at(&path, &intake.endpoint());
        let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
        let rev = rev_of(&path);
        pages.push((
            "the protected page",
            account_post(
                &url,
                Some("bob@x.com bob@old.com"),
                &[
                    ("rev", rev.as_str()),
                    ("uuid", ACCOUNT_BOB),
                    ("confirm_email", "bob@x.com"),
                ],
            ),
        ));
        let _ = std::fs::remove_file(&path);
    }

    for (label, g) in pages {
        assert!(
            !g.body.contains("<script"),
            "{label}: the deletion's flow carries no script: {}",
            account_readable(&g.body)
        );
        assert!(
            !g.body.contains("javascript:"),
            "{label}: no javascript: href: {}",
            account_readable(&g.body)
        );
        assert!(
            account_extra_handlers(&g.body).is_empty(),
            "{label}: the only handlers are the account menu's two list boxes, so every \
                 step is markup alone: {:?}",
            account_extra_handlers(&g.body)
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// The same file with `gate.identity_attrs` narrowed to `uuid`: nginx then injects no
/// `X-Auth-Email` at all, so there is no identity for this page to act on.
const ACCOUNT_SETTINGS_NO_EMAIL: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"],
        "identity_attrs": ["uuid"] },
        "web": { "admins": ["admin@x.com"] } }"#;

/// Every caller §13.4's table lists, in the header form each one arrives in. The page
/// must name each of them, as the header carried it, normalised.
const ACCOUNT_CALLERS: [&str; 5] = [
    "bob@x.com",
    "BOB@old.com bob@x.com",
    "carol@x.com",
    "admin@x.com",
    "stranger@elsewhere.com",
];

/// The deployment's settings plus the administrator's default theme.
const ACCOUNT_SETTINGS_THEME_DARK: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"] },
        "web": { "admins": ["admin@x.com"] },
        "ui": { "theme": "dark" } }"#;

/// A missing `X-Auth-Email` means nginx gated this location and forgot to inject the
/// identity. That is a broken deployment, not an anonymous visitor, so the page refuses
/// rather than rendering a page about nobody: an open door here is silent.
#[test]
fn account_a_request_with_no_identity_header_is_a_401() {
    let path = account_scratch("no-header", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    let g = account_call(&base, None);
    assert_eq!(
        g.status, 401,
        "a header nobody sent is not an anonymous visitor: {g:?}"
    );

    // A header set to spaces is the same broken deployment: nginx wrote the header and
    // put nobody in it, and an identity of spaces is not a person either.
    let g = account_call(&base, Some("   "));
    assert_eq!(g.status, 401, "a header of spaces names nobody: {g:?}");

    cleanup(&path);
}

/// `gate.identity_attrs` without `email` means nginx injects no `X-Auth-Email`, so this
/// page has no identity to act on at all. That is a deployment fault, and the answer has
/// to name the setting, because the operator reading it is the only person who can fix it.
#[test]
fn account_settings_without_the_email_attribute_are_a_500_naming_the_setting() {
    let path = account_scratch("no-email-attr", ACCOUNT_SETTINGS_NO_EMAIL);
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        500,
        "a deployment that injects no email has no caller to serve: {}",
        account_readable(&g.body)
    );
    assert!(
        g.body.contains("identity_attrs"),
        "the page must name the setting to fix: {}",
        account_readable(&g.body)
    );

    cleanup(&path);
}

/// `X-Auth-Email` carries every identifier of one row, space-joined, so several values
/// that resolve to **different** rows is nginx having built one header out of two people.
/// There is no page that is about both, so this is a fault, not a caller.
#[test]
fn account_values_from_two_different_rows_are_a_500() {
    let path = account_scratch("two-rows", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com carol@x.com"));
    assert_eq!(
        g.status,
        500,
        "two rows in one header is not one person: {}",
        account_readable(&g.body)
    );

    cleanup(&path);
}

/// `denied` is checked **first**, ahead of the row resolution that decides 500 vs 200:
/// the gate refuses a vetoed identity before it ever reaches this page, so this is the
/// second lock for a file edited mid-request, and a lock that a caller escapes by
/// sending *less* is not a lock.
#[test]
fn account_a_vetoed_identity_is_a_403_checked_before_the_rest() {
    let path = account_scratch("vetoed", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    let g = account_call(&base, Some("spammer@x.com"));
    assert_eq!(
        g.status,
        403,
        "a vetoed identity gets a refusal, not the page: {}",
        account_readable(&g.body)
    );

    // A vetoed value joined to a live one is still a vetoed request, and it is a 403
    // rather than the 500 the two-rows rule would hand it: the veto outranks it.
    let g = account_call(&base, Some("bob@x.com spammer@x.com"));
    assert_eq!(g.status, 403, "the veto outranks the two-row 500: {g:?}");

    cleanup(&path);
}

/// Every caller in §13.4's table reaches the page, and the page names them: a roster
/// user, a row whose two emails both arrived, an administrator (whose `web.admins` entry
/// is **not** read here, so they are treated as any stranger), and a stranger no row
/// knows, whom the `authenticated` scope lets in.
#[test]
fn account_a_signed_in_caller_gets_a_page_naming_them() {
    let path = account_scratch("callers", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    for who in ACCOUNT_CALLERS {
        let g = account_call(&base, Some(who));
        assert_eq!(
            g.status,
            200,
            "{who} is signed in and reaches the page: {}",
            account_readable(&g.body)
        );
        for part in who.split_ascii_whitespace() {
            let id = norm_email(part);
            assert!(g.body.contains(&id), "the page must name {id}: {g:?}");
        }
    }

    cleanup(&path);
}

/// This page is one of the estate's HTML documents, so it carries the shared header set
/// the library decides once, and a policy of its own; and it is a page a stranger reaches,
/// so it carries no script and no inline handler at all.
#[test]
fn account_every_page_carries_the_shared_headers_and_no_script() {
    let path = account_scratch("headers", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    for who in ACCOUNT_CALLERS {
        let g = account_call(&base, Some(who));
        assert_eq!(g.status, 200, "{who}");
        for (k, v) in PAGE_SECURITY_HEADERS {
            assert_eq!(
                g.header(k),
                Some(v),
                "{who}: the response must carry {k}: {v}"
            );
        }
        assert!(
            g.header("Content-Security-Policy").is_some(),
            "{who}: every HTML page carries a policy: {g:?}"
        );
        assert!(
            !g.body.to_ascii_lowercase().contains("<script"),
            "{who}: no script tag, the page works with scripting off"
        );
        assert!(
            account_extra_handlers(&g.body).is_empty(),
            "{who}: the only handler on the page is the Preferences one: {:?}",
            account_extra_handlers(&g.body)
        );
    }

    cleanup(&path);
}

/// The answer to "where can I go?" is a list of places, so the section names each
/// application and then that application's scopes, in the order the file writes them: an
/// operator comparing the page with the file they wrote should read them in the same
/// order. `anonymous` is absent because it grants with no credential and so says nothing
/// about this person, and a scope whose credentials are `api_key` only is absent because
/// the caller reading this page is signed in with a browser, not with a key.
#[test]
fn account_the_reach_section_lists_every_app_and_scope_bob_reaches_in_file_order() {
    let path = account_scratch_full("reach-bob");
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob is a roster user: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "reach");
    for pair in ["mpa/admin", "mpa/onboarding", "mcp/logs"] {
        assert!(
            s.contains(&format!("<li><code>{pair}</code></li>")),
            "bob reaches {pair}, so the reach section must list it as one flat item: {s}"
        );
    }
    let at = |n: &str| s.find(n).unwrap_or_default();
    assert!(
        at("mpa/admin") < at("mpa/onboarding") && at("mpa/onboarding") < at("mcp/logs"),
        "the pairs are listed in file order, an application's scopes together: {s}"
    );
    assert!(
        !s.contains("healthz"),
        "an anonymous scope is reached by everyone with no credential, so it says nothing \
             about bob and must not be listed: {s}"
    );
    assert!(
        !s.contains("api"),
        "mcp/api admits only an api_key, and a browser login never reaches it: {s}"
    );

    cleanup(&path);
}

/// A group is how an operator writes a reusable set of people, so the groups section
/// answers the question a person actually has: not "which scopes list my uuid" (a
/// `@group` lists none of them directly) but "under which named set am I filed".
#[test]
fn account_the_groups_section_names_the_groups_the_caller_belongs_to() {
    let path = account_scratch_full("groups-bob");
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob is a roster user: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "groups");
    assert!(
        s.contains("<li><code>admins</code></li>"),
        "bob is a member of the admins group, so the page must name it, one item in code: {s}"
    );
    assert_eq!(
        account_heading(&s, "h2"),
        "Groups",
        "the heading says Groups, not the console's \"User groups\" for the file section: {s}"
    );

    cleanup(&path);
}

/// The keys section is where a person learns which machine credentials exist for them, so
/// it shows the id, the expiry and the restriction, all of them facts the file states. The
/// secret is the one thing that must never come back: the file stores only a hash, the
/// bearer is shown once at minting, and a page that reprinted either would be a way to
/// read a credential out of a page that is not its reveal.
#[test]
fn account_the_keys_section_shows_id_expiry_and_restriction_and_never_the_secret() {
    let path = account_scratch_full("keys-bob");
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob is a roster user: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "keys");
    assert!(
        s.contains("laptop") && s.contains("ci"),
        "bob has two keys, so both ids must be listed: {s}"
    );
    assert!(
        s.contains("never"),
        "the laptop key's duration is `never`, and that is the fact a person acts on: {s}"
    );
    assert!(
        s.contains("2027-01-01"),
        "the ci key was released 2026-01-01 for 365 days, so it expires 2027-01-01: {s}"
    );
    assert!(
        s.contains("mcp/api"),
        "the laptop key is restricted to mcp/api, and an owner has to see that a key is \
             narrower than they are: {s}"
    );

    // Absence is asserted on the whole document, not on the section: a bearer printed
    // anywhere, in a comment or a data attribute, is the same leak.
    for secret in [
        ACCOUNT_BEARER_LAPTOP.to_string(),
        ACCOUNT_BEARER_CI.to_string(),
        sha256_hex(ACCOUNT_BEARER_LAPTOP),
        sha256_hex(ACCOUNT_BEARER_CI),
    ] {
        assert!(
            !g.body.contains(&secret),
            "the page must carry neither a raw key nor its hash, and it carries {secret}"
        );
    }

    cleanup(&path);
}

/// The profile section shows what the estate hands to the applications behind the gate:
/// the claims the deployment configured, as the proxy forwarded them. The gate sends a
/// claim value percent-encoded (that construction is the whole header-safety argument), so
/// the page has to decode it: a name rendered as `Bob%20Smith` is a name nobody can read,
/// and a claim shown with no name against it is not evidence of anything.
#[test]
fn account_the_profile_section_shows_a_forwarded_claim_by_name_and_decoded() {
    let path = account_scratch_full("profile-bob");
    let base = account_serve(&path);

    let g = account_call_with(
        &base,
        Some("bob@x.com"),
        &[("X-Auth-Given-Name", "Bob%20Smith")],
    );
    assert_eq!(
        g.status,
        200,
        "bob is a roster user: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "profile");
    assert!(
        s.contains(t(Lang::En, K::AttrGivenName)) && !s.contains("given_name"),
        "the page names the claim it is showing by its word label, not the claim name: {s}"
    );
    // The claim is named in words, the form's own label (user decision 2026-11-25), so the
    // read-only panel and the edit form never disagree about what a field is called.
    let lis: Vec<String> = elements(&s, "<li>", "</li>")
        .iter()
        .map(|l| visible_text(l))
        .collect();
    assert!(
        lis.contains(&format!("{}: Bob Smith", t(Lang::En, K::AttrGivenName))),
        "the forwarded value is percent-encoded on the wire and must reach the page decoded, \
             after the claim's word label: {lis:?}"
    );

    // Nothing forwarded, nothing shown: a page that invented a value would be showing a
    // person a fact about them that the estate never said.
    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(g.status, 200, "bob is signed in with no claim forwarded");
    let s = account_section(&g.body, "profile");
    assert!(
        !s.contains("Bob"),
        "no header arrived, so the page may not show a given name: {s}"
    );

    cleanup(&path);
}

/// A stranger is a real caller, because the page's own scope is `authenticated`, and what
/// they reach is exactly the scopes that grant on identity alone: no restricted scope
/// lists them, they belong to no group, and a key needs a roster owner, so there are none
/// to show.
#[test]
fn account_a_stranger_reaches_only_the_authenticated_scope_and_has_no_groups_or_keys() {
    let path = account_scratch_full("stranger");
    let base = account_serve(&path);

    let g = account_call(&base, Some("stranger@elsewhere.com"));
    assert_eq!(
        g.status,
        200,
        "a stranger Cognito vouches for reaches this page: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "reach");
    assert!(
        s.contains("<li><code>mpa/onboarding</code></li>"),
        "the authenticated scope is reached by everyone signed in, so the page must list \
             it as an app/scope pair: {s}"
    );
    for name in ["admin", "logs", "mcp", "healthz", "api"] {
        assert!(
            !s.contains(name),
            "the stranger reaches no {name}, so the page must not name it: {s}"
        );
    }
    assert!(
        !account_section(&g.body, "groups").contains("admins"),
        "a stranger is in no group: {}",
        account_section(&g.body, "groups")
    );
    let k = account_section(&g.body, "keys");
    assert!(
        !k.contains("laptop") && !k.contains("ci"),
        "a key must have a roster owner, so a stranger has no keys to be shown: {k}"
    );

    cleanup(&path);
}

/// `web.admins` is not read here: an administrator with no roster row is one more person
/// looking at their own account. So the page they get is the stranger's page, section for
/// section. Anything else would make a list in the settings file a second, invisible way
/// to be granted something on a page whose whole subject is the access file.
///
/// In this binary the point is sharper than it was in `bb-auth-me`: `admin@x.com` is the
/// name in `web.admins`, so the same identity that owns the console is the one that must
/// be answered here like any other caller.
#[test]
fn account_an_administrator_with_no_row_is_answered_exactly_as_a_stranger() {
    let path = account_scratch_full("admin-is-a-stranger");
    let base = account_serve(&path);

    for id in ["reach", "groups", "keys"] {
        let stranger = account_section(
            &account_call(&base, Some("stranger@elsewhere.com")).body,
            id,
        );
        let admin = account_section(&account_call(&base, Some("admin@x.com")).body, id);
        assert_eq!(
            stranger, admin,
            "the {id} section must say the same thing to an administrator with no roster \
                 row as to any other caller with no row"
        );
    }

    cleanup(&path);
}

/// This page is served to whoever nginx vouches for, a stranger included, so the access
/// file's URLs are not information to hand out: which areas exist, and which paths inside
/// them are gated, is exactly what somebody holding any account at all should not learn.
/// Names of applications and scopes are fine, and are what §13.4 chose to show instead.
#[test]
fn account_no_page_shows_a_url_from_the_access_file() {
    let path = account_scratch_full("no-urls");
    let base = account_serve(&path);

    for who in ["bob@x.com", "carol@x.com", "stranger@elsewhere.com"] {
        let g = account_call(&base, Some(who));
        assert_eq!(
            g.status,
            200,
            "{who} reaches the page: {}",
            account_readable(&g.body)
        );
        for url in ["https://app.x.com", "https://ai.x.com", "/mpa/", "/mcp/"] {
            assert!(
                !g.body.contains(url),
                "{who}: the page must not leak {url} from the access file"
            );
        }
    }

    cleanup(&path);
}

/// `denied` removes everything, and that includes the list: the veto is answered with a
/// refusal before the page is built, so a section of grants on a refusal page would be the
/// page telling a person it is refusing them what it just said they can reach.
#[test]
fn account_a_denied_identity_gets_a_403_and_sees_no_list_at_all() {
    let path = account_scratch_full("denied-full");
    let base = account_serve(&path);

    let g = account_call(&base, Some("spammer@x.com"));
    assert_eq!(
        g.status,
        403,
        "a vetoed identity gets a refusal, on the rich fixture too: {}",
        account_readable(&g.body)
    );
    assert!(
        !g.body.contains("<section id=\"reach\""),
        "a refusal carries no list of what the caller reaches: {}",
        account_readable(&g.body)
    );

    cleanup(&path);
}

/// The estate's rule is that a page works with scripting off, and the identity page has
/// nothing to script beyond the Preferences menu, whose one handler is the estate's own.
/// The rich page is the one that tempts a developer into a disclosure toggle, so it is the
/// one worth pinning.
#[test]
fn account_the_rich_page_carries_no_script_and_only_the_menu_handler() {
    let path = account_scratch_full("nojs-full");
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob is a roster user: {}",
        account_readable(&g.body)
    );
    assert!(
        !g.body.to_ascii_lowercase().contains("<script"),
        "no script tag: the page works with scripting off"
    );
    assert!(
        account_extra_handlers(&g.body).is_empty(),
        "the only handler on the page is the Preferences one: {:?}",
        account_extra_handlers(&g.body)
    );

    cleanup(&path);
}

/// The administrator's `ui.theme` is the theme a page starts in, stamped on `<html>` as
/// `data-theme` exactly as the admin console stamps it. A deployment that configured
/// nothing gets no attribute at all, which is what leaves the browser and the OS deciding.
#[test]
fn account_the_administrators_default_theme_is_stamped_on_the_html_tag() {
    let path = account_scratch("theme-default", ACCOUNT_SETTINGS_THEME_DARK);
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob reaches the page: {}",
        account_readable(&g.body)
    );
    assert!(
        account_html_tag(&g.body).contains(r#"data-theme="dark""#),
        "ui.theme dark must reach the html tag: {}",
        account_html_tag(&g.body)
    );

    // No `ui` section at all: no attribute, so `prefers-color-scheme` is what paints.
    let plain = account_scratch("theme-none", ACCOUNT_SETTINGS);
    let plain_base = account_serve(&plain);
    let g = account_call(&plain_base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob reaches the page: {}",
        account_readable(&g.body)
    );
    assert!(
        !account_html_tag(&g.body).contains("data-theme"),
        "a deployment that set no theme must emit no data-theme at all: {}",
        account_html_tag(&g.body)
    );

    cleanup(&path);
    cleanup(&plain);
}

/// The person's own cookie outranks the administrator's default, and `system` is the choice
/// to give the choice back: it falls through to the deployment's default rather than
/// painting a third thing, so a session that un-chose ends up where it started.
#[test]
fn account_a_theme_cookie_outranks_the_administrators_default() {
    let path = account_scratch("theme-cookie", ACCOUNT_SETTINGS_THEME_DARK);
    let base = account_serve(&path);

    let g = account_call_pref(&base, Some("bob@x.com"), Some("theme=light"), None);
    assert_eq!(
        g.status,
        200,
        "bob reaches the page: {}",
        account_readable(&g.body)
    );
    assert!(
        account_html_tag(&g.body).contains(r#"data-theme="light""#),
        "the person's own choice must outrank the deployment's default: {}",
        account_html_tag(&g.body)
    );

    let g = account_call_pref(&base, Some("bob@x.com"), Some("theme=system"), None);
    assert_eq!(
        g.status,
        200,
        "bob reaches the page: {}",
        account_readable(&g.body)
    );
    assert!(
        account_html_tag(&g.body).contains(r#"data-theme="dark""#),
        "system falls through to the administrator's dark: {}",
        account_html_tag(&g.body)
    );

    cleanup(&path);
}

/// Choosing a preference is a `GET` with a parameter, answered by a cookie and a redirect
/// that takes the parameter back out of the URL, so a bookmark does not carry a preference
/// around forever. The cookie names and values are the console's, which is what makes a
/// choice made in one program carry to the other on the same host, and the redirect lands
/// back on `/account/` rather than on the console's dashboard.
#[test]
fn account_a_theme_or_language_choice_becomes_a_cookie_and_a_redirect_home() {
    let path = account_scratch("pref-redirect", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    let g = account_call(&format!("{base}?theme=dark"), Some("bob@x.com"));
    assert_eq!(
        g.status,
        302,
        "?theme=dark must be applied and redirected, not answered with a page: {}",
        account_readable(&g.body)
    );
    let cookie = g
        .header("Set-Cookie")
        .expect("the choice must be remembered in a cookie");
    assert!(
        cookie.starts_with("theme=dark;"),
        "the cookie must be the console's own theme cookie: {cookie}"
    );
    for part in ["Path=/", "HttpOnly", "SameSite=Lax"] {
        assert!(
            cookie.contains(part),
            "the preference cookie must carry {part}: {cookie}"
        );
    }
    assert_eq!(
        g.header("Location"),
        Some(ACCOUNT_PAGE),
        "the redirect goes back to this page with the parameter gone: {:?}",
        g.header("Location")
    );

    let g = account_call(&format!("{base}?lang=it"), Some("bob@x.com"));
    assert_eq!(
        g.status,
        302,
        "?lang=it must be applied and redirected: {}",
        account_readable(&g.body)
    );
    let cookie = g
        .header("Set-Cookie")
        .expect("the choice must be remembered in a cookie");
    assert!(
        cookie.starts_with("lang=it;"),
        "the cookie must be the console's own lang cookie: {cookie}"
    );
    assert_eq!(
        g.header("Location"),
        Some(ACCOUNT_PAGE),
        "the redirect goes back to this page with the parameter gone: {:?}",
        g.header("Location")
    );

    cleanup(&path);
}

/// The selector's one submit carries `theme` and `lang` in the same `GET`, so one request
/// has to remember both. The console cannot today: its theme check answers with a redirect
/// of its own, so a submit that names both preferences is answered one at a time and the
/// browser has to come back in for the second. On the self-service page the selector is a
/// visible form with a submit button and no script, so one request is the whole
/// interaction, and a preference that is never stored is a choice that did not happen: the
/// person watches their own pick revert on the next load.
#[test]
fn account_one_submit_of_the_selector_remembers_both_choices() {
    let path = account_scratch("pref-both", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    let g = account_call(&format!("{base}?theme=light&lang=it"), Some("bob@x.com"));
    assert_eq!(
        g.status,
        302,
        "one submit of both preferences must be applied and redirected: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.header("Location"),
        Some(ACCOUNT_PAGE),
        "the redirect goes back to this page with the parameters gone: {:?}",
        g.header("Location")
    );
    let set = g.cookies();
    assert_eq!(
        set.len(),
        2,
        "one submit of two preferences must set two cookies in one response, and it set \
             {set:?} (all headers: {:?})",
        g.headers
    );
    assert!(
        set.iter().any(|c| c.starts_with("theme=light;")),
        "the theme picked on this submit must be remembered: {set:?}"
    );
    assert!(
        set.iter().any(|c| c.starts_with("lang=it;")),
        "the language picked on the same submit must be remembered too: {set:?}"
    );
    for c in &set {
        assert!(
            c.contains("Path=/"),
            "a preference cookie is `Path=/`, so a choice made on the page carries to the \
                 console and back on one host: {c}"
        );
    }

    // One recognised value and one nobody recognises is one choice, not two: the
    // unrecognised value is not a preference and must set nothing, while the recognised
    // half still lands.
    let g = account_call(&format!("{base}?theme=light&lang=xx"), Some("bob@x.com"));
    assert_eq!(
        g.status,
        302,
        "the recognised half of a submit is still a choice: {}",
        account_readable(&g.body)
    );
    let set = g.cookies();
    assert_eq!(
        set.len(),
        1,
        "a value nobody recognises must set no cookie, and the response set {set:?}"
    );
    assert!(
        set[0].starts_with("theme=light;"),
        "the recognised half must be the theme cookie: {set:?}"
    );

    cleanup(&path);
}

/// A value that is not one of the three themes, or one of the two languages plus `auto`, is
/// not a preference at all: nothing is remembered and the page is served as it was.
/// Storing a nonsense value would leave the person looking at a choice the page cannot show
/// as chosen, and would let a crafted link write a cookie for them.
#[test]
fn account_a_preference_nobody_recognises_sets_no_cookie() {
    let path = account_scratch("pref-bogus", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    for q in ["theme=purple", "lang=xx"] {
        let g = account_call(&format!("{base}?{q}"), Some("bob@x.com"));
        assert_eq!(
            g.status,
            200,
            "{q} is not a choice, so the page is served as it was: {}",
            account_readable(&g.body)
        );
        assert!(
            g.header("Set-Cookie").is_none(),
            "{q} must set no cookie, and the response set {:?}",
            g.header("Set-Cookie")
        );
    }

    cleanup(&path);
}

/// The language is the person's cookie, failing that the browser's `Accept-Language`,
/// failing that English: most explicit wins, and `auto` is the choice to keep letting the
/// browser decide, which is what a session that never chose has always been getting.
#[test]
fn account_the_language_is_the_cookie_then_the_browser_header_then_english() {
    let path = account_scratch("lang", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    let cases: [(Option<&str>, Option<&str>, &str); 5] = [
        (Some("lang=it"), None, "it"),
        (None, Some("it-IT,it;q=0.9"), "it"),
        (None, Some("de-DE"), "en"),
        (Some("lang=en"), Some("it"), "en"),
        (Some("lang=auto"), Some("it"), "it"),
    ];
    for (cookie, accept, want) in cases {
        let g = account_call_pref(&base, Some("bob@x.com"), cookie, accept);
        assert_eq!(
            g.status,
            200,
            "bob reaches the page: {}",
            account_readable(&g.body)
        );
        assert!(
            account_html_tag(&g.body).contains(&format!(r#"lang="{want}""#)),
            "cookie {cookie:?} with Accept-Language {accept:?} must render lang=\"{want}\": {}",
            account_html_tag(&g.body)
        );
    }

    cleanup(&path);
}

/// The Italian strings are compiled into the binary, not fetched: this is the page a person
/// reaches when something is already wrong, and a page that needs a translation host has
/// picked the worst moment to have a dependency. The headings are the prose, so they are
/// what proves the table is being read at all.
#[test]
fn account_the_italian_page_is_translated() {
    let path = account_scratch_full("lang-it");
    let base = account_serve(&path);

    let en = account_call_pref(&base, Some("bob@x.com"), Some("lang=en"), None);
    let it = account_call_pref(&base, Some("bob@x.com"), Some("lang=it"), None);
    assert_eq!(
        en.status,
        200,
        "bob reaches the page: {}",
        account_readable(&en.body)
    );
    assert_eq!(
        it.status,
        200,
        "bob reaches the page: {}",
        account_readable(&it.body)
    );

    let reach_h2 = |g: &AccountGot| account_heading(&account_section(&g.body, "reach"), "h2");
    assert_ne!(
        reach_h2(&en),
        reach_h2(&it),
        "the reach heading must be translated, and both pages say the same thing in it"
    );
    assert_ne!(
        account_heading(&en.body, "h1"),
        account_heading(&it.body, "h1"),
        "the page's own title must be translated too"
    );

    cleanup(&path);
}

/// WHY: one key (`AccountNone`) answers "none" for all four sections, so a single Italian
/// string has to agree with four nouns at once and can only agree with one. The keys section
/// sits under "Chiavi API", feminine plural, and today answers "Nessuno.", which agrees with
/// nothing a reader can see; the profile's empty state answers for a claim's *value*
/// ("valore", masculine), so "Nessuno." is right there and must stay. The two assertions
/// together pin the sections **apart**, because the fix is a key per noun: a fix that just
/// edits the shared string to the feminine would repaint the profile too, and pass a test
/// that only looked at keys. The English page is asserted alongside, since the fix must not
/// reach the language that has no grammatical gender. `reach` and `groups` are deliberately
/// not pinned: `groups` is "gruppi", masculine, so today's "Nessuno." already agrees, and
/// `reach` is "Dove puoi arrivare", which carries no noun for an adjective to agree with, so
/// nothing here should force a word the plan says to leave alone.
///
/// §13.16 reworded the keys entry to "No API keys yet.", which is the same rule one step
/// on: the keys section has its own key, so the empty state says what is missing in its own
/// noun, and the shared word is left to the sections that answer for a value.
#[test]
fn account_the_italian_keys_empty_state_agrees_with_chiavi() {
    // bob has a roster row, no `api_keys`, and these settings name no `profile_claims`, so
    // both sections answer with their empty state rather than with content.
    let path = account_scratch("keys-none-it", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    let it = account_call_pref(&base, Some("bob@x.com"), Some("lang=it"), None);
    assert_eq!(
        it.status,
        200,
        "bob reaches the page: {}",
        account_readable(&it.body)
    );
    assert!(
        account_html_tag(&it.body).contains(r#"lang="it""#),
        "the cookie must have chosen Italian, or the test asserts on English: {}",
        account_html_tag(&it.body)
    );

    let keys = account_section(&it.body, "keys");
    let profile = account_section(&it.body, "profile");
    assert!(
        keys.contains("Chiavi API"),
        "the section under test is the keys section: {keys}"
    );
    let keys_empty = t(Lang::It, K::AccountKeysNone);
    assert!(
        keys.contains(keys_empty),
        "the keys section answers an empty roster with its own key's words: {keys}"
    );
    assert!(
        keys_empty.to_lowercase().contains("chiavi"),
        "\"Chiavi API\" is feminine plural, so the keys empty state has to name keys, in \
             the feminine, rather than borrow a bare pronoun: {keys_empty}"
    );
    assert_ne!(
        keys_empty,
        t(Lang::It, K::None),
        "the keys empty state is its own entry, so an edit of the shared word cannot \
             repaint this section: {keys_empty}"
    );
    assert!(
        profile.contains("Questa installazione non condivide dettagli del profilo."),
        "the profile has its own empty sentence, which names what is missing: {profile}"
    );
    assert!(
        !profile.contains(keys_empty),
        "the fix is one key per noun, so the profile must not pick up the keys section's \
             words: {profile}"
    );

    let en = account_call_pref(&base, Some("bob@x.com"), Some("lang=en"), None);
    assert_eq!(
        en.status,
        200,
        "bob reaches the page: {}",
        account_readable(&en.body)
    );
    assert!(
        account_section(&en.body, "keys").contains("No API keys yet."),
        "§13.16 reworded the keys empty state to say what is missing and to read as an \
             invitation, since the + now sits below it: {}",
        account_section(&en.body, "keys")
    );
    assert!(
        account_section(&en.body, "profile").contains("This deployment shares no profile details."),
        "and the profile section says what is missing in its own sentence: {}",
        account_section(&en.body, "profile")
    );

    cleanup(&path);
}

/// The selector is a plain `GET` form with a visible submit button. Unlike the console this
/// page emits no script and no handler at all, so there is no `onchange` to apply a pick on
/// the fly, and a browser with scripting off is not a fallback here but the only browser
/// there is.
#[test]
fn account_the_page_carries_a_theme_and_language_selector_with_a_submit_button() {
    let path = account_scratch("selector", ACCOUNT_SETTINGS);
    let base = account_serve(&path);

    let g = account_call_pref(&base, Some("bob@x.com"), Some("theme=dark"), None);
    assert_eq!(
        g.status,
        200,
        "bob reaches the page: {}",
        account_readable(&g.body)
    );
    let body = account_readable(&g.body);
    // 8b-2: the selector lives in the header's Preferences menu, Language then Theme (the
    // console's order), and the foot form is gone.
    let top = the_header_bar(&g.body, "selector");
    let form = top
        .find("<form")
        .expect("the header menu must carry a form");
    let lang = top
        .find(r#"<select name="lang""#)
        .expect("the menu must carry a language list box");
    let theme = top
        .find(r#"<select name="theme""#)
        .expect("the menu must carry a theme list box");
    assert!(
        form < lang && lang < theme,
        "both list boxes sit inside one form in the header, Language first: {top}"
    );
    assert!(
        !body.contains("selfserve-prefs"),
        "no foot form any more: {body}"
    );
    assert!(
        top.contains(r#"method="get""#),
        "a preference is a GET, so a bookmark and a reload cannot change anything: {top}"
    );
    for value in ["light", "dark", "system"] {
        assert!(
            body.contains(&format!(r#"<option value="{value}""#)),
            "the theme list must offer {value}: {body}"
        );
    }
    for value in ["en", "it", "auto"] {
        assert!(
            body.contains(&format!(r#"<option value="{value}""#)),
            "the language list must offer {value}: {body}"
        );
    }
    assert!(
        body.contains("<button"),
        "the form needs a visible submit button, since no script applies a pick: {body}"
    );
    assert!(
        body.contains(r#"<option value="dark" selected>"#),
        "the option in force must be marked chosen: {body}"
    );

    cleanup(&path);
}

/// The brand and the logo come from the same `ui` section that restyles the admin console
/// and the gate's pages, so one save signs every surface of the estate in one name. A
/// deployment that configured neither shows no image and no brand: the built-in page is
/// complete, and a page that needs an asset host to be up is a page that cannot get in.
#[test]
fn account_the_administrators_brand_and_logo_reach_the_page() {
    let path = account_scratch("brand", ACCOUNT_SETTINGS_BRAND);
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob reaches the page: {}",
        account_readable(&g.body)
    );
    assert!(
        g.body.contains("BadBat75"),
        "the brand the administrator set must name the page: {}",
        account_readable(&g.body)
    );
    assert!(
        g.body
            .contains(r#"<img src="https://assets.badbat75.com/logo.png""#),
        "the logo the administrator set must be shown: {}",
        account_readable(&g.body)
    );

    let plain = account_scratch("brand-none", ACCOUNT_SETTINGS);
    let plain_base = account_serve(&plain);
    let g = account_call(&plain_base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob reaches the page: {}",
        account_readable(&g.body)
    );
    assert!(
        !g.body.contains("<img"),
        "nothing configured, so the page fetches no image: {}",
        account_readable(&g.body)
    );
    assert!(
        !g.body.contains("BadBat75"),
        "nothing configured, so the page claims no brand: {}",
        account_readable(&g.body)
    );

    cleanup(&path);
    cleanup(&plain);
}

/// A claim the deployment configured and the proxy did not forward is a fact the estate
/// never said, and the page has to say so in words: a name with nothing after it reads as
/// "your name is empty", which is a statement about the person that nobody actually made.
#[test]
fn account_a_claim_nobody_forwarded_shows_the_word_for_none() {
    let path = account_scratch_full("claim-none");
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob reaches the page: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "profile");
    assert!(
        s.contains(t(Lang::En, K::AttrGivenName)),
        "the page must still name the claim it has nothing to show, in words: {s}"
    );
    assert!(
        s.contains("<span class=\"muted\">not provided</span>"),
        "a claim with no forwarded value says so in a muted span, never an empty value: {s}"
    );
    assert!(
        !s.contains("None."),
        "the bare word for none has no caller left on this page: {s}"
    );
    assert!(
        !s.contains("<code>not provided</code>") && !s.contains(":</li>"),
        "the muted word is not wrapped in code, and a bare colon never ends the item: {s}"
    );

    cleanup(&path);
}

/// What the page says between its `h1` and its first section: the lede, and nothing the
/// header bar already says. §13.26 §1 puts the sections in a new order, so the boundary is
/// the first `<section`, not one named section: a named one would swallow the three that
/// now come before it.
fn account_lede_zone(body: &str) -> String {
    let after = body
        .split_once("</h1>")
        .unwrap_or_else(|| panic!("no h1: {}", account_readable(body)))
        .1;
    let end = after
        .find("<section")
        .unwrap_or_else(|| panic!("no section: {}", account_readable(body)));
    after[..end].to_string()
}

/// The lede says which addresses and which account, in one paragraph: every address in
/// `code`, a line break, then the label and the uuid. The bar already says "signed in as",
/// so the body must not. A caller with **no** roster row gets the addresses and nothing
/// else, in either language: the second line names an id, and there is none to name.
#[test]
fn the_lede_names_the_addresses_and_the_account_id() {
    let path = account_scratch_full("lede");
    let base = account_serve(&path);

    let g = account_call(&base, Some("BOB@old.com bob@x.com"));
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let zone = account_lede_zone(&g.body);
    assert_eq!(
        zone.matches("<p class=\"lede\">").count(),
        1,
        "exactly one lede before the first section: {zone}"
    );
    assert!(
        zone.contains("<code>bob@old.com</code>") && zone.contains("<code>bob@x.com</code>"),
        "both addresses of the row are in code: {zone}"
    );
    assert!(
        zone.contains(&format!(
            "<br>Account id: <code class=\"uid\">{ACCOUNT_BOB}</code>"
        )),
        "after a line break, the label and the uuid in code: {zone}"
    );
    assert!(
        !zone.contains("signed in as") && !zone.contains("your uuid"),
        "the old paragraphs are gone, the bar says who is signed in: {zone}"
    );

    // Step 13: a caller with no roster row is told **nothing** about it here. The line under
    // the addresses exists to name an account id, so with no id to name there is no line, no
    // label and no sentence: the page has nothing to say about a row it does not have, and a
    // stranger reads the same shape of page as a person who has one.
    let g = account_call(&base, Some("stranger@elsewhere.com"));
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let zone = account_lede_zone(&g.body);
    assert!(
        zone.contains("<code>stranger@elsewhere.com</code>"),
        "a stranger's lede is the address they signed in with: {zone}"
    );
    for words in [
        m(Lang::En, ACCOUNT_NO_ROW_EN, ACCOUNT_NO_ROW_IT),
        m(Lang::It, ACCOUNT_NO_ROW_EN, ACCOUNT_NO_ROW_IT),
        t(Lang::En, K::AccountIdLabel),
        t(Lang::It, K::AccountIdLabel),
    ] {
        assert!(
            !zone.contains(words),
            "the lede says none of this, in either language: {zone}"
        );
    }
    assert!(
        !zone.contains("<br"),
        "the line break that separated the id from the addresses goes with the id: {zone}"
    );
    assert!(
        !zone.contains("<code class=\"uid\""),
        "a stranger has no account id to show: {zone}"
    );

    // The same caller in Italian: the sentence is a translation, so a check written in
    // English only passes a page that dropped the English and kept the Italian.
    let it = account_call_pref(&base, Some("stranger@elsewhere.com"), Some("lang=it"), None);
    assert_eq!(it.status, 200, "{}", account_readable(&it.body));
    let zone = account_lede_zone(&it.body);
    assert!(
        zone.contains("<code>stranger@elsewhere.com</code>")
            && !zone.contains("<br")
            && !zone.contains(m(Lang::It, ACCOUNT_NO_ROW_EN, ACCOUNT_NO_ROW_IT)),
        "the Italian page says the same nothing: {zone}"
    );

    let it = account_call_pref(&base, Some("bob@x.com"), Some("lang=it"), None);
    let zone = account_lede_zone(&it.body);
    assert!(
        zone.contains(&format!(
            "<br>Id dell'account: <code class=\"uid\">{ACCOUNT_BOB}</code>"
        )),
        "the label is translated: {zone}"
    );

    cleanup(&path);
}

/// Each section opens with one sub-line saying what it is for, right after its heading.
#[test]
fn each_section_says_what_it_is_for() {
    let path = account_scratch_full("subs");
    let base = account_serve(&path);
    let subs = [
        (
            "reach",
            "The applications your sign-in opens, and the areas inside each.",
            "Le applicazioni a cui il tuo accesso apre la porta, e le aree dentro ciascuna.",
        ),
        (
            "groups",
            "Groups an administrator has put you in.",
            "I gruppi in cui ti ha messo un amministratore.",
        ),
        (
            "keys",
            "A key lets a script or a tool sign in as you. It reaches at most what you reach.",
            "Una chiave permette a uno script o a uno strumento di accedere come te. \
                 Arriva al massimo dove arrivi tu.",
        ),
        (
            "profile",
            PROFILE_SUB,
            "Cosa il tuo accesso dice di te alle tue applicazioni.",
        ),
    ];
    for (cookie, pick) in [("lang=en", 1), ("lang=it", 2)] {
        let g = account_call_pref(&base, Some("bob@x.com"), Some(cookie), None);
        assert_eq!(g.status, 200, "{}", account_readable(&g.body));
        for (id, en, it) in subs {
            let want = if pick == 1 { en } else { it };
            let s = account_section(&g.body, id);
            assert_eq!(
                s.matches("class=\"lede sub\"").count(),
                1,
                "{id} ({cookie}) has exactly one sub-line: {s}"
            );
            assert!(
                s.contains(&format!("</h2><p class=\"lede sub\">{want}</p>")),
                "{id} ({cookie}) says what it is for, right after its heading: {s}"
            );
        }
    }

    cleanup(&path);
}

/// An empty section says what is missing, in a muted paragraph with its own sentence, and
/// the bare "None." has no caller left.
#[test]
fn empty_sections_name_what_is_missing() {
    // A stranger with no groups and no keys, settings with no claims, and an access file
    // in which nothing is reachable by identity alone.
    let path = account_scratch("empties", ACCOUNT_SETTINGS);
    std::fs::write(
        &path,
        r#"{ "version": 1,
              "applications": [ { "name": "mpa", "base": ["https://app.x.com/mpa"],
                "scopes": [ { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"],
                              "access": "restricted" } ] } ],
              "users": [] }"#,
    )
    .expect("write the access fixture");
    let base = account_serve(&path);
    let sentences = [
        (
            "reach",
            "Your sign-in opens no application yet.",
            "Il tuo accesso non apre ancora nessuna applicazione.",
        ),
        (
            "groups",
            "You are in no group.",
            "Non sei in nessun gruppo.",
        ),
        (
            "profile",
            "This deployment shares no profile details.",
            "Questa installazione non condivide dettagli del profilo.",
        ),
    ];
    for (cookie, pick) in [("lang=en", 1), ("lang=it", 2)] {
        let g = account_call_pref(&base, Some("stranger@elsewhere.com"), Some(cookie), None);
        assert_eq!(g.status, 200, "{}", account_readable(&g.body));
        for (id, en, it) in sentences {
            let want = if pick == 1 { en } else { it };
            let s = account_section(&g.body, id);
            assert!(
                s.contains(&format!("<p class=\"muted\">{want}</p>")),
                "{id} ({cookie}) names what is missing in a muted paragraph: {s}"
            );
        }
        let page = account_readable(&g.body);
        assert!(
            !page.contains("None.") && !page.contains("Nessuno."),
            "the bare word for none is gone ({cookie}): {page}"
        );
    }

    cleanup(&path);
}

/// Reach, groups and profile are flat lists in the console's own `ul.plain`, one item each.
#[test]
fn the_sections_are_plain_lists() {
    let path = account_scratch_full("plain-lists");
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    for id in ["reach", "groups", "profile"] {
        let s = account_section(&g.body, id);
        assert_eq!(
            s.matches("<ul").count(),
            1,
            "{id} is one list, with no nested one: {s}"
        );
        assert!(
            s.contains("<ul class=\"plain\">"),
            "{id} is a ul.plain: {s}"
        );
    }
    let reach = account_section(&g.body, "reach");
    assert_eq!(
        reach.matches("<li>").count(),
        3,
        "one item per app/scope pair bob reaches: {reach}"
    );
    assert!(
        !reach.contains("<p><code>mpa</code></p>"),
        "the per-application paragraph is gone: {reach}"
    );
    assert!(
        visible_text(&account_section(&g.body, "profile"))
            .contains(&format!("{}: not provided", t(Lang::En, K::AttrGivenName))),
        "a configured but unforwarded claim says not provided: {}",
        account_section(&g.body, "profile")
    );

    cleanup(&path);
}

/// The estate's rule, on every page this step adds and on the refusals beside them: no
/// script tag, and no handler beyond the Preferences menu's. The preference form is the
/// first thing here that a script would be tempting to wire up, so the rule is walked across
/// every variant.
#[test]
fn account_every_look_and_preference_page_carries_no_script_and_only_the_menu_handler() {
    let path = account_scratch("nojs-look", ACCOUNT_SETTINGS_THEME_DARK);
    let base = account_serve(&path);
    let brand = account_scratch("nojs-brand", ACCOUNT_SETTINGS_BRAND);
    let brand_base = account_serve(&brand);

    // Only queries that are not a choice: a real one is answered with a `302` and no body.
    let pages: [(Option<&str>, Option<&str>, &str, u16); 7] = [
        (Some("bob@x.com"), None, "", 200),
        (Some("bob@x.com"), Some("theme=light"), "", 200),
        (Some("bob@x.com"), Some("lang=it"), "", 200),
        (Some("bob@x.com"), None, "?theme=purple", 200),
        (Some("bob@x.com"), None, "?lang=xx", 200),
        (None, None, "", 401),
        (Some("spammer@x.com"), None, "", 403),
    ];
    for root in [&base, &brand_base] {
        for (identity, cookie, query, want) in pages {
            let url = if query.is_empty() {
                root.to_string()
            } else {
                format!("{root}{query}")
            };
            let g = account_call_pref(&url, identity, cookie, Some("it"));
            assert_eq!(
                g.status,
                want,
                "{identity:?} at {url} with cookie {cookie:?}: {}",
                account_readable(&g.body)
            );
            assert!(
                !g.body.to_ascii_lowercase().contains("<script"),
                "{identity:?} at {url}: no script tag, the page works with scripting off: {}",
                account_readable(&g.body)
            );
            assert!(
                account_extra_handlers(&g.body).is_empty(),
                "{identity:?} at {url}: the only handler is the Preferences one: {:?}",
                account_extra_handlers(&g.body)
            );
        }
    }

    cleanup(&path);
    cleanup(&brand);
}

/// The new wording §13.26 §5 gives, spelled out here because this module may not add `K`
/// variants, and the coder adds them. Each literal is the designer's sentence, so a key
/// added with different words fails the test that names it.
const PROFILE_SUB: &str = "What your sign-in tells your applications about you.";

/// The row of actions at the foot of an outcome page, and the spacing rule the screenshot
/// review of §13.30 §4 added (WCAG 2.5.8, target spacing).
///
/// maud writes no whitespace between siblings, so pills written straight into one paragraph
/// touch borders and read as one control. A row of **two or more** therefore rides in
/// `div.actions`, which `admin.css` gives `gap:12px` and the confirmation page's form already
/// uses; `p.primary` stays only where there is a single pill, which is the shape the rest of
/// the estate's pages already have. Zero pills is a page that offers nothing (the done page
/// where the operator named no logout destination), and gets neither container.
fn assert_action_row(who: &str, body: &str, count: usize) {
    let main = the_main(body);
    let page = account_readable(body);
    let primary = controls_with_class(&main, "p", "primary");
    let actions = controls_with_class(&main, "div", "actions");
    match count {
        0 => assert!(
            primary.is_empty() && actions.is_empty(),
            "{who}: no actions, so no row of them: {page}"
        ),
        1 => {
            assert_eq!(
                primary.len(),
                1,
                "{who}: one action sits in one p.primary: {page}"
            );
            assert!(
                actions.is_empty(),
                "{who}: one pill needs no gap, so no div.actions: {page}"
            );
        }
        n => {
            assert_eq!(
                actions.len(),
                1,
                "{who}: {n} actions sit in one div.actions, whose gap separates them: {page}"
            );
            assert!(
                primary.is_empty(),
                "{who}: {n} pills written into p.primary touch borders: {page}"
            );
        }
    }
    // The container named above is the one holding the pills the person sees, not an empty one
    // standing beside a row that stayed where it was.
    let rows = the_page_actions(body);
    assert_eq!(
        rows.len(),
        if count == 0 { 0 } else { 1 },
        "{who}: the page's actions are one row: {page}"
    );
    let held: usize = rows
        .iter()
        .map(|a| controls_with_class(a, "a", "pill").len())
        .sum();
    assert_eq!(
        held, count,
        "{who}: the row holds exactly the {count} actions the page offers: {page}"
    );
}
