use super::*;

// ---------------------------------------------------------------------
// Slice 14b (docs/ARCHITECTURE.md §13.32 §1 §4, §13.33 §3): a deletion that queued
// everything signs this browser out by itself. The `POST` answers a `303` to the gate's
// logout with the gate's sign-in page as its `rd`, so the gate clears the cookie (it is the
// only program that knows the cookie's name and builds the clearing `Set-Cookie`) and the
// person lands on the sign-in page with the notice, never on a page that asks them to sign
// out. Three things follow and are each pinned below: only the **full success** redirects
// (a partial one offers "Try again", and the retry is a walk over the header's addresses,
// which needs the session); a deployment with no `BB_AUTH_WEB_LOGOUT_URL` keeps the done
// page, because there is nowhere to send the browser; and bb-auth-web sends no `Set-Cookie`
// of its own (§13.32 §1's rejected option (b): a second builder of a clearing cookie).
//
// The words of the two `200` rows of §13.30 §4 moved to the notice, in `login.html`
// (§13.33 §3), so no test here asserts them: what is left on the page side is the
// no-logout-URL page, whose last sentence is reworded because the cookie carries `Max-Age`
// and so outlives a closed browser.
//
// The journal lines this flow writes (`user rm`, `N queued`) are on stderr, as every
// mutation line in this program is, so no over-the-socket test can read them (the same
// limit the key-rotation tests record). The effects those lines describe are asserted
// instead, in the access file and at the intake.
// ---------------------------------------------------------------------

/// §13.32 §4: a deletion where every address was answered `202` ends in a `303` to the
/// logout, for a roster user and for a stranger, in both languages. Nothing about the answer
/// depends on who: no page is rendered, so there is nothing for the redirect to translate,
/// which is the same reason the notice is one code (§13.33 §1).
///
/// The walk is asserted as well as the answer. The redirect is not a shorter path: the row
/// still has to go before the first `POST`, and every address still has to be queued, since
/// a `303` that skipped the work would look identical to a browser.
#[test]
fn a_complete_deletion_answers_with_the_gates_logout() {
    let at = |port: u16| format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");

    // The roster user: two addresses, so a walk of two `whoami` and two `POST`, and a row
    // the page writes out. A fixture per language, because the row goes on the first drive
    // and the second would be answered by the `409` that says so.
    for lang in [Lang::En, Lang::It] {
        let intake = FakeIntake::answering(vec![
            (WHOAMI_PATH, whoami_ok()),
            (DELETE_PATH, delete_accepted()),
        ]);
        let path = account_scratch_roster(&format!("delete-14b-roster-{}", lang.code()));
        let port = account_port_intake_at(&path, &intake.endpoint());
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
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
            303,
            "{}: every POST answered 202, so the answer is a redirect: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            g.header("Location"),
            Some(DELETE_LOGOUT_LOCATION),
            "{}: the gate's logout, and its own sign-in page as the round trip",
            lang.code()
        );
        assert!(
            g.body.is_empty(),
            "{}: the answer is a redirect, not a page that asks to be signed out: {:?}",
            lang.code(),
            g.body
        );
        assert!(
            g.cookies().is_empty(),
            "{}: the gate clears the cookie, and only the gate: it is the program that \
                 knows the cookie's name and builds the clearing Set-Cookie (§13.32 §1b): {:?}",
            lang.code(),
            g.cookies()
        );
        // The work is the same work it was: the redirect replaces the page, not the walk.
        assert_eq!(
            intake.at(),
            vec![WHOAMI_PATH, WHOAMI_PATH, DELETE_PATH, DELETE_PATH],
            "{}: both addresses checked and queued before the redirect: {:?}",
            lang.code(),
            intake.at()
        );
        let doc = bb_auth_core::read_access_file(&path)
            .expect("the file the write left parses with the gate's own parser");
        let uuids: Vec<&String> = doc.users.iter().map(|u| &u.uuid).collect();
        assert!(
            !uuids.contains(&&ACCOUNT_BOB.to_string()),
            "{}: the row is out of the file: {uuids:?}",
            lang.code()
        );
        let _ = std::fs::remove_file(&path);
    }

    // The stranger: one address, no row, and the same answer. One fixture serves both
    // languages, because this walk writes nothing to the file and cannot go stale.
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_full("delete-14b-stranger");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = at(port);
    let rev = rev_of(&path);
    let before = read(&path);
    let fields = [
        ("rev", rev.as_str()),
        ("uuid", ""),
        ("confirm_email", "stranger@elsewhere.com"),
    ];
    for lang in [Lang::En, Lang::It] {
        let seen = intake.calls().len();
        let g = account_post_lang(&url, "stranger@elsewhere.com", &fields, lang);
        assert_eq!(
            g.status,
            303,
            "{}: a stranger with every address queued gets the same redirect: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            g.header("Location"),
            Some(DELETE_LOGOUT_LOCATION),
            "{}: the redirect names nothing about the caller, so it is the same bytes for \
                 both",
            lang.code()
        );
        assert!(
            g.cookies().is_empty(),
            "{}: no Set-Cookie here either: {:?}",
            lang.code(),
            g.cookies()
        );
        assert_eq!(
            intake.at_since(seen),
            vec![WHOAMI_PATH, DELETE_PATH],
            "{}: asked, queued, redirected: {:?}",
            lang.code(),
            intake.at_since(seen)
        );
    }
    assert_eq!(
        read(&path),
        before,
        "a caller the file has no row for leaves its bytes alone"
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.32 §4: the `rd` is **added to** the operator's logout URL, not written over it, and
/// it lands inside the query, not after the fragment. The operator's own `rd` (the console's
/// round trip) is gone, cut by `logout_without_rd` at startup, and ours appears exactly
/// once: a URL carrying two `rd` parameters is one whose meaning depends on which half of
/// the estate reads it first.
///
/// `x=1` is there so the builder has to notice a query already exists and join with `&`.
/// The `#f` is there so it has to put the fragment **last**, which is the half a textual
/// append gets wrong: `?x=1&rd=…#f` sends the browser to the login page, `…#f&rd=…` sends
/// it to the fragment and drops the notice.
#[test]
fn the_deletion_rd_is_added_to_the_operators_query() {
    // The bytes the answer must carry, spelled out: the operator's `x=1` kept, the console's
    // `rd=/admin` gone, ours in its place, and the fragment after the query.
    const WANT: &str =
        "https://auth.x.com/auth/logout?x=1&rd=%2Fauth%2Flogin%3Fnotice%3Daccount-deleted#f";
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_full("delete-14b-operator-query");
    let port = account_port_intake_logout(
        &path,
        &intake.endpoint(),
        Some("https://auth.x.com/auth/logout?x=1&rd=/admin#f"),
    );
    let rev = rev_of(&path);
    let g = account_post(
        &format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete"),
        Some("stranger@elsewhere.com"),
        &[
            ("rev", rev.as_str()),
            ("uuid", ""),
            ("confirm_email", "stranger@elsewhere.com"),
        ],
    );
    assert_eq!(
        g.status,
        303,
        "an absolute logout URL changes nothing about the answer: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.header("Location"),
        Some(WANT),
        "the operator's query kept, the console's `rd` gone, ours added once, the fragment \
             last"
    );
    let location = g.header("Location").unwrap_or_default();
    assert_eq!(
        location.matches("rd=").count(),
        1,
        "the operator's `rd` is replaced, not joined to: {location}"
    );
    assert!(
        !location.contains("/admin"),
        "the console's landing page is not on the wire after a deletion: {location}"
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.32 §1 and §13.33 §3: with no `BB_AUTH_WEB_LOGOUT_URL` there is nowhere to send the
/// browser, so the `200` done page stays, in both languages, for a roster user and for a
/// stranger, with the rows §13.33 §3's table names and **no pill** (the bar's account menu
/// is the only sign-out left, and it is chrome, not the page's action).
///
/// The page's last sentence is the reworded one (§13.33 §1: "close your browser to end it"
/// was false, the cookie carries `Max-Age`), so the words that are pinned are "until the
/// session ends", and the words that are **banned** are the closing advice, in both
/// languages: a page that tells a person to close the browser tells them to do something
/// that does not end the session.
#[test]
fn with_no_logout_url_the_done_page_stays() {
    let at = |port: u16| format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");

    for lang in [Lang::En, Lang::It] {
        // The roster user: `NowGone` first, because the write is the half that is already
        // true when the page is drawn (§13.30 §4).
        let intake = FakeIntake::answering(vec![
            (WHOAMI_PATH, whoami_ok()),
            (DELETE_PATH, delete_accepted()),
        ]);
        let path = account_scratch_roster(&format!("delete-14b-nologout-roster-{}", lang.code()));
        let port = account_port_intake_logout(&path, &intake.endpoint(), None);
        let rev = rev_of(&path);
        let g = account_post_lang(
            &at(port),
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
            200,
            "{}: no logout URL, so a page: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_QUEUED_TITLE_EN, DELETE_QUEUED_TITLE_IT),
            "{}: being deleted, not deleted: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            the_page_lede(&g.body),
            format!(
                "{} {} {}",
                m(lang, DELETE_NOW_GONE_EN, DELETE_NOW_GONE_IT),
                m(lang, DELETE_QUEUED_EN, DELETE_QUEUED_IT),
                m(lang, DELETE_CLOSE_EN, DELETE_CLOSE_IT)
            ),
            "{}: what went, then the queue, then this browser: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert!(
            controls_with_class(&the_main(&g.body), "a", "pill").is_empty(),
            "{}: nowhere to send the browser, so the page offers no pill: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert!(
            !the_main(&g.body).contains(&format!("href=\"{ACCOUNT_PAGE}\"")),
            "{}: the page offers no way back to a page about an account that is going: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_no_closing_advice(&the_page_words(&g.body), lang);
        let _ = std::fs::remove_file(&path);

        // The stranger: no row, so no `NowGone`, and the same page otherwise.
        let path = account_scratch_full(&format!("delete-14b-nologout-stranger-{}", lang.code()));
        let port = account_port_intake_logout(&path, &intake.endpoint(), None);
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
        assert_eq!(
            g.status,
            200,
            "{}: no logout URL, so a page: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            the_page_lede(&g.body),
            format!(
                "{} {}",
                m(lang, DELETE_QUEUED_EN, DELETE_QUEUED_IT),
                m(lang, DELETE_CLOSE_EN, DELETE_CLOSE_IT)
            ),
            "{}: a stranger has no keys and no access given by name: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert!(
            controls_with_class(&the_main(&g.body), "a", "pill").is_empty(),
            "{}: no URL, so no pill: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert!(
            !the_main(&g.body).contains(&format!("href=\"{ACCOUNT_PAGE}\"")),
            "{}: this page is the end of the account, not a step back into it: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_no_closing_advice(&the_page_words(&g.body), lang);
        let _ = std::fs::remove_file(&path);
    }
}

/// The page must not tell anybody to close the browser: the sentence's replacement says the
/// session ends, and the cookie carries `Max-Age` (`build_cookie`), so closing the browser
/// ends nothing (§13.33 §1). Checked case-insensitively over the words a person reads, in
/// the language they read them in.
fn assert_no_closing_advice(words: &str, lang: Lang) {
    let needle = match lang {
        Lang::En => "close",
        Lang::It => "chiudi",
    };
    assert!(
        !words.to_ascii_lowercase().contains(needle),
        "{}: the page says nothing about closing the browser: {words}",
        lang.code()
    );
}

/// §13.32 §1: **only** the full success signs the browser out. The first `POST` refused,
/// after the row went, is the `502` partial page, and it has to stay a page: its "Try
/// again" pill is the stranger's walk over the header's addresses, and that walk is a
/// request the gate admits by the session cookie. A `303` through the logout here would
/// sign out the person who was told to try again.
///
/// The words of this row are pinned by `each_delete_outcome_states_its_result_in_the_h1`;
/// what is pinned here is the absence of the redirect, and the Sign out pill that stands in
/// its place: the person signs out by hand, when they have finished retrying.
#[test]
fn a_partial_deletion_does_not_sign_out() {
    let lang = Lang::En;
    let intake = FakeIntake::answering(vec![(WHOAMI_PATH, whoami_ok())]);
    intake.in_order(DELETE_PATH, vec![delete_refused(503)]);
    let path = account_scratch_roster("delete-14b-partial");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let rev = rev_of(&path);
    let g = account_post_lang(
        &format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete"),
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
        "the intake refused the record, so the page says so: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.header("Location"),
        None,
        "a page that offers a retry signs nobody out"
    );
    let pills = the_action_pills(&g.body);
    let got: Vec<String> = pills.iter().map(|p| visible_text(p)).collect();
    assert_eq!(
        got,
        vec![t(lang, K::AccountDeleteRetry), t(lang, K::SignOut)],
        "the retry, then the sign out the person takes themselves: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        attr(open_tag(&pills[0]), "href").as_deref(),
        Some(format!("{ACCOUNT_PATH}/delete").as_str()),
        "Try again leads back to the confirmation page: {}",
        pills[0]
    );
    assert_eq!(
        attr(open_tag(&pills[1]), "href").as_deref(),
        Some("/auth/logout"),
        "the sign-out pill is the config's URL, `rd` dropped: {}",
        pills[1]
    );
    assert!(
        g.cookies().is_empty(),
        "nothing is cleared on a page that asks for a retry: {:?}",
        g.cookies()
    );
    let doc = bb_auth_core::read_access_file(&path)
        .expect("the file the write left parses with the gate's own parser");
    let uuids: Vec<&String> = doc.users.iter().map(|u| &u.uuid).collect();
    assert!(
        !uuids.contains(&&ACCOUNT_BOB.to_string()),
        "the row went before the POST that was refused: {uuids:?}"
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.28 §4 as §13.34 narrows it: `aria-current` names the current page in the strip, and
/// in the ☰'s copy of the strip, and **nowhere else**. The page's own heading carries the
/// page's own words, in both languages.
///
/// Red for the second half: today the account menu carries a copy of the mark (on its tab
/// rows, and on its System settings row), and the settings page's tab does not exist.
#[test]
fn aria_current_names_the_page() {
    let path = account_scratch_full("aria-current");
    let port = account_port(&path);
    let marked = |markup: &str| -> Vec<String> {
        controls_with_class(markup, "a", "pill")
            .iter()
            .filter(|a| attr(open_tag(a), "aria-current").as_deref() == Some("page"))
            .map(|a| visible_text(a).to_string())
            .collect()
    };

    for (cookie, current) in [
        ("lang=en", t(Lang::En, K::Users)),
        ("lang=it", t(Lang::It, K::Users)),
    ] {
        let g = console_at(port, "admin@x.com", "/users", cookie);
        assert_eq!(g.status, 200, "{cookie}: {}", account_readable(&g.body));
        assert_eq!(
            marked(&the_tab_nav(&g.body, cookie)),
            vec![current.to_string()],
            "{cookie}: exactly one tab is current: {}",
            the_tab_nav(&g.body, cookie)
        );
        assert_eq!(
            marked(&the_nav_panel(&g.body, cookie)),
            vec![current.to_string()],
            "{cookie}: the ☰ marks the same page the strip does: {}",
            the_nav_panel(&g.body, cookie)
        );
        assert!(
            marked(&the_panel(&g.body, cookie)).is_empty(),
            "{cookie}: the account menu marks no page: {}",
            the_panel(&g.body, cookie)
        );
    }

    // The settings page: the tab is current in the strip and in the ☰, in the reader's
    // words, and it wears `.on` beside the attribute.
    for (lang, cookie) in [(Lang::En, "lang=en"), (Lang::It, "lang=it")] {
        let g = console_at(port, "admin@x.com", "/config", cookie);
        assert_eq!(g.status, 200, "{cookie}: {}", account_readable(&g.body));
        let tab_word = t(lang, K::ConfigTab);
        let strip = the_tab_nav(&g.body, cookie);
        assert_eq!(
            marked(&strip),
            vec![tab_word.to_string()],
            "{cookie}: Settings is the current tab: {strip}"
        );
        assert_eq!(
            marked(&the_nav_panel(&g.body, cookie)),
            vec![tab_word.to_string()],
            "{cookie}: the ☰ marks Settings current: {}",
            the_nav_panel(&g.body, cookie)
        );
        assert!(
            marked(&the_panel(&g.body, cookie)).is_empty(),
            "{cookie}: the account menu names no current page: {}",
            the_panel(&g.body, cookie)
        );
        let row = controls_with_class(&strip, "a", "pill")
            .into_iter()
            .find(|a| attr(open_tag(a), "aria-current").as_deref() == Some("page"))
            .expect("the current tab");
        assert!(
            attr(open_tag(&row), "class")
                .is_some_and(|c| c.split_whitespace().any(|word| word == "on")),
            "{cookie}: the current tab wears .on: {row}"
        );

        // One name per place, and the tab is not it. The heading and the `<title>` read the
        // page's words, which are deliberately **not** the tab's: the tab has to fit the
        // strip, and the heading can say what the page is (§13.34 §4).
        let word = t(lang, K::Config);
        assert_ne!(
            word, tab_word,
            "{cookie}: the page's words and the tab's are two words, by design"
        );
        let h1 = elements(&g.body, "<h1", "</h1>");
        assert_eq!(h1.len(), 1, "{cookie}: {}", account_readable(&g.body));
        assert_eq!(visible_text(&h1[0]), word, "{cookie}: {}", h1[0]);
        let title = elements(&g.body, "<title>", "</title>");
        assert_eq!(title.len(), 1, "{cookie}");
        assert!(
            visible_text(&title[0]).contains(word),
            "{cookie}: the title reads the same word: {}",
            title[0]
        );
    }

    // The words themselves, pinned in both languages (§13.28 §8, §13.34 §4).
    assert_eq!(t(Lang::En, K::Config), "System settings");
    assert_eq!(t(Lang::It, K::Config), "Impostazioni di sistema");
    assert_eq!(t(Lang::En, K::AccountMenu), "account menu");
    assert_eq!(t(Lang::It, K::AccountMenu), "menu dell'account");
    let _ = std::fs::remove_file(&path);
}

/// §13.28 §3 and step 13: the Preferences form is **one form on both surfaces**, handler and
/// all. The console's keeps its one handler and its `noscript` way round, and so does
/// `/account/`'s: picking a theme or a language submits, and the Apply is what a browser
/// running no code sees. The flag that used to make the page plain is gone, so the two
/// panels are asserted against each other rather than against two rules.
#[test]
fn the_preferences_form_is_scripted_on_both_surfaces() {
    let path = account_scratch_full("prefs-form");
    let port = account_port(&path);
    let base = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/");

    let g = console_get(port, "admin@x.com", &[]);
    let prefs = nested_block(
        &the_panel(&g.body, "console"),
        "<details class=\"prefs\">",
        "details",
    );
    assert_eq!(
        handlers_in(&prefs),
        vec![
            format!("onchange=\"{SETTINGS_ONCHANGE}\""),
            format!("onchange=\"{SETTINGS_ONCHANGE}\"")
        ],
        "the console's two list boxes carry the one handler: {prefs}"
    );
    assert!(
        prefs.contains("<noscript>"),
        "and the way round it is inside noscript: {prefs}"
    );

    let g = account_call(&base, Some("bob@x.com"));
    let prefs = nested_block(
        &the_panel(&g.body, "account"),
        "<details class=\"prefs\">",
        "details",
    );
    assert_eq!(
        handlers_in(&prefs),
        vec![
            format!("onchange=\"{SETTINGS_ONCHANGE}\""),
            format!("onchange=\"{SETTINGS_ONCHANGE}\"")
        ],
        "the page's two list boxes carry the same one handler the console's do: {prefs}"
    );
    assert!(
        prefs.contains("<noscript>"),
        "and its Apply hides behind noscript, as the console's does: {prefs}"
    );
    let actions = controls_with_class(&prefs, "div", "actions");
    assert_eq!(
        actions.len(),
        1,
        "one actions block, inside the noscript: {prefs}"
    );
    assert!(
        prefs.contains("<noscript>")
            && prefs.find("<noscript>").unwrap() < prefs.find("div class=\"actions\"").unwrap(),
        "the block is the noscript's: {prefs}"
    );
    assert_eq!(
        visible_text(&actions[0]),
        t(Lang::En, K::Apply),
        "{}",
        actions[0]
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.28 §6 (slice L): the console's bar carries `ui.logo_url`, and its policy permits that
/// one source. The account page's policy is what it was, and the console's is unchanged when
/// nothing is configured, so the widening is exactly as wide as the setting.
#[test]
fn the_console_shows_the_logo_and_permits_it() {
    // Configured: the logo sits in the brand, before the name, and `img-src` names its
    // source beside the `data:` that was already there.
    let path = account_scratch("logo-set", ACCOUNT_SETTINGS_BRAND);
    let port = account_port(&path);
    let g = console_get(port, "admin@x.com", &[]);
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let top = the_header_bar(&g.body, "console");
    let brand = the_brand(&top, "console");
    let img = elements(&brand, "<img", ">");
    assert_eq!(img.len(), 1, "the brand holds the logo: {}", brand);
    assert_eq!(
        attr(open_tag(&img[0]), "src").as_deref(),
        Some("https://assets.badbat75.com/logo.png"),
        "{}",
        img[0]
    );
    assert_eq!(
        attr(open_tag(&img[0]), "alt").as_deref(),
        Some(""),
        "the name beside it says what the picture is: {}",
        img[0]
    );
    assert!(
        brand.find("<img").unwrap() < brand.find("BadBat75").unwrap(),
        "the logo is left of the name: {}",
        brand
    );
    let csp = g.header("Content-Security-Policy").expect("a policy");
    assert!(
        csp.contains("img-src https://assets.badbat75.com data:"),
        "img-src is the logo's source followed by data:: {csp}"
    );
    // The page's own policy already did this, and does it the same way.
    let a = account_call(
        &format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/"),
        Some("bob@x.com"),
    );
    assert_eq!(a.status, 200, "{}", account_readable(&a.body));
    assert!(
        a.header("Content-Security-Policy")
            .expect("a policy")
            .contains("img-src https://assets.badbat75.com data:"),
        "the account page's policy is unchanged: {}",
        a.header("Content-Security-Policy").unwrap()
    );
    // And the same mark in the same slot of the account bar: `brand_block` is one function
    // for both shells (§13.28 §7), so an operator who sets `ui.logo_url` once sees it in
    // both bars, and a logo that arrived by two routes is two rules to keep in step.
    let top = the_header_bar(&a.body, "account");
    let img = elements(&top, "<img", ">");
    assert_eq!(img.len(), 1, "the account bar carries the logo too: {top}");
    assert_eq!(
        attr(open_tag(&img[0]), "src").as_deref(),
        Some("https://assets.badbat75.com/logo.png"),
        "{top}"
    );
    assert!(
        top.find("<img").unwrap() < top.find("BadBat75").unwrap(),
        "the logo is left of the brand name: {top}"
    );
    cleanup(&path);

    // Not configured: no image, and `img-src data:` exactly as today on both surfaces.
    let path = account_scratch("logo-unset", ACCOUNT_SETTINGS);
    let port = account_port(&path);
    for (label, g) in [
        ("console", console_get(port, "admin@x.com", &[])),
        (
            "account",
            account_call(
                &format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/"),
                Some("bob@x.com"),
            ),
        ),
    ] {
        assert_eq!(g.status, 200, "{label}: {}", account_readable(&g.body));
        let top = the_header_bar(&g.body, label);
        assert!(!top.contains("<img"), "{label}: no logo in the bar: {top}");
        assert!(
            g.header("Content-Security-Policy")
                .expect("a policy")
                .contains("img-src data:;"),
            "{label}: img-src is data: and nothing else: {}",
            g.header("Content-Security-Policy").unwrap()
        );
    }
    cleanup(&path);
}

/// §13.28 §4 as §13.34 §10 moves it: the bar is **one row by construction**, and the
/// breakpoint where the tabs leave it is the measured one. `flex-wrap:nowrap` means no
/// operator's font, brand or person's name can make a second line; at 883px the five-tab
/// worst case (Italian, the longest brand measured, a logo, the longest given name) stops
/// fitting, and the tabs move into the ☰.
///
/// The `@media(min-width:884px)` block is pinned with it, because it is what the breakpoint
/// is measured *by*, and §13.34 §12d rewrote what is in it: the brand's slot takes
/// `flex-shrink:0` so a long name never costs the tabs their room, and the account end
/// carries the bar's give at the default rate. `nav.acct{flex-shrink:100}` used to sit there,
/// and a shrink factor is a multiplier, not a budget, so the account end gave 100 parts in
/// 101: the name pill lost the person's name at 883 while the brand's words were being cut
/// beside it, with the bar's own give unused. Below the breakpoint the ☰ regime keeps
/// proportional shrinking, which is why the rules are scoped and not top level.
///
/// The panel is pinned here too, because §13.34 §0 measured what a floor did with no width:
/// one rule produced a 230px panel on the console and a 286px panel on the account page,
/// because a panel's floor was its trigger's width, and the account page's trigger carries a
/// longer word than the console's name pill. One declared width, capped to the viewport, is
/// the fix, so this asserts the **absence** of `min-width` as much as the presence of `width`.
#[test]
fn the_bar_stays_one_row_at_every_width() {
    let scoped = css_scoped(CSS);
    // A rule's last compound, per comma-part: the declarations belong to the box the last
    // name names, and this stylesheet shares declarations across comma-lists.
    let compounds = |sel: &str| -> Vec<String> {
        sel.split(',')
            .map(|p| {
                p.rsplit(['>', '+', '~', ' '])
                    .next()
                    .unwrap_or(p)
                    .to_string()
            })
            .collect()
    };

    let bar = top_rule(&scoped, ".bar");
    assert_eq!(
        css_decl(&bar, "flex-wrap").as_deref(),
        Some("nowrap"),
        "the bar cannot make a second row: {bar}"
    );

    // The breakpoint is 883px, and the one it replaced is **gone**: a stale 941px block
    // hides the strip at a width where the ☰ is the only navigation, which is a bar with
    // tabs and no room for them, and a 900px window that the measurement says fits.
    let at = "@media(max-width:883px)";
    let media: Vec<&String> = scoped
        .iter()
        .map(|(a, _, _)| a)
        .filter(|a| a.starts_with("@media"))
        .collect();
    assert!(
        scoped.iter().any(|(a, _, _)| a == at),
        "{at}: admin.css breaks where the five tabs stop fitting: {media:?}"
    );
    for stale in ["@media(max-width:941px)", "@media(max-width:800px)"] {
        assert!(
            !media.iter().any(|a| a.as_str() == stale),
            "the {stale} block moved to 883px, it did not join it: {media:?}"
        );
    }

    // In it, the strip is out and the ☰ is in. Both by declaration, so the pair cannot be
    // half-written: a strip hidden with nothing to replace it is a bar with no navigation.
    let hidden = rules_setting(&scoped, at, "display", "none");
    assert!(
        hidden.iter().any(|(sel, _)| {
            compounds(sel)
                .iter()
                .any(|c| c.starts_with("nav") && !c.contains("nav.acct") && !c.contains("navm"))
        }),
        "{at}: the bar's tab strip is hidden: {hidden:?}"
    );
    let shown = rules_setting(&scoped, at, "display", "flex");
    assert!(
        shown
            .iter()
            .any(|(sel, _)| compounds(sel).iter().any(|c| c.contains("navm"))),
        "{at}: the ☰ appears in the bar: {shown:?}"
    );
    let navm = rule_named(&scoped, "", "nav.navm");
    assert_eq!(
        css_decl(&navm, "display").as_deref(),
        Some("none"),
        "outside the breakpoint the ☰ is not in the bar at all, so it costs the bar no room: \
             {navm}"
    );

    // Above it, the bar's give, in its own block. §13.34 §12d: the brand's slot **never**
    // shrinks, so the room the five tabs need is never taken from the deployment's name, and
    // the account end carries the give at the default rate. The `nav.acct{flex-shrink:100}`
    // that used to sit in this block is the bug this replaces: a shrink factor is a
    // multiplier and not a budget, so the account end gave 100 parts in 101, and a long
    // brand cost the name pill the person's name at 883 while the brand's words were being
    // cut beside it. The rule is therefore an **absence**, because `flex-shrink:1` is the
    // default: nothing in this block may name the account end's shrink at all.
    //
    // These rules are read with [`the_rule`] for the top level, whose `flex` shorthand needs
    // its whitespace; the scoped reader is what sees inside an at-rule block.
    let at_desktop = "@media(min-width:884px)";
    assert!(
        scoped.iter().any(|(a, _, _)| a == at_desktop),
        "{at_desktop}: the give the tag line used to be is scoped to the widths the ☰ is not \
             in the bar: {media:?}"
    );
    for (a, sel, body) in &scoped {
        if a == at_desktop && sel.split(',').any(|p| p.trim() == "nav.acct") {
            assert!(
                css_decl(body, "flex-shrink").is_none(),
                "{at_desktop}: the account end gives way at the default rate, so the brand is \
                     never cut while the name pill has room left: {sel}: {body}"
            );
        }
    }
    let brand_desktop = rule_named(&scoped, at_desktop, ".brand");
    assert_eq!(
        css_decl(&brand_desktop, "flex-shrink").as_deref(),
        Some("0"),
        "{at_desktop}: the brand's slot is the part of the bar that never gives: {brand_desktop}"
    );
    // Its cap is a **formula**, never the reading of one width: §13.34 §12a measured the tab
    // strip at 334px in English and 359 in Italian against a brand cap of 224px, so the fixed
    // part of the bar is 558px and the slot's box is `100% - 39.25rem`. At 884 that is 258px,
    // the 2px of slack the measurement leaves; at 1280 it is 653px, the room this design stops
    // spending a breakpoint over. A constant read off 884 is the number that cuts a name a
    // wide bar has room to show.
    let console_brand = rule_named(&scoped, at_desktop, ".bar:has(nav.tabs a) .brand");
    assert_eq!(
        css_decl(&console_brand, "max-width").as_deref(),
        Some("calc(100%-39.25rem)"),
        "{at_desktop}: the brand's slot is the bar's own width less what the tabs and the \
             account end take: {console_brand}"
    );
    let acct = the_rule(CSS, "nav.acct").expect("admin.css styles the account end of the bar");
    assert!(
        acct.contains("flex:0 1 auto"),
        "the account end shrinks, and the scoped rule narrows that, it does not replace it: \
             {acct}"
    );
    assert!(
        acct.contains("min-width:0"),
        "the account end can shrink below its content: {acct}"
    );

    // The panel is **one width**, declared, with a viewport cap for the narrowest phone, and
    // no floor measured against a trigger.
    let menu = top_rule(&scoped, ".menu");
    assert_eq!(
        css_decl(&menu, "width").as_deref(),
        Some("20rem"),
        "the panel is a declared width, so it is one box on every page: {menu}"
    );
    assert_eq!(
        css_decl(&menu, "max-width").as_deref(),
        Some("calc(100vw-32px)"),
        "and it cannot outgrow a phone: {menu}"
    );
    assert!(
        css_decl(&menu, "min-width").is_none(),
        "no floor measured against a trigger: that is the 230px/286px drift §13.34 §0 \
             measured: {menu}"
    );

    // The ☰ opens from the bar's left edge, the account menu from its right. One shared
    // `right:0` would push the ☰'s panel off the screen on a phone.
    let navm_menu = rule_named(&scoped, "", "details.navmenu .menu");
    assert_eq!(
        css_decl(&navm_menu, "left").as_deref(),
        Some("0"),
        "the ☰'s panel is anchored under the ☰: {navm_menu}"
    );
    assert_eq!(
        css_decl(&navm_menu, "right").as_deref(),
        Some("auto"),
        "and not at the right edge as well: {navm_menu}"
    );

    // The ☰'s rows are always the column, so `div.menu-tabs` carries no display rule that
    // hides it anywhere: it lives in one panel now, and a `display:none` there is a phone
    // whose ☰ opens on an empty box.
    for (a, sel, body) in &scoped {
        if sel.split(',').any(|part| part.ends_with(".menu-tabs")) {
            assert_eq!(
                css_decl(body, "display").as_deref(),
                Some("flex"),
                ".menu-tabs is the column in every rule that names it: {sel} in {a}: {body}"
            );
            assert_eq!(
                css_decl(body, "flex-direction").as_deref(),
                Some("column"),
                "{sel} in {a}: {body}"
            );
        }
    }
}

/// §13.28 §1 and §4: what gives when the bar runs out of room, in order. The name pill
/// shrinks with an ellipsis, then the brand's text; the tabs and the logo never shrink, and
/// the identity is never hidden outright (the phone rule that did that hides the trigger
/// now, because the name **is** the trigger).
///
/// §13.34 §12 changes two of the numbers and swaps the phone's half. The brand's cap is a
/// `max()`, never the reading of one width: `14rem` is the floor (the longest name worth
/// reading) and `100% - 10.5rem` is what the narrowest bar that shows the tabs has left, so
/// a name that fits at 1280 is not cut at 884 by a constant somebody measured there. And at
/// 640px and below the **words** give way while the mark stays, the shape the user
/// chose for §13.34 §12g on 2026-11-27, which puts the bar's phone arm back as it stood
/// before step 19 (option (c): no script, so a mark that answers `404` on a phone leaves the
/// brand with the empty box it paints).
#[test]
fn the_bar_gives_room_by_shrinking_the_ellipsis_pieces() {
    let scoped = css_scoped(CSS);

    // `text-overflow` needs exactly these companions, and a box that cannot shrink below its
    // content shows no ellipsis at all.
    for sel in [".who-name", ".brand .t"] {
        let rule = top_rule(&scoped, sel);
        for (prop, want) in [
            ("overflow", "hidden"),
            ("text-overflow", "ellipsis"),
            ("white-space", "nowrap"),
        ] {
            assert_eq!(
                css_decl(&rule, prop).as_deref(),
                Some(want),
                "{sel} needs {prop}:{want} to cut at all: {rule}"
            );
        }
    }
    let (sel, trigger) = trigger_cap(&scoped, "", "16rem");
    assert_eq!(
        css_decl(trigger, "min-width").as_deref(),
        Some("0"),
        "the trigger ({sel}) is the bar's first give: {trigger}"
    );
    // The brand's cap, in the form the design writes it: a floor and the room the bar has
    // left, whichever is wider. `10.5rem` is the bar's own padding and gaps (32px) plus the
    // mark's box (96px) rounded up, so the words are capped by the space the slot can
    // actually take and not by a number read off one screenshot.
    let brand = top_rule(&scoped, ".brand");
    assert_eq!(
        css_decl(&brand, "max-width").as_deref(),
        Some("max(14rem,100%-10.5rem)"),
        "the brand's cap is a floor and the bar's room, not a constant: {brand}"
    );
    assert_eq!(
        css_decl(&brand, "min-width").as_deref(),
        Some("0"),
        "and a flex item with no `min-width` cannot shrink to it: {brand}"
    );

    // The phone block: a tighter cap on the name pill, and the **words** give way while the
    // mark stays, the shape the user chose for §13.34 §12g. The words go by the clip pattern,
    // which is the row's own `flex-shrink:0`: with them off the row, the ellipsis pieces and
    // nothing else are what gives, so the cap arithmetic above is the whole budget.
    let at = "@media(max-width:640px)";
    trigger_cap(&scoped, at, "11rem");
    let hidden = rule_named(&scoped, at, ".brand:has(img) .t");
    assert_eq!(
        css_decl(&hidden, "flex-shrink").as_deref(),
        Some("0"),
        "the words that go must not be the part that shrinks, or the row spends room on a \
             name nobody sees: {hidden}"
    );
    for (a, sel, body) in &scoped {
        if a == at && sel.contains(".brand img") {
            panic!("{sel} at {at} is the rule §13.34 §12g's reversal takes back: {body}");
        }
    }

    // The rule that hid the identity on a phone hides the trigger outright now.
    for (a, sel, body) in &scoped {
        if sel.split(',').any(|p| p.ends_with("nav.acct .who")) {
            panic!("{sel} in {a} is the rule §13.28 deletes: {body}");
        }
    }
}

/// §13.34 §12g's follow-up (the designer's review of step 19, 2026-11-27): on a phone the
/// words give way, so the **mark is the whole brand**, and the slot that holds it has to be as
/// wide as the mark. It is not. The slot is one of the bar's give (`min-width:0`, and the cap
/// above it), and the mark never shrinks (`.brand img` is `flex:none`), so on the phone's
/// crowded first line the slot is the piece the row spends, and the mark is left standing
/// outside the box that was shrunk under it. Measured at 320 with a mark and the long given
/// name: the slot came to **86px** in the designer's review and 87px in this suite's own run,
/// while the mark is capped at 96px; the mark's right edge landed at x=147 and the name pill's
/// left edge at x=145, so the brand paints over the left border of the one control the phone's
/// whole panel is reached through.
///
/// `flex-shrink:0` is the row's arithmetic, the same reasoning the hidden words two rules up
/// already carry: a part that cannot shrink is not the part the row may spend. `:has(img)` is
/// what makes it safe, and it is the reason the rule is scoped to a slot carrying a mark: with
/// no `ui.logo_url` there is no mark, the phone shows the **words**, and a slot that cannot
/// shrink there spends the name pill's room instead of its own, which is the one control the
/// phone's whole panel is reached through (§13.28: the trigger is the identity). The rule
/// belongs in the phone arm alone, because above 640 the words share the slot and the cap's
/// arithmetic is the whole budget.
///
/// Two facts about the reach of this pin, both measured on 2026-11-27 rather than assumed. It
/// is a stylesheet pin, so it says nothing about the layout: the browser's side, including the
/// 2px overlap and the mark's 96px box, is `thePhoneMarkStaysClearOfThePill` in
/// `e2e/tests/settings.js`. And it does **not** pin the `:has(img)` scoping: a `.brand` rule
/// with the same declaration, written in the same phone block, leaves the whole settings area
/// green (418/418), because every phone brand walk in that area runs on the fixture's built-in
/// brand, which is short, and a short brand under the cap never needs the slot to shrink. A
/// slice that needs the scoping defended has to add the walk that measures it (a long brand,
/// no logo, the long given name, at 320, reading the pill's floor).
#[test]
fn the_phone_brand_slot_with_a_mark_keeps_the_marks_room() {
    let scoped = css_scoped(CSS);
    let at = "@media(max-width:640px)";
    let slot = rule_named(&scoped, at, ".brand:has(img)");
    assert_eq!(
        css_decl(&slot, "flex-shrink").as_deref(),
        Some("0"),
        "the phone's brand slot holds a mark that cannot shrink, so the slot must not shrink \
             either, or the mark leaves the box and lands on the pill: {slot}"
    );
}

/// §13.28 §2: the panel's glyphs are the bar's glyphs, and the bar's rule does not reach
/// them. `.bar .who svg` sizes the caret in the trigger; the panel's own rows (the sliders on
/// the Preferences row, the door on Sign out) sit inside `details.settings`, so they are
/// `.menu svg` and nothing else. An `svg` with no box is 300x150: the 2026-11-26 review
/// measured the Sign out glyph at 170x170, which pushes every row of a 230px panel out of the
/// viewport, and the sliders and the caret, drawn with `fill` and no `stroke`, answer as a
/// black dot and a black triangle. The declarations are the base sheet's `.pill.ico svg`, at
/// the panel's own size.
#[test]
fn the_panel_glyphs_are_sized_and_stroked() {
    let scoped = css_scoped(CSS);
    let rule = rule_named(&scoped, "", ".menu svg");
    for (prop, want) in [
        ("width", "1em"),
        ("height", "1em"),
        ("fill", "none"),
        ("stroke", "currentColor"),
        // A stroke with no width paints nothing, and the outline is the whole drawing: the
        // glyph names no colour, so `currentColor` at width 2 is all there is to see.
        ("stroke-width", "2"),
        // The panel's rows are flex boxes; a glyph with no `flex` is squeezed by a long row.
        ("flex", "none"),
    ] {
        assert_eq!(
            css_decl(&rule, prop).as_deref(),
            Some(want),
            ".menu svg sets {prop}:{want}: {rule}"
        );
    }
    // The glyph rides beside the row's word, so it needs the gap the word's own box does not
    // give it. The panel's rows are full-width blocks, so the space has to be a margin.
    let pill = rule_named(&scoped, "", ".menu .pill svg");
    assert_eq!(
        css_decl(&pill, "margin-right").as_deref(),
        Some(".5em"),
        "the glyph sits off the word it names: {pill}"
    );
}

/// §13.28 §4: the tab strip never wraps and never shrinks, and the bar's give is at the other
/// end. `nav{flex-wrap:wrap}` is the base row's rule and is right for the account end (two
/// controls, room to spare); the strip is the piece the design says is never cut, and a
/// wrapped strip is a strip whose second row hangs under the bar's height. The 2026-11-26
/// review measured exactly that from 804 to 900px: a long brand, a logo and a long given name
/// leave the strip too little room, `wrap` makes it two rows, and the bar is 76px tall.
/// `min-width:max-content` is the half that makes `nowrap` cost anything: a flex item's floor
/// is its content, so without it the strip is squeezed and its pills overflow their box in
/// silence, which is a cut tab nobody can read.
#[test]
fn the_tab_strip_never_wraps_and_never_shrinks() {
    let scoped = css_scoped(CSS);
    let tabs = rule_named(&scoped, "", "nav:not(.acct)");
    assert_eq!(
        css_decl(&tabs, "flex-wrap").as_deref(),
        Some("nowrap"),
        "the strip cannot make a second row: {tabs}"
    );
    assert_eq!(
        css_decl(&tabs, "min-width").as_deref(),
        Some("max-content"),
        "the strip is never squeezed below what its tabs need: {tabs}"
    );

    // The room has to come from somewhere, and it is the account end's: a flex item with no
    // `min-width` cannot give an inch, so the trigger's 16rem cap is a cap the box never goes
    // under while the tabs wrap. `flex:0 1 auto` is the row's own half of that (the tabs are
    // `flex:1 1 auto`, which takes the space that is left; this row never should).
    //
    // These two rules are read with [`the_rule`] and not `css_scoped`: the scoped reader
    // strips a declaration body's whitespace, and a `flex` shorthand's three numbers survive
    // that only as `01auto`, which is not a value anything can check.
    let acct = the_rule(CSS, "nav.acct").expect("admin.css styles the account end of the bar");
    assert!(
        acct.contains("flex:0 1 auto"),
        "the account end shrinks, so the tabs do not have to: {acct}"
    );
    assert!(
        acct.contains("min-width:0"),
        "the account end can shrink below its content: {acct}"
    );
    let settings = the_rule(CSS, "details.settings").expect("admin.css styles the panel box");
    assert!(
        settings.contains("min-width:0"),
        "the box that holds the trigger gives room too: {settings}"
    );
}

/// §13.34 §12g, the user's option (c) of 2026-11-27, restoring the shape of §13.28 §4: at
/// 640px and below a bar that carries a mark hides the brand's **words**, and the mark stays.
/// The words go by the clip pattern (`base.css`'s `.vh`: a 1px box, `overflow:hidden`, a
/// `clip-path`), and the two properties that would take them out of the accessibility tree,
/// `display` and `visibility`, must not appear on it. That pairing is the whole decision: the
/// image carries `alt=""`, so the words are the bar's only name, and hiding them from a reader
/// too is the empty brand §12g's option (b) was built to avoid, while option (c)'s accepted
/// cost is only the **sightless** case of a mark that answers `404` on a phone.
///
/// The pattern lives inside the phone arm and nowhere else. `position:absolute` is not a
/// width, so a rule at the top level takes the words out of the row at 1280 as much as at 320,
/// which is the §12c bug: a deployment with a logo had no brand name on the console at any
/// width, and a broken mark made that bar nameless everywhere.
///
/// §13.34 §10 removes the tag line the 2026-11-26 review found left standing, so this pins
/// the **absence** of a rule for it as much as the presence of the one for the name: a
/// stylesheet rule naming an element no page renders is the half of that fix nobody keeps
/// fixed, and the slot's second line comes back one edit at a time.
///
/// And the panel's tab rows need no gap (§13.28 §2): `.menu .pill` carries
/// `margin-bottom:4px`, so a `gap` on the row stacks a second space between rows and the
/// panel's rows stop reading as the one list they are.
#[test]
fn the_words_hide_with_a_logo_and_the_panel_rows_need_no_gap() {
    let scoped = css_scoped(CSS);
    let at = "@media(max-width:640px)";

    // The phone's rule: the words exist to be hidden, and hidden by the pattern that keeps
    // them in the accessibility tree.
    let hidden = rule_named(&scoped, at, ".brand:has(img) .t");
    for (prop, want) in [
        ("position", "absolute"),
        ("width", "1px"),
        ("height", "1px"),
        ("overflow", "hidden"),
        ("clip-path", "inset(50%)"),
    ] {
        assert_eq!(
            css_decl(&hidden, prop).as_deref(),
            Some(want),
            "the words are hidden by the clip pattern, and {prop} is part of it: {hidden}"
        );
    }
    for prop in ["display", "visibility"] {
        assert!(
            css_decl(&hidden, prop).is_none(),
            "the words carry the bar's only name (the image's `alt` is empty), and {prop} \
                 takes that name out of the accessibility tree: {hidden}"
        );
    }

    // And only on a phone: a bar with room shows its name.
    for (a, sel, body) in &scoped {
        if a != at && sel.split(',').any(|part| part.contains(".brand:has(img)")) {
            panic!(
                "{sel} in {a:?} hides the brand's words where the bar has the room to \
                       show them: {body}"
            );
        }
    }

    // The mark's own name is empty, because the words beside it say what it is, and on a
    // phone they are the only name the bar has.
    let brand = brand_block("BadBat75 Operations Console", Some("/img/logo.svg"), "").into_string();
    assert!(
        brand.contains("alt=\"\""),
        "the mark names itself, so the words the bar hides are not its only name: {brand}"
    );

    // No rule, at any width, names the tag line: `admin.css` styled `.brand .v` at the top
    // level and hid it under 641px, and both are the markup's own history now.
    for (a, sel, _) in &scoped {
        for part in sel.split(',') {
            assert!(
                !part.contains(".brand .v") && !part.contains(".brand:has(img) .v"),
                "{sel} in {a:?} styles a tag line the bar no longer has"
            );
        }
    }

    // No `.menu-tabs` rule, at any width, stacks a gap on top of the rows' own margin.
    for (a, sel, body) in &scoped {
        if sel.split(',').any(|part| part.trim() == ".menu-tabs") {
            if let Some(gap) = css_decl(body, "gap") {
                assert_eq!(
                    gap, "0",
                    "{sel} in {a} adds a second space between the panel's rows: {body}"
                );
            }
        }
    }
}

/// §13.34 §12d: the brand's slot is a row that never wraps, on **both** surfaces. The bar is
/// `flex-wrap:nowrap`, but a child that wraps makes its own second line inside that row, and
/// every child of a centred flex row keeps the same centre, so the row count the suite
/// measures stays at one while the bar grows 40px taller and takes that much from the page
/// below it. `.selfserve-brand` carried `flex-wrap:wrap` to put the account id under the
/// mark, and the bar's brand slot is the same box.
#[test]
fn the_brand_slot_never_wraps() {
    let scoped = css_scoped(CSS);
    for (a, sel, body) in &scoped {
        for part in sel.split(',') {
            // The box a rule paints is its last compound, and the sheet names the
            // account page's slot `.brand.selfserve-brand`, so both spellings count.
            let last = part
                .rsplit(['>', '+', '~', ' '])
                .next()
                .unwrap_or(part)
                .trim();
            if last.contains("brand") {
                assert_ne!(
                    css_decl(body, "flex-wrap").as_deref(),
                    Some("wrap"),
                    "{sel} in {a:?} lets the brand's slot wrap, which grows the bar a second \
                         line while its children stay centred: {body}"
                );
            }
        }
    }
}

/// §13.28 §6: one rule sizes the logo on both surfaces, bounded by **height** so a wide
/// wordmark cannot eat the tabs' room, and `flex:none` so the bar never squeezes it.
#[test]
fn the_logo_is_bounded_by_height() {
    let scoped = css_scoped(CSS);
    let rule = top_rule(&scoped, ".brand img");
    for prop in ["height", "max-width", "flex"] {
        assert!(
            css_decl(&rule, prop).is_some(),
            ".brand img sets {prop}: {rule}"
        );
    }
    assert_eq!(
        css_decl(&rule, "flex").as_deref(),
        Some("none"),
        "the logo never shrinks: {rule}"
    );
    assert_eq!(
        css_decl(&rule, "width").as_deref(),
        Some("auto"),
        "the height is the bound, not the width: {rule}"
    );
    // The account page's own rule is replaced by this one, not added to it.
    assert!(
        !scoped
            .iter()
            .any(|(_, sel, _)| sel == ".selfserve-brand img"),
        "one rule sizes the logo on both surfaces"
    );
}

/// §13.28 §2: "Auto" is the theme that follows the operating system, and the option has to
/// say so. The bare word answers nothing when a person is choosing between three options.
#[test]
fn the_auto_theme_says_what_it_follows() {
    assert_eq!(t(Lang::En, K::ThemeSystem), "Auto (system)");
    assert_eq!(t(Lang::It, K::ThemeSystem), "Auto (sistema)");

    // And the word is what the page shows, in both languages.
    let path = account_scratch_full("theme-word");
    let port = account_port(&path);
    for (label, cookie, word) in [
        ("English", "lang=en", "Auto (system)"),
        ("Italian", "lang=it", "Auto (sistema)"),
    ] {
        let g = console_get(port, "admin@x.com", &[("Cookie", cookie)]);
        assert_eq!(g.status, 200, "{label}: {}", account_readable(&g.body));
        // The option element, not a substring: the selected one carries `selected` beside
        // its `value`, so a literal `<option value="system">` is not what the page spells.
        let mut sels = elements(&g.body, "<select name=\"theme\"", "</select>");
        assert_eq!(sels.len(), 1, "{label}: one theme select");
        let opts = elements(&sels.remove(0), "<option", "</option>");
        let sys: Vec<String> = opts
            .iter()
            .filter(|o| attr(open_tag(o), "value").as_deref() == Some("system"))
            .cloned()
            .collect();
        assert_eq!(sys.len(), 1, "{label}: one system option: {opts:?}");
        assert_eq!(
            visible_text(&sys[0]),
            word,
            "{label}: the theme option reads {word}: {}",
            account_readable(&g.body)
        );
    }
    let _ = std::fs::remove_file(&path);
}
