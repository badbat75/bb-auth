use super::*;

// --------------------------------------------------------------- §13.15 ----
//
// Three things in one slice: the copy control is an icon, the key's duration
// is a choice made from five, and revoking a key from the self-service page
// asks first. Each test below is named for the item §13.15 gives it, so the
// red before the coder lands is a name that does not exist yet, and not a
// typo in a fixture.

/// A [`Form`] out of pairs, for the tests that call a form reader directly.
fn form_of(fields: &[(&str, &str)]) -> Form {
    Form(
        fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

/// [`duration_from_form`]'s answer as a shape a test can compare.
///
/// `K` carries no `PartialEq` (it is a translation key, not a value anyone
/// compares), so a refusal is named by its variant. That is also what a
/// failure prints: the key the form answered with, which is the thing the
/// person on the other end of the form sees.
fn dur_answer(fields: &[(&str, &str)]) -> Result<String, &'static str> {
    duration_from_form(&form_of(fields)).map_err(|k| match k {
        K::KeyDurationRequired => "KeyDurationRequired",
        K::KeyDaysWithoutCustom => "KeyDaysWithoutCustom",
        K::KeyDaysInvalid => "KeyDaysInvalid",
        _ => "some other key",
    })
}

/// The reveal's copy control is an **icon**, and an icon needs a name.
///
/// §13.15 replaces the text button with a box carrying two inline SVGs, a
/// copy glyph and a done glyph, and no visible words. Everything that made
/// the text button usable has to be put back on purpose: a name for the
/// assistive technology and a `title` for a sighted pointer, because a box
/// with no visible text has no accessible name; `aria-hidden="true"
/// focusable="false"` on each glyph, because a decorative shape that takes a
/// tab stop is a trap; and a separate `role="status"` span for the word the
/// script writes, because a word written **into** the button replaces the
/// icon the person is looking at. The glyphs carry no colour of their own:
/// the stylesheet paints them, which is what keeps the palette the only
/// place a colour is named.
///
/// §13.17 says **how** the name is carried: text inside the control in
/// `span.vh`, plus a `title` with the same words, and **no `aria-label`**.
/// One mechanism, not two, because the header's Preferences trigger is a
/// `summary`, which has no implicit ARIA role, so an `aria-label` there is
/// not a name every reader exposes while text content is. The box is the
/// shared `pill ico` component, so its 24px minimum (WCAG 2.5.8) lives in
/// `base.css` with the component and not in a rule of the reveal's: the
/// reveal keeps only the glyph swap on `data-state`.
///
/// The button is served `hidden` and only the script shows it, which is the
/// half that keeps the scripting-off page honest: an icon nobody can press
/// is worse than no icon.
///
/// All four reveals, through [`reveal_cases`]: the console's mint and rotate
/// and the self-service page's two. One of the four missing the name is the
/// same bug as all four, and the console is the surface a person with no
/// administrator in the room never sees.
#[test]
fn the_copy_control_is_an_icon_with_a_name() {
    let (cases, paths) = reveal_cases("copy-icon");
    for (label, g) in &cases {
        let btn = element_containing(&g.body, "id=\"bearer-copy\"", "</button>");
        let open = tag_containing(&btn, "id=\"bearer-copy\"");
        assert!(
            open.starts_with("<button") && open.contains("type=\"button\""),
            "{label}: still a button, and a bare `button` is a submit button: {open}"
        );
        assert!(
            open.contains("hidden=\"hidden\"") || open.contains(" hidden"),
            "{label}: served hidden, because the script is the only thing that can \
                 make this icon work: {open}"
        );
        assert!(
            attr(&open, "class").is_some_and(|c| c == "pill ico"),
            "{label}: the copy control is the shared icon component, not a box of its \
                 own: {open}"
        );
        assert!(
            !open.contains("aria-label"),
            "{label}: the name is text inside the control, so no second naming mechanism \
                 is left to drift out of step with it: {open}"
        );
        assert_eq!(
            visible_text(&btn),
            "Copy the key",
            "{label}: the name is written inside the control, hidden visually, which is \
                 the one naming mechanism every reader exposes: {btn}"
        );
        assert!(
            open.contains("title=\"Copy the key\""),
            "{label}: and the same words are what a pointer shows, for the person using \
                 a mouse: {open}"
        );
        assert_eq!(
            controls_with_class(&btn, "span", "vh").len(),
            1,
            "{label}: exactly one span of hidden words, so the control has one name and \
                 not two: {btn}"
        );
        assert!(
            !visible_text(&btn).contains("Copied") && !visible_text(&btn).contains("Copy refused"),
            "{label}: the words the click writes belong to the status span, never to the \
                 control: {btn}"
        );

        for glyph in ["i-copy", "i-done"] {
            let svg = element_containing(&btn, &format!("class=\"{glyph}\""), "</svg>");
            assert!(
                svg.starts_with("<svg"),
                "{label}: `{glyph}` is an inline SVG, not an image from a host: {svg}"
            );
            assert!(
                svg.contains("viewBox=\"0 0 24 24\""),
                "{label}: `{glyph}` is drawn on the grid the stylesheet sizes it to: \
                     {svg}"
            );
            assert!(
                svg.contains("aria-hidden=\"true\"") && svg.contains("focusable=\"false\""),
                "{label}: `{glyph}` is decoration, so it is hidden from the \
                     accessibility tree and takes no tab stop: {svg}"
            );
            assert!(
                !svg.contains("fill=") && !svg.contains("stroke=") && !svg.contains("style="),
                "{label}: `{glyph}` names no colour, so the palette stays the only \
                     place one is defined: {svg}"
            );
        }

        let status = tag_containing(&g.body, "id=\"bearer-copy-status\"");
        assert!(
            status.starts_with("<span") && status.contains("role=\"status\""),
            "{label}: the word the click writes lands in a live region beside the \
                 icon, not inside it: {status}"
        );
        let at = g
            .body
            .find("id=\"bearer-copy-status\"")
            .expect("the status span is served");
        let rest = &g.body[at..];
        let inner = &rest[rest.find('>').expect("the span opens") + 1
            ..rest.find("</span>").expect("the span closes")];
        assert_eq!(
            inner.trim(),
            "",
            "{label}: the status is empty as served, because it says what the last \
                 click did and no click has happened"
        );
        // The two words the click writes are attributes, because the markup is
        // rendered server-side and translated, and the script is a constant that
        // knows no language. A missing attribute is a click that writes nothing.
        for (attr, word) in [("data-done", "Copied"), ("data-failed", "Copy refused")] {
            assert!(
                open.contains(&format!("{attr}=\"{word}")),
                "{label}: the button carries `{attr}` starting with the words the \
                     click puts in the status span: {open}"
            );
        }
        assert!(
            g.body.contains(COPY_SCRIPT),
            "{label}: the script is on the page that shows the icon"
        );
    }

    // The component's CSS is a stylesheet fact, and the stylesheet is the only place one
    // can read it from Rust. §13.17 moves the sizing into the shared `.pill.ico` in
    // `base.css` (both programs emit it) and deletes the reveal's own `.secret .copy`
    // rules, so both halves are pinned: the rule that exists, and the ones that must not.
    let ico = the_rule(BASE_CSS, ".pill.ico").expect("base.css defines the icon component");
    assert!(
        ico.contains("min-width:24px") && ico.contains("min-height:24px"),
        "an icon target is at least 24 by 24 CSS pixels (WCAG 2.5.8), and the minimum is \
             in the component so no call site can forget it: {ico}"
    );
    let glyph = the_rule(BASE_CSS, ".pill.ico svg").expect("base.css sizes the glyph");
    assert!(
        glyph.contains("stroke:currentColor") && glyph.contains("fill:none"),
        "the glyph is painted by the palette, so a token file repaints it and \
             `THEME_CSS` stays the only place a colour is named: {glyph}"
    );
    let vh = the_rule(BASE_CSS, ".vh").expect("base.css defines the hidden-text utility");
    assert!(
        !vh.contains("display:none"),
        "the name is hidden by geometry, not by `display:none`, which would hide it from \
             the assistive technology the whole mechanism exists to feed: {vh}"
    );
    assert!(
        the_rule(CSS, ".bar .pill.ico").is_some(),
        "the console's bar sizes its own icons square, in the stylesheet that owns the bar"
    );
    for (sheet, name) in [(BASE_CSS, "base.css"), (CSS, "admin.css")] {
        assert!(
            the_rule(sheet, ".secret .copy").is_none(),
            "{name} no longer sizes the copy control: §13.17 gave it to the shared \
                 component, and a second answer to how big an icon is is the drift this \
                 repository keeps writing rules about"
        );
    }
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

/// Every icon control in the estate is named by **hidden text**, in the reader's language.
///
/// §13.17 puts every glyph in one component (`pill ico`), and what makes a glyph usable
/// is the naming, not the shape: a decorative `svg` must be out of the accessibility tree
/// and out of the tab order, and the control's name must be content a reader exposes, not
/// an attribute whose support varies by element (the header's Preferences trigger is a
/// `summary`, which has no implicit ARIA role at all).
///
/// The assertions run over **every** `.pill.ico` in the document rather than over a list
/// of controls this test names, for two reasons: the header's icons land in slice 8b and
/// are covered the day they exist, and a control added by an edit that forgets its name
/// fails here, in Rust, rather than in a screen reader in front of the page. The header is
/// deliberately not asserted today: a test that required it would be red for a slice that
/// has not been built.
///
/// The name is checked **translated**, on the Italian page, because the words are the
/// page's and go through the `K` table. An icon whose name stays English on an Italian
/// page is the same untranslated text the 4b screenshot caught in a field label, and a
/// glyph is worse: it carries no word of its own to translate.
#[test]
fn icon_controls_are_named_by_hidden_text() {
    let (cases, mut paths) = reveal_cases("icon-names");
    let mut docs: Vec<(String, String)> = cases
        .iter()
        .map(|(label, g)| (format!("the {label} reveal"), g.body.clone()))
        .collect();

    // The keys table, with a key in it to revoke, in both languages.
    let path = account_scratch_access("icon-names", &account_access_keys());
    paths.push(path.clone());
    let base = account_serve(&path);
    for (label, lang) in [("English", "en"), ("Italian", "it")] {
        let g = account_call_pref(
            &base,
            Some("bob@x.com"),
            Some(&format!("lang={lang}")),
            None,
        );
        assert_eq!(
            g.status,
            200,
            "bob reaches his own keys page, in {label}: {}",
            account_readable(&g.body)
        );
        docs.push((format!("the account keys table in {label}"), g.body));
    }

    // The header (8b-1, 8b-2) as §13.28 §2-§3 rebuilt it: its rows are no longer icon-only,
    // so they are not in the walk below. They are checked by the rule that replaced the
    // hidden-name one: a glyph in the header is decoration beside a **visible** word, and
    // that word is the reader's language. The panel is closed in the markup, so the rows are
    // read out of the source, which is what every other assertion in this file does.
    let path = account_scratch_full("icon-names-console");
    paths.push(path.clone());
    let port = account_port(&path);
    for (lang, code) in [(Lang::En, "en"), (Lang::It, "it")] {
        let g = console_get(port, "admin@x.com", &[("Cookie", &format!("lang={code}"))]);
        assert_eq!(
            g.status,
            200,
            "the console answers the admin: {}",
            account_readable(&g.body)
        );
        check_header_glyphs(&g.body, lang, "console");
    }

    // `/account/`: the same rows, the same rule.
    let path = account_scratch_full("icon-names-account");
    paths.push(path.clone());
    let base = account_serve(&path);
    for (lang, code) in [(Lang::En, "en"), (Lang::It, "it")] {
        let g = account_call_pref(
            &base,
            Some("bob@x.com"),
            Some(&format!("lang={code}")),
            None,
        );
        assert_eq!(g.status, 200, "{}", account_readable(&g.body));
        check_header_glyphs(&g.body, lang, "account");
    }

    for (where_, body) in &docs {
        let icons = controls_with_class(body, "button", "ico")
            .into_iter()
            .chain(controls_with_class(body, "a", "ico"))
            .chain(controls_with_class(body, "summary", "ico"))
            .collect::<Vec<_>>();
        assert!(
            !icons.is_empty(),
            "{where_}: the page under test carries at least one icon control, or this \
                 test is asserting nothing about it"
        );
        for el in &icons {
            let open = open_tag(el);
            for glyph in elements(el, "<svg", "</svg>") {
                assert!(
                    glyph.starts_with("<svg")
                        && glyph.contains("aria-hidden=\"true\"")
                        && glyph.contains("focusable=\"false\""),
                    "{where_}: a glyph is decoration, so it is out of the accessibility \
                         tree and takes no tab stop: {glyph}"
                );
                assert!(
                    !glyph.contains("fill=")
                        && !glyph.contains("stroke=")
                        && !glyph.contains("style="),
                    "{where_}: a glyph names no colour, so the palette stays the only \
                         place one is defined: {glyph}"
                );
            }
            let names = controls_with_class(el, "span", "vh");
            assert_eq!(
                names.len(),
                1,
                "{where_}: the control carries exactly one span of hidden words, so it \
                     has one name and not two: {el}"
            );
            let words = visible_text(&names[0]);
            assert!(
                !words.is_empty(),
                "{where_}: the hidden words are a name, not an empty span: {el}"
            );
            assert_eq!(
                attr(open, "title").as_deref(),
                Some(words.as_str()),
                "{where_}: the pointer tooltip says the same words the reader reads, so \
                     a sighted person and a screen reader are told the same action"
            );
        }
    }

    // The names themselves, and they are the table's words, not the markup's.
    for (label, g) in &cases {
        let btn = element_containing(&g.body, "id=\"bearer-copy\"", "</button>");
        assert_eq!(
            visible_text(&btn),
            t(Lang::En, K::CopyKey),
            "the {label}: the copy control's name is the translation table's entry, so \
                 the Italian reveal names it in Italian: {btn}"
        );
    }
    let it = docs
        .iter()
        .find(|(w, _)| w.ends_with("Italian"))
        .expect("built above");
    let revoke = controls_with_class(&it.1, "a", "ico")
        .into_iter()
        .find(|el| el.contains("/keys/remove"))
        .expect("the keys table's revoke is an icon control (§13.17)");
    assert_eq!(
        visible_text(&revoke),
        format!("{} laptop", t(Lang::It, K::AccountKeyRemove)),
        "the revoke names the key it is about to remove, in the reader's language: a \
             glyph alone says \"×\", which is the same word for close, delete and cancel: \
             {revoke}"
    );
    let en = docs
        .iter()
        .find(|(w, _)| w.ends_with("English"))
        .expect("built above");
    let revoke = controls_with_class(&en.1, "a", "ico")
        .into_iter()
        .find(|el| el.contains("/keys/remove"))
        .expect("the keys table's revoke is an icon control (§13.17)");
    assert_eq!(
        visible_text(&revoke),
        format!("{} laptop", t(Lang::En, K::AccountKeyRemove)),
        "and the English page says the same thing in English: {revoke}"
    );

    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

/// 8b-1 (§13.17, "The identity, added to the console too"), as §13.28 §1 reshaped it: who is
/// signed in is said **once**, as the trigger's label. `who` is pure: the forwarded
/// `given_name` (when the deployment configures that claim) else the FIRST address of
/// `X-Auth-Email`, which may hold several joined by a space; and every address of the header,
/// in order, for the panel that says the rest.
///
/// Red until the coder replaces `identity_label` with `who`: the stub answers nothing, so the
/// label is empty and the panel has no addresses to print.
#[test]
fn the_identity_is_the_given_name_and_the_first_address() {
    assert_eq!(who(Some("Bot"), "bot@example.com").label, "Bot");
    assert_eq!(
        who(Some("Bot"), "bot@example.com alt@example.com").label,
        "Bot",
        "of several addresses only the first is shown, and a name beats both"
    );
    assert_eq!(who(None, "bot@example.com").label, "bot@example.com");
    assert_eq!(
        strings(&who(None, "bot@example.com alt@example.com").emails),
        ["bot@example.com", "alt@example.com"],
        "the panel lists every address, in the header's order"
    );
    assert_eq!(
        who(Some("  "), "bot@example.com").label,
        "bot@example.com",
        "a blank given name is no given name"
    );
    assert_eq!(who(Some(""), "bot@example.com").label, "bot@example.com");
    for given in [Some("Bot"), None, Some("  ")] {
        let label = who(given, "bot@example.com alt@example.com").label;
        assert!(
            !label.contains('\u{b7}'),
            "{given:?}: one fact per line, no joined label: {label}"
        );
    }

    // On a rendered console page: the label is the trigger's `span.who-name`, and the panel's
    // `p.who-full` prints every address. The `span.who` of §13.17 is gone.
    let path = account_scratch_full("identity-label-console");
    let port = account_port(&path);
    for (extra, label) in [
        (vec![("X-Auth-Given-Name", "Ada%20Admin")], "Ada Admin"),
        (vec![], "admin@x.com"),
    ] {
        let g = console_get(port, "admin@x.com admin@alt.com", &extra);
        assert_eq!(g.status, 200, "{}", account_readable(&g.body));
        let nav = the_account_nav(&g.body, "console");
        let names = controls_with_class(&nav, "span", "who-name");
        assert_eq!(names.len(), 1, "the label is in one span.who-name: {nav}");
        assert_eq!(visible_text(&names[0]), label, "{}", names[0]);
        assert!(
            controls_with_class(&nav, "span", "who").is_empty(),
            "the label is the trigger, not a span standing beside it: {nav}"
        );
        let panel = the_panel(&g.body, "console");
        let full = controls_with_class(&panel, "p", "who-full");
        assert_eq!(full.len(), 1, "the panel says who: {panel}");
        for addr in ["admin@x.com", "admin@alt.com"] {
            assert!(
                full[0].contains(addr),
                "every address of the caller is in the panel: {addr}: {}",
                full[0]
            );
        }
        assert!(
            !full[0].contains('\u{b7}'),
            "the panel prints the facts on their own lines, never a joined string: {}",
            full[0]
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// 8c-3 (§13.17, "The console's 403"): a signed-in person who is not on `web.admins` and
/// opens the console gets the `403` with the caller named in the bar (as on every other
/// page), and one way forward, a `p.primary a.pill` to the self-service page. A vetoed
/// caller sees the same page: the console never reads the veto, and the link leads to a
/// page that answers them with its own `403`.
///
/// Red until the coder adds `K::NotAdminToAccount` ("Go to your account", "Vai al tuo
/// account"), `shell_named` and the `403` branch's call to it: the key does not exist, so
/// the test module does not compile (E0599), which is the expected red for this slice.
#[test]
fn the_console_403_names_the_caller_and_links_to_their_account() {
    let path = account_scratch_full("console-403-names");
    let port = account_port(&path);
    let want_href = format!("{ACCOUNT_PATH}/");
    for (label, lang, code) in [("English", Lang::En, "en"), ("Italian", Lang::It, "it")] {
        let cookie = format!("lang={code}");
        for (who, extra, shown) in [
            ("bob@x.com", vec![], "bob@x.com"),
            (
                "bob@x.com",
                vec![("X-Auth-Given-Name", "Bob%20Smith")],
                "Bob Smith",
            ),
            ("bob@x.com carol@x.com", vec![], "bob@x.com"),
            // Vetoed in the fixture: the console does not read the veto, so same page.
            ("spammer@x.com", vec![], "spammer@x.com"),
        ] {
            let mut headers = vec![("Cookie", cookie.as_str())];
            headers.extend(extra);
            let g = console_get(port, who, &headers);
            let ctx = format!("{label}, {who}, {shown}");
            assert_eq!(g.status, 403, "{ctx}: {}", account_readable(&g.body));

            let navs = elements(&g.body, "<nav", "</nav>");
            let acct = elements(&g.body, "<nav class=\"acct\"", "</nav>");
            assert_eq!(acct.len(), 1, "{ctx}: {}", account_readable(&g.body));
            let before = &g.body[..g.body.find("<nav class=\"acct\"").unwrap()];
            let tabs = elements(before, "<nav", "</nav>");
            assert!(
                tabs.iter().all(|n| visible_text(n).is_empty()),
                "{ctx}: the tabs nav before nav.acct is empty: {tabs:?} of {navs:?}"
            );
            let names = controls_with_class(&acct[0], "span", "who-name");
            assert_eq!(
                names.len(),
                1,
                "{ctx}: the caller is named by the trigger: {}",
                acct[0]
            );
            assert_eq!(visible_text(&names[0]), shown, "{ctx}");
            let panel = the_panel(&g.body, &ctx);
            let full = controls_with_class(&panel, "p", "who-full");
            assert_eq!(
                full.len(),
                1,
                "{ctx}: the panel says who the caller is: {panel}"
            );
            assert!(full[0].contains(shown), "{ctx}: {}", full[0]);

            // One way forward: the account page, as the one primary action.
            let primary = controls_with_class(&g.body, "p", "primary");
            assert_eq!(
                primary.len(),
                1,
                "{ctx}: one p.primary: {}",
                account_readable(&g.body)
            );
            let links = controls_with_class(&primary[0], "a", "pill");
            assert_eq!(links.len(), 1, "{ctx}: one a.pill in it: {}", primary[0]);
            assert_eq!(
                attr(open_tag(&links[0]), "href").as_deref(),
                Some(want_href.as_str()),
                "{ctx}: {}",
                links[0]
            );
            assert_eq!(
                visible_text(&links[0]),
                t(lang, K::NotAdminToAccount),
                "{ctx}"
            );

            // Sign out stays, still the console's configured URL, as the panel's row.
            let outs: Vec<String> = controls_with_class(&panel, "a", "pill")
                .into_iter()
                .filter(|el| el.contains("/auth/logout"))
                .collect();
            assert_eq!(outs.len(), 1, "{ctx}: Sign out is kept: {panel}");
            assert_eq!(
                visible_text(&outs[0]),
                t(lang, K::SignOut),
                "{ctx}: the row says Sign out in the reader's language: {}",
                outs[0]
            );
        }
    }
    assert_eq!(t(Lang::En, K::NotAdminToAccount), "Go to your account");
    assert_eq!(t(Lang::It, K::NotAdminToAccount), "Vai al tuo account");
    let _ = std::fs::remove_file(&path);
}

/// 8b-1: the footer keeps the version and no longer says who is signed in (one home for
/// the fact).
#[test]
fn the_console_footer_no_longer_names_the_identity() {
    let html = render("footer-identity", Route::Dashboard);
    let footer = elements(&html, "<footer", "</footer>");
    assert_eq!(footer.len(), 1, "{}", account_readable(&html));
    assert!(
        footer[0].contains(&version_line("bb-auth-web")),
        "the footer keeps the version: {}",
        footer[0]
    );
    assert!(
        !footer[0].contains("admin@x.com") && !footer[0].contains("signed in as"),
        "the footer no longer says who is signed in: {}",
        footer[0]
    );
    // The Italian page too: the words are the table's, not the markup's.
    let path = account_scratch_full("footer-identity-it");
    let port = account_port(&path);
    let g = console_get(port, "admin@x.com", &[("Cookie", "lang=it")]);
    let footer = elements(&g.body, "<footer", "</footer>");
    assert_eq!(footer.len(), 1);
    assert!(
        !footer[0].contains("admin@x.com") && !footer[0].contains("accesso come"),
        "{}",
        footer[0]
    );
    let _ = std::fs::remove_file(&path);
}

/// 8b-2 (§13.17, "The header: the console's, shared"): the console and `/account/` wear one
/// bar from `top_bar`, and differ only where the design says: the brand slot, the (empty)
/// tabs, the Preferences menu's handler, and the Sign out `href`.
///
/// Red until `account_shell` calls `top_bar`: today the account page has no `header.top`.
#[test]
fn both_surfaces_share_one_header() {
    let path = account_scratch_full("shared-header");
    let port = account_port(&path);
    let base = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/");

    let console = console_get(port, "admin@x.com", &[]);
    assert_eq!(console.status, 200, "{}", account_readable(&console.body));
    let acct_page = account_call_with(
        &base,
        Some("bob@x.com"),
        &[("X-Auth-Given-Name", "Bob%20Smith")],
    );
    assert_eq!(
        acct_page.status,
        200,
        "{}",
        account_readable(&acct_page.body)
    );

    let c_top = the_header_bar(&console.body, "console");
    let a_top = the_header_bar(&acct_page.body, "account");
    let c_bar = elements(&c_top, "<div class=\"bar\"", "</div>");
    assert_eq!(c_bar.len(), 1, "console: one div.bar: {c_top}");
    assert!(
        a_top.contains("<div class=\"bar\">"),
        "account: the same `div.bar` inside the header: {a_top}"
    );

    // Brand slot: one shape on both surfaces (§13.34 §10 as §11 overruled it), differing
    // only in the account page's own arrangement class.
    let c_brand = the_brand(&c_top, "console");
    assert!(
        attr(open_tag(&c_brand), "class")
            .is_some_and(|c| c.split_whitespace().collect::<Vec<_>>() == vec!["brand"]),
        "the console's brand slot carries the slot's own class and nothing else: {c_brand}"
    );
    let a_brand = the_brand(&a_top, "account");
    assert!(
        attr(open_tag(&a_brand), "class")
            .is_some_and(|c| c.split_whitespace().any(|w| w == "selfserve-brand")),
        "the account's brand slot is `span.brand.selfserve-brand`: {}",
        a_brand
    );
    assert!(
        visible_text(&a_brand).contains(DEFAULT_ACCOUNT_BRAND),
        "the brand names the deployment: {}",
        a_brand
    );
    assert!(
        !acct_page.body.contains("<header class=\"selfserve-brand\""),
        "the old standalone brand header is gone: {}",
        account_readable(&acct_page.body)
    );

    // Tabs: the console's five pills (§13.28 §4, §13.34); the account's an empty `nav`.
    assert_eq!(
        controls_with_class(&c_top, "nav", "acct").len(),
        1,
        "console: one nav.acct: {c_top}"
    );
    assert_eq!(
        controls_with_class(&the_tab_nav(&console.body, "console"), "a", "pill").len(),
        5,
        "console: the bar keeps five tabs: {}",
        the_tab_nav(&console.body, "console")
    );
    // §13.34 §2 gives the strip its own class so the 883px rule can name it, and §4 says
    // `/account/` keeps that element empty: the same header, with nothing in the strip.
    assert!(
        a_top.contains("<nav class=\"tabs\"></nav>"),
        "account: an empty `nav.tabs` where the tabs would be: {a_top}"
    );
    assert!(
        !a_top.contains("class=\"pill on\""),
        "account: no tab is current: {a_top}"
    );
    // §13.34 §4: and no ☰ either. The navigation menu belongs to the console's tabs, and this
    // page has none, so a ☰ here would be a control that opens on an empty box. Read the
    // header's markup, not the page: every page inlines `admin.css`, whose rules name
    // `details.navmenu` at the top level and in the 883 block, so a substring over the whole
    // document is true of the stylesheet, not of the markup.
    assert!(
        !a_top.contains("<nav class=\"navm\"") && !a_top.contains("navmenu"),
        "account: no navigation menu: {a_top}"
    );
    // §13.34 §2: the account menu's `details` carries the group name on **both** surfaces, so
    // the one shared function emits it unconditionally. The page has no ☰ to trade places
    // with, and an element that changed attributes per caller is not one object.
    assert!(
        a_top.contains("<details class=\"settings\" name=\"bar-menu\""),
        "account: the account menu is in the bar's exclusive group here too: {a_top}"
    );

    // The account end: one menu on each surface, built by one function, so the trigger is
    // class for class the same. The panel's rows are not: the console's carries the places
    // of a console the caller may not reach, and the page's carries none (§13.28 §2).
    let c_acct = the_account_nav(&c_top, "console");
    let a_acct = the_account_nav(&a_top, "account");
    for (label, nav) in [("console", &c_acct), ("account", &a_acct)] {
        let trigger = controls_with_class(nav, "summary", "who");
        assert_eq!(trigger.len(), 1, "{label}: one summary.pill.who: {nav}");
        assert_eq!(
            class_values(&trigger[0]),
            class_values(&controls_with_class(&c_acct, "summary", "who")[0]),
            "{label}: the trigger is the same markup on both surfaces, class for class: \
                 {}",
            trigger[0]
        );
        assert!(
            nav.contains("<details class=\"settings\""),
            "{label}: the outer element stays details.settings: {nav}"
        );
        assert!(nav.contains("<div class=\"menu\""), "{label}: {nav}");
        assert!(
            !nav.contains("<p class=\"lede\""),
            "{label}: the panel is not a lede, so the page keeps its one lede: {nav}"
        );
        // The preferences live in the nested box, in the console's field order.
        let prefs = nested_block(nav, "<details class=\"prefs\">", "details");
        assert!(
            attr(open_tag(&prefs), "open").is_none(),
            "{label}: the nested box is closed by default: {prefs}"
        );
        let lang = prefs.find("<select name=\"lang\"").unwrap_or(usize::MAX);
        let theme = prefs.find("<select name=\"theme\"").unwrap_or(usize::MAX);
        assert!(
            lang < theme && theme != usize::MAX,
            "{label}: Language then Theme: {prefs}"
        );
        // Sign out is a row of the panel, with the word on it, from the same setting.
        let panel = the_panel(nav, label);
        let outs: Vec<String> = controls_with_class(&panel, "a", "pill")
            .into_iter()
            .filter(|el| el.contains("/auth/logout"))
            .collect();
        assert_eq!(
            outs.len(),
            1,
            "{label}: Sign out is one a.pill row: {panel}"
        );
        assert_eq!(
            visible_text(&outs[0]),
            t(Lang::En, K::SignOut),
            "{label}: the row says Sign out: {}",
            outs[0]
        );
    }
    // §13.34: the console's account menu is no longer a list of the console's places. The
    // tabs ride in the ☰, the settings page is a tab, and what is left in this panel is the
    // caller's own page, which is the one place the menu has on both surfaces.
    let c_panel = the_panel(&c_acct, "console");
    let a_panel = the_panel(&a_acct, "account");
    assert!(
        !c_panel.contains("<div class=\"menu-tabs\"")
            && !c_panel.contains(&format!("{ADMIN_BASE}/config")),
        "the console's account menu carries no console place: {c_panel}"
    );
    assert!(
        c_panel.contains(&format!("href=\"{ACCOUNT_PATH}/\"")),
        "the console's account menu carries the caller's own page: {c_panel}"
    );
    assert!(
        !a_panel.contains("menu-tabs") && !a_panel.contains(&format!("{ADMIN_BASE}/config")),
        "the page offers no console place at all: {a_panel}"
    );

    // §13.26 ("F. The flat ground"): the account page's `main` is the console's `main`,
    // class for class, so the ground rule that keyed off a class on this one element has
    // nothing to key on. The bare class is gone from the markup; `selfserve-brand`, the
    // brand slot's own arrangement asserted above, is a different class and not this string.
    for (label, body) in [("console", &console.body), ("account", &acct_page.body)] {
        assert!(
            body.contains("<main>"),
            "{label}: the main carries no class: {}",
            account_readable(body)
        );
    }
    assert!(
        !acct_page.body.contains("class=\"selfserve\""),
        "no element on the account page carries the bare `selfserve` class: {}",
        account_readable(&acct_page.body)
    );
    let _ = std::fs::remove_file(&path);

    // The operator's brand and logo wear the same slot.
    let path = account_scratch("shared-header-brand", ACCOUNT_SETTINGS_BRAND);
    let base = account_serve(&path);
    let g = account_call(&base, Some("bob@x.com"));
    let top = the_header_bar(&g.body, "branded account");
    let brand = controls_with_class(&top, "span", "brand");
    assert_eq!(brand.len(), 1, "{top}");
    assert!(
        brand[0].contains("<img src=\"https://assets.badbat75.com/logo.png\"")
            && visible_text(&brand[0]).contains("BadBat75"),
        "the logo and the brand name are inside the brand slot: {}",
        brand[0]
    );
    cleanup(&path);
}

/// 8b-2 and step 13: the page's **policy** admits the Preferences handler and nothing else.
/// The handler rides in an attribute, so the policy needs `'unsafe-hashes'` beside the hash
/// of [`SETTINGS_ONCHANGE`], and the copy script's hash must not appear: the bearer reveal is
/// the only page that carries that script, and a policy that admitted it everywhere under the
/// prefix would let any page there run it. The form is still a plain `GET` back to the page
/// and still answers the `302` that sets both cookies, and its Apply is the way in for a
/// browser running no code, so the scripting-off path is the one it always was.
#[test]
fn the_account_policy_admits_the_preferences_handler() {
    let path = account_scratch_full("menu-csp");
    let base = account_serve(&path);

    for cookie in ["lang=en", "lang=it"] {
        let g = account_call_pref(&base, Some("bob@x.com"), Some(cookie), None);
        assert_eq!(g.status, 200, "{}", account_readable(&g.body));
        let csp = g.header("Content-Security-Policy").unwrap_or_default();
        assert!(
            csp.contains(&format!(
                "script-src 'unsafe-hashes' {}",
                csp_hash(SETTINGS_ONCHANGE)
            )),
            "{cookie}: the policy admits the one handler the page emits: {csp}"
        );
        assert!(
            !csp.contains(&csp_hash(COPY_SCRIPT)),
            "{cookie}: the copy script is not on this page, and is not admitted: {csp}"
        );
        let top = the_header_bar(&g.body, cookie);
        let menu = elements(&top, "<div class=\"menu\"", "</form>");
        assert_eq!(menu.len(), 1, "{cookie}: one menu with its form: {top}");
        let form = elements(&menu[0], "<form", "</form>");
        assert_eq!(form.len(), 1, "{cookie}: {}", menu[0]);
        let tag = open_tag(&form[0]);
        assert_eq!(attr(tag, "method").as_deref(), Some("get"), "{tag}");
        assert_eq!(
            attr(tag, "action").as_deref(),
            Some(ACCOUNT_PAGE),
            "the form goes back to the account page: {tag}"
        );
        let actions = controls_with_class(&form[0], "div", "actions");
        assert_eq!(actions.len(), 1, "{cookie}: div.actions: {}", form[0]);
        let buttons = elements(&actions[0], "<button", "</button>");
        assert_eq!(
            buttons.len(),
            1,
            "{cookie}: one Apply button: {}",
            actions[0]
        );
        let lang = if cookie == "lang=it" {
            Lang::It
        } else {
            Lang::En
        };
        assert_eq!(
            visible_text(&buttons[0]),
            t(lang, K::Apply),
            "{}",
            buttons[0]
        );
        assert!(
            form[0].contains("<noscript>"),
            "{cookie}: the Apply is the scripting-off way round, so it hides behind \
                 noscript: {}",
            form[0]
        );
    }

    // The foot form is gone: the page's only theme and language selects are the menu's.
    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.body.matches("<select name=\"theme\"").count(),
        1,
        "one theme list box on the page: {}",
        account_readable(&g.body)
    );
    assert_eq!(g.body.matches("<select name=\"lang\"").count(), 1);
    assert!(
        !g.body.contains("selfserve-prefs"),
        "the foot form is gone: {}",
        account_readable(&g.body)
    );

    // Submitting the menu's own fields still answers one 302 that sets both cookies.
    let top = the_header_bar(&g.body, "submit");
    let names: Vec<String> = elements(&top, "<select", ">")
        .iter()
        .filter_map(|s| attr(s, "name"))
        .collect();
    assert_eq!(names, ["lang", "theme"], "{top}");
    let g = account_call(&format!("{base}?lang=it&theme=dark"), Some("bob@x.com"));
    assert_eq!(g.status, 302, "{}", account_readable(&g.body));
    assert_eq!(g.header("Location"), Some(ACCOUNT_PAGE));
    let set = g.cookies();
    assert!(set.iter().any(|c| c.starts_with("theme=dark;")), "{set:?}");
    assert!(set.iter().any(|c| c.starts_with("lang=it;")), "{set:?}");
    cleanup(&path);
}

/// §13.28 §3: the header's controls say what they do **in words**, in the reader's language.
/// §13.17 named them by hidden text, because there the glyph was the whole control. §13.28
/// puts a visible word beside every header glyph, so the half of that pair that applies is
/// the other one: the glyph is decoration, out of the accessibility tree, and a glyph that
/// kept a name of its own would make the row say "Sign out" twice to a reader. The generic
/// walk (`icon_controls_are_named_by_hidden_text`) covers the icon controls that remain,
/// which are the row actions, not the header's.
#[test]
fn the_account_header_says_what_it_does_in_the_readers_language() {
    let path = account_scratch_full("header-words");
    let base = account_serve(&path);
    for (code, lang) in [("en", Lang::En), ("it", Lang::It)] {
        let g = account_call_pref(
            &base,
            Some("bob@x.com"),
            Some(&format!("lang={code}")),
            None,
        );
        assert_eq!(g.status, 200, "{}", account_readable(&g.body));
        check_header_glyphs(&g.body, lang, "account");
        // The icon-only spelling is gone from the bar: a control with a word on it wears no
        // `ico`, because `ico` is the class that says "the glyph is the whole label".
        let top = the_header_bar(&g.body, code);
        for tag in ["summary", "a"] {
            let icons = controls_with_class(&top, tag, "ico");
            assert!(
                icons.is_empty(),
                "{code}: no header control is an icon-only {tag}: {icons:?}"
            );
        }
    }
    cleanup(&path);
}

/// The five choices map onto the file's duration grammar, in one function,
/// and the refusals are named.
///
/// §13.15 puts the mapping in `duration_from_form` because the console and
/// the self-service page mint the same field, and a mapping written twice is
/// two mappings. The presets are stored **verbatim** (`365d`, `182d`, `91d`)
/// so the file keeps the spelling an operator reads in `bb-auth-adm show`; a
/// custom number becomes `<n>d`, and the console's box keeps taking a unit,
/// because twelve hours is a window a deployment genuinely wants and the
/// self-service page is the one that cannot name it.
///
/// The refusals are the half worth reading. An **empty** duration is refused
/// and not read as "no expiry": `parse_duration("")` is `Dur::Never`, so a
/// form that lost its radio would mint a key that never dies, which is the
/// one outcome a person did not ask for and cannot undo from the page. A
/// number typed while a preset is picked is a form that contradicts itself,
/// and an empty custom box is a refusal, not a default.
#[test]
fn the_duration_choice_maps_onto_the_grammar() {
    for preset in ["365d", "182d", "91d"] {
        assert_eq!(
            dur_answer(&[("duration", preset), ("days", "")]),
            Ok(preset.to_string()),
            "a preset is stored as it is spelled, so the file reads the same to \
                 every program that opens it"
        );
    }
    assert_eq!(
        dur_answer(&[("duration", "custom"), ("days", "40")]),
        Ok("40d".to_string()),
        "a custom number is a number of days, which is the unit the file's grammar \
             needs"
    );
    assert_eq!(
        dur_answer(&[("duration", "custom"), ("days", "12h")]),
        Ok("12h".to_string()),
        "the console's box has always taken a unit, and a key for the length of a \
             shift is a real request"
    );
    assert_eq!(
        dur_answer(&[("duration", "never"), ("days", "")]),
        Ok("never".to_string()),
        "no expiry is the file's own word, stored as the file spells it"
    );

    // The empty field is not "no expiry", and a field that is not there at
    // all is the same form, so both are the same refusal.
    let nothing: &[(&str, &str)] = &[];
    for fields in [
        &[("duration", ""), ("days", "")][..],
        nothing,
        &[("days", "40")][..],
    ] {
        assert_eq!(
            dur_answer(fields),
            Err("KeyDurationRequired"),
            "a mint with no duration named is refused, never defaulted: an empty \
                 field is what parse_duration reads as `never`"
        );
    }
    assert_eq!(
        dur_answer(&[("duration", "365d"), ("days", "40")]),
        Err("KeyDaysWithoutCustom"),
        "a number typed while a preset is picked is a form that contradicts itself, \
             and guessing which half the person meant is how a key outlives its reason"
    );

    // The custom box's refusals. `never` is among them: it is a choice, not a
    // number, and a box that accepted it would be a second way to spell one
    // thing, which is the bug this repository keeps writing warnings about.
    for bad in [
        "",
        "0",
        "-3",
        "-",
        "never",
        "abc",
        "40x",
        "999999999999999999999999d",
    ] {
        assert_eq!(
            dur_answer(&[("duration", "custom"), ("days", bad)]),
            Err("KeyDaysInvalid"),
            "`{bad}` is not a number of days"
        );
    }
}

/// A key minted from the self-service page may **never expire**, and the
/// custom box has no upper bound.
///
/// §13.15. The page used to refuse `never` and anything past a year, which
/// was a rule about what a person may decide and not a rule about what the
/// file can hold: `bb-auth-adm` mints a never-expiring key today, so the
/// restriction only ever meant the person with no administrator in the room
/// was told no. The floor stays, because a key that expires in seconds is a
/// key that does not work, and that refusal is this page's own
/// `ACCOUNT_KEY_MIN_SECS`.
///
/// Every refusal here is checked against the file as well as the status: a
/// 400 that wrote a key is a mint that worked.
#[test]
fn a_self_service_key_may_never_expire() {
    let path = account_scratch_access("never-expires", &account_access_mint());
    let base = account_serve(&path);

    // The choice the page offers, minted.
    let rev = sha256_hex(&read(&path));
    let g = account_post(
        &format!("{base}keys"),
        Some("bob@x.com"),
        &[
            ("rev", &rev),
            ("id", "long"),
            ("duration", "never"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(
        g.status,
        200,
        "`never` is a choice the form offers, so the page must accept it: {}",
        account_readable(&g.body)
    );
    let bearer = account_bearer_in(&g.body).to_string();
    let on_disk = read(&path);
    let key = account_key_json(&on_disk, 0, "long");
    assert_eq!(
        key["duration"].as_str(),
        Some("never"),
        "the file carries the word, not a date invented for it: {key}"
    );
    assert_eq!(
        key_expiry(
            key["released"].as_str().expect("a mint stamps a release"),
            "never"
        ),
        Some(None),
        "and the gate's own expiry reads it as no expiry: {key}"
    );
    assert!(
        on_disk.contains(&sha256_hex(&bearer)),
        "and the secret this page handed out is the one that works"
    );

    // No upper bound: a year and a day is a person's decision, not the page's.
    let rev = sha256_hex(&read(&path));
    let g = account_post(
        &format!("{base}keys"),
        Some("bob@x.com"),
        &[
            ("rev", &rev),
            ("id", "far"),
            ("duration", "custom"),
            ("days", "366"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(
        g.status,
        200,
        "the custom box has no ceiling: {}",
        account_readable(&g.body)
    );
    let far = account_key_json(&read(&path), 0, "far");
    assert_eq!(
        far["duration"].as_str(),
        Some("366d"),
        "and it is stored as the grammar spells it: {far}"
    );
    let released = far["released"].as_str().expect("a mint stamps a release");
    // `key_expiry` answers an **absolute instant**, so what a day adds to a year is a
    // day of seconds, not the instant a one-day key happens to expire at.
    let year = key_expiry(released, "365d")
        .and_then(|e| e)
        .expect("a year has an expiry");
    assert_eq!(
        key_expiry(released, "366d").and_then(|e| e),
        Some(year + 86_400),
        "366 days is a year and a day, read the way the gate reads it"
    );
    let on_disk = read(&path);

    // The refusals, each of which writes nothing.
    for (case, days) in [
        ("an empty box", ""),
        ("zero", "0"),
        ("a negative", "-3"),
        ("the word never in the number box", "never"),
        ("letters", "abc"),
    ] {
        let rev = sha256_hex(&read(&path));
        let g = account_post(
            &format!("{base}keys"),
            Some("bob@x.com"),
            &[
                ("rev", &rev),
                ("id", "bad"),
                ("duration", "custom"),
                ("days", days),
                ("restrict", "all"),
            ],
        );
        assert_eq!(g.status, 400, "the custom box refuses {case} (`{days}`)");
        assert_eq!(
            read(&path),
            on_disk,
            "a refused mint writes nothing, so the refusal costs the person nothing"
        );
    }

    // An empty duration field is refused, and is not read as "no expiry".
    let rev = sha256_hex(&read(&path));
    let g = account_post(
        &format!("{base}keys"),
        Some("bob@x.com"),
        &[
            ("rev", &rev),
            ("id", "blank"),
            ("duration", ""),
            ("restrict", "all"),
        ],
    );
    assert_eq!(
        g.status, 400,
        "an empty duration is not a mint with no expiry: that is the one default \
             this page must never take"
    );
    assert_eq!(read(&path), on_disk, "and it wrote nothing");

    // A rotate of a key with no expiry keeps it that way: the window is the
    // key's, and changing the secret is not a decision to end it.
    let rev = sha256_hex(&read(&path));
    let g = account_post(
        &format!("{base}keys/rotate"),
        Some("bob@x.com"),
        &[("rev", &rev), ("id", "long")],
    );
    assert_eq!(
        g.status,
        200,
        "a rotate of a never-expiring key is answered: {}",
        account_readable(&g.body)
    );
    let key = account_key_json(&read(&path), 0, "long");
    assert_eq!(
        key["duration"].as_str(),
        Some("never"),
        "the rotate changed the secret and left the window alone: {key}"
    );
    assert_eq!(
        key_expiry(
            key["released"].as_str().expect("a rotate keeps a release"),
            "never"
        ),
        Some(None),
        "and grew no expiry: {key}"
    );

    cleanup(&path);
}

/// The key form offers **five** choices, on both surfaces, and reads an
/// existing key back into them.
///
/// §13.15. The console's mint, the self-service page's mint, and the
/// console's edit of a key whose duration is one of the five, one of the
/// spellings of "no expiry", and one the five cannot name. The last one is
/// the case a form rewrite loses: `8760h` is a real value in a real file, and
/// a form that shows nothing picked for it is a form that will save `365d`
/// over it the moment the person presses the button.
#[test]
fn the_key_form_offers_five_choices() {
    // --- the console, over a socket: the mint form and the read-backs ------
    let path = scratch("dur-console", SAMPLE);
    let port = serve(&path, ADMIN_BASE);
    let get = |at: Route| -> AccountGot {
        let url = format!("http://127.0.0.1:{port}{ADMIN_BASE}{}", at.path());
        got_of(
            get_with_secret(&url)
                .header(IDENTITY_HEADER, "admin@x.com")
                .call()
                .expect("a GET response"),
        )
    };

    let g = get(Route::KeyAdd(BOB.to_string()));
    assert_eq!(
        g.status,
        200,
        "the mint form is a page: {}",
        account_readable(&g.body)
    );
    assert_duration_choices(&g.body, "365d", "the console's mint form", true);

    // A key whose duration is written another way, rendered from a fixture
    // that says so. The fixture is the sample with one field changed, so the
    // read-back is about the form and not about a second hand-built file.
    let edit = |duration: &str| -> AccountGot {
        let fixture = SAMPLE.replace(
            "\"duration\": \"1d\"",
            &format!("\"duration\": \"{duration}\""),
        );
        let p = scratch(&format!("dur-edit-{duration}"), &fixture);
        let port = serve(&p, ADMIN_BASE);
        let url = format!(
            "http://127.0.0.1:{port}{ADMIN_BASE}{}",
            Route::KeyEdit(BOB.to_string(), "laptop".to_string()).path()
        );
        let g = got_of(
            get_with_secret(&url)
                .header(IDENTITY_HEADER, "admin@x.com")
                .call()
                .expect("a GET response"),
        );
        cleanup(&p);
        g
    };

    let g = edit("91d");
    assert_eq!(g.status, 200, "a key of three months is editable");
    assert_duration_choices(&g.body, "91d", "a key of three months", false);

    let g = edit("never");
    assert_eq!(g.status, 200, "a key that never expires is editable");
    assert_duration_choices(&g.body, "never", "a key that never expires", false);

    // A duration the five cannot name is the custom box, filled in with the
    // file's own bytes.
    let g = edit("8760h");
    assert_eq!(g.status, 200, "a key of a year in hours is editable");
    assert_duration_choices(
        &g.body,
        "custom",
        "a duration only the custom box can name",
        false,
    );
    assert!(
        g.body.contains("value=\"8760h\""),
        "the box carries the duration it is reading back, so saving the form cannot \
             quietly move the expiry"
    );

    // An expired key (`0`, and the `-` a hand-edited file may hold) reads back
    // as no expiry, not as a nonsense number in the box.
    for expired in ["0", "-"] {
        let g = edit(expired);
        assert_eq!(g.status, 200, "an expired key is editable");
        assert_duration_choices(
            &g.body,
            "never",
            &format!("an expired key (`{expired}`)"),
            false,
        );
    }

    // --- the self-service page: the same five, on the page the + opens ------
    //
    // §13.16 moved the mint form out of the keys section and onto its own page,
    // because the row it opens is a row of the keys table. The five choices are
    // the same component on both surfaces, so the read is from `keys/new`.
    let apath = account_scratch_access("dur-account", &account_access_mint());
    let base = account_serve(&apath);
    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "the page renders: {}",
        account_readable(&g.body)
    );
    assert!(
        g.body.contains("keys/new"),
        "the page offers the way to the mint form: {}",
        account_readable(&g.body)
    );
    assert!(
        !g.body.contains("name=\"duration\""),
        "the plain page carries no mint form, so the table is all a person reads \
             before they decide to add a key: {}",
        account_readable(&g.body)
    );
    let g = account_call(&format!("{base}keys/new"), Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "the mint form is a page of its own: {}",
        account_readable(&g.body)
    );
    assert_duration_choices(&g.body, "365d", "the self-service mint form", true);
    assert!(
        !g.body.contains("keys/new"),
        "the page that is the mint form does not offer to open itself again: {}",
        account_readable(&g.body)
    );

    cleanup(&path);
    cleanup(&apath);
}
