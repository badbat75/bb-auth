use super::*;

// ===========================================================================================
// §13.28 (plan step 8, slice H): one account menu in the shared header, on one row.
//
// The bar's identity span, sliders trigger and Sign out icon of §13.17, and the Preferences
// menu's lede of §13.20, become ONE trigger that opens ONE panel: who you are, the console's
// places, Preferences, Sign out. The bar is one row at every width by construction, and the
// console's tabs move into that panel at 800px.
// ===========================================================================================

/// §13.28 §1: the trigger shows **one** string, and the panel says the rest. `who` is the
/// one place that decides which: the given name when nginx forwards one, else the first
/// address, with every address of the header kept for the panel.
///
/// Red until the coder implements `who`: the stub in the file answers nothing, so the label
/// is empty and there are no addresses, which is a behavioural red about the label rule
/// rather than a compile error.
#[test]
fn who_is_the_name_else_the_first_address() {
    let w = who(Some("Ada"), "a@x b@x");
    assert_eq!(w.label, "Ada");
    assert_eq!(strings(&w.emails), ["a@x", "b@x"]);
    assert_eq!(
        w.name.as_deref(),
        Some("Ada"),
        "the panel prints the name alone"
    );
    assert!(
        !w.label.contains('\u{b7}'),
        "no separator in a label: {}",
        w.label
    );

    // No name, or a name that is only whitespace: the first address, as `identity_label`
    // did, for the same reason (a blank is nothing to show).
    for given in [None, Some(""), Some("  "), Some("\t")] {
        let w = who(given, "a@x b@x");
        assert_eq!(w.label, "a@x", "{given:?}");
        assert_eq!(strings(&w.emails), ["a@x", "b@x"], "{given:?}");
        assert_eq!(w.name, None, "{given:?}: a blank is no name");
    }

    // No address at all: nothing to say, and nothing to invent.
    let w = who(None, "  ");
    assert_eq!(w.label, "");
    assert!(w.emails.is_empty(), "{:?}", w.emails);

    // A name with no address is still a name: the trigger shows it, and the panel has no
    // address lines to print.
    let w = who(Some("Ada"), "");
    assert_eq!(w.label, "Ada");
    assert!(w.emails.is_empty(), "{:?}", w.emails);
}

/// §13.28 §3: the trigger is `details.settings > summary.pill.who`; its accessible name is
/// "Ada, account menu" (the visible label first, as WCAG 2.5.3 Label in Name asks); its
/// `title` carries the full label the ellipsis may cut; and the plain `span.who` of §13.17
/// is gone, because a label beside a control is two things where the design has one.
#[test]
fn the_trigger_is_the_label() {
    let path = account_scratch_full("trigger-label");
    let port = account_port(&path);
    let base = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/");

    for (lang, cookie) in [(Lang::En, "lang=en"), (Lang::It, "lang=it")] {
        // The console: the dispatcher's `given` (the `given_name` claim's header, which
        // ACCOUNT_SETTINGS_FULL configures) else the first address of `X-Auth-Email`.
        for (extra, label) in [
            (vec![("X-Auth-Given-Name", "Ada%20Admin")], "Ada Admin"),
            (vec![], "admin@x.com"),
        ] {
            let mut headers: Vec<(&str, &str)> = vec![("Cookie", cookie)];
            headers.extend(extra);
            let g = console_get(port, "admin@x.com admin@alt.com", &headers);
            assert_eq!(
                g.status,
                200,
                "{cookie} {label}: {}",
                account_readable(&g.body)
            );
            check_trigger(&g.body, label, lang, "console");
        }

        // `/account/`: the same rule, from `handle_account`, in both languages.
        for (extra, label) in [
            (vec![("X-Auth-Given-Name", "Bob%20Smith")], "Bob Smith"),
            (vec![], "bob@x.com"),
        ] {
            let mut headers: Vec<(&str, &str)> = extra.iter().map(|(k, v)| (*k, *v)).collect();
            headers.push(("Cookie", cookie));
            let g = account_call_with(&base, Some("bob@x.com bob@old.com"), &headers);
            assert_eq!(
                g.status,
                200,
                "{cookie} {label}: {}",
                account_readable(&g.body)
            );
            check_trigger(&g.body, label, lang, "account");
        }
    }
    let _ = std::fs::remove_file(&path);
}

/// The trigger's shape, asserted the same way on both surfaces.
fn check_trigger(html: &str, label: &str, lang: Lang, at: &str) {
    let nav = the_account_nav(html, at);
    assert!(
        nav.contains("<details class=\"settings\""),
        "{at}: the outer element stays details.settings: {nav}"
    );
    let triggers = controls_with_class(&nav, "summary", "who");
    assert_eq!(triggers.len(), 1, "{at}: one summary.pill.who: {nav}");
    let text = visible_text(&triggers[0]);
    assert!(
        text.starts_with(label),
        "{at}: the visible name starts with the label {label:?}: {}",
        triggers[0]
    );
    assert!(
        text.contains(&format!(", {}", t(lang, K::AccountMenu))),
        "{at}: the accessible name is the label plus the menu word: {}",
        triggers[0]
    );
    assert_eq!(
        attr(open_tag(&triggers[0]), "title").as_deref(),
        Some(label),
        "{at}: the title carries the full label the ellipsis may cut: {}",
        triggers[0]
    );
    assert!(
        !text.contains('\u{b7}'),
        "{at}: no separator, the panel says the rest: {}",
        triggers[0]
    );
    assert!(
        controls_with_class(&nav, "span", "who").is_empty(),
        "{at}: no plain span.who is left in nav.acct: {nav}"
    );
    // The label is in `span.who-name`, the one box the stylesheet caps and cuts.
    let names = controls_with_class(&triggers[0], "span", "who-name");
    assert_eq!(
        names.len(),
        1,
        "{at}: the label is in span.who-name: {}",
        triggers[0]
    );
    assert_eq!(visible_text(&names[0]), label, "{at}: {}", names[0]);
}

/// §13.28 §4 as §13.34 extends it: the bar keeps **five** tabs. Settings rides in the strip
/// as the fifth and last, so a phone reaches it through the ☰ with no extra row anywhere,
/// and the bar's tabs say which one is current in words a reader hears, not only in colour
/// (WCAG 1.3.1).
///
/// Red until the coder adds the tab: the strip today is the four, and the fifth's word is
/// not in it.
#[test]
fn the_bar_has_five_tabs() {
    let scratch = account_scratch_full("five-tabs");
    let port = account_port(&scratch);
    let want = [
        ("/", K::Dashboard),
        ("/apps", K::Apps),
        ("/users", K::Users),
        ("/audit", K::Audit),
        ("/config", K::ConfigTab),
    ];

    for (lang, code) in [(Lang::En, "en"), (Lang::It, "it")] {
        let g = console_get(port, "admin@x.com", &[("Cookie", &format!("lang={code}"))]);
        assert_eq!(g.status, 200, "{code}: {}", account_readable(&g.body));
        let tabs = the_tab_nav(&g.body, "console");
        let pills = controls_with_class(&tabs, "a", "pill");
        assert_eq!(
            pills.len(),
            want.len(),
            "{code}: the bar's tabs are exactly the five places: {tabs}"
        );
        for (i, (path, key)) in want.iter().enumerate() {
            assert_eq!(
                attr(open_tag(&pills[i]), "href").as_deref(),
                Some(format!("{ADMIN_BASE}{path}").as_str()),
                "{code}: tab {i}: {}",
                pills[i]
            );
            assert_eq!(
                visible_text(&pills[i]),
                t(lang, *key),
                "{code}: tab {i}: {}",
                pills[i]
            );
        }
        // Settings is last, which is the whole arrangement of §13.34: it is the tab a phone
        // reaches last, through the ☰, and the bar's own row is unchanged at four words.
        assert_eq!(
            attr(open_tag(pills.last().unwrap()), "href").as_deref(),
            Some(format!("{ADMIN_BASE}/config").as_str()),
            "{code}: Settings is the last tab: {tabs}"
        );
        // The current one is named, and only one is, on a page that is one of them.
        let current = pills
            .iter()
            .filter(|a| attr(open_tag(a), "aria-current").as_deref() == Some("page"))
            .collect::<Vec<_>>();
        assert_eq!(
            current.len(),
            1,
            "{code}: exactly one tab is aria-current on the dashboard: {tabs}"
        );
    }

    // The two words, pinned in both languages. `Config` keeps its own words: it is the
    // page's heading and `<title>`, and the tab has to fit the strip (§13.34 §4).
    assert_eq!(t(Lang::En, K::ConfigTab), "Settings");
    assert_eq!(t(Lang::It, K::ConfigTab), "Impostazioni");
    assert_eq!(t(Lang::En, K::Config), "System settings");
    assert_eq!(t(Lang::It, K::Config), "Impostazioni di sistema");
    cleanup(&scratch);
}

/// §13.34: the bar's **navigation menu** is the phone's tab strip, and it is *the tabs*. The
/// console's account menu no longer carries a copy of them, so on a phone the ☰ is the only
/// way to the tabs, and the rows it holds have to be the strip's own, in the strip's own
/// order, named in the reader's language.
///
/// The markup half of §7. The width of the trigger box is a real measurement, and lives in
/// `e2e/tests/settings.js`, where a browser lays the bar out.
///
/// Red until the coder adds it: there is no `nav.navm` on the page, and the ☰'s word is not
/// a key.
#[test]
fn the_navigation_menu_holds_the_tabs() {
    let scratch = account_scratch_full("nav-menu");
    let port = account_port(&scratch);
    let hrefs = |els: &[String]| -> Vec<String> {
        els.iter()
            .filter_map(|a| attr(open_tag(a), "href"))
            .collect()
    };

    for (lang, code) in [(Lang::En, "en"), (Lang::It, "it")] {
        let g = console_get(port, "admin@x.com", &[("Cookie", &format!("lang={code}"))]);
        assert_eq!(g.status, 200, "{code}: {}", account_readable(&g.body));
        let bar = the_bar(&g.body, &format!("console {code}"));
        let nav = the_nav_menu(&g.body, &format!("console {code}"));

        // The menu is the bar's first child, ahead of the brand: §13.34 §0 measured that the
        // bar's width is set by the trigger box, and a box that is not in the bar at all, or
        // sits at the far end, is a bar measured on somebody else's arithmetic.
        let nav_at = bar
            .find("<nav class=\"navm\"")
            .expect("the navigation menu is in the bar");
        let brand_at = bar
            .find("class=\"brand\"")
            .expect("the brand is in the bar");
        assert!(nav_at < brand_at, "{code}: the ☰ precedes the brand: {bar}");

        // One `details`, of the menu family, in the same exclusive-open group as the account
        // menu (§13.28 §5), and shut: the bar measures a closed ☰.
        let boxes = elements(&nav, "<details", ">");
        assert_eq!(
            boxes.len(),
            1,
            "{code}: one details in the navigation menu: {nav}"
        );
        let tag = open_tag(&boxes[0]);
        let classes = attr(tag, "class").unwrap_or_default();
        for class in ["settings", "navmenu"] {
            assert!(
                classes.split_whitespace().any(|word| word == class),
                "{code}: the details carries `{class}`: {tag}"
            );
        }
        assert_eq!(
            attr(tag, "name").as_deref(),
            Some("bar-menu"),
            "{code}: the two bar menus are one exclusive group: {tag}"
        );
        assert!(
            attr(tag, "open").is_none(),
            "{code}: the ☰ starts shut: {tag}"
        );

        // The trigger is the icon-only pill: glyph out of the accessibility tree, named by
        // one hidden word, in the reader's language, and the same word in `title` for the
        // pointer (§13.28 §2).
        let summaries = controls_with_class(&nav, "summary", "ico");
        assert_eq!(summaries.len(), 1, "{code}: one icon summary: {nav}");
        let summary = open_tag(&summaries[0]);
        assert!(
            attr(summary, "class").is_some_and(|c| c.split_whitespace().any(|word| word == "pill")),
            "{code}: the trigger is a pill: {summary}"
        );
        let word = t(lang, K::NavMenu);
        let hidden = controls_with_class(&summaries[0], "span", "vh");
        assert_eq!(
            hidden.len(),
            1,
            "{code}: the glyph is named by exactly one hidden span: {}",
            summaries[0]
        );
        assert_eq!(
            visible_text(&hidden[0]),
            word,
            "{code}: the ☰ says the word in the reader's language: {}",
            summaries[0]
        );
        assert_eq!(
            attr(summary, "title").as_deref(),
            Some(word),
            "{code}: {summary}"
        );
        let glyphs = elements(&summaries[0], "<svg", "</svg>");
        assert_eq!(
            glyphs.len(),
            1,
            "{code}: the trigger carries one glyph: {}",
            summaries[0]
        );
        assert!(
            glyphs[0].contains("aria-hidden=\"true\""),
            "{code}: the glyph is decoration: {}",
            glyphs[0]
        );

        // The panel is the tabs: the strip's links, in the strip's order, and nothing else.
        let panel = the_nav_panel(&g.body, &format!("console {code}"));
        let tabs = nested_block(&panel, "<div class=\"menu-tabs\">", "div");
        let rows = controls_with_class(&tabs, "a", "pill");
        assert_eq!(
            rows.len(),
            5,
            "{code}: the navigation menu's panel is the five tabs: {panel}"
        );
        assert_eq!(
            hrefs(&rows),
            hrefs(&controls_with_class(
                &the_tab_nav(&g.body, "console"),
                "a",
                "pill"
            )),
            "{code}: the ☰'s rows are the strip's tabs, in order: {panel}"
        );
        assert!(
            !panel.contains("<div class=\"menu-places\"") && !panel.contains("/auth/logout"),
            "{code}: the ☰ is the tabs and nothing else: {panel}"
        );
    }

    // A page the visitor cannot use has no tabs to reach, so it carries no ☰ at all: the
    // console's `403` is not a console page, and `/account/` never was one (§13.34 §2). Read
    // the header's markup: every page inlines `admin.css`, whose top-level and 883-block
    // rules name `details.navmenu`, so a substring over the whole document reports the
    // stylesheet, not the page.
    let denied = console_get(port, "bob@x.com", &[]);
    assert_eq!(
        denied.status, 403,
        "a non-administrator is refused the console"
    );
    let denied_bar = the_header_bar(&denied.body, "403");
    assert!(
        !denied_bar.contains("<nav class=\"navm\"") && !denied_bar.contains("navmenu"),
        "the 403 carries no navigation menu: {denied_bar}"
    );
    assert!(
        !denied_bar.contains("<div class=\"menu-tabs\""),
        "the 403 carries no copy of the tabs: {denied_bar}"
    );

    // The word, in both languages: the ☰ is an icon, so its accessible name is this string
    // and the string that ships wrong is the English one on an Italian page.
    assert_eq!(t(Lang::En, K::NavMenu), "Navigation menu");
    assert_eq!(t(Lang::It, K::NavMenu), "Menu di navigazione");
}

/// §13.34: the account menu is **one object** on both surfaces, and what differs between the
/// console and `/account/` is a block, never a size.
///
/// Pinned as the same ordered list of classes, because what §13.34 §0 measured was three
/// panel widths from one shared rule: the console's panel was 230px and the account page's
/// was 286px, because `min-width` was measured against a trigger no panel on that page
/// uses. A width cannot be measured by a unit test, so the size is pinned twice over: by
/// the one rule that sets it (`the_bar_stays_one_row_at_every_width`) and by a browser
/// measuring the box (`e2e/tests/settings.js`).
///
/// Red for the console: its account box carries no `name`, and its panel holds a copy of
/// the tabs and a row to the settings page.
#[test]
fn the_account_menu_is_one_object() {
    let path = account_scratch_full("one-menu");
    let port = account_port(&path);
    let a_port = account_port(&path);
    let console = console_get(port, "admin@x.com", &[]).body;
    let account = account_call(
        &format!("http://127.0.0.1:{a_port}{ACCOUNT_PATH}/"),
        Some("bob@x.com"),
    )
    .body;

    for (label, html) in [("console", &console), ("account", &account)] {
        let nav = the_account_nav(html, label);
        let boxes: Vec<(String, String)> = elements(&nav, "<details", ">")
            .iter()
            .map(|el| {
                let tag = open_tag(el);
                (
                    attr(tag, "class").unwrap_or_default(),
                    attr(tag, "name").unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(
            boxes.len(),
            2,
            "{label}: the account box and the nested Preferences box: {nav}"
        );
        assert_eq!(
            boxes[0].0, "settings",
            "{label}: the account box is `details.settings`: {nav}"
        );
        assert_eq!(
            boxes[0].1, "bar-menu",
            "{label}: the account box is in the bar's exclusive group, so opening it shuts \
                 the ☰ on a phone where both live in the bar: {nav}"
        );
        assert_eq!(
            boxes[1].0, "prefs",
            "{label}: the nested box is `details.prefs`: {nav}"
        );
        assert_eq!(
            boxes[1].1, "",
            "{label}: the nested box is in no group, so it opens while its own panel stays \
                 open (§13.28 §5): {nav}"
        );

        // The trigger and the panel are the same controls on both surfaces. A class list is
        // matched one word at a time (`controls_with_class`), so the lookup uses the word that
        // names *this* control: `pill` is on the Preferences trigger too, and a two-word
        // value matches nothing. The trigger's whole class value is read off the tag.
        for (tag, class) in [("summary", "who"), ("div", "menu")] {
            let found = controls_with_class(&nav, tag, class);
            assert_eq!(
                found.len(),
                1,
                "{label}: exactly one `{tag}.{class}` in the account menu: {nav}"
            );
            if tag == "summary" {
                assert_eq!(
                    attr(open_tag(&found[0]), "class").as_deref(),
                    Some("pill who"),
                    "{label}: the trigger is a name pill, class for class: {}",
                    found[0]
                );
            }
        }
    }

    // The panel's contents as the ordered list of classes it emits, once the two blocks that
    // belong to one page each are out: the console's `div.menu-places` (which §13.34 empties
    // of the tabs and of the settings row) and the account page's `div.menu-danger`.
    // Everything left is one object; a row that arrives on one surface wearing a class the
    // other does not have shows up here.
    let shape = |html: &str, label: &str| -> Vec<String> {
        let mut panel = the_panel(html, label);
        for class in ["menu-places", "menu-danger"] {
            let open = format!("<div class=\"{class}\"");
            if panel.contains(&open) {
                let block = nested_block(&panel, &open, "div");
                let at = panel.find(&open).expect("the block is in the panel");
                panel.replace_range(at..at + block.len(), "");
            }
        }
        class_values(&panel)
    };
    let console_shape = shape(&console, "console");
    let account_shape = shape(&account, "account");
    assert!(
        console_shape.iter().any(|c| c == "who-full")
            && account_shape.iter().any(|c| c == "who-full"),
        "both panels open with who the caller is: {console_shape:?} / {account_shape:?}"
    );
    assert_eq!(
        console_shape, account_shape,
        "the account menu is one object, in the same order, on both surfaces"
    );

    // And the blocks that do differ are the one block of their surface. The console offers
    // the caller's own page and nothing else: no copy of the tabs (§13.34 moved them to the
    // ☰), and no settings row (the settings page is a tab now, so a second row to it in the
    // panel would be two answers to "where is Settings").
    let panel = the_panel(&console, "console");
    let rows: Vec<String> = controls_with_class(&panel, "a", "pill")
        .iter()
        .filter_map(|a| attr(open_tag(a), "href"))
        .collect();
    assert!(
        !panel.contains("<div class=\"menu-tabs\""),
        "§13.34: the console's account menu carries no copy of the tabs: {panel}"
    );
    assert!(
        !rows.iter().any(|href| href.ends_with("/config")),
        "§13.34: the settings page is a tab, so the account menu names it nowhere: {rows:?}"
    );
    assert_eq!(
        rows.iter()
            .filter(|href| href.starts_with(ACCOUNT_PATH))
            .count(),
        1,
        "the account menu's one place is the caller's own page: {rows:?}"
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.28 §2 as §13.34 narrows it: the panel's content and order, on both surfaces. The
/// panel was opened by clicking a name, so it starts with who that name is; on the console
/// comes the one place the menu has left, the caller's own page, then a rule; Preferences is
/// a closed group inside it; a rule and Sign out, the row that leaves the estate. The tab
/// rows and the System settings row are gone: §13.34 moved the tabs into the ☰ and made the
/// settings page a tab, so a row to it here would be two answers to one question.
#[test]
fn the_panel_is_in_order() {
    let path = account_scratch_full("panel-order");
    let port = account_port(&path);
    let base = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/");

    // --- the console: who, the caller's own page, Preferences, Sign out.
    let g = console_get(port, "admin@x.com admin@alt.com", &[]);
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let panel = the_panel(&g.body, "console");

    let who = controls_with_class(&panel, "p", "who-full");
    assert_eq!(who.len(), 1, "one p.who-full: {panel}");
    for addr in ["admin@x.com", "admin@alt.com"] {
        assert!(
            who[0].contains(addr),
            "every address of the caller is in the panel: {addr}: {}",
            who[0]
        );
    }
    assert!(
        !panel.contains(ACCOUNT_BOB) && !panel.contains(ACCOUNT_CAROL),
        "the uuid is not in the panel: {panel}"
    );

    // §13.34 §3: the console's panel is who, the caller's own page, Preferences, Sign out.
    // The tab rows are gone from it (they ride in the ☰ now), and so is the System settings
    // row (the settings page is a tab), which leaves the places block with one row in it.
    let who_at = panel
        .find("<p class=\"who-full\"")
        .expect("the panel opens with the caller");
    let places_at = panel
        .find("<div class=\"menu-places\">")
        .expect("the console's panel carries its places block");
    let prefs_at = panel
        .find("<details class=\"prefs\">")
        .expect("the console's panel carries the nested Preferences box");
    let sign_out = controls_with_class(&panel, "a", "pill")
        .into_iter()
        .find(|a| visible_text(a) == t(Lang::En, K::SignOut))
        .expect("the panel has a Sign out row that says Sign out");
    let sign_out_at = panel
        .find(&sign_out)
        .expect("the Sign out row is in the panel");
    assert!(
        who_at < places_at && places_at < prefs_at && prefs_at < sign_out_at,
        "the panel's order is the caller, the places, Preferences, Sign out: {panel}"
    );

    // The blocks are divided by a rule (§2), and Sign out sits behind the last of them: it is
    // the row that leaves the estate, and the rule is what separates it from the rows that
    // only change how the estate looks.
    let mut seps = Vec::new();
    let mut rest = panel.as_str();
    while let Some(i) = rest.find("<div class=\"sep\"") {
        seps.push(panel.len() - rest.len() + i);
        rest = &rest[i + 1..];
    }
    assert!(
        !seps.is_empty(),
        "the panel's groups are divided by a rule: {panel}"
    );
    assert!(
        *seps.last().unwrap() > prefs_at && *seps.last().unwrap() < sign_out_at,
        "Sign out sits behind the last rule: {panel}"
    );

    let hrefs = |markup: &str| -> Vec<String> {
        controls_with_class(markup, "a", "pill")
            .iter()
            .filter_map(|a| attr(open_tag(a), "href"))
            .collect()
    };

    // The tab rows and the settings row are out of this panel. The tabs live in the ☰, and
    // the settings page is a tab, so a row to it here would be two answers to "where is
    // Settings", one of them a row a phone cannot reach.
    assert!(
        !panel.contains("<div class=\"menu-tabs\""),
        "§13.34: no copy of the tab rows in the account menu: {panel}"
    );
    assert!(
        !hrefs(&panel).iter().any(|href| href.ends_with("/config")),
        "§13.34: the settings page is named nowhere in the account menu: {:?}",
        hrefs(&panel)
    );

    // Preferences is a closed group holding the one form.
    let prefs = nested_block(&panel, "<details class=\"prefs\">", "details");
    assert!(
        attr(open_tag(&prefs), "open").is_none(),
        "the nested box is closed by default: {prefs}"
    );
    let summaries = controls_with_class(&prefs, "summary", "pill");
    assert_eq!(
        summaries.len(),
        1,
        "the box's row is a summary.pill: {prefs}"
    );
    assert_eq!(
        visible_text(&summaries[0]),
        t(Lang::En, K::Settings),
        "the row says Preferences: {}",
        summaries[0]
    );
    let forms = elements(&prefs, "<form", "</form>");
    assert_eq!(forms.len(), 1, "one form in the box: {prefs}");
    assert!(
        prefs.contains("<select name=\"lang\"") && prefs.contains("<select name=\"theme\""),
        "the box holds the two list boxes: {prefs}"
    );
    assert!(
        panel.find("<form").expect("the panel has a form") >= prefs_at,
        "the form is inside the Preferences box, not loose in the panel: {panel}"
    );

    // Sign out is a row with the word on it, not an icon that is only named.
    assert!(
        sign_out.contains("/auth/logout"),
        "the Sign out row is the configured link: {sign_out}"
    );
    assert!(
        !sign_out.contains("class=\"pill ico\""),
        "in a panel there is room for the word, so it is not an icon-only control: \
             {sign_out}"
    );

    // No lede in the panel on any page: `p.who-full` is not a lede, so the panel adds no
    // second lede to a page (§13.23 §3 counts one per page).
    assert!(!panel.contains("<p class=\"lede\""), "no p.lede: {panel}");

    // The console's panel **does** carry the way to the caller's own page: the user's
    // decision of 2026-11-25 (PLAN.md step 8, §13.28 §2, open question 2 answered yes),
    // which supersedes the reading this test first pinned. An `a.pill` to the account
    // prefix, worded `K::NotAdminToAccount`, sitting with the console's places and ahead of
    // the Preferences box, because it is a place to go and not a preference. Pinned in both
    // languages: the pair that breaks is the row that ships the English word on an Italian
    // page, and English alone passes on that.
    let account_href = format!("{ACCOUNT_PATH}/");
    for (lang, code) in [(Lang::En, "en"), (Lang::It, "it")] {
        let cookie = format!("lang={code}");
        let g = console_get(
            port,
            "admin@x.com admin@alt.com",
            &[("Cookie", cookie.as_str())],
        );
        assert_eq!(g.status, 200, "{code}: {}", account_readable(&g.body));
        let panel = the_panel(&g.body, &format!("console {code}"));
        let rows = anchors_to(&panel, &account_href)
            .into_iter()
            .filter(|a| visible_text(a) == t(lang, K::NotAdminToAccount))
            .collect::<Vec<_>>();
        assert_eq!(
            rows.len(),
            1,
            "{code}: the console's panel carries one Go to your account row: {panel}"
        );
        assert_eq!(
            attr(open_tag(&rows[0]), "href").as_deref(),
            Some(account_href.as_str()),
            "{code}: the row goes to the account prefix: {}",
            rows[0]
        );
        assert!(
            attr(open_tag(&rows[0]), "class")
                .is_some_and(|c| c.split_whitespace().any(|word| word == "pill")),
            "{code}: the row is an a.pill, the panel's row component: {}",
            rows[0]
        );
        // Among the places, before Preferences: inside `div.menu-places` (§2 names that
        // container), ahead of the nested box. The row is located by its href, not by the
        // word, because the Settings tab now carries the word the settings page answers to.
        let places = nested_block(&panel, "<div class=\"menu-places\">", "div");
        assert!(
            places.contains(&rows[0]),
            "{code}: the row is one of the console's places: {panel}"
        );
        assert_eq!(
            hrefs(&places),
            vec![account_href.clone()],
            "{code}: §13.34 leaves one row in the places block, the caller's own page: {places}"
        );
        let prefs_at = panel
            .find("<details class=\"prefs\">")
            .expect("the panel carries the nested Preferences box");
        let places_end = panel
            .find(&places)
            .expect("the places block is in its panel")
            + places.len();
        assert!(
            places_end < prefs_at,
            "{code}: the places block closes before the nested Preferences box: {panel}"
        );
    }

    // The `403`'s panel carries no such row: its caller has no places block at all (the
    // places are administrators only, §2), and that page's body already ends in the one
    // action, which `the_console_403_names_the_caller_and_links_to_their_account` pins.
    let panel = the_panel(&console_get(port, "bob@x.com", &[]).body, "403");
    assert!(
        !panel.contains(t(Lang::En, K::NotAdminToAccount))
            && !panel.contains(&format!("href=\"{ACCOUNT_PATH}/\"")),
        "the 403's panel offers no account row: {panel}"
    );
    for at in every_route() {
        let url = format!("http://127.0.0.1:{port}{ADMIN_BASE}{}", at.path());
        let r = get_with_secret(url)
            .header(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("a response");
        let g = got_of(r);
        // A page that names a subject the fixture does not hold is a `404`, and a `404`
        // renders the shell: the bar, the panel, and a lede in `main`. The assertion below
        // is about the panel, so both answers are the page shape under test.
        assert!(
            g.status == 200 || g.status == 404,
            "{at:?}: a page, not a refusal: {}",
            account_readable(&g.body)
        );
        assert!(
            !the_panel(&g.body, &format!("{at:?}")).contains("<p class=\"lede\""),
            "no p.lede in the panel on {at:?}"
        );
    }

    // --- `/account/`: no tabs, no Settings row, no console place at all.
    let g = account_call(&base, Some("bob@x.com bob@old.com"));
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let panel = the_panel(&g.body, "account");
    assert!(
        !panel.contains("menu-tabs"),
        "the page has no tabs to move: {panel}"
    );
    assert!(
        !panel.contains(&format!("{ADMIN_BASE}/config")),
        "the page has no System settings row: {panel}"
    );
    assert!(!panel.contains("<p class=\"lede\""), "{panel}");
    let who = controls_with_class(&panel, "p", "who-full");
    assert_eq!(who.len(), 1, "{panel}");
    for addr in ["bob@x.com", "bob@old.com"] {
        assert!(who[0].contains(addr), "{addr}: {}", who[0]);
    }
    assert!(
        panel.contains("<details class=\"prefs\">") && panel.contains(t(Lang::En, K::SignOut)),
        "the page's panel is who, Preferences, Sign out: {panel}"
    );
    // No "Go to your account" row here: this **is** that page, and the panel's rows are
    // places to go (§13.28 §2), so the console's row is exactly the one row this surface
    // must not carry, in either language, under either spelling of the prefix. The page's
    // own address reaches the panel only as a form `action`, never as a link.
    assert!(
        !panel.contains(t(Lang::En, K::NotAdminToAccount))
            && !panel.contains(t(Lang::It, K::NotAdminToAccount))
            && !panel.contains(&format!("href=\"{ACCOUNT_PATH}/\""))
            && !panel.contains(&format!("href=\"{ACCOUNT_PATH}\"")),
        "the page offers no link to itself: {panel}"
    );

    // --- the console's `403`: the same panel, with only the person's own rows.
    let g = console_get(port, "bob@x.com", &[]);
    assert_eq!(g.status, 403, "{}", account_readable(&g.body));
    let panel = the_panel(&g.body, "403");
    assert_eq!(
        controls_with_class(&panel, "p", "who-full").len(),
        1,
        "the 403 names the caller: {panel}"
    );
    assert!(
        !panel.contains("menu-tabs") && !panel.contains(&format!("{ADMIN_BASE}/config")),
        "a person who is not an administrator is offered no console page: {panel}"
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.34 §3 as the designer's review of the two menus narrowed it: the console's one place
/// row wears a glyph as every other row of the panel does (the trigger's caret, Preferences'
/// sliders, Sign out's arrow, the delete row's bin), and the glyph is **decoration**: the
/// visible word stays the row's name, so the row reads the same to a screen reader and in a
/// language the reader cannot see a glyph in. The panel's rows are a list of places and the
/// review caught that this one was bare text among drawn marks, which reads as the odd row
/// out rather than as a place.
///
/// Red until the coder draws it: the places block is the only block in the panel whose row
/// carries no `svg` today, which is the gap, and no colour may be spelled in it (`.menu svg`
/// paints it, as the other glyphs).
#[test]
fn the_account_menu_place_carries_a_glyph() {
    let path = account_scratch_full("place-glyph");
    let port = account_port(&path);
    let account_href = format!("{ACCOUNT_PATH}/");
    for (lang, code) in [(Lang::En, "en"), (Lang::It, "it")] {
        let g = console_get(
            port,
            "admin@x.com admin@alt.com",
            &[("Cookie", &format!("lang={code}"))],
        );
        assert_eq!(g.status, 200, "{code}: {}", account_readable(&g.body));
        let panel = the_panel(&g.body, &format!("console {code}"));
        let rows = anchors_to(&panel, &account_href)
            .into_iter()
            .filter(|a| visible_text(a) == t(lang, K::NotAdminToAccount))
            .collect::<Vec<_>>();
        assert_eq!(
            rows.len(),
            1,
            "{code}: the console's panel carries one Go to your account row: {panel}"
        );
        let row = &rows[0];
        // One glyph, **inside** the row: a mark sitting beside the control would be a stray
        // box in the panel, and a second glyph in a one-word row is a second mark to read.
        let glyphs = elements(row, "<svg", "</svg>");
        assert_eq!(glyphs.len(), 1, "{code}: the row carries its glyph: {row}");
        let open = open_tag(&glyphs[0]);
        assert!(
            open.contains("aria-hidden=\"true\"") && open.contains("focusable=\"false\""),
            "{code}: the glyph is decoration, never a second name: {open}"
        );
        assert!(
            open.contains("viewBox=\"0 0 24 24\""),
            "{code}: the glyph is drawn on the panel's 24 box: {open}"
        );
        assert!(
            attr(open, "class").is_some(),
            "{code}: the glyph is sized and painted by class, like the panel's other glyphs: \
                 {open}"
        );
        assert!(
            !open.contains("fill=") && !open.contains("stroke=") && !open.contains("style="),
            "{code}: the glyph names no colour: {open}"
        );
        // The word is still the row's name: a glyph that **replaced** the word would name
        // the row in pictures, and §13.17's naming rule does not reach a row that lost it.
        assert_eq!(
            visible_text(row),
            t(lang, K::NotAdminToAccount),
            "{code}: the visible word is the row: {row}"
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.28 §5: the delete row is **not built in slice H**. Step 7 adds the row, its route,
/// its `K` key and its tests together; hidden markup would be a dead link a stylesheet could
/// reveal, and an unused `K` key is dead code. H only reserves the place (last, after a
/// rule) and the wording.
#[test]
fn nothing_in_the_header_deletes_an_account() {
    let path = account_scratch_full("no-delete");
    let port = account_port(&path);
    let base = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/");

    for (label, html) in [
        ("console", console_get(port, "admin@x.com", &[]).body),
        ("403", console_get(port, "bob@x.com", &[]).body),
        ("account", account_call(&base, Some("bob@x.com")).body),
    ] {
        let panel = the_panel(&html, label);
        assert!(
            !panel.contains("/delete"),
            "{label}: no delete link in the panel: {panel}"
        );
        assert!(
            !panel.contains("pill rm"),
            "{label}: no delete row styled as a remove: {panel}"
        );
        assert!(
            !panel.contains("Delete account") && !panel.contains("Elimina l'account"),
            "{label}: no delete words: {panel}"
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// The words §13.28's key and §13.30 §1 pin for the menu row, spelled out here because the
/// `K` key that carries them is the coder's to add. `K` has no `PartialEq`, so the rendered
/// wording is what a test can compare, and the row's accessible name **is** its visible
/// text (§13.28: a row that carries a word is named by that word, not by its glyph).
const DELETE_ROW_EN: &str = "Delete account and all its data";
const DELETE_ROW_IT: &str = "Elimina l'account e tutti i suoi dati";

/// The three assertions every "no delete row here" test makes, in one place so the console's
/// panel, the `403`'s panel and the page's panel with the intake unset cannot drift apart.
/// The words are checked in both languages because a row that appears in one language only
/// is the same row.
fn assert_no_delete_row(panel: &str, at: &str) {
    assert!(
        !panel.contains("/delete"),
        "{at}: no delete link in the panel: {panel}"
    );
    assert!(
        !panel.contains("pill rm"),
        "{at}: no row styled as a remove: {panel}"
    );
    assert!(
        !panel.contains(DELETE_ROW_EN) && !panel.contains(DELETE_ROW_IT),
        "{at}: no delete words: {panel}"
    );
}

/// §13.30 §1: with the intake set, the account panel **ends** in the delete row, behind its
/// own rule, after Sign out's. The row is a `GET` link to `{account}/delete` (a link, so a
/// prefetch cannot delete, and the confirmation page is 7b's), it is the panel's last child,
/// its words are `K::AccountDelete` in the reader's language, and its trash glyph is
/// decoration, so the visible word is the accessible name. The target answers `404` in this
/// slice, which is the point: the row has a page in 7b, and 7a's job is to make the fields
/// have a production reader.
#[test]
fn the_account_menu_ends_with_delete_after_sign_out() {
    let path = account_scratch_full("menu-delete");
    let port = account_port_intake(&path);
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/");

    for (cookie, words) in [("lang=en", DELETE_ROW_EN), ("lang=it", DELETE_ROW_IT)] {
        let g = account_call_pref(&url, Some("bob@x.com"), Some(cookie), None);
        assert_eq!(g.status, 200, "{cookie}: {}", account_readable(&g.body));
        let panel = the_panel(&g.body, cookie);

        // One row, carrying the component's two classes, and it is a link.
        let rows = controls_with_class(&panel, "a", "rm");
        assert_eq!(rows.len(), 1, "{cookie}: exactly one delete row: {panel}");
        let row = &rows[0];
        assert!(
            attr(open_tag(row), "class").is_some_and(|c| c.split_whitespace().any(|w| w == "pill")),
            "the row is a menu pill, so it wears the rows above it: {row}"
        );
        let href = attr(open_tag(row), "href").unwrap_or_default();
        assert_eq!(
            href,
            format!("{ACCOUNT_PATH}/delete"),
            "the row links to the page under the account prefix, as a path on this host: \
                 the intake's own origin never reaches a page"
        );

        // The panel's order: who, Preferences, rule, Sign out, rule, Delete.
        let prefs_at = panel
            .find("<details class=\"prefs\">")
            .unwrap_or_else(|| panic!("{cookie}: the panel has Preferences: {panel}"));
        let out = anchors_to(&panel, "/auth/logout");
        assert_eq!(out.len(), 1, "{cookie}: one Sign out row: {panel}");
        let out_at = panel
            .find(&out[0])
            .unwrap_or_else(|| panic!("{cookie}: Sign out is in the panel: {panel}"));
        let row_at = panel
            .find(row.as_str())
            .unwrap_or_else(|| panic!("{cookie}: the row is in the panel: {panel}"));
        assert!(
            prefs_at < out_at && out_at < row_at,
            "{cookie}: the row comes after Sign out: {panel}"
        );
        assert_eq!(
            elements(&panel, "<div class=\"sep\"", "</div>").len(),
            2,
            "{cookie}: two rules, one above Sign out and one above the row: {panel}"
        );
        // The rule directly above the row, with nothing in between.
        let sep_end = panel[..row_at]
            .rfind("</div>")
            .map(|i| i + "</div>".len())
            .unwrap_or(0);
        assert!(
            panel[sep_end..row_at].trim().is_empty(),
            "{cookie}: the row follows its rule at once: {:?}",
            &panel[sep_end..row_at]
        );
        // And it is the last child: nothing follows it inside `div.menu`.
        for tag in ["<a ", "<div", "<details", "<p ", "<form"] {
            assert!(
                !panel[row_at + row.len()..].contains(tag),
                "{cookie}: the row is the panel's last child, {tag} follows it: {panel}"
            );
        }

        // The glyph is decoration and the visible word is the name: a glyph that kept a
        // name of its own would make the row say the words twice to a reader.
        assert_eq!(
            visible_text(row),
            words,
            "{cookie}: the row reads the key's words, and nothing else: {row}"
        );
        let glyphs = elements(row, "<svg", "</svg>");
        assert_eq!(glyphs.len(), 1, "{cookie}: one glyph: {row}");
        assert!(
            glyphs[0].contains("aria-hidden=\"true\"") && glyphs[0].contains("focusable=\"false\""),
            "{cookie}: the glyph is out of the accessibility tree: {}",
            glyphs[0]
        );
        // A trash can, not the keys table's `×`: at the bottom of a panel an `×` reads as
        // "close this panel" (§13.30 §1). The three paths are the ones the design spells.
        for d in ["M3 6h18", "M8 6V4h8v2", "M6 6l1 14h10l1-14"] {
            assert!(
                glyphs[0].contains(d),
                "{cookie}: the trash glyph's {d}: {}",
                glyphs[0]
            );
        }

        // A link, never a form: a `GET` must never mutate, and a prefetched link is a
        // normal thing a browser does to the last row of a menu.
        for form in elements(&g.body, "<form", "</form>") {
            assert!(
                !form.contains(&format!("action=\"{ACCOUNT_PATH}/delete")),
                "{cookie}: the row is a link, not a submission: {form}"
            );
        }
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.28 §5, unchanged: the console's panel has **no** delete row, with the intake set.
/// This program's administrator surface is not where a person deletes their own account,
/// and the row is not hidden there: markup a stylesheet could reveal is a dead link on the
/// surface that edits users.
#[test]
fn the_console_menu_has_no_delete_row() {
    let path = account_scratch_full("console-no-delete");
    let port = account_port_intake(&path);

    for (label, g) in [
        ("console", console_get(port, "admin@x.com", &[])),
        (
            "users",
            console_at(port, "admin@x.com", "/users", "lang=en"),
        ),
        (
            "settings",
            console_at(port, "admin@x.com", "/config", "lang=it"),
        ),
        ("403", console_get(port, "bob@x.com", &[])),
    ] {
        assert!(
            g.status == 200 || g.status == 403,
            "{label}: a page: {}",
            account_readable(&g.body)
        );
        assert_no_delete_row(&the_panel(&g.body, label), label);
        assert!(
            !g.body.contains(&format!("{ACCOUNT_PATH}/delete")),
            "{label}: the whole document names no delete page: {}",
            account_readable(&g.body)
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W2: unset is the feature **off**. The panel ends where it ends today, with Sign
/// out, and `{account}/delete` is the ordinary `404` every unknown path under the prefix
/// gets, so a deployment that never wired the worker shows a person a door to nothing.
#[test]
fn no_delete_row_when_the_intake_is_unset() {
    let path = account_scratch_full("intake-unset");
    let port = account_port(&path);
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/");

    for (cookie, who) in [("lang=en", "bob@x.com"), ("lang=it", "admin@x.com")] {
        let g = account_call_pref(&url, Some(who), Some(cookie), None);
        assert_eq!(g.status, 200, "{cookie}: {}", account_readable(&g.body));
        let panel = the_panel(&g.body, cookie);
        assert_no_delete_row(&panel, cookie);
        // The panel ends in Sign out, so the row's place is not reserved as hidden markup.
        let out = anchors_to(&panel, "/auth/logout");
        assert_eq!(out.len(), 1, "{cookie}: one Sign out row: {panel}");
        let out_at = panel
            .find(&out[0])
            .unwrap_or_else(|| panic!("{cookie}: Sign out is in the panel: {panel}"));
        assert!(
            !panel[out_at + out[0].len()..].contains("</a>"),
            "{cookie}: Sign out is the panel's last row: {panel}"
        );
    }

    // The route is not added in 7a, and the page is the 404 every unknown path gets: the
    // row's target arrives with 7b.
    let g = account_call(&format!("{url}delete"), Some("bob@x.com"));
    assert_eq!(
        g.status,
        404,
        "with the intake unset there is no delete page: {}",
        account_readable(&g.body)
    );
    assert_no_delete_row(&the_panel(&g.body, "404"), "404");
    let _ = std::fs::remove_file(&path);
}
