use super::*;

// --- language -----------------------------------------------------------

#[test]
fn negotiate_lang_prefers_query_then_cookie_then_header_then_default() {
    // query beats everything
    assert_eq!(
        negotiate_lang(Some("it"), Some("en"), Some("en-GB"), Lang::En).1,
        Lang::It
    );
    // cookie beats the header
    assert_eq!(
        negotiate_lang(None, Some("it"), Some("en-GB"), Lang::En).1,
        Lang::It
    );
    // header beats the default
    assert_eq!(
        negotiate_lang(None, None, Some("it-IT,it;q=0.9"), Lang::En).1,
        Lang::It
    );
    // and the default is the floor
    assert_eq!(
        negotiate_lang(None, None, Some("de-DE"), Lang::En).1,
        Lang::En
    );
    assert_eq!(negotiate_lang(None, None, None, Lang::It).1, Lang::It);
    // an unparseable preference is not a preference
    assert_eq!(
        negotiate_lang(Some("fr"), Some("it"), None, Lang::En).1,
        Lang::It
    );
}

#[test]
fn parse_lang_pref_accepts_auto_and_the_two_codes() {
    assert_eq!(parse_lang_pref("auto"), Some(LangPref::Auto));
    assert_eq!(parse_lang_pref(" Auto "), Some(LangPref::Auto));
    assert_eq!(parse_lang_pref("en"), Some(LangPref::Fixed(Lang::En)));
    assert_eq!(parse_lang_pref("IT"), Some(LangPref::Fixed(Lang::It)));
    assert_eq!(parse_lang_pref("fr"), None);
    assert_eq!(parse_lang_pref(""), None);
    // The code a choice is stored under is the one it is read back from.
    for p in [
        LangPref::Auto,
        LangPref::Fixed(Lang::En),
        LangPref::Fixed(Lang::It),
    ] {
        assert_eq!(parse_lang_pref(p.code()), Some(p));
    }
}

#[test]
fn auto_is_the_floor_and_is_choosable_back_out_of_a_fixed_choice() {
    // No preference expressed at all reads as Auto, which is what makes naming the
    // behaviour in the menu change nobody's page.
    assert_eq!(negotiate_lang(None, None, None, Lang::En).0, LangPref::Auto);
    // A stored `auto` beats no header and still follows one when there is one, so
    // choosing it undoes a fixed choice instead of freezing today's answer.
    assert_eq!(
        negotiate_lang(None, Some("auto"), Some("it-IT"), Lang::En),
        (LangPref::Auto, Lang::It)
    );
    assert_eq!(
        negotiate_lang(None, Some("auto"), Some("de-DE"), Lang::En),
        (LangPref::Auto, Lang::En)
    );
    // And an explicit `?lang=auto` outranks a fixed cookie: that is the submit that
    // switches the menu back to Auto.
    assert_eq!(
        negotiate_lang(Some("auto"), Some("it"), Some("de-DE"), Lang::En),
        (LangPref::Auto, Lang::En)
    );
    // A fixed choice reports itself, never the language it happens to agree with.
    assert_eq!(
        negotiate_lang(None, Some("en"), Some("en-GB"), Lang::En).0,
        LangPref::Fixed(Lang::En)
    );
}

#[test]
fn preference_href_drops_the_parameter_and_keeps_the_rest() {
    let cfg = cfg_for("x.json", "/admin");
    // An application's page, because that is where a query worth keeping lives now: the
    // two fields of its access check.
    let app = Route::App("mpa".to_string());
    assert_eq!(
        preference_href(&cfg, &app, "email=bob%40x.com&lang=en", LANG_COOKIE),
        "/admin/apps/mpa?email=bob%40x.com"
    );
    // The other preference survives the first redirect, which is what lets one submit
    // set both: see the two checks in `handle`.
    assert_eq!(
        preference_href(&cfg, &app, "lang=en&theme=dark", LANG_COOKIE),
        "/admin/apps/mpa?theme=dark"
    );
    assert_eq!(
        preference_href(&cfg, &app, "lang=en&theme=dark", THEME_COOKIE),
        "/admin/apps/mpa?lang=en"
    );
    assert_eq!(
        preference_href(&cfg, &Route::Dashboard, "", LANG_COOKIE),
        "/admin/"
    );
}

#[test]
fn preference_href_never_carries_client_bytes_verbatim() {
    // Everything a client sent is re-encoded, so this string is safe in a Location:.
    let cfg = cfg_for("x.json", "");
    for param in [LANG_COOKIE, THEME_COOKIE] {
        let href = preference_href(
            &cfg,
            &Route::App("mpa".to_string()),
            "url=https://x/%0d%0aX:+1&lang=it&theme=dark",
            param,
        );
        assert!(href.bytes().all(|b| b.is_ascii_graphic()), "{href}");
        assert!(!href.contains('\r') && !href.contains('\n'));
    }
}

#[test]
fn preserved_query_keeps_everything_the_settings_form_does_not_set() {
    // The form sends its own fields and nothing else, so what it does not put back as a
    // hidden field is lost: an access-check verdict, and the flash the page is showing.
    let kept = preserved_query(
        "email=bob%40x.com&url=https%3A%2F%2Fx%2Fa&lang=en&theme=dark&msg=user-added",
    );
    assert_eq!(
        kept,
        vec![
            ("email".to_string(), "bob@x.com".to_string()),
            ("url".to_string(), "https://x/a".to_string()),
            ("msg".to_string(), "user-added".to_string()),
        ]
    );
    assert!(preserved_query("").is_empty());
}

#[test]
fn cookie_value_parses_the_language_cookie() {
    assert_eq!(cookie_value("lang=it", LANG_COOKIE), Some("it"));
    assert_eq!(cookie_value("a=1; lang=en; b=2", LANG_COOKIE), Some("en"));
    assert_eq!(cookie_value("mylang=it", LANG_COOKIE), None);
    assert_eq!(cookie_value("a=1", LANG_COOKIE), None);
}

// --- theme ----------------------------------------------------------------

#[test]
fn parse_theme_accepts_the_three_spellings_and_nothing_else() {
    assert_eq!(parse_theme("light"), Some(UiTheme::Light));
    assert_eq!(parse_theme("Dark"), Some(UiTheme::Dark));
    assert_eq!(parse_theme(" system "), Some(UiTheme::System));
    // an unrecognised value is not an error, just no preference expressed
    assert_eq!(parse_theme("blue"), None);
    assert_eq!(parse_theme(""), None);
}

#[test]
fn negotiate_theme_prefers_query_then_cookie_then_system() {
    // query beats the cookie
    assert_eq!(negotiate_theme(Some("dark"), Some("light")), UiTheme::Dark);
    // cookie beats the default
    assert_eq!(negotiate_theme(None, Some("light")), UiTheme::Light);
    // System is the floor, with nothing expressed
    assert_eq!(negotiate_theme(None, None), UiTheme::System);
    // an unparseable preference is not a preference, so the next source still applies
    assert_eq!(negotiate_theme(Some("blue"), Some("dark")), UiTheme::Dark);
    assert_eq!(negotiate_theme(None, Some("blue")), UiTheme::System);
}

#[test]
fn cookie_value_parses_the_theme_cookie() {
    assert_eq!(cookie_value("theme=dark", THEME_COOKIE), Some("dark"));
    assert_eq!(
        cookie_value("a=1; theme=light; b=2", THEME_COOKIE),
        Some("light")
    );
    assert_eq!(cookie_value("mytheme=dark", THEME_COOKIE), None);
    assert_eq!(cookie_value("a=1", THEME_COOKIE), None);
}

#[test]
fn theme_attr_is_none_only_for_system() {
    // `None` is what leaves `data-theme` off the page for System; an explicit choice
    // always carries its own spelling.
    assert_eq!(UiTheme::Light.attr(), Some("light"));
    assert_eq!(UiTheme::Dark.attr(), Some("dark"));
    assert_eq!(UiTheme::System.attr(), None);
}

#[test]
fn shell_emits_data_theme_only_for_an_explicit_choice() {
    // The stylesheet itself mentions `data-theme` in its selectors, so the assertion has
    // to look at the `<html ...>` tag specifically, not the page as a whole.
    let cfg = cfg_for("x.json", "");
    let mut v = view(&cfg, Route::Dashboard, "REV");
    let html = shell(&v, "t", html! { "x" }).into_string();
    assert!(
        html.contains(r#"<html lang="en">"#),
        "System must render no data-theme attribute at all: {html}"
    );
    v.theme = UiTheme::Dark;
    let html = shell(&v, "t", html! { "x" }).into_string();
    assert!(
        html.contains(r#"<html lang="en" data-theme="dark">"#),
        "{html}"
    );
}

#[test]
fn the_settings_menu_marks_the_chosen_option_in_both_list_boxes() {
    let cfg = cfg_for("x.json", "");
    let mut v = view(&cfg, Route::Dashboard, "REV");
    let html = shell(&v, "t", html! { "x" }).into_string();
    // The floor, and the reason it has to be a LangPref: `Auto` renders an English page
    // and must still come back as `Auto`, not as `en`.
    assert!(html.contains(r#"<option value="auto" selected>"#), "{html}");
    assert!(
        html.contains(r#"<option value="system" selected>"#),
        "{html}"
    );
    assert_eq!(html.matches(" selected>").count(), 2, "{html}");

    v.lang_pref = LangPref::Fixed(Lang::It);
    v.theme = UiTheme::Dark;
    let html = shell(&v, "t", html! { "x" }).into_string();
    assert!(html.contains(r#"<option value="it" selected>"#), "{html}");
    assert!(html.contains(r#"<option value="dark" selected>"#), "{html}");
    assert_eq!(html.matches(" selected>").count(), 2, "{html}");
}

#[test]
fn every_small_control_is_a_pill_of_the_same_family() {
    // The rule the CSS states in prose: nothing at a call site decides how a pill looks,
    // and every small control is in the family, the way back and the Settings trigger
    // included.
    let app = render("pill-app", Route::App("mpa".into()));
    assert!(
        app.contains(r#"<a class="pill" href="/apps">"#),
        "the way back is a pill, not prose: {app}"
    );
    // Three different structures sit in that bar (the nav's tabs, the trigger's `summary`,
    // and the panel's rows), and every one of them must be the same object with the same
    // click area. The size rule therefore selects the CONTAINER and not the structures: a
    // list of them is a list that can miss one, which is what it did.
    assert!(
        the_rule(CSS, ".bar .pill").is_some(),
        "every pill in the header shares one size rule, named by the bar and not one by one"
    );
    assert!(
        !CSS.contains("details.settings>summary.pill,"),
        "and no rule may go back to naming them one at a time"
    );
    // Same size is only half of "the same object": the other half is the same STRUCTURE,
    // because a flex container blockifies its children and an inline-flex box left on a
    // text baseline answers a click over its line box rather than over the rectangle a
    // person can see. So every pill in the header is a flex item of a `nav` — the tabs in
    // theirs, the menu in `nav.acct`. The summary is the one that cannot be moved (it must
    // stay inside its `details`), so the CSS makes that `details` a flex container instead,
    // which blockifies it the same way.
    assert!(
        app.contains(r#"<nav class="acct">"#),
        "the account controls share one flex row: {app}"
    );
    assert!(
        CSS.contains("details.settings{display:flex"),
        "and the trigger is blockified by its own details"
    );
    assert!(
        app.contains(r#"<summary class="pill who""#),
        "the trigger is a pill of the family, wearing the class the size rule selects: {app}"
    );
    // §13.28 §3: the panel's rows are pills too, so they read as the same objects as the
    // bar's tabs. The Sign out row is the one every page has.
    assert!(
        app.contains(r#"<a class="pill" href="/auth/logout">"#),
        "a panel row is a pill, not an icon-only control: {app}"
    );
    // The footer never tells anybody to reload: `bb-auth-reload.path` does it.
    assert!(!app.contains("systemctl reload"), "{app}");
}

#[test]
fn sign_out_is_in_the_bar_when_configured_and_absent_when_not() {
    let html = render("signout", Route::Dashboard);
    // §13.28 §2: Sign out is a row of the panel, and in a panel there is room for the word,
    // so the icon stops being the only label: the row says Sign out in the reader's language.
    let panel = the_panel(&html, "console");
    let outs: Vec<String> = controls_with_class(&panel, "a", "pill")
        .into_iter()
        .filter(|a| a.contains("/auth/logout"))
        .collect();
    assert_eq!(outs.len(), 1, "one Sign out row: {panel}");
    assert_eq!(
        visible_text(&outs[0]),
        t(Lang::En, K::SignOut),
        "{}",
        outs[0]
    );
    assert!(
        !outs[0].contains(r#"class="pill ico""#),
        "the word is visible, not hidden behind an icon: {}",
        outs[0]
    );
    // It is the panel's last row (§13.28 §2), which is also what keeps the Tab order off the
    // destructive row step 7 adds after it.
    let sign_out_at = panel.find(&outs[0]).expect("the row is in the panel");
    assert!(
        !panel[sign_out_at + outs[0].len()..].contains("<a "),
        "Sign out is the panel's last link: {panel}"
    );
    assert!(
        the_rule(CSS, ".bar .pill").is_some(),
        "and share the header's size step, which reaches it for being IN the bar"
    );

    // A logout URL carrying the gate's `?rd=` reaches the href intact, which is the whole
    // of "sign out and come back here": the operator states the round trip in one value
    // and this GUI neither parses it nor adds to it. The `&` an rd with two parameters
    // would carry comes out escaped, because it is emitted as an attribute and maud
    // escapes attributes; that is why this asserts on the rendered string.
    let path = scratch("signout-rd", SAMPLE);
    let mut cfg = cfg_for(&path, "");
    cfg.logout_url = Some("/auth/logout?rd=https%3A%2F%2Fauth.example.com%2Fadmin%2F".to_string());
    let (doc, access) = open_access_file(&cfg.access_path).unwrap();
    let v = view(&cfg, Route::Dashboard, "REV");
    let html = shell(&v, "t", page_dashboard(&v, &doc, &access)).into_string();
    assert!(
        html.contains(r#"href="/auth/logout?rd=https%3A%2F%2Fauth.example.com%2Fadmin%2F""#),
        "{html}"
    );
    cleanup(&path);

    // Unset means no control at all, rather than a guess: this GUI speaks plain HTTP on
    // loopback and knows neither its scheme nor its host, and the one thing it is handed
    // is a client-supplied `Host`. A dead or attacker-chosen link is worse than none.
    let path = scratch("signout-off", SAMPLE);
    let mut cfg = cfg_for(&path, "");
    cfg.logout_url = None;
    let (doc, access) = open_access_file(&cfg.access_path).unwrap();
    let v = view(&cfg, Route::Dashboard, "REV");
    let html = shell(&v, "t", page_dashboard(&v, &doc, &access)).into_string();
    // The anchor, not the words: `CSS` is emitted inline on every page and its comments
    // name the control, so a text search finds it whether or not anything is rendered.
    assert!(!html.contains(r#"href="/auth/logout""#), "{html}");
    cleanup(&path);
}

/// The policy names the page's own bytes by hash, so the two have to *be* the same bytes.
///
/// A nonce cannot be wrong: it is generated and emitted in one breath. A hash can, and
/// silently: add a fourth constant to the `<style>` block, or a separator between the
/// three, and the browser refuses to apply the whole stylesheet while every test that
/// reads HTML goes on passing. This is what stands between that and a deployment
/// discovering it as an unstyled admin interface.
#[test]
fn the_policy_hashes_the_bytes_the_page_actually_carries() {
    let html = render("csp-style", Route::Dashboard);
    let open = html.find("<style>").expect("the built-in stylesheet");
    let close = html.find("</style>").expect("a closed style element");
    let inline = &html[open + "<style>".len()..close];
    // Not a reveal: this is the page that carries the stylesheet and no script.
    let csp = admin_csp(&Look::default(), false);
    assert!(
        csp.contains(&csp_hash(inline)),
        "style-src must name the hash of the bytes in the page"
    );
    // And the one handler, by the hash the policy allows it under.
    assert!(csp.contains(&csp_hash(SETTINGS_ONCHANGE)), "{csp}");
    assert!(
        csp.contains("'unsafe-hashes'"),
        "an attribute handler needs it: {csp}"
    );
    // Nothing else may run, load or be framed, and no form may leave this host: the gate
    // widened its own `form-action` to the estate because its pages are answered with a
    // redirect off-host, and this one must not follow it there. The semicolon is what
    // says nothing has been added beside `'self'`.
    assert!(csp.starts_with("default-src 'none';"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(csp.contains("form-action 'self';"), "{csp}");
}

/// `admin.css` as `(selector, declarations)` pairs, comments gone and whitespace squeezed
/// out, so a rule is matched by what it says and not by how it is indented. Nested blocks
/// (`@media`) yield their inner rules too.
fn css_rules() -> Vec<(String, String)> {
    let mut css = String::new();
    let mut rest = CSS;
    while let Some(a) = rest.find("/*") {
        css.push_str(&rest[..a]);
        let b = rest[a..].find("*/").expect("a closed comment") + a + 2;
        rest = &rest[b..];
    }
    css.push_str(rest);
    let css: String = css.chars().filter(|c| !c.is_whitespace()).collect();
    let (mut rules, mut head, mut stack) = (Vec::new(), String::new(), Vec::new());
    let mut body = String::new();
    for c in css.chars() {
        match c {
            '{' => {
                stack.push(std::mem::take(&mut head));
                body.clear();
            }
            '}' => {
                let sel = stack.pop().unwrap_or_default();
                if !body.is_empty() {
                    rules.push((sel, std::mem::take(&mut body)));
                }
                head.clear();
            }
            ';' if stack.is_empty() => head.clear(),
            _ if stack.is_empty() => head.push(c),
            _ => body.push(c),
        }
    }
    rules
}

/// Light dismiss in CSS (ARCHITECTURE section 13.20): while the Preferences menu is open
/// its trigger grows a transparent box over the whole viewport, so a click anywhere
/// outside the panel lands on the `summary` and toggles the `details` shut. The three
/// things that can silently break it are all pinned here: the cover itself, the panel
/// standing above it, and an ancestor that would become the cover's containing block.
#[test]
fn an_open_menu_closes_on_a_click_outside_it() {
    let rules = css_rules();
    let rule = |sel: &str| -> String {
        rules
            .iter()
            .find(|(s, _)| s.split(',').any(|one| one == sel))
            .unwrap_or_else(|| panic!("admin.css has no rule for {sel}"))
            .1
            .clone()
    };

    // The cover: a fixed box over the viewport, on the summary and not on the details,
    // since a click on the details itself toggles nothing.
    let cover = rule("details.settings[open]>summary::before");
    assert_eq!(
        css_decl(&cover, "content").as_deref(),
        Some(r#""""#),
        "{cover}"
    );
    assert_eq!(
        css_decl(&cover, "position").as_deref(),
        Some("fixed"),
        "{cover}"
    );
    assert_eq!(css_decl(&cover, "inset").as_deref(), Some("0"), "{cover}");
    let cover_z: i32 = css_decl(&cover, "z-index")
        .unwrap_or_else(|| panic!("the cover has no z-index: {cover}"))
        .parse()
        .expect("a numeric z-index");

    // The nested Preferences box grows **no cover of its own**. The cover's selector is a child
    // combinator off `details.settings`, which is what makes a click outside close the panel
    // while the inner box toggles only from its own row: a second fixed cover would answer one
    // click twice, so closing the panel would leave the preferences open under a hidden panel.
    for (sel, body) in &rules {
        assert!(
            !(sel.contains("details.prefs") && sel.contains("::before")),
            "details.prefs grows a cover of its own: {sel} {{{body}}}"
        );
    }

    // The panel stays above it, or the list boxes inside would hit the cover first.
    let menu_z: i32 = css_decl(&rule(".menu"), "z-index")
        .expect(".menu has a z-index")
        .parse()
        .expect("a numeric z-index");
    assert!(
        menu_z > cover_z,
        "menu {menu_z} must be above the cover {cover_z}"
    );

    // With the cover up the pointer is "on" the trigger everywhere, so the open trigger
    // wears the hover look for as long as it is open.
    let open = rule("details.settings[open]>summary");
    assert_eq!(
        css_decl(&open, "background").as_deref(),
        Some("var(--chip)"),
        "{open}"
    );
    assert_eq!(
        css_decl(&open, "border-color").as_deref(),
        Some("var(--accent)"),
        "{open}"
    );
    assert_eq!(
        css_decl(&open, "color").as_deref(),
        Some("var(--accent)"),
        "{open}"
    );

    // A fixed box is placed against the viewport only while no ancestor of the trigger
    // establishes a containing block for it.
    let ancestors = ["header.top", ".bar", "nav.acct", "details.settings"];
    for (sel, body) in &rules {
        for one in sel.split(',') {
            let last = one.rsplit(['>', '+', '~']).next().unwrap_or(one);
            let is_ancestor = ancestors.iter().any(|a| {
                last.strip_prefix(a).is_some_and(|tail| {
                    !tail.starts_with(|c: char| c.is_alphanumeric() || c == '-' || c == '_')
                })
            });
            if !is_ancestor {
                continue;
            }
            for prop in ["transform", "filter", "perspective", "will-change"] {
                assert!(
                    css_decl(body, prop).is_none(),
                    "{one} sets {prop}, which would shrink the menu's click cover to its box"
                );
            }
        }
    }
}

/// The estate's rule, in its 13.14 shape: **no page may need a script**, and exactly one
/// page is allowed to carry one.
///
/// The first half is the old test, unchanged: every route of [`every_route`], over a
/// socket, carries zero `<script`, no `javascript:` href, and an allowlist of handlers
/// that is still exactly the two Settings list boxes (`SETTINGS_ONCHANGE`). The copy
/// button is built with `addEventListener`, so the widening of the rule to "the reveal
/// carries a script" must not widen the *handler* rule by one attribute.
///
/// The second half is new, and it is the half the design buys the script with: each of
/// the four reveal responses (the console's mint and rotate, the self-service page's mint
/// and rotate) carries **exactly one** `<script>`, its content is `COPY_SCRIPT` byte for
/// byte, and that response's own `Content-Security-Policy` names its sha256. The pairing
/// is the point: a script on a page whose policy does not name it is a button that never
/// appears, and a hash in a policy with no script beside it is a page that allows a
/// constant it does not run.
#[test]
fn no_page_but_the_reveal_carries_a_script() {
    let path = scratch("nojs-all", SAMPLE);
    let served = cfg_for(&path, "");
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &served);
        }
    });

    for at in every_route() {
        let mut r = get_with_secret(format!("http://127.0.0.1:{port}{}", at.path()))
            .header(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("a response");
        assert_eq!(r.status(), 200, "{at:?}");
        let html = r.body_mut().read_to_string().unwrap();
        assert!(!html.contains("<script"), "a script tag on {at:?}");
        assert!(
            !html.contains("javascript:"),
            "a javascript: href on {at:?}"
        );

        for h in handlers_in(&html) {
            assert_eq!(
                h,
                format!("onchange=\"{SETTINGS_ONCHANGE}\""),
                "the only handler this GUI may carry is the Settings list box's, and \
                     {at:?} carries {h}"
            );
        }
        // The two Settings list boxes carry it, and the way through without a script is
        // on the page, inside <noscript>.
        assert_eq!(handlers_in(&html).len(), 2, "on {at:?}");
        assert!(
            html.contains("<noscript><div class=\"actions\"><button>"),
            "the no-script submit must be there, and inside noscript: {at:?}"
        );
    }
    cleanup(&path);

    let (cases, paths) = reveal_cases("reveal-script");
    for (label, g) in cases.iter() {
        assert_eq!(
            g.status,
            200,
            "{label}: a reveal is the direct `POST` response, so the walk below has one: \
                 {}",
            account_readable(&g.body)
        );
        let scripts = scripts_in(&g.body);
        assert_eq!(
            scripts.len(),
            1,
            "{label}: the reveal is the one page allowed a script, and it is allowed \
                 exactly one ({} found): {}",
            scripts.len(),
            account_readable(&g.body)
        );
        assert_eq!(
            g.body.matches("<script").count(),
            1,
            "{label}: one opening tag, whatever the count of blocks says"
        );
        // The policy and the page are derived from the same `&str`, which is the design's
        // argument for a hash over a nonce. This is what says so: the bytes in the page
        // *are* the constant the policy names, so neither can be edited alone.
        assert_eq!(
            scripts[0], COPY_SCRIPT,
            "{label}: the one script must be COPY_SCRIPT byte for byte, or the hash the \
                 policy names is not the hash of what runs"
        );
        let csp = g
            .header("Content-Security-Policy")
            .unwrap_or_else(|| panic!("{label}: every page carries a policy"));
        assert!(
            csp.contains(&csp_hash(COPY_SCRIPT)),
            "{label}: the policy of this very response must name the script it carries: {csp}"
        );

        // The handler rule is unchanged by the new script: both shells carry the shell's
        // two list boxes, and the copy button is wired with `addEventListener`, never an
        // attribute. Step 13 made the self-service shell the console's shell here too.
        let markup = markup_without_scripts(&g.body);
        let handlers = handlers_in(&markup);
        for h in handlers.iter() {
            assert_eq!(
                h,
                &format!("onchange=\"{SETTINGS_ONCHANGE}\""),
                "{label}: the copy script is a script, not a handler, and {h} is a handler"
            );
        }
        assert_eq!(
            handlers.len(),
            2,
            "{label}: both shells carry the same two Settings handlers, and the copy \
                 button adds no third"
        );
    }
    for p in paths {
        cleanup(&p);
    }
}

/// The content of every `<script …>…</script>` block in `html`, in document order.
fn scripts_in(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("<script") {
        let after = &rest[i + "<script".len()..];
        let Some(open) = after.find('>') else { break };
        let body = &rest[i + "<script".len() + open + 1..];
        let Some(close) = body.find("</script>") else {
            break;
        };
        out.push(body[..close].to_string());
        rest = &body[close + "</script>".len()..];
    }
    out
}

/// `html` with every script block replaced by an empty one, so [`handlers_in`] sees the
/// markup and not the script's own source. The scan is for **attributes**, and a string
/// inside a script (`" on click"`, `x = on;`) is not an attribute: an allowlist that
/// tripped on script text would be a rule about how the script happens to be spelled.
fn markup_without_scripts(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(i) = rest.find("<script") {
        let after = &rest[i + "<script".len()..];
        let Some(open) = after.find('>') else { break };
        let body = &rest[i + "<script".len() + open + 1..];
        let Some(close) = body.find("</script>") else {
            break;
        };
        out.push_str(&rest[..i]);
        out.push_str("<script></script>");
        rest = &body[close + "</script>".len()..];
    }
    out.push_str(rest);
    out
}

/// The reveal page shows **the key**, and nothing that reads like a credential header.
///
/// The user's decision (13.14) is that the page shows `bbk_…` alone, not the
/// `Authorization: Bearer` line. Two properties carry that, and both are about the bytes
/// a person copies:
///
/// * the text of `code#bearer` **is** the bearer, with nothing around it, and it occurs
///   exactly once in the response, so the one place the secret is is the one place a
///   click selects;
/// * the bearer is never glued to `Bearer `. The hint is allowed to *name* the header in
///   prose ("paste it as `Authorization: Bearer <key>`"), so a search for the word
///   `Authorization` is not the rule; the rule is that no occurrence of the secret sits
///   behind that prefix, which is what stops the page handing out a line somebody pastes
///   into the wrong field.
///
/// The button is checked here too, because it is the reason the script exists: a real
/// `type="button"` (the block is in no form, and a button that can submit one is a
/// mutation on a click) carrying `hidden`, so a browser with scripting off shows no
/// control that does nothing. Since §13.15 it is an **icon**, and §13.17 carries its name
/// as text inside the control (`span.vh`), so the shape this test has always wanted here is
/// the one that survives that: the control's words stay inside the control, adding nothing
/// to the block that shows the key, so the one thing a person reads there is the key. What
/// the icon needs in exchange, its name and its glyphs, is pinned by
/// [`the_copy_control_is_an_icon_with_a_name`].
#[test]
fn the_reveal_shows_only_the_key() {
    let (cases, paths) = reveal_cases("reveal-only");
    for (label, g) in cases.iter() {
        assert_eq!(g.status, 200, "{label}: {}", account_readable(&g.body));
        let shown = code_text(&g.body, "bearer");
        assert!(
            shown.starts_with("bbk_") && shown.len() >= 40,
            "{label}: the text of code#bearer is the credential itself, not a label and \
                 not a prefix of it: {shown:?}"
        );
        assert_eq!(
            g.body.matches(shown.as_str()).count(),
            1,
            "{label}: the bearer occurs exactly once in the response, and that one \
                 occurrence is the code element, since the code's text is the bearer"
        );
        assert!(
            !g.body.contains("Authorization: Bearer bbk_"),
            "{label}: no `Authorization: Bearer bbk_…` line anywhere in the response"
        );
        for (i, _) in g.body.match_indices(shown.as_str()) {
            let before = &g.body[i.saturating_sub(7)..i];
            assert_ne!(
                before, "Bearer ",
                "{label}: the key is shown alone, never as a header value"
            );
        }

        let tag = tag_containing(&g.body, "id=\"bearer-copy\"");
        let attrs: Vec<&str> = tag
            .trim_start_matches('<')
            .trim_end_matches('>')
            .split_whitespace()
            .collect();
        assert!(
            tag.starts_with("<button"),
            "{label}: the copy control is a button, and a link that runs a script is a \
                 link that does nothing with scripting off: {tag}"
        );
        assert!(
            attrs.contains(&"type=\"button\""),
            "{label}: type=\"button\", because a bare `button` is a submit button and \
                 this block sits where a form may later be wrapped around it: {tag}"
        );
        assert!(
            attrs
                .iter()
                .any(|a| *a == "hidden" || a.starts_with("hidden=")),
            "{label}: the button starts hidden, so the scripting-off page shows no dead \
                 control: {tag}"
        );
        // §13.17 moved the control's name into a `span.vh` **inside** the button, so "the
        // button's text is empty" is a claim about the old `aria-label` markup and is now
        // false of a correct control (the green `the_copy_control_is_an_icon_with_a_name`
        // pins that text as the name). What survives the move is the property this test was
        // after: the control's words belong to the control, so the block that shows the key
        // carries none of them outside it, and the one thing a person reads there is the key.
        let outside = g.body.replace(
            &element_containing(&g.body, "id=\"bearer-copy\"", "</button>"),
            "",
        );
        for word in ["Copy the key", "Copied", "Copy refused"] {
            assert!(
                !outside.contains(word),
                "{label}: the control's name and its status words are inside the control, \
                     so the reveal's text outside it carries no words of its own: {word}"
            );
        }
    }
    for p in paths {
        cleanup(&p);
    }
}

/// The copy script is allowed **on the reveal and nowhere else**.
///
/// The widening is a response path, not a flag every page passes (13.14), so the
/// assertions go both ways: the `false` policies name no copy hash at all (step 13 gave the
/// self-service page the Preferences handler's hash, and the copy script stays out), the
/// `true` ones name the copy hash, and
/// over the wire no page in the estate names it except the four reveals. A policy that
/// names a script the page does not carry is harmless to a browser and a slow rot: it is
/// the page that gains a script later, by accident, that this pins shut.
///
/// The two refusals on the mint path are here for the same reason: a `400` (a window the
/// page refuses) and a `409` (the `rev` the reveal page still holds) are rendered by the
/// same code as the reveal, and neither mints anything, so neither has a key to copy.
#[test]
fn only_the_reveal_policy_names_the_copy_script() {
    let hash = csp_hash(COPY_SCRIPT);

    let plain = admin_csp(&Look::default(), false);
    assert!(
        !plain.contains(&hash),
        "a console page with no script must not allow one: {plain}"
    );
    assert!(
        admin_csp(&Look::default(), true).contains(&hash),
        "the console's reveal policy must name the script the reveal carries"
    );

    let plain = account_csp(&AccountLook::default(), false);
    assert!(
        !plain.contains(&hash),
        "the self-service page's own rule is that it carries no script: {plain}"
    );
    // Step 13: the page's two list boxes submit through the shell's handler, so its policy
    // admits that handler by hash, and the directive is the **console's**, because one rule
    // about what may run cannot have two answers on two surfaces.
    assert_eq!(
        script_src(&plain),
        script_src(&admin_csp(&Look::default(), false)),
        "the page's script-src is the console's, and names the handler and nothing else: \
             {plain}"
    );
    let reveal = account_csp(&AccountLook::default(), true);
    assert!(
        reveal.contains(&hash),
        "the self-service reveal policy must name the script the reveal carries"
    );
    assert!(
        !reveal.contains("script-src 'none'"),
        "a policy that says `'none'` and names a hash is a policy that runs nothing: {reveal}"
    );
    assert_eq!(
        script_src(&reveal),
        script_src(&admin_csp(&Look::default(), true)),
        "and the reveal's directive is the console's too: {reveal}"
    );

    // Over the wire: every console page, and the self-service page, carry a policy that
    // names no script.
    let path = scratch("reveal-csp", SAMPLE);
    let served = cfg_for(&path, ADMIN_BASE);
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &served);
        }
    });
    for at in every_route() {
        let g = got_of(
            get_with_secret(format!("http://127.0.0.1:{port}{ADMIN_BASE}{}", at.path()))
                .header(IDENTITY_HEADER, "admin@x.com")
                .call()
                .expect("a response"),
        );
        let csp = g
            .header("Content-Security-Policy")
            .unwrap_or_else(|| panic!("{at:?}: every page carries a policy"));
        assert!(
            !csp.contains(&hash),
            "{at:?} carries no script, so its policy must not allow one: {csp}"
        );
    }
    cleanup(&path);

    let apath = account_scratch_access("reveal-csp-account", &account_access_mint());
    let base = account_serve(&apath);
    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(g.status, 200, "bob reaches the page");
    let csp = g
        .header("Content-Security-Policy")
        .expect("the page carries a policy");
    assert!(
        !csp.contains(&hash),
        "the page that offers the mint form carries no script: {csp}"
    );

    // The `400`: a duration this page refuses to mint. §13.15 made `never` a choice the page
    // offers (and `a_self_service_key_may_never_expire` pins it as a `200`), so the refusal
    // here is the empty field, the one the grammar reads as no expiry and the page refuses
    // rather than minting a key that never dies. The `409`: the same form posted again,
    // which is what reloading the reveal page does.
    let mint = format!("{base}keys");
    let rev = sha256_hex(&read(&apath));
    let bad = account_post(
        &mint,
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "refused"),
            ("duration", ""),
            ("restrict", "all"),
        ],
    );
    assert_eq!(
        bad.status,
        400,
        "an empty duration is a 400: {}",
        account_readable(&bad.body)
    );
    assert!(
        !bad.body.contains("<script"),
        "a refusal mints nothing, so it has no key to copy"
    );
    assert!(
        !bad.header("Content-Security-Policy")
            .unwrap_or_default()
            .contains(&hash),
        "and its policy allows no script"
    );

    // The `409`: the reveal page's own `rev`, posted again. The mint's write is what
    // makes it stale, so the mint has to happen first, and the replay has to name the
    // key the mint created (a stale `rev` on a key that exists is the mint's own 409).
    let fields = [
        ("rev", rev.as_str()),
        ("id", "again"),
        ("duration", "30d"),
        ("restrict", "all"),
    ];
    let minted = account_post(&mint, Some("bob@x.com"), &fields);
    assert_eq!(
        minted.status,
        200,
        "the mint itself, so its own `rev` is the stale one: {}",
        account_readable(&minted.body)
    );
    let replay = account_post(&mint, Some("bob@x.com"), &fields);
    assert_eq!(
        replay.status,
        409,
        "the reveal page's own `rev` is stale by its own write: {}",
        account_readable(&replay.body)
    );
    assert!(
        !replay.body.contains("<script"),
        "a 409 has no bearer, so it has nothing to copy"
    );
    assert!(
        !replay
            .header("Content-Security-Policy")
            .unwrap_or_default()
            .contains(&hash),
        "and its policy allows no script"
    );
    cleanup(&apath);

    // The console's two refusals, over its socket.
    let path = scratch("reveal-csp-console", SAMPLE);
    let served = cfg_for(&path, ADMIN_BASE);
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &served);
        }
    });
    let rev = rev_of(&path);
    let bad = console_post(
        port,
        &Route::KeyAdd(BOB.to_string()),
        &[("rev", &rev), ("id", ""), ("duration", "365d")],
    );
    assert_eq!(
        bad.status,
        400,
        "a key with no id is a 400, not a mint: {}",
        account_readable(&bad.body)
    );
    assert!(
        !bad.body.contains("<script"),
        "the console's 400 carries no script"
    );
    assert!(
        !bad.header("Content-Security-Policy")
            .unwrap_or_default()
            .contains(&hash),
        "and no script in its policy"
    );
    let fields = [("rev", rev.as_str()), ("id", "ci"), ("duration", "365d")];
    let minted = console_post(port, &Route::KeyAdd(BOB.to_string()), &fields);
    assert_eq!(
        minted.status,
        200,
        "the mint itself, so its own `rev` is the stale one: {}",
        account_readable(&minted.body)
    );
    let replay = console_post(port, &Route::KeyAdd(BOB.to_string()), &fields);
    assert_eq!(
        replay.status,
        409,
        "a replay of the mint form is the 409, and it is rendered by the code that \
             renders the reveal: {}",
        account_readable(&replay.body)
    );
    assert!(
        !replay.body.contains("<script"),
        "the console's 409 carries no script"
    );
    assert!(
        !replay
            .header("Content-Security-Policy")
            .unwrap_or_default()
            .contains(&hash),
        "and no script in its policy"
    );
    cleanup(&path);
}

/// The `script-src` directive of a policy, trimmed. A policy is `;`-separated directives,
/// and a claim about **what may run** is a claim about that one, so an assertion written
/// against the whole header passes when an unrelated directive changes.
fn script_src(csp: &str) -> String {
    csp.split(';')
        .map(str::trim)
        .find(|d| d.starts_with("script-src"))
        .unwrap_or("<no script-src>")
        .to_string()
}

/// Does [`every_route`] still name every page there is?
///
/// The `match` is the check and the compiler is what runs it: it is exhaustive, so a new
/// `Route` variant does not compile until somebody has looked at this list, and the
/// count then says whether they added it to `every_route` as well. Without this, the
/// no-script guarantee quietly stops covering the newest page, which is the page most
/// likely to have reached for a script.
#[test]
fn every_route_covers_every_variant() {
    fn variant(at: &Route) -> usize {
        match at {
            Route::Dashboard => 0,
            Route::Apps => 1,
            Route::App(_) => 2,
            Route::Denied => 3,
            Route::Users => 4,
            Route::User(_) => 5,
            Route::Config => 6,
            Route::AppAdd => 7,
            Route::AppEdit(_) => 8,
            Route::AppRm(_) => 9,
            Route::ScopeAdd(_) => 10,
            Route::ScopeEdit(_, _) => 11,
            Route::ScopeRm(_, _) => 12,
            Route::ScopeMove(_, _) => 13,
            Route::UserAdd => 14,
            Route::UserEdit(_) => 15,
            Route::UserRm(_) => 16,
            Route::EmailAdd(_) => 17,
            Route::EmailRm(_, _) => 18,
            Route::KeyAdd(_) => 19,
            Route::KeyEdit(_, _) => 20,
            Route::KeyRotate(_, _) => 21,
            Route::KeyRm(_, _) => 22,
            Route::GroupAdd => 23,
            Route::GroupEdit(_) => 24,
            Route::GroupRm(_) => 25,
            Route::DenyAdd => 26,
            Route::DenyRm(_) => 27,
            Route::Audit => 28,
            Route::Groups => 29,
            Route::Group(_) => 30,
        }
    }
    let seen: std::collections::HashSet<usize> = every_route().iter().map(variant).collect();
    // All of them but `ScopeMove`, which has no page to render: it is POST only.
    let missing: Vec<usize> = (0..=29).filter(|i| !seen.contains(i)).collect();
    assert_eq!(missing, vec![13], "every_route must name every page");
}

#[test]
fn the_settings_menu_is_a_get_that_carries_the_rest_of_the_query() {
    // A GET, because it mutates nothing: every POST in this binary is a write to the
    // access file, guarded by the rev and the same-origin check, and a display
    // preference is neither.
    let cfg = cfg_for("x.json", "/admin");
    let mut v = view(&cfg, Route::App("mpa".to_string()), "REV");
    v.query = "email=bob%40x.com&lang=en&theme=dark";
    let html = shell(&v, "t", html! { "x" }).into_string();
    // §13.28 §2: the form lives in the nested Preferences box now, so it is found there and
    // not by a class. The class is the coder's; what must not move is that a GET goes back to
    // the page it is on, which is what keeps a filter and a pager alive across a theme change.
    let prefs = nested_block(&html, "<details class=\"prefs\">", "details");
    let forms = elements(&prefs, "<form", "</form>");
    assert_eq!(forms.len(), 1, "one form in the box: {prefs}");
    let form = open_tag(&forms[0]);
    assert_eq!(attr(form, "method").as_deref(), Some("get"), "{form}");
    assert_eq!(
        attr(form, "action").as_deref(),
        Some("/admin/apps/mpa"),
        "{form}"
    );
    // The access check's own fields survive the round trip; the two parameters the form
    // sets itself do not come back as hidden fields, or the list boxes could never
    // change them.
    assert!(
        html.contains(r#"<input type="hidden" name="email" value="bob@x.com">"#),
        "{html}"
    );
    assert!(!html.contains(r#"type="hidden" name="lang""#), "{html}");
    assert!(!html.contains(r#"type="hidden" name="theme""#), "{html}");
}
