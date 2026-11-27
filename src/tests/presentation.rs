use super::*;

/// The hash a policy names has to be the hash a *browser* computes, and the difference
/// between the two is invisible from inside this crate.
///
/// An HTML parser normalises the document's newlines before the CSP check ever runs, so a
/// browser hashes the block with every CRLF already collapsed. This repository is
/// developed on a CRLF checkout (`core.autocrlf=true`), `include_str!` embeds the
/// stylesheets exactly as they sit on disk, and the release is cross-compiled from that
/// same tree: hashing the raw bytes ships a binary whose every page carries a policy that
/// refuses its own stylesheet, with nothing in any log and nothing in a test that only
/// compares this function against itself. Hence the literal below rather than a
/// round trip.
#[test]
fn a_hash_names_the_newlines_a_browser_sees_and_not_the_ones_on_disk() {
    let crlf = "a{color:red}\r\nb{color:blue}\r\n";
    let lf = "a{color:red}\nb{color:blue}\n";
    assert_eq!(csp_hash(crlf), csp_hash(lf));
    assert_eq!(
        csp_hash(lf),
        "'sha256-S20dnUqfVjBZxb8Zswwd1Uxqocz3m5nEgSQSEQdyC7w='"
    );
}

#[test]
fn the_theme_defines_every_token_in_all_four_arms() {
    // The dark list is written twice on purpose (see theme.css), and the two copies have
    // to stay in step by hand. This is what notices when one of them does not.
    let arms: Vec<&str> = THEME_CSS.split("--bg:").collect();
    assert_eq!(arms.len(), 4, "one light arm and two dark ones define --bg");
    for token in [
        // `--bg-grad:` does not contain `--bg:`, so the split above does not see it and it
        // has to be listed here like any other. It is in the list at all because the ground
        // is now a gradient in both arms: a dark arm that forgot it would paint the light
        // theme's gradient over the dark theme's fill.
        "--bg-grad:",
        "--card:",
        "--card-border:",
        "--text:",
        "--muted:",
        "--input-bg:",
        "--input-border:",
        "--accent:",
        "--accent-hover:",
        "--accent-weak:",
        "--on-accent:",
        "--ok:",
        "--ok-bg:",
        "--warn:",
        "--warn-bg:",
        "--error:",
        "--error-bg:",
        "--on-state:",
        "--chip:",
        "--logo-filter:",
        "--shadow-lg:",
        "--shadow-md:",
    ] {
        assert_eq!(
            THEME_CSS.matches(token).count(),
            3,
            "{token} must be defined in the light arm and in both dark arms"
        );
    }
    // Shape and typography are theme-independent and defined exactly once, in the light
    // arm: a radius does not change with the palette.
    for token in [
        "--r-box:",
        "--r-ctl:",
        "--r-pill:",
        "--fs-sm:",
        "--font-ui:",
        "--font-mono:",
    ] {
        assert_eq!(
            THEME_CSS.matches(token).count(),
            1,
            "{token} is not a colour"
        );
    }
    // The selectors that make an explicit choice outrank the OS.
    assert!(THEME_CSS.contains(":root[data-theme=dark]"));
    assert!(THEME_CSS.contains(":root[data-theme=light]"));
    assert!(THEME_CSS.contains("@media (prefers-color-scheme:dark){:root:not([data-theme=light])"));
}

/// Everything a CSS comment says, removed. The prose in all four stylesheets talks about
/// colours by name and by hex on purpose, so a scan that did not strip comments would be
/// a scan of the documentation.
#[cfg(test)]
fn without_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(open) = rest.find("/*") {
        out.push_str(&rest[..open]);
        match rest[open..].find("*/") {
            Some(close) => rest = &rest[open + close + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Every rule of a stylesheet as `(selector, declarations)`, comments and all whitespace
/// removed. A rule inside an at-rule reports its own selector. Good enough for this
/// project's flat stylesheets, which is all it is used on.
#[cfg(test)]
fn flat_rules(css: &str) -> Vec<(String, String)> {
    let code: String = without_comments(css)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut rules = Vec::new();
    for chunk in code.split('}') {
        let parts: Vec<&str> = chunk.split('{').collect();
        if parts.len() >= 2 {
            rules.push((
                parts[parts.len() - 2].to_string(),
                parts[parts.len() - 1].to_string(),
            ));
        }
    }
    rules
}

/// The four arms of `THEME_CSS`, each as the declarations between its braces:
/// light (`:root`), the dark media arm, and the explicit `data-theme` dark arm.
/// The explicit light arm only sets `color-scheme` and is not an arm of values.
#[cfg(test)]
fn theme_arms() -> Vec<(&'static str, String)> {
    let code = without_comments(THEME_CSS);
    let light_start = code.find(":root{").expect("light arm");
    let light_end = code[light_start..].find("\n}").expect("light end") + light_start;
    let media = code
        .find("@media (prefers-color-scheme:dark)")
        .expect("media arm");
    let media_end = code[media..].find("}}").expect("media end") + media;
    let dark = code.find(":root[data-theme=dark]{").expect("dark arm");
    let dark_end = code[dark..].find("\n}").expect("dark end") + dark;
    vec![
        ("light", code[light_start..light_end].to_string()),
        ("dark (media)", code[media..media_end].to_string()),
        ("dark (explicit)", code[dark..dark_end].to_string()),
    ]
}

/// The value a custom property takes inside one arm's text.
#[cfg(test)]
fn arm_value(arm: &str, token: &str) -> String {
    let needle = format!("{token}:");
    let at = arm
        .find(&needle)
        .unwrap_or_else(|| panic!("{token} missing in arm"));
    let rest = &arm[at + needle.len()..];
    rest[..rest.find(';').unwrap()].trim().to_string()
}

#[cfg(test)]
fn hex_luminance(hex: &str) -> f64 {
    let h = hex.trim().trim_start_matches('#');
    assert_eq!(h.len(), 6, "expected #rrggbb, got {hex}");
    let ch = |i: usize| {
        let v = f64::from(u8::from_str_radix(&h[i..i + 2], 16).unwrap()) / 255.0;
        if v <= 0.03928 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * ch(0) + 0.7152 * ch(2) + 0.0722 * ch(4)
}

#[cfg(test)]
fn contrast(a: &str, b: &str) -> f64 {
    let (la, lb) = (hex_luminance(a), hex_luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// The theme contract of slice 8d: the set of custom properties `THEME_CSS` defines is
/// fixed, so an operator's token file written against today's names keeps working. A
/// rename or a removal is red; so is a new name, which would be a contract change that
/// needs the design's say-so first. Green today and meant to stay green.
#[test]
fn the_token_set_is_the_contract() {
    let code = without_comments(THEME_CSS);
    let mut found: std::collections::BTreeSet<String> = Default::default();
    let bytes = code.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if &bytes[i..i + 2] == b"--" && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let rest = &code[i..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .unwrap();
            if rest[end..].starts_with(':') {
                found.insert(rest[..end].to_string());
            }
            i += end.max(2);
        } else {
            i += 1;
        }
    }
    let expected: std::collections::BTreeSet<String> = [
        "--bg",
        "--bg-grad",
        "--card",
        "--card-border",
        "--text",
        "--muted",
        "--input-bg",
        "--input-border",
        "--accent",
        "--accent-hover",
        "--accent-weak",
        "--on-accent",
        "--ok",
        "--ok-bg",
        "--warn",
        "--warn-bg",
        "--error",
        "--error-bg",
        "--on-state",
        "--chip",
        "--logo-filter",
        "--shadow-lg",
        "--shadow-md",
        "--r-box",
        "--r-ctl",
        "--r-pill",
        "--fs-sm",
        "--font-ui",
        "--font-mono",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(expected.len(), 29);
    assert_eq!(
        found, expected,
        "THEME_CSS must define exactly the 29 contract tokens"
    );
}

/// WCAG 2.2 SC 1.4.11: the boundary of a field must be 3:1 against what it sits on, which
/// is the card (or the page) around it and its own fill. All four arms are read, because
/// the dark list is written twice and an edit to one copy is easy to miss.
#[test]
fn fields_have_a_three_to_one_border_in_every_arm() {
    let arms = theme_arms();
    assert_eq!(
        arms.len(),
        3,
        "light, dark media, dark explicit (the 4th sets no values)"
    );
    for (name, arm) in &arms {
        let border = arm_value(arm, "--input-border");
        for neighbour in ["--card", "--input-bg", "--bg"] {
            let other = arm_value(arm, neighbour);
            let ratio = contrast(&border, &other);
            // The page behind a light field is only the outer neighbour, so it is
            // held to the same bar as the card the field normally sits on.
            assert!(
                ratio >= 3.0,
                "{name}: --input-border {border} on {neighbour} {other} is {ratio:.2}:1, needs 3:1"
            );
        }
    }
}

/// The glow behind a page is painted once at the top. Without `no-repeat` it starts again
/// one viewport down, a hard band across any page longer than the window.
#[test]
fn the_ground_is_painted_once() {
    let body = flat_rules(BASE_CSS)
        .into_iter()
        .find(|(sel, _)| sel == "body")
        .expect("base.css has a body rule");
    assert!(
        body.1
            .contains("background:var(--bg-grad)no-repeat,var(--bg)"),
        "body background must read `var(--bg-grad) no-repeat,var(--bg)`, got {}",
        body.1
    );
}

/// A shadow says "this floats above the page". The surfaces in normal flow carry none; the
/// sign-in card and the preferences menu, which do float, name theirs.
#[test]
fn only_floating_surfaces_cast_a_shadow() {
    let surface = ".card,.panel,.msg,.flash,.err,.secret";
    let base = flat_rules(BASE_CSS);
    let rule = base
        .iter()
        .find(|(sel, _)| sel == surface)
        .expect("the shared surface rule");
    assert!(
        rule.1.contains("box-shadow:none"),
        "surface rule: {}",
        rule.1
    );

    let auth = include_str!("../assets/auth.css");
    let admin = include_str!("../assets/admin.css");
    for (file, css) in [
        ("base.css", BASE_CSS),
        ("auth.css", auth),
        ("admin.css", admin),
    ] {
        for (sel, decls) in flat_rules(css) {
            for token in ["var(--shadow-lg)", "var(--shadow-md)"] {
                if decls.contains(token) {
                    let allowed = (file == "auth.css"
                        && sel == ".card"
                        && token == "var(--shadow-lg)")
                        || (file == "admin.css" && sel == ".menu" && token == "var(--shadow-md)");
                    assert!(allowed, "{file}: `{sel}` casts {token}; only auth .card (lg) and admin .menu (md) may");
                }
            }
        }
    }
    assert!(flat_rules(auth)
        .iter()
        .any(|(s, d)| s == ".card" && d.contains("box-shadow:var(--shadow-lg)")));
    assert!(flat_rules(admin)
        .iter()
        .any(|(s, d)| s == ".menu" && d.contains("box-shadow:var(--shadow-md)")));
}

/// The declarations of every rule whose selector list names `selector` (whitespace-free,
/// as [`flat_rules`] spells it), in file order. A rule inside a `@media` block counts.
#[cfg(test)]
fn rules_named(css: &str, selector: &str) -> Vec<String> {
    flat_rules(css)
        .into_iter()
        .filter(|(sel, _)| sel.split(',').any(|s| s == selector))
        .map(|(_, d)| d)
        .collect()
}

/// §13.18 (8e): the type scale. `h1` 1.5rem / 1.25 / 650 / -.01em, `h2` 1.0625rem / 600,
/// with the margins the section gives (`flat_rules` strips whitespace, hence `margin:006px`).
#[test]
fn the_headings_follow_the_type_scale() {
    let h1 = rules_named(BASE_CSS, "h1");
    assert_eq!(h1.len(), 1, "one `h1` rule");
    for want in [
        "font-size:1.5rem",
        "line-height:1.25",
        "font-weight:650",
        "letter-spacing:-.01em",
        "margin:006px",
    ] {
        assert!(h1[0].contains(want), "h1 lacks {want}: {}", h1[0]);
    }
    let h2 = rules_named(BASE_CSS, "h2");
    assert_eq!(h2.len(), 1, "one `h2` rule");
    for want in ["font-size:1.0625rem", "font-weight:600", "margin:28px010px"] {
        assert!(h2[0].contains(want), "h2 lacks {want}: {}", h2[0]);
    }
}

/// §13.18 (8d-2): the secondary pill is neutral. Text `--text`, a 3:1 `--input-border` box,
/// and the accent fill belongs to `.pill.on` alone.
#[test]
fn the_secondary_pill_is_neutral() {
    let pill = rules_named(BASE_CSS, ".pill");
    assert_eq!(pill.len(), 1, "one `.pill` rule");
    assert!(pill[0].contains("color:var(--text)"), "text: {}", pill[0]);
    assert!(
        pill[0].contains("var(--input-border)"),
        "border: {}",
        pill[0]
    );
    assert!(!pill[0].contains("currentColor"), "border: {}", pill[0]);
    assert!(
        !pill[0].contains("color:var(--accent)"),
        "text: {}",
        pill[0]
    );
    for (sel, decls) in flat_rules(BASE_CSS) {
        if sel.contains(".pill") && decls.contains("background:var(--accent)") {
            assert_eq!(sel, ".pill.on,.pill.on:hover", "only .pill.on fills accent");
        }
    }
    let hover = rules_named(BASE_CSS, ".pill:hover");
    assert!(
        hover.iter().any(|d| d.contains("background:var(--chip)")
            && d.contains("border-color:var(--accent)")
            && d.contains("color:var(--accent)")),
        "hover: {hover:?}"
    );
}

/// §13.18 (8d-2): a pill in a `nav` is a tab, with no visible box at rest.
#[test]
fn a_pill_in_a_nav_is_a_tab() {
    let tab = rules_named(BASE_CSS, "nav.pill");
    assert_eq!(tab.len(), 1, "a `nav .pill` rule in BASE_CSS");
    assert!(tab[0].contains("var(--card)"), "box: {}", tab[0]);
    assert!(!tab[0].contains("var(--card-border)"), "box: {}", tab[0]);
    assert!(tab[0].contains("color:var(--muted)"), "text: {}", tab[0]);
    let hover = rules_named(BASE_CSS, "nav.pill:hover");
    assert!(
        hover.iter().any(|d| d.contains("background:var(--chip)")),
        "hover: {hover:?}"
    );
}

/// §13.18 (8d-2): links in a table cell or a list item are plain at rest and underlined
/// on hover.
#[test]
fn table_links_underline_on_hover() {
    for at_rest in ["tda", "lia"] {
        let rest = rules_named(BASE_CSS, at_rest);
        assert!(
            rest.iter().any(|d| d.contains("text-decoration:none")),
            "`{at_rest}` has no text-decoration:none rule"
        );
        let hover = rules_named(BASE_CSS, &format!("{at_rest}:hover"));
        assert!(
            hover
                .iter()
                .any(|d| d.contains("text-decoration:underline")),
            "`{at_rest}:hover` has no underline rule"
        );
    }
}

/// §13.18 (8d-2), `admin.css`: the bar shares `main`'s column, the header's pills are
/// tabs and not buttons, a pill beside a button has the button's measure, and the tiles
/// fill one row.
///
/// §13.26 (5g): the account page is the console's width, so the bar shares *one* column and
/// nothing narrows it for one surface. The `.selfserve` width rules are gone, and the
/// reading measure that replaces them (`main p.lede` at 75ch, a profile field at 40ch) is
/// asserted here because it is the rule that keeps a 1000px column readable on both pages.
///
/// §13.26 ("F. The flat ground"): the body override that painted this page's ground flat is
/// gone too, so the bare `body:has(.selfserve)` rule joins the forbidden list. The account
/// page wears the estate's ground, and `rules_named` matches one part of a selector list
/// exactly (whitespace-free), so the rule is named by its own spelling.
#[test]
fn the_header_shares_the_content_column() {
    let admin = include_str!("../assets/admin.css");
    let has = |sel: &str, want: &str| {
        let rules = rules_named(admin, sel);
        assert!(
            rules.iter().any(|d| d.contains(want)),
            "`{sel}` lacks `{want}` (rules: {rules:?})"
        );
    };
    has("header.top", "padding:10px0");
    has("header.top", "padding:6px0");
    has(".bar", "padding:016px");
    for gone in [
        ".selfserve",
        "body:has(.selfserve)",
        "body:has(.selfserve).bar",
        ".selfserve.panelh2",
    ] {
        assert!(
            rules_named(admin, gone).is_empty(),
            "`{gone}` must be gone: the account page is the console's column and wears the \
                 estate's ground, and a rule naming `.selfserve` alone is the drift §13.26 \
                 deletes ({:?})",
            rules_named(admin, gone)
        );
    }
    // `rules_named` matches one part of a selector list at a time, so each arm of the
    // measure is looked up on its own, and both must land on the same one rule (that is
    // the point of one rule for both surfaces).
    for arm in ["mainp.lede", "mainp.muted"] {
        let rules = rules_named(admin, arm);
        assert_eq!(rules.len(), 1, "`{arm}` needs exactly one rule: {rules:?}");
        assert!(
            rules[0].contains("max-width:75ch"),
            "`{arm}` lacks the reading measure: {}",
            rules[0]
        );
    }
    has("input.f-profile", "max-width:40ch");
    // §13.23: the profile code field is a short numeric token, so it wears the short-id
    // measure and not the 40ch one above it: a full-width box reads as "type a sentence".
    has("input.f-code", "max-width:14ch");
    has(".bar.pill", "font-size:.95rem");
    has(".bar.pill", "padding:6px12px");
    has(".bar.pill.ico", "padding:6px");
    has("p.primary.pill", "font-size:inherit");
    has("p.primary.pill", "line-height:1.55");
    has("p.primary.pill", "padding:9px16px");
    has(".actions.pill", "line-height:1.55");
    has(".actions.pill", "padding:9px16px");
    has(".cards", "repeat(auto-fill,minmax(140px,1fr))");
}

/// A surface owns its padding, so its first child's top margin and its last child's bottom
/// margin do not add an empty band inside it.
#[test]
fn a_surface_owns_its_padding() {
    let rules = flat_rules(BASE_CSS);
    for (child, decl) in [
        (":first-child", "margin-top:0"),
        (":last-child", "margin-bottom:0"),
    ] {
        let found = rules.iter().any(|(sel, decls)| {
            [".card", ".panel", ".msg", ".flash", ".err", ".secret"]
                .iter()
                .all(|s| sel.split(',').any(|part| part == format!("{s}>{child}")))
                && decls.contains(decl)
        });
        assert!(
            found,
            "base.css needs one rule over all six surfaces: `>{child}{{{decl}}}`"
        );
    }
}

/// §13.21 (3): a ticked radio or checkbox wears the palette's accent, not the engine's
/// own blue.
#[test]
fn ticks_wear_the_accent() {
    // `rules_named` matches one selector of a list at a time, so each kind is looked up
    // on its own and must find the same single rule.
    for kind in ["input[type=radio]", "input[type=checkbox]"] {
        let rules = rules_named(BASE_CSS, kind);
        assert_eq!(rules.len(), 1, "one rule tints `{kind}`");
        assert!(
            rules[0].contains("accent-color:var(--accent)"),
            "the tint of `{kind}` is the accent token: {}",
            rules[0]
        );
    }
}

#[test]
fn only_the_palette_names_a_colour() {
    // The contract that makes `ui.stylesheet_url` a TOKEN file: a deployment restyles both
    // programs by redefining custom properties, which only works while every other
    // stylesheet reads them and states none of its own. One literal in a layout and that
    // stops being true for whatever it paints, silently and only in one of the two
    // surfaces — the exact failure this is here to catch.
    //
    // Both layouts are checked here, in the library, and not each in its own binary,
    // because the rule is not "this layout is tidy": it is that the shared files are the
    // ONLY answer to what a colour is worth, which is a statement about all of them at
    // once and belongs where the shared files live.
    for (name, css) in [
        ("base.css", BASE_CSS),
        (
            "auth.css (the gate's layout)",
            include_str!("../assets/auth.css"),
        ),
        (
            "admin.css (bb-auth-web's layout)",
            include_str!("../assets/admin.css"),
        ),
    ] {
        let code = without_comments(css);
        assert!(
            !code.contains('#'),
            "{name} names a colour by hex; it may only read one from theme.css"
        );
        // Every other way CSS has of writing a colour, not just `rgb`. The scan used to
        // be `#` and `rgb`, which let `hsl()`, `oklch()`, `color-mix()` and the 148 named
        // colours through: a rule that only catches the spelling somebody happened to
        // think of is a rule that stops holding the first time somebody writes it
        // differently.
        for how in [
            "rgb(",
            "rgba(",
            "hsl(",
            "hsla(",
            "hwb(",
            "lab(",
            "lch(",
            "oklab(",
            "oklch(",
            "color(",
            "color-mix(",
            "light-dark(",
        ] {
            assert!(
                !code.contains(how),
                "{name} names a colour with {how}; it may only read one from theme.css"
            );
        }
        // The named colours worth naming: the ones somebody actually reaches for, and
        // `transparent` and `currentColor` deliberately not among them (neither is a
        // colour a token file could have supplied instead).
        for named in [
            ":white", ":black", ":red", ":green", ":blue", ":gray", ":grey", ":silver", ":orange",
            ":yellow", ":purple", ":pink", ":brown", ":navy", ":teal", ":lime", ":aqua", ":cyan",
            ":magenta", ":gold", ":crimson",
        ] {
            assert!(
                !code.replace(' ', "").contains(named),
                "{name} names the colour {named}; it may only read one from theme.css"
            );
        }
    }
}

#[test]
fn the_components_are_shared_and_the_layouts_only_arrange_them() {
    // What "one product" means mechanically: the objects a person operates are defined
    // once, in the file both programs emit, so a change to a button's shape or a field's
    // height cannot reach one surface and miss the other. The four below are the ones that
    // had actually drifted when this was written — the sign-in page's rectangles against
    // the admin's lozenges, its 12px fields against the admin's 7px ones.
    for object in ["button{", ".pill{", ".tag{", ".card,.panel,"] {
        assert!(
            BASE_CSS.contains(object),
            "{object} belongs to the shared component layer"
        );
    }
    // And the negative half, which is the one that rots: a layout that starts redefining a
    // control has taken it back, and only its own program will ever see the change.
    //
    // A TOP-LEVEL rule is what that looks like: a selector at column zero. An indented one
    // is inside a media query, where a layout adjusting a control's padding at a
    // breakpoint is arrangement and is allowed (`admin.css` does exactly that, on
    // purpose). The whitespace before the brace is normalised, because `button {` and
    // `button{` are the same rule and the previous scan for `"\nbutton{"` saw only the
    // second: a rule a reformat can switch off is not a rule.
    for (name, css) in [
        ("admin.css", include_str!("../assets/admin.css")),
        ("auth.css", include_str!("../assets/auth.css")),
    ] {
        for line in without_comments(css).lines() {
            if line.starts_with(char::is_whitespace) {
                continue;
            }
            let flat: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            for selector in ["button{", ".pill{", ".tag{"] {
                assert!(
                    !flat.starts_with(selector),
                    "{name} redefines {selector} at the top level: a layout may arrange \
                         the shared controls, never redefine one"
                );
            }
        }
    }
}

/// The two settings a deployment can point at another host, and the policy that has to
/// let them through.
///
/// This is the pairing with something to get wrong. `ui.stylesheet_url` and
/// `ui.logo_url` are the only external references either program emits, and the same
/// two values feed the `<link>`/`<img>` and the policy that decides whether the browser
/// will fetch them. Derive the policy from anything but those values and a deployment
/// with a logo gets a page that renders without one, with nothing in the response to say
/// why: the header is present, the element is present, and the browser refuses.
///
/// Three shapes each, because [`compile_asset_url`] admits exactly three: an absolute
/// `https://` URL (its origin joins the policy), a root-relative path (`'self'` does),
/// and unset (nothing does, and the built-in stylesheet stands alone).
#[test]
fn the_policy_admits_exactly_the_asset_hosts_the_settings_name() {
    let csp = |style: Option<&str>, logo: Option<&str>| {
        page_csp("'nonce-N'", "'nonce-N'", "'self'", style, logo, &[])
    };

    // Neither set: nothing external may load, and an image may still be a data: URI,
    // which cannot script and is the one way a logo travels inside the page.
    let none = csp(None, None);
    assert!(none.contains("style-src 'nonce-N';"), "{none}");
    assert!(none.contains("img-src data:;"), "{none}");
    // No font at all: the built-in CSS names system faces and fetches nothing.
    assert!(none.contains("font-src 'none';"), "{none}");

    // Both on another host: that origin, and only that origin, joins the two lists.
    let both = csp(
        Some("https://assets.badbat75.com/css/theme.css"),
        Some("https://assets.badbat75.com/img/logo.svg"),
    );
    assert!(
        both.contains("style-src 'nonce-N' https://assets.badbat75.com;"),
        "the stylesheet's origin must be in style-src: {both}"
    );
    assert!(
        both.contains("img-src https://assets.badbat75.com data:;"),
        "the logo's origin must be in img-src: {both}"
    );
    // A stylesheet may bring its own @font-face, from where it came from and nowhere
    // else. Here that is the same host as the logo, so the mixed case below is the one
    // that pins which of the two settings font-src actually follows.
    assert!(
        both.contains("font-src https://assets.badbat75.com data:;"),
        "the stylesheet's origin must be in font-src: {both}"
    );
    // The path is NOT in the policy: a source expression is an origin, and carrying the
    // path would stop the next file on that host from loading.
    assert!(!both.contains("/css/theme.css"), "{both}");
    assert!(!both.contains("/img/logo.svg"), "{both}");

    // Root-relative, which is the better answer when the same vhost serves them: the
    // page's own origin, spelled the way a policy spells it.
    let own = csp(Some("/css/theme.css"), Some("/img/logo.svg"));
    assert!(own.contains("style-src 'nonce-N' 'self';"), "{own}");
    assert!(own.contains("img-src 'self' data:;"), "{own}");

    // One of each, which is an ordinary deployment: a shared asset host for the
    // stylesheet, the logo served beside the page.
    let mixed = csp(Some("https://cdn.example.com/t.css"), Some("/logo.png"));
    assert!(
        mixed.contains("style-src 'nonce-N' https://cdn.example.com;"),
        "{mixed}"
    );
    assert!(mixed.contains("img-src 'self' data:;"), "{mixed}");
    // font-src follows the STYLESHEET and not the logo: the typeface travels with the
    // file that asks for it.
    assert!(
        mixed.contains("font-src https://cdn.example.com data:;"),
        "{mixed}"
    );

    // A logo but no stylesheet: an image host, and still no font anywhere.
    let logo_only = csp(None, Some("https://assets.badbat75.com/logo.svg"));
    assert!(logo_only.contains("font-src 'none';"), "{logo_only}");

    // A host with a port keeps it, since an origin is scheme, host AND port.
    let port = csp(Some("https://assets.internal:8443/t.css"), None);
    assert!(
        port.contains("style-src 'nonce-N' https://assets.internal:8443;"),
        "{port}"
    );
}

/// Where a form may end up, which is a different question from where it posts, and the
/// one a hardcoded `'self'` got wrong for every Chromium login in this estate.
///
/// The two spellings of a cookie domain must give one answer: RFC 6265 ignores the
/// leading dot, so a file that writes it and a file that does not describe the same set of
/// hosts, and a directive that disagreed with the cookie would let a login land somewhere
/// the session does not reach (or, as it did, stop one landing where it does).
#[test]
fn the_form_action_is_the_estate_the_cookie_already_covers() {
    // The dot is the operator's spelling and not a source expression: what goes into the
    // policy is the domain and a wildcard for what is under it.
    let dotted = estate_form_action(Some(".badbat75.com"));
    assert_eq!(
        dotted, "'self' https://badbat75.com https://*.badbat75.com",
        "a leading dot must not reach the policy"
    );
    assert_eq!(estate_form_action(Some("badbat75.com")), dotted);

    // The apex is listed beside the wildcard because a CSP `*.x.com` does not match
    // `x.com`, exactly as `compile_host_pattern` does not: the gate's own host is often
    // the apex, and a login that lands there would be the same failure again.
    assert!(dotted.contains("https://badbat75.com "), "{dotted}");

    // No domain at all is a host-only cookie, so there is no second host a session could
    // survive to and nothing here worth permitting.
    assert_eq!(estate_form_action(None), "'self'");
    assert_eq!(estate_form_action(Some("")), "'self'");

    // And it reaches the emitted policy rather than only the helper, which is the half a
    // unit test of the helper alone would leave unproven.
    let live = page_csp(
        "'none'",
        "'none'",
        &estate_form_action(Some(".badbat75.com")),
        None,
        None,
        &[],
    );
    assert!(
        live.contains("form-action 'self' https://badbat75.com https://*.badbat75.com;"),
        "{live}"
    );
}
