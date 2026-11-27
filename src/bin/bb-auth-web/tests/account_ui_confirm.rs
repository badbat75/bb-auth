use super::*;

/// Revoking a key from the self-service page **asks first**.
///
/// §13.15. The console already asks, through [`page_confirm`]; the
/// self-service page posted the removal straight from the list, which meant
/// one stray Enter on a page whose buttons are stacked revoked a working
/// credential with no way back. So the removal became two steps: a control
/// that opens a confirmation, and the `POST` that removes, which lives only
/// on that confirmation. §13.16 made the control the console's row action, an
/// `a.pill.rm` link, because that is what `act_rm` is and a browser cannot
/// submit a link by accident.
///
/// The confirm page is a `GET`, so it writes nothing, and that is asserted on
/// the bytes. It names the key it is about to remove, because a card that
/// says "revoke a key" is a card that revokes whichever key its form
/// carries. The refusals are `404` and **name nothing**: an id the caller does
/// not have is answered exactly like an id that does not exist, and a page
/// that said "no such key" about an id on somebody else's row would be an
/// enumeration oracle over this estate's whole roster.
#[test]
fn revoking_a_key_asks_first_on_the_account_page() {
    let path = account_scratch_access("revoke-asks", &account_access_keys());
    let base = account_serve(&path);
    let on_disk = read(&path);

    // --- the list: the remove control asks, it does not do ------------------
    //
    // §13.16: the control is the console's row action, an `a.pill.rm` link to the
    // confirmation, not a form. A link is the cheaper promise, because a browser
    // cannot submit a link by accident, and the confirmation page is still the
    // only thing that mutates.
    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(g.status, 200, "bob's page: {}", account_readable(&g.body));
    let removes = anchors_to(&g.body, "keys/remove");
    assert_eq!(
        removes.len(),
        2,
        "one remove control per key of the caller's"
    );
    let mut ids: Vec<String> = Vec::new();
    for a in &removes {
        let class = attr(a, "class").unwrap_or_default();
        let cls: Vec<&str> = class.split_whitespace().collect();
        assert!(
            cls.contains(&"pill") && cls.contains(&"rm"),
            "the control is the destructive member of the row's pills, so it takes \
                 the styling every destructive action already has: {a}"
        );
        let href = attr(a, "href").unwrap_or_default();
        let id = href.split("id=").last().unwrap_or_default().to_string();
        assert!(
            href.contains("keys/remove?id=") && !id.is_empty(),
            "the link carries **that** key's id in its address, so the card cannot \
                 name one key and remove another: {a}"
        );
        ids.push(id.clone());
        // WCAG 2.4.6: ten links all called "Revoke key" are ten identical
        // entries in a screen reader's list of links. §13.17 carries that name
        // as hidden text inside the link, not as `aria-label`, because the
        // shared component is also used on a `summary`, which has no implicit
        // ARIA role for an `aria-label` to name.
        assert_eq!(
            visible_text(a),
            format!("Revoke key {id}"),
            "the link's name is text inside it, and carries the id: {a}"
        );
        assert_eq!(
            attr(a, "title").as_deref(),
            Some(format!("Revoke key {id}").as_str()),
            "and a pointer user sees the same words: {a}"
        );
        assert!(
            !a.contains("aria-label"),
            "one naming mechanism, so the tooltip and the reader's name cannot drift \
                 apart: {a}"
        );
    }
    assert_eq!(
        ids,
        vec!["laptop".to_string(), "ci".to_string()],
        "each control carries its own key's id, in the order the keys are listed"
    );
    for form in account_forms(&g.body) {
        assert!(
            !form.contains("keys/remove"),
            "nothing on the plain page posts a removal: the mutation lives on the \
                 confirmation, which is the step that asks: {form}"
        );
    }

    // Rotate asks too, and is the same shape with a word on it.
    let rotates = links_to(&g.body, "keys/rotate");
    assert_eq!(
        rotates.len(),
        2,
        "one rotate control per key of the caller's"
    );
    for a in &rotates {
        let class = attr(a, "class").unwrap_or_default();
        let cls: Vec<&str> = class.split_whitespace().collect();
        assert!(cls.contains(&"pill"), "rotate is a pill: {a}");
        assert!(
            attr(a, "aria-label")
                .unwrap_or_default()
                .starts_with("Rotate key "),
            "and its name carries the id, as the remove's does: {a}"
        );
    }

    // --- the confirm page: it names the key, and it writes nothing ---------
    let g = account_call(&format!("{base}keys/remove?id=laptop"), Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "the confirm page is a page: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        read(&path),
        on_disk,
        "a GET writes nothing: the key is still there until the person says so"
    );
    assert!(
        g.body.contains("laptop"),
        "the card names the key it is about to remove: {}",
        account_readable(&g.body)
    );
    assert!(
        !g.body.contains("bbk_"),
        "and it shows no secret, because a confirmation is not a reveal"
    );
    let card = account_forms(&g.body)
        .into_iter()
        .find(|f| f.contains("method=\"post\""))
        .expect("the card carries the POST that removes");
    assert!(
        card.contains("keys/remove"),
        "the card posts to the path that removes: {card}"
    );
    assert!(
        card.contains("class=\"danger\""),
        "the card's own button is marked destructive, so the page that does the \
             damage looks like damage: {card}"
    );
    assert!(
        card.contains(&format!("value=\"{}\"", sha256_hex(&on_disk))),
        "the card carries the fingerprint of the file as this page read it, so a key \
             somebody else removed in the meantime is a 409 and not a clobber"
    );
    assert!(
        card.contains("name=\"id\"") && card.contains("laptop"),
        "and it carries this key's id: {card}"
    );
    let words = account_readable(&g.body).to_lowercase();
    assert!(
        words.contains("cancel"),
        "the card offers the way out, in words: {}",
        account_readable(&g.body)
    );
    assert!(
        words.contains("revok"),
        "and it says in words what pressing the button does: {}",
        account_readable(&g.body)
    );

    // --- the confirm page's refusals name nothing --------------------------
    //
    // "Names nothing **else**": the id the caller asked for may come back, and
    // does not matter, because the caller already typed it. What must not come
    // back is any other key's id and any address, which is what would turn a
    // typo into a way to read the roster.
    for (case, query, asked) in [
        ("an id the caller has no such key for", "id=nope", "nope"),
        ("no id at all", "", ""),
        ("an id on somebody else's row", "id=phone", "phone"),
    ] {
        let g = account_call(&format!("{base}keys/remove?{query}"), Some("bob@x.com"));
        assert_eq!(g.status, 404, "the confirm page refuses {case} with a 404");
        // What the **reader** sees. The raw body carries the inline stylesheets, and
        // their comments say "phone" (the stacking rules) and "ci" (inside "decide",
        // "specificity"), so a substring test over the bytes fails on a page that
        // names nothing.
        // The header's glyphs are `<svg>` markup (`<circle` holds "ci"), and no id is
        // ever written in one, so the SVG blocks are cut out before the names are sought.
        let mut shown = account_readable(&g.body);
        while let Some(i) = shown.find("<svg") {
            let end = shown[i..].find("</svg>").map_or(shown.len(), |e| i + e + 6);
            shown.replace_range(i..end, "");
        }
        for name in [
            "laptop",
            "ci",
            "phone",
            // Not "bob@x.com": the header (8b-2) says who is signed in, which is the
            // caller's own address and no leak. Every other address stays barred.
            "bob@old.com",
            "carol@x.com",
            ACCOUNT_BOB,
            ACCOUNT_CAROL,
        ] {
            if name == asked {
                continue;
            }
            assert!(
                !shown.contains(name),
                "the refusal for {case} names `{name}`, which tells a caller which \
                     ids exist and whose they are: {shown}"
            );
        }
    }

    // A stranger and a denied caller get the page's own refusals, unchanged.
    for (case, who) in [
        ("a stranger", Some("dave@x.com")),
        ("a denied address", Some("spammer@x.com")),
    ] {
        let g = account_call(&format!("{base}keys/remove?id=laptop"), who);
        assert_eq!(g.status, 403, "the confirm page is {case}'s 403, not a 404");
        assert!(!g.body.contains("laptop"), "and it names nothing: {case}");
    }

    // --- and the POST on the card still removes ----------------------------
    let rev = sha256_hex(&read(&path));
    let g = account_post(
        &format!("{base}keys/remove"),
        Some("bob@x.com"),
        &[("rev", &rev), ("id", "laptop")],
    );
    assert_eq!(
        g.status, 303,
        "the card's own POST is the mutation, answered with a redirect"
    );
    let after = read(&path);
    assert_ne!(after, on_disk, "the file moved");
    let doc: serde_json::Value = serde_json::from_str(&after).expect("the file parses");
    let ids: Vec<&str> = doc["users"][0]["api_keys"]
        .as_array()
        .expect("bob's row has keys")
        .iter()
        .map(|k| k["id"].as_str().expect("every key has an id"))
        .collect();
    assert_eq!(
        ids,
        vec!["ci"],
        "the key the card named is gone, and its owner's other key stands"
    );
    assert_eq!(
        account_key_json(&after, 1, "phone")["key_hash"],
        account_key_json(&on_disk, 1, "phone")["key_hash"],
        "and nobody else's key is touched"
    );

    cleanup(&path);
}

/// The keys section is the **console's table**, not a layout of its own.
///
/// §13.16. The person's keys became a table with the console's markup: no class
/// on the `table`, so the console's table rules, its row hover and its phone
/// stacking all apply as they are, and each cell is a function the console
/// already calls (`url_list` for the restriction, `expiry_markup` for the
/// expiry). The header row reads "Name / Scopes / Expiry" where the console's
/// reads the file's field names, because this page is read by somebody who has
/// never seen the file.
///
/// The claim worth a test is the sharing, not the columns: a second table and a
/// second expiry renderer is two answers to "when does this key die", and the
/// two surfaces drift one edit at a time, which is the argument that put
/// `expiry_markup` in the shared pile in the first place.
#[test]
fn the_keys_are_the_consoles_table() {
    let path = account_scratch_access("keys-table", &account_access_keys());
    let base = account_serve(&path);
    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob reaches his own page: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "keys");

    // One table, and it carries no class: a class is a second set of table
    // rules, and the section's whole argument is that the console's apply.
    assert_eq!(
        s.matches("<table").count(),
        1,
        "the section holds one table: {}",
        account_readable(&g.body)
    );
    assert!(
        !s.contains("<table class="),
        "the table is the console's markup, unclassed: {}",
        open_tag(&s[s.find("<table").expect("the table is there")..])
    );

    let heads = elements(&s, "<thead>", "</thead>");
    assert_eq!(heads.len(), 1, "one header row: {s}");
    let th = elements(&heads[0], "<th>", "</th>");
    assert_eq!(
        th.len(),
        4,
        "four columns: name, scopes, expiry, actions: {s}"
    );
    assert_eq!(
        visible_text(&th[0]),
        t(Lang::En, K::KeyColName),
        "the name column is headed by the word a person uses, not the file's `id`"
    );
    assert_eq!(visible_text(&th[1]), t(Lang::En, K::Scopes));
    assert_eq!(visible_text(&th[2]), t(Lang::En, K::ColExpiry));
    assert_eq!(
        visible_text(&th[3]),
        "",
        "the actions column is headed by nothing, as the console's is: a heading there \
             names a column of buttons nobody reads"
    );

    let bodies = elements(&s, "<tbody>", "</tbody>");
    assert_eq!(bodies.len(), 1, "one body: {s}");
    let rows = table_rows(&bodies[0]);
    let ids: Vec<String> = rows
        .iter()
        .map(|r| visible_text(&elements(r, "<td", "</td>")[0]))
        .collect();
    assert_eq!(
        ids,
        vec!["laptop", "ci"],
        "one row per key, in the file's order, which is the order the console's table \
             shows them in too"
    );

    // The name cell is the console's `td.mono`: an id is a string to be typed,
    // not prose, and it is the same string on both surfaces.
    for r in &rows {
        let cells: Vec<String> = elements(r, "<td", "</td>");
        let first = open_tag(&cells[0]);
        assert!(
            first.contains("class=\"mono\""),
            "the id cell is monospaced, as the console's is: {first}"
        );
    }

    // The restriction cell is `url_list`'s: the pairs, one per line, or the
    // words for "not narrowed" in the muted span that function already uses.
    let cells: Vec<String> = rows
        .iter()
        .map(|r| elements(r, "<td", "</td>")[1].clone())
        .collect();
    assert!(
        cells[0].contains("mcp/api") && cells[0].contains("<ul"),
        "the narrowed key lists its pair, one per line: {}",
        cells[0]
    );
    assert_eq!(
        visible_text(&cells[1]),
        t(Lang::En, K::KeyScopesAll),
        "the key with no restriction says so in words, in the muted span `url_list` \
             writes for an absent list: {}",
        cells[1]
    );

    // The expiry cell is `expiry_markup` unchanged, which is the same words and
    // the same tag the console's person page shows for the same key.
    let expiry: Vec<String> = rows
        .iter()
        .map(|r| visible_text(&elements(r, "<td", "</td>")[2]))
        .collect();
    assert_eq!(
        expiry[0],
        t(Lang::En, K::NeverExpires),
        "a key that never expires is the console's `never expires` tag: {}",
        expiry[0]
    );
    // The **shape**: the date the file's window ends on, and a days-left figure.
    // The stored `365d` is not in the cell, and cannot be: the cell answers "when
    // does this key die", and the days left are counted from today, so an
    // assertion on the window is a test that holds on one day a year.
    let when = key_expiry("2026-01-01", "365d")
        .and_then(|e| e)
        .expect("the fixture's ci key has a 365d window");
    let left = expiry[1]
        .strip_suffix("d)")
        .and_then(|s| s.rsplit('(').next())
        .unwrap_or_default();
    assert!(
        expiry[1].starts_with(t(Lang::En, K::Expires))
            && expiry[1].contains(&format_date(when))
            && !left.is_empty()
            && left.chars().all(|c| c.is_ascii_digit()),
        "a key with an expiry is the date its window ends on and the days left, as the \
             console spells them: {}",
        expiry[1]
    );

    // The section shows no URL. A key's restriction is a pair of names, and the
    // page's rule is that a person reads where they reach, not what the file
    // matches: the URL is the estate's, and it is not this page's to leak.
    assert!(
        !s.contains("https://"),
        "the keys section names scopes, never URLs: {s}"
    );

    // With no keys there is no table, as in the console: a table with a header
    // and no rows is a shape that says "look, a table" about nothing.
    let empty = account_scratch_access("keys-table-empty", &account_access_mint());
    let empty_base = account_serve(&empty);
    let g = account_call(&empty_base, Some("bob@x.com"));
    let s = account_section(&g.body, "keys");
    assert!(
        !s.contains("<table"),
        "no keys, no table: {}",
        account_readable(&g.body)
    );
    assert!(
        s.contains(t(Lang::En, K::AccountKeysNone)),
        "and the section says so in the words the file's own empty state uses: {s}"
    );
    cleanup(&empty);

    // A pair the owner no longer reaches is marked in words inside the line.
    // Colour alone is not a statement a screen reader hears (WCAG 1.4.1), and a
    // key narrowed to a scope its owner was removed from is the case where the
    // person most needs to know the key reaches less than it says.
    // The uuid, not the fixture's `__BOB__` token: `account_access_keys` hands back
    // the expanded document, so a replace written against the token changes nothing
    // and this case would silently test a scope the key still reaches.
    let gone = account_access_keys().replace(
        &format!(r#""users": ["{ACCOUNT_BOB}"], "credentials": ["api_key"]"#),
        r#""credentials": ["api_key"]"#,
    );
    assert!(
        !gone.contains(&format!(
            r#""users": ["{ACCOUNT_BOB}"], "credentials": ["api_key"]"#
        )),
        "the fixture really removed bob from the `api` scope, or this case tests a \
             scope the key still reaches: {gone}"
    );
    let gone_path = account_scratch_access("keys-table-gone", &gone);
    let gone_base = account_serve(&gone_path);
    let g = account_call(&gone_base, Some("bob@x.com"));
    let s = account_section(&g.body, "keys");
    assert!(
        s.contains("mcp/api"),
        "the pair is still listed, because the key still carries it: {}",
        account_readable(&g.body)
    );
    assert!(
        s.contains(t(Lang::En, K::KeyScopeGone)),
        "and it is marked as no longer reached, in words beside it: {s}"
    );
    cleanup(&gone_path);
    cleanup(&path);
}

/// Every key row is acted on the way a console row is: two links, no form.
///
/// §13.16. A console row is acted on by `act` (an `a.pill`) and `act_rm` (an
/// `a.pill.rm`), each a link to a `GET` page that changes nothing. The keys
/// table does the same, and two things follow. A crawler, a prefetch and a
/// link-following bot cannot revoke a credential, because following a link is a
/// `GET` and a `GET` never mutates. And the mutation form exists, on the page
/// the link opens, so the page works with scripting off.
///
/// The revoke is §13.17's icon component (`pill rm ico`), so its name is hidden
/// text; rotate keeps its visible word, and a word that is not the whole name
/// carries the rest as `aria-label` (WCAG 2.5.3 asks for the visible label to be
/// *inside* the accessible name, which "rotate" is, inside "Rotate key laptop").
///
/// The cell is asserted last and is the one CSS fact here: `td.pills` is
/// `display:flex` today, and a flex `td` is not a table cell, so its bottom
/// border stops short of the row the moment another cell wraps. The cell stays a
/// cell and the no-wrap moves to the `span.pills` inside it.
#[test]
fn each_key_row_acts_like_a_console_row() {
    let path = account_scratch_access("keys-row-actions", &account_access_keys());
    let base = account_serve(&path);
    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(g.status, 200, "the page renders");
    let s = account_section(&g.body, "keys");
    let rows = table_rows(&the_tbody(&s, "the keys table"));
    assert_eq!(rows.len(), 2, "one row per key");

    for r in &rows {
        let id = visible_text(&elements(r, "<td", "</td>")[0]);
        let cell = elements(r, "<td", "</td>")
            .into_iter()
            .find(|c| open_tag(c).contains("class=\"pills\""))
            .unwrap_or_else(|| panic!("the `{id}` row has no actions cell: {r}"));
        assert!(
            cell.contains("<span class=\"pills\">"),
            "the actions cell holds the `.pills` group, which is what the cell-scoped \
                 no-wrap rule applies to: {cell}"
        );

        // Rotate: the console's `act`, a link to a page that changes nothing.
        let rot = links_to(&cell, "keys/rotate")
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("the `{id}` row links to a rotate page: {cell}"));
        assert_eq!(
            attr(&rot, "class").as_deref(),
            Some("pill"),
            "rotate is the console's plain pill: {rot}"
        );
        assert_eq!(
            attr(&rot, "href").as_deref(),
            // The **path**, not the URL the harness connected to: the document
            // carries `href` as a path, and the port is the harness's, not the page's.
            Some(format!("{ACCOUNT_PATH}/keys/rotate?id={id}").as_str()),
            "the link names the key it is about: {rot}"
        );
        assert_eq!(visible_text(&cell), {
            // The visible words of the whole cell: rotate's word, and nothing
            // spoken for the icon.
            format!("{} Revoke key {id}", t(Lang::En, K::Rotate))
        });
        assert_eq!(
            attr(&rot, "aria-label").as_deref(),
            Some(format!("{} {id}", t(Lang::En, K::AccountKeyRotate)).as_str()),
            "the visible word is not the whole name, so the rest is written down: {rot}"
        );

        // Revoke: §13.17's icon, named by hidden text and a `title`. The whole
        // element, because the name is *inside* it and the glyph is too.
        let rm = anchors_to(&cell, "keys/remove")
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("the `{id}` row links to a revoke page: {cell}"));
        assert_eq!(
            attr(&rm, "class").as_deref(),
            Some("pill rm ico"),
            "the revoke is the destructive icon pill, the shared component: {rm}"
        );
        assert_eq!(
            attr(&rm, "href").as_deref(),
            Some(format!("{ACCOUNT_PATH}/keys/remove?id={id}").as_str()),
            "the link names the key it is about: {rm}"
        );
        assert_eq!(
            visible_text(&rm),
            format!("{} {id}", t(Lang::En, K::AccountKeyRemove)),
            "the icon's name is text inside it, and carries the id: {rm}"
        );
        assert_eq!(
            attr(&rm, "title").as_deref(),
            Some(format!("{} {id}", t(Lang::En, K::AccountKeyRemove)).as_str()),
            "and a pointer user sees the same words: {rm}"
        );
        assert!(
            !rm.contains("aria-label"),
            "one naming mechanism, so the tooltip and the reader's name cannot drift \
                 apart: {rm}"
        );
        assert_eq!(elements(&rm, "<svg", "</svg>").len(), 1, "one glyph: {rm}");
    }

    // Nothing on the plain page posts. The only form is the preferences
    // selector, which is a `GET` by design, so a page that carries a mutation
    // form here has put a revoke one Enter key away again.
    for f in account_forms(&g.body) {
        assert!(
            f.contains("method=\"get\""),
            "the plain page's forms are the preferences selector and nothing else, so \
                 nothing on it can mutate: {}",
            &f[..f.find('>').map_or(f.len(), |i| i + 1)]
        );
    }

    // The cell is a cell. `display:flex` on a `td` removes it from the table
    // layout, and the row's bottom border then stops short of the row whenever a
    // cell wraps, which the mockup showed on every wrapped row.
    let rule = the_rule(CSS, "td.pills").expect("admin.css styles the actions cell");
    assert!(
        !rule.contains("display:flex"),
        "the actions cell stays a table cell: {rule}"
    );
    assert!(
        rule.contains("white-space:nowrap") && rule.contains("text-align:right"),
        "the no-wrap and the alignment move to the cell, and the group keeps its own \
             rule: {rule}"
    );
    assert!(
        the_rule(CSS, "td.pills .pills").is_some(),
        "the group inside the cell is what the cell-scoped rule applies to"
    );

    cleanup(&path);
}

/// The rules of `admin.css`'s phone block as `(selector, declarations)`, whitespace
/// removed. [`the_rule`] cannot serve here: it swallows the first rule inside an at-rule
/// and returns the first match in file order, which for `td.pills` is the desktop rule.
fn phone_rules() -> Vec<(String, String)> {
    let mut bare = String::new();
    let mut rest = CSS;
    while let Some(i) = rest.find("/*") {
        bare.push_str(&rest[..i]);
        rest = rest[i..].find("*/").map_or("", |j| &rest[i + j + 2..]);
    }
    bare.push_str(rest);
    let flat: String = bare.chars().filter(|c| !c.is_whitespace()).collect();
    let at = flat
        .find("@media(max-width:640px){")
        .expect("admin.css has its phone block");
    let block = &flat[at + "@media(max-width:640px){".len()..];
    block
        .split('}')
        .filter_map(|c| c.split_once('{'))
        .map(|(s, d)| (s.to_string(), d.to_string()))
        .collect()
}

/// `td.pills` is a table cell (§13.21, 1). `BASE_CSS`'s `.pills{display:inline-flex}`
/// matches the `td` as well as the `span.pills` inside it, so the cell computes
/// `inline-flex` and is wrapped in an anonymous cell: the row's rule stops short of the
/// table's edge. The old "no `display:flex`" assertion passed while the defect stood, so
/// the cell must say `table-cell` itself, and `block` again on a phone, where the
/// stacking rule `td{display:block}` (0,0,1) would otherwise lose to it.
#[test]
fn the_actions_cell_is_a_table_cell() {
    let rule = the_rule(CSS, "td.pills").expect("admin.css styles the actions cell");
    assert!(
        rule.replace(' ', "").contains("display:table-cell"),
        "the cell must beat `.pills{{display:inline-flex}}` from base.css: {rule}"
    );
    let phone = phone_rules()
        .into_iter()
        .find(|(s, _)| s == "td.pills")
        .expect("the phone block restyles the actions cell");
    assert!(
        phone.1.contains("display:block"),
        "on a phone the cell stacks like its siblings: {}",
        phone.1
    );
}

/// A row pill is one size at every width (§13.21, 2): the phone block must not carry a
/// bare `.pill` rule, which shrank `rotate` to 28px while `.pill.ico` (more specific)
/// stayed 30px.
#[test]
fn a_row_pill_is_one_size_at_every_width() {
    let bare: Vec<_> = phone_rules()
        .into_iter()
        .filter(|(s, _)| s.split(',').any(|p| p == ".pill"))
        .collect();
    assert!(bare.is_empty(), "no bare `.pill` rule on a phone: {bare:?}");
}

/// A filter's field is as tall as its Apply (§13.21, 2). `min-height` is the compact
/// pill's own box, and the pill must still be that box for the formula to hold.
#[test]
fn a_filter_field_is_its_buttons_height() {
    for sel in [
        ".listctl input[type=search]",
        ".listctl select",
        ".listctl input.tzc",
    ] {
        let rule = the_rule(CSS, sel).unwrap_or_else(|| panic!("admin.css styles `{sel}`"));
        assert!(
            rule.replace([' ', '\n'], "")
                .contains("min-height:calc(1.45em+10px)"),
            "`{sel}` needs min-height:calc(1.45em + 10px): {rule}"
        );
    }
    let pill = the_rule(BASE_CSS, ".pill").expect("base.css defines the pill");
    let pill: String = pill.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        pill.contains("line-height:1.45") && pill.contains("padding:4px11px"),
        "the formula is the pill's box: {pill}"
    );
}

/// The `+ New key` row is a page of its own.
///
/// §13.16. The mint form is not a block above the table (4h) and not a
/// permanently open row: it is a row that appears when the `+` is followed, on
/// `GET keys/new`, as one `td colspan="4"` holding the console's `form.edit`. A
/// `form` may not wrap a table row, but it may sit inside a cell, so no `form`
/// attribute is needed and the row is in the table the person is looking at.
///
/// The `+` sits **below** the table, which is the one place the console's
/// `p.primary` convention is deliberately not followed: the user asked for the
/// `+` at the end, and the row it opens appears at the end.
///
/// `autofocus`, `required` and `pattern` are the browser's constraint
/// validation and need no script, which is what keeps this page inside the
/// no-JavaScript rule; the server checks every one of them again.
#[test]
fn the_new_key_row_is_a_page_of_its_own() {
    let path = account_scratch_access("keys-new", &account_access_keys());
    let base = account_serve(&path);

    // --- the plain page: the + below the table, and no form -----------------
    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(g.status, 200, "the page renders");
    let s = account_section(&g.body, "keys");
    let plus = anchors_to(&s, "keys/new")
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("the section offers the way to add a key: {s}"));
    assert_eq!(
        attr(&plus, "class").as_deref(),
        Some("pill"),
        "the + is the console's pill: {plus}"
    );
    assert_eq!(visible_text(&plus), t(Lang::En, K::AccountKeyNew));
    let at = s
        .find("p class=\"primary\"")
        .unwrap_or_else(|| panic!("the + sits in the console's add-control paragraph: {s}"));
    assert!(
        s.find("</table>").expect("the table is there") < at,
        "the + is below the table, because the row it opens appears at the end: {s}"
    );
    assert!(
        !g.body.contains("name=\"id\""),
        "the plain page carries no mint field: {}",
        account_readable(&g.body)
    );

    // --- keys/new: the same page, the + gone, one row more ------------------
    let g = account_call(&format!("{base}keys/new"), Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "the mint row is a page: {}",
        account_readable(&g.body)
    );
    assert!(
        !g.body.contains("keys/new"),
        "the page that is the mint row does not offer to open itself again: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "keys");
    let cells = elements(&s, "<td", "</td>");
    let wide: Vec<&String> = cells
        .iter()
        .filter(|c| open_tag(c).contains("colspan=\"4\""))
        .collect();
    assert_eq!(
        wide.len(),
        1,
        "one row spanning every column, so the form is in the table it belongs to: {s}"
    );
    let form = element_containing(wide[0], "class=\"edit\"", "</form>");
    assert!(
        // The **path**, which is the form the server emits: an `action` is resolved
        // against the page by the browser, so a document that named the host it was
        // served on would be a document that knows its own port.
        form.contains(&format!("action=\"{ACCOUNT_PATH}/keys\""))
            && form.contains("method=\"post\""),
        "the row's form posts to the path that mints: {}",
        open_tag(&form)
    );
    assert!(
        form.contains("name=\"rev\""),
        "and carries the file's fingerprint, so a stale form is a 409 that writes \
             nothing: {form}"
    );

    // The name field, with the browser's own validation on it.
    let id = tag_containing(&form, "name=\"id\"");
    assert!(
        id.contains("autofocus") && id.contains("required"),
        "the person lands in the field the + asked for: {id}"
    );
    assert_eq!(
        attr(&id, "pattern").as_deref(),
        Some("[a-z0-9-]{1,32}"),
        "the format the server enforces is the format the form enforces: {id}"
    );
    assert_eq!(attr(&id, "maxlength").as_deref(), Some("32"));
    assert_eq!(attr(&id, "placeholder").as_deref(), Some("laptop"));
    assert!(
        form.contains(t(Lang::En, K::KeyColName)),
        "the field is labelled with the column's own word: {form}"
    );
    assert!(
        form.contains(t(Lang::En, K::KeyColExpires)),
        "and the expiry field with its column's: {form}"
    );

    // The five choices, the same component the console's mint form renders.
    assert_duration_choices(&form, "365d", "the self-service mint row", true);

    // The box beside "Other" is named. A number field whose only hint is a
    // placeholder loses the hint the moment it is typed in, and a box that
    // counts days has to say so out loud (WCAG 3.3.2).
    let days = tag_containing(&form, "name=\"days\"");
    assert_eq!(
        attr(&days, "aria-label").as_deref(),
        Some(t(Lang::En, K::DurDaysLabel)),
        "the days box says what it counts: {days}"
    );

    // The form ends the way every console form ends: the submit and the cancel.
    assert!(
        form.contains(&format!(
            "><button type=\"submit\" class=\"\">{}</button>",
            t(Lang::En, K::AccountKeyCreate)
        )),
        "the submit is the form shell's own button, carrying the words that say what it \
             does: {form}"
    );
    assert!(
        form.contains(&format!(">{}<", t(Lang::En, K::Cancel))),
        "and the way out is a link back to the page, not a reset: {form}"
    );

    // --- a caller with no row has neither ----------------------------------
    for (case, who) in [
        ("a stranger", Some("dave@x.com")),
        ("a denied address", Some("spammer@x.com")),
    ] {
        let g = account_call(&base, who);
        assert!(
            !g.body.contains("keys/new"),
            "{case} is offered no way to mint: {}",
            account_readable(&g.body)
        );
        let g = account_call(&format!("{base}keys/new"), who);
        assert_eq!(g.status, 403, "the mint page is {case}'s 403, not a form");
        assert!(
            !g.body.contains("colspan=\"4\""),
            "and it carries no mint row: {case}"
        );
    }

    cleanup(&path);
}

/// A key refused at the mint row **keeps the row open, the value typed, and
/// says which field is wrong**.
///
/// §13.16. The refusals are `form_shell`'s: the library's sentence at the top of
/// the form, the field it is about marked `aria-invalid` and pointed at the
/// message, and every value as posted. WCAG 3.3.1 and 3.3.3 ask for the error to
/// be identified in text and the fix suggested, and the person who typed
/// `My Laptop` should not have to type it again.
///
/// The last case is the one that is easy to get wrong: scopes ticked beside
/// "all scopes". Today the handler drops the ticks and files the widest key the
/// person did not ask for, which is a credential broader than the one that was
/// requested. It is refused, and no field is marked, because a radio group has
/// no invalid style and marking one radio of a group reads as "this button is
/// broken" rather than "your choice is contradictory".
#[test]
fn a_refused_key_keeps_the_row_and_says_where() {
    let path = account_scratch_access("keys-refused", &account_access_keys());
    let base = account_serve(&path);
    let keys = format!("{base}keys");
    let before = read(&path);

    // A name the grammar refuses: the row stays, the value stays, the field is
    // marked, and the file does not move.
    let rev = sha256_hex(&before);
    let g = account_post(
        &keys,
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "My Laptop"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(g.status, 400, "a name with a space is refused");
    assert!(
        g.body.contains("colspan=\"4\""),
        "the answer is the row, open, not a page about the failure: {}",
        account_readable(&g.body)
    );
    assert!(
        g.body.contains("value=\"My Laptop\""),
        "the name as typed comes back, so the person fixes it instead of retyping it: {}",
        account_readable(&g.body)
    );
    let err = element_containing(&g.body, "class=\"err\"", "</div>");
    assert_eq!(
        visible_text(&err),
        t(Lang::En, K::AccountKeyIdBad),
        "a bad name is refused with the name's own sentence (8c-2): {err}"
    );
    let id = tag_containing(&g.body, "name=\"id\"");
    assert_eq!(
        attr(&id, "aria-invalid").as_deref(),
        Some("true"),
        "and the field it is about says so: {id}"
    );
    let described = attr(&id, "aria-describedby").expect("the marked field points at the message");
    assert!(
        g.body.contains(&format!("id=\"{described}\"")),
        "the message is the one this field names: {described}"
    );
    assert_eq!(read(&path), before, "the refusal wrote nothing");

    // A name already taken: the library's own words, on the same field.
    let rev = sha256_hex(&before);
    let g = account_post(
        &keys,
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "laptop"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(
        g.status,
        400,
        "a second key named `laptop` is refused: {}",
        account_readable(&g.body)
    );
    assert!(
        g.body.contains(t(Lang::En, K::AccountKeyDup)),
        "the refusal is the table's own sentence, in the reader's language: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        attr(&tag_containing(&g.body, "name=\"id\""), "aria-invalid").as_deref(),
        Some("true"),
        "and it is the name field that is wrong"
    );
    assert_eq!(read(&path), before, "the duplicate refusal wrote nothing");

    // Ticks beside "all scopes": a choice the person thinks they made.
    let rev = sha256_hex(&before);
    let g = account_post(
        &keys,
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "phone"),
            ("duration", "30d"),
            ("restrict", "all"),
            ("scope", "mcp/logs"),
        ],
    );
    assert_eq!(
        g.status,
        400,
        "scopes ticked while \"all scopes\" is picked is refused, not quietly widened: {}",
        account_readable(&g.body)
    );
    assert!(
        g.body.contains(t(Lang::En, K::KeyScopesWithoutOnly)),
        "and the sentence names the fix, because a person with no administrator at hand \
             has to choose one of the two: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.body.matches("aria-invalid").count(),
        0,
        "a radio group has no invalid style, so no field is marked: the contradiction is \
             between two controls, not inside one"
    );
    assert_eq!(
        read(&path),
        before,
        "the contradictory choice wrote nothing"
    );

    cleanup(&path);
}

/// 8c-2 (§13.17): a refused key name says one fact, and it is the name's. The old
/// `AccountKeyBound` also spoke about durations, so a person who typed `My Laptop` read
/// about days. The marked field is the name, and the select is not marked.
#[test]
fn a_bad_key_name_is_refused_without_naming_the_duration() {
    let path = account_scratch_access("keys-bad-name", &account_access_keys());
    let base = account_serve(&path);
    let before = read(&path);
    let rev = sha256_hex(&before);
    let g = account_post(
        &format!("{base}keys"),
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "My Laptop"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(g.status, 400, "{}", account_readable(&g.body));
    let err = visible_text(&element_containing(&g.body, "class=\"err\"", "</div>"));
    assert_eq!(err, t(Lang::En, K::AccountKeyIdBad), "{err}");
    let low = err.to_lowercase();
    assert!(
        !low.contains("day") && !low.contains("giorn") && !low.contains("last"),
        "a bad name is not a sentence about durations: {err}"
    );
    assert_eq!(
        attr(&tag_containing(&g.body, "name=\"id\""), "aria-invalid").as_deref(),
        Some("true"),
        "the name field is the marked one"
    );
    assert_eq!(
        attr(
            &tag_containing(&g.body, "name=\"duration\""),
            "aria-invalid"
        ),
        None,
        "the select is not"
    );
    assert_eq!(read(&path), before, "the refusal wrote nothing");
    cleanup(&path);
}

/// 8c-2 (§13.17): a window under a day (`12h` in the custom box) is the duration's
/// refusal, on the select, and says nothing about the name.
#[test]
fn a_too_short_key_is_refused_without_naming_the_name() {
    let path = account_scratch_access("keys-too-short", &account_access_keys());
    let base = account_serve(&path);
    let before = read(&path);
    let rev = sha256_hex(&before);
    let g = account_post(
        &format!("{base}keys"),
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "phone"),
            ("duration", "custom"),
            ("days", "12h"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(g.status, 400, "{}", account_readable(&g.body));
    let err = visible_text(&element_containing(&g.body, "class=\"err\"", "</div>"));
    assert_eq!(err, t(Lang::En, K::AccountKeyTooShort), "{err}");
    let low = err.to_lowercase();
    assert!(
        !low.contains("name") && !low.contains("lowercase") && !low.contains("dash"),
        "a short window is not a sentence about the name: {err}"
    );
    assert_eq!(
        attr(
            &tag_containing(&g.body, "name=\"duration\""),
            "aria-invalid"
        )
        .as_deref(),
        Some("true"),
        "the select is the marked field"
    );
    assert_eq!(
        attr(&tag_containing(&g.body, "name=\"id\""), "aria-invalid"),
        None,
        "the name field is not"
    );
    assert_eq!(read(&path), before, "the refusal wrote nothing");
    cleanup(&path);
}

/// 8c-2 (§13.17): the account form's refusals and the three duration ones are sentences,
/// in both languages (a capital, a full stop), and the texts are the design's.
/// `AccountKeyNotYours` is Italian for "rigenerare", the button's own verb.
#[test]
fn the_account_refusals_are_sentences() {
    let all = [
        ("AccountKeyIdBad", K::AccountKeyIdBad),
        ("AccountKeyTooShort", K::AccountKeyTooShort),
        ("KeyScopesChoose", K::KeyScopesChoose),
        ("KeyDurationRequired", K::KeyDurationRequired),
        ("KeyDaysWithoutCustom", K::KeyDaysWithoutCustom),
        ("KeyDaysInvalid", K::KeyDaysInvalid),
        ("AccountKeyFull", K::AccountKeyFull),
        ("AccountKeyDup", K::AccountKeyDup),
        ("AccountKeyUnknownScope", K::AccountKeyUnknownScope),
    ];
    for lang in [Lang::En, Lang::It] {
        for (name, k) in &all {
            let s = t(lang, *k);
            assert!(
                s.chars().next().is_some_and(char::is_uppercase) && s.ends_with('.'),
                "{name} in {}: a sentence has a capital and a full stop: {s:?}",
                lang.code()
            );
        }
    }
    for (k, en, it) in [
            (
                K::AccountKeyIdBad,
                "A key name is lowercase letters, digits and dashes, up to 32 characters, such as laptop.",
                "Il nome di una chiave \u{e8} fatto di lettere minuscole, cifre e trattini, fino a 32 caratteri, per esempio laptop.",
            ),
            (
                K::AccountKeyTooShort,
                "A key must last at least a day; choose a longer duration.",
                "Una chiave deve durare almeno un giorno; scegli una durata pi\u{f9} lunga.",
            ),
            (
                K::KeyScopesChoose,
                "Choose 'all scopes' or 'only these'.",
                "Scegli 'tutti gli ambiti' o 'solo questi'.",
            ),
            (
                K::KeyDaysWithoutCustom,
                "You typed a number of days; choose 'after a number of days', or clear it.",
                "Hai scritto un numero di giorni; scegli 'dopo un numero di giorni', o cancellalo.",
            ),
            (
                K::KeyDaysInvalid,
                "Write a whole number of days, at least 1.",
                "Scrivi un numero intero di giorni, almeno 1.",
            ),
            (
                K::AccountKeyFull,
                "This account has ten keys, which is the most this page mints.",
                "Questo account ha dieci chiavi, il massimo che questa pagina crea.",
            ),
            (
                K::AccountKeyDup,
                "This account already has a key with that name.",
                "Questo account ha gi\u{e0} una chiave con quel nome.",
            ),
            (
                K::AccountKeyUnknownScope,
                "A scope you picked is not one a key of yours can reach.",
                "Uno degli ambiti scelti non \u{e8} uno che una tua chiave pu\u{f2} raggiungere.",
            ),
        ] {
            assert_eq!(t(Lang::En, k), en);
            assert_eq!(t(Lang::It, k), it);
        }
    let it = t(Lang::It, K::AccountKeyNotYours);
    assert!(
        it.contains("rigenerarla") && !it.contains("ruotarla"),
        "the Italian refusal uses the button's verb: {it}"
    );
}

/// 8c-2 (§13.17): on `/account/` the days box has a placeholder and its own accessible
/// name and the form has no hint line; on the console the box has no placeholder and the
/// hint `<n>d · <n>h` stays, because that box takes the whole grammar.
#[test]
fn the_days_box_has_a_placeholder_and_its_own_name() {
    let path = account_scratch_access("keys-days-box", &account_access_keys());
    let base = account_serve(&path);
    for (lang, cookie, hint, label) in [
        (Lang::En, "lang=en", "days", "Number of days"),
        (Lang::It, "lang=it", "giorni", "Numero di giorni"),
    ] {
        let g = account_call_pref(
            &format!("{base}keys/new"),
            Some("bob@x.com"),
            Some(cookie),
            None,
        );
        assert_eq!(g.status, 200, "{}", account_readable(&g.body));
        let s = account_section(&g.body, "keys");
        let days = tag_containing(&s, "name=\"days\"");
        assert_eq!(attr(&days, "placeholder").as_deref(), Some(hint), "{days}");
        assert_eq!(attr(&days, "aria-label").as_deref(), Some(label), "{days}");
        assert_eq!(t(lang, K::DurDaysLabel), label);
        for h in elements(&s, "<span class=\"hint\"", "</span>") {
            assert_ne!(
                visible_text(&h),
                hint,
                "the bare word under the row is gone: {h}"
            );
        }
    }
    cleanup(&path);

    let path = scratch("console-days-box", SAMPLE);
    let cfg = cfg_for(&path, "");
    let v = view(&cfg, Route::KeyAdd(BOB.to_string()), "REV");
    let f = KeyForm {
        duration: "365d".to_string(),
        ..Default::default()
    };
    let page = page_key_form(&v, "bob", None, "2026-01-01", &f, None).into_string();
    let days = tag_containing(&page, "name=\"days\"");
    assert_eq!(attr(&days, "placeholder"), None, "no placeholder: {days}");
    assert_eq!(
        attr(&days, "aria-label").as_deref(),
        Some("Number of days"),
        "the reworded name is on both surfaces: {days}"
    );
    assert!(
        page.contains("&lt;n&gt;d \u{b7} &lt;n&gt;h"),
        "the console keeps its hint: {page}"
    );
    cleanup(&path);
}

/// 8c-2 (§13.17): with nothing to narrow to there is no choice to show, and the form
/// carries `restrict=all` hidden; with pairs it offers both radios as before.
#[test]
fn a_key_with_nothing_to_narrow_has_no_scope_choice() {
    let path = account_scratch_access(
        "keys-no-choice",
        &ACCOUNT_ACCESS_NO_NARROW.replace("__DAVE__", ACCOUNT_DAVE),
    );
    let base = account_serve(&path);
    let g = account_call(&format!("{base}keys/new"), Some("dave@x.com"));
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let s = account_section(&g.body, "keys");
    assert!(
        !s.contains("type=\"radio\""),
        "no radio at all, not a choice of one: {s}"
    );
    assert!(
        !s.contains(t(Lang::En, K::KeyScopesAll)),
        "and no \"all scopes\" in the form: {s}"
    );
    assert_eq!(s.matches("name=\"restrict\"").count(), 1, "{s}");
    let hidden = tag_containing(&s, "name=\"restrict\"");
    assert!(
        hidden.contains("type=\"hidden\"") && attr(&hidden, "value").as_deref() == Some("all"),
        "one hidden restrict=all stands in: {hidden}"
    );
    let rev = sha256_hex(&read(&path));
    let g = account_post(
        &format!("{base}keys"),
        Some("dave@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "phone"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    assert!(
        account_key_json(&read(&path), 0, "phone")
            .get("scopes")
            .is_none(),
        "the form as rendered mints a key with no scopes"
    );
    cleanup(&path);

    let path = account_scratch_access("keys-with-choice", &account_access_keys());
    let base = account_serve(&path);
    let g = account_call(&format!("{base}keys/new"), Some("bob@x.com"));
    let s = account_section(&g.body, "keys");
    assert_eq!(s.matches("type=\"radio\"").count(), 2, "{s}");
    assert!(
        s.contains("value=\"all\"") && s.contains("value=\"some\""),
        "{s}"
    );
    assert!(!s.contains("type=\"hidden\" name=\"restrict\""), "{s}");
    cleanup(&path);
}

/// At ten keys the `+` row is **gone**, and the sentence says why.
///
/// §13.16. Not a disabled control: a disabled control is skipped by the keyboard,
/// says nothing, and leaves the person to guess. The bound is ten per row
/// counting every key, the administrator's included, so the row's own keys are
/// what closed it and revoking one is the fix the sentence names.
#[test]
fn the_tenth_key_closes_the_row() {
    let path = account_scratch_access("keys-full", &account_access_ten_keys());
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(g.status, 200, "the page renders");
    let s = account_section(&g.body, "keys");
    assert_eq!(
        table_rows(&the_tbody(&s, "the keys table at the bound")).len(),
        10,
        "the ten keys are all listed: the bound is about the file, and the person can \
             see which key to revoke"
    );
    assert!(!s.contains("keys/new"), "and the + is not offered: {s}");
    assert!(
        s.contains(t(Lang::En, K::AccountKeyFullRow)),
        "the row is replaced by the sentence that explains it, in the muted paragraph \
             the empty state uses: {s}"
    );

    // Following the link anyway is the same page with the same sentence and no
    // row: the bound is the handler's, and a page that 404s on a link the person
    // reached by typing it is a worse answer than the one that explains.
    let g = account_call(&format!("{base}keys/new"), Some("bob@x.com"));
    assert_eq!(g.status, 200, "the mint page is still reachable");
    assert!(
        !g.body.contains("colspan=\"4\""),
        "and it carries no mint row: {}",
        account_readable(&g.body)
    );
    assert!(
        g.body.contains(t(Lang::En, K::AccountKeyFullRow)),
        "with the same sentence on it: {}",
        account_readable(&g.body)
    );

    cleanup(&path);
}

/// Rotating a key from the self-service page **asks first**, as revoking does.
///
/// §13.16. A rotate replaces a working secret, and anything using the old one
/// stops getting in within seconds, so it is the second control on this page
/// that cannot be answered by a stray Enter. The confirmation is the console's
/// `page_confirm`, and the warning is the sentence that says what is about to
/// happen, because a card that says "rotate" is a card that rotates whichever
/// key its form carries.
///
/// The card's button is **not** marked destructive: a rotate keeps the name,
/// the restriction and the person's own copy of nothing, and a red button on it
/// would train the person to read the red button on the revoke as one more
/// routine thing.
#[test]
fn rotating_a_key_asks_first_on_the_account_page() {
    let path = account_scratch_access("rotate-asks", &account_access_keys());
    let base = account_serve(&path);
    let on_disk = read(&path);

    // The link opens a page, and the page writes nothing: a `GET` never mutates,
    // and this one is reached by following a link a crawler may follow.
    let g = account_call(&format!("{base}keys/rotate?id=laptop"), Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "the rotate confirmation is a page: {}",
        account_readable(&g.body)
    );
    assert_eq!(read(&path), on_disk, "opening the card wrote nothing");

    // The card is `page_confirm`'s shape, with the rotate's own warning.
    assert!(
        g.body.contains("<h1>") && g.body.contains("class=\"lede\""),
        "what is being done, and what it means: {}",
        account_readable(&g.body)
    );
    let panel = element_containing(&g.body, "class=\"panel bad\"", "</div>");
    assert!(
        panel.contains("<code>laptop</code>"),
        "the card names the key it is about to rotate, because the form carries an id \
             and a card that does not say which is a card that rotates whichever: {panel}"
    );
    assert!(
        g.body.contains(t(Lang::En, K::AccountKeyRotateWarn)),
        "and says what a rotate costs, in the reader's language: {}",
        account_readable(&g.body)
    );
    // The header's Preferences menu is also a `form.edit`, so the card's form is found by
    // the path it posts to.
    let form = element_containing(
        &g.body,
        &format!("action=\"{ACCOUNT_PATH}/keys/rotate\""),
        "</form>",
    );
    assert!(
        form.contains(&format!("action=\"{ACCOUNT_PATH}/keys/rotate\""))
            && form.contains("method=\"post\""),
        "the card posts to the path that rotates: {}",
        open_tag(&form)
    );
    assert!(
        form.contains(&format!("value=\"{}\"", sha256_hex(&on_disk))),
        "the card carries the fingerprint of the file as this page read it, so a key \
             somebody else rotated in the meantime is a 409 and not a clobber"
    );
    assert!(
        form.contains("name=\"id\"") && form.contains("laptop"),
        "and it carries this key's id: {form}"
    );
    assert!(
        !form.contains("class=\"danger\""),
        "a rotate is not a revoke: the red button belongs to the one control that \
             cannot be undone: {form}"
    );
    let words = account_readable(&g.body).to_lowercase();
    assert!(
        words.contains(&t(Lang::En, K::Cancel).to_lowercase()),
        "the card offers the way out, in words: {}",
        account_readable(&g.body)
    );

    // Cancelling is a link, and a person who takes it changes nothing.
    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "the page is still there to come back to: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        read(&path),
        on_disk,
        "reading the page away again wrote nothing"
    );

    // The POST on the card rotates, and the narrowing survives byte for byte:
    // a rotate is the answer to a leak, not a widening.
    let old = account_key_json(&on_disk, 0, "laptop");
    let g = account_post(
        &format!("{base}keys/rotate"),
        Some("bob@x.com"),
        &[("rev", &sha256_hex(&on_disk)), ("id", "laptop")],
    );
    assert_eq!(
        g.status,
        200,
        "the card's own POST is the mutation: {}",
        account_readable(&g.body)
    );
    let bearer = account_bearer_in(&g.body);
    assert!(
        bearer.starts_with("bbk_"),
        "and shows the new secret: {bearer}"
    );
    let after = read(&path);
    let now = account_key_json(&after, 0, "laptop");
    assert_eq!(
        now["scopes"], old["scopes"],
        "the administrator's narrowing is untouched: {now}"
    );
    assert_eq!(
        account_key_json(&after, 0, "ci"),
        account_key_json(&on_disk, 0, "ci"),
        "and the caller's other key is untouched"
    );

    // A key that is not the caller's is a `404` that names nothing, exactly as
    // the revoke answers it: a page that said "no such key" about an id on
    // somebody else's row is an enumeration oracle over the whole roster.
    for op in ["rotate", "remove"] {
        let g = account_call(&format!("{base}{op}?id=phone"), Some("bob@x.com"));
        assert_eq!(
            g.status, 404,
            "carol's key is {op}'s 404 for bob, not a form and not a 403 that confirms \
                 the key exists"
        );
        assert!(
            // The readable body: the inline stylesheet this page carries says
            // "phone" in its stacking comments, which is not the refusal naming
            // carol's key.
            !account_readable(&g.body).contains("phone"),
            "and the refusal names nothing: {op}"
        );
    }

    cleanup(&path);
}

/// The console's revoke confirmation is **byte for byte what it is today**.
///
/// §13.16. `page_confirm` and the `form_shell` it calls take a console `View`
/// for three things (the form's action, the `rev`, the cancel link), and they
/// take those three values instead so that one function renders the
/// confirmation on both surfaces. That is a refactor of a function every
/// destructive console page goes through, and the only honest check that the
/// console came out of it unchanged is the bytes it emits.
///
/// The two halves are pinned around the `rev`, which is the file's fingerprint
/// and so changes with the fixture: everything before it and everything after it
/// is fixed, including the `·` separators, the em dash in the library's own
/// sentence, the `danger` class and the cancel link's target.
#[test]
fn page_confirm_renders_both_surfaces() {
    const BEFORE: &str = "<h1>bob@x.com · api_keys · remove</h1>\
             <p class=\"lede\">The bearer stops working the moment the gate reloads. It cannot \
             be restored — only a new key can be minted.</p>\
             <div class=\"panel bad\"><p><code>laptop</code></p>\
             <form class=\"edit\" method=\"post\" \
             action=\"/admin/users/8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b/keys/laptop/rm\">\
             <input type=\"hidden\" name=\"rev\" value=\"";
    const AFTER: &str = "\"><div class=\"actions\"><button type=\"submit\" \
             class=\"danger\">remove</button><a class=\"pill\" \
             href=\"/admin/users/8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b\">cancel</a></div></form></div>";

    let path = scratch("confirm-console", SAMPLE);
    let port = serve(&path, ADMIN_BASE);
    let url = format!(
        "http://127.0.0.1:{port}{ADMIN_BASE}{}",
        Route::KeyRm(BOB.to_string(), "laptop".to_string()).path()
    );
    let g = got_of(
        get_with_secret(&url)
            .header(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("a GET response"),
    );
    assert_eq!(
        g.status,
        200,
        "the console's revoke confirmation is a page: {}",
        account_readable(&g.body)
    );
    let at = g.body.find(BEFORE).unwrap_or_else(|| {
        panic!(
            "the console's revoke confirmation must be the bytes it emits today: {}",
            account_readable(&g.body)
        )
    });
    let tail = &g.body[at + BEFORE.len()..];
    let rev = &tail[..64];
    assert!(
        rev.bytes().all(|b| b.is_ascii_hexdigit()),
        "the pinned halves meet at the file's fingerprint, which is the only thing on \
             this page that moves: {rev}"
    );
    assert!(
        tail[64..].starts_with(AFTER),
        "and the rest of the card is unchanged: {}",
        &tail[64..tail[64..].find("<!--").map_or(400, |i| i.min(400))]
    );
    cleanup(&path);

    // The self-service card is the same shape, with its own words and its own
    // target: one function, two surfaces, and the shape is what the person who
    // has seen one console page already knows.
    let apath = account_scratch_access("confirm-account", &account_access_keys());
    let base = account_serve(&apath);
    let g = account_call(&format!("{base}keys/remove?id=laptop"), Some("bob@x.com"));
    assert_eq!(g.status, 200, "the account card is a page");
    for piece in [
        "<h1>",
        "class=\"lede\"",
        "class=\"panel bad\"",
        "<code>laptop</code>",
        "class=\"edit\"",
        "class=\"actions\"",
        "<button type=\"submit\" class=\"danger\">",
        "name=\"rev\"",
    ] {
        assert!(
            g.body.contains(piece),
            "the account's confirmation carries the console's card, piece by piece: \
                 `{piece}` is missing from {}",
            account_readable(&g.body)
        );
    }
    assert!(
        g.body
            .contains(&format!("action=\"{ACCOUNT_PATH}/keys/remove\"")),
        "and it posts to the path this surface mints on: {}",
        account_readable(&g.body)
    );
    cleanup(&apath);
}

/// 8b-3 (§13.17, "Sign out on /account/"): the account page's Sign out link is the
/// operator's logout URL with only its `rd` query parameter removed. Pure, so every shape
/// of URL is a case here.
///
/// Red until the coder adds `fn logout_without_rd(url: &str) -> String`: it does not
/// exist, so the test module does not compile (E0425).
#[test]
fn logout_without_rd_keeps_everything_else() {
    let rd = "rd=https%3A%2F%2Fa.x.com%2Fadmin%2F";
    let cases: [(String, &str); 12] = [
        (format!("/auth/logout?{rd}"), "/auth/logout"),
        (
            format!("https://a.x.com/auth/logout?{rd}&x=1&y=2"),
            "https://a.x.com/auth/logout?x=1&y=2",
        ),
        (
            format!("https://a.x.com/auth/logout?x=1&{rd}&y=2"),
            "https://a.x.com/auth/logout?x=1&y=2",
        ),
        (
            format!("https://a.x.com/auth/logout?x=1&y=2&{rd}"),
            "https://a.x.com/auth/logout?x=1&y=2",
        ),
        ("/auth/logout".into(), "/auth/logout"),
        (
            "https://a.x.com/auth/logout?x=1".into(),
            "https://a.x.com/auth/logout?x=1",
        ),
        // A name that merely contains or starts with `rd` is somebody else's parameter.
        (
            "/auth/logout?ord=1&rdx=2".into(),
            "/auth/logout?ord=1&rdx=2",
        ),
        (
            format!("/auth/logout?ord=1&{rd}&rdx=2"),
            "/auth/logout?ord=1&rdx=2",
        ),
        // The percent-encoded value goes whole, `%26` inside it included.
        (
            "/auth/logout?rd=https%3A%2F%2Fa.x.com%2F%3Fa%3D1%26b%3D2&x=1".into(),
            "/auth/logout?x=1",
        ),
        // Scheme, host, path and the fragment survive.
        (
            format!("https://a.x.com:8443/p/auth/logout?{rd}#top"),
            "https://a.x.com:8443/p/auth/logout#top",
        ),
        (
            format!("https://a.x.com/auth/logout?x=1&{rd}#top"),
            "https://a.x.com/auth/logout?x=1#top",
        ),
        // Two `rd` parameters: both are the console's round trip.
        (format!("/auth/logout?{rd}&x=1&rd=y"), "/auth/logout?x=1"),
    ];
    for (input, want) in &cases {
        assert_eq!(&logout_without_rd(input), want, "input: {input}");
    }
}

/// 8b-3: with `BB_AUTH_WEB_LOGOUT_URL` carrying an `rd`, the console's Sign out keeps it
/// and `/account/`'s drops it (an `rd` to the console would bring a non-administrator to a
/// 403). Every other parameter of the URL stays.
#[test]
fn the_account_sign_out_carries_no_rd() {
    let path = account_scratch_full("signout-no-rd");
    let operator = "/auth/logout?x=1&rd=https%3A%2F%2Fa.x.com%2Fadmin%2F";
    let mut cfg = cfg_for(&path, ADMIN_BASE);
    cfg.logout_url = Some(operator.to_string());
    cfg.account_logout_url = Some(logout_without_rd(operator));
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &cfg);
        }
    });

    let logout_links = |body: &str| -> Vec<String> {
        anchors_to(&account_readable(body), "/auth/logout")
            .into_iter()
            .filter_map(|a| attr(&a, "href"))
            .collect()
    };

    let g = account_call(
        &format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/"),
        Some("bob@x.com"),
    );
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let links = logout_links(&g.body);
    assert_eq!(
        links,
        vec!["/auth/logout?x=1".to_string()],
        "the account page's pill is the operator's link without its rd: {}",
        account_readable(&g.body)
    );

    let c = console_get(port, "admin@x.com", &[]);
    assert_eq!(c.status, 200, "{}", account_readable(&c.body));
    let links = logout_links(&c.body);
    assert_eq!(
        links,
        vec!["/auth/logout?x=1&amp;rd=https%3A%2F%2Fa.x.com%2Fadmin%2F".to_string()],
        "the console keeps the value as written: {}",
        account_readable(&c.body)
    );
    cleanup(&path);
}

/// 8b-3 (§13.17, "One h1 on the account's confirmation"): the rotate and the revoke
/// confirmation are the shell's one `<h1>`, and it names the action, as does the `<title>`.
///
/// Red until `page_account_confirm` returns only the card and its caller passes the action
/// word as the shell title: today the page has two `<h1>`s ("Your account", then the
/// action).
#[test]
fn the_account_confirmation_has_one_h1() {
    let path = account_scratch_full("confirm-one-h1");
    let base = account_serve(&path);
    for (route, key) in [
        ("rotate", K::AccountKeyRotate),
        ("remove", K::AccountKeyRemove),
    ] {
        let g = account_call(&format!("{base}keys/{route}?id=laptop"), Some("bob@x.com"));
        assert_eq!(g.status, 200, "{route}: {}", account_readable(&g.body));
        let page = account_readable(&g.body);
        let word = t(Lang::En, key);
        let h1s = elements(&page, "<h1", "</h1>");
        assert_eq!(h1s.len(), 1, "{route}: exactly one h1: {page}");
        assert_eq!(visible_text(&h1s[0]).trim(), word, "{route}: {page}");
        let titles = elements(&page, "<title>", "</title>");
        assert_eq!(titles.len(), 1, "{route}: {page}");
        assert!(
            visible_text(&titles[0]).trim().ends_with(word),
            "{route}: the title names the action: {}",
            titles[0]
        );
        assert!(page.contains("laptop"), "{route}: still names the key");
    }
    cleanup(&path);
}

/// 8d-3 (§13.18, "The two brands agree") as §13.34 §10 ends it: the console's bar and the
/// account's name the deployment alike, `ui.brand_name` else `bb-auth`, in **one shape** and
/// with **one line**. The tag line is gone, so what the two bars agree on is the name, and
/// the name is the whole of what the slot says: the version lives in the footer only.
///
/// The shape is pinned in both languages, because the tag was the only translated word in
/// the slot: an English-only check passes on an Italian bar that still says Amministrazione.
#[test]
fn both_bars_name_the_deployment() {
    for (name, settings, want) in [
        ("brands-default", ACCOUNT_SETTINGS, DEFAULT_ACCOUNT_BRAND),
        ("brands-set", ACCOUNT_SETTINGS_BRAND, "BadBat75"),
    ] {
        let path = account_scratch(name, settings);
        let port = account_port(&path);
        let base = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/");
        for cookie in ["lang=en", "lang=it"] {
            let c = console_get(port, "admin@x.com", &[("Cookie", cookie)]);
            assert_eq!(c.status, 200, "{}", account_readable(&c.body));
            let top = the_header_bar(&c.body, "console");
            let brand = the_brand(&top, &format!("{name}/{cookie}"));
            assert_eq!(
                visible_text(&brand).trim(),
                want,
                "{name}/{cookie}: the console's brand says the deployment's name and \
                     nothing else: {brand}"
            );
            let footer = elements(&c.body, "<footer", "</footer>");
            assert_eq!(footer.len(), 1);
            assert!(
                footer[0].contains(&version_line("bb-auth-web")),
                "{name}/{cookie}: the version stays in the footer: {}",
                footer[0]
            );
        }
        let a = account_call_with(&base, Some("bob@x.com"), &[]);
        assert_eq!(a.status, 200, "{}", account_readable(&a.body));
        let top = the_header_bar(&a.body, "account");
        let brand = the_brand(&top, name);
        assert_eq!(
            visible_text(&brand).trim(),
            want,
            "{name}: the account's brand says the same thing in the same shape: {brand}"
        );
        cleanup(&path);
    }
}

/// §13.34 §10 as §11 overruled it: the page a non-administrator lands on names **only the
/// deployment**. That bar has no tab strip and no home to link to, and its brand's tag line
/// was the one word saying what this surface is; with the tag gone the bar says the
/// deployment's name, in a span, and nothing else. Pinned in both languages, because the tag
/// was the only translated word in the slot and it is the Italian page an English-only check
/// waves through.
///
/// Green today, and kept as the pin the other two are: the `403`'s brand is the self-service
/// page's slot (§13.34 §11), which is already a `span.brand` with no `href` and no second
/// line, so nothing here goes red until the console changes. Its job is to stay red if the
/// tag comes back on **this** page, whose bar is built by the same function the console's
/// change touches.
#[test]
fn the_forbidden_bar_names_only_the_deployment() {
    let path = account_scratch_full_settings("forbidden-brand", ACCOUNT_SETTINGS_BRAND);
    let port = account_port(&path);
    for cookie in ["lang=en", "lang=it"] {
        let g = console_get(port, "bob@x.com", &[("Cookie", cookie)]);
        assert_eq!(
            g.status,
            403,
            "a non-administrator is refused the console: {}",
            account_readable(&g.body)
        );
        let top = the_header_bar(&g.body, "403");
        let brand = the_brand(&top, &format!("403/{cookie}"));
        assert_eq!(
            visible_text(&brand).trim(),
            "BadBat75",
            "the refused bar's only word is the deployment's name: {brand}"
        );
    }
    cleanup(&path);
}

/// 8d-3 (§13.18, "The account id on a phone"): the id is `code.uid`, a single token the
/// stylesheet can keep whole (`.uid{white-space:nowrap}`). Red until the markup has the
/// class. The 320px layout half is in `e2e/tests/nojs.js`.
#[test]
fn the_account_id_is_one_token() {
    let path = account_scratch_full("uid-token");
    let base = account_serve(&path);
    let g = account_call_with(&base, Some("bob@x.com"), &[]);
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let ids = controls_with_class(&g.body, "code", "uid");
    assert_eq!(ids.len(), 1, "one code.uid: {}", account_readable(&g.body));
    let id = visible_text(&ids[0]);
    assert!(
        id.len() == 36 && id.matches('-').count() == 4,
        "the code holds the uuid and nothing else: {id:?}"
    );
    cleanup(&path);
}

/// 8d-3 (§13.18, "The Name hint while a refusal shows"): the id field's hint is shown on
/// the open row and omitted when that field carries the refusal, since the refusal already
/// says what is allowed. Other fields' hints are untouched. Red until `account_key_row`
/// drops the hint under `about("id")`.
#[test]
fn a_refused_field_shows_the_refusal_not_the_hint() {
    let path = account_scratch_access("refused-hint", &account_access_keys());
    let base = account_serve(&path);
    let name_label = |body: &str| {
        elements(body, "<label>", "</label>")
            .into_iter()
            .find(|l| l.contains("name=\"id\""))
            .unwrap_or_else(|| panic!("no name label: {}", account_readable(body)))
    };
    let open = account_call_with(&format!("{base}keys/new"), Some("bob@x.com"), &[]);
    assert_eq!(open.status, 200, "{}", account_readable(&open.body));
    let label = name_label(&open.body);
    assert!(
        label.contains("class=\"hint\"") && label.contains(t(Lang::En, K::AccountKeyIdHint)),
        "an open row keeps the hint: {label}"
    );

    let rev = sha256_hex(&read(&path));
    let g = account_post(
        &format!("{base}keys"),
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "My Laptop"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(g.status, 400, "{}", account_readable(&g.body));
    let err = visible_text(&element_containing(&g.body, "class=\"err\"", "</div>"));
    assert_eq!(err, t(Lang::En, K::AccountKeyIdBad));
    let label = name_label(&g.body);
    assert!(
        !label.contains("class=\"hint\"") && !label.contains(t(Lang::En, K::AccountKeyIdHint)),
        "the refused field shows the refusal, not the hint: {label}"
    );
    cleanup(&path);
}
