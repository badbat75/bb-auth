use super::*;

// --- the users tab's three sub-pages (§13.36, plan step 22, slice A) -----------------

/// The words §13.36 §6 gives the sub-pages, spelled out here as the design's table spells
/// them, EN and IT. They are words and not `K` variants because the variants do not exist
/// yet: naming one is a compile error for the whole target, which is a red that proves
/// nothing about the page. Once the table carries them, these consts are the design's
/// answer the coder must match.
const PEOPLE_EN: &str = "People";
const PEOPLE_IT: &str = "Persone";
/// `K::GroupsTab`: the sub-tab's short word, deliberately not `K::Groups`'s "User groups",
/// so the row fits a phone (§13.36 §1).
const GROUPS_TAB_EN: &str = "Groups";
const GROUPS_TAB_IT: &str = "Gruppi";
/// `K::UsersSections`: the sub-tab `nav` is the page's fourth navigation landmark, so it is
/// named, as the APG asks of more than one landmark of a kind.
const SUBNAV_EN: &str = "Users sections";
const SUBNAV_IT: &str = "Sezioni di Utenti";
/// `K::FilterPeople`: the roster's box says what it searches, and the placeholder and the
/// `aria-label` are the same string, which makes WCAG 2.5.3 Label in Name trivially true.
const FILTER_PEOPLE_EN: &str = "email, uuid or key id";
const FILTER_PEOPLE_IT: &str = "email, uuid o id chiave";
/// The group page's **members heading** (§13.36 §2 item 3, as the designer read the
/// screenshots of plan step 22): the section's word, title case like the `Scopes` heading
/// above it, and not the Groups list's lowercase column word `K::Members` the heading
/// borrowed. Spelled as words and not a `K` variant, because naming a variant the enum has
/// not got is a compile error for the whole target, a red that says nothing about a page.
const MEMBERS_HEADING_EN: &str = "Members";
const MEMBERS_HEADING_IT: &str = "Membri";
/// The group page's **member box** (§13.36 §4's rule, one list along): it searches a
/// member's email and uuid, and nothing else, so it cannot borrow `K::FilterPeople`, whose
/// sentence promises a key id this list has no key in.
const FILTER_MEMBERS_EN: &str = "email or uuid";
const FILTER_MEMBERS_IT: &str = "email o uuid";

/// A fixture whose three counts are things a test can read straight off it: four people,
/// two groups, one veto. `@admins` is referenced by `mpa/admin`, `@staff` by nothing, which
/// is the state §13.35 §1 keeps its `referenced by nothing` sentence for, and bob's
/// `laptop` key is the key id the roster's filter is supposed to reach.
const SUBS: &str = r#"{ "version": 1,
      "applications": [
        { "name": "mpa", "base": ["https://app.x.com/mpa"],
          "scopes": [
            { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"], "access": "restricted",
              "groups": ["@admins"] }
          ] }
      ],
      "user_groups": {
        "admins": ["8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b",
                   "22222222-2222-4222-8222-222222222222"],
        "staff": ["33333333-3333-4333-8333-333333333333"]
      },
      "denied": ["spammer@x.com"],
      "users": [
        { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b", "emails": ["Bob@X.com"],
          "api_keys": [ { "id": "laptop",
            "key_hash": "1111111111111111111111111111111111111111111111111111111111111111",
            "released": "1970-01-01", "duration": "1d" } ] },
        { "uuid": "11111111-1111-1111-1111-111111111111", "emails": ["nowhere@x.com"] },
        { "uuid": "22222222-2222-4222-8222-222222222222", "emails": ["you@x.com"] },
        { "uuid": "33333333-3333-4333-8333-333333333333", "emails": ["suspended@x.com"] }
      ]
    }"#;

/// Bob's row and the enrolled-nothing row, as the per-row Remove action spells them: the
/// action only a roster table renders, so it says "this row is in the table" rather than
/// "this address is mentioned somewhere on the page".
const BOB_RM: &str = "/users/8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b/rm";
const NOWHERE_RM: &str = "/users/11111111-1111-1111-1111-111111111111/rm";

/// Serve `fixture` and `GET` `path` as the fixture's administrator, with `lang` as the
/// browser's language cookie. The sub-pages are reached **by URL**, so these tests go over a
/// socket: [`render_of`]'s match is over the routes the code has, and `Route::Groups` is not
/// one of them yet, which makes a rendering helper that named it a compile error.
fn console_page(name: &str, fixture: &str, path: &str, lang: &str) -> (u16, String) {
    let file = scratch(name, fixture);
    let port = serve(&file, "");
    let mut r = get_with_secret(format!("http://127.0.0.1:{port}{path}"))
        .header(IDENTITY_HEADER, "admin@x.com")
        .header("Cookie", lang)
        .call()
        .expect("a response");
    let out = (
        r.status().as_u16(),
        r.body_mut().read_to_string().expect("utf-8"),
    );
    cleanup(&file);
    out
}

/// Thirty roster rows whose emails start with `prefix`, numbered from `from` at the uuid.
///
/// The uuid is spelled in decimal digits on purpose: a hex uuid carries `a` to `f`, so a
/// filter typed as a single letter would reach rows the test did not count, and the pager's
/// "30 of 60" would be the wrong numbers.
fn lettered(prefix: &str, from: usize) -> String {
    (0..30)
        .map(|i| {
            format!(
                r#"{{ "uuid": "{:08}-0000-4000-8000-000000000000",
                          "emails": ["{}{i:02}@x.com"] }}"#,
                from + i,
                prefix
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// A file that gives a group's page everything §13.36 §2 says it has to show: `@admins` is
/// named by two scopes; `@outsiders` is named by one of them **as an exclusion**, which is
/// the reference the page has to say is a keeping-out and not a letting-in; `@empty` is
/// referenced and has no members at all; and `@admins` carries a uuid no roster row has,
/// which the page has to name as nobody rather than as a name with no link.
const GROUP_PAGE: &str = r#"{ "version": 1,
      "applications": [
        { "name": "mpa", "base": ["https://app.x.com/mpa"],
          "scopes": [
            { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"], "access": "restricted",
              "groups": ["@admins"] },
            { "name": "gate", "urls": ["https://app.x.com/mpa/gate/*"], "access": "restricted",
              "groups": ["@admins", "@empty"], "excluded": ["@outsiders"] }
          ] }
      ],
      "user_groups": {
        "admins": ["8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b",
                   "22222222-2222-4222-8222-222222222222",
                   "99999999-9999-4999-8999-999999999999"],
        "empty": [],
        "outsiders": ["33333333-3333-4333-8333-333333333333"]
      },
      "denied": [],
      "users": [
        { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b", "emails": ["Bob@X.com"] },
        { "uuid": "22222222-2222-4222-8222-222222222222", "emails": ["you@x.com"] },
        { "uuid": "33333333-3333-4333-8333-333333333333", "emails": ["suspended@x.com"] }
      ]
    }"#;

/// A roster where one person is in **two** groups and one in none, for the roster's groups
/// column (§13.36 §3): two links have a file order to get right, and none has an empty
/// state. The group names are spelled so that the file's order is **not** the order they
/// were written in: `user_groups` is a `BTreeMap`, so the file's order is alphabetical, and
/// a page that emitted insertion order would read alpha, beta.
const ROSTER_GROUPS: &str = r#"{ "version": 1,
      "applications": [
        { "name": "mpa", "base": ["https://app.x.com/mpa"],
          "scopes": [
            { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"], "access": "restricted",
              "groups": ["@admins"] },
            { "name": "desk", "urls": ["https://app.x.com/mpa/desk/*"], "access": "restricted",
              "groups": ["@staff"] },
            { "name": "ops", "urls": ["https://app.x.com/mpa/ops/*"], "access": "restricted",
              "groups": ["@beta", "@alpha"] }
          ] }
      ],
      "user_groups": {
        "beta": ["11111111-1111-1111-1111-111111111111"],
        "alpha": ["11111111-1111-1111-1111-111111111111"],
        "admins": ["8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b",
                   "22222222-2222-4222-8222-222222222222"],
        "staff": ["33333333-3333-4333-8333-333333333333"]
      },
      "denied": [],
      "users": [
        { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b", "emails": ["Bob@X.com"] },
        { "uuid": "11111111-1111-1111-1111-111111111111", "emails": ["nowhere@x.com"] },
        { "uuid": "22222222-2222-4222-8222-222222222222", "emails": ["you@x.com"] },
        { "uuid": "33333333-3333-4333-8333-333333333333", "emails": ["suspended@x.com"] },
        { "uuid": "44444444-4444-4444-8444-444444444444", "emails": ["nofile@x.com"] }
      ]
    }"#;

/// The roster rows of [`SUBS`] that have no constant of their own yet: the two the group
/// page and the roster's column have to name in an href.
const YOU_UUID: &str = "22222222-2222-4222-8222-222222222222";
const YOU_RM: &str = "/users/22222222-2222-4222-8222-222222222222/rm";
const STAFF_RM: &str = "/users/33333333-3333-4333-8333-333333333333/rm";

/// The words §13.36 §6 adds, spelled exactly as the design's table spells them, EN and IT.
/// They are words and not `K` variants because the variants do not exist yet: naming one is
/// a compile error for the whole target, which is a red that says nothing about a page.
/// Once the table carries them, these consts are the answer the coder has to match.
const COL_GROUPS_EN: &str = "groups";
const COL_GROUPS_IT: &str = "gruppi";
const GROUP_IN_ROSTER_EN: &str = "show them in People";
const GROUP_IN_ROSTER_IT: &str = "mostrali in Persone";
const GROUP_FILTER_EN: &str = "group: ";
const GROUP_FILTER_IT: &str = "gruppo: ";
const GROUP_FILTER_CLEAR_EN: &str = "show every group";
const GROUP_FILTER_CLEAR_IT: &str = "mostra tutti i gruppi";

/// The panel a section heading introduces: the first `div.panel` after `needle`.
/// [`nested_block`] counts the nested `div`s, so a panel that holds a table ends where the
/// page ends it and not at the first `</div>`.
fn panel_after(html: &str, needle: &str, label: &str) -> String {
    let at = html
        .find(needle)
        .unwrap_or_else(|| panic!("{label}: the page carries no {needle:?}: {html}"));
    nested_block(&html[at..], "<div class=\"panel\"", "div")
}

/// The cells of one table row, as `<td …>…</td>` elements, in document order.
fn row_cells(row: &str) -> Vec<String> {
    elements(row, "<td", "</td>")
}

/// A page's list-control row: the filter form and the pager above a list.
fn the_listctl(main: &str) -> String {
    nested_block(main, "div class=\"listctl\"", "div")
}

#[test]
fn route_maps_the_three_sub_pages_and_a_group() {
    // §13.36 §1: People, Groups and Denied are three pages under the one Users tab, and the
    // three URLs already exist, so none of them moves. Every assertion runs through `path()`,
    // `tab()` and `title()` rather than naming `Route::Groups`: a test that named a variant
    // the code does not have is a compile error that reddens the whole target, which says
    // nothing about the route. §13.36 §2 adds the fourth route the same way.
    let groups = route("/groups", "").expect("/groups is a page");
    assert_eq!(
        groups.path(),
        "/groups",
        "the groups list is its own route, not `Route::Users` wearing the URL"
    );
    assert_eq!(
        route(&groups.path(), ""),
        Some(groups.clone()),
        "path() and route() are inverses"
    );
    assert_eq!(
        groups.tab(),
        Route::Users,
        "and it still lights the Users tab, the bar keeps five tabs"
    );
    assert_eq!(
        groups.title(),
        "user_groups",
        "and names the section it edits"
    );

    // §13.36 §2: one group is a page too, at `/groups/{name}`, matched after the `+add`
    // arm. A group name is `[A-Za-z0-9_-]`, so no name can spell `+add` and the two arms
    // cannot trade a URL.
    let grp = route("/groups/admins", "").expect("a group is a page");
    assert_eq!(
        grp.path(),
        "/groups/admins",
        "the URL is the name, as a row links it"
    );
    assert_eq!(
        route(&grp.path(), ""),
        Some(grp.clone()),
        "path() and route() are inverses"
    );
    assert_eq!(
        grp.tab(),
        Route::Users,
        "it lights the Users tab, so the bar keeps its five tabs"
    );
    assert_eq!(
        grp.title(),
        "user_groups",
        "and names the section it edits, as the list does"
    );
    assert_eq!(
        grp.parent().path(),
        "/groups",
        "it is reached from, and cancels back to, the list it is a row of"
    );
    assert_eq!(
        route("/groups/+add", ""),
        Some(Route::GroupAdd),
        "the new arm is after `+add`, which is why a name can never reach the form"
    );

    let people = route("/users", "").expect("People is the tab's default");
    assert_eq!(
        people.path(),
        "/users",
        "the bar's Users tab still lands here"
    );
    assert_eq!(people.title(), "users");

    let denied = route("/denied", "").expect("Denied is a page");
    assert_eq!(denied, Route::Denied, "and its route does not move either");
    assert_eq!(denied.tab(), Route::Users);
    assert_eq!(denied.title(), "denied");

    // The group forms already live under /groups and stay there. §1's table moves their
    // `parent()` (the cancel target and the `409` back): add goes back to the list, because
    // the group it made did not exist when the operator opened the form, and the edit and
    // the removal go back to the group's page, which is the page that shows the membership
    // the form is about to write, and the group the removal is about to take away.
    for (at, parent) in [
        (Route::GroupAdd, "/groups"),
        (Route::GroupEdit("admins".to_string()), "/groups/admins"),
        (Route::GroupRm("admins".to_string()), "/groups/admins"),
    ] {
        assert_eq!(
            route(&at.path(), ""),
            Some(at.clone()),
            "{at:?} round-trips"
        );
        assert_eq!(at.tab(), Route::Users, "{at:?} lights the Users tab");
        assert_eq!(at.title(), "user_groups", "{at:?} edits user_groups");
        assert_eq!(
            at.parent().path(),
            parent,
            "{at:?} cancels back to {}",
            parent
        );
    }
    assert_eq!(Route::GroupAdd.path(), format!("/groups/{ACTION_ADD}"));
}

#[test]
fn each_users_sub_page_carries_the_three_sub_tabs_with_counts() {
    // §13.36 §1: the same row of three sub-tabs on all three pages, each naming its section
    // and its **whole** count, the current one marked the bar's way, because `.on` is a
    // colour and colour alone is not a distinction WCAG 1.3.1 accepts.
    for (path, current) in [("/users", 0), ("/groups", 1), ("/denied", 2)] {
        let (status, html) = console_page("subs-tabs", SUBS, path, "lang=en");
        assert_eq!(status, 200, "{path} is a page");
        let (nav, links) = sub_tabs(&html);
        assert_eq!(
            attr(&nav, "aria-label").as_deref(),
            Some(SUBNAV_EN),
            "a page with more than one navigation landmark names each one: {nav}"
        );
        assert_eq!(
            links
                .iter()
                .map(|a| attr(a, "href").unwrap_or_default())
                .collect::<Vec<_>>(),
            ["/users", "/groups", "/denied"],
            "three links, in this order: {nav}"
        );
        assert_eq!(
            links.iter().map(|a| visible_text(a)).collect::<Vec<_>>(),
            [
                format!("{PEOPLE_EN} (4)"),
                format!("{GROUPS_TAB_EN} (2)"),
                format!("{} (1)", t(Lang::En, K::Denied)),
            ],
            "the section's short word and its count, as one text node: {nav}"
        );
        assert_eq!(
            attr(&links[1], "id").as_deref(),
            Some("user_groups"),
            "so the old `/users#user_groups` bookmark scrolls to the link that means it"
        );
        assert_eq!(
            attr(&links[2], "id").as_deref(),
            Some("denied"),
            "and `/users#denied` does the same: {nav}"
        );
        let on: Vec<usize> = (0..links.len())
            .filter(|i| links[*i].contains(r#"aria-current="page""#))
            .collect();
        assert_eq!(
            on,
            [current],
            "exactly one sub-tab says you are here: {nav}"
        );
        assert!(
            links[current].contains(r#"class="pill on""#),
            "and the current one is marked in the markup, not only to a reader: {}",
            links[current]
        );
    }

    // The words in Italian, which is where a table that grew one column shows up.
    let (_, html) = console_page("subs-tabs-it", SUBS, "/groups", "lang=it");
    let (nav, links) = sub_tabs(&html);
    assert_eq!(
        attr(&nav, "aria-label").as_deref(),
        Some(SUBNAV_IT),
        "{nav}"
    );
    assert_eq!(
        links.iter().map(|a| visible_text(a)).collect::<Vec<_>>(),
        [
            format!("{PEOPLE_IT} (4)"),
            format!("{GROUPS_TAB_IT} (2)"),
            format!("{} (1)", t(Lang::It, K::Denied)),
        ],
        "{nav}"
    );
}

#[test]
fn each_sub_page_shares_the_tabs_h1_and_names_its_own_section() {
    // §13.36 §1 "One shape for all three pages": the `h1` is the tab's word on all three, so
    // the page says which tab it is under. The section's `h2` is the **section's** word, which
    // for Groups is the long one: §1 item 3 says "Groups' is `User groups user_groups`", and
    // the reason sits beside the sub-tab's rule, "`GroupsTab` is not `K::Groups` ... the row
    // must fit a phone, **and the section's `h2` spells the name out**". So People's `h2` does
    // repeat its sub-tab (`K::People`, the design's own choice, "the sub-tab's word and the
    // heading it lands on are the same word"), and Groups' deliberately does not.
    // `page_denied`'s own `h1` goes, because the shared one is now "Users".
    for (path, heading) in [
        ("/users", format!("{PEOPLE_EN} users")),
        ("/groups", format!("{} user_groups", t(Lang::En, K::Groups))),
        ("/denied", format!("{} denied", t(Lang::En, K::Denied))),
    ] {
        let (_, html) = console_page("subs-shape", SUBS, path, "lang=en");
        let doc = account_readable(&html);
        let h1 = elements(&doc, "<h1", "</h1>");
        assert_eq!(h1.len(), 1, "one `h1` on a sub-page: {doc}");
        assert_eq!(
            visible_text(&h1[0]),
            t(Lang::En, K::Users),
            "{path} says which tab it is under"
        );
        let h2 = elements(&doc, "<h2", "</h2>");
        assert_eq!(
            visible_text(&h2[0]),
            heading,
            "{path} heads its own section: {doc}"
        );
    }

    // The roster's lede describes the roster and nothing else, so it moved down to People and
    // is wrong on the other two.
    let intro = t(Lang::En, K::UsersIntro);
    let needle: &str = intro;
    let (_, html) = console_page("subs-lede", SUBS, "/users", "lang=en");
    assert!(
        html.contains(needle),
        "People keeps the sentence about the roster"
    );
    for path in ["/groups", "/denied"] {
        let (_, html) = console_page("subs-lede", SUBS, path, "lang=en");
        let doc = account_readable(&html);
        assert!(!doc.contains(needle), "{path} is not the roster: {doc}");
    }
}

#[test]
fn the_users_sub_page_shows_only_its_own_list() {
    // §13.36 §1: the stacked page is gone. A long file opens on the list the operator came
    // for, and `groups_section` and `denied_list` are no longer rendered on `/users`.
    //
    // Every check runs on [`the_main`], the page's own column, and not on the document: every
    // page of this console inlines the three stylesheets, and `admin.css`'s comments are prose
    // about the code they document, so the bytes of a page that shows no roster carry the word
    // `api_keys` anyway (and the bar's account menu names the caller, links to the caller's
    // person page, and repeats the tab links). The claim here is about the **list area**, so
    // that is what gets read.
    let (_, html) = console_page("subs-only-users", SUBS, "/users", "lang=en");
    let main = the_main(&html);
    assert!(main.contains(NOWHERE_RM), "the roster is here: {main}");
    // What must be absent is the **section**, not the word: §13.36 §3 gives the roster a
    // groups column, so `@admins` is legitimately on this page as a cell of a row. The
    // section heading's file key (`section_heading`) and the section's own `+ add` are what
    // say a section is here, and the sub-tab row's `id="user_groups"` is neither.
    for gone in [
        "<span class=\"muted mono\">user_groups</span>",
        "<span class=\"muted mono\">denied</span>",
        "spammer@x.com",
        &format!("/groups/{ACTION_ADD}"),
        &format!("/denied/{ACTION_ADD}"),
    ] {
        assert!(
            !main.contains(gone),
            "the groups and the veto have their own page now, so {gone} is not on the \
                 roster's page: {main}"
        );
    }

    let (_, html) = console_page("subs-only-groups", SUBS, "/groups", "lang=en");
    let main = the_main(&html);
    assert!(
        main.contains("/groups/staff/edit"),
        "the groups are here: {main}"
    );
    for gone in ["api_keys", "/users/", "spammer@x.com"] {
        assert!(
            !main.contains(gone),
            "no roster and no veto on the group list, so {gone} is not here: {main}"
        );
    }

    let (_, html) = console_page("subs-only-denied", SUBS, "/denied", "lang=en");
    let main = the_main(&html);
    assert!(main.contains("spammer@x.com"), "the veto is here: {main}");
    for gone in ["api_keys", "/users/", "@admins"] {
        assert!(
            !main.contains(gone),
            "no roster and no groups on the veto page, so {gone} is not here: {main}"
        );
    }
}

#[test]
fn group_writes_land_on_the_group_or_the_list() {
    // §13.36 §1's PRG table: a form lands where its object is shown. Add and edit land on
    // the group's **own page**, which is the page that shows the membership the form just
    // wrote; a removal lands on the list, because the page it was on no longer exists. The
    // `?msg=` notice renders on any page, so the moved targets need nothing more.
    // `parent()` of each route, the other half of the same table, is pinned by
    // `route_maps_the_three_sub_pages_and_a_group`.
    let path = scratch("group-prg", SUBS);
    let cfg = cfg_for(&path, "");
    let got = post(
        &cfg,
        Route::GroupAdd,
        &[
            ("rev", &rev_of(&path)),
            ("name", "newest"),
            ("members", "you@x.com"),
        ],
    );
    assert_eq!(got.location(), "/groups/newest?msg=group-added");
    let got = post(
        &cfg,
        Route::GroupEdit("staff".to_string()),
        &[
            ("rev", &rev_of(&path)),
            ("name", "staff"),
            ("members", "suspended@x.com"),
        ],
    );
    assert_eq!(got.location(), "/groups/staff?msg=group-saved");
    let got = post(
        &cfg,
        Route::GroupRm("newest".to_string()),
        &[("rev", &rev_of(&path))],
    );
    assert_eq!(got.location(), "/groups?msg=group-removed");
    // The veto already lands where its list is, and stays: §1's table calls it unchanged.
    let got = post(
        &cfg,
        Route::DenyAdd,
        &[("rev", &rev_of(&path)), ("email", "nasty@x.com")],
    );
    assert_eq!(got.location(), "/denied?msg=denied-added");
    let got = post(
        &cfg,
        Route::DenyRm("nasty@x.com".to_string()),
        &[("rev", &rev_of(&path))],
    );
    assert_eq!(got.location(), "/denied?msg=denied-removed");
    cleanup(&path);
}

#[test]
fn each_list_filters_on_its_own_and_the_sub_tab_count_stays_whole() {
    // Three lists, three namespaces, now on three pages. The filter of one page is nobody
    // else's, and the sub-tab's number is the **file's**, never the filtered one, so the row
    // does not move under the person's hands while they type (§13.36 §1).
    let (_, html) = console_page("ns-users", SUBS, "/users?uq=nowhere", "lang=en");
    assert!(html.contains(NOWHERE_RM), "the roster is narrowed: {html}");
    assert!(
        !html.contains(BOB_RM),
        "the roster row for bob is filtered out: {html}"
    );
    let (_, links) = sub_tabs(&html);
    assert_eq!(
        visible_text(&links[0]),
        format!("{PEOPLE_EN} (4)"),
        "and the count beside the tab is the file's, not the narrowed one"
    );

    let (_, html) = console_page("ns-groups", SUBS, "/groups?uq=staff", "lang=en");
    assert!(
        html.contains("@admins"),
        "the roster's parameter does not reach the group list: {html}"
    );
    let (_, html) = console_page("ns-groups-g", SUBS, "/groups?gq=staff", "lang=en");
    assert!(html.contains("@staff"), "the group list's own does: {html}");
    assert!(!html.contains("@admins"), "and narrows it to one: {html}");

    let (_, html) = console_page("ns-denied", SUBS, "/denied?dq=spammer", "lang=en");
    assert!(
        html.contains("spammer@x.com"),
        "the veto list's own: {html}"
    );
    let (_, html) = console_page("ns-denied-none", SUBS, "/denied?dq=nobodyatall", "lang=en");
    assert!(
        html.contains(t(Lang::En, K::NoMatch)),
        "and a veto filter that matches says so: {html}"
    );
}

#[test]
fn the_roster_filter_reaches_the_uuid_and_a_key_id() {
    // §13.36 §4: the reach is already uuid and key id, what was never pinned is the reach,
    // and what is missing is that nobody can read it off a box that says "filter".
    for q in ["uq=8f14e45f", "uq=laptop"] {
        let (_, html) = console_page("roster-reach", SUBS, &format!("/users?{q}"), "lang=en");
        assert!(
            html.contains(BOB_RM),
            "{q} keeps the row it matches: {html}"
        );
        assert!(!html.contains(NOWHERE_RM), "{q} keeps nothing else: {html}");
    }
    for (lang, words) in [("lang=en", FILTER_PEOPLE_EN), ("lang=it", FILTER_PEOPLE_IT)] {
        let (_, html) = console_page("roster-box", SUBS, "/users", lang);
        let box_tag = field_tag(&html, "uq");
        assert_eq!(
            attr(&box_tag, "placeholder").as_deref(),
            Some(words),
            "the box says what it searches: {box_tag}"
        );
        assert_eq!(
            attr(&box_tag, "aria-label").as_deref(),
            Some(words),
            "and the visible hint and the name are one string, which is what makes WCAG \
                 2.5.3 Label in Name true by construction: {box_tag}"
        );
    }
}

#[test]
fn the_pager_says_which_rows_of_how_many() {
    // §13.36 §4: one sentence in the shared control says what two fragments said, with the
    // text in front of the two buttons, because between them the Italian sentence was
    // squeezed into a column one word wide at 320px.
    //
    // The sentence is read out of the whole `div.listctl` and not out of the `span.pager`:
    // the pager holds two nested spans, and `elements` cuts at the first `</span>`, so a
    // slice of the pager alone silently loses the buttons standing beside the words.
    let ctl_text = |html: &str| -> String {
        let ctl = elements(html, r#"<div class="listctl""#, "</div>");
        assert_eq!(ctl.len(), 1, "one list, so one control row: {html}");
        visible_text(&ctl[0])
    };
    let (prev, next) = (
        format!("← {}", t(Lang::En, K::PagePrev)),
        format!("{} →", t(Lang::En, K::PageNext)),
    );

    let big = many_users(60);
    let (_, html) = console_page("pager-p1", &big, "/users", "lang=en");
    let text = ctl_text(&html);
    assert!(
        text.contains("rows 1–25 of 60"),
        "the first row's number, the last's, and how many matched: {text}"
    );
    assert!(
        text.find("rows 1–25 of 60") < text.find(&prev),
        "the words come before the two controls, so a narrow column breaks the sentence \
             under the buttons rather than between the words: {text}"
    );
    assert!(
        text.contains(&next),
        "and the second control follows: {text}"
    );
    assert!(
        !text.contains("1/3"),
        "the sentence replaces the `page n/m` fragment: {text}"
    );

    let (_, html) = console_page("pager-p3", &big, "/users?up=3", "lang=en");
    let text = ctl_text(&html);
    assert!(
        text.contains("rows 51–60 of 60"),
        "the last page says where it stops: {text}"
    );

    // Thirty of the sixty carry a letter the other thirty have not got, so the filter that
    // matches 30 of 60 is one query string away, and the sentence names both numbers.
    let halves = format!(
        r#"{{ "version": 1, "applications": [], "users": [{},{}] }}"#,
        lettered("a", 0),
        lettered("b", 30)
    );
    let (_, html) = console_page("pager-filtered", &halves, "/users?uq=a", "lang=en");
    let text = ctl_text(&html);
    assert!(
        text.contains("rows 1–25 of 30 (filtered from 60)"),
        "the filtered sentence, which replaces the bare `matched/total` span: {text}"
    );
    assert!(!text.contains("30/60"), "{text}");

    // Nothing to count on a page that shows every row, and nothing to count when no row
    // matches: the panel's own sentence already says that.
    let (_, html) = console_page("pager-one-page", SUBS, "/denied", "lang=en");
    assert!(
        !html.contains("rows 1–1 of 1"),
        "one unfiltered page needs no count, and the sub-tab says the total: {html}"
    );
    let (_, html) = console_page("pager-none", &big, "/users?uq=nobodyatall", "lang=en");
    assert!(
        !ctl_text(&html).contains("rows 1–"),
        "no matching row, so no count: {html}"
    );

    // Italian, with the same order.
    let (_, html) = console_page("pager-it", &big, "/users", "lang=it");
    let text = ctl_text(&html);
    assert!(
        text.contains("righe 1–25 di 60"),
        "the same sentence in the reader's language: {text}"
    );
    assert!(
        text.find("righe 1–25 di 60") < text.find(&format!("← {}", t(Lang::It, K::PagePrev))),
        "and in front of the controls there too: {text}"
    );
}

#[test]
fn the_dashboard_count_of_groups_links_to_the_group_list() {
    // §13.36 §1 "Old links": a count row points at the page that shows what it counts.
    let html = render_of("dash-cards", SUBS, Route::Dashboard, "");
    let cards = elements(&html, r#"<a class="card""#, "</a>");
    for (label, href) in [
        ("user_groups", "/groups"),
        (">users<", "/users"),
        ("denied", "/denied"),
    ] {
        let card = cards
            .iter()
            .find(|c| c.contains(label))
            .unwrap_or_else(|| panic!("the dashboard counts {label}: {html}"));
        assert_eq!(
            attr(open_tag(card), "href").as_deref(),
            Some(href),
            "the `{label}` card links the page that lists it: {card}"
        );
    }
}

#[test]
fn the_sub_tab_row_and_the_pager_wrap() {
    // §13.36 §1 and §4, both measured. The bar's `nav:not(.acct){flex-wrap:nowrap;
    // min-width:max-content}` matches any `nav`, so it reaches the row inside the page as
    // well, and at 320px with four-digit counts that row was 17px wider than the column.
    let rule = the_rule(CSS, "main nav.sub").expect("admin.css gives the sub-tab row a rule");
    for want in ["flex-wrap:wrap", "min-width:0", "margin:0 0 18px"] {
        assert!(rule.contains(want), "the sub-tab row needs {want}: {rule}");
    }
    let rule = the_rule(CSS, ".listctl .pager").expect("admin.css styles the pager");
    assert!(
        rule.contains("flex-wrap:wrap"),
        "the pager sentence wraps under its own buttons, which is what keeps 320px free of \
             sideways scroll: {rule}"
    );
}

// --- one page per group, the roster's groups column, the group filter (§13.36 §2, §3, §5,
//     §6, plan step 22 slice B) --------------------------------------------------------

/// The roster row that carries `href` among its actions. A row is in the table when its
/// action is, which is what §13.36 §3's claims about a **row** are about: the address of a
/// person appears in the group's own member list too, and a page that shows one list cannot
/// be told from one that shows the other by an address alone.
fn row_with(html: &str, href: &str, label: &str) -> String {
    elements(html, "<tr", "</tr>")
        .into_iter()
        .find(|r| r.contains(href))
        .unwrap_or_else(|| panic!("{label}: no row carries {href}: {html}"))
}

/// The roster's group chip: the pill in the control row that names the group the list is
/// filtered to, and clears it (§13.36 §3).
fn group_chip(main: &str) -> String {
    let ctl = the_listctl(main);
    elements(&ctl, "<a ", "</a>")
        .into_iter()
        .find(|a| {
            let text = visible_text(a);
            text.starts_with(GROUP_FILTER_EN) || text.starts_with(GROUP_FILTER_IT)
        })
        .unwrap_or_else(|| panic!("the control row names the group the list is filtered to: {ctl}"))
}

#[test]
fn a_group_page_lists_scopes_then_members() {
    // §13.36 §2: one group is a page at `/groups/{name}`, and it answers first the question
    // the dashboard's "referenced by nothing" warning was sent to ask: the scopes that name
    // the group come **before** its members, because the scopes are why the group matters.
    // Everything is read over a socket, because the page is reached by URL and `render_of`'s
    // match is over the routes the code has, which does not have this one yet.
    let (status, html) = console_page("group-page", GROUP_PAGE, "/groups/admins", "lang=en");
    assert_eq!(status, 200, "a group is a page of its own");
    let main = the_main(&html);

    // The head is the person page's head: the name as the file spells it, the section it
    // edits, the way back to the list it is a row of, and the two writes the file already
    // has forms for. Nothing is asked of the forms, only of where they return (§1's table).
    let h1 = elements(&main, "<h1", "</h1>");
    assert_eq!(h1.len(), 1, "one `h1` on a group's page: {main}");
    assert!(
        h1[0].contains("<code>@admins</code>"),
        "the head names the group as the file spells it: {h1:?}"
    );
    assert!(
        h1[0].contains(r#"<span class="muted mono">user_groups</span>"#),
        "and the section it edits, as every section page does: {h1:?}"
    );
    for href in ["/groups/admins/edit", "/groups/admins/rm"] {
        assert!(
            main.contains(href),
            "the page offers the {href} form: {main}"
        );
    }
    assert!(
        main.contains(r#"href="/groups""#),
        "and the way back to the list: {main}"
    );

    // The two sections, in the order the design gives them, each under its own heading. The
    // members heading is the section's word in title case, the pair the screenshot review of
    // plan step 22 asked for; `the_group_pages_members_heading_is_the_sections_word` pins the
    // words themselves, so this one is about the order.
    let h2 = elements(&main, "<h2", "</h2>");
    assert_eq!(
        h2.iter().map(|h| visible_text(h)).collect::<Vec<_>>(),
        [
            format!("{} scopes", t(Lang::En, K::Scopes)),
            MEMBERS_HEADING_EN.to_string(),
        ],
        "scopes, then members: {main}"
    );
    let scopes = panel_after(
        &main,
        r#"<span class="muted mono">scopes</span>"#,
        "the scopes panel",
    );
    // The panel is cut from the heading **as the page spells it**, so a change to the
    // heading's wording reddens the heading assertion above and not this lookup too.
    let members = panel_after(&main, &h2[1], "the members panel");
    for id in ["mpa/admin", "mpa/gate"] {
        assert!(
            scopes.contains(&format!("<a href=\"/apps/mpa\"><code>{id}</code></a>")),
            "a scope that names the group is a link to the application that owns it: {scopes}"
        );
    }
    assert!(
        main.find("mpa/admin") < main.find("mpa/gate"),
        "and in the file's order: {main}"
    );
    assert!(
        main.find("mpa/gate") < main.find("bob@x.com"),
        "the whole scopes section stands above the members, which is why the warning that \
             linked here is answered by the first thing under the head: {main}"
    );

    // The panel agrees with the library's list entry for entry, which is the rule §2 states
    // so that this page and the removal's refusal cannot answer "who names me?" twice.
    let doc: AccessFile = serde_json::from_str(GROUP_PAGE).expect("the fixture parses");
    let refs = user_group_refs(&doc, "admins");
    assert_eq!(refs, ["mpa/admin", "mpa/gate"], "the fixture's references");
    assert_eq!(
        elements(&scopes, "<li", "</li>").len(),
        refs.len(),
        "one line per reference, no more: {scopes}"
    );

    // A scope that keeps the group **out** is on the list as much as one that lets it in,
    // and says so in words beside the link. Those words are the file's own (`EXCLUDED_REF`,
    // which `user_group_refs` already prints) and not a colour, so a reader who does not see
    // colour hears them too (WCAG 1.4.1).
    let (status, html) = console_page("group-page-out", GROUP_PAGE, "/groups/outsiders", "lang=en");
    assert_eq!(
        status, 200,
        "a group named only as an exclusion is a page too"
    );
    let scopes = panel_after(
        &the_main(&html),
        r#"<span class="muted mono">scopes</span>"#,
        "the exclusion's scopes panel",
    );
    assert!(
        scopes.contains(r#"<a href="/apps/mpa"><code>mpa/gate</code></a>"#),
        "{scopes}"
    );
    assert!(
        scopes.contains(r#"<span class="tag bad">excluded</span>"#),
        "the reference is a keeping-out, and the page says so beside the link: {scopes}"
    );

    // The members: the pill that asks the roster for them (§3), landing on page 1, and the
    // members behind a filter and a pager of their **own** prefix, so a group of a thousand
    // people is a page and not a scroll.
    let pill = element_containing(&main, GROUP_IN_ROSTER_EN, "</a>");
    assert_eq!(
        attr(open_tag(&pill), "href").as_deref(),
        Some("/users?ug=admins"),
        "the pill lands on the roster filtered by this group, starting at the first page: \
             {pill}"
    );
    assert_eq!(
        main.matches("<div class=\"listctl\"").count(),
        1,
        "the members list has its own control row, and the scopes panel has none: {main}"
    );
    for name in ["mq", "mp"] {
        let tag = field_tag(&main, name);
        assert!(
            tag.contains(&format!("name=\"{name}\"")),
            "the members' Listing is prefixed `m`, so it never borrows the roster's `u`: {tag}"
        );
    }
    for (uuid, label) in [(BOB, "bob@x.com"), (YOU_UUID, "you@x.com")] {
        assert!(
            members.contains(&format!("<a href=\"/users/{uuid}\">{label}</a>")),
            "a member a roster row resolves is a link to that person's page: {members}"
        );
    }
    // A member no row resolves is named as nobody, in the file's spelling, with the words
    // beside it. The gate refuses such a file, so this is a file mid-edit, and the page says
    // what is wrong rather than showing a name that leads nowhere.
    assert!(
        members.contains(r#"<code class="bad">99999999-9999-4999-8999-999999999999</code>"#),
        "an unknown member keeps the uuid the file wrote: {members}"
    );
    assert!(
        members.contains(&format!(
            "<span class=\"tag bad\">{}</span>",
            t(Lang::En, K::UnknownMember)
        )),
        "and is labelled as one, not left bare: {members}"
    );

    // The pill's words are the console's, in the reader's language: Italian is the long
    // spelling, and this is the surface where §13.34 §0's lesson about translated length bites.
    let (_, html) = console_page("group-page-it", GROUP_PAGE, "/groups/admins", "lang=it");
    let main = the_main(&html);
    let pill = element_containing(&main, GROUP_IN_ROSTER_IT, "</a>");
    assert_eq!(
        attr(open_tag(&pill), "href").as_deref(),
        Some("/users?ug=admins"),
        "the Italian pill leads to the same filtered roster: {pill}"
    );

    // An unknown name is the `404` the edit form already answers, and it names the name.
    let (status, html) = console_page("group-page-none", GROUP_PAGE, "/groups/nope", "lang=en");
    assert_eq!(status, 404, "no group, no page");
    assert!(
        html.contains(t(Lang::En, K::NoSuchGroup)) && html.contains("nope"),
        "and the page says which name is missing: {html}"
    );
}

#[test]
fn a_group_nothing_references_says_so_on_its_page() {
    // §13.36 §2: the empty state of the scopes panel is the **same sentence** as the
    // dashboard warning that linked here, because the warning's answer is this panel. It
    // carries no kind label, for the reason §13.35 §1 gave: the heading above it names the
    // kind, so a label would repeat the heading.
    let (status, html) = console_page("group-page-unused", SUBS, "/groups/staff", "lang=en");
    assert_eq!(
        status, 200,
        "a group nothing references is a page of its own"
    );
    let panel = panel_after(
        &the_main(&html),
        r#"<span class="muted mono">scopes</span>"#,
        "the empty scopes panel",
    );
    assert_eq!(
        visible_text(&panel),
        t(Lang::En, K::ReferencedByNothing),
        "one sentence and nothing beside it: {panel}"
    );
    assert!(
        panel.contains(r#"<span class="muted">"#),
        "it is the muted sentence, as the warning's line is: {panel}"
    );
    assert!(!panel.contains(KIND_GROUP), "no kind label: {panel}");
}

#[test]
fn the_group_page_carries_no_users_sub_tabs() {
    // §13.36 §2, as the designer read the screenshots of plan step 22: a group's page is the
    // **person page's** shape, and the person page has no row of sub-tabs. The row belongs to
    // the three list pages, where it says which of the three is showing; on a page about one
    // object it says again what the `h1` has already said, and it pushes the page's answer
    // (the scopes that name the group) down the screen. The row goes; the back link stays,
    // because that is the one thing on the page saying "this is a row of the Groups list".
    let (status, html) = console_page("group-no-subnav", GROUP_PAGE, "/groups/admins", "lang=en");
    assert_eq!(status, 200, "a group is a page of its own");
    let main = the_main(&html);
    assert!(
        elements(&main, r#"<nav class="sub""#, "</nav>").is_empty(),
        "a group's page carries no Users sub-tab row: {main}"
    );
    let lede = element_containing(&main, r#"class="lede""#, "</p>");
    assert!(
        lede.contains(r#"href="/groups""#),
        "and keeps the way back to the list it is a row of: {lede}"
    );
    // The page still sits under the Users tab, which is what the row pointed at: the bar
    // lights it, so dropping the row costs the duplicate and not the way back.
    let tabs = elements(&html, r#"<nav class="tabs""#, "</nav>");
    assert_eq!(tabs.len(), 1, "the bar keeps its strip: {html}");
    assert!(
        tabs[0].contains(r#"<a class="pill on" href="/users" aria-current="page">"#),
        "and lights Users for this page: {tabs:?}"
    );

    // The three list pages keep their row, and the person page, the shape this page copies,
    // has never had one. Both asserted beside the fix so a repair removes the row from the
    // **detail** pages, and not from the pages that answer with it.
    for path in ["/users", "/groups", "/denied"] {
        let (status, html) = console_page("subs-keep-row", SUBS, path, "lang=en");
        assert_eq!(status, 200, "{path} is a page");
        let (_, links) = sub_tabs(&the_main(&html));
        assert_eq!(links.len(), 3, "{path} keeps its three sub-tabs: {html}");
    }
    let (status, html) = console_page(
        "person-no-subnav",
        GROUP_PAGE,
        &format!("/users/{BOB}"),
        "lang=en",
    );
    assert_eq!(status, 200, "a person is a page");
    assert!(
        elements(&the_main(&html), r#"<nav class="sub""#, "</nav>").is_empty(),
        "the person page, whose shape the group page copies, carries none: {html}"
    );
}

#[test]
fn the_group_pages_members_heading_is_the_sections_word() {
    // §13.36 §2 item 3, as the designer read the screenshots of plan step 22: the members
    // heading reads the Groups list's **column** word, because it borrowed `K::Members`.
    // Every other heading is the section's word in title case (the `Scopes` heading above
    // it), and in Italian a heading and a column label then differ by a capital alone, so
    // the page's second section reads as a table label. The heading is its own word; the
    // list's column keeps the lowercase one, because a column label is not a heading.
    for (lang, heading) in [
        ("lang=en", MEMBERS_HEADING_EN),
        ("lang=it", MEMBERS_HEADING_IT),
    ] {
        let (status, html) =
            console_page("group-members-heading", GROUP_PAGE, "/groups/admins", lang);
        assert_eq!(status, 200, "a group is a page of its own");
        let h2 = elements(&the_main(&html), "<h2", "</h2>");
        assert_eq!(h2.len(), 2, "the scopes section, then the members: {html}");
        assert_eq!(
            visible_text(&h2[1]),
            heading,
            "the members section is headed by the section's own word, in the reader's \
                 language: {:?}",
            h2.iter().map(|h| visible_text(h)).collect::<Vec<_>>()
        );
    }
    // The Groups list's column keeps the file's word: the fix is the heading's alone, and a
    // label that grew a capital mid-table reads as a heading.
    let (_, html) = console_page("groups-column-word", SUBS, "/groups", "lang=en");
    let head = elements(&the_main(&html), "<thead", "</thead>");
    assert_eq!(head.len(), 1, "the group list is a table: {html}");
    assert_eq!(
        visible_text(&elements(&head[0], "<th", "</th>")[1]),
        t(Lang::En, K::Members),
        "the members column is untouched by the new heading"
    );
}

#[test]
fn the_group_member_box_says_email_or_uuid() {
    // §13.36 §4's rule is that a box says what its list searches. The group page's member
    // box borrows the roster's sentence, and the roster earns that sentence because
    // `l_keeps_user` reads every email, the uuid **and** each key's id. The member list
    // filters a member's label and uuid, so the third thing this box promises is a search
    // that answers nothing, which is the failure mode §4 exists to close.
    for (lang, members, people) in [
        ("lang=en", FILTER_MEMBERS_EN, FILTER_PEOPLE_EN),
        ("lang=it", FILTER_MEMBERS_IT, FILTER_PEOPLE_IT),
    ] {
        let (status, html) = console_page("group-members-box", GROUP_PAGE, "/groups/admins", lang);
        assert_eq!(status, 200, "a group is a page of its own");
        let tag = field_tag(&the_main(&html), "mq");
        for name in ["placeholder", "aria-label"] {
            assert_eq!(
                attr(&tag, name).as_deref(),
                Some(members),
                "the box says what the member list searches, and the visible hint and the \
                     name are one string, which is what makes WCAG 2.5.3 Label in Name true by \
                     construction: {tag}"
            );
        }
        // The roster keeps the wider sentence, because the reach that earns it is its own.
        let (_, html) = console_page("roster-box-word", SUBS, "/users", lang);
        let roster = field_tag(&the_main(&html), "uq");
        assert_eq!(
            attr(&roster, "placeholder").as_deref(),
            Some(people),
            "the roster's box keeps the reach it has: {roster}"
        );
    }
}

#[test]
fn the_groups_list_is_a_table_of_counts() {
    // §13.36 §2: the list stops stacking a panel per group, which is what made the page
    // long. One row per group, and the members are a **count**: the list's job is "how many,
    // and where is this named", and the roll call is on the group's own page. This replaces
    // `the_group_panel_still_says_referenced_by_nothing_alone`, whose muted sentence moves
    // into the scopes cell, kindless as it was.
    let (status, html) = console_page("groups-table", SUBS, "/groups", "lang=en");
    assert_eq!(status, 200, "the group list is a page");
    let main = the_main(&html);
    let head = elements(&main, "<thead", "</thead>");
    assert_eq!(head.len(), 1, "the group list is a table: {main}");
    assert_eq!(
        elements(&head[0], "<th", "</th>")
            .iter()
            .map(|h| visible_text(h))
            .collect::<Vec<_>>(),
        ["name", t(Lang::En, K::Members), t(Lang::En, K::Scopes), "",],
        "the file's word for the first column, as the applications table heads its own"
    );
    let rows = elements(&the_tbody(&main, "the group list"), "<tr", "</tr>");
    assert_eq!(rows.len(), 2, "one row per group: {main}");

    let cells = row_cells(&rows[0]);
    assert_eq!(cells.len(), 4, "{cells:?}");
    assert!(
        cells[0].contains(r#"<a href="/groups/admins"><code>@admins</code></a>"#),
        "the name links the group's page: {cells:?}"
    );
    assert_eq!(
        visible_text(&cells[1]),
        "2",
        "the members are a count, not a list: {cells:?}"
    );
    assert!(
        cells[2].contains(r#"<a href="/apps/mpa"><code>mpa/admin</code></a>"#),
        "the scopes cell carries the same links as the group page: {cells:?}"
    );
    // The row's actions, and the inner `span` is not decoration: `td.pills` is a table cell
    // with no gap, and two pills standing straight in it touch (mockup, 1280).
    assert_eq!(
        attr(open_tag(&cells[3]), "class").as_deref(),
        Some("pills"),
        "{cells:?}"
    );
    assert!(cells[3].contains(r#"<span class="pills">"#), "{cells:?}");
    for href in ["/groups/admins/edit", "/groups/admins/rm"] {
        assert!(cells[3].contains(href), "the row offers {href}: {cells:?}");
    }

    let cells = row_cells(&rows[1]);
    assert!(
        cells[0].contains(r#"<a href="/groups/staff"><code>@staff</code></a>"#),
        "{cells:?}"
    );
    assert_eq!(
        visible_text(&cells[2]),
        t(Lang::En, K::ReferencedByNothing),
        "the sentence the panel used to carry, in its cell: {cells:?}"
    );
    assert!(cells[2].contains(r#"<span class="muted">"#), "{cells:?}");
    assert!(
        !cells[2].contains(KIND_GROUP),
        "the table's heading names the kind, so the cell names none: {cells:?}"
    );

    // A reference that keeps people out is told apart in the cell too, in words.
    let (_, html) = console_page("groups-table-out", GROUP_PAGE, "/groups", "lang=en");
    let rows = elements(
        &the_tbody(&the_main(&html), "the group list"),
        "<tr",
        "</tr>",
    );
    let row = rows
        .iter()
        .find(|r| r.contains("@outsiders"))
        .expect("a group named only as an exclusion is listed");
    let cell = &row_cells(row)[2];
    assert!(
        cell.contains(r#"<a href="/apps/mpa"><code>mpa/gate</code></a>"#),
        "{cell}"
    );
    assert!(
        cell.contains(r#"<span class="tag bad">excluded</span>"#),
        "the list says which reference is a keeping-out: {cell}"
    );
}

#[test]
fn the_roster_shows_each_persons_groups() {
    // §13.36 §3: the two lists link. A roster row says which groups name that person, so
    // "is bob an admin?" is answered on the page the operator already has open, and every
    // group link goes to the group's page, like every other `@name` and `app/scope` in the
    // console: a link that filtered here would be the one that behaved differently.
    let (status, html) = console_page("roster-groups", ROSTER_GROUPS, "/users", "lang=en");
    assert_eq!(status, 200, "the roster is a page");
    let main = the_main(&html);

    // The column sits between the addresses and the keys, so a phone reading the row as a
    // stack of labelled cells reads the same order the table shows.
    let head = elements(&main, "<thead", "</thead>");
    assert_eq!(
        elements(&head[0], "<th", "</th>")[..3]
            .iter()
            .map(|h| visible_text(h))
            .collect::<Vec<_>>(),
        [t(Lang::En, K::Emails), COL_GROUPS_EN, "api_keys",],
        "the new column is between the two it was put between: {main}"
    );

    let cells = row_cells(&row_with(&main, BOB_RM, "bob's row"));
    assert_eq!(
        attr(open_tag(&cells[1]), "data-label").as_deref(),
        Some(COL_GROUPS_EN),
        "a phone's stacked cell needs the column's word: {cells:?}"
    );
    assert!(
        cells[1].contains(r#"<a href="/groups/admins"><code>@admins</code></a>"#),
        "the group is a link to its page: {cells:?}"
    );
    assert!(!cells[1].contains('?'), "and not to a filter: {cells:?}");

    // Two groups, in the file's order and not the order they were written in: the fixture
    // spells `beta` before `alpha`, so a page that emitted insertion order reads beta.
    let cells = row_cells(&row_with(
        &main,
        "/users/11111111-1111-1111-1111-111111111111/rm",
        "the row in two groups",
    ));
    let alpha = cells[1]
        .find("/groups/alpha")
        .unwrap_or_else(|| panic!("alpha names this person: {cells:?}"));
    let beta = cells[1]
        .find("/groups/beta")
        .unwrap_or_else(|| panic!("beta names this person: {cells:?}"));
    assert!(
        alpha < beta,
        "the cell lists them in the file's order: {cells:?}"
    );
    assert!(!cells[1].contains('?'), "and both link the page: {cells:?}");

    // A person in no group is a word, not a blank: an empty cell reads as a page that
    // forgot to fill it in.
    let cells = row_cells(&row_with(
        &main,
        "/users/44444444-4444-4444-8444-444444444444/rm",
        "the row in no group",
    ));
    assert_eq!(
        visible_text(&cells[1]),
        t(Lang::En, K::None),
        "the empty state says none: {cells:?}"
    );
    assert!(cells[1].contains(r#"<span class="muted">"#), "{cells:?}");

    // Italian, which is where a new column's word has to be there as well.
    let (_, html) = console_page("roster-groups-it", ROSTER_GROUPS, "/users", "lang=it");
    let main = the_main(&html);
    let head = elements(&main, "<thead", "</thead>");
    assert_eq!(
        visible_text(&elements(&head[0], "<th", "</th>")[1]),
        COL_GROUPS_IT,
        "{main}"
    );
    let cells = row_cells(&row_with(&main, BOB_RM, "bob's row in Italian"));
    assert_eq!(
        attr(open_tag(&cells[1]), "data-label").as_deref(),
        Some(COL_GROUPS_IT),
        "{cells:?}"
    );
}

#[test]
fn the_roster_filters_by_group_exactly_and_with_the_text() {
    // §13.36 §3: `ug={name}` is the roster's group filter. **Exact** (`@staff` must not
    // carry `@staff-old`'s rows), **AND** with the text filter, and it says it is set in a
    // chip that clears it, so an operator who arrived from a group page knows which rows
    // they are looking at.
    let (status, html) = console_page("ug-exact", SUBS, "/users?ug=admins", "lang=en");
    assert_eq!(status, 200, "a group name is a filter, never a 404");
    let main = the_main(&html);
    for href in [BOB_RM, YOU_RM] {
        assert!(
            main.contains(href),
            "the members of `@admins` are the rows on the page: {main}"
        );
    }
    for href in [NOWHERE_RM, STAFF_RM] {
        assert!(!main.contains(href), "and nobody else is: {main}");
    }
    let chip = group_chip(&main);
    assert_eq!(
        visible_text(&chip),
        format!("{GROUP_FILTER_EN}@admins ×"),
        "one text node: {chip}"
    );
    assert_eq!(
        attr(open_tag(&chip), "title").as_deref(),
        Some(GROUP_FILTER_CLEAR_EN),
        "the pill says what it clears: {chip}"
    );

    // The text filter narrows the group rather than leaving it, and the chip's `×` clears
    // the group and keeps everything else, so the two filters answer one question.
    let (status, html) = console_page("ug-and-text", SUBS, "/users?ug=admins&uq=you", "lang=en");
    assert_eq!(status, 200);
    let main = the_main(&html);
    assert!(main.contains(YOU_RM), "{main}");
    assert!(!main.contains(BOB_RM), "the two filters are AND: {main}");
    let chip = group_chip(&main);
    let href = attr(open_tag(&chip), "href").expect("the chip is a link");
    assert!(
        !href.contains("ug=") && !href.contains("up="),
        "the × drops the group and its page: {href}"
    );
    assert!(
        href.contains("uq=you"),
        "and keeps the rest of the query, including the page the person is on: {href}"
    );
    // The form carries the group once, as a hidden field beside the chip, so one Apply
    // submits both and `ug` is not sent twice.
    let ctl = the_listctl(&main);
    assert_eq!(ctl.matches("name=\"ug\"").count(), 1, "exactly one: {ctl}");
    assert!(
        field_tag(&ctl, "ug").contains(r#"value="admins""#),
        "so a filter typed here stays in the group: {ctl}"
    );
    // No group list box: with many groups a box of all of them is the scrolling this step
    // is removing, and the group page and the roster's column are the two ways in.
    assert!(!ctl.contains("<select"), "no `select` of groups: {ctl}");

    // A name that is no group (the bookmark a removal leaves behind) matches nobody and says
    // so, chip included: the page exists, the filter is what is wrong.
    let (status, html) = console_page("ug-stale", SUBS, "/users?ug=staf", "lang=en");
    assert_eq!(status, 200, "a stale group name is not a 404");
    let main = the_main(&html);
    assert!(main.contains(t(Lang::En, K::NoMatch)), "{main}");
    assert_eq!(
        visible_text(&group_chip(&main)),
        format!("{GROUP_FILTER_EN}@staf ×"),
        "the chip still names what to clear: {main}"
    );
    for href in [BOB_RM, YOU_RM, NOWHERE_RM, STAFF_RM] {
        assert!(
            !main.contains(href),
            "`@staf` is not `@staff`, so an exact name matches nobody: {main}"
        );
    }

    // Italian.
    let (_, html) = console_page("ug-it", SUBS, "/users?ug=admins", "lang=it");
    let main = the_main(&html);
    assert_eq!(
        visible_text(&group_chip(&main)),
        format!("{GROUP_FILTER_IT}@admins ×"),
        "the chip in the reader's language"
    );
    assert_eq!(
        attr(open_tag(&group_chip(&main)), "title").as_deref(),
        Some(GROUP_FILTER_CLEAR_IT),
        "and the pill's name for what it clears is translated too: {main}"
    );
}

#[test]
fn the_apps_list_says_which_credentials_get_in() {
    let html = render("appcreds", Route::Apps);
    // mpa/admin is restricted with no `credentials` field, which means BOTH — the one
    // default a reader can get wrong, so the column spells it out.
    assert!(html.contains("login, api_key"), "{html}");
}

#[test]
fn a_scope_shows_its_credentials_and_its_exclusions() {
    let fixture = SAMPLE.replace(
        r#""groups": ["@admins"], "notes": "the admin area""#,
        r#""groups": ["@admins"], "excluded": ["nowhere@x.com"], "notes": "the admin area""#,
    );
    let html = render_of("scopeblock", &fixture, Route::App("mpa".into()), "");
    assert!(html.contains("excluded"), "{html}");
    assert!(html.contains("nowhere@x.com"), "{html}");
    assert!(html.contains("login, api_key"), "{html}");
}

#[test]
fn denied_page_shows_a_stranger_by_email() {
    let html = render("denied", Route::Denied);
    assert!(html.contains("spammer@x.com"));
}

#[test]
fn hostile_values_from_the_file_come_out_escaped() {
    // The access file is operator-owned, but it is also a text file that anything with
    // root can write, and half of it ends up in a page. maud escapes on the way in;
    // this pins that it stays that way.
    let json = r#"{ "version": 1, "users": [
            { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b",
              "emails": ["<script>alert(1)</script>@x.com"], "notes": "<b>bold</b>" } ] }"#;
    let path = scratch("xss", json);
    let cfg = cfg_for(&path, "");
    let (doc, access) = open_access_file(&cfg.access_path).unwrap();
    let v = view(&cfg, Route::Users, "REV");
    for html in [
        shell(&v, "t", page_users(&v, &doc, &access)).into_string(),
        shell(&v, "t", page_user(&v, &doc, &access, BOB).1).into_string(),
    ] {
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;@x.com"),
            "{html}"
        );
        assert!(!html.contains("<script>alert(1)"), "{html}");
        assert!(!html.contains("<b>bold</b>"), "{html}");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_broken_file_renders_the_librarys_message_verbatim() {
    let path = scratch(
        "broken",
        r#"{ "version": 1, "applications": [
                { "name": "a", "base": ["https://x.com/a"], "scopes": [
                    { "name": "s", "urls": ["https://x.com/a/*"], "access": "restricted",
                      "groups": ["@nope"] } ] } ] }"#,
    );
    let cfg = cfg_for(&path, "");
    // `Access` has no `Debug` on purpose (a table of live credentials), so no unwrap_err.
    let err = match open_access_file(&cfg.access_path) {
        Ok(_) => panic!("a dangling @group reference must be refused"),
        Err(e) => e,
    };
    let v = view(&cfg, Route::Dashboard, "REV");
    let html = page_file_error(&v, &err).into_string();
    assert!(
        html.contains("the gate would reject this file as it stands"),
        "{html}"
    );
    assert!(html.contains("unknown user group"), "{html}");
    let _ = std::fs::remove_file(&path);
}
