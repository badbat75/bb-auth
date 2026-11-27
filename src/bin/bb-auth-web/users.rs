use crate::*;

/// The users tab's row of sub-tabs: People, Groups, Denied (§13.36 §1).
///
/// Three pages under one tab, because all three answer the same question from different
/// sides, and the tab's five-slot bar has no room for three more tabs. The row is a
/// navigation landmark of its own beside the bar's tabs and the account end, so it is named
/// (`K::UsersSections`): the practice asks that more than one landmark of a kind be named.
/// Each link carries the section's short word and its **whole file** count, never the
/// filtered one, so the row does not move under the operator's hands while they type. The
/// Groups and Denied links carry the `id`s the old `/users#user_groups` and `/users#denied`
/// bookmarks named, so a note an operator wrote years ago scrolls to the link that means it.
fn users_subnav(v: &View, doc: &AccessFile) -> Markup {
    /// One pill: the current one marked the bar's way, in the markup and not only to a
    /// reader, because `.on` is a colour, and colour alone is not a distinction WCAG 1.3.1
    /// accepts. The row lights the page a route was reached *from* (`parent()`), which is the
    /// bar's own rule one level down: a group's form lights Groups, a veto's form lights
    /// Denied, and the roster's pages, including a person's, light People.
    fn pill(v: &View, at: &Route, label: &str, id: Option<&'static str>, n: usize) -> Markup {
        let on = v.at.parent() == *at;
        html! {
            a class=(if on { "pill on" } else { "pill" }) href=(v.href(at)) id=[id]
              aria-current=[on.then_some("page")]
              { (label) " (" (n) ")" }
        }
    }
    html! {
        nav class="sub" aria-label=(v.t(K::UsersSections)) {
            (pill(v, &Route::Users, v.t(K::People), None, doc.users.len()))
            (pill(
                v,
                &Route::Groups,
                v.t(K::GroupsTab),
                Some("user_groups"),
                doc.user_groups.len(),
            ))
            (pill(
                v,
                &Route::Denied,
                v.t(K::Denied),
                Some("denied"),
                doc.denied.len(),
            ))
        }
    }
}

/// `/users`: the roster, the users tab's People sub-page (§13.36 §1).
///
/// It used to be one stacked page of three sections, and a long file opened on the list the
/// operator did not come for. The shared `h1` is the tab's word, so the page says which tab
/// it is under, and the `h2` is the sub-tab's, so the link a person followed and the heading
/// they landed on are the same word. The filter and the pager are namespaced (`u`), as on
/// the other two pages, because all three lists live in one query string.
///
/// A row carries the **groups naming it**, as links to each group's page (§13.36 §5): the
/// file writes membership on the side of the group, and a roster that shows only emails asks
/// "which of these is an administrator?" with no way to answer. Beside the box, the
/// `?ug=` chip answers "who is in this group?" from the other side, on the group's page.
pub(crate) fn page_users(v: &View, doc: &AccessFile, access: &Access) -> Markup {
    let mut lu = Listing::read("u", v.query);
    // The group filter: `ug` names one `user_groups` entry **exactly** (a group name is a
    // `[A-Za-z0-9_-]` word, so a substring test on a name would invent matches), and it is
    // ANDed with the box rather than replacing it. A name the file has not got narrows to
    // nobody, which is what the panel's `no matches for this filter` says; the page is not an
    // error, because the chip is a link and links rot.
    let group = query_param(v.query, "ug").unwrap_or_default();
    let group = group.trim().to_string();
    let members = doc
        .user_groups
        .get(&group)
        .map(|ms| ms.iter().map(|m| m.trim().to_ascii_lowercase()).collect())
        .or_else(|| (!group.is_empty()).then(Vec::new));
    lu.filtered = !group.is_empty();
    let rows: Vec<&UserSpec> = doc
        .users
        .iter()
        .filter(|u| l_keeps_user(&lu, u))
        .filter(|u| {
            members
                .as_ref()
                .is_none_or(|ms| ms.iter().any(|m| *m == u.uuid.trim().to_ascii_lowercase()))
        })
        .collect();
    let (start, end, _, _) = lu.window(rows.len());
    // The membership map, built **once per request** (§13.36 §3): walking the groups per row
    // would read the whole section once per row of the page. The names come out in the file's
    // order, which for a `BTreeMap` is alphabetical.
    let mut by_uuid: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (name, ms) in &doc.user_groups {
        for m in ms {
            by_uuid
                .entry(m.trim().to_ascii_lowercase())
                .or_default()
                .push(name.clone());
        }
    }
    // The chip: what the list is narrowed to, and the one control that clears it. It rides in
    // the same form as the box, so Apply keeps the group with the text, and the group is
    // `owned` so the form carries it once.
    let chip = if group.is_empty() {
        html! {}
    } else {
        html! {
            input type="hidden" name="ug" value=(group);
            a class="pill" href=(clear_group_href(v, &lu)) title=(v.t(K::GroupFilterClear)) {
                (fill(v.t(K::GroupFilter), &[format!("@{group}").as_str()])) " ×"
            }
        }
    };
    html! {
        h1 { (v.t(K::Users)) }
        (users_subnav(v, doc))

        h2 { (section_heading(v.t(K::People), "users")) }
        p class="lede sub" { (v.t(K::UsersIntro)) }
        p class="primary" { (act(v, &Route::UserAdd, &format!("+ {}", v.t(K::Add)))) }
        (list_controls_with(
            v,
            &lu,
            rows.len(),
            doc.users.len(),
            &["ug"],
            chip,
            K::FilterPeople,
        ))
        (list_panel(v, doc.users.len(), rows.len(), html! {
                table {
                    thead { tr {
                        th { (v.t(K::Emails)) }
                        th { (v.t(K::ColGroups)) }
                        th { "api_keys" }
                        th {}
                    } }
                    tbody {
                        @for u in &rows[start..end] {
                            @let uuid = u.uuid.trim().to_ascii_lowercase();
                            @let groups = by_uuid.get(&uuid).cloned().unwrap_or_default();
                            tr {
                                td data-label=(v.t(K::Emails)) {
                                    a href=(v.href(&Route::User(uuid.clone()))) { (user_label(u)) }
                                    @if access.denied_users.contains(&uuid) {
                                        " " (tag("bad", "denied"))
                                    }
                                }
                                td data-label=(v.t(K::ColGroups)) {
                                    @if groups.is_empty() {
                                        span class="muted" { (v.t(K::None)) }
                                    } @else {
                                        @for (at, g) in groups.iter().enumerate() {
                                            @if at > 0 { ", " }
                                            a href=(v.href(&Route::Group(g.clone()))) {
                                                code { "@" (g) }
                                            }
                                        }
                                    }
                                }
                                td data-label="api_keys" { (u.api_keys.len()) }
                                td class="pills" {
                                    (act_rm(v, &Route::UserRm(uuid.clone()), v.t(K::Remove)))
                                }
                            }
                        }
                    }
                }
        }))

    }
}

/// The roster's own URL with the **group** filter dropped and everything else kept, the
/// chip's href (§13.36 §5). [`listing_href`] cannot answer this one: it clears the box and
/// the page of its own list, and a chip that clears the text the operator typed would be a
/// control that destroys a filter nobody asked it to destroy.
fn clear_group_href(v: &View, l: &Listing) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, val) in form_urlencoded::parse(v.query.as_bytes()) {
        if k != "ug" && k != l.p_name() {
            ser.append_pair(&k, &val);
        }
    }
    let q = ser.finish();
    if q.is_empty() {
        v.href(&v.at)
    } else {
        format!("{}?{q}", v.href(&v.at))
    }
}

/// A roster row's searchable text: every identifier, the uuid, and each key's id — all of
/// what identifies the person, not just the label the table happens to show.
fn l_keeps_user(l: &Listing, u: &UserSpec) -> bool {
    let mut hay = u.uuid.trim().to_string();
    for e in &u.emails {
        hay.push(' ');
        hay.push_str(e.trim());
    }
    for k in &u.api_keys {
        hay.push(' ');
        hay.push_str(k.id.trim());
    }
    l.keeps(&hay)
}

/// `/users/{uuid}` — one roster row, as the file stores it, plus the scopes computed from
/// [`Access::scopes_for`]: membership only, so a user reached by an `anonymous` or
/// `authenticated` scope is not listed here even though they get in — that is a property of
/// the scope, not of them.
pub(crate) fn page_user(v: &View, doc: &AccessFile, access: &Access, key: &str) -> (u16, Markup) {
    let u: &UserSpec = match user_pos(doc, key).map(|i| &doc.users[i]) {
        Some(u) => u,
        None => return (404, page_missing(v, v.t(K::NoSuchUser), key, &Route::Users)),
    };
    let n = now();
    let uuid = u.uuid.trim().to_ascii_lowercase();
    let denied = access.denied_users.contains(&uuid);
    let notes = u.extra.get("notes").and_then(|n| n.as_str());
    let scopes = access.scopes_for(&uuid);

    (
        200,
        html! {
            h1 {
                (user_label(u))
                @if denied { " " (tag("bad", "denied")) }
            }
            p class="lede" { (back(v, &Route::Users)) }
            p class="pills" {
                (act_rm(v, &Route::UserRm(uuid.clone()), v.t(K::Remove)))
            }

            @if let Some(notes) = notes {
                div class="panel" { span class="muted mono" { "notes " } (notes) }
            }

            h2 { (v.t(K::Uuid)) }
            div class="panel" { span class="mono" { (uuid) } }

            h2 { (v.t(K::Emails)) }
            p class="primary" {
                (act(v, &Route::EmailAdd(uuid.clone()), &format!("+ {}", v.t(K::AddEmail))))
            }
            div class="panel" {
                ul class="plain" {
                    @for e in &u.emails {
                        @let email = norm_email(e);
                        li class="pills" {
                            code { (email) }
                            (act_rm(v, &Route::EmailRm(uuid.clone(), email.clone()), v.t(K::Remove)))
                        }
                    }
                }
            }

            h2 { (section_heading(v.t(K::Scopes), "scopes")) }
            div class="panel" {
                @if scopes.is_empty() {
                    span class="bad" { (v.t(K::InNoScope)) }
                } @else {
                    ul class="plain" {
                        @for (a, s) in &scopes {
                            li {
                                a href=(v.href(&Route::App(a.name.clone()))) {
                                    code { (a.name) "/" (s.name) }
                                }
                            }
                        }
                    }
                }
            }

            (user_check(v, access, u, &uuid))

            h2 { "api_keys" }
            p class="primary" { (act(v, &Route::KeyAdd(uuid.clone()), &format!("+ {}", v.t(K::Add)))) }
            div class="panel" {
                @if u.api_keys.is_empty() {
                    span class="muted" { (v.t(K::None)) }
                } @else {
                    table {
                        thead { tr {
                            th { "id" }
                            th { "released" }
                            th { "duration" }
                            th { (v.t(K::ColExpiry)) }
                            th { (v.t(K::Scopes)) }
                            th {}
                        } }
                        tbody {
                            @for k in &u.api_keys {
                                @let id = k.id.trim().to_string();
                                tr {
                                    td class="mono" data-label="id" { (id) }
                                    td class="mono" data-label="released" { (k.released.trim()) }
                                    td class="mono" data-label="duration" { (k.duration.trim()) }
                                    td data-label=(v.t(K::ColExpiry)) {
                                        (expiry_markup(v.lang, &expiry_of(k, n)))
                                    }
                                    td data-label=(v.t(K::Scopes)) {
                                        (url_list(v.lang, k.scopes.as_ref(), t(v.lang, K::KeyScopeInherit)))
                                    }
                                    td class="pills" {
                                        (act(v, &Route::KeyEdit(uuid.clone(), id.clone()),
                                             v.t(K::Edit)))
                                        (act(v, &Route::KeyRotate(uuid.clone(), id.clone()),
                                             v.t(K::Rotate)))
                                        (act_rm(v, &Route::KeyRm(uuid.clone(), id.clone()),
                                             v.t(K::Remove)))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// `/groups`: the `user_groups` list, the users tab's Groups sub-page (§13.36 §1).
///
/// **A table, one row per group** (§13.36 §3). The list used to be one panel per group, which
/// put a name, a count and a reference list into prose a row at a time and said nothing about
/// how big each group is; a column answers "how big is each?" at a glance, and the names are
/// links to the page each one is about (§13.36 §2). The filter keeps the old reach (`@name`
/// and each member's label), because "which group is bob in?" is still the question this list
/// is opened to answer.
pub(crate) fn page_groups(v: &View, doc: &AccessFile) -> Markup {
    let l = Listing::read("g", v.query);
    let rows: Vec<(&String, &Vec<String>)> = doc
        .user_groups
        .iter()
        .filter(|(name, members)| {
            let people: Vec<String> = members.iter().map(|m| label_of(doc, m)).collect();
            l.keeps(&format!("@{name} {}", people.join(" ")))
        })
        .collect();
    let (start, end, _, _) = l.window(rows.len());
    html! {
        h1 { (v.t(K::Users)) }
        (users_subnav(v, doc))

        // §13.36 §1 item 3: the section's heading spells the name out (`User groups`), which is
        // why the sub-tab above is `K::GroupsTab` and not this: the row must fit a phone.
        h2 { (section_heading(v.t(K::Groups), "user_groups")) }
        p class="lede sub" { (v.t(K::GroupsIntro)) }
        p class="primary" { (act(v, &Route::GroupAdd, &format!("+ {}", v.t(K::Add)))) }
        (list_controls(v, &l, rows.len(), doc.user_groups.len()))
        (list_panel(v, doc.user_groups.len(), rows.len(), html! {
            table {
                thead { tr {
                    // `name` is the file's word, as the applications table heads its first
                    // column with it: the group's name is a key of the document, not a label.
                    th { "name" }
                    th { (v.t(K::Members)) }
                    th { (v.t(K::Scopes)) }
                    th {}
                } }
                tbody {
                    @for (name, members) in &rows[start..end] {
                        @let refs = user_group_refs(doc, name);
                        tr {
                            td data-label="name" {
                                a href=(v.href(&Route::Group((*name).clone()))) {
                                    code { "@" (name) }
                                }
                            }
                            td data-label=(v.t(K::Members)) { (members.len()) }
                            td data-label=(v.t(K::Scopes)) {
                                @if refs.is_empty() {
                                    span class="muted" { (v.t(K::ReferencedByNothing)) }
                                } @else {
                                    @for r in refs.iter() {
                                        (scope_ref_link(v, r)) " "
                                    }
                                }
                            }
                            td class="pills" {
                                // The inner `span` is not decoration: `td.pills` is a table
                                // cell with no gap, and two pills straight in it touch.
                                span class="pills" {
                                    (act(v, &Route::GroupEdit((*name).clone()), v.t(K::Edit)))
                                    (act_rm(v, &Route::GroupRm((*name).clone()), v.t(K::Remove)))
                                }
                            }
                        }
                    }
                }
            }
        }))
    }
}

/// One entry of [`user_group_refs`] as a page shows it: the scope as a link to the application
/// that owns it (a scope has no page of its own, and an application lists its scopes), and a
/// scope that keeps the group **out** carrying the file's own word beside the link.
///
/// The words come from [`EXCLUDED_REF`], which is what `user_group_refs` appends, so this page
/// and the removal's refusal cannot disagree about which references they are listing; and they
/// are words and not a colour, so a reader who does not see colour hears them (WCAG 1.4.1).
fn scope_ref_link(v: &View, entry: &str) -> Markup {
    let marker = format!(" ({EXCLUDED_REF})");
    let (at, excluded) = match entry.strip_suffix(marker.as_str()) {
        Some(rest) => (rest, true),
        None => (entry, false),
    };
    let app = at.split('/').next().unwrap_or_default().trim().to_string();
    html! {
        a href=(v.href(&Route::App(app))) { code { (at.trim()) } }
        @if excluded {
            " " (tag("bad", EXCLUDED_REF))
        }
    }
}

/// `/groups/{name}`: one `user_groups` entry (§13.36 §2).
///
/// Scopes come **before** members: the scopes are why the group matters, and this is the page
/// the dashboard's "referenced by nothing" warning links to, so its answer is the first thing
/// under the head. The two writes are the **existing** forms, reached from here; only where
/// they return changed (§1).
pub(crate) fn page_group(v: &View, doc: &AccessFile, name: &str) -> (u16, Markup) {
    let Some(members) = doc.user_groups.get(name.trim()) else {
        return (
            404,
            page_missing(v, v.t(K::NoSuchGroup), name.trim(), &Route::Groups),
        );
    };
    let refs = user_group_refs(doc, name.trim());
    // The members behind a `Listing` of their own prefix, so a group of a thousand people is a
    // page and not a scroll, and the scopes panel above has no control row of its own.
    let lm = Listing::read("m", v.query);
    let shown: Vec<&String> = members
        .iter()
        .filter(|m| lm.keeps(&format!("{} {}", m.trim(), label_of(doc, m))))
        .collect();
    let (start, end, _, _) = lm.window(shown.len());
    (
        200,
        html! {
            h1 {
                code { "@" (name.trim()) }
                " "
                span class="muted mono" { "user_groups" }
            }
            // No Users sub-tab row (§13.36 §2, as the screenshot review of plan step 22 read
            // it): this is the person page's shape, and that page has none. The row's job is to
            // say which of the three lists is showing, and on a page about one object the `h1`
            // has already said it, while the row pushes the page's answer, the scopes that name
            // the group, down the screen. The bar above still lights the Users tab, and the
            // back link below is the one thing here naming the list this page is a row of.
            p class="lede" { (back(v, &Route::Groups)) }
            p class="pills" {
                (act(v, &Route::GroupEdit(name.trim().to_string()), v.t(K::Edit)))
                (act_rm(v, &Route::GroupRm(name.trim().to_string()), v.t(K::Remove)))
            }

            h2 { (section_heading(v.t(K::Scopes), "scopes")) }
            div class="panel" {
                @if refs.is_empty() {
                    span class="muted" { (v.t(K::ReferencedByNothing)) }
                } @else {
                    ul class="plain" {
                        @for r in refs.iter() {
                            li { (scope_ref_link(v, r)) }
                        }
                    }
                }
            }

            // The section's word, in title case like the `Scopes` heading above it, and not the
            // Groups list's lowercase column word `K::Members` this heading used to borrow: a
            // heading that reads as a table label is the screenshot review's finding (§13.36 §2
            // item 3). The list's column keeps the lowercase word, because a column label is
            // not a heading.
            h2 { (v.t(K::MembersHeading)) }
            p class="primary" {
                a class="pill" href=(format!("{}?ug={}", v.href(&Route::Users), name.trim())) {
                    (v.t(K::GroupInRoster))
                }
            }
            // The box says what *this* list searches, a member's label and uuid, and not the
            // roster's wider reach (§13.36 §4): a key id is not in this list to find.
            (list_controls_named(v, &lm, shown.len(), members.len(), K::FilterMembers))
            (list_panel(v, members.len(), shown.len(), html! {
                ul class="plain" {
                    @for m in &shown[start..end] {
                        @let uuid = m.trim().to_ascii_lowercase();
                        li {
                            @match user_pos(doc, &uuid) {
                                Some(i) => {
                                    a href=(v.href(&Route::User(uuid.clone()))) {
                                        (user_label(&doc.users[i]))
                                    }
                                }
                                None => {
                                    code class="bad" { (uuid) }
                                    " " (tag("bad", v.t(K::UnknownMember)))
                                }
                            }
                        }
                    }
                }
            }))
        },
    )
}

/// `/denied`: the veto, the users tab's Denied sub-page (§13.36 §1), and the page the
/// add/remove PRG redirects land on, which is why it has always had its own URL.
///
/// It shares the `h1` and the sub-tab row with the other two, so the page says which tab it
/// is under; the heading it used to carry as an `h1` is now its `h2`, where the sub-tab's
/// word and the heading it lands on are the same word.
pub(crate) fn page_denied(v: &View, doc: &AccessFile) -> Markup {
    html! {
        h1 { (v.t(K::Users)) }
        (users_subnav(v, doc))

        h2 { (section_heading(v.t(K::Denied), "denied")) }
        p class="lede sub" { (v.t(K::DeniedIntro)) }
        p class="primary" { (act(v, &Route::DenyAdd, &format!("+ {}", v.t(K::Add)))) }
        (denied_list(v, doc))
    }
}

/// The `denied` list: the empty state, or the list itself, one row per vetoed entry; a uuid
/// names the user it vetoes, a bare email names a stranger.
fn denied_list(v: &View, doc: &AccessFile) -> Markup {
    let l = Listing::read("d", v.query);
    // Filtered on what the row *shows*, which for an enrolled user is their label rather
    // than the uuid the file stores: searching for the email you can see must work.
    let rows: Vec<&String> = doc
        .denied
        .iter()
        .filter(|d| {
            let raw = d.trim().to_ascii_lowercase();
            l.keeps(&format!("{raw} {}", label_of(doc, &raw)))
        })
        .collect();
    let (start, end, _, _) = l.window(rows.len());
    html! {
        (list_controls(v, &l, rows.len(), doc.denied.len()))
        (list_panel(v, doc.denied.len(), rows.len(), html! {
                ul class="plain" {
                    @for d in &rows[start..end] {
                        @let raw = d.trim().to_ascii_lowercase();
                        li class="pills" {
                            @match user_pos(doc, &raw) {
                                Some(i) => {
                                    @let u = &doc.users[i];
                                    a href=(v.href(&Route::User(u.uuid.trim().to_ascii_lowercase()))) {
                                        code { (user_label(u)) }
                                    }
                                }
                                None => { code { (norm_email(&raw)) } }
                            }
                            (act_rm(v, &Route::DenyRm(raw.clone()), v.t(K::Remove)))
                        }
                    }
                }
        }))
    }
}
