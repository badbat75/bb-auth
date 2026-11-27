use crate::*;

/// `/apps` — the applications, with their base, their scope count, and which credential
/// classes get in anywhere inside them ([`app_credentials`]).
pub(crate) fn page_apps(v: &View, doc: &AccessFile) -> Markup {
    let l = Listing::read("a", v.query);
    // Filtered on everything the row shows, so what an operator reads is what they can
    // search: the name, the area, and the credentials column.
    let rows: Vec<&AppSpec> = doc
        .applications
        .iter()
        .filter(|a| {
            let creds = match app_credentials(a) {
                None => "anonymous".to_string(),
                Some(list) => list.join(" "),
            };
            l.keeps(&format!("{} {} {creds}", a.name.trim(), a.base.join(" ")))
        })
        .collect();
    let (start, end, _, _) = l.window(rows.len());
    html! {
        h1 { (section_heading(v.t(K::Apps), "applications")) }
        p class="lede" { (v.t(K::AppsIntro)) }
        p class="primary" { (act(v, &Route::AppAdd, &format!("+ {}", v.t(K::Add)))) }
        (list_controls(v, &l, rows.len(), doc.applications.len()))
        (list_panel(v, doc.applications.len(), rows.len(), html! {
                table {
                    thead { tr {
                        th { "name" }
                        th { (v.t(K::Base)) }
                        th { (v.t(K::Scopes)) }
                        th { (v.t(K::Credentials)) }
                        th {}
                    } }
                    tbody {
                        @for a in &rows[start..end] {
                            tr {
                                td data-label="name" {
                                    a href=(v.href(&Route::App(a.name.trim().to_string()))) {
                                        code { (a.name.trim()) }
                                    }
                                }
                                td data-label=(v.t(K::Base)) { (url_list(v.lang, Some(&a.base), "")) }
                                td data-label=(v.t(K::Scopes)) { (a.scopes.len()) }
                                td data-label=(v.t(K::Credentials)) {
                                    @match app_credentials(a) {
                                        None => (tag("warn", v.t(K::CredNoneNeeded))),
                                        Some(list) if list.is_empty() => {
                                            span class="muted" { (v.t(K::None)) }
                                        }
                                        Some(list) => code { (list.join(", ")) }
                                    }
                                }
                                td class="pills" {
                                    (act_rm(v, &Route::AppRm(a.name.trim().to_string()), v.t(K::Remove)))
                                }
                            }
                        }
                    }
                }
        }))
    }
}

/// `/apps/{app}` — one application: its base, its login page, its scopes **in file
/// order**, the number carrying the meaning first-match-wins gives it, and the access check
/// over the area they divide up.
///
/// The check is last because it is the conclusion of the list above it: it names the scope
/// that answered, which is one of the numbered ones, so what the page shows and what the gate
/// decides can be read against each other without leaving the page. That is also why this
/// page needs the compiled [`Access`] and not only the document.
pub(crate) fn page_app(v: &View, doc: &AccessFile, access: &Access, name: &str) -> (u16, Markup) {
    let a = match app_pos(doc, name).map(|i| &doc.applications[i]) {
        Some(a) => a,
        None => return (404, page_missing(v, v.t(K::NoSuchApp), name, &Route::Apps)),
    };
    let last = a.scopes.len().saturating_sub(1);
    let app_name = a.name.trim().to_string();
    (
        200,
        html! {
            h1 { (app_name) }
            p class="lede" { (back(v, &Route::Apps)) }
            p class="pills" {
                (act(v, &Route::AppEdit(app_name.clone()), v.t(K::Edit)))
                (act_rm(v, &Route::AppRm(app_name.clone()), v.t(K::Remove)))
            }

            @if let Some(notes) = &a.notes {
                div class="panel" { span class="muted mono" { "notes " } (notes) }
            }

            h2 { (v.t(K::Base)) }
            div class="panel" { (url_list(v.lang, Some(&a.base), "")) }
            @if let Some(l) = &a.login_url {
                p class="muted" { (v.t(K::LoginUrl)) " " span class="mono" { (l) } }
            }

            h2 { (section_heading(v.t(K::Scopes), "scopes")) }
            p class="lede sub" { (v.t(K::ScopesIntro)) }
            p class="primary" {
                (act(v, &Route::ScopeAdd(app_name.clone()), &format!("+ {}", v.t(K::Add))))
            }
            div class="panel" {
                @if a.scopes.is_empty() {
                    span class="muted" { (v.t(K::NoScopes)) }
                } @else {
                    ol class="scopes" {
                        @for (i, s) in a.scopes.iter().enumerate() {
                            li { (scope_block(v, doc, &app_name, s, i, last)) }
                        }
                    }
                }
            }

            (app_check(v, access, a))
        },
    )
}

/// One `POST` button that moves a scope one place inside its application. Order is meaning
/// — `AppRecord::scopes` is first-match-wins — so this is a mutation like any other: same
/// `rev`, same audit line, and a `303` back to this page. It is a button and not a link
/// because a `GET` never mutates, and it is per row because two buttons beat a position
/// field an operator has to count out.
fn move_button(
    v: &View,
    app: &str,
    scope: &str,
    dir: &str,
    label: &str,
    glyph: &str,
    disabled: bool,
) -> Markup {
    html! {
        form method="post" action=(v.href(&Route::ScopeMove(app.to_string(), scope.to_string()))) {
            input type="hidden" name="rev" value=(v.rev);
            input type="hidden" name="dir" value=(dir);
            button type="submit" class="pill" title=(label) disabled[disabled] { (glyph) }
        }
    }
}

/// One scope, as one item of the ordered list [`page_app`] renders: its access kind, its
/// urls, its members (people, resolved where the roster still can) and its move buttons.
fn scope_block(
    v: &View,
    doc: &AccessFile,
    app: &str,
    s: &ScopeSpec,
    i: usize,
    last: usize,
) -> Markup {
    let name = s.name.trim().to_string();
    let access = s.access.trim();
    let access_label = match access {
        "anonymous" => v.t(K::AccessAnonymous),
        "authenticated" => v.t(K::AccessAuthenticated),
        "restricted" => v.t(K::AccessRestricted),
        other => other,
    };
    html! {
        div {
            strong { (name) }
            " "
            (tag(if access == "restricted" { "" } else { "warn" }, access_label))
            " "
            span class="pills" {
                (act(v, &Route::ScopeEdit(app.to_string(), name.clone()), v.t(K::Edit)))
                (act_rm(v, &Route::ScopeRm(app.to_string(), name.clone()), v.t(K::Remove)))
                (move_button(v, app, &name, "up", v.t(K::MoveUp), "↑", i == 0))
                (move_button(v, app, &name, "down", v.t(K::MoveDown), "↓", i >= last))
            }
        }
        @if s.urls.is_empty() {
            div class="bad" { "urls: [] — " (v.t(K::ReachesNothing)) }
        } @else {
            ul class="plain mono" { @for u in &s.urls { li { (u) } } }
        }
        @match access {
            "anonymous" => div class="muted" { (v.t(K::AnonymousWarn)) },
            "authenticated" => div class="muted" { (v.t(K::AuthenticatedWarn)) },
            "restricted" => {
                @let members = scope_members_display(doc, s);
                div class="muted" {
                    (v.t(K::Members)) ": "
                    @if members.is_empty() {
                        span class="bad" { (v.t(K::WarnNoMembers)) }
                    } @else {
                        @for (i, m) in members.iter().enumerate() {
                            @if i > 0 { ", " }
                            code { (m) }
                        }
                    }
                }
            }
            _ => {}
        }
        // Credentials, and the exclusions, on every kind rather than only where the file
        // carries a field. An absent `credentials` means BOTH, which is the one default in
        // this format an operator can misread as "none", and `anonymous`/`authenticated`
        // have an answer too even though they have no field: this line says what actually
        // gets in, which is what the question is.
        div class="muted" {
            (v.t(K::Credentials)) ": "
            @match scope_credentials(s) {
                None => span class="mono" { (v.t(K::CredNoneNeeded)) },
                Some(list) => code { (list.join(", ")) }
            }
        }
        @if access != "anonymous" {
            @let excluded = scope_excluded_display(doc, s);
            div class="muted" {
                (v.t(K::Excluded)) ": "
                @if excluded.is_empty() {
                    span { (v.t(K::ExcludedNone)) }
                } @else {
                    @for (i, e) in excluded.iter().enumerate() {
                        @if i > 0 { ", " }
                        code class="bad" { (e) }
                    }
                }
            }
        }
    }
}

/// Which credential classes actually get into this scope, as the file's own words.
///
/// `None` is not "nothing": it is an `anonymous` scope, which needs no credential at all.
/// `authenticated` is `login` alone, because Cognito vouches for no static key of ours, and
/// `restricted` with no `credentials` field is **both** — the default this exists to spell
/// out, since an absent field is exactly where a reader guesses wrong.
fn scope_credentials(s: &ScopeSpec) -> Option<Vec<&'static str>> {
    match s.access.trim() {
        "anonymous" => None,
        "authenticated" => Some(vec!["login"]),
        _ => match &s.credentials {
            None => Some(vec!["login", "api_key"]),
            Some(list) => {
                let mut out = Vec::new();
                if list.iter().any(|c| c.trim() == "login") {
                    out.push("login");
                }
                if list.iter().any(|c| c.trim() == "api_key") {
                    out.push("api_key");
                }
                Some(out)
            }
        },
    }
}

/// Every credential class that gets in **anywhere** in this application: the union of
/// [`scope_credentials`] over its scopes, for the one column [`page_apps`] has room for.
///
/// A `None` from any scope (an `anonymous` one) makes the whole application answerable
/// without a credential, and that outranks the rest of the union: it is the thing an
/// operator scanning the list most needs to see.
fn app_credentials(a: &AppSpec) -> Option<Vec<&'static str>> {
    let (mut login, mut api_key) = (false, false);
    for s in &a.scopes {
        let list = scope_credentials(s)?;
        login |= list.contains(&"login");
        api_key |= list.contains(&"api_key");
    }
    // Built in a fixed order rather than sorted, so the column reads the same way the scope
    // below it does and the two can be compared at a glance.
    let mut out = Vec::new();
    if login {
        out.push("login");
    }
    if api_key {
        out.push("api_key");
    }
    Some(out)
}

/// A scope's `users` (resolved to a label where the roster still can) and `groups` (`@name`,
/// shown exactly as the file spells it), for display only. See [`parse_members`] for the
/// inverse, on submit.
pub(crate) fn scope_members_display(doc: &AccessFile, s: &ScopeSpec) -> Vec<String> {
    let mut out: Vec<String> = s.users.iter().flatten().map(|u| label_of(doc, u)).collect();
    out.extend(s.groups.iter().flatten().map(|g| g.trim().to_string()));
    out
}

/// A scope's `excluded`, for display and for the form's textarea.
///
/// One flat list, because the field is one flat list: a `@group` stays as written, a uuid
/// the roster still resolves becomes the person, and anything else — a stranger's email —
/// stays exactly as the file spells it. [`parse_exclusions`] is the inverse, and the
/// round-trip through the form is what that pairing has to keep exact.
pub(crate) fn scope_excluded_display(doc: &AccessFile, s: &ScopeSpec) -> Vec<String> {
    s.excluded
        .iter()
        .flatten()
        .map(|e| {
            let e = e.trim();
            if e.starts_with('@') {
                e.to_string()
            } else {
                label_of(doc, e)
            }
        })
        .collect()
}
