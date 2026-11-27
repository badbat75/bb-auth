use crate::*;

// ---------------------------------------------------------------------------
// Key expiry
// ---------------------------------------------------------------------------

/// A key's validity window, resolved against the wall clock — the library's [`key_expiry`]
/// plus the "is that in the past?" the gate applies on every request.
pub(crate) enum Expiry {
    /// `released`/`duration` do not parse: the gate skips this key entirely.
    Invalid,
    Never,
    /// Unix seconds, and the days from now (negative once past).
    At(u64, i64),
}

/// Anything closer than this is called out on the dashboard. A month is the window in which
/// re-minting a key is a chore rather than an incident.
const SOON_DAYS: i64 = 30;

pub(crate) fn expiry_of(k: &ApiKeySpec, now: u64) -> Expiry {
    match key_expiry(&k.released, &k.duration) {
        None => Expiry::Invalid,
        Some(None) => Expiry::Never,
        Some(Some(exp)) => Expiry::At(exp, (exp as i64 - now as i64) / 86_400),
    }
}

impl Expiry {
    /// Sort rank for the dashboard table: what expires soonest first, then the broken ones
    /// (which need attention but have no date to sort by), then the ones that never expire.
    fn rank(&self) -> (u8, i64) {
        match self {
            Expiry::At(_, days) => (0, *days),
            Expiry::Invalid => (1, 0),
            Expiry::Never => (2, 0),
        }
    }
}

pub(crate) fn expiry_markup(lang: Lang, e: &Expiry) -> Markup {
    html! {
        @match e {
            Expiry::Invalid => (tag("bad", t(lang, K::KeyInvalid))),
            Expiry::Never => (tag("", t(lang, K::NeverExpires))),
            Expiry::At(exp, days) if *days < 0 => {
                (tag("bad", t(lang, K::Expired)))
                " " span class="mono muted" { (format_date(*exp)) }
            }
            Expiry::At(exp, days) if *days <= SOON_DAYS => {
                (tag("warn", t(lang, K::ExpiresSoon)))
                " " span class="mono muted" { (format_date(*exp)) " (" (days) "d)" }
            }
            Expiry::At(exp, days) => {
                span class="muted" { (t(lang, K::Expires)) " " }
                span class="mono" { (format_date(*exp)) }
                span class="muted" { " (" (days) "d)" }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// The emails on `denied`, normalised — every page that marks one needs this set.
/// How a uuid appears to an operator wherever a members list is rendered, or wherever a
/// route's own uuid needs a friendly heading: the roster's own label if the row still
/// exists, else the uuid itself — a dangling reference is shown for what it is rather than
/// hidden.
pub(crate) fn label_of(doc: &AccessFile, key: &str) -> String {
    let key = key.trim().to_ascii_lowercase();
    match user_pos(doc, &key) {
        Some(i) => user_label(&doc.users[i]),
        None => key,
    }
}

/// `/` — the counts, what expires next, and everything the file says that an operator would
/// rather hear now than at 3am.
///
/// The warnings are computed from library data only: [`Access::scopes_for`], the compiled
/// scopes (for shadowing and empty-membership), [`user_group_refs`] and [`Access::denied_users`].
/// Shadowing is a heuristic, and it needs an operator to explain itself to; it earns its
/// place here because the alternative (a scope that answers for nothing, with nobody
/// noticing) is worse.
///
/// Each warning reads kind, identifier, sentence (§13.35): one list mixes scopes, people and
/// groups, and `@delete-test` on its own does not say which of the three it is. The identifier
/// is a link wherever the object has a page of its own (a scope to its application, because a
/// shadowed scope is explained only by the scopes listed above it there; a person to their
/// page; a user group to its own page, §13.36 §2, where "nothing references me" is answered by
/// the scopes panel first under the head).
pub(crate) fn page_dashboard(v: &View, doc: &AccessFile, access: &Access) -> Markup {
    let n = now();
    let scope_count: usize = doc.applications.iter().map(|a| a.scopes.len()).sum();
    let key_count: usize = doc.users.iter().map(|u| u.api_keys.len()).sum();

    // Every key in the file, soonest expiry first.
    let mut keys: Vec<(&UserSpec, &ApiKeySpec, Expiry)> = doc
        .users
        .iter()
        .flat_map(|u| u.api_keys.iter().map(move |k| (u, k, expiry_of(k, n))))
        .collect();
    keys.sort_by_key(|(_, _, e)| e.rank());

    let mut warnings: Vec<Markup> = Vec::new();
    for a in doc.applications.iter() {
        for (si, s) in a.scopes.iter().enumerate() {
            if shadowing_scope(&a.scopes[..si], &s.urls).is_some() {
                warnings.push(html! {
                    (v.t(K::KindScope)) " "
                    a href=(v.href(&Route::App(a.name.trim().to_string()))) {
                        code { (a.name.trim()) "/" (s.name.trim()) }
                    }
                    " " (v.t(K::WarnShadowed))
                });
            }
        }
    }
    for a in &access.apps {
        for s in &a.scopes {
            if s.access == bb_auth_core::AccessKind::Restricted && s.members.is_empty() {
                warnings.push(html! {
                    (v.t(K::KindScope)) " "
                    a href=(v.href(&Route::App(a.name.trim().to_string()))) {
                        code { (a.name) "/" (s.name) }
                    }
                    " " (v.t(K::WarnNoMembers))
                });
            }
        }
    }
    for u in &doc.users {
        let uuid = u.uuid.trim().to_ascii_lowercase();
        if access.scopes_for(&uuid).is_empty() {
            warnings.push(html! {
                (v.t(K::KindUser)) " "
                a href=(v.href(&Route::User(uuid.clone()))) { code { (user_label(u)) } }
                " " (v.t(K::WarnNoScope))
            });
        }
        if access.denied_users.contains(&uuid) {
            warnings.push(html! {
                (v.t(K::KindUser)) " "
                a href=(v.href(&Route::User(uuid))) { code { (user_label(u)) } }
                " " (v.t(K::WarnEnrolledAndDenied))
            });
        }
    }
    for name in doc.user_groups.keys() {
        if user_group_refs(doc, name).is_empty() {
            warnings.push(html! {
                (v.t(K::KindGroup)) " "
                a href=(v.href(&Route::Group(name.clone()))) { code { "@" (name) } }
                " " (v.t(K::ReferencedByNothing))
            });
        }
    }

    html! {
        h1 { (v.t(K::Dashboard)) }
        p class="lede" { code { (v.cfg.access_path) } }

        h2 { (v.t(K::Counts)) }
        div class="cards" {
            @for (label, count, route) in [
                ("applications", doc.applications.len(), Some(Route::Apps)),
                ("scopes", scope_count, None),
                ("users", doc.users.len(), Some(Route::Users)),
                ("api_keys", key_count, None),
                ("user_groups", doc.user_groups.len(), Some(Route::Groups)),
                ("denied", doc.denied.len(), Some(Route::Denied)),
            ] {
                @if let Some(r) = &route {
                    a class="card" href=(v.href(r)) {
                        div class="n" { (count) }
                        div class="l mono" { (label) }
                    }
                } @else {
                    div class="card" {
                        div class="n" { (count) }
                        div class="l mono" { (label) }
                    }
                }
            }
        }

        h2 { (v.t(K::KeyExpiry)) }
        div class="panel" {
            @if keys.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                table {
                    thead { tr {
                        th { (v.t(K::ColOwner)) }
                        th { "id" }
                        th { (v.t(K::ColExpiry)) }
                    } }
                    tbody {
                        @for (u, k, e) in &keys {
                            @let uuid = u.uuid.trim().to_ascii_lowercase();
                            tr {
                                td data-label=(v.t(K::ColOwner)) {
                                    a href=(v.href(&Route::User(uuid))) { (user_label(u)) }
                                }
                                td class="mono" data-label="id" { (k.id.trim()) }
                                td data-label=(v.t(K::ColExpiry)) { (expiry_markup(v.lang, e)) }
                            }
                        }
                    }
                }
            }
        }

        h2 { (v.t(K::Warnings)) }
        div class=@if warnings.is_empty() { "panel" } @else { "panel warn" } {
            @if warnings.is_empty() {
                span class="muted" { (v.t(K::NoWarnings)) }
            } @else {
                ul class="plain" { @for w in &warnings { li { (*w) } } }
            }
        }
    }
}
