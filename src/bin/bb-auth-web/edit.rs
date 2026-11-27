use crate::*;

// ---------------------------------------------------------------------------
// Editing pages
// ---------------------------------------------------------------------------
//
// One struct and one page function per form. The struct is what the fields hold, and it is
// filled from two places — the access file, when the form is first rendered, and the
// submitted body, when a refusal sends the same form back. That is what "the submitted
// values are preserved" is: the same page function, one error string later.

/// The `users` form: one email. Used both for `users · add` (the row's first identifier)
/// and for `/users/{uuid}/emails/+add`: the two places an email is ever typed in, since an
/// identity carries no URL and its uuid never changes. `UserForm` gains nothing beyond
/// this: there is nothing else on a [`UserSpec`] a form could usefully edit.
#[derive(Default)]
pub(crate) struct UserForm {
    pub(crate) email: String,
}

impl UserForm {
    pub(crate) fn read(f: &Form) -> UserForm {
        UserForm {
            email: f.get("email").to_string(),
        }
    }
}

/// `users · add`: mints a uuid and enrols the first email.
pub(crate) fn page_user_form(v: &View, f: &UserForm, err: Option<&Refusal>) -> Markup {
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (v.t(K::Users)) " · " (v.t(K::Add)) }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field("email", "email", &f.email, "bob@x.com", None, about("email")))
            }, v.t(K::Create), false))
        }
    }
}

/// `/users/{uuid}/emails/+add`: one more identifier for an existing row.
pub(crate) fn page_email_form(
    v: &View,
    owner: &str,
    f: &UserForm,
    err: Option<&Refusal>,
) -> Markup {
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (owner) " · " (v.t(K::AddEmail)) }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field("email", "email", &f.email, "bob@x.com", None, about("email")))
            }, v.t(K::Create), false))
        }
    }
}

/// The `api_keys` form: a label, a window, and the `application/scope` restriction. Empty
/// means every scope the owner reaches ([`K::KeyScopesHelp`]) — a restriction, never a
/// grant, so it can only subtract from what the owner already has.
#[derive(Default)]
pub(crate) struct KeyForm {
    pub(crate) id: String,
    pub(crate) duration: String,
    pub(crate) days: String,
    pub(crate) scopes: String,
}

impl KeyForm {
    pub(crate) fn of(k: &ApiKeySpec) -> KeyForm {
        let (duration, days) = duration_of_stored(&k.duration);
        KeyForm {
            id: k.id.trim().to_string(),
            duration,
            days,
            scopes: urls_text(k.scopes.as_ref()),
        }
    }
    pub(crate) fn read(f: &Form) -> KeyForm {
        let (duration, days) = duration_of_posted(f.get("duration"), f.get("days"));
        KeyForm {
            id: f.get("id").to_string(),
            duration,
            days,
            scopes: f.get("scopes").to_string(),
        }
    }
}

/// The stored `duration`, read back into the control that spells it: a preset for a preset,
/// no expiry for **every** spelling of it (`never`, `0`, `-`, and the empty field
/// `parse_duration` reads as never), and the custom box filled with the file's own bytes for
/// anything the five cannot name. That last case is the one a form rewrite loses: `8760h` is
/// a real value in a real file, and a form that showed nothing picked for it would save
/// `365d` over it the moment the person pressed the button.
pub(crate) fn duration_of_stored(stored: &str) -> (String, String) {
    let stored = stored.trim();
    match stored {
        "365d" | "182d" | "91d" => (stored.to_string(), String::new()),
        _ => match parse_duration(stored) {
            Some(Dur::Never) => ("never".to_string(), String::new()),
            _ => ("custom".to_string(), stored.to_string()),
        },
    }
}

/// What a submission names, in the same shape, so the re-render after a refusal shows the
/// person what they posted. A hand-written client that posts `duration=30d` gets the custom
/// box filled with it, and a form that arrived with no `duration` at all opens on the add
/// form's default, which is what keeps the control carrying exactly one `selected`.
pub(crate) fn duration_of_posted(choice: &str, days: &str) -> (String, String) {
    let choice = choice.trim();
    match choice {
        "365d" | "182d" | "91d" | "custom" | "never" => {
            (choice.to_string(), days.trim().to_string())
        }
        "" => ("365d".to_string(), days.trim().to_string()),
        other => ("custom".to_string(), other.to_string()),
    }
}

/// The five choices, mapped onto the file's duration grammar, in **one** function for both
/// surfaces (§13.15): the console's mint, the console's edit and the self-service page mint
/// the same field, and a mapping written twice is two mappings.
///
/// The presets come back **verbatim** (`365d`, `182d`, `91d`, `never`), because they are not
/// codes to translate: they are the exact strings the file stores, so `bb-auth-adm show`, the
/// gate and every existing file see nothing new. A custom all-digit value gets the `d` the
/// grammar needs, so the file reads unambiguously; a custom value with a unit (`12h`) passes
/// through as typed, because the console's box has always taken the whole grammar and twelve
/// hours is a window a deployment genuinely wants. Anything else is passed through as typed,
/// so a hand-written `duration=30d` keeps working.
///
/// The refusals are the half worth reading. An empty or absent `duration` is refused and not
/// read as "no expiry": `parse_duration("")` is `Dur::Never`, so a form that lost its control
/// would mint a key that never dies, which is the one outcome the person did not ask for and
/// cannot undo from the page. A number typed while a preset is picked is a form that
/// contradicts itself, and guessing which half was meant is how a key outlives its reason.
pub(crate) fn duration_from_form(form: &Form) -> Result<String, K> {
    let choice = form.get("duration").trim();
    if choice.is_empty() {
        return Err(K::KeyDurationRequired);
    }
    let days = form.get("days").trim();
    if choice == "custom" {
        let stored = if days.is_empty() {
            String::new()
        } else if days.bytes().all(|b| b.is_ascii_digit()) {
            format!("{days}d")
        } else {
            days.to_string()
        };
        // A spelling of never has its own choice, and `parse_duration` reads `0`, `-` and
        // `never` as `Dur::Never`: taking one here would be a second way to spell one thing.
        if !matches!(parse_duration(&stored), Some(Dur::Secs(secs)) if secs > 0) {
            return Err(K::KeyDaysInvalid);
        }
        return Ok(stored);
    }
    if !days.is_empty() {
        return Err(K::KeyDaysWithoutCustom);
    }
    Ok(choice.to_string())
}

/// `api_keys · add` / `· edit`. `released` is not editable: on an add it is today, and on an
/// edit it is what the file says — a key's issue date is a fact about a secret that exists,
/// not a setting. (`bb-auth-adm key set --released` is there for a repair; a GUI that
/// offered it would mostly be a way to move an expiry by accident.)
pub(crate) fn page_key_form(
    v: &View,
    owner: &str,
    existing: Option<&str>,
    released: &str,
    f: &KeyForm,
    err: Option<&Refusal>,
) -> Markup {
    let editing = existing.is_some();
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (owner) " · api_keys · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(id) = existing { p class="lede" { code { (id) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                @if !editing {
                    (text_field("id", "id", &f.id, "laptop", None, about("id")))
                }
                (duration_choice(
                    v.lang,
                    "duration",
                    &f.duration,
                    &f.days,
                    // No placeholder: this box takes the whole grammar, and the hint says so.
                    None,
                    Some("<n>d · <n>h"),
                    about("duration"),
                ))
                label {
                    span class="lbl" { "released" }
                    span class="mono" { (released) }
                }
                (urls_field("scopes", "scopes", &f.scopes, html! { (v.t(K::KeyScopesHelp)) },
                            about("scopes")))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// A free-text notes field: operator documentation, round-tripped untouched. Not a pattern
/// list, so it gets no per-line framing.
fn notes_field(value: &str) -> Markup {
    html! {
        label {
            span class="lbl" { "notes" }
            textarea name="notes" rows="3" spellcheck="true" { (value) }
        }
    }
}

/// The `applications` form: `name`, `base`, `login_url`, `denied_url`, `notes`. There is no field here
/// that names a user, and there never may be one: an application describes a **place**, and
/// grants to named users live in a scope's `users`/`groups` alone.
#[derive(Default)]
pub(crate) struct AppForm {
    pub(crate) name: String,
    base: String,
    pub(crate) login_url: String,
    /// Where a refusal inside this area lands. Beside `login_url` because the pair is the
    /// same question twice: which page this area sends somebody to when they cannot pass.
    pub(crate) denied_url: String,
    pub(crate) notes: String,
}

impl AppForm {
    pub(crate) fn of(a: &AppSpec) -> AppForm {
        AppForm {
            name: a.name.trim().to_string(),
            base: a.base.join("\n"),
            login_url: a.login_url.clone().unwrap_or_default(),
            denied_url: a.denied_url.clone().unwrap_or_default(),
            notes: a.notes.clone().unwrap_or_default(),
        }
    }
    pub(crate) fn read(f: &Form) -> AppForm {
        AppForm {
            name: f.get("name").to_string(),
            base: f.get("base").to_string(),
            login_url: f.get("login_url").to_string(),
            denied_url: f.get("denied_url").to_string(),
            notes: f.get("notes").to_string(),
        }
    }
}

pub(crate) fn page_app_form(
    v: &View,
    existing: Option<&str>,
    f: &AppForm,
    err: Option<&Refusal>,
) -> Markup {
    let editing = existing.is_some();
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (v.t(K::Apps)) " · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(n) = existing { p class="lede" { code { (n) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field(if editing { v.t(K::NewName) } else { "name" },
                            "name", &f.name, "app1", None, about("name")))
                (urls_field(v.t(K::Base), "base", &f.base, html! { (v.t(K::BaseHelp)) }, about("base")))
                (text_field(v.t(K::LoginUrl), "login_url", &f.login_url, "https://login.x.com/",
                            Some(v.t(K::LoginUrlHelp)), about("login_url")))
                (text_field(v.t(K::DeniedUrl), "denied_url", &f.denied_url, "https://x.com/denied",
                            Some(v.t(K::DeniedUrlHelp)), about("denied_url")))
                (notes_field(&f.notes))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// The `scopes` form: `name`, `urls`, `access`, and — only meaningful under `restricted` —
/// `members` (people, one per line: an email or uuid resolved to a uuid, `@name` kept as a
/// group reference) and `credentials`.
#[derive(Default)]
pub(crate) struct ScopeForm {
    pub(crate) name: String,
    urls: String,
    pub(crate) access: String,
    pub(crate) members: String,
    pub(crate) cred_login: bool,
    pub(crate) cred_api_key: bool,
    /// The scope's own `excluded`, one per line: a person, a `@group`, or a stranger's
    /// email. Its own box and not a `-` prefix inside `members`, because the two lists say
    /// opposite things and a typo that turned one into the other would fail *open*.
    pub(crate) excluded: String,
    pub(crate) notes: String,
}

impl ScopeForm {
    pub(crate) fn of(doc: &AccessFile, s: &ScopeSpec) -> ScopeForm {
        let (cred_login, cred_api_key) = match &s.credentials {
            None => (true, true),
            Some(list) => (
                list.iter().any(|c| c.trim() == "login"),
                list.iter().any(|c| c.trim() == "api_key"),
            ),
        };
        ScopeForm {
            name: s.name.trim().to_string(),
            urls: s.urls.join("\n"),
            access: s.access.trim().to_string(),
            members: scope_members_display(doc, s).join("\n"),
            cred_login,
            cred_api_key,
            excluded: scope_excluded_display(doc, s).join("\n"),
            notes: s.notes.clone().unwrap_or_default(),
        }
    }
    pub(crate) fn read(f: &Form) -> ScopeForm {
        ScopeForm {
            name: f.get("name").to_string(),
            urls: f.get("urls").to_string(),
            access: f.get("access").to_string(),
            members: f.get("members").to_string(),
            cred_login: f.checked("cred_login"),
            cred_api_key: f.checked("cred_api_key"),
            excluded: f.get("excluded").to_string(),
            notes: f.get("notes").to_string(),
        }
    }
}

pub(crate) fn page_scope_form(
    v: &View,
    app: &str,
    existing: Option<&str>,
    f: &ScopeForm,
    err: Option<&Refusal>,
) -> Markup {
    let editing = existing.is_some();
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (app) " · " (v.t(K::Scopes)) " · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(n) = existing { p class="lede" { code { (n) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field(if editing { v.t(K::NewName) } else { "name" },
                            "name", &f.name, "admin", None, about("name")))
                (urls_field("urls", "urls", &f.urls, html! { (v.t(K::ScopeUrlsHelp)) }, about("urls")))
                div {
                    span class="lbl" { (v.t(K::AccessWord)) }
                    @for (val, label) in [
                        ("anonymous", v.t(K::AccessAnonymous)),
                        ("authenticated", v.t(K::AccessAuthenticated)),
                        ("restricted", v.t(K::AccessRestricted)),
                    ] {
                        label class="radio" {
                            input type="radio" name="access" value=(val) checked[f.access == val];
                            span { (label) }
                        }
                    }
                    span class="hint" { (v.t(K::AccessHelp)) }
                }
                (urls_field(v.t(K::Members), "members", &f.members, html! { (v.t(K::MembersHelp)) },
                            about("members")))
                (urls_field(v.t(K::Excluded), "excluded", &f.excluded,
                            html! { (v.t(K::ExcludedHelp)) }, about("excluded")))
                div {
                    span class="lbl" { (v.t(K::Credentials)) }
                    label class="radio" {
                        input type="checkbox" name="cred_login" value="on" checked[f.cred_login];
                        span { (v.t(K::CredLogin)) }
                    }
                    label class="radio" {
                        input type="checkbox" name="cred_api_key" value="on" checked[f.cred_api_key];
                        span { (v.t(K::CredApiKey)) }
                    }
                    span class="hint" { (v.t(K::CredentialsHelp)) }
                }
                (notes_field(&f.notes))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// The `user_groups` form: a name and its members, who are people rather than URL patterns.
#[derive(Default)]
pub(crate) struct GroupForm {
    pub(crate) name: String,
    pub(crate) members: String,
}

impl GroupForm {
    pub(crate) fn read(f: &Form) -> GroupForm {
        GroupForm {
            name: f.get("name").to_string(),
            members: f.get("members").to_string(),
        }
    }
}

pub(crate) fn page_group_form(
    v: &View,
    existing: Option<&str>,
    f: &GroupForm,
    err: Option<&Refusal>,
) -> Markup {
    let editing = existing.is_some();
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (v.t(K::Groups)) " · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(n) = existing { p class="lede" { code { "@" (n) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                // No rename: the library refuses to have one, and says why.
                @if editing {
                    p class="muted" { (v.t(K::GroupNoRename)) }
                } @else {
                    (text_field("name", "name", &f.name, "admins", None, about("name")))
                }
                (urls_field(v.t(K::Members), "members", &f.members, html! { (v.t(K::GroupMembersHelp)) },
                            about("members")))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// Which file a route edits, and therefore which one its `rev` fingerprints.
///
/// Two files, one optimistic-concurrency check. A settings form carrying the access file's
/// fingerprint would `409` on every unrelated roster edit, and, far worse, one carrying a
/// fingerprint of the wrong file would not notice a concurrent `bb-auth-adm settings set` at
/// all, which is the whole thing the check exists for.
pub(crate) fn edited_file<'a>(cfg: &'a Config, at: &Route) -> &'a str {
    match at.tab() {
        Route::Config => &cfg.settings_path,
        _ => &cfg.access_path,
    }
}
