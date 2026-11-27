use crate::*;

/// The access check's one text field, in whichever of the two forms is asking.
///
/// `fld` is base.css's field label, the same class the sign-in page puts over its own inputs:
/// the type comes from there and admin.css only says these sit side by side. Without it this
/// form would grow a second answer to what a label looks like, which is the whole thing
/// base.css exists to prevent.
///
/// Neither form carries a hidden `lang`, though both replace the whole query when they submit:
/// by the time a page renders, the language is a cookie (an explicit `?lang=` is redirected
/// into one first), so it survives a submit on its own, and re-sending it would turn a
/// [`LangPref::Auto`] preference into a fixed choice on the operator's first check.
fn check_field(name: &str, value: &str, placeholder: &str) -> Markup {
    html! {
        label class="fld" {
            (name)
            input type="text" name=(name) value=(value) placeholder=(placeholder)
                  autocapitalize="off" spellcheck="false";
        }
    }
}

/// The `ok`/`bad` panel one answer lands in, shared by the two pages that ask.
///
/// The wrapper is shared and not just [`verdict`], because the left bar's colour is part of
/// the answer: the one thing an operator scanning a page cannot afford is a verdict that
/// looks the same whether it granted or refused.
/// The id the access check's heading carries, and the fragment both check forms submit to.
///
/// A `GET` form lands on a fresh document at the top of the page, which on an application or
/// a person is several screens above the question that was just asked: the operator types a
/// URL, presses the button, and the answer arrives out of sight. The fragment on the form's
/// `action` survives submission (the browser replaces the query and keeps the fragment), so
/// the answer arrives where the question was asked, with no script anywhere near it.
const CHECK_ANCHOR: &str = "check";

fn verdict_panel(v: &View, access: &Access, email: &str, url_in: &str) -> Markup {
    let (granted, markup) = verdict(v, access, email, &request_url(url_in));
    html! {
        div class=@if granted { "panel ok" } @else { "panel bad" } { (markup) }
    }
}

/// The access check as a section of a person's page: one field, because this page is the
/// other half of the question.
///
/// It sits under `scopes` and above `api_keys` on purpose. `scopes` says what the file
/// *lists*; this says what [`decide`] *answers*, which is not the same thing the moment an
/// `excluded`, a `denied` or an `authenticated` scope is involved, and the two belong side by
/// side. Above `api_keys` because it does not speak for a key: that verdict is
/// [`bb_auth_core::decide_api_key`]'s, and `bb-auth-adm can --key ID` is where it stays
/// (naming a key means picking one, which is a second field and a listing, and it is one
/// invocation away on the host that has the file).
///
/// The subject is [`user_label`]'s identifier, which is also this page's `h1`, and any of the
/// row's emails would give the same answer: an identifier that resolves is folded onto its
/// uuid at load, so a veto or an exclusion written against one address is written against the
/// row. A row with no email at all can be asked nothing, and says so rather than quietly
/// testing a stranger.
pub(crate) fn user_check(v: &View, access: &Access, u: &UserSpec, uuid: &str) -> Markup {
    // The identifiers that can actually resolve, which is not the same as the rows in
    // `emails`: an empty or non-ASCII one is dropped at load, so a row can list two and be
    // reachable through one.
    let ids: Vec<String> = u
        .emails
        .iter()
        .map(|e| norm_email(e))
        .filter(|e| !e.is_empty())
        .collect();
    let url_in = query_param(v.query, "url").unwrap_or_default();
    html! {
        h2 id=(CHECK_ANCHOR) { (v.t(K::Can)) }
        @match ids.first() {
            None => div class="panel" { span class="muted" { (v.t(K::CanNoIdentifier)) } },
            Some(email) => {
                p class="lede sub" {
                    (v.t(K::CanIntroUser))
                    @if ids.len() > 1 { " " (v.t(K::CanAnyEmail)) }
                }
                div class="panel" {
                    // The canonical spelling of this row's own route: the page renders under
                    // an email too, and the answer is about the identity either way.
                    form class="can" method="get"
                         action=(format!("{}#{CHECK_ANCHOR}", v.href(&Route::User(uuid.to_string())))) {
                        (check_field("url", &url_in, "https://app.x.com/reports"))
                        button type="submit" { (v.t(K::Submit)) }
                    }
                }
                @if !url_in.trim().is_empty() {
                    (verdict_panel(v, access, email, &url_in))
                }
            }
        }
    }
}

/// The access check as a section of an application's page: both fields, and the answer names
/// the scope that gave it, which is one of the numbered scopes listed directly above.
///
/// An email left blank tests [`Subject::Anonymous`] rather than refusing to answer: that is
/// the only way to check what an `anonymous` scope actually opens, and this is the only one of
/// the two places that can ask it, since a person's page always has a person.
///
/// The url field starts on this area's own `base` rather than empty, so an operator appends a
/// path instead of retyping a host. It is a *starting point* and not a restriction: whatever
/// is submitted goes to [`decide`], which resolves it against the whole file, so a URL typed
/// outside this area is answered honestly and the verdict says which application answered.
pub(crate) fn app_check(v: &View, access: &Access, a: &AppSpec) -> Markup {
    let email_in = query_param(v.query, "email").unwrap_or_default();
    let url_in = query_param(v.query, "url").unwrap_or_default();
    let asked = !url_in.trim().is_empty();
    let url_value = if asked {
        url_in.clone()
    } else {
        a.base
            .first()
            .map(|b| b.trim().to_string())
            .unwrap_or_default()
    };
    html! {
        h2 id=(CHECK_ANCHOR) { (v.t(K::Can)) }
        p class="lede sub" { (v.t(K::CanIntroApp)) }
        div class="panel" {
            form class="can" method="get"
                 action=(format!("{}#{CHECK_ANCHOR}",
                                 v.href(&Route::App(a.name.trim().to_string())))) {
                (check_field("email", &email_in, "bob@x.com"))
                (check_field("url", &url_value, "https://app.x.com/reports"))
                button type="submit" { (v.t(K::Submit)) }
            }
        }
        @if asked {
            (verdict_panel(v, access, &email_in, &url_in))
        }
    }
}

/// One verdict, with the reason the gate would have. The wording follows `bb-auth-adm can`'s:
/// same decision, same explanation, so an operator who has read one recognises the other.
/// Returns whether the request was granted alongside the markup, so the caller can carry that
/// same boolean onto the panel wrapping it (an `ok` or `bad` left bar).
fn verdict(v: &View, access: &Access, email_in: &str, url: &str) -> (bool, Markup) {
    let email = norm_email(email_in);
    let subject = if email.is_empty() {
        Subject::Anonymous
    } else {
        Subject::Identifier(&email)
    };
    let decision = decide(access, &subject, Some(url));
    let granted = decision.granted();
    let at = |app: &str, scope: &str| html! { code { (app) "/" (scope) } };
    let markup = html! {
        p class=@if granted { "verdict yes" } @else { "verdict no" } {
            @if granted { (v.t(K::Authorized)) } @else { (v.t(K::VerdictDenied)) }
        }
        p {
            @match &decision {
                Decision::Anonymous { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyAnonymousGrant))
                }
                Decision::Granted { app, scope } => { (at(app, scope)) " " (v.t(K::WhyGranted)) }
                Decision::Vetoed => { code { (email) } " " (v.t(K::WhyVetoed)) }
                Decision::Excluded { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyExcluded))
                }
                Decision::NoApplication => { code { (url) } " " (v.t(K::WhyNoApplication)) }
                Decision::NoScope { app } => { code { (app) } " " (v.t(K::WhyNoScope)) }
                Decision::Unauthenticated { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyUnauthenticated))
                }
                Decision::CredentialRefused { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyCredentialRefused))
                }
                Decision::NotEnrolled { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyNotEnrolled))
                }
                Decision::NotMember { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyNotMember))
                }
                Decision::KeyOutOfScope { app, scope } => {
                    (at(app, scope)) " " (v.t(K::WhyKeyOutOfScope))
                }
            }
        }
        @if granted && !matches!(decision, Decision::Anonymous { .. }) {
            p class="muted" {
                (v.t(K::AppSees)) " "
                // Every header this deployment's `gate.identity_attrs` will actually send,
                // by the library's own derivation, not the literal one this page used to
                // name. On a `["uuid"]` deployment there is no `X-Auth-Email` at all, and
                // saying otherwise here is saying it on the page whose whole job is to
                // predict what the application receives.
                @for (i, h) in v.identity.iter().enumerate() {
                    @if i > 0 { ", " }
                    code { (h) ": " (email) }
                }
            }
        }
    };
    (granted, markup)
}
