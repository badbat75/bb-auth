use crate::*;

// ---------------------------------------------------------------------------
// The self-service page
// ---------------------------------------------------------------------------

/// The self-service page's look: the four `ui` values, all four of which it paints.
///
/// [`Look`] is the console's, and carries only what that shell paints out of it: a theme, a
/// stylesheet and the name its bar shows, because its header bar shows no logo. This page shows
/// a logo, and widening `Look` by a field the console paints nothing for is how a struct starts
/// lying about what it means.
///
/// `AccountLook::default()` is "nothing configured", and it is the honest answer on every page
/// rendered **before** the settings file has been read: the `401` happens above that read, and a
/// page that cannot know the operator's stylesheet shows the built-in one rather than guessing.
///
/// `theme` here is the **deployment's** default, kept beside the visitor's own choice rather than
/// folded into it: the two answer different questions and both have to survive to the page, since
/// the selector must show `System` as chosen while the page renders the dark the administrator
/// asked for.
#[derive(Clone, Copy, Default)]
pub(crate) struct AccountLook<'a> {
    /// `ui.theme`: which arm of the palette a page starts in when the visitor has expressed no
    /// preference of their own.
    theme: UiTheme,
    /// `ui.stylesheet_url`: an operator's own stylesheet, loaded after the built-in one.
    stylesheet: Option<&'a str>,
    /// `ui.logo_url`: needed for the policy as much as for the markup, since it is the one image
    /// this page may fetch.
    logo: Option<&'a str>,
    /// `ui.brand_name`: the name the page calls this deployment.
    brand: Option<&'a str>,
}

/// The name a page calls this deployment when `ui.brand_name` is empty: the self-service page's
/// brand slot and the console's bar both fall back to it, so a deployment nobody has branded
/// names itself the same on both. A package creates the settings file with that field empty, so
/// this is what a first install shows.
pub(crate) const DEFAULT_ACCOUNT_BRAND: &str = "bb-auth";

/// What the chrome needs that is not the page: this browser's two preferences, the language they
/// render as, the URL the selector form goes back to, and the two facts the header bar shows
/// beside it (§13.17).
///
/// A struct rather than four more arguments because every page under the prefix is answered
/// through [`respond_account`], and a preference that reached only some of them is a page whose
/// selector shows something other than what that page is rendered in. The bar's two facts are
/// here for the same reason: the identity and the Sign out target exist only once the identity
/// header and the settings have been read, and a bar that showed them on some pages and not
/// others is the drift this struct exists to stop.
pub(crate) struct AccountPrefs<'a> {
    /// The language every string on the page is looked up by.
    lang: Lang,
    /// Which option the selector shows as the chosen language, which is not the same thing as
    /// `lang`: `Auto` renders as one of the two and must still come back as `Auto`.
    lang_pref: LangPref,
    /// Which appearance **this browser** asked for, `System` included. It is not on its own what
    /// the page renders in: [`account_shell`] falls through to [`AccountLook::theme`] after it.
    theme: UiTheme,
    /// The prefix with a trailing slash: the form's `action` and the target of the preference
    /// redirect, both built from [`Config::account_path`].
    pub(crate) page: &'a str,
    /// Who the bar says is signed in, once the identity header has been read: the forwarded
    /// `given_name` and every address, or the addresses alone. `None` on the pages answered
    /// before any identity exists (the `401`), where there is nobody to name.
    who: Option<Who>,
    /// Where Sign out points: [`Config::account_logout_url`], the operator's link with its `rd`
    /// dropped, and no control at all when the operator named no destination. The console's own
    /// pill is the same setting unchanged (§13.17).
    pub(crate) logout: Option<&'a str>,
    /// The delete row's target: `{account}/delete`, and `None` when
    /// [`Config::delete_intake`] is unset (§13.29 W2, §13.30 §1).
    ///
    /// A field and not something the shell derives, because the row exists only where there is a
    /// worker behind the page: a deployment that never wired one must show nobody a door to
    /// nothing, and the page's `{account}/delete` stays the ordinary `404`.
    delete: Option<&'a str>,
    /// Whether **this page** carries its own `p.lede`, and the bar's menu therefore keeps the
    /// identity out.
    ///
    /// The menu's lede is the identity's second home for a page that has no lede of its own: the
    /// bar hides the name on a phone, and the menu opens with the answer. A step page whose lede
    /// is the sentence the person must read first (the code page names the address the code went
    /// to, an outcome page says why nothing was saved) is the case the design counts as *one*
    /// `p.lede` (§13.23 §3, §4): a second one above it in the document would put the identity
    /// ahead of the sentence that explains the page. The bar's own name is untouched.
    pub(crate) page_lede: bool,
}

/// This page's `Content-Security-Policy`.
///
/// The style hash is the **same** value [`admin_csp`] computes, because the `<style>` block is
/// the same bytes: the palette, the components and [`CSS`]. That is why the page's arrangement
/// lives in `src/assets/admin.css` and not beside this code: a second stylesheet is a second
/// hash, and a page whose policy is a list of hashes to keep in step is a page that breaks when
/// one of them is edited.
///
/// `script-src` is the console's, through [`page_script_src`]: the shared Preferences form
/// carries the shell's one handler on **both** surfaces, so picking a theme or a language
/// submits on this page exactly as it does in the console, and the `<noscript>` Apply is the
/// way in for a browser running no code. `reveal` adds the copy script's hash and nothing
/// else (§13.14): the bearer reveal is the one page under this prefix that carries a
/// `<script>`, and a policy that said `'none'` beside a hash would run nothing, so the sources
/// replace each other rather than joining.
///
/// `form-action` is `'self'`: the selector is a `GET` back to this same page, which is the whole
/// interaction.
///
/// `img-src` names the deployment's logo beside the `data:` that was already there, exactly as
/// [`admin_csp_logo`] does for the console: both surfaces show the mark in the bar, so both name
/// its source, and neither names a second one (§13.28 §6).
pub(crate) fn account_csp(look: &AccountLook, reveal: bool) -> String {
    let style = csp_hash(&format!("{THEME_CSS}{BASE_CSS}{CSS}"));
    page_csp(
        &page_script_src(reveal),
        &style,
        "'self'",
        look.stylesheet,
        look.logo,
        &[],
    )
}

/// The chrome every page under the prefix is wrapped in: the palette, the components built out of
/// it, the console's arrangement, then the operator's stylesheet, so an override wins by
/// source order and needs no `!important`.
///
/// The bar is the console's, from [`top_bar`], and the three slots say what the two surfaces are
/// for: the operator's brand where the console names the tool, an empty `nav` where the console's
/// four tabs are (this page is one page, so there is nothing to switch between), and the account
/// end with the identity, the Preferences menu and Sign out. The menu is the console's, worn
/// here exactly as it is worn there: the two list boxes carry the shell's one handler, so a
/// choice applies the moment it is picked, and the Apply sits behind a `noscript` as the way in
/// for a browser running no code (step 13, PLAN.md). The form is a plain `GET` back to the page,
/// so the existing `302` that sets the `theme` and `lang` cookies keeps working.
fn account_shell(prefs: &AccountPrefs, title: &str, content: Markup, look: AccountLook) -> Markup {
    // The two list boxes' options, each in the order they are offered, both leading with the
    // choice that follows something outside this page (the browser, the OS), because that is
    // where every session starts and what the other options are departures from.
    let brand_name = look.brand.unwrap_or(DEFAULT_ACCOUNT_BRAND);
    // The brand slot: the operator's mark and name, worn as the page showed them before the bar
    // existed, and now worn the same way on every surface, the console's bar included
    // (§13.34 §11).
    let brand = brand_block(brand_name, look.logo, "selfserve-brand");
    // The account end: one menu, built by the console's own function, so the two surfaces cannot
    // drift. No places: this page has no tabs to move and offers no console page (§13.28 §2), so
    // the panel is who the caller is, the Preferences box, and Sign out.
    let prefs_box = prefs_form(prefs.lang, prefs.lang_pref, prefs.theme, prefs.page, &[]);
    let acct = html! {
        nav class="acct" {
            (account_menu(
                prefs.lang,
                prefs.who.as_ref(),
                None,
                prefs_box,
                prefs.logout,
                prefs.delete,
                // Grouped: this page's bar has the account menu and no ☰, and the console's bar
                // beside it has both, so the name is the pair's, written the same on each half.
                true,
            ))
        }
    };
    page_document(
        prefs.lang,
        prefs.theme.attr().or(look.theme.attr()),
        &format!("{brand_name} · {title}"),
        look.stylesheet,
        html! {
            // No ☰ here (§13.34 §4), and the strip is the strip with its own name and empty:
            // the breakpoint rules hide the strip by name (`nav.tabs`), because with the ☰ in
            // the console's bar the old `nav:not(.acct)` would hide that too. A strip written
            // without the class is invisible to every one of those rules, and on a phone it
            // lands in front of the brand as an ordering item, which is what moves the brand
            // off the left edge the page's `h1` starts at.
            (top_bar(html! {}, brand, html! { nav class="tabs" {} }, acct))
            main {
                h1 { (title) }
                (content)
            }
        },
    )
}

/// One HTML page under the prefix, with the estate's shared headers and this page's own policy.
///
/// It does not go through [`respond_page`], because that answers with the console's [`Look`],
/// and this page's look is its own read of the `ui` section: it paints the operator's logo,
/// which the console's shell carries as a separate argument, and a page rendered above the
/// settings read has an `AccountLook::default()` of its own (§13.28 §6). What the two policies
/// **allow to run** is not one of the differences: both surfaces wear the same Preferences form,
/// so both admit the same handler through [`page_script_src`], and the only widening here is the
/// reveal's (§13.17).
pub(crate) fn respond_account(
    req: Request,
    status: u16,
    prefs: &AccountPrefs,
    title: &str,
    content: Markup,
    look: AccountLook,
    reveal: bool,
) {
    let page = account_shell(prefs, title, content, look);
    let mut resp = Response::from_data(page.into_string().into_bytes())
        .with_status_code(StatusCode(status))
        .with_header(h("Content-Type", "text/html; charset=utf-8"))
        .with_header(h("Content-Security-Policy", &account_csp(&look, reveal)));
    for (k, v) in PAGE_SECURITY_HEADERS {
        resp.add_header(h(k, v));
    }
    let _ = req.respond(resp);
}

/// `302` back to the page, setting **one cookie per preference this request named**.
///
/// One response for both, because the selector is a form with a submit button and no script: one
/// `GET` carries `theme` and `lang` together, and a program that answered one at a time would
/// leave the person watching the other half of their own submit revert on the next load. The
/// console gets away with one cookie per redirect only because its handler fires per list box.
///
/// A value nobody recognises sets nothing: storing it would write a cookie the page cannot show
/// as chosen, and would let a crafted link write a preference for somebody.
///
/// `location` is [`Config::account_path`] plus a slash, so it is printable ASCII by construction
/// and [`h`] cannot panic on it; the cookie values are one of a closed enum's own codes.
fn respond_account_preferences(
    req: Request,
    location: &str,
    theme: Option<UiTheme>,
    lang: Option<LangPref>,
) {
    let mut resp = Response::empty(StatusCode(302)).with_header(h("Location", location));
    if let Some(chosen) = theme {
        resp.add_header(h(
            "Set-Cookie",
            &format!(
                "{THEME_COOKIE}={}; Max-Age={PREFERENCE_COOKIE_MAX_AGE}; Path=/; HttpOnly; \
                 SameSite=Lax",
                chosen.code()
            ),
        ));
    }
    if let Some(chosen) = lang {
        resp.add_header(h(
            "Set-Cookie",
            &format!(
                "{LANG_COOKIE}={}; Max-Age={PREFERENCE_COOKIE_MAX_AGE}; Path=/; HttpOnly; \
                 SameSite=Lax",
                chosen.code()
            ),
        ));
    }
    resp.add_header(h("Cache-Control", "no-store"));
    let _ = req.respond(resp);
}

/// What the four sections show: most of it read out of the two files this request opened, and
/// the two facts that belong to the request itself (`native`, and the paths) beside them.
///
/// A struct because the page function takes the caller's identity separately (it comes from the
/// request, not from the files), and a page that took six loose arguments was a page whose
/// arguments could be swapped without a compiler noticing.
pub(crate) struct AccountOwn<'a> {
    /// Each application the caller reaches, with the scope names under it, in file order.
    reached: Vec<(&'a str, Vec<&'a str>)>,
    /// The `user_groups` that list the caller's uuid.
    pub(crate) groups: Vec<&'a str>,
    /// The keys on the caller's roster row, in the file's order.
    pub(crate) keys: Vec<&'a ApiKeySpec>,
    /// Each configured `gate.profile_claims` entry, with the value the proxy forwarded.
    claims: Vec<(&'a str, Option<String>)>,
    /// The scopes a key of the caller's may be narrowed to, from
    /// [`bb_auth_core::Access::key_scopes_for`]. Empty for a caller with no row, which is what
    /// takes the mint form out of the page.
    mintable: Vec<(&'a str, &'a str)>,
    /// The `POST` target of the mint form, and the fingerprint of the file as this page was
    /// rendered. Both belong to the request, not to the files, so they arrive beside the facts
    /// the files gave rather than as two more arguments to the page.
    keys_path: &'a str,
    rev: &'a str,
    /// The page's own URL: where every cancel link goes.
    page: &'a str,
    /// `<prefix>/profile`, the form's `POST` target and the Edit pill's href. Beside `keys_path`
    /// for the same reason: it belongs to the request, not to the files.
    profile_path: &'a str,
    /// Whether the edit can work here at all, which is what puts the Edit pill on the panel or
    /// takes it off (§13.22, "The client is `gate.client_id`").
    profile_edit: bool,
    /// Whether this session is a **native** Cognito sign-in, which is the gate's
    /// `X-Auth-Native-Username` speaking (§13.25). The edit acts on that one Cognito user, so a
    /// session the gate did not name gets no pill, no form and no code, and the sentence that
    /// says why. It is a `bool` and not the name because the page only asks whether to offer.
    native: bool,
}

/// The scopes a signed-in caller reaches, grouped by application in file order.
///
/// The grouping is [`bb_auth_core::Access::scopes_reached`] restated as pairs of names, because
/// the page shows an application and then its scopes, and a renderer that walked the raw list
/// would have to notice the application changed at every step.
fn account_reached<'a>(access: &'a Access, identifier: &str) -> Vec<(&'a str, Vec<&'a str>)> {
    let mut out: Vec<(&str, Vec<&str>)> = Vec::new();
    for (app, scope) in access.scopes_reached(identifier) {
        match out.last_mut() {
            Some((name, scopes)) if *name == app.name => scopes.push(scope.name.as_str()),
            _ => out.push((app.name.as_str(), vec![scope.name.as_str()])),
        }
    }
    out
}

/// The groups that list `uuid`.
///
/// The **document** is asked, not the table: `compile_access` expands a `@group` into each
/// scope's members and keeps no group names, and the question a person has is "under which named
/// set am I filed", which a scope's member list cannot answer (a `@group` lists none of them
/// directly). Members are compared the way the library compares them, with [`norm_email`]. A
/// caller with no roster row is in no group, because a group lists uuids.
fn account_groups<'a>(doc: &'a AccessFile, uuid: Option<&str>) -> Vec<&'a str> {
    let Some(want) = uuid else {
        return Vec::new();
    };
    let want = norm_email(want);
    doc.user_groups
        .iter()
        .filter(|(_, members)| members.iter().any(|m| norm_email(m) == want))
        .map(|(name, _)| name.as_str())
        .collect()
}

/// The keys on the caller's roster row, in the file's order.
///
/// Read off the **document**, not the compiled table: the table is a `HashMap` and has lost the
/// order, a page that reshuffled a person's keys between two reloads is a page nobody can compare
/// with the file they wrote, and the console's own table lists them in the file's order too. It
/// is also the row the ten-key bound counts, including a key whose hash the gate skipped, since a
/// person has to be able to see and revoke that one as well. The bearer is not on a roster row at
/// all, only its hash, and the hash is never shown: this list is free of the secret by the shape
/// of what the page reads from it.
pub(crate) fn account_keys<'a>(doc: &'a AccessFile, uuid: Option<&str>) -> Vec<&'a ApiKeySpec> {
    uuid.and_then(|u| user_pos(doc, u))
        .map_or_else(Vec::new, |i| doc.users[i].api_keys.iter().collect())
}

/// The Cognito user this session **is**, as the gate named it, or `None` when the gate named
/// nobody.
///
/// The gate sends [`bb_auth_core::NATIVE_USERNAME_HEADER`] (the token's `cognito:username`) only
/// for a sign-in that went straight to Cognito: a federated sign-in, an API key, an anonymous
/// grant, and a cookie minted before that header existed all send nothing. That is the whole
/// basis of the profile edit, because the edit acts on **one Cognito user** and the only honest
/// name for that user is the one the token carried. Reading it from anywhere else is the bug this
/// step exists for: the rpi-01 deployment has native accounts whose roster email is not their
/// Cognito username, so an edit aimed at an email resolves to a different user, or to nobody, and
/// the person's save silently lands somewhere else.
///
/// An empty value counts as no name: a header that names nothing cannot be sent as a `USERNAME`,
/// and offering the edit on it would end in a pool error the page cannot explain.
///
/// The value is never written to a log, the journal or the audit: it is a personal identifier, and
/// the only thing that reads it is the Cognito request that carries it.
pub(crate) fn native_user(req: &Request) -> Option<&str> {
    header_value(req, bb_auth_core::NATIVE_USERNAME_HEADER).filter(|v| !v.is_empty())
}

/// Everything the page shows, gathered from the two files this request opened. One function for
/// the page a `GET` renders and for the page a refused mint answers with, so the refusal cannot
/// show a different account from the one it refused.
#[allow(clippy::too_many_arguments)]
pub(crate) fn account_own<'a>(
    doc: &'a AccessFile,
    access: &'a Access,
    settings: &'a Settings,
    req: &Request,
    ids: &[String],
    uuid: Option<&str>,
    keys_path: &'a str,
    rev: &'a str,
    page: &'a str,
    profile_path: &'a str,
) -> AccountOwn<'a> {
    AccountOwn {
        reached: account_reached(access, &ids[0]),
        groups: account_groups(doc, uuid),
        keys: account_keys(doc, uuid),
        claims: account_claims(settings, req),
        mintable: match uuid {
            Some(u) => access
                .key_scopes_for(u)
                .iter()
                .map(|(a, s)| (a.name.as_str(), s.name.as_str()))
                .collect(),
            None => Vec::new(),
        },
        keys_path,
        rev,
        page,
        profile_path,
        profile_edit: profile_offered(settings),
        native: native_user(req).is_some(),
    }
}

/// Each configured claim, with the value this request actually carried for its derived header.
///
/// The claim names come from the settings and the values from the request, and keeping them in one
/// function is what makes "configured" and "forwarded" one list rather than two a renderer has to
/// line up by hand. `None` when no header arrived, and the page shows the name with the word for
/// none: a page that filled in a value nobody sent would be telling a person something the estate
/// never said.
fn account_claims<'a>(settings: &'a Settings, req: &Request) -> Vec<(&'a str, Option<String>)> {
    settings
        .profile_claims
        .iter()
        .map(|c| {
            (
                c.claim.as_str(),
                header_value(req, &c.header).map(pct_decode),
            )
        })
        .collect()
}

/// The values one delete line names, each in `code` and joined by `", "`: an address, a key id, a
/// group name is a value, and a person reads a value in the same face they read it in everywhere
/// else in this estate (§13.30 §2).
pub(crate) fn code_list(values: &[&str]) -> Markup {
    html! {
        @for (i, v) in values.iter().enumerate() {
            @if i > 0 { ", " }
            code { (v) }
        }
    }
}

/// The page a mint or a rotate answers with, and the one place this page ever renders a bearer.
///
/// Rendered **directly**, for the console's reason ([`page_minted`]): a redirect would put the
/// result behind a `GET` that has no bearer to show, and the bearer exists nowhere else. The
/// block is [`bearer_reveal`], the console's own: the key, the copy button and the script are one
/// rendering, so a person who mints from the console and from `/account/` sees one page, and the
/// words are the console's three, because "shown once, copy it now" is one fact with one spelling
/// in this program, and a person who sees it in two places must not read two claims. A rotate
/// lands on the same page for the same reason: it mints a secret, and the old one is already dead
/// at the next reload.
pub(crate) fn page_account_minted(lang: Lang, page: &str, bearer: &str) -> Markup {
    html! {
        (bearer_reveal(lang, bearer))
        p { a href=(page) { "← " (t(lang, K::Back)) } }
    }
}

/// The page a caller gets: who they are, as the header carried it, their uuid when the access file
/// has a row for them, and the four sections about their own account.
///
/// A stranger is named too: the `authenticated` scope §13.4 chose for this URL admits any
/// identity Cognito vouches for, so "bb-auth knows nothing about you" is a page a real caller
/// reaches, not a defensive one. A stranger and an administrator with no roster row get the same
/// page, because `web.admins` is not read here. Where there is **no** row the lede says nothing
/// about it (the user, 2026-11-26, PLAN.md step 13): the line under the addresses exists to name
/// an account id, so with no id to name the line and its `br` go, and the page writes no sentence
/// standing in for a row it does not have.
///
/// The sections are siblings, each a `.panel` whose `h2 class="tight"` is followed by one
/// `p.lede.sub` saying what that section is for, and whose empty state is a `p.muted` naming what
/// is missing. The page's contract is the one that made this page few keys: **which fact belongs
/// in which section**, so a sub-line says what a section is for and never states a fact that
/// belongs to another one.
///
/// The order is what a person **does** first (§13.26 §1): the two sections you act in, profile
/// and keys, then the two you read, groups and reach. The ids do not move with it, so no link and
/// no selector changes. The heading carries `tight` because the page is the console's column now
/// and the console writes the same rule at each of its headings; a rule scoped to this page is
/// what used to say it, and that rule was one of the width rules §13.26 deleted.
pub(crate) fn page_account(
    lang: Lang,
    ids: &[String],
    uuid: Option<&str>,
    own: &AccountOwn,
    row: Option<&NewKeyRow>,
    profile: Option<&ProfileForm>,
) -> Markup {
    html! {
        // One paragraph says who this page is about: every address of the row (as the gate sends
        // them), and on the line below the account these addresses resolve to. The bar already
        // says who is signed in, so the body does not say it twice. A caller with no row gets the
        // addresses alone: the second line names an id, and with no id there is no line and no
        // `br` to stand under it (step 13).
        p class="lede" {
            @for id in ids {
                code { (id) } " "
            }
            @if let Some(u) = uuid {
                br;
                (t(lang, K::AccountIdLabel)) ": " code class="uid" { (u) }
            }
        }
        section id="profile" class="panel" {
            h2 class="tight" { (t(lang, K::AccountProfile)) }
            // The sub-line says what this section is doing: reading, or editing. The edit page
            // says what happens after the form (a code by email), because that is the fact a
            // person needs before they type anything (§13.23 §2).
            p class="lede sub" {
                (t(lang, if profile.is_some() { K::AccountProfileEditSub } else { K::AccountProfileSub }))
            }
            @if let Some(f) = profile {
                // The form, on this page alone (`<prefix>/profile`, the `keys/new` pattern): the
                // panel is the section, and the section is what a caller of `/account/profile`
                // came to.
                (profile_form(lang, f, own.profile_path, own.page))
            } @else {
                @if own.claims.is_empty() {
                    p class="muted" { (t(lang, K::AccountProfileNone)) }
                } @else {
                    ul class="plain" {
                        @for (claim, value) in &own.claims {
                            li {
                                // A claim the design names a word for is called by that word, in
                                // the same words the form labels it with, so the panel and the
                                // form never call one field by two names. The rest keep the
                                // claim's own name, in code: it is the file's vocabulary, and a
                                // name nobody translated is the honest answer.
                                @if let Some(word) = profile_label(lang, claim) {
                                    (word)
                                } @else {
                                    code { (claim) }
                                }
                                ": "
                                // The value is the person's name or department, which is prose. A
                                // claim the deployment configured and the proxy did not forward is
                                // a fact about the wiring, and says so in words: a bare colon after
                                // a name reads as "your name is empty", a statement nobody made.
                                @if let Some(v) = value {
                                    (v)
                                } @else {
                                    span class="muted" { (t(lang, K::AccountNotProvided)) }
                                }
                            }
                        }
                    }
                }
                // The way in, and only where the edit can work: a pool, a native client, at least
                // one editable claim, and a session the gate named a Cognito user for (§13.25).
                // A control that can only end in an error is a promise the page cannot keep, so it
                // is absent, not disabled, and the person is told the reason in the sentence that
                // stands where the pill would be. A deployment with no pool says nothing about
                // editing at all: there is nothing to sign out and back into.
                @if own.profile_edit {
                    @if own.native {
                        p class="primary" {
                            (pill_link(own.profile_path, t(lang, K::AccountProfileEdit)))
                        }
                    } @else {
                        p class="muted" { (t(lang, K::AccountProfileNotNative)) }
                    }
                }
            }
        }
        section id="keys" class="panel" {
            h2 class="tight" { (t(lang, K::AccountKeys)) }
            p class="lede sub" { (t(lang, K::AccountKeysSub)) }
            // Ten keys close the row (§13.16), counting every key on the row. A sentence and not
            // a disabled control: a disabled control is skipped by the keyboard and says nothing
            // about why.
            @let full = own.keys.len() >= ACCOUNT_MAX_KEYS;
            @let open = if full { None } else { row.filter(|_| uuid.is_some()) };
            @if own.keys.is_empty() && open.is_none() {
                p class="muted" { (t(lang, K::AccountKeysNone)) }
            } @else {
                table {
                    thead { tr {
                        th { (t(lang, K::KeyColName)) }
                        th { (t(lang, K::Scopes)) }
                        th { (t(lang, K::ColExpiry)) }
                        th {}
                    } }
                    tbody {
                        @for k in &own.keys {
                            (account_key_line(lang, k, &own.mintable, own.keys_path, now()))
                        }
                        @if let Some(r) = open {
                            tr { (account_key_row(lang, own.keys_path, own.rev, own.page, &own.mintable, r)) }
                        }
                    }
                }
            }
            // The mint control, and only for a caller the file has a row for: a key is filed
            // under a uuid, so a stranger has no account to mint into, and a control that would
            // be refused before it was read is a promise the page cannot keep.
            @if uuid.is_some() {
                @if full {
                    @if let Some(e) = row.and_then(|r| r.err) { div class="err" { (e.msg) } }
                    p class="muted" { (t(lang, K::AccountKeyFullRow)) }
                } @else if row.is_none() {
                    p class="primary" {
                        (pill_link(
                            &format!("{}/new", own.keys_path),
                            t(lang, K::AccountKeyNew),
                        ))
                    }
                }
            }
        }
        section id="groups" class="panel" {
            h2 class="tight" { (t(lang, K::AccountGroups)) }
            p class="lede sub" { (t(lang, K::AccountGroupsSub)) }
            @if own.groups.is_empty() {
                p class="muted" { (t(lang, K::AccountGroupsNone)) }
            } @else {
                ul class="plain" {
                    @for g in &own.groups {
                        li { code { (g) } }
                    }
                }
            }
        }
        section id="reach" class="panel" {
            h2 class="tight" { (t(lang, K::AccountReach)) }
            p class="lede sub" { (t(lang, K::AccountReachSub)) }
            @if own.reached.is_empty() {
                p class="muted" { (t(lang, K::AccountReachNone)) }
            } @else {
                // One flat list of `app/scope` pairs, in the file's order: the question is "where
                // can I go", and each answer is one place. The console's person page lists them
                // the same way.
                ul class="plain" {
                    @for (app, scopes) in &own.reached {
                        @for scope in scopes {
                            li { code { (app) "/" (scope) } }
                        }
                    }
                }
            }
        }
    }
}

/// The uuid every address in the header resolves to, or `None` when the file has no row for any of
/// them. `Err` when they do not all resolve to the same one.
///
/// A stranger is `Ok(None)`, and reaches the page: the `authenticated` scope admits identities the
/// file has never heard of, and "bb-auth knows nothing about you" is a fact about the caller that
/// the page is the right place to say.
fn account_uuid_of<'a>(access: &'a Access, ids: &[String]) -> Result<Option<&'a str>, ()> {
    let mut found: Option<&str> = None;
    for id in ids {
        if let Some(u) = access.uuid_of(id) {
            match found {
                // Two addresses of one row name one uuid, and that is the ordinary case.
                Some(seen) if seen == u => {}
                Some(_) => return Err(()),
                None => found = Some(u),
            }
        }
    }
    Ok(found)
}

/// Answer one request under the self-service prefix.
///
/// The order is the console's own, and for the console's own reasons: the proxy secret has already
/// been proved by the caller here, so the first thing this does is read the identity, and the
/// `denied` veto is checked **ahead** of the row resolution that decides `500` vs `200`. The gate
/// refuses a vetoed identity before it reaches this page, so this is the second lock for a file
/// edited mid-request, and a lock a caller escapes by sending *less* is not a lock.
///
/// `web.admins` is never read. An administrator here is one more person acting on their own
/// account, and a list in the settings file must not become a second, invisible way to be granted
/// something on a page whose whole subject is the access file.
pub(crate) fn handle_account(
    req: Request,
    cfg: &Config,
    path: &str,
    query: &str,
    lang_pref: LangPref,
    lang: Lang,
    theme: UiTheme,
) {
    // The page's own URL: the prefix plus a slash. The form's `action` and the target of a
    // preference redirect are both this, and the bare prefix is answered as the page too, so
    // `/account` and `/account/` are one page rather than a page and a redirect.
    let page = format!("{}/", cfg.account_path);
    // The delete row's target (§13.30 §1). The row exists only where an intake is wired, because
    // it is the door to the worker: a deployment that never wired one shows nobody a door to
    // nothing, and this path stays the ordinary `404` every unknown path under the prefix gets.
    let delete_path = cfg
        .delete_intake
        .as_ref()
        .map(|_| format!("{}/delete", cfg.account_path));
    // The keys prefix, and the mint's `POST` target. A path and not a query flag because a
    // mutation is a `POST` to a URL that names the mutation, exactly as every console route does,
    // and because the keys section's form has to name it in its `action`.
    let keys = format!("{}/keys", cfg.account_path);
    // The two mutations every key of the caller's carries, one path below the mint's, each
    // naming its own verb for the same reason every console route does.
    let rotate = format!("{keys}/rotate");
    let remove = format!("{keys}/remove");
    // The mint row is a page of its own (§13.16): the keys section with one more row.
    let new_key = format!("{keys}/new");
    // The profile edit (§13.22) and its interface (§13.23): the panel with fields instead of
    // text, the `POST` target of those fields, and the code step the code page posts to. Each is
    // a path because each is a mutation with its own verb, exactly as every console route is.
    let profile = format!("{}/profile", cfg.account_path);
    let code = format!("{profile}/code");
    let posting = *req.method() == Method::Post;
    // The bar's identity starts empty and is filled as the facts behind it are read: the
    // address once nginx has named somebody, the given name once the settings say which
    // header carries it. A page answered before any of that (the `404`, the `401`) shows no
    // name, because there is nobody to name.
    let mut prefs = AccountPrefs {
        lang,
        lang_pref,
        theme,
        page: &page,
        who: None,
        logout: cfg.account_logout_url.as_deref(),
        delete: delete_path.as_deref(),
        page_lede: false,
    };
    // Below the prefix, only the page, the profile edit, the three key mutations and the delete
    // confirmation exist. A path that is nothing is a `404` for every caller alike, administrator
    // included, because a page that answers a stranger `403` and an administrator `404` is a page
    // describing its own layout to whoever asks. The confirmation is on the list only where an
    // intake is wired, so a deployment that never wired one answers its URL as the ordinary
    // nothing (§13.29 W2).
    if path != cfg.account_path
        && path != page
        && path != keys
        && path != rotate
        && path != remove
        && path != new_key
        && path != profile
        && path != code
        && delete_path.as_deref() != Some(path)
    {
        respond_account(
            req,
            404,
            &prefs,
            t(lang, K::NotFoundTitle),
            html! { p { (t(lang, K::NotFoundBody)) } },
            AccountLook::default(),
            false,
        );
        return;
    }
    // Identity comes from nginx and from nowhere else, exactly as it does for the console: a
    // missing header is a broken deployment, not an anonymous visitor, and this page's whole
    // subject is a person, so there is nothing to render without one.
    let raw = match header_value(&req, IDENTITY_HEADER) {
        Some(e) if !e.trim().is_empty() => e.to_string(),
        _ => {
            // The built-in look, and here there is no other: the settings have not been read, and
            // a request with no identity at all is not going to reach them.
            respond_account(
                req,
                401,
                &prefs,
                t(lang, K::NoIdentityTitle),
                html! { p { (t(lang, K::NoIdentityBody)) } },
                AccountLook::default(),
                false,
            );
            return;
        }
    };
    // The header is a list, not one address: the gate puts **every** email of the roster row into
    // it, joined by a single space. Every one of them is shown, because the page is about the
    // identity the estate handed over, not about one address picked out of it.
    let ids: Vec<String> = raw.split_ascii_whitespace().map(norm_email).collect();
    // The bar can name this person now, the address alone: the given name needs the settings.
    prefs.who = Some(who(None, &raw));
    // A preference is applied before anything is rendered, so the page a person lands on after a
    // submit is in the language and the appearance they just picked. `None` for a value nobody
    // recognises, which is what makes an unrecognised value set no cookie and leave the page as it
    // was.
    let want_theme = query_param(query, THEME_COOKIE).and_then(|v| parse_theme(&v));
    let want_lang = query_param(query, LANG_COOKIE).and_then(|v| parse_lang_pref(&v));
    if want_theme.is_some() || want_lang.is_some() {
        respond_account_preferences(req, &page, want_theme, want_lang);
        return;
    }
    // The settings, fresh off disk, for the same reason the console reads them per request: the
    // `ui` section is what makes one save restyle every surface of the estate at once.
    let settings = match open_settings_file(&cfg.settings_path) {
        Ok((_, s)) => s,
        Err(e) => {
            respond_account(
                req,
                500,
                &prefs,
                t(lang, K::FileErrorTitle),
                html! { p { (e) } },
                AccountLook::default(),
                false,
            );
            return;
        }
    };
    // The given name the bar shows, by the console's rule: it exists only where the deployment
    // configures the claim, since the settings are what say which header the proxy was told to
    // fill, and it is percent-decoded because the gate sends a profile value encoded.
    let given = settings
        .profile_claims
        .iter()
        .find(|c| c.claim == "given_name")
        .and_then(|c| header_value(&req, &c.header))
        .map(pct_decode);
    prefs.who = Some(who(given.as_deref(), &raw));
    let look = AccountLook {
        theme: settings.theme,
        stylesheet: settings.stylesheet_url.as_deref(),
        logo: settings.logo_url.as_deref(),
        brand: settings.brand_name.as_deref(),
    };
    // `gate.identity_attrs` without `email` means nginx injects no `X-Auth-Email`, so there is no
    // identity for this page to act on. The page names the setting, because the operator reading it
    // is the only person who can fix it.
    if !settings.identity_attrs.iter().any(|a| a.attr == "email") {
        respond_account(
            req,
            500,
            &prefs,
            t(lang, K::AccountNoEmailTitle),
            html! { p { (t(lang, K::AccountNoEmailBody)) } },
            look,
            false,
        );
        return;
    }
    // The access file, fresh off disk too: this page answers "what may I do", and an answer cached
    // from an earlier request is an answer about a file that is not the one the gate is enforcing.
    let (doc, access) = match open_access_file(&cfg.access_path) {
        Ok(pair) => pair,
        Err(e) => {
            respond_account(
                req,
                500,
                &prefs,
                t(lang, K::FileErrorTitle),
                html! { p { (e) } },
                look,
                false,
            );
            return;
        }
    };
    // The veto, ahead of everything the file has to say about grants.
    if ids.iter().any(|e| access.vetoes_identifier(e)) {
        respond_account(
            req,
            403,
            &prefs,
            t(lang, K::AccountVetoTitle),
            html! { p { (t(lang, K::AccountVetoBody)) } },
            look,
            false,
        );
        return;
    }
    // Every address in the header has to resolve to the **same** row. The gate builds the header
    // out of one row's emails, so several values that resolve to different rows is nginx having
    // written one header for two people, and there is no page that is about both.
    let uuid = match account_uuid_of(&access, &ids) {
        Ok(u) => u,
        Err(()) => {
            respond_account(
                req,
                500,
                &prefs,
                t(lang, K::AccountAmbiguousTitle),
                html! { p { (t(lang, K::AccountAmbiguousBody)) } },
                look,
                false,
            );
            return;
        }
    };
    // The mint, the one mutation this page offers, and the reason the file's exact bytes are
    // kept: the form's `rev` is the fingerprint of the file as this page renders it, the same
    // lost-update guard every console form carries.
    let bytes = match std::fs::read_to_string(&cfg.access_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            let msg = format!("read {}: {e}", cfg.access_path);
            respond_account(
                req,
                500,
                &prefs,
                t(lang, K::FileErrorTitle),
                html! { p { (msg) } },
                look,
                false,
            );
            return;
        }
    };
    let rev = sha256_hex(&bytes);
    // The facts the page is built out of, for a `GET` and for a `POST` alike: the profile
    // submission answers with the page around its form, and the panel that holds the form is
    // part of that page, so it needs the same facts the `GET` showed.
    let own = account_own(
        &doc, &access, &settings, &req, &ids, uuid, &keys, &rev, &page, &profile,
    );
    // A `POST` to one of the key paths, or to the profile edit, is answered here: after the
    // proxy secret, the identity, the veto and the row resolution, because each of those is a
    // refusal this submission has to meet on the same terms as the `GET` that rendered its form.
    if posting {
        if path == code {
            account_profile_code_post(req, cfg, &mut prefs, lang, look, &settings, &profile, &page);
            return;
        }
        if path == profile {
            account_profile_post(
                req, cfg, &mut prefs, lang, look, &settings, &ids, uuid, &own, &profile, &page,
            );
            return;
        }
        // The delete `POST` is claimed here for the same reason the mint guard was: every path
        // this branch does not claim is the mint below, and a submission to the delete URL that
        // fell through would mint an API key on the page that asks to delete the row.
        if delete_path.as_deref() == Some(path) {
            account_delete_post(
                req,
                cfg,
                &mut prefs,
                lang,
                look,
                &ids,
                uuid,
                &own,
                &settings,
                cfg.delete_intake.as_deref(),
                path,
                &page,
                &rev,
            );
            return;
        }
        let op = if path == rotate {
            AccountKeyOp::Rotate
        } else if path == remove {
            AccountKeyOp::Remove
        } else {
            AccountKeyOp::Mint
        };
        account_key_post(
            req, cfg, &prefs, lang, look, uuid, op, &settings, &ids, &keys, &profile,
        );
        return;
    }
    // The three pages that are about one key or one row exist for a caller with a row, and a
    // stranger gets the page's own refusal for them, exactly as the mutations give it.
    let wants_row = path == new_key || path == rotate || path == remove;
    if wants_row && uuid.is_none() {
        respond_account(
            req,
            403,
            &prefs,
            t(lang, K::AccountNoRowTitle),
            html! { p { (t(lang, K::AccountNoRowBody)) } },
            look,
            false,
        );
        return;
    }
    if path == rotate || path == remove {
        // The caller's own row only, and every miss is one `404` that names nothing: an unknown
        // id, no id at all and a key filed under somebody else are the same answer, so the page
        // is not an oracle for which ids exist on the estate.
        let id = query_param(query, "id").unwrap_or_default();
        if !own.keys.iter().any(|k| k.id.trim() == id) {
            respond_account(
                req,
                404,
                &prefs,
                t(lang, K::NotFoundTitle),
                html! { p { (t(lang, K::NotFoundBody)) } },
                look,
                false,
            );
            return;
        }
        let op = if path == rotate {
            AccountKeyOp::Rotate
        } else {
            AccountKeyOp::Remove
        };
        respond_account(
            req,
            200,
            &prefs,
            // The action word as the page title, so the shell's one `h1` and the `<title>` both
            // name what is about to happen, as the console's confirmation does (§13.17).
            t(lang, op.title()),
            page_account_confirm(lang, &page, &keys, &rev, &id, op),
            look,
            false,
        );
        return;
    }
    // The delete confirmation (§13.30 §2). It answers a caller with no roster row too, because the
    // sign-in accounts are theirs and are what the worker deletes, so it is not on the list of
    // paths that need a row. The page writes nothing and calls nothing: the intake is asked on the
    // `POST`, after the typed address and the `rev` (§13.29 W3).
    if delete_path.as_deref() == Some(path) {
        // The page carries its own lede (the irreversibility statement), so the bar's menu keeps
        // the identity out: the design counts one `p.lede` per page (§13.23 §3, §4).
        prefs.page_lede = true;
        respond_account(
            req,
            200,
            &prefs,
            t(lang, K::AccountDeleteTitle),
            page_account_delete(
                lang,
                path,
                &page,
                &rev,
                uuid,
                &ids,
                &own,
                &settings.audit_policy,
                "",
                None,
            ),
            look,
            false,
        );
        return;
    }
    // The edit form rides on one page only: `<prefix>/profile` is the panel with fields, and
    // every other page under the prefix shows the panel as read-only text (§13.22). A session the
    // gate named no Cognito user for gets the read-only panel on that path too (§13.25): the form
    // acts on one Cognito user, and a page with no user to act on is not an edit page, so its
    // title says the same thing the panel says.
    let form = (path == profile && own.native).then(|| ProfileForm::open(&settings, &req));
    respond_account(
        req,
        200,
        &prefs,
        if form.is_some() {
            t(lang, K::AccountProfileEdit)
        } else {
            t(lang, K::AccountTitle)
        },
        page_account(
            lang,
            &ids,
            uuid,
            &own,
            (path == new_key).then_some(&NewKeyRow::OPEN),
            form.as_ref(),
        ),
        look,
        false,
    );
}
