use crate::*;

// ---------------------------------------------------------------------------
// Filtering and paging a list
// ---------------------------------------------------------------------------
//
// Both live entirely in the query string, which is the only place they *can* live: a page
// here must work with scripting off, and a `GET` never mutates, so a filter is a form that
// navigates and a page is a link. That also makes both bookmarkable and survivable across a
// language change for free — `preserved_query` already carries every parameter but the two
// preferences through the Settings form.
//
// Each list namespaces its two parameters with a prefix (`uq`/`up`, `gq`/`gp`, …) so that
// several lists can sit on one page (as users, groups and denied do) without stealing
// each other's state.
//
// Scopes are deliberately NOT in this scheme. They are first-match-wins, their position is
// their meaning, and the ↑/↓ buttons move a scope within the *file*: a filtered view would
// show positions that are not the file's and a move that appears to do nothing. A list whose
// order is data does not get to be reordered by a search box.

/// Rows of one list per page.
pub(crate) const PAGE_SIZE: usize = 25;

/// One list's filter and page, read out of the query string.
pub(crate) struct Listing {
    /// Namespaces this list's two parameters. `""` is legal and means the page has one list.
    prefix: &'static str,
    /// The filter as typed, lowercased once so [`Listing::keeps`] does not do it per row.
    pub(crate) q: String,
    /// 0-based, as requested. [`Listing::window`] is what clamps it to what exists.
    page: usize,
    /// Whether the list is narrowed by something **besides** the box: the roster's group chip
    /// (§13.36 §5), which is a filter no field of the panel shows. A filter no box shows is a
    /// filter no box clears, so it has to count for the sentence the pager prints, and the
    /// panel answers it with a chip of its own.
    pub(crate) filtered: bool,
}

impl Listing {
    pub(crate) fn read(prefix: &'static str, query: &str) -> Listing {
        let q = query_param(query, &format!("{prefix}q")).unwrap_or_default();
        let page = query_param(query, &format!("{prefix}p"))
            .and_then(|p| p.trim().parse::<usize>().ok())
            .unwrap_or(1);
        Listing {
            prefix,
            q: q.trim().to_lowercase(),
            // Pages are 1-based in the URL, where a human reads them, and 0-based here.
            page: page.saturating_sub(1),
            // A caller whose list is narrowed by something outside the box says so.
            filtered: false,
        }
    }

    /// Does this row survive the filter? A plain case-insensitive substring, over whatever
    /// the caller decided the row's searchable text is — no globs, because the box next to a
    /// list of URL patterns must not look like it takes one.
    pub(crate) fn keeps(&self, hay: &str) -> bool {
        self.q.is_empty() || hay.to_lowercase().contains(&self.q)
    }

    /// The visible slice of `matched` rows, and how many pages there are.
    ///
    /// The page is clamped rather than refused: a filter that shrinks the list under the
    /// page someone was on is an ordinary thing to do, and answering it with an empty table
    /// would read as "nothing matches" when plenty does.
    pub(crate) fn window(&self, matched: usize) -> (usize, usize, usize, usize) {
        let pages = matched.div_ceil(PAGE_SIZE).max(1);
        let page = self.page.min(pages - 1);
        let start = page * PAGE_SIZE;
        (start, (start + PAGE_SIZE).min(matched), page, pages)
    }

    /// This list's own two parameter names.
    pub(crate) fn q_name(&self) -> String {
        format!("{}q", self.prefix)
    }
    pub(crate) fn p_name(&self) -> String {
        format!("{}p", self.prefix)
    }
}

/// An href for this page with this list's parameters replaced by `set`, everything else
/// kept: `[("up", "3")]` pages, `[]` clears both the filter and the page.
///
/// Every byte is a constant, a [`Route::path`] or a re-encoded parameter, so the result is
/// safe in an `href` for the same reason [`preference_href`]'s is.
pub(crate) fn listing_href(v: &View, l: &Listing, set: &[(String, String)]) -> String {
    let (q_name, p_name) = (l.q_name(), l.p_name());
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, val) in form_urlencoded::parse(v.query.as_bytes()) {
        if k != q_name && k != p_name {
            ser.append_pair(&k, &val);
        }
    }
    for (k, val) in set {
        ser.append_pair(k, val);
    }
    let q = ser.finish();
    if q.is_empty() {
        v.href(&v.at)
    } else {
        format!("{}?{q}", v.href(&v.at))
    }
}

/// This list's page `page` (1-based), with its filter kept.
fn page_href(v: &View, l: &Listing, page: usize) -> String {
    let mut set = Vec::new();
    if !l.q.is_empty() {
        set.push((l.q_name(), l.q.clone()));
    }
    set.push((l.p_name(), page.to_string()));
    listing_href(v, l, &set)
}

/// The filter box and the pager for one list, rendered above it.
///
/// The form is a `GET` back to this same route, exactly like the Settings menu: submitting
/// it *is* the navigation. Every other parameter on the page rides along as a hidden input
/// so filtering one list does not reset another's page — except this list's own page, which
/// is dropped on purpose, because a new filter belongs at the top of its results.
pub(crate) fn list_controls(v: &View, l: &Listing, matched: usize, total: usize) -> Markup {
    list_controls_named(v, l, matched, total, K::Filter)
}

/// [`list_controls`] where the box names what it searches. Only the roster's does today
/// (`K::FilterPeople`), because only its reach is wider than the column beside it: the box
/// finds a uuid and a key id too, and a box that says "filter" says nobody can (§13.36 §4).
pub(crate) fn list_controls_named(
    v: &View,
    l: &Listing,
    matched: usize,
    total: usize,
    ph: K,
) -> Markup {
    list_controls_with(v, l, matched, total, &[], html! {}, ph)
}

/// [`list_controls`] with fields of its own in front of the filter box.
///
/// `extra` is rendered inside the same form, so one submit applies the whole row and there is
/// one Apply button rather than one per control. `owned` names the parameters `extra` renders
/// itself: they are then left out of the hidden inputs, or every one of them would be
/// submitted twice and the page would read whichever value came last.
///
/// This exists for the audit, which is the only list here filtered by anything but text, and
/// it stays a parameter of the shared control rather than a second control beside it: two
/// forms over one list are two Apply buttons, and an operator who set a period and typed a
/// name would have to guess which one applies both.
pub(crate) fn list_controls_with(
    v: &View,
    l: &Listing,
    matched: usize,
    total: usize,
    owned: &[&str],
    extra: Markup,
    ph: K,
) -> Markup {
    let (start, end, page, pages) = l.window(matched);
    let q_name = l.q_name();
    let p_name = l.p_name();
    // Anything narrowing this list, from the box or from a control that is not a field.
    let narrowed = !l.q.is_empty() || l.filtered;
    // One sentence says where in the list this page sits, in place of the "page 2/5" fragment
    // and the bare "matched/total" span (§13.36 §4): the first row shown, the last, how many
    // matched, and while anything narrows the list, the list's whole length beside it.
    let rows = if !narrowed {
        fill(
            t(v.lang, K::PagerRows),
            &[
                &(start + 1).to_string(),
                &end.to_string(),
                &matched.to_string(),
            ],
        )
    } else {
        fill(
            t(v.lang, K::PagerRowsFiltered),
            &[
                &(start + 1).to_string(),
                &end.to_string(),
                &matched.to_string(),
                &total.to_string(),
            ],
        )
    };
    html! {
        div class="listctl" {
            form method="get" action=(v.href(&v.at)) {
                @for (k, val) in preserved_query(v.query) {
                    @if k != q_name && k != p_name && !owned.contains(&k.as_str()) {
                        input type="hidden" name=(k) value=(val);
                    }
                }
                (extra)
                input type="search" name=(q_name) value=(l.q) placeholder=(v.t(ph))
                      aria-label=(v.t(ph));
                // The page a submit lands on, spelled out rather than left to the absence of
                // `p`: a new filter belongs at the top of its results, and a field carrying the
                // first page says that to whoever reads the form.
                input type="hidden" name=(p_name) value="1";
                button type="submit" class="pill" { (v.t(K::Apply)) }
                @if !l.q.is_empty() {
                    a class="pill" href=(listing_href(v, l, &[])) title=(v.t(K::FilterClear)) { "×" }
                }
            }
            @if matched > 0 && (pages > 1 || narrowed) {
                span class="pager" {
                    // The words first, the two controls after them. With the sentence standing
                    // between them it was squeezed into a column one word wide at 320px in
                    // Italian (§13.36 §4, measured).
                    span class="muted" { (rows) }
                    @if pages > 1 {
                        @if page > 0 {
                            a class="pill" href=(page_href(v, l, page)) { "← " (v.t(K::PagePrev)) }
                        } @else {
                            span class="pill off" { "← " (v.t(K::PagePrev)) }
                        }
                        @if page + 1 < pages {
                            a class="pill" href=(page_href(v, l, page + 2)) { (v.t(K::PageNext)) " →" }
                        } @else {
                            span class="pill off" { (v.t(K::PageNext)) " →" }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

/// How this deployment asks its pages to look: the `ui` section of the settings file, as far
/// as [`shell`] is concerned.
///
/// It is a type of its own, and carried beside the visitor's own preference rather than folded
/// into it, because the two answer different questions and both have to survive to the page.
/// `theme` here is the deployment's default and `View::theme` is what this browser chose, so
/// the Settings menu can still show `System` as selected while the page renders dark.
///
/// [`Look::default`] is "nothing configured", and it is the honest answer on every page
/// rendered *before* the settings file has been read: a 401 from a missing identity header and
/// a 500 from a file that will not compile both happen above that read, and a page that cannot
/// know the operator's stylesheet must show the built-in one rather than guess.
#[derive(Clone, Copy, Default)]
pub(crate) struct Look<'a> {
    /// `ui.theme`: which arm of the palette a page starts in when the visitor has expressed no
    /// preference of their own.
    pub(crate) theme: UiTheme,
    /// `ui.stylesheet_url`: an operator's own stylesheet, loaded after the built-in one.
    pub(crate) stylesheet: Option<&'a str>,
    /// `ui.brand_name`: the deployment's name in the bar, so one settings read per request
    /// feeds every part of the look.
    pub(crate) brand: Option<&'a str>,
}

/// Everything the page shell needs that is not the page.
pub(crate) struct View<'a> {
    pub(crate) cfg: &'a Config,
    pub(crate) lang: Lang,
    /// Which option the Settings menu shows as the chosen language, which is not the same
    /// thing as `lang`: `Auto` renders as one of the two and must still come back as `Auto`
    /// (see [`LangPref`]). Both come from one [`negotiate_lang`] call.
    pub(crate) lang_pref: LangPref,
    /// Which appearance **this browser** asked for; see [`UiTheme`]. `System` unless the
    /// visitor chose otherwise, and it is its own chosen-option marker in the Settings menu,
    /// `System` included, which is why the choice needs no second field beside this one.
    ///
    /// It is not, on its own, what the page renders in: `System` means "no choice", and
    /// [`shell`] then falls through to the deployment's own [`Look::theme`] before leaving the
    /// decision to the OS.
    pub(crate) theme: UiTheme,
    /// Which clock **this browser** reads the audit in; see [`TzPref`]. Only the audit page
    /// looks at it, and it is carried here with the other two preferences because it comes
    /// from the same place (a cookie) for the same reason (a preference outlives a page).
    pub(crate) tz: TzPref,
    /// Whether the Settings page opens folded; see [`GroupsPref`].
    pub(crate) groups: GroupsPref,
    /// The audit's rotation and retention, from the same settings read as everything else on
    /// the page: the Audit tab shows no event the retention says is gone, whether or not the
    /// gate's hourly maintenance has reached it yet.
    pub(crate) audit: AuditPolicy,
    /// How this deployment asks the page to look. See [`Look`].
    pub(crate) look: Look<'a>,
    /// The signed-in administrator, when there is one. `None` suppresses the navigation:
    /// a visitor who got a `401` or a `403` has nowhere to go but the login page.
    pub(crate) admin: Option<&'a str>,
    /// The route being rendered, for the current tab and the language switch.
    pub(crate) at: Route,
    /// The query as received, so switching language keeps an access check's fields filled in.
    pub(crate) query: &'a str,
    /// sha256 of the access file's exact bytes as this request read them. Every form on the
    /// page carries it, and the `POST` that comes back must still match — see [`mutate`].
    /// Empty when the file could not be read, in which case there is no form to render.
    pub(crate) rev: &'a str,
    /// What the redirect that landed here says it did, if this binary said it ([`Msg`]).
    pub(crate) msg: Option<Msg>,
    /// The header names an authorized `204` will actually carry, derived from
    /// `gate.identity_attrs` by the library exactly as the gate derives them.
    ///
    /// Here because the access check answers "what will the application receive?", and that
    /// is a question about *this* deployment's settings. It used to answer with the literal
    /// `X-Auth-Email`, two clicks from the Settings field that can make it `X-Auth-Uuid` and
    /// nothing else, so the one page whose whole job is to predict the gate's behaviour was
    /// the page describing a header that would never arrive.
    pub(crate) identity: Vec<String>,
}

impl View<'_> {
    pub(crate) fn t(&self, key: K) -> &'static str {
        t(self.lang, key)
    }

    /// An absolute href for one of our own routes.
    pub(crate) fn href(&self, at: &Route) -> String {
        format!("{}{}", self.cfg.base_path, at.path())
    }
}

/// Who the bar says is signed in, in the two pieces the account menu needs: the **one** string
/// the trigger shows, and **every** address of the identity header for the panel to print.
///
/// The header is a list and not one address: the gate puts **every** email of the roster row
/// into it, joined by a single space (see `handle`), and a row with three addresses is one
/// person. Naming all three in a bar that has a few characters of room would be a second
/// sentence about the same person, so the bar names the one the person signs in as and the
/// panel prints the rest.
///
/// The given name is decoration from a profile claim, and a deployment that does not configure
/// `given_name` forwards no header at all. The address alone is then the whole label, which is
/// why this takes an `Option` and answers the address alone for a name that is empty: a trigger
/// reading `· bot@example.com` is a trigger with a hole in it.
pub(crate) struct Who {
    /// The trigger's visible label: a name, else an address, never both and never a separator.
    pub(crate) label: String,
    /// Every address of `X-Auth-Email`, in the order the gate wrote them.
    pub(crate) emails: Vec<String>,
    /// The name alone, when there is one: the panel prints it in `strong` above the addresses,
    /// and `label` is the same word cut to one line. `None` is "no name", which is why the
    /// trigger shows an address.
    pub(crate) name: Option<String>,
}

/// [`Who`] from the two headers. See the struct.
pub(crate) fn who(given_name: Option<&str>, email_header: &str) -> Who {
    let emails: Vec<String> = email_header
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect();
    let name = given_name
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    let label = name
        .clone()
        .or_else(|| emails.first().cloned())
        .unwrap_or_default();
    Who {
        label,
        emails,
        name,
    }
}

/// The bar every page of this program wears, as four slots: the navigation menu, the brand,
/// the tabs, and the account end.
///
/// Factored out of [`shell`] because the self-service page wears the same bar (§13.17), and
/// two copies of one bar is how two surfaces drift a pixel at a time, each editor changing the
/// file in front of them. The slots are markup and not a type because that is all the two
/// surfaces differ on: the account page has no tabs to move and no ☰ to move them in. Every
/// class is `admin.css`'s already, so a slot that arrives with one of its own is the thing to
/// fix.
pub(crate) fn top_bar(navn: Markup, brand: Markup, tabs: Markup, acct: Markup) -> Markup {
    html! {
        header class="top" {
            div class="bar" {
                (navn)
                (brand)
                (tabs)
                (acct)
            }
        }
    }
}

/// The brand slot of both shells: the operator's mark and the name (§13.28 §6, §7, as §13.34
/// §10 and §11 end it). It is a `span` on **every** surface, with no `href`: `/account/` is the
/// only page of its surface and the `403` names a console the caller may not open, and the
/// console's Dashboard tab beside the slot is the way home, so a link there would name a page the
/// bar already names. `extra` carries the page's own class (`selfserve-brand`), which is
/// arrangement and not the slot's own shape.
///
/// One function because the mark and the name are one object on both surfaces: two call sites
/// drawing the same pair is how a logo arrives in one bar and not the other, which is the drift
/// this file keeps writing rules about. The `alt` is empty because the name beside the picture
/// already says what it is. At 640px and below the bar shows the **mark** and hides the words
/// (§13.34 §12g, the user's reversal of 2026-11-27, which is the phone arm as §13.28 §4 wrote
/// it), and the words are hidden visually only: `admin.css` clips them to a 1px box, so they
/// stay in the accessibility tree and a reader hears the deployment's name from them, once. An
/// `alt` naming the picture would say it twice to that reader.
pub(crate) fn brand_block(name: &str, logo: Option<&str>, extra: &str) -> Markup {
    let cls = if extra.is_empty() {
        "brand".to_string()
    } else {
        format!("brand {extra}")
    };
    html! {
        span class=(cls) {
            @if let Some(src) = logo {
                img src=(src) alt="";
            }
            span class="t" { (name) }
        }
    }
}

/// The Preferences form, shared by both shells (§13.28 §3, §7).
///
/// One function because the two surfaces have **one** form: step 13 (PLAN.md) gave the
/// self-service page the console's behaviour, so the two list boxes submit themselves through
/// [`SETTINGS_ONCHANGE`] on both, and Apply rides in a `noscript` on both as the way in for a
/// browser running no code. The flag that used to make the page's copy plain is gone, and with
/// it the second shape of the form: two copies is how one list box gains a third option on one
/// surface only, which is the drift this file keeps writing rules about. `action` is the page
/// the `GET` returns to, and `hidden` re-carries the query the page was read with, so choosing
/// a theme from a filtered list does not throw the filter away.
pub(crate) fn prefs_form(
    lang: Lang,
    lang_pref: LangPref,
    theme: UiTheme,
    action: &str,
    hidden: &[(String, String)],
) -> Markup {
    // Both lead with the choice that follows something outside this GUI (the browser, the OS),
    // because that is where every session starts and what the other options are departures from.
    let langs = [
        LangPref::Auto,
        LangPref::Fixed(Lang::En),
        LangPref::Fixed(Lang::It),
    ];
    let themes = [UiTheme::System, UiTheme::Light, UiTheme::Dark];
    html! {
        form class="edit" method="get" action=(action) {
            @for (k, val) in hidden {
                input type="hidden" name=(k) value=(val);
            }
            label {
                span class="lbl" { (t(lang, K::SettingLanguage)) }
                select name=(LANG_COOKIE) onchange=(SETTINGS_ONCHANGE) {
                    @for p in langs {
                        option value=(p.code()) selected[p == lang_pref] { (p.label(lang)) }
                    }
                }
            }
            label {
                span class="lbl" { (t(lang, K::SettingTheme)) }
                select name=(THEME_COOKIE) onchange=(SETTINGS_ONCHANGE) {
                    @for th in themes {
                        option value=(th.code()) selected[th == theme] {
                            (t(lang, theme_label(th)))
                        }
                    }
                }
            }
            // The way in for a browser with scripting off. The browser parses the `noscript`
            // block as text, so with scripting on the button is not in the DOM at all and
            // picking an option is the whole interaction.
            noscript { div class="actions" { button { (t(lang, K::Apply)) } } }
        }
    }
}

/// The account menu both shells wear (§13.28 §1, §2, §3): one trigger that opens one panel.
///
/// The trigger is the person's own name, because the bar has a few characters of room and a
/// name is what a person recognises in it; the word "account menu" rides along inside the
/// control, visually hidden, so a reader is told what the name **is** rather than left with a
/// word that reads as a heading. The panel says who they are in full, offers the places this
/// menu has (`places`: §13.34 leaves the console's one, the caller's own page, and the
/// self-service page has none), the nested Preferences box, and Sign out, and ends in the delete
/// row on the one surface that offers it.
///
/// The panel is a `details` for the reason §13.20 gave: it opens with no script, closes by
/// itself when a row navigates away, and its trigger keeps the light-dismiss cover the console
/// already has. The nested box gets no cover of its own, so it toggles only from its own row.
/// `logout` is `None` when the operator named no destination, and then there is no row.
///
/// `grouped` is whether the bar carries a ☰ beside this menu (§13.34 §2), and it is a parameter
/// because the answer is not this function's to read: the console's pages have one, `/account/`
/// has one, and the console's `403` has none, because a page with no tabs has no tab strip to
/// move. `name="bar-menu"` is the exclusive-open group, and it groups **two** boxes, so a page
/// with one menu names a group nothing else belongs to. A group of one is not a rule, it is a
/// claim about a control that is not on the page.
///
/// The panel's groups are divided by a rule on **both** surfaces (§13.34 §3): one ahead of
/// Preferences, one ahead of Sign out. A rule that appears only where the console has places is
/// how the two panels stopped being one object, which is what `the_account_menu_is_one_object`
/// reads as the ordered list of classes.
///
/// `delete` is the self-service page's last row (§13.30 §1), and `None` is the whole reason it
/// is a parameter rather than something read here: the console's panel never carries it, and the
/// page carries it only where an intake is wired.
pub(crate) fn account_menu(
    lang: Lang,
    who: Option<&Who>,
    places: Option<Markup>,
    prefs: Markup,
    logout: Option<&str>,
    delete: Option<&str>,
    grouped: bool,
) -> Markup {
    let label = who.map(|w| w.label.as_str()).unwrap_or("");
    let menu_word = format!(", {}", t(lang, K::AccountMenu));
    let group = grouped.then_some("bar-menu");
    html! {
        details class="settings" name=[group] {
            // The name, the caret, and the word that names the control. `title` carries the full
            // label because the ellipsis may cut it, and a tooltip is the one place a cut name is
            // still the whole name.
            summary class="pill who" title=(label) {
                span class="who-name" { (label) }
                span class="vh" { (menu_word) }
                svg class="i-caret" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                    path d="M6 9l6 6 6-6" {}
                }
            }
            div class="menu" {
                // Who the name is, in full: every address of the roster row, because a caller is
                // their whole row and not the one address the bar had room for. No uuid: the
                // panel is read by a person, and an id is what the account page names under its
                // own label.
                @if let Some(w) = who {
                    p class="who-full" {
                        @if let Some(n) = &w.name {
                            strong { (n) }
                        }
                        @for e in &w.emails {
                            span class="addr muted" { (e) }
                        }
                    }
                }
                // The console's places, and the rule that divides them from the rows below (§13.34
                // §3). A caller with no places gets no container and no rule at all, which is what
                // keeps the `403` from offering a page it has refused. The rule is an `hr` and not
                // the panel's `div.sep`, because the panel must stay **one object** across the two
                // surfaces: `the_account_menu_is_one_object` reads the ordered list of classes the
                // panel emits once its two surface-only blocks are out, and a classed rule that
                // only the console emits is exactly the difference that test is there to catch.
                // `hr` is the element for a thematic break, so the divider is semantics with no
                // class to drift, and it sits after the places block, not inside it: the block is
                // the places, and a rule closing it would divide the block from itself.
                @if let Some(p) = places {
                    div class="menu-places" {
                        (p)
                    }
                    hr;
                }
                details class="prefs" {
                    // The sliders, and the word "Preferences": the panel's rows are places to go
                    // and this one is not, and the row that opens the two display choices must
                    // not read as the System settings page beside it.
                    summary class="pill" {
                        svg class="i-sliders" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                            path d="M3 6h12" {}
                            circle cx="18" cy="6" r="2.5" {}
                            path d="M9 12h12" {}
                            circle cx="6" cy="12" r="2.5" {}
                            path d="M3 18h8" {}
                            circle cx="14" cy="18" r="2.5" {}
                        }
                        (t(lang, K::Settings))
                    }
                    (prefs)
                }
                // Sign out behind the last rule: it is the row that leaves the estate, and the
                // rule is what separates it from the rows that only change how the estate looks.
                @if let Some(u) = logout {
                    div class="sep" {}
                    a class="pill" href=(u) {
                        svg class="i-out" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                            path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" {}
                            path d="M16 17l5-5-5-5" {}
                            path d="M21 12H9" {}
                        }
                        (t(lang, K::SignOut))
                    }
                }
                // The delete row, last (§13.30 §1). It is a link to the page that asks, not a
                // submission: a `GET` never mutates, and a browser prefetches the last row of an
                // open menu, which must not cost a person their account. The words name what the
                // press costs, because the worker's deletion is the one action on this estate
                // nobody can undo, and the glyph is decoration behind `aria-hidden`, so the
                // visible word stays the accessible name. A trash can and not the keys table's
                // `×`: at the bottom of a panel an `×` reads as "close this".
                @if let Some(href) = delete {
                    div class="sep" {}
                    a class="pill rm" href=(href) {
                        svg class="i-trash" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                            path d="M3 6h18" {}
                            path d="M8 6V4h8v2" {}
                            path d="M6 6l1 14h10l1-14" {}
                        }
                        (t(lang, K::AccountDelete))
                    }
                }
            }
        }
    }
}

/// The document skeleton both HTML surfaces of this program wear: the doctype, `<html>` stamped
/// with the language and with the theme when one is chosen, the head, and `body` as the whole
/// contents of the `<body>` element.
///
/// One function for both surfaces, because the head is the part the estate's safety argument
/// rests on: a page's `Content-Security-Policy` carries the hash of the three inlined
/// stylesheets **as one string** (see [`admin_csp`] and [`account_csp`]), so a head that emitted
/// them in another order, or with whitespace between them, is a page whose own policy refuses
/// its own look. Two heads written by hand is two chances for that to drift, and the drift is
/// invisible from inside either one.
///
/// The three stylesheets are the deliberately raw emissions on any page, and all three are
/// compile-time constants: never request data and never anything read out of the access file.
/// Their order is the contract: the palette, the components built out of it (the same bytes the
/// gate's pages get), the layout that arranges them, then whatever the operator wants to say
/// over the top.
///
/// `theme_attr` is the resolved theme's spelling, and the caller resolves the fallback order
/// (this browser's choice, then the deployment's default, then nothing). It is optional in the
/// type as well as in the markup: `None` omits `data-theme` outright rather than emitting
/// `data-theme=""`, because an empty attribute is one the palette's `[data-theme=…]` selectors
/// do not match, and leaving it off is what lets the `prefers-color-scheme` rule in `THEME_CSS`
/// be the one deciding.
///
/// `title` is the **whole** `<title>` text, escaped, and this function adds no prefix of its
/// own: that is what lets the console say `bb-auth-web · …` and the self-service page say
/// `{brand} · …` from the one skeleton.
///
/// `stylesheet` is the operator's own stylesheet, linked **after** the `<style>` so an override
/// wins by source order and needs no `!important`; `None` links nothing at all, because the
/// built-in look is complete and a deployment that configured nothing fetches nothing (a host
/// that is down then costs a page its palette and nothing else). The link is raw because the
/// library builds a whole `<link>` element out of a URL that has already passed
/// `compile_asset_url`, and maud has no way to say "an element" except in maud.
pub(crate) fn page_document(
    lang: Lang,
    theme_attr: Option<&str>,
    title: &str,
    stylesheet: Option<&str>,
    body: Markup,
) -> Markup {
    html! {
        (DOCTYPE)
        html lang=(lang.code()) data-theme=[theme_attr] {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { (title) }
                style { (PreEscaped(THEME_CSS)) (PreEscaped(BASE_CSS)) (PreEscaped(CSS)) }
                (PreEscaped(stylesheet_link(stylesheet)))
            }
            body { (body) }
        }
    }
}

/// The chrome around every page: the tabs, the account menu, the footer.
///
/// [`shell_as`] with no given name, no identity header and no logo to show, which is the
/// honest answer for a page built from a [`View`] nobody made from a request: there is no
/// forwarded claim and no settings read on one, so the bar says the address alone and shows
/// no mark.
pub(crate) fn shell(v: &View, title: &str, content: Markup) -> Markup {
    shell_as(v, None, "", None, title, content)
}

/// [`shell`] for a page rendered out of a request, which is the only place the bar's two
/// facts exist: the given name the proxy forwarded for the `given_name` claim (`None` when
/// the deployment does not configure it), and the whole identity header, `emails`: the gate
/// puts **every** email of the roster row into it, and a caller admitted by their second
/// address reads a panel naming every address they have, which is the answer the account page
/// already gives (§13.28 §2). `logo` is the deployment's `ui.logo_url`, the same `Option` the
/// response's policy is built from. The name goes in the bar beside the session controls and
/// at the top of the Preferences menu, and nowhere else: the footer used to say it too, and
/// one fact in two places is one fact that starts disagreeing with itself.
pub(crate) fn shell_as(
    v: &View,
    given_name: Option<&str>,
    emails: &str,
    logo: Option<&str>,
    title: &str,
    content: Markup,
) -> Markup {
    let ident = if emails.trim().is_empty() {
        v.admin.unwrap_or_default()
    } else {
        emails
    };
    shell_named(
        v,
        v.admin.map(|_| who(given_name, ident)),
        logo,
        title,
        content,
    )
}

/// [`shell_as`] with the bar's identity **given** rather than read out of `v.admin`.
///
/// The console's `403` is the caller that needs it (§13.17). That page has to name the person
/// it is refusing, and `v.admin` is `None` there precisely because the allowlist said no, so
/// deriving the label from it leaves the bar empty on the one page where the reader most needs
/// to see who the sentence is about. The tabs and the brand stay keyed on `v.admin`, which is
/// what makes "an identity in the bar, no tabs" expressible: that pair *is* the refusal. The
/// identity arrives as a built [`Who`] because each caller builds it out of two headers. One
/// identity in and not two computed out of it: the bar and the panel render the same facts,
/// and on a phone the panel is the only one of the two left standing, because the bar would
/// wrap to a second line to hold the name.
pub(crate) fn shell_named(
    v: &View,
    who: Option<Who>,
    logo: Option<&str>,
    title: &str,
    content: Markup,
) -> Markup {
    // Five tabs, Settings last (§13.34 §1): it is the page the bar's own row has room for, and
    // the row a phone reaches last through the ☰. The word is `K::ConfigTab` and not
    // `K::Config`, because the strip has to fit the bar and the page's heading can say what the
    // page is; the two words are pinned apart by `aria_current_names_the_page`.
    let tabs = [
        (Route::Dashboard, v.t(K::Dashboard)),
        (Route::Apps, v.t(K::Apps)),
        (Route::Users, v.t(K::Users)),
        (Route::Audit, v.t(K::Audit)),
        (Route::Config, v.t(K::ConfigTab)),
    ];
    let current = v.at.tab();
    // The brand says the deployment's name, in one line, in one shape on every surface: no tag
    // under it (§13.34 §10) and no link on it (§13.34 §11, the user's decision). The name is
    // `ui.brand_name` so the console's bar and `/account/` name the same deployment (§13.18),
    // and the tag is gone because what it said is said by the five tabs, the page's `h1` and the
    // `<title>`, and on a 1280px screen it was the word being cut. A link would lead to the page
    // the Dashboard tab beside it already names, so the slot is a `span` here as it is on
    // `/account/` and on the `403`.
    let name = v
        .look
        .brand
        .map(str::to_string)
        .unwrap_or_else(|| DEFAULT_ACCOUNT_BRAND.to_string());
    let brand = brand_block(&name, logo, "");
    // The strip, and the same four rows inside the panel, from one loop (§13.28 §4): moving one
    // element between the bar and a closed `details` cannot be done in CSS, so the links are
    // emitted twice and exactly one copy is displayed. `aria-current="page"` is the word a
    // reader hears for "you are here", because `.on` is a colour and colour alone is not a
    // distinction WCAG 1.3.1 accepts.
    // The strip's links, and the ☰'s copy of them, from one loop (§13.28 §4, §13.34 §1): moving
    // an element between the bar and a closed `details` cannot be done in CSS, so the links are
    // emitted twice and exactly one copy is displayed, which is also why the panel's rows are
    // `.pill`s, so the copy that appears is the same object as the copy it replaces.
    // `aria-current="page"` is the word a reader hears for "you are here", because `.on` is a
    // colour and colour alone is not a distinction WCAG 1.3.1 accepts.
    let tab_links = html! {
        @for (r, label) in &tabs {
            a class=@if *r == current { "pill on" } @else { "pill" }
              href=(v.href(r)) aria-current=[(*r == current).then_some("page")] { (label) }
        }
    };
    // The strip is named `tabs` so the breakpoint rule can hide it by name: with the ☰ in the
    // bar, `nav:not(.acct)` would hide that too (§13.34 §2). A page with no places to move
    // carries an empty strip, which is what keeps the bar's slots one shape on both surfaces.
    let tab_nav = html! {
        @if v.admin.is_some() { nav class="tabs" { (tab_links) } } @else { nav class="tabs" {} }
    };
    // The bar's navigation menu (§13.34 §2): the phone's tab strip, and the tabs' only home at
    // and below the breakpoint. It is a `nav` because it is navigation, which also gives its
    // rows the quiet tab look of `nav .pill`. `name="bar-menu"` puts it in one exclusive group
    // with the account menu, so opening one shuts the other with no script; the nested
    // `details.prefs` stays out of that group, or opening Preferences would close the menu it
    // sits in. The trigger is the glyph plus `K::NavMenu` in `span.vh`: a `summary` has no ARIA
    // role, so the name is hidden text and not `aria-label`, and `title` is the tooltip for the
    // pointer. A `403` names no console page, so it gets no ☰ at all: a page with no tabs has
    // no tab strip to move.
    let nav_word = v.t(K::NavMenu);
    let navn = v
        .admin
        .map(|_| {
            html! {
                nav class="navm" {
                    details class="settings navmenu" name="bar-menu" {
                        summary class="pill ico" title=(nav_word) {
                            svg class="i-menu" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                                path d="M4 6h16" {}
                                path d="M4 12h16" {}
                                path d="M4 18h16" {}
                            }
                            span class="vh" { (nav_word) }
                        }
                        div class="menu" {
                            div class="menu-tabs" { (tab_links) }
                        }
                    }
                }
            }
        })
    .unwrap_or_default();
    // The console's places, in the account panel: one row, the caller's own page (§13.34 §3).
    // The tabs left it for the ☰ and the settings page left it for the strip, so a row to
    // either here would be two answers to one question, one of them a row a phone cannot reach.
    // `v.admin` is the gate: a caller the allowlist refused is offered no console page at all,
    // and gets no `div.menu-places` to be offered in.
    let account_word = v.t(K::NotAdminToAccount);
    let account_href = format!("{}/", v.cfg.account_path);
    let places = v.admin.map(|_| {
        html! {
            // The row wears a glyph as every other row of the panel does (§13.34 §3, the
            // review of 2026-11-26): bare text among drawn marks starts left of its
            // neighbours and reads as the odd row out of a list of places. The person
            // outline says what the row is the page of, and it is **decoration** behind
            // `aria-hidden`: the visible word stays the row's name, in a language the reader
            // cannot see a glyph in and to a screen reader.
            a class="pill" href=(account_href) {
                svg class="i-person" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                    circle cx="12" cy="8" r="4" {}
                    path d="M4 20a8 8 0 0 1 16 0" {}
                }
                (account_word)
            }
        }
    });
    let prefs = prefs_form(
        v.lang,
        v.lang_pref,
        v.theme,
        &v.href(&v.at),
        &preserved_query(v.query),
    );
    // The account end of the bar, and it is a `nav` for the same reason the tabs are: it makes
    // these controls flex items of a flex row, exactly as the tabs are. One menu, opened by the
    // person's own name, replaces the identity span, the sliders trigger and the Sign out icon
    // of §13.17 and the Preferences menu of §13.20.
    //
    // Sign out is rendered even without an administrator, unlike the places: the `403` page is
    // exactly where this is most useful, because the way out of "you are signed in as somebody
    // who may not use this" is to end that session and start another. It is a plain link and not
    // a form: the gate's `/auth/logout` is a `GET` that clears the cookie and redirects, guarded
    // there against cross-site navigation.
    let acct = html! {
        nav class="acct" {
            (account_menu(
                v.lang,
                who.as_ref(),
                places,
                prefs,
                v.cfg.logout_url.as_deref(),
                // No delete row here (§13.28 §5): this surface edits **other people's** accounts,
                // and a person deletes their own on the page under the account prefix.
                None,
                // The ☰ is in this bar exactly where it is, so the two menus are one group
                // exactly where there are two menus to group (§13.34 §2).
                v.admin.is_some(),
            ))
        }
    };
    page_document(
        v.lang,
        v.theme.attr().or(v.look.theme.attr()),
        &format!("bb-auth-web · {title}"),
        v.look.stylesheet,
        html! {
            (top_bar(navn, brand, tab_nav, acct))
            main {
                // The one thing a redirect is allowed to say, from a closed set.
                @if let Some(msg) = v.msg {
                    div class="flash" { (msg.text(v.lang)) }
                }
                (content)
            }
            footer {
                // No reload hint: `bb-auth-reload.path` watches the file and reloads the
                // gate on every save, so telling an administrator to run
                // `systemctl reload bb-auth` would describe work nobody has to do.
                //
                // And no "signed in as": the bar above says it, where the session controls
                // are, and a fact kept in two places is a fact that starts disagreeing
                // with itself one edit at a time.
                // What these bytes were built from, which the version in the bar cannot
                // say: a `.deb` reads 1.99.1-1 for a clean release and for a working tree
                // somebody built by hand, and this is the one place a person can see
                // which of the two is answering.
                span class="muted" { code { (version_line("bb-auth-web")) } }
            }
        },
    )
}

/// What an unordered list looks like when it has nothing to show, which is **three** states
/// and not two.
///
/// "The file holds none of these" and "your filter matched none of them" are different
/// sentences and lead to different next actions, and every list on this GUI has to make that
/// distinction. It was made four times, in four page functions, each spelling out the same
/// three-armed `@if` around its own table: four places to change when the wording moves, and
/// four chances for one of them to say the wrong thing to somebody staring at an empty page.
///
/// `body` is rendered by the caller and passed in, because the four bodies have nothing in
/// common (a table, another table, a list, a run of panels) and pretending otherwise would be
/// the wrong abstraction: what is shared is the emptiness, not the content.
pub(crate) fn list_panel(v: &View, total: usize, shown: usize, body: Markup) -> Markup {
    html! {
        div class="panel" {
            @if total == 0 {
                span class="muted" { (v.t(K::None)) }
            } @else if shown == 0 {
                span class="muted" { (v.t(K::NoMatch)) }
            } @else {
                (body)
            }
        }
    }
}

/// [`list_panel`] for a list whose rows are panels of their own, so the empty states get a
/// panel and the rows are emitted bare.
pub(crate) fn list_rows(v: &View, total: usize, shown: usize, rows: Markup) -> Markup {
    html! {
        @if total == 0 || shown == 0 {
            (list_panel(v, total, shown, html! {}))
        } @else {
            (rows)
        }
    }
}

/// Every way into this deployment, and the app client each one runs through: one table, one
/// row per way, and a hidden field naming the set the page drew.
///
/// **A table, because a way in is three facts and only one of them is a choice.** What a
/// visitor reads on the button, the `identity_provider` Cognito matches byte for byte, and
/// the app client the sign-in runs through are three different things that a stacked list of
/// checkboxes ran together: `Microsoft` is the word on the button and `MicrosoftPersonal` is
/// the name Amazon knows, and an operator comparing this page with the Cognito console has to
/// see which is which.
///
/// **The email row is in it and has no checkbox**, which is the honest shape: the email path
/// is not something a deployment turns off, and its app client is the same kind of value as
/// every other row's. Leaving it out would have made the table look like the whole answer
/// while the most important app client lived somewhere else on the page.
///
/// The provider rows are [`SOCIAL_IDPS`] plus anything already in the file that is not in it,
/// in that order. The second half is what keeps this page honest about a file it did not
/// write: `bb-auth-adm` accepts any well-formed `identity_provider` name, a user pool may
/// federate a SAML or OIDC provider under a name nobody here anticipated, and a page that
/// rendered only the two it knows would quietly drop the third on the next save. Rendered, it
/// is named in the hidden field, so [`ConfigForm::read`] can keep it.
///
/// The hidden field is what makes that work without this function and `read` having to agree
/// twice: the form states what it offered, and the reader believes the form.
pub(crate) fn social_choices(v: &View, f: &ConfigForm, err: Option<&Refusal>) -> Markup {
    let about = |name: &str| err.is_some_and(|e| e.is(name));
    let offered = known_and_configured(&f.buttons);
    html! {
        div {
            span class="lbl" { (v.t(K::SignInWays)) }
            input type="hidden" name="idps" value=(offered.join(" "));
            table {
                thead { tr {
                    th { (v.t(K::ColShownAs)) }
                    // Cognito's own field name, untranslated, because it is what has to match
                    // on Amazon's side and a translated column heading would suggest it does
                    // not.
                    th class="mono" { "identity_provider" }
                    th { (v.t(K::ColAudience)) }
                } }
                tbody {
                    tr {
                        td data-label=(v.t(K::ColShownAs)) { (v.t(K::SignInEmail)) }
                        // An em-dash as data rather than prose: the email path is not
                        // federated, so this cell has nothing to name.
                        td class="mono muted" data-label="identity_provider" { "—" }
                        td data-label=(v.t(K::ColAudience)) {
                            input type="text" name="client_id" value=(f.client_id)
                                  placeholder="1h2j3k4l5m6n7o8p9q0r1s2t3u"
                                  class=(format!("f-aud{}", if about("client_id") { " invalid" } else { "" }))
                                  autocapitalize="off" spellcheck="false"
                                  aria-invalid=[about("client_id").then_some("true")]
                                  aria-describedby=[about("client_id").then_some(ERR_ID)];
                        }
                    }
                    @for idp in &offered {
                        @let field = aud_field(idp);
                        tr {
                            td data-label=(v.t(K::ColShownAs)) {
                                label class="radio" {
                                    input type="checkbox" name=(idp_field(idp)) value="on"
                                          checked[f.buttons.iter().any(|(e, _)| e.eq_ignore_ascii_case(idp))];
                                    span { (social_idp_label(idp)) }
                                }
                            }
                            td class="mono" data-label="identity_provider" { (idp) }
                            td data-label=(v.t(K::ColAudience)) {
                                input type="text" name=(field) value=(audience_of(&f.buttons, idp))
                                      placeholder="1h2j3k4l5m6n7o8p9q0r1s2t3u"
                                      class=(format!("f-aud{}", if about(&field) { " invalid" } else { "" }))
                                      autocapitalize="off" spellcheck="false"
                                      aria-invalid=[about(&field).then_some("true")]
                                      aria-describedby=[about(&field).then_some(ERR_ID)];
                            }
                        }
                    }
                }
            }
            span class="hint" { (v.t(K::SocialWaysHelp)) }
        }
    }
}

/// The app client the form holds for `idp`, or the empty string: what a row renders in its
/// last cell, whether or not the row is ticked.
fn audience_of(buttons: &[(String, String)], idp: &str) -> String {
    buttons
        .iter()
        .find(|(e, _)| e.eq_ignore_ascii_case(idp))
        .map(|(_, aud)| aud.clone())
        .unwrap_or_default()
}

/// The providers to draw a switch for: the ones this project knows, then any others the file
/// already enables, each exactly once.
fn known_and_configured(enabled: &[(String, String)]) -> Vec<String> {
    let mut out: Vec<String> = SOCIAL_IDPS.iter().map(|(idp, _)| idp.to_string()).collect();
    for (idp, _) in enabled {
        if !out.iter().any(|k| k.eq_ignore_ascii_case(idp)) {
            out.push(idp.clone());
        }
    }
    out
}

/// The form field name for one provider's checkbox. One function, because the renderer and
/// the reader must spell it the same way and there is no third caller to keep them honest.
pub(crate) fn idp_field(idp: &str) -> String {
    format!("idp-{idp}")
}

/// The form field name for one provider's app client, and a [`Refusal`]'s field name for it:
/// a bad app client is attributed to the row that carries it, which is the only way a table
/// of them can say which one it means.
pub(crate) fn aud_field(idp: &str) -> String {
    format!("aud-{idp}")
}

/// A rounded label — a `denied` badge, an expiry state, a scope's `access`.
pub(crate) fn tag(class: &str, text: &str) -> Markup {
    html! { span class=(format!("tag {class}")) { (text) } }
}

/// A top-level section page's `h1`: the descriptive, translated label the nav carries,
/// with the access file's own key for that section beside it in muted monospace. The label
/// is the headline; the key is what the docs, the CLI and the file itself all speak, so it
/// must not disappear, only stop being the first thing an operator reads.
pub(crate) fn section_heading(label: &str, key: &str) -> Markup {
    html! { (label) " " span class="muted mono" { (key) } }
}

/// A URL-pattern list as the file stores it. `@group` references are shown **raw, never
/// expanded**: the file is what an operator edits and what `bb-auth-adm` prints, so a page
/// that quietly substituted a group's patterns would be showing something nobody wrote.
pub(crate) fn url_list(lang: Lang, urls: Option<&Vec<String>>, absent: &str) -> Markup {
    url_list_marked(lang, urls, absent, |_| None)
}

/// [`url_list`] where a line may carry a warning tag after it: `mark` answers, per line, the
/// words to put there (or `None`). The words are text beside the line and not a colour, so a
/// reader that does not see colour hears them too (WCAG 1.4.1).
pub(crate) fn url_list_marked(
    lang: Lang,
    urls: Option<&Vec<String>>,
    absent: &str,
    mark: impl Fn(&str) -> Option<&'static str>,
) -> Markup {
    html! {
        @match urls {
            None => span class="muted" { (absent) },
            Some(l) if l.is_empty() => span class="bad" { "[] — " (t(lang, K::ReachesNothing)) },
            Some(l) => ul class="plain mono" {
                @for u in l {
                    li {
                        (u)
                        @if let Some(words) = mark(u) { " " (tag("warn", words)) }
                    }
                }
            },
        }
    }
}
