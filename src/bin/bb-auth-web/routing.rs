use crate::*;

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// A page. The four section routes are the access file's four sections, which is most of the
/// navigation: what the file has, the GUI has a tab for. [`Route::Config`] is the exception
/// and says so by being one: it edits the *other* file. Everything else is a form, a
/// confirmation, or the one `POST`-only route ([`Route::ScopeMove`]).
///
/// A route that mutates is reached by `POST` on **the same path** that renders its form by
/// `GET`, which is what makes "re-render this form with the library's refusal" a matter of
/// calling the same page function again. The names a route carries — an email, a key id, an
/// application, scope or group name — are already percent-**decoded**.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Route {
    Dashboard,
    /// The applications, which is where every grant in the file is written.
    Apps,
    /// One application and its scopes, in file order.
    App(String),
    Denied,
    Users,
    /// The `user_groups` list, the users tab's Groups sub-page. It has always had the URL;
    /// §13.36 §1 made it the page that URL shows, instead of the roster's page.
    Groups,
    /// One roster row, addressed by its uuid: the identity is what the file references,
    /// and an email can be added or dropped without the page moving.
    User(String),
    /// The audit: what the gate has actually answered, which is the one page here that reads
    /// neither file and edits nothing. It sits between the people and the settings because it
    /// is about the people, one step later: `users` says who *may* get in, this says who did.
    Audit,
    /// The settings file, which is not a section of the access file at all: the five values
    /// the gate reads per request, and the list of people this GUI opens for.
    Config,

    AppAdd,
    AppEdit(String),
    AppRm(String),
    /// A scope is named by its application and its own name, which is exactly how the file
    /// and both editors name it: `app/scope`.
    ScopeAdd(String),
    ScopeEdit(String, String),
    ScopeRm(String, String),
    /// `POST` only: a per-row button, so there is nothing to render on a `GET`.
    ScopeMove(String, String),

    UserAdd,
    UserEdit(String),
    UserRm(String),
    /// An identifier is added and dropped on its own, which is what stands in place of a
    /// rename: the identity never changes.
    EmailAdd(String),
    EmailRm(String, String),
    KeyAdd(String),
    KeyEdit(String, String),
    KeyRotate(String, String),
    KeyRm(String, String),

    GroupAdd,
    /// One group's own page at `/groups/{name}` (§13.36 §2): the scopes that name it first,
    /// then its members. Matched after the `+add` arm; a group name is `[A-Za-z0-9_-]`, so
    /// no name can spell `+add` and the two arms cannot trade a URL.
    Group(String),
    GroupEdit(String),
    GroupRm(String),

    DenyAdd,
    DenyRm(String),
}

/// The segment that marks an action rather than a name, in a position where a name could
/// also appear (`/users/+add` vs `/users/bob@x.com`).
///
/// A `+` is what makes the two unambiguous, and by construction rather than by luck:
/// [`pct_encode_segment`] escapes everything outside the unreserved set, `+` included, so
/// no href this binary builds for a name can ever spell one — whatever the roster holds.
pub(crate) const ACTION_ADD: &str = "+add";

impl Route {
    /// This route's path below the base — the canonical spelling, which is also what every
    /// href, the language redirect and the post-mutation `Location:` are built from. Nothing
    /// a client sent survives into one: names are re-encoded by [`pct_encode_segment`], so
    /// the result is printable ASCII whatever the access file contains.
    pub(crate) fn path(&self) -> String {
        let seg = pct_encode_segment;
        match self {
            Route::Dashboard => "/".to_string(),
            Route::Apps => "/apps".to_string(),
            Route::App(a) => format!("/apps/{}", seg(a)),
            Route::Denied => "/denied".to_string(),
            Route::Users => "/users".to_string(),
            Route::Groups => "/groups".to_string(),
            Route::User(u) => format!("/users/{}", seg(u)),
            Route::Audit => "/audit".to_string(),
            Route::Config => "/config".to_string(),

            Route::AppAdd => format!("/apps/{ACTION_ADD}"),
            Route::AppEdit(a) => format!("/apps/{}/edit", seg(a)),
            Route::AppRm(a) => format!("/apps/{}/rm", seg(a)),
            Route::ScopeAdd(a) => format!("/apps/{}/scopes/{ACTION_ADD}", seg(a)),
            Route::ScopeEdit(a, s) => format!("/apps/{}/scopes/{}/edit", seg(a), seg(s)),
            Route::ScopeRm(a, s) => format!("/apps/{}/scopes/{}/rm", seg(a), seg(s)),
            Route::ScopeMove(a, s) => format!("/apps/{}/scopes/{}/move", seg(a), seg(s)),

            Route::UserAdd => format!("/users/{ACTION_ADD}"),
            Route::UserEdit(u) => format!("/users/{}/edit", seg(u)),
            Route::UserRm(u) => format!("/users/{}/rm", seg(u)),
            Route::EmailAdd(u) => format!("/users/{}/emails/{ACTION_ADD}", seg(u)),
            Route::EmailRm(u, e) => format!("/users/{}/emails/{}/rm", seg(u), seg(e)),
            Route::KeyAdd(u) => format!("/users/{}/keys/{ACTION_ADD}", seg(u)),
            Route::KeyEdit(u, i) => format!("/users/{}/keys/{}/edit", seg(u), seg(i)),
            Route::KeyRotate(u, i) => format!("/users/{}/keys/{}/rotate", seg(u), seg(i)),
            Route::KeyRm(u, i) => format!("/users/{}/keys/{}/rm", seg(u), seg(i)),

            Route::GroupAdd => format!("/groups/{ACTION_ADD}"),
            Route::Group(n) => format!("/groups/{}", seg(n)),
            Route::GroupEdit(n) => format!("/groups/{}/edit", seg(n)),
            Route::GroupRm(n) => format!("/groups/{}/rm", seg(n)),

            Route::DenyAdd => format!("/denied/{ACTION_ADD}"),
            Route::DenyRm(e) => format!("/denied/{}/rm", seg(e)),
        }
    }

    /// Which nav tab to mark current for this route: everything about a user belongs to
    /// the `users` tab, and so on down the sections. The group list and `denied` have no tab
    /// of their own: their pages live at their own routes, reached from the sub-tab row
    /// beneath [`page_users`]'s tab, because all three lists are about people, which is what
    /// the Users tab is for (§13.36 §1).
    pub(crate) fn tab(&self) -> Route {
        match self {
            Route::User(_)
            | Route::UserAdd
            | Route::UserEdit(_)
            | Route::UserRm(_)
            | Route::EmailAdd(_)
            | Route::EmailRm(..)
            | Route::KeyAdd(_)
            | Route::KeyEdit(..)
            | Route::KeyRotate(..)
            | Route::KeyRm(..)
            | Route::Denied
            | Route::DenyAdd
            | Route::DenyRm(_)
            | Route::Groups => Route::Users,
            Route::App(_)
            | Route::AppAdd
            | Route::AppEdit(_)
            | Route::AppRm(_)
            | Route::ScopeAdd(_)
            | Route::ScopeEdit(..)
            | Route::ScopeRm(..)
            | Route::ScopeMove(..) => Route::Apps,
            Route::Group(_) | Route::GroupAdd | Route::GroupEdit(_) | Route::GroupRm(_) => {
                Route::Users
            }
            other => other.clone(),
        }
    }

    /// Where a form's `cancel` link goes, and where a `409` offers to send the browser
    /// back: the page this route was reached *from*.
    pub(crate) fn parent(&self) -> Route {
        match self {
            Route::UserEdit(u)
            | Route::UserRm(u)
            | Route::EmailAdd(u)
            | Route::EmailRm(u, _)
            | Route::KeyAdd(u)
            | Route::KeyEdit(u, _)
            | Route::KeyRotate(u, _)
            | Route::KeyRm(u, _) => Route::User(u.clone()),
            Route::UserAdd => Route::Users,
            // A scope's form was reached from its application's page, which is the only
            // place a scope is ever listed: order is meaning there, so it is where an
            // operator needs to land back.
            Route::ScopeAdd(a)
            | Route::ScopeEdit(a, _)
            | Route::ScopeRm(a, _)
            | Route::ScopeMove(a, _)
            | Route::AppEdit(a)
            | Route::AppRm(a) => Route::App(a.clone()),
            Route::AppAdd => Route::Apps,
            // §13.36 §1's table: the add form cancels to the list, because the group it is
            // about to make did not exist when the form was opened. The edit and the removal
            // cancel to the group's own page, which is the page that shows the membership the
            // form is about to write, and the page a removal is about to take away.
            Route::Group(_) | Route::GroupAdd => Route::Groups,
            Route::GroupEdit(n) | Route::GroupRm(n) => Route::Group(n.clone()),
            Route::DenyAdd | Route::DenyRm(_) => Route::Denied,
            other => other.clone(),
        }
    }

    /// The `<title>`: the section's own name, untranslated, because that is the word an
    /// operator types. Matched on `self` and not on [`Route::tab`]: `denied` and
    /// `user_groups` share the `users` *tab*, but a form's `<title>` should still say
    /// which section it edits, not which tab is lit.
    pub(crate) fn title(&self) -> &'static str {
        match self {
            Route::Denied | Route::DenyAdd | Route::DenyRm(_) => "denied",
            Route::Groups
            | Route::Group(_)
            | Route::GroupAdd
            | Route::GroupEdit(_)
            | Route::GroupRm(_) => "user_groups",
            _ => match self.tab() {
                Route::Apps => "applications",
                Route::Users => "users",
                Route::Config => "settings",
                // The one title that names no section of either file, because this tab is
                // about neither: it is the file the gate writes.
                Route::Audit => "audit",
                _ => "bb-auth-web",
            },
        }
    }
}

/// Resolve a request path to a page, or `None` for a 404.
///
/// `base` is [`normalize_base_path`]'s output. A request outside it is not this service's —
/// it 404s rather than falling through to the dashboard, so a misconfigured `location` in
/// nginx shows up as a missing page instead of a GUI that silently answers everywhere.
///
/// Segments are decoded one by one, so a name containing a `/` (a key id may) round-trips
/// through [`Route::path`] and back. Literal arms come before the ones that capture a name;
/// [`ACTION_ADD`] is why that is unambiguous rather than a precedence a future name could
/// steal.
pub(crate) fn route(path: &str, base: &str) -> Option<Route> {
    let rest = if base.is_empty() {
        path
    } else {
        match path.strip_prefix(base) {
            // `/admin` and `/admin/…` are ours; `/administrivia` is not.
            Some("") => "/",
            Some(r) if r.starts_with('/') => r,
            _ => return None,
        }
    };
    let decoded: Vec<String> = rest
        .trim_end_matches('/')
        .split('/')
        .skip(1)
        .map(pct_decode)
        .collect();
    let segs: Vec<&str> = decoded.iter().map(String::as_str).collect();
    let s = |x: &&str| x.to_string();
    match segs.as_slice() {
        [] | [""] => Some(Route::Dashboard),
        ["config"] => Some(Route::Config),

        ["audit"] => Some(Route::Audit),

        ["users"] => Some(Route::Users),
        ["users", ACTION_ADD] => Some(Route::UserAdd),
        ["users", u] if !u.is_empty() => Some(Route::User(s(u))),
        ["users", u, "edit"] if !u.is_empty() => Some(Route::UserEdit(s(u))),
        ["users", u, "rm"] if !u.is_empty() => Some(Route::UserRm(s(u))),
        ["users", u, "emails", ACTION_ADD] if !u.is_empty() => Some(Route::EmailAdd(s(u))),
        ["users", u, "emails", e, "rm"] if !u.is_empty() => Some(Route::EmailRm(s(u), s(e))),
        ["users", u, "keys", ACTION_ADD] if !u.is_empty() => Some(Route::KeyAdd(s(u))),
        ["users", u, "keys", i, "edit"] if !u.is_empty() => Some(Route::KeyEdit(s(u), s(i))),
        ["users", u, "keys", i, "rotate"] if !u.is_empty() => Some(Route::KeyRotate(s(u), s(i))),
        ["users", u, "keys", i, "rm"] if !u.is_empty() => Some(Route::KeyRm(s(u), s(i))),

        ["apps"] => Some(Route::Apps),
        ["apps", ACTION_ADD] => Some(Route::AppAdd),
        ["apps", a] if !a.is_empty() => Some(Route::App(s(a))),
        ["apps", a, "edit"] if !a.is_empty() => Some(Route::AppEdit(s(a))),
        ["apps", a, "rm"] if !a.is_empty() => Some(Route::AppRm(s(a))),
        ["apps", a, "scopes", ACTION_ADD] if !a.is_empty() => Some(Route::ScopeAdd(s(a))),
        ["apps", a, "scopes", n, "edit"] if !a.is_empty() => Some(Route::ScopeEdit(s(a), s(n))),
        ["apps", a, "scopes", n, "rm"] if !a.is_empty() => Some(Route::ScopeRm(s(a), s(n))),
        ["apps", a, "scopes", n, "move"] if !a.is_empty() => Some(Route::ScopeMove(s(a), s(n))),

        // The group list is a page of its own, under the Users tab (§13.36 §1). It has
        // always had this URL; what changed is what the URL shows. One group is a page too
        // (§13.36 §2), matched **after** `+add`, which is what makes a name that spells the
        // action impossible: a group name is `[A-Za-z0-9_-]`, so it carries no `+`.
        ["groups"] => Some(Route::Groups),
        ["groups", ACTION_ADD] => Some(Route::GroupAdd),
        ["groups", n] if !n.is_empty() => Some(Route::Group(s(n))),
        ["groups", n, "edit"] if !n.is_empty() => Some(Route::GroupEdit(s(n))),
        ["groups", n, "rm"] if !n.is_empty() => Some(Route::GroupRm(s(n))),

        ["denied"] => Some(Route::Denied),
        ["denied", ACTION_ADD] => Some(Route::DenyAdd),
        ["denied", e, "rm"] if !e.is_empty() => Some(Route::DenyRm(s(e))),

        _ => None,
    }
}

/// Percent-encode one path segment per RFC 3986: everything outside the unreserved set
/// becomes `%XX`.
///
/// Hand-rolled for the same reason the gate hand-rolls its own: `form_urlencoded` is the
/// wrong grammar here. It spells a space `+`, which would make `a+tag@x.com` — a perfectly
/// ordinary address — ambiguous with `a tag@x.com` in a path segment. Encoding and decoding
/// are exact inverses, and the output is printable ASCII for **any** input, which is what
/// lets a route path go into a `Location:` header unchecked.
pub(crate) fn pct_encode_segment(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// The inverse of [`pct_encode_segment`]: `%XX` decoded, every other byte literal — a `+`
/// is a `+`. Invalid UTF-8 is replaced rather than rejected; the result is only ever
/// compared against roster emails, and a mangled one simply matches nobody.
pub(crate) fn pct_decode(s: &str) -> String {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (
            b[i],
            b.get(i + 1).copied().and_then(hex),
            b.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(hi), Some(lo)) => {
                out.push(hi * 16 + lo);
                i += 3;
            }
            _ => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// First request header matching `name`, compared case-insensitively.
pub(crate) fn header_value<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

/// Pull one cookie's value out of a `Cookie:` header.
pub(crate) fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header
        .split(';')
        .filter_map(|p| p.trim().strip_prefix(name))
        .find_map(|rest| rest.strip_prefix('='))
}

/// The value of query parameter `name`. `form_urlencoded` **is** the right grammar here —
/// this is what a browser puts in the query string when it submits an access check.
pub(crate) fn query_param(query: &str, name: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Build a response header. Panics only on a caller-side bug; every call site passes a
/// constant or a value that is printable ASCII by construction.
pub(crate) fn h(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("valid header")
}

/// Is this `POST` a same-origin form submission?
///
/// The classification is the library's [`request_site`], which the gate's `/auth/session`
/// door now uses too; what is this program's own is the **policy**, and it is the strict one:
/// `same-origin` and nothing else. Every form here is rendered by this binary and submitted
/// to the same origin, so there is no legitimate `same-site` submission to allow, and each
/// form deletes a user or rewrites the access file. The gate is deliberately laxer, because a
/// sign-in page an operator serves themselves may sit on a sibling host.
///
/// Neither header present ⇒ **refused**. That is not a browser submitting a form, and no
/// token in the page would help against a client that sends neither.
pub(crate) fn csrf_ok(
    sec_fetch_site: Option<&str>,
    origin: Option<&str>,
    host: Option<&str>,
) -> bool {
    request_site(sec_fetch_site, origin, host) == RequestSite::SameOrigin
}

/// The most a form body may be. Every field here is an email, a name or a handful of URL
/// patterns; anything past this is not one of our forms, and reading it would be a way to
/// make a 2-thread server chew memory.
const MAX_BODY: usize = 256 * 1024;

/// Read a request body, capped. A truncated read is not distinguished from a short one on
/// purpose: what comes out is parsed as a form, and a form missing its `rev` is refused by
/// the concurrency check anyway.
pub(crate) fn read_body(req: &mut Request) -> String {
    let mut body = String::new();
    let _ = req
        .as_reader()
        .take(MAX_BODY as u64)
        .read_to_string(&mut body);
    body
}

/// A submitted form, parsed once. `form_urlencoded` is exactly the right grammar here: this
/// is what a browser sends for a `<form method="post">` with no `enctype`.
///
/// The content type is deliberately not checked. A body in another grammar simply does not
/// produce the fields a handler asks for — starting with `rev`, whose absence is a refusal —
/// so there is nothing a wrong `Content-Type` buys that the same-origin check does not
/// already deny.
pub(crate) struct Form(pub(crate) Vec<(String, String)>);

impl Form {
    pub(crate) fn parse(body: &str) -> Form {
        Form(
            form_urlencoded::parse(body.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
        )
    }

    /// The first value of `name`, or `""`. Nothing is trimmed here — a field that must be
    /// trimmed says so at its use.
    pub(crate) fn get(&self, name: &str) -> &str {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map_or("", |(_, v)| v.as_str())
    }

    /// A checkbox: present at all ⇒ ticked. Browsers omit an unticked box entirely.
    pub(crate) fn checked(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| k == name)
    }

    /// Every value submitted under `name`, in the order the browser sent them. A group of
    /// checkboxes sharing one name is a list, not a textarea, so it is not [`Form::lines`]:
    /// a browser sends each ticked box as its own pair and sends nothing for an unticked one.
    pub(crate) fn all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect()
    }

    /// A textarea of URL patterns, one per line: trimmed, blanks dropped. `@refs` are left
    /// exactly as typed — the file's own spelling, which is what the library expands.
    pub(crate) fn lines(&self, name: &str) -> Vec<String> {
        self.get(name)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }
}

/// Send a rendered page.
///
/// `Response::from_data` rather than `from_string` because the latter installs its own
/// `Content-Type: text/plain` header that `with_header` would then *append* to rather than
/// replace, putting two of them on the wire.
///
/// Three headers on every response, and they are the same three every time: `no-store`
/// because a page is a snapshot of a file that changes under it, `nosniff` because a browser
/// guessing at a content type is a browser deciding something we already know, and the
/// charset because the roster is full of names that are not ASCII.
///
/// `logo` is the deployment's `ui.logo_url`, handed to the policy beside the [`Look`] that
/// builds the page: the bar's `<img>` and the policy's `img-src` are one value read once, and
/// a page that shows a mark its policy does not name is a broken image. The policy is built
/// from that same `Option`, so the widening is exactly as wide as the setting.
pub(crate) fn respond_page(
    req: Request,
    status: u16,
    page: Markup,
    look: &Look,
    logo: Option<&str>,
    reveal: bool,
) {
    // The mark is named in `img-src` on the page that shows it and on no other. Every page
    // rendered above the settings read has no logo to name, and so has a deployment that never
    // set one, and those take `admin_csp`, which is that policy.
    let csp = match logo {
        Some(src) => admin_csp_logo(look, Some(src), reveal),
        None => admin_csp(look, reveal),
    };
    let mut resp = Response::from_data(page.into_string().into_bytes())
        .with_status_code(StatusCode(status))
        .with_header(h("Content-Type", "text/html; charset=utf-8"))
        .with_header(h("Content-Security-Policy", &csp));
    for (k, v) in PAGE_SECURITY_HEADERS {
        resp.add_header(h(k, v));
    }
    let _ = req.respond(resp);
}

/// This GUI's `Content-Security-Policy`.
///
/// Hashes and not a nonce, because everything this program executes or styles is a
/// compile-time constant: the `<style>` block is [`THEME_CSS`] + [`BASE_CSS`] + [`CSS`], the
/// handler on the Preferences list boxes is [`SETTINGS_ONCHANGE`], and the one `<script>`, the
/// reveal's [`COPY_SCRIPT`], is a constant too. So the policy is derived from the same `&str`s
/// the page is, and the two cannot disagree.
///
/// `'unsafe-hashes'` is what an inline event handler needs: a nonce cannot be put on an
/// attribute, and the alternative to naming this one handler by its hash is `'unsafe-inline'`,
/// which would permit every handler anybody ever adds. The `<noscript>` button behind it means
/// a browser that refuses the handler still works, which makes this the rare case where the
/// strict policy has a fallback already built.
///
/// `img-src` is `data:` and nothing else: this is the policy of a page that shows **no** image,
/// which is every page rendered above the settings read (the file that would name a logo is the
/// file those pages exist to report on) and every page of a deployment that never set
/// `ui.logo_url`. [`admin_csp_logo`] is the same policy with the mark named beside it, and the
/// widening is exactly as wide as the setting (§13.28 §6).
///
/// `form-action` stays `'self'`, which is the one place this GUI is stricter than the gate and
/// is meant to be. Every form here posts to this program and is answered with a `302` back to
/// a page of this program, so nothing of the estate's wider boundary applies: a redirect off
/// this host would be a bug, and a policy that permitted one would be the wrong place to find
/// out.
///
/// `reveal` is the bearer reveal and nothing else (§13.14): the one page allowed a `<script>`,
/// so its policy names that script's hash beside the Settings handler's. The console's shell
/// carries the Preferences list boxes on every page including this one, so both hashes ride the
/// same `'unsafe-hashes'` source, and every other page's policy is byte for byte what it was.
pub(crate) fn admin_csp(look: &Look, reveal: bool) -> String {
    admin_csp_logo(look, None, reveal)
}

/// The `script-src` sources **both surfaces** allow: the hash of [`SETTINGS_ONCHANGE`], which
/// the two Preferences list boxes of the shared form carry, and beside it the hash of
/// [`COPY_SCRIPT`] on the bearer reveal and on nothing else (§13.14).
///
/// One function because a rule about what may run cannot have two answers on two surfaces:
/// step 13 (PLAN.md) gave the self-service page the console's handler, and its policy is
/// asserted against this one (`only_the_reveal_policy_names_the_copy_script`), so the two
/// policies cannot drift by one hash.
pub(crate) fn page_script_src(reveal: bool) -> String {
    if reveal {
        format!(
            "'unsafe-hashes' {} {}",
            csp_hash(SETTINGS_ONCHANGE),
            csp_hash(COPY_SCRIPT)
        )
    } else {
        format!("'unsafe-hashes' {}", csp_hash(SETTINGS_ONCHANGE))
    }
}

/// [`admin_csp`] with the deployment's logo named in `img-src`: the policy of a page that shows
/// it, which is every page served from a settings read that has one (§13.28 §6). The logo
/// arrives as its own argument and not inside [`Look`] because the two consumers of it (the
/// bar's `<img>` and this policy) are handed the same `Option` from one settings read, and a
/// policy that named a source the bar cannot show, or the reverse, is the drift an argument
/// shared by both cannot have.
pub(crate) fn admin_csp_logo(look: &Look, logo: Option<&str>, reveal: bool) -> String {
    let script = page_script_src(reveal);
    let style = csp_hash(&format!("{THEME_CSS}{BASE_CSS}{CSS}"));
    page_csp(&script, &style, "'self'", look.stylesheet, logo, &[])
}

/// `302` to `location`, setting one preference cookie to `value`. `location` is built from a
/// [`Route`] and re-encoded query parameters, so it is printable ASCII by construction and
/// [`h`] cannot panic on it; `value` is one of a closed enum's own [`Lang::code`] or
/// [`UiTheme::code`], or a [`TzPref::code`], whose one request-supplied spelling has passed
/// [`custom_zone`]'s charset, which holds no byte a cookie value may not carry.
///
/// The one redirect every preference uses: see [`respond_lang_redirect`] and
/// [`respond_theme_redirect`].
pub(crate) fn respond_preference_redirect(
    req: Request,
    location: &str,
    cookie_name: &str,
    value: &str,
) {
    let cookie =
        format!("{cookie_name}={value}; Max-Age={PREFERENCE_COOKIE_MAX_AGE}; Path=/; HttpOnly; SameSite=Lax");
    let resp = Response::empty(StatusCode(302))
        .with_header(h("Location", location))
        .with_header(h("Set-Cookie", &cookie[..]))
        .with_header(h("Cache-Control", "no-store"));
    let _ = req.respond(resp);
}

/// [`respond_preference_redirect`] for a language choice. It takes the [`LangPref`] and not
/// the [`Lang`] it resolved to: `Auto` has to be storable, or choosing it would write the
/// language it happens to resolve to today and stop following the browser.
pub(crate) fn respond_lang_redirect(req: Request, location: &str, pref: LangPref) {
    respond_preference_redirect(req, location, LANG_COOKIE, pref.code());
}

/// [`respond_preference_redirect`] for a theme choice.
pub(crate) fn respond_theme_redirect(req: Request, location: &str, theme: UiTheme) {
    respond_preference_redirect(req, location, THEME_COOKIE, theme.code());
}

/// `303` to `location` — the redirect half of POST-redirect-GET, so a reload of the result
/// page cannot repeat the mutation.
///
/// `303` and not `302`: it is the status that tells every browser to follow with a `GET`,
/// which is the entire point. `location` is a [`Route::path`] under the base plus a
/// [`Msg::key`], both printable ASCII by construction, so [`h`] cannot panic on it — and
/// nothing request-supplied is in it.
///
/// Its other uses: a `GET` that carried nothing but a time zone nobody could read, which comes
/// back to its page with the zone dropped (that `location` is a [`preference_href`], so the
/// same argument holds: every client byte in it has been re-encoded); and the completed account
/// deletion, sent through the gate's logout (§13.32 §1, [`delete_logout_location`]), whose
/// `location` is operator config and library constants, no request byte.
pub(crate) fn respond_redirect(req: Request, location: &str) {
    let resp = Response::empty(StatusCode(303))
        .with_header(h("Location", location))
        .with_header(h("Cache-Control", "no-store"));
    let _ = req.respond(resp);
}

/// The preference in force and the language it renders as. Query, then cookie, then
/// `Accept-Language`, then the configured default — most explicit wins.
///
/// Both halves come back because the page needs both, and they are genuinely different
/// questions: the [`Lang`] looks every string up, while the [`LangPref`] is which option the
/// Settings menu must show as chosen, and `Auto` and `en` can render the identical page
/// while being different answers to that one. Returning the pair from a single function is
/// what keeps the rule stated once, where two negotiate calls could drift apart.
///
/// The `Accept-Language` check is deliberately crude: does the header start with `it`? A
/// full RFC 4647 negotiation over two languages would be more code than the question is
/// worth, and both wrong answers are one choice in the menu from being right (and then
/// remembered).
pub(crate) fn negotiate_lang(
    query: Option<&str>,
    cookie: Option<&str>,
    accept: Option<&str>,
    default: Lang,
) -> (LangPref, Lang) {
    let pref = query
        .and_then(parse_lang_pref)
        .or_else(|| cookie.and_then(parse_lang_pref))
        .unwrap_or(LangPref::Auto);
    let lang = match pref {
        LangPref::Fixed(l) => l,
        LangPref::Auto
            if accept.is_some_and(|a| a.trim().to_ascii_lowercase().starts_with("it")) =>
        {
            Lang::It
        }
        LangPref::Auto => default,
    };
    (pref, lang)
}

/// Which theme to render in. Query, then cookie, then `UiTheme::System`: most explicit wins,
/// and `System` is the floor rather than a configured default, since there is nothing to
/// configure; it is what every session already has until it chooses otherwise.
pub(crate) fn negotiate_theme(query: Option<&str>, cookie: Option<&str>) -> UiTheme {
    if let Some(t) = query.and_then(parse_theme) {
        return t;
    }
    if let Some(t) = cookie.and_then(parse_theme) {
        return t;
    }
    UiTheme::System
}

/// This request's URL with the `param` query parameter dropped: where a preference redirect
/// lands, once the choice that parameter carried has become a cookie. The rest of the query
/// survives, which is what keeps an access-check verdict on screen across a preference change.
///
/// One builder for both preferences, named by the cookie constant at the call site
/// (`LANG_COOKIE`, `THEME_COOKIE`): each doubles as its query parameter's name, so there is
/// one spelling per preference and no second place to keep in step. Every byte of the result
/// is a constant, a [`Route::path`] or a re-encoded query parameter — nothing the client sent
/// survives verbatim, which is what makes the string safe in a `Location:` header.
pub(crate) fn preference_href(cfg: &Config, at: &Route, query: &str, param: &str) -> String {
    preference_href_without(cfg, at, query, &[param])
}

/// [`preference_href`] for a preference that arrives as more than one parameter, which today
/// is the audit's clock: a list box and the text box a `custom` choice reads.
pub(crate) fn preference_href_without(
    cfg: &Config,
    at: &Route,
    query: &str,
    params: &[&str],
) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        if !params.contains(&k.as_ref()) {
            ser.append_pair(&k, &v);
        }
    }
    let q = ser.finish();
    let path = format!("{}{}", cfg.base_path, at.path());
    if q.is_empty() {
        path
    } else {
        format!("{path}?{q}")
    }
}

/// The query as received, minus the two parameters the Settings form sets itself, as hidden
/// fields for that form to put back.
///
/// The redirect that follows a pick rebuilds the whole URL ([`preference_href`]); a `GET`
/// form sends its own fields and nothing else, so without this, changing the theme on a page
/// showing an access-check verdict would throw the verdict away. `msg` is deliberately *not*
/// dropped: the flash belongs to the page the operator is looking at.
pub(crate) fn preserved_query(query: &str) -> Vec<(String, String)> {
    form_urlencoded::parse(query.as_bytes())
        .filter(|(k, _)| k != LANG_COOKIE && k != THEME_COOKIE)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}
