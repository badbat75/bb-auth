use crate::*;

/// The response headers every HTML page either program serves carries, and the one place
/// that set is decided.
///
/// It is here for the reason [`BASE_CSS`] is. Two programs emit pages now, and "what does an
/// HTML response carry" had two answers: the gate sent `X-Frame-Options` and no `nosniff`,
/// the GUI sent `nosniff` and no `X-Frame-Options`. Nobody chose that; each file was edited
/// by somebody looking at that file. The consequence is not cosmetic like a mismatched
/// radius: the page that could be framed was the one whose forms delete users.
///
/// A caller emits these on every HTML response and adds a
/// [`Content-Security-Policy`](page_csp) of its own, which is per page because its sources
/// are.
pub const PAGE_SECURITY_HEADERS: [(&str, &str); 4] = [
    // A page here is a snapshot of a file that is being edited under it, or of one attempt
    // at a login: a cached copy is a page that is right about a request nobody is making any
    // more.
    ("Cache-Control", "no-store"),
    // A browser guessing at a content type is a browser deciding something we already know.
    ("X-Content-Type-Options", "nosniff"),
    // A login form, or a delete button, in somebody else's frame is a clickjacking target,
    // and each service says so itself rather than trusting the proxy in front of it to have
    // said it. `frame-ancestors` in the CSP is the modern spelling and is emitted too; this
    // one costs a header and covers what does not implement it.
    ("X-Frame-Options", "DENY"),
    // These URLs carry an `rd`, a uuid, a key id or an email. None of it has business
    // travelling to a third-party host in a `Referer`, and the gate reads that header as a
    // redirect candidate itself, which is one more reason not to hand other people's out.
    ("Referrer-Policy", "no-referrer"),
];

/// A `'sha256-…'` CSP source expression for a piece of inline content, exactly as a browser
/// computes it: SHA-256 of the bytes between the tags, standard base64.
///
/// The alternative to a nonce, and the better one wherever the content is a compile-time
/// constant: there is nothing to generate per response, nothing to thread through a renderer,
/// and no way for the policy and the page to disagree, because both are derived from the same
/// `&str`. It is a hash and not a copy, so a stale value cannot survive an edit to the
/// content: the browser recomputes it and refuses to apply a block that changed.
///
/// **Newlines are normalised to LF first, and that is not a nicety.** An HTML parser
/// normalises the document's newlines before anything else sees it, so what a browser hashes
/// is the block with every CRLF already collapsed. This repository is developed on Windows
/// with `core.autocrlf=true`, so the working tree's stylesheets have CRLF, `include_str!`
/// embeds them verbatim, and the release is cross-compiled from that same tree: without this
/// line the served page and the policy that describes it disagree on every build made here,
/// the browser refuses the whole stylesheet, and the admin interface renders as unstyled
/// markup with nothing in the journal and nothing in any test. It costs one pass over a
/// compile-time constant and is a no-op wherever the checkout is LF.
pub fn csp_hash(content: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    let normalized = content.replace("\r\n", "\n");
    format!(
        "'sha256-{}'",
        STANDARD.encode(Sha256::digest(normalized.as_bytes()))
    )
}

/// The CSP source for one of the two operator-supplied asset URLs: its origin when it is
/// absolute, `'self'` when it is root-relative, and nothing at all when it is unset.
///
/// [`compile_asset_url`] has already reduced the shapes to those three, which is what makes
/// this a `split` rather than a URL parser.
fn csp_asset_source(url: Option<&str>) -> Option<String> {
    let u = url?;
    match u.strip_prefix("https://") {
        Some(rest) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            (!authority.is_empty()).then(|| format!("https://{authority}"))
        }
        None => Some("'self'".to_string()),
    }
}

/// The `form-action` source list for a page whose forms are answered with a redirect into the
/// estate: `'self'` plus the cookie's domain and every host under it.
///
/// The source is the **cookie domain** and deliberately not [`GateSettings::authorized_hosts`],
/// which is the list that actually decides where a login may land. Two reasons, and the second
/// is why the obvious choice is the wrong one. [`compile_settings`] already refuses a file
/// whose authorized hosts are not all covered by the cookie domain, so this is by construction
/// a superset of every host a login can legitimately reach, and it is the same boundary the
/// file already reasons about. And [`compile_host_pattern`] admits globs that a CSP
/// host-source cannot express at all (`*bat75.com`, `a.*.com`), so building the directive out
/// of those would mean silently dropping the entries that do not translate, which is this bug
/// again for whoever wrote one. [`compile_cookie_domain`], by contrast, has already vouched
/// for a bare domain with no scheme, no port, no path and no glob, so the value drops into a
/// source expression with nothing left to escape or check.
///
/// An empty domain keeps `'self'`, and that is the right answer rather than a fallback: with
/// no `Domain` the session cookie is host-only, so a cross-host landing would arrive with no
/// session at all and there is nothing here worth permitting.
///
/// **This is not the authorization boundary and is not being asked to be one.** `safe_rd` in
/// the gate still decides where a login may go, against `authorized_hosts`, exactly as before;
/// all this directive has to do is stop cancelling a redirect the gate has already approved.
pub fn estate_form_action(cookie_domain: Option<&str>) -> String {
    match cookie_domain
        .map(cookie_domain_host)
        .filter(|d| !d.is_empty())
    {
        Some(d) => format!("'self' https://{d} https://*.{d}"),
        None => "'self'".to_string(),
    }
}

/// Assemble the `Content-Security-Policy` for a page either program serves.
///
/// The shape is `default-src 'none'` plus exactly what the page needs, which is short because
/// these pages are built to be complete on their own: the palette, the components and the
/// layout are inline, and the only external references a deployment can add are the two
/// [`UiSettings`] URLs, both already validated by [`compile_asset_url`] and both optional.
/// So the policy writes itself out of the settings, and an operator who sets neither gets a
/// page that may load nothing from anywhere.
///
/// The three arguments the caller supplies are the three things this file cannot know:
///
/// * `script_src` is what the page's own scripting is allowed to be. A nonce where the script
///   is assembled per response (the sign-in page substitutes configuration into it), a
///   [`csp_hash`] where it is a constant, `'none'` where there is no script at all.
/// * `style_src` is the same question for the inline `<style>` block that carries
///   [`THEME_CSS`], [`BASE_CSS`] and the caller's own layout. The operator's stylesheet is
///   appended to it here, because *that* source is this function's business.
/// * `form_action` is where the page's forms may **end up**, which is not the same question as
///   where they post. Chromium applies this directive to every hop of a form submission, the
///   redirect the response carries included, so a page that posts to its own origin and is
///   answered with a `302` onto another host of the estate needs that host named here or the
///   browser cancels the navigation. That is not hypothetical: it is what a hardcoded `'self'`
///   did to every Chromium login in a multi-host deployment, and it did it in the worst shape
///   available, since the session was already minted and the person was left watching a
///   spinner on a page that had succeeded. [`estate_form_action`] derives the answer for a
///   page that redirects, `'self'` is right for a form that lands on its own origin, and
///   `'none'` for a page that carries no form at all.
///
/// `connect` is for the hosts a page's script legitimately talks to: the gate's sign-in page
/// speaks to Cognito, and nothing else here speaks to anything. The two asset URLs are passed
/// rather than the whole [`Settings`], because one caller renders a page from a settings file
/// it has just read and the other from a snapshot of four fields, and this needs neither.
///
/// **`font-src` follows the stylesheet, and only the stylesheet.** A token file that changes
/// the estate's typeface has to be able to bring its `@font-face` with it, and there is only
/// one honest place for those files to live: the host the stylesheet itself came from, which
/// is a host this deployment has already named. So the origin that may serve the CSS may
/// serve its fonts, plus `data:` for a face embedded in the file. A third-party font host is
/// deliberately out of reach: it would be a second external host on the page whose whole
/// argument is that it needs none, and self-hosting a font beside the stylesheet costs a
/// copy. With no stylesheet configured the answer is `'none'`, because the built-in CSS asks
/// for no font at all: it names system faces, which are not fetched.
///
/// One thing this cannot do for the operator: a font is fetched in CORS mode even from a
/// host the policy allows, so the file has to be served with `Access-Control-Allow-Origin`.
/// A policy that permits it and a server that does not is a font that silently never
/// arrives.
///
/// This is worth having on a login page more than anywhere else in the estate. It is the one
/// page whose whole job is to hold a credential for a moment, the one page a deployment can
/// point at an external stylesheet, and the page where a future templating slip would be
/// worth the most to whoever found it. `default-src 'none'` is what makes all three cost
/// nothing.
pub fn page_csp(
    script_src: &str,
    style_src: &str,
    form_action: &str,
    stylesheet_url: Option<&str>,
    logo_url: Option<&str>,
    connect: &[&str],
) -> String {
    let mut style = style_src.to_string();
    if let Some(s) = csp_asset_source(stylesheet_url) {
        style.push(' ');
        style.push_str(&s);
    }
    // Whatever may serve the stylesheet may serve its fonts, and nothing else may. `data:`
    // for a face embedded in the file itself, which is the other way a token file travels
    // with its typeface.
    let font = match csp_asset_source(stylesheet_url) {
        Some(s) => format!("{s} data:"),
        None => "'none'".to_string(),
    };
    // `data:` because a logo is the one asset small enough that a deployment may reasonably
    // inline it rather than serve it, and an image URI cannot script.
    let img = match csp_asset_source(logo_url) {
        Some(s) => format!("{s} data:"),
        None => "data:".to_string(),
    };
    let connect_src = if connect.is_empty() {
        "'none'".to_string()
    } else {
        connect.join(" ")
    };
    format!(
        "default-src 'none'; script-src {script_src}; style-src {style}; img-src {img}; \
         font-src {font}; connect-src {connect_src}; form-action {form_action}; \
         frame-ancestors 'none'; base-uri 'none'"
    )
}

/// Where the browser says a request came from, which is the input to every CSRF decision
/// either program makes.
///
/// The classification is shared; the **policy is not**, and that separation is the point.
/// Both programs accept `POST`s from forms they rendered themselves, so there must not be two
/// answers to "where did this come from" (the GUI had one, the gate had none, which left
/// `/auth/session` minting a session cookie for a cross-site form post that `SameSite=Lax`
/// does nothing about: that attribute governs when a cookie is *sent*, never who may cause
/// one to be *set*). But what each program then does about a `same-site` request is genuinely
/// its own business, and writing one function that decided it for both would be the wrong
/// kind of sharing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestSite {
    /// Same scheme, host and port as the page: a form submitting to its own origin.
    SameOrigin,
    /// The same registrable domain, a different origin. Only a browser can tell us this;
    /// there is no public-suffix list here to work it out from `Origin` alone.
    SameSite,
    /// Another site entirely. This is the one every caller refuses.
    CrossSite,
    /// The browser said nothing usable: no `Sec-Fetch-Site` and no `Origin`, or a
    /// user-initiated navigation with no originating document at all (`none`). Not a form
    /// submission from a page of ours, whatever else it is.
    Unknown,
}

/// Classify a request by what the browser told us about its origin.
///
/// Two sources, in the order they deserve to be believed:
///
/// * **`Sec-Fetch-Site`** is set by the browser on every request and cannot be set by a page,
///   so where it exists it is the whole answer.
/// * **`Origin`** is the fallback, and only its **host** is compared, against the `Host:`
///   header's. Not the scheme: both binaries speak plain HTTP behind a TLS-terminating nginx,
///   so the browser's `https://…` origin can never equal a scheme reconstructed here, and
///   comparing one would refuse every honest request. The port travels with the host in both
///   headers, so comparing the authority as written is right in the default-port case *and*
///   the explicit-port one. This arm needs nginx to forward `Host`, which the deployment
///   examples now show; a mismatch here can only report [`RequestSite::CrossSite`], because
///   distinguishing a sibling host from a stranger needs a public-suffix list.
pub fn request_site(
    sec_fetch_site: Option<&str>,
    origin: Option<&str>,
    host: Option<&str>,
) -> RequestSite {
    if let Some(sfs) = sec_fetch_site {
        let s = sfs.trim();
        return if s.eq_ignore_ascii_case("same-origin") {
            RequestSite::SameOrigin
        } else if s.eq_ignore_ascii_case("same-site") {
            RequestSite::SameSite
        } else if s.eq_ignore_ascii_case("cross-site") {
            RequestSite::CrossSite
        } else {
            // `none`, and anything a future browser invents.
            RequestSite::Unknown
        };
    }
    match (origin, host) {
        (Some(o), Some(hst)) => {
            let authority = o
                .trim()
                .split_once("://")
                .map(|(_, rest)| rest.trim_end_matches('/'));
            match authority {
                Some(a) if !a.is_empty() && a.eq_ignore_ascii_case(hst.trim()) => {
                    RequestSite::SameOrigin
                }
                Some(a) if !a.is_empty() => RequestSite::CrossSite,
                _ => RequestSite::Unknown,
            }
        }
        _ => RequestSite::Unknown,
    }
}
