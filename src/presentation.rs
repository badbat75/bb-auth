use crate::*;

// ---------------------------------------------------------------------------
// The presentation contract
// ---------------------------------------------------------------------------
//
// What follows is here on the library's own membership rule, and it is worth saying out
// loud because a stylesheet is not a file on disk that two programs parse. The gate's login
// page and `bb-auth-web`'s admin GUI must agree, byte for byte, on what `--accent` names,
// on where an operator's own stylesheet is allowed to land in the cascade, and on how a page
// declares which arm of the palette it starts in. Two answers to any of those and
// `ui.stylesheet_url` restyles one surface while the other stands in a different palette.
//
// The same argument reaches one step further than the palette, and it took a live comparison
// of the two surfaces to see how far. A shared vocabulary of colours does not stop a button
// from being a rounded rectangle on one page and a lozenge on the other, a field from being
// 12px tall here and 7px there, or a message box from being tinted here and outlined there.
// Each of those is one program's author changing the file in front of them, which is drift
// nobody can see from inside either file. So the COMPONENTS are shared too ([`BASE_CSS`]),
// and the rule for what that means is mechanical: a THING (a button, a field, a card, a tag,
// a message) is defined once, for both; an ARRANGEMENT of things is not.
//
// What is NOT here, therefore: the two layouts. The admin's header, tabs, tables and phone
// stacking are the GUI's; the centred auth card, its steps and its social buttons are the
// gate's. Both read the tokens and the components below and define no colour of their own.

/// The palette every HTML surface in this project paints itself from, compiled in from
/// `src/assets/theme.css`.
///
/// It defines custom properties and nothing else. It is emitted **first**, ahead of
/// [`BASE_CSS`], ahead of each program's own layout and ahead of any override, so the cascade
/// order is always: tokens, components, layout, operator.
pub const THEME_CSS: &str = include_str!("assets/theme.css");

/// The components every HTML surface in this project is built from, compiled in from
/// `src/assets/base.css`: the document, the type scale, the card, the state boxes, the
/// fields, the buttons, the pills, the tags and the spinner.
///
/// It is what makes "the sign-in page and the admin interface are one product" a property of
/// the code rather than an intention: a control's shape, size and behaviour are written once
/// and both programs emit the same bytes. It reads its values from [`THEME_CSS`] and defines
/// no literal of its own, so an operator's `ui.stylesheet_url` still restyles everything by
/// redefining tokens alone.
///
/// Emitted immediately after [`THEME_CSS`] and immediately before whichever layout the page
/// belongs to, which is what lets a layout override a component where the page's own
/// arrangement forces it (the auth card's elevation, the admin's compact filter row) without
/// either of them being able to restyle a control for everybody.
pub const BASE_CSS: &str = include_str!("assets/base.css");

/// How long a brand name may be. Long enough for a real product name, short enough that it
/// cannot push a login card's header off a phone: the value is emitted into a page, not into
/// a header, so this is a layout bound rather than a safety one.
pub const MAX_BRAND_NAME: usize = 64;

/// Which arm of [`THEME_CSS`] a page starts in.
///
/// `System` is the absence of a choice and emits no attribute at all, which is what leaves
/// `prefers-color-scheme` deciding. The other two are an explicit choice and outrank the
/// media query by specificity alone, with no script involved. `bb-auth-web` lets an
/// administrator override this per browser with a cookie; the gate's pages have no such
/// state and take it as given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum UiTheme {
    /// Follow the browser and the OS.
    #[default]
    System,
    Light,
    Dark,
}

impl UiTheme {
    /// The wire spelling: what the settings file holds and what an editor prints.
    pub fn code(self) -> &'static str {
        match self {
            UiTheme::System => "system",
            UiTheme::Light => "light",
            UiTheme::Dark => "dark",
        }
    }

    /// The `data-theme` attribute for `<html>`, or `None` for `System`, whose whole meaning
    /// is that the attribute is absent.
    pub fn attr(self) -> Option<&'static str> {
        match self {
            UiTheme::System => None,
            UiTheme::Light => Some("light"),
            UiTheme::Dark => Some("dark"),
        }
    }

    /// Parse a wire spelling; `None` is "not one of the three". An empty string is `System`,
    /// because that is a setting left unset rather than a value spelled wrong, and every
    /// caller turns the `None` into a refusal: a misspelled theme that quietly became
    /// `system` is a setting an operator would go on believing they had set.
    pub fn parse(s: &str) -> Option<UiTheme> {
        match s.trim().to_ascii_lowercase().as_str() {
            "system" | "" => Some(UiTheme::System),
            "light" => Some(UiTheme::Light),
            "dark" => Some(UiTheme::Dark),
            _ => None,
        }
    }
}

/// Escape the HTML-significant characters for safe interpolation into a page or into a
/// double-quoted attribute.
///
/// Named-entity form so one function serves both contexts. It is in the library because both
/// HTML-emitting programs need it and there must not be two answers to "what is escaped":
/// `bb-auth-web` reaches it through `maud`, which escapes its own interpolations, and calls
/// this only where it hands a whole attribute value over.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// The `<link>` that loads an operator's own stylesheet, or the empty string when none is
/// configured.
///
/// One function for both programs, because the *position* is the contract: this is emitted
/// after the built-in `<style>`, so an override wins by source order alone and needs no
/// `!important` and no knowledge of the layout it is restyling. The URL has already passed
/// [`compile_asset_url`], which forbids the quote characters outright; it is escaped here
/// as well, because "already validated" is a property of today's callers and escaping is a
/// property of the emission.
pub fn stylesheet_link(url: Option<&str>) -> String {
    match url {
        Some(u) => format!("<link rel=\"stylesheet\" href=\"{}\">", html_escape(u)),
        None => String::new(),
    }
}

/// Validate a URL a page will load an asset from: [`UiSettings::stylesheet_url`] and
/// [`UiSettings::logo_url`].
///
/// Two shapes, and only two. An absolute `https://` URL, held to exactly what
/// [`compile_login_url`] holds a login page to, because it lands in the same kind of place:
/// inside an attribute on a page one of these programs emits. Or a root-relative path
/// (`/css/theme.css`), which is the better answer when the file is served by the same vhost,
/// since it needs nothing of the deployment's hostname and nothing of a cross-origin CSP.
///
/// Empty is not an error, it is the setting being unset: `Ok(None)`, and the built-in
/// stylesheet stands alone. That is deliberate and load-bearing. A page must never *need* a
/// second host to be up in order to be usable, so an override is an addition to a complete
/// page and never the page itself.
///
/// Printable ASCII forbids the CR/LF and the spaces; the quote characters and the angle
/// brackets are refused outright so the value cannot break out of the attribute it is
/// emitted into. That is belt and braces over the escaping in [`stylesheet_link`], and it is
/// the belt worth having: this string is written by an administrator through a GUI, which is
/// one hop further from the code than an env var is.
pub fn compile_asset_url(field: &str, raw: &str) -> Result<Option<String>, String> {
    asset_url_core(raw).map_err(|(raw, fault)| format!("{field} '{raw}': {fault}"))
}

/// [`compile_asset_url`]'s checks, answering the typed refusal (§13.31 §3), with the same split
/// as [`page_url_core`]: the pair is the text today's sentence quotes, which here is the
/// **trimmed** value the leaf printed, and the fault. Empty is `Ok(None)`, the setting unset,
/// and so is never a refusal.
pub(crate) fn asset_url_core(raw: &str) -> Result<Option<String>, (String, UrlFault)> {
    let u = raw.trim();
    if u.is_empty() {
        return Ok(None);
    }
    let e = |fault| Err((u.to_string(), fault));
    if !u.bytes().all(|b| b.is_ascii_graphic()) {
        return e(UrlFault::NotPrintable);
    }
    if u.contains('"') || u.contains('\'') || u.contains('<') || u.contains('>') {
        return e(UrlFault::Quote);
    }
    if u.contains('\\') {
        return e(UrlFault::Backslash);
    }
    if let Some(rest) = u.strip_prefix("https://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() {
            return e(UrlFault::EmptyHost);
        }
        if authority.contains('@') {
            return e(UrlFault::Userinfo);
        }
        return Ok(Some(u.to_string()));
    }
    // A single leading slash. `//host/path` is protocol-relative, which is an absolute URL
    // wearing a relative URL's clothes, and the one shape somebody writes by accident.
    if u.starts_with('/') && !u.starts_with("//") {
        return Ok(Some(u.to_string()));
    }
    e(UrlFault::NotHttpsOrRooted)
}

/// Validate a brand name: the product name a login page puts under its logo.
///
/// It is HTML-escaped where it is emitted, so this is not the safety boundary; it is the
/// quality one. Control characters are refused because they are never intended, and the
/// length is bounded because the value is laid out, not merely stored. Empty means unset,
/// and each page falls back to whatever it calls itself.
pub fn compile_brand_name(raw: &str) -> Result<Option<String>, String> {
    brand_name_core(raw).map_err(|r| r.sentence())
}

/// [`compile_brand_name`]'s checks, answering the typed refusal (§13.31 §3). The refusal quotes
/// the **trimmed** value, which is what today's sentence printed, and the length it names is a
/// count of **characters**, because the bound is on what a page lays out and not on what the file
/// stores. Empty is `Ok(None)`, the setting unset, so it is never a refusal.
pub(crate) fn brand_name_core(raw: &str) -> Result<Option<String>, SettingsRefusal> {
    let n = raw.trim();
    if n.is_empty() {
        return Ok(None);
    }
    if n.chars().any(|c| c.is_control()) {
        return Err(SettingsRefusal::BrandControl {
            name: n.to_string(),
        });
    }
    let chars = n.chars().count();
    if chars > MAX_BRAND_NAME {
        return Err(SettingsRefusal::BrandTooLong { chars });
    }
    Ok(Some(n.to_string()))
}
