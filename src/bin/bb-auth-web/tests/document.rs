use super::*;

// -------------------------------------------------------------------
// §13.26 §6 D: one document skeleton
//
// `shell_named` and `account_shell` each wrote the same document head, and the head is
// the part the estate's safety argument rests on: the CSP's style hash covers the three
// inlined stylesheets as one string, so a head that emits them in another order, or with
// whitespace between them, is a page whose own policy refuses its own look. One function
// for both surfaces is what stops that drifting one edit at a time, and these tests pin
// the shape of that one function, then pin that both surfaces still wear it.
// -------------------------------------------------------------------

/// The `<head>` element of a document, both tags included, byte for byte.
fn head_of(doc: &str) -> String {
    let start = doc.find("<head>").unwrap_or_else(|| {
        panic!("the document has no <head>: {}", account_readable(doc));
    });
    let rest = &doc[start..];
    let end = rest
        .find("</head>")
        .unwrap_or_else(|| panic!("the document has no </head>: {}", account_readable(doc)))
        + "</head>".len();
    rest[..end].to_string()
}

#[test]
fn page_document_opens_with_the_doctype() {
    // The first bytes of the document, in order, with nothing before them: a stray
    // whitespace text node ahead of `<!DOCTYPE html>` puts a browser in quirks mode, and
    // the layout the three stylesheets describe is written for the standard one.
    let doc = page_document(Lang::En, None, "t", None, html! {}).into_string();
    assert!(doc.starts_with("<!DOCTYPE html>"), "{doc}");
}

#[test]
fn page_document_stamps_the_theme_and_omits_the_attribute_for_none() {
    // `None` is the `System` arm, and it must leave the attribute **absent** rather than
    // empty: `data-theme=""` is an attribute the palette's `[data-theme=…]` selectors do
    // not match, and the `prefers-color-scheme` rule in `THEME_CSS` is what decides then.
    // The tag is read, not the page, because `THEME_CSS` spells `data-theme` in its own
    // selectors and a whole-document search matches the stylesheet.
    let dark = page_document(Lang::It, Some("dark"), "t", None, html! {}).into_string();
    assert_eq!(
        account_html_tag(&dark),
        r#"<html lang="it" data-theme="dark">"#,
        "{dark}"
    );
    let none = page_document(Lang::En, None, "t", None, html! {}).into_string();
    assert_eq!(account_html_tag(&none), r#"<html lang="en">"#, "{none}");
    assert!(
        !account_html_tag(&none).contains("data-theme"),
        "no theme chosen means no attribute at all: {}",
        account_html_tag(&none)
    );
}

#[test]
fn page_document_titles_with_the_text_as_given_and_escaped() {
    // The title is the **whole** `<title>` text: the function adds no prefix of its own,
    // which is what lets the console say `bb-auth-web · …` and the self-service page say
    // `{brand} · …` from the one skeleton. And it is escaped, because a brand name comes
    // out of the settings file and a page title is HTML.
    let doc = page_document(Lang::En, None, "A & B <x>", None, html! {}).into_string();
    assert!(doc.contains("<title>A &amp; B &lt;x&gt;</title>"), "{doc}");
    assert_eq!(title_of(&doc), "A &amp; B &lt;x&gt;");
}

#[test]
fn page_document_inlines_the_three_stylesheets_then_the_operators_link() {
    // The order is the contract, and it is byte-exact rather than "contains all three":
    // the response's CSP carries `csp_hash(&format!("{THEME_CSS}{BASE_CSS}{CSS}"))`, so
    // anything between the three constants, or one of them moved, is a page whose policy
    // refuses its own stylesheet. The operator's link goes **after** the `<style>`, so an
    // override wins by source order and needs no `!important`.
    let url = "https://assets.badbat75.com/css/theme.css";
    let doc = page_document(Lang::En, None, "t", Some(url), html! {}).into_string();
    let styles = elements(&doc, "<style>", "</style>");
    assert_eq!(styles.len(), 1, "one inline style element: {doc}");
    let style = &styles[0];
    let inner = &style["<style>".len()..style.len() - "</style>".len()];
    assert_eq!(inner, format!("{THEME_CSS}{BASE_CSS}{CSS}"));

    let head = head_of(&doc);
    let link = format!("<link rel=\"stylesheet\" href=\"{url}\">");
    assert!(
        head.contains(&link),
        "the operator's stylesheet is linked in the head: {}",
        account_readable(&head)
    );
    assert_eq!(head.matches("<link").count(), 1, "{head}");
    assert!(
        head.find("</style>").expect("the style element")
            < head.find(&link).expect("the stylesheet link"),
        "the override lands after the built-in look: {}",
        account_readable(&head)
    );
}

#[test]
fn page_document_links_nothing_when_no_stylesheet_is_given() {
    // The property the whole arrangement rests on: the built-in look is complete, so a
    // deployment that configured nothing fetches nothing, and a host that is down costs a
    // page its palette and nothing else.
    let doc = page_document(Lang::En, None, "t", None, html! {}).into_string();
    assert!(!doc.contains("<link"), "{doc}");
}

#[test]
fn page_document_puts_the_body_markup_inside_the_body_element() {
    // `body` is the whole contents of the element, so the caller keeps its own arrangement
    // (the console's `main` plus footer, the page's bar plus `main`) and the
    // skeleton owns only the document around it.
    let body = html! { main { h1 { "Hello" } } };
    let doc = page_document(Lang::En, None, "t", None, body).into_string();
    let rest = &doc[doc.find("<body>").expect("the document has no <body>")..];
    let inner = &rest["<body>".len()..];
    let inner = &inner[..inner.find("</body>").expect("the document has no </body>")];
    assert!(
        inner.contains("<main><h1>Hello</h1></main>"),
        "{}",
        account_readable(&doc)
    );
}

#[test]
fn the_console_and_the_account_page_wear_the_same_document_head() {
    // The point of the slice: two surfaces, one head. Both fixtures configure no `ui`
    // section, so both take the built-in look (no theme attribute, no operator stylesheet),
    // which is the shape `page_document` is called with here. The head is compared byte for
    // byte, title text read out of each page, so a skeleton that changed the meta tags, the
    // order of the three stylesheets or the link's position is red on both surfaces.
    let console = render("skeleton-console", Route::Dashboard);
    let want = page_document(Lang::En, None, &title_of(&console), None, html! {}).into_string();
    assert_eq!(
        head_of(&console),
        head_of(&want),
        "the console's head is not the skeleton's"
    );

    let path = account_scratch("skeleton-account", ACCOUNT_SETTINGS);
    let url = account_serve(&path);
    let g = account_call(&url, Some("bob@x.com"));
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let want = page_document(Lang::En, None, &title_of(&g.body), None, html! {}).into_string();
    assert_eq!(
        head_of(&g.body),
        head_of(&want),
        "the self-service page's head is not the skeleton's"
    );
    let _ = std::fs::remove_file(&path);
}
