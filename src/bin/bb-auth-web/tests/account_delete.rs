use super::*;

// ===========================================================================================
// §13.30 §2: the delete confirmation page (slice 7b)
//
// `GET {account}/delete`, and nothing else: the page changes nothing and calls nothing, not
// even the intake (§13.29 W3), so every request here is a `GET`, the intake is a listener
// that records, and the access file is read back byte for byte. The `POST` and the intake's
// contract are 7c's.
//
// The wording is spelled out below in both languages, verbatim from §13.30 §5's table,
// because the `K` keys that carry it are the coder's to add and `K` has no `PartialEq`, so
// the rendered words are what a test can compare. Where a key **already** exists (`Cancel`,
// `AccountVeto*`, the `Unit*` words) the assertion compares with `t(lang, K::…)` instead, and
// the veto's words are therefore never written here. The account page's "no roster row"
// sentence is spelled below as well (`ACCOUNT_NO_ROW_EN` / `_IT`): step 13 left that key with
// no caller in the page, so its words are something to look **for** now, and a test may not
// name a key the coder is deleting.
// ===========================================================================================

const DELETE_LEAD_EN: &str = "This cannot be undone. To confirm, type your email address \
                                  below and press Delete my account.";
const DELETE_LEAD_IT: &str = "Non si può annullare. Per confermare, scrivi qui sotto il tuo \
                                  indirizzo email e premi Elimina il mio account.";
const DELETE_GOES_EN: &str = "What is deleted";
const DELETE_GOES_IT: &str = "Cosa viene eliminato";
const DELETE_RECORD_EN: &str = "Your bb-auth record, and every access an administrator gave \
                                    you by name.";
const DELETE_RECORD_IT: &str = "I tuoi dati in bb-auth, e ogni accesso che un amministratore \
                                    ti ha dato per nome.";
const DELETE_KEYS_EN: &str = "Your API keys, which stop working within seconds:";
const DELETE_KEYS_IT: &str = "Le tue chiavi API, che smettono di funzionare in pochi secondi:";
const DELETE_GROUPS_EN: &str = "Your place in these groups:";
const DELETE_GROUPS_IT: &str = "Il tuo posto in questi gruppi:";
const DELETE_ONE_EN: &str = "Every sign-in account with this email address, whether you sign \
                                 in with an emailed code or with a provider such as Google:";
const DELETE_ONE_IT: &str = "Ogni account di accesso con questo indirizzo email, sia che tu \
                                 acceda con un codice via email sia con un fornitore come Google:";
const DELETE_MANY_EN: &str = "Every sign-in account with any of these email addresses, \
                                  whether you sign in with an emailed code or with a provider \
                                  such as Google:";
const DELETE_MANY_IT: &str = "Ogni account di accesso con uno di questi indirizzi email, \
                                  sia che tu acceda con un codice via email sia con un fornitore \
                                  come Google:";
const DELETE_LATER_EN: &str = "The sign-in accounts are not deleted at once: they are queued \
                                   for a separate deletion service.";
const DELETE_LATER_IT: &str = "Gli account di accesso non vengono eliminati subito: vengono \
                                   messi in coda per un servizio di eliminazione separato.";
const DELETE_KEPT_EN: &str = "The record of your sign-ins and refusals is kept for";
const DELETE_KEPT_IT: &str = "Il registro dei tuoi accessi e dei rifiuti è conservato per";
const DELETE_KEPT_TAIL_EN: &str = ", then dropped.";
const DELETE_KEPT_TAIL_IT: &str = ", poi viene eliminato.";
const DELETE_SIZE_EN: &str = "The record of your sign-ins and refusals is kept until newer \
                                  entries replace it; this deployment keeps at most";
const DELETE_SIZE_IT: &str = "Il registro dei tuoi accessi e dei rifiuti resta finché voci \
                                  più recenti non lo sostituiscono; questa installazione ne \
                                  conserva al massimo";
const DELETE_TYPE_EN: &str = "Type your email address to confirm";
const DELETE_TYPE_IT: &str = "Scrivi il tuo indirizzo email per confermare";
const DELETE_HINT_EN: &str = "Any one of the addresses above.";
const DELETE_HINT_IT: &str = "Uno qualsiasi degli indirizzi qui sopra.";
const DELETE_CONFIRM_EN: &str = "Delete my account";
const DELETE_CONFIRM_IT: &str = "Elimina il mio account";

/// The full roster with bob named in one scope's `excluded`, for the page that must say
/// nothing about it (§13.30 §2: "The veto is never named"). `denied` stays in the file so
/// the words a leak would print are words that exist somewhere to be found.
const ACCOUNT_ACCESS_EXCLUDED: &str = r#"{ "version": 1,
      "applications": [
        { "name": "mpa", "base": ["https://app.x.com/mpa"],
          "scopes": [
            { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"], "access": "restricted",
              "groups": ["@admins"], "excluded": ["__BOB__"], "credentials": ["login"] },
            { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
              "access": "authenticated" } ] } ],
      "user_groups": { "admins": ["__BOB__"] },
      "denied": ["spammer@x.com"],
      "users": [
        { "uuid": "__BOB__", "emails": ["bob@x.com", "bob@old.com"] },
        { "uuid": "__CAROL__", "emails": ["carol@x.com"] } ] }"#;

/// The deployment's settings with an audit retention **in time**: the page's audit sentence
/// then names the retention rather than a size (§13.30 §2 §4). The rotation is a size, which
/// is the one combination `AuditPolicy::new` accepts.
const ACCOUNT_SETTINGS_AUDIT_6M: &str = r#"{ "version": 3, "gate": { "client_id": "email-client",
        "issuer": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST",
        "authorized_hosts": ["badbat75.com", "*.badbat75.com"] },
        "web": { "admins": ["admin@x.com"] },
        "audit": { "rotation": "4 MiB", "retention": "6 months" } }"#;

/// The words a person reads: the document with its stylesheets cut out (the palette is text
/// between tags, so [`visible_text`] alone reads forty kilobytes of CSS as prose) and its
/// markup removed. A "this page says no X" assertion is about these words.
fn the_words(body: &str) -> String {
    visible_text(&account_readable(body))
}

/// The panel a `confirm_card` is made of: the facts and the form, marked destructive
/// (§13.30 §2's "one red press").
fn the_delete_panel(body: &str, at: &str) -> String {
    assert!(
        body.contains("<div class=\"panel bad\">"),
        "{at}: the confirmation is a card whose subject is destructive, so the facts and the \
             form sit in a `div.panel.bad`: {}",
        account_readable(body)
    );
    nested_block(body, "<div class=\"panel bad\">", "div")
}

/// The `li`s of the panel's one `ul.plain`, in document order.
fn the_delete_list(panel: &str, at: &str) -> Vec<String> {
    let lists = elements(panel, "<ul class=\"plain\">", "</ul>");
    assert_eq!(
        lists.len(),
        1,
        "{at}: what is deleted is one plain list, not one per kind: {panel}"
    );
    elements(&lists[0], "<li>", "</li>")
}

/// The typed-address field, as §13.30 §2 §5 spells it, in both variants: a `text` field (not
/// `type="email"`, because the browser's own refusal would be in the browser's words),
/// empty on a `GET`, `required`, `inputmode="email"`, the width class the console's email
/// field wears, under a visible label, with the plural hint only where there is a plural to
/// pick from.
///
/// **No `autocomplete`.** §13.30 §2 asked for `autocomplete="email"` for WCAG 1.3.5, and the
/// user removed it on 2026-11-26 (PLAN.md, "the confirmation stays the person's own act, a
/// deliberate exception to WCAG 1.3.5"), so a browser that fills this field has undone the
/// one gesture the page exists to ask for.
fn assert_the_typed_field(form: &str, label: &str, hint: Option<&str>, at: &str) {
    let i = input_named(form, "confirm_email");
    assert_eq!(attr(&i, "type").as_deref(), Some("text"), "{at}: {i}");
    assert_eq!(
        attr(&i, "value").as_deref(),
        Some(""),
        "{at}: a `GET` offers an empty field: {i}"
    );
    assert!(
        bare_attr(&i, "required"),
        "{at}: an empty submission is refused in the browser as well as here: {i}"
    );
    assert_eq!(
        attr(&i, "inputmode").as_deref(),
        Some("email"),
        "{at}: the keyboard to offer is the address one: {i}"
    );
    assert_eq!(
        attr(&i, "class").as_deref(),
        Some("f-email"),
        "{at}: the field is as wide as the console's email field: {i}"
    );
    assert!(
        !i.contains("autocomplete"),
        "{at}: the typed address is the person's own act, so nothing offers it: {i}"
    );
    assert!(
        !i.contains("autofocus"),
        "{at}: Enter must not be one keystroke from a deletion: {i}"
    );

    let labels = elements(form, "<label>", "</label>");
    assert_eq!(labels.len(), 1, "{at}: one field, so one label: {form}");
    let field = &labels[0];
    assert!(
        field.contains(i.as_str()),
        "{at}: the label wraps its input, as every field on both surfaces does: {field}"
    );
    let words = controls_with_class(field, "span", "lbl");
    assert_eq!(words.len(), 1, "{at}: the field's visible label: {field}");
    assert_eq!(
        visible_text(&words[0]),
        label,
        "{at}: the label says what to type: {field}"
    );
    let hints = controls_with_class(field, "span", "hint");
    match hint {
        Some(want) => {
            assert_eq!(
                hints.len(),
                1,
                "{at}: a row with two addresses says any one of them will do: {field}"
            );
            assert_eq!(visible_text(&hints[0]), want, "{at}: {field}");
        }
        None => {
            assert!(
                hints.is_empty(),
                "{at}: one address needs no hint about picking one: {field}"
            );
        }
    }
}

/// §13.30 §2: the roster variant lists what goes, in the file's order, and asks for an
/// address. The heading echoes the row that was clicked (Nielsen 4); the sign-in line is
/// last because it is the one item that does not go at once; the audit sentence is the fact
/// about what is kept after the deletion is queued.
#[test]
fn delete_page_for_a_roster_user_lists_what_goes_and_asks_for_the_address() {
    let path = account_scratch_full("delete-roster");
    let port = account_port_intake(&path);
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");

    for (cookie, lang) in [("lang=en", Lang::En), ("lang=it", Lang::It)] {
        let at = format!("{cookie} roster");
        // Two addresses, in the header's order, which is the order the page lists them.
        let g = account_call_pref(&url, Some("BOB@old.com bob@x.com"), Some(cookie), None);
        assert_eq!(g.status, 200, "{at}: {}", account_readable(&g.body));

        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_TITLE_EN, DELETE_TITLE_IT),
            "{at}: the heading"
        );
        let ledes = controls_with_class(&g.body, "p", "lede");
        assert_eq!(
            ledes.len(),
            1,
            "{at}: one lede: {}",
            account_readable(&g.body)
        );
        assert_eq!(
            visible_text(&ledes[0]),
            m(lang, DELETE_LEAD_EN, DELETE_LEAD_IT),
            "{at}: the lede is the irreversibility statement and the two acts that confirm it"
        );

        let panel = the_delete_panel(&g.body, &at);
        let goes = controls_with_class(&panel, "p", "lbl");
        assert_eq!(goes.len(), 1, "{at}: one label over the list: {panel}");
        assert_eq!(
            visible_text(&goes[0]),
            m(lang, DELETE_GOES_EN, DELETE_GOES_IT),
            "{at}: {panel}"
        );

        let items = the_delete_list(&panel, &at);
        assert_eq!(
            items.len(),
            4,
            "{at}: record, keys, groups, sign-in accounts: {panel}"
        );
        assert_eq!(
            visible_text(&items[0]),
            m(lang, DELETE_RECORD_EN, DELETE_RECORD_IT),
            "{at}: the record line names no uuid: {panel}"
        );
        assert_eq!(
            visible_text(&items[1]),
            format!("{} laptop, ci", m(lang, DELETE_KEYS_EN, DELETE_KEYS_IT)),
            "{at}: each key id, in the file's order: {panel}"
        );
        assert_eq!(
            visible_text(&items[2]),
            format!("{} admins", m(lang, DELETE_GROUPS_EN, DELETE_GROUPS_IT)),
            "{at}: each group: {panel}"
        );
        assert_eq!(
            visible_text(&items[3]),
            format!(
                "{} bob@old.com, bob@x.com",
                m(lang, DELETE_MANY_EN, DELETE_MANY_IT)
            ),
            "{at}: every address, in the header's order: {panel}"
        );
        // The ids and the addresses are values, so they are `code`: a person reads an
        // address in the same face they read it in everywhere in this estate.
        for (li, want) in [
            (&items[1], ["laptop", "ci"]),
            (&items[3], ["bob@old.com", "bob@x.com"]),
        ] {
            let codes: Vec<String> = elements(li, "<code>", "</code>")
                .iter()
                .map(|c| visible_text(c))
                .collect();
            let codes: Vec<&str> = codes.iter().map(String::as_str).collect();
            assert_eq!(
                codes,
                want.to_vec(),
                "{at}: the values are in `code`, in order: {li}"
            );
        }
        let group_codes: Vec<String> = elements(&items[2], "<code>", "</code>")
            .iter()
            .map(|c| visible_text(c))
            .collect();
        assert_eq!(
            group_codes,
            vec!["admins".to_string()],
            "{at}: the group's name, as the file spells it: {}",
            items[2]
        );

        // After the list: queued, not deleted, then what the audit keeps. The default
        // fixture sets no retention, so the sentence is the size one.
        let muted: Vec<String> = controls_with_class(&panel, "p", "muted")
            .iter()
            .map(|p| visible_text(p))
            .collect();
        assert_eq!(
            muted,
            vec![
                m(lang, DELETE_LATER_EN, DELETE_LATER_IT).to_string(),
                format!(
                    "{} {}.",
                    m(lang, DELETE_SIZE_EN, DELETE_SIZE_IT),
                    size_text(AuditPolicy::default().max_bytes())
                ),
            ],
            "{at}: the queued sentence, then the audit's: {panel}"
        );

        // The form: where it posts, the file's `rev`, and this caller's uuid.
        let form = the_delete_form(&g.body, ACCOUNT_BOB, &at);
        assert_eq!(
            hidden_value(&form, "rev").as_deref(),
            Some(rev_of(&path).as_str()),
            "{at}: the form carries the current rev, so a stale one is a 409 and not a clobber"
        );
        assert_the_typed_field(
            &form,
            m(lang, DELETE_TYPE_EN, DELETE_TYPE_IT),
            Some(m(lang, DELETE_HINT_EN, DELETE_HINT_IT)),
            &at,
        );

        let buttons = elements(&form, "<button", "</button>");
        assert_eq!(buttons.len(), 1, "{at}: one press: {form}");
        assert_eq!(
            attr(open_tag(&buttons[0]), "class").as_deref(),
            Some("danger"),
            "{at}: the press that deletes is the danger button: {form}"
        );
        assert_eq!(
            visible_text(&buttons[0]),
            m(lang, DELETE_CONFIRM_EN, DELETE_CONFIRM_IT),
            "{at}: the button says what it does in words, and its accessible name is that \
                 text (WCAG 2.5.3): {form}"
        );
        let pills = controls_with_class(&form, "a", "pill");
        assert_eq!(pills.len(), 1, "{at}: one way out: {form}");
        assert_eq!(
            attr(open_tag(&pills[0]), "href").as_deref(),
            Some(ACCOUNT_PAGE),
            "{at}: cancel goes back to the account page: {form}"
        );
        assert_eq!(visible_text(&pills[0]), t(lang, K::Cancel), "{at}: {form}");

        // Nothing on the page is focused, and the page is not the stranger's.
        assert!(
            !account_readable(&g.body).contains("autofocus"),
            "{at}: no autofocus anywhere: {}",
            account_readable(&g.body)
        );
        assert!(
            !the_words(&g.body).contains(m(lang, ACCOUNT_NO_ROW_EN, ACCOUNT_NO_ROW_IT)),
            "{at}: a roster row is not a stranger: {}",
            the_words(&g.body)
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.30 §2: a caller with no roster row has something to delete too, and the page says so
/// by listing the one thing that is theirs: the sign-in accounts, and nothing else.
///
/// The user's rule of 2026-11-26 (PLAN.md step 13): where there is no roster row the page
/// writes **nothing** in its place. The account page's old "no roster row" sentence
/// (`ACCOUNT_NO_ROW_EN` / `_IT`, spelled here because the key has no caller left) is not
/// repeated here, because a person who came to delete is being told what goes, and a line
/// about what is not there is not a fact about the deletion.
#[test]
fn delete_page_for_a_stranger_lists_only_the_sign_in_accounts() {
    let path = account_scratch_full("delete-stranger");
    let port = account_port_intake(&path);
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");

    for (cookie, lang) in [("lang=en", Lang::En), ("lang=it", Lang::It)] {
        let at = format!("{cookie} stranger");
        // The language is the browser's choice, carried in the `lang` cookie, so each
        // iteration has to send the one it reads its words from.
        let g = account_call_pref(&url, Some("stranger@elsewhere.com"), Some(cookie), None);
        assert_eq!(g.status, 200, "{at}: {}", account_readable(&g.body));

        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_TITLE_EN, DELETE_TITLE_IT),
            "{at}: the heading"
        );
        let panel = the_delete_panel(&g.body, &at);
        let items = the_delete_list(&panel, &at);
        assert_eq!(
            items.len(),
            1,
            "{at}: the sign-in accounts are all the pool and bb-auth hold for them: {panel}"
        );
        assert_eq!(
            visible_text(&items[0]),
            format!(
                "{} stranger@elsewhere.com",
                m(lang, DELETE_ONE_EN, DELETE_ONE_IT)
            ),
            "{at}: the singular, for one address: {panel}"
        );

        let muted: Vec<String> = controls_with_class(&panel, "p", "muted")
            .iter()
            .map(|p| visible_text(p))
            .collect();
        assert_eq!(
            muted,
            vec![
                m(lang, DELETE_LATER_EN, DELETE_LATER_IT).to_string(),
                format!(
                    "{} {}.",
                    m(lang, DELETE_SIZE_EN, DELETE_SIZE_IT),
                    size_text(AuditPolicy::default().max_bytes())
                ),
            ],
            "{at}: queued, then the audit's, and nothing about a row the caller has not got: \
                 {panel}"
        );
        // The rule of 2026-11-26: no row, so no sentence standing in for one. The account
        // page's own words for having no row must not reach this page.
        assert!(
            !the_words(&g.body).contains(m(lang, ACCOUNT_NO_ROW_EN, ACCOUNT_NO_ROW_IT)),
            "{at}: the page writes nothing where a roster row would be: {}",
            the_words(&g.body)
        );
        // What a stranger has no claim on is not listed, not even as an empty line.
        for words in [
            m(lang, DELETE_RECORD_EN, DELETE_RECORD_IT),
            m(lang, DELETE_KEYS_EN, DELETE_KEYS_IT),
            m(lang, DELETE_GROUPS_EN, DELETE_GROUPS_IT),
        ] {
            assert!(
                !the_words(&g.body).contains(words),
                "{at}: no roster line for a caller with no roster: {}",
                the_words(&g.body)
            );
        }

        // The same field and the same press, and a hidden uuid that says there is none.
        let form = the_delete_form(&g.body, "", &at);
        assert_the_typed_field(&form, m(lang, DELETE_TYPE_EN, DELETE_TYPE_IT), None, &at);
        assert_eq!(
            visible_text(&elements(&form, "<button", "</button>")[0]),
            m(lang, DELETE_CONFIRM_EN, DELETE_CONFIRM_IT),
            "{at}: the same one press: {form}"
        );
        assert!(
            !account_readable(&g.body).contains("autofocus"),
            "{at}: no autofocus anywhere: {}",
            account_readable(&g.body)
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.30 §2 §4: the audit sentence is the retention the operator set, in the reader's
/// words, and the size the deployment keeps where no retention is set. The unit is the
/// console's own (`Unit*`), so "6 mesi" on an Italian page is the same word the Settings
/// page shows for the same setting.
///
/// The size is [`AuditPolicy::max_bytes`], the most the audit takes on disk, which is **two
/// files** at the rotation size: 8 MiB for a deployment that names no audit section, the
/// same number the console's Audit tab prints ("At most on disk: 8 MiB"). It is not
/// `AUDIT_MAX_BYTES`, which is one file. The value is read from the policy here rather than
/// written out, so a change to the default moves the page and this test together.
#[test]
fn delete_page_says_how_long_the_audit_keeps_lines() {
    // A retention in time: kept for the retention, then dropped.
    let path = account_scratch_full_settings("delete-audit-retained", ACCOUNT_SETTINGS_AUDIT_6M);
    let port = account_port_intake(&path);
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    for (cookie, lang) in [("lang=en", Lang::En), ("lang=it", Lang::It)] {
        let at = format!("{cookie} retention 6 months");
        // The page's language is the `lang` cookie's, so the Italian words need the Italian
        // cookie on the request.
        let g = account_call_pref(&url, Some("bob@x.com"), Some(cookie), None);
        assert_eq!(g.status, 200, "{at}: {}", account_readable(&g.body));
        let panel = the_delete_panel(&g.body, &at);
        let muted: Vec<String> = controls_with_class(&panel, "p", "muted")
            .iter()
            .map(|p| visible_text(p))
            .collect();
        let kept = muted
            .iter()
            .find(|p| p.starts_with(m(lang, DELETE_KEPT_EN, DELETE_KEPT_IT)))
            .unwrap_or_else(|| panic!("{at}: the audit sentence names the retention: {panel}"));
        assert_eq!(
            *kept,
            format!(
                "{} 6 {}{}",
                m(lang, DELETE_KEPT_EN, DELETE_KEPT_IT),
                t(lang, K::UnitMonths),
                m(lang, DELETE_KEPT_TAIL_EN, DELETE_KEPT_TAIL_IT)
            ),
            "{at}: the retention, in the reader's words: {panel}"
        );
        assert!(
            !muted
                .iter()
                .any(|p| p.contains(m(lang, DELETE_SIZE_EN, DELETE_SIZE_IT))),
            "{at}: a retention in time says how long, not how big: {panel}"
        );
    }
    let _ = std::fs::remove_file(&path);

    // No retention: the size the deployment keeps at most, which is the number the policy
    // answers, not a number this test repeats.
    let path = account_scratch_full("delete-audit-size");
    let port = account_port_intake(&path);
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    for (cookie, lang) in [("lang=en", Lang::En), ("lang=it", Lang::It)] {
        let at = format!("{cookie} no retention");
        let g = account_call_pref(&url, Some("bob@x.com"), Some(cookie), None);
        assert_eq!(g.status, 200, "{at}: {}", account_readable(&g.body));
        let panel = the_delete_panel(&g.body, &at);
        let muted: Vec<String> = controls_with_class(&panel, "p", "muted")
            .iter()
            .map(|p| visible_text(p))
            .collect();
        let kept = muted
            .iter()
            .find(|p| p.starts_with(m(lang, DELETE_SIZE_EN, DELETE_SIZE_IT)))
            .unwrap_or_else(|| panic!("{at}: the audit sentence names the size: {panel}"));
        assert_eq!(
            *kept,
            format!(
                "{} {}.",
                m(lang, DELETE_SIZE_EN, DELETE_SIZE_IT),
                size_text(AuditPolicy::default().max_bytes())
            ),
            "{at}: the bound is the policy's own number: {panel}"
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W7: `denied` is checked ahead of everything this page would otherwise say, and a
/// refusal is a refusal, not a page with a delete button on it. The joined header is the
/// same request: a veto the caller escapes by sending *less* is not a veto.
#[test]
fn delete_page_refuses_a_denied_identity() {
    let path = account_scratch_full("delete-denied");
    let port = account_port_intake(&path);
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");

    for (label, who) in [
        ("a denied address", "spammer@x.com"),
        (
            "a denied address joined to a live one",
            "bob@x.com spammer@x.com",
        ),
    ] {
        let g = account_call(&url, Some(who));
        assert_eq!(
            g.status,
            403,
            "{label}: a refusal, not the page: {}",
            account_readable(&g.body)
        );
        assert!(
            !g.body
                .contains(&format!("action=\"{ACCOUNT_PATH}/delete\"")),
            "{label}: a refusal carries no delete form: {}",
            account_readable(&g.body)
        );
        for words in [DELETE_CONFIRM_EN, DELETE_CONFIRM_IT] {
            assert!(
                !the_words(&g.body).contains(words),
                "{label}: no press to delete on a refusal: {}",
                the_words(&g.body)
            );
        }
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.30 §2: "The veto is never named." A row named in an `excluded` entry gets the ordinary
/// page, and the page says nothing that tells the person they are kept out of somewhere:
/// `remove_user` keeps the exclusion as the email, and the person reading this page is not
/// the reader of that fact.
#[test]
fn delete_page_never_names_the_veto() {
    let access = ACCOUNT_ACCESS_EXCLUDED
        .replace("__BOB__", ACCOUNT_BOB)
        .replace("__CAROL__", ACCOUNT_CAROL);
    let path = account_scratch_access("delete-veto-named", &access);
    let port = account_port_intake(&path);
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");

    for (cookie, lang) in [("lang=en", Lang::En), ("lang=it", Lang::It)] {
        let at = format!("{cookie} excluded row");
        let g = account_call(&url, Some("bob@x.com"));
        assert_eq!(
            g.status,
            200,
            "{at}: an exclusion from one scope is not a refusal of this page: {}",
            account_readable(&g.body)
        );
        let words = the_words(&g.body);
        for forbidden in [
            "excluded",
            "denied",
            "veto",
            t(lang, K::AccountVetoTitle),
            t(lang, K::AccountVetoBody),
        ] {
            assert!(
                !words.contains(forbidden),
                "{at}: the page names no veto, to anyone: {forbidden:?} is in {words}"
            );
        }
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W3: the page changes nothing and calls nothing, not even the intake's `whoami`.
/// The intake is a listener that records, so "calls nothing" is a listener that saw nothing,
/// and the file is read back byte for byte because a `GET` that wrote the access file would
/// be a prefetch deleting a person.
#[test]
fn delete_page_changes_nothing_and_calls_nothing() {
    let (intake, seen) = intake_listener();
    let path = account_scratch_full("delete-nothing");
    let port = account_port_intake_at(&path, &format!("http://127.0.0.1:{intake}"));
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = std::fs::read(&path).expect("read the fixture");

    for who in ["bob@x.com", "stranger@elsewhere.com"] {
        let g = account_call(&url, Some(who));
        assert_eq!(g.status, 200, "{who}: {}", account_readable(&g.body));
    }

    assert_eq!(
        std::fs::read(&path).expect("read the fixture again"),
        before,
        "a `GET` writes no byte of the access file"
    );
    assert_eq!(
        seen.lock().unwrap().clone(),
        Vec::<String>::new(),
        "the confirmation page reaches the intake in no way at all"
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W2: with no intake configured there is no page, so the menu row 7a hides has no
/// target either. This is the same behaviour 7a's `no_delete_row_when_the_intake_is_unset`
/// pins from the menu; here it is pinned as the page's own contract, and it is green before
/// 7b exists, which is the point: the route must not arrive as a page that posts to nothing.
#[test]
fn delete_page_is_a_404_when_the_intake_is_unset() {
    let path = account_scratch_full("delete-no-intake");
    let port = account_port(&path);
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");

    for who in ["bob@x.com", "stranger@elsewhere.com"] {
        let g = account_call(&url, Some(who));
        assert_eq!(
            g.status,
            404,
            "{who}: no intake, so no page: {}",
            account_readable(&g.body)
        );
        assert!(
            !g.body
                .contains(&format!("action=\"{ACCOUNT_PATH}/delete\"")),
            "{who}: a 404 carries no delete form: {}",
            account_readable(&g.body)
        );
    }
    let _ = std::fs::remove_file(&path);
}
