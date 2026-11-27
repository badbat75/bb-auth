use super::*;

// ---------------------------------------------------------------------
// The profile edit, slice 5b (docs/ARCHITECTURE.md §13.22 and §13.23): the form, the
// refusals that happen before any call, `InitiateAuth`, the code page. The code step
// (`RespondToAuthChallenge` onward) is 5c's.
//
// Everything here talks to a fake Cognito that is a local socket: `Config::cognito_endpoint`
// points the process at it, and no test reaches a real pool.
// ---------------------------------------------------------------------

/// The usual answer: this session's own user, and the masked address the code goes to.
fn email_code_challenge() -> Reply {
    email_otp(FAKE_USERNAME, Some("b***@x.com"))
}

/// The profile headers with `X-Auth-Native-Username` set to `username`: the same session on
/// a different Cognito user. The whole list is rebuilt rather than one header appended,
/// because a request that carries the header twice is a fixture that asks which one the
/// server reads, not a session on a second user.
fn profile_headers_for(username: &'static str) -> Vec<(&'static str, &'static str)> {
    PROFILE_HEADERS
        .iter()
        .map(|(k, v)| {
            if *k == NATIVE_USERNAME_HEADER {
                (*k, username)
            } else {
                (*k, *v)
            }
        })
        .collect()
}

fn profile_get(url: &str, who: &str, extra: &[(&str, &str)]) -> AccountGot {
    profile_get_as(url, who, &PROFILE_HEADERS, extra)
}

/// A `GET` that arrives with no `X-Auth-Native-Username`: a federated session, or one whose
/// cookie predates §13.25's gate change.
fn profile_get_no_native(url: &str, who: &str) -> AccountGot {
    profile_get_as(url, who, &profile_headers_no_native(), &[])
}

fn profile_get_as(
    url: &str,
    who: &str,
    headers: &[(&str, &str)],
    extra: &[(&str, &str)],
) -> AccountGot {
    let mut all: Vec<(&str, &str)> = headers.to_vec();
    all.extend_from_slice(extra);
    account_call_with(url, Some(who), &all)
}

/// A `POST` that arrives with no `X-Auth-Native-Username` (§13.25 step 1).
fn profile_post_no_native(url: &str, who: &str, fields: &[(&str, &str)]) -> AccountGot {
    profile_post_headers(
        url,
        Some(who),
        fields,
        "same-origin",
        true,
        &profile_headers_no_native(),
        &[],
    )
}

/// A refusal that happened before any call: the status, and the fake saw nothing.
fn assert_refused_before_cognito(g: &AccountGot, status: u16, fake: &FakeCognito, what: &str) {
    assert_eq!(g.status, status, "{what}: {}", account_readable(&g.body));
    assert!(
        fake.calls().is_empty(),
        "{what}: no call may reach Cognito, and these did: {:?}",
        fake.calls()
    );
}

/// The edit is offered only where it can work: the pool, the native client and at least one
/// editable claim, and then as `p.primary > a.pill` to `/account/profile` with no fragment,
/// for a stranger too (§13.22 "Who may edit", §13.23 §1).
#[test]
fn the_profile_panel_offers_edit_only_when_wired() {
    let fake = FakeCognito::answering(vec![]);
    let cases = [
        (
            "no-client",
            profile_settings("", PROFILE_POOL, PROFILE_CLAIMS),
            false,
        ),
        (
            "no-issuer",
            profile_settings("email-client", "", PROFILE_CLAIMS),
            false,
        ),
        (
            "no-editable",
            profile_settings("email-client", PROFILE_POOL, r#""phone_number", "address""#),
            false,
        ),
        ("wired", profile_wired(), true),
    ];
    for (name, settings, offered) in cases {
        let (path, base) = profile_boot(
            &format!("panel-{name}"),
            &settings,
            Some(fake.endpoint()),
            None,
            1,
        );
        for who in ["bob@x.com", "stranger@elsewhere.com"] {
            let g = profile_get(&base, who, &[]);
            assert_eq!(g.status, 200, "{name}/{who}: {}", account_readable(&g.body));
            let panel = account_section(&g.body, "profile");
            let pills = anchors_to(&panel, "/account/profile");
            if offered {
                assert_eq!(pills.len(), 1, "{name}/{who}: one Edit pill: {panel}");
                assert_eq!(attr(&pills[0], "href").as_deref(), Some("/account/profile"));
                assert_eq!(visible_text(&pills[0]), t(Lang::En, K::AccountProfileEdit));
                assert!(
                    panel.contains("<p class=\"primary\"><a class=\"pill\""),
                    "{name}/{who}: the pill is p.primary > a.pill: {panel}"
                );
            } else {
                assert!(pills.is_empty(), "{name}/{who}: no Edit offered: {panel}");
            }
        }
        cleanup(&path);
    }
    assert!(
        fake.calls().is_empty(),
        "reading the page never calls Cognito"
    );
}

/// Only an editable claim becomes an input: the others stay read-only text, in code, and a
/// configured claim outside the allowlist can never be posted into.
#[test]
fn the_profile_form_offers_only_editable_claims() {
    let fake = FakeCognito::answering(vec![]);
    let (path, base) = profile_serve("form-editable", &fake);
    let g = profile_get(&format!("{base}profile"), "bob@x.com", &[]);
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let panel = account_section(&g.body, "profile");
    let form = form_posting_to(&panel, "/account/profile");
    for editable in ["given_name", "family_name", "birthdate", "zoneinfo"] {
        let i = input_named(&form, editable);
        assert_eq!(attr(&i, "type").as_deref(), Some("text"), "{editable}: {i}");
    }
    for fixed in [
        "phone_number",
        "preferred_username",
        "address",
        "custom:department",
    ] {
        assert!(
            !form.contains(&format!("name=\"{fixed}\"")),
            "{fixed} is never an input: {form}"
        );
    }
    assert!(
        visible_text(&panel).contains("Sales") && panel.contains("<code>custom:department</code>"),
        "a configured claim that is not editable is shown read-only, by claim name: {panel}"
    );
    // The rest of the account page is still there around the open panel.
    let _ = account_section(&g.body, "reach");
    assert!(fake.calls().is_empty());
    cleanup(&path);
}

/// Every field is labelled in words, in both languages, with the autofill token WCAG 1.3.5
/// asks for, as text, 2048 characters at most, the first one focused (§13.23 §2).
#[test]
fn the_profile_form_labels_fields_in_words() {
    let fake = FakeCognito::answering(vec![]);
    let (path, base) = profile_serve("form-labels", &fake);
    let tokens = [
        ("given_name", "given-name"),
        ("family_name", "family-name"),
        ("birthdate", "bday"),
    ];
    for (lang, cookie, labels) in [
        (
            Lang::En,
            "lang=en",
            [
                ("given_name", "Given name"),
                ("family_name", "Family name"),
                ("birthdate", "Date of birth"),
                ("zoneinfo", "Time zone"),
            ],
        ),
        (
            Lang::It,
            "lang=it",
            [
                ("given_name", "Nome"),
                ("family_name", "Cognome"),
                ("birthdate", "Data di nascita"),
                ("zoneinfo", "Fuso orario"),
            ],
        ),
    ] {
        let g = profile_get(
            &format!("{base}profile"),
            "bob@x.com",
            &[("Cookie", cookie)],
        );
        assert_eq!(g.status, 200, "{}", account_readable(&g.body));
        let form = form_posting_to(&account_section(&g.body, "profile"), "/account/profile");
        for (claim, word) in labels {
            let label = elements(&form, "<label", "</label>")
                .into_iter()
                .find(|l| l.contains(&format!("name=\"{claim}\"")))
                .unwrap_or_else(|| panic!("{claim}: no label holds the input: {form}"));
            let text = visible_text(&label);
            assert!(
                text.contains(word),
                "{lang:?} {claim}: label says {text:?}, wants {word:?}"
            );
            assert!(
                !text.contains(claim),
                "{claim}: the label is words, not the claim name: {text}"
            );
            let i = input_named(&label, claim);
            assert_eq!(attr(&i, "type").as_deref(), Some("text"));
            assert_eq!(attr(&i, "maxlength").as_deref(), Some("2048"), "{claim}");
        }
        for (claim, token) in tokens {
            let i = input_named(&form, claim);
            assert_eq!(
                attr(&i, "autocomplete").as_deref(),
                Some(token),
                "{claim}: {i}"
            );
        }
        assert!(
            attr(&input_named(&form, "zoneinfo"), "autocomplete").is_none(),
            "zoneinfo has no autofill token"
        );
        let texts: Vec<String> = elements(&form, "<input", ">")
            .into_iter()
            .filter(|i| attr(i, "type").as_deref() == Some("text"))
            .collect();
        assert!(
            bare_attr(&texts[0], "autofocus"),
            "the first field is focused, and the attribute is bare: {}",
            texts[0]
        );
        assert!(
            texts.iter().skip(1).all(|i| !i.contains("autofocus")),
            "only the first: {texts:?}"
        );
        assert!(
            form.contains(t(lang, K::AccountProfileDateHint)),
            "birthdate carries its format hint: {form}"
        );
    }
    cleanup(&path);
}

/// §13.26 "One text field": `text_field_with` is the one markup every text field on
/// both surfaces is built from, so every option is asserted **present when set and
/// absent when not**. An attribute that leaks out of a default is a constraint on a
/// field that never asked for it (a `required` the server does not enforce, a
/// `maxlength` that silently truncates what a person typed), and one that never
/// appears is a constraint the browser will never apply.
#[test]
fn the_shared_field_carries_exactly_what_it_is_told() {
    fn field(placeholder: &str, hints: &[&str], invalid: bool, opts: FieldOpts<'_>) -> String {
        text_field_with("Name", "x", "v", placeholder, hints, invalid, opts).into_string()
    }
    fn input(markup: &str) -> String {
        tag_containing(markup, "name=\"x\"")
    }

    // --- the default: the console's field, and nothing else ------------------
    let m = field("ph", &[], false, FieldOpts::default());
    let i = input(&m);
    assert!(
        m.starts_with("<label>"),
        "the field is a label wrapping its input: {m}"
    );
    assert!(
        m.contains("<span class=\"lbl\">Name</span>"),
        "the label is the visible word, in the console's span: {m}"
    );
    assert!(
        m.find("<input").expect("an input") > m.find("class=\"lbl\"").expect("the label"),
        "the word comes before the control: {m}"
    );
    assert_eq!(attr(&i, "type").as_deref(), Some("text"), "{i}");
    assert_eq!(attr(&i, "value").as_deref(), Some("v"), "{i}");
    assert_eq!(attr(&i, "placeholder").as_deref(), Some("ph"), "{i}");
    assert_eq!(
        attr(&i, "class").as_deref(),
        Some("f-x"),
        "the width class is keyed off the wire name, as the console's is: {i}"
    );
    assert_eq!(attr(&i, "autocapitalize").as_deref(), Some("off"), "{i}");
    assert_eq!(attr(&i, "spellcheck").as_deref(), Some("false"), "{i}");
    for absent in [
        "autofocus",
        "required",
        "maxlength",
        "pattern",
        "autocomplete",
        "inputmode",
        "aria-invalid",
        "aria-describedby",
    ] {
        assert!(
            !i.contains(absent),
            "an option that was not set emits no attribute at all: {absent} in {i}"
        );
    }
    assert!(!m.contains("class=\"hint\""), "no hints, no hint line: {m}");

    // --- an empty placeholder is nothing said --------------------------------
    assert!(
        attr(
            &input(&field("", &[], false, FieldOpts::default())),
            "placeholder"
        )
        .is_none(),
        "a field with nothing to suggest carries no placeholder attribute"
    );

    // --- each option, set ---------------------------------------------------
    let i = input(&field(
        "ph",
        &[],
        false,
        FieldOpts {
            autofocus: true,
            required: true,
            maxlength: Some(32),
            pattern: Some("[a-z0-9-]{1,32}"),
            autocomplete: Some("given-name"),
            inputmode: Some("numeric"),
            ..FieldOpts::default()
        },
    ));
    assert!(bare_attr(&i, "autofocus"), "bare, as HTML spells it: {i}");
    assert!(bare_attr(&i, "required"), "bare, as HTML spells it: {i}");
    assert_eq!(attr(&i, "maxlength").as_deref(), Some("32"), "{i}");
    assert_eq!(
        attr(&i, "pattern").as_deref(),
        Some("[a-z0-9-]{1,32}"),
        "the grammar the server enforces, on the field too: {i}"
    );
    assert_eq!(
        attr(&i, "autocomplete").as_deref(),
        Some("given-name"),
        "WCAG 1.3.5: {i}"
    );
    assert_eq!(attr(&i, "inputmode").as_deref(), Some("numeric"), "{i}");

    // --- the class override, and the invalid mark on top of it --------------
    let i = input(&field(
        "ph",
        &[],
        false,
        FieldOpts {
            class: Some("f-profile"),
            ..FieldOpts::default()
        },
    ));
    assert_eq!(
        attr(&i, "class").as_deref(),
        Some("f-profile"),
        "a field that is not sized by its wire name names its own class: {i}"
    );
    let i = input(&field(
        "ph",
        &[],
        true,
        FieldOpts {
            class: Some("f-profile"),
            ..FieldOpts::default()
        },
    ));
    assert_eq!(
        attr(&i, "class").as_deref(),
        Some("f-profile invalid"),
        "the invalid state rides on the class the caller chose: {i}"
    );
    let i = input(&field("ph", &[], true, FieldOpts::default()));
    assert_eq!(
        attr(&i, "class").as_deref(),
        Some("f-x invalid"),
        "and on the default one: {i}"
    );

    // --- prose: a name keeps the browser's capitalisation and spell check ---
    let i = input(&field(
        "ph",
        &[],
        false,
        FieldOpts {
            prose: true,
            ..FieldOpts::default()
        },
    ));
    assert!(
        attr(&i, "autocapitalize").is_none() && attr(&i, "spellcheck").is_none(),
        "prose drops both: a browser that capitalises `Ada` on its own is the point: {i}"
    );

    // --- several hints, in the order the caller gave them -------------------
    let m = field("ph", &["First.", "Second."], false, FieldOpts::default());
    let hints: Vec<String> = elements(&m, "<span class=\"hint\"", "</span>")
        .iter()
        .map(|h| visible_text(h))
        .collect();
    assert_eq!(
        hints,
        vec!["First.".to_string(), "Second.".to_string()],
        "one line per hint, in order, below the control: {m}"
    );
    assert!(
        m.find("<input").expect("an input") < m.find("class=\"hint\"").expect("a hint"),
        "the hints are under the field they describe: {m}"
    );

    // --- invalid: the pair, pointing at the shared message box --------------
    let i = input(&field("ph", &[], true, FieldOpts::default()));
    assert_eq!(attr(&i, "aria-invalid").as_deref(), Some("true"), "{i}");
    assert_eq!(
        attr(&i, "aria-describedby").as_deref(),
        Some(ERR_ID),
        "the one id every form's message box carries: {i}"
    );
}

/// `text_field` keeps its signature as a one-line wrapper, so the console's 23 callers
/// do not change: the bytes it renders today are pinned, and they are the same bytes
/// `text_field_with` renders from a one-item hint slice and the default options.
#[test]
fn the_console_wrapper_is_the_shared_field_with_no_options() {
    // The console's field as it renders today, byte for byte, so the shared helper
    // cannot repaint a console field one attribute at a time.
    const GOLDEN_INVALID: &str = concat!(
        "<label><span class=\"lbl\">Name</span>",
        "<input type=\"text\" name=\"name\" value=\"v\" placeholder=\"app1\"",
        " class=\"f-name invalid\" autocapitalize=\"off\" spellcheck=\"false\"",
        " aria-invalid=\"true\" aria-describedby=\"form-error\">",
        "<span class=\"hint\">Shape here</span></label>",
    );
    const GOLDEN_PLAIN: &str = concat!(
        "<label><span class=\"lbl\">Name</span>",
        "<input type=\"text\" name=\"name\" value=\"v\" placeholder=\"app1\"",
        " class=\"f-name\" autocapitalize=\"off\" spellcheck=\"false\"></label>",
    );
    assert_eq!(
        text_field("Name", "name", "v", "app1", Some("Shape here"), true).into_string(),
        GOLDEN_INVALID
    );
    assert_eq!(
        text_field("Name", "name", "v", "app1", None, false).into_string(),
        GOLDEN_PLAIN
    );

    let hints: &[&str] = &["Shape here"];
    assert_eq!(
        text_field("Name", "name", "v", "app1", Some("Shape here"), true).into_string(),
        text_field_with(
            "Name",
            "name",
            "v",
            "app1",
            hints,
            true,
            FieldOpts::default()
        )
        .into_string(),
        "the wrapper is the shared field with a one-item hint slice"
    );
    assert_eq!(
        text_field("Name", "name", "v", "app1", None, false).into_string(),
        text_field_with(
            "Name",
            "name",
            "v",
            "app1",
            &[],
            false,
            FieldOpts::default()
        )
        .into_string(),
        "and no hint is an empty slice"
    );
}

/// The mint row's name field is the shared field with the browser's constraints on it
/// (§13.26 "One text field"): the console's markup, `autocapitalize` and `spellcheck`
/// **kept** (a key id is a name typed, not prose), the bare `autofocus` and `required`,
/// the 32-character window and the grammar, and the shape hint only while the row is
/// clean. The refusal replaces the hint with its own sentence and adds the aria pair,
/// pointing at the shared message box.
#[test]
fn the_mint_name_field_is_the_shared_field_with_constraints() {
    let path = account_scratch_access("keys-new-field", &account_access_keys());
    let base = account_serve(&path);
    let g = account_call(&format!("{base}keys/new"), Some("bob@x.com"));
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let id = tag_containing(&g.body, "name=\"id\"");
    assert_eq!(attr(&id, "type").as_deref(), Some("text"), "{id}");
    assert_eq!(attr(&id, "placeholder").as_deref(), Some("laptop"), "{id}");
    assert_eq!(
        attr(&id, "class").as_deref(),
        Some("f-id"),
        "the console's width class, not an override: {id}"
    );
    assert_eq!(attr(&id, "maxlength").as_deref(), Some("32"), "{id}");
    assert_eq!(
        attr(&id, "pattern").as_deref(),
        Some("[a-z0-9-]{1,32}"),
        "{id}"
    );
    assert_eq!(
        attr(&id, "autocapitalize").as_deref(),
        Some("off"),
        "an id is a name typed, so the console's rule stands: {id}"
    );
    assert_eq!(attr(&id, "spellcheck").as_deref(), Some("false"), "{id}");
    assert!(
        bare_attr(&id, "autofocus"),
        "the person lands in the field the + asked for: {id}"
    );
    assert!(
        bare_attr(&id, "required"),
        "an empty name is refused by the browser as well as the server: {id}"
    );
    assert!(
        attr(&id, "aria-invalid").is_none() && attr(&id, "aria-describedby").is_none(),
        "a clean field carries no mark: {id}"
    );
    let label_of_id = || {
        elements(&g.body, "<label", "</label>")
            .into_iter()
            .find(|l| l.contains("name=\"id\""))
            .unwrap_or_else(|| {
                panic!(
                    "the mint row carries its name field: {}",
                    account_readable(&g.body)
                )
            })
    };
    assert!(
        label_of_id().contains(&format!(
            "<span class=\"hint\">{}</span>",
            t(Lang::En, K::AccountKeyIdHint)
        )),
        "the open row says the shape under a clean field: {}",
        label_of_id()
    );

    // Refused: the hint is gone, the pair is there, and it names the shared box.
    let before = read(&path);
    let rev = sha256_hex(&before);
    let g = account_post(
        &format!("{base}keys"),
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "My Laptop"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(g.status, 400, "{}", account_readable(&g.body));
    let id = tag_containing(&g.body, "name=\"id\"");
    assert_eq!(attr(&id, "aria-invalid").as_deref(), Some("true"), "{id}");
    assert_eq!(
        attr(&id, "aria-describedby").as_deref(),
        Some(ERR_ID),
        "the marked field points at the shared message box: {id}"
    );
    assert!(
        g.body.contains(&format!("class=\"err\" id=\"{ERR_ID}\"")),
        "and that box is the refusal above the form: {}",
        account_readable(&g.body)
    );
    // The hint line is gone from the field. The check is scoped to the label, because
    // the refusal's own sentence *contains* the hint's words: a page-wide search for
    // them is satisfied by the message that replaced the hint.
    let label = elements(&g.body, "<label", "</label>")
        .into_iter()
        .find(|l| l.contains("name=\"id\""))
        .expect("the refused row keeps its name field");
    assert!(
        !label.contains("class=\"hint\""),
        "the refusal says the shape in the reader's language, so the hint is dropped: \
             {label}"
    );
    assert_eq!(read(&path), before, "a refusal writes nothing");
    cleanup(&path);
}

/// The profile fields are the shared field in **prose** mode (§13.26's review nit): a
/// person's name keeps the browser's capitalisation and its spell check, so the field
/// carries no `autocapitalize` and no `spellcheck` at all. Everything else is the
/// shared field's: the `f-profile` class, the 2048 window, the autofill token, one
/// **bare** `autofocus` on the first field only, no placeholder attribute, and the
/// hints in the order the page gives them.
#[test]
fn the_profile_fields_are_prose() {
    let fake = FakeCognito::answering(vec![]);
    let (path, base) = profile_serve("prose-fields", &fake);
    let g = profile_get(&format!("{base}profile"), "bob@x.com", &[]);
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let form = form_posting_to(&account_section(&g.body, "profile"), "/account/profile");
    let labels = elements(&form, "<label", "</label>");
    for claim in ["given_name", "family_name", "birthdate", "zoneinfo"] {
        let i = input_named(&form, claim);
        assert_eq!(attr(&i, "type").as_deref(), Some("text"), "{claim}: {i}");
        assert_eq!(
            attr(&i, "class").as_deref(),
            Some("f-profile"),
            "{claim}: the profile's own width class: {i}"
        );
        assert_eq!(
            attr(&i, "maxlength").as_deref(),
            Some("2048"),
            "{claim}: {i}"
        );
        assert!(
            attr(&i, "placeholder").is_none(),
            "{claim}: the page has nothing to suggest, so no attribute: {i}"
        );
        assert!(
            attr(&i, "autocapitalize").is_none(),
            "{claim}: a name keeps the browser's capitalisation: {i}"
        );
        assert!(
            attr(&i, "spellcheck").is_none(),
            "{claim}: a name keeps the spell check: {i}"
        );
    }
    let first = input_named(&form, "given_name");
    assert!(
        bare_attr(&first, "autofocus"),
        "the first field is focused, and the attribute is bare: {first}"
    );
    for claim in ["family_name", "birthdate", "zoneinfo"] {
        let i = input_named(&form, claim);
        assert!(
            !i.contains("autofocus"),
            "one focus on a page, on the first field only: {i}"
        );
    }
    assert_eq!(
        attr(&input_named(&form, "birthdate"), "autocomplete").as_deref(),
        Some("bday"),
        "the autofill token the claim has one"
    );
    assert!(
        attr(&input_named(&form, "zoneinfo"), "autocomplete").is_none(),
        "and a claim with no token in the spec's vocabulary carries no attribute"
    );

    let label_of = |claim: &str| {
        labels
            .iter()
            .find(|l| l.contains(&format!("name=\"{claim}\"")))
            .cloned()
            .unwrap_or_default()
    };
    let hints = |claim: &str| -> Vec<String> {
        elements(&label_of(claim), "<span class=\"hint\"", "</span>")
            .iter()
            .map(|h| visible_text(h))
            .collect()
    };
    assert_eq!(
        hints("given_name"),
        vec![t(Lang::En, K::AccountProfileClearDeletes)],
        "a field with a value says emptying it removes it"
    );
    assert_eq!(
        hints("zoneinfo"),
        Vec::<String>::new(),
        "an empty field has nothing to remove, so no line"
    );
    assert_eq!(
        hints("birthdate"),
        vec![
            t(Lang::En, K::AccountProfileClearDeletes),
            t(Lang::En, K::AccountProfileDateHint)
        ],
        "the two hints a field can carry, in the order a person reads them"
    );
    assert!(fake.calls().is_empty(), "a GET asks the pool nothing");
    cleanup(&path);
}

/// The profile form's refusal box carries the **shared** id, so the field it attributes
/// points at it with `aria-describedby` exactly as every console form's fields do
/// (§13.26 "One text field"): one id for the message a marked field names, on both
/// surfaces.
#[test]
fn the_profile_refusal_shares_the_error_id() {
    let fake = FakeCognito::answering(vec![]);
    let (path, base) = profile_serve("refusal-id", &fake);
    let long = Box::leak("a".repeat(2049).into_boxed_str());
    let g = profile_post(
        &format!("{base}profile"),
        "bob@x.com",
        &profile_with(profile_same(), "given_name", long),
    );
    assert_eq!(g.status, 400, "{}", account_readable(&g.body));
    assert!(
        fake.calls().is_empty(),
        "a bad value is refused before the pool"
    );
    let err = element_containing(&g.body, &format!("id=\"{ERR_ID}\""), "</div>");
    assert!(
        err.starts_with("<div class=\"err\""),
        "the refusal is the shared box, carrying the shared id: {err}"
    );
    assert!(
        visible_text(&err).contains(t(Lang::En, K::AccountProfileValueBad)),
        "and it is the sentence about the value: {err}"
    );
    let i = input_named(&g.body, "given_name");
    assert_eq!(attr(&i, "aria-invalid").as_deref(), Some("true"), "{i}");
    assert_eq!(
        attr(&i, "aria-describedby").as_deref(),
        Some(ERR_ID),
        "the marked field names the box above it: {i}"
    );
    assert!(
        !g.body.contains("id=\"err\""),
        "no page-local id is left on this form: {}",
        account_readable(&g.body)
    );
    cleanup(&path);
}

/// The twelve `Attr*` words, English and Italian, as §13.23 §5 gives them: the form's label,
/// the change summary's name and the read-only panel's name are one key each.
#[test]
fn the_attr_labels_are_the_designers_words() {
    let table = [
        (K::AttrName, "Full name", "Nome completo"),
        (K::AttrGivenName, "Given name", "Nome"),
        (K::AttrFamilyName, "Family name", "Cognome"),
        (K::AttrMiddleName, "Middle name", "Secondo nome"),
        (K::AttrNickname, "Nickname", "Soprannome"),
        (K::AttrProfile, "Profile page", "Pagina del profilo"),
        (
            K::AttrPicture,
            "Picture (web address)",
            "Immagine (indirizzo web)",
        ),
        (K::AttrWebsite, "Website", "Sito web"),
        (K::AttrGender, "Gender", "Genere"),
        (K::AttrBirthdate, "Date of birth", "Data di nascita"),
        (K::AttrZoneinfo, "Time zone", "Fuso orario"),
        (K::AttrLocale, "Language and region", "Lingua e regione"),
    ];
    for (k, en, it) in table {
        assert_eq!(t(Lang::En, k), en);
        assert_eq!(t(Lang::It, k), it);
    }
    // The decisions of 2026-11-25 that are literal: the clock the code page names, and the
    // act's own words.
    assert_eq!(
        t(Lang::En, K::AccountProfileCodeLasts),
        "It works for 3 minutes."
    );
    assert_eq!(
        t(Lang::It, K::AccountProfileCodeLasts),
        "Vale per 3 minuti."
    );
    assert_eq!(t(Lang::En, K::AccountProfileEdit), "Edit profile");
    assert_eq!(t(Lang::It, K::AccountProfileEdit), "Modifica il profilo");
    assert_eq!(t(Lang::En, K::AccountProfileSendCode), "Send code");
    assert_eq!(t(Lang::En, K::AccountProfileSave), "Save profile");
    assert_eq!(t(Lang::En, K::AccountProfileSendNew), "Send a new code");
    assert_eq!(
        t(Lang::En, K::AccountProfileClearDeletes),
        "Empty it to remove it."
    );
}

/// The read-only panel names a claim in the same words as the form (user decision
/// 2026-11-25); a claim with no word keeps its name, in code.
#[test]
fn the_read_only_panel_uses_the_word_labels() {
    let fake = FakeCognito::answering(vec![]);
    let (path, base) = profile_serve("panel-words", &fake);
    for (cookie, given, dept) in [
        ("lang=en", "Given name", "Sales"),
        ("lang=it", "Nome", "Sales"),
    ] {
        let g = profile_get(&base, "bob@x.com", &[("Cookie", cookie)]);
        let panel = account_section(&g.body, "profile");
        let items: Vec<String> = elements(&panel, "<li>", "</li>")
            .iter()
            .map(|l| visible_text(l))
            .collect();
        assert!(
            items.contains(&format!("{given}: Bob")),
            "{cookie}: {items:?}"
        );
        assert!(
            items.contains(&format!("custom:department: {dept}")),
            "{cookie}: {items:?}"
        );
        assert!(
            !panel.contains("<code>given_name</code>"),
            "{cookie}: {panel}"
        );
    }
    cleanup(&path);
}

/// An emptied field is announced where it happens (a hint under each field that has a value)
/// and again on the code page, where a removal is a word and the old value follows "was".
#[test]
fn an_emptied_field_is_announced_before_saving() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("emptied", &fake);
    let g = profile_get(&format!("{base}profile"), "bob@x.com", &[]);
    let hint = t(Lang::En, K::AccountProfileClearDeletes);
    assert_eq!(
        g.body.matches(hint).count(),
        3,
        "one hint per field that has a value (given, family, birthdate), none for the empty \
             zoneinfo: {}",
        account_readable(&g.body)
    );

    let g = profile_post(
        &format!("{base}profile"),
        "bob@x.com",
        &profile_with(profile_same(), "family_name", ""),
    );
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let changes = element_containing(&g.body, "changes", "</ul>");
    let lis = elements(&changes, "<li>", "</li>");
    assert_eq!(lis.len(), 1, "only the emptied field changed: {changes}");
    let text = visible_text(&lis[0]);
    assert!(
        lis[0].contains("tag warn"),
        "a removal is a warn tag: {}",
        lis[0]
    );
    for want in [
        t(Lang::En, K::AttrFamilyName),
        t(Lang::En, K::AccountProfileRemoved),
        t(Lang::En, K::AccountProfileWas),
        "Smith Jr",
    ] {
        assert!(text.contains(want), "{text:?} lacks {want:?}");
    }
    cleanup(&path);
}

const NOT_NATIVE: &str = "If you sign in with a social account such as Google, your profile \
                             comes from that provider and cannot be changed here. If you sign in \
                             with your email address, sign out and sign in again to edit it.";
/// The same sentence in Italian. It is pinned because this is the one sentence the page
/// says to a person who cannot act on it, and a page that speaks one language to a
/// person who reads another says nothing.
const NOT_NATIVE_IT: &str = "Se accedi con un account social come Google, il tuo profilo \
                                viene da quel fornitore e non si può cambiare qui. Se accedi \
                                con il tuo indirizzo email, esci e accedi di nuovo per \
                                modificarlo.";
const CODE_SENT_NO_DEST: &str = "We emailed a code to the address you sign in with.";
/// The Italian of the same sentence: the page that shows it is the one a person reads in
/// the language they chose, and §13.26 §5 gives both.
const CODE_SENT_NO_DEST_IT: &str = "Abbiamo inviato un codice all'indirizzo con cui accedi.";
/// `AccountProfileNoCode` loses its social sentence, which §13.26 §5 says is now never true
/// of the person reading it: a session that cannot get a code never reaches this page.
const NO_CODE: &str = "No email after a minute? Look in your spam folder, or send a new code.";
const NO_CODE_IT: &str =
    "Nessuna email dopo un minuto? Guarda nello spam, o invia un nuovo codice.";
const NO_USER: &str = "The sign-in service no longer has the account you signed in with, so \
                          no code was sent. Sign out and sign in again.";
/// The Italian of the two sentences §13.26 §5 adds and rewords, spelled here for the same
/// reason as the English: the outcome page is read by the person who chose Italian, and the
/// design gives both strings, so both are pinned.
const NO_USER_IT: &str = "Il servizio di accesso non ha più l'account con cui hai effettuato \
                             l'accesso, quindi non è stato inviato alcun codice. Esci e accedi \
                             di nuovo.";
const NOT_YOURS_IT: &str = "Il servizio di accesso ha risposto per un altro account, quindi \
                               non è cambiato nulla.";
/// The sentences §13.26 §5 removes, spelled here so a test can say none of them is rendered
/// anywhere. They are prefixes, not whole sentences, because the whole of a removed sentence
/// is what must not appear in any shape.
const GONE_SEND_TO: &str = "Send the code to";
const GONE_SOCIAL_NOTE: &str = "If you sign in only with a social account";
const GONE_NOT_YOUR_EMAIL: &str = "The code can only go to one of your own email addresses.";
const GONE_NO_EMAIL_SIGN_IN: &str = "Your account signs in through a social provider";
/// The Italian spelling of the same four, because a removed key is two strings and the
/// Italian one is what a `lang=it` page renders.
const GONE_SEND_TO_IT: &str = "Invia il codice a";
const GONE_SOCIAL_NOTE_IT: &str = "Se accedi solo con un account social";
const GONE_NOT_YOUR_EMAIL_IT: &str = "Il codice può andare solo a uno dei tuoi indirizzi email.";
const GONE_NO_EMAIL_SIGN_IN_IT: &str = "Il tuo account accede tramite un fornitore social";

/// Every `p.muted` of a document, as visible text.
fn muted_paragraphs(body: &str) -> Vec<String> {
    elements(body, "<p class=\"muted\"", "</p>")
        .into_iter()
        .map(|p| visible_text(&p))
        .collect()
}

/// §13.26 §1: the two sections a person acts in come first and the two read-only lists
/// last, on every path that draws the page. The ids do not change, so no link and no
/// selector changes.
#[test]
fn the_sections_come_in_the_users_order() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("order", &fake);
    let pages = [
        ("account", base.clone()),
        ("profile", format!("{base}profile")),
        ("keys/new", format!("{base}keys/new")),
    ];
    for (name, url) in pages {
        let g = profile_get(&url, "bob@x.com", &[]);
        assert_eq!(g.status, 200, "{name}: {}", account_readable(&g.body));
        let at = |id: &str| {
            g.body
                .find(&format!("id=\"{id}\""))
                .unwrap_or_else(|| panic!("{name}: no section id=\"{id}\""))
        };
        let seen = [at("profile"), at("keys"), at("groups"), at("reach")];
        assert!(
            seen.windows(2).all(|w| w[0] < w[1]),
            "{name}: the sections must come profile, keys, groups, reach, and their byte \
                 offsets are {seen:?}"
        );
    }
    cleanup(&path);
}

/// The form names no address at all (§13.26 §4): no `select`, no `email` field, no "Send
/// the code to" line and no social note, for one address or several, and the reason the
/// email is not a field is a `p.muted` after the fields. The resend form carries no
/// `email` either.
#[test]
fn the_form_names_no_address() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("no-address", &fake);
    let fixed = t(Lang::En, K::AccountProfileEmailFixed);
    for who in [
        "bob@x.com",
        "bob@x.com bob@old.com",
        "stranger@elsewhere.com",
    ] {
        let g = profile_get(&format!("{base}profile"), who, &[]);
        assert_eq!(g.status, 200, "{who}: {}", account_readable(&g.body));
        let form = form_posting_to(&account_section(&g.body, "profile"), "/account/profile");
        assert!(!form.contains("<select"), "{who}: {form}");
        assert!(!form.contains("name=\"email\""), "{who}: {form}");
        for gone in [
            GONE_SEND_TO,
            GONE_SOCIAL_NOTE,
            GONE_NOT_YOUR_EMAIL,
            GONE_NO_EMAIL_SIGN_IN,
        ] {
            assert!(
                !g.body.contains(gone),
                "{who}: `{gone}` is removed: {}",
                account_readable(&g.body)
            );
        }
        assert!(
            muted_paragraphs(&g.body).iter().any(|p| p == fixed),
            "the reason the email is not a field is a `p.muted`: {}",
            account_readable(&g.body)
        );
        let at = |needle: &str| form.find(needle).unwrap_or(usize::MAX);
        assert!(
            at("name=\"zoneinfo\"") < at(fixed),
            "{who}: the sentence sits after the fields: {form}"
        );
    }

    // Resend posts the changed values only.
    let g = profile_post(
        &format!("{base}profile"),
        "bob@x.com",
        &profile_with(profile_same(), "given_name", "Robert"),
    );
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let resend = form_posting_to(&g.body, "/account/profile");
    assert!(!resend.contains("name=\"email\""), "{resend}");
    assert!(
        hidden_fields(&resend).contains(&("given_name".to_string(), "Robert".to_string())),
        "{resend}"
    );
    cleanup(&path);
}

/// §13.26 §7: the four sentences the design removes are rendered nowhere, on any page of the
/// flow, in either language. Each page named here is one that used to carry one of them: the
/// form named an address and carried the social note, the address refusal named an address,
/// and the `UserNotFoundException` row said the account signs in through a social provider.
/// The check runs on `account_readable`, because every page inlines the stylesheets.
#[test]
fn the_removed_sentences_are_rendered_nowhere() {
    let gone: [(&str, &str); 4] = [
        (GONE_SEND_TO, GONE_SEND_TO_IT),
        (GONE_SOCIAL_NOTE, GONE_SOCIAL_NOTE_IT),
        (GONE_NOT_YOUR_EMAIL, GONE_NOT_YOUR_EMAIL_IT),
        (GONE_NO_EMAIL_SIGN_IN, GONE_NO_EMAIL_SIGN_IN_IT),
    ];
    let check = |what: &str, body: &str| {
        let text = account_readable(body);
        for (en, it) in gone {
            for s in [en, it] {
                assert!(!text.contains(s), "{what}: `{s}` is a removed sentence");
            }
        }
    };
    let edit = profile_with(profile_same(), "given_name", "Robert");

    // The wired deployment: the page, the form for one address, several and none of the
    // caller's own, the code page, and the refusal of a posted `email`.
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("gone", &fake);
    let url = format!("{base}profile");
    for cookie in ["lang=en", "lang=it"] {
        check(
            "account page",
            &profile_get(&base, "bob@x.com", &[("Cookie", cookie)]).body,
        );
        for who in ["bob@x.com", "bob@x.com bob@old.com", "sam@elsewhere.com"] {
            check(
                "profile page",
                &profile_get(&url, who, &[("Cookie", cookie)]).body,
            );
        }
        check(
            "code page",
            &profile_post_as(
                &url,
                Some("bob@x.com"),
                &edit,
                "same-origin",
                true,
                &[("Cookie", cookie)],
            )
            .body,
        );
        check(
            "a posted email",
            &profile_post(
                &url,
                "bob@x.com",
                &edit
                    .clone()
                    .into_iter()
                    .chain([("email", "bob@x.com")])
                    .collect::<Vec<_>>(),
            )
            .body,
        );
    }
    cleanup(&path);

    // The two refusals that used to name a social sign-in or an address.
    let fake = FakeCognito::answering(vec![(
        "InitiateAuth",
        reply(
            400,
            r#"{"__type":"com.amazonaws.cognito#UserNotFoundException","message":"gone"}"#,
        ),
    )]);
    let (path, base) = profile_serve("gone-nouser", &fake);
    for cookie in ["lang=en", "lang=it"] {
        check(
            "the user is gone",
            &profile_post_as(
                &format!("{base}profile"),
                Some("bob@x.com"),
                &edit,
                "same-origin",
                true,
                &[("Cookie", cookie)],
            )
            .body,
        );
    }
    cleanup(&path);

    // A session with nothing to edit: the sentence it gets is the new one, not the old note.
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("gone-native", &fake);
    for cookie in ["lang=en", "lang=it"] {
        check(
            "no native username",
            &profile_get_as(
                &base,
                "bob@x.com",
                &profile_headers_no_native(),
                &[("Cookie", cookie)],
            )
            .body,
        );
        check(
            "no native username, posted",
            &profile_post_headers(
                &format!("{base}profile"),
                Some("bob@x.com"),
                &edit,
                "same-origin",
                true,
                &profile_headers_no_native(),
                &[("Cookie", cookie)],
            )
            .body,
        );
    }
    cleanup(&path);
}

/// §13.25 step 1, shown §13.26 §3: a session with no `X-Auth-Native-Username` (a federated
/// sign-in, or a cookie minted before the gate change) is offered nothing. The read-only
/// panel shows its claims and one sentence where the pill would be; `GET profile` is the
/// same page, and both `POST`s refuse with that sentence and no Cognito call. A deployment
/// that does not wire the edit says nothing about editing.
#[test]
fn a_session_with_no_native_username_gets_no_form_and_no_code() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("no-native", &fake);
    for who in ["bob@x.com", "stranger@elsewhere.com"] {
        let g = profile_get_no_native(&base, who);
        assert_eq!(g.status, 200, "{who}: {}", account_readable(&g.body));
        let panel = account_section(&g.body, "profile");
        assert!(
            anchors_to(&panel, "/account/profile").is_empty(),
            "{who}: no Edit pill: {panel}"
        );
        assert_eq!(
            panel.matches(NOT_NATIVE).count(),
            1,
            "{who}: exactly one sentence, inside #profile: {panel}"
        );
        assert!(
            muted_paragraphs(&panel).iter().any(|p| p == NOT_NATIVE),
            "{who}: it is a `p.muted`: {panel}"
        );
        // The claims are still read, and the form is not there.
        assert!(
            panel.contains("Bob"),
            "{who}: the panel still shows the claims: {panel}"
        );
        assert!(
            !panel.contains("name=\"given_name\""),
            "{who}: no form: {panel}"
        );

        let g = profile_get_no_native(&format!("{base}profile"), who);
        assert_eq!(g.status, 200, "{who}: GET profile is the same page");
        assert!(
            g.body.contains(NOT_NATIVE),
            "{who}: {}",
            account_readable(&g.body)
        );
        assert!(
            !g.body.contains("name=\"given_name\""),
            "{who}: no form on GET profile: {}",
            account_readable(&g.body)
        );

        let edit = profile_with(profile_same(), "given_name", "Robert");
        let g = profile_post_no_native(&format!("{base}profile"), who, &edit);
        assert_refused_before_cognito(&g, 400, &fake, "the start POST");
        assert!(
            g.body.contains(NOT_NATIVE),
            "{who}: the start refusal names the same sentence: {}",
            account_readable(&g.body)
        );
        assert!(
            !g.body.contains("class=\"err\""),
            "{who}: the person did nothing wrong, so this is not an error: {}",
            account_readable(&g.body)
        );
        let g = profile_post_no_native(
            &format!("{base}profile/code"),
            who,
            &[("code", "123456"), ("Session", FAKE_SESSION)],
        );
        assert_refused_before_cognito(&g, 400, &fake, "the code POST");
        assert!(
            g.body.contains(NOT_NATIVE),
            "{who}: the code refusal names the same sentence: {}",
            account_readable(&g.body)
        );
    }

    // The sentence is translated: this is the one sentence the page says to a person who
    // cannot act on it, so it has to speak the reader's language.
    let g = profile_get_as(
        &base,
        "bob@x.com",
        &profile_headers_no_native(),
        &[("Cookie", "lang=it")],
    );
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let panel = account_section(&g.body, "profile");
    assert!(
        panel.contains(NOT_NATIVE_IT),
        "the Italian page says it in Italian: {panel}"
    );
    assert!(
        !panel.contains(NOT_NATIVE),
        "an Italian page carries no English sentence: {panel}"
    );

    // A deployment that does not wire the edit says nothing about editing.
    let unwired = profile_settings("", PROFILE_POOL, PROFILE_CLAIMS);
    let (path2, base2) = profile_boot("no-native-unwired", &unwired, None, None, 1);
    let g = profile_get_no_native(&base2, "bob@x.com");
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    assert!(
        !g.body.contains(NOT_NATIVE),
        "no sentence about editing where there is no edit to offer: {}",
        account_readable(&g.body)
    );
    cleanup(&path);
    cleanup(&path2);
}

/// §13.25 step 2: the code is asked for the session's own Cognito user, the header's value,
/// and the request names no address at all. A stranger's own header names their own user.
#[test]
fn the_code_is_asked_for_the_sessions_own_username() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("own-username", &fake);
    let url = format!("{base}profile");

    let g = profile_post(
        &url,
        "bob@x.com",
        &profile_with(profile_same(), "given_name", "Robert"),
    );
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let calls = fake.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0].body["AuthFlow"], "USER_AUTH");
    assert_eq!(calls[0].body["AuthParameters"]["USERNAME"], FAKE_USERNAME);
    assert_eq!(
        calls[0].body["AuthParameters"]["PREFERRED_CHALLENGE"],
        "EMAIL_OTP"
    );
    assert!(
        !calls[0].body.to_string().contains("bob@x.com"),
        "the call names the username, never an address: {}",
        calls[0].body
    );

    // A stranger with no roster row, on their own username. The pool is scripted with
    // *their* username in the challenge: a reply naming bob would be the pool answering
    // for somebody else, which is the refusal the next test pins, not this one.
    let sam = "cog-sam-0002";
    let fake = FakeCognito::answering(vec![(
        "InitiateAuth",
        email_otp(sam, Some("s***@e***.com")),
    )]);
    let (path2, base2) = profile_serve("own-username-stranger", &fake);
    let g = profile_post_headers(
        &format!("{base2}profile"),
        Some("sam@elsewhere.com"),
        &profile_with(profile_same(), "given_name", "Samuel"),
        "same-origin",
        true,
        &profile_headers_for(sam),
        &[],
    );
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let calls = fake.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0].body["AuthParameters"]["USERNAME"], sam);
    assert!(
        !calls[0].body.to_string().contains("sam@elsewhere.com"),
        "the call names the username, never an address: {}",
        calls[0].body
    );
    cleanup(&path2);
    cleanup(&path);
}

/// A posted `email` is a non-editable name like any other (§13.26 §4): refused before
/// Cognito, naming the field.
#[test]
fn a_posted_email_field_is_refused_before_cognito() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("posted-email", &fake);
    let url = format!("{base}profile");
    for email in ["bob@x.com", "carol@x.com", ""] {
        let g = profile_post(
            &url,
            "bob@x.com",
            &profile_with(profile_same(), "given_name", "Robert")
                .into_iter()
                .chain([("email", email)])
                .collect::<Vec<_>>(),
        );
        assert_refused_before_cognito(&g, 400, &fake, &format!("email {email:?}"));
        assert!(
            visible_text(&g.body).contains(&format!(
                "email: {}",
                t(Lang::En, K::AccountProfileCannotEdit)
            )),
            "email: the sentence names the field: {}",
            account_readable(&g.body)
        );
    }
    cleanup(&path);
}

/// §13.25 step 2: a `ChallengeParameters.USERNAME` that is present and is not the header's
/// value is a refusal, and nothing further is sent. The pool answered for somebody else.
#[test]
fn a_challenge_for_another_username_is_refused() {
    let twin = "0f8fad5b-d9cb-469f-a165-70867728950e";
    // The `InitiateAuth` reply is the whole case, so the fake is scripted here rather than
    // through `flow_with`, whose two replies are the code step and the update.
    let fake = FakeCognito::answering(vec![
        ("InitiateAuth", email_otp(twin, Some("b***@x.com"))),
        ("UpdateUserAttributes", ok_empty()),
    ]);
    let (path, base) = profile_serve("c5-twin-challenge", &fake);
    let g = profile_post(
        &format!("{base}profile"),
        "bob@x.com",
        &profile_with(profile_same(), "given_name", "Robert"),
    );
    assert_eq!(g.status, 403, "{}", account_readable(&g.body));
    assert_eq!(
        fake.actions(),
        ["InitiateAuth"],
        "nothing further is sent to the pool"
    );
    assert_eq!(
        account_heading(&g.body, "h1"),
        t(Lang::En, K::AccountProfileNotSavedTitle),
        "{}",
        account_readable(&g.body)
    );
    assert!(lede_of(&g).contains(NOT_YOURS), "{}", lede_of(&g));
    assert!(!g.body.contains(twin), "the other user is not named");
    cleanup(&path);
}

/// The regression of rpi-01 (§13.25): the code is answered with a token for the **native
/// twin** of the session's email, a different Cognito user. The bind is the username, so
/// this is a refusal, and the twin is never written.
#[test]
fn the_rpi01_twin_is_never_written() {
    let twin = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let f = flow_with(
        "c5-rpi01-twin",
        signed_in(&token_from("bob@x.com", twin)),
        ok_empty(),
    );
    let g = start_bob(&f);
    let g = post_code(&f, "bob@x.com", &code_fields(&g, "123456"));
    assert_eq!(g.status, 403, "{}", account_readable(&g.body));
    assert_eq!(
        f.fake.actions(),
        ["InitiateAuth", "RespondToAuthChallenge"],
        "no `UpdateUserAttributes`: the twin's attributes stand"
    );
    assert_eq!(
        account_heading(&g.body, "h1"),
        t(Lang::En, K::AccountProfileNotSavedTitle),
        "{}",
        account_readable(&g.body)
    );
    assert!(lede_of(&g).contains(NOT_YOURS), "{}", lede_of(&g));
    assert!(!g.body.contains(twin), "the twin is not named");
    cleanup(&f.path);
}

/// §13.25 step 3: the code step answers the challenge with the username the **header**
/// names on that request, not a hidden field. A header that changed between the steps is
/// the one used, so the bind fails and nothing is written.
#[test]
fn the_code_step_uses_the_header_not_a_form_field() {
    let other = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let f = flow("c5-code-header");
    let g = start_bob(&f);
    let form = form_posting_to(&g.body, "/account/profile/code");
    assert!(
        !form.contains("name=\"username\""),
        "no username rides in the form: {form}"
    );
    let fields = code_fields(&g, "123456");
    f.fake.calls.lock().unwrap().clear();
    let g = post_code_with(&f, "bob@x.com", &fields, &[(NATIVE_USERNAME_HEADER, other)]);
    assert_eq!(g.status, 403, "{}", account_readable(&g.body));
    let calls = f.fake.calls();
    assert_eq!(calls.len(), 1, "one call, and no update: {calls:?}");
    assert_eq!(
        calls[0].body["ChallengeResponses"]["USERNAME"], other,
        "the code step answers with the header it arrived on"
    );
    assert_eq!(
        calls[0].target,
        format!("{CALL_PREFIX}RespondToAuthChallenge")
    );
    cleanup(&f.path);
}

/// §13.26 §4: the code page names Cognito's masked destination, escaped as every value is.
/// A destination that is absent, empty, over 254 characters, or holds a space, is not shown
/// at all, and the lede is the whole generic sentence.
#[test]
fn the_code_page_names_cognitos_masked_destination() {
    let shown = "e***@o***.com";
    for (name, destination, want) in [
        ("masked", Some(shown), true),
        ("escaped", Some("<b>&x</b>"), true),
        ("absent", None, false),
        ("empty", Some(""), false),
        ("space", Some("e***@o***. com"), false),
        ("long", Some(&"a".repeat(255)), false),
    ] {
        let fake = FakeCognito::answering(vec![(
            "InitiateAuth",
            email_otp(FAKE_USERNAME, destination),
        )]);
        let (path, base) = profile_serve(&format!("dest-{name}"), &fake);
        let g = profile_post(
            &format!("{base}profile"),
            "bob@x.com",
            &profile_with(profile_same(), "given_name", "Robert"),
        );
        assert_eq!(g.status, 200, "{name}: {}", account_readable(&g.body));
        let lede = element_containing(&g.body, "class=\"lede\"", "</p>");
        if want {
            let escaped = destination
                .unwrap()
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            assert!(
                lede.contains(&format!("<code>{escaped}</code>")),
                "{name}: the destination is in `code`: {lede}"
            );
            assert!(
                lede.contains(t(Lang::En, K::AccountProfileCodeSent)),
                "{name}: {lede}"
            );
            assert!(
                visible_text(&lede).contains(t(Lang::En, K::AccountProfileCodeLasts)),
                "{name}: {lede}"
            );
        } else {
            assert!(
                !lede.contains("<code>"),
                "{name}: nothing to name, so no `code`: {lede}"
            );
            assert!(lede.contains(CODE_SENT_NO_DEST), "{name}: {lede}");
            assert!(
                visible_text(&lede).contains(t(Lang::En, K::AccountProfileCodeLasts)),
                "{name}: {lede}"
            );
            // The same page in the other language the estate speaks: the generic sentence is
            // one key, so its Italian is what this person reads.
            let it_g = profile_post_as(
                &format!("{base}profile"),
                Some("bob@x.com"),
                &profile_with(profile_same(), "given_name", "Robert"),
                "same-origin",
                true,
                &[("Cookie", "lang=it")],
            );
            assert_eq!(
                it_g.status,
                200,
                "{name} (lang=it): {}",
                account_readable(&it_g.body)
            );
            let it_lede = element_containing(&it_g.body, "class=\"lede\"", "</p>");
            assert!(
                !it_lede.contains("<code>"),
                "{name} (lang=it): nothing to name, so no `code`: {it_lede}"
            );
            assert!(
                it_lede.contains(CODE_SENT_NO_DEST_IT),
                "{name} (lang=it): {it_lede}"
            );
            assert!(
                visible_text(&it_lede).contains(t(Lang::It, K::AccountProfileCodeLasts)),
                "{name} (lang=it): {it_lede}"
            );
        }
        cleanup(&path);
    }
}

/// An attribute outside the allowlist (configured but not editable, or not configured at
/// all) is refused with no call, and the page says which one.
#[test]
fn a_non_editable_attribute_is_refused_before_cognito() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("non-editable", &fake);
    let url = format!("{base}profile");
    for attr_name in [
        "phone_number",
        "preferred_username",
        "address",
        "custom:department",
        "nickname",
        "email_verified",
        "sub",
    ] {
        let g = profile_post(
            &url,
            "bob@x.com",
            &profile_with(profile_same(), "given_name", "Robert")
                .into_iter()
                .chain([(attr_name, "changed")])
                .collect::<Vec<_>>(),
        );
        assert_refused_before_cognito(&g, 400, &fake, attr_name);
        assert!(
            visible_text(&g.body).contains(&format!(
                "{attr_name} {}",
                t(Lang::En, K::AccountProfileCannotEdit)
            )) || visible_text(&g.body).contains(&format!(
                "{attr_name}: {}",
                t(Lang::En, K::AccountProfileCannotEdit)
            )),
            "{attr_name}: the sentence names the claim and says it cannot be changed here: {}",
            account_readable(&g.body)
        );
    }
    cleanup(&path);
}

/// A value over 2048 characters or holding a control character is refused with no call,
/// the page names the field by its visible label, marks it invalid and keeps what was
/// typed in the other fields.
#[test]
fn a_bad_value_names_the_field_by_its_label() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("bad-value", &fake);
    let url = format!("{base}profile");
    let long = "a".repeat(2049);
    for bad in [long.as_str(), "x\u{7}y", "line\nbreak"] {
        let fields = profile_with(
            profile_with(
                profile_same(),
                "given_name",
                Box::leak(bad.to_string().into_boxed_str()),
            ),
            "family_name",
            "Typed",
        );
        let g = profile_post(&url, "bob@x.com", &fields);
        assert_refused_before_cognito(&g, 400, &fake, "a bad value");
        let err = element_containing(&g.body, &format!("id=\"{ERR_ID}\""), "</div>");
        assert!(
            err.contains("class=\"err\""),
            "div.err carrying the shared id: {err}"
        );
        assert_eq!(
            visible_text(&err),
            format!(
                "{}: {}",
                t(Lang::En, K::AttrGivenName),
                t(Lang::En, K::AccountProfileValueBad)
            )
        );
        let i = input_named(&g.body, "given_name");
        assert_eq!(attr(&i, "aria-invalid").as_deref(), Some("true"), "{i}");
        assert_eq!(attr(&i, "aria-describedby").as_deref(), Some(ERR_ID), "{i}");
        assert_eq!(
            attr(&input_named(&g.body, "family_name"), "value").as_deref(),
            Some("Typed")
        );
    }
    cleanup(&path);
}

/// Nothing differs from what nginx forwarded (a trimmed value is the same value): no code
/// is sent, the form comes back as a `200` with a warning, not an error.
#[test]
fn an_unchanged_form_sends_no_code() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("unchanged", &fake);
    let url = format!("{base}profile");
    for fields in [
        profile_same(),
        profile_with(profile_same(), "given_name", "  Bob  "),
    ] {
        let g = profile_post(&url, "bob@x.com", &fields);
        assert_refused_before_cognito(&g, 200, &fake, "an unchanged form");
        let warn = element_containing(&g.body, "msg warn", "</div>");
        assert_eq!(
            visible_text(&warn),
            t(Lang::En, K::AccountProfileNothingChanged)
        );
        assert!(
            !g.body.contains("class=\"err\""),
            "not an error: {}",
            account_readable(&g.body)
        );
        assert!(form_posting_to(&g.body, "/account/profile").contains("name=\"given_name\""));
    }
    cleanup(&path);
}

/// The veto, a cross-site `POST`, a missing secret and a missing identity are each refused
/// with no call, and the new paths are fixed ones: anything under them is a `404`.
#[test]
fn the_profile_post_is_guarded_like_every_other_write() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("guards", &fake);
    let url = format!("{base}profile");
    let edit = profile_with(profile_same(), "given_name", "Robert");

    let g = profile_post_as(&url, Some("spammer@x.com"), &edit, "same-origin", true, &[]);
    assert_refused_before_cognito(&g, 403, &fake, "a denied caller");
    let g = profile_get(&url, "spammer@x.com", &[]);
    assert_eq!(g.status, 403, "a denied caller is not shown the form");

    let g = profile_post_as(&url, Some("bob@x.com"), &edit, "cross-site", true, &[]);
    assert_refused_before_cognito(&g, 403, &fake, "a cross-site POST");
    let g = profile_post_as(&url, Some("bob@x.com"), &edit, "same-origin", false, &[]);
    assert_refused_before_cognito(&g, 403, &fake, "no proxy secret");
    let g = profile_post_as(&url, None, &edit, "same-origin", true, &[]);
    assert_refused_before_cognito(&g, 401, &fake, "no identity header");

    for nothing in ["profile/nope", "profile/code/deeper"] {
        let g = profile_get(&format!("{base}{nothing}"), "bob@x.com", &[]);
        assert_eq!(g.status, 404, "{nothing}");
    }
    cleanup(&path);
}

/// One `InitiateAuth`: the target header, the content type, `USER_AUTH`, the native client
/// from the settings, the session's own username and `EMAIL_OTP`, and nothing secret beside
/// them. §13.26: the username, not an address, so the body names no email at all.
#[test]
fn starting_an_edit_asks_cognito_for_an_email_code() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("initiate", &fake);
    let g = profile_post(
        &format!("{base}profile"),
        "bob@x.com",
        &profile_with(profile_same(), "given_name", "Robert"),
    );
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    let calls = fake.calls();
    assert_eq!(calls.len(), 1, "exactly one call at the start: {calls:?}");
    let c = &calls[0];
    assert_eq!(c.target, "AWSCognitoIdentityProviderService.InitiateAuth");
    assert_eq!(c.content_type, "application/x-amz-json-1.1");
    assert_eq!(c.body["AuthFlow"], "USER_AUTH", "{}", c.body);
    assert_eq!(c.body["ClientId"], "email-client");
    assert_eq!(c.body["AuthParameters"]["USERNAME"], FAKE_USERNAME);
    assert_eq!(c.body["AuthParameters"]["PREFERRED_CHALLENGE"], "EMAIL_OTP");
    assert!(
        !c.body.to_string().contains('@'),
        "the call names a username, never an address: {}",
        c.body
    );
    assert!(
        c.body.get("ClientSecret").is_none()
            && c.body["AuthParameters"].get("SECRET_HASH").is_none()
    );
    cleanup(&path);
}

/// The code page: its own page, `no-store`, one code field made for a one-time code, the
/// clock said as a number in both languages, the session in a hidden field, and no script.
#[test]
fn the_code_page_carries_the_session_and_is_not_stored() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("code-page", &fake);
    let url = format!("{base}profile");
    for (lang, cookie, lasts, no_code) in [
        (Lang::En, "lang=en", "It works for 3 minutes.", NO_CODE),
        (Lang::It, "lang=it", "Vale per 3 minuti.", NO_CODE_IT),
    ] {
        let g = profile_post_as(
            &url,
            Some("bob@x.com"),
            &profile_with(profile_same(), "given_name", "Robert"),
            "same-origin",
            true,
            &[("Cookie", cookie)],
        );
        assert_eq!(g.status, 200, "{}", account_readable(&g.body));
        assert!(
            g.header("Cache-Control").unwrap_or("").contains("no-store"),
            "{:?}",
            g.headers
        );
        assert_eq!(
            account_heading(&g.body, "h1"),
            t(lang, K::AccountProfileCodeTitle)
        );
        let lede = element_containing(&g.body, "class=\"lede\"", "</p>");
        assert!(lede.contains("<code>b***@x.com</code>"), "{lede}");
        assert!(
            !lede.contains("bob@x.com"),
            "the masked destination, never the address: {lede}"
        );
        assert!(visible_text(&lede).contains(lasts), "{lede}");

        // The "no code arrived" hint says nothing about a social account: a session that
        // cannot get a code never reaches this page (§13.26 §5).
        assert!(
            muted_paragraphs(&g.body).iter().any(|p| p == no_code),
            "{lang:?}: the hint is the whole sentence: {}",
            account_readable(&g.body)
        );

        let form = form_posting_to(&g.body, "/account/profile/code");
        assert!(
            hidden_fields(&form).iter().any(|(_, v)| v == FAKE_SESSION),
            "the Session rides in a hidden field: {form}"
        );
        let code = input_named(&form, "code");
        for needle in [
            "type=\"text\"",
            "inputmode=\"numeric\"",
            "autocomplete=\"one-time-code\"",
            " required",
            "maxlength=\"32\"",
            " autofocus",
        ] {
            assert!(code.contains(needle), "{needle} in {code}");
        }
        assert!(!code.contains("pattern"), "{code}");
        let label = elements(&form, "<label", "</label>")
            .into_iter()
            .find(|l| l.contains("name=\"code\""))
            .expect("a label holds the code field");
        assert!(visible_text(&label).contains(t(lang, K::AccountProfileCodeLabel)));
        assert!(form.contains(t(lang, K::AccountProfileSave)));

        // Neither the script nor a handler beyond the menu's: every step of the profile
        // edit is a link or a form.
        let doc = g.body.to_ascii_lowercase();
        assert!(!doc.contains("<script"), "{}", account_readable(&g.body));
        assert!(
            account_extra_handlers(&g.body).is_empty(),
            "{:?}",
            account_extra_handlers(&g.body)
        );
    }
    let form = profile_get(&url, "bob@x.com", &[]);
    assert!(!form.body.to_ascii_lowercase().contains("<script"));
    assert!(
        account_extra_handlers(&form.body).is_empty(),
        "{:?}",
        account_extra_handlers(&form.body)
    );
    cleanup(&path);
}

/// Resend is starting over: a form of its own that re-posts the changed values to the start,
/// never the Session and never an address (§13.26 §4); submitting it asks Cognito again and
/// the new page lists the same changes.
#[test]
fn resend_starts_over_with_the_same_values() {
    let fake = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let (path, base) = profile_serve("resend", &fake);
    let url = format!("{base}profile");
    let g = profile_post(
        &url,
        "bob@x.com",
        &profile_with(profile_same(), "given_name", "Robert"),
    );
    assert_eq!(g.status, 200);
    let resend = form_posting_to(&g.body, "/account/profile");
    assert!(
        !resend.contains(FAKE_SESSION),
        "no Session in the resend form: {resend}"
    );
    assert!(
        resend.contains(t(Lang::En, K::AccountProfileSendNew)),
        "{resend}"
    );
    let hidden = hidden_fields(&resend);
    assert!(
        hidden.iter().all(|(k, _)| k != "email"),
        "no address rides in the resend form: {hidden:?}"
    );
    assert!(
        hidden.contains(&("given_name".into(), "Robert".into())),
        "{hidden:?}"
    );

    let fields: Vec<(&str, &str)> = hidden
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let g = profile_post(&url, "bob@x.com", &fields);
    assert_eq!(g.status, 200, "{}", account_readable(&g.body));
    assert_eq!(fake.actions(), ["InitiateAuth", "InitiateAuth"]);
    let changes = visible_text(&element_containing(&g.body, "changes", "</ul>"));
    assert!(
        changes.contains("Robert") && changes.contains("Bob"),
        "{changes}"
    );
    cleanup(&path);
}

/// What a person is told for each way the start can end, §13.23 §4's rows that 5b reaches:
/// the `h1`, the sentence, the status, and whether "Send a new code" is offered. Cognito's
/// own `message` text and the tokens never reach the page. The lede is spelled as text, not
/// as a `K`, because §13.26 §5 changes one of them and adds one, and each is asked in both
/// languages: a page that answers one language to a person who reads the other says nothing.
#[test]
fn each_start_outcome_states_its_result_in_the_h1() {
    let tokens = r#"{"AuthenticationResult":{"IdToken":"FAKEID.x.y","AccessToken":"FAKEACCESS","RefreshToken":"FAKEREFRESH"}}"#;
    let other = r#"{"ChallengeName":"PASSWORD_VERIFIER","ChallengeParameters":{},"Session":"FAKESESSION0123456789abcdefghijklmnop"}"#;
    let cases: Vec<(&str, Reply, u16, &str, &str)> = vec![
        (
            // §13.26 §4: the request names the pool's user by username, so a
            // `UserNotFoundException` now means the session's own user is gone from the
            // pool, which is a different sentence from the social one it used to mean.
            "user-not-found",
            reply(
                400,
                r#"{"__type":"com.amazonaws.cognito#UserNotFoundException","message":"secret-detail bob@x.com"}"#,
            ),
            400,
            NO_USER,
            NO_USER_IT,
        ),
        (
            "too-many",
            reply(
                400,
                r#"{"__type":"TooManyRequestsException","message":"secret-detail"}"#,
            ),
            502,
            t(Lang::En, K::AccountProfileTooMany),
            t(Lang::It, K::AccountProfileTooMany),
        ),
        (
            "other-error",
            reply(
                500,
                r#"{"__type":"InternalErrorException","message":"secret-detail"}"#,
            ),
            502,
            t(Lang::En, K::AccountProfileRefused),
            t(Lang::It, K::AccountProfileRefused),
        ),
        (
            "tokens-at-once",
            reply(200, tokens),
            502,
            t(Lang::En, K::AccountProfileRefused),
            t(Lang::It, K::AccountProfileRefused),
        ),
        (
            "other-challenge",
            reply(200, other),
            502,
            t(Lang::En, K::AccountProfileRefused),
            t(Lang::It, K::AccountProfileRefused),
        ),
        (
            "not-json",
            reply(200, "<html>nope</html>"),
            502,
            t(Lang::En, K::AccountProfileRefused),
            t(Lang::It, K::AccountProfileRefused),
        ),
        (
            // §13.25 step 2: the pool answered for a **different** user, so the code page is
            // never drawn. One outcome with a token for that user, one sentence.
            "challenge-other-username",
            email_otp("0f8fad5b-d9cb-469f-a165-70867728950e", Some("b***@x.com")),
            403,
            NOT_YOURS,
            NOT_YOURS_IT,
        ),
    ];
    for (name, answer, status, en, it) in cases {
        let fake = FakeCognito::answering(vec![("InitiateAuth", answer)]);
        let (path, base) = profile_serve(&format!("outcome-{name}"), &fake);
        for (lang, cookie, lede_text) in [(Lang::En, "lang=en", en), (Lang::It, "lang=it", it)] {
            let g = profile_post_as(
                &format!("{base}profile"),
                Some("bob@x.com"),
                &profile_with(profile_same(), "given_name", "Robert"),
                "same-origin",
                true,
                &[("Cookie", cookie)],
            );
            assert_eq!(
                g.status,
                status,
                "{name} ({cookie}): {}",
                account_readable(&g.body)
            );
            assert_eq!(
                account_heading(&g.body, "h1"),
                t(lang, K::AccountProfileNotSavedTitle),
                "{name} ({cookie})"
            );
            let lede = visible_text(&element_containing(&g.body, "class=\"lede\"", "</p>"));
            assert_eq!(lede, lede_text, "{name} ({cookie})");
            assert!(
                !anchors_to(&g.body, "href=\"/account/\"").is_empty(),
                "{name} ({cookie}): a way back"
            );
            assert!(
                !g.body.contains(t(lang, K::AccountProfileSendNew)),
                "{name} ({cookie}): nothing to resend"
            );
            for secret in [
                "secret-detail",
                "FAKEACCESS",
                "FAKEID",
                "FAKEREFRESH",
                FAKE_SESSION,
            ] {
                assert!(
                    !everything(&g).contains(secret),
                    "{name} ({cookie}): {secret} reached the response"
                );
            }
        }
        assert_eq!(fake.calls().len(), 2, "{name}: one call each, no retry");
        cleanup(&path);
    }
}

fn everything(g: &AccountGot) -> String {
    let mut all = String::new();
    for (k, v) in &g.headers {
        all.push_str(&format!("{k}: {v}\n"));
    }
    all.push_str(&g.body);
    all
}

/// A redirect from the API is a refusal, never a second host handed a token or a code: the
/// second listener sees nothing.
#[test]
fn a_cognito_call_follows_no_redirect() {
    let elsewhere = FakeCognito::answering(vec![("InitiateAuth", email_code_challenge())]);
    let fake = FakeCognito::answering(vec![(
        "InitiateAuth",
        Reply {
            status: 302,
            body: String::new(),
            location: Some(elsewhere.endpoint()),
        },
    )]);
    let (path, base) = profile_serve("redirect", &fake);
    let g = profile_post(
        &format!("{base}profile"),
        "bob@x.com",
        &profile_with(profile_same(), "given_name", "Robert"),
    );
    assert_eq!(g.status, 502, "{}", account_readable(&g.body));
    assert_eq!(fake.calls().len(), 1);
    assert!(
        elsewhere.calls().is_empty(),
        "the redirect target was called: {:?}",
        elsewhere.calls()
    );
    cleanup(&path);
}

/// A pool that never answers costs one worker the bound and no more: a `504` that says
/// nothing was changed and offers a new code, within the bound plus two seconds, and the
/// single worker then serves the next request.
#[test]
fn a_silent_cognito_answers_within_the_bound_and_frees_the_worker() {
    let fake = FakeCognito::silent();
    let (path, base) = profile_boot(
        "silent",
        &profile_wired(),
        Some(fake.endpoint()),
        Some(300),
        1,
    );
    let started = std::time::Instant::now();
    let g = profile_post(
        &format!("{base}profile"),
        "bob@x.com",
        &profile_with(profile_same(), "given_name", "Robert"),
    );
    let took = started.elapsed();
    assert_eq!(g.status, 504, "{}", account_readable(&g.body));
    assert!(
        took >= std::time::Duration::from_millis(250),
        "it waited for the bound: {took:?}"
    );
    assert!(
        took < std::time::Duration::from_millis(2300),
        "and not past it: {took:?}"
    );
    assert_eq!(
        account_heading(&g.body, "h1"),
        t(Lang::En, K::AccountProfileNotSavedTitle)
    );
    assert!(visible_text(&g.body).contains(t(Lang::En, K::AccountProfileNoAnswer)));
    assert!(
        form_posting_to(&g.body, "/account/profile")
            .contains(t(Lang::En, K::AccountProfileSendNew)),
        "a new code is offered"
    );
    let next = profile_get(&base, "bob@x.com", &[]);
    assert_eq!(next.status, 200, "the only worker is free again");
    cleanup(&path);
}

/// The production bound is the one the design says, and the production config names no fake.
#[test]
fn the_cognito_bound_is_five_seconds_and_no_env_names_a_fake() {
    assert_eq!(COGNITO_TIMEOUT, std::time::Duration::from_secs(5));
    let cfg = cfg_for("x", "/admin");
    assert!(cfg.cognito_endpoint.is_none());
    assert_eq!(cfg.cognito_timeout, COGNITO_TIMEOUT);
}
