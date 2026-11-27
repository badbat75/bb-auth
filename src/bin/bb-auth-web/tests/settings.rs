use super::*;

// --- the settings page ---------------------------------------------------

#[test]
fn the_settings_page_writes_the_five_and_the_administrators() {
    let path = scratch("cfg-write", SAMPLE);
    let cfg = cfg_for(&path, "");
    let sp = cfg.settings_path.clone();
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[
                ("identity", "email\nuuid"),
                ("claims", " given_name \n\n family_name "),
                ("ttl", "604800"),
                ("social", "on"),
                ("providers", "Google"),
                ("admins", "admin@x.com\nAnother@X.com"),
            ],
        ),
    );
    assert_eq!(got.location(), "/config?msg=settings-saved");

    let (_, s) = open_settings_file(&sp).unwrap();
    assert_eq!(
        s.identity_attrs
            .iter()
            .map(|a| a.attr.as_str())
            .collect::<Vec<_>>(),
        vec!["email", "uuid"]
    );
    // Trimmed, blanks dropped, and the header derived rather than configured.
    assert_eq!(s.profile_claims[1].header, "X-Auth-Family-Name");
    assert_eq!(s.session_ttl, 604_800);
    assert!(s.allow_unverified_social);
    assert_eq!(s.social_providers, Some(vec!["Google".to_string()]));
    assert_eq!(s.admins.len(), 2);
    // The access file was not touched: this page edits the other one.
    assert_eq!(read(&path), SAMPLE);
    cleanup(&path);
}

#[test]
fn the_settings_page_writes_the_look_and_refuses_one_it_cannot() {
    let path = scratch("cfg-look", SAMPLE);
    let cfg = cfg_for(&path, "");
    let sp = cfg.settings_path.clone();
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[
                ("brand", "  BadBat75  "),
                ("stylesheet", "https://assets.badbat75.com/css/theme.css"),
                ("logo", "/img/logo.png"),
                ("ui_theme", "dark"),
            ],
        ),
    );
    assert_eq!(got.location(), "/config?msg=settings-saved");
    let (_, s) = open_settings_file(&sp).unwrap();
    assert_eq!(s.brand_name.as_deref(), Some("BadBat75"), "trimmed");
    assert_eq!(
        s.stylesheet_url.as_deref(),
        Some("https://assets.badbat75.com/css/theme.css")
    );
    assert_eq!(s.logo_url.as_deref(), Some("/img/logo.png"));
    assert_eq!(s.theme, UiTheme::Dark);

    // A URL the library refuses is refused HERE, attributed to the field that carries it,
    // and nothing is written: the same shape every other refusal on this page has.
    let before = read(&sp);
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(&rev_of(&sp), &[("stylesheet", "javascript:alert(1)")]),
    );
    let (status, body) = got.page();
    assert_eq!(status, 400, "{body}");
    // What the message has to do is say what the field wants. It used to be asserted by
    // finding the wire key `stylesheet_url` in it, which is the English sentence §13.31
    // replaces with the page's own words; the shape it names is what stays true of both.
    assert!(err_text(body).contains("https://"), "{body}");
    assert!(
        body.contains(r#"class="f-stylesheet invalid""#),
        "the refusal must point at the field: {body}"
    );
    assert_eq!(read(&sp), before, "nothing written");
    cleanup(&path);
}

#[test]
fn the_settings_form_saves_the_landing_url() {
    let path = scratch("cfg-landing", SAMPLE);
    let cfg = cfg_for(&path, "");
    let sp = cfg.settings_path.clone();
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[("landing_url", "  https://auth.badbat75.com/account/  ")],
        ),
    );
    assert_eq!(got.location(), "/config?msg=settings-saved");
    let (_, s) = open_settings_file(&sp).unwrap();
    assert_eq!(
        s.landing_url, "https://auth.badbat75.com/account/",
        "trimmed"
    );

    // An empty field is the setting being unset, and the key leaves the file.
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(&rev_of(&sp), &[("landing_url", "")]),
    );
    assert_eq!(got.location(), "/config?msg=settings-saved");
    assert_eq!(open_settings_file(&sp).unwrap().1.landing_url, "");
    assert!(!read(&sp).contains("landing_url"), "{}", read(&sp));
    cleanup(&path);
}

#[test]
fn the_settings_form_refuses_a_landing_url_off_the_authorized_hosts() {
    let path = scratch("cfg-landing-off", SAMPLE);
    let cfg = cfg_for(&path, "");
    let sp = cfg.settings_path.clone();
    let before = read(&sp);
    // Syntactically fine, and a host `gate.authorized_hosts` does not cover: `safe_rd`
    // would refuse it at every login, so the form must say so on the way to disk.
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[("landing_url", "https://evil.example.org/account/")],
        ),
    );
    let (status, body) = got.page();
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("landing_url"), "{body}");
    assert!(
        body.contains(r#"class="f-landing_url invalid""#),
        "the refusal must point at the field: {body}"
    );
    // The field is on the page, labelled in the reader's language, with its help line.
    assert!(body.contains(t(Lang::En, K::GlobalLandingUrl)), "{body}");
    assert!(body.contains("name=\"landing_url\""), "{body}");
    assert_eq!(read(&sp), before, "nothing written");

    // A malformed one is refused the same way, by the same field.
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[("landing_url", "http://auth.badbat75.com/")],
        ),
    );
    let (status, body) = got.page();
    assert_eq!(status, 400, "{body}");
    assert!(body.contains(r#"class="f-landing_url invalid""#), "{body}");
    assert_eq!(read(&sp), before, "nothing written");
    cleanup(&path);
}

// --- a settings refusal in the reader's words (§13.31 S8) -----------------

/// The five codes this page's own form can never produce (§13.31 §5), each for a reason the
/// form's construction gives. Each is mapped to one wrapper around the library's English
/// sentence and attributed to nothing: the operator who meets these is at a shell, and the
/// English is exactly what `--check-settings` will say there.
const FILE_ONLY: [&str; 5] = [
    "version",
    "button_bare_name",
    "button_no_idp",
    "button_idp_charset",
    "button_twice",
];

/// Every wire key a translated refusal must not contain (§13.31 §6). A message names the
/// label the reader sees, never the name the file gives the setting: a message quoting
/// `profile_claims` is the sentence the CLI prints, and showing that on an Italian page is
/// the thing this slice ends. `issuer` is absent because its label, "User pool (issuer)",
/// carries the word in both languages.
const WIRE_KEYS: [&str; 19] = [
    "profile_claims",
    "identity_attrs",
    "session_ttl_secs",
    "client_id",
    "login_url",
    "denied_url",
    "landing_url",
    "cookie_domain",
    "authorized_hosts",
    "oauth_domain",
    "social_callback_url",
    "social_buttons",
    "client_ip_header",
    "request_id_header",
    "audit.rotation",
    "audit.retention",
    "stylesheet_url",
    "logo_url",
    "brand_name",
];

/// The text of a form's refusal block, as the reader reads it. Asserted on **instead of**
/// the body: the body carries `name="landing_url"` and every other wire name the form has,
/// so a body-wide search for a wire key passes whatever the message says (§13.31 §6).
fn err_text(html: &str) -> String {
    const AT: &str = "<div class=\"err\" id=\"form-error\">";
    let at = html
        .find(AT)
        .unwrap_or_else(|| panic!("the page must carry a refusal block: {html}"));
    let rest = &html[at + AT.len()..];
    rest.split("</div>").next().unwrap_or(rest).to_string()
}

/// `true` when `s` still holds a `{digit}`: a placeholder that reached the page unfilled.
fn holds_placeholder(s: &str) -> bool {
    let b = s.as_bytes();
    (0..b.len()).any(|i| b[i] == b'{' && b.get(i + 1).is_some_and(|c| c.is_ascii_digit()))
}

/// The visible label a refusal's message must start with, for the field it marks
/// (docs/ARCHITECTURE.md §13.31 §10): the page's own map from a field's `name=` to the
/// label printed above it. One map, read by the walk over the page's own refusals and by
/// the walk over the library's, so the two cannot disagree about what "starts with the
/// label" means. Three messages name more than the field they mark, and say so at the call
/// site: the two app-client rows ("App client for …", which has no label of its own), the
/// half-wired social pair, and the audit's rotation/retention pair.
fn field_label(lang: Lang, field: &str) -> String {
    let k = match field {
        "ttl" => K::SessionTtl,
        "admins" => K::Admins,
        "issuer" => K::Issuer,
        "hosts" => K::AuthorizedHosts,
        "ui_theme" => K::DefaultTheme,
        "claims" => K::ProfileClaims,
        "identity" => K::IdentityAttrs,
        "cookie_domain" => K::CookieDomain,
        "brand" => K::BrandName,
        "domain" => K::OauthDomain,
        "callback" => K::SocialCallback,
        "login_url" => K::GlobalLoginUrl,
        "denied_url" => K::GlobalDeniedUrl,
        "landing_url" => K::GlobalLandingUrl,
        "stylesheet" => K::StylesheetUrl,
        "logo" => K::LogoUrl,
        "client_ip_header" => K::ClientIpHeader,
        "request_id_header" => K::RequestIdHeader,
        "audit_rotation" => K::AuditRotation,
        "audit_retention" => K::AuditRetention,
        _ => panic!("this test's map knows no field {field:?}"),
    };
    t(lang, k).to_string()
}

/// The prefix of an app-client refusal: the row's heading, behind the words the row's
/// message opens with. Spelled here because no `K` key names those words on their own:
/// they are the front of `ClientIdNeeded`, `AudienceNeeded` and `SetRefAppClientId`.
fn app_client_prefix(lang: Lang, who: &str) -> String {
    match lang {
        Lang::En => format!("App client for {who}"),
        Lang::It => format!("App client per {who}"),
    }
}

/// "A and B" / "A e B": the join of the two labels a refusal names at once.
fn two_labels(lang: Lang, a: &str, b: &str) -> String {
    match lang {
        Lang::En => format!("{a} and {b}"),
        Lang::It => format!("{a} e {b}"),
    }
}

/// The raw contents of the string literal that starts at `at` (a `"`), and the index just
/// after its closing quote. A `\` skips the next character, which is what makes a `\` at
/// the end of a line (rustfmt's continuation) part of the literal.
fn string_literal(src: &str, at: usize) -> (String, usize) {
    let b = src.as_bytes();
    assert_eq!(b[at], b'"', "a string literal starts at a quote");
    let mut i = at + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return (src[at + 1..i].to_string(), i + 1),
            _ => i += 1,
        }
    }
    panic!("an unterminated string literal");
}

/// A string literal's contents as the compiler reads them: `\"`, `\\`, `\n`, `\r`, `\t`,
/// `\0` and `\u{…}` become their character, and a `\` at the end of a line drops the
/// newline and the next line's leading whitespace. The test compares the words the page
/// shows, so it has to read them the way the binary does.
fn unescape(src: &str) -> String {
    let cs: Vec<char> = src.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < cs.len() {
        if cs[i] != '\\' {
            out.push(cs[i]);
            i += 1;
            continue;
        }
        i += 1;
        assert!(i < cs.len(), "a literal ends in a backslash");
        match cs[i] {
            '\n' => {
                i += 1;
                while matches!(cs.get(i), Some(' ') | Some('\t')) {
                    i += 1;
                }
            }
            '"' => {
                out.push('"');
                i += 1;
            }
            '\\' => {
                out.push('\\');
                i += 1;
            }
            'n' => {
                out.push('\n');
                i += 1;
            }
            'r' => {
                out.push('\r');
                i += 1;
            }
            't' => {
                out.push('\t');
                i += 1;
            }
            '0' => {
                out.push('\0');
                i += 1;
            }
            'u' => {
                assert_eq!(
                    cs.get(i + 1),
                    Some(&'{'),
                    "a unicode escape names its braces"
                );
                let close = i
                    + 2
                    + cs[i + 2..]
                        .iter()
                        .position(|c| *c == '}')
                        .expect("a closing brace");
                let hex: String = cs[i + 2..close].iter().collect();
                let n = u32::from_str_radix(&hex, 16).expect("a code point in hex");
                out.push(char::from_u32(n).expect("a character"));
                i = close + 1;
            }
            c => panic!("an escape this test does not read: \\{c}"),
        }
    }
    out
}

/// The Italian of every arm of `fn t`, with the keys that arm answers for.
///
/// `K` has no list of its variants and none is added for a test, so the table is read
/// where it is written: `k_text.rs`, one directory up from this topic file, from the
/// signature of `fn t` to the first brace at column 0 (rustfmt indents every inner
/// block, so that brace closes the function), arm by arm. Each arm's third argument is
/// the Italian. An arm that answers for several keys is reported under all of them, so a
/// fault in a shared string names every key that shows it (§13.31 §10a).
fn italian_k_strings() -> Vec<(String, String)> {
    const SRC: &str = include_str!("../k_text.rs");
    const HEAD: &str = "fn t(lang: Lang, key: K) -> &'static str {";
    let start = SRC.find(HEAD).expect("the translation function, by name") + HEAD.len();
    let end = start
        + SRC[start..]
            .find("\n}")
            .expect("the translation function's end");
    let body = &SRC[start..end];
    let mut out = Vec::new();
    let mut from = 0;
    // Two spellings, both rustfmt's doing: `=> m(lang, "…", "…")` on one line, and
    // `=> m(` with the two strings on their own lines when the pair is long. The scan
    // takes the arm, then its first string (the English) and the one after it (the
    // Italian), which is the same in both.
    while let Some(rel) = body[from..].find("=> m(") {
        let arrow = from + rel;
        let keys: Vec<String> = body[from..arrow]
            .split_whitespace()
            .filter_map(|w| {
                w.strip_prefix("K::")
                    .map(|k| k.trim_end_matches('|').to_string())
            })
            .collect();
        assert!(!keys.is_empty(), "an arm names at least one key: {keys:?}");
        let en = arrow + body[arrow..].find('"').expect("the English literal");
        let (_, after_en) = string_literal(body, en);
        let it = after_en + body[after_en..].find('"').expect("the Italian literal");
        let (raw, _) = string_literal(body, it);
        out.push((keys.join(" | "), unescape(&raw)));
        from = it;
    }
    out
}

/// The index of every apostrophe written in place of an accent (§13.31 §10).
///
/// The rule, exactly: `'` (U+0027) is a fault when the character before it is a plain
/// vowel (`a e i o u A E I O U`) and the character after it is not a letter, **unless it
/// closes a quotation**, where a quotation opens at a `'` that starts the string or follows
/// a space or `(`, and closes at the next `'` followed by a non-letter. The quotation arm
/// is not decoration: the page's own Italian quotes (`'chiunque'`, `'@nome'`) close after a
/// vowel, which is exactly the shape of the fault, and a rule that flagged them would be a
/// rule an operator answers by deleting the accents.
fn accent_faults(s: &str) -> Vec<usize> {
    let cs: Vec<char> = s.chars().collect();
    let letter = |c: char| c.is_alphabetic();
    let vowel = |c: char| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'A' | 'E' | 'I' | 'O' | 'U');
    let mut out = Vec::new();
    let mut quoted = false;
    for (i, c) in cs.iter().enumerate() {
        if *c != '\'' {
            continue;
        }
        let before = i.checked_sub(1).map(|j| cs[j]);
        let after = cs.get(i + 1).copied();
        if quoted {
            if !after.is_some_and(letter) {
                quoted = false;
            }
            continue;
        }
        if before.is_none_or(|b| b == ' ' || b == '(') {
            quoted = true;
            continue;
        }
        if before.is_some_and(vowel) && !after.is_some_and(letter) {
            out.push(i);
        }
    }
    out
}

/// Every code says something on this page, in both languages, on a field, in this page's
/// own words (§13.31 §6).
///
/// The mapping is a pure function, so this one test covers all 46 codes; the route needs
/// one test per path into it, which is what the two below are.
#[test]
fn every_settings_refusal_reads_in_both_languages() {
    let samples = bb_auth_core::settings_refusal_samples();
    assert_eq!(
        samples.len(),
        bb_auth_core::SETTINGS_REFUSAL_CODES.len(),
        "one sample per code"
    );
    for r in &samples {
        let code = r.code();
        let english = settings_refusal(Lang::En, r);
        let italian = settings_refusal(Lang::It, r);
        for (lang, got) in [(Lang::En, &english), (Lang::It, &italian)] {
            let name = lang.code();
            assert!(!got.msg.is_empty(), "{code} in {name}: an empty message");
            assert!(
                !holds_placeholder(&got.msg),
                "{code} in {name}: a placeholder reached the page unfilled: {:?}",
                got.msg
            );
            if FILE_ONLY.contains(&code) {
                assert!(
                    got.msg.contains(&r.to_string()),
                    "{code} in {name}: the wrapper must carry the gate's own sentence, \
                         which is what the operator meets at the shell: {:?}",
                    got.msg
                );
                assert!(
                    got.field.is_none(),
                    "{code} in {name}: this form cannot produce it, so it marks no field"
                );
            } else {
                assert!(
                    got.field.is_some(),
                    "{code} in {name}: a refusal this form can produce marks the field it \
                         is about"
                );
                // The label rule of the page's own refusals (§10) reaches the three
                // library arms that reuse the page's keys, and every arm that fills a
                // label: the message opens with the label of the field it marks. The map
                // is the walk's, so the two read the same pair.
                let field = got.field.as_deref().unwrap();
                let label = if field == "client_id" {
                    app_client_prefix(lang, t(lang, K::SignInEmail))
                } else if let Some(idp) = field.strip_prefix("aud-") {
                    app_client_prefix(lang, social_idp_label(idp))
                } else if code == "social_half_configured" {
                    two_labels(lang, t(lang, K::OauthDomain), t(lang, K::SocialCallback))
                } else if code == "audit_unbounded" {
                    two_labels(lang, t(lang, K::AuditRotation), t(lang, K::AuditRetention))
                } else {
                    field_label(lang, field)
                };
                assert!(
                    got.msg.starts_with(&format!("{label}:")),
                    "{code} in {name}: the message must open with the label of the field \
                         it marks ({label:?}): {:?}",
                    got.msg
                );
                assert!(
                    !got.msg.contains(&r.to_string()),
                    "{code} in {name}: the page shows its own words, not the library's: {:?}",
                    got.msg
                );
                for key in WIRE_KEYS {
                    assert!(
                        !got.msg.contains(key),
                        "{code} in {name}: the message names the label, not the file's key \
                             {key:?}: {:?}",
                        got.msg
                    );
                }
            }
        }
        assert_ne!(
            english.msg, italian.msg,
            "{code}: the English and the Italian are one string"
        );
    }
}

/// `fill` substitutes once, so an argument that looks like a placeholder stays text
/// (§13.31 §4, and the same reason `render_page` gives for its own substitution).
#[test]
fn fill_is_single_pass() {
    assert_eq!(fill("{0} and {1}", &["one", "two"]), "one and two");
    assert_eq!(fill("{1} then {0}", &["one", "two"]), "two then one");
    assert_eq!(fill("{0}: {0}", &["Name"]), "Name: Name");
    assert_eq!(fill("nothing to fill", &["x"]), "nothing to fill");
    // The single pass, both ways: what one placeholder expands to is never rescanned, so a
    // typed value that spells a placeholder cannot inject a second round of substitution.
    assert_eq!(fill("{0} {1}", &["a", "{0}"]), "a {0}");
    assert_eq!(fill("{0} {1}", &["{1}", "{0}"]), "{1} {0}");
}

/// The landing page off the authorized hosts, refused on an Italian page, names the two
/// labels an operator can see ("Pagina di arrivo", "Host autorizzati") and neither wire
/// key, and still marks its own field (§13.31 §6).
///
/// Over the socket with the `lang=it` cookie, because the language is negotiated from the
/// request: the in-process `post` renders the English view.
#[test]
fn an_italian_settings_refusal_names_the_labels() {
    let path = scratch("cfg-landing-it", SAMPLE);
    let cfg = cfg_for(&path, "/admin");
    let sp = cfg.settings_path.clone();
    let port = serve(&path, "/admin");
    let url = format!(
        "http://127.0.0.1:{port}{ADMIN_BASE}{}",
        Route::Config.path()
    );
    let before = read(&sp);
    let rev = rev_of(&sp);
    let fields = settings_fields(
        &rev,
        &[("landing_url", "https://evil.example.org/account/")],
    );
    // The same request `console_post` makes, plus the cookie: the language the page answers
    // in is the thing under test.
    let _permit = WRITE_PERMIT.lock().unwrap_or_else(|e| e.into_inner());
    let r = post_with_secret(&url)
        .header(IDENTITY_HEADER, "admin@x.com")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Cookie", "lang=it")
        .send_form(fields.iter().copied())
        .expect("a POST response");
    let got = got_of(r);
    assert_eq!(got.status, 400, "{got:?}");
    let err = err_text(&got.body);
    assert!(err.contains("Pagina di arrivo"), "{err}");
    assert!(err.contains("Host autorizzati"), "{err}");
    assert!(!err.contains("landing_url"), "{err}");
    assert!(!err.contains("authorized_hosts"), "{err}");
    assert!(
        got.body.contains(r#"class="f-landing_url invalid""#),
        "the refusal must still point at the field: {}",
        got.body
    );
    assert_eq!(read(&sp), before, "nothing written");
    cleanup(&path);
}

/// A host the cookie domain cannot reach, refused on an Italian save, says §4's Italian
/// sentence on the hosts field (§13.31 §6, S9).
///
/// Red today because `ConfigForm::apply` makes this cross-check itself and answers it with
/// an inline English `format!` (the `'…' is outside cookie_domain '…'` sentence), so the
/// refusal never reaches `settings_refusal` and an Italian page shows English. S9 removes
/// the duplicate check, and the refusal arrives from `SettingsWrite::prepare` instead.
#[test]
fn the_settings_form_says_a_stray_host_in_italian() {
    let path = scratch("cfg-stray-host-it", SAMPLE);
    let cfg = cfg_for(&path, "/admin");
    let sp = cfg.settings_path.clone();
    let port = serve(&path, "/admin");
    let url = format!(
        "http://127.0.0.1:{port}{ADMIN_BASE}{}",
        Route::Config.path()
    );
    let before = read(&sp);
    let rev = rev_of(&sp);
    // Only the cookie domain is typed in: the fixture's hosts stay exactly as the file has
    // them, so no host is taken away and the save stays out of the guarded changes, which
    // would answer a confirmation page ahead of the refusal under test.
    let fields = settings_fields(&rev, &[("cookie_domain", ".example.com")]);
    let _permit = WRITE_PERMIT.lock().unwrap_or_else(|e| e.into_inner());
    let r = post_with_secret(&url)
        .header(IDENTITY_HEADER, "admin@x.com")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Cookie", "lang=it")
        .send_form(fields.iter().copied())
        .expect("a POST response");
    let got = got_of(r);
    assert_eq!(got.status, 400, "{got:?}");
    let err = err_text(&got.body);
    // §4's sentence verbatim, with the two labels and the two values filled in: the label
    // of the field the refusal marks, the cookie domain's label, the domain, and every
    // stray host joined by ", ". Compared byte for byte: maud escapes `&`, `<`, `>` and
    // the double quote only, so an apostrophe reaches the page as the design spells it.
    let want = "Host autorizzati: il Dominio del cookie '.example.com' non raggiunge \
                    badbat75.com, *.badbat75.com, quindi un accesso che arriva lì non porta \
                    il cookie di sessione e torna in ciclo alla pagina di accesso.";
    assert_eq!(err, want, "{err}");
    assert!(
        got.body.contains(r#"class="f-hosts invalid""#),
        "the refusal must point at the hosts box: {}",
        got.body
    );
    assert_eq!(read(&sp), before, "nothing written");
    cleanup(&path);
}

/// The two audit headers naming one header, refused on an Italian save, says §4's Italian
/// sentence on the request id field (§13.31 §6, S9).
///
/// Red today for the same reason as the stray host: `apply` compares the two itself and
/// answers with an inline English `format!` (`'…' is already the client address header`),
/// so the page never sees `SettingsRefusal::AuditHeadersSame`.
#[test]
fn the_settings_form_says_a_shared_audit_header_in_italian() {
    let path = scratch("cfg-shared-header-it", SAMPLE);
    let cfg = cfg_for(&path, "/admin");
    let sp = cfg.settings_path.clone();
    let port = serve(&path, "/admin");
    let url = format!(
        "http://127.0.0.1:{port}{ADMIN_BASE}{}",
        Route::Config.path()
    );
    let before = read(&sp);
    let rev = rev_of(&sp);
    let fields = settings_fields(
        &rev,
        &[
            ("client_ip_header", "X-Forwarded-For"),
            ("request_id_header", "X-Forwarded-For"),
        ],
    );
    let _permit = WRITE_PERMIT.lock().unwrap_or_else(|e| e.into_inner());
    let r = post_with_secret(&url)
        .header(IDENTITY_HEADER, "admin@x.com")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Cookie", "lang=it")
        .send_form(fields.iter().copied())
        .expect("a POST response");
    let got = got_of(r);
    assert_eq!(got.status, 400, "{got:?}");
    let err = err_text(&got.body);
    // §4's sentence verbatim: the field it marks, the header both boxes name, and the
    // label of the other box, which is the one the operator has to go and change. Byte
    // for byte, as in the test above: maud leaves an apostrophe alone.
    let want = "Header dell'id della richiesta: 'X-Forwarded-For' è già l'Header \
                    dell'indirizzo del client; un solo header non può portare sia un indirizzo \
                    sia un id di richiesta.";
    assert_eq!(err, want, "{err}");
    assert!(
        got.body.contains(r#"class="f-request_id_header invalid""#),
        "the refusal must point at the request id box: {}",
        got.body
    );
    assert_eq!(read(&sp), before, "nothing written");
    cleanup(&path);
}

/// Every refusal of the page's own reads "label: what is allowed." in the reader's
/// language, on the field that can fix it, in both languages (§13.31 §10, §10a).
///
/// Over the socket with the `lang` cookie, because the language is negotiated from the
/// request and the page's own refusals are raised by `ConfigForm::apply`, which the
/// in-process `post` answers in English only. The message is read out of the `div.err`
/// block and not out of the body: the body carries every help text on the page, and a
/// help text is not the refusal.
///
/// The expected text is spelled out here, in both languages, because these are the words
/// the designer wrote and the operator reads: a test that only asserted "starts with a
/// colon" would pass on any sentence.
#[test]
fn every_config_refusal_starts_with_its_label() {
    // One row per refusal `ConfigForm::apply` raises, plus the one the library raises that
    // this page answers with its own key (`domain`, from `social_half_configured`). `over`
    // is the form that triggers it, on top of `settings_fields`'s defaults.
    #[derive(Debug)]
    struct Case {
        field: &'static str,
        en_label: &'static str,
        it_label: &'static str,
        over: Vec<(&'static str, &'static str)>,
        /// The whole message, byte for byte, in each language, where this row's words are
        /// the point of the row (the two administrators refusals, §13.31 §10).
        words: Option<(&'static str, &'static str)>,
    }
    let cases = vec![
        Case {
            field: "ttl",
            en_label: "Session lifetime",
            it_label: "Durata della sessione",
            over: vec![("ttl", "abc")],
            words: None,
        },
        Case {
            field: "admins",
            en_label: "Administrators",
            it_label: "Amministratori",
            over: vec![("admins", "")],
            words: Some((
                "Administrators: at least one is needed; an empty list must never come to \
                     mean 'everyone'.",
                "Amministratori: ne serve almeno uno; una lista vuota non deve mai finire \
                     per significare 'chiunque'.",
            )),
        },
        Case {
            field: "admins",
            en_label: "Administrators",
            it_label: "Amministratori",
            over: vec![("admins", "someone@else.com")],
            words: Some((
                "Administrators: your own address must stay on the list; to remove \
                     yourself, use bb-auth-adm over SSH.",
                "Amministratori: il tuo indirizzo deve restare nella lista; per rimuovere \
                     te stesso usa bb-auth-adm via SSH.",
            )),
        },
        Case {
            field: "client_id",
            en_label: "App client for Email and code",
            it_label: "App client per Email e codice",
            over: vec![("client_id", "")],
            words: None,
        },
        Case {
            field: "issuer",
            en_label: "User pool (issuer)",
            it_label: "User pool (issuer)",
            over: vec![("issuer", "")],
            words: None,
        },
        Case {
            field: "hosts",
            en_label: "Authorized hosts",
            it_label: "Host autorizzati",
            over: vec![("hosts", "")],
            words: None,
        },
        Case {
            field: "aud-Google",
            en_label: "App client for Google",
            it_label: "App client per Google",
            over: vec![("idps", "Google"), ("idp-Google", "on"), ("aud-Google", "")],
            words: None,
        },
        Case {
            field: "ui_theme",
            en_label: "Default appearance",
            it_label: "Aspetto predefinito",
            over: vec![("ui_theme", "purple")],
            words: None,
        },
        Case {
            field: "domain",
            en_label: "Hosted UI domain and Callback URL",
            it_label: "Dominio della hosted UI e URL di callback",
            over: vec![
                ("idps", "Google"),
                ("idp-Google", "on"),
                ("aud-Google", "google-client"),
                ("domain", ""),
                ("callback", ""),
            ],
            words: None,
        },
    ];
    let path = scratch("cfg-labels", SAMPLE);
    let cfg = cfg_for(&path, "/admin");
    let sp = cfg.settings_path.clone();
    let port = serve(&path, "/admin");
    let url = format!(
        "http://127.0.0.1:{port}{ADMIN_BASE}{}",
        Route::Config.path()
    );
    let before = read(&sp);
    let rev = rev_of(&sp);
    for c in &cases {
        let mut said: Vec<String> = Vec::new();
        for (cookie, label, words) in [
            ("lang=en", c.en_label, c.words.map(|w| w.0)),
            ("lang=it", c.it_label, c.words.map(|w| w.1)),
        ] {
            let fields = settings_fields(&rev, &c.over);
            let _permit = WRITE_PERMIT.lock().unwrap_or_else(|e| e.into_inner());
            let r = post_with_secret(&url)
                .header(IDENTITY_HEADER, "admin@x.com")
                .header("Sec-Fetch-Site", "same-origin")
                .header("Cookie", cookie)
                .send_form(fields.iter().copied())
                .expect("a POST response");
            let got = got_of(r);
            assert_eq!(got.status, 400, "{cookie} {:?} {c:?}", got);
            let err = err_text(&got.body);
            assert!(
                err.starts_with(&format!("{label}:")),
                "the {cookie} refusal must open with the label of the field it is about, \
                     as the page prints it ({label:?}): {err}"
            );
            assert!(
                err.ends_with('.'),
                "the {cookie} refusal ends with a full stop: {err}"
            );
            assert!(
                !holds_placeholder(&err),
                "a placeholder reached the {cookie} page unfilled: {err}"
            );
            if let Some(want) = words {
                assert_eq!(err, want, "{cookie}");
            }
            if c.field == "ui_theme" {
                // The list box carries no `invalid` marking, so what this row can pin is
                // that the refusal is not folded away: the group holding it opens, on a
                // plain `/config` with no `?groups=open` (§13.31 §10a).
                assert!(
                    got.body
                        .contains(r#"<details class="panel group" id="g-look" open>"#),
                    "a theme refusal opens the group that holds the list box: {}",
                    got.body
                );
            } else {
                let tag = field_tag(&got.body, c.field);
                assert!(
                    tag.contains("invalid")
                        && tag.contains(r#"aria-invalid="true""#)
                        && tag.contains(&format!(r#"aria-describedby="{ERR_ID}""#)),
                    "the refusal must mark {} as the field to fix: {tag}",
                    c.field
                );
            }
            said.push(err);
        }
        assert_ne!(
            said[0], said[1],
            "{:?}: English and Italian are one string",
            c.over
        );
        // The administrators rows share a label and a field, so the pair is told apart by
        // its own words above; the rest are told apart by their label.
        assert_eq!(
            read(&sp),
            before,
            "a refused save writes nothing: {:?}",
            c.over
        );
    }
    // The help text keeps its own sentence beside the new refusal: the bracketed line is
    // the one that tells an administrator where the removal *is* possible, and the refusal
    // now says the same thing in its own register, so both are on the page at once.
    for (cookie, help) in [
        ("lang=en", "you cannot remove yourself here"),
        ("lang=it", "non puoi rimuovere te stesso da qui"),
    ] {
        let fields = settings_fields(&rev, &[("admins", "  ")]);
        let _permit = WRITE_PERMIT.lock().unwrap_or_else(|e| e.into_inner());
        let r = post_with_secret(&url)
            .header(IDENTITY_HEADER, "admin@x.com")
            .header("Sec-Fetch-Site", "same-origin")
            .header("Cookie", cookie)
            .send_form(fields.iter().copied())
            .expect("a POST response");
        let got = got_of(r);
        assert_eq!(got.status, 400, "{cookie} {got:?}");
        assert!(
            got.body.contains(help),
            "the {cookie} page keeps the administrators help text ({help:?}): {}",
            &got.body[..200.min(got.body.len())]
        );
    }
    cleanup(&path);
}

/// The Italian of every `K` entry writes its accents as letters (§13.31 §10).
///
/// Red today on 22 occurrences in five keys, all of them genuine: `puo'` for `può`, `e'`
/// for `è`, `perche'` for `perché`, `da'` for `dà`. An apostrophe there is not a typographic
/// choice, it is a word spelled wrong on the page an Italian operator reads, and it is what
/// a shell-era habit leaves behind when nobody looks.
#[test]
fn italian_k_strings_write_accents_as_letters() {
    let table = italian_k_strings();
    // A parser that found no arm would pass this test vacuously, so the walk's own reach is
    // asserted: the table has 457 keys, and a walk that finds a handful is broken.
    assert!(
        table.len() > 400,
        "the walk read {} arms out of `fn t`, which is not the whole table",
        table.len()
    );
    let mut faults: Vec<String> = Vec::new();
    for (keys, it) in &table {
        for at in accent_faults(it) {
            let from = at.saturating_sub(14);
            let around: String = it.chars().skip(from).take(28).collect();
            faults.push(format!("{keys}: …{around}…"));
        }
    }
    assert!(
        faults.is_empty(),
        "{} Italian strings write an accent as an apostrophe:\n{}",
        faults.len(),
        faults.join("\n")
    );
}

/// The accent rule, on strings that are not from the table: it flags the faults and leaves
/// the apostrophes alone. This is what keeps the test above from being satisfied by a rule
/// that flags nothing, and from being answered by an operator deleting real apostrophes
/// (§13.31 §10a).
#[test]
fn the_accent_rule_flags_only_apostrophe_accents() {
    for s in [
        "puo' x",
        "c'e' x",
        "ne' dove",
        "È bene. E' l",
        "da' a",
        "perche'.",
        "gia'",
    ] {
        assert!(
            !accent_faults(s).is_empty(),
            "{s:?} is a fault: it means può, c'è, né, \
                     è, dà, perché, già with an apostrophe where the accented letter goes"
        );
    }
    for s in [
        "l'Header",
        "un'email",
        "dell'URL",
        "'chiunque'",
        "'solo questi',",
        "'@nome'",
        "('tutti gli ambiti')",
        "un’email",
    ] {
        assert!(
            accent_faults(s).is_empty(),
            "{s:?} is not a fault: {:?}",
            accent_faults(s)
        );
    }
}

/// Every response to `/config` carries the title the `GET` carries, in the reader's
/// language (§13.31 §10: WCAG 2.2 SC 2.4.2 Page Titled).
///
/// Over the socket, because the title is the response's, and the three responses are the
/// three the `POST` answers with: a refusal (`400`), a held guarded change (`200`), and a
/// stale `rev` (`409`). Today all three are titled with `Route::title`, the untranslated
/// "settings", while the `GET` says "System settings" / "Impostazioni di sistema": a tab
/// that changes wording and language after a save is a page that seems to have moved.
#[test]
fn a_refused_settings_save_keeps_the_page_title() {
    let path = scratch("cfg-title", SAMPLE);
    let cfg = cfg_for(&path, "/admin");
    let sp = cfg.settings_path.clone();
    let port = serve(&path, "/admin");
    let url = format!(
        "http://127.0.0.1:{port}{ADMIN_BASE}{}",
        Route::Config.path()
    );
    let rev = rev_of(&sp);
    for (cookie, want) in [
        ("lang=en", "System settings"),
        ("lang=it", "Impostazioni di sistema"),
    ] {
        let r = get_with_secret(&url)
            .header(IDENTITY_HEADER, "admin@x.com")
            .header("Cookie", cookie)
            .call()
            .expect("a GET response");
        let got = got_of(r);
        assert_eq!(got.status, 200, "{cookie} {got:?}");
        let titled = title_of(&got.body);
        assert!(titled.contains(want), "the {cookie} GET: {titled}");
        let cases = vec![
            // A refusal: the form is wrong.
            (400, settings_fields(&rev, &[("ttl", "abc")])),
            // A guarded change: the form is fine and the page asks. A new pool is one of
            // the five, so this is the confirmation and not a save.
            (
                200,
                settings_fields(
                    &rev,
                    &[(
                        "issuer",
                        "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_OTHER",
                    )],
                ),
            ),
            // A stale `rev`: the shared conflict page, on this route.
            (409, settings_fields("deadbeef", &[("ttl", "3600")])),
        ];
        for (status, fields) in cases {
            let _permit = WRITE_PERMIT.lock().unwrap_or_else(|e| e.into_inner());
            let r = post_with_secret(&url)
                .header(IDENTITY_HEADER, "admin@x.com")
                .header("Sec-Fetch-Site", "same-origin")
                .header("Cookie", cookie)
                .send_form(fields.iter().copied())
                .expect("a POST response");
            let got = got_of(r);
            assert_eq!(got.status, status, "{cookie} {fields:?} {got:?}");
            assert_eq!(
                title_of(&got.body),
                titled,
                "the {cookie} {status} must carry the title the GET carries"
            );
        }
    }
    cleanup(&path);
}

/// A claim the library refuses marks the claims field (§13.31 §6). Today this refusal
/// reaches the page through `SettingsWrite::prepare` and is attributed to nothing, because
/// the attribution is a sniff for one string in the English sentence; the field stays
/// unmarked and the operator is left to find which box held `bad claim`.
#[test]
fn a_claim_refusal_is_marked_on_its_field() {
    let path = scratch("cfg-claim-field", SAMPLE);
    let cfg = cfg_for(&path, "");
    let sp = cfg.settings_path.clone();
    let before = read(&sp);
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(&rev_of(&sp), &[("claims", "bad claim")]),
    );
    let (status, body) = got.page();
    assert_eq!(status, 400, "{body}");
    let err = err_text(body);
    assert!(err.contains(t(Lang::En, K::ProfileClaims)), "{err}");
    assert!(err.contains("bad claim"), "{err}");
    assert!(!err.contains("profile_claims"), "{err}");
    assert!(
        body.contains(r#"class="f-claims invalid""#),
        "the refusal must point at the field: {body}"
    );
    assert_eq!(read(&sp), before, "nothing written");
    cleanup(&path);
}

#[test]
fn the_look_is_the_palette_the_components_the_layout_then_the_operator() {
    let path = scratch("look-order", SAMPLE);
    let cfg = cfg_for(&path, "");
    let (doc, access) = open_access_file(&cfg.access_path).unwrap();
    let mut v = view(&cfg, Route::Dashboard, "REV");
    v.look = Look {
        theme: UiTheme::Dark,
        stylesheet: Some("https://assets.badbat75.com/css/theme.css"),
        brand: None,
    };
    let html = shell(&v, "t", page_dashboard(&v, &doc, &access)).into_string();

    // Order is the contract, and it is four deep: the palette, the components that read
    // it, the layout that arranges them, then an override that wins by source order alone
    // and therefore needs no `!important` and no knowledge of what it is restyling. The
    // middle two are the same bytes the gate emits on its own pages.
    let tokens = html.find("--accent:").expect("the palette is inlined");
    let components = html.find(".pill{").expect("the components are inlined");
    let layout = html.find("header.top{").expect("the layout is inlined");
    let link = html.find("<link rel=\"stylesheet\"").expect("the override");
    assert!(
        tokens < components && components < layout && layout < link,
        "{html}"
    );
    // The deployment's default theme reaches the page when the visitor chose nothing.
    assert!(html.contains(r#"data-theme="dark""#), "{html}");
    // And the visitor's own choice still outranks it.
    v.theme = UiTheme::Light;
    let html = shell(&v, "t", html! {}).into_string();
    assert!(html.contains(r#"data-theme="light""#), "{html}");
    cleanup(&path);
}

#[test]
fn with_no_stylesheet_configured_the_page_links_nothing_at_all() {
    // The property the whole arrangement rests on: the built-in look is complete, so a
    // deployment that configures nothing fetches nothing, and one whose asset host is
    // down still has a working page.
    let html = render("look-none", Route::Dashboard);
    assert!(!html.contains("<link"), "{html}");
    assert!(
        html.contains("--accent:"),
        "the palette must still be there"
    );
}

/// The ways in are a table, and what a table cannot show it must not destroy.
///
/// What is pinned here: the email row writes `client_id`, a ticked provider row writes
/// its own app client beside its name, unticking one takes it off the sign-in page, and a
/// provider this build has never heard of (which only `bb-auth-adm` can add) still gets a
/// row and survives a save that did not touch it, because the page names what it drew in
/// a hidden field.
#[test]
fn the_settings_page_writes_every_way_in_and_its_app_client() {
    let path = scratch("cfg-aud", SAMPLE);
    let sp = settings_path(&path);
    let cfg = cfg_for(&path, "");
    const EMAIL_AUD: &str = "9z8y7x6w5v4u3t2s1r0q9p8o7n";
    const GOOGLE_AUD: &str = "4f5g6h7j8k9l0m1n2p3q4r5s6t";

    let got = post_settings(
        &cfg,
        &sp,
        &[
            ("client_id", EMAIL_AUD),
            ("domain", "pool.auth.eu-central-1.amazoncognito.com"),
            ("callback", "https://auth.x.com/auth/callback"),
            ("idps", "Google MicrosoftPersonal"),
            ("idp-Google", "on"),
            ("aud-Google", GOOGLE_AUD),
        ],
    );
    assert!(matches!(got, Got::Redirect(_)), "{got:?}");
    let (doc, s) = open_settings_file(&sp).unwrap();
    assert_eq!(doc.gate.client_id, EMAIL_AUD);
    assert_eq!(s.client_id, EMAIL_AUD);
    assert_eq!(s.social_buttons.len(), 1);
    assert_eq!(s.social_buttons[0].idp, "Google");
    assert_eq!(s.social_buttons[0].audience, GOOGLE_AUD);
    // Derived, and this is the point of deriving it: two app clients are named on the
    // page and both are accepted, with nothing kept in step by hand.
    assert_eq!(s.audiences, [EMAIL_AUD, GOOGLE_AUD]);

    // Every row renders its own app client, and the unticked one renders the empty cell
    // it has rather than borrowing its neighbour's.
    let rev = rev_of(&sp);
    let v = view(&cfg, Route::Config, &rev);
    let html = page_config(&v, &ConfigForm::of(&doc), None, None).into_string();
    assert!(
        html.contains(&format!(r#"name="client_id" value="{EMAIL_AUD}""#)),
        "{html}"
    );
    assert!(
        html.contains(&format!(r#"name="aud-Google" value="{GOOGLE_AUD}""#)),
        "{html}"
    );
    assert!(
        html.contains(r#"name="aud-MicrosoftPersonal" value="""#),
        "{html}"
    );

    // A ticked provider with no app client is refused on its own row, and the file is
    // left exactly as it was: Cognito federates per app client, so there is nothing to
    // fall back on.
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[
                ("client_id", EMAIL_AUD),
                ("domain", "pool.auth.eu-central-1.amazoncognito.com"),
                ("callback", "https://auth.x.com/auth/callback"),
                ("idps", "Google"),
                ("idp-Google", "on"),
                ("aud-Google", ""),
            ],
        ),
    );
    match got {
        Got::Page(status, body) => {
            assert_eq!(status, 400, "the form again, with the message on the row");
            assert!(
                body.contains(r#"name="aud-Google" value="" placeholder"#),
                "{body}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(open_settings_file(&sp).unwrap().0.gate.client_id, EMAIL_AUD);

    // And the email row cannot be emptied: a deployment with no app client at all is one
    // where no login can complete, which is not a thing to save by accident.
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(&rev_of(&sp), &[("client_id", "")]),
    );
    assert!(matches!(got, Got::Page(400, _)), "{got:?}");
}

/// The two-step, which is the whole guard: a save that takes away one of the five things
/// people get in through is SHOWN and held, and only a second post carrying the token
/// that page rendered writes it.
///
/// What this pins beyond "it asks" is the two halves that make asking worth anything. The
/// held save must write **nothing** (a guard that half-applied would be worse than none),
/// and the token must be about the value it was shown for, or the confirmation would be a
/// blanket permission to write whatever the next post happens to carry.
#[test]
fn the_settings_page_asks_before_it_can_lock_anybody_out() {
    let path = scratch("cfg-guard", SAMPLE);
    let sp = settings_path(&path);
    let cfg = cfg_for(&path, "");
    const OTHER_POOL: &str = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_OTHER";

    // Moving the pool: held, with the reason on the page and the file untouched.
    let held = post(
        &cfg,
        Route::Config,
        &settings_fields(&rev_of(&sp), &[("issuer", OTHER_POOL)]),
    );
    let (status, html) = held.page();
    assert_eq!(status, 200, "a question, not a refusal");
    assert!(html.contains("can stop people getting in"), "{html}");
    assert!(html.contains(OTHER_POOL), "the new value is shown");
    assert!(html.contains(TEST_ISSUER), "and so is the one it replaces");
    assert_eq!(
        open_settings_file(&sp).unwrap().0.gate.issuer,
        TEST_ISSUER,
        "a held save must write nothing at all"
    );

    // The token is about that value. Answering with it while posting a different one is
    // refused the same way, which is what stops a confirmation being a blank cheque.
    let token = confirm_token(html).expect("the page carries its token");
    let elsewhere = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[
                (
                    "issuer",
                    "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_THIRD",
                ),
                ("confirm", &token),
            ],
        ),
    );
    assert_eq!(elsewhere.page().0, 200, "a stale token confirms nothing");
    assert_eq!(open_settings_file(&sp).unwrap().0.gate.issuer, TEST_ISSUER);

    // Answered, it writes.
    let done = post_settings(&cfg, &sp, &[("issuer", OTHER_POOL)]);
    assert!(matches!(done, Got::Redirect(_)), "{done:?}");
    assert_eq!(open_settings_file(&sp).unwrap().0.gate.issuer, OTHER_POOL);

    // Two more shapes that must NOT ask, because a confirmation on every save is a button
    // people learn to click. Adding a host widens where a login may land and can lock
    // nobody out...
    let added = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[
                ("issuer", OTHER_POOL),
                ("hosts", "badbat75.com\n*.badbat75.com\nextra.badbat75.com"),
            ],
        ),
    );
    assert!(matches!(added, Got::Redirect(_)), "{added:?}");

    // ...and neither can filling in a value that was empty, whatever it is filled with.
    let first_time = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[
                ("issuer", OTHER_POOL),
                ("hosts", "badbat75.com\n*.badbat75.com\nextra.badbat75.com"),
                ("cookie_domain", ".badbat75.com"),
            ],
        ),
    );
    assert!(matches!(first_time, Got::Redirect(_)), "{first_time:?}");
    // And now that it has one, moving it is the one change that orphans every cookie
    // already issued, so it is asked about like the rest. The estate has to move with it,
    // because a cookie that cannot reach a listed host is refused outright and a refusal
    // outranks a question: there is nothing to confirm about a file that cannot be saved.
    let moved = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[
                ("issuer", OTHER_POOL),
                ("hosts", "other.com\n*.other.com"),
                ("cookie_domain", ".other.com"),
            ],
        ),
    );
    let (status, html) = moved.page();
    assert_eq!(status, 200);
    // Both of them, in one panel: this save takes two things away, and an operator has to
    // see the pair rather than the first of them.
    assert!(
        html.contains("cookie_domain") && html.contains("authorized_hosts"),
        "{html}"
    );

    cleanup(&path);
}

/// A host the cookie can never reach is refused on the way in, not warned about: the
/// failure it prevents leaves no trace anywhere, since the login works, the redirect
/// lands, and the browser simply sends no cookie.
#[test]
fn the_settings_page_refuses_a_host_outside_the_cookie_domain() {
    let path = scratch("cfg-reach", SAMPLE);
    let sp = settings_path(&path);
    let cfg = cfg_for(&path, "");
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[
                ("cookie_domain", ".badbat75.com"),
                ("hosts", "badbat75.com\n*.badbat75.com\napp.elsewhere.com"),
            ],
        ),
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    assert!(html.contains("app.elsewhere.com"), "{html}");
    // Attributed to the field an operator has to go back to, which is why this check is
    // made here as well as in the library.
    assert!(
        html.contains(r#"name="hosts" class="invalid"#) || html.contains("invalid"),
        "{html}"
    );
    cleanup(&path);
}

#[test]
fn the_settings_page_writes_which_social_buttons_are_offered() {
    let path = scratch("cfg-buttons", SAMPLE);
    let sp = settings_path(&path);
    let cfg = cfg_for(&path, "");
    let wired: &[(&str, &str)] = &[
        ("client_id", "9z8y7x6w5v4u3t2s1r0q9p8o7n"),
        ("domain", "pool.auth.eu-central-1.amazoncognito.com"),
        ("callback", "https://auth.x.com/auth/callback"),
        ("idps", "Google MicrosoftPersonal"),
        ("idp-Google", "on"),
        ("aud-Google", "google-client"),
        ("idp-MicrosoftPersonal", "on"),
        ("aud-MicrosoftPersonal", "microsoft-client"),
    ];

    let got = post_settings(&cfg, &sp, wired);
    assert!(matches!(got, Got::Redirect(_)), "{got:?}");
    let (_, s) = open_settings_file(&sp).unwrap();
    assert_eq!(
        s.social_buttons
            .iter()
            .map(|b| (b.idp.as_str(), b.audience.as_str()))
            .collect::<Vec<_>>(),
        [
            ("Google", "google-client"),
            ("MicrosoftPersonal", "microsoft-client")
        ]
    );

    // One of the two, which is the ordinary edit: a browser sends no checkbox at all for
    // an unticked box, so this is what "turn Microsoft off" arrives as. Its app client
    // comes back in the form and is dropped with it, because the row is the entry.
    let mut off: Vec<(&str, &str)> = wired.to_vec();
    off.retain(|(k, _)| *k != "idp-MicrosoftPersonal");
    let got = post(&cfg, Route::Config, &settings_fields(&rev_of(&sp), &off));
    assert!(matches!(got, Got::Redirect(_)), "{got:?}");
    let (_, s) = open_settings_file(&sp).unwrap();
    assert_eq!(s.social_buttons.len(), 1);
    assert_eq!(s.social_buttons[0].idp, "Google");

    // None: the section leaves the sign-in page, and the hosted UI wiring may stay.
    let mut none: Vec<(&str, &str)> = off.to_vec();
    none.retain(|(k, _)| *k != "idp-Google");
    let got = post(&cfg, Route::Config, &settings_fields(&rev_of(&sp), &none));
    assert!(matches!(got, Got::Redirect(_)), "{got:?}");
    assert!(open_settings_file(&sp).unwrap().1.social_buttons.is_empty());

    // A provider from outside the table: the page renders a row for it, and a save that
    // leaves it ticked keeps it, app client and all.
    std::fs::write(
            &sp,
            format!(
                r#"{{ "version": {}, "web": {{ "admins": ["admin@x.com"] }},
                 "gate": {{ "client_id": "email-client",
                            "oauth_domain": "pool.auth.eu-central-1.amazoncognito.com",
                            "social_callback_url": "https://auth.x.com/auth/callback",
                            "social_buttons": [{{ "idp": "Okta", "audience": "okta-client" }}] }} }}"#,
                bb_auth_core::SETTINGS_VERSION
            ),
        )
        .unwrap();
    let rev = rev_of(&sp);
    let v = view(&cfg, Route::Config, &rev);
    let (doc, _) = open_settings_file(&sp).unwrap();
    let html = page_config(&v, &ConfigForm::of(&doc), None, None).into_string();
    assert!(html.contains(r#"name="idp-Okta""#), "a row for it: {html}");
    assert!(
        html.contains(r#"name="aud-Okta" value="okta-client""#),
        "{html}"
    );
    assert!(
        html.contains(r#"value="Google MicrosoftPersonal Okta""#),
        "{html}"
    );
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(
            &rev_of(&sp),
            &[
                ("client_id", "email-client"),
                ("domain", "pool.auth.eu-central-1.amazoncognito.com"),
                ("callback", "https://auth.x.com/auth/callback"),
                ("idps", "Google MicrosoftPersonal Okta"),
                ("idp-Okta", "on"),
                ("aud-Okta", "okta-client"),
            ],
        ),
    );
    assert!(matches!(got, Got::Redirect(_)), "{got:?}");
    let (_, s) = open_settings_file(&sp).unwrap();
    assert_eq!(s.social_buttons.len(), 1);
    assert_eq!(s.social_buttons[0].idp, "Okta");
    assert_eq!(s.audiences, ["email-client", "okta-client"]);
}

#[test]
fn the_settings_page_refuses_what_would_lock_the_administrator_out() {
    let path = scratch("cfg-lockout", SAMPLE);
    let cfg = cfg_for(&path, "");
    let sp = cfg.settings_path.clone();
    let before = read(&sp);

    // Removing yourself: refused here, and the message says where it can be done.
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(&rev_of(&sp), &[("admins", "someone@else.com")]),
    );
    let (status, page) = got.page();
    assert_eq!(status, 400);
    // The refusal's own words, in the `div.err` block and not the body: the body carries
    // the help text, which says the same thing in its own register (§13.31 §10).
    assert_eq!(
        err_text(page),
        "Administrators: your own address must stay on the list; to remove yourself, use \
             bb-auth-adm over SSH."
    );

    // Emptying the list: refused before the library ever sees it, because an empty list
    // must never come to mean "everyone".
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(&rev_of(&sp), &[("admins", "  \n ")]),
    );
    assert_eq!(got.page().0, 400);
    assert_eq!(
        err_text(got.page().1),
        "Administrators: at least one is needed; an empty list must never come to mean \
             'everyone'."
    );

    // An identity list the gate would refuse never reaches the disk either, and the page
    // says so in the reader's language, naming the field by its visible label (§13.31 §4).
    // The sentence below is that table's `attr_unknown` row spelled out: `{0}` the label,
    // `{1}` the entry the operator typed, `{2}` the attributes the field accepts. The
    // library's English sentence, which is what this asserted while the page showed it, is
    // what `bb-auth-adm` prints at a shell, and belongs to the CLI and the gate.
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields(&rev_of(&sp), &[("identity", "phone")]),
    );
    assert_eq!(got.page().0, 400);
    assert_eq!(
        err_text(got.page().1),
        "Identity attributes: 'phone' is not one of: uuid, email."
    );

    assert_eq!(read(&sp), before, "nothing was written on any refusal");
    cleanup(&path);
}

#[test]
fn the_settings_form_is_guarded_by_the_settings_file_own_fingerprint() {
    let path = scratch("cfg-rev", SAMPLE);
    let cfg = cfg_for(&path, "");
    let sp = cfg.settings_path.clone();

    // The form a `GET` renders carries the settings file's fingerprint, not the access
    // file's; otherwise every roster edit would 409 this page, and a concurrent
    // `bb-auth-adm settings set` would go unnoticed, which is the case the check is for.
    let rev = rev_of(&sp);
    let v = view(&cfg, Route::Config, &rev);
    let (doc, _) = open_settings_file(&sp).unwrap();
    let html = shell(
        &v,
        "settings",
        page_config(&v, &ConfigForm::of(&doc), None, None),
    )
    .into_string();
    assert_eq!(rev_in(&html), rev_of(&sp));
    assert_ne!(rev_of(&sp), rev_of(&path));

    // And a stale one is a 409 that writes nothing.
    let got = post(
        &cfg,
        Route::Config,
        &settings_fields("stale", &[("ttl", "60")]),
    );
    assert_eq!(got.page().0, 409);
    assert_eq!(open_settings_file(&sp).unwrap().1.session_ttl, 2_592_000);
    cleanup(&path);
}

#[test]
fn an_unreadable_settings_file_is_an_error_page_not_a_denial() {
    // Saying "you are not an administrator" when the file that would say so cannot be
    // read is a lie, and one that sends an operator looking in the wrong place.
    let path = scratch("cfg-broken", SAMPLE);
    let cfg = cfg_for(&path, "");
    std::fs::write(&cfg.settings_path, "{ not json").unwrap();

    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    let served = cfg_for(&path, "");
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &served);
        }
    });
    let mut r = get_with_secret(format!("http://127.0.0.1:{port}/"))
        .header(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("a response");
    assert_eq!(r.status(), 500);
    let body = r.body_mut().read_to_string().unwrap();
    assert!(body.contains("settings"), "{body}");
    cleanup(&path);
}
