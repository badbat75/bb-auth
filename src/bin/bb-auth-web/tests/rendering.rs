use super::*;

// --- rendering ----------------------------------------------------------

/// §13.26 P: a pill's markup has one home. The `/account` pages have no [`View`] (no
/// route, no rev, no bar), so they reach that one home through three free functions, and
/// the console's `act`, `act_rm` and `back` are wrappers over them. Pinned byte for byte
/// because the class list and the arrow are what the stylesheets style: a helper that
/// spelled them differently would repaint the self-service page while every console page
/// stayed put, which is exactly the drift no file in front of an editor can show.
#[test]
fn the_pill_helpers_emit_the_pill_markup() {
    assert_eq!(
        pill_link("/account/keys/new", "New key").into_string(),
        r#"<a class="pill" href="/account/keys/new">New key</a>"#
    );
    assert_eq!(
        pill_link_rm("/account/keys/remove?id=laptop", "Remove").into_string(),
        r#"<a class="pill rm" href="/account/keys/remove?id=laptop">Remove</a>"#
    );
    // Both languages, spelled as the `K` table spells them, so a helper that reached for
    // another key, or an implementation that paraphrased the Italian, is caught here.
    assert_eq!(
        back_link(Lang::En, "/account/").into_string(),
        "<a class=\"pill\" href=\"/account/\">\u{2190} back</a>"
    );
    assert_eq!(
        back_link(Lang::It, "/account/").into_string(),
        "<a class=\"pill\" href=\"/account/\">\u{2190} indietro</a>"
    );
}

/// The helpers take a caller's strings, not a literal: an href on the account page is built
/// from a key id an operator typed, and a label is translated text. The escaped bytes are
/// the pin that says the helper emits an attribute and a text node, and not markup.
#[test]
fn the_pill_helpers_escape_the_href_and_the_label() {
    let href = r#"/account/keys/remove?id=a&b="<c"#;
    let label = r#""Q" & <b"#;
    assert_eq!(
        pill_link(href, label).into_string(),
        r#"<a class="pill" href="/account/keys/remove?id=a&amp;b=&quot;&lt;c">&quot;Q&quot; &amp; &lt;b</a>"#
    );
    assert_eq!(
        pill_link_rm(href, label).into_string(),
        r#"<a class="pill rm" href="/account/keys/remove?id=a&amp;b=&quot;&lt;c">&quot;Q&quot; &amp; &lt;b</a>"#
    );
}

/// The refactor moves no byte: `act`, `act_rm` and `back` are one-line wrappers over the
/// three helpers, so each pair answers the same string for the same href and label. This is
/// the pin that says every console page renders as it did.
#[test]
fn act_act_rm_and_back_are_the_helpers() {
    let cfg = cfg_for("x.json", "/admin");
    let v = view(&cfg, Route::Apps, "REV");
    let at = Route::App("mpa".to_string());
    let href = v.href(&at);
    // The href is the view's, base included, so the comparison below is about the markup
    // and not about two empty strings.
    assert_eq!(href, "/admin/apps/mpa");
    assert_eq!(
        act(&v, &at, "edit").into_string(),
        pill_link(&href, "edit").into_string()
    );
    assert_eq!(
        act_rm(&v, &at, "remove").into_string(),
        pill_link_rm(&href, "remove").into_string()
    );
    assert_eq!(
        back(&v, &at).into_string(),
        back_link(v.lang, &href).into_string()
    );
    // `back` takes the language from the view, and that is the one thing the wrapper adds
    // over `back_link`, so pin it on a view that is not English.
    let mut it = view(&cfg, Route::Apps, "REV");
    it.lang = Lang::It;
    assert_eq!(
        back(&it, &at).into_string(),
        back_link(Lang::It, &href).into_string()
    );
}

/// The audit file [`cfg_for`] points at, which is beside the access file [`scratch`]
/// writes and is therefore named by the same test name.
fn audit_path_for(name: &str) -> String {
    format!(
        "{}.audit",
        std::env::temp_dir()
            .join(format!("bb-auth-web-{name}.json"))
            .to_string_lossy()
    )
}

/// An audit on disk, written through the gate's own writer: the page under test then reads
/// exactly the bytes a real gate would have left, rather than a fixture hand-rolled to
/// match what the reader expects.
fn audit_fixture(name: &str, events: &[AuditEvent]) -> String {
    let p = audit_path_for(name);
    let _ = std::fs::remove_file(&p);
    let w = bb_auth_core::AuditWriter::new(&p);
    for e in events {
        w.record(e, &AuditPolicy::default()).unwrap();
    }
    p
}

#[test]
fn the_audit_shows_newest_first_and_filters_on_every_axis() {
    let now = now();
    let key = AuditEvent::new(
        now - 60,
        AuditKind::AccessRefused,
        AuditCredential::Key {
            id: "laptop".into(),
        },
    )
    .of(BOB)
    .at(Some(("mpa", "admin")))
    .on(Some("https://mpa.x.com/admin"))
    .because("key_out_of_scope");
    let login = AuditEvent::new(
        now - 30,
        AuditKind::LoginGranted,
        AuditCredential::Social {
            provider: "Google".into(),
        },
    )
    .by("newcomer@x.com", None);
    // Older than every period the page offers, so it is only ever visible under
    // "everything": the period is a real cut and not decoration.
    let ancient = AuditEvent::new(
        now - 40 * 86_400,
        AuditKind::LoginEnded,
        AuditCredential::Session,
    )
    .by("ancient@x.com", None);
    let p = audit_fixture("audit", &[ancient, key, login]);

    let html = render_of("audit", SAMPLE, Route::Audit, "");
    let (first, second) = (
        html.find("newcomer@x.com").expect("the login is shown"),
        html.find("laptop").expect("the key refusal is shown"),
    );
    assert!(first < second, "newest first: {html}");
    // A key names a row, and the row is what the page shows and links to, because that is
    // the name a reader can look up.
    assert!(
        html.contains("bob@x.com"),
        "the key's owner is named: {html}"
    );
    assert!(html.contains(&format!("href=\"/users/{BOB}\"")), "{html}");
    // The default period is a day, so nothing older is in the page at all.
    assert!(!html.contains("ancient@x.com"), "{html}");
    assert!(
        render_of("audit", SAMPLE, Route::Audit, "aw=all").contains("ancient@x.com"),
        "everything means everything"
    );

    // Each filter cuts on its own axis.
    let only_keys = render_of("audit", SAMPLE, Route::Audit, "ac=key");
    assert!(only_keys.contains("laptop"));
    assert!(!only_keys.contains("newcomer@x.com"), "{only_keys}");
    let only_allowed = render_of("audit", SAMPLE, Route::Audit, "ao=ok");
    assert!(only_allowed.contains("newcomer@x.com"));
    assert!(!only_allowed.contains("laptop"), "{only_allowed}");
    // And the text filter reaches the fields a row is made of, the reason included.
    let by_text = render_of("audit", SAMPLE, Route::Audit, "aq=key_out_of_scope");
    assert!(by_text.contains("laptop"));
    assert!(!by_text.contains("newcomer@x.com"), "{by_text}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn an_audit_that_is_off_says_so_rather_than_looking_empty() {
    // The difference matters: an empty page reads as "nobody has done anything", which on
    // an unconfigured deployment is a lie an administrator would act on.
    let path = scratch("audit-off", SAMPLE);
    let mut cfg = cfg_for(&path, "");
    cfg.audit_path = String::new();
    let (doc, _) = open_access_file(&cfg.access_path).unwrap();
    let v = view(&cfg, Route::Audit, "REV");
    let html = page_audit(&v, &doc).into_string();
    assert!(html.contains("The audit is off"), "{html}");
    assert!(html.contains("BB_AUTH_AUDIT_FILE"), "{html}");
    let _ = std::fs::remove_file(&path);
}

/// A row carries where its request came from, and the filter box finds it by any of it.
#[test]
fn the_audit_says_where_a_request_came_from() {
    let login = AuditEvent::new(now() - 60, AuditKind::LoginGranted, AuditCredential::Local)
        .by("far-away@x.com", None)
        .account(Some("9d8e7f60-1a2b-4c3d-8e9f-0a1b2c3d4e5f"))
        .from(&bb_auth_core::AuditClient {
            ip: Some("203.0.113.7".into()),
            ua: Some("Mozilla/5.0 (Macintosh)".into()),
            rid: Some("5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f".into()),
        });
    let p = audit_fixture("audit-client", &[login]);

    let html = render_of("audit-client", SAMPLE, Route::Audit, "");
    for part in [
        "203.0.113.7",
        "Mozilla/5.0 (Macintosh)",
        "rid 5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f",
        "sub 9d8e7f60-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
        // No preference is UTC, and the heading says so.
        "When (UTC)",
    ] {
        assert!(html.contains(part), "{part}: {html}");
    }
    // An address pasted from a firewall's log finds the row; another one does not.
    let hit = render_of("audit-client", SAMPLE, Route::Audit, "aq=203.0.113");
    assert!(hit.contains("far-away@x.com"), "{hit}");
    let miss = render_of("audit-client", SAMPLE, Route::Audit, "aq=198.51.100");
    assert!(!miss.contains("far-away@x.com"), "{miss}");
    let _ = std::fs::remove_file(&p);
}

/// Central Europe, built by hand so no test needs the host's zone database: an hour ahead
/// of UTC in winter and two in summer, changing on the last Sunday of March and October.
fn cet() -> Zone {
    use tz::timezone::{AlternateTime, LocalTimeType, MonthWeekDay, RuleDay, TransitionRule};
    let std = LocalTimeType::new(3600, false, Some(b"CET")).unwrap();
    let dst = LocalTimeType::new(7200, true, Some(b"CEST")).unwrap();
    let rule = AlternateTime::new(
        std,
        dst,
        RuleDay::MonthWeekDay(MonthWeekDay::new(3, 5, 0).unwrap()),
        7200,
        RuleDay::MonthWeekDay(MonthWeekDay::new(10, 5, 0).unwrap()),
        10800,
    )
    .unwrap();
    Zone {
        label: "Europe/Rome".to_string(),
        rules: tz::TimeZone::new(
            vec![],
            vec![std],
            vec![],
            Some(TransitionRule::Alternate(rule)),
        )
        .unwrap(),
        per_row: true,
    }
}

/// Noon UTC on a given day of 2026.
fn noon(day: &str) -> u64 {
    bb_auth_core::parse_date_epoch(day).unwrap() + 12 * 3600
}

#[test]
fn a_time_is_read_on_the_clock_its_zone_had_that_day() {
    let (winter, summer) = (noon("2026-01-15"), noon("2026-07-15"));
    // A zone with two clocks names the one each row was read on, or the hour either side
    // of a change would read the same twice.
    assert_eq!(
        zoned(winter, &cet()),
        ("2026-01-15 13:00:00".to_string(), Some("CET".to_string()))
    );
    assert_eq!(
        zoned(summer, &cet()),
        ("2026-07-15 14:00:00".to_string(), Some("CEST".to_string()))
    );
    // A fixed offset and UTC need no such note: the heading already says which they are.
    let india = resolve_zone(&TzPref::Custom("+05:30".into())).unwrap();
    assert_eq!(india.label, "+05:30");
    assert_eq!(
        zoned(winter, &india),
        ("2026-01-15 17:30:00".to_string(), None)
    );
    assert_eq!(
        zoned(winter, &utc_zone()),
        ("2026-01-15 12:00:00".to_string(), None)
    );
    // A name nobody has is said to be missing rather than read as something else, which is
    // also what a workstation with no zone database gives for every name.
    assert_eq!(
        resolve_zone(&TzPref::Custom("No/Such_Zone".into())).err(),
        Some(ZoneMissing::Custom("No/Such_Zone".into()))
    );
}

/// The one path the hand-built zone above cannot cover: a real file out of the host's
/// database, parsed by the library the page uses. Unix only, since that is where the
/// database is, and skipped on a host with no tzdata rather than failed, since a missing
/// zone is a state the page already handles and says so.
#[cfg(unix)]
#[test]
fn a_named_zone_is_read_out_of_the_hosts_database() {
    if !std::path::Path::new(&format!("{ZONEINFO_DIR}/Europe/Rome")).exists() {
        return;
    }
    let rome = resolve_zone(&TzPref::Custom("Europe/Rome".into())).unwrap();
    assert_eq!(rome.label, "Europe/Rome");
    assert_eq!(
        zoned(noon("2026-01-15"), &rome),
        ("2026-01-15 13:00:00".to_string(), Some("CET".to_string()))
    );
    assert_eq!(
        zoned(noon("2026-07-15"), &rome),
        ("2026-07-15 14:00:00".to_string(), Some("CEST".to_string()))
    );
}

#[test]
fn a_zone_preference_is_a_word_a_name_or_an_offset_and_nothing_else() {
    assert_eq!(parse_tz_pref("utc"), Some(TzPref::Utc));
    assert_eq!(parse_tz_pref(" Local "), Some(TzPref::Local));
    for name in [
        "Europe/Rome",
        "America/Argentina/Buenos_Aires",
        "Etc/GMT+2",
        "GMT",
    ] {
        assert_eq!(
            parse_tz_pref(name),
            Some(TzPref::Custom(name.to_string())),
            "{name}"
        );
    }
    // An offset is stored in one spelling however it was typed, and its sign means ahead
    // of UTC: the opposite of what a POSIX TZ string would have made of `UTC-2`.
    for (typed, stored) in [
        ("+2", "+02:00"),
        ("+0200", "+02:00"),
        ("UTC+02:00", "+02:00"),
        ("gmt-3", "-03:00"),
        ("+5:30", "+05:30"),
        ("-0930", "-09:30"),
        ("+14", "+14:00"),
    ] {
        assert_eq!(
            parse_tz_pref(typed),
            Some(TzPref::Custom(stored.to_string())),
            "{typed}"
        );
    }
    assert_eq!(parse_offset("UTC-2"), Some(-7200));
    // Nothing that could climb out of the zone directory, or break a cookie, becomes one.
    for junk in [
        "",
        "../../etc/passwd",
        "Europe/../../etc",
        "/etc/localtime",
        "Europe//Rome",
        "Europe/Rome/",
        "Rome;x=1",
        "a b",
        "+15",
        "+02:60",
        "+",
    ] {
        assert_eq!(parse_tz_pref(junk), None, "{junk:?}");
    }
    // What is stored reads back as itself.
    for p in [
        TzPref::Utc,
        TzPref::Local,
        TzPref::Custom("Europe/Rome".into()),
        TzPref::Custom("+05:30".into()),
    ] {
        assert_eq!(parse_tz_pref(p.code()), Some(p.clone()));
    }
}

/// The page in the clock a reader chose, and the page that says so when that clock
/// cannot be had, rather than one printing UTC under a heading somebody takes at its word.
#[test]
fn the_audit_reads_in_the_chosen_zone_or_says_why_not() {
    let at = noon("2026-01-15");
    let ev = AuditEvent::new(at, AuditKind::LoginGranted, AuditCredential::Local)
        .by("clock@x.com", None);
    let p = audit_fixture("audit-zone", &[ev]);
    let path = scratch("audit-zone", SAMPLE);
    let cfg = cfg_for(&path, "");
    let (doc, _) = open_access_file(&cfg.access_path).unwrap();
    let mut v = view(&cfg, Route::Audit, "REV");
    // January is further back than the default day.
    v.query = "aw=all";

    v.tz = TzPref::Custom("+05:30".into());
    let html = page_audit(&v, &doc).into_string();
    assert!(html.contains("When (+05:30)"), "{html}");
    assert!(html.contains("2026-01-15 17:30:00"), "{html}");
    assert!(
        html.contains(r#"<option value="custom" selected>"#),
        "{html}"
    );
    assert!(html.contains(r#"name="tzc" value="+05:30""#), "{html}");

    v.tz = TzPref::Custom("No/Such_Zone".into());
    let html = page_audit(&v, &doc).into_string();
    assert!(
        html.contains("is not a time zone this server knows"),
        "{html}"
    );
    assert!(html.contains("When (UTC)"), "{html}");
    assert!(html.contains("2026-01-15 12:00:00"), "{html}");
    // What was asked for stays in the box, to be corrected rather than retyped.
    assert!(
        html.contains(r#"name="tzc" value="No/Such_Zone""#),
        "{html}"
    );

    cleanup(&path);
    let _ = std::fs::remove_file(&p);
}

/// A zone is a preference: it becomes a cookie and leaves the address, like the language
/// and the theme, and a zone nothing can read sets nothing at all.
#[test]
fn a_zone_is_remembered_and_leaves_the_address() {
    let path = scratch("tz-redirect", SAMPLE);
    let served = cfg_for(&path, "");
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &served);
        }
    });
    let get = |query: &str, cookie: &str| {
        let mut r = get_with_secret(format!("http://127.0.0.1:{port}/audit?{query}"))
            .header(IDENTITY_HEADER, "admin@x.com");
        if !cookie.is_empty() {
            r = r.header("Cookie", cookie);
        }
        r.call().expect("a response")
    };
    let header = |r: &ureq::http::Response<ureq::Body>, name: &str| {
        r.headers()
            .get(name)
            .map(|h| h.to_str().unwrap().to_string())
    };

    // Typed as an offset, stored in one spelling, and the filters survive the trip.
    let r = get("aw=7d&tz=custom&tzc=%2B2", "");
    assert_eq!(r.status(), 302);
    assert_eq!(header(&r, "Location").as_deref(), Some("/audit?aw=7d"));
    let set = header(&r, "Set-Cookie").unwrap();
    assert!(set.starts_with("tz=+02:00;"), "{set}");

    // A word is the whole answer, whatever the box beside it still holds.
    let r = get("tz=local&tzc=Europe%2FRome", "");
    assert!(header(&r, "Set-Cookie").unwrap().starts_with("tz=local;"));

    // A zone nothing can read sets nothing, and both parameters leave the address anyway.
    let r = get("aw=24h&tz=custom&tzc=..%2F..%2Fetc%2Fpasswd", "");
    assert_eq!(r.status(), 303);
    assert_eq!(header(&r, "Set-Cookie"), None);
    assert_eq!(header(&r, "Location").as_deref(), Some("/audit?aw=24h"));

    // And the page reads whatever the cookie says. This audit is empty, so there is no
    // table to head; the list box and the box beside it are what show the choice.
    let mut r = get("", "tz=+05:30");
    assert_eq!(r.status(), 200);
    let body = r.body_mut().read_to_string().unwrap();
    assert!(
        body.contains(r#"<option value="custom" selected>"#),
        "{body}"
    );
    assert!(body.contains(r#"name="tzc" value="+05:30""#), "{body}");
    cleanup(&path);
}

#[test]
fn the_settings_page_writes_the_audit_headers_and_refuses_a_credential() {
    let path = scratch("cfg-audit-headers", SAMPLE);
    let sp = settings_path(&path);
    let cfg = cfg_for(&path, "");

    let got = post_settings(
        &cfg,
        &sp,
        &[
            ("client_ip_header", "X-Real-IP"),
            ("request_id_header", "X-Request-ID"),
        ],
    );
    assert!(matches!(got, Got::Redirect(_)), "{got:?}");
    let (doc, s) = open_settings_file(&sp).unwrap();
    assert_eq!(s.client_ip_header.as_deref(), Some("X-Real-IP"));
    assert_eq!(s.request_id_header.as_deref(), Some("X-Request-ID"));
    let rev = rev_of(&sp);
    let v = view(&cfg, Route::Config, &rev);
    let html = page_config(&v, &ConfigForm::of(&doc), None, None).into_string();
    assert!(
        html.contains(r#"name="client_ip_header" value="X-Real-IP""#),
        "{html}"
    );

    // A header that carries a credential is refused on its own field, and nothing lands:
    // an id is written down as it arrives, and a cookie is not something to write down.
    let before = read(&sp);
    let got = post_settings(&cfg, &sp, &[("request_id_header", "Cookie")]);
    let (status, html) = got.page();
    assert_eq!(status, 400);
    assert!(html.contains("carries a credential"), "{html}");
    assert_eq!(read(&sp), before);
    cleanup(&path);
}

/// Rotation and retention are an amount and a unit each, written back in the file's one
/// spelling, and the pair that bounds no bytes is refused on the retention's box.
#[test]
fn the_settings_page_writes_the_rotation_and_the_retention() {
    let path = scratch("cfg-audit-limits", SAMPLE);
    let sp = settings_path(&path);
    let cfg = cfg_for(&path, "");

    let got = post_settings(
        &cfg,
        &sp,
        &[
            ("audit_rotation", "1"),
            ("audit_rotation_unit", "GiB"),
            ("audit_retention", "6"),
            ("audit_retention_unit", "months"),
        ],
    );
    assert!(matches!(got, Got::Redirect(_)), "{got:?}");
    let (doc, s) = open_settings_file(&sp).unwrap();
    assert_eq!(doc.audit.rotation, "1 GiB");
    assert_eq!(doc.audit.retention, "6 months");
    assert_eq!(
        s.audit_policy.retention.and_then(|r| r.seconds()),
        Some(6 * 2_629_746)
    );
    // And the page renders the controls back as it saved them.
    let rev = rev_of(&sp);
    let v = view(&cfg, Route::Config, &rev);
    let html = page_config(&v, &ConfigForm::of(&doc), None, None).into_string();
    assert!(
        html.contains(r#"name="audit_retention" value="6""#),
        "{html}"
    );
    assert!(
        html.contains(r#"<option value="months" selected>"#),
        "{html}"
    );

    // A rotation in time with no size anywhere: refused, nothing written, the retention's
    // box the one marked.
    let before = read(&sp);
    let got = post_settings(
        &cfg,
        &sp,
        &[
            ("audit_rotation", "1"),
            ("audit_rotation_unit", "months"),
            ("audit_retention", "1"),
            ("audit_retention_unit", "years"),
        ],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    assert!(html.contains("without limit"), "{html}");
    assert!(
        html.contains(r#"class="f-audit_retention invalid""#),
        "{html}"
    );
    assert_eq!(read(&sp), before);

    // No retention is the list box's `none`, whatever the number beside it says.
    let got = post_settings(
        &cfg,
        &sp,
        &[("audit_retention", "3"), ("audit_retention_unit", "")],
    );
    assert!(matches!(got, Got::Redirect(_)), "{got:?}");
    assert_eq!(open_settings_file(&sp).unwrap().0.audit.retention, "");
    cleanup(&path);
}

/// Every group folds, the two commands say how the page opens and are remembered, and a
/// refused field is never left inside a folded group.
#[test]
fn the_settings_groups_fold_and_a_refusal_is_never_folded_away() {
    let path = scratch("cfg-groups", SAMPLE);
    let sp = settings_path(&path);
    let cfg = cfg_for(&path, "");
    let (doc, _) = open_settings_file(&sp).unwrap();
    let rev = rev_of(&sp);
    // How many groups render open: the ones whose opening tag carries the attribute.
    let count_open = |html: &str| {
        html.match_indices(r#"<details class="panel group" id="g-"#)
            .filter(|(i, _)| html[*i..].split('>').next().unwrap().contains(" open"))
            .count()
    };

    // Folded by default: the page reads as its five headings.
    let mut v = view(&cfg, Route::Config, &rev);
    v.groups = GroupsPref::default();
    let html = page_config(&v, &ConfigForm::of(&doc), None, None).into_string();
    assert_eq!(html.matches(r#"<details class="panel group""#).count(), 5);
    assert_eq!(count_open(&html), 0, "{html}");
    assert!(
        html.contains("?groups=open") && html.contains("?groups=closed"),
        "both commands are on the page"
    );

    // Open by preference, all five.
    v.groups = GroupsPref::Open;
    let html = page_config(&v, &ConfigForm::of(&doc), None, None).into_string();
    assert_eq!(count_open(&html), 5, "{html}");
    v.groups = GroupsPref::Closed;

    // A refusal on a field opens that field's group, and only that one.
    let err = Refusal::on("audit_retention", "no");
    let html = page_config(&v, &ConfigForm::of(&doc), Some(&err), None).into_string();
    assert_eq!(count_open(&html), 1, "{html}");
    assert!(
        html.contains(r#"<details class="panel group" id="g-audit" open>"#),
        "{html}"
    );
    // One that names no field opens everything: the page cannot say where to look.
    let html = page_config(
        &v,
        &ConfigForm::of(&doc),
        Some(&Refusal::from("x".to_string())),
        None,
    )
    .into_string();
    assert_eq!(count_open(&html), 5, "{html}");

    // The commands are remembered the way a theme is: a cookie, and the parameter gone.
    let served = cfg_for(&path, "");
    let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
    let port = server.server_addr().to_ip().expect("an ip address").port();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &served);
        }
    });
    let get = |target: &str, cookie: Option<&str>| {
        let mut r = get_with_secret(format!("http://127.0.0.1:{port}{target}"))
            .header(IDENTITY_HEADER, "admin@x.com");
        if let Some(c) = cookie {
            r = r.header("Cookie", c);
        }
        r.call().expect("a response")
    };
    let r = get("/config?groups=open", None);
    assert_eq!(r.status(), 302);
    assert_eq!(r.headers().get("Location").unwrap(), "/config");
    let set = r.headers().get("Set-Cookie").unwrap().to_str().unwrap();
    assert!(set.starts_with("groups=open;"), "{set}");
    let body = |mut r: ureq::http::Response<ureq::Body>| r.body_mut().read_to_string().unwrap();
    // A browser that never chose sees the headings; one that chose sees what it chose.
    assert_eq!(count_open(&body(get("/config", None))), 0);
    assert_eq!(count_open(&body(get("/config", Some("groups=open")))), 5);
    assert_eq!(count_open(&body(get("/config", Some("groups=closed")))), 0);
    cleanup(&path);
}

/// A retention in time is a floor on every period the Audit tab offers, `everything`
/// included, and the page says how the audit rotates and what it keeps.
#[test]
fn the_audit_shows_nothing_the_retention_has_expired() {
    let now = now();
    let old = AuditEvent::new(
        now - 30 * 86_400,
        AuditKind::LoginGranted,
        AuditCredential::Local,
    )
    .by("last-month@x.com", None);
    let new = AuditEvent::new(now - 60, AuditKind::LoginGranted, AuditCredential::Local)
        .by("just-now@x.com", None);
    let p = audit_fixture("audit-retention", &[old, new]);
    let path = scratch("audit-retention", SAMPLE);
    let cfg = cfg_for(&path, "");
    let (doc, _) = open_access_file(&cfg.access_path).unwrap();
    let mut v = view(&cfg, Route::Audit, "REV");
    v.query = "aw=all";

    let html = page_audit(&v, &doc).into_string();
    assert!(
        html.contains("last-month@x.com"),
        "no retention, everything: {html}"
    );

    v.audit = AuditPolicy::new(
        AuditLimit::new(4, AuditUnit::MiB),
        Some(AuditLimit::new(1, AuditUnit::Weeks)),
    )
    .unwrap();
    let html = page_audit(&v, &doc).into_string();
    assert!(
        !html.contains("last-month@x.com"),
        "a week is a week: {html}"
    );
    assert!(html.contains("just-now@x.com"), "{html}");
    assert!(html.contains("Retention: 1 week"), "{html}");
    assert!(html.contains("At most on disk: 8 MiB"), "{html}");
    cleanup(&path);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn dashboard_counts_expiries_and_warnings() {
    let html = render("dash", Route::Dashboard);
    assert!(html.contains("user_groups"));
    // the 1970 key is long past
    assert!(html.contains("expired"), "{html}");
    // nowhere@x.com is in no scope, and @unused references nobody
    assert!(html.contains("reaches nothing"), "{html}");
    assert!(html.contains("@unused"));
    assert!(html.contains("referenced by nothing"));
    // §13.35: a line says **what kind of thing** it is about before it names one, and the
    // identifier is a link wherever the object has a page of its own. The two warnings
    // this fixture raises are one person and one user group. The messages print the
    // warnings list and not the page: the shell inlines three stylesheets, and a document
    // dump buries the one line that is wrong.
    let items = warning_items(&html);
    for (needle, want) in [
        (
            "@unused",
            format!("User group @unused {}", t(Lang::En, K::ReferencedByNothing)),
        ),
        (
            "nowhere@x.com",
            format!("User nowhere@x.com {}", t(Lang::En, K::WarnNoScope)),
        ),
    ] {
        assert_eq!(
            visible_text(&warning_line(&items, needle)),
            want,
            "{}",
            warning_words(&items)
        );
    }
    assert!(
        warning_line(&items, "nowhere@x.com").contains(&format!(
            "<a href=\"/users/{NOWHERE}\"><code>nowhere@x.com</code></a>"
        )),
        "the person line links to the page of that person: {}",
        warning_line(&items, "nowhere@x.com")
    );
}

/// A file that raises **all five** dashboard warnings at once, so the kind of each can be
/// pinned on one rendered page: `mpa/old` is shadowed by the `mpa/wide` scope listed above
/// it, `mpa/empty` is `restricted` and lists nobody, `nowhere@x.com` is in no scope,
/// `gone@x.com` is enrolled and denied, and `@unused` is referenced by nothing.
///
/// Each identifier is named by exactly **one** warning, which is what makes "the line that
/// names X" a lookup with one answer: the denied row is a member of `mpa/private` through
/// `@admins`, so its line is the veto and not "reaches nothing"; Bob reaches that scope
/// too; and `@admins` is referenced while `@unused` is not.
const DASH_KINDS: &str = r#"{ "version": 1,
      "applications": [
        { "name": "mpa", "base": ["https://app.x.com/mpa"],
          "scopes": [
            { "name": "empty", "urls": ["https://app.x.com/mpa/empty/*"], "access": "restricted" },
            { "name": "private", "urls": ["https://app.x.com/mpa/private/*"], "access": "restricted",
              "groups": ["@admins"], "users": ["22222222-2222-2222-2222-222222222222"] },
            { "name": "wide", "urls": ["https://app.x.com/mpa/*"], "access": "authenticated" },
            { "name": "old", "urls": ["https://app.x.com/mpa/old/*"], "access": "authenticated" }
          ] }
      ],
      "user_groups": {
        "admins": ["8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b"],
        "unused": ["11111111-1111-1111-1111-111111111111"]
      },
      "denied": ["gone@x.com"],
      "users": [
        { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b", "emails": ["Bob@X.com"] },
        { "uuid": "11111111-1111-1111-1111-111111111111", "emails": ["nowhere@x.com"] },
        { "uuid": "22222222-2222-2222-2222-222222222222", "emails": ["gone@x.com"] }
      ]
    }"#;

/// The uuid of the row that is enrolled and denied.
const GONE: &str = "22222222-2222-2222-2222-222222222222";

/// The kind words §13.35 adds (`K::KindScope`, `K::KindUser`, `K::KindGroup`), spelled
/// here as the design's table spells them, EN and IT. They are written as words and not
/// as `K` variants because the variants do not exist yet: naming one is a compile error
/// for the whole target, which is a red that proves nothing about the page. Once the
/// table carries them, these consts are the design's answer the coder must match.
const KIND_SCOPE: &str = "Scope";
const KIND_USER: &str = "User";
const KIND_SCOPE_IT: &str = "Scope";
const KIND_USER_IT: &str = "Utente";
const KIND_GROUP_IT: &str = "Gruppo di utenti";

/// The dashboard's warnings list, as `<li>` elements in document order. The scope is the
/// panel, not the `ul`: `panel warn` is on this page alone, and `ul.plain` is a component
/// the users page and the bar's menus use too.
fn warning_items(html: &str) -> Vec<String> {
    let panel = element_containing(html, "class=\"panel warn\"", "</div>");
    elements(&panel, "<li", "</li>")
}

/// The one warning line that names `needle`. A line that is not there is the failure this
/// family is about, so the message says what the page does show.
fn warning_line(items: &[String], needle: &str) -> String {
    items
        .iter()
        .find(|li| visible_text(li).contains(needle))
        .cloned()
        .unwrap_or_else(|| panic!("no warning names {needle}: {}", warning_words(items)))
}

/// Every warning line's words, on one printable line, for a failure message that must not
/// dump the whole document (the shell inlines three stylesheets).
fn warning_words(items: &[String]) -> String {
    items
        .iter()
        .map(|li| visible_text(li))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// §13.35 §1: each of the five warnings opens with the word for the kind of thing it is
/// about. The user read "`@delete-test` referenced by nothing" on a live dashboard and
/// could not tell a user group from a scope, so the line says kind, identifier, sentence,
/// and the sentence is the predicate the page already said, unchanged.
#[test]
fn each_dashboard_warning_names_its_kind_first() {
    let html = render_of("dash-kinds", DASH_KINDS, Route::Dashboard, "");
    let items = warning_items(&html);
    assert_eq!(
        items.len(),
        5,
        "the fixture raises all five: {}",
        warning_words(&items)
    );
    for li in &items {
        let words = visible_text(li);
        assert!(
            words.starts_with(KIND_SCOPE)
                || words.starts_with(KIND_GROUP)
                || words.starts_with(KIND_USER),
            "a warning opens with the kind of thing it names: {words}"
        );
    }
    // And the right kind on the right line: "User group" starts with "User ", so the
    // loop above is a shape check and this table is the answer.
    for (needle, want) in [
        (
            "mpa/old",
            format!("{KIND_SCOPE} mpa/old {}", t(Lang::En, K::WarnShadowed)),
        ),
        (
            "mpa/empty",
            format!("{KIND_SCOPE} mpa/empty {}", t(Lang::En, K::WarnNoMembers)),
        ),
        (
            "nowhere@x.com",
            format!("{KIND_USER} nowhere@x.com {}", t(Lang::En, K::WarnNoScope)),
        ),
        (
            "gone@x.com",
            format!(
                "{KIND_USER} gone@x.com {}",
                t(Lang::En, K::WarnEnrolledAndDenied)
            ),
        ),
        (
            "@unused",
            format!(
                "{KIND_GROUP} @unused {}",
                t(Lang::En, K::ReferencedByNothing)
            ),
        ),
    ] {
        assert_eq!(
            visible_text(&warning_line(&items, needle)),
            want,
            "{}",
            warning_words(&items)
        );
    }
    // The group line byte for byte as the page renders it: the kind, the identifier in
    // `code`, the predicate, and nothing else. The identifier sits inside a link to
    // `/groups/unused`, which §13.36 §2 added: §13.35 left this line plain only because a
    // group had no page of its own to land on, and the group page's scopes panel is the
    // answer to "referenced by nothing", so the warning is now one click from its own
    // remedy. The byte-for-byte shape still matters: it is what says the line carries no
    // third element, no count and no panel of its own.
    assert!(
        items.iter().any(|li| {
            li == &format!(
                "<li>{KIND_GROUP} <a href=\"/groups/unused\"><code>@unused</code></a> {}</li>",
                t(Lang::En, K::ReferencedByNothing)
            )
        }),
        "the group line, linking the group's page: {}",
        items.join(" | ")
    );
}

/// §13.35 §3: the same five lines, in Italian. "Scope" is the console's own singular in
/// both languages (the design's table), and the predicates already read with a masculine
/// subject, which is why no predicate key changes: the predicates below are read from the
/// table, and only the kind words are spelled here.
#[test]
fn dashboard_warning_kinds_are_translated() {
    let path = scratch("dash-kinds-it", DASH_KINDS);
    let cfg = cfg_for(&path, "");
    let (doc, access) = open_access_file(&cfg.access_path).unwrap();
    let mut v = view(&cfg, Route::Dashboard, "REV");
    v.lang = Lang::It;
    let html = shell(&v, "t", page_dashboard(&v, &doc, &access)).into_string();
    let items = warning_items(&html);
    assert_eq!(items.len(), 5, "{}", warning_words(&items));
    assert!(
        html.contains(t(Lang::It, K::Warnings)),
        "the page is Italian: {}",
        warning_words(&items)
    );
    for (needle, want) in [
        (
            "mpa/old",
            format!("{KIND_SCOPE_IT} mpa/old {}", t(Lang::It, K::WarnShadowed)),
        ),
        (
            "mpa/empty",
            format!(
                "{KIND_SCOPE_IT} mpa/empty {}",
                t(Lang::It, K::WarnNoMembers)
            ),
        ),
        (
            "nowhere@x.com",
            format!(
                "{KIND_USER_IT} nowhere@x.com {}",
                t(Lang::It, K::WarnNoScope)
            ),
        ),
        (
            "gone@x.com",
            format!(
                "{KIND_USER_IT} gone@x.com {}",
                t(Lang::It, K::WarnEnrolledAndDenied)
            ),
        ),
        (
            "@unused",
            format!(
                "{KIND_GROUP_IT} @unused {}",
                t(Lang::It, K::ReferencedByNothing)
            ),
        ),
    ] {
        assert_eq!(
            visible_text(&warning_line(&items, needle)),
            want,
            "{}",
            warning_words(&items)
        );
    }
    cleanup(&path);
}

/// §13.35 §2: the identifier becomes a link to the page of the thing it names, so the
/// operator no longer has to find it by hand. A scope links to **its application's** page,
/// because a shadowed scope is explained only by the scopes listed above it there. A person
/// links to their own page. A user group links to its own page (§13.36 §2), which is where
/// "nothing references me" is answered: the scopes panel, first under the head.
#[test]
fn a_dashboard_warning_links_to_the_page_of_what_it_names() {
    let html = render_of("dash-kind-links", DASH_KINDS, Route::Dashboard, "");
    let items = warning_items(&html);
    for id in ["mpa/old", "mpa/empty"] {
        assert!(
            warning_line(&items, id)
                .contains(&format!("<a href=\"/apps/mpa\"><code>{id}</code></a>")),
            "a scope line links its identifier to the application page: {}",
            warning_line(&items, id)
        );
    }
    for (id, uuid) in [("nowhere@x.com", NOWHERE), ("gone@x.com", GONE)] {
        assert!(
            warning_line(&items, id)
                .contains(&format!("<a href=\"/users/{uuid}\"><code>{id}</code></a>")),
            "a person line links its identifier to that person's page: {}",
            warning_line(&items, id)
        );
    }
    assert!(
        warning_line(&items, "@unused")
            .contains(r#"<a href="/groups/unused"><code>@unused</code></a>"#),
        "and a group line links the group's page, which is the answer to its own warning: {}",
        warning_line(&items, "@unused")
    );
}

#[test]
fn user_page_shows_its_scopes_and_notes() {
    let html = render("user", Route::User(BOB.to_string()));
    assert!(
        html.contains("mpa/admin"),
        "the scope that lists this user is shown"
    );
    assert!(html.contains("the bot"), "notes come from extra");
    assert!(
        html.contains("everything its owner reaches"),
        "the sample key declares no scopes of its own"
    );
}

#[test]
fn user_in_no_scope_gets_the_warning() {
    let html = render("nowhere", Route::User(NOWHERE.to_string()));
    assert!(html.contains("in no scope"), "{html}");
}

#[test]
fn app_page_lists_its_scopes_in_file_order_with_raw_group_refs() {
    let html = render("app", Route::App("mpa".to_string()));
    assert!(
        html.contains("<ol"),
        "order is meaning, so it is an ordered list"
    );
    assert!(html.contains("admin") && html.contains("restricted"));
    // A `@group` reference is shown as the file spells it, never expanded to who it
    // resolves to today.
    assert!(html.contains("@admins"), "the reference is shown as stored");
}

#[test]
fn apps_page_lists_applications_with_their_scope_count() {
    let html = render("apps", Route::Apps);
    assert!(html.contains("mpa"));
}

#[test]
fn the_access_check_answers_on_both_pages_that_ask_it() {
    // A person's page asks with the identity fixed: one field, and the subject is the row
    // itself. The `mpa/admin` scope lists Bob through `@admins`, so the gate lets him in.
    let user = render_of(
        "check-user",
        SAMPLE,
        Route::User(BOB.to_string()),
        "url=https://app.x.com/mpa/admin/x",
    );
    assert!(user.contains("AUTHORIZED"), "{user}");
    assert!(user.contains("X-Auth-Email"), "{user}");
    assert!(
        !user.contains(r#"name="email""#),
        "the identity is the page, not a field: {user}"
    );

    // An application's page asks with both, and the same pair gets the same verdict: one
    // `decide`, two arrangements of the question.
    let app = render_of(
        "check-app",
        SAMPLE,
        Route::App("mpa".to_string()),
        "email=bob@x.com&url=https://app.x.com/mpa/admin/x",
    );
    assert!(app.contains("AUTHORIZED"), "{app}");
    assert!(app.contains(r#"name="email""#), "{app}");

    // And a refusal reads as one, on the page that can ask it: an anonymous client on a
    // restricted scope. The panel's own class is what carries that to the eye.
    let anon = render_of(
        "check-anon",
        SAMPLE,
        Route::App("mpa".to_string()),
        "url=https://app.x.com/mpa/admin/x",
    );
    assert!(anon.contains("DENIED"), "{anon}");
    assert!(anon.contains(r#"class="panel bad""#), "{anon}");
}

#[test]
fn the_access_check_starts_on_the_area_it_is_asked_about() {
    // With nothing asked yet, the url field is prefilled with this application's own base:
    // an operator appends a path instead of retyping a host. And no verdict yet, because
    // nothing was asked.
    let html = render("check-empty", Route::App("mpa".to_string()));
    assert!(
        html.contains(r#"value="https://app.x.com/mpa""#),
        "the url field starts on the area: {html}"
    );
    assert!(
        !html.contains("AUTHORIZED") && !html.contains("DENIED"),
        "{html}"
    );
}

#[test]
fn a_row_with_no_email_has_nothing_to_check() {
    // No identifier resolves to this row, so there is no question to ask: the section says
    // so instead of quietly testing the empty subject, which `decide` would read as
    // anonymous and answer about somebody else entirely.
    const NO_EMAIL: &str = r#"{ "version": 1,
          "applications": [],
          "users": [ { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b", "emails": [] } ]
        }"#;
    let html = render_of("check-noemail", NO_EMAIL, Route::User(BOB.to_string()), "");
    assert!(html.contains("no email"), "{html}");
    assert!(!html.contains(r#"name="url""#), "no form to submit: {html}");
}

#[test]
fn the_users_page_leads_to_the_group_list() {
    // §13.36 §1: the groups are no longer a section stacked on the roster's page, so the
    // way to them is the row of sub-tabs, in the file's own section order, and the old
    // `/users#user_groups` bookmark has to land on something.
    let html = render_of("groups", SAMPLE, Route::Users, "");
    let (_, links) = sub_tabs(&html);
    assert_eq!(
        links
            .iter()
            .map(|a| attr(a, "href").unwrap_or_default())
            .collect::<Vec<_>>(),
        ["/users", "/groups", "/denied"],
        "People, Groups, Denied, in that order: {html}"
    );
    assert_eq!(
        attr(&links[1], "id").as_deref(),
        Some("user_groups"),
        "the bookmark an operator has in a note still means the groups"
    );
    assert_eq!(
        attr(&links[2], "id").as_deref(),
        Some("denied"),
        "and the one for the veto does the same"
    );
}

#[test]
fn a_list_filters_and_pages_with_nothing_but_the_query_string() {
    let big = many_users(PAGE_SIZE + 5);

    // Page one: the first PAGE_SIZE rows, and a pager offering the second.
    let html = render_of("pg1", &big, Route::Users, "");
    assert!(html.contains("user000@x.com"), "{html}");
    assert!(
        !html.contains("user025@x.com"),
        "page 1 must stop at the size"
    );
    assert!(html.contains("up=2"), "a next-page link: {html}");

    // Page two, asked for the way a link asks: 1-based, in the URL.
    let html = render_of("pg2", &big, Route::Users, "up=2");
    assert!(html.contains("user025@x.com"), "{html}");
    assert!(!html.contains("user000@x.com"));

    // The filter narrows, and the pager goes away when one page is enough.
    let html = render_of("pg3", &big, Route::Users, "uq=user01");
    assert!(html.contains("user010@x.com"));
    assert!(!html.contains("user020@x.com"));
    assert!(!html.contains("up=2"), "10 rows need no pager: {html}");

    // A filter that matches nothing says so, rather than looking like an empty file.
    let html = render_of("pg4", &big, Route::Users, "uq=nobodyatall");
    assert!(html.contains("matches that filter"), "{html}");

    // And none of it needs scripting.
    assert!(!html.contains("<script"), "{html}");
}
