use super::*;

// --- the audit file -----------------------------------------------------

/// A fresh audit path of its own, so these tests run in parallel like the rest.
fn audit_tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("bb-auth-audit-{name}.jsonl"));
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(audit_previous(&p));
    p
}

fn login(ts: u64, who: &str) -> AuditEvent {
    AuditEvent::new(ts, AuditKind::LoginGranted, AuditCredential::Local).by(who, None)
}

/// Append under the policy a settings file that says nothing gets.
fn put(w: &AuditWriter, ev: AuditEvent) {
    w.record(&ev, &AuditPolicy::default()).unwrap();
}

#[test]
fn the_audit_reads_back_newest_first() {
    let p = audit_tmp("order");
    let w = AuditWriter::new(&p);
    for (i, who) in ["a@x.com", "b@x.com", "c@x.com"].iter().enumerate() {
        put(&w, login(100 + i as u64, who));
    }
    let page = read_audit(&p, None, 100).unwrap();
    let seen: Vec<&str> = page
        .events
        .iter()
        .map(|e| e.subject.as_deref().unwrap())
        .collect();
    assert_eq!(seen, ["c@x.com", "b@x.com", "a@x.com"]);
    assert!(!page.more);
    assert_eq!(page.damaged, 0);
    assert_eq!(page.events[0].v, AUDIT_SCHEMA);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn the_audit_stops_at_the_window_and_at_the_cap() {
    let p = audit_tmp("window");
    let w = AuditWriter::new(&p);
    for ts in 100..110 {
        put(&w, login(ts, "a@x.com"));
    }
    // The window is a floor on `ts`, and the file being time-ordered is what lets the
    // read stop there rather than parse the rest.
    assert_eq!(read_audit(&p, Some(105), 100).unwrap().events.len(), 5);
    // The cap says so instead of trimming in silence.
    let page = read_audit(&p, None, 3).unwrap();
    assert_eq!(page.events.len(), 3);
    assert!(page.more);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_torn_line_is_counted_and_the_rest_is_read() {
    let p = audit_tmp("torn");
    let w = AuditWriter::new(&p);
    put(&w, login(100, "a@x.com"));
    // What a power cut mid-append leaves behind.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"ts\":101,\"kin\n").unwrap();
    }
    put(&w, login(102, "b@x.com"));
    let page = read_audit(&p, None, 100).unwrap();
    assert_eq!(page.events.len(), 2, "the whole lines are still readable");
    assert_eq!(page.damaged, 1, "and the broken one is reported");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_rotation_keeps_the_window_whole() {
    let p = audit_tmp("rotate");
    let w = AuditWriter::new(&p);
    put(&w, login(100, "old@x.com"));
    // Rotate by hand rather than by writing four megabytes: what is under test is that a
    // read spans both files, not that `metadata` can measure one.
    std::fs::rename(&p, audit_previous(&p)).unwrap();
    put(&w, login(101, "new@x.com"));
    let page = read_audit(&p, None, 100).unwrap();
    let seen: Vec<&str> = page
        .events
        .iter()
        .map(|e| e.subject.as_deref().unwrap())
        .collect();
    assert_eq!(seen, ["new@x.com", "old@x.com"]);
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(audit_previous(&p));
}

/// Lines of an audit file, as the writer would have left them, oldest first.
fn lines_of(stamps: &[u64]) -> String {
    stamps
        .iter()
        .map(|ts| {
            format!(
                "{}\n",
                serde_json::to_string(&login(*ts, "a@x.com")).unwrap()
            )
        })
        .collect()
}

fn stamps(p: &std::path::Path) -> Vec<u64> {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| line_ts(l.as_bytes()))
        .collect()
}

fn cleanup_audit(p: &std::path::Path) {
    let _ = std::fs::remove_file(p);
    let _ = std::fs::remove_file(audit_previous(p));
}

/// The live file rotates before the line that would take it past its size, not after, so
/// the pair never holds more than the policy says: the bound is exact, not exact give or
/// take a line.
#[test]
fn the_live_file_rotates_before_it_would_pass_its_size() {
    let p = audit_tmp("rotate-size");
    // A retention of 2 MiB rotates the live file at 1 MiB.
    let policy = AuditPolicy::new(
        AuditLimit::new(4, AuditUnit::MiB),
        Some(AuditLimit::new(2, AuditUnit::MiB)),
    )
    .unwrap();
    let limit = policy.rotate_at_bytes();
    let one = lines_of(&[100]);
    let mut fill = String::new();
    let mut ts = 100;
    while fill.len() + one.len() <= limit as usize {
        fill.push_str(&lines_of(&[ts]));
        ts += 1;
    }
    std::fs::write(&p, &fill).unwrap();
    let w = AuditWriter::new(&p);
    w.record(&login(ts, "next@x.com"), &policy).unwrap();
    assert_eq!(
        stamps(&p),
        [ts],
        "the live file starts again with the new event"
    );
    assert_eq!(
        std::fs::read_to_string(audit_previous(&p)).unwrap(),
        fill,
        "and the one before it is what the live file was, whole"
    );
    assert!(std::fs::metadata(audit_previous(&p)).unwrap().len() <= limit);
    cleanup_audit(&p);
}

/// Maintenance is what makes a time mean something on a deployment that writes nothing
/// for a month: a live file whose oldest event is past the rotation age moves on, and
/// every event past a retention in time goes, whichever file it is in.
#[test]
fn maintenance_rotates_on_age_and_drops_what_the_retention_expired() {
    let now = 10_000_000;
    let week = 604_800;

    // Rotation on age: the oldest event is two weeks old, the rotation is one week.
    let p = audit_tmp("maintain-age");
    std::fs::write(&p, lines_of(&[now - 2 * week, now - 10])).unwrap();
    let rotate_weekly = AuditPolicy::new(
        AuditLimit::new(1, AuditUnit::Weeks),
        Some(AuditLimit::new(64, AuditUnit::MiB)),
    )
    .unwrap();
    AuditWriter::new(&p).maintain(&rotate_weekly, now).unwrap();
    assert!(!p.exists(), "rotated away");
    assert_eq!(stamps(&audit_previous(&p)), [now - 2 * week, now - 10]);
    cleanup_audit(&p);

    // Retention in time: `.1` entirely expired, the live file half.
    let p = audit_tmp("maintain-retention");
    std::fs::write(audit_previous(&p), lines_of(&[1_000, 1_001])).unwrap();
    let mut live = lines_of(&[5_000, now - 2 * week]);
    live.push_str("{\"ts\":42,\"kin\n"); // a torn line among the expired ones
    live.push_str(&lines_of(&[now - 3_600, now - 60]));
    std::fs::write(&p, live).unwrap();
    let keep_a_week = AuditPolicy::new(
        AuditLimit::new(4, AuditUnit::MiB),
        Some(AuditLimit::new(1, AuditUnit::Weeks)),
    )
    .unwrap();
    AuditWriter::new(&p).maintain(&keep_a_week, now).unwrap();
    assert!(
        !audit_previous(&p).exists(),
        "a file with nothing left in it goes"
    );
    assert_eq!(stamps(&p), [now - 3_600, now - 60]);
    assert_eq!(
        read_audit(&p, None, 100).unwrap().damaged,
        0,
        "and the torn line went with the expired events around it"
    );
    // Run again, nothing changes: a retention already met costs no rewrite.
    let before = std::fs::read(&p).unwrap();
    AuditWriter::new(&p).maintain(&keep_a_week, now).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), before);
    cleanup_audit(&p);
}

/// A stricter policy takes effect at the next maintenance, which the gate runs on every
/// reload: a `.1` written under a looser one is cut down to its newest events, at a line
/// boundary, rather than standing too big until the next rotation.
#[test]
fn a_stricter_size_cuts_a_file_written_under_a_looser_one() {
    let p = audit_tmp("maintain-size");
    let old: Vec<u64> = (0..40_000).collect();
    std::fs::write(audit_previous(&p), lines_of(&old)).unwrap();
    std::fs::write(&p, lines_of(&[50_000])).unwrap();
    let tight = AuditPolicy::new(
        AuditLimit::new(4, AuditUnit::MiB),
        Some(AuditLimit::new(2, AuditUnit::MiB)),
    )
    .unwrap();
    AuditWriter::new(&p).maintain(&tight, 60_000).unwrap();
    let prev = audit_previous(&p);
    assert!(std::fs::metadata(&prev).unwrap().len() <= tight.rotate_at_bytes());
    let kept = stamps(&prev);
    assert_eq!(
        kept.last(),
        Some(&39_999),
        "the newest events are the ones kept"
    );
    assert!(kept.len() < old.len());
    assert_eq!(
        read_audit(&p, None, 100_000).unwrap().damaged,
        0,
        "cut at a line"
    );
    cleanup_audit(&p);
}

/// Backwards through a file in blocks far smaller than its lines: every line comes out
/// whole, last first, blank ones skipped, with or without a final newline.
#[test]
fn a_file_is_read_backwards_in_blocks_and_every_line_comes_out_whole() {
    let p = audit_tmp("revlines");
    for body in [
        "alpha\nbravo-is-a-much-longer-line\n\ncharlie\n",
        "alpha\nbravo-is-a-much-longer-line\n\ncharlie",
        "",
        "\n\n",
        "only",
    ] {
        std::fs::write(&p, body).unwrap();
        let expect: Vec<&str> = body.lines().filter(|l| !l.is_empty()).rev().collect();
        for block in [1, 3, 7, 64 * 1024] {
            let mut r = RevLines::with_block(&p, block).unwrap();
            let mut got = Vec::new();
            while let Some(l) = r.next_line().unwrap() {
                got.push(String::from_utf8(l).unwrap());
            }
            assert_eq!(got, expect, "{body:?} in blocks of {block}");
        }
    }
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_missing_audit_is_an_empty_page_and_not_a_fault() {
    // What a gate that has never refused anybody looks like. It must not read as an
    // error, or the page would report a fault on a healthy deployment.
    let p = audit_tmp("absent");
    let page = read_audit(&p, None, 100).unwrap();
    assert!(page.events.is_empty());
    assert_eq!(page.damaged, 0);
}

#[test]
fn an_event_serializes_to_one_line_of_only_what_it_has() {
    let ev = AuditEvent::new(
        1_700_000_000,
        AuditKind::AccessRefused,
        AuditCredential::Key {
            id: "laptop".into(),
        },
    )
    .of("11111111-2222-3333-4444-555555555555")
    .at(Some(("ai", "root")))
    .on(Some("https://ai.x.com/mcp"))
    .because(decision_reason(&Decision::KeyOutOfScope {
        app: "ai".into(),
        scope: "root".into(),
    }));
    let line = serde_json::to_string(&ev).unwrap();
    assert!(!line.contains('\n'), "one event is one line");
    // An absent field is absent, not null: the file is read by a program and written on
    // a card, and half these fields are absent on any given event.
    assert!(!line.contains("subject"));
    assert!(line.contains(r#""reason":"key_out_of_scope""#));
    assert!(line.contains(r#""cred":{"type":"key","id":"laptop"}"#));
    assert_eq!(serde_json::from_str::<AuditEvent>(&line).unwrap(), ev);
    // The filter matches on the key's id, the scope and the reason alike.
    let hay = ev.haystack();
    for part in ["laptop", "ai", "root", "key_out_of_scope", "ai.x.com"] {
        assert!(hay.contains(part), "{part} is filterable");
    }
}

#[test]
fn where_a_request_came_from_rides_on_the_event_and_is_filterable() {
    let client = AuditClient {
        ip: Some("203.0.113.7".into()),
        ua: Some("Mozilla/5.0 (X11; Linux aarch64)".into()),
        rid: Some("5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f".into()),
    };
    let ev = login(1_700_000_000, "a@x.com")
        .account(Some("9d8e7f60-1a2b-4c3d-8e9f-0a1b2c3d4e5f"))
        .from(&client);
    assert_eq!(ev.ip, client.ip);
    assert_eq!(ev.ua, client.ua);
    assert_eq!(ev.rid, client.rid);
    let line = serde_json::to_string(&ev).unwrap();
    assert!(line.contains(r#""ip":"203.0.113.7""#), "{line}");
    assert!(line.contains(r#""sub":"9d8e7f60-"#), "{line}");
    assert_eq!(serde_json::from_str::<AuditEvent>(&line).unwrap(), ev);

    // Pasting an address from a firewall's log, or an id from nginx's, is how a reader
    // arrives at this page, so both have to find the row.
    let hay = ev.haystack();
    for part in ["203.0.113.7", "5f1c0a9e", "9d8e7f60", "aarch64"] {
        assert!(hay.contains(part), "{part} is filterable");
    }

    // A client that said nothing leaves nothing behind, not three nulls.
    let bare = login(1_700_000_000, "a@x.com").from(&AuditClient::default());
    let line = serde_json::to_string(&bare).unwrap();
    for absent in ["\"ip\"", "\"ua\"", "\"rid\"", "\"sub\""] {
        assert!(!line.contains(absent), "{absent} in {line}");
    }
}

/// The schema is additive, and a line an older gate wrote is still read. That is the whole
/// reason `AUDIT_SCHEMA` did not move when four fields arrived: nobody holds a line of this
/// file, so tolerating one without them costs nothing.
#[test]
fn a_line_from_before_the_client_fields_still_reads() {
    let old = r#"{"v":1,"ts":1700000000,"kind":"login_granted","cred":{"type":"local"},"subject":"a@x.com"}"#;
    let ev: AuditEvent = serde_json::from_str(old).unwrap();
    assert_eq!(ev.subject.as_deref(), Some("a@x.com"));
    assert_eq!((ev.ip, ev.ua, ev.rid, ev.sub), (None, None, None, None));
}

/// The audit is created group-readable, and that is a deployment contract rather than a
/// detail: the gate writes this file under `UMask=0077`, and `bb-auth-web` reads it
/// through the `bb-auth` group it already belongs to. At 0600 the Audit tab is a
/// permission error on a deployment where everything else is correct, and the only sign
/// of it is a page nobody looks at until they need it.
#[cfg(unix)]
#[test]
fn the_audit_is_readable_by_the_group_that_has_to_read_it() {
    use std::os::unix::fs::PermissionsExt;
    let p = audit_tmp("mode");
    put(&AuditWriter::new(&p), login(100, "a@x.com"));
    let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o640,
        "owner writes, the gate's group reads, nobody else"
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn the_credential_tag_is_the_kind_and_not_the_instance() {
    // The filter offers five words; a key's id must not be one of them, or filtering by
    // credential would mean filtering by which key.
    assert_eq!(
        AuditCredential::Key {
            id: "laptop".into()
        }
        .tag(),
        AuditCredential::Key { id: "phone".into() }.tag()
    );
    assert_eq!(
        AuditCredential::Social {
            provider: "Google".into()
        }
        .tag(),
        "social"
    );
    assert!(AuditKind::LoginGranted.granted());
    assert!(!AuditKind::AccessRefused.granted());
}

#[test]
fn the_cognito_endpoint_is_the_issuers_origin() {
    // The pool id is the only part of an issuer URL that is not the API's address.
    let s = settings(
        r#"{ "version": 3, "gate": { "issuer":
                "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TESTPOOL" } }"#,
    )
    .unwrap();
    assert_eq!(
        s.cognito_endpoint(),
        "https://cognito-idp.eu-central-1.amazonaws.com/"
    );
    // A port belongs to the origin, the path does not.
    let s =
        settings(r#"{ "version": 3, "gate": { "issuer": "https://idp.example.com:8443/pool" } }"#)
            .unwrap();
    assert_eq!(s.cognito_endpoint(), "https://idp.example.com:8443/");
    // No issuer, no endpoint: empty, never a bare "/" a page would then post to.
    let s = settings(r#"{ "version": 3 }"#).unwrap();
    assert_eq!(s.cognito_endpoint(), "");
}

#[test]
fn email_verified_is_true_or_the_string_true() {
    assert!(email_verified_true(&serde_json::json!(true)));
    assert!(email_verified_true(&serde_json::json!("true")));
    assert!(email_verified_true(&serde_json::json!("TRUE")));
    assert!(!email_verified_true(&serde_json::json!(false)));
    assert!(!email_verified_true(&serde_json::json!("false")));
    assert!(!email_verified_true(&serde_json::json!("1")));
    assert!(!email_verified_true(&serde_json::json!(1)));
    assert!(!email_verified_true(&serde_json::json!(null)));
}

/// The GUI's unit lets the process reach Cognito (docs/ARCHITECTURE.md §13.22, slice 5b):
/// `IPAddressDeny=any` would drop every packet the profile edit sends, so the directive
/// pair is gone, while the two things that keep egress from coming with the HMAC key stay.
#[test]
fn the_gui_unit_lets_cognito_out() {
    let unit = include_str!("../../deploy/bb-auth-web.service");
    let directives: Vec<&str> = unit
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    assert!(
        !directives.iter().any(|l| l.starts_with("IPAddress")),
        "the unit must carry no IPAddressDeny/IPAddressAllow line: {directives:?}"
    );
    assert!(
        directives.contains(&"InaccessiblePaths=/opt/bb-auth/etc"),
        "the HMAC key stays unreachable: {directives:?}"
    );
    assert!(
        directives
            .iter()
            .any(|l| l.starts_with("RestrictAddressFamilies=")),
        "the address families stay restricted: {directives:?}"
    );
}
