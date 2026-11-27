use super::*;

// --- the argument grammar -----------------------------------------------
//
// This tool writes the production access file, as root, over SSH, and until now its
// parser had no test at all: the grammar was whatever `parse_args` happened to do, and
// one of its behaviours (a bare flag) was detected by matching on the *text* of an error
// message raised somewhere else. What follows pins the grammar itself, so that the next
// person to touch it finds out from `cargo test` rather than from a host.

/// `parse_args` over a command line written the way a person would type it.
fn args(line: &str) -> (Vec<String>, Flags) {
    let argv: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    parse_args(&argv).expect("this line parses")
}

#[test]
fn the_two_spellings_of_a_flag_value_are_the_same_thing() {
    for line in [
        "scope add mpa admin --access restricted",
        "scope add mpa admin --access=restricted",
    ] {
        let (words, mut flags) = args(line);
        assert_eq!(words, ["scope", "add", "mpa", "admin"]);
        assert_eq!(
            flags.take_one("access").unwrap().as_deref(),
            Some("restricted")
        );
        flags.finish().expect("nothing left over");
    }
}

#[test]
fn a_bare_flag_is_a_boolean_and_a_valued_one_is_still_read() {
    let (_, mut flags) = args("scope set mpa admin --no-scopes");
    assert_eq!(flags.take("no-scopes").unwrap(), Taken::Bare);

    // The whole point of the type: `take_flag` must not be reading this off an error
    // string. Bare is true, an explicit false is false, and a value that is neither is a
    // refusal rather than a silent true.
    let (_, mut flags) = args("key set bob laptop --force");
    assert!(flags.take_flag("force").unwrap());
    let (_, mut flags) = args("key set bob laptop --force=no");
    assert!(!flags.take_flag("force").unwrap());
    let (_, mut flags) = args("key set bob laptop --force=perhaps");
    assert!(flags.take_flag("force").is_err());
    let (_, mut flags) = args("key set bob laptop");
    assert!(!flags.take_flag("force").unwrap());
}

#[test]
fn a_flag_that_wants_a_value_refuses_a_bare_one() {
    let (_, mut flags) = args("app add mpa --base");
    let e = flags.take_one("base").unwrap_err();
    assert!(e.contains("needs a value"), "{e}");
}

#[test]
fn a_repeated_single_value_is_an_error_rather_than_a_silent_choice() {
    let (_, mut flags) = args("app add mpa --login-url a --login-url b");
    let e = flags.take_one("login-url").unwrap_err();
    assert!(e.contains("more than once"), "{e}");
}

#[test]
fn take_many_accumulates_across_repeats_and_commas() {
    let (_, mut flags) = args("scope add mpa admin --url a,b --url c");
    assert_eq!(flags.take_many("url").unwrap(), ["a", "b", "c"]);
    // Empty items are dropped, so a trailing comma is not a pattern.
    let (_, mut flags) = args("scope add mpa admin --url a,,b,");
    assert_eq!(flags.take_many("url").unwrap(), ["a", "b"]);
    // And a bare one is still a missing value, not an empty list.
    let (_, mut flags) = args("scope add mpa admin --url");
    assert!(flags.take_many("url").is_err());
}

#[test]
fn an_unclaimed_flag_is_refused_by_finish() {
    // The reflex the whole tool is built on: a typo must never be shrugged off by the
    // one program whose job is keeping typos out of the access file.
    let (_, flags) = args("user add bob@x.com --emial x");
    let e = flags.finish().unwrap_err();
    assert!(e.contains("--emial"), "{e}");
}

#[test]
fn a_single_dash_option_is_refused_outright() {
    let argv: Vec<String> = ["user", "add", "-x"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let e = parse_args(&argv).unwrap_err();
    assert!(e.contains("unknown option"), "{e}");
}

#[test]
fn a_value_that_looks_like_a_flag_is_treated_as_a_flag() {
    // A documented limit rather than a bug, and worth pinning so a change to it is a
    // decision: `--note --base` is read as two bare flags, so the note is reported
    // missing instead of being given the text "--base". A value that must start with two
    // dashes is written `--note=--base`.
    let (_, mut flags) = args("app add mpa --note --base");
    assert_eq!(flags.take("note").unwrap(), Taken::Bare);
    assert_eq!(flags.take("base").unwrap(), Taken::Bare);
    let (_, mut flags) = args("app add mpa --note=--base");
    assert_eq!(
        flags.take("note").unwrap(),
        Taken::Valued("--base".to_string())
    );
}

// --- `settings set --landing-url` ------------------------------------------

/// A settings file of its own under the temp directory (tests run in parallel), and the
/// `Ctx` that `settings set LINE` would get for it.
fn landing_ctx(name: &str, line: &str) -> (Ctx, String) {
    let p = std::env::temp_dir().join(format!("bb-auth-adm-landing-{name}.json"));
    std::fs::write(
        &p,
        r#"{ "version": 3, "gate": { "authorized_hosts": ["auth.x.com"] } }"#,
    )
    .unwrap();
    let path = p.to_string_lossy().into_owned();
    let (_, flags) = args(line);
    let ctx = Ctx {
        path: String::new(),
        settings_path: path.clone(),
        dry_run: false,
        flags,
    };
    (ctx, path)
}

#[test]
fn settings_set_landing_url_writes_and_an_empty_value_unsets() {
    let (ctx, path) = landing_ctx(
        "set",
        "settings set --landing-url https://auth.x.com/account/",
    );
    assert!(cmd_settings_set(ctx).is_ok());
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("https://auth.x.com/account/"), "{on_disk}");

    // An empty value is how it is unset, and the key leaves the file.
    let (_, flags) = args("settings set --landing-url=");
    let ctx = Ctx {
        path: String::new(),
        settings_path: path.clone(),
        dry_run: false,
        flags,
    };
    assert!(cmd_settings_set(ctx).is_ok());
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(!on_disk.contains("landing_url"), "{on_disk}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn settings_set_landing_url_off_the_authorized_hosts_is_refused() {
    let (ctx, path) = landing_ctx(
        "off",
        "settings set --landing-url https://evil.example.org/",
    );
    let before = std::fs::read_to_string(&path).unwrap();
    let e = cmd_settings_set(ctx).unwrap_err();
    assert!(
        e.contains("landing_url") && e.contains("authorized_hosts"),
        "{e}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "nothing written"
    );

    // Not an absolute https URL: refused naming the flag that was typed.
    let (ctx, path2) = landing_ctx("bad", "settings set --landing-url /account/");
    let e = cmd_settings_set(ctx).unwrap_err();
    assert!(e.contains("landing"), "{e}");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&path2);
}

#[test]
fn to_exclusions_keeps_a_stranger_and_resolves_a_user() {
    let doc: AccessFile = serde_json::from_str(
        r#"{ "version": 1, "user_groups": { "admins": [] },
                 "users": [ { "uuid": "11111111-1111-4111-8111-111111111111",
                              "emails": ["bob@x.com"] } ] }"#,
    )
    .unwrap();
    let got = to_exclusions(
        &doc,
        &[
            "BOB@x.com".to_string(),
            "@admins".to_string(),
            "Stranger@X.com".to_string(),
        ],
    )
    .unwrap();
    assert_eq!(
        got,
        [
            "11111111-1111-4111-8111-111111111111",
            "@admins",
            "stranger@x.com"
        ]
    );
    // Something that is none of the three is refused rather than written down as a
    // string nothing will ever equal.
    assert!(to_exclusions(&doc, &["nonsense".to_string()]).is_err());
}

#[test]
fn shadowing_scope_finds_the_broad_scope_listed_first() {
    let broad = ScopeSpec {
        name: "broad".into(),
        urls: vec!["https://x.com/a/*".into()],
        access: "authenticated".into(),
        ..Default::default()
    };
    let narrow = ScopeSpec {
        name: "narrow".into(),
        urls: vec!["https://x.com/a/deep/*".into()],
        access: "authenticated".into(),
        ..Default::default()
    };
    let scopes = [broad, narrow];
    assert_eq!(shadowing_scope(&scopes[..1], &scopes[1].urls), Some(0));
    assert_eq!(shadowing_scope(&scopes[..0], &scopes[0].urls), None);
}

// --- what `user rm` reports ---------------------------------------------
//
// `remove_user` rewrites an exclusion to the row's primary email instead of dropping it,
// so the report may not say the person was "removed from" that scope: they are still
// kept out of it, now as a stranger. `user_rm_report(label, primary, swept)` returns the
// lines to print (each without the `[bb-auth-adm] ` prefix); `primary` is the email
// `remove_user` wrote in, `None` for a row that had none.

fn swept(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn an_exclusion_that_became_an_email_is_reported_as_still_in_force() {
    let lines = user_rm_report(
        "bob@x.com",
        Some("bob@x.com"),
        &swept(&["mpa/admin", "mpa/onb (excluded)", "@staff"]),
    );
    let all = lines.join("\n");
    assert!(
        all.contains("bob@x.com: also removed from mpa/admin, @staff"),
        "grants keep the old wording, without the exclusion: {all}"
    );
    let kept = lines
        .iter()
        .find(|l| l.contains("mpa/onb"))
        .unwrap_or_else(|| panic!("the exclusion is reported: {all}"));
    assert!(!kept.contains("removed from"), "{kept}");
    assert!(kept.contains("still kept out"), "{kept}");
    assert!(kept.contains("by email bob@x.com"), "{kept}");
    assert!(!kept.contains("(excluded)"), "{kept}");
}

#[test]
fn a_row_with_no_email_keeps_the_removed_from_wording_for_exclusions() {
    let uuid = "11111111-2222-4333-8444-555555555555";
    let lines = user_rm_report(uuid, None, &swept(&["mpa/onb (excluded)", "@staff"]));
    assert_eq!(
        lines,
        [format!(
            "{uuid}: also removed from mpa/onb (excluded), @staff"
        )]
    );
}

#[test]
fn nothing_swept_reports_nothing() {
    assert!(user_rm_report("bob@x.com", Some("bob@x.com"), &[]).is_empty());
}

#[test]
fn only_exclusions_leave_no_removed_from_line_at_all() {
    let lines = user_rm_report(
        "bob@x.com",
        Some("bob@x.com"),
        &swept(&["mpa/onb (excluded)"]),
    );
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(!lines[0].contains("removed from"), "{lines:?}");
}
