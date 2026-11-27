use super::*;

// ===========================================================================================
// §13.29 W3 step 5, W10 slice 7d: the roster row goes before the first POST
//
// A caller WITH a roster row. The whoami walk (7c) finishes, then the row is removed
// through the library's editing core under the GUI's write lock, and only then are the
// addresses posted. The order is the whole slice, and no assertion on a response can see
// it: the row has to be looked for in the file, from inside the request that is supposed
// to follow the write, which is what [`FakeIntake::watch`] does.
//
// The partial outcomes (a `POST` refused after the row is gone) are slice 7e, so the fake
// answers every `POST` on this path with `202 accepted`.
// ===========================================================================================

/// `AccountDeleteWriteFailed` (§13.30 §5), verbatim in both languages. A const and not a
/// `K` key: the key does not exist yet, and the red this slice wants is the missing
/// behaviour, not a missing symbol.
const DELETE_WRITE_FAILED_EN: &str = "bb-auth could not save the change, so nothing was \
                                          deleted and you can still sign in. Try again in a \
                                          minute; if it fails again, tell an administrator.";
const DELETE_WRITE_FAILED_IT: &str = "bb-auth non è riuscito a salvare la modifica, quindi \
                                          non è stato eliminato nulla e puoi ancora accedere. \
                                          Riprova tra un minuto; se non funziona di nuovo, \
                                          avvisa un amministratore.";

/// The roster fixture in a directory of its own, made **read-only**. The write ends with a
/// temp file renamed into the access file's directory, so a directory that refuses creates
/// is the write failing on the path the handler takes, not on a mock of it. `r-x` for its
/// owner keeps the reads a request starts (`rev`, the file) working, and uid 1000 is not
/// root, so the mode means what it says.
#[cfg(unix)]
fn account_scratch_roster_locked(name: &str) -> (String, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("bb-auth-web-account-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory");
    let path = dir.join("access.json").to_string_lossy().into_owned();
    std::fs::write(&path, account_access_roster()).expect("write the access fixture");
    std::fs::write(settings_path(&path), ACCOUNT_SETTINGS_FULL)
        .expect("write the settings fixture");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500))
        .expect("the scratch directory is made read-only");
    (path, dir)
}

/// The directory writable again, so the scratch can be removed.
#[cfg(unix)]
fn account_scratch_unlocked(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .expect("the scratch directory is made writable again");
}

/// §13.29 W3 step 5, the order the slice exists for: the row is out of the access file
/// **before** the first `POST` reaches the worker. A worker that found the row standing
/// would find the key too, and the whole point of the step is that it finds neither. The
/// answer is the `303` §13.32 §1 gives a completed deletion, which renders no page: what
/// this test reads is the file and the intake, and the order they show is the same order
/// the done page used to describe.
///
/// The identity carries both of the row's addresses, space-joined as the gate sends them,
/// because the order this test pins is only visible on a walk over more than one: a single
/// address makes "every `whoami` before the first `POST`" and "the write before the first
/// `POST`" the same one request, and a handler that posted first would pass.
#[test]
fn a_roster_deletion_removes_the_row_before_the_first_post() {
    for lang in [Lang::En, Lang::It] {
        let intake = FakeIntake::answering(vec![
            (WHOAMI_PATH, whoami_ok()),
            (DELETE_PATH, delete_accepted()),
        ]);
        let path = account_scratch_roster(&format!("delete-7d-order-{}", lang.code()));
        intake.watch(&path, ACCOUNT_BOB);
        let port = account_port_intake_at(&path, &intake.endpoint());
        let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
        let rev = rev_of(&path);
        let fields = [
            ("rev", rev.as_str()),
            ("uuid", ACCOUNT_BOB),
            ("confirm_email", "bob@x.com"),
        ];

        let g = account_post_lang(&url, "bob@x.com bob@old.com", &fields, lang);
        assert_eq!(
            g.status,
            303,
            "{}: every address was asked and posted, so the answer is the logout redirect \
                 (§13.32 §1): {}",
            lang.code(),
            account_readable(&g.body)
        );
        // The walk: every address asked, then every address posted.
        assert_eq!(
            intake.at(),
            vec![
                WHOAMI_PATH.to_string(),
                WHOAMI_PATH.to_string(),
                DELETE_PATH.to_string(),
                DELETE_PATH.to_string()
            ],
            "{}: both addresses are asked before either is posted: {:?}",
            lang.code(),
            intake.at()
        );
        // The order the slice exists for, where only the file can see it: bob's uuid is in
        // the file when each `whoami` lands and out of it when each `POST` does. A worker
        // that landed on the row would find the key too, so a `POST` that arrives while the
        // row stands is the failure this witness is built for.
        let rows = intake.rows_since(0);
        assert_eq!(
            rows,
            vec![Some(true), Some(true), Some(false), Some(false)],
            "{}: the row is gone before the first POST arrives: {rows:?}",
            lang.code()
        );
        // And the file as it stands says the same.
        let doc = bb_auth_core::read_access_file(&path)
            .expect("the file the write left parses with the gate's own parser");
        let uuids: Vec<&String> = doc.users.iter().map(|u| &u.uuid).collect();
        assert!(
            !uuids.contains(&&ACCOUNT_BOB.to_string()),
            "{}: bob's row is out of the file: {uuids:?}",
            lang.code()
        );
        assert!(
            uuids.contains(&&ACCOUNT_CAROL.to_string()),
            "{}: the row nobody asked about stands: {uuids:?}",
            lang.code()
        );
        // The answer: the gate's logout, and nothing rendered. The redirect replaces the
        // page's words, and the two effects this test is about are untouched by it.
        assert_eq!(
            g.header("Location"),
            Some(DELETE_LOGOUT_LOCATION),
            "{}: the completed deletion is answered by the gate's logout",
            lang.code()
        );
        assert!(
            g.body.is_empty(),
            "{}: no page, so no words to translate: {:?}",
            lang.code(),
            g.body
        );
        let _ = std::fs::remove_file(&path);
    }
}

/// §13.29 W3 step 5: the row goes **with everything attached to it**. The key is the one
/// that must not survive (a bearer that still works after the person asked to be deleted is
/// the failure); the scope and group references are what the library's sweep exists for;
/// and the exclusion is the one reference that is rewritten rather than dropped.
#[test]
fn keys_scope_and_group_references_go_and_exclusions_become_the_email() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_roster("delete-7d-sweep");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let rev = rev_of(&path);
    let g = account_post(
        &url,
        Some("bob@x.com bob@old.com"),
        &[
            ("rev", rev.as_str()),
            ("uuid", ACCOUNT_BOB),
            ("confirm_email", "bob@x.com"),
        ],
    );
    assert_eq!(
        g.status,
        303,
        "the roster walk completes, and its answer is the logout redirect (§13.32 §1): {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.header("Location"),
        Some(DELETE_LOGOUT_LOCATION),
        "the sweep below is asserted on the file a completed walk left behind"
    );

    // The file the write left, read by the gate's own parser: a file the gate would refuse
    // is a boot loop on the next reload, and no page is worth one.
    let doc = bb_auth_core::read_access_file(&path)
        .expect("the file the write left parses with the gate's own parser");
    let uuids: Vec<&String> = doc.users.iter().map(|u| &u.uuid).collect();
    assert!(
        !uuids.contains(&&ACCOUNT_BOB.to_string()),
        "bob's row is gone: {uuids:?}"
    );
    // The key went with the row: the file keeps no hash of a credential nobody can revoke
    // any more, and no id that names one.
    let text = read(&path);
    assert!(
        !text.contains("laptop"),
        "bob's key went with the row: {text}"
    );
    assert!(
        !text.contains(&sha256_hex(ACCOUNT_BEARER_LAPTOP)),
        "the hash of a bearer that would still be accepted is gone: {text}"
    );
    // The scopes that named the row by uuid, and the veto that named it.
    for app in &doc.applications {
        for scope in &app.scopes {
            let at = format!("{}/{}", app.name, scope.name);
            if let Some(users) = &scope.users {
                assert!(
                    !users.iter().any(|u| u == ACCOUNT_BOB),
                    "{at}: a scope no longer names a row that does not exist: {users:?}"
                );
            }
            if app.name == "mpa" && scope.name == "onboarding" {
                // The veto, rewritten: the row's primary email is the only spelling left
                // for an identity the roster no longer knows, and `authenticated` admits
                // that identity the moment it re-registers.
                assert_eq!(
                    scope.excluded,
                    Some(vec!["bob@x.com".to_string()]),
                    "{at}: the excluded entry became the row's primary email, it did not \
                         go away"
                );
            }
        }
    }
    // The group that named it.
    let admins = doc.user_groups.get("admins").cloned().unwrap_or_default();
    assert!(
        !admins.iter().any(|u| u == ACCOUNT_BOB),
        "the group no longer names bob: {admins:?}"
    );
    // The write is an edit, not a rewrite: the row nobody asked about stands, with its own
    // addresses untouched.
    let carol = doc
        .users
        .iter()
        .find(|u| u.uuid == ACCOUNT_CAROL)
        .expect("carol's row stands");
    assert_eq!(
        carol.emails,
        vec!["carol@x.com".to_string()],
        "carol is exactly as she was"
    );
    let _ = std::fs::remove_file(&path);
}

/// §13.30 §4 on the roster path: the `rev` and the uuid are re-checked under the write
/// lock, and a page that is not the current one writes nothing **and posts nothing**. A
/// queued deletion for an account the person was never shown is the one outcome this page
/// cannot take back, and the console's conflict sentence is not this page's words.
#[test]
fn a_stale_rev_is_a_409_and_posts_nothing() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_roster("delete-7d-stale");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    // Bytes the page never saw: the file moved after the form was rendered.
    let stale = "0000000000000000000000000000000000000000000000000000000000000000";
    let fields = [
        ("rev", stale),
        ("uuid", ACCOUNT_BOB),
        ("confirm_email", "bob@x.com"),
    ];

    for lang in [Lang::En, Lang::It] {
        let g = account_post_lang(&url, "bob@x.com", &fields, lang);
        assert_eq!(
            g.status,
            409,
            "{}: a form submitted onto bytes it never saw is a conflict: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_CHANGED_TITLE_EN, DELETE_CHANGED_TITLE_IT),
            "{}: the heading says the account changed: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            the_page_lede(&g.body),
            m(lang, DELETE_CHANGED_EN, DELETE_CHANGED_IT),
            "{}: the lede says nothing was deleted: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert!(
            !the_page_words(&g.body).contains(t(lang, K::ConflictBody)),
            "{}: the console's conflict sentence is not this page's: {}",
            lang.code(),
            the_page_words(&g.body)
        );
        let pills = the_action_pills(&g.body);
        assert!(
            pills.iter().any(
                |p| visible_text(p) == m(lang, DELETE_START_EN, DELETE_START_IT)
                    && attr(open_tag(p), "href").as_deref()
                        == Some(&format!("{ACCOUNT_PATH}/delete")[..])
            ),
            "{}: Start again re-renders the confirmation against the current file: \
                 {pills:?}",
            lang.code()
        );
        // Nothing was sent, at all: not a `whoami`, not a `POST`.
        assert!(
            intake.calls().is_empty(),
            "{}: a conflict sends the intake nothing: {:?}",
            lang.code(),
            intake.calls()
        );
        // And nothing was written.
        assert_eq!(
            read(&path),
            before,
            "{}: the conflict wrote nothing: the access file is byte for byte what it was",
            lang.code()
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.29 W5 on the roster path: the protected check is **ahead of the write**, so a
/// caller on the intake's list leaves the row, the key, every reference and every queue
/// standing. This is the guard that the write step does not run for a caller the walk
/// refused.
#[test]
fn a_protected_roster_user_keeps_the_row() {
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_protected()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let path = account_scratch_roster("delete-7d-protected");
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    let rev = rev_of(&path);
    let fields = [
        ("rev", rev.as_str()),
        ("uuid", ACCOUNT_BOB),
        ("confirm_email", "bob@x.com"),
    ];

    for lang in [Lang::En, Lang::It] {
        let seen = intake.calls().len();
        let g = account_post_lang(&url, "bob@x.com", &fields, lang);
        assert_eq!(
            g.status,
            403,
            "{}: a protected address is refused: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_NOT_DONE_EN, DELETE_NOT_DONE_IT),
            "{}: the heading states the result, in the reader's words: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            the_page_lede(&g.body),
            m(lang, DELETE_PROTECTED_EN, DELETE_PROTECTED_IT),
            "{}: the lede: {}",
            lang.code(),
            account_readable(&g.body)
        );
        let asked = intake.at_since(seen);
        assert_eq!(
            asked,
            vec![WHOAMI_PATH.to_string()],
            "{}: asked, refused, posted nothing: {asked:?}",
            lang.code()
        );
        assert_eq!(
            read(&path),
            before,
            "{}: a protected account leaves the file byte for byte as it was",
            lang.code()
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// §13.30 §4: the write is the step that can fail on its own, and a failure is the
/// server's, said as one: `500`, the row standing, and **no `POST /account/delete`**. A
/// queued address whose row was never removed is a deletion the worker carries out against
/// a file that still says the person is here. The `whoami` of W3 step 4 is asked **before**
/// the write of step 5, so it is expected here: what step 5 forbids is step 6.
#[cfg(unix)]
#[test]
fn a_failed_write_posts_nothing() {
    let (path, dir) = account_scratch_roster_locked("delete-7d-write-fail");
    let intake = FakeIntake::answering(vec![
        (WHOAMI_PATH, whoami_ok()),
        (DELETE_PATH, delete_accepted()),
    ]);
    let port = account_port_intake_at(&path, &intake.endpoint());
    let url = format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/delete");
    let before = read(&path);
    let rev = rev_of(&path);
    let fields = [
        ("rev", rev.as_str()),
        ("uuid", ACCOUNT_BOB),
        ("confirm_email", "bob@x.com"),
    ];

    for lang in [Lang::En, Lang::It] {
        let seen = intake.calls().len();
        let g = account_post_lang(&url, "bob@x.com", &fields, lang);
        assert_eq!(
            g.status,
            500,
            "{}: a write that cannot land is the server's fault, not the caller's: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            account_heading(&g.body, "h1"),
            m(lang, DELETE_NOT_DONE_EN, DELETE_NOT_DONE_IT),
            "{}: the heading states the result: {}",
            lang.code(),
            account_readable(&g.body)
        );
        assert_eq!(
            the_page_lede(&g.body),
            m(lang, DELETE_WRITE_FAILED_EN, DELETE_WRITE_FAILED_IT),
            "{}: the lede says the file could not be written, and that signing in still \
                 works: {}",
            lang.code(),
            account_readable(&g.body)
        );
        let pills = the_action_pills(&g.body);
        let texts: Vec<String> = pills.iter().map(|p| visible_text(p)).collect();
        assert_eq!(
            texts,
            vec![
                m(lang, DELETE_START_EN, DELETE_START_IT).to_string(),
                back_words(lang)
            ],
            "{}: start again, then back: {pills:?}",
            lang.code()
        );
        // W3 step 4 (`whoami`) runs ahead of step 5 (the write), so a `whoami` is the walk
        // doing its job. What a failed write must not do is step 6: queue a record for a row
        // that is still standing.
        let asked = intake.at_since(seen);
        assert!(
            !asked.iter().any(|c| c == DELETE_PATH),
            "{}: a failed write posts no deletion record: {asked:?}",
            lang.code()
        );
        assert_eq!(
            read(&path),
            before,
            "{}: a failed write leaves the file byte for byte as it was",
            lang.code()
        );
    }
    account_scratch_unlocked(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}
