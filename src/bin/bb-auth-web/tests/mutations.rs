use super::*;

// --- mutations ----------------------------------------------------------

#[test]
fn csrf_accepts_only_a_same_origin_submission() {
    // Sec-Fetch-Site is the whole answer where the browser sends it.
    assert!(csrf_ok(Some("same-origin"), None, None));
    assert!(csrf_ok(Some(" Same-Origin "), None, None));
    for bad in ["cross-site", "same-site", "none", ""] {
        assert!(!csrf_ok(Some(bad), None, None), "{bad:?} must be refused");
    }
    // A hostile Origin does not rescue a cross-site Sec-Fetch-Site.
    assert!(!csrf_ok(
        Some("cross-site"),
        Some("https://x.com"),
        Some("x.com")
    ));
    // Origin is the fallback, and only the host is compared — the scheme cannot be,
    // since this binary speaks http behind a TLS-terminating nginx.
    assert!(csrf_ok(
        None,
        Some("https://admin.x.com"),
        Some("admin.x.com")
    ));
    assert!(csrf_ok(
        None,
        Some("http://admin.x.com:8091"),
        Some("admin.x.com:8091")
    ));
    assert!(!csrf_ok(
        None,
        Some("https://evil.com"),
        Some("admin.x.com")
    ));
    assert!(!csrf_ok(None, Some("null"), Some("admin.x.com")));
    // Neither header is not a browser posting a form.
    assert!(!csrf_ok(None, None, Some("admin.x.com")));
    assert!(!csrf_ok(None, None, None));
}

#[test]
fn a_user_add_mints_a_uuid_and_redirects_to_it() {
    let path = scratch("m-useradd", SAMPLE);
    let cfg = cfg_for(&path, "");
    let got = post(
        &cfg,
        Route::UserAdd,
        &[("rev", &rev_of(&path)), ("email", " New@X.com ")],
    );
    let doc = bb_auth_core::read_access_file(&path).unwrap();
    let u = doc
        .users
        .iter()
        .find(|u| u.emails.iter().any(|e| e == "new@x.com"))
        .expect("the new row");
    assert_eq!(
        u.emails,
        ["new@x.com"],
        "the email is normalised on the way in"
    );
    assert_eq!(got.location(), format!("/users/{}?msg=user-added", u.uuid));
    cleanup(&path);
}

#[test]
fn a_rev_mismatch_is_a_409_and_writes_nothing() {
    let path = scratch("m-rev", SAMPLE);
    let cfg = cfg_for(&path, "");
    let before = read(&path);
    let got = post(
        &cfg,
        Route::UserAdd,
        &[
            (
                "rev",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            ("email", "new@x.com"),
        ],
    );
    let (status, html) = got.page();
    assert_eq!(status, 409);
    assert!(html.contains("The file changed"), "{html}");
    // The typed input is one Back-button press away, and the page says so.
    assert!(html.contains("Back button"), "{html}");
    assert_eq!(read(&path), before, "nothing may be written on a conflict");
    // A form with no rev at all is the same refusal, not a bypass.
    let got = post(&cfg, Route::UserAdd, &[("email", "new@x.com")]);
    assert_eq!(got.page().0, 409);
    assert_eq!(read(&path), before);
    cleanup(&path);
}

#[test]
fn a_refused_scope_add_re_renders_the_form_with_the_librarys_words() {
    let path = scratch("m-refused", SAMPLE);
    let cfg = cfg_for(&path, "");
    let before = read(&path);
    let got = post(
        &cfg,
        Route::ScopeAdd("mpa".to_string()),
        &[
            ("rev", &rev_of(&path)),
            ("name", "reports"),
            ("urls", "https://elsewhere.com/x"),
            ("access", "anonymous"),
        ],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    // Verbatim, in the English the CLI says it in.
    assert!(html.contains("refusing to write"), "{html}");
    assert!(html.contains("outside this application's base"), "{html}");
    // And the submitted values are still in the fields.
    assert!(
        html.contains("https://elsewhere.com/x</textarea>"),
        "{html}"
    );
    assert!(html.contains("value=\"reports\""), "{html}");
    assert_eq!(read(&path), before, "a refusal writes nothing");
    cleanup(&path);
}

#[test]
fn hostile_submitted_values_come_back_escaped() {
    let path = scratch("m-hostile", SAMPLE);
    let cfg = cfg_for(&path, "");
    let before = read(&path);
    let got = post(
        &cfg,
        Route::ScopeAdd("mpa".to_string()),
        &[
            ("rev", &rev_of(&path)),
            ("name", "reports"),
            ("urls", "https://app.x.com/mpa/reports/*"),
            ("access", "restricted"),
            ("members", "\"><img src=x onerror=alert(1)>"),
        ],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    assert!(!html.contains("<img src=x"), "{html}");
    assert_eq!(read(&path), before);
    cleanup(&path);
}

#[test]
fn a_hostile_email_comes_back_escaped_in_the_user_form() {
    // The local part is deliberately unrestricted (`well_formed_email` only checks the
    // domain), so a script tag ahead of an ordinary `@x.com` is accepted; this uses a
    // `>` in the domain instead, which the label check does refuse.
    let path = scratch("m-hostile-email", SAMPLE);
    let cfg = cfg_for(&path, "");
    let before = read(&path);
    let got = post(
        &cfg,
        Route::UserAdd,
        &[
            ("rev", &rev_of(&path)),
            ("email", "<script>alert(1)</script>@evil>.com"),
        ],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;@evil&gt;.com"),
        "{html}"
    );
    assert!(!html.contains("<script>alert(1)"), "{html}");
    assert_eq!(read(&path), before);
    cleanup(&path);
}

#[test]
fn minting_shows_the_bearer_once_and_files_only_its_hash() {
    let path = scratch("m-mint", SAMPLE);
    let cfg = cfg_for(&path, "");
    let stale = rev_of(&path);
    let got = post(
        &cfg,
        Route::KeyAdd(BOB.to_string()),
        &[("rev", &stale), ("id", "ci"), ("duration", "365d")],
    );
    let (status, html) = got.page();
    assert_eq!(
        status, 200,
        "a mint renders its result, it does not redirect"
    );
    // The reveal shows the key alone (§13.14), so the bearer is the text of the code
    // element and not the tail of a header line.
    let bearer = code_text(html, "bearer");
    assert!(bearer.starts_with("bbk_"), "{bearer}");
    assert!(html.contains("stored nowhere"), "{html}");

    // The file carries the hash and never the bearer.
    let on_disk = read(&path);
    assert!(on_disk.contains(&sha256_hex(&bearer)), "the hash is filed");
    assert!(!on_disk.contains(&bearer), "the raw key is never stored");
    let doc = bb_auth_core::read_access_file(&path).unwrap();
    let k = &doc.users[0].api_keys;
    assert_eq!(k.len(), 2);
    assert!(
        k[1].scopes.is_none(),
        "an empty scopes field is the field being absent"
    );

    // A re-submitted form cannot double-mint: the write moved the file, so the rev the
    // browser still holds is stale.
    let replay = post(
        &cfg,
        Route::KeyAdd(BOB.to_string()),
        &[("rev", &stale), ("id", "ci2"), ("duration", "365d")],
    );
    assert_eq!(replay.page().0, 409);
    assert_eq!(read(&path), on_disk, "the replay wrote nothing");
    cleanup(&path);
}

#[test]
fn a_reloaded_reveal_page_gets_the_mint_conflict_not_the_generic_409() {
    let path = scratch("m-mint-reload", SAMPLE);
    let cfg = cfg_for(&path, "");
    let stale = rev_of(&path);
    let fields = [("rev", stale.as_str()), ("id", "ci"), ("duration", "365d")];
    let first = post(&cfg, Route::KeyAdd("bob@x.com".to_string()), &fields);
    assert_eq!(first.page().0, 200, "the mint itself succeeds");
    let on_disk = read(&path);

    // The reveal page is the direct POST response, so reloading it re-submits these
    // exact bytes. The rev is stale — the mint's own write moved the file — and the
    // key exists, so the answer is the mint's own 409, not "someone else wrote".
    let replay = post(&cfg, Route::KeyAdd("bob@x.com".to_string()), &fields);
    let (status, html) = replay.page();
    assert_eq!(status, 409);
    assert!(html.contains("This key was already created"), "{html}");
    assert!(
        !html.contains("The file changed"),
        "the generic advice would mint a second key: {html}"
    );
    // A lost bearer's remedy is rotation, and the link is on the page.
    assert!(html.contains("/users/bob%40x.com/keys/ci/rotate"), "{html}");
    assert!(!html.contains("bbk_"), "no bearer on a replay: {html}");
    assert_eq!(read(&path), on_disk, "the replay wrote nothing");
    let doc = bb_auth_core::read_access_file(&path).unwrap();
    let ci = doc.users[0].api_keys.iter().filter(|k| k.id.trim() == "ci");
    assert_eq!(ci.count(), 1, "still exactly one key with this id");

    // A stale rev whose key does NOT exist is a genuine concurrent edit, and keeps
    // the generic page — nothing was created, redoing the change is the right advice.
    let other = post(
        &cfg,
        Route::KeyAdd("bob@x.com".to_string()),
        &[("rev", &stale), ("id", "other"), ("duration", "365d")],
    );
    let (status, html) = other.page();
    assert_eq!(status, 409);
    assert!(html.contains("The file changed"), "{html}");
    assert_eq!(read(&path), on_disk);
    cleanup(&path);
}

#[test]
fn a_malformed_email_is_refused_on_the_form_it_came_from() {
    let path = scratch("m-bademail", SAMPLE);
    let cfg = cfg_for(&path, "");
    let before = read(&path);
    let got = post(
        &cfg,
        Route::UserAdd,
        &[("rev", &rev_of(&path)), ("email", "not an email")],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    // The library's refusal, verbatim, above the field that caused it.
    assert!(
        html.contains("does not look like an email address"),
        "{html}"
    );
    assert!(
        html.contains("value=\"not an email\""),
        "the typed value is still in the field: {html}"
    );
    assert_eq!(read(&path), before, "a refusal writes nothing");

    // The same door guards denied — a malformed veto would fail open.
    let got = post(
        &cfg,
        Route::DenyAdd,
        &[("rev", &rev_of(&path)), ("email", "bob@example,com")],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    assert!(
        html.contains("does not look like an email address"),
        "{html}"
    );
    assert_eq!(read(&path), before);
    cleanup(&path);
}

#[test]
fn a_malformed_email_marks_the_email_field_invalid() {
    let path = scratch("m-bademail-attr", SAMPLE);
    let cfg = cfg_for(&path, "");
    let got = post(
        &cfg,
        Route::UserAdd,
        &[("rev", &rev_of(&path)), ("email", "not an email")],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    // The one field the refusal is about: an invalid border, and the two attributes
    // that tie it to the message above the form for assistive tech.
    assert!(
        html.contains("class=\"f-email invalid\""),
        "the email field carries the invalid state: {html}"
    );
    assert!(
        html.contains(&format!("aria-describedby=\"{ERR_ID}\"")),
        "{html}"
    );
    assert!(
        html.contains(&format!("id=\"{ERR_ID}\"")),
        "the error box carries the id aria-describedby points at: {html}"
    );
    assert_eq!(
        html.matches("aria-invalid=\"true\"").count(),
        1,
        "only the email field is marked: {html}"
    );
    cleanup(&path);
}

#[test]
fn an_unattributable_refusal_marks_no_field_invalid() {
    // An application's `base` and `login_url` are both still-unvalidated when `commit`
    // runs, so a compile failure there cannot be pinned to either one with certainty,
    // unlike a malformed email, which always names `email` (see `mutate`'s
    // `Route::UserAdd` arm). A confidently wrong field is worse than none, so this
    // refusal marks nothing.
    let path = scratch("m-unattributed", SAMPLE);
    let cfg = cfg_for(&path, "");
    let got = post(
        &cfg,
        Route::AppAdd,
        &[
            ("rev", &rev_of(&path)),
            ("name", "app1"),
            ("base", "https://app.x.com/app1"),
            ("login_url", "http://login.x.com/"),
        ],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    assert!(html.contains("must be an absolute https"), "{html}");
    assert!(!html.contains("aria-invalid=\"true\""), "{html}");
    assert!(
        !html.contains(&format!("aria-describedby=\"{ERR_ID}\"")),
        "{html}"
    );
    assert!(!html.contains("class=\"invalid\""), "{html}");
    assert!(!html.contains(" invalid\""), "{html}");
    cleanup(&path);
}

#[test]
fn a_key_scopes_field_collapses_empty_to_inherit() {
    let path = scratch("m-keyscope", SAMPLE);
    let cfg = cfg_for(&path, "");
    let key = || Route::KeyEdit(BOB.to_string(), "laptop".to_string());
    let scopes = || {
        bb_auth_core::read_access_file(&path).unwrap().users[0].api_keys[0]
            .scopes
            .clone()
    };
    assert_eq!(scopes(), None, "the sample key inherits");

    let got = post(
        &cfg,
        key(),
        &[
            ("rev", &rev_of(&path)),
            ("duration", "1d"),
            ("scopes", "mpa/admin"),
        ],
    );
    assert_eq!(got.location(), format!("/users/{BOB}?msg=key-saved"));
    assert_eq!(scopes(), Some(vec!["mpa/admin".to_string()]));

    // And back: an empty textarea collapses to absent, "everything the owner reaches".
    let got = post(
        &cfg,
        key(),
        &[
            ("rev", &rev_of(&path)),
            ("duration", "1d"),
            ("scopes", "   \n  "),
        ],
    );
    assert_eq!(got.location(), format!("/users/{BOB}?msg=key-saved"));
    assert_eq!(scopes(), None, "an emptied textarea collapses to inherit");
    cleanup(&path);
}

#[test]
fn a_bad_key_window_is_refused_before_anything_is_minted() {
    let path = scratch("m-window", SAMPLE);
    let cfg = cfg_for(&path, "");
    let before = read(&path);
    let got = post(
        &cfg,
        Route::KeyAdd(BOB.to_string()),
        &[
            ("rev", &rev_of(&path)),
            ("id", "ci"),
            ("duration", "forever"),
        ],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    assert!(html.contains("not a valid window"), "{html}");
    assert!(!html.contains("bbk_"), "no secret is handed out: {html}");
    assert_eq!(read(&path), before);
    // The same for a key with no id.
    let got = post(
        &cfg,
        Route::KeyAdd(BOB.to_string()),
        &[("rev", &rev_of(&path)), ("id", "  "), ("duration", "365d")],
    );
    assert!(got.page().1.contains("a key needs an id"));
    assert_eq!(read(&path), before);
    cleanup(&path);
}

#[test]
fn removing_a_referenced_group_is_refused_with_its_referrers() {
    let path = scratch("m-grouprm", SAMPLE);
    let cfg = cfg_for(&path, "");
    let before = read(&path);
    let got = post(
        &cfg,
        Route::GroupRm("admins".to_string()),
        &[("rev", &rev_of(&path))],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    assert!(html.contains("is still referenced by"), "{html}");
    assert!(html.contains("mpa/admin"), "the referrer is named: {html}");
    assert_eq!(read(&path), before);

    // The unreferenced one goes.
    let got = post(
        &cfg,
        Route::GroupRm("unused".to_string()),
        &[("rev", &rev_of(&path))],
    );
    // Back to the groups page: §13.36 §1's PRG table puts a group removal's `303` at
    // `/groups`, because that is the page that shows the list the form just changed.
    assert_eq!(got.location(), "/groups?msg=group-removed");
    let doc = bb_auth_core::read_access_file(&path).unwrap();
    assert!(!doc.user_groups.contains_key("unused"));
    assert!(doc.user_groups.contains_key("admins"));
    cleanup(&path);
}

#[test]
fn a_scope_is_edited_and_reordered_by_its_buttons() {
    let path = scratch("m-scopes", TWO_SCOPES);
    let cfg = cfg_for(&path, "");
    let names = || {
        bb_auth_core::read_access_file(&path).unwrap().applications[0]
            .scopes
            .iter()
            .map(|s| s.name.clone())
            .collect::<Vec<_>>()
    };

    // Editing replaces the record wholesale: urls, access, members and credentials.
    let got = post(
        &cfg,
        Route::ScopeEdit("app1".to_string(), "second".to_string()),
        &[
            ("rev", &rev_of(&path)),
            ("name", "second"),
            ("urls", "https://app.x.com/b\nhttps://app.x.com/b/*"),
            ("access", "restricted"),
            ("members", "bob@x.com"),
            ("cred_login", "on"),
            ("notes", "the vip area"),
        ],
    );
    assert_eq!(got.location(), "/apps/app1?msg=scope-saved");
    let doc = bb_auth_core::read_access_file(&path).unwrap();
    let second = &doc.applications[0].scopes[1];
    assert_eq!(second.urls.len(), 2);
    assert_eq!(second.access, "restricted");
    assert_eq!(second.users.as_deref(), Some(&[BOB.to_string()][..]));
    assert_eq!(
        second.credentials.as_deref(),
        Some(&["login".to_string()][..])
    );
    assert_eq!(second.notes.as_deref(), Some("the vip area"));

    // An access of "anonymous" with no members/credentials sent is not a stray field:
    // there is nothing to send, since this form never sends those fields blank-vs-set.
    let got = post(
        &cfg,
        Route::ScopeEdit("app1".to_string(), "second".to_string()),
        &[
            ("rev", &rev_of(&path)),
            ("name", "second"),
            ("urls", "https://app.x.com/b/*"),
            ("access", "anonymous"),
        ],
    );
    assert_eq!(got.location(), "/apps/app1?msg=scope-saved");
    let doc = bb_auth_core::read_access_file(&path).unwrap();
    assert_eq!(doc.applications[0].scopes[1].access, "anonymous");
    assert!(doc.applications[0].scopes[1].users.is_none());

    // Order is meaning, so a move is a mutation like any other.
    assert_eq!(names(), ["first", "second"]);
    let got = post(
        &cfg,
        Route::ScopeMove("app1".to_string(), "second".to_string()),
        &[("rev", &rev_of(&path)), ("dir", "up")],
    );
    assert_eq!(got.location(), "/apps/app1?msg=scope-moved");
    assert_eq!(names(), ["second", "first"]);
    // And a move off the end changes nothing rather than erroring.
    let before = read(&path);
    post(
        &cfg,
        Route::ScopeMove("app1".to_string(), "second".to_string()),
        &[("rev", &rev_of(&path)), ("dir", "up")],
    );
    assert_eq!(read(&path), before);
    cleanup(&path);
}

#[test]
fn a_scope_form_writes_and_refuses_exclusions() {
    let path = scratch("m-excl", TWO_SCOPES);
    let cfg = cfg_for(&path, "");

    // An enrolled person becomes their uuid; a stranger stays their email, which is
    // the only exclusion an `authenticated` scope can have.
    let got = post(
        &cfg,
        Route::ScopeEdit("app1".to_string(), "second".to_string()),
        &[
            ("rev", &rev_of(&path)),
            ("name", "second"),
            ("urls", "https://app.x.com/b/*"),
            ("access", "authenticated"),
            ("excluded", "bob@x.com\nstranger@x.com"),
        ],
    );
    assert_eq!(got.location(), "/apps/app1?msg=scope-saved");
    let doc = bb_auth_core::read_access_file(&path).unwrap();
    assert_eq!(
        doc.applications[0].scopes[1].excluded.as_deref(),
        Some(&[BOB.to_string(), "stranger@x.com".to_string()][..])
    );

    // And the form refuses the one kind that cannot mean anything, out loud, with the
    // field named so it renders invalid.
    let before = read(&path);
    let got = post(
        &cfg,
        Route::ScopeEdit("app1".to_string(), "second".to_string()),
        &[
            ("rev", &rev_of(&path)),
            ("name", "second"),
            ("urls", "https://app.x.com/b/*"),
            ("access", "anonymous"),
            ("excluded", "bob@x.com"),
        ],
    );
    let (status, html) = got.page();
    assert_eq!(status, 400);
    assert!(html.contains("no credential at all"), "{html}");
    assert_eq!(read(&path), before);
    cleanup(&path);
}

#[test]
fn a_denied_email_is_added_once_and_lifted() {
    let path = scratch("m-deny", TWO_SCOPES);
    let cfg = cfg_for(&path, "");
    let got = post(
        &cfg,
        Route::DenyAdd,
        &[("rev", &rev_of(&path)), ("email", " Bob@X.com ")],
    );
    assert_eq!(got.location(), "/denied?msg=denied-added");
    // An enrolled user is written down by uuid, so the veto covers every email they hold.
    assert_eq!(bb_auth_core::read_access_file(&path).unwrap().denied, [BOB]);
    // Twice is a refusal, not a second row.
    let got = post(
        &cfg,
        Route::DenyAdd,
        &[("rev", &rev_of(&path)), ("email", "bob@x.com")],
    );
    assert!(got.page().1.contains("already on denied"));
    // And the veto lifts.
    let got = post(
        &cfg,
        Route::DenyRm("bob@x.com".to_string()),
        &[("rev", &rev_of(&path))],
    );
    assert_eq!(got.location(), "/denied?msg=denied-removed");
    assert!(bb_auth_core::read_access_file(&path)
        .unwrap()
        .denied
        .is_empty());
    cleanup(&path);
}

#[test]
fn a_page_route_does_not_take_a_post() {
    let path = scratch("m-405", SAMPLE);
    let cfg = cfg_for(&path, "");
    let before = read(&path);
    let got = post(&cfg, Route::Users, &[("rev", &rev_of(&path))]);
    assert_eq!(got.page().0, 405);
    assert_eq!(read(&path), before);
    cleanup(&path);
}

#[test]
fn a_user_edit_route_has_nothing_to_post_and_falls_to_405() {
    // There is nothing left on a `UserSpec` for a standalone edit to change: the uuid
    // is fixed, and emails and keys manage themselves on their own routes.
    let path = scratch("m-useredit", SAMPLE);
    let cfg = cfg_for(&path, "");
    let before = read(&path);
    let got = post(
        &cfg,
        Route::UserEdit(BOB.to_string()),
        &[("rev", &rev_of(&path))],
    );
    assert_eq!(got.page().0, 405);
    assert_eq!(read(&path), before);
    cleanup(&path);
}

#[test]
fn an_email_is_added_and_removed() {
    let path = scratch("m-email", SAMPLE);
    let cfg = cfg_for(&path, "");
    let got = post(
        &cfg,
        Route::EmailAdd(BOB.to_string()),
        &[("rev", &rev_of(&path)), ("email", " Second@X.com ")],
    );
    assert_eq!(got.location(), format!("/users/{BOB}?msg=user-saved"));
    let doc = bb_auth_core::read_access_file(&path).unwrap();
    // The original email round-trips exactly as the file had it (case untouched); only
    // the freshly submitted one is normalised on the way in.
    assert_eq!(doc.users[0].emails, ["Bob@X.com", "second@x.com"]);

    let got = post(
        &cfg,
        Route::EmailRm(BOB.to_string(), "second@x.com".to_string()),
        &[("rev", &rev_of(&path))],
    );
    assert_eq!(got.location(), format!("/users/{BOB}?msg=user-saved"));
    let doc = bb_auth_core::read_access_file(&path).unwrap();
    assert_eq!(doc.users[0].emails, ["Bob@X.com"]);

    // The last email is refused: a row nobody can sign in as is not a retirement, it
    // is a dead end.
    let got = post(
        &cfg,
        Route::EmailRm(BOB.to_string(), "bob@x.com".to_string()),
        &[("rev", &rev_of(&path))],
    );
    assert!(got.page().1.contains("only email"));
    cleanup(&path);
}

#[test]
fn a_mutation_under_a_base_path_redirects_under_it() {
    let path = scratch("m-base", SAMPLE);
    let cfg = cfg_for(&path, "/admin");
    let got = post(
        &cfg,
        Route::UserAdd,
        &[("rev", &rev_of(&path)), ("email", "new@x.com")],
    );
    let doc = bb_auth_core::read_access_file(&path).unwrap();
    let uuid = &doc
        .users
        .iter()
        .find(|u| u.emails.iter().any(|e| e == "new@x.com"))
        .unwrap()
        .uuid;
    assert_eq!(
        got.location(),
        format!("/admin/users/{uuid}?msg=user-added")
    );
    cleanup(&path);
}

#[test]
fn a_known_msg_key_renders_and_an_unknown_one_is_dropped() {
    assert_eq!(Msg::parse("user-added"), Some(Msg::UserAdded));
    assert_eq!(Msg::parse("scope-moved"), Some(Msg::ScopeMoved));
    assert_eq!(Msg::parse("<script>"), None);
    assert_eq!(Msg::parse(""), None);
    assert_eq!(Msg::UserRemoved.text(Lang::It), "utente rimosso");
    // Every key round-trips, so a redirect can never name a banner that does not exist.
    for m in [
        Msg::UserAdded,
        Msg::KeySaved,
        Msg::AppAdded,
        Msg::ScopeAdded,
        Msg::GroupRemoved,
        Msg::DeniedAdded,
    ] {
        assert_eq!(Msg::parse(m.key()), Some(m));
    }
}
