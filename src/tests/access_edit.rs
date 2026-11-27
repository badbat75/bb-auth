use super::*;

// --- editing the document -----------------------------------------------

#[test]
fn removing_a_user_rewrites_the_exclusions_that_named_them_to_their_email() {
    let mut doc = doc_of(&with_exclusion(
        "https://app.x.com/mpa/*",
        &format!("\"{BOB}\""),
    ));
    let refs = user_refs(&doc, BOB);
    assert!(
        refs.iter().any(|r| r == "mpa/onboarding (excluded)"),
        "an exclusion is a reference, and marked as one: {refs:?}"
    );
    let (_, swept) = remove_user(&mut doc, "bob@x.com").unwrap();
    assert!(swept.iter().any(|r| r.contains("excluded")), "{swept:?}");
    // The exclusion is a veto, so dropping it would lift it: it becomes the primary
    // email, the spelling an exclusion uses for an identity the roster does not know.
    assert_eq!(
        doc.applications[0].scopes[2].excluded.as_deref(),
        Some(&["bob@x.com".to_string()][..])
    );
    // The file that comes out compiles, and keeps the person out as a stranger.
    let w = AccessWrite::prepare(&doc).unwrap();
    assert_eq!(
        decide(
            w.access(),
            &Subject::Identifier("bob@x.com"),
            Some("https://app.x.com/mpa/anything")
        ),
        Decision::Excluded {
            app: "mpa".into(),
            scope: "onboarding".into()
        }
    );
}

#[test]
fn removing_a_user_with_no_email_leaves_nothing_behind_in_excluded() {
    let mut doc = doc_of(&with_exclusion(
        "https://app.x.com/mpa/*",
        &format!("\"{BOB}\""),
    ));
    doc.users[0].emails.clear();
    remove_user(&mut doc, BOB).unwrap();
    let left = doc.applications[0].scopes[2].excluded.clone();
    assert!(
        left.iter()
            .flatten()
            .all(|e| e.trim().is_empty() || norm_email(e) != BOB),
        "{left:?}"
    );
    assert!(
        left.iter().flatten().all(|e| !e.trim().is_empty()),
        "no blank entry either: {left:?}"
    );
}

#[test]
fn a_uuid_excluded_in_several_scopes_is_rewritten_in_each() {
    let mut doc = doc_of(&with_exclusion(
        "https://app.x.com/mpa/*",
        &format!("\"{BOB}\""),
    ));
    doc.applications[1].scopes[0].excluded = Some(vec![BOB.to_string()]);
    doc.applications[0].scopes[1].excluded = Some(vec![BOB.to_string()]);
    remove_user(&mut doc, "bob@x.com").unwrap();
    for (a, s) in [(0, 1), (0, 2), (1, 0)] {
        assert_eq!(
            doc.applications[a].scopes[s].excluded.as_deref(),
            Some(&["bob@x.com".to_string()][..]),
            "scope {a}/{s}"
        );
    }
    AccessWrite::prepare(&doc).unwrap();
}

#[test]
fn an_exclusion_through_a_group_stays_a_group_reference() {
    let mut doc = doc_of(&with_exclusion("https://app.x.com/mpa/*", "\"@admins\""));
    remove_user(&mut doc, "bob@x.com").unwrap();
    // The group is swept as it always was, and the scope still names the group: the
    // rewrite is for uuids only, so no email is added behind the group's back.
    assert!(doc.user_groups["admins"]
        .iter()
        .all(|m| norm_email(m) != BOB));
    assert_eq!(
        doc.applications[0].scopes[2].excluded.as_deref(),
        Some(&["@admins".to_string()][..])
    );
    AccessWrite::prepare(&doc).unwrap();
}

#[test]
fn a_group_only_an_exclusion_names_still_cannot_be_removed() {
    // `compile_access` refuses an unknown group in `excluded` too, so removing this one
    // would produce a file the gate rejects. The refusal names where to go and fix it.
    let mut doc = doc_of(&fixture().replace(
        r#"{ "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
                  "access": "authenticated" }"#,
        r#"{ "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
                  "access": "authenticated", "excluded": ["@admins"] }"#,
    ));
    // The membership reference goes first, so only the exclusion is left holding it.
    doc.applications[0].scopes[1].groups = None;
    doc.applications[0].scopes[1].users = Some(vec![BOB.to_string()]);
    let e = err_of(remove_user_group(&mut doc, "admins"));
    assert!(e.contains("still referenced by"), "{e}");
    assert!(e.contains("mpa/onboarding (excluded)"), "{e}");
}

#[test]
fn add_user_mints_a_uuid_and_refuses_a_taken_email() {
    let mut doc = doc_of(&fixture());
    add_user(
        &mut doc,
        UserSpec {
            emails: vec!["dave@x.com".into()],
            ..Default::default()
        },
    )
    .unwrap();
    let dave = &doc.users[2];
    assert!(well_formed_uuid(&dave.uuid));

    let e = err_of(add_user(
        &mut doc,
        UserSpec {
            emails: vec!["BOB@x.com".into()],
            ..Default::default()
        },
    ));
    assert!(e.contains("already belongs to another user"), "{e}");
}

#[test]
fn add_user_refuses_a_value_that_could_never_be_an_email() {
    let mut doc = doc_of(&fixture());
    let e = err_of(add_user(
        &mut doc,
        UserSpec {
            emails: vec!["not an email".into()],
            ..Default::default()
        },
    ));
    assert!(e.contains("does not look like an email"), "{e}");
}

#[test]
fn a_user_is_found_by_uuid_or_by_any_of_their_emails() {
    let doc = doc_of(&fixture());
    assert_eq!(user_pos(&doc, BOB), Some(0));
    assert_eq!(user_pos(&doc, "bob@old.com"), Some(0));
    assert_eq!(user_pos(&doc, "carol@x.com"), Some(1));
    assert_eq!(user_pos(&doc, "nobody@x.com"), None);
}

#[test]
fn identifiers_are_added_and_dropped_but_never_all_of_them() {
    let mut doc = doc_of(&fixture());
    assert!(add_user_email(&mut doc, BOB, "bob@new.com").unwrap());
    assert!(
        !add_user_email(&mut doc, BOB, "BOB@NEW.COM").unwrap(),
        "idempotent"
    );
    let e = err_of(add_user_email(&mut doc, CAROL, "bob@new.com"));
    assert!(e.contains("already belongs"), "{e}");

    assert!(remove_user_email(&mut doc, BOB, "bob@new.com").unwrap());
    let e = err_of(remove_user_email(&mut doc, CAROL, "carol@x.com"));
    assert!(e.contains("only email"), "{e}");
}

#[test]
fn remove_user_sweeps_every_reference_to_them() {
    let mut doc = doc_of(&fixture());
    let (gone, swept) = remove_user(&mut doc, "bob@x.com").unwrap();
    assert_eq!(gone.uuid, BOB);
    assert!(swept.contains(&"mcp/logs".to_string()), "{swept:?}");
    assert!(swept.contains(&"@admins".to_string()), "{swept:?}");
    // And the file that comes out has no dangling reference left in it.
    assert!(user_refs(&doc, BOB).is_empty());
    let rendered = render_access_file(&doc).unwrap();
    assert!(!rendered.contains(BOB), "{rendered}");
}

#[test]
fn renaming_an_application_repoints_the_keys_that_named_it() {
    let mut doc = doc_of(&fixture());
    rename_application(&mut doc, "mcp", "gateway").unwrap();
    assert_eq!(
        doc.users[0].api_keys[0].scopes.as_deref(),
        Some(&["gateway/api".to_string()][..])
    );
    // And the result still compiles, which is what the re-pointing is for.
    AccessWrite::prepare(&doc).unwrap();
}

#[test]
fn renaming_a_scope_repoints_the_keys_that_named_it() {
    let mut doc = doc_of(&fixture());
    rename_scope(&mut doc, "mcp", "api", "tools").unwrap();
    assert_eq!(
        doc.users[0].api_keys[0].scopes.as_deref(),
        Some(&["mcp/tools".to_string()][..])
    );
    AccessWrite::prepare(&doc).unwrap();
}

#[test]
fn moving_a_scope_changes_who_answers_without_changing_a_field() {
    let mut doc = doc_of(&fixture());
    move_scope(&mut doc, "mcp", 0, 1).unwrap();
    let a = AccessWrite::prepare(&doc).unwrap();
    let (_, s) = a
        .access()
        .resolve(Some("https://ai.x.com/mcp/logs/x"))
        .unwrap();
    assert_eq!(s.name, "api", "the broad scope now answers first");
}

#[test]
fn scope_and_application_names_must_be_free() {
    let mut doc = doc_of(&fixture());
    let e = err_of(add_application(
        &mut doc,
        AppSpec {
            name: "mpa".into(),
            ..Default::default()
        },
    ));
    assert!(e.contains("already exists"), "{e}");
    let e = err_of(add_scope(
        &mut doc,
        "mpa",
        ScopeSpec {
            name: "admin".into(),
            ..Default::default()
        },
        None,
    ));
    assert!(e.contains("already exists"), "{e}");
}

#[test]
fn a_group_cannot_be_removed_while_a_scope_names_it() {
    let mut doc = doc_of(&fixture());
    let e = err_of(remove_user_group(&mut doc, "admins"));
    assert!(e.contains("mpa/admin"), "{e}");
    // Drop the reference and it goes.
    doc.applications[0].scopes[1].groups = None;
    assert_eq!(remove_user_group(&mut doc, "admins").unwrap(), vec![BOB]);
}

#[test]
fn denying_an_enrolled_user_writes_their_uuid() {
    let mut doc = doc_of(&fixture());
    assert!(add_denied(&mut doc, "bob@old.com").unwrap());
    assert!(doc.denied.contains(&BOB.to_string()), "{:?}", doc.denied);
    assert!(
        !add_denied(&mut doc, BOB).unwrap(),
        "already vetoed, by either name"
    );
    assert_eq!(remove_denied(&mut doc, &["bob@x.com".to_string()]), 1);
}

#[test]
fn denying_a_stranger_keeps_the_email() {
    let mut doc = doc_of(&fixture());
    assert!(add_denied(&mut doc, "Nuisance@X.com").unwrap());
    assert!(doc.denied.contains(&"nuisance@x.com".to_string()));
    let e = err_of(add_denied(&mut doc, "not an email"));
    assert!(e.contains("does not look like an email"), "{e}");
}

// --- the write order ----------------------------------------------------

#[test]
fn access_write_refuses_a_document_the_gate_would_reject() {
    let mut doc = doc_of(&fixture());
    doc.applications[0].scopes[0].access = "anonimous".into();
    let e = err_of(AccessWrite::prepare(&doc));
    assert!(e.contains("refusing to write"), "{e}");
}

#[test]
fn access_write_commits_exactly_the_bytes_it_compiled() {
    let path = users_tmp("commit", &fixture());
    let mut doc = doc_of(&fixture());
    add_user(
        &mut doc,
        UserSpec {
            emails: vec!["dave@x.com".into()],
            ..Default::default()
        },
    )
    .unwrap();
    let w = AccessWrite::prepare(&doc).unwrap();
    let expected = w.json().to_string();
    let receipt = w.commit(path.to_str().unwrap()).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
    assert!(receipt.backup.exists());
    let _ = std::fs::remove_file(&receipt.backup);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn open_access_file_refuses_a_file_the_gate_would_reject() {
    let path = users_tmp("open-bad", r#"{ "version": 1, "denied": ["nope"] }"#);
    let e = err_of(open_access_file(path.to_str().unwrap()));
    assert!(e.contains("the gate would reject this file"), "{e}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn add_api_key_seals_the_bearer_until_the_file_carries_its_hash() {
    let path = users_tmp("seal", &fixture());
    let mut doc = doc_of(&fixture());
    let sealed = add_api_key(
        &mut doc,
        "carol@x.com",
        ApiKeySpec {
            id: "ci".into(),
            released: "2026-08-17".into(),
            duration: "30d".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let w = AccessWrite::prepare(&doc).unwrap();
    let receipt = w.commit(path.to_str().unwrap()).unwrap();
    // The receipt is what unseals it: a dry run has no bearer to leak.
    let bearer = sealed.reveal(&receipt);
    assert!(bearer.starts_with(API_KEY_PREFIX));
    let a = read_access(path.to_str().unwrap()).unwrap();
    assert!(a.by_key_hash.contains_key(&sha256_hex(&bearer)));
    let _ = std::fs::remove_file(&receipt.backup);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn add_api_key_refuses_a_duplicate_id() {
    let mut doc = doc_of(&fixture());
    let e = err_of(add_api_key(
        &mut doc,
        BOB,
        ApiKeySpec {
            id: "laptop".into(),
            ..Default::default()
        },
    ));
    assert!(e.contains("already has a key 'laptop'"), "{e}");
}

#[test]
fn rotate_api_key_replaces_the_hash_and_redates_the_row() {
    let mut doc = doc_of(&fixture());
    let before = doc.users[0].api_keys[0].key_hash.clone();
    let _sealed = rotate_api_key(&mut doc, "bob@x.com", "laptop").unwrap();
    assert_ne!(doc.users[0].api_keys[0].key_hash, before);
    assert_eq!(doc.users[0].api_keys[0].released, format_date(now()));
}

#[test]
fn scopes_for_lists_where_a_user_is_named() {
    let a = access_of("scopes-for", &fixture());
    let mine: Vec<String> = a
        .scopes_for(BOB)
        .iter()
        .map(|(app, s)| format!("{}/{}", app.name, s.name))
        .collect();
    assert_eq!(mine, vec!["mpa/admin", "mcp/logs", "mcp/api"]);
    assert!(a.scopes_for(CAROL).is_empty());
}

#[test]
fn any_authenticated_scope_is_what_session_asks() {
    let a = access_of("any-authn", &fixture());
    assert!(a.any_authenticated_scope());
    let b = access_of(
        "no-authn",
        r#"{ "version": 1, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"],
                     "access": "restricted" } ] } ] }"#,
    );
    assert!(!b.any_authenticated_scope());
}

// --- what an identity reaches -------------------------------------------

/// The pairs as `app/scope` strings, in the order the function returns them, so each
/// assertion below reads as the list the user page will show and pins file order too.
fn reached(a: &Access, identifier: &str) -> Vec<String> {
    a.scopes_reached(identifier)
        .iter()
        .map(|(app, s)| format!("{}/{}", app.name, s.name))
        .collect()
}

/// One URL per non-anonymous scope of the fixture, chosen so that **that** scope answers
/// it: scopes are first match wins, so `mpa/onboarding` answers `/mpa/welcome` and never
/// `/mpa/admin/panel`, and `mcp/api` answers `/mcp/other` and never `/mcp/logs/today`.
/// The agreement test checks this table against `resolve` before trusting it.
const PROBES: &[(&str, &str)] = &[
    ("mpa/admin", "https://app.x.com/mpa/admin/panel"),
    ("mpa/onboarding", "https://app.x.com/mpa/welcome"),
    ("mcp/logs", "https://ai.x.com/mcp/logs/today"),
    ("mcp/api", "https://ai.x.com/mcp/other"),
];

/// The set is the page's promise about a signed-in person, so every kind has to be right
/// in it: bob reaches mpa/admin only through `@admins`, mcp/logs directly, and
/// mpa/onboarding because that grant admits any signed-in identity. mpa/healthz is
/// anonymous, so it says nothing about him, and mcp/api's credentials admit a key and
/// refuse a login, so a browser never reaches it.
#[test]
fn scopes_reached_lists_a_roster_user_in_file_order() {
    let a = access_of("reached-bob", &fixture());
    assert_eq!(
        reached(&a, "bob@x.com"),
        vec!["mpa/admin", "mpa/onboarding", "mcp/logs"]
    );
}

/// The identifier is an email and the answer comes from the roster row, so an old
/// address, or the same address in another case, must not show a shorter list than the
/// one the person signs in with.
#[test]
fn scopes_reached_answers_the_same_for_every_email_of_a_user() {
    let a = access_of("reached-emails", &fixture());
    assert_eq!(reached(&a, "BOB@old.com"), reached(&a, "bob@x.com"));
    assert_eq!(
        reached(&a, " BOB@OLD.COM "),
        vec!["mpa/admin", "mpa/onboarding", "mcp/logs"]
    );
}

/// A stranger has no uuid, so no restricted scope can name them, and `authenticated`
/// exists precisely to admit a signed-in identity the file has never heard of. This is
/// why the function takes an email and not a uuid.
#[test]
fn scopes_reached_gives_a_stranger_only_the_authenticated_scope() {
    let a = access_of("reached-stranger", &fixture());
    assert_eq!(
        reached(&a, "stranger@elsewhere.com"),
        vec!["mpa/onboarding"]
    );
}

/// carol is in the roster and named by no scope: a `restricted` scope reads membership,
/// not enrolment, so being a user buys a person no access on its own.
#[test]
fn scopes_reached_gives_an_enrolled_non_member_only_the_authenticated_scope() {
    let a = access_of("reached-carol", &fixture());
    assert_eq!(reached(&a, "carol@x.com"), vec!["mpa/onboarding"]);
}

/// `denied` outranks every grant, so a vetoed identity is shown no list at all: the page
/// that would show it is a 403. This one asserts absence, so it is green against the
/// stub and must be rerun once the code exists.
#[test]
fn scopes_reached_is_empty_for_an_identity_the_file_denies() {
    let a = access_of("reached-denied", &fixture());
    assert!(a.vetoes_identifier("spammer@x.com"));
    assert!(reached(&a, "spammer@x.com").is_empty());
}

/// The scope's own veto is local, unlike `denied`: bob is kept out of mpa/admin without
/// unpicking `@admins`, so the rest of his list stands.
#[test]
fn scopes_reached_drops_a_scope_that_excludes_the_identity_by_uuid() {
    let a = access_of(
        "reached-excl-uuid",
        &with_exclusion("https://app.x.com/mpa/admin/*", &format!("\"{BOB}\"")),
    );
    assert_eq!(reached(&a, "bob@x.com"), vec!["mpa/onboarding", "mcp/logs"]);
}

/// An `authenticated` scope lists nobody, so an email is the only way to keep a stranger
/// out of one, and in this fixture it is the only scope they reached at all. This one
/// asserts absence, so it is green against the stub and must be rerun once the code
/// exists.
#[test]
fn scopes_reached_is_empty_for_a_stranger_excluded_from_the_only_scope() {
    let a = access_of(
        "reached-excl-stranger",
        &with_exclusion("https://app.x.com/mpa/*", "\"stranger@elsewhere.com\""),
    );
    assert!(reached(&a, "stranger@elsewhere.com").is_empty());
}

/// The page's list and the gate's answer are the same rule written twice, and two copies
/// of a grant rule drift. So for every identifier, every non-anonymous scope of the
/// fixture must be listed exactly when `decide` grants on a URL that scope itself
/// answers: the whole set, both directions, on one fixture.
#[test]
fn scopes_reached_agrees_with_decide_on_every_scope() {
    let a = access_of("reached-agree", &fixture());

    // The probe table is the whole file: a scope added to the fixture has to be probed.
    let probed: Vec<String> = PROBES.iter().map(|(name, _)| name.to_string()).collect();
    let non_anonymous: Vec<String> = a
        .apps
        .iter()
        .flat_map(|app| {
            app.scopes
                .iter()
                .filter(|s| s.access != AccessKind::Anonymous)
                .map(|s| format!("{}/{}", app.name, s.name))
        })
        .collect();
    assert_eq!(
        probed, non_anonymous,
        "the probe table must cover every non-anonymous scope"
    );

    for id in [
        "bob@x.com",
        "BOB@old.com",
        "carol@x.com",
        "stranger@elsewhere.com",
        "spammer@x.com",
    ] {
        let listed = reached(&a, id);
        for (name, url) in PROBES {
            let (app, scope) = a.resolve(Some(url)).expect("every probe url resolves");
            assert_eq!(
                (app.name.as_str(), scope.name.as_str()),
                name.split_once('/').unwrap(),
                "{url} must be answered by {name}, not by a scope that shadows it"
            );
            let granted = decide(&a, &Subject::Identifier(id), Some(url)).granted();
            let shows = listed.iter().any(|s| s == name);
            assert_eq!(
                granted, shows,
                "{id} at {url}: decide granted {granted}, scopes_reached listed {shows} \
                     (list: {listed:?})"
            );
        }
    }
}

// --- what a key reaches -------------------------------------------------

const DAVE: &str = "33333333-3333-4333-8333-333333333333";
const NOBODY: &str = "99999999-9999-4999-8999-999999999999";
const BOB_BEARER: &str = "bbk_keytestbob000000000000000000000";
const CAROL_BEARER: &str = "bbk_keytestcarol00000000000000000000";
const DAVE_BEARER: &str = "bbk_keytestdave00000000000000000000";

/// The estate of [`fixture`] arranged for the key rule, so every arm that rule has is in
/// one file: bob's key carries **no** `scopes` restriction, which is the spelling the
/// binding rule is stated for ("at most what the owner reaches"), so nothing has
/// subtracted from the answer. `mpa/reports` names bob directly and spells out both
/// credential classes; `mpa/admin` admits a login only, so a key is refused there even
/// though `@admins` names him; `mcp/logs` names bob and excludes him by uuid; `mcp/keys`
/// reaches him through `@machines`; `mcp/other` is carol's alone and leaves `credentials`
/// unset, which means both classes; `mcp/api` names bob and dave and admits a key only.
/// dave is `denied` by uuid, and `mpa/reports` sits first in the file so the expected
/// order is the reverse of the alphabetical one.
fn key_fixture() -> String {
    r#"{
          "version": 1,
          "applications": [
            { "name": "mpa",
              "base": ["https://app.x.com/mpa"],
              "scopes": [
                { "name": "reports", "urls": ["https://app.x.com/mpa/reports/*"],
                  "access": "restricted", "users": ["BOBUUID"],
                  "credentials": ["login", "api_key"] },
                { "name": "healthz", "urls": ["https://app.x.com/mpa/healthz"],
                  "access": "anonymous" },
                { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"],
                  "access": "restricted", "groups": ["@admins"],
                  "credentials": ["login"] },
                { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
                  "access": "authenticated" } ] },
            { "name": "mcp",
              "base": ["https://ai.x.com/mcp"],
              "scopes": [
                { "name": "logs", "urls": ["https://ai.x.com/mcp/logs/*"],
                  "access": "restricted", "users": ["BOBUUID"],
                  "excluded": ["BOBUUID"] },
                { "name": "keys", "urls": ["https://ai.x.com/mcp/keys/*"],
                  "access": "restricted", "groups": ["@machines"],
                  "credentials": ["login", "api_key"] },
                { "name": "other", "urls": ["https://ai.x.com/mcp/other/*"],
                  "access": "restricted", "users": ["CAROLUUID"] },
                { "name": "api", "urls": ["https://ai.x.com/mcp/*"],
                  "access": "restricted", "users": ["BOBUUID", "DAVEUUID"],
                  "credentials": ["api_key"] } ] } ],
          "user_groups": { "admins": ["BOBUUID"], "machines": ["BOBUUID", "DAVEUUID"] },
          "denied": ["spammer@x.com", "DAVEUUID"],
          "users": [
            { "uuid": "BOBUUID", "emails": ["bob@x.com"],
              "api_keys": [ { "id": "laptop", "key_hash": "BOBHASH",
                              "released": "2026-01-01", "duration": "never" } ] },
            { "uuid": "CAROLUUID", "emails": ["carol@x.com"],
              "api_keys": [ { "id": "desk", "key_hash": "CAROLHASH",
                              "released": "2026-01-01", "duration": "never" } ] },
            { "uuid": "DAVEUUID", "emails": ["dave@x.com"],
              "api_keys": [ { "id": "old", "key_hash": "DAVEHASH",
                              "released": "2026-01-01", "duration": "never" } ] } ] }"#
        .replace("BOBUUID", BOB)
        .replace("CAROLUUID", CAROL)
        .replace("DAVEUUID", DAVE)
        .replace("BOBHASH", &sha256_hex(BOB_BEARER))
        .replace("CAROLHASH", &sha256_hex(CAROL_BEARER))
        .replace("DAVEHASH", &sha256_hex(DAVE_BEARER))
}

/// The pairs as `app/scope` strings, in the order the function returns them, so each
/// assertion below reads as the list the key form will show and pins file order too.
fn key_scopes(a: &Access, uuid: &str) -> Vec<String> {
    a.key_scopes_for(uuid)
        .iter()
        .map(|(app, s)| format!("{}/{}", app.name, s.name))
        .collect()
}

/// The key, resolved the way the gate resolves a bearer: by its hash, through
/// [`decide_api_key`]. A denied owner's key does not get through that door, so the test
/// that needs one takes the record from [`Access::by_key_hash`] instead.
fn owner_key<'a>(a: &'a Access, bearer: &str) -> &'a ApiKeyRecord {
    match decide_api_key(a, &sha256_hex(bearer), 1_000) {
        KeyDecision::Granted(r) => r,
        KeyDecision::Unknown => panic!("the fixture key is not in the file"),
        KeyDecision::OwnerDenied(_) => panic!("the fixture key's owner is denied"),
        KeyDecision::Expired(_) => panic!("the fixture key is expired"),
    }
}

/// One URL per non-anonymous scope of [`key_fixture`], chosen so that **that** scope
/// answers it: scopes are first match wins, so `mpa/onboarding` answers `/mpa/welcome` and
/// never `/mpa/reports/q1`, and `mcp/api` answers `/mcp/plain` and never
/// `/mcp/keys/report`. The agreement test checks this table against `resolve` before
/// trusting it.
const KEY_PROBES: &[(&str, &str)] = &[
    ("mpa/reports", "https://app.x.com/mpa/reports/q1"),
    ("mpa/admin", "https://app.x.com/mpa/admin/panel"),
    ("mpa/onboarding", "https://app.x.com/mpa/welcome"),
    ("mcp/logs", "https://ai.x.com/mcp/logs/today"),
    ("mcp/keys", "https://ai.x.com/mcp/keys/report"),
    ("mcp/other", "https://ai.x.com/mcp/other/today"),
    ("mcp/api", "https://ai.x.com/mcp/plain"),
];

/// The list is the set of scopes a key of this owner may be narrowed to, so it has to be
/// exactly what such a key reaches: `mpa/reports` (named directly, both classes),
/// `mcp/keys` (through `@machines`, both classes) and `mcp/api` (named directly, key
/// only). Everything else is out for a reason the tests below take one each: `mpa/admin`
/// refuses the credential class, `mpa/onboarding` is `authenticated`, `mcp/logs` excludes
/// him, `mcp/other` does not name him, `mpa/healthz` is anonymous.
#[test]
fn key_scopes_for_lists_the_scopes_an_unrestricted_key_of_the_owner_reaches() {
    let a = access_of("key-scopes-bob", &key_fixture());
    assert_eq!(
        key_scopes(&a, BOB),
        vec!["mpa/reports", "mcp/keys", "mcp/api"]
    );
}

/// A key acts as its owner and not as anybody else, so carol's list is her own scopes and
/// none of bob's: `mcp/other` names her and leaves `credentials` unset, which restricts
/// nothing, so a key of hers reaches it.
#[test]
fn key_scopes_for_lists_only_what_a_key_of_that_owner_reaches() {
    let a = access_of("key-scopes-carol", &key_fixture());
    assert_eq!(key_scopes(&a, CAROL), vec!["mcp/other"]);
}

/// The list is what the **owner** reaches, never what one existing key of theirs is
/// narrowed to: [`fixture`]'s `laptop` key names only `mcp/api`, and a form that offered
/// only that could never widen the key back, which is the whole point of showing the
/// owner's reach.
#[test]
fn key_scopes_for_answers_for_the_owner_and_not_for_one_narrowed_key() {
    let a = access_of("key-scopes-owner", &fixture());
    assert_eq!(
        fixture_key(&a).scopes.as_ref().map(|s| s.len()),
        Some(1),
        "the fixture key must be narrowed to one scope for this to mean anything"
    );
    assert_eq!(key_scopes(&a, BOB), vec!["mcp/logs", "mcp/api"]);
}

/// A scope whose `credentials` admit a login only refuses a key, and bob is a member of
/// one, through `@admins`: membership alone must not put `mpa/admin` in the form, because
/// the form would then mint a key the gate refuses on its very first request.
#[test]
fn key_scopes_for_skips_a_scope_whose_credentials_admit_only_a_login() {
    let a = access_of("key-scopes-login-only", &key_fixture());
    assert!(
        a.scopes_for(BOB).iter().any(|(_, s)| s.name == "admin"),
        "bob must be a member of mpa/admin for the refusal to be about the class"
    );
    assert!(!key_scopes(&a, BOB).iter().any(|s| s == "mpa/admin"));
}

/// Groups are expanded at load and `credentials` is a statement about the place, so a
/// scope that reaches bob through `@machines` and spells out both classes is in his list
/// exactly as one that names him.
#[test]
fn key_scopes_for_lists_a_scope_reached_through_a_group_that_admits_both_classes() {
    let a = access_of("key-scopes-group", &key_fixture());
    assert!(key_scopes(&a, BOB).iter().any(|s| s == "mcp/keys"));
}

/// The scope's own veto is a key's veto too: `mcp/logs` names bob and excludes him, so
/// the form must not offer a scope the gate answers with `excluded`.
#[test]
fn key_scopes_for_drops_a_scope_that_excludes_the_uuid() {
    let a = access_of("key-scopes-excluded", &key_fixture());
    let logs = a
        .resolve(Some("https://ai.x.com/mcp/logs/today"))
        .expect("the probe url resolves")
        .1;
    assert!(logs.members.contains(BOB), "the fixture excludes a member");
    assert!(logs.excluded_users.contains(BOB));
    assert!(!key_scopes(&a, BOB).iter().any(|s| s == "mcp/logs"));
}

/// `denied` outranks every grant on every credential and a key is one of them, so a
/// vetoed owner is offered nothing at all: the page that would offer it is a 403. The
/// scopes are there to be reached, which is what makes the emptiness the veto's doing
/// rather than the file's.
#[test]
fn key_scopes_for_is_empty_for_a_uuid_the_file_denies() {
    let a = access_of("key-scopes-denied", &key_fixture());
    assert!(a.denied_users.iter().any(|u| u == DAVE));
    assert!(
        a.scopes_for(DAVE).iter().any(|(_, s)| s.name == "api"),
        "dave is named by mcp/api, so only the veto can empty his list"
    );
    assert!(key_scopes(&a, DAVE).is_empty());
}

/// A uuid the file has never heard of has no key, no membership and no grant, so the page
/// for it must offer no checkbox. This one asserts only absence, so it is green against
/// anything that returns an empty list and must be re-read once the code exists.
#[test]
fn key_scopes_for_is_empty_for_a_uuid_the_file_has_never_heard_of() {
    let a = access_of("key-scopes-unknown", &key_fixture());
    assert!(!a.by_uuid.contains_key(NOBODY));
    assert!(key_scopes(&a, NOBODY).is_empty());
}

/// `decide` answers an [`AccessKind::Anonymous`] scope **before** it looks at the
/// credential, so a key is granted there, and a denied owner's key is granted there too.
/// That is why the agreement test compares only non-anonymous scopes, and it is why the
/// design's word "restricted" is the right contract for this list: an anonymous scope says
/// nothing about whose key it is, so offering it as a restriction would be a checkbox that
/// changes nothing.
#[test]
fn key_scopes_for_omits_the_anonymous_scope_that_decide_grants_to_a_key_anyway() {
    let a = access_of("key-scopes-anon", &key_fixture());
    let url = "https://app.x.com/mpa/healthz";
    assert_eq!(
        decide(&a, &Subject::Key(owner_key(&a, BOB_BEARER)), Some(url)),
        Decision::Anonymous {
            app: "mpa".into(),
            scope: "healthz".into()
        }
    );
    let dead = a
        .by_key_hash
        .get(&sha256_hex(DAVE_BEARER))
        .expect("the fixture key is in the file");
    assert!(
        decide(&a, &Subject::Key(dead), Some(url)).granted(),
        "the veto sits after an anonymous grant, which is the reason for the exception"
    );
    assert!(!key_scopes(&a, BOB).iter().any(|s| s == "mpa/healthz"));
    assert!(!key_scopes(&a, DAVE).iter().any(|s| s == "mpa/healthz"));
}

/// The list the key form offers and the gate's answer are the same rule written twice, and
/// two copies of a grant rule drift. So for every owner of an unrestricted key, every
/// non-anonymous scope of the fixture must be listed exactly when `decide` grants that key
/// on a URL that scope itself answers: the whole set, both directions, on one fixture.
#[test]
fn key_scopes_for_agrees_with_decide_for_a_key_with_no_restriction() {
    let a = access_of("key-scopes-agree", &key_fixture());

    // The probe table is the whole file: a scope added to the fixture has to be probed.
    let probed: Vec<String> = KEY_PROBES
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    let non_anonymous: Vec<String> = a
        .apps
        .iter()
        .flat_map(|app| {
            app.scopes
                .iter()
                .filter(|s| s.access != AccessKind::Anonymous)
                .map(|s| format!("{}/{}", app.name, s.name))
        })
        .collect();
    assert_eq!(
        probed, non_anonymous,
        "the probe table must cover every non-anonymous scope"
    );

    for (uuid, bearer) in [(BOB, BOB_BEARER), (CAROL, CAROL_BEARER)] {
        let key = owner_key(&a, bearer);
        assert_eq!(key.uuid, uuid, "the fixture key must belong to {uuid}");
        assert!(
            key.scopes.is_none(),
            "the agreement is stated for a key with no restriction"
        );
        let listed = key_scopes(&a, uuid);
        for (name, url) in KEY_PROBES {
            let (app, scope) = a.resolve(Some(url)).expect("every probe url resolves");
            assert_eq!(
                (app.name.as_str(), scope.name.as_str()),
                name.split_once('/').unwrap(),
                "{url} must be answered by {name}, not by a scope that shadows it"
            );
            let granted = decide(&a, &Subject::Key(key), Some(url)).granted();
            let shows = listed.iter().any(|s| s == name);
            assert_eq!(
                granted, shows,
                "{uuid} at {url}: decide granted {granted}, key_scopes_for listed {shows} \
                     (list: {listed:?})"
            );
        }
    }

    // The vetoed owner: `decide_api_key` refuses the bearer at the first door, so the
    // record comes from the hash index, and `decide` vetoes it on every scope. The list
    // has to be empty for the same reason the gate refuses.
    let dead = a
        .by_key_hash
        .get(&sha256_hex(DAVE_BEARER))
        .expect("the fixture key is in the file");
    assert!(a.denied_users.iter().any(|u| u == &dead.uuid));
    let listed = key_scopes(&a, &dead.uuid);
    assert!(
        listed.is_empty(),
        "a denied owner is offered nothing: {listed:?}"
    );
    for (name, url) in KEY_PROBES {
        assert!(
            !decide(&a, &Subject::Key(dead), Some(url)).granted(),
            "{name} must not grant a denied owner's key"
        );
    }
}

/// The list is the file's order, not an alphabetical one: the form groups its checkboxes
/// under their application in the order the operator reads the file, and a list sorted by
/// name moves a scope the operator has just read. In this fixture the file's order starts
/// with `mpa/reports`, which is the exact reverse of the alphabetical one, so the
/// assertion below cannot be satisfied by a sort.
#[test]
fn key_scopes_for_returns_the_scopes_in_file_order() {
    let a = access_of("key-scopes-order", &key_fixture());
    let listed = key_scopes(&a, BOB);
    assert_eq!(listed, vec!["mpa/reports", "mcp/keys", "mcp/api"]);
    let mut sorted = listed.clone();
    sorted.sort();
    assert_ne!(
        listed, sorted,
        "the order pinned above is the file's, which is not alphabetical: {sorted:?}"
    );
}
