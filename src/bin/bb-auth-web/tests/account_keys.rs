use super::*;

// =====================================================================
// Self-service key minting (docs/ARCHITECTURE.md §13.6): the keys section
// offers a form, and `POST /account/keys` mints through the library's
// `add_api_key`, keyed by the uuid the identity header resolves to, never
// by a form field.
//
// The statuses follow the console's own conventions, because the same
// machinery answers both surfaces: a refused submission is the `400` the
// console's `mutate` answers every form refusal with, a stale `rev` is the
// `409`, a cross-site `POST` is the CSRF `403`, and a caller with no row
// to mint into is refused with the `403` the page already gives a vetoed
// identity.
// =====================================================================

/// The one form that posts to `action` for the key `id`, and the failure that
/// names what the page offered instead, because "there is no rotate form for
/// `ci`" is only useful if the test can say which forms it saw.
fn account_form_for(forms: &[String], action: &str, id: &str) -> String {
    forms
        .iter()
        .find(|f| {
            f.contains(&format!("action=\"{action}\"")) && f.contains(&format!("value=\"{id}\""))
        })
        .cloned()
        .unwrap_or_else(|| {
            let seen: Vec<&str> = forms
                .iter()
                .map(|f| {
                    let a = f.find("action=\"").map_or("", |i| &f[i + 8..]);
                    a.split('"').next().unwrap_or("")
                })
                .collect();
            panic!(
                "the page must carry a form posting to {action} for the key `{id}`; it \
                     posts to {seen:?}"
            )
        })
}

/// Every key the caller sees gets a rotate action and a revoke action, each
/// naming **that key**, and each answered by a page that carries the `POST`
/// with the file's fingerprint and that key's id.
///
/// §13.16 made the row action a **link** and moved the form onto the page it
/// opens, which is the console's shape (`Route::KeyRm` is a `GET` page and a
/// `POST` endpoint). Two things follow and both are asserted here. The section
/// carries no mutation form, so a crawler, a prefetch or a link-following
/// bot cannot revoke a credential: a `GET` never mutates. And the form still
/// exists, on the page the link opens, with its `rev`, its submit button and
/// its key id, because the page works with scripting off and a form that
/// names the wrong key revokes the wrong secret.
#[test]
fn account_every_key_of_the_caller_gets_a_rotate_form_and_a_remove_form() {
    let path = account_scratch_access("keys-forms", &account_access_keys());
    let base = account_serve(&path);
    let rev = sha256_hex(&read(&path));

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob is a roster user with keys: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "keys");
    assert!(
        account_forms(&s).is_empty(),
        "the keys section carries no mutation form: the row actions are links to a \
             confirmation page, and a page that lists credentials must not be a page that \
             can delete one: {s}"
    );
    for id in ["laptop", "ci"] {
        for (path, verb) in [("keys/rotate", "rotate"), ("keys/remove", "revoke")] {
            assert_eq!(
                links_to(&s, &format!("/account/{path}?id={id}")).len(),
                1,
                "the `{id}` row carries exactly one {verb} link to its own page: {s}"
            );
            let page = account_call(&format!("{base}{path}?id={id}"), Some("bob@x.com"));
            assert_eq!(
                page.status,
                200,
                "the {verb} link opens a page, and opening it changes nothing: {}",
                account_readable(&page.body)
            );
            let f = account_form_for(&account_forms(&page.body), &format!("/account/{path}"), id);
            assert!(
                f.contains("method=\"post\""),
                "a mutation is a POST, so a bookmark, a prefetch or a crawler cannot {verb} \
                     a credential: {f}"
            );
            assert!(
                f.contains("name=\"rev\"") && f.contains(&rev),
                "the form carries the fingerprint of the file as it was rendered, the same \
                     lost-update guard every console form carries: {f}"
            );
            assert!(
                f.contains("name=\"id\"") && f.contains(&format!("value=\"{id}\"")),
                "the form names the key it acts on, and only that one: {f}"
            );
            assert!(
                f.contains("type=\"submit\""),
                "the page works with scripting off, so each form ends in its own submit \
                     button: {f}"
            );
        }
    }
    assert!(
        !s.contains("id=phone"),
        "carol's key is not bob's, so bob's page carries no action that names it: {s}"
    );
    assert!(
        !g.body.contains("<script"),
        "no script tag: the estate rule these pages must not break"
    );
    assert!(
        account_extra_handlers(&g.body).is_empty(),
        "the only handler is the Preferences one: {:?}",
        account_extra_handlers(&g.body)
    );

    cleanup(&path);
}

/// WCAG 2.5.3 *Label in Name*: the accessible name of a control must contain the words a
/// sighted person reads on it, because a voice-control user says what they see.
///
/// The rotate pill shows `K::Rotate` ("rotate" / "rigenera") and is named
/// `K::AccountKeyRotate` plus the id ("Rotate key laptop" / "Rigenera la chiave laptop"),
/// which contains that word in both languages. It is pinned because the containment is a
/// property of two strings written in two places: renaming the pill's word, or the name,
/// to a verb the other does not use ("ruota") breaks the rule with nothing else on the
/// page changing.
/// The revoke pill is an icon with no visible word, and its name is the `span.vh` text inside
/// it, which is the string the `title` carries too, so it satisfies the rule by
/// construction. That half is pinned as well: a visible word added to that control later
/// cannot arrive without a name that carries it.
///
/// Both languages are walked, and the whole anchor (`anchors_to`, not `links_to`) is read,
/// because the name of an icon control lives *inside* it and an open tag cannot see it.
#[test]
fn account_key_row_actions_name_their_own_visible_words() {
    let path = account_scratch_access("keys-label-in-name", &account_access_keys());
    let base = account_serve(&path);

    for (cookie, lang) in [(Some("lang=en"), Lang::En), (Some("lang=it"), Lang::It)] {
        let g = account_call_pref(&base, Some("bob@x.com"), cookie, None);
        assert_eq!(
            g.status,
            200,
            "bob is a roster user with keys: {}",
            account_readable(&g.body)
        );
        assert!(
            account_html_tag(&g.body).contains(&format!(r#"lang="{}""#, lang.code())),
            "the cookie must have chosen {}, or this test asserts on the wrong language: {}",
            lang.code(),
            account_html_tag(&g.body)
        );
        let s = account_section(&g.body, "keys");
        for (verb, needle) in [
            ("rotate", "/account/keys/rotate?id="),
            ("revoke", "/account/keys/remove?id="),
        ] {
            let rows = anchors_to(&s, needle);
            assert_eq!(
                rows.len(),
                2,
                "bob has two keys, so the section carries two {verb} links to judge: {s}"
            );
            for a in rows {
                let seen = visible_text(&a);
                assert!(
                    !seen.is_empty(),
                    "the {verb} link shows a word, so there is something to contain: {a}"
                );
                let name = attr(&a, "aria-label").or_else(|| {
                    elements(&a, "<span class=\"vh\"", "</span>")
                        .into_iter()
                        .next()
                        .map(|vh| visible_text(&vh))
                });
                let name = name.unwrap_or_else(|| {
                    panic!(
                        "the {verb} link carries neither an aria-label nor `span.vh` text, \
                                so it has no accessible name at all: {a}"
                    )
                });
                assert!(
                    name.to_lowercase().contains(&seen.to_lowercase()),
                    "WCAG 2.5.3: in {lang:?} the {verb} link shows \"{seen}\", so its name \
                         must contain those words, or a voice user who says what they read gets \
                         nothing. Name is \"{name}\"."
                );
            }
        }
    }

    cleanup(&path);
}

/// The rotate, in full: a `200` that shows the new bearer exactly once (never
/// behind a redirect, because a bearer cannot survive one), `Cache-Control:
/// no-store`, the file carrying the hash of that bearer in place of the old
/// one, `released` today, and **everything else of the row identical**: the
/// administrator's `scopes` narrowing and the `duration`, byte for byte, and
/// every other key of every row untouched. The old bearer's hash is gone, so
/// the leaked secret stops working the moment the gate reloads.
#[test]
fn account_a_rotate_shows_a_new_bearer_once_and_changes_only_the_secret_and_the_date() {
    let path = account_scratch_access("rotate-all", &account_access_keys());
    let base = account_serve(&path);
    let rotate = format!("{base}keys/rotate");
    let before = read(&path);
    let rev = sha256_hex(&before);
    let old = account_key_json(&before, 0, "laptop");

    let g = account_post(
        &rotate,
        Some("bob@x.com"),
        &[("rev", &rev), ("id", "laptop")],
    );
    assert_eq!(
        g.status,
        200,
        "a rotate of one's own key is answered by a page, not a redirect: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.header("Cache-Control"),
        Some("no-store"),
        "the page carries a credential: no cache may keep it"
    );
    let bearer = account_bearer_in(&g.body);
    assert!(
        bearer.starts_with("bbk_"),
        "the new bearer is a bbk_ credential: {bearer}"
    );
    assert_ne!(
        bearer, ACCOUNT_BEARER_LAPTOP,
        "the rotate minted a new secret, not the one it replaced: {bearer}"
    );
    assert_eq!(
        g.body.matches(bearer.as_str()).count(),
        1,
        "the bearer is shown exactly once, and the page carries it {} times: {bearer}",
        g.body.matches(bearer.as_str()).count()
    );

    let after = read(&path);
    let now_key = account_key_json(&after, 0, "laptop");
    assert_eq!(
        now_key["key_hash"],
        serde_json::json!(sha256_hex(&bearer)),
        "the filed credential is sha256 of the bearer the page just showed: {after}"
    );
    assert!(
        !after.contains(&sha256_hex(ACCOUNT_BEARER_LAPTOP)),
        "the old bearer's hash is gone, so the leaked secret stops working on the next \
             reload: {after}"
    );
    assert!(
        !after.contains(&bearer),
        "the file keeps the hash, never the bearer"
    );
    assert_eq!(
        now_key["released"],
        serde_json::json!(format_date(now())),
        "a key's issue date is a fact about the secret being created now: {now_key}"
    );
    assert_eq!(
        now_key["duration"], old["duration"],
        "the window is untouched, and the fixture's is `never`, which this page would \
             refuse to mint, so a rotate that rewrote it cannot pass: {now_key}"
    );
    assert_eq!(
        now_key["scopes"], old["scopes"],
        "the administrator's narrowing survives a rotate byte for byte: a rotate is the \
             answer to a leak, not a widening: {now_key}"
    );
    assert_eq!(
        account_key_json(&after, 0, "ci"),
        account_key_json(&before, 0, "ci"),
        "the caller's other key is untouched by a rotate of this one"
    );
    assert_eq!(
        account_key_json(&after, 1, "phone"),
        account_key_json(&before, 1, "phone"),
        "carol's key is untouched, and its hash still names her working secret"
    );

    let g = account_call(&base, Some("bob@x.com"));
    assert!(
        !g.body.contains(&bearer),
        "the bearer is shown once: the next GET of the page does not carry it"
    );

    cleanup(&path);
}

/// The remove: a `303` back to the page, because a `GET` never mutates and the
/// answer to a mutation is a redirect the browser can reload without revoking
/// the key twice. The redirect carries nothing secret, so the key is simply
/// gone, and every other key of every row is byte for byte what it was.
#[test]
fn account_a_remove_is_a_303_to_the_page_and_leaves_the_other_keys_alone() {
    let path = account_scratch_access("remove-one", &account_access_keys());
    let base = account_serve(&path);
    let remove = format!("{base}keys/remove");
    let before = read(&path);
    let rev = sha256_hex(&before);

    let g = account_post(&remove, Some("bob@x.com"), &[("rev", &rev), ("id", "ci")]);
    assert_eq!(
        g.status,
        303,
        "a mutation answers with a redirect, so a reload cannot repeat it: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.header("Location"),
        Some(ACCOUNT_PAGE),
        "the redirect lands back on the page the form was on"
    );
    assert!(
        !g.body.contains("bbk_"),
        "a redirect carries nothing secret, and this one has no reason to: {}",
        account_readable(&g.body)
    );

    let after = read(&path);
    let doc: serde_json::Value = serde_json::from_str(&after).expect("the written file parses");
    assert!(
        doc["users"][0]["api_keys"]
            .as_array()
            .is_some_and(|ks| !ks.iter().any(|k| k["id"] == "ci")),
        "the key is gone from the caller's row: {after}"
    );
    assert_eq!(
        account_key_json(&after, 0, "laptop"),
        account_key_json(&before, 0, "laptop"),
        "the caller's other key is untouched, narrowing and window included"
    );
    assert_eq!(
        account_key_json(&after, 1, "phone"),
        account_key_json(&before, 1, "phone"),
        "carol's key is untouched"
    );

    let g = account_call(&base, Some("bob@x.com"));
    let s = account_section(&g.body, "keys");
    assert!(
        !s.contains("value=\"ci\""),
        "the page no longer offers a form for a key that does not exist: {s}"
    );

    cleanup(&path);
}

/// A key the caller does not own is refused on both endpoints, with the file
/// unchanged: carol's real id, and an id nobody has. The status is the
/// console's `400`, because the console answers every `key_mut` and
/// `remove_api_key` refusal with the `400` refusal page and this page is the
/// same machinery. A form field naming another identity changes nothing: the
/// caller is the identity header, and a field that chose the row would let any
/// signed-in person revoke anybody's credential.
#[test]
fn account_a_key_the_caller_does_not_own_is_a_400_on_both_endpoints_and_writes_nothing() {
    let path = account_scratch_access("keys-foreign", &account_access_keys());
    let base = account_serve(&path);
    let before = read(&path);
    let rev = sha256_hex(&before);

    for endpoint in ["rotate", "remove"] {
        for id in ["phone", "nope"] {
            let g = account_post(
                &format!("{base}keys/{endpoint}"),
                Some("bob@x.com"),
                &[("rev", &rev), ("id", id)],
            );
            assert_eq!(
                g.status,
                400,
                "`{id}` is not bob's key ({endpoint}), so the request is refused: {}",
                account_readable(&g.body)
            );
            assert_eq!(
                read(&path),
                before,
                "the refusal of `{id}` on {endpoint} wrote nothing: the file is byte for \
                     byte what it was"
            );
        }
        // A field naming another identity is ignored, exactly as the mint's is:
        // it cannot make carol's key bob's.
        let g = account_post(
            &format!("{base}keys/{endpoint}"),
            Some("bob@x.com"),
            &[
                ("rev", &rev),
                ("id", "phone"),
                ("email", "carol@x.com"),
                ("uuid", ACCOUNT_CAROL),
            ],
        );
        assert_eq!(
            g.status,
            400,
            "the form named carol on {endpoint}, and a form field is not an identity: {}",
            account_readable(&g.body)
        );
        assert_eq!(
            read(&path),
            before,
            "the {endpoint} that named carol in a field wrote nothing"
        );
    }
    assert_eq!(
        account_key_json(&before, 1, "phone"),
        account_key_json(&read(&path), 1, "phone"),
        "carol's secret is standing, hash included"
    );

    cleanup(&path);
}

/// A stranger, an administrator with no row, and a vetoed identity are refused
/// the `403` the mint already gives them, on both endpoints, and nothing is
/// written: a rotate hands out a credential and a remove destroys one, so a
/// refusal that did either is an admission.
#[test]
fn account_a_stranger_and_a_denied_caller_are_refused_a_403_on_rotate_and_remove() {
    let path = account_scratch_access("keys-no-caller", &account_access_keys());
    let base = account_serve(&path);
    let before = read(&path);
    let rev = sha256_hex(&before);

    for who in ["stranger@elsewhere.com", "admin@x.com", "spammer@x.com"] {
        for endpoint in ["rotate", "remove"] {
            let g = account_post(
                &format!("{base}keys/{endpoint}"),
                Some(who),
                &[("rev", &rev), ("id", "laptop")],
            );
            assert_eq!(
                g.status,
                403,
                "a {endpoint} POST from {who} is refused: {}",
                account_readable(&g.body)
            );
        }
    }
    assert_eq!(
        read(&path),
        before,
        "a refusal may not write: no key rotated, no key revoked"
    );

    cleanup(&path);
}

/// The two doors in front of every mutation, on both endpoints: a `rev` that
/// is not the file's current fingerprint is the console's `409` (the file
/// moved under the form, and revoking onto bytes nobody saw would clobber that
/// edit), and a `POST` the browser says came from another site is the CSRF
/// `403`. Both write nothing.
#[test]
fn account_a_rotate_or_remove_on_a_stale_rev_or_from_another_site_writes_nothing() {
    let path = account_scratch_access("keys-doors", &account_access_keys());
    let base = account_serve(&path);
    let before = read(&path);
    let rev = sha256_hex(&before);
    let stale = "0000000000000000000000000000000000000000000000000000000000000000";

    for endpoint in ["rotate", "remove"] {
        let url = format!("{base}keys/{endpoint}");
        let g = account_post(&url, Some("bob@x.com"), &[("rev", stale), ("id", "laptop")]);
        assert_eq!(
            g.status,
            409,
            "a {endpoint} form submitted onto bytes it never saw is a conflict: {}",
            account_readable(&g.body)
        );
        assert_eq!(
            read(&path),
            before,
            "the {endpoint} conflict wrote nothing: the access file is byte for byte what \
                 it was"
        );

        let g = account_post_as(
            &url,
            Some("bob@x.com"),
            &[("rev", &rev), ("id", "laptop")],
            "cross-site",
            true,
        );
        assert_eq!(
            g.status,
            403,
            "a cross-site {endpoint} is a form on somebody else's page revoking a \
                 signed-in person's credential: {}",
            account_readable(&g.body)
        );
        assert_eq!(
            read(&path),
            before,
            "the cross-site {endpoint} refusal wrote nothing"
        );
    }

    cleanup(&path);
}

/// The first 4b fix, seen in the 4b screenshot: the mint form's two field
/// labels are the file's field names, `id` and `duration`, and on the Italian
/// page that is untranslated text in an otherwise Italian form. The labels are
/// the page's words, so they go through the table; the field **names** stay the
/// file's, because the handler reads those.
///
/// §13.16 names which entries they are: the name field is labelled `K::KeyColName`
/// and the duration `K::KeyColExpires`, the same two entries the table's column
/// headers use. That is the stronger form of the 4b fix, and the reason this test
/// asserts the table's own entries rather than the words "Id della chiave" and
/// "Durata della chiave" it asked for first: a field and the column that shows the
/// same value must not answer that value's name from two entries, and one entry
/// has one translation, so an Italian page cannot carry a label in English. The
/// English page is asserted alongside, because the fix is the labels, not one
/// language's strings.
#[test]
fn account_the_mint_form_labels_are_translated_on_the_italian_page() {
    let path = account_scratch_access("mint-labels", &account_access_keys());
    let base = account_serve(&path);

    let it = account_call_pref(
        &format!("{base}keys/new"),
        Some("bob@x.com"),
        Some("lang=it"),
        None,
    );
    assert_eq!(
        it.status,
        200,
        "bob reaches the mint page: {}",
        account_readable(&it.body)
    );
    assert!(
        account_html_tag(&it.body).contains(r#"lang="it""#),
        "the cookie must have chosen Italian, or the test asserts on English: {}",
        account_html_tag(&it.body)
    );
    let s = account_section(&it.body, "keys");
    assert!(
        s.contains("Chiavi API"),
        "the section under test is the keys section: {s}"
    );
    assert!(
        s.contains("action=\"/account/keys\""),
        "the page under test is the one that carries the mint form: {s}"
    );
    for key in [K::KeyColName, K::KeyColExpires] {
        let label = t(Lang::It, key);
        assert!(
            s.contains(label),
            "the mint form's label must read \"{label}\", the translation table's own words \
                 for that field: {s}"
        );
        assert_ne!(
            label,
            t(Lang::En, key),
            "the entry has to carry Italian: an entry whose two sides are the same string \
                 is an untranslated label wearing a translation table's name"
        );
    }
    for bare in [
        r#"<span class="lbl">id</span>"#,
        r#"<span class="lbl">duration</span>"#,
        ">id<",
        ">duration<",
    ] {
        assert!(
            !s.contains(bare),
            "a bare field name is not a label in the reader's language: {s}"
        );
    }
    assert!(
        s.contains("name=\"id\"") && s.contains("name=\"duration\""),
        "the field names stay the file's, because the handler reads them: {s}"
    );

    let en = account_call_pref(
        &format!("{base}keys/new"),
        Some("bob@x.com"),
        Some("lang=en"),
        None,
    );
    assert_eq!(
        en.status,
        200,
        "bob reaches the mint page: {}",
        account_readable(&en.body)
    );
    let e = account_section(&en.body, "keys");
    for key in [K::KeyColName, K::KeyColExpires] {
        assert!(
            e.contains(t(Lang::En, key)),
            "the fix is the labels, so the English page carries the same entry's words: {e}"
        );
    }
    for bare in [
        r#"<span class="lbl">id</span>"#,
        r#"<span class="lbl">duration</span>"#,
        ">id<",
        ">duration<",
    ] {
        assert!(
            !e.contains(bare),
            "the English page carries a label and not a field name either: {e}"
        );
    }

    cleanup(&path);
}

/// The second 4b fix: dave's keys can be narrowed to no scope at all, so the
/// form must not offer "only the scopes you pick" (a radio with `value="some"`
/// and nothing beside it is a control that can only be answered wrong, and
/// `restrict=some` with no pair writes a key narrowed to nothing), and it must
/// still mint with `restrict=all`, which files no `scopes` field at all.
///
/// §13.16 moved the form to `GET <prefix>/keys/new`, so the form is read from
/// there. The `POST` is unchanged, and a hand-written `duration=30d` is still
/// the grammar's own spelling (§13.15 step 4), which is why the mint below posts
/// it rather than the select's `custom` + `days` pair: this test is about the
/// restriction, and the mint that proves it must not depend on the field layout.
#[test]
fn account_a_caller_with_nothing_to_narrow_gets_no_some_option_and_still_mints() {
    let path = account_scratch_access(
        "mint-no-narrow",
        &ACCOUNT_ACCESS_NO_NARROW.replace("__DAVE__", ACCOUNT_DAVE),
    );
    let base = account_serve(&path);

    let g = account_call(&format!("{base}keys/new"), Some("dave@x.com"));
    assert_eq!(
        g.status,
        200,
        "dave is a roster user, so he reaches the mint page: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "keys");
    assert!(
        s.contains("action=\"/account/keys\""),
        "dave has a row, so the mint form is his: {s}"
    );
    assert!(
        !s.contains(r#"value="some""#),
        "key_scopes_for is empty for dave, so the form must not offer the narrowing \
             choice at all: {s}"
    );
    assert!(
        !s.contains("type=\"checkbox\""),
        "there is no scope to check, so the form carries no checkbox: {s}"
    );
    assert!(
        s.contains(r#"value="all""#),
        "the unrestricted mint is the only choice the page can honestly offer, so it stays: {s}"
    );

    let rev = sha256_hex(&read(&path));
    let g = account_post(
        &format!("{base}keys"),
        Some("dave@x.com"),
        &[
            ("rev", &rev),
            ("id", "phone"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(
        g.status,
        200,
        "the mint the form offers is the mint that stands: {}",
        account_readable(&g.body)
    );
    let after = read(&path);
    let key = account_key_json(&after, 0, "phone");
    assert!(
        key.get("scopes").is_none(),
        "restrict=all files no restriction, which the gate reads as the owner's reach: {key}"
    );

    cleanup(&path);
}

/// The mint form offers a `POST` to `/account/keys` carrying the file
/// fingerprint, an id, a duration, the restrict choice, and one checkbox per
/// scope `Access::key_scopes_for` returns for the caller, valued
/// `application/scope` and grouped under the application. A scope the caller's
/// keys cannot reach gets no checkbox, because a key narrowed to it fails on
/// its very first request, and no URL from the file appears: the restriction is
/// named by scope, never by a URL (§13.6).
///
/// §13.16 moved the form onto a page of its own, `GET <prefix>/keys/new`, so
/// the keys section is a table and one link. That is asserted first, because a
/// form left in the section is the design's own defect: the row it opens would
/// appear above the + that opens it, and the section would carry an input a
/// person who came to *read* their keys has to tab past.
#[test]
fn account_the_keys_section_offers_a_mint_form_with_one_checkbox_per_narrowable_scope() {
    let path = account_scratch_access("mint-form", &account_access_mint());
    let base = account_serve(&path);

    let g = account_call(&base, Some("bob@x.com"));
    assert_eq!(
        g.status,
        200,
        "bob is a roster user: {}",
        account_readable(&g.body)
    );
    let s = account_section(&g.body, "keys");
    assert!(
        !s.contains("action=\"/account/keys\""),
        "the mint form is a page of its own (§13.16), so the section is a table and a \
             link: {s}"
    );
    assert_eq!(
        links_to(&g.body, "/account/keys/new").len(),
        1,
        "the section opens the form through one link, which is the only way to a mint \
             with scripting off: {}",
        account_readable(&g.body)
    );

    let n = account_call(&format!("{base}keys/new"), Some("bob@x.com"));
    assert_eq!(
        n.status,
        200,
        "bob reaches the mint page: {}",
        account_readable(&n.body)
    );
    let s = account_section(&n.body, "keys");
    assert!(
        s.contains("method=\"post\"") && s.contains("action=\"/account/keys\""),
        "the mint is a POST to the page's own prefix: {s}"
    );
    assert!(
        s.contains("name=\"rev\"") && s.contains(&sha256_hex(&read(&path))),
        "the form carries the fingerprint of the file as rendered, the same lost-update \
             guard every console form carries: {s}"
    );
    for field in ["name=\"id\"", "name=\"duration\"", "name=\"restrict\""] {
        assert!(s.contains(field), "the form must carry {field}: {s}");
    }
    assert!(
        s.contains("mcp/logs") && s.contains("mcp/api"),
        "bob's keys reach mcp/logs and mcp/api, so the form must offer exactly those, \
             under the application name: {s}"
    );
    for outside in ["mcp/vault", "mpa/admin", "mpa/onboarding"] {
        assert!(
            !s.contains(&format!("value=\"{outside}\"")),
            "{outside} is not in bob's key_scopes_for set (carol's scope, login-only \
                 credentials, authenticated): a checkbox the gate refuses mints a key that \
                 fails on its first request: {s}"
        );
    }
    assert!(
        s.contains("type=\"submit\""),
        "the page works with scripting off, so the form ends in a submit button: {s}"
    );
    assert!(
        !s.contains("https://"),
        "the restriction is named by application and scope, never by a URL: {s}"
    );

    cleanup(&path);
}

/// A stranger has no row to file a key under, an administrator with no
/// row is one more stranger, and a vetoed caller is out everywhere: none
/// of them gets the form, and a hand-crafted `POST` is refused with the
/// `403` the console gives a caller the route does not serve. Nothing is
/// written: a mint is a credential, and a refusal that files one is an
/// admission.
///
/// §13.16 split the form onto `GET <prefix>/keys/new`, so both pages are
/// asked: the section, which must carry no form, and the mint page, which
/// must not exist as a form for a caller with no row. The `POST` is asked
/// of the unchanged endpoint, because moving a form is not moving a door.
#[test]
fn account_a_stranger_and_a_vetoed_caller_get_no_form_and_a_posted_mint_writes_nothing() {
    let path = account_scratch_access("mint-no-caller", &account_access_mint());
    let base = account_serve(&path);
    let keys = format!("{base}keys");
    let before = read(&path);
    let rev = sha256_hex(&before);

    for id in ["stranger@elsewhere.com", "admin@x.com", "spammer@x.com"] {
        for page in ["", "keys/new"] {
            let g = account_call(&format!("{base}{page}"), Some(id));
            if g.status == 200 {
                let s = account_section(&g.body, "keys");
                assert!(
                    !s.contains("<form"),
                    "{id} has no row to mint into, so `{page}` must answer the keys \
                         section with no form at all: {s}"
                );
            }
        }
        let p = account_post(
            &keys,
            Some(id),
            &[
                ("rev", rev.as_str()),
                ("id", "phone"),
                ("duration", "30d"),
                ("restrict", "all"),
            ],
        );
        assert_eq!(
            p.status,
            403,
            "a mint POST from {id} is refused: {}",
            account_readable(&p.body)
        );
    }
    assert_eq!(
        read(&path),
        before,
        "a refusal may not write: the access file is byte for byte what it was"
    );

    cleanup(&path);
}

/// The whole reveal-once contract (§13.6): the `POST` that mints answers
/// with the bearer in its own `200` (never behind a redirect, because a
/// bearer cannot survive one), `Cache-Control: no-store`, the bearer
/// exactly once in the body, the file carrying the key under the caller's
/// row with the hash of that bearer and never the bearer, and the next
/// `GET` of the page not carrying it at all. `restrict=all` writes no
/// `scopes` field, which the gate reads as "at most what the owner
/// reaches".
#[test]
fn account_a_mint_shows_the_bearer_once_and_files_only_its_hash() {
    let path = account_scratch_access("mint-all", &account_access_mint());
    let base = account_serve(&path);
    let keys = format!("{base}keys");
    let rev = sha256_hex(&read(&path));

    let g = account_post(
        &keys,
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "phone"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(
        g.status,
        200,
        "a valid mint is answered by a page, not a redirect: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        g.header("Cache-Control"),
        Some("no-store"),
        "the page carries a credential: no cache may keep it"
    );
    let bearer = account_bearer_in(&g.body);
    assert!(
        bearer.starts_with("bbk_"),
        "the bearer is a bbk_ credential: {bearer}"
    );
    assert_eq!(
        g.body.matches(bearer.as_str()).count(),
        1,
        "the bearer is shown exactly once, and the page carries it {n} times: {bearer}",
        n = g.body.matches(bearer.as_str()).count()
    );

    let file = read(&path);
    let doc: serde_json::Value = serde_json::from_str(&file).expect("the written file parses");
    let key = doc["users"][0]["api_keys"]
        .as_array()
        .and_then(|ks| ks.iter().find(|k| k["id"] == "phone"))
        .unwrap_or_else(|| panic!("the minted key is filed under the caller's row: {file}"));
    assert_eq!(
        key["duration"], "30d",
        "the submitted window is filed: {file}"
    );
    assert!(
        key.get("scopes").is_none(),
        "restrict=all writes no scopes field, which the gate reads as the owner's full \
             reach: {file}"
    );
    assert!(
        !file.contains(&bearer),
        "the file keeps only sha256(bearer), never the bearer"
    );
    assert!(
        file.contains(&sha256_hex(&bearer)),
        "the hash of the shown bearer is the filed credential"
    );

    let g = account_call(&base, Some("bob@x.com"));
    assert!(
        !g.body.contains(&bearer),
        "the bearer is shown once: the next GET of the page does not carry it"
    );

    cleanup(&path);
}

/// `restrict=some` writes exactly the submitted pairs, sorted (§13.6): the
/// submitted order is a browser's, not a fact about the file, and one
/// canonical spelling is what makes "this key is narrowed to these
/// scopes" a comparison and not a string match.
#[test]
fn account_a_mint_narrowed_to_two_scopes_writes_exactly_those_pairs_sorted() {
    let path = account_scratch_access("mint-some", &account_access_mint());
    let base = account_serve(&path);
    let keys = format!("{base}keys");
    let rev = sha256_hex(&read(&path));

    let g = account_post(
        &keys,
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "two"),
            ("duration", "90d"),
            ("restrict", "some"),
            ("scope", "mcp/logs"),
            ("scope", "mcp/api"),
        ],
    );
    assert_eq!(
        g.status,
        200,
        "both pairs are in bob's set, so the mint stands: {}",
        account_readable(&g.body)
    );

    let file = read(&path);
    let doc: serde_json::Value = serde_json::from_str(&file).expect("the written file parses");
    let scopes = doc["users"][0]["api_keys"]
        .as_array()
        .and_then(|ks| ks.iter().find(|k| k["id"] == "two"))
        .and_then(|k| k["scopes"].as_array())
        .unwrap_or_else(|| panic!("the key is filed with its restriction: {file}"));
    let got: Vec<&str> = scopes.iter().map(|s| s.as_str().unwrap()).collect();
    assert_eq!(
        got,
        ["mcp/api", "mcp/logs"],
        "the two pairs, sorted, and nothing else: {file}"
    );

    cleanup(&path);
}

/// A pair outside `key_scopes_for` is a `400` and nothing is written
/// (§13.6): carol's scope, an `authenticated` scope (Cognito vouches for
/// no static key of ours), and a pair that names nothing. A silently
/// dropped pair would mint a key **wider** than the person asked for,
/// which is the one direction a restriction must never move.
#[test]
fn account_a_scope_outside_the_callers_own_set_is_a_400_that_writes_nothing() {
    let path = account_scratch_access("mint-outside", &account_access_mint());
    let base = account_serve(&path);
    let keys = format!("{base}keys");
    let before = read(&path);

    for pair in ["mcp/vault", "mpa/onboarding", "mcp/nope"] {
        let rev = sha256_hex(&read(&path));
        let g = account_post(
            &keys,
            Some("bob@x.com"),
            &[
                ("rev", rev.as_str()),
                ("id", "phone"),
                ("duration", "30d"),
                ("restrict", "some"),
                ("scope", pair),
            ],
        );
        assert_eq!(
            g.status,
            400,
            "the pair {pair} is outside bob's set, so the mint is refused: {}",
            account_readable(&g.body)
        );
        assert_eq!(
            read(&path),
            before,
            "the refusal of {pair} wrote nothing: the file is byte for byte what it was"
        );
    }

    cleanup(&path);
}

/// The abuse bounds are constants (§13.6): `id` from `[a-z0-9-]{1,32}`,
/// `duration` required and at least a day, at most ten keys per row counting
/// the administrator's. Each is a `400` that writes nothing. The duplicate id
/// rides on the full fixture because bob's two fixture keys are what make
/// `laptop` a duplicate, and the tenth-key bound counts keys the caller did
/// not make.
///
/// There is no ceiling and no ban on `never` here, and that is §13.15: the
/// two cases this test used to carry are now minted successfully by
/// [`a_self_service_key_may_never_expire`].
#[test]
fn account_every_mint_bound_is_a_400_that_writes_nothing() {
    let long = "x".repeat(33);
    let cases = [
        ("Bad ID", "30d", "the id is not [a-z0-9-]{1,32}"),
        (long.as_str(), "30d", "the id is 33 characters"),
        ("phone", "", "the duration is missing"),
        ("phone", "0d", "zero days is not a window"),
    ];
    let path = account_scratch_access("mint-bounds", &account_access_mint());
    let base = account_serve(&path);
    let keys = format!("{base}keys");
    let before = read(&path);
    for (id, duration, why) in cases {
        let rev = sha256_hex(&read(&path));
        let g = account_post(
            &keys,
            Some("bob@x.com"),
            &[
                ("rev", rev.as_str()),
                ("id", id),
                ("duration", duration),
                ("restrict", "all"),
            ],
        );
        assert_eq!(
            g.status,
            400,
            "{id} / {duration}: {why}: {}",
            account_readable(&g.body)
        );
        assert_eq!(
            read(&path),
            before,
            "{id} / {duration}: the refusal wrote nothing"
        );
    }
    cleanup(&path);

    // A duplicate id, on the fixture whose bob already holds `laptop`.
    let dup = account_scratch_full("mint-dup");
    let dup_base = account_serve(&dup);
    let before_dup = read(&dup);
    let rev = sha256_hex(&read(&dup));
    let g = account_post(
        &format!("{dup_base}keys"),
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "laptop"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(
        g.status,
        400,
        "an id names a key in `key rotate`, so a second `laptop` is refused: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        read(&dup),
        before_dup,
        "the duplicate refusal wrote nothing"
    );
    cleanup(&dup);

    // The eleventh key on a row that already holds ten.
    let ten = account_scratch_access("mint-ten", &account_access_ten_keys());
    let ten_base = account_serve(&ten);
    let before_ten = read(&ten);
    let rev = sha256_hex(&read(&ten));
    let g = account_post(
        &format!("{ten_base}keys"),
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "phone"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(
        g.status,
        400,
        "ten keys per row is the bound, and these ten count: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        read(&ten),
        before_ten,
        "the eleventh-key refusal wrote nothing"
    );
    cleanup(&ten);
}

/// A `rev` that is not the file's current fingerprint is the console's
/// `409`: the file moved under the form (a `bb-auth-adm` over SSH, another
/// tab), and minting onto bytes nobody saw would clobber that edit.
#[test]
fn account_a_mint_on_a_stale_rev_is_a_409_that_writes_nothing() {
    let path = account_scratch_access("mint-stale", &account_access_mint());
    let base = account_serve(&path);
    let keys = format!("{base}keys");
    let before = read(&path);

    let g = account_post(
        &keys,
        Some("bob@x.com"),
        &[
            (
                "rev",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            ("id", "phone"),
            ("duration", "30d"),
            ("restrict", "all"),
        ],
    );
    assert_eq!(
        g.status,
        409,
        "a form submitted onto bytes it never saw is a conflict: {}",
        account_readable(&g.body)
    );
    assert_eq!(
        read(&path),
        before,
        "the conflict wrote nothing: the access file is byte for byte what it was"
    );

    cleanup(&path);
}

/// The GUI served on `workers` **request threads**, the shape of `main`'s worker loop, so
/// two handlers really can be in flight at once. The shared [`serve`] helper answers
/// requests one at a time from a single thread, which would serialize any pair of writers
/// by itself and leave a concurrency test measuring the harness instead of the lock.
fn account_serve_with_workers(path: &str, workers: usize) -> String {
    let cfg = std::sync::Arc::new(cfg_for(path, ADMIN_BASE));
    let server = std::sync::Arc::new(Server::http("127.0.0.1:0").expect("bind an ephemeral port"));
    let port = server.server_addr().to_ip().expect("an ip address").port();
    for _ in 0..workers {
        let server = std::sync::Arc::clone(&server);
        let cfg = std::sync::Arc::clone(&cfg);
        std::thread::spawn(move || loop {
            match server.recv() {
                Ok(req) => handle(req, &cfg),
                Err(e) => eprintln!("[bb-auth-web test] recv error: {e}"),
            }
        });
    }
    format!("http://127.0.0.1:{port}{ACCOUNT_PATH}/")
}

/// One mint `POST` **without** the harness's [`WRITE_PERMIT`], for the one test that needs
/// two writers in flight at once. Every other account writer takes that permit because the
/// suite's wall time is the fsync queue behind the production [`WRITE_LOCK`]; a race test
/// that took it would serialize its own racers and measure the queue, not the lock.
fn account_race_post(url: &str, rev: &str, id: &str) -> u16 {
    let fields = [
        ("rev", rev),
        ("id", id),
        ("duration", "30d"),
        ("restrict", "all"),
    ];
    let req = account_client()
        .post(url)
        .header("Sec-Fetch-Site", "same-origin")
        .header(SECRET_HEADER, TEST_SECRET)
        .header(IDENTITY_HEADER, "bob@x.com");
    let r = req
        .send_form(fields.iter().copied())
        .expect("a POST response");
    r.status().as_u16()
}

/// Two mints that arrive at the same moment, each carrying the `rev` of the bytes it was
/// rendered from, come to **one success and one `409`**, never two successes
/// (docs/ARCHITECTURE.md §13.13). The `rev` is compared against the file's current bytes
/// inside [`WRITE_LOCK`], so the writer that loses the race is told the file moved rather
/// than clobbering the winner: two mints that both passed the check would write two files,
/// and the second rename would drop the first mint's key, leaving a bearer that was shown
/// in a browser and authorizes nothing.
///
/// This is the regression guard for the narrower lock scope in `account_key_post`, where
/// the guard ends at the commit instead of after the response is sent. What must not move
/// with it is the `rev` check, and this is the assertion that says so. The fixture is
/// served on two worker threads for the same reason: on the single-threaded [`serve`]
/// helper the two requests never overlap and the test proves nothing.
#[test]
fn account_two_concurrent_mints_against_one_rev_give_one_success_and_one_409() {
    let path = account_scratch_access("mint-race", &account_access_mint());
    let base = account_serve_with_workers(&path, 2);
    let keys = format!("{base}keys");
    let rev = sha256_hex(&read(&path));

    // Both clients fire the moment the barrier opens, so both handlers are in flight and
    // neither can be answered before the other has read the same bytes.
    let gate = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mint = |id: &'static str| {
        let keys = keys.clone();
        let rev = rev.clone();
        let gate = std::sync::Arc::clone(&gate);
        std::thread::spawn(move || {
            gate.wait();
            account_race_post(&keys, &rev, id)
        })
    };
    let phone = mint("phone");
    let laptop = mint("laptop");
    gate.wait();
    let mut both = [
        phone.join().expect("the first mint answered"),
        laptop.join().expect("the second mint answered"),
    ];
    both.sort_unstable();
    assert_eq!(
        both,
        [200, 409],
        "one mint lands and the other is told the file moved under it"
    );

    // And the file carries exactly one new key, so the loser wrote nothing and the winner's
    // key is the one still standing. Which of the two won is the race's business.
    let file = read(&path);
    let doc: serde_json::Value = serde_json::from_str(&file).expect("the written file parses");
    let ids: Vec<String> = doc["users"][0]["api_keys"]
        .as_array()
        .map(|ks| {
            ks.iter()
                .filter_map(|k| k["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(ids.len(), 1, "exactly one key was filed, not two: {file}");
    assert!(
        ids[0] == "phone" || ids[0] == "laptop",
        "the filed key is one of the two mints that raced: {file}"
    );

    cleanup(&path);
}

/// The two doors in front of every mutation, answered as the console
/// answers them: a `POST` the browser says came from another site is the
/// CSRF `403`, and a `POST` that did not come through nginx at all is the
/// proxy-secret `403`. Both write nothing, and the mint is the mutation
/// most worth locking, because it hands out a credential.
#[test]
fn account_a_mint_post_from_another_site_or_outside_the_proxy_is_refused() {
    let path = account_scratch_access("mint-doors", &account_access_mint());
    let base = account_serve(&path);
    let keys = format!("{base}keys");
    let before = read(&path);
    let rev = sha256_hex(&read(&path));
    let fields = [
        ("rev", rev.as_str()),
        ("id", "phone"),
        ("duration", "30d"),
        ("restrict", "all"),
    ];

    let g = account_post_as(&keys, Some("bob@x.com"), &fields, "cross-site", true);
    assert_eq!(
        g.status,
        403,
        "a cross-site mint is login CSRF for a credential: {}",
        account_readable(&g.body)
    );
    assert_eq!(read(&path), before, "the cross-site refusal wrote nothing");

    let g = account_post_as(&keys, Some("bob@x.com"), &fields, "same-origin", false);
    assert_eq!(
        g.status,
        403,
        "a request without the proxy secret never reached this page through nginx: {}",
        account_readable(&g.body)
    );
    assert_eq!(read(&path), before, "the secretless refusal wrote nothing");

    cleanup(&path);
}

/// The mint is keyed by the uuid the identity header resolves to, never
/// by a form field (§13.6): fields a caller can write are not evidence of
/// who the caller is, and a field that chose the row would let any
/// signed-in person mint a credential on anybody's account.
#[test]
fn account_a_mint_ignores_the_identity_in_the_form_and_files_on_the_header() {
    let path = account_scratch_access("mint-identity", &account_access_mint());
    let base = account_serve(&path);
    let keys = format!("{base}keys");
    let rev = sha256_hex(&read(&path));

    let g = account_post(
        &keys,
        Some("bob@x.com"),
        &[
            ("rev", rev.as_str()),
            ("id", "phone"),
            ("duration", "30d"),
            ("restrict", "all"),
            ("email", "carol@x.com"),
            ("uuid", ACCOUNT_CAROL),
        ],
    );
    assert_eq!(
        g.status,
        200,
        "the mint stands on the header alone: {}",
        account_readable(&g.body)
    );

    let file = read(&path);
    let doc: serde_json::Value = serde_json::from_str(&file).expect("the written file parses");
    assert!(
        doc["users"][0]["api_keys"]
            .as_array()
            .is_some_and(|ks| ks.iter().any(|k| k["id"] == "phone")),
        "the key lands under the caller's row: {file}"
    );
    assert!(
        doc["users"][1].get("api_keys").is_none_or(|ks| ks
            .as_array()
            .is_some_and(|ks| !ks.iter().any(|k| k["id"] == "phone"))),
        "the form named carol's uuid, and carol's row must not carry the key: {file}"
    );

    cleanup(&path);
}

/// The estate's standing rule, re-asserted on the page **with** the new
/// form: no `<script>`, and no inline handler beyond the Preferences menu's.
/// The mint form is plain fields and a submit button, because a page that
/// needs scripting to hand out a credential is the thing that must never ship.
///
/// Both pages are walked, because §13.16 split them: the page that lists the
/// keys and the page that carries the form. A `<script>` added to make the +
/// open the row is exactly the regression this test is for, and it would land
/// on whichever of the two somebody edited.
#[test]
fn account_the_page_with_the_mint_form_carries_no_script_and_only_the_menu_handler() {
    let path = account_scratch_access("mint-noscript", &account_access_mint());
    let base = account_serve(&path);

    for page in ["", "keys/new"] {
        let g = account_call(&format!("{base}{page}"), Some("bob@x.com"));
        assert_eq!(
            g.status,
            200,
            "bob reaches `{page}`: {}",
            account_readable(&g.body)
        );
        assert!(
            !g.body.contains("<script"),
            "`{page}`: no script tag, the estate rule the form must not break"
        );
        assert!(
            account_extra_handlers(&g.body).is_empty(),
            "`{page}`: the only handler is the Preferences one: {:?}",
            account_extra_handlers(&g.body)
        );
    }

    let n = account_call(&format!("{base}keys/new"), Some("bob@x.com"));
    assert!(
        account_section(&n.body, "keys").contains("action=\"/account/keys\""),
        "the page under test is the one that carries the form: {}",
        account_section(&n.body, "keys")
    );

    cleanup(&path);
}

// =====================================================================
// Self-service key rotation and removal (docs/ARCHITECTURE.md §13.6, PLAN.md
// step 4c): every key the caller owns gets two more forms, `POST
// <prefix>/keys/rotate` and `POST <prefix>/keys/remove`, each carrying the
// file fingerprint and that key's id, and both go through the library's
// `rotate_api_key` / `remove_api_key` and the same `AccessWrite` door as the
// mint.
//
// The statuses are the console's, because the same machinery answers both
// surfaces: a key the caller does not own is the `400` the console's
// `Route::KeyRotate` / `Route::KeyRm` answer every `key_mut` and
// `remove_api_key` refusal with (not a `404`: the console has no `404` for a
// mutation, and a page that answers "no such key" and "not your key"
// differently is an enumeration oracle for anybody with an account); a
// caller with no row is the `403` the mint already gives; a stale `rev` is
// the `409`; a cross-site `POST` is the CSRF `403`.
//
// The journal line (`[bb-auth-web] <uuid> (self): key rotate <id>`, and
// `key remove <id>`) is on stderr, as every mutation line here is, so no
// over-the-socket test can read it: the same limit 4b's mint tests have, and
// the reason the assertions below are about the bytes the request leaves
// behind.
// =====================================================================
