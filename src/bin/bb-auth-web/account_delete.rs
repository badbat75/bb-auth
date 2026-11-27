use crate::*;

/// The confirmation a row's rotate or revoke link opens: the console's [`confirm_card`] card
/// in this page's words, with the key's id in a hidden field because the two paths do not name
/// it. **No heading**: the shell's one `h1` carries the action word, which is why the caller
/// passes `op.title()` as the page title (§13.17).
///
/// A rotate is not marked destructive: it keeps the name and the restriction, and a red button on
/// it would teach the person to read the revoke's red as one more routine thing.
pub(crate) fn page_account_confirm(
    lang: Lang,
    page: &str,
    keys_path: &str,
    rev: &str,
    id: &str,
    op: AccountKeyOp,
) -> Markup {
    let (verb, word, warn, danger) = match op {
        AccountKeyOp::Rotate => (
            "rotate",
            K::AccountKeyRotate,
            K::AccountKeyRotateWarn,
            false,
        ),
        _ => ("remove", K::AccountKeyRemove, K::AccountKeyRemoveWarn, true),
    };
    confirm_card(
        &format!("{keys_path}/{verb}"),
        rev,
        page,
        t(lang, K::Cancel),
        html! { p { code { (id) } } },
        t(lang, warn),
        html! { input type="hidden" name="id" value=(id); },
        t(lang, word),
        None,
        danger,
    )
}

/// The delete confirmation page, in its two variants (§13.30 §2).
///
/// A `GET` renders it and does nothing else: it writes no byte of the access file and reaches the
/// intake in no way, because a prefetch of this URL is somebody who wanted to read, not somebody
/// who pressed (§13.29 W3). The facts are the two files' and the settings': what goes is the
/// roster row (the record, the keys, the groups) and the sign-in accounts, and a caller with no
/// row has only the accounts, which is why the stranger's variant is a page and not a refusal.
///
/// The audit sentence is the deployment's own bound, read from the compiled policy through the
/// console's own [`limit_text`] and [`size_text`], so the page cannot promise a retention an
/// operator did not set, and the unit word is the one the Settings page shows for that setting.
///
/// The typed address carries no `autocomplete`: the user removed it on 2026-11-26 (PLAN.md), so
/// the confirmation stays the person's own act, a deliberate exception to WCAG 1.3.5. Nothing on
/// the page is focused, because Enter must not be one keystroke from a deletion, and an empty
/// `required` field stops a stray Enter in the browser anyway.
///
/// `typed` and `err` are the `400` (§13.30 §2): the page that asked for the address is the page a
/// typo is answered on, with what was typed kept in the field, so a typo is seen and fixed rather
/// than retyped (forgiving input, WCAG 3.3.1 and 3.3.3). A `GET` renders the same page empty.
#[allow(clippy::too_many_arguments)]
pub(crate) fn page_account_delete(
    lang: Lang,
    action: &str,
    page: &str,
    rev: &str,
    uuid: Option<&str>,
    ids: &[String],
    own: &AccountOwn<'_>,
    audit: &AuditPolicy,
    typed: &str,
    err: Option<&Refusal>,
) -> Markup {
    // The one field this form has, so the refusal on it is what marks the field: the class,
    // `aria-invalid` and the link to the message box above the fields are one decision, made by
    // [`text_field_with`], and this page does not get to make it differently.
    let invalid = err.is_some_and(|e| e.is("confirm_email"));
    // Two addresses is the case that needs the hint, because the field asks for one of them and a
    // person with one has nothing to pick.
    let many = ids.len() > 1;
    let keys: Vec<&str> = own.keys.iter().map(|k| k.id.as_str()).collect();
    let addresses: Vec<&str> = ids.iter().map(String::as_str).collect();
    let hint = t(lang, K::AccountDeleteTypeHintMany);
    let hints: Vec<&str> = if many { vec![hint] } else { Vec::new() };
    let facts = html! {
        p class="lbl" { (t(lang, K::AccountDeleteGoes)) }
        ul class="plain" {
            @if uuid.is_some() {
                li { (t(lang, K::AccountDeleteRecord)) }
                @if !keys.is_empty() {
                    li { (t(lang, K::AccountDeleteKeysLead)) " " (code_list(&keys)) }
                }
                @if !own.groups.is_empty() {
                    li { (t(lang, K::AccountDeleteGroupsLead)) " " (code_list(&own.groups)) }
                }
            }
            // Last, because it is the one item that does not go at once (§13.30 §2).
            li {
                @if many {
                    (t(lang, K::AccountDeleteSignInMany))
                } @else {
                    (t(lang, K::AccountDeleteSignInOne))
                }
                " " (code_list(&addresses))
            }
        }
        p class="muted" { (t(lang, K::AccountDeleteLater)) }
        p class="muted" {
            @match audit.retention {
                Some(r) => {
                    (t(lang, K::AccountDeleteAuditKept)) " " (limit_text(lang, &r))
                    (t(lang, K::AccountDeleteAuditTail))
                },
                None => {
                    (t(lang, K::AccountDeleteAuditSize)) " " (size_text(audit.max_bytes())) "."
                },
            }
        }
    };
    confirm_card(
        action,
        rev,
        page,
        t(lang, K::Cancel),
        facts,
        t(lang, K::AccountDeleteLead),
        html! {
            // The subject of the press, as a hidden field and not in the path: the page is about
            // the caller, and the caller's uuid is what the `POST` re-checks against the header
            // (§13.29 W3 step 5). Empty for a stranger, and a stranger's deletion is the pool's
            // alone.
            input type="hidden" name="uuid" value=(uuid.unwrap_or(""));
            (text_field_with(
                t(lang, K::AccountDeleteTypeLabel),
                "confirm_email",
                typed,
                "",
                &hints,
                invalid,
                FieldOpts {
                    required: true,
                    inputmode: Some("email"),
                    class: Some("f-email"),
                    ..FieldOpts::default()
                },
            ))
        },
        t(lang, K::AccountDeleteConfirm),
        err,
        true,
    )
}

/// The most addresses one deletion request queues (§13.29 W3).
///
/// Named after the worker's own `MAX_PER_RUN`: it takes ten addresses per run and refuses the
/// **whole** run above that, so a caller with more is refused here, before anything is sent,
/// rather than leaving nine queued and the tenth not.
pub(crate) const DELETE_MAX_ADDRESSES: usize = 10;

/// The intake's two paths, hard-coded on **its** side (§13.29 W1), which is why
/// `BB_AUTH_WEB_DELETE_INTAKE` names only an origin: a path an operator can set is a path the
/// intake may not answer.
const INTAKE_WHOAMI_PATH: &str = "/account/whoami";
const INTAKE_DELETE_PATH: &str = "/account/delete";

/// The header the shared secret travels in (§13.29 W8 §1), on both calls and only where the
/// deployment set one.
const INTAKE_SECRET_HEADER: &str = "X-BB-Delete-Secret";

/// What one `GET /account/whoami` answered (§13.29 W3 step 4).
enum Whoami {
    /// The intake will take this address.
    Open,
    /// The intake will not (§13.29 W5). The protected list is its own, and this page never names
    /// it, the address that matched, or the intake's word for it (§13.30 §7).
    Protected,
    /// It gave no HTTP answer at all: the timeout, or a socket that will not carry the request.
    NoAnswer,
    /// It answered, in a way the contract does not read: not a `200`, not this address, no
    /// `protected` it is willing to state.
    Unusable,
}

/// What one `POST /account/delete` answered (§13.29 W3 step 6).
///
/// A run that stops on anything but [`Self::Accepted`] is a **partial** run for a caller whose
/// row went at step 5, and its page never says the account is deleted: the row going is a fact
/// this process did with its own hands, while the sign-in accounts sit in a queue this process
/// cannot read (§13.29 W6), so "deleted" would be a claim about the worker and "only partly
/// deleted" is the whole of what is known. The retry that page offers still works, and works as
/// a stranger: the row is gone, so the confirmation page the retry renders is the stranger's
/// variant, and the walk that follows runs over the addresses the session's own header names,
/// which is exactly the walk that queues what the first run did not.
enum Queued {
    /// `202` with `"ok": true`, the only acceptance the contract has (§13.29 W1).
    Accepted,
    /// An HTTP answer that is not an acceptance, with the status that said so. A `403` is the
    /// intake's protected list, and for a caller with no roster row that is the same page
    /// `whoami` would have given (§13.30 §4).
    Refused(u16),
    /// No HTTP answer at all, so the record may or may not be queued and the page says exactly
    /// that (§13.29 W6).
    NoAnswer,
}

/// The intake's HTTP client: the same three settings as [`cognito_post`], for the same reasons.
///
/// `timeout_global` is the bound the caller waits on (§13.29 W2), because `tiny_http` runs a
/// fixed pool of handler threads and a call that hangs forever is a worker that never serves
/// anybody again. `http_status_as_error(false)`, so a `403` and a `503` arrive as the answers
/// they are and not as errors. `max_redirects` **0**, because ureq's own default is 10 and a
/// `3xx` from the intake would hand the identity header, written here, to whatever host the
/// intake named.
fn intake_agent(cfg: &Config) -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(cfg.intake_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    )
}

/// Ask the intake whether one address may be deleted (§13.29 W3 step 4).
///
/// **One address per call**, as `X-Auth-Email`: the intake reads the whole header as one address,
/// so the gate's joined header (every email of one roster row) would queue an address no Cognito
/// user has and report it accepted. `X-Real-IP` is sent by nobody here: the intake records the
/// address of the socket that asked, and this client is not the proxy that knows the caller's.
///
/// The answer counts only from a `200` that echoes the address sent and states `protected` as a
/// boolean; anything else is [`Whoami::Unusable`]. Guessing "not protected" from an answer that
/// did not say so is the one guess this walk may not make, because the price of that guess is a
/// queued deletion.
fn intake_whoami(agent: &ureq::Agent, cfg: &Config, origin: &str, email: &str) -> Whoami {
    let mut request = agent
        .get(&format!("{origin}{INTAKE_WHOAMI_PATH}"))
        .header(IDENTITY_HEADER, email);
    if let Some(secret) = cfg.delete_secret.as_deref() {
        request = request.header(INTAKE_SECRET_HEADER, secret);
    }
    let response = match request.call() {
        Ok(r) => r,
        Err(ureq::Error::Timeout(_)) => return Whoami::NoAnswer,
        Err(_) => return Whoami::Unusable,
    };
    if response.status().as_u16() != 200 {
        return Whoami::Unusable;
    }
    let mut body = response.into_body();
    let text = body.read_to_string().unwrap_or_default();
    let value = serde_json::from_str::<serde_json::Value>(&text).unwrap_or_default();
    if value.get("email").and_then(|v| v.as_str()) != Some(email) {
        return Whoami::Unusable;
    }
    match value.get("protected").and_then(|v| v.as_bool()) {
        Some(true) => Whoami::Protected,
        Some(false) => Whoami::Open,
        None => Whoami::Unusable,
    }
}

/// Queue one address with the intake (§13.29 W3 step 6).
///
/// The body carries `confirm_email` equal to the header's address: the intake refuses a
/// `confirm_email` that differs from `X-Auth-Email` (`confirm_mismatch`), and the two are one
/// fact stated twice, so a request that means one address says it twice.
fn intake_delete(agent: &ureq::Agent, cfg: &Config, origin: &str, email: &str) -> Queued {
    let mut request = agent
        .post(&format!("{origin}{INTAKE_DELETE_PATH}"))
        .header(IDENTITY_HEADER, email);
    if let Some(secret) = cfg.delete_secret.as_deref() {
        request = request.header(INTAKE_SECRET_HEADER, secret);
    }
    let response = match request.send_form([("confirm_email", email)]) {
        Ok(r) => r,
        // A timeout and a socket that refuses the request are one fact to the person: the intake
        // did not say. "May or may not be queued" is the honest page for both, and the page's
        // own advice, try again, is safe in the case where it was queued.
        Err(_) => return Queued::NoAnswer,
    };
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let text = body.read_to_string().unwrap_or_default();
    let value = serde_json::from_str::<serde_json::Value>(&text).unwrap_or_default();
    if status == 202 && value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Queued::Accepted
    } else {
        Queued::Refused(status)
    }
}

/// The page a deletion request ends on (§13.30 §4): the profile outcome's shape, one `h1` that
/// states the result, one `p.lede`, one row of pills.
///
/// `muted` is the line the "some are queued" outcome adds: the addresses this walk cannot
/// confirm, which is a list of values for the administrator the person is sent to ask, not a
/// sentence of the lede (§13.30 §4). Every other outcome passes `None`.
///
/// The row's tag depends on how many pills it holds. maud writes no whitespace between
/// siblings, so pills written straight into one paragraph touch borders and read as one control
/// (WCAG 2.5.8, target spacing): a row of two rides in `div.actions`, which `admin.css` gives
/// `gap:12px` and the confirmation page's form already uses. `p.primary` stays for the single
/// pill, which needs no gap and is the shape the rest of the estate's pages have.
fn page_account_delete_outcome(lede: Markup, muted: Option<Markup>, pills: Vec<Markup>) -> Markup {
    html! {
        p class="lede" { (lede) }
        @if let Some(line) = muted {
            p class="muted" { (line) }
        }
        @if pills.len() > 1 {
            div class="actions" {
                @for pill in &pills { (pill) }
            }
        } @else if !pills.is_empty() {
            p class="primary" {
                @for pill in &pills { (pill) }
            }
        }
    }
}

/// The actions of an outcome page that says something **did** go: the retry, then the sign out
/// (§13.30 §4). The sign out is there because the cookie outlives the deletion and signing out is
/// the one action left that is true, and it is absent exactly where the operator named no
/// destination, which is the same rule the bar's row follows. The completed deletion answers no
/// page at all when a destination **is** named (§13.32 §1).
fn with_sign_out(prefs: &AccountPrefs, lang: Lang, retry: Markup) -> Vec<Markup> {
    let mut pills = vec![retry];
    if let Some(url) = prefs.logout {
        pills.push(pill_link(url, t(lang, K::SignOut)));
    }
    pills
}

/// Why the roster row did not go, and which page each answer is (§13.30 §4).
enum RowGone {
    /// The page is not the current one: its bytes moved under it, or the row it names is no
    /// longer in the file. The same page as the check at (2) answers this, because for the
    /// person each is "my account changed", and one page for both is also what stops the
    /// delete form being an oracle for which of the two checks fired.
    Changed,
    /// The write did not land, for a reason the filesystem or the parser gave. The library's
    /// sentence rides along for the journal, and the page says only that bb-auth could not
    /// save: the person has no use for an `EPERM`, and an operator reads it in the journal.
    Failed(String),
}

/// Answer the delete `POST` (§13.29 W3).
///
/// The order is W3's, and every step that can refuse refuses **before** the intake is asked,
/// because a `202` is the one answer this page cannot take back:
///
/// 1. the same-origin door, before the body is read, the door every `/account` `POST` goes
///    through;
/// 2. the page is the current one: the posted `uuid` is the live row's (`""` for a caller the
///    file has no row for) and the posted `rev` is the file's exact bytes. A person who opened
///    the page as a stranger and gained a row before pressing is refused, because the page they
///    hold says the file names nobody, and acting on that deletes a record they were never shown;
/// 3. the typed address is one of the caller's own, normalised as the header's are;
/// 4. no more than [`DELETE_MAX_ADDRESSES`] addresses;
/// 5. `whoami` for **every** address, ahead of any `POST`. The protected list is the intake's, and
///    a caller whose second address is protected must not leave a record queued behind the first,
///    which is why this is a loop of its own and not a check inside the write loop;
/// 6. for a caller the file has a row for: that row, removed under [`WRITE_LOCK`] through
///    [`remove_user`], ahead of the first `POST` (the reason is at the step);
/// 7. `POST` each address, stopping at the first that is not accepted;
/// 8. the journal lines (§13.29 W7), then the answer: where every address queued and the
///    operator named a logout URL, a `303` through the gate's logout (§13.32 §1); every other
///    outcome a page (§13.30 §4).
///
/// A caller with no row skips (6) and the access file is never opened for writing on that path,
/// which is the stranger's half of W3: the same walk, one effect short.
#[allow(clippy::too_many_arguments)]
pub(crate) fn account_delete_post(
    mut req: Request,
    cfg: &Config,
    prefs: &mut AccountPrefs,
    lang: Lang,
    look: AccountLook,
    ids: &[String],
    uuid: Option<&str>,
    own: &AccountOwn<'_>,
    settings: &Settings,
    intake: Option<&str>,
    delete_path: &str,
    page: &str,
    rev: &str,
) {
    // (1) The door, and the console's strict policy: `same-origin` and nothing else.
    if !csrf_ok(
        header_value(&req, "Sec-Fetch-Site"),
        header_value(&req, "Origin"),
        header_value(&req, "Host"),
    ) {
        respond_account(
            req,
            403,
            prefs,
            t(lang, K::CsrfTitle),
            html! { p { (t(lang, K::CsrfBody)) } },
            look,
            false,
        );
        return;
    }
    let form = Form::parse(&read_body(&mut req));
    // Every page below carries its own `p.lede`, as the confirmation page does (§13.23 §4).
    prefs.page_lede = true;
    let typed = norm_email(form.get("confirm_email").trim());
    // (2) The page is the current one. The `rev` alone is not the check: a page rendered after
    // the row landed carries the current `rev` and no uuid, and is refused by the uuid.
    if form.get("rev").trim() != rev || form.get("uuid").trim() != uuid.unwrap_or("") {
        respond_account(
            req,
            409,
            prefs,
            t(lang, K::AccountDeleteChangedTitle),
            page_account_delete_outcome(
                html! { (t(lang, K::AccountDeleteChanged)) },
                None,
                vec![
                    pill_link(delete_path, t(lang, K::AccountDeleteStartAgain)),
                    back_link(lang, page),
                ],
            ),
            look,
            false,
        );
        return;
    }
    // (3) The typed address **is** the confirmation, so a typo is refused here, with the page
    // that asked for it kept on screen and the typo kept in the field, and nothing sent.
    if !ids.contains(&typed) {
        let refusal = Refusal::on("confirm_email", t(lang, K::AccountDeleteTypedWrong));
        respond_account(
            req,
            400,
            prefs,
            t(lang, K::AccountDeleteTitle),
            page_account_delete(
                lang,
                delete_path,
                page,
                rev,
                uuid,
                ids,
                own,
                &settings.audit_policy,
                &typed,
                Some(&refusal),
            ),
            look,
            false,
        );
        return;
    }
    // (4) The worker's bound, checked before the first call: nine addresses queued and a tenth
    // refused is a half-deleted account, which is the one outcome this page cannot explain.
    if ids.len() > DELETE_MAX_ADDRESSES {
        respond_account(
            req,
            400,
            prefs,
            t(lang, K::AccountDeleteNotDoneTitle),
            page_account_delete_outcome(
                html! { (t(lang, K::AccountDeleteTooMany)) },
                None,
                vec![back_link(lang, page)],
            ),
            look,
            false,
        );
        return;
    }
    // The intake, and the walk starts here. The path is dispatched only where an intake is
    // wired (§13.29 W2), so this is the same fact the `404` above already answered.
    let Some(origin) = intake else {
        respond_account(
            req,
            404,
            prefs,
            t(lang, K::NotFoundTitle),
            html! { p { (t(lang, K::NotFoundBody)) } },
            look,
            false,
        );
        return;
    };
    let agent = intake_agent(cfg);
    // (5) Every address is asked before any is posted.
    for id in ids {
        match intake_whoami(&agent, cfg, origin, id) {
            Whoami::Open => {}
            Whoami::Protected => {
                audit(
                    &format!("{typed} (self)"),
                    "delete-request",
                    "refused protected",
                );
                respond_account(
                    req,
                    403,
                    prefs,
                    t(lang, K::AccountDeleteNotDoneTitle),
                    page_account_delete_outcome(
                        html! { (t(lang, K::AccountDeleteProtected)) },
                        None,
                        vec![back_link(lang, page)],
                    ),
                    look,
                    false,
                );
                return;
            }
            who => {
                // No answer is a 504 and an unusable answer a 502, and both say the same thing:
                // nothing was deleted, and the caller can still sign in. Try again is the way
                // forward, because the confirmation page this link renders is still true.
                let (status, journal) = match who {
                    Whoami::NoAnswer => (504, "no answer"),
                    _ => (502, "refused no check"),
                };
                audit(&format!("{typed} (self)"), "delete-request", journal);
                respond_account(
                    req,
                    status,
                    prefs,
                    t(lang, K::AccountDeleteNotDoneTitle),
                    page_account_delete_outcome(
                        html! { (t(lang, K::AccountDeleteNoCheck)) },
                        None,
                        vec![
                            pill_link(delete_path, t(lang, K::AccountDeleteRetry)),
                            back_link(lang, page),
                        ],
                    ),
                    look,
                    false,
                );
                return;
            }
        }
    }
    // (6) The row, ahead of the first `POST` (§13.29 W3 step 5).
    //
    // **Why the row goes first, and not after a `202`.** The worker runs `user show` and then
    // `user rm`, and a row that disappears between the two fails its whole run: the cursor is
    // kept, the owner is mailed, and every later deletion waits for the spool to change again
    // (W1). A row that is **already** gone when the record lands is the path its contract
    // tolerates: `show` finds nothing, the worker logs "not in the roster" and goes on. Removing
    // the row after the `202` races that by construction, however short our write is. The
    // person's half is the same fact seen from their side: the row goes with its keys and every
    // reference to it, so no credential that still works is left waiting on a queue nobody can
    // read, and `bb-auth-reload.path` hands the gate the new file as soon as this write lands.
    //
    // The lock ends at the commit, as every write in this program does (§13.13): what it owes is
    // that no other writer renames between this one's `rev` check and this one's rename, and the
    // intake walk that follows is a network call, which is the one thing never held across it.
    let mut row_gone = false;
    if let Some(uuid) = uuid {
        let writing = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let done = (|| -> Result<(), RowGone> {
            // `rev` **again**, under the lock. The check at (2) is a courtesy to a stale page:
            // between it and here a console save, an `bb-auth-adm` over SSH or this page's own
            // mint can land, and the bytes the person confirmed are the bytes this write replaces.
            let raw = std::fs::read_to_string(&cfg.access_path)
                .map_err(|e| RowGone::Failed(format!("read {}: {e}", cfg.access_path)))?;
            if form.get("rev").trim() != sha256_hex(&raw) {
                return Err(RowGone::Changed);
            }
            let (mut doc, _) = open_access_file(&cfg.access_path).map_err(RowGone::Failed)?;
            // The library's sweep, the same one `bb-auth-adm user rm` runs: the row, its keys,
            // every scope and group that named it, and an `excluded` entry **rewritten** to the
            // row's primary email rather than dropped, because dropping a veto lifts it and an
            // `authenticated` scope lets that identity walk straight back in.
            remove_user(&mut doc, uuid).map_err(|_| RowGone::Changed)?;
            AccessWrite::prepare(&doc)
                .map_err(RowGone::Failed)?
                .commit(&cfg.access_path)
                .map_err(RowGone::Failed)?;
            Ok(())
        })();
        drop(writing);
        match done {
            Ok(()) => {
                row_gone = true;
                audit(&format!("{typed} (self)"), "user rm", uuid);
            }
            Err(RowGone::Changed) => {
                // The page (2) renders, for the reason §13.30 §4 gives: to the person a file that
                // moved and a row an administrator took away are the same fact, "my account
                // changed", and one page for both is what keeps this form from reporting which
                // check fired. Nothing was written and nothing has been posted.
                respond_account(
                    req,
                    409,
                    prefs,
                    t(lang, K::AccountDeleteChangedTitle),
                    page_account_delete_outcome(
                        html! { (t(lang, K::AccountDeleteChanged)) },
                        None,
                        vec![
                            pill_link(delete_path, t(lang, K::AccountDeleteStartAgain)),
                            back_link(lang, page),
                        ],
                    ),
                    look,
                    false,
                );
                return;
            }
            Err(RowGone::Failed(msg)) => {
                // One journal line for the one effect that failed, carrying the library's sentence
                // (a path and an OS error, never a bearer), and a page that says only that the
                // save failed and signing in still works: the row stands, so that is true.
                audit(
                    &format!("{typed} (self)"),
                    "user rm",
                    &format!("failed: {msg}"),
                );
                respond_account(
                    req,
                    500,
                    prefs,
                    t(lang, K::AccountDeleteNotDoneTitle),
                    page_account_delete_outcome(
                        html! { (t(lang, K::AccountDeleteWriteFailed)) },
                        None,
                        vec![
                            pill_link(delete_path, t(lang, K::AccountDeleteStartAgain)),
                            back_link(lang, page),
                        ],
                    ),
                    look,
                    false,
                );
                return;
            }
        }
    }
    // (7) The records, one address per request, stopping at the first that is not accepted.
    //
    // A stop is one of three pages, and the two facts that choose it are what has already
    // **gone** and what has already been **queued** (§13.30 §4):
    //
    // - an address before this one was accepted: some of the sign-in accounts are queued, so
    //   the page says "some" and lists the addresses it cannot confirm, from this one on, for
    //   the administrator the person is sent to ask;
    // - the row went at (6): the keys and the named access are gone and these accounts are not
    //   queued, so the account is *only partly* deleted, and "your account was not deleted"
    //   would be false. The page leads with what did go (Nielsen 9);
    // - neither: nothing has gone, and a `403` here is the intake's protected list answering
    //   where `whoami` did not, which is the page §4 gives it.
    //
    // The actions are the same facts read as advice: a page that says something did go ends in
    // Sign out, because the cookie outlives the deletion and signing out is the one thing left
    // that is true; a page that says nothing went offers the retry and the way back. The retry
    // works for a caller whose row is gone because the confirmation page it renders is the
    // stranger's variant, and the walk over the header's addresses is the same walk.
    for (i, id) in ids.iter().enumerate() {
        let outcome = intake_delete(&agent, cfg, origin, id);
        if matches!(outcome, Queued::Accepted) {
            continue;
        }
        let refused = match outcome {
            Queued::Refused(status) => Some(status),
            _ => None,
        };
        // One journal line for the effect that stopped the walk: the status the intake gave,
        // and nothing of the credential this call carries (§13.29 W7).
        audit(
            &format!("{typed} (self)"),
            "delete-request",
            &match refused {
                Some(status) => format!("refused {status}"),
                None => "no answer".to_string(),
            },
        );
        let unanswered = refused.is_none();
        let retry = pill_link(delete_path, t(lang, K::AccountDeleteRetry));
        // The row went, so the account is only partly deleted, and a row that had two addresses
        // says so: the retry reaches the one this session signs in with, and the rest of what
        // the row held is an administrator's to take (§13.30 §4).
        if i > 0 {
            // Some are queued and this one is not, so the page cannot speak of the accounts as
            // a whole, and the addresses it cannot confirm are the fact the person has no way
            // to check. Not "not queued": an unanswered request may have been queued.
            let unconfirmed: Vec<&str> = ids[i..].iter().map(String::as_str).collect();
            respond_account(
                req,
                if unanswered { 504 } else { 502 },
                prefs,
                t(lang, K::AccountDeletePartialTitle),
                page_account_delete_outcome(
                    html! {
                        @if row_gone {
                            (t(lang, K::AccountDeleteNowGone)) " "
                        }
                        (t(lang, K::AccountDeleteSome)) " "
                        (t(lang, K::AccountDeleteRetryOneAddress))
                    },
                    Some(html! {
                        (t(lang, K::AccountDeleteUnconfirmedLead)) " " (code_list(&unconfirmed))
                    }),
                    with_sign_out(prefs, lang, retry),
                ),
                look,
                false,
            );
            return;
        }
        if row_gone {
            respond_account(
                req,
                if unanswered { 504 } else { 502 },
                prefs,
                t(
                    lang,
                    if unanswered {
                        K::AccountDeleteUnsureTitle
                    } else {
                        K::AccountDeletePartialTitle
                    },
                ),
                page_account_delete_outcome(
                    html! {
                        (t(lang, K::AccountDeleteNowGone)) " "
                        (t(lang, if unanswered {
                            K::AccountDeleteMaybeQueued
                        } else {
                            K::AccountDeleteNotQueued
                        }))
                        @if ids.len() > 1 {
                            " " (t(lang, K::AccountDeleteRetryOneAddress))
                        }
                    },
                    None,
                    with_sign_out(prefs, lang, retry),
                ),
                look,
                false,
            );
            return;
        }
        if refused == Some(403) {
            // Nothing has changed for a caller with no row, so the protected page is true, and
            // it names no list, no address and no rule (§13.30 §7).
            respond_account(
                req,
                403,
                prefs,
                t(lang, K::AccountDeleteNotDoneTitle),
                page_account_delete_outcome(
                    html! { (t(lang, K::AccountDeleteProtected)) },
                    None,
                    vec![back_link(lang, page)],
                ),
                look,
                false,
            );
            return;
        }
        // Nothing went, so the account stands, signing in still works, and the retry renders a
        // confirmation page that is still true.
        respond_account(
            req,
            if unanswered { 504 } else { 502 },
            prefs,
            t(
                lang,
                if unanswered {
                    K::AccountDeleteUnsureTitle
                } else {
                    K::AccountDeleteNotDoneTitle
                },
            ),
            page_account_delete_outcome(
                html! {
                    (t(lang, if unanswered {
                        K::AccountDeleteMaybeQueued
                    } else {
                        K::AccountDeleteNotQueued
                    }))
                },
                None,
                vec![retry, back_link(lang, page)],
            ),
            look,
            false,
        );
        // The walk stops at the answer: a `POST` after a refusal would queue an address behind
        // one the intake has just refused, which is the half-state §13.29 W3 exists to avoid.
        return;
    }
    // (8) Every address is queued, which is all this program knows (§13.29 W6): the worker's
    // outcome is not readable from here, so the answer says "being deleted" and never
    // "deleted". Where the operator named a logout URL this is also the one outcome that
    // signs the browser out, through the gate's logout (§13.32 §1): by the time a page is
    // drawn the person is signed out, so nothing here ever asks them to sign out. Every
    // partial outcome above keeps its page and its Sign out pill, because its "Try again"
    // is a walk over the header's addresses and that walk needs the session. With no logout
    // URL there is nowhere to send the browser, so the done page stays, and its last
    // sentence says what the person can do themselves.
    audit(
        &format!("{typed} (self)"),
        "delete-request",
        &format!("{} queued", ids.len()),
    );
    if let Some(url) = prefs.logout {
        respond_redirect(req, &delete_logout_location(url));
        return;
    }
    respond_account(
        req,
        200,
        prefs,
        t(lang, K::AccountDeleteQueuedTitle),
        page_account_delete_outcome(
            // The row's half first, and only where the row went: it is the part that is already
            // true, while the queue is a promise about a process this page cannot see (§13.30 §4).
            html! {
                @if row_gone {
                    (t(lang, K::AccountDeleteNowGone)) " "
                }
                (t(lang, K::AccountDeleteQueued)) " " (t(lang, K::AccountDeletedClose))
            },
            None,
            // No pill: the page's one action used to be the sign out, and §13.32 §1 moved
            // that action into the redirect this branch does not answer with. The bar's
            // account menu is the sign out that is left.
            vec![],
        ),
        look,
        false,
    );
}
