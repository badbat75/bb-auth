use crate::*;

/// The most keys this page mints onto one roster row. The administrator's CLI has no such
/// bound, and does not need one: an operator typing `bb-auth-adm key add` over SSH is one
/// person doing a counted thing. This form is reachable by every signed-in identity on the
/// estate, and a row accumulating keys is a row whose credentials nobody can review.
pub(crate) const ACCOUNT_MAX_KEYS: usize = 10;

/// The shortest window a self-service mint may ask for, in seconds.
///
/// There is no longest. With "no expiry" among the five choices a ceiling protects nothing:
/// a key of 36500 days and a key that never expires are the same credential, and refusing the
/// first while offering the second is a rule with no reason, which is what the page's own
/// ceiling was. The grammar is the only limit, and it is a real one: `parse_duration` and
/// `key_expiry` use checked arithmetic and answer `None` on overflow. The floor stays, because
/// a key that expires in seconds is a key that does not work, and an `hours` value a
/// hand-written `POST` may bring is refused by it.
const ACCOUNT_KEY_MIN_SECS: u64 = 86_400;

/// Is `id` one this page will file? `[a-z0-9-]{1,32}`, which is the shape that stays readable
/// in a log line and in a `key rotate`, and is short enough to be the whole name of a thing.
fn account_key_id_ok(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Is `duration` a window this page will file? See [`ACCOUNT_KEY_MIN_SECS`]: the parse is the
/// library's, so `365d`, `8760h` and a bare `365` are all one year, and the floor is on the
/// seconds they mean, not on the spelling. No expiry passes too, because the page offers it.
fn account_key_window_ok(duration: &str) -> bool {
    match parse_duration(duration) {
        Some(Dur::Never) => true,
        Some(Dur::Secs(secs)) => secs >= ACCOUNT_KEY_MIN_SECS,
        None => false,
    }
}

/// The values the mint row shows. A fresh row opens on the one-year choice and "all scopes"; a
/// refused submission puts back exactly what was posted, so the person fixes the one thing wrong
/// instead of retyping the rest (WCAG 3.3.1 and 3.3.3).
pub(crate) struct NewKeyRow<'a> {
    id: &'a str,
    choice: &'a str,
    days: &'a str,
    /// The radio: `true` when "only these" is picked.
    some: bool,
    ticked: &'a [String],
    pub(crate) err: Option<&'a Refusal>,
}

impl NewKeyRow<'_> {
    /// The row as `GET <prefix>/keys/new` opens it.
    pub(crate) const OPEN: NewKeyRow<'static> = NewKeyRow {
        id: "",
        choice: "365d",
        days: "",
        some: false,
        ticked: &[],
        err: None,
    };
}

/// The mint row's name field: [`text_field_with`]'s markup, plus the browser's own constraints.
///
/// [`text_field_with`] is the one field both surfaces build from, and the console's key form puts
/// no constraint on its id: an operator typing `bb-auth-adm key add` over SSH is one person doing a
/// counted thing, and the library checks the grammar anyway. This form is reachable by every
/// signed-in identity on the estate, so the grammar goes on the field as well, and `autofocus`
/// puts the person in the field the `+` asked for. All four are the browser's constraint
/// validation and need no script, which is what keeps this page inside the estate's no-JavaScript
/// rule; the server checks every one of them again.
///
/// The hint is the shape, spelled out, and it is shown on the open row. It is **omitted the
/// moment the field carries the refusal**: the refusal is a sentence that already says what is
/// allowed, in the reader's language, so the hint under it is one rule in two registers, and the
/// one that is not the reason for the refusal is the one to drop.
fn account_key_id_field(lang: Lang, value: &str, invalid: bool) -> Markup {
    // The shape, spelled out, on the open row only: see the doc comment.
    let hints: Vec<&str> = if invalid {
        Vec::new()
    } else {
        vec![t(lang, K::AccountKeyIdHint)]
    };
    text_field_with(
        t(lang, K::KeyColName),
        "id",
        value,
        "laptop",
        &hints,
        invalid,
        FieldOpts {
            autofocus: true,
            required: true,
            maxlength: Some(32),
            pattern: Some("[a-z0-9-]{1,32}"),
            ..FieldOpts::default()
        },
    )
}

/// The mint row: the console's `form.edit` inside one cell that spans the table.
///
/// §13.16. A `form` may not wrap a table row, but it may sit inside a cell, so the row that mints
/// is in the table the person is looking at and no `form` attribute is needed anywhere.
///
/// Two of the console's fields are deliberately absent. There is no **owner** field: the owner is
/// the person asking, read from the identity header nginx wrote, and a field that chose the row
/// would let any signed-in person mint a credential on anybody's account. There is no `released`:
/// a key's issue date is a fact about a secret being created now, and the handler stamps it.
///
/// The checkboxes are [`bb_auth_core::Access::key_scopes_for`], so the pairs on offer are exactly
/// the pairs the handler accepts, and each checkbox's value is the `application/scope` pair the
/// file stores. A hand-written form can still name a pair that is not on the list, and the handler
/// answers that with a `400`: a pair the gate would refuse mints a key that fails on its very
/// first request. That list is **empty** for a caller whose scopes take `login` only, and then the
/// whole block is absent, a hidden `restrict=all` in its place: a lone checked radio beside a
/// "Scopes" heading is a choice of one, a control that can only be answered wrong, and
/// `restrict=some` with no pair writes a key narrowed to nothing.
///
/// No URL appears. The restriction is named by application and scope, never by the pattern behind
/// it (§13.6): a URL from the file is information about the estate, and this page is about the
/// person.
pub(crate) fn account_key_row(
    lang: Lang,
    keys_path: &str,
    rev: &str,
    cancel: &str,
    scopes: &[(&str, &str)],
    row: &NewKeyRow,
) -> Markup {
    let about = |name| row.err.is_some_and(|e| e.is(name));
    // Grouped by application, in the order `key_scopes_for` yields them, which is file order.
    let mut apps: Vec<(&str, Vec<&str>)> = Vec::new();
    for (app, scope) in scopes {
        match apps.iter_mut().find(|(name, _)| *name == *app) {
            Some((_, names)) => names.push(*scope),
            None => apps.push((*app, vec![*scope])),
        }
    }
    let fields = html! {
        (account_key_id_field(lang, row.id, about("id")))
        (duration_choice(
            lang,
            t(lang, K::KeyColExpires),
            row.choice,
            row.days,
            // This box takes a number and nothing else, so the placeholder can name the unit;
            // the console's takes `12h` too and keeps its hint line instead (§13.17).
            Some(t(lang, K::DurDaysHint)),
            None,
            about("duration"),
        ))
        @if apps.is_empty() {
            // Nothing to narrow to, so there is no choice to show, not even a checked radio
            // beside a "Scopes" heading: a choice of one is a control that can only be
            // answered wrong. The restriction the owner reaches is carried unseen, so the
            // handler is unchanged and still refuses a request that chose nothing.
            input type="hidden" name="restrict" value="all";
        } @else {
            div {
                span class="lbl" { (t(lang, K::Scopes)) }
                label class="radio" {
                    input type="radio" name="restrict" value="all" checked[!row.some];
                    span { (t(lang, K::KeyScopesAll)) }
                }
                // The narrowing choice, and only when there is something to narrow **to**.
                label class="radio" {
                    input type="radio" name="restrict" value="some" checked[row.some];
                    span { (t(lang, K::KeyScopesOnly)) ":" }
                }
                @for (app, names) in apps {
                    div {
                        span class="lbl" { code { (app) } }
                        @for name in names {
                            @let pair = format!("{app}/{name}");
                            label class="radio" {
                                input type="checkbox" name="scope" value=(pair)
                                      checked[row.ticked.contains(&pair)];
                                span { code { (name) } }
                            }
                        }
                    }
                }
            }
        }
    };
    html! {
        td colspan="4" {
            (form_shell_at(
                keys_path,
                rev,
                cancel,
                t(lang, K::Cancel),
                row.err,
                fields,
                t(lang, K::AccountKeyCreate),
                false,
            ))
        }
    }
}

/// A key's restriction cell, and its table row: [`url_list_marked`] and [`expiry_markup`], the
/// functions the console's person page calls, so the two surfaces answer "what does this key
/// reach" and "when does it die" from one place.
///
/// A pair the owner no longer reaches is still listed, because the key still carries it, and is
/// marked in words (WCAG 1.4.1): a key narrowed to a scope its owner was removed from is the case
/// where the person most needs to know it reaches less than it says.
///
/// The two row actions are the console's: [`act`]'s plain pill for a rotate and [`act_rm`]'s
/// destructive one for a revoke, each a link to a `GET` page that changes nothing, so a crawler
/// or a prefetch cannot rotate or revoke a credential. They are written out here rather than
/// called because those two take a console `View`. The name carries the id because ten links all
/// called "Revoke key" are ten identical entries in a reader's list of links (WCAG 2.4.6).
pub(crate) fn account_key_line(
    lang: Lang,
    k: &ApiKeySpec,
    mintable: &[(&str, &str)],
    keys_path: &str,
    n: u64,
) -> Markup {
    let id = k.id.trim();
    let query: String = form_urlencoded::byte_serialize(id.as_bytes()).collect();
    let remove = format!("{} {id}", t(lang, K::AccountKeyRemove));
    html! {
        tr {
            td class="mono" data-label=(t(lang, K::KeyColName)) { (id) }
            td data-label=(t(lang, K::Scopes)) {
                (url_list_marked(lang, k.scopes.as_ref(), t(lang, K::KeyScopesAll), |u| {
                    let reached = mintable.iter().any(|(a, s)| format!("{a}/{s}") == u);
                    (!reached).then(|| t(lang, K::KeyScopeGone))
                }))
            }
            td data-label=(t(lang, K::ColExpiry)) { (expiry_markup(lang, &expiry_of(k, n))) }
            td class="pills" {
                span class="pills" {
                    a class="pill" href=(format!("{keys_path}/rotate?id={query}"))
                      aria-label=(format!("{} {id}", t(lang, K::AccountKeyRotate))) {
                        (t(lang, K::Rotate))
                    }
                    " "
                    a class="pill rm ico" href=(format!("{keys_path}/remove?id={query}"))
                      title=(remove) {
                        svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                            path d="M6 6l12 12M18 6L6 18" {}
                        }
                        span class="vh" { (remove) }
                    }
                }
            }
        }
    }
}

/// Which key mutation a `POST` under the keys prefix is asking for.
///
/// A closed set, because all three stand behind the **same** doors (the same-origin check, the
/// row the identity header resolves to, the write lock, the file's fingerprint) and differ only
/// in what the library is asked to do once those doors are open. Three handlers that each
/// re-checked the doors are three chances for one of them to be missing from one of them, and a
/// `remove` that skipped the fingerprint is a silent clobber of somebody else's edit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccountKeyOp {
    Mint,
    Rotate,
    Remove,
}

impl AccountKeyOp {
    /// The word this operation is named by: the verb the form's own button used, so the page a
    /// refusal lands on is headed by the word the reader just clicked, and the confirmation a
    /// row's link opens is headed by the word the reader is about to click (§13.17).
    pub(crate) fn title(self) -> K {
        match self {
            AccountKeyOp::Mint => K::AccountKeyAdd,
            AccountKeyOp::Rotate => K::AccountKeyRotate,
            AccountKeyOp::Remove => K::AccountKeyRemove,
        }
    }
}

/// Answer a key mutation: `POST <prefix>/keys`, `…/keys/rotate` or `…/keys/remove`.
///
/// The order is the console's, for the console's reasons ([`mutate`]), and it is the order that
/// makes "nothing was written" a fact on every refusal path rather than a hope:
///
/// 1. the same-origin door, before the body is read, because a mint hands out a credential, a
///    rotate hands out a new one and a revoke destroys one, and a form on somebody else's page
///    doing any of those to a signed-in person is the exact attack this door exists for;
/// 2. the row, which the identity header resolves to and no form field may choose;
/// 3. [`WRITE_LOCK`], then the file's current bytes against the form's `rev`, then
///    [`open_access_file`], which refuses to start editing from bytes the gate would reject.
///    The guard **ends at the commit**, before anything is rendered or sent, as `mutate`'s does
///    (docs/ARCHITECTURE.md §13.13): what the lock owes is that no other writer in this process
///    renames between this one's `rev` check and this one's rename, and a response's send is
///    none of that;
/// 4. the mutation's own checks, before anything is written, because a secret created for a
///    refusal is a secret handed out for nothing;
/// 5. [`add_api_key`] / [`rotate_api_key`] / [`remove_api_key`] through [`AccessWrite`], the
///    library's own door, and for the two that mint, the bearer opened against the receipt of
///    the completed write.
///
/// The refusal pages are short: this page's caller has no administrator in the room, so each
/// message names what to write instead, and the way back is the page they came from.
#[allow(clippy::too_many_arguments)]
pub(crate) fn account_key_post(
    mut req: Request,
    cfg: &Config,
    prefs: &AccountPrefs,
    lang: Lang,
    look: AccountLook,
    uuid: Option<&str>,
    op: AccountKeyOp,
    settings: &Settings,
    ids: &[String],
    keys_path: &str,
    profile_path: &str,
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
    // (2) A key is filed under a uuid, so a caller the file has no row for has no account to
    // mint into. The page says the same thing to them (§13.6); a hand-crafted `POST` gets the
    // same answer, and the vetoed caller never reaches here: the veto is answered above.
    let Some(owner) = uuid else {
        respond_account(
            req,
            403,
            prefs,
            t(lang, K::AccountNoRowTitle),
            html! { p { (t(lang, K::AccountNoRowBody)) } },
            look,
            false,
        );
        return;
    };
    let form = Form::parse(&read_body(&mut req));
    // (3) Serialized against every other write in this process, exactly as the console's
    // `mutate` is: two workers, one person with two tabs, and a loser whose mint vanishes
    // behind a success page is the silent clobber the `rev` cannot see. The guard is named so
    // it can be **released at the commit** below, and every refusal path that returns from here
    // drops it on the way out, so the lock is never held across a response.
    let writing = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let raw = match std::fs::read_to_string(&cfg.access_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            let msg = format!("read {}: {e}", cfg.access_path);
            respond_account(
                req,
                500,
                prefs,
                t(lang, K::FileErrorTitle),
                html! { p { (msg) } },
                look,
                false,
            );
            return;
        }
    };
    if form.get("rev").trim() != sha256_hex(&raw) {
        // The console's `409` in this page's shell. The advice is the console's too, and it is
        // the honest one: nothing was written, and the file says something the form never saw.
        respond_account(
            req,
            409,
            prefs,
            t(lang, K::ConflictTitle),
            html! {
                p { (t(lang, K::ConflictBody)) }
                p { (t(lang, K::ConflictRecover)) }
                p { a href=(prefs.page) { "← " (t(lang, K::ConflictBack)) } }
            },
            look,
            false,
        );
        return;
    }
    let (mut doc, access) = match open_access_file(&cfg.access_path) {
        Ok(pair) => pair,
        Err(e) => {
            respond_account(
                req,
                500,
                prefs,
                t(lang, K::FileErrorTitle),
                html! { p { (e) } },
                look,
                false,
            );
            return;
        }
    };
    let id = form.get("id").trim().to_string();
    // (4) then (5), in one closure so that "every path out of here wrote nothing" is a fact
    // about the shape of the code: the only `Ok` is the one that has committed. The payload is
    // `Some(bearer)` for the two mutations that mint a secret and `None` for the one that only
    // takes one away.
    let done = (|| -> Result<Option<String>, Refusal> {
        if op == AccountKeyOp::Mint {
            let duration =
                duration_from_form(&form).map_err(|k| Refusal::on("duration", t(lang, k)))?;
            let restrict = form.get("restrict").trim().to_string();
            let pairs = form.all("scope");
            // Each refusal names the field it is about, because the row it re-renders marks that
            // field and not the other, and says one fact: the sentence a person reads has to be
            // the sentence about what they got wrong.
            if !account_key_id_ok(&id) {
                return Err(Refusal::on("id", t(lang, K::AccountKeyIdBad)));
            }
            if !account_key_window_ok(&duration) {
                return Err(Refusal::on("duration", t(lang, K::AccountKeyTooShort)));
            }
            // The row's keys, read off the **document**, not the compiled table: the bound is on
            // how many credentials one identity carries, and a key whose hash the gate skipped is
            // still a row a person has to review.
            let mine = user_pos(&doc, owner).map_or(&[][..], |i| &doc.users[i].api_keys);
            // The bound counts the administrator's keys too: it is a bound on the row, not on
            // how many mints this page handed out.
            if mine.len() >= ACCOUNT_MAX_KEYS {
                return Err(t(lang, K::AccountKeyFull).to_string().into());
            }
            // An id is how a key is named back (in the journal line, and in `bb-auth-adm key
            // rotate`), so two keys called `laptop` on one row is one name naming two secrets.
            if mine.iter().any(|k| k.id.trim() == id) {
                return Err(Refusal::on("id", t(lang, K::AccountKeyDup)));
            }
            // `all` writes **no** `scopes` field, which the gate reads as the owner's whole reach.
            // `some` writes the submitted pairs sorted: the submitted order is a browser's, and
            // one canonical spelling is what makes a restriction a comparison, not a string match.
            let scopes = match restrict.as_str() {
                // Ticks beside "all scopes" are a choice the person thinks they made: dropping
                // them would file the widest key the person did not ask for. No field is marked,
                // since the contradiction is between two controls and not inside one.
                "all" if !pairs.is_empty() => {
                    return Err(t(lang, K::KeyScopesWithoutOnly).to_string().into());
                }
                "all" => None,
                "some" => {
                    let allowed = access.key_scopes_for(owner);
                    for pair in &pairs {
                        if !allowed
                            .iter()
                            .any(|(a, s)| format!("{}/{}", a.name, s.name) == *pair)
                        {
                            return Err(t(lang, K::AccountKeyUnknownScope).to_string().into());
                        }
                    }
                    let mut sorted = pairs.clone();
                    sorted.sort();
                    Some(sorted)
                }
                // Neither of the two the form can send. Refused rather than read as `all`: a key
                // with no restriction is the widest credential this page mints, and a request
                // that did not choose it must not get it by default. No field is marked: the
                // request chose nothing, so the fix is to name the two it could choose.
                _ => return Err(t(lang, K::KeyScopesChoose).to_string().into()),
            };
            let sealed = add_api_key(
                &mut doc,
                owner,
                ApiKeySpec {
                    id: id.clone(),
                    // Today, and not a field: a key's issue date is a fact about a secret that is
                    // being created right now.
                    released: format_date(now()),
                    duration: duration.clone(),
                    scopes,
                    ..Default::default()
                },
            )?;
            let written = AccessWrite::prepare(&doc)?.commit(&cfg.access_path)?;
            // The acting identity, marked as acting for itself, and the key's id. No bearer and
            // no hash: the line says which credential exists, and the file says anything more.
            audit(&format!("{owner} (self)"), "key add", &id);
            Ok(Some(sealed.reveal(&written)))
        } else {
            // The two mutations that act on a key the caller already has. The id is **not**
            // validated against the mint's grammar: a rotate naming an id this row does not carry
            // is refused by the library's own lookup, and the page answers every miss with the
            // same sentence, so a probe for which ids exist on the estate gets one answer for all
            // of them. The library resolves the row from the caller's uuid, so a key filed under
            // another person is not found at all: that is the ownership check, and it is the
            // library's, so the console and this page cannot answer it differently.
            let sealed = match op {
                AccountKeyOp::Rotate => rotate_api_key(&mut doc, owner, &id)
                    .map(Some)
                    .map_err(|_| t(lang, K::AccountKeyNotYours).to_string())?,
                AccountKeyOp::Remove => remove_api_key(&mut doc, owner, &id)
                    .map(|_| None)
                    .map_err(|_| t(lang, K::AccountKeyNotYours).to_string())?,
                AccountKeyOp::Mint => None,
            };
            let written = AccessWrite::prepare(&doc)?.commit(&cfg.access_path)?;
            audit(
                &format!("{owner} (self)"),
                if op == AccountKeyOp::Rotate {
                    "key rotate"
                } else {
                    "key remove"
                },
                &id,
            );
            // A rotate mints a new secret, so it comes back sealed like a mint does and is opened
            // against this write's receipt; a revoke mints nothing, so there is nothing to reveal.
            Ok(sealed.map(|sealed| sealed.reveal(&written)))
        }
    })();
    // The lock ends here, at the commit, and not at the response (§13.13): what it owes is that
    // no other writer renames between this one's `rev` check and this one's rename, and the
    // reveal page's send is nothing to that. Holding it across the write to the socket couples
    // every other writer's wait to one response.
    drop(writing);
    // The key's id rides in the title, because the shell renders the title as the page's one
    // heading: "API keys · phone" says which secret this is, which is the fact a person with two
    // browser tabs open needs in front of them.
    match done {
        // A mint and a rotate answer `200` directly, and that is why they are the two mutations
        // here that are not POST-redirect-GET: the bearer cannot ride a redirect, because a
        // `Location:` is a URL and a URL is a credential in a proxy log. The page that shows it
        // once has to be the response to the `POST`, and a reload of that page re-sends the
        // `POST`: the same price the console's mint page pays, for the same reason. It is also
        // the one response under this prefix that carries a script (§13.14), so it is the one
        // that passes `reveal`: a `400` here mints nothing, and a `409` has no key to copy.
        Ok(Some(bearer)) => respond_account(
            req,
            200,
            prefs,
            &format!("{} · {}", t(lang, K::AccountKeys), id),
            page_account_minted(lang, prefs.page, &bearer),
            look,
            true,
        ),
        // A revoke mints nothing, so it follows the estate's rule and answers `303` to the page
        // it came from. No `?msg=`: the key is gone from the list, and that is the confirmation.
        Ok(None) => respond_redirect(req, prefs.page),
        // A refused mint answers with the page and its row still open: the values as posted,
        // the sentence in the console's error box, and the field it is about marked (§13.16).
        Err(refusal) if op == AccountKeyOp::Mint => {
            let rev = sha256_hex(&raw);
            let own = account_own(
                &doc,
                &access,
                settings,
                &req,
                ids,
                uuid,
                keys_path,
                &rev,
                prefs.page,
                profile_path,
            );
            let ticked = form.all("scope");
            let row = NewKeyRow {
                id: &id,
                choice: form.get("duration").trim(),
                days: form.get("days").trim(),
                some: form.get("restrict").trim() == "some",
                ticked: &ticked,
                err: Some(&refusal),
            };
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountTitle),
                page_account(lang, ids, uuid, &own, Some(&row), None),
                look,
                false,
            );
        }
        Err(refusal) => respond_account(
            req,
            400,
            prefs,
            t(lang, op.title()),
            html! {
                div class="err" { (refusal.msg) }
                p { a href=(prefs.page) { "← " (t(lang, K::Back)) } }
            },
            look,
            false,
        ),
    }
}
