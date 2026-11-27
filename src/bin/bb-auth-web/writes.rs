use crate::*;

/// The `denied` form — one address, and the veto that outranks every grant.
#[derive(Default)]
pub(crate) struct DenyForm {
    email: String,
}

impl DenyForm {
    pub(crate) fn read(f: &Form) -> DenyForm {
        DenyForm {
            email: f.get("email").to_string(),
        }
    }
}

pub(crate) fn page_deny_form(v: &View, f: &DenyForm, err: Option<&Refusal>) -> Markup {
    let about = |name| err.is_some_and(|e| e.is(name));
    html! {
        h1 { (v.t(K::Denied)) " · " (v.t(K::Add)) }
        p class="lede" { (v.t(K::DeniedIntro)) }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field("email", "email", &f.email, "spammer@x.com", None, about("email")))
            }, v.t(K::Create), false))
        }
    }
}

/// The block that reveals a freshly minted bearer, rendered by **both** surfaces: the console's
/// [`page_minted`] and the self-service page's [`page_account_minted`] (§13.14).
///
/// One function because the two must not drift. The key, the button and the script are the same
/// bytes on the console and on `/account/`; only the words around them are each page's own.
///
/// The `code id="bearer"` carries **the key and nothing else**, with no whitespace around it,
/// because that text is what a click selects (`user-select: all` in `admin.css`) and what the
/// button copies. The button is server-rendered `hidden`: a browser running no code must show no
/// control that does nothing, and [`COPY_SCRIPT`] is the only thing that shows it, so the script
/// goes last, after the three elements it looks up exist, and needs no load event. `type="button"`
/// because this block sits where a form may later be wrapped around it, and a button that submits
/// one is a mutation on a click.
///
/// The button is the estate's shared icon component, `pill ico` (§13.17), so its size, its
/// 24 by 24 target and the way a glyph is painted all live in `base.css` with every other icon
/// control, and this block keeps only the rule that is its own: the glyph swap on `data-state`.
/// Its name is a `span.vh` of translated words inside it, repeated as `title`, and **not** an
/// `aria-label`: one naming mechanism for every icon in the estate, because the header's
/// Preferences trigger is a `summary`, which carries no reliable `aria-label` while text content
/// is read by every reader. The two glyphs are inline geometry, `aria-hidden` and `focusable`
/// false, so the shape is out of the accessibility tree and out of the tab order, and they name
/// no colour, which keeps `THEME_CSS` the only place one is defined. The word a click writes goes
/// to the `role="status"` span beside the icon, empty as served, so the icon stays an icon and
/// the word is announced to a reader.
///
/// The bearer is in **exactly one place** in the response: the text of this `code`. The script is
/// a compile-time constant and reads the key from the DOM at click time, and the button's two
/// data attributes carry only translated text, so the key is in no script, no attribute, no URL
/// and no header. The hint below the panel spells the word `Bearer` in a `code` of its own: that
/// is a word somebody types, not the credential, and it is the reason the hint sits **outside**
/// the panel. Inside `.secret` a `code` is the key's block chip (`admin.css`), so a second one
/// there would render as a second box the size of the secret.
pub(crate) fn bearer_reveal(lang: Lang, bearer: &str) -> Markup {
    let name = t(lang, K::CopyKey);
    html! {
        div class="secret" {
            div { strong { (t(lang, K::BearerHeading)) } }
            p { (t(lang, K::BearerOnce)) }
            code id="bearer" { (bearer) }
            // `hidden="hidden"`: the serialised form of the boolean attribute, which is what
            // `admin.css`'s `.secret button[hidden]` pins shut against an operator stylesheet
            // that gives `button` a `display` of its own.
            button type="button" id="bearer-copy" class="pill ico" hidden="hidden" title=(name)
                data-done=(t(lang, K::CopyDone)) data-failed=(t(lang, K::CopyFailed)) {
                // Two overlapping rounded squares: the sheet in front, and the one behind it.
                svg class="i-copy" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                    rect x="9" y="9" width="12" height="12" rx="2" {}
                    path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" {}
                }
                // The check, shown by the state the click stamps on the button.
                svg class="i-done" viewBox="0 0 24 24" aria-hidden="true" focusable="false" {
                    path d="M20 6 9 17l-5-5" {}
                }
                span class="vh" { (name) }
            }
            span id="bearer-copy-status" class="copy-status" role="status" {}
            script { (PreEscaped(COPY_SCRIPT)) }
        }
        // The word is an element, so the sentence is two translated halves around it, and the
        // word itself is not translated: it is what the person types.
        p class="hint" {
            (t(lang, K::BearerHintLead)) " " code { "Bearer" } (t(lang, K::BearerHintTail))
        }
    }
}

/// The page a mint answers with — and the one place a `bbk_` bearer is ever rendered.
///
/// Rendered **directly**, not after a redirect: a `303` would put the result behind a fresh
/// `GET` that has no bearer to show, and the bearer exists nowhere else — the file keeps
/// only its sha256. It is not logged and never travels in a URL.
///
/// The key itself, the copy button and the script are [`bearer_reveal`], shared with the
/// self-service page so the two surfaces cannot answer the same moment differently.
pub(crate) fn page_minted(
    v: &View,
    owner_uuid: &str,
    owner_label: &str,
    id: &str,
    bearer: &str,
) -> Markup {
    html! {
        h1 { (owner_label) " · api_keys · " (id) }
        (bearer_reveal(v.lang, bearer))
        p { (back(v, &Route::User(owner_uuid.to_string()))) }
    }
}

/// The `409`: the file moved under the form. Nothing was written, and the way out is a
/// fresh read of what the file says now — with a pointer at the browser's Back button,
/// which (no page here runs a script **on load**: the one script this program emits,
/// [`COPY_SCRIPT`], is the bearer reveal's copy button, wired to a click, so nothing
/// disturbs the bfcache) still holds the form exactly as it was filled in.
fn page_conflict(v: &View) -> Markup {
    // A `POST`-only route has no form to reload, so it goes back to its section.
    let back = match &v.at {
        Route::ScopeMove(..) => v.at.parent(),
        other => other.clone(),
    };
    html! {
        h1 { (v.t(K::ConflictTitle)) }
        div class="panel warn" {
            p { (v.t(K::ConflictBody)) }
            p { (v.t(K::ConflictRecover)) }
            p { a href=(v.href(&back)) { "← " (v.t(K::ConflictBack)) } }
        }
    }
}

/// The `409` for the two routes that **reveal a bearer**: the `rev` is stale *and* the key in
/// question exists, which is what a reload of the reveal page looks like from here, the reveal
/// being the direct `POST` response ([`page_minted`]).
///
/// The generic [`page_conflict`] is wrong twice on these paths. The "someone else" who moved
/// the file was this administrator's own submit; and "make the change again" would mint a
/// second key, or, on a rotation, destroy the bearer that was just shown and produce this page
/// again, so each recovery attempt would undo the previous one.
///
/// `rotated` picks which of the two happened, because the difference matters to the person
/// reading it: after a mint the offer of a rotation is the answer to a lost bearer, and after
/// a rotation it is the thing not to do twice. There is deliberately no Back-button hint on
/// either: the typed input is not worth recovering.
pub(crate) fn page_mint_conflict(v: &View, owner: &str, id: &str, rotated: bool) -> Markup {
    let owner = norm_email(owner);
    let (title, body) = if rotated {
        (K::RotateConflictTitle, K::RotateConflictBody)
    } else {
        (K::MintConflictTitle, K::MintConflictBody)
    };
    html! {
        h1 { (v.t(title)) }
        div class="panel warn" {
            p { code { (owner) } " · api_keys · " code { (id) } }
            p { (v.t(body)) }
            p { (v.t(K::MintConflictLost)) }
            p class="pills" {
                @if !rotated {
                    a class="pill"
                      href=(v.href(&Route::KeyRotate(owner.clone(), id.to_string()))) {
                        (v.t(K::MintConflictRotate))
                    }
                }
                (back(v, &Route::User(owner.clone())))
            }
        }
    }
}

/// A page that is only a message: the `401`, the `403`, the `404`, the `405` and the
/// broken-file page. Content only — the caller wraps it in [`shell`], as it does any page.
/// `kind` styles the panel the same way [`tag`] styles a label (`"bad"`, `"warn"`, `"ok"`,
/// or `""` for a neutral one); every call site today is a refusal, so every one passes
/// `"bad"`.
pub(crate) fn notice(kind: &str, title: &str, body: Markup) -> Markup {
    html! {
        h1 { (title) }
        div class=(format!("panel {kind}")) { (body) }
    }
}

/// The page for an access file the gate would refuse. The library's message goes out
/// **verbatim** — it is the same sentence `bb-auth --check-access` and a failed startup
/// print, and an operator who can match those three is an operator who can fix the file.
pub(crate) fn page_file_error(v: &View, err: &str) -> Markup {
    notice(
        "bad",
        v.t(K::FileErrorTitle),
        html! {
            p class="mono bad" { (err) }
            p class="muted" { (v.t(K::FileErrorHint)) }
        },
    )
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/// What a `POST` came to: either it happened, and the browser is sent to the page it
/// belongs to, or there is a page to render right here.
pub(crate) enum Outcome {
    /// POST-redirect-GET: `303` to this route with `?msg=`, so a reload cannot repeat it.
    Done(Route, Msg),
    /// A form re-rendered with a refusal, the `409`, or the one page that carries a freshly
    /// minted bearer and therefore cannot be behind a redirect.
    Page(u16, &'static str, Markup),
}

/// One line per successful mutation, on stderr, in the shape the gate logs in.
///
/// The acting administrator, the verb spelled as `bb-auth-adm` spells the equivalent
/// command, and the target's name. Never a bearer, never a `key_hash`, and no submitted
/// value beyond the name of the thing that changed — a scope full of URLs is in the file,
/// and the file keeps a `.bak` of what it was.
pub(crate) fn audit(admin: &str, verb: &str, target: &str) {
    eprintln!("[bb-auth-web] {admin}: {verb} {target}");
}

/// Check the edit with the gate's own parser, write it, and log the line.
///
/// [`AccessWrite`] is the only door: `prepare` compiles the exact bytes, `commit` writes the
/// bytes it compiled. An `Err` is the library's own sentence and means the file on disk was
/// not touched — which is what every error path in [`mutate`] relies on.
fn commit(v: &View, doc: &AccessFile, verb: &str, target: &str) -> Result<Written, String> {
    let written = AccessWrite::prepare(doc)?.commit(&v.cfg.access_path)?;
    audit(v.admin.unwrap_or("?"), verb, target);
    Ok(written)
}

/// Apply one `POST`.
///
/// Three things happen before any mutation is even looked at, and they are the load-bearing
/// order:
///
/// 1. the access file is re-read, and its sha256 must equal the `rev` the form carries —
///    otherwise the file moved under the form (a `bb-auth-adm` over SSH, another tab) and
///    this is a `409` that writes nothing;
/// 2. the document is opened with [`open_access_file`], which refuses to start from a file
///    the gate would reject — an edit must begin from a file that works;
/// 3. only then does the arm for this route run, and every one of them ends in [`commit`].
///
/// (1) and (2) are two reads of the same file, so a writer landing exactly between them is
/// still not seen. What the `rev` removes is the interesting case, the one measured in
/// minutes: a form loaded, read, thought about, and submitted onto a file that has since
/// moved.
///
/// **Within this process, the whole of it is serialized** by [`WRITE_LOCK`], and that half is
/// not something `rev` can do: two workers submitting at the same moment both read the same
/// bytes, both compute the same fingerprint, and both are entitled to write. There are two
/// workers, an administrator with two tabs is ordinary, and the loser's edit vanishing with a
/// success page is exactly the silent clobber the `rev` exists to prevent. The lock costs
/// nothing: this serves a handful of people and a save is a few milliseconds.
///
/// What it cannot cover is the other process. A concurrent `bb-auth-adm` over SSH is still
/// only guarded by the fingerprint, which is the window it has always had, and the write
/// itself is atomic on both sides.
///
/// A refusal — from a form's own check or from the library — re-renders the very form that
/// caused it, with the submitted values still in the fields and the message verbatim. On
/// every one of those paths nothing has been written: `prepare` fails before `commit`, and
/// `commit` is atomic.
///
/// The status for a refused submission is `400`, and a failed write is reported the same
/// way. From the browser's side the two say the same thing — nothing happened, here is the
/// sentence that says why — and the sentence itself is what distinguishes them.
pub(crate) fn mutate(v: &View, form: &Form) -> Outcome {
    // Held for the whole of the read-check-write, and released when this returns. A poisoned
    // lock is taken anyway: the panic it remembers happened in some other request's mutation,
    // and refusing every edit afterwards would be a worse answer than proceeding, since every
    // write is validated and atomic in its own right.
    let _writing = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Whichever file this route edits: the same `rev` field, checked against the file whose
    // fingerprint the form was given ([`edited_file`]).
    let path = edited_file(v.cfg, &v.at);
    // The settings page is titled with its own name, translated, on every response this route
    // gives: the settings file is a whole file in four sections, so `Route::title`'s
    // untranslated word ("settings") names no section an operator types, and a browser tab
    // that changes wording and language after a save is a page that seems to have moved
    // (§13.31 §10, WCAG 2.2 SC 2.4.2). The access-file pages keep the section word.
    let title = match &v.at {
        Route::Config => v.t(K::Config),
        _ => v.at.title(),
    };

    // (1) The file as it is right now, byte for byte.
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("read {path}: {e}");
            return Outcome::Page(500, title, page_file_error(v, &msg));
        }
    };
    if form.get("rev").trim() != sha256_hex(&raw) {
        // On the mint route, a stale rev is usually this administrator's own write: the
        // reveal page is the direct POST response (a bearer cannot survive a redirect), so
        // reloading it re-submits the mint. If the requested key now exists, say what
        // actually happened — the generic page's advice, "make the change again", would
        // mint a second key. A stale rev with no such key is a genuine concurrent edit,
        // and keeps the generic answer.
        // Both routes that REVEAL a bearer, not just the mint: a rotate answers with a page
        // for the same reason a mint does (a bearer cannot survive a redirect), so reloading
        // it re-submits with a stale rev too. The generic page's advice, "make the change
        // again", is actively destructive there: rotating a second time invalidates the
        // bearer just copied, and lands on the same page offering the same advice.
        let reveal = match &v.at {
            Route::KeyAdd(owner) => Some((owner, false)),
            Route::KeyRotate(owner, id) => Some((owner, !id.is_empty())),
            _ => None,
        };
        if let Some((owner, rotated)) = reveal {
            let id = match &v.at {
                Route::KeyRotate(_, id) => id.clone(),
                _ => form.get("id").trim().to_string(),
            };
            let exists = |d: &AccessFile| {
                user_pos(d, owner)
                    .is_some_and(|i| d.users[i].api_keys.iter().any(|k| k.id.trim() == id))
            };
            if !id.is_empty() && serde_json::from_str::<AccessFile>(&raw).is_ok_and(|d| exists(&d))
            {
                return Outcome::Page(409, title, page_mint_conflict(v, owner, &id, rotated));
            }
        }
        return Outcome::Page(409, title, page_conflict(v));
    }

    // The settings file's own mutation, and the only one that never touches the access file.
    // It sits here, between the concurrency check and the access file's own parse, because it
    // needs the first and has no use for the second.
    if v.at == Route::Config {
        let f = ConfigForm::read(form);
        let r = (|| -> Result<Option<Confirm>, Refusal> {
            let (mut doc, _) = open_settings_file(path)?;
            // What the file says now, kept before the form touches it: the five guarded
            // settings are compared against this and not against whatever the form mentions.
            let before = doc.gate.clone();
            f.apply(&mut doc, v.admin.unwrap_or_default(), v.lang)?;
            // A save that takes one of the five away is shown and held rather than written,
            // until a `POST` comes back carrying the token the shown page named. It is not an
            // error, so it is not a 400: nothing is wrong with the form, it is a step.
            if let Some(c) = Confirm::of(&before, &doc.gate) {
                if form.get("confirm").trim() != c.token {
                    return Ok(Some(c));
                }
            }
            // The library is the only door here too: `prepare` compiles the exact bytes with
            // the parser the gate uses, `commit` writes the bytes it compiled. What it refuses
            // is a code, and this page says it in the reader's language and marks the box the
            // operator has to go back to (§13.31): the library names the setting, only this
            // page knows which field holds it.
            SettingsWrite::prepare(&doc)
                .map_err(|e| match &e {
                    PrepareError::Refused(r) => settings_refusal(v.lang, r),
                    // Not a settings refusal at all: serde on our own structs, never seen, and
                    // nothing on the page to blame.
                    _ => Refusal::from(e.to_string()),
                })?
                .commit(path)?;
            audit(v.admin.unwrap_or("?"), "settings set", path);
            Ok(None)
        })();
        return match r {
            Ok(None) => Outcome::Done(Route::Config, Msg::SettingsSaved),
            Ok(Some(c)) => Outcome::Page(200, title, page_config(v, &f, None, Some(&c))),
            Err(e) => Outcome::Page(400, title, page_config(v, &f, Some(&e), None)),
        };
    }

    // (2) And as the gate would read it. A file that does not compile is not a file to edit.
    let (mut doc, _) = match open_access_file(path) {
        Ok(pair) => pair,
        Err(e) => return Outcome::Page(500, title, page_file_error(v, &e)),
    };

    // (3) The mutation itself. Each arm: read the form, ask the library, write, say where
    // the browser goes — or hand the refusal back to the form it came from.
    match &v.at {
        Route::UserAdd => {
            let f = UserForm::read(form);
            let r = (|| -> Result<String, Refusal> {
                let email = norm_email(&f.email);
                if email.is_empty() {
                    return Err(Refusal::on("email", v.t(K::EmailRequired)));
                }
                add_user(
                    &mut doc,
                    UserSpec {
                        emails: vec![email.clone()],
                        ..Default::default()
                    },
                )
                .map_err(|e| Refusal::on("email", e))?;
                let uuid = user_pos(&doc, &email)
                    .map(|i| doc.users[i].uuid.trim().to_ascii_lowercase())
                    .unwrap_or_default();
                commit(v, &doc, "user add", &email)?;
                Ok(uuid)
            })();
            match r {
                Ok(uuid) => Outcome::Done(Route::User(uuid), Msg::UserAdded),
                Err(e) => Outcome::Page(400, title, page_user_form(v, &f, Some(&e))),
            }
        }

        Route::UserRm(target) => {
            let r = (|| -> Result<(), Refusal> {
                let (u, _swept) = remove_user(&mut doc, target)?;
                commit(v, &doc, "user rm", &user_label(&u))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Users, Msg::UserRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Users)) " · " (v.t(K::Remove)) },
                        html! { p { code { (target) } } },
                        v.t(K::ConfirmUserRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::EmailAdd(owner) => {
            let f = UserForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                let email = norm_email(&f.email);
                if email.is_empty() {
                    return Err(Refusal::on("email", v.t(K::EmailRequired)));
                }
                add_user_email(&mut doc, owner, &email).map_err(|e| Refusal::on("email", e))?;
                commit(
                    v,
                    &doc,
                    "user email add",
                    &format!("{}: +{email}", label_of(&doc, owner)),
                )?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::User(owner.clone()), Msg::UserSaved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_email_form(v, &label_of(&doc, owner), &f, Some(&e)),
                ),
            }
        }

        Route::EmailRm(owner, email) => {
            let r = (|| -> Result<(), Refusal> {
                remove_user_email(&mut doc, owner, email)?;
                commit(
                    v,
                    &doc,
                    "user email rm",
                    &format!("{}: -{}", label_of(&doc, owner), norm_email(email)),
                )?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::User(owner.clone()), Msg::UserSaved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Emails)) " · " (v.t(K::Remove)) },
                        html! { p { code { (norm_email(email)) } } },
                        v.t(K::ConfirmEmailRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::KeyAdd(owner) => {
            let f = KeyForm::read(form);
            // Today, and not a field: a key's issue date is a fact about a secret that is
            // being created right now.
            let released = format_date(now());
            let owner_label = label_of(&doc, owner);
            let r = (|| -> Result<(String, String), Refusal> {
                let id = f.id.trim().to_string();
                if id.is_empty() {
                    return Err(Refusal::on("id", v.t(K::KeyIdRequired)));
                }
                let duration =
                    duration_from_form(form).map_err(|k| Refusal::on("duration", v.t(k)))?;
                // Fail before minting: a key the file would reject is a secret handed out
                // for nothing.
                if key_expiry(&released, &duration).is_none() {
                    return Err(Refusal::on("duration", v.t(K::BadKeyWindow)));
                }
                let lines = form.lines("scopes");
                let scopes = if lines.is_empty() { None } else { Some(lines) };
                // Not attributed: besides a duplicate id, this can also fail on an owner
                // lookup or on entropy for the mint itself; neither is a field to blame.
                let sealed: SealedKey = add_api_key(
                    &mut doc,
                    owner,
                    ApiKeySpec {
                        id: id.clone(),
                        released: released.clone(),
                        duration,
                        scopes,
                        ..Default::default()
                    },
                )?;
                // The bearer opens only against the receipt of a completed write, so this
                // order is the library's and not a convention this file could get wrong.
                // The id and duration already passed; the scopes just submitted are the
                // only new, still-unvalidated content left for the compile to catch.
                let written = commit(v, &doc, "key add", &format!("{owner_label}/{id}"))
                    .map_err(|e| Refusal::on("scopes", e))?;
                Ok((id, sealed.reveal(&written)))
            })();
            match r {
                Ok((id, bearer)) => Outcome::Page(
                    200,
                    title,
                    page_minted(v, owner, &owner_label, &id, &bearer),
                ),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_key_form(v, &owner_label, None, &released, &f, Some(&e)),
                ),
            }
        }

        Route::KeyEdit(owner, id) => {
            let f = KeyForm::read(form);
            let owner_label = label_of(&doc, owner);
            let released = key_mut(&mut doc, owner, id)
                .map(|k| k.released.trim().to_string())
                .unwrap_or_default();
            let r = (|| -> Result<(), Refusal> {
                let duration =
                    duration_from_form(form).map_err(|e| Refusal::on("duration", v.t(e)))?;
                let k = key_mut(&mut doc, owner, id)?;
                k.duration = duration;
                if key_expiry(&k.released, &k.duration).is_none() {
                    return Err(Refusal::on("duration", v.t(K::BadKeyWindow)));
                }
                // Empty collapses to absent, which is what "everything the owner reaches"
                // means: see `KeyScopesHelp`.
                let lines = form.lines("scopes");
                let clear = lines.is_empty();
                edit_urls(&mut k.scopes, lines, Vec::new(), Vec::new(), clear);
                commit(v, &doc, "key set", &format!("{owner_label}/{id}"))
                    .map_err(|e| Refusal::on("scopes", e))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::User(owner.clone()), Msg::KeySaved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_key_form(v, &owner_label, Some(id), &released, &f, Some(&e)),
                ),
            }
        }

        Route::KeyRotate(owner, id) => {
            let owner_label = label_of(&doc, owner);
            let r = (|| -> Result<String, Refusal> {
                let sealed = rotate_api_key(&mut doc, owner, id)?;
                let written = commit(v, &doc, "key rotate", &format!("{owner_label}/{id}"))?;
                Ok(sealed.reveal(&written))
            })();
            match r {
                Ok(bearer) => {
                    Outcome::Page(200, title, page_minted(v, owner, &owner_label, id, &bearer))
                }
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (owner_label) " · api_keys · " (v.t(K::Rotate)) },
                        html! { p { code { (id) } } },
                        v.t(K::ConfirmKeyRotate),
                        v.t(K::Rotate),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::KeyRm(owner, id) => {
            let owner_label = label_of(&doc, owner);
            let r = (|| -> Result<(), Refusal> {
                remove_api_key(&mut doc, owner, id)?;
                commit(v, &doc, "key rm", &format!("{owner_label}/{id}"))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::User(owner.clone()), Msg::KeyRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (owner_label) " · api_keys · " (v.t(K::Remove)) },
                        html! { p { code { (id) } } },
                        v.t(K::ConfirmKeyRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::AppAdd => {
            let f = AppForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                let name = f.name.trim().to_string();
                let base = form.lines("base");
                let login_url = match f.login_url.trim() {
                    "" => None,
                    l => Some(l.to_string()),
                };
                let denied_url = match f.denied_url.trim() {
                    "" => None,
                    l => Some(l.to_string()),
                };
                let notes = match f.notes.trim() {
                    "" => None,
                    n => Some(n.to_string()),
                };
                add_application(
                    &mut doc,
                    AppSpec {
                        name: name.clone(),
                        base,
                        login_url,
                        denied_url,
                        notes,
                        ..Default::default()
                    },
                )
                .map_err(|e| Refusal::on("name", e))?;
                // Not attributed: base and login_url are both still unvalidated at this
                // point, so a compile failure could be either.
                commit(v, &doc, "app add", &name)?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Apps, Msg::AppAdded),
                Err(e) => Outcome::Page(400, title, page_app_form(v, None, &f, Some(&e))),
            }
        }

        Route::AppEdit(target) => {
            let f = AppForm::read(form);
            let r = (|| -> Result<String, Refusal> {
                let name = f.name.trim().to_string();
                if name.is_empty() {
                    return Err(Refusal::on("name", v.t(K::NameRequired)));
                }
                rename_application(&mut doc, target, &name).map_err(|e| Refusal::on("name", e))?;
                let a = app_mut(&mut doc, &name)?;
                a.base = form.lines("base");
                a.login_url = match f.login_url.trim() {
                    "" => None,
                    l => Some(l.to_string()),
                };
                a.denied_url = match f.denied_url.trim() {
                    "" => None,
                    l => Some(l.to_string()),
                };
                a.notes = match f.notes.trim() {
                    "" => None,
                    n => Some(n.to_string()),
                };
                commit(v, &doc, "app set", &name)?;
                Ok(name)
            })();
            match r {
                Ok(name) => Outcome::Done(Route::App(name), Msg::AppSaved),
                Err(e) => Outcome::Page(400, title, page_app_form(v, Some(target), &f, Some(&e))),
            }
        }

        Route::AppRm(target) => {
            let r = (|| -> Result<(), Refusal> {
                let a = remove_application(&mut doc, target)?;
                commit(v, &doc, "app rm", a.name.trim())?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Apps, Msg::AppRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Apps)) " · " (v.t(K::Remove)) },
                        html! { p { code { (target) } } },
                        v.t(K::ConfirmAppRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::ScopeAdd(app) => {
            let f = ScopeForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                let spec = scope_spec(v, &doc, &f, form.lines("urls"))?;
                add_scope(&mut doc, app, spec, None).map_err(|e| Refusal::on("name", e))?;
                commit(v, &doc, "scope add", &format!("{app}/{}", f.name.trim()))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::App(app.clone()), Msg::ScopeAdded),
                Err(e) => Outcome::Page(400, title, page_scope_form(v, app, None, &f, Some(&e))),
            }
        }

        Route::ScopeEdit(app, target) => {
            let f = ScopeForm::read(form);
            let r = (|| -> Result<String, Refusal> {
                let name = f.name.trim().to_string();
                if name.is_empty() {
                    return Err(Refusal::on("name", v.t(K::NameRequired)));
                }
                rename_scope(&mut doc, app, target, &name).map_err(|e| Refusal::on("name", e))?;
                let spec = scope_spec(v, &doc, &f, form.lines("urls"))?;
                *scope_mut(&mut doc, app, &name)? = spec;
                commit(v, &doc, "scope set", &format!("{app}/{name}"))?;
                Ok(name)
            })();
            match r {
                Ok(_) => Outcome::Done(Route::App(app.clone()), Msg::ScopeSaved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_scope_form(v, app, Some(target), &f, Some(&e)),
                ),
            }
        }

        Route::ScopeRm(app, target) => {
            let r = (|| -> Result<(), Refusal> {
                let s = remove_scope(&mut doc, app, target)?;
                commit(v, &doc, "scope rm", &format!("{app}/{}", s.name.trim()))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::App(app.clone()), Msg::ScopeRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Scopes)) " · " (v.t(K::Remove)) },
                        html! { p { code { (app) "/" (target) } } },
                        v.t(K::ConfirmScopeRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::ScopeMove(app, target) => {
            let r = (|| -> Result<(), String> {
                let ai =
                    app_pos(&doc, app).ok_or_else(|| format!("no application '{}'", app.trim()))?;
                let si = scope_pos(&doc.applications[ai], target)
                    .ok_or_else(|| format!("{app}/{}: no such scope", target.trim()))?;
                let to = match form.get("dir") {
                    "up" => si.checked_sub(1),
                    "down" => Some(si + 1).filter(|j| *j < doc.applications[ai].scopes.len()),
                    _ => None,
                };
                // A move off either end is not an error, it is a button that was already
                // disabled: nothing changes, and nothing is written.
                if let Some(to) = to {
                    move_scope(&mut doc, app, si, to)?;
                    commit(
                        v,
                        &doc,
                        "scope mv",
                        &format!("{app}/{} --at {to}", target.trim()),
                    )?;
                }
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::App(app.clone()), Msg::ScopeMoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    notice("bad", v.t(K::NotFoundTitle), html! { p { (e) } }),
                ),
            }
        }

        Route::GroupAdd => {
            let f = GroupForm::read(form);
            let r = (|| -> Result<String, Refusal> {
                let name = f.name.trim().to_string();
                let members =
                    parse_group_members(&doc, &f.members).map_err(|e| Refusal::on("members", e))?;
                add_user_group(&mut doc, &name, members).map_err(|e| Refusal::on("name", e))?;
                commit(v, &doc, "group add", &format!("@{name}"))?;
                Ok(name)
            })();
            match r {
                // The group's own page (§13.36 §1): the add form names the members, and the
                // page that shows them is where an operator checks what they typed.
                Ok(name) => Outcome::Done(Route::Group(name), Msg::GroupAdded),
                Err(e) => Outcome::Page(400, title, page_group_form(v, None, &f, Some(&e))),
            }
        }

        Route::GroupEdit(target) => {
            let f = GroupForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                // No rename: a reference names a group by its exact spelling, so the
                // library does not offer one and neither does this form.
                let members =
                    parse_group_members(&doc, &f.members).map_err(|e| Refusal::on("members", e))?;
                *user_group_mut(&mut doc, target)? = members;
                commit(v, &doc, "group set", &format!("@{}", target.trim()))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Group(target.trim().to_string()), Msg::GroupSaved),
                Err(e) => Outcome::Page(400, title, page_group_form(v, Some(target), &f, Some(&e))),
            }
        }

        Route::GroupRm(target) => {
            let r = (|| -> Result<(), Refusal> {
                // The library refuses while anything still references the group, and its
                // refusal names every referrer — which is the list of places to go and fix.
                remove_user_group(&mut doc, target)?;
                commit(v, &doc, "group rm", &format!("@{}", target.trim()))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Groups, Msg::GroupRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Groups)) " · " (v.t(K::Remove)) },
                        html! { p { code { "@" (target) } } },
                        v.t(K::ConfirmGroupRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::DenyAdd => {
            let f = DenyForm::read(form);
            let r = (|| -> Result<(), Refusal> {
                let email = norm_email(&f.email);
                if email.is_empty() {
                    return Err(Refusal::on("email", v.t(K::EmailRequired)));
                }
                if !add_denied(&mut doc, &email).map_err(|e| Refusal::on("email", e))? {
                    return Err(Refusal::on("email", v.t(K::AlreadyDenied)));
                }
                commit(v, &doc, "deny add", &email)?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Denied, Msg::DeniedAdded),
                Err(e) => Outcome::Page(400, title, page_deny_form(v, &f, Some(&e))),
            }
        }

        Route::DenyRm(target) => {
            let email = norm_email(target);
            let r = (|| -> Result<(), Refusal> {
                if remove_denied(&mut doc, std::slice::from_ref(&email)) == 0 {
                    return Err(Refusal::from(v.t(K::NoSuchDenied).to_string()));
                }
                commit(v, &doc, "deny rm", &email)?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Denied, Msg::DeniedRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (v.t(K::Denied)) " · " (v.t(K::Remove)) },
                        html! { p { code { (email) } } },
                        v.t(K::ConfirmDenyRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        // Everything else is a page, and a page does not take a POST — `Route::UserEdit`
        // included: nothing is left on a `UserSpec` for a standalone edit to change (the
        // uuid is fixed, emails and keys have their own routes), so its `GET` just shows
        // the user and its `POST` falls here.
        _ => Outcome::Page(
            405,
            title,
            notice(
                "bad",
                v.t(K::NotAllowedTitle),
                html! { p { (v.t(K::NotAllowedBody)) } },
            ),
        ),
    }
}

/// Build a `ScopeSpec` from a submitted form: `urls` already split into lines by the
/// caller, `access` copied verbatim (the library is the judge of whether it is one of the
/// three words), and the membership fields populated only under `restricted` — present on
/// any other kind is fatal, so this is what keeps a stray tick from ever reaching the
/// compile.
fn scope_spec(
    v: &View,
    doc: &AccessFile,
    f: &ScopeForm,
    urls: Vec<String>,
) -> Result<ScopeSpec, Refusal> {
    let access = f.access.trim().to_string();
    let (users, groups, credentials) = if access == "restricted" {
        let (u, g) = parse_members(doc, &f.members).map_err(|e| Refusal::on("members", e))?;
        let credentials = if !f.cred_login && !f.cred_api_key {
            None
        } else {
            let mut list = Vec::new();
            if f.cred_login {
                list.push("login".to_string());
            }
            if f.cred_api_key {
                list.push("api_key".to_string());
            }
            Some(list)
        };
        (
            (!u.is_empty()).then_some(u),
            (!g.is_empty()).then_some(g),
            credentials,
        )
    } else {
        (None, None, None)
    };
    // Exclusions belong to `restricted` *and* to `authenticated` — that kind lists nobody,
    // so an exclusion is the only way to keep one person out of it. `anonymous` refuses
    // them, and refuses them out loud: silently dropping what an operator typed into a box
    // meant to keep somebody out is the worst of the three possible answers.
    let excluded = if access == "anonymous" {
        if !f.excluded.trim().is_empty() {
            return Err(Refusal::on("excluded", v.t(K::ExcludedNotAnon)));
        }
        None
    } else {
        let list = parse_exclusions(doc, &f.excluded).map_err(|e| Refusal::on("excluded", e))?;
        (!list.is_empty()).then_some(list)
    };
    Ok(ScopeSpec {
        name: f.name.trim().to_string(),
        urls,
        access,
        users,
        groups,
        credentials,
        excluded,
        notes: match f.notes.trim() {
            "" => None,
            n => Some(n.to_string()),
        },
    })
}

/// Split a members textarea into `users` (each line resolved to a uuid, exactly as an
/// operator types it: email or uuid, through [`user_pos`]) and `groups` (`@name`, kept
/// exactly as written — the file's own spelling, and what `compile_access` expands).
pub(crate) fn parse_members(
    doc: &AccessFile,
    text: &str,
) -> Result<(Vec<String>, Vec<String>), String> {
    let mut users = Vec::new();
    let mut groups = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if group_ref(line).is_some() {
            groups.push(line.to_string());
        } else {
            match user_pos(doc, line) {
                Some(i) => users.push(doc.users[i].uuid.trim().to_ascii_lowercase()),
                None => return Err(format!("no user '{line}' (add them with: user add {line})")),
            }
        }
    }
    Ok((users, groups))
}

/// The inverse of [`scope_excluded_display`]: one textarea into a scope's `excluded`, one
/// line at a time through the library's [`parse_exclusion`].
///
/// The rule itself is not here, and that is the fix rather than a detail: this and the CLI's
/// `--exclude` had one implementation each and they had already come apart over what an
/// `@name` line has to satisfy. Unlike [`parse_members`] it accepts an email the roster has
/// never heard of, which is the whole point of the field on an `authenticated` scope.
pub(crate) fn parse_exclusions(doc: &AccessFile, text: &str) -> Result<Vec<String>, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| parse_exclusion(doc, l))
        .collect()
}

/// [`parse_members`] for a `user_groups` member list, which may only ever hold uuids: a
/// group cannot reference another group, so an `@name` line is refused here rather than
/// silently dropped into a field nothing reads.
fn parse_group_members(doc: &AccessFile, text: &str) -> Result<Vec<String>, String> {
    let mut users = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(g) = group_ref(line) {
            return Err(format!("'@{g}': a group cannot reference another group"));
        }
        match user_pos(doc, line) {
            Some(i) => users.push(doc.users[i].uuid.trim().to_ascii_lowercase()),
            None => return Err(format!("no user '{line}' (add them with: user add {line})")),
        }
    }
    Ok(users)
}
