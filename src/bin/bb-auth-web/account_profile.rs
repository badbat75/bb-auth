use crate::*;

/// The longest value this page accepts for one claim, and the `maxlength` the field says.
///
/// One constant for both, because a field that lets a person type more than the server will
/// accept is a field that sets them up to be refused.
const PROFILE_VALUE_MAX: usize = 2048;

/// The longest code this page accepts, and the `maxlength` the field says. Cognito's email OTP is
/// 6 digits; the room is for a pool configured with a longer one, and the field's own bound is
/// what stops a paste of a whole email landing in the API call.
const PROFILE_CODE_MAX: usize = 32;

/// The code as the pool must receive it: `None` for anything that cannot be a code.
///
/// Whitespace goes first, because a pasted `123 456` is the same code typed twice (§13.23 §3), and
/// a browser `pattern` would refuse the space the server can simply drop. What is left must be
/// ASCII letters and digits, 1 to 16: a code is a short alphanumeric string, and a value that is
/// not one is a hand-made form, not a person with a code.
fn profile_code(code: &str) -> Option<String> {
    let clean: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() <= 16 && !clean.is_empty() && clean.chars().all(|c| c.is_ascii_alphanumeric()) {
        Some(clean)
    } else {
        None
    }
}

/// The claims the profile form puts a field for, in the order the OIDC profile document
/// lists them (§13.22).
///
/// These are the claims Cognito keeps as user-pool attributes, so the update step
/// (`UpdateUserAttributes`, slice 5c) accepts them; a claim outside this list is refused on
/// the way in, because a field the directory will not store is a field that cannot save, and a
/// field that cannot save is worse than no field at all. `preferred_username` is absent on
/// purpose: it is the sign-in name, and changing it changes who the person is, which is not
/// what this page is for.
const PROFILE_EDITABLE: [&str; 12] = [
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
];

/// The word a claim is shown under, and `None` when the design names no word for it.
///
/// One function for the form's label, the change summary's name and the read-only panel's
/// name, because the panel and the form must never call one field by two names: a person who
/// read "Given name" on the panel is entitled to read it on the field they type into. A claim
/// with no word keeps its own name, in `code`, which is the file's vocabulary and the honest
/// answer for a name nobody translated.
pub(crate) fn profile_label(lang: Lang, claim: &str) -> Option<String> {
    let key = match claim {
        "name" => K::AttrName,
        "given_name" => K::AttrGivenName,
        "family_name" => K::AttrFamilyName,
        "middle_name" => K::AttrMiddleName,
        "nickname" => K::AttrNickname,
        "profile" => K::AttrProfile,
        "picture" => K::AttrPicture,
        "website" => K::AttrWebsite,
        "gender" => K::AttrGender,
        "birthdate" => K::AttrBirthdate,
        "zoneinfo" => K::AttrZoneinfo,
        "locale" => K::AttrLocale,
        _ => return None,
    };
    Some(t(lang, key).to_string())
}

/// The configured claims that are editable, in the settings' own order.
///
/// The order is the settings', not the allowlist's, because the operator chose it:
/// `gate.profile_claims` is the list the deployment says it forwards, and the form is a
/// field-for-field version of the panel that shows that list.
fn profile_editable(settings: &Settings) -> Vec<String> {
    settings
        .profile_claims
        .iter()
        .map(|c| c.claim.as_str())
        .filter(|c| PROFILE_EDITABLE.contains(c))
        .map(str::to_string)
        .collect()
}

/// Whether the edit can work at all: a pool to call, a native app client to call it with, and
/// at least one claim worth a field.
///
/// All three, because a form that can only end in an error is a promise the page cannot keep.
/// The pill is absent rather than disabled: a disabled control is skipped by the keyboard and
/// says nothing, and the reason here is a setting, not the person's doing.
pub(crate) fn profile_offered(settings: &Settings) -> bool {
    !settings.issuer.trim().is_empty()
        && !settings.client_id.trim().is_empty()
        && !profile_editable(settings).is_empty()
}

/// The autofill token for a field, as WCAG 1.3.5 asks for one: a name, a birthday and a
/// nickname are values the browser already holds, and a person who has typed them once should
/// not have to type them again. A claim with no token in the HTML spec's vocabulary gets no
/// attribute at all, which leaves the browser guessing nothing.
fn autocomplete_of(claim: &str) -> Option<&'static str> {
    match claim {
        "name" => Some("name"),
        "given_name" => Some("given-name"),
        "family_name" => Some("family-name"),
        "middle_name" => Some("additional-name"),
        "nickname" => Some("nickname"),
        "picture" => Some("photo"),
        "gender" => Some("sex"),
        "birthdate" => Some("bday"),
        _ => None,
    }
}

/// The profile form as one render needs it: the fields, and the one sentence above the form,
/// which is an error, a warning, or nothing.
///
/// A struct and not six arguments because the page that renders it is the page that refused a
/// submission, and every one of these is what the person left on the page: the values they
/// typed, the field that was refused. Deriving that from the request at render time would be a
/// second answer to "what did they submit".
pub(crate) struct ProfileForm {
    /// Each editable claim, with the value its field shows.
    editable: Vec<(String, String)>,
    /// Each configured claim that is not editable, with the value the panel shows it by.
    other: Vec<(String, String)>,
    /// The claim a refusal is attributed to, and the sentence above the form. The sentence
    /// names the field by its visible label, because that is the word the person read.
    err: Option<(String, String)>,
    /// A sentence above the form that is not an error: the values changed nothing.
    warn: Option<String>,
}

impl ProfileForm {
    /// The form as the page shows it before anyone has typed anything: every editable claim
    /// prefilled with the value the proxy forwarded.
    pub(crate) fn open(settings: &Settings, req: &Request) -> ProfileForm {
        let (editable, other) = profile_split(settings, req, &profile_editable(settings), None);
        ProfileForm {
            editable,
            other,
            err: None,
            warn: None,
        }
    }

    /// The form as it comes back after a refusal: the values as posted, and the sentence. A
    /// person who typed a name is not being asked to type it again.
    fn again(
        settings: &Settings,
        req: &Request,
        form: &Form,
        err: Option<(String, String)>,
        warn: Option<String>,
    ) -> ProfileForm {
        let (editable, other) =
            profile_split(settings, req, &profile_editable(settings), Some(form));
        ProfileForm {
            editable,
            other,
            err,
            warn,
        }
    }
}

/// The two lists of claims the edit page shows, from the settings, the forwarded values and
/// (after a refusal) what was posted: the editable ones as fields, the rest as read-only text.
///
/// `posted` is the submission whose values the fields must show; `None` is the first render,
/// where every field holds what the proxy forwarded.
///
/// The two lists are a pair of `(claim, value)` vectors, which is exactly what the form and
/// the read-only list consume; naming that pair would say less than the tuple does, so
/// clippy's `type_complexity` is answered here rather than with an alias.
#[allow(clippy::type_complexity)]
fn profile_split(
    settings: &Settings,
    req: &Request,
    editable_claims: &[String],
    posted: Option<&Form>,
) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let mut editable = Vec::new();
    let mut other = Vec::new();
    for c in &settings.profile_claims {
        let value = forwarded_claim(req, &c.header);
        if editable_claims.iter().any(|e| e == &c.claim) {
            editable.push((
                c.claim.clone(),
                match posted {
                    Some(f) if f.0.iter().any(|(k, _)| k == &c.claim) => {
                        f.get(&c.claim).to_string()
                    }
                    _ => value,
                },
            ));
        } else {
            other.push((c.claim.clone(), value));
        }
    }
    (editable, other)
}

/// The value the proxy forwarded for one derived header, percent-decoded, `""` for none.
fn forwarded_claim(req: &Request, header: &str) -> String {
    header_value(req, header)
        .map(pct_decode)
        .unwrap_or_default()
}

/// The edit form (§13.23 §2). Every field is a `label` that wraps its input, so the name is
/// the click target too, and the value is prefilled, because a person correcting a name is
/// correcting one word and not retyping the rest.
///
/// Nothing here names an address (§13.26 §4). The code goes to the Cognito user the session
/// **is** (§13.25), which is a name the person did not type and cannot choose, so there is
/// nothing to pick: the "Send the code to" line, its `select` and its hidden `email` are gone,
/// and a posted `email` is refused as a non-editable name. What stays is the sentence that says
/// why the email is not a field, after the fields, where a person who is looking for it reads it.
pub(crate) fn profile_form(lang: Lang, f: &ProfileForm, action: &str, page: &str) -> Markup {
    // Each editable claim as the shared field, in **prose** mode (§13.26): a person's name
    // keeps the browser's capitalisation and its spell check, which the console's field drops
    // because a URL, a header name and a key id have neither.
    let mut fields: Vec<Markup> = Vec::new();
    for (claim, value) in &f.editable {
        let label = profile_label(lang, claim).unwrap_or_else(|| claim.clone());
        // Where there is something to remove, the page says so before the person finds it by
        // submitting: emptying a field is a removal, not a no-op.
        let mut hints: Vec<&str> = Vec::new();
        if !value.is_empty() {
            hints.push(t(lang, K::AccountProfileClearDeletes));
        }
        if claim == "birthdate" {
            hints.push(t(lang, K::AccountProfileDateHint));
        }
        fields.push(text_field_with(
            &label,
            claim,
            value,
            "",
            &hints,
            f.err.as_ref().is_some_and(|(c, _)| c == claim),
            FieldOpts {
                class: Some("f-profile"),
                maxlength: Some(PROFILE_VALUE_MAX),
                autocomplete: autocomplete_of(claim),
                // The first text field is the one the page focuses, and only it: two
                // `autofocus` on one page is no focus at all.
                autofocus: f.editable.first().is_some_and(|(c, _)| c == claim),
                prose: true,
                ..FieldOpts::default()
            },
        ));
    }
    html! {
        form class="edit" method="post" action=(action) {
            // The console's shape in this page's shell: the sentence above the form, and the
            // field it names marked for assistive tech and not only coloured. The box carries
            // [`ERR_ID`], the id every form's message box carries on both surfaces, so the
            // `aria-describedby` the shared field writes points at something here too.
            @if let Some((_, msg)) = &f.err {
                div class="err" id=(ERR_ID) { (msg) }
            }
            @if let Some(msg) = &f.warn {
                div class="msg warn" { (msg) }
            }
            @for field in &fields { (field) }
            // Configured and not editable: shown as the read-only panel shows them, so the page
            // a person is editing says everything the page they came from said.
            @if !f.other.is_empty() {
                ul class="plain" {
                    @for (claim, value) in &f.other {
                        li {
                            @if let Some(word) = profile_label(lang, claim) {
                                (word)
                            } @else {
                                code { (claim) }
                            }
                            ": "
                            @if value.is_empty() {
                                span class="muted" { (t(lang, K::AccountNotProvided)) }
                            } @else {
                                (value)
                            }
                        }
                    }
                }
            }
            // Said after the fields, because this is the page of the person who was looking for
            // an email field and did not find one: the address is how they sign in, so it is not
            // a field here, and the sentence that says so belongs where their eye lands.
            p class="muted" { (t(lang, K::AccountProfileEmailFixed)) }
            p class="actions" {
                button type="submit" { (t(lang, K::AccountProfileSendCode)) }
                (pill_link(page, t(lang, K::Cancel)))
            }
        }
    }
}

/// One line of the change summary: the claim, what it was, what it becomes. `after` is `None`
/// for a removal, which is the case that has to be a word and not an empty box.
struct ProfileChange {
    claim: String,
    before: Option<String>,
    after: Option<String>,
}

/// What the code page carries, and what its two forms post.
///
/// The two field lists are separate on purpose. `carry` is the code step's: the `Session` and one
/// entry per changed claim, which is everything the step needs to answer the challenge and write
/// the attributes. `resend` is the start's: the changed claims, **never** the `Session`, because
/// "send a new code" is starting over and a page holding two sessions would be two answers to
/// which code the field belongs to. Neither carries a username (§13.25 step 2): the code step
/// answers for the user of the request that arrives, named by the gate's header.
struct ProfileCode<'a> {
    /// The masked address Cognito said it sent to, as the challenge named it, and `None` when the
    /// pool did not name one. Shown only when [`code_destination`] accepts it.
    destination: Option<&'a str>,
    changes: &'a [ProfileChange],
    carry: &'a [(String, String)],
    resend: &'a [(String, String)],
    /// The sentence above the change list when the code just was not right, and the field it
    /// marks. Nothing on the page says why the code was wrong beyond this: Cognito's own words
    /// are a sentence written for an AWS console.
    err: Option<&'a str>,
}

/// The masked destination the pool named, when it is a value this page may put on a page.
///
/// It is the provider's word, not the person's, and it arrives in a response body: a value that
/// is not printable ASCII has no business in a document, and one with a space in it is not an
/// address-shaped mask (Cognito's own mask is `t***@e***`). The bound is the length a mask can
/// plausibly be, and a value over it is a provider saying something this page cannot lay out.
/// Anything rejected is simply not named: the generic sentence says everything the page knows,
/// and a page that shows a raw address it was handed would be a page leaking somebody's address
/// through a field meant to mask it.
fn code_destination(destination: Option<&str>) -> Option<&str> {
    destination
        .map(str::trim)
        .filter(|d| !d.is_empty() && d.chars().count() <= 254)
        .filter(|d| d.chars().all(|c| c.is_ascii_graphic()))
}

/// The page that asks for the code (§13.23 §3, §13.26 §4): the masked address it went to, the
/// clock as a number, the changes as they will be described back, the code field, and a way to
/// start over.
///
/// The `Session` rides in a hidden field and nowhere else: this is a form, not a server-side
/// transaction, and a person who opens two tabs holds two independent codes.
fn page_profile_code(
    lang: Lang,
    c: &ProfileCode,
    profile_path: &str,
    code_path: &str,
    page: &str,
) -> Markup {
    html! {
        p class="lede" {
            @if let Some(dest) = code_destination(c.destination) {
                (t(lang, K::AccountProfileCodeSent)) " "
                code { (dest) }
                "." " " (t(lang, K::AccountProfileCodeLasts))
            } @else {
                // The pool named no address, so the page says what it knows and no more: the code
                // went to the address the account signs in with. It invents nothing, because the
                // address the pool writes to is the pool's, and on a pool whose `email` and
                // `username` differ the address this page could invent is not the one used.
                (t(lang, K::AccountProfileCodeSentNoDest)) " "
                (t(lang, K::AccountProfileCodeLasts))
            }
        }
        // The card, as the confirmations wear theirs: the summary and the field are one act, and
        // the shell has already rendered the act's name as the page's one heading.
        div class="card" {
            @if let Some(msg) = c.err {
                // Inside the card and above the summary: the person is reading this page again,
                // and the first thing they need to know is that this attempt did not work.
                div class="err" id="err" { (msg) }
            }
            p class="lbl" { (t(lang, K::AccountProfileChanges)) }
            ul class="plain changes" {
                @for ch in c.changes {
                    li {
                        (profile_label(lang, &ch.claim).unwrap_or_else(|| ch.claim.clone())) ": "
                        @if let Some(after) = &ch.after {
                            strong { (after) }
                            // An attribute that had no value has no `was` part: there is nothing
                            // to say it was.
                            @if let Some(before) = &ch.before {
                                " " (t(lang, K::AccountProfileWas)) " " code { (before) }
                            }
                        } @else {
                            // A removal is a word, not strike-through: `s` is not announced by
                            // most screen readers, and this is the deletion the person must
                            // confirm before it happens. `warn` and not `bad`: it is what they
                            // asked for, so it is pointed out, not alarmed about.
                            span class="tag warn" { (t(lang, K::AccountProfileRemoved)) }
                            " " (t(lang, K::AccountProfileWas)) " "
                            code { (ch.before.clone().unwrap_or_default()) }
                        }
                    }
                }
            }
            form class="edit" method="post" action=(code_path) {
                @for (name, value) in c.carry {
                    input type="hidden" name=(name) value=(value);
                }
                label {
                    span class="lbl" { (t(lang, K::AccountProfileCodeLabel)) }
                    // A text field with `inputmode="numeric"`, not a `number` field: a code is
                    // digits, and a `number` field brings a spinner and a locale-dependent
                    // decimal separator to a value that is never a number. `one-time-code` is
                    // what lets the browser fill it from the message it arrived in. **No
                    // `pattern`**: a pasted `123 456` would be blocked by the browser for a
                    // space the server simply strips.
                    //
                    // The value is never put back: a code that was refused is not worth typing
                    // again, and a field holding one invites a submit of the same answer. The
                    // focus does not move here either, on a page that is being read again: it
                    // stays where the reader's eye is, which is the summary above.
                    input class="f-code" name="code" type="text" inputmode="numeric"
                          autocomplete="one-time-code" autocapitalize="off" spellcheck="false"
                          required maxlength=(PROFILE_CODE_MAX)
                          autofocus=[(c.err.is_none()).then(|| "true")]
                          aria-invalid=[c.err.is_some().then_some("true")]
                          aria-describedby=[c.err.is_some().then_some("err")];
                }
                div class="actions" {
                    button type="submit" { (t(lang, K::AccountProfileSave)) }
                    (pill_link(page, t(lang, K::Cancel)))
                }
            }
        }
        // Resend is starting over, and says so by being the start's own form: the changed values,
        // never the `Session`, posted back to the start.
        form class="edit" method="post" action=(profile_path) {
            @for (name, value) in c.resend {
                input type="hidden" name=(name) value=(value);
            }
            p class="muted" { (t(lang, K::AccountProfileNoCode)) }
            div class="actions" {
                button type="submit" class="pill" { (t(lang, K::AccountProfileSendNew)) }
            }
        }
    }
}

/// The page a save lands on (§13.23 §4): the `h1` says it worked, the lede names what changed in
/// the same words the form used, and says before the person sees it that the account page still
/// shows the old values.
///
/// The panel is drawn from what the proxy forwarded at sign-in, so "back" lands on the values
/// that were there before. Saying so here is the difference between a save that reads as a save
/// and one that reads as a failure.
fn page_profile_saved(lang: Lang, changes: &[ProfileChange], page: &str) -> Markup {
    let names: Vec<String> = changes
        .iter()
        .map(|c| profile_label(lang, &c.claim).unwrap_or_else(|| c.claim.clone()))
        .collect();
    html! {
        p class="lede" {
            (t(lang, K::AccountProfileSavedLead)) " " (names.join(", ")) ". "
            (t(lang, K::AccountProfileSavedBody))
        }
        p class="primary" {
            (back_link(lang, page))
        }
    }
}

/// The page a start that did not work ends on: the `h1` says the profile was not saved, the
/// lede says why, and a way back is the only action.
///
/// Cognito's own `message` is never on the page. It is a sentence written for an AWS console, it
/// repeats the address back, and for the cases that mean "this account cannot sign in this way"
/// it is a string the person has no vocabulary for. The status is the operator's diagnostic; the
/// words are the person's.
fn page_profile_outcome(
    lang: Lang,
    key: K,
    resend: Option<&[(String, String)]>,
    profile_path: &str,
    page: &str,
) -> Markup {
    html! {
        p class="lede" { (t(lang, key)) }
        @if let Some(fields) = resend {
            // Only the case that timed out offers a new code: the pool may have taken the
            // request, so the honest answer is "ask again", and asking again is the same start.
            // A refusal that named the account has nothing to resend. The button is the primary
            // action here, because on this page it is the way forward.
            form class="edit" method="post" action=(profile_path) {
                @for (name, value) in fields {
                    input type="hidden" name=(name) value=(value);
                }
                div class="actions" {
                    button type="submit" { (t(lang, K::AccountProfileSendNew)) }
                    (back_link(lang, page))
                }
            }
        } @else {
            p class="primary" {
                (back_link(lang, page))
            }
        }
    }
}

/// How a call to Cognito's API ended, when it did not produce a code.
pub(crate) enum CognitoError {
    /// The endpoint answered, and the answer is not a code. The key is which of §13.23 §4's
    /// sentences to show; the status is the operator's, and the line is whether the pool was
    /// reached: a refusal the pool means is a `502` (an upstream said no), a pool that never
    /// answered is a `504`.
    Refused(K, u16),
    /// No answer within the bound.
    NoAnswer,
}

/// Where this deployment's Cognito API lives: the endpoint a test named, else the origin of the
/// issuer the settings name.
///
/// The fake is a `Config` field and not an environment variable, and that is the whole
/// argument: an env var is a setting a deployment can point at a host of its choosing, and the
/// only thing a test needs is a host on loopback. `compile_issuer` is https-only, so the real
/// answer can only ever be an https origin, and a plain-HTTP loopback URL cannot be expressed as
/// a setting at all.
fn cognito_endpoint_of(cfg: &Config, settings: &Settings) -> String {
    match cfg.cognito_endpoint.as_deref() {
        Some(e) => e.to_string(),
        None => settings.cognito_endpoint(),
    }
}

/// What the pool's API answered when it answered at all.
pub(crate) enum CognitoReply {
    /// A status that means "done", and the JSON body it came with.
    Ok(serde_json::Value),
    /// A status that means "no". The body is kept, because the `Session` a rejected code comes
    /// back with is in it, and the code page needs that to stay the same page.
    Error(serde_json::Value),
}

/// The reason a refusal carries: `__type` is `"TooManyRequestsException"` or
/// `"com.amazonaws.cognito#UserNotFoundException"`, and the reason is after the last `#`.
fn cognito_error_name(body: &serde_json::Value) -> String {
    body.get("__type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .rsplit('#')
        .next()
        .unwrap_or("")
        .to_string()
}

/// One call to Cognito's API (§13.22): the JSON 1.1 envelope every operation of it uses, the
/// operation named in `X-Amz-Target`, and the endpoint this deployment's issuer names.
///
/// No `ClientSecret` and no `SECRET_HASH`: the client this flow uses is a public client, the
/// same one the browser's sign-in page uses, and a secret is exactly what a binary that ships to
/// a browser does not have.
///
/// One attempt, and the bound is the whole wait. `http_status_as_error(false)` because a `400`
/// from this API is a named reason, and the reason is what the person is told;
/// `max_redirects(0)` because a redirect from a managed API is not a step this code takes, and
/// following one would hand a code, an address and a session to a host the settings never named.
/// Nothing that comes back is logged: the response carries the `Session`, and where it answers
/// with an `AuthenticationResult` it carries tokens.
pub(crate) fn cognito_post(
    cfg: &Config,
    settings: &Settings,
    target: &str,
    payload: &serde_json::Value,
) -> Result<CognitoReply, CognitoError> {
    let endpoint = cognito_endpoint_of(cfg, settings);
    if endpoint.is_empty() {
        return Err(CognitoError::Refused(K::AccountProfileRefused, 502));
    }
    let agent = ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(cfg.cognito_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    );
    let response = match agent
        .post(&endpoint)
        .header("X-Amz-Target", target)
        .header("Content-Type", "application/x-amz-json-1.1")
        .send(payload.to_string())
    {
        Ok(r) => r,
        Err(ureq::Error::Timeout(_)) => return Err(CognitoError::NoAnswer),
        Err(_) => return Err(CognitoError::Refused(K::AccountProfileRefused, 502)),
    };
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let text = body.read_to_string().unwrap_or_default();
    // A body that is not JSON is an answer this code cannot read, and the two callers read a
    // refusal by name and a success by field: an empty object answers both as "no".
    let value =
        serde_json::from_str::<serde_json::Value>(&text).unwrap_or_else(|_| serde_json::json!({}));
    if (200..300).contains(&status) {
        Ok(CognitoReply::Ok(value))
    } else {
        Ok(CognitoReply::Error(value))
    }
}

/// Ask Cognito for an email code for **the session's own user** (§13.22's one call, §13.25
/// step 1): `USER_AUTH`, the native app client from the settings, and
/// `PREFERRED_CHALLENGE=EMAIL_OTP`.
///
/// `username` is the gate's `X-Auth-Native-Username`, never an address and never a posted field.
/// That is the whole point of the shape: the pool resolves a `USERNAME` to one of its users, and
/// the only name that is guaranteed to be *this* session's user is the one the session's own
/// token carried. An address is not that name, and on a pool whose users' `email` and
/// `username` differ it is a different user or nobody. The body carries no `SECRET_HASH` and no
/// `ClientSecret` for the same reason the login page carries none: this is a public native
/// client, and a secret here would be a secret shipped to a binary a browser can read.
///
/// The answer is the `Session` to answer with, the masked address the code went to
/// (`CODE_DELIVERY_DESTINATION`, shown on the code page), and the `USERNAME` the challenge named
/// (`ChallengeParameters.USERNAME`). The third is the pool saying which of its users it is
/// asking: a pool that names one **other** than the user it was asked about has answered for
/// somebody else, and that is a refusal here, at the start, before a code reaches anybody's
/// mailbox on someone's behalf.
fn cognito_call(
    cfg: &Config,
    settings: &Settings,
    username: &str,
) -> Result<(String, Option<String>, String), CognitoError> {
    let payload = serde_json::json!({
        "AuthFlow": "USER_AUTH",
        "ClientId": settings.client_id,
        "AuthParameters": {
            "USERNAME": username,
            "PREFERRED_CHALLENGE": "EMAIL_OTP",
        },
    });
    let value = match cognito_post(
        cfg,
        settings,
        "AWSCognitoIdentityProviderService.InitiateAuth",
        &payload,
    )? {
        CognitoReply::Error(body) => {
            return Err(match cognito_error_name(&body).as_str() {
                // The pool has no such user, or has one it will not sign in. Both mean the same
                // thing to the person: the account this session signed in with is not one the
                // pool will send a code to, and signing out and in again is the way to find out
                // what happened.
                "UserNotFoundException"
                | "UserNotConfirmedException"
                | "NotAuthorizedException"
                | "CodeDeliveryFailureException" => {
                    CognitoError::Refused(K::AccountProfileNoUser, 400)
                }
                "TooManyRequestsException" | "LimitExceededException" => {
                    CognitoError::Refused(K::AccountProfileTooMany, 502)
                }
                _ => CognitoError::Refused(K::AccountProfileRefused, 502),
            });
        }
        CognitoReply::Ok(value) => value,
    };
    // A pool that hands back tokens at once is a pool that did not do what was asked: the
    // request was for a code, and these are not this page's to keep. They are dropped here, and
    // they reach no page, no header and no log line.
    if value.get("AuthenticationResult").is_some() {
        return Err(CognitoError::Refused(K::AccountProfileRefused, 502));
    }
    if value.get("ChallengeName").and_then(|v| v.as_str()) != Some("EMAIL_OTP") {
        return Err(CognitoError::Refused(K::AccountProfileRefused, 502));
    }
    let params = value.get("ChallengeParameters");
    // The username the challenge names, when it names one. A pool that names none is answering
    // about the user it was asked about, which is the name this call already holds.
    let named = params
        .and_then(|p| p.get("USERNAME"))
        .and_then(|v| v.as_str())
        .filter(|u| !u.trim().is_empty())
        .map(|u| u.trim().to_string());
    if let Some(named) = &named {
        if named != username {
            // The pool answered for a different account. Nothing is sent on, and the other
            // account is not named on the page: this is a shared surface, and a refusal that
            // says which user the pool reached is an oracle for anybody with any account.
            return Err(CognitoError::Refused(K::AccountProfileNotYours, 403));
        }
    }
    match value.get("Session").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => Ok((
            s.to_string(),
            params
                .and_then(|p| p.get("CODE_DELIVERY_DESTINATION"))
                .and_then(|v| v.as_str())
                .filter(|d| !d.trim().is_empty())
                .map(|d| d.to_string()),
            named.unwrap_or_else(|| username.to_string()),
        )),
        _ => Err(CognitoError::Refused(K::AccountProfileRefused, 502)),
    }
}

/// Answer the `EMAIL_OTP` challenge with the code the person typed (§13.22's second call): the
/// `Session` the challenge carried, the `USERNAME` the challenge named, and the code.
///
/// The username is the pool's own, not the address the form chose: `ChallengeParameters` is the
/// pool telling this page which of its users it is asking, and answering with an address the
/// pool did not name is a request to sign in as somebody else.
///
/// On success the answer is the `AuthenticationResult`, which carries the access token the update
/// step needs. It is returned by value and never stored: no page, header, log line or file sees
/// it (§13.22).
fn cognito_answer(
    cfg: &Config,
    settings: &Settings,
    session: &str,
    username: &str,
    code: &str,
) -> Result<serde_json::Value, CognitoAnswer> {
    let payload = serde_json::json!({
        "ChallengeName": "EMAIL_OTP",
        "ClientId": settings.client_id,
        "Session": session,
        "ChallengeResponses": { "USERNAME": username, "EMAIL_OTP_CODE": code },
    });
    let reply = cognito_post(
        cfg,
        settings,
        "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
        &payload,
    )?;
    match reply {
        CognitoReply::Ok(value) => match value.get("AuthenticationResult") {
            Some(auth) => Ok(auth.clone()),
            None => Err(CognitoAnswer::Refused(K::AccountProfileRefused)),
        },
        CognitoReply::Error(body) => {
            let name = cognito_error_name(&body);
            Err(match name.as_str() {
                // The code the person typed, mistyped. The page that asked for it comes back,
                // with the `Session` this answer carried if it carried one.
                "CodeMismatchException" => CognitoAnswer::WrongCode(
                    body.get("Session")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| s.to_string()),
                ),
                // The code is gone, or the session with it: the only way forward is a new one,
                // which is the same start.
                "ExpiredCodeException"
                | "NotAuthorizedException"
                | "UserNotFoundException"
                | "UserNotConfirmedException" => CognitoAnswer::Expired,
                "TooManyRequestsException" | "LimitExceededException" => {
                    CognitoAnswer::Refused(K::AccountProfileTooMany)
                }
                _ => CognitoAnswer::Refused(K::AccountProfileRefused),
            })
        }
    }
}

/// How the code step ended, when it did not produce an `AuthenticationResult`.
enum CognitoAnswer {
    /// The code was not the one the pool sent. The `Session` to ask again with, when the answer
    /// named a new one.
    WrongCode(Option<String>),
    /// The code, or the session that carried it, is gone: start again.
    Expired,
    /// The page that says why, in §13.23 §4's words.
    Refused(K),
    /// No answer within the bound.
    NoAnswer,
}

/// A call that never reached the pool, or reached it and got nothing readable, is the same
/// refusal at the code step as at the start; only the status is the step's own, and each caller
/// names it.
impl From<CognitoError> for CognitoAnswer {
    fn from(e: CognitoError) -> Self {
        match e {
            CognitoError::NoAnswer => CognitoAnswer::NoAnswer,
            CognitoError::Refused(key, _) => CognitoAnswer::Refused(key),
        }
    }
}

/// Write the attributes the person changed (§13.22's third call): one `UpdateUserAttributes`
/// carries every change, a removal as a blank value, which is what keeps a mixed edit at two
/// calls in the code request rather than three.
///
/// The access token arrives by value from the step that verified the code, and is used here and
/// dropped: it is not this page's to keep, and it reaches no page, header, log line or file.
fn cognito_update(
    cfg: &Config,
    settings: &Settings,
    access: &str,
    changes: &[ProfileChange],
) -> Result<(), CognitoError> {
    let attrs: Vec<serde_json::Value> = changes
        .iter()
        .map(|c| {
            serde_json::json!({
                "Name": c.claim,
                // A blank value is how this API deletes an attribute (§13.22), which is what
                // makes an emptied field a removal in the same call as a changed one.
                "Value": c.after.clone().unwrap_or_default(),
            })
        })
        .collect();
    let payload = serde_json::json!({ "AccessToken": access, "UserAttributes": attrs });
    match cognito_post(
        cfg,
        settings,
        "AWSCognitoIdentityProviderService.UpdateUserAttributes",
        &payload,
    )? {
        CognitoReply::Ok(_) => Ok(()),
        CognitoReply::Error(body) => {
            // One of the values is not one the directory will store: the person can fix that, so
            // it is a `400` and not a `502`.
            let (key, status) = match cognito_error_name(&body).as_str() {
                "InvalidParameterException" | "InvalidUserTypeException" => {
                    (K::AccountProfileBadValue, 400)
                }
                _ => (K::AccountProfileRefused, 502),
            };
            Err(CognitoError::Refused(key, status))
        }
    }
}

/// The `cognito:username` of the ID token the code step just got back, and `None` for a token
/// that does not name a user this page can use.
///
/// The token is **not** verified, and that is the design's decision (§13.22): it arrives over the
/// same TLS call that asked for the code, from the endpoint the settings name, and the only thing
/// this page does with it is check that it names the user the code went to. A signature check
/// would need the pool's JWKS, which the gate holds and this process does not, and it would
/// change nothing: whoever can hand this process a token can hand it one that passes every claim
/// check below as well. What the checks are for is the accident, not the attacker: a pool that
/// answered the wrong user, and a token from another pool, from another app client, for an access
/// token, or out of its life, are all a token this page must not spend.
///
/// §13.25 step 3: the name compared is the **username**, not the `email`. The address is not the
/// identity here, and on a pool whose users' two names differ a token that names this user
/// carries an address nobody signed in with (the fixture's stranger signs in as
/// `sam@elsewhere.com` on a token whose `email` is `Sam@Elsewhere.COM`). A token with no
/// `cognito:username` is refused: a bind that cannot be satisfied is a bind that failed.
fn id_token_username(token: &str, settings: &Settings) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let text = |key: &str| claims.get(key).and_then(|v| v.as_str()).unwrap_or("");
    if text("token_use") != "id"
        || text("iss") != settings.issuer
        || text("aud") != settings.client_id
    {
        return None;
    }
    // A token whose life has run out is not this page's to spend. `exp` in the future is all
    // "not expired" can mean here: there is no clock of the pool's to compare against, and the
    // code step runs inside the code's own three minutes, so no leeway constant is worth one.
    claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .filter(|exp| *exp > now() as i64)?;
    if !email_verified_true(
        claims
            .get("email_verified")
            .unwrap_or(&serde_json::Value::Null),
    ) {
        return None;
    }
    claims
        .get("cognito:username")
        .and_then(|v| v.as_str())
        .filter(|u| !u.trim().is_empty())
        .map(|u| u.trim().to_string())
}

/// The profile edit's `POST` (§13.22, §13.23, §13.25): refuse everything that must be refused
/// without asking Cognito anything, then ask for a code for **this session's own Cognito user**
/// and show the page that names the address it went to.
///
/// The order is the console's, for the same reasons: the door (`Sec-Fetch-Site`) first, because
/// a cross-site form must not reach anybody's mailbox; then the user, because the pool acts on
/// one name and only the gate's header names the one this session is; then the field names,
/// because a claim outside the allowlist is a field that cannot save and a request cannot be
/// honoured in part; then the values. Every refusal writes nothing and calls nothing.
///
/// There is no `rev` here. This `POST` writes no access file: the write is Cognito's, and it
/// happens in slice 5c, behind the code.
#[allow(clippy::too_many_arguments)]
pub(crate) fn account_profile_post(
    mut req: Request,
    cfg: &Config,
    prefs: &mut AccountPrefs,
    lang: Lang,
    look: AccountLook,
    settings: &Settings,
    ids: &[String],
    uuid: Option<&str>,
    own: &AccountOwn,
    profile_path: &str,
    page: &str,
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
    let editable = profile_editable(settings);
    // (2) The session must name the Cognito user the edit acts on. The gate sends that name for a
    // native sign-in and for nothing else, so a social session, an API key and a cookie from
    // before the header has no user this page can ask a pool about, and the sentence that says so
    // is the one the panel already shows. Refused before the body is looked at beyond the names,
    // and before any call: a code sent on a name nobody holds goes to a stranger's mailbox.
    let native = match native_user(&req) {
        Some(u) => u.to_string(),
        None => {
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountProfileNotSavedTitle),
                html! { p { (t(lang, K::AccountProfileNotNative)) } },
                look,
                false,
            );
            return;
        }
    };
    // (3) Every posted name is an editable claim, or the whole submission is refused. A name
    // that is not one is a hand-made form naming a claim Cognito will not accept, and honouring
    // the rest of it would tell the person their change was sent. `email` is one of those names
    // now (§13.26 §4): the address is not a field on this page, and a form that posts one is a
    // form trying to choose where the code goes.
    for (name, _) in &form.0 {
        if !editable.iter().any(|c| c == name) {
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountProfileNotSavedTitle),
                html! { p { (format!("{name}: {}", t(lang, K::AccountProfileCannotEdit))) } },
                look,
                false,
            );
            return;
        }
    }
    // (4) Each value: at most the length the field says, and no control character. A newline in
    // a name is not a name, and a value that reaches a directory with control bytes in it is a
    // value every later reader has to guess about. The refusal names the field by the word the
    // person read, marks it, and leaves the rest of the form standing.
    for (name, value) in &form.0 {
        if value.chars().count() > PROFILE_VALUE_MAX || value.chars().any(|c| c.is_control()) {
            let label = profile_label(lang, name).unwrap_or_else(|| name.clone());
            // The page is built before the response, because the page reads the request's
            // headers (the forwarded claims) and the response takes the request.
            let body = page_account(
                lang,
                ids,
                uuid,
                own,
                None,
                Some(&ProfileForm::again(
                    settings,
                    &req,
                    &form,
                    Some((
                        name.clone(),
                        format!("{label}: {}", t(lang, K::AccountProfileValueBad)),
                    )),
                    None,
                )),
            );
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountProfileEdit),
                body,
                look,
                false,
            );
            return;
        }
    }
    // (5) What would change, against what the proxy forwarded. A field the form did not post is
    // a field that is not being changed, which is what lets the code page's resend post only the
    // changed ones: an absent field means "leave it", an empty one means "remove it".
    let mut changes: Vec<ProfileChange> = Vec::new();
    let mut resend: Vec<(String, String)> = Vec::new();
    for (name, value) in &form.0 {
        let header = match settings
            .profile_claims
            .iter()
            .find(|c| &c.claim == name)
            .map(|c| c.header.clone())
        {
            Some(header) => header,
            None => continue,
        };
        let before = forwarded_claim(&req, &header).trim().to_string();
        let after = value.trim().to_string();
        if before == after {
            continue;
        }
        changes.push(ProfileChange {
            claim: name.clone(),
            before: (!before.is_empty()).then_some(before),
            after: (!after.is_empty()).then_some(after),
        });
        resend.push((name.clone(), value.clone()));
    }
    if changes.is_empty() {
        // Not an error: nothing was refused and nothing was sent. A warning, in the page the
        // person is already looking at, because the ordinary cause is a field they did not type
        // in.
        let body = page_account(
            lang,
            ids,
            uuid,
            own,
            None,
            Some(&ProfileForm::again(
                settings,
                &req,
                &form,
                None,
                Some(t(lang, K::AccountProfileNothingChanged).to_string()),
            )),
        );
        respond_account(
            req,
            200,
            prefs,
            t(lang, K::AccountProfileEdit),
            body,
            look,
            false,
        );
        return;
    }
    // Every page past this point carries its own lede (the address the code went to, or why
    // nothing was saved), so the bar's menu keeps the identity out: the design counts one
    // `p.lede` per page (§13.23 §3, §4).
    prefs.page_lede = true;
    match cognito_call(cfg, settings, &native) {
        Ok((session, destination, _)) => {
            // What the code step needs, as hidden fields: the `Session` to answer with, and one
            // entry per changed claim, an emptied one posted empty. The code page is a form and
            // not a session: everything the next request must send is on the page, and nothing
            // the person did not type is kept on the server (§13.22). The username is **not**
            // among them (§13.25 step 2): the code step answers for the user of the request that
            // arrives, and a username that rides in a form is a form that can be posted by
            // somebody else and answered for them.
            let mut carry: Vec<(String, String)> = vec![("Session".to_string(), session)];
            for ch in &changes {
                carry.push((ch.claim.clone(), ch.after.clone().unwrap_or_default()));
            }
            respond_account(
                req,
                200,
                prefs,
                t(lang, K::AccountProfileCodeTitle),
                page_profile_code(
                    lang,
                    &ProfileCode {
                        destination: destination.as_deref(),
                        changes: &changes,
                        carry: &carry,
                        resend: &resend,
                        err: None,
                    },
                    profile_path,
                    &format!("{profile_path}/code"),
                    page,
                ),
                look,
                false,
            )
        }
        Err(CognitoError::NoAnswer) => respond_account(
            req,
            504,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(
                lang,
                K::AccountProfileNoAnswer,
                Some(&resend),
                profile_path,
                page,
            ),
            look,
            false,
        ),
        Err(CognitoError::Refused(key, status)) => respond_account(
            req,
            status,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(lang, key, None, profile_path, page),
            look,
            false,
        ),
    }
}

/// The code step (§13.22, §13.25 step 2): answer the `EMAIL_OTP` challenge **for the user of the
/// request that arrived**, bind the token it returns to that same user, write the attributes, and
/// render the outcome.
///
/// Every check the start made is made **again** here, against the live files, because the two
/// steps are two requests and the files are edited between requests: the claim list, the roster
/// and the `denied` list are all re-read, and a form whose claim has left the settings is refused
/// rather than sent. The `Session` is not a credential and buys nothing: it names a challenge, and
/// the person answering it has already been proved by the proxy secret, the identity header and
/// the veto, which `handle_account` has just done for this request on the same terms as the `GET`.
///
/// The order of the calls is the design's: at most two, and the update only after the code has
/// been accepted **and** the token it returned names this session's user. A token for another
/// account is dropped unused, so no `UpdateUserAttributes` ever runs with an access token the pool
/// handed to somebody else.
#[allow(clippy::too_many_arguments)]
pub(crate) fn account_profile_code_post(
    mut req: Request,
    cfg: &Config,
    prefs: &mut AccountPrefs,
    lang: Lang,
    look: AccountLook,
    settings: &Settings,
    profile_path: &str,
    page: &str,
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
    let editable = profile_editable(settings);
    // A refusal before any call: the page that says nothing was changed, the sentence, and the
    // same start offered, because starting over is always correct once the form is refused.
    let refused = |req: Request, prefs: &mut AccountPrefs, key: K, fields: &[(String, String)]| {
        respond_account(
            req,
            400,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(lang, key, Some(fields), profile_path, page),
            look,
            false,
        );
    };
    // (2) The user this request is, as the gate named it on **this** request (§13.25 step 2).
    // Not a field: a code step that answered the username its form carried would answer for the
    // user of whoever posted the form, and the person whose session minted it would be the one
    // whose attributes got written. A request the gate named nobody for answers nothing.
    let native = match native_user(&req) {
        Some(u) => u.to_string(),
        None => {
            refused(req, prefs, K::AccountProfileNotNative, &[]);
            return;
        }
    };
    // (3) Every posted name is the code, the `Session` the page carries, or an editable claim
    // **the settings still list**. A name that is not one is a hand-made form naming a claim the
    // directory will not accept, and honouring the rest of it would tell the person their change
    // was written. `email` and `username` are not names any more: a form that posts one of them
    // is a form from before this step, or a form choosing where a code goes.
    for (name, _) in &form.0 {
        let known = name == "code" || name == "Session" || editable.iter().any(|c| c == name);
        if !known {
            refused(req, prefs, K::AccountProfileCannotEdit, &[]);
            return;
        }
    }
    // (4) The values and the `Session`: bounded, and no control character. The last is the pool's
    // own string riding through a form, so it gets the same bound as anything else a hand-made
    // form can fill.
    for (name, value) in &form.0 {
        if name == "code" {
            continue;
        }
        if value.chars().count() > PROFILE_VALUE_MAX || value.chars().any(|c| c.is_control()) {
            let label = profile_label(lang, name).unwrap_or_else(|| name.clone());
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountProfileNotSavedTitle),
                html! { p class="lede" { (format!("{label}: {}", t(lang, K::AccountProfileValueBad))) } },
                look,
                false,
            );
            return;
        }
    }
    // (5) The code, and the session it belongs to. A missing `Session` is the challenge being
    // gone, which is what an expired code means, and the way forward is the same: a new one.
    let session = form.get("Session").trim().to_string();
    let code = match profile_code(form.get("code")) {
        Some(c) => c,
        None => {
            refused(req, prefs, K::AccountProfileWrongCode, &[]);
            return;
        }
    };
    if session.is_empty() {
        refused(req, prefs, K::AccountProfileExpired, &[]);
        return;
    }
    // (6) What the form says to write, recomputed against the claims the settings list **now**
    // and the values the proxy forwarded on this request. A claim that left the settings between
    // the two steps is not written, and a form left with nothing to write is refused rather than
    // answered with a save that changed nothing.
    let mut changes: Vec<ProfileChange> = Vec::new();
    for (name, value) in &form.0 {
        if name == "code" || name == "Session" {
            continue;
        }
        let header = match settings
            .profile_claims
            .iter()
            .find(|c| &c.claim == name)
            .map(|c| c.header.clone())
        {
            Some(header) => header,
            None => continue,
        };
        let before = forwarded_claim(&req, &header).trim().to_string();
        let after = value.trim().to_string();
        if before == after {
            continue;
        }
        changes.push(ProfileChange {
            claim: name.clone(),
            before: (!before.is_empty()).then_some(before),
            after: (!after.is_empty()).then_some(after),
        });
    }
    // What the code page and the start's form carry, rebuilt from this request so a refusal shows
    // the same summary the person was reading.
    let mut resend: Vec<(String, String)> = Vec::new();
    let mut carry: Vec<(String, String)> = vec![("Session".to_string(), session.clone())];
    for ch in &changes {
        let value = ch.after.clone().unwrap_or_default();
        resend.push((ch.claim.clone(), value.clone()));
        carry.push((ch.claim.clone(), value));
    }
    if changes.is_empty() {
        refused(req, prefs, K::AccountProfileNothingChanged, &resend);
        return;
    }
    // Every page past here carries its own lede, so the bar's menu keeps the identity out.
    prefs.page_lede = true;
    let code_path = format!("{profile_path}/code");
    match cognito_answer(cfg, settings, &session, &native, &code) {
        Ok(auth) => {
            // The token the challenge returned, bound to this session's user (§13.22, §13.25
            // step 3). It is decoded, not verified, and what the checks are for is the accident:
            // a pool that answered the wrong user, a token from another pool, from another app
            // client, an access token posing as an ID token, and a token out of its life are
            // each a token this page must not spend. `id_token_username` is that list, and the
            // name it returns is compared to the header, never to an address.
            let id = auth
                .get("IdToken")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if id_token_username(id, settings).as_deref() != Some(native.as_str()) {
                // The other user is not named on the page: this is a shared surface, and a
                // refusal that says which account the code belonged to is an oracle for anybody
                // with any account at all.
                respond_account(
                    req,
                    403,
                    prefs,
                    t(lang, K::AccountProfileNotSavedTitle),
                    page_profile_outcome(lang, K::AccountProfileNotYours, None, profile_path, page),
                    look,
                    false,
                );
                return;
            }
            let access = auth
                .get("AccessToken")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            match cognito_update(cfg, settings, access, &changes) {
                Ok(()) => respond_account(
                    req,
                    200,
                    prefs,
                    t(lang, K::AccountProfileSavedTitle),
                    page_profile_saved(lang, &changes, page),
                    look,
                    false,
                ),
                Err(CognitoError::NoAnswer) => respond_account(
                    req,
                    504,
                    prefs,
                    t(lang, K::AccountProfileUnsureTitle),
                    page_profile_outcome(
                        lang,
                        K::AccountProfileNoAnswerUnsure,
                        None,
                        profile_path,
                        page,
                    ),
                    look,
                    false,
                ),
                Err(CognitoError::Refused(key, status)) => respond_account(
                    req,
                    status,
                    prefs,
                    t(lang, K::AccountProfileNotSavedTitle),
                    page_profile_outcome(lang, key, None, profile_path, page),
                    look,
                    false,
                ),
            }
        }
        Err(CognitoAnswer::WrongCode(new_session)) => {
            // The code page again, the field emptied, and the `Session` this answer carried when
            // it carried one: the pool has moved the challenge on, and the old one is gone.
            let session = new_session.unwrap_or(session);
            carry[0] = ("Session".to_string(), session);
            respond_account(
                req,
                400,
                prefs,
                t(lang, K::AccountProfileCodeTitle),
                page_profile_code(
                    lang,
                    &ProfileCode {
                        // No destination on this page: the answer that refused the code names a
                        // new `Session`, not a new address, and the address the first code went to
                        // is not this page's to repeat.
                        destination: None,
                        changes: &changes,
                        carry: &carry,
                        resend: &resend,
                        err: Some(t(lang, K::AccountProfileWrongCode)),
                    },
                    profile_path,
                    &code_path,
                    page,
                ),
                look,
                false,
            )
        }
        Err(CognitoAnswer::Expired) => respond_account(
            req,
            400,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(
                lang,
                K::AccountProfileExpired,
                Some(&resend),
                profile_path,
                page,
            ),
            look,
            false,
        ),
        Err(CognitoAnswer::NoAnswer) => respond_account(
            req,
            504,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(
                lang,
                K::AccountProfileNoAnswer,
                Some(&resend),
                profile_path,
                page,
            ),
            look,
            false,
        ),
        Err(CognitoAnswer::Refused(key)) => respond_account(
            req,
            502,
            prefs,
            t(lang, K::AccountProfileNotSavedTitle),
            page_profile_outcome(lang, key, None, profile_path, page),
            look,
            false,
        ),
    }
}
