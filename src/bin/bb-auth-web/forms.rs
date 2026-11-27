use crate::*;

// ---------------------------------------------------------------------------
// Form furniture
// ---------------------------------------------------------------------------

/// A refused submission: the library's or a handler's own sentence, verbatim, and, only
/// when the failing step can be about exactly one field, the wire `name=` of that field.
///
/// Most refusals attribute nothing: a bare `String` converts into one via [`From`] with
/// `field: None`, so a `?` on a library call that cannot be pinned to one field costs a
/// handler nothing. [`Refusal::on`] is the deliberate exception, spelled out at each call
/// site [`mutate`] attributes; never guessed from the message text.
pub(crate) struct Refusal {
    pub(crate) msg: String,
    /// The offending input's `name=`, owned rather than `&'static str`: a table of app
    /// clients names its fields after the providers in the file, so which field a refusal is
    /// about is not always a literal this binary contains.
    pub(crate) field: Option<String>,
}

impl Refusal {
    /// Attribute this refusal to the field named `field` (its `name=` attribute, exactly).
    pub(crate) fn on(field: impl Into<String>, msg: impl Into<String>) -> Self {
        Refusal {
            msg: msg.into(),
            field: Some(field.into()),
        }
    }

    /// `true` when this refusal is attributed to the field named `name`: what
    /// [`text_field`] and [`urls_field`] ask to decide whether to render themselves invalid.
    pub(crate) fn is(&self, name: &str) -> bool {
        self.field.as_deref() == Some(name)
    }
}

impl From<String> for Refusal {
    /// The common case: a message with nothing to attribute it to.
    fn from(msg: String) -> Self {
        Refusal { msg, field: None }
    }
}

/// The id of a form's `div.err` block. The one field a [`Refusal`] is attributed to points
/// at it with `aria-describedby`, since the message itself lives above the form, not beside
/// the field.
pub(crate) const ERR_ID: &str = "form-error";

/// Fill `{0}`, `{1}`, … in `template` from `args`, in one pass.
///
/// The single pass is the point, for the reason `render_page` (the gate's page filler) gives for
/// its own substitution:
/// every argument is something an operator typed, and rescanning what a placeholder expanded to
/// would let a claim named `{1}` ask for a second round of substitution inside the sentence
/// about it. A `{` that opens nothing (no closing `}`, or a body that is not a number) is left
/// as the text it is, and an index past the end of `args` fills the empty string: a message with
/// a hole in it is a bug in this file, and the test over every code is what catches it, not a
/// panic on a page an operator is reading.
pub(crate) fn fill(template: &str, args: &[&str]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(at) = rest.find('{') {
        out.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        match rest.find('}') {
            Some(end) if rest[..end].bytes().all(|b| b.is_ascii_digit()) => {
                let n = rest[..end].parse::<usize>().unwrap_or(usize::MAX);
                out.push_str(args.get(n).copied().unwrap_or(""));
                rest = &rest[end + 1..];
            }
            _ => out.push('{'),
        }
    }
    out.push_str(rest);
    out
}

/// The field a [`SettingKey`] is about on the Settings page: its `name=` and its visible label.
///
/// One helper for the pair because a translated refusal has to name the label in its message and
/// mark the input by its `name=`, and the two are the same fact said twice. A key the library
/// names is the library's; which box on this page holds it is this page's, and this is the one
/// place that knows both.
fn setting_field(key: SettingKey) -> (&'static str, K) {
    match key {
        SettingKey::LoginUrl => ("login_url", K::GlobalLoginUrl),
        SettingKey::DeniedUrl => ("denied_url", K::GlobalDeniedUrl),
        SettingKey::LandingUrl => ("landing_url", K::GlobalLandingUrl),
        SettingKey::Issuer => ("issuer", K::Issuer),
        SettingKey::SocialCallbackUrl => ("callback", K::SocialCallback),
        SettingKey::StylesheetUrl => ("stylesheet", K::StylesheetUrl),
        SettingKey::LogoUrl => ("logo", K::LogoUrl),
        SettingKey::ClientIpHeader => ("client_ip_header", K::ClientIpHeader),
        SettingKey::RequestIdHeader => ("request_id_header", K::RequestIdHeader),
        SettingKey::AuditRotation => ("audit_rotation", K::AuditRotation),
        SettingKey::AuditRetention => ("audit_retention", K::AuditRetention),
    }
}

/// A settings-file refusal as this page says it: in the reader's language, naming the visible
/// label of the field it is about, and marking that field `invalid` (docs/ARCHITECTURE.md
/// §13.31).
///
/// The match is exhaustive, with **no `_` arm on purpose**. `SettingsRefusal` is the library's
/// answer about a file three programs read, so a refusal added there must not be able to arrive
/// here and be shown in English on an Italian page, which is what a wildcard would do silently.
/// Without one, a new variant is a compile error until somebody decides what the page says about
/// it and writes the `K` key, which is the same reflex that makes [`SettingsRefusal::code`] an
/// exhaustive match.
///
/// `{0}` of every key is `t(lang, label)`, which is what "names the visible field label" means
/// mechanically. A typed value is quoted only where the field cannot show which part of it is
/// wrong: an entry of a list (a claim, an attribute, a host) or a header name. The five codes
/// this form can never produce (§13.31 §5) are the one place the library's English sentence is
/// shown, because the operator who meets them is at a shell, where that is exactly what
/// `bb-auth-adm --check-settings` says.
pub(crate) fn settings_refusal(lang: Lang, r: &SettingsRefusal) -> Refusal {
    // The attributes the field accepts, as its own help spells them: the library's list, joined,
    // so a fourth attribute added there is named here by the same edit.
    let known = IDENTITY_ATTRS.join(", ");
    match r {
        SettingsRefusal::Version { .. }
        | SettingsRefusal::ButtonBareName { .. }
        | SettingsRefusal::ButtonNoIdp
        | SettingsRefusal::ButtonIdpCharset { .. }
        | SettingsRefusal::ButtonTwice { .. } => {
            Refusal::from(fill(t(lang, K::SetRefFileOnly), &[&r.to_string()]))
        }
        SettingsRefusal::ClaimCharset { claim } => Refusal::on(
            "claims",
            fill(
                t(lang, K::SetRefClaimCharset),
                &[t(lang, K::ProfileClaims), claim],
            ),
        ),
        SettingsRefusal::ClaimEmptyPart { claim } => Refusal::on(
            "claims",
            fill(
                t(lang, K::SetRefClaimEmptyPart),
                &[t(lang, K::ProfileClaims), claim],
            ),
        ),
        SettingsRefusal::ClaimConsumed { claim } => Refusal::on(
            "claims",
            fill(
                t(lang, K::SetRefClaimConsumed),
                &[t(lang, K::ProfileClaims), claim],
            ),
        ),
        SettingsRefusal::ClaimHeaderReserved { claim, header } => Refusal::on(
            "claims",
            fill(
                t(lang, K::SetRefClaimHeaderReserved),
                &[t(lang, K::ProfileClaims), claim, header],
            ),
        ),
        SettingsRefusal::ClaimsCollide {
            first,
            second,
            header,
        } => Refusal::on(
            "claims",
            fill(
                t(lang, K::SetRefClaimsCollide),
                &[t(lang, K::ProfileClaims), first, second, header],
            ),
        ),
        SettingsRefusal::AttrUnknown { attr } => Refusal::on(
            "identity",
            fill(
                t(lang, K::SetRefAttrUnknown),
                &[t(lang, K::IdentityAttrs), attr, &known],
            ),
        ),
        SettingsRefusal::AttrTwice { attr } => Refusal::on(
            "identity",
            fill(
                t(lang, K::SetRefAttrTwice),
                &[t(lang, K::IdentityAttrs), attr],
            ),
        ),
        SettingsRefusal::AttrNone => Refusal::on(
            "identity",
            fill(
                t(lang, K::SetRefAttrNone),
                &[t(lang, K::IdentityAttrs), &known],
            ),
        ),
        SettingsRefusal::TtlBelowFloor { .. } => Refusal::on(
            "ttl",
            fill(
                t(lang, K::SetRefTtlBelowFloor),
                &[t(lang, K::SessionTtl), &MIN_SESSION_TTL.to_string()],
            ),
        ),
        SettingsRefusal::TtlAboveCeiling { .. } => Refusal::on(
            "ttl",
            fill(
                t(lang, K::SetRefTtlAboveCeiling),
                &[t(lang, K::SessionTtl), &MAX_SESSION_TTL.to_string()],
            ),
        ),
        // The app client of the email flow and the one of a button are the same grammar in two
        // rows of the "Ways in" table, so the row's own heading is what the message names.
        SettingsRefusal::AppClientId { button: None, id } => Refusal::on(
            "client_id",
            fill(
                t(lang, K::SetRefAppClientId),
                &[t(lang, K::SignInEmail), id],
            ),
        ),
        SettingsRefusal::AppClientId {
            button: Some(idp),
            id,
        } => Refusal::on(
            aud_field(idp),
            fill(t(lang, K::SetRefAppClientId), &[social_idp_label(idp), id]),
        ),
        SettingsRefusal::Url { key, fault, .. } => {
            let (field, label) = setting_field(*key);
            let key = match fault {
                UrlFault::NotPrintable => K::SetRefUrlNotPrintable,
                UrlFault::NotHttps => K::SetRefUrlNotHttps,
                UrlFault::EmptyHost => K::SetRefUrlEmptyHost,
                UrlFault::Userinfo => K::SetRefUrlUserinfo,
                UrlFault::Backslash => K::SetRefUrlBackslash,
                UrlFault::UserinfoOrBackslash => K::SetRefUrlUserinfoOrBackslash,
                UrlFault::QueryOrFragment => K::SetRefUrlQueryOrFragment,
                UrlFault::Quote => K::SetRefUrlQuote,
                UrlFault::NotHttpsOrRooted => K::SetRefUrlNotHttpsOrRooted,
            };
            Refusal::on(field, fill(t(lang, key), &[t(lang, label)]))
        }
        SettingsRefusal::CallbackNotHttps => {
            let (field, label) = setting_field(SettingKey::SocialCallbackUrl);
            Refusal::on(
                field,
                fill(t(lang, K::SetRefCallbackNotHttps), &[t(lang, label)]),
            )
        }
        SettingsRefusal::CookieDomainNotBare { .. } => Refusal::on(
            "cookie_domain",
            fill(
                t(lang, K::SetRefCookieDomainNotBare),
                &[t(lang, K::CookieDomain)],
            ),
        ),
        SettingsRefusal::CookieDomainSingleLabel { .. } => Refusal::on(
            "cookie_domain",
            fill(
                t(lang, K::SetRefCookieDomainSingleLabel),
                &[t(lang, K::CookieDomain)],
            ),
        ),
        SettingsRefusal::HostControlByte { raw } => Refusal::on(
            "hosts",
            fill(
                t(lang, K::SetRefHostControlByte),
                &[t(lang, K::AuthorizedHosts), raw],
            ),
        ),
        SettingsRefusal::HostNotBare { raw } => Refusal::on(
            "hosts",
            fill(
                t(lang, K::SetRefHostNotBare),
                &[t(lang, K::AuthorizedHosts), raw],
            ),
        ),
        SettingsRefusal::HostAtOrDotDot { raw } => Refusal::on(
            "hosts",
            fill(
                t(lang, K::SetRefHostAtOrDotDot),
                &[t(lang, K::AuthorizedHosts), raw],
            ),
        ),
        // Attributed to the hosts field, which is where the operator goes to fix it, and naming
        // the cookie domain by its label, because the two are checked against each other and sit
        // one above the other for exactly that reason.
        SettingsRefusal::HostsOutsideCookieDomain {
            hosts,
            cookie_domain,
        } => Refusal::on(
            "hosts",
            fill(
                t(lang, K::SetRefHostsOutsideCookieDomain),
                &[
                    t(lang, K::AuthorizedHosts),
                    &hosts.join(", "),
                    t(lang, K::CookieDomain),
                    cookie_domain,
                ],
            ),
        ),
        SettingsRefusal::LandingOffHosts => Refusal::on(
            "landing_url",
            fill(
                t(lang, K::SetRefLandingOffHosts),
                &[t(lang, K::GlobalLandingUrl), t(lang, K::AuthorizedHosts)],
            ),
        ),
        SettingsRefusal::OauthDomainNotBare { .. } => Refusal::on(
            "domain",
            fill(
                t(lang, K::SetRefOauthDomainNotBare),
                &[t(lang, K::OauthDomain)],
            ),
        ),
        // The two the form can produce and already says something about, in its own words, in
        // both languages: reused rather than rewritten, because the row says the same thing
        // before the save as after it.
        SettingsRefusal::ButtonNoAudience { idp } => Refusal::on(
            aud_field(idp),
            fill(t(lang, K::AudienceNeeded), &[social_idp_label(idp)]),
        ),
        SettingsRefusal::SocialHalfConfigured { .. } => Refusal::on(
            "domain",
            fill(
                t(lang, K::SocialWiringNeeded),
                &[t(lang, K::OauthDomain), t(lang, K::SocialCallback)],
            ),
        ),
        SettingsRefusal::AuditHeader { key, name, fault } => {
            let (field, label) = setting_field(*key);
            let key = match fault {
                HeaderFault::NotAName => K::SetRefHeaderNotAName,
                HeaderFault::Credential => K::SetRefHeaderCredential,
            };
            Refusal::on(field, fill(t(lang, key), &[t(lang, label), name]))
        }
        // The shared header is marked on the request id, and the message names the other field
        // by its label, which is the one the operator has to go and change.
        SettingsRefusal::AuditHeadersSame { name } => Refusal::on(
            "request_id_header",
            fill(
                t(lang, K::SetRefHeadersSame),
                &[
                    t(lang, K::RequestIdHeader),
                    name,
                    t(lang, K::ClientIpHeader),
                ],
            ),
        ),
        SettingsRefusal::AuditLimitNotAmount { key, .. } => {
            let (field, label) = setting_field(*key);
            Refusal::on(
                field,
                fill(t(lang, K::SetRefLimitNotAmount), &[t(lang, label)]),
            )
        }
        SettingsRefusal::AuditLimitZero { key, .. } => {
            let (field, label) = setting_field(*key);
            Refusal::on(field, fill(t(lang, K::SetRefLimitZero), &[t(lang, label)]))
        }
        SettingsRefusal::AuditLimitTooMuch { key, unit, .. } => {
            let (field, label) = setting_field(*key);
            let max = unit.max_amount();
            Refusal::on(
                field,
                fill(
                    t(lang, K::SetRefLimitTooMuch),
                    &[
                        t(lang, label),
                        &max.to_string(),
                        unit_label(lang, *unit, max),
                    ],
                ),
            )
        }
        // The pair, not one of them: the refusal is that neither of the two is a size, and the
        // retention is the box an operator is more likely to fill in.
        SettingsRefusal::AuditUnbounded { .. } => Refusal::on(
            "audit_retention",
            fill(
                t(lang, K::SetRefAuditUnbounded),
                &[t(lang, K::AuditRotation), t(lang, K::AuditRetention)],
            ),
        ),
        SettingsRefusal::BrandControl { .. } => Refusal::on(
            "brand",
            fill(t(lang, K::SetRefBrandControl), &[t(lang, K::BrandName)]),
        ),
        SettingsRefusal::BrandTooLong { chars } => Refusal::on(
            "brand",
            fill(
                t(lang, K::SetRefBrandTooLong),
                &[
                    t(lang, K::BrandName),
                    &chars.to_string(),
                    &MAX_BRAND_NAME.to_string(),
                ],
            ),
        ),
        // The field is `ui_theme` and not the file's `theme`: it is the page's own name for the
        // box, and the one the form posts (§13.31 §2).
        SettingsRefusal::ThemeUnknown { .. } => Refusal::on(
            "ui_theme",
            fill(t(lang, K::DefaultThemeBad), &[t(lang, K::DefaultTheme)]),
        ),
    }
}

/// The scaffold every editing form shares: the `POST` back to the route that rendered it,
/// the `rev` the concurrency check reads, the refusal above the fields it is about, and a
/// way out that changes nothing.
///
/// The action is always [`View::at`] — a form posts to the path it was served from — which
/// is what makes a re-render after a refusal literally the same call with an error added.
pub(crate) fn form_shell(
    v: &View,
    err: Option<&Refusal>,
    fields: Markup,
    submit: &str,
    danger: bool,
) -> Markup {
    form_shell_at(
        &v.href(&v.at),
        v.rev,
        &v.href(&v.at.parent()),
        v.t(K::Cancel),
        err,
        fields,
        submit,
        danger,
    )
}

/// [`form_shell`] with the three things it takes from a console [`View`] given as values: where
/// the form posts, the `rev` it carries, and where its cancel link goes. The self-service page
/// has no `View` and renders the same form through this, so the two surfaces cannot drift.
#[allow(clippy::too_many_arguments)]
pub(crate) fn form_shell_at(
    action: &str,
    rev: &str,
    cancel: &str,
    cancel_label: &str,
    err: Option<&Refusal>,
    fields: Markup,
    submit: &str,
    danger: bool,
) -> Markup {
    html! {
        form class="edit" method="post" action=(action) {
            // The library's words, verbatim: the sentence `bb-auth-adm` prints for the same
            // refusal, so an operator who has read one recognises the other. `id` is what
            // an attributed field's `aria-describedby` points at.
            @if let Some(e) = err { div class="err" id=(ERR_ID) { (e.msg) } }
            input type="hidden" name="rev" value=(rev);
            (fields)
            div class="actions" {
                button type="submit" class=@if danger { "danger" } @else { "" } { (submit) }
                a class="pill" href=(cancel) { (cancel_label) }
            }
        }
    }
}

/// A one-line text field. The label is the file's own field name wherever there is one.
/// The input also carries an `f-<name>` class, keyed off that same wire name, so the
/// stylesheet can size each field to what it holds (an email wide, a `duration` narrow)
/// without this helper knowing anything about measures itself.
///
/// `invalid` marks this as the one field a [`Refusal`] is attributed to: it adds `.invalid`
/// (the `.f-<name>` class stays, so the width rule still applies) to colour the border
/// `--error`, and sets `aria-invalid` plus `aria-describedby` so the association with the
/// message above the form is real for assistive tech, not just a colour.
pub(crate) fn text_field(
    label: &str,
    name: &str,
    value: &str,
    placeholder: &str,
    hint: Option<&str>,
    invalid: bool,
) -> Markup {
    text_field_with(
        label,
        name,
        value,
        placeholder,
        hint.as_slice(),
        invalid,
        FieldOpts::default(),
    )
}

/// The options a text field can be asked for beyond the console's plain one. They live here
/// rather than as more arguments because the console's field takes none of them and the
/// self-service page's fields take five of the eight: a positional list would put a
/// `pattern` behind six blanks at every console call site, and a field that reads
/// `text_field(label, name, v, "", "", true, true, None, …)` says nothing about what it asks
/// the browser to enforce.
///
/// `prose` is the one that is not a constraint. A field that holds a person's **name** must
/// not carry `autocapitalize="off"` and `spellcheck="false"`: those two are right for a URL,
/// a header name and a key id, where a capital or a wavy underline is a typo, and wrong for
/// `Ada Lovelace`, where the browser's own capitalisation is what a person expects to see.
/// So it is one flag naming the kind of content, not two flags for two attributes.
#[derive(Default)]
pub(crate) struct FieldOpts<'a> {
    /// Put the cursor in this field when the page opens. One per page.
    pub(crate) autofocus: bool,
    /// Refuse an empty submission in the browser as well as on the server.
    pub(crate) required: bool,
    /// The window the browser lets a person type into.
    pub(crate) maxlength: Option<usize>,
    /// The grammar the server enforces, spelled for the browser too.
    pub(crate) pattern: Option<&'a str>,
    /// An autofill token (WCAG 1.3.5).
    pub(crate) autocomplete: Option<&'a str>,
    /// The keyboard to offer, for a field that takes a shape and not prose.
    pub(crate) inputmode: Option<&'a str>,
    /// The width class, for a field that is not sized by its wire name.
    pub(crate) class: Option<&'a str>,
    /// The value is prose: keep the browser's capitalisation and spell check.
    pub(crate) prose: bool,
}

/// The **one** text field: every label, input, hint and invalid mark on both surfaces is
/// built here (§13.26 "One text field"). The console's [`text_field`] is this with no
/// options, and the self-service page's fields are this with the browser's constraints on
/// them, so a field on one surface cannot gain a border, a hint line, an `aria` pair or a
/// width class that the other does not know about. That drift is invisible from inside
/// either page, and it is the same argument that put the palette and the components in the
/// library.
///
/// `placeholder` is an attribute only when there is something to suggest: an empty
/// `placeholder=""` is an empty bubble in a Chromium field, and it says nothing. `hints` is
/// one line per entry, in the order the caller gives them, under the control. `invalid` is
/// the pair [`text_field`] describes, and it points at [`ERR_ID`], the id every form's
/// message box carries on both surfaces.
pub(crate) fn text_field_with(
    label: &str,
    name: &str,
    value: &str,
    placeholder: &str,
    hints: &[&str],
    invalid: bool,
    opts: FieldOpts<'_>,
) -> Markup {
    let sized = format!("f-{name}");
    let class = format!(
        "{}{}",
        opts.class.unwrap_or(&sized),
        if invalid { " invalid" } else { "" }
    );
    html! {
        label {
            span class="lbl" { (label) }
            input type="text" name=(name) value=(value)
                  placeholder=[(!placeholder.is_empty()).then_some(placeholder)]
                  class=(class)
                  autocapitalize=[(!opts.prose).then_some("off")]
                  spellcheck=[(!opts.prose).then_some("false")]
                  autofocus[opts.autofocus]
                  required[opts.required]
                  maxlength=[opts.maxlength]
                  pattern=[opts.pattern]
                  autocomplete=[opts.autocomplete]
                  inputmode=[opts.inputmode]
                  aria-invalid=[invalid.then_some("true")]
                  aria-describedby=[invalid.then_some(ERR_ID)];
            @for h in hints {
                span class="hint" { (h) }
            }
        }
    }
}

/// The key's duration, chosen from five: one `select` whose values are the strings the file
/// stores, and the custom box beside it (§13.15, as §13.16 amended its markup).
///
/// One component and not two, because the console's mint, the console's edit and the
/// self-service page all mint the same field, and a component rendered two ways is two
/// components that drift one edit at a time. One `select` and not five radios because on
/// `/account/` it lives in one cell of a table row, where five stacked rows would be the
/// tallest thing in it.
///
/// The box is a **text** field with `inputmode="numeric"`, not a `number` field, because the
/// console's custom value takes the whole grammar (`40`, `40d`, `12h`): a `number` field
/// cannot type `12h`, and the keyboard hint is what a numeric box was wanted for. It shares
/// the row with the choice it belongs to (`form.edit .limit`, the furniture `admin.css`
/// already has) and has no visible label of its own, so its name is written down as an
/// `aria-label` (WCAG 3.3.2).
///
/// `choice` is one of the five values, `days` what the box shows; [`duration_of_stored`] and
/// [`duration_of_posted`] are what put a file's bytes, or a person's submission, into that
/// shape, and they always name one of the five, so exactly one option is picked.
///
/// The box's two words are the surfaces' own, because the two boxes take different grammars.
/// `placeholder` is what the empty box says: `/account/` passes "days", since its box takes a
/// number and nothing else. The console passes nothing, because its box takes the whole
/// grammar (`12h` is a legal value there) and a placeholder of "days" would be a lie about it.
/// `hint` is the line under the row, and is `None` where the placeholder already says the
/// same thing: a bare word alone on the line below reads as a caption of the whole row. The
/// box keeps its own name as an `aria-label` either way, since a placeholder is not a label
/// (WCAG 3.3.2) and the wrapping `label` labels only its first labelable descendant, the
/// select.
pub(crate) fn duration_choice(
    lang: Lang,
    label: &str,
    choice: &str,
    days: &str,
    placeholder: Option<&str>,
    hint: Option<&str>,
    invalid: bool,
) -> Markup {
    html! {
        label {
            span class="lbl" { (label) }
            span class="limit" {
                select name="duration" aria-label=(label)
                      class=[invalid.then_some("invalid")]
                      aria-invalid=[invalid.then_some("true")]
                      aria-describedby=[invalid.then_some(ERR_ID)] {
                    // The longest bounded choice is the one an add form opens on, and `never`
                    // is never preselected: the widest credential has to be asked for.
                    option value="365d" selected[choice == "365d"] { (t(lang, K::DurOneYear)) }
                    option value="182d" selected[choice == "182d"] { (t(lang, K::DurSixMonths)) }
                    option value="91d" selected[choice == "91d"] { (t(lang, K::DurThreeMonths)) }
                    option value="custom" selected[choice == "custom"] { (t(lang, K::DurCustom)) }
                    option value="never" selected[choice == "never"] { (t(lang, K::DurNever)) }
                }
                input type="text" inputmode="numeric" name="days" size="6" value=(days)
                      class="f-days"
                      placeholder=[placeholder]
                      aria-label=(t(lang, K::DurDaysLabel));
            }
            @if let Some(hint) = hint {
                span class="hint" { (hint) }
            }
        }
    }
}

/// A URL-pattern list: one per line, `@refs` written literally. The same shape for an
/// application's `base`, a scope's `urls`, its members and its exclusions, a key's `scopes`
/// and a group's members — one grammar, as in the file.
///
/// `invalid` is the same attribution [`text_field`] takes: see its doc comment.
pub(crate) fn urls_field(
    label: &str,
    name: &str,
    value: &str,
    hint: Markup,
    invalid: bool,
) -> Markup {
    html! {
        label {
            // An empty label is a field whose heading is already above it (the key form's
            // scope radios) — not a blank line to leave in the page.
            @if !label.is_empty() { span class="lbl" { (label) } }
            // `f-{name}` as every other field carries: it is what lets a refusal's `name=` be
            // found in the page, and the layout's width rules are written on `input.f-…`, so a
            // textarea wearing its own name costs nothing.
            textarea name=(name) rows="6" spellcheck="false" autocapitalize="off"
                      class=(format!("f-{name}{}", if invalid { " invalid" } else { "" }))
                      aria-invalid=[invalid.then_some("true")]
                      aria-describedby=[invalid.then_some(ERR_ID)] { (value) }
            span class="hint" { (hint) }
        }
    }
}

/// A unit's name in the reader's language, singular for one of it and plural otherwise. The
/// two of space are the same word in every language, and are left as the file spells them.
///
/// It takes the language and not the [`View`], because a refusal translated outside the page's
/// own render has a language and no view (§13.31 §4).
fn unit_label(lang: Lang, unit: AuditUnit, amount: u64) -> &'static str {
    let one = amount == 1;
    match unit {
        AuditUnit::Weeks => t(lang, if one { K::UnitWeek } else { K::UnitWeeks }),
        AuditUnit::Months => t(lang, if one { K::UnitMonth } else { K::UnitMonths }),
        AuditUnit::Years => t(lang, if one { K::UnitYear } else { K::UnitYears }),
        AuditUnit::MiB => "MiB",
        AuditUnit::GiB => "GiB",
    }
}

/// An audit limit in the reader's words: `4 MiB`, `6 mesi`, `1 year`.
///
/// The language and not the [`View`], for the reason [`unit_label`] gives: the delete
/// confirmation page (§13.30 §2) has a language and no view, and a second spelling of
/// "6 months" there is one unit word the Settings page can drift from (§13.29 W10 7b).
pub(crate) fn limit_text(lang: Lang, l: &AuditLimit) -> String {
    format!("{} {}", l.amount, unit_label(lang, l.unit, l.amount))
}

/// An amount-and-unit field: a number and a list box of [`AuditUnit`]s, posted as `name` and
/// `name_unit`, which the form puts back together into the one string the file stores.
///
/// Two controls and not one text box because the unit is a choice among five, and a box that
/// took "4 MB" would be a box that accepted a number the file then refuses. `none` is offered
/// only where empty means something (a retention), and never where it would be an error.
#[allow(clippy::too_many_arguments)]
pub(crate) fn limit_field(
    v: &View,
    label: &str,
    name: &str,
    amount: &str,
    unit: &str,
    none: bool,
    hint: &str,
    invalid: bool,
) -> Markup {
    html! {
        label {
            span class="lbl" { (label) }
            span class="limit" {
                input type="number" min="1" step="1" name=(name) value=(amount)
                      class=(format!("f-{name}{}", if invalid { " invalid" } else { "" }))
                      aria-invalid=[invalid.then_some("true")]
                      aria-describedby=[invalid.then_some(ERR_ID)];
                select name=(format!("{name}_unit")) aria-label=(label) {
                    @if none {
                        option value="" selected[unit.is_empty()] { (v.t(K::LimitNone)) }
                    }
                    @for u in AuditUnit::ALL {
                        option value=(u.code()) selected[u.code() == unit] {
                            (unit_label(v.lang, u, 2))
                        }
                    }
                }
            }
            span class="hint" { (hint) }
        }
    }
}

/// The lines of a pattern list, as a textarea's value.
pub(crate) fn urls_text(urls: Option<&Vec<String>>) -> String {
    urls.map(|l| l.join("\n")).unwrap_or_default()
}

/// A pill: the estate's small control, as a link. Declared once because **nothing at a call
/// site is allowed to say how a pill looks**: the class list is what the stylesheets style, so
/// a call site that spelled one out would repaint that page and leave every other standing,
/// which is drift no file in front of an editor can show. A link and not a button, because it
/// navigates and changes nothing; a pill and not body prose, because it sits in the same row as
/// `edit` and `remove` and is the same kind of thing.
///
/// These three helpers are that one home, and they take an `href` and a label as values rather
/// than a [`View`] for the same reason [`confirm_card`] takes a heading and a `rev`: the pages
/// under `/account` have no `View` at all (no route, no `rev`, no bar), so they reach the
/// console's pill through them, and the console's [`act`], [`act_rm`] and [`back`] are wrappers
/// over them. A second pill spelled for the self-service page is the drift this ends.
pub(crate) fn pill_link(href: &str, label: &str) -> Markup {
    html! { a class="pill" href=(href) { (label) } }
}

/// A pill marked as the destructive member of its `.pills` group (CSS `.pill.rm`): the action
/// that removes a row, not one that just changes it. See [`pill_link`] for why the markup is
/// here and not at a call site.
pub(crate) fn pill_link_rm(href: &str, label: &str) -> Markup {
    html! { a class="pill rm" href=(href) { (label) } }
}

/// The way back out of a page, in the reader's language: an arrow and [`K::Back`] on the pill
/// every other small control wears. See [`pill_link`] for why the markup is here.
pub(crate) fn back_link(lang: Lang, href: &str) -> Markup {
    html! { a class="pill" href=(href) { "\u{2190} " (t(lang, K::Back)) } }
}

/// A small `add` / `edit` / `remove` pill beside the thing it acts on.
pub(crate) fn act(v: &View, at: &Route, label: &str) -> Markup {
    pill_link(&v.href(at), label)
}

/// The way back out of a detail page, taking its language and href from the view.
pub(crate) fn back(v: &View, to: &Route) -> Markup {
    back_link(v.lang, &v.href(to))
}

/// Same as [`act`], marked destructive. `rotate` replaces a credential rather than deleting
/// anything, so it stays plain [`act`]; only an actual `Rm` route earns this.
pub(crate) fn act_rm(v: &View, at: &Route, label: &str) -> Markup {
    pill_link_rm(&v.href(at), label)
}

/// A confirmation page: what is about to go, what that means, and a `POST` that does it.
/// The `GET` that renders this changes nothing, which is the whole reason destructive
/// actions are two steps and not a link.
pub(crate) fn page_confirm(
    v: &View,
    heading: Markup,
    what: Markup,
    why: &str,
    button: &str,
    err: Option<&Refusal>,
) -> Markup {
    page_confirm_at(
        &v.href(&v.at),
        v.rev,
        &v.href(&v.at.parent()),
        v.t(K::Cancel),
        heading,
        what,
        why,
        html! {},
        button,
        err,
        true,
    )
}

/// [`page_confirm`] on values instead of a [`View`]: the console's heading above the
/// [`confirm_card`] the self-service page renders on its own. `fields` is what the form carries
/// besides the `rev`: nothing on the console, whose route names the key, and the key's id on
/// `/account/`, whose two paths do not.
#[allow(clippy::too_many_arguments)]
fn page_confirm_at(
    action: &str,
    rev: &str,
    cancel: &str,
    cancel_label: &str,
    heading: Markup,
    what: Markup,
    why: &str,
    fields: Markup,
    button: &str,
    err: Option<&Refusal>,
    danger: bool,
) -> Markup {
    html! {
        h1 { (heading) }
        (confirm_card(
            action, rev, cancel, cancel_label, what, why, fields, button, err, danger,
        ))
    }
}

/// The card a confirmation is made of: what is about to go, what that means, and the `POST`
/// that does it. Split out of [`page_confirm_at`] for the self-service page (§13.17), whose
/// shell already wears the action word as the page's one `h1`, so the card arrives with no
/// heading of its own and the confirmation reads the way the console's does: the bar says where
/// you are, the `h1` says what is about to happen.
#[allow(clippy::too_many_arguments)]
pub(crate) fn confirm_card(
    action: &str,
    rev: &str,
    cancel: &str,
    cancel_label: &str,
    what: Markup,
    why: &str,
    fields: Markup,
    button: &str,
    err: Option<&Refusal>,
    danger: bool,
) -> Markup {
    html! {
        p class="lede" { (why) }
        div class="panel bad" {
            (what)
            (form_shell_at(action, rev, cancel, cancel_label, err, fields, button, danger))
        }
    }
}

/// "no such user / api key / application / scope / group" — a `GET` for a name the file does
/// not have.
pub(crate) fn page_missing(v: &View, what: &str, name: &str, back_to: &Route) -> Markup {
    html! {
        h1 { (what) }
        p class="lede" { code { (name) } }
        p { (back(v, back_to)) }
    }
}
