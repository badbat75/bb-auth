use crate::*;

/// The settings form: the five the gate answers with, and the list of people this GUI opens
/// for.
///
/// One form, not five, and one `Save`: these are read together on every request and written
/// together in one file, so splitting them into a form each would only invent five chances to
/// hit a stale `rev`.
///
/// Nothing here is a secret and nothing here can lock anybody out, which is exactly the rule
/// that decided what the file holds; see `bb_auth_core::Settings`. What is *not* on this page
/// is the rest of the configuration: the listener, the HMAC key, the Cognito trust roots, the
/// login page and the authorized hosts stay in the env file on the host, where changing one
/// costs a restart and getting one wrong costs the service.
pub(crate) struct ConfigForm {
    claims: String,
    identity: String,
    ttl: String,
    social: bool,
    providers: String,
    /// The app client the email flow uses, `gate.client_id`. Empty is a deployment that
    /// cannot complete a login, which this form refuses to write.
    pub(crate) client_id: String,
    /// `gate.login_url`. Empty = the gate's own `/auth/login`.
    login_url: String,
    /// `gate.denied_url`. Empty = the gate's own `/auth/denied`. The one URL on this page
    /// that can close nothing: it is only what somebody already refused is shown.
    denied_url: String,
    /// `gate.landing_url`. Empty = the caller's root. It is refused off `gate.authorized_hosts`
    /// for the reason the help line gives: `safe_rd` refuses a landing page outside them at
    /// every login, so the setting would silently do nothing.
    landing_url: String,
    /// `gate.issuer`, the Cognito user pool. This form refuses to write an empty one, for the
    /// reason it refuses an empty `client_id`: both mean no login can complete.
    issuer: String,
    /// `gate.cookie_domain`. Empty = a host-only cookie.
    cookie_domain: String,
    /// `gate.authorized_hosts`, one per line.
    hosts: String,
    /// `gate.oauth_domain`, the hosted UI's bare host. Empty = no social sign-in.
    domain: String,
    /// `gate.social_callback_url`. Empty = no social sign-in.
    callback: String,
    /// The enabled social providers as `(identity_provider, app client)`. Pairs rather than
    /// names because Cognito federates per app client: see [`social_choices`].
    pub(crate) buttons: Vec<(String, String)>,
    /// `audit.client_ip_header`. Empty = the audit records no address.
    ip_header: String,
    /// `audit.request_id_header`. Empty = the audit records no request id.
    rid_header: String,
    /// `audit.rotation`, as the two controls it is edited in: an amount, and a unit's code.
    rotation_n: String,
    rotation_unit: String,
    /// `audit.retention` likewise. An empty unit is no retention, whatever the amount says.
    retention_n: String,
    retention_unit: String,
    admins: String,
    stylesheet: String,
    logo: String,
    brand: String,
    theme: String,
}

impl ConfigForm {
    /// The form as the file says it, which is what a `GET` renders.
    pub(crate) fn of(doc: &SettingsFile) -> ConfigForm {
        // Both parse, because a file that did not would not have been opened for editing: a
        // file the gate refuses is an error page, not this form.
        let rotation =
            AuditLimit::parse(&doc.audit.rotation).unwrap_or(AuditPolicy::default().rotation);
        let retention = AuditLimit::parse(&doc.audit.retention).ok();
        ConfigForm {
            claims: doc.gate.profile_claims.join("\n"),
            identity: doc.gate.identity_attrs.join("\n"),
            ttl: doc.gate.session_ttl_secs.to_string(),
            social: doc.gate.allow_unverified_social,
            providers: doc.gate.social_providers.join("\n"),
            client_id: doc.gate.client_id.clone(),
            login_url: doc.gate.login_url.clone(),
            denied_url: doc.gate.denied_url.clone(),
            landing_url: doc.gate.landing_url.clone(),
            issuer: doc.gate.issuer.clone(),
            cookie_domain: doc.gate.cookie_domain.clone(),
            hosts: doc.gate.authorized_hosts.join("\n"),
            domain: doc.gate.oauth_domain.clone(),
            callback: doc.gate.social_callback_url.clone(),
            // A bare-name entry is the pre-2 shape, which `compile_settings` refuses; it is
            // rendered as a row with no app client so the page can show what the file says
            // and the operator can fix it here rather than over SSH.
            buttons: doc
                .gate
                .social_buttons
                .iter()
                .map(|b| match b {
                    SocialButtonSpec::Wired(w) => (w.idp.clone(), w.audience.clone()),
                    SocialButtonSpec::Name(n) => (n.clone(), String::new()),
                })
                .collect(),
            ip_header: doc.audit.client_ip_header.clone(),
            rid_header: doc.audit.request_id_header.clone(),
            // The file's spelling split into the two controls. A rotation nobody wrote is the
            // default one, shown as what it is rather than as an empty box that means it.
            rotation_n: rotation.amount.to_string(),
            rotation_unit: rotation.unit.code().to_string(),
            retention_n: retention.map(|r| r.amount.to_string()).unwrap_or_default(),
            retention_unit: retention
                .map(|r| r.unit.code().to_string())
                .unwrap_or_default(),
            admins: doc.web.admins.join("\n"),
            stylesheet: doc.ui.stylesheet_url.clone(),
            logo: doc.ui.logo_url.clone(),
            brand: doc.ui.brand_name.clone(),
            // A file that says nothing renders the list box on `system`, which is what saying
            // nothing means. Writing it back as the word costs nothing and makes the file read
            // the way the page does.
            theme: UiTheme::parse(&doc.ui.theme)
                .unwrap_or_default()
                .code()
                .to_string(),
        }
    }

    pub(crate) fn read(f: &Form) -> ConfigForm {
        ConfigForm {
            claims: f.get("claims").to_string(),
            identity: f.get("identity").to_string(),
            ttl: f.get("ttl").to_string(),
            // An unchecked checkbox sends nothing at all, which is what makes its absence the
            // `false` rather than a value to parse.
            social: !f.get("social").is_empty(),
            providers: f.get("providers").to_string(),
            client_id: f.get("client_id").to_string(),
            login_url: f.get("login_url").to_string(),
            denied_url: f.get("denied_url").to_string(),
            landing_url: f.get("landing_url").to_string(),
            issuer: f.get("issuer").to_string(),
            cookie_domain: f.get("cookie_domain").to_string(),
            hosts: f.get("hosts").to_string(),
            domain: f.get("domain").to_string(),
            callback: f.get("callback").to_string(),
            // The page says which providers it drew a row for, and this keeps the ones whose
            // box came back ticked, with the app client typed beside it. Reading the offered
            // set off the form rather than re-deriving it here is what makes a provider this
            // build has never heard of survive a save: it was rendered, so it is named, so it
            // can be kept.
            buttons: f
                .get("idps")
                .split_whitespace()
                .filter(|idp| f.checked(&idp_field(idp)))
                .map(|idp| (idp.to_string(), f.get(&aud_field(idp)).trim().to_string()))
                .collect(),
            ip_header: f.get("client_ip_header").to_string(),
            rid_header: f.get("request_id_header").to_string(),
            rotation_n: f.get("audit_rotation").to_string(),
            rotation_unit: f.get("audit_rotation_unit").to_string(),
            retention_n: f.get("audit_retention").to_string(),
            retention_unit: f.get("audit_retention_unit").to_string(),
            admins: f.get("admins").to_string(),
            stylesheet: f.get("stylesheet").to_string(),
            logo: f.get("logo").to_string(),
            brand: f.get("brand").to_string(),
            theme: f.get("ui_theme").to_string(),
        }
    }

    /// One textarea's lines, trimmed, blanks dropped: the grammar every list field in this
    /// GUI already uses.
    fn lines(s: &str) -> Vec<String> {
        s.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Apply the form to the document. The refusals here are the ones the library cannot make
    /// on its own: it does not know who is signed in, and it does not parse a form. Every other
    /// check is `compile_settings`'s, made once on the way to disk, where its refusal is said in
    /// the reader's language on the field that can fix it (docs/ARCHITECTURE.md §13.31 §5).
    pub(crate) fn apply(
        &self,
        doc: &mut SettingsFile,
        admin: &str,
        lang: Lang,
    ) -> Result<(), Refusal> {
        // Every refusal here is said in the page's own register: the visible label of the
        // field, then what is allowed, through `fill` like the library's (§13.31 §10).
        let ttl: u64 = self.ttl.trim().parse().map_err(|_| {
            Refusal::on(
                "ttl",
                fill(t(lang, K::SessionTtlBad), &[t(lang, K::SessionTtl)]),
            )
        })?;
        let admins = Self::lines(&self.admins);
        if admins.is_empty() {
            return Err(Refusal::on(
                "admins",
                fill(t(lang, K::SetRefAdminsNone), &[t(lang, K::Admins)]),
            ));
        }
        // The guard that makes this page safe to hand an administrator: you may add anyone
        // and remove anyone but yourself. Removing the last administrator is refused above;
        // removing *this* one would leave a GUI nobody can open, and the way back is the SSH
        // this page exists to save people from. `bb-auth-adm` will still do it.
        if !admins.iter().any(|a| norm_email(a) == admin) {
            return Err(Refusal::on(
                "admins",
                fill(t(lang, K::SetRefAdminsSelf), &[t(lang, K::Admins)]),
            ));
        }
        // The four the GUI is stricter than the gate about on purpose: a deployment with an
        // empty one of these is one where no login can complete, and a form should not be able
        // to write that. A fresh install has none of them and no way to reach this page either,
        // so the first one is set with `bb-auth-adm` over SSH.
        let client_id = compile_app_client_id("client_id", &self.client_id)
            .unwrap_or(self.client_id.trim().to_string());
        if client_id.is_empty() {
            return Err(Refusal::on(
                "client_id",
                fill(t(lang, K::ClientIdNeeded), &[t(lang, K::SignInEmail)]),
            ));
        }
        let issuer = compile_issuer(&self.issuer).unwrap_or(self.issuer.trim().to_string());
        if issuer.is_empty() {
            return Err(Refusal::on(
                "issuer",
                fill(t(lang, K::IssuerNeeded), &[t(lang, K::Issuer)]),
            ));
        }
        let hosts = Self::lines(&self.hosts);
        if hosts.is_empty() {
            return Err(Refusal::on(
                "hosts",
                fill(
                    t(lang, K::AuthorizedHostsNeeded),
                    &[t(lang, K::AuthorizedHosts)],
                ),
            ));
        }
        for (idp, aud) in &self.buttons {
            if aud.trim().is_empty() {
                return Err(Refusal::on(
                    aud_field(idp),
                    fill(t(lang, K::AudienceNeeded), &[social_idp_label(idp)]),
                ));
            }
        }
        // A value this list box cannot produce, so a refusal here means the request was not
        // this form. It is still a refusal and not a silent `system`: see `UiTheme::parse`.
        // The field is `ui_theme`, the page's name for the box, as `settings_refusal` says:
        // `theme` is the file's key, and marks nothing on this page (§13.31 §10).
        let theme = UiTheme::parse(&self.theme).ok_or_else(|| {
            Refusal::on(
                "ui_theme",
                fill(t(lang, K::DefaultThemeBad), &[t(lang, K::DefaultTheme)]),
            )
        })?;
        // The validators stay where their `Ok` value is what the file stores: the issuer with
        // its trailing slash gone, the cookie domain lowercased, an app client and a header
        // trimmed, the two audit limits in the file's own spelling. The refusal does not stay:
        // `.unwrap_or` takes the trimmed input, so a value the library accepts is written byte
        // for byte as before and one it refuses reaches `prepare` and is answered there.
        let cookie_domain = compile_cookie_domain(&self.cookie_domain)
            .unwrap_or(self.cookie_domain.trim().to_string());
        let ip_header = compile_audit_header("client_ip_header", &self.ip_header)
            .unwrap_or(self.ip_header.trim().to_string());
        let rid_header = compile_audit_header("request_id_header", &self.rid_header)
            .unwrap_or(self.rid_header.trim().to_string());
        let rotation_raw = format!("{} {}", self.rotation_n.trim(), self.rotation_unit.trim());
        let rotation = AuditLimit::parse(&rotation_raw)
            .map(|r| r.spelled())
            .unwrap_or(rotation_raw);
        let retention = match self.retention_unit.trim() {
            "" => String::new(),
            unit => {
                let raw = format!("{} {unit}", self.retention_n.trim());
                AuditLimit::parse(&raw).map(|r| r.spelled()).unwrap_or(raw)
            }
        };

        doc.gate.profile_claims = Self::lines(&self.claims);
        doc.gate.identity_attrs = Self::lines(&self.identity);
        doc.gate.session_ttl_secs = ttl;
        doc.gate.allow_unverified_social = self.social;
        doc.gate.social_providers = Self::lines(&self.providers);
        doc.gate.client_id = client_id;
        doc.gate.login_url = self.login_url.trim().to_string();
        doc.gate.denied_url = self.denied_url.trim().to_string();
        doc.gate.landing_url = self.landing_url.trim().to_string();
        doc.gate.issuer = issuer;
        doc.gate.cookie_domain = cookie_domain;
        doc.gate.authorized_hosts = hosts;
        doc.gate.oauth_domain = self.domain.trim().to_string();
        doc.gate.social_callback_url = self.callback.trim().to_string();
        doc.gate.social_buttons = self
            .buttons
            .iter()
            .map(|(idp, aud)| {
                SocialButtonSpec::Wired(WiredButton {
                    idp: idp.clone(),
                    audience: aud.clone(),
                })
            })
            .collect();
        doc.audit.client_ip_header = ip_header;
        doc.audit.request_id_header = rid_header;
        doc.audit.rotation = rotation;
        doc.audit.retention = retention;
        doc.web.admins = admins;
        doc.ui.stylesheet_url = self.stylesheet.trim().to_string();
        doc.ui.logo_url = self.logo.trim().to_string();
        doc.ui.brand_name = self.brand.trim().to_string();
        doc.ui.theme = theme.code().to_string();
        Ok(())
    }
}

/// A save held for confirmation: the guarded settings this form would change, each with what
/// it is going from and to.
///
/// It is a type rather than a list of tuples because the page renders it AND the hidden field
/// is built from it, and those two have to be about the same values. A confirmation that
/// showed one thing and authorised another would be a worse guard than none at all.
pub(crate) struct Confirm {
    /// `(which, before, after)`, in [`guarded_changes`]'s order.
    changes: Vec<(GuardedSetting, String, String)>,
    /// What the hidden field carries and what the next `POST` is checked against: the sha256
    /// of the values being confirmed, rather than the values themselves. One field to check
    /// instead of five, and no list has to survive a round trip through an attribute.
    ///
    /// It binds a confirmation to exactly the change it was shown for: edit the field again
    /// on the confirmation page and the token no longer matches, so the page asks again about
    /// the new value instead of writing it on the strength of an answer about the old one.
    pub(crate) token: String,
}

impl Confirm {
    /// What `new` changes about `old` that is worth stopping for, or `None` for a save that
    /// takes nothing away.
    pub(crate) fn of(old: &GateSettings, new: &GateSettings) -> Option<Confirm> {
        let changes: Vec<(GuardedSetting, String, String)> = guarded_changes(old, new)
            .into_iter()
            .map(|c| (c, guarded_value(c, old), guarded_value(c, new)))
            .collect();
        if changes.is_empty() {
            return None;
        }
        let token = sha256_hex(
            &changes
                .iter()
                .map(|(c, _, after)| format!("{}={after}", c.field()))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        Some(Confirm { changes, token })
    }
}

/// One guarded setting's value, spelled the one way the page shows it and the token is built
/// from. Both come through here, so the two cannot disagree.
fn guarded_value(which: GuardedSetting, gate: &GateSettings) -> String {
    match which {
        GuardedSetting::Issuer => gate.issuer.trim().to_string(),
        GuardedSetting::ClientId => gate.client_id.trim().to_string(),
        GuardedSetting::LoginUrl => gate.login_url.trim().to_string(),
        GuardedSetting::CookieDomain => gate.cookie_domain.trim().to_string(),
        GuardedSetting::AuthorizedHosts => gate.authorized_hosts.join(" "),
    }
}

/// What each guarded setting costs when it is wrong, in the reader's language. The library
/// says *which* settings are guarded, because both editors have to agree on that; the
/// sentence is this program's, because it is addressed to whoever is looking at the form.
fn guarded_risk(which: GuardedSetting) -> K {
    match which {
        GuardedSetting::Issuer => K::RiskIssuer,
        GuardedSetting::ClientId => K::RiskClientId,
        GuardedSetting::LoginUrl => K::RiskLoginUrl,
        GuardedSetting::CookieDomain => K::RiskCookieDomain,
        GuardedSetting::AuthorizedHosts => K::RiskAuthorizedHosts,
    }
}

/// One group of the Settings page: a panel that folds to its heading.
///
/// A `details`, because that is how HTML has always opened and closed something with no
/// script behind it, and this GUI may have none. Its inputs are part of the form whether it is
/// open or not, so a folded group is saved exactly as a visible one is.
fn settings_group(id: &str, open: bool, heading: Markup, body: Markup) -> Markup {
    html! {
        details class="panel group" id=(format!("g-{id}")) open[open] {
            summary { h2 class="tight" { (heading) } }
            (body)
        }
    }
}

/// Which group of the Settings page a refused field is in, by its `name=`: the group that has
/// to be open whatever the reader asked for, since a refusal pointing at a folded field is a
/// refusal nobody can act on.
fn settings_group_of(field: &str) -> &'static str {
    match field {
        "social" | "providers" | "ttl" => "access",
        "identity" | "claims" => "handover",
        "client_ip_header" | "request_id_header" | "audit_rotation" | "audit_retention" => "audit",
        // The list box is `ui_theme`, the page's name for it; `theme` is the file's key, and a
        // refusal spelled that way opened no group at all (§13.31 §10).
        "admins" | "brand" | "stylesheet" | "logo" | "ui_theme" => "look",
        // Everything else on the page is the sign-in box's, including the table of ways in,
        // whose fields are named after the providers in the file (`aud-Google`).
        _ => "signin",
    }
}

pub(crate) fn page_config(
    v: &View,
    f: &ConfigForm,
    err: Option<&Refusal>,
    confirm: Option<&Confirm>,
) -> Markup {
    let about = |name| err.is_some_and(|e| e.is(name));
    let days = f.ttl.trim().parse::<u64>().unwrap_or(0) / 86_400;
    // Which groups are open: the reader's preference, then whatever the page has to show them.
    // A refusal opens its field's group, and one that names no field opens them all, since
    // the page cannot say where the problem is; a held save opens the sign-in group, which is
    // where every guarded setting lives.
    let refused = err.map(|e| e.field.as_deref().map(settings_group_of));
    let open = |id: &str| {
        v.groups == GroupsPref::Open
            || matches!(refused, Some(None))
            || refused.flatten() == Some(id)
            || (confirm.is_some() && id == "signin")
    };
    let groups_href =
        |pref: GroupsPref| format!("{}?{GROUPS_COOKIE}={}", v.href(&Route::Config), pref.code());
    html! {
        h1 { (v.t(K::Config)) }
        p class="lede" { (v.t(K::ConfigIntro)) }
        // The two commands. Links and not buttons, because they change nothing but how this
        // page opens: each is a `GET` the handler turns into a cookie and redirects back from,
        // exactly as a language or a theme is chosen.
        p class="primary" {
            a class="pill" href=(groups_href(GroupsPref::Open)) { "⊞ " (v.t(K::GroupsExpand)) }
            " "
            a class="pill" href=(groups_href(GroupsPref::Closed)) { "⊟ " (v.t(K::GroupsCollapse)) }
        }
        // A save that takes one of the five guarded settings away is SHOWN before it is
        // written, and the form below is re-rendered with the values that are waiting, so
        // the answer to "no, not that" is to edit the field rather than to start again.
        @if let Some(c) = confirm {
            div class="panel warn" {
                h2 class="tight" { (v.t(K::ConfirmTitle)) }
                p class="lede" { (v.t(K::ConfirmLede)) }
                table {
                    thead { tr {
                        th { (v.t(K::ColSetting)) }
                        th { (v.t(K::ColNow)) }
                        th { (v.t(K::ColAfter)) }
                    } }
                    tbody {
                        @for (which, before, after) in &c.changes {
                            tr {
                                td data-label=(v.t(K::ColSetting)) {
                                    div class="mono" { (which.field()) }
                                    span class="hint" { (v.t(guarded_risk(*which))) }
                                }
                                td class="mono" data-label=(v.t(K::ColNow)) {
                                    (if before.is_empty() { "\u{2014}" } else { before })
                                }
                                td class="mono" data-label=(v.t(K::ColAfter)) {
                                    (if after.is_empty() { "\u{2014}" } else { after })
                                }
                            }
                        }
                    }
                }
                p class="muted" { (v.t(K::ConfirmSafety)) }
            }
        }
        // FIVE GROUPS, ONE FORM. The grouping is by what a setting decides, not by which
        // section of the file it lands in: an operator asking "who gets in, and for how
        // long" should not have to read past what the application receives to find out, and
        // the two questions are answered by fields that happen to be neighbours in the file.
        // Each group still names the section it writes; where a group spans two, it names both.
        //
        // One form and one save, because the `rev` guard is over the whole file: five forms
        // would be five fingerprints and four chances to lose an edit somebody else made
        // between them. Folding a group does not take it out of the form.
        (form_shell(v, err, html! {
            (settings_group("access", open("access"), section_heading(v.t(K::ConfigAccess), "gate"), html! {
                // The scope form's own furniture, because a checkbox here is the same thing
                // it is there and inventing a second one would show.
                div {
                    label class="radio" {
                        input type="checkbox" name="social" value="on" checked[f.social];
                        span { (v.t(K::UnverifiedSocial)) }
                    }
                    span class="hint" { (v.t(K::UnverifiedSocialHelp)) }
                }
                (urls_field(v.t(K::SocialProviders), "providers", &f.providers,
                            html! { (v.t(K::SocialProvidersHelp)) }, about("providers")))
                // The hint carries both halves: what this value is in days, which is the
                // only way a number of seconds reads as a lifetime, and what changing it
                // does to sessions that already exist. The second half used to appear only
                // as the refusal on a typo, which is the one moment nobody is reading it.
                (text_field(v.t(K::SessionTtl), "ttl", &f.ttl, "2592000",
                            Some(&format!("{days} {}. {}", v.t(K::Days), v.t(K::SessionTtlHelp))),
                            about("ttl")))
            }))
            (settings_group("handover", open("handover"), section_heading(v.t(K::ConfigHandover), "gate"), html! {
                (urls_field(v.t(K::IdentityAttrs), "identity", &f.identity,
                            html! { (v.t(K::IdentityAttrsHelp)) }, about("identity")))
                (urls_field(v.t(K::ProfileClaims), "claims", &f.claims,
                            html! { (v.t(K::ProfileClaimsHelp)) }, about("claims")))
            }))
            // The headers that come IN, beside the ones that go out above: both are the
            // nginx contract, and an operator wiring one is looking at the other. Named by
            // the file's own keys, since both are typed into an nginx config next. Then how
            // long what they record is kept, which is the other half of the same decision.
            (settings_group("audit", open("audit"), section_heading(v.t(K::ConfigAudit), "audit"), html! {
                (text_field(v.t(K::ClientIpHeader), "client_ip_header", &f.ip_header,
                            "X-Real-IP", Some(v.t(K::ClientIpHeaderHelp)),
                            about("client_ip_header")))
                (text_field(v.t(K::RequestIdHeader), "request_id_header", &f.rid_header,
                            "X-Request-ID", Some(v.t(K::RequestIdHeaderHelp)),
                            about("request_id_header")))
                (limit_field(v, v.t(K::AuditRotation), "audit_rotation", &f.rotation_n,
                             &f.rotation_unit, false, v.t(K::AuditRotationHelp),
                             about("audit_rotation")))
                (limit_field(v, v.t(K::AuditRetention), "audit_retention", &f.retention_n,
                             &f.retention_unit, true, v.t(K::AuditRetentionHelp),
                             about("audit_retention")))
            }))
            (settings_group("signin", open("signin"), section_heading(v.t(K::ConfigSignIn), "gate"), html! {
                // Where people sign in at all, first: it is the page the two below only
                // add a way into.
                // The pool first: everything else in this box is a way into it.
                (text_field(v.t(K::Issuer), "issuer", &f.issuer,
                            "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_xxxxxxxxx",
                            Some(v.t(K::IssuerHelp)), about("issuer")))
                (text_field(v.t(K::GlobalLoginUrl), "login_url", &f.login_url,
                            "https://auth.example.com/auth/login",
                            Some(v.t(K::GlobalLoginUrlHelp)), about("login_url")))
                // The other page a browser is sent to, and the reason it sits beside the
                // sign-in page rather than under the look below: the two are one decision,
                // where this estate answers somebody it will not let through.
                (text_field(v.t(K::GlobalDeniedUrl), "denied_url", &f.denied_url,
                            "https://auth.example.com/auth/denied",
                            Some(v.t(K::GlobalDeniedUrlHelp)), about("denied_url")))
                // The third page of the trio, and the one that is not a refusal: where a
                // sign-in puts a person down when nothing named a place. It is checked against
                // the hosts below, which is why it sits directly above them.
                (text_field(v.t(K::GlobalLandingUrl), "landing_url", &f.landing_url,
                            "https://auth.example.com/account/",
                            Some(v.t(K::GlobalLandingUrlHelp)), about("landing_url")))
                // These two are neighbours because they are checked against each other: a
                // host the cookie cannot reach is refused, and an operator told so has to be
                // able to see both without scrolling.
                (text_field(v.t(K::CookieDomain), "cookie_domain", &f.cookie_domain,
                            ".example.com",
                            Some(v.t(K::CookieDomainHelp)), about("cookie_domain")))
                (urls_field(v.t(K::AuthorizedHosts), "hosts", &f.hosts,
                            html! { (v.t(K::AuthorizedHostsHelp)) }, about("hosts")))
                // Where the browser goes and where it comes back to, above the table of who
                // it goes as: both are one per deployment, and both are Amazon's to agree
                // with, so they read as the frame the rows sit in.
                (text_field(v.t(K::OauthDomain), "domain", &f.domain,
                            "pool.auth.eu-central-1.amazoncognito.com",
                            Some(v.t(K::OauthDomainHelp)), about("domain")))
                (text_field(v.t(K::SocialCallback), "callback", &f.callback,
                            "https://auth.example.com/auth/callback",
                            Some(v.t(K::SocialCallbackHelp)), about("callback")))
                // Every way in, and the app client each runs through. Switches and not a list
                // of names to type, because the answer is a choice among a handful of things
                // this project knows by name, and a free-text field invites a spelling
                // Cognito will not match (`Microsoft` for `MicrosoftPersonal`, say) with
                // nothing to catch it but a button that never appears.
                (social_choices(v, f, err))
            }))
            (settings_group("look", open("look"), section_heading(v.t(K::ConfigAdminLook), "web + ui"), html! {
                (urls_field(v.t(K::Admins), "admins", &f.admins,
                            html! { (v.t(K::AdminsHelp)) " (" (v.t(K::AdminsKeepYourself)) ")" },
                            about("admins")))
                (text_field(v.t(K::BrandName), "brand", &f.brand, "BadBat75",
                            Some(v.t(K::BrandNameHelp)), about("brand")))
                (text_field(v.t(K::StylesheetUrl), "stylesheet", &f.stylesheet,
                            "https://assets.example.com/css/theme.css",
                            Some(v.t(K::StylesheetUrlHelp)), about("stylesheet")))
                (text_field(v.t(K::LogoUrl), "logo", &f.logo,
                            "https://assets.example.com/img/logo.png",
                            Some(v.t(K::LogoUrlHelp)), about("logo")))
                // A list box and not three radios, because it is the same choice the Settings
                // menu in the header offers and it must be the same object: three named
                // values, one line, no invented furniture.
                //
                // `ui_theme` and not `theme`, which is the one field on this page whose wire
                // name is not the file's own. The header's menu is on every page including
                // this one, and its own control is `theme`, the cookie; two controls of that
                // name on one document is a page where "the theme" means two different
                // things depending on which form you are looking at.
                label {
                    span class="lbl" { (v.t(K::DefaultTheme)) }
                    select name="ui_theme" {
                        @for th in [UiTheme::System, UiTheme::Light, UiTheme::Dark] {
                            option value=(th.code()) selected[th.code() == f.theme] {
                                (v.t(theme_label(th)))
                            }
                        }
                    }
                    span class="hint" { (v.t(K::DefaultThemeHelp)) }
                }
            }))
            @if let Some(c) = confirm {
                input type="hidden" name="confirm" value=(c.token);
            }
        }, if confirm.is_some() { v.t(K::ConfirmSave) } else { v.t(K::Save) },
           confirm.is_some()))
        p class="muted" { (v.t(K::ConfigHot)) }
    }
}
