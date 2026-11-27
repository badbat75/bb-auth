use crate::*;

/// Which settings-file value a [`SettingsRefusal::Url`] is about, so the refusal can name the
/// setting in the reader's language instead of carrying a sentence that names it (§13.31 §3).
///
/// The name is the string today's sentences spell, because that is what an operator reads in
/// `--check-settings`, in the journal and in `bb-auth-adm`: a gate key bare (`login_url`), an
/// audit key with its section (`audit.rotation`). The audit four were named here a slice before
/// the one that reads them, because a name is cheapest pinned the day the type exists, not the
/// day it is first printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingKey {
    /// `gate.login_url`: the page a `401` sends somebody to.
    LoginUrl,
    /// `gate.denied_url`: the page a `403` lands on.
    DeniedUrl,
    /// `gate.landing_url`: where a sign-in with no `rd` arrives.
    LandingUrl,
    /// `gate.issuer`: the Cognito endpoint an id_token's `iss` must equal.
    Issuer,
    /// `gate.social_callback_url`: the OAuth `redirect_uri` registered on the app client.
    SocialCallbackUrl,
    /// `ui.stylesheet_url`: the operator's stylesheet a page loads after the built-in one.
    StylesheetUrl,
    /// `ui.logo_url`: the operator's logo a page loads.
    LogoUrl,
    /// `audit.client_ip_header`: the header the audit reads an address out of.
    ClientIpHeader,
    /// `audit.request_id_header`: the header the audit reads nginx's request id out of.
    RequestIdHeader,
    /// `audit.rotation`: when the live audit file rotates.
    AuditRotation,
    /// `audit.retention`: how much of the audit the pair keeps.
    AuditRetention,
}

impl SettingKey {
    /// The name today's sentences quote this setting by, which is what `Display` and every
    /// `String` leaf wrapper print, byte for byte as before.
    pub fn name(self) -> &'static str {
        match self {
            Self::LoginUrl => "login_url",
            Self::DeniedUrl => "denied_url",
            Self::LandingUrl => "landing_url",
            Self::Issuer => "issuer",
            Self::SocialCallbackUrl => "social_callback_url",
            Self::StylesheetUrl => "stylesheet_url",
            Self::LogoUrl => "logo_url",
            Self::ClientIpHeader => "audit.client_ip_header",
            Self::RequestIdHeader => "audit.request_id_header",
            Self::AuditRotation => "audit.rotation",
            Self::AuditRetention => "audit.retention",
        }
    }
}

/// The nine shapes a URL setting is refused for, as a name rather than a sentence (§13.31 §2).
///
/// It is a type of its own because the same checks are reached from callers that name the value
/// differently: `compile_settings` names the settings key, the access file's parser names the
/// field it is compiling (`denied_url`), and `bb-auth-adm` names its own flag (`--stylesheet`).
/// Each tail lives here once, so the leaf's `String` wrapper and the enum's `sentence()` cannot
/// drift apart, which is the whole reason [`SettingsRefusal::Url`] is nested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlFault {
    /// A byte outside printable ASCII, such as a space, a tab or a CR/LF. These values are
    /// emitted into a `Location:` header, into `X-Auth-Login-URL` and into an attribute on a
    /// page, where a CR/LF is a response-splitting gadget and a space breaks the URL.
    NotPrintable,
    /// Not an absolute `https://` URL. The estate is https-only and a sign-in page hands a real
    /// credential over this address, so a plain-http one gives the token to whoever is listening.
    NotHttps,
    /// An empty authority (`https://`), which names nowhere: the redirect lands on a page that
    /// never loads.
    EmptyHost,
    /// A userinfo `@` before the host, the lookalike [`rd_url_allowed`] rejects for the same
    /// reason: `https://badbat75.com@evil.com` reads as the estate and goes to the attacker.
    Userinfo,
    /// A backslash, which a browser folds to `/` and a URL parser does not, so the host a person
    /// reads is not the host the request goes to.
    Backslash,
    /// The issuer's spelling of the two above, in one sentence, because that value is compared
    /// byte for byte against a token claim and both shapes are refused together.
    UserinfoOrBackslash,
    /// A query or a fragment on the issuer. Cognito's `iss` is an origin and a pool id and
    /// nothing else, so a value carrying either was written meaning a different URL, and
    /// trimming it would build a JWKS URL nobody asked for.
    QueryOrFragment,
    /// A quote or an angle bracket, which would close the attribute the value is emitted into.
    /// Belt over the escaping in [`stylesheet_link`], spent on purpose: this field is written by
    /// an administrator through a GUI, one hop further from the code than an env var is.
    Quote,
    /// Neither an absolute `https://` URL nor a root-relative path, the only two shapes an asset
    /// URL may take. `//host/path` is refused with it: protocol-relative is an absolute URL
    /// wearing a relative URL's clothes, and the one shape somebody writes by accident.
    NotHttpsOrRooted,
}

impl UrlFault {
    /// The `url_<fault>` code §2 lists, which is what the GUI maps to a `K` key in slice S8.
    fn code(self) -> &'static str {
        match self {
            Self::NotPrintable => "url_not_printable",
            Self::NotHttps => "url_not_https",
            Self::EmptyHost => "url_empty_host",
            Self::Userinfo => "url_userinfo",
            Self::Backslash => "url_backslash",
            Self::UserinfoOrBackslash => "url_userinfo_or_backslash",
            Self::QueryOrFragment => "url_query_or_fragment",
            Self::Quote => "url_quote",
            Self::NotHttpsOrRooted => "url_not_https_or_rooted",
        }
    }
}

impl std::fmt::Display for UrlFault {
    /// The tail of a URL refusal, byte for byte as the leaves spelled it before this type
    /// existed. The setting's name and the quoted value come from the caller; the reason comes
    /// from here, once.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tail = match self {
            Self::NotPrintable => "must be printable ASCII (no spaces, no control bytes)",
            Self::NotHttps => "must be an absolute https:// URL",
            Self::EmptyHost => "empty host",
            Self::Userinfo => "userinfo '@' is not allowed in the host",
            Self::Backslash => "backslash is not allowed",
            Self::UserinfoOrBackslash => "userinfo '@' and backslashes are not allowed",
            Self::QueryOrFragment => "must be the bare issuer URL: no query, no fragment",
            Self::Quote => "must not contain a quote or an angle bracket",
            Self::NotHttpsOrRooted => {
                "must be an absolute https:// URL or a root-relative path starting with '/'"
            }
        };
        f.write_str(tail)
    }
}

/// The two shapes an audit header name is refused for, as a name rather than a sentence
/// (§13.31 §2).
///
/// It is a type of its own for the reason [`UrlFault`] is: the same check is reached by callers
/// that name the value differently, `compile_settings` naming the settings key
/// (`audit.client_ip_header`) and `bb-auth-adm` naming its own flag (`--client-ip-header`), so
/// each tail lives here once and the leaf's `String` wrapper and the enum's `sentence()` cannot
/// drift apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderFault {
    /// A name outside letters, digits and `-`, or longer than the 64 bytes the leaf bounds it
    /// at. The underscore is the shape that costs an afternoon: nginx drops a request header
    /// whose name carries one unless `underscores_in_headers` says otherwise, so a setting that
    /// allowed it is a setting that reads nothing, in silence, on a file that looks configured.
    NotAName,
    /// One of the three headers in `CREDENTIAL_HEADERS`. An address is parsed and whatever is
    /// not one is dropped, so naming `Authorization` there would only record nothing; a request
    /// id is written down **as it arrives**, so naming a credential header there would copy a
    /// bearer into a file an administrator reads, which is the one thing this system never does
    /// with a key.
    Credential,
}

impl HeaderFault {
    /// The `audit_header_<fault>` code §2 lists, which is what the GUI maps to a `K` key in
    /// slice S8, spelled the way [`UrlFault::code`] is.
    fn code(self) -> &'static str {
        match self {
            Self::NotAName => "audit_header_not_a_name",
            Self::Credential => "audit_header_credential",
        }
    }
}

impl std::fmt::Display for HeaderFault {
    /// The tail of a header refusal, byte for byte as the leaf spelled it before this type
    /// existed. The setting's name and the quoted value come from the caller; the reason comes
    /// from here, once.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tail = match self {
            Self::NotAName => {
                "is not a header name, which is letters, digits and '-' (nginx drops a request \
                 header with an underscore in its name)"
            }
            Self::Credential => "carries a credential, and the audit never writes one down",
        };
        f.write_str(tail)
    }
}

/// Why a settings file is refused, as a name and its arguments rather than as a sentence
/// (docs/ARCHITECTURE.md §13.31).
///
/// This lives in the library because what a settings file is refused for is an opinion about a
/// file three programs read, the same argument that put [`decision_reason`] here for the audit.
/// The **translation** does not: the library has no language, and the `K` table is the one home
/// of what the GUI shows. So `Display` is the exact English the CLI (`bb-auth-adm`) and the gate
/// (`--check-settings`, startup, SIGHUP) printed before this type existed, byte for byte, which
/// is why moving the sentences into each binary was rejected: two binaries print them, so that
/// would be two copies of each. `code()` is the stable name the GUI maps to a `K` key in slice
/// S8, so a page can say the same thing in the reader's language without sniffing English.
///
/// Every code §2 lists is named once in [`SETTINGS_REFUSAL_CODES`] and sampled once in
/// [`settings_refusal_samples`], and §6's tests pin that the two line up with the variants of
/// this enum, so a new variant arrives with a code, a sample and a settings file that reaches it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsRefusal {
    /// The file declares a version this format is not: 1 predates the app clients, 2 predates
    /// the pool, and anything else is not this format at all.
    Version { found: u32 },
    /// A claim name outside `[A-Za-z0-9_:-]`. That charset is what lets
    /// [`derive_profile_header`] build a header from the name at all, so a name with a space, a
    /// quote or a control byte derives a header nginx cannot carry. The file is refused rather
    /// than the entry skipped because a silently skipped claim is a header an application waits
    /// for in silence.
    ClaimCharset { claim: String },
    /// A claim with an empty part around a separator (`:dept`, `dept:`, `a--b`), which would
    /// derive a header with an empty component: the same defect as a name outside the charset,
    /// reached by a different typo.
    ClaimEmptyPart { claim: String },
    /// A claim in [`RESERVED_CLAIMS`], which the gate's `Claims` reads into a typed field,
    /// so `#[serde(flatten)]` never sees the key it names. Configuring one propagates nothing,
    /// forever, and the operator would keep seeing the claim listed as captured on a page that
    /// shows it empty.
    ClaimConsumed { claim: String },
    /// A claim whose derived header is one the gate writes itself: any possible identity header,
    /// [`LOGIN_URL_HEADER`], [`NATIVE_USERNAME_HEADER`]. A self-asserted claim arriving on
    /// `X-Auth-Email` would be an identity the caller typed, and one arriving on
    /// `X-Auth-Native-Username` would be a pool name for the profile edit to act on. The check
    /// runs against every **possible** identity header, not the enabled ones, because turning an
    /// attribute on tomorrow must not discover a collision with a claim configured yesterday, on
    /// a header an application already trusts.
    ClaimHeaderReserved { claim: String, header: String },
    /// Two claims that derive one header, which would make that header carry whichever of the two
    /// the emitter reached first. This is also what catches a repeated claim and spellings that
    /// differ only in case or a separator: all three are the same ambiguity.
    ClaimsCollide {
        first: String,
        second: String,
        header: String,
    },
    /// An identity attribute outside [`IDENTITY_ATTRS`]. Passing an unknown name through instead
    /// of refusing it would let a typo quietly turn an attribute off, and the set of possible
    /// header names has to stay finite and code-defined so nginx can clear every one of them.
    AttrUnknown { attr: String },
    /// The same attribute listed twice, which would emit one header twice.
    AttrTwice { attr: String },
    /// An empty identity attribute list: the one refusal here that names no value, because the
    /// problem is that nothing is left. An authorized `204` that names nobody breaks every
    /// application behind this gate, in silence, which is why an empty list refuses the file
    /// rather than falling back to a default.
    AttrNone,
    /// `session_ttl_secs` under [`MIN_SESSION_TTL`]: a session that expires as it is handed
    /// over is a login loop, not a short login.
    TtlBelowFloor { ttl: u64 },
    /// `session_ttl_secs` past [`MAX_SESSION_TTL`]: the cookie's `exp` arithmetic wraps and
    /// mints a cookie that is already expired.
    TtlAboveCeiling { ttl: u64 },
    /// A Cognito app client id outside letters, digits, `.`, `_` and `-`: the email flow's
    /// `gate.client_id` with no `button`, a social button's `audience` with that button's name.
    ///
    /// Refused because the value is **emitted**, not stored: it is substituted into the sign-in
    /// page as a JavaScript string literal, into an HTML attribute on a button, and into the
    /// query string of Cognito's authorize URL, so this charset is what makes all three safe by
    /// construction rather than by escaping. A real app client id is 26 lowercase alphanumerics,
    /// so nothing this refuses could ever have been one.
    AppClientId {
        /// The button whose `audience` this is, by its `identity_provider` name; `None` for
        /// `gate.client_id`, which belongs to no button.
        button: Option<String>,
        /// The id as given, trimmed, which is what today's sentence quoted.
        id: String,
    },
    /// Hosts `gate.authorized_hosts` names that `gate.cookie_domain` cannot reach, so a login
    /// lands there, sends no session cookie, and bounces back to the sign-in page for ever.
    HostsOutsideCookieDomain {
        hosts: Vec<String>,
        cookie_domain: String,
    },
    /// `gate.landing_url`'s host is outside `gate.authorized_hosts`, so [`rd_url_allowed`]
    /// refuses it at every login and a sign-in with no `rd` falls back to the sign-in page.
    LandingOffHosts,
    /// A URL setting is not an address this estate can be trusted with. `key` says which
    /// setting, `raw` is the text today's sentence quotes (the value as given for the issuer and
    /// the page URLs, trimmed for an asset URL, which is what each leaf printed), and `fault` is
    /// which of the nine shapes [`UrlFault`] lists.
    ///
    /// These are refused because the value is **emitted**, not stored. A page URL goes into a
    /// `Location:` header, into `X-Auth-Login-URL` and into the sign-in page; the issuer is
    /// fetched from over the network and compared byte for byte against a token's `iss`, and
    /// lands in that page's `connect-src`; an asset URL goes into an attribute on a page both
    /// programs emit. Printable ASCII, https-only, no userinfo, no backslash and no quote are
    /// what make those emissions safe with no per-use check, and each fault's own doc says what
    /// the shape would cost.
    Url {
        key: SettingKey,
        raw: String,
        fault: UrlFault,
    },
    /// `gate.social_callback_url` is not an absolute https URL, and Cognito compares the
    /// `redirect_uri` byte for byte.
    CallbackNotHttps,
    /// `gate.cookie_domain` carries a scheme, a port, a path, a leading or trailing dot or dash,
    /// a `..`, or a byte outside letters, digits, `.` and `-`.
    ///
    /// Refused because this is the value of a `Set-Cookie` `Domain=` attribute and a browser
    /// matches that attribute textually, so anything that is not a bare domain is a cookie no
    /// request ever sends: the login lands, the browser arrives with no session, nginx answers
    /// `401`, and the person is back at the sign-in page. That is
    /// [`Self::HostsOutsideCookieDomain`] arrived at from the other end, and it is checked
    /// rather than stripped because a value carrying a scheme was written by somebody who meant
    /// a URL.
    CookieDomainNotBare {
        /// The value as given, which is what today's sentence quoted.
        raw: String,
    },
    /// `gate.cookie_domain` is a single label (`example`, `com`): the mistake here that looks
    /// most like it should work.
    ///
    /// Refused because a browser will not store a cookie for a public suffix and has no use for
    /// one on a bare hostname that is not the request's own, so the setting reaches nothing in
    /// silence. What is wanted is the registrable domain the services share, and the sentence
    /// names it.
    CookieDomainSingleLabel {
        /// The value as given, which is what today's sentence quoted.
        raw: String,
    },
    /// A `gate.authorized_hosts` entry with a control byte in it, the paste that arrived from a
    /// spreadsheet.
    ///
    /// Refused because these entries are compiled into [`UrlPattern`] and the host they
    /// authorize is written into a `Location:` header by the gate's `safe_rd`, where a CR/LF is
    /// a response-splitting gadget.
    HostControlByte {
        /// The pattern as given, which is what today's sentence quoted.
        raw: String,
    },
    /// A `gate.authorized_hosts` entry carrying a scheme, a port or a path.
    ///
    /// Refused because [`rd_url_allowed`] strips those from the candidate before matching, so a
    /// pattern that keeps one matches nothing: the operator reads a host in the list and every
    /// sign-in that names it falls back to the sign-in page, with nothing saying why. The
    /// em-dash in the sentence is today's data, kept byte for byte.
    HostNotBare {
        /// The pattern as given, which is what today's sentence quoted.
        raw: String,
    },
    /// A `gate.authorized_hosts` entry with a userinfo `@` or a `..`.
    ///
    /// Refused for the two shapes [`rd_url_allowed`] refuses on the candidate it matches, so the
    /// list and the matcher cannot disagree: `@` is the lookalike that reads as the estate and
    /// sends the browser to the attacker, and a `..` is a pattern no host can match, which
    /// leaves an operator looking at a host they believe is authorized.
    HostAtOrDotDot {
        /// The pattern as given, which is what today's sentence quoted.
        raw: String,
    },
    /// `gate.oauth_domain` carries a scheme, a path, a leading or trailing dot, or a byte
    /// outside letters, digits, `.` and `-`.
    ///
    /// Refused because the hosted UI's authorize and callback URLs are **built out of this
    /// value**, so a scheme or a path inside it produces a URL nobody wrote, pointing at a host
    /// nobody meant, and the browser leaves the estate to go sign in. Checked, not stripped, for
    /// the same reason as the cookie domain: a value carrying either was written by somebody who
    /// meant a URL.
    OauthDomainNotBare {
        /// The value trimmed, which is what today's sentence quoted.
        raw: String,
    },
    /// A `gate.social_buttons` entry that is a bare string: the shape from before every button
    /// carried its own app client, when one `gate.client_id` served them all.
    ///
    /// Refused rather than read as a button with no audience, because Cognito federates **per
    /// app client**: the name says which provider the pool offers, not which client offers it,
    /// so there is no value this entry could be completed with. The sentence writes the entry in
    /// the shape that works, because the one thing an operator holding this file has to do is add
    /// a value, and that is easier with the shape in front of them than described.
    ButtonBareName {
        /// The name as given, which is what today's sentence quoted, twice.
        name: String,
    },
    /// A `gate.social_buttons` entry whose `identity_provider` is empty once trimmed, so nothing
    /// says what the button is for.
    ///
    /// Refused because that name is the whole entry: it is what the sign-in page shows on the
    /// button, what Cognito is named in the authorize URL, and what the callback matches the
    /// button against. An empty one draws a button that leads a visitor to a provider no pool
    /// offers. It refuses the file rather than skipping the entry for the reason the whole list
    /// is fatal: a button an operator wrote and the page does not draw is invisible, with no
    /// error and no log line at the moment it matters.
    ButtonNoIdp,
    /// A `gate.social_buttons` `identity_provider` outside letters, digits, `.`, `_` and `-`.
    ///
    /// Refused because the name is **emitted**: into the sign-in page's HTML, into the
    /// `identity_provider` query parameter of Cognito's authorize URL, and into the button's
    /// label. That charset is what makes all three safe by construction rather than by escaping,
    /// the same argument [`compile_app_client_id`] makes for the audience beside it. It is not a
    /// list of known providers, because a pool may federate a SAML or OIDC provider under any
    /// name its administrator chose; what this refuses is a value that could never be one.
    ButtonIdpCharset {
        /// The name trimmed, which is what today's sentence quoted.
        idp: String,
    },
    /// One `identity_provider` listed by two `gate.social_buttons` entries, compared
    /// case-insensitively because Cognito's own names differ only in case.
    ///
    /// Refused rather than deduplicated: two buttons for one provider is not what anybody meant,
    /// and quietly dropping one hides a copy-paste from an operator looking straight at the
    /// list. It also keeps one provider bound to exactly one app client, which is what the
    /// callback's lookup of a button by provider assumes.
    ButtonTwice {
        /// The name as the **second** entry spelled it, which is what today's sentence quoted:
        /// the comparison is case-insensitive, so the stored name is the first entry's, and
        /// naming that would blame the line nobody wrote wrong.
        idp: String,
    },
    /// A `gate.social_buttons` entry with an empty `audience`: a provider with no app client.
    ///
    /// Refused because the app client is the half that offers the provider, so a button drawn
    /// from this entry opens the hosted UI on a client that does not list that provider, and the
    /// visitor sits on Cognito's own error page with the reason in Amazon's words. A button that
    /// cannot be drawn is refused rather than dropped, for the same reason as a bad provider
    /// name, and the sentence names the value to add.
    ButtonNoAudience {
        /// The provider name trimmed, which is what today's sentence quoted, twice.
        idp: String,
    },
    /// Social buttons are configured with no `gate.oauth_domain` or no
    /// `gate.social_callback_url`: nowhere to send a visitor, nowhere for them to come back to.
    SocialHalfConfigured { buttons: usize },
    /// An `audit.client_ip_header` / `audit.request_id_header` value the audit may not read a
    /// value out of. `key` says which of the two settings, `name` is the name **trimmed** (the
    /// text today's sentence quoted), `fault` is which of the two shapes [`HeaderFault`] lists.
    ///
    /// Refused because the audit believes a header only when an operator has named it, and a
    /// name that reaches nothing is worse than the setting switched off: every row goes on
    /// looking configured with nothing in the field the setting was written for. The underscore
    /// is the shape that bites, because nginx drops such a header before the gate ever sees it.
    /// A credential is refused because a request id is recorded as it arrives, so this is the
    /// one place a bearer could be written into a file an administrator reads.
    AuditHeader {
        key: SettingKey,
        name: String,
        fault: HeaderFault,
    },
    /// The two audit headers name one header, which cannot carry an address and a request id
    /// at once.
    AuditHeadersSame { name: String },
    /// An `audit.rotation` / `audit.retention` value that is not an amount and a unit at all.
    /// `key` says which of the two settings, `raw` is the value **trimmed** (the text today's
    /// sentence quoted).
    ///
    /// Refused rather than defaulted, because the rotation decides when the live audit file is
    /// replaced: a value silently read as the default rotates that file on a schedule nobody
    /// wrote, and an operator reading a limit in the file believes it is the one in force.
    AuditLimitNotAmount { key: SettingKey, raw: String },
    /// A limit of zero (`0 MiB`): an amount of nothing.
    ///
    /// Refused because both settings turn a zero into a destruction: a rotation of `0 MiB`
    /// rotates on every event, and a retention of `0 MiB` keeps nothing, so the audit would
    /// prune the evidence it exists to keep, quietly, from the next request onward.
    AuditLimitZero { key: SettingKey, raw: String },
    /// A limit past the ceiling of the unit it was written in (a century, a tebibyte). `unit`
    /// is that unit, because the ceiling the sentence names is the unit's own.
    ///
    /// Refused because a limit that high bounds nothing, which is the promise the section makes:
    /// the audit is bounded by construction, and the arithmetic behind a limit saturates, so
    /// `999999999 GiB` is a file that grows past any disk while looking bounded. The ceilings
    /// are far past any disk on this host, so nothing an operator means is refused.
    AuditLimitTooMuch {
        key: SettingKey,
        raw: String,
        unit: AuditUnit,
    },
    /// A rotation and a retention that are both units of time, so nothing bounds how many bytes
    /// the audit takes on disk. The two strings are the limits as the file spells them
    /// ([`AuditLimit::spelled`]), which is what today's sentence quoted, and the retention is
    /// `None` when nobody wrote one, which is the sentence's other arm.
    ///
    /// Refused because this is the one combination the audit's bound does not cover: a time says
    /// how old the audit gets and says nothing about how big, so a flood of refusals inside one
    /// rotation period grows the live file without limit, and a flood is the one case an audit
    /// exists for. With a size in either setting, [`AuditPolicy::max_bytes`] is an answer.
    AuditUnbounded {
        rotation: String,
        retention: Option<String>,
    },
    /// `ui.brand_name` carries a control character: the paste that arrived from a spreadsheet,
    /// or a terminal that wrote an escape into the middle of the name.
    ///
    /// Refused because this value is **laid out and emitted**, not merely stored: it is the word
    /// a sign-in page, the console and the self-service page print beside the logo, and the name
    /// the browser tab carries. It is HTML-escaped on the way out, so a control byte is not a
    /// hole in the page; it is a deployment whose name has an invisible character in it, which is
    /// never what somebody typed and is invisible to fix, because nothing on the page shows it.
    /// `name` is the **trimmed** value, which is what today's sentence quoted.
    BrandControl { name: String },
    /// `ui.brand_name` is longer than [`MAX_BRAND_NAME`] characters.
    ///
    /// Refused because the bound is on what a page lays out, not on what the file stores: the
    /// name sits in one header row beside the logo and in a tab title, and a value of a thousand
    /// characters pushes the rest of that row out of it. The count is of **characters**, so an
    /// accented name is measured as a reader counts it, and the sentence prints that count, since
    /// a byte count blames a name the layout does fit.
    BrandTooLong { chars: usize },
    /// `ui.theme` is not one of `system`, `light`, `dark`.
    ThemeUnknown { raw: String },
}

impl SettingsRefusal {
    /// The stable `snake_case` name of this refusal, the one §13.31 §2 lists and the GUI maps
    /// to a `K` key. No production code branches on it: it is the refusal's name for the tests
    /// and for the page, as [`Decision`]'s are for the audit. Every name it answers is listed
    /// exactly once in [`SETTINGS_REFUSAL_CODES`].
    pub fn code(&self) -> &'static str {
        match self {
            Self::Version { .. } => "version",
            Self::ClaimCharset { .. } => "claim_charset",
            Self::ClaimEmptyPart { .. } => "claim_empty_part",
            Self::ClaimConsumed { .. } => "claim_consumed",
            Self::ClaimHeaderReserved { .. } => "claim_header_reserved",
            Self::ClaimsCollide { .. } => "claims_collide",
            Self::AttrUnknown { .. } => "attr_unknown",
            Self::AttrTwice { .. } => "attr_twice",
            Self::AttrNone => "attr_none",
            Self::TtlBelowFloor { .. } => "ttl_below_floor",
            Self::TtlAboveCeiling { .. } => "ttl_above_ceiling",
            Self::AppClientId { .. } => "app_client_id",
            Self::HostsOutsideCookieDomain { .. } => "hosts_outside_cookie_domain",
            Self::LandingOffHosts => "landing_off_hosts",
            Self::Url { fault, .. } => fault.code(),
            Self::CallbackNotHttps => "callback_not_https",
            Self::CookieDomainNotBare { .. } => "cookie_domain_not_bare",
            Self::CookieDomainSingleLabel { .. } => "cookie_domain_single_label",
            Self::HostControlByte { .. } => "host_control_byte",
            Self::HostNotBare { .. } => "host_not_bare",
            Self::HostAtOrDotDot { .. } => "host_at_or_dot_dot",
            Self::OauthDomainNotBare { .. } => "oauth_domain_not_bare",
            Self::ButtonBareName { .. } => "button_bare_name",
            Self::ButtonNoIdp => "button_no_idp",
            Self::ButtonIdpCharset { .. } => "button_idp_charset",
            Self::ButtonTwice { .. } => "button_twice",
            Self::ButtonNoAudience { .. } => "button_no_audience",
            Self::SocialHalfConfigured { .. } => "social_half_configured",
            Self::AuditHeader { fault, .. } => fault.code(),
            Self::AuditHeadersSame { .. } => "audit_headers_same",
            Self::AuditLimitNotAmount { .. } => "audit_limit_not_amount",
            Self::AuditLimitZero { .. } => "audit_limit_zero",
            Self::AuditLimitTooMuch { .. } => "audit_limit_too_much",
            Self::AuditUnbounded { .. } => "audit_unbounded",
            Self::BrandControl { .. } => "brand_control",
            Self::BrandTooLong { .. } => "brand_too_long",
            Self::ThemeUnknown { .. } => "theme_unknown",
        }
    }

    /// The key `compile_settings` used to write in front of the leaf's own sentence, as a
    /// `map_err(|e| format!("…: {e}"))`: `profile_claims` and `identity_attrs` for the leaves
    /// whose parser knows nothing of the file's keys, `authorized_hosts` for the three host
    /// faults (the leaf's sentence starts `host pattern '…'`, and the settings function named
    /// the key), `login_url` for the sign-in page's URL (which is how today's doubled
    /// `login_url: login_url '…': …` is kept), `audit.rotation` / `audit.retention` for a limit
    /// (the leaf's sentence starts `'…': an amount of nothing`, and the settings function named
    /// the key), and `audit` for the unbounded pair (the settings function prefixed the pair
    /// leaf's sentence with `audit:`, which is the prefix `bb-auth-adm` swaps for its own flags).
    /// Nothing at all for a refusal the settings function spells itself, whose sentence already
    /// names its key: the two audit header refusals and the two brand refusals are among those,
    /// because each sentence opens with the name of the setting it refuses (§13.31 §2).
    pub(crate) fn prefix(&self) -> Option<&'static str> {
        match self {
            Self::ClaimCharset { .. }
            | Self::ClaimEmptyPart { .. }
            | Self::ClaimConsumed { .. }
            | Self::ClaimHeaderReserved { .. }
            | Self::ClaimsCollide { .. } => Some("profile_claims"),
            Self::AttrUnknown { .. } | Self::AttrTwice { .. } | Self::AttrNone => {
                Some("identity_attrs")
            }
            Self::HostControlByte { .. }
            | Self::HostNotBare { .. }
            | Self::HostAtOrDotDot { .. } => Some("authorized_hosts"),
            Self::Url {
                key: SettingKey::LoginUrl,
                ..
            } => Some("login_url"),
            Self::AuditLimitNotAmount { key, .. }
            | Self::AuditLimitZero { key, .. }
            | Self::AuditLimitTooMuch { key, .. } => Some(key.name()),
            Self::AuditUnbounded { .. } => Some("audit"),
            _ => None,
        }
    }

    /// The refusal's own words, without [`Self::prefix`]: what a `String` leaf wrapper returns,
    /// since the access file's parser and the CLI's flag-named pre-checks call that leaf for a
    /// value the file's keys say nothing about, and what `Display` puts after the prefix.
    pub(crate) fn sentence(&self) -> String {
        match self {
            // Explanatory for the one version that exists in the wild, terse for anything else.
            Self::Version { found } => match *found {
                1 => format!(
                    "\"version\": 1 was written before the app clients moved into this file \
                     (expected {SETTINGS_VERSION}). Set gate.client_id, gate.oauth_domain and \
                     gate.social_callback_url, give every gate.social_buttons entry its own \
                     audience, and bump the version; see the CHANGELOG"
                ),
                2 => format!(
                    "\"version\": 2 was written before the pool, the cookie domain and the \
                     authorized hosts moved into this file (expected {SETTINGS_VERSION}). Copy \
                     BB_AUTH_COGNITO_ISSUER into gate.issuer, BB_AUTH_COOKIE_DOMAIN into \
                     gate.cookie_domain and BB_AUTH_AUTHORIZED_HOSTS into gate.authorized_hosts \
                     (as a list), bump the version, and take all three out of bb-auth.env; see \
                     the CHANGELOG"
                ),
                v => format!("\"version\": {v} is not this format (expected {SETTINGS_VERSION})"),
            },
            Self::ClaimCharset { claim } => {
                format!("claim '{claim}' must be non-empty and contain only [A-Za-z0-9_:-]")
            }
            Self::ClaimEmptyPart { claim } => {
                format!("claim '{claim}' has an empty part around a '_', ':' or '-'")
            }
            Self::ClaimConsumed { claim } => {
                format!("claim '{claim}' is consumed by the gate itself and cannot be propagated")
            }
            Self::ClaimHeaderReserved { claim, header } => {
                format!("claim '{claim}' derives '{header}', which is reserved")
            }
            Self::ClaimsCollide {
                first,
                second,
                header,
            } => format!("claims '{first}' and '{second}' both derive '{header}'"),
            Self::AttrUnknown { attr } => format!(
                "unknown identity attribute '{attr}' (known: {})",
                IDENTITY_ATTRS.join(", ")
            ),
            Self::AttrTwice { attr } => format!("identity attribute '{attr}' is listed twice"),
            Self::AttrNone => format!(
                "at least one identity attribute is required (known: {}); a 204 that names \
                 nobody breaks every application behind this gate, in silence",
                IDENTITY_ATTRS.join(", ")
            ),
            Self::TtlBelowFloor { ttl } => format!(
                "session_ttl_secs: {ttl} is below the {MIN_SESSION_TTL}s floor; a session that \
                 expires as it is handed over is a login loop, not a short login"
            ),
            Self::TtlAboveCeiling { ttl } => format!(
                "session_ttl_secs: {ttl} is past the {MAX_SESSION_TTL}s ceiling; a lifetime that \
                 does not fit the arithmetic mints a cookie that is already expired"
            ),
            Self::AppClientId { button, id } => match button {
                None => format!("client_id: '{id}' {APP_CLIENT_TAIL}"),
                Some(b) => format!("social_buttons '{b}': audience: '{id}' {APP_CLIENT_TAIL}"),
            },
            Self::HostsOutsideCookieDomain {
                hosts,
                cookie_domain,
            } => format!(
                "authorized_hosts: {} outside cookie_domain '{cookie_domain}', so a login would \
                 redirect there and the browser would send no session cookie: a 401, a bounce \
                 back to the sign-in page, and a loop",
                hosts.join(", ")
            ),
            Self::LandingOffHosts => "landing_url: its host is not covered by authorized_hosts, \
                 so every sign-in with no rd would fall back to the sign-in page"
                .to_string(),
            Self::Url { key, raw, fault } => {
                format!("{} '{raw}': {fault}", key.name())
            }
            Self::CallbackNotHttps => "social_callback_url: must be the absolute https:// URL \
                 registered on the app client, because Cognito compares it byte for byte"
                .to_string(),
            Self::CookieDomainNotBare { raw } => format!(
                "cookie_domain '{raw}': is not a bare domain: letters, digits, '.' and '-', an \
                 optional leading dot, and no scheme, port or path"
            ),
            Self::CookieDomainSingleLabel { raw } => format!(
                "cookie_domain '{raw}': is a single label, which a browser stores for nothing: \
                 name the registrable domain the services share, such as '.example.com'"
            ),
            Self::HostControlByte { raw } => {
                format!("host pattern '{raw}': contains a control byte")
            }
            Self::HostNotBare { raw } => {
                format!("host pattern '{raw}': must be a bare host — no scheme, port or path")
            }
            Self::HostAtOrDotDot { raw } => {
                format!("host pattern '{raw}': must not contain '@' or '..'")
            }
            Self::OauthDomainNotBare { raw } => format!(
                "oauth_domain: '{raw}' is not a bare host, which is letters, digits, '.' and \
                 '-' with no scheme and no path"
            ),
            Self::ButtonBareName { name } => format!(
                "social_buttons: '{name}' is a bare provider name, which was the shape before \
                 each button carried its own app client. Write it as {{ \"idp\": \"{name}\", \
                 \"audience\": \"<app client id>\" }}"
            ),
            Self::ButtonNoIdp => "social_buttons: an entry names no identity_provider".to_string(),
            Self::ButtonIdpCharset { idp } => format!(
                "social_buttons '{idp}': a Cognito identity_provider name is letters, digits, \
                 '.', '_' and '-'"
            ),
            Self::ButtonTwice { idp } => format!("social_buttons: '{idp}' is listed twice"),
            Self::ButtonNoAudience { idp } => format!(
                "social_buttons '{idp}': names no app client, so no button could be drawn for \
                 it. Cognito federates per app client, so this is the one that offers {idp}"
            ),
            Self::SocialHalfConfigured { buttons } => format!(
                "social_buttons: {buttons} button(s) configured, but oauth_domain or \
                 social_callback_url is empty, so there is nowhere to send a visitor and \
                 nowhere for them to come back to"
            ),
            Self::AuditHeader { key, name, fault } => {
                format!("{}: '{name}' {fault}", key.name())
            }
            Self::AuditHeadersSame { name } => format!(
                "audit.client_ip_header and audit.request_id_header both name '{name}'; one \
                 header cannot carry an address and a request id at once"
            ),
            Self::AuditLimitNotAmount { raw, .. } => format!(
                "'{raw}' is not an amount and a unit: write it as, say, '4 MiB', '1 GiB', \
                 '26 weeks', '6 months' or '1 year'"
            ),
            Self::AuditLimitZero { raw, .. } => {
                format!("'{raw}': an amount of nothing is not a limit")
            }
            Self::AuditLimitTooMuch { raw, unit, .. } => format!(
                "'{raw}': at most {} {}, which is already more than any disk or any audit needs",
                unit.max_amount(),
                unit.code()
            ),
            Self::AuditUnbounded {
                rotation,
                retention,
            } => format!(
                "rotation '{rotation}' with {} bounds how old the audit gets and not how big: \
                 a flood of refusals would grow the live file without limit. Rotate on a size \
                 (MiB, GiB) or give the retention one",
                match retention {
                    Some(r) => format!("retention '{r}'"),
                    None => "no retention".to_string(),
                }
            ),
            Self::BrandControl { name } => {
                format!("brand_name '{name}': contains a control character")
            }
            Self::BrandTooLong { chars } => format!(
                "brand_name: {chars} characters is longer than the {MAX_BRAND_NAME} allowed"
            ),
            Self::ThemeUnknown { raw } => {
                format!("theme: '{raw}' is not one of system, light, dark")
            }
        }
    }
}

impl std::fmt::Display for SettingsRefusal {
    /// Today's sentence, byte for byte, pinned by the S0 goldens: `prefix`, a `": "`, then
    /// `sentence`, which is exactly how `compile_settings` spelled a leaf's refusal through its
    /// `map_err` before this type existed. Every refusal is spelled out of its own arguments, so
    /// the GUI can say the same thing in the reader's language from the variant and its fields,
    /// and this stays the one English the CLI and the gate print (§13.31 §3).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.prefix() {
            Some(p) => write!(f, "{p}: {}", self.sentence()),
            None => f.write_str(&self.sentence()),
        }
    }
}

/// Every [`SettingsRefusal::code`], exactly once, in the order docs/ARCHITECTURE.md §13.31 §2
/// lists the refusals.
///
/// It exists for the tests (§13.31 §6): one asserts that the codes of
/// [`settings_refusal_samples`] are exactly this list, each exactly once, and one asserts that the
/// settings documents the golden test carries reach every code here and no code outside it. A new
/// variant therefore has to be listed, sampled and given a fixture that reaches it, and the test
/// names which of the three is missing. No production code reads it: the GUI matches on the
/// variant, and the CLI and the gate print the sentence.
pub const SETTINGS_REFUSAL_CODES: &[&str] = &[
    "version",
    "claim_charset",
    "claim_empty_part",
    "claim_consumed",
    "claim_header_reserved",
    "claims_collide",
    "attr_unknown",
    "attr_twice",
    "attr_none",
    "ttl_below_floor",
    "ttl_above_ceiling",
    "app_client_id",
    "url_not_printable",
    "url_not_https",
    "url_empty_host",
    "url_userinfo",
    "url_backslash",
    "url_userinfo_or_backslash",
    "url_query_or_fragment",
    "url_quote",
    "url_not_https_or_rooted",
    "callback_not_https",
    "cookie_domain_not_bare",
    "cookie_domain_single_label",
    "host_control_byte",
    "host_not_bare",
    "host_at_or_dot_dot",
    "hosts_outside_cookie_domain",
    "landing_off_hosts",
    "oauth_domain_not_bare",
    "button_bare_name",
    "button_no_idp",
    "button_idp_charset",
    "button_twice",
    "button_no_audience",
    "social_half_configured",
    "audit_header_not_a_name",
    "audit_header_credential",
    "audit_headers_same",
    "audit_limit_not_amount",
    "audit_limit_zero",
    "audit_limit_too_much",
    "audit_unbounded",
    "brand_control",
    "brand_too_long",
    "theme_unknown",
];

/// One refusal of every code in [`SETTINGS_REFUSAL_CODES`], in that order, built with neutral
/// arguments.
///
/// It exists for the tests (§13.31 §3): the GUI's test walks every code and asserts its page says
/// something about it in both languages, and a `cfg(test)` item is invisible across the crate
/// boundary, so the samples are built here. The arguments avoid every wire key that test forbids
/// in a translated message (`brand_name`, `login_url`, `client_id`, `audit.rotation`, …), so a
/// message cannot pass it by quoting the setting's own name.
#[doc(hidden)]
pub fn settings_refusal_samples() -> Vec<SettingsRefusal> {
    vec![
        // A version that is neither of the two older formats, so the sentence is the terse one.
        SettingsRefusal::Version { found: 4 },
        SettingsRefusal::ClaimCharset {
            claim: "a b".to_string(),
        },
        SettingsRefusal::ClaimEmptyPart {
            claim: "a::b".to_string(),
        },
        SettingsRefusal::ClaimConsumed {
            claim: "nickname".to_string(),
        },
        SettingsRefusal::ClaimHeaderReserved {
            claim: "mail_alias".to_string(),
            header: "X-Auth-Mail-Alias".to_string(),
        },
        SettingsRefusal::ClaimsCollide {
            first: "a_b".to_string(),
            second: "a:b".to_string(),
            header: "X-Auth-A-B".to_string(),
        },
        SettingsRefusal::AttrUnknown {
            attr: "nope".to_string(),
        },
        SettingsRefusal::AttrTwice {
            attr: "mail".to_string(),
        },
        SettingsRefusal::AttrNone,
        SettingsRefusal::TtlBelowFloor { ttl: 30 },
        SettingsRefusal::TtlAboveCeiling { ttl: 3_153_600_001 },
        SettingsRefusal::AppClientId {
            button: None,
            id: "bad id".to_string(),
        },
        // One of each URL fault, all on one setting: the code is the fault's, and the GUI's arm
        // takes the setting from `key`, so nine settings would only repeat the fault nine times.
        SettingsRefusal::Url {
            key: SettingKey::DeniedUrl,
            raw: "https://x.com/a b".to_string(),
            fault: UrlFault::NotPrintable,
        },
        SettingsRefusal::Url {
            key: SettingKey::DeniedUrl,
            raw: "http://x.com".to_string(),
            fault: UrlFault::NotHttps,
        },
        SettingsRefusal::Url {
            key: SettingKey::DeniedUrl,
            raw: "https://".to_string(),
            fault: UrlFault::EmptyHost,
        },
        SettingsRefusal::Url {
            key: SettingKey::DeniedUrl,
            raw: "https://a@x.com".to_string(),
            fault: UrlFault::Userinfo,
        },
        SettingsRefusal::Url {
            key: SettingKey::DeniedUrl,
            raw: "https://x.com\\a".to_string(),
            fault: UrlFault::Backslash,
        },
        SettingsRefusal::Url {
            key: SettingKey::Issuer,
            raw: "https://a@x.com\\a".to_string(),
            fault: UrlFault::UserinfoOrBackslash,
        },
        SettingsRefusal::Url {
            key: SettingKey::Issuer,
            raw: "https://x.com?q".to_string(),
            fault: UrlFault::QueryOrFragment,
        },
        SettingsRefusal::Url {
            key: SettingKey::StylesheetUrl,
            raw: "https://x.com/\"a\"".to_string(),
            fault: UrlFault::Quote,
        },
        SettingsRefusal::Url {
            key: SettingKey::LogoUrl,
            raw: "ftp://x.com".to_string(),
            fault: UrlFault::NotHttpsOrRooted,
        },
        SettingsRefusal::CallbackNotHttps,
        SettingsRefusal::CookieDomainNotBare {
            raw: "https://x.com".to_string(),
        },
        SettingsRefusal::CookieDomainSingleLabel {
            raw: "example".to_string(),
        },
        SettingsRefusal::HostControlByte {
            raw: "ho\tst".to_string(),
        },
        SettingsRefusal::HostNotBare {
            raw: "https://x.com".to_string(),
        },
        SettingsRefusal::HostAtOrDotDot {
            raw: "a..b".to_string(),
        },
        SettingsRefusal::HostsOutsideCookieDomain {
            hosts: vec!["other.com".to_string()],
            cookie_domain: ".example.com".to_string(),
        },
        SettingsRefusal::LandingOffHosts,
        SettingsRefusal::OauthDomainNotBare {
            raw: "https://x.com".to_string(),
        },
        SettingsRefusal::ButtonBareName {
            name: "Google".to_string(),
        },
        SettingsRefusal::ButtonNoIdp,
        SettingsRefusal::ButtonIdpCharset {
            idp: "a b".to_string(),
        },
        SettingsRefusal::ButtonTwice {
            idp: "Google".to_string(),
        },
        SettingsRefusal::ButtonNoAudience {
            idp: "Google".to_string(),
        },
        SettingsRefusal::SocialHalfConfigured { buttons: 1 },
        SettingsRefusal::AuditHeader {
            key: SettingKey::ClientIpHeader,
            name: "X_Real_IP".to_string(),
            fault: HeaderFault::NotAName,
        },
        SettingsRefusal::AuditHeader {
            key: SettingKey::RequestIdHeader,
            name: "Authorization".to_string(),
            fault: HeaderFault::Credential,
        },
        SettingsRefusal::AuditHeadersSame {
            name: "X-Real-IP".to_string(),
        },
        SettingsRefusal::AuditLimitNotAmount {
            key: SettingKey::AuditRotation,
            raw: "4".to_string(),
        },
        SettingsRefusal::AuditLimitZero {
            key: SettingKey::AuditRotation,
            raw: "0 MiB".to_string(),
        },
        SettingsRefusal::AuditLimitTooMuch {
            key: SettingKey::AuditRotation,
            raw: "2048 GiB".to_string(),
            unit: AuditUnit::GiB,
        },
        SettingsRefusal::AuditUnbounded {
            rotation: "1 year".to_string(),
            retention: None,
        },
        SettingsRefusal::BrandControl {
            name: "Bad\u{7}Bat".to_string(),
        },
        SettingsRefusal::BrandTooLong {
            chars: MAX_BRAND_NAME + 1,
        },
        SettingsRefusal::ThemeUnknown {
            raw: "sepia".to_string(),
        },
    ]
}
