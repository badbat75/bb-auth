use crate::*;

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

/// The two languages the binary carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Lang {
    En,
    It,
}

impl Lang {
    /// The `lang=` attribute, the cookie value, and the query parameter — one spelling.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::It => "it",
        }
    }

    /// How the language names itself, for its option in the Settings menu. A language menu
    /// that translated its own entries would hide the one an operator is looking for behind
    /// the language they cannot read, which is the one case where translating is the bug.
    fn name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::It => "Italiano",
        }
    }
}

/// Parse a language name, from `BB_AUTH_WEB_DEFAULT_LANG` or, through [`parse_lang_pref`],
/// from the query and the cookie. `None` for anything else — an unknown value is simply not
/// a preference.
pub(crate) fn parse_lang(s: &str) -> Option<Lang> {
    match s.trim().to_ascii_lowercase().as_str() {
        "en" => Some(Lang::En),
        "it" => Some(Lang::It),
        _ => None,
    }
}

/// What the Settings menu offers, which is not the same set as [`Lang`]: `Auto` is the
/// choice to make no choice, and it resolves per request against the browser's
/// `Accept-Language` (see [`negotiate_lang`]).
///
/// It needs a type of its own because [`Lang`] has to stay the two the table actually holds:
/// every string on the page is looked up by one, so `Auto` could never travel that far. The
/// theme needs no such second type for exactly the mirror reason: [`UiTheme::System`] *is* a
/// value the renderer carries all the way to the page, as an absent attribute.
///
/// `Auto` is also the floor, not an extra state bolted on: a session that never expressed a
/// preference has always been served what `Auto` means, so naming the behaviour changes
/// nobody's page and only makes it choosable again after choosing something else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LangPref {
    Auto,
    Fixed(Lang),
}

impl LangPref {
    /// The cookie value and the query parameter value: one spelling, and for a fixed choice
    /// it is [`Lang::code`]'s own, so `?lang=it` still means exactly what it always meant.
    pub(crate) fn code(self) -> &'static str {
        match self {
            LangPref::Auto => "auto",
            LangPref::Fixed(l) => l.code(),
        }
    }

    /// The label its option in the Settings menu shows, rendered in `lang`. Only `Auto` is
    /// translated: the other two name themselves (see [`Lang::name`]).
    pub(crate) fn label(self, lang: Lang) -> &'static str {
        match self {
            LangPref::Auto => t(lang, K::LangAuto),
            LangPref::Fixed(l) => l.name(),
        }
    }
}

/// Parse a language preference, from the query or the cookie: the two language codes plus
/// `auto`. `None` for anything else, exactly as [`parse_lang`] does and for the same reason.
pub(crate) fn parse_lang_pref(s: &str) -> Option<LangPref> {
    match s.trim().to_ascii_lowercase().as_str() {
        "auto" => Some(LangPref::Auto),
        _ => parse_lang(s).map(LangPref::Fixed),
    }
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

/// The three appearances a page can render in are [`UiTheme`], the library's, and not a
/// second enum here saying the same three words.
///
/// That is the presentation contract's doing rather than convenience: the settings file names
/// a theme, both programs stamp it onto `html` as `data-theme`, and one selector in
/// [`THEME_CSS`] keys off it. Two enums would be two spellings of `dark` waiting to disagree.
/// What stays local is the only part that is this GUI's alone: the label an option shows, and
/// what a cookie value means, neither of which the gate has any use for.
///
/// The label is a [`K`] and not a string, unlike [`LangPref::label`]: an appearance is prose
/// about the page, so it translates.
pub(crate) fn theme_label(theme: UiTheme) -> K {
    match theme {
        UiTheme::Light => K::ThemeLight,
        UiTheme::Dark => K::ThemeDark,
        UiTheme::System => K::ThemeSystem,
    }
}

/// Parse a theme name out of the query or the cookie, where **empty means no choice** rather
/// than `System`, which is the one place this differs from [`UiTheme::parse`] and the reason
/// it is a function and not a call.
///
/// A settings file that leaves `theme` blank has said "no preference", and `System` is the
/// right reading of that. A cookie whose value is blank has not said anything at all, and must
/// fall back exactly as a missing cookie does, so that a deployment's own default still
/// applies. `None` for an unrecognised value, for the same reason.
pub(crate) fn parse_theme(s: &str) -> Option<UiTheme> {
    match s.trim() {
        "" => None,
        v => UiTheme::parse(v),
    }
}

/// How the Settings page opens: every group expanded, or every group folded to its heading.
///
/// A preference and not a parameter of the page, because the commands that set it are meant to
/// stick: an operator who opens everything to work through the page wants it open after the
/// next save too, and a save ends in a redirect that carries no query. Each group still opens
/// and closes on its own in the browser, with no script, since each one is a `details`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum GroupsPref {
    Open,
    /// Where every browser starts: the page reads as its five headings, which is its table of
    /// contents, and the one group somebody came to change is a click away. A page of every
    /// field at once is a page that has to be scrolled to find the one that matters.
    #[default]
    Closed,
}

impl GroupsPref {
    /// The cookie value and the query value: one spelling.
    pub(crate) fn code(self) -> &'static str {
        match self {
            GroupsPref::Open => "open",
            GroupsPref::Closed => "closed",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<GroupsPref> {
        match s.trim() {
            "open" => Some(GroupsPref::Open),
            "closed" => Some(GroupsPref::Closed),
            _ => None,
        }
    }
}

/// Which clock the audit is read in: the third preference, and the only one that is not in the
/// Settings menu, because it changes one page and its `Custom` choice needs a text box.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum TzPref {
    /// What the file stores, and where every session starts until it chooses otherwise: the
    /// same floor `Auto` and `System` are for the other two, so a deployment that never
    /// chooses reads the page it always read.
    #[default]
    Utc,
    /// The zone of the **host** this program runs on, and not the browser's: no request header
    /// carries a browser's zone, and a page that may not need a script has no way to ask for it.
    Local,
    /// A zone the operator named: an IANA name out of the host's database, or a fixed offset,
    /// held in the spelling [`custom_zone`] gives it.
    Custom(String),
}

impl TzPref {
    /// The cookie value, which is also what [`parse_tz_pref`] reads back. A custom zone is its
    /// own spelling, which [`custom_zone`] has already held to a charset a cookie may carry.
    pub(crate) fn code(&self) -> &str {
        match self {
            TzPref::Utc => "utc",
            TzPref::Local => "local",
            TzPref::Custom(z) => z,
        }
    }

    /// Which option of the audit's list box this is.
    pub(crate) fn choice(&self) -> &'static str {
        match self {
            TzPref::Utc => "utc",
            TzPref::Local => "local",
            TzPref::Custom(_) => "custom",
        }
    }
}

/// Parse a zone preference out of the cookie or out of the audit's text box. `None` for
/// anything that is neither of the two words nor a zone [`custom_zone`] accepts, which leaves
/// whatever preference was already in force standing.
pub(crate) fn parse_tz_pref(s: &str) -> Option<TzPref> {
    let v = s.trim();
    if v.eq_ignore_ascii_case("utc") {
        Some(TzPref::Utc)
    } else if v.eq_ignore_ascii_case("local") {
        Some(TzPref::Local)
    } else {
        custom_zone(v).map(TzPref::Custom)
    }
}

/// A zone of the operator's own, in the spelling the cookie stores: a fixed offset as
/// `+HH:MM`, or an IANA name as typed. `None` for anything else.
///
/// A name is letters, digits, `_`, `+`, `-` and `/`, starting with a letter, which is every
/// name in the database and nothing that can leave it: there is no `.`, so there is no `..`,
/// so there is no path that climbs out of [`ZONEINFO_DIR`]. The same charset is what makes the
/// value safe in a `Set-Cookie`, which is where it goes next. Whether the host has a zone of
/// that name is a question for the page that reads it, which says so when it does not.
pub(crate) fn custom_zone(v: &str) -> Option<String> {
    let v = v.trim();
    if let Some(secs) = parse_offset(v) {
        return Some(format_offset(secs));
    }
    let named = !v.is_empty()
        && v.len() <= 64
        && v.starts_with(|c: char| c.is_ascii_alphabetic())
        && !v.ends_with('/')
        && !v.contains("//")
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-' | b'/'));
    named.then(|| v.to_string())
}

/// A fixed offset from UTC in seconds: `+2`, `+02`, `+0200` or `+02:00`, optionally after `UTC`
/// or `GMT`, with the sign meaning what it means on a clock: ahead of UTC.
///
/// The sign is why this exists rather than the string going to a POSIX `TZ` parser, which is
/// what the zone library would have done with it: POSIX spells two hours **ahead** of UTC as
/// `UTC-2`, the opposite of what anybody typing it into a box means, and a page that silently
/// read four hours out would be worse than one that refused. Up to fourteen hours either way,
/// which is every offset in use.
pub(crate) fn parse_offset(v: &str) -> Option<i32> {
    let up = v.trim().to_ascii_uppercase();
    let rest = up
        .strip_prefix("UTC")
        .or_else(|| up.strip_prefix("GMT"))
        .unwrap_or(&up);
    let (sign, digits) = match rest.as_bytes().first()? {
        b'+' => (1, &rest[1..]),
        b'-' => (-1, &rest[1..]),
        _ => return None,
    };
    let (h, m) = match digits.split_once(':') {
        Some(pair) => pair,
        None if digits.len() > 2 => digits.split_at(digits.len() - 2),
        None => (digits, "0"),
    };
    let two_digits = |s: &str| (1..=2).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    if !two_digits(h) || !two_digits(m) {
        return None;
    }
    let (h, m): (i32, i32) = (h.parse().ok()?, m.parse().ok()?);
    if m > 59 || h * 60 + m > 14 * 60 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60))
}

/// An offset in seconds as `+HH:MM`, which is how the heading names a fixed zone and how the
/// cookie stores one.
pub(crate) fn format_offset(secs: i32) -> String {
    let a = secs.unsigned_abs();
    let sign = if secs < 0 { '-' } else { '+' };
    format!("{sign}{:02}:{:02}", a / 3600, (a % 3600) / 60)
}

/// Every translatable string in the GUI, as a variant.
///
/// An enum rather than a string key so that [`t`]'s match is **exhaustive**: adding a key
/// without translating it does not fall back at runtime, it fails to compile. And because
/// each arm names both spellings on one line, no key can be half-translated either.
///
/// [`K::Dashboard`], [`K::Groups`], [`K::Apps`], [`K::Users`] and [`K::Denied`] are the nav
/// labels and page headings: descriptive prose *about* a section, not that
/// section's name. [`K::Can`] reads the same way and heads no section of the file at all:
/// the access check is not a place, it is a question, and it is asked on the two pages that
/// each already hold half of it. The name itself stays untranslated wherever it appears as itself,
/// namely `base`, `urls`, `access`, `login_url`, `api_keys`, `released`, `duration`,
/// `notes`, `bbk_`, every `@group` reference, and the raw key shown in muted monospace
/// beside a heading; that is because it is what an operator types into the file and into
/// `bb-auth-adm`, and translating it would invent a second name for a thing that has one.
#[derive(Clone, Copy)]
pub(crate) enum K {
    Dashboard,
    Groups,
    Apps,
    Scopes,
    /// The group page's members **section heading** (§13.36 §2 item 3, as the screenshot review
    /// of plan step 22 read it). Not `K::Members`: that is the Groups list's lowercase *column*
    /// word, and a heading borrowing it reads as a table label, in Italian by a capital alone.
    /// Title case like the `Scopes` heading above it, because every heading is the section's word.
    MembersHeading,
    Users,
    /// The users tab's People sub-page, and the word its section heading carries. The tab's
    /// own word is `K::Users`, and the roster's heading used to repeat it, so the heading said
    /// which tab it was under and not which list it headed (§13.36 §1).
    People,
    /// The Groups sub-tab's short word. Not `K::Groups` ("User groups"), for the bar's own
    /// reason (`K::ConfigTab` versus `K::Config`): the row has to fit a phone, and the
    /// section's `h2` spells the name out (§13.36 §1).
    GroupsTab,
    /// The name of the users tab's row of sub-tabs. The page carries four navigation landmarks
    /// with it, and the accessibility practice asks that more than one of a kind be named.
    UsersSections,
    Denied,
    Can,
    Back,
    None,
    Counts,
    KeyExpiry,
    ColOwner,
    ColExpiry,
    Expired,
    ExpiresSoon,
    NeverExpires,
    KeyInvalid,
    Expires,
    Warnings,
    NoWarnings,
    /// The kind word that opens a dashboard warning (§13.35). The warnings list mixes scopes,
    /// people and groups in one list, and an identifier such as `@delete-test` does not say on
    /// its own which of the three it is. Capitalised because it opens the list item; the words
    /// are the console's own singular for that object, as its add/save messages use them.
    KindScope,
    KindUser,
    KindGroup,
    WarnNoScope,
    WarnEnrolledAndDenied,
    ReferencedBy,
    ReferencedByNothing,
    ReachesNothing,
    NoSuchUser,
    UsersIntro,
    GroupsIntro,
    /// The group page's pill that asks the roster for the group's members (§13.36 §2). It
    /// names the page it lands on, because the members are already on this one: the pill asks
    /// to see them **as roster rows**, which is the one thing this page cannot show.
    GroupInRoster,
    /// The roster's chip naming the group its rows are filtered to (§13.36 §3). `{0}` is the
    /// group's name, spelled as the file spells it, `@` included.
    GroupFilter,
    /// The chip's name for what its `×` does: the whole filter, not one row.
    GroupFilterClear,
    AppsIntro,
    ScopesIntro,
    DeniedIntro,
    CanIntroUser,
    CanAnyEmail,
    CanIntroApp,
    CanNoIdentifier,
    Submit,
    Authorized,
    VerdictDenied,
    // --- the eleven decisions, in the order `Decision` declares them ---
    WhyAnonymousGrant,
    WhyGranted,
    WhyVetoed,
    WhyExcluded,
    WhyNoApplication,
    WhyNoScope,
    WhyUnauthenticated,
    WhyCredentialRefused,
    WhyNotEnrolled,
    WhyNotMember,
    WhyKeyOutOfScope,
    // --- the refusals only the audit ever shows, since no access check can reach them ---
    WhyTokenInvalid,
    WhyCrossSite,
    WhyKeyUnknown,
    WhyKeyExpired,
    WhyKeyOwnerDenied,
    WhyUnEnrolledGrant,
    WhyUnknownReason,
    // --- the audit ---
    Audit,
    AuditIntro,
    AuditOff,
    AuditOffHelp,
    AuditRefresh,
    AuditWindow,
    AuditAll,
    AuditOutcome,
    AuditAny,
    AuditAllowed,
    AuditRefused,
    AuditCredential,
    AuditDamaged,
    AuditTruncated,
    AuditDeduped,
    ColWhen,
    ColEvent,
    ColWho,
    ColClient,
    ColWhere,
    ColWhy,
    AuditZone,
    TzLocal,
    TzCustom,
    TzCustomHint,
    TzUnknown,
    TzLocalMissing,
    KindLoginGranted,
    KindLoginRefused,
    KindLoginEnded,
    KindAccessGranted,
    KindAccessRefused,
    CredSocial,
    CredLocal,
    CredKey,
    CredSession,
    CredAnonymous,
    AppSees,
    NoProxyTitle,
    NoProxyBody,
    NoIdentityTitle,
    NoIdentityBody,
    NotAdminTitle,
    NotAdminBody,
    NotAdminToAccount,
    NotFoundTitle,
    NotFoundBody,
    FileErrorTitle,
    FileErrorHint,
    SignOut,
    // --- the settings menu ---
    Settings,
    // The word that turns the bar's name into a control's name: "Ada, account menu"
    // (§13.28 §1).
    AccountMenu,
    // §13.34 §4: the fifth tab's word. `Config` stays the page's own title ("System settings"),
    // because the heading and the `<title>` say what the page is and a tab has to fit the strip.
    ConfigTab,
    // §13.34 §2: the ☰'s accessible name. The control is an icon, so this string is its name.
    NavMenu,
    // The self-service menu's last row (§13.30 §1). The words say what the press costs, because
    // the worker's deletion is the one action on this estate nobody can undo.
    AccountDelete,
    SettingLanguage,
    SettingTheme,
    LangAuto,
    Apply,
    ThemeLight,
    ThemeDark,
    ThemeSystem,
    // --- actions, buttons, form furniture ---
    Add,
    Edit,
    Remove,
    Rotate,
    Save,
    Create,
    Cancel,
    MoveUp,
    MoveDown,
    KeyScopeInherit,
    KeyScopesHelp,
    ScopeUrlsHelp,
    AnonymousWarn,
    AuthenticatedWarn,
    GroupMembersHelp,
    GroupNoRename,
    NewName,
    // --- the filter and pager every list carries ---
    Filter,
    /// The roster's box, and the only one that says what it searches: the reach (every email,
    /// the uuid, every key id) was never readable off a box that said "filter" (§13.36 §4).
    FilterPeople,
    /// The group page's member box (§13.36 §4, one list along). Its list filters a member's
    /// label and uuid and nothing else, so it cannot borrow `K::FilterPeople`, whose sentence
    /// promises a key id this list holds no key in: a box promising a search that answers
    /// nothing is the failure mode §4 exists to close.
    FilterMembers,
    FilterClear,
    PagePrev,
    PageNext,
    /// "rows 26–50 of 1234": the first row shown, the last, and how many matched. The one
    /// sentence that replaced the "page 2/5" fragment and the bare "matched/total" span
    /// (§13.36 §4). The en dash is a range, so it is data and not prose.
    PagerRows,
    /// The same with the list's whole length, while a filter is set (§13.36 §4).
    PagerRowsFiltered,
    NoMatch,
    // --- the words the application-centric file is made of ---
    Base,
    BaseHelp,
    LoginUrl,
    LoginUrlHelp,
    DeniedUrl,
    DeniedUrlHelp,
    AccessWord,
    AccessAnonymous,
    AccessAuthenticated,
    AccessRestricted,
    AccessHelp,
    Credentials,
    CredentialsHelp,
    CredLogin,
    CredApiKey,
    Members,
    MembersHelp,
    Excluded,
    ExcludedHelp,
    ExcludedNone,
    CredNoneNeeded,
    Uuid,
    Emails,
    /// The roster's groups column (§13.36 §3): the groups that name this person. Lowercase
    /// like the `emails` column beside it, because it names the file's `user_groups` section.
    ColGroups,
    AddEmail,
    ConfirmEmailRm,
    NoScopes,
    InNoScope,
    WarnShadowed,
    WarnNoMembers,
    /// A scope's or a group's member that resolves to no roster row: a dangling uuid, shown
    /// for what it is rather than silently hidden.
    UnknownMember,
    // --- what a destructive page warns about ---
    ConfirmUserRm,
    ConfirmKeyRm,
    ConfirmKeyRotate,
    ConfirmAppRm,
    ConfirmScopeRm,
    ConfirmGroupRm,
    ConfirmDenyRm,
    // --- the minted bearer ---
    BearerHeading,
    BearerOnce,
    /// The two halves of the click hint, with the word `Bearer` emitted between them as a
    /// `code` element. Split because a word the person has to type is markup, not prose: a
    /// backtick inside a translated sentence reaches the page as a backtick.
    BearerHintLead,
    BearerHintTail,
    CopyKey,
    CopyDone,
    CopyFailed,
    // --- refusals a form makes on its own ---
    ExcludedNotAnon,
    EmailRequired,
    NameRequired,
    KeyIdRequired,
    BadKeyWindow,
    AlreadyDenied,
    NoSuchKey,
    NoSuchApp,
    NoSuchScope,
    NoSuchGroup,
    NoSuchDenied,
    // --- whole-request refusals ---
    ConflictTitle,
    ConflictBody,
    ConflictRecover,
    ConflictBack,
    MintConflictTitle,
    MintConflictBody,
    RotateConflictTitle,
    RotateConflictBody,
    MintConflictLost,
    MintConflictRotate,
    CsrfTitle,
    CsrfBody,
    NotAllowedTitle,
    NotAllowedBody,
    // --- what a redirect says it did ---
    MsgUserAdded,
    MsgUserSaved,
    MsgUserRemoved,
    MsgKeySaved,
    MsgKeyRemoved,
    MsgAppAdded,
    MsgScopeAdded,
    MsgAppSaved,
    MsgScopeSaved,
    MsgAppRemoved,
    MsgScopeRemoved,
    MsgScopeMoved,
    MsgGroupAdded,
    MsgGroupSaved,
    MsgGroupRemoved,
    MsgDeniedAdded,
    MsgDeniedRemoved,
    MsgSettingsSaved,
    // --- the settings page ---
    // The word for that page, and for the panel's row to it (§13.28 §2, §8). It says "system"
    // because the page edits the deployment's settings, and the panel's own rows are a
    // person's preferences: two words for two places, since one row in a menu that holds both
    // is read as the menu's whole subject.
    Config,
    ConfigIntro,
    ConfigAccess,
    ConfigHandover,
    ConfigSignIn,
    ConfigAdminLook,
    ConfigAudit,
    ClientIpHeader,
    ClientIpHeaderHelp,
    RequestIdHeader,
    RequestIdHeaderHelp,
    AuditRotation,
    AuditRotationHelp,
    AuditRetention,
    AuditRetentionHelp,
    AuditOnDisk,
    LimitNone,
    UnitWeek,
    UnitWeeks,
    UnitMonth,
    UnitMonths,
    UnitYear,
    UnitYears,
    GroupsExpand,
    GroupsCollapse,
    ConfigHot,
    ProfileClaims,
    ProfileClaimsHelp,
    IdentityAttrs,
    IdentityAttrsHelp,
    SessionTtl,
    SessionTtlHelp,
    SessionTtlBad,
    UnverifiedSocial,
    UnverifiedSocialHelp,
    SocialWaysHelp,
    GlobalLoginUrl,
    GlobalLoginUrlHelp,
    GlobalDeniedUrl,
    GlobalDeniedUrlHelp,
    GlobalLandingUrl,
    GlobalLandingUrlHelp,
    OauthDomain,
    OauthDomainHelp,
    SocialCallback,
    SocialCallbackHelp,
    SignInWays,
    SignInEmail,
    ClientIdNeeded,
    AudienceNeeded,
    SocialWiringNeeded,
    ColShownAs,
    ColAudience,
    SocialProviders,
    SocialProvidersHelp,
    Issuer,
    IssuerHelp,
    IssuerNeeded,
    CookieDomain,
    CookieDomainHelp,
    AuthorizedHosts,
    AuthorizedHostsHelp,
    AuthorizedHostsNeeded,
    ConfirmTitle,
    ConfirmLede,
    ConfirmSafety,
    ConfirmSave,
    ColSetting,
    ColNow,
    ColAfter,
    RiskIssuer,
    RiskClientId,
    RiskLoginUrl,
    RiskCookieDomain,
    RiskAuthorizedHosts,
    Admins,
    AdminsHelp,
    AdminsKeepYourself,
    AdminsNeverEmpty,
    StylesheetUrl,
    StylesheetUrlHelp,
    LogoUrl,
    LogoUrlHelp,
    BrandName,
    BrandNameHelp,
    DefaultTheme,
    DefaultThemeHelp,
    DefaultThemeBad,
    // --- a settings-file refusal, in the reader's language (docs/ARCHITECTURE.md §13.31) ---
    //
    // One key per refusal the library answers with a code, so the page that refuses a save says
    // the same thing in Italian as it says in English. The `{0}` of each is the visible label of
    // the field it is marked on, which is why none of them spells a wire name: an operator reads
    // "Landing page", never `landing_url`. A typed value is quoted only where the refusal is
    // about one entry of a list (a claim, an attribute, a host) or about a header name, since
    // there the value is the thing to point at; a whole-field refusal quotes nothing, because the
    // field below already shows what was typed.
    //
    // The library's code list is the authority on how many there are: `settings_refusal` matches
    // on the variant with no wildcard arm, so a refusal added there stops this GUI compiling
    // until it is given a key here.
    SetRefFileOnly,
    SetRefClaimCharset,
    SetRefClaimEmptyPart,
    SetRefClaimConsumed,
    SetRefClaimHeaderReserved,
    SetRefClaimsCollide,
    SetRefAttrUnknown,
    SetRefAttrTwice,
    SetRefAttrNone,
    SetRefTtlBelowFloor,
    SetRefTtlAboveCeiling,
    SetRefAppClientId,
    SetRefUrlNotPrintable,
    SetRefUrlNotHttps,
    SetRefUrlEmptyHost,
    SetRefUrlUserinfo,
    SetRefUrlBackslash,
    SetRefUrlUserinfoOrBackslash,
    SetRefUrlQueryOrFragment,
    SetRefUrlQuote,
    SetRefUrlNotHttpsOrRooted,
    SetRefCallbackNotHttps,
    SetRefCookieDomainNotBare,
    SetRefCookieDomainSingleLabel,
    SetRefHostControlByte,
    SetRefHostNotBare,
    SetRefHostAtOrDotDot,
    SetRefHostsOutsideCookieDomain,
    SetRefLandingOffHosts,
    SetRefOauthDomainNotBare,
    SetRefHeaderNotAName,
    SetRefHeaderCredential,
    SetRefHeadersSame,
    SetRefLimitNotAmount,
    SetRefLimitZero,
    SetRefLimitTooMuch,
    SetRefAuditUnbounded,
    SetRefBrandControl,
    SetRefBrandTooLong,
    // The two the page raises itself, in the same register as the library's (`Admins:` then
    // what is needed), because the library cannot make them: it does not know who is signed
    // in. Their `Admins*` neighbours keep their own keys and words, since those read as a
    // shell message and as a bracketed help line, where a label in front would repeat the
    // label printed just above them (§13.31 §10).
    SetRefAdminsNone,
    SetRefAdminsSelf,
    Days,
    // --- the self-service page ---
    //
    // Deliberately few, because the page's contract is about which fact belongs in which
    // section: prose in one is a word a test about another could match by accident, and the
    // sections carry a heading, the names, and one short "none" line. The mint form's words are
    // the one place this page carries prose, and they are the shape of what it asks for and the
    // reason a submission was refused: the person reading them has no administrator in the room,
    // so each has to say what to write instead.
    AccountTitle,
    AccountIdLabel,
    AccountNoRowTitle,
    AccountNoRowBody,
    AccountReach,
    AccountReachSub,
    AccountReachNone,
    AccountGroups,
    AccountGroupsSub,
    AccountGroupsNone,
    AccountKeys,
    AccountKeysSub,
    AccountKeysNone,
    AccountProfile,
    AccountProfileSub,
    AccountProfileNone,
    AccountNotProvided,
    // The profile edit (§13.22) and its interface (§13.23). The words are the designer's, in one
    // table, and no logic reads any of them.
    AccountProfileEdit,
    AccountProfileEditSub,
    AccountProfileNotNative,
    AccountProfileEmailFixed,
    AccountProfileClearDeletes,
    AccountProfileDateHint,
    AccountProfileSendCode,
    AccountProfileNothingChanged,
    AccountProfileValueBad,
    AccountProfileCannotEdit,
    AccountProfileCodeTitle,
    AccountProfileCodeSent,
    AccountProfileCodeSentNoDest,
    AccountProfileCodeLasts,
    AccountProfileChanges,
    AccountProfileWas,
    AccountProfileRemoved,
    AccountProfileCodeLabel,
    AccountProfileSave,
    AccountProfileNoCode,
    AccountProfileSendNew,
    AccountProfileNotSavedTitle,
    AccountProfileNoAnswer,
    AccountProfileNoUser,
    AccountProfileTooMany,
    AccountProfileRefused,
    // The code step (§13.22, §13.23 §4): the three ways the code itself goes wrong, the page a
    // save lands on, and the one page that cannot say whether anything changed.
    AccountProfileWrongCode,
    AccountProfileExpired,
    AccountProfileNotYours,
    AccountProfileSavedTitle,
    AccountProfileSavedLead,
    AccountProfileSavedBody,
    AccountProfileUnsureTitle,
    AccountProfileNoAnswerUnsure,
    AccountProfileBadValue,
    // The twelve `oidc:profile` attributes in words (§13.23 §5). One key each, used as the form's
    // label, as the change summary's name and as the read-only panel's name, so the three can
    // never call one field by two names.
    AttrName,
    AttrGivenName,
    AttrFamilyName,
    AttrMiddleName,
    AttrNickname,
    AttrProfile,
    AttrPicture,
    AttrWebsite,
    AttrGender,
    AttrBirthdate,
    AttrZoneinfo,
    AttrLocale,
    AccountKeyAdd,
    AccountKeyCreate,
    AccountKeyIdHint,
    AccountKeyRotate,
    AccountKeyRemove,
    AccountKeyNotYours,
    // The mint form's refusals, one per fact (§13.17): the one that replaced
    // `AccountKeyBound` says which of the two fields is wrong, not both.
    AccountKeyIdBad,
    AccountKeyTooShort,
    AccountKeyFull,
    AccountKeyDup,
    AccountKeyUnknownScope,
    // The keys table and its `+ New key` row (§13.16). The two column words are the
    // table's headings **and** the mint form's field labels: a field and the column
    // that shows the same value must not answer that value's name from two entries.
    AccountKeyNew,
    AccountKeyFullRow,
    AccountKeyRotateWarn,
    AccountKeyRemoveWarn,
    KeyColName,
    KeyColExpires,
    KeyScopesAll,
    KeyScopesOnly,
    KeyScopeGone,
    KeyScopesWithoutOnly,
    KeyScopesChoose,
    // The five duration choices (§13.15), the custom box, and the three refusals
    // `duration_from_form` answers with.
    DurOneYear,
    DurSixMonths,
    DurThreeMonths,
    DurCustom,
    DurNever,
    DurDaysLabel,
    DurDaysHint,
    KeyDurationRequired,
    KeyDaysWithoutCustom,
    KeyDaysInvalid,
    AccountVetoTitle,
    AccountVetoBody,
    AccountAmbiguousTitle,
    AccountAmbiguousBody,
    AccountNoEmailTitle,
    AccountNoEmailBody,
    // The delete confirmation page (§13.30 §2), in its two variants. The words name what goes
    // and what is kept, because the one act this page asks for cannot be undone, and the design
    // names no euphemism for it: the sign-in accounts are "queued", never "deleted", since the
    // press does not delete them (§13.29 W3). The audit sentence is the deployment's own number,
    // read from the policy, so the page cannot promise a retention an operator did not set.
    AccountDeleteTitle,
    AccountDeleteLead,
    AccountDeleteGoes,
    AccountDeleteRecord,
    AccountDeleteKeysLead,
    AccountDeleteGroupsLead,
    AccountDeleteSignInOne,
    AccountDeleteSignInMany,
    AccountDeleteLater,
    AccountDeleteAuditKept,
    AccountDeleteAuditTail,
    AccountDeleteAuditSize,
    AccountDeleteTypeLabel,
    AccountDeleteTypeHintMany,
    AccountDeleteConfirm,
    // The pages a deletion request answers with (§13.30 §4). The words are here, never in a
    // handler: the handler picks a key, and the key's words are the reader's language's.
    AccountDeleteQueuedTitle,
    AccountDeleteNowGone,
    AccountDeleteQueued,
    AccountDeletedClose,
    AccountDeletePartialTitle,
    AccountDeleteNotQueued,
    AccountDeleteUnsureTitle,
    AccountDeleteMaybeQueued,
    AccountDeleteSome,
    AccountDeleteUnconfirmedLead,
    AccountDeleteRetryOneAddress,
    AccountDeleteNotDoneTitle,
    AccountDeleteProtected,
    AccountDeleteNoCheck,
    AccountDeleteRetry,
    AccountDeleteStartAgain,
    AccountDeleteWriteFailed,
    AccountDeleteChangedTitle,
    AccountDeleteChanged,
    AccountDeleteTypedWrong,
    AccountDeleteTooMany,
}

/// Pick one of a key's two spellings.
pub(crate) fn m(lang: Lang, en: &'static str, it: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::It => it,
    }
}
