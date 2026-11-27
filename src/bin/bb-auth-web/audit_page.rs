use crate::*;

// ---------------------------------------------------------------------------
// The audit page
// ---------------------------------------------------------------------------
//
// The one tab that reads neither file and writes nothing. Everything else here is a view of
// what an operator wrote; this is a view of what the gate *did* with it, which is the only
// way to find out that a rule written months ago is refusing somebody today.

/// The periods the page offers, as `(query value, seconds back from now)`. "Everything" is the
/// absence of a period and so is not one of them.
const AUDIT_PERIODS: [(&str, u64); 4] = [
    ("1h", 3_600),
    ("24h", 86_400),
    ("7d", 7 * 86_400),
    ("30d", 30 * 86_400),
];

/// The period a page with no `aw=` shows.
///
/// A day and not everything, because the read stops at the far edge of the period: the default
/// view parses the last day of a file that may hold a year, which is what keeps this page cheap
/// on the hardware it runs on. It is also the answer to the question somebody opening this tab
/// usually has, which is what happened just now.
const AUDIT_DEFAULT_PERIOD: &str = "24h";

/// How many events one read may return before it says there are more.
///
/// Far more than a page shows, because the filters run *after* the read: a text filter over a
/// month has to see the month. Twenty pages of fifty rows either way.
const AUDIT_READ_CAP: usize = 5_000;

/// The credentials the filter offers, in the order they appear, as `(tag, label)`. The tags are
/// [`AuditCredential::tag`]'s, so a row and a filter can never disagree about what a key is.
fn audit_credentials(v: &View) -> [(&'static str, &'static str); 5] {
    [
        ("social", v.t(K::CredSocial)),
        ("local", v.t(K::CredLocal)),
        ("key", v.t(K::CredKey)),
        ("session", v.t(K::CredSession)),
        ("anonymous", v.t(K::CredAnonymous)),
    ]
}

/// One event's credential, in words: the kind, and what names this one instance of it.
fn audit_cred_markup(v: &View, cred: &AuditCredential) -> Markup {
    html! {
        @match cred {
            AuditCredential::Social { provider } => {
                (v.t(K::CredSocial)) " " span class="muted mono" { (provider) }
            }
            AuditCredential::Key { id } if !id.is_empty() => {
                (v.t(K::CredKey)) " " span class="muted mono" { (id) }
            }
            other => (v.t(match other {
                AuditCredential::Local => K::CredLocal,
                AuditCredential::Session => K::CredSession,
                AuditCredential::Key { .. } => K::CredKey,
                _ => K::CredAnonymous,
            })),
        }
    }
}

/// The sentence a refusal code stands for, in the reader's language.
///
/// The nine that a [`Decision`] can produce are the **same phrases the access check prints**,
/// deliberately: a page that explained `not_member` one way here and another way there would
/// be two explanations of one rule. A code this binary has never heard of is shown as itself
/// with a note, because an audit written by a newer gate is still worth reading.
fn audit_reason(v: &View, code: &str) -> Markup {
    let key = match code {
        "vetoed" => Some(K::WhyVetoed),
        "excluded" => Some(K::WhyExcluded),
        "no_application" => Some(K::WhyNoApplication),
        "no_scope" => Some(K::WhyNoScope),
        "unauthenticated" => Some(K::WhyUnauthenticated),
        "credential_refused" => Some(K::WhyCredentialRefused),
        "not_enrolled" => Some(K::WhyNotEnrolled),
        "not_member" => Some(K::WhyNotMember),
        "key_out_of_scope" => Some(K::WhyKeyOutOfScope),
        "token_invalid" => Some(K::WhyTokenInvalid),
        "cross_site" => Some(K::WhyCrossSite),
        "key_unknown" => Some(K::WhyKeyUnknown),
        "key_expired" => Some(K::WhyKeyExpired),
        "key_owner_denied" => Some(K::WhyKeyOwnerDenied),
        "un_enrolled" => Some(K::WhyUnEnrolledGrant),
        _ => None,
    };
    html! {
        @match key {
            Some(k) => (v.t(k)),
            None => {
                code { (code) } " " span class="muted" { (v.t(K::WhyUnknownReason)) }
            }
        }
    }
}

/// A zone the audit can be read in: what the page calls it, and the rules that turn a Unix time
/// into that zone's wall clock.
pub(crate) struct Zone {
    /// What the column heading and the list box say: `UTC`, a name out of the host's
    /// database, or an offset.
    pub(crate) label: String,
    pub(crate) rules: tz::TimeZone,
    /// Whether each row says which of the zone's clocks it was read on (`CET`, `CEST`). A zone
    /// that changes its clock needs it, or the hour either side of a change reads the same
    /// twice; a fixed offset does not, and the heading already says which one it is.
    pub(crate) per_row: bool,
}

/// UTC as a [`Zone`]: what the file stores, and what the page falls back to when the zone it
/// was asked for cannot be had.
pub(crate) fn utc_zone() -> Zone {
    Zone {
        label: "UTC".to_string(),
        rules: tz::TimeZone::utc(),
        per_row: false,
    }
}

/// Why the zone a preference names could not be had, which the page says above the table
/// rather than quietly showing UTC under a heading somebody would take at its word.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ZoneMissing {
    /// The host's own zone is not readable, which is what a workstation without one looks like.
    Local,
    /// No zone of this name in the host's database.
    Custom(String),
}

/// The zone a preference names, read out of the host's database on every request.
///
/// On every request, like everything else this program shows: a zone file is two or three
/// kilobytes, a host whose clock is moved by `timedatectl` is read correctly on the next page
/// rather than after a restart, and there is no cache to be the stale half of anything.
pub(crate) fn resolve_zone(pref: &TzPref) -> Result<Zone, ZoneMissing> {
    let read = |path: &str| {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| tz::TimeZone::from_tz_data(&bytes).ok())
    };
    match pref {
        TzPref::Utc => Ok(utc_zone()),
        TzPref::Local => Ok(Zone {
            label: local_zone_name().unwrap_or_else(|| "localtime".to_string()),
            rules: read(LOCALTIME_FILE).ok_or(ZoneMissing::Local)?,
            per_row: true,
        }),
        TzPref::Custom(zone) => match parse_offset(zone) {
            Some(secs) => Ok(Zone {
                label: format_offset(secs),
                rules: tz::TimeZone::fixed(secs).map_err(|_| ZoneMissing::Custom(zone.clone()))?,
                per_row: false,
            }),
            // `custom_zone` held the name to a charset with no `.` in it before it could
            // become a preference, which is what makes this join unable to leave the directory.
            None => Ok(Zone {
                label: zone.clone(),
                rules: read(&format!("{ZONEINFO_DIR}/{zone}"))
                    .ok_or_else(|| ZoneMissing::Custom(zone.clone()))?,
                per_row: true,
            }),
        },
    }
}

/// The host's own zone by name, for the list box and the heading: where [`LOCALTIME_FILE`]
/// points, which is how systemd records it. `None` for a copy rather than a link, and the
/// name is held to [`custom_zone`]'s rule because a link can point anywhere.
fn local_zone_name() -> Option<String> {
    let target = std::fs::read_link(LOCALTIME_FILE).ok()?;
    let (_, name) = target.to_str()?.rsplit_once("zoneinfo/")?;
    custom_zone(name).filter(|n| parse_offset(n).is_none())
}

/// One Unix time on this zone's wall clock, and the name of the clock when the zone has more
/// than one. `format_datetime` stays the one formatter: this only moves the seconds first.
pub(crate) fn zoned(ts: u64, zone: &Zone) -> (String, Option<String>) {
    match zone.rules.find_local_time_type(ts as i64) {
        Ok(t) => (
            format_datetime(ts.saturating_add_signed(i64::from(t.ut_offset()))),
            zone.per_row
                .then(|| t.time_zone_designation().to_string())
                .filter(|d| !d.is_empty()),
        ),
        // A time outside what the rules describe, which a zone file with a rule for the
        // future never has. The one honest rendering left is the one that is stored.
        Err(_) => (format_datetime(ts), Some("UTC".to_string())),
    }
}

/// Where this row's request came from: the address, the user agent, and nginx's id for it.
///
/// The address first and never broken, because it is what a reader compares down the column
/// and half an address is no address. The user agent under it, in a hint's small type and at
/// most two lines, because it is the client's description of itself and must not read as
/// evidence. The id last, on one line cut short by the stylesheet: it exists to be copied into
/// a search of nginx's log, and a cut on screen is not a cut in the text, so a double click
/// still copies all of it (and the title shows it). Its label is the file's own `rid`,
/// untranslated like every other word the file is made of.
fn audit_origin(e: &AuditEvent) -> Markup {
    html! {
        @if let Some(ip) = &e.ip {
            div class="mono ip" { (ip) }
        }
        @if let Some(ua) = &e.ua {
            div class="hint ua" title=(ua) { (ua) }
        }
        @if let Some(rid) = &e.rid {
            div class="hint mono clip" title=(rid) { "rid " (rid) }
        }
        @if e.ip.is_none() && e.ua.is_none() && e.rid.is_none() {
            span class="muted" { "—" }
        }
    }
}

/// `/audit` — what the gate has answered, newest first, filtered and paged entirely in the
/// query string like every other list here.
///
/// It reads the file **on every request**, which is what makes Refresh a plain link to this
/// same URL rather than a control that has to do anything: there is no cache to bust, and a
/// page that reloaded itself would be a page that needs a script.
pub(crate) fn page_audit(v: &View, doc: &AccessFile) -> Markup {
    if v.cfg.audit_path.is_empty() {
        return html! {
            h1 { (v.t(K::Audit)) }
            p class="lede" { (v.t(K::AuditIntro)) }
            div class="panel warn" {
                p { strong { (v.t(K::AuditOff)) } }
                p class="muted" { (v.t(K::AuditOffHelp)) }
            }
        };
    }
    let period = query_param(v.query, "aw").unwrap_or_else(|| AUDIT_DEFAULT_PERIOD.to_string());
    let since = AUDIT_PERIODS
        .iter()
        .find(|(name, _)| *name == period)
        .map(|(_, secs)| now().saturating_sub(*secs));
    // A retention in time is a floor on every period, "everything" included: the gate prunes
    // hourly, and in the hour between, a page that showed what the settings say is gone would
    // be showing somebody's address the operator decided nobody keeps.
    let since = match (since, v.audit.keep_since(now())) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let read = read_audit(
        std::path::Path::new(&v.cfg.audit_path),
        since,
        AUDIT_READ_CAP,
    );
    // A file that will not open is worth saying plainly and in the operator's own terms: the
    // one that actually happens is a mode the gate wrote and this service cannot read, and
    // "permission denied" plus the path is the whole diagnosis.
    let read = match read {
        Ok(p) => p,
        Err(e) => {
            return html! {
                h1 { (v.t(K::Audit)) }
                div class="panel bad" {
                    p { (v.t(K::FileErrorTitle)) }
                    p class="mono" { (v.cfg.audit_path) ": " (e) }
                    p class="muted" { (v.t(K::FileErrorHint)) }
                }
            }
        }
    };

    let cred = query_param(v.query, "ac").unwrap_or_default();
    let outcome = query_param(v.query, "ao").unwrap_or_default();
    let l = Listing::read("a", v.query);
    let rows: Vec<&AuditEvent> = read
        .events
        .iter()
        .filter(|e| cred.is_empty() || e.cred.tag() == cred)
        .filter(|e| match outcome.as_str() {
            "ok" => e.kind.granted(),
            "no" => !e.kind.granted(),
            _ => true,
        })
        // The row's own fields, plus what the roster currently calls the uuid on it: a key
        // event names a row and not an address, and searching for the address you can see has
        // to find it.
        .filter(|e| {
            let who = e
                .uuid
                .as_deref()
                .map(|u| label_of(doc, u))
                .unwrap_or_default();
            l.keeps(&format!("{} {who}", e.haystack()))
        })
        .collect();
    let (start, end, _, _) = l.window(rows.len());
    // The clock the page is read in, and why it is not the one asked for when that could not
    // be had: a heading saying `Europe/Rome` over UTC times would be a page lying about the one
    // thing a reader of an audit compares across rows.
    let (zone, missing) = match resolve_zone(&v.tz) {
        Ok(z) => (z, None),
        Err(m) => (utc_zone(), Some(m)),
    };
    let local = local_zone_name();
    let custom = match &v.tz {
        TzPref::Custom(z) => z.as_str(),
        _ => "",
    };
    let selects = html! {
        select name="aw" aria-label=(v.t(K::AuditWindow)) {
            @for (name, _) in AUDIT_PERIODS {
                option value=(name) selected[name == period] { (name) }
            }
            option value="all" selected[!AUDIT_PERIODS.iter().any(|(n, _)| *n == period)] {
                (v.t(K::AuditAll))
            }
        }
        select name="ac" aria-label=(v.t(K::AuditCredential)) {
            option value="" selected[cred.is_empty()] { (v.t(K::AuditCredential)) ": " (v.t(K::AuditAny)) }
            @for (tag, label) in audit_credentials(v) {
                option value=(tag) selected[tag == cred] { (label) }
            }
        }
        select name="ao" aria-label=(v.t(K::AuditOutcome)) {
            option value="" selected[outcome.is_empty()] { (v.t(K::AuditOutcome)) ": " (v.t(K::AuditAny)) }
            option value="ok" selected[outcome == "ok"] { (v.t(K::AuditAllowed)) }
            option value="no" selected[outcome == "no"] { (v.t(K::AuditRefused)) }
        }
        // The clock, and for a zone of the operator's own the box to type it in. In the same
        // form as the filters, so one Apply sets it with them, and remembered as a cookie
        // rather than carried in the URL, because it is a preference and not a filter: the
        // same zone is wanted tomorrow, on a link that says nothing about it. The box is shown
        // only while `custom` is chosen, which the stylesheet decides, since no script may.
        span class="tzpick" {
            select name=(TZ_COOKIE) aria-label=(v.t(K::AuditZone)) {
                option value="utc" selected[v.tz.choice() == "utc"] { "UTC" }
                option value="local" selected[v.tz.choice() == "local"] {
                    (v.t(K::TzLocal))
                    @if let Some(name) = &local { " (" (name) ")" }
                }
                option value="custom" selected[v.tz.choice() == "custom"] { (v.t(K::TzCustom)) }
            }
            input type="text" class="tzc" name=(TZ_CUSTOM_PARAM) value=(custom)
                  placeholder=(v.t(K::TzCustomHint)) aria-label=(v.t(K::TzCustom));
        }
    };
    html! {
        h1 { (v.t(K::Audit)) }
        p class="lede" { (v.t(K::AuditIntro)) }
        p class="primary" {
            // Refresh is this same URL: every filter is in it, so re-reading the file with the
            // view intact is a link and nothing more.
            a class="pill" href=(listing_href(v, &l, &audit_kept(&l, &period, &cred, &outcome))) {
                "↻ " (v.t(K::AuditRefresh))
            }
        }
        (list_controls_with(
            v,
            &l,
            rows.len(),
            read.events.len(),
            &["aw", "ac", "ao", TZ_COOKIE, TZ_CUSTOM_PARAM],
            selects,
            K::Filter,
        ))
        @match &missing {
            Some(ZoneMissing::Local) => div class="msg warn" { (v.t(K::TzLocalMissing)) },
            Some(ZoneMissing::Custom(name)) => div class="msg warn" {
                code { (name) } " " (v.t(K::TzUnknown))
            },
            None => {}
        }
        @if read.more {
            p class="muted" { (v.t(K::AuditTruncated)) }
        }
        @if read.damaged > 0 {
            p class="muted" { (read.damaged) " " (v.t(K::AuditDamaged)) }
        }
        (list_rows(v, read.events.len(), rows.len(), html! {
            div class="panel" {
                table {
                    // Six columns, and the credential is under the event rather than in a
                    // seventh: a table this wide is already what squeezes the sentence in the
                    // last column, and "signed in, through Google" is one fact read together.
                    thead { tr {
                        th { (v.t(K::ColWhen)) " (" (zone.label) ")" }
                        th { (v.t(K::ColEvent)) }
                        th { (v.t(K::ColWho)) }
                        th class="client" { (v.t(K::ColClient)) }
                        th { (v.t(K::ColWhere)) }
                        th class="why" { (v.t(K::ColWhy)) }
                    } }
                    tbody {
                        @for e in &rows[start..end] {
                            // The outcome is the tag in the event column and nowhere else: a
                            // whole row in the error colour is a page of red on the deployment
                            // that has most to read here, which is the one being probed.
                            @let (wall, clock) = zoned(e.ts, &zone);
                            tr {
                                td class="mono when" data-label=(v.t(K::ColWhen)) {
                                    (wall)
                                    @if let Some(c) = clock { " " span class="muted" { (c) } }
                                }
                                td data-label=(v.t(K::ColEvent)) {
                                    (audit_kind(v, e.kind))
                                    // Nothing under a refusal that came before any credential
                                    // was read: the reason column already says why, and "None"
                                    // under the tag would read as a second answer to it.
                                    @if !matches!(e.cred, AuditCredential::Anonymous) {
                                        div class="hint" { (audit_cred_markup(v, &e.cred)) }
                                    }
                                }
                                td data-label=(v.t(K::ColWho)) { (audit_who(v, doc, e)) }
                                td class="client" data-label=(v.t(K::ColClient)) {
                                    (audit_origin(e))
                                }
                                td class="where" data-label=(v.t(K::ColWhere)) {
                                    (audit_where(e))
                                }
                                td class="why" data-label=(v.t(K::ColWhy)) {
                                    @match &e.reason {
                                        Some(r) => (audit_reason(v, r)),
                                        None => span class="muted" { "—" },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }))
        p class="muted" { (v.t(K::AuditDeduped)) }
        // How far back this page can reach at all, which is a question a reader of an audit
        // always has and the page is the only one who can answer without a shell.
        p class="muted" {
            (v.t(K::AuditRotation)) ": " (limit_text(v.lang, &v.audit.rotation))
            " · " (v.t(K::AuditRetention)) ": "
            (match v.audit.retention {
                Some(r) => limit_text(v.lang, &r),
                None => v.t(K::LimitNone).to_string(),
            })
            " · " (v.t(K::AuditOnDisk)) ": " (size_text(v.audit.max_bytes()))
        }
    }
}

/// A number of bytes the way the settings write them: whole GiB or MiB where it is one, a
/// tenth of a MiB where half a retention is not.
pub(crate) fn size_text(bytes: u64) -> String {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    if bytes >= GIB && bytes.is_multiple_of(GIB) {
        format!("{} GiB", bytes / GIB)
    } else if bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    }
}

/// This page's own parameters, for a link that must keep the whole view: [`listing_href`]
/// replaces only the listing's two, and these three are not its business.
fn audit_kept(l: &Listing, period: &str, cred: &str, outcome: &str) -> Vec<(String, String)> {
    let mut set = Vec::new();
    if !l.q.is_empty() {
        set.push((l.q_name(), l.q.clone()));
    }
    for (name, val) in [("aw", period), ("ac", cred), ("ao", outcome)] {
        if !val.is_empty() {
            set.push((name.to_string(), val.to_string()));
        }
    }
    set
}

/// What kind of thing this row is, in one phrase.
fn audit_kind(v: &View, kind: AuditKind) -> Markup {
    let (key, class) = match kind {
        AuditKind::LoginGranted => (K::KindLoginGranted, "tag ok"),
        AuditKind::LoginRefused => (K::KindLoginRefused, "tag bad"),
        AuditKind::LoginEnded => (K::KindLoginEnded, "tag"),
        AuditKind::AccessGranted => (K::KindAccessGranted, "tag ok"),
        AuditKind::AccessRefused => (K::KindAccessRefused, "tag bad"),
    };
    html! { span class=(class) { (v.t(key)) } }
}

/// Who this row is about: a link to their page when the roster still has them, the identifier
/// as recorded when it does not.
///
/// The two are not interchangeable and the difference is the point: an audit is history, and
/// resolving a uuid through the file as it is **now** is how a reader finds out that the person
/// refused last week is the person whose row was edited yesterday. A row that has been deleted
/// since keeps its uuid and simply stops being a link.
fn audit_who(v: &View, doc: &AccessFile, e: &AuditEvent) -> Markup {
    html! {
        @match (&e.uuid, &e.subject) {
            (Some(uuid), _) if user_pos(doc, uuid).is_some() => {
                a href=(v.href(&Route::User(uuid.clone()))) { (label_of(doc, uuid)) }
            }
            (_, Some(s)) => code { (s) }
            (Some(uuid), None) => code class="muted" { (uuid) }
            (None, None) => span class="muted" { "—" },
        }
        // The Cognito account under the name, where a token was validated: the line that tells
        // this month's owner of an address from last month's, once somebody has deleted an
        // account and registered the address again. Labelled with the claim's own name, and on
        // one line, since the first group of a UUID is what an eye compares.
        @if let Some(sub) = &e.sub {
            div class="hint mono clip" title=(sub) { "sub " (sub) }
        }
    }
}

/// Where this row happened: the scope that answered, and the URL that was being reached for.
fn audit_where(e: &AuditEvent) -> Markup {
    html! {
        @if let (Some(app), Some(scope)) = (&e.app, &e.scope) {
            code { (app) @if !scope.is_empty() { "/" (scope) } }
        }
        @if let Some(url) = &e.url {
            div class="muted mono" { (url) }
        }
        @if e.app.is_none() && e.url.is_none() {
            span class="muted" { "—" }
        }
    }
}
