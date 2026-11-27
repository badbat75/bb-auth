use crate::*;

// ---------------------------------------------------------------------------
// The audit file
// ---------------------------------------------------------------------------
//
// The third file more than one program has an opinion about, and it is here on the same
// membership rule as the other two: the gate appends to it, `bb-auth-web` reads it back, and
// a second answer to "what is one line of this" would be a reader showing something the
// writer did not mean. What is new is the direction. The access file and the settings file
// are written by the editors and read by the gate; this one goes the other way, and it is the
// only thing in this system that does.
//
// It is NOT the journal, and the two are kept apart on purpose. The journal is prose, for an
// operator, with a volume knob; this is a record with a schema, for a program, with a
// retention. An event has exactly one of those homes at a time (see `AuditEvent`), because an
// event written to both is one an operator has to reconcile by eye, and reconciling by eye is
// what a schema is for.

/// The audit record's schema version, carried on every line as `v`.
///
/// The schema is **additive**: a new field is optional and an older reader ignores it, so
/// this is bumped only when an existing field changes *meaning*, never when one is added.
/// That is the opposite conclusion from the session cookie's `COOKIE_VERSION`, and for the
/// opposite reason: a cookie format change logs everybody out, while nobody is holding a line
/// of this file, so there is nothing to pay for tolerance here.
pub const AUDIT_SCHEMA: u32 = 1;

/// Where the audit lives when nothing says otherwise, on both sides.
///
/// A constant rather than two env vars that have to agree, for the reason this whole library
/// exists: the gate writes the file and the GUI reads it, and a path written twice drifts with
/// nothing to catch it. It is under `/var/log` and not beside the access file because the
/// gate's own prefix is `ReadOnlyPaths` and must stay that way: a gate that could write
/// `var/lib` could rewrite the access list it enforces, which is a much larger hole than an
/// audit is worth. `LogsDirectory=bb-auth` in the unit is what creates it.
pub const DEFAULT_AUDIT_FILE: &str = "/var/log/bb-auth/audit.jsonl";

/// The rotation an audit gets when `audit.rotation` says nothing: the live file moves onto
/// `.1` at this size, so the pair is bounded by twice it and the disk cannot be filled by
/// whoever is being refused.
///
/// A size and not a period, because the thing that must be bounded is *bytes*: a flood of
/// refusals is exactly the case an audit is for and exactly the case that would otherwise fill
/// a Raspberry Pi's card. An event is about 200 bytes without the client fields and about 450
/// with them (a browser's user agent is most of the difference), so this is ten to twenty
/// thousand events per file: years at this deployment's rate, hours under a flood. The flood
/// is visible in what is kept either way. See [`AuditPolicy`] for what an operator can say
/// instead, and the one thing they cannot.
pub const AUDIT_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// A unit an audit limit is written in: the three of time and the two of space an operator
/// thinks about a log in.
///
/// Nothing finer than a week or a mebibyte, on purpose: a limit that small would rotate or
/// prune on nearly every event, and an audit that is mostly rewrites is one nobody can trust
/// to still hold last week.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditUnit {
    Weeks,
    Months,
    Years,
    MiB,
    GiB,
}

impl AuditUnit {
    /// Every unit, in the order a list box offers them: time first, then space.
    pub const ALL: [AuditUnit; 5] = [
        AuditUnit::Weeks,
        AuditUnit::Months,
        AuditUnit::Years,
        AuditUnit::MiB,
        AuditUnit::GiB,
    ];

    /// The file's own word for it, plural, which is also what a form posts.
    pub fn code(self) -> &'static str {
        match self {
            AuditUnit::Weeks => "weeks",
            AuditUnit::Months => "months",
            AuditUnit::Years => "years",
            AuditUnit::MiB => "MiB",
            AuditUnit::GiB => "GiB",
        }
    }

    /// The file's word for exactly one of it.
    fn singular(self) -> &'static str {
        match self {
            AuditUnit::Weeks => "week",
            AuditUnit::Months => "month",
            AuditUnit::Years => "year",
            AuditUnit::MiB => "MiB",
            AuditUnit::GiB => "GiB",
        }
    }

    /// Whether this is a unit of time rather than of space.
    pub fn is_time(self) -> bool {
        matches!(
            self,
            AuditUnit::Weeks | AuditUnit::Months | AuditUnit::Years
        )
    }

    /// A unit as written, singular or plural, in any case.
    ///
    /// `MB` and `GB` are refused rather than read as their binary cousins: they are a
    /// different number, and a setting that silently meant 5% less than it said is the kind of
    /// thing nobody notices until it matters.
    pub fn parse(s: &str) -> Option<AuditUnit> {
        match s.trim().to_ascii_lowercase().as_str() {
            "week" | "weeks" => Some(AuditUnit::Weeks),
            "month" | "months" => Some(AuditUnit::Months),
            "year" | "years" => Some(AuditUnit::Years),
            "mib" => Some(AuditUnit::MiB),
            "gib" => Some(AuditUnit::GiB),
            _ => None,
        }
    }

    /// One of this unit, in seconds or in bytes.
    ///
    /// A month and a year are the Gregorian averages (30.436875 and 365.2425 days) and not
    /// calendar arithmetic: a retention of "6 months" is a length of time, and a limit that
    /// meant 181 days in one half of the year and 184 in the other would be a limit nobody
    /// could state.
    fn scale(self) -> u64 {
        match self {
            AuditUnit::Weeks => 7 * 86_400,
            AuditUnit::Months => 2_629_746,
            AuditUnit::Years => 31_556_952,
            AuditUnit::MiB => 1 << 20,
            AuditUnit::GiB => 1 << 30,
        }
    }

    /// The largest amount of it that is a setting and not a typo: a century, or a tebibyte.
    ///
    /// The admin GUI reads it to name the ceiling in a refusal, so the page states the same
    /// limit the parser applied.
    pub fn max_amount(self) -> u64 {
        match self {
            AuditUnit::Weeks => 5_200,
            AuditUnit::Months => 1_200,
            AuditUnit::Years => 100,
            AuditUnit::MiB => 1 << 20,
            AuditUnit::GiB => 1 << 10,
        }
    }
}

/// A limit on the audit, as an amount of time or of space: `4 MiB`, `6 months`.
///
/// It keeps the unit it was written in rather than being reduced to seconds or bytes, because
/// it is shown back to whoever wrote it, and "26 weeks" coming back as "0.4986 years" would be
/// a page arguing with its own operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditLimit {
    pub amount: u64,
    pub unit: AuditUnit,
}

impl AuditLimit {
    pub const fn new(amount: u64, unit: AuditUnit) -> AuditLimit {
        AuditLimit { amount, unit }
    }

    /// Parse `<amount> <unit>`, the space optional: `4 MiB`, `4MiB`, `1 year`, `26 weeks`.
    /// The amount is a whole number, at least one, and at most [`AuditUnit`]'s ceiling.
    pub fn parse(raw: &str) -> Result<AuditLimit, String> {
        // The key is the setting a refusal names, and a limit refusal's sentence names no key at
        // all (its caller prefixes its own, the CLI's flag or the settings function's), so every
        // caller of this prints the bytes it always printed (§13.31 §3).
        audit_limit_core(raw, SettingKey::AuditRotation).map_err(|r| r.sentence())
    }

    /// How the file writes it: `4 MiB`, `1 year`, `6 months`. What [`AuditLimit::parse`]
    /// reads back as the same limit.
    pub fn spelled(&self) -> String {
        let word = if self.amount == 1 {
            self.unit.singular()
        } else {
            self.unit.code()
        };
        format!("{} {word}", self.amount)
    }

    /// The limit in seconds, when it is one of time.
    pub fn seconds(&self) -> Option<u64> {
        self.unit
            .is_time()
            .then(|| self.amount.saturating_mul(self.unit.scale()))
    }

    /// The limit in bytes, when it is one of space.
    pub fn bytes(&self) -> Option<u64> {
        (!self.unit.is_time()).then(|| self.amount.saturating_mul(self.unit.scale()))
    }
}

/// [`AuditLimit::parse`]'s checks, answering the typed refusal (§13.31 §3). `key` is the setting
/// the caller is compiling, which the refusal carries so the page can mark the right box; the
/// quoted `raw` is the value **trimmed**, which is what today's sentence printed.
fn audit_limit_core(raw: &str, key: SettingKey) -> Result<AuditLimit, SettingsRefusal> {
    let s = raw.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, unit) = s.split_at(split);
    let refuse = || {
        Err(SettingsRefusal::AuditLimitNotAmount {
            key,
            raw: s.to_string(),
        })
    };
    let Some(unit) = AuditUnit::parse(unit) else {
        return refuse();
    };
    let Ok(amount) = digits.parse::<u64>() else {
        return refuse();
    };
    if amount == 0 {
        return Err(SettingsRefusal::AuditLimitZero {
            key,
            raw: s.to_string(),
        });
    }
    if amount > unit.max_amount() {
        return Err(SettingsRefusal::AuditLimitTooMuch {
            key,
            raw: s.to_string(),
            unit,
        });
    }
    Ok(AuditLimit { amount, unit })
}

/// When the live audit file rotates and how much of the audit is kept: `audit.rotation` and
/// `audit.retention`, compiled, and the arithmetic between them in one place.
///
/// **There are only ever two files**, the live one and the one it last rotated onto (`.1`):
/// a rotation replaces the previous `.1`, so what a rotation keeps is one file's worth. A
/// retention then says how much of that pair may stay at most. In time: no event older than it
/// is kept, whatever file it is in. In space: the pair together never exceeds it, which is
/// done by rotating the live file at half of it at the latest, so it needs no rewriting at all.
///
/// **At least one of the two is a size**, and [`AuditPolicy::new`] refuses the combination
/// that is not. A time bounds how old the audit gets and says nothing about how big: a flood
/// of refusals inside one rotation period would grow the live file without limit, and a flood
/// is the one case an audit exists for. With a size anywhere, [`AuditPolicy::max_bytes`] is
/// the most the audit can ever take on disk, which is what keeps it bounded by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditPolicy {
    pub rotation: AuditLimit,
    pub retention: Option<AuditLimit>,
}

impl Default for AuditPolicy {
    /// Four mebibytes and no retention: what the audit did before either was a setting.
    fn default() -> Self {
        AuditPolicy {
            rotation: AuditLimit::new(AUDIT_MAX_BYTES >> 20, AuditUnit::MiB),
            retention: None,
        }
    }
}

impl AuditPolicy {
    /// A policy, or the sentence saying why it bounds no bytes.
    pub fn new(rotation: AuditLimit, retention: Option<AuditLimit>) -> Result<AuditPolicy, String> {
        audit_policy_core(rotation, retention).map_err(|r| r.sentence())
    }

    /// The size the live file rotates at: the rotation's own, or half a retention in space,
    /// whichever is smaller, so that the live file and the one before it together never exceed
    /// that retention. Always an answer: a policy [`AuditPolicy::new`] refused would fall back
    /// to [`AUDIT_MAX_BYTES`] here rather than to no bound.
    pub fn rotate_at_bytes(&self) -> u64 {
        let half = self.retention.and_then(|r| r.bytes()).map(|b| b / 2);
        match (self.rotation.bytes(), half) {
            (Some(r), Some(h)) => r.min(h),
            (Some(r), None) => r,
            (None, Some(h)) => h,
            (None, None) => AUDIT_MAX_BYTES,
        }
    }

    /// The age, in seconds, the live file's oldest event may reach before the file rotates.
    pub fn rotate_at_age(&self) -> Option<u64> {
        self.rotation.seconds()
    }

    /// The oldest timestamp an event may carry at `now` and still be kept, for a retention in
    /// time.
    pub fn keep_since(&self, now: u64) -> Option<u64> {
        self.retention
            .and_then(|r| r.seconds())
            .map(|s| now.saturating_sub(s))
    }

    /// The most the audit can take on disk: two files at [`AuditPolicy::rotate_at_bytes`].
    pub fn max_bytes(&self) -> u64 {
        self.rotate_at_bytes().saturating_mul(2)
    }
}

/// [`AuditPolicy::new`]'s check, answering the typed refusal (§13.31 §3). The pair it refuses
/// carries the limits as the file **spells** them, which is what today's sentence quoted:
/// `'1 weeks'` is refused as `'1 week'`, because the spelling the file does not accept is not a
/// spelling to point an operator at.
fn audit_policy_core(
    rotation: AuditLimit,
    retention: Option<AuditLimit>,
) -> Result<AuditPolicy, SettingsRefusal> {
    let sized = rotation.bytes().is_some() || retention.is_some_and(|r| r.bytes().is_some());
    if !sized {
        return Err(SettingsRefusal::AuditUnbounded {
            rotation: rotation.spelled(),
            retention: retention.map(|r| r.spelled()),
        });
    }
    Ok(AuditPolicy {
        rotation,
        retention,
    })
}

/// [`compile_audit_policy`]'s checks, answering the typed refusal (§13.31 §3): the two limits,
/// each named by its own setting, and the pair between them, in the order the settings function
/// reads them. An empty value is a default and not a refusal for both, so the enum holds no
/// refusal of it.
pub(crate) fn audit_section_core(
    rotation: &str,
    retention: &str,
) -> Result<AuditPolicy, SettingsRefusal> {
    let rotation = match rotation.trim() {
        "" => AuditPolicy::default().rotation,
        raw => audit_limit_core(raw, SettingKey::AuditRotation)?,
    };
    let retention = match retention.trim() {
        "" => None,
        raw => Some(audit_limit_core(raw, SettingKey::AuditRetention)?),
    };
    audit_policy_core(rotation, retention)
}

/// What kind of thing happened. The outcome is a property of the kind rather than a field of
/// its own: there is no granted-and-refused event, and a second field would let one be
/// written.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// A session cookie was minted: somebody signed in.
    LoginGranted,
    /// `/auth/session` refused to mint one, with `reason` saying which of its doors closed.
    LoginRefused,
    /// A session was cleared at `/auth/logout`. It authorizes nothing and refuses nothing,
    /// and it is here because "when did this person's session end" is a question about the
    /// same timeline as when it began.
    LoginEnded,
    /// A gated request was allowed and was worth saying so: today that is an identity Cognito
    /// vouches for walking into an `authenticated` scope while being in no roster row. An
    /// ordinary grant to an enrolled person is **not** an event (see [`AuditEvent`]).
    AccessGranted,
    /// A gated request was refused, having presented a credential.
    AccessRefused,
}

impl AuditKind {
    /// Did this end in a yes? What the audit page's outcome filter is, and what keeps the
    /// answer from being spelled out twice.
    pub fn granted(self) -> bool {
        matches!(self, AuditKind::LoginGranted | AuditKind::AccessGranted)
    }
}

/// Which credential the client presented, which is the one thing about an access that the
/// access file cannot be asked afterwards.
///
/// [`AuditCredential::Session`] is the honest cost of the cookie's wire format: a
/// `bb1` cookie carries an identity and the profile claims and nothing about how that
/// identity was proved, so on every request after the login the gate knows *who* and not
/// *how*. Stamping the provider into the cookie would say how, and would log every existing
/// session out to start saying it. The login events carry the exact answer, and they are the
/// ones the question is really about.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditCredential {
    /// A federated id_token, naming the upstream identity providers it came through.
    Social { provider: String },
    /// A native Cognito id_token: an account of the pool's own, with no federation behind it.
    Local,
    /// A `bbk_` static key, by its id. The owning row is in `uuid`, since a key acts as its
    /// user and the id alone is only unique within one.
    Key { id: String },
    /// A session cookie this gate signed. Which of the two kinds above minted it is not
    /// recoverable from it.
    Session,
    /// No credential at all, which reaches the audit only where the refusal happened before
    /// one could be read.
    Anonymous,
}

impl AuditCredential {
    /// The word the audit page's credential filter matches on: the tag, without its payload,
    /// so filtering by `key` finds every key rather than one key's id.
    pub fn tag(&self) -> &'static str {
        match self {
            AuditCredential::Social { .. } => "social",
            AuditCredential::Local => "local",
            AuditCredential::Key { .. } => "key",
            AuditCredential::Session => "session",
            AuditCredential::Anonymous => "anonymous",
        }
    }
}

/// Where a request came from, as far as the gate can be told: the three things about a request
/// that are not about the credential it carried.
///
/// A type of its own because the gate reads it once per request and every event recorded on
/// that request's behalf carries it ([`AuditEvent::from`]). A caller that had to name each field
/// at each call site would be a caller that forgets one, and the row it forgets it on is the
/// row somebody needed it on.
///
/// **How far each is to be believed differs, and the difference is why they are three fields
/// and not one.** The gate listens on loopback and never sees a client's address itself, so
/// `ip` is only as true as the proxy that wrote it: it is recorded only when
/// [`AuditSettings::client_ip_header`] names a header, which nginx must then overwrite on every
/// location that reaches the gate. `rid` is nginx's own id for the request, recorded the same
/// way under [`AuditSettings::request_id_header`], and it is there to find this request's line
/// in nginx's access log, which holds everything this record deliberately does not. `ua` is the
/// client's word about itself and nothing more: a hint for whoever reads the row ("that is my
/// phone"), never evidence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditClient {
    pub ip: Option<String>,
    pub ua: Option<String>,
    pub rid: Option<String>,
}

/// One line of the audit file: one authentication event.
///
/// **What is deliberately not here is every allowed request.** The gate answers an
/// `auth_request` on every asset of every page, and this estate's own traffic is on the order
/// of fifteen hundred of those a day, so an audit of all of them is a file nobody reads and a
/// write on the path that must never be slow. The events kept are the ones that change
/// something: a session begins, a session is refused, a session ends, somebody who is in no
/// roster row is let in anyway, and a credential is turned away. What a per-request access log
/// would say is already said by nginx's, which has the URL, the status and the byte count for
/// every request; `rid` is how a row here finds its line there.
///
/// The other deliberate omission is the refusal that carries **no** credential, which is what
/// every signed-out browser gets on its way to the login page. It is the ordinary case, it
/// says nothing about anybody, and it is the only one an anonymous client could produce
/// without limit.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuditEvent {
    /// [`AUDIT_SCHEMA`] as written. Defaulted on read so a line from a future writer that
    /// dropped it is still shown rather than counted as damage.
    #[serde(default)]
    pub v: u32,
    /// Unix seconds. The file is append-ordered, so this is also its sort order, which is
    /// what lets a reader stop at the far edge of a time window instead of parsing the rest.
    pub ts: u64,
    pub kind: AuditKind,
    pub cred: AuditCredential,
    /// The identifier the credential resolved to, when there is one: an email, normally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The roster row, when the identity is in one. Both are kept because they answer
    /// different questions later: the uuid still names the row after an address is dropped,
    /// and the identifier is what was actually presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// The application and the scope that answered, `app/scope`, when one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The URL that was being reached for, as the gate resolved it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// **A code, never a sentence**: `not_member`, `token_invalid`, `key_expired`. The
    /// wording belongs to whoever is reading, the same way a header name belongs to
    /// [`derive_profile_header`] and not to the operator who named a claim. It is what lets
    /// the admin GUI show a refusal in the reader's own language, in the same words its
    /// access check already uses for the same verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The Cognito account behind the credential: the id_token's `sub`, which unlike the email
    /// is never handed to anybody else. It is what tells the account that signed in last month
    /// from a new one registered on the same address after the first was deleted.
    ///
    /// Present only where a token was validated on this request. A session cookie carries no
    /// `sub`, and making it carry one would change the cookie's wire format, which logs
    /// everybody out; the login event is where the answer is recorded, once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// The client's address, as the proxy in front of the gate reported it; see
    /// [`AuditClient`] for how far that is to be believed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// The client's `User-Agent`, cut short by the gate so a line stays a line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ua: Option<String>,
    /// The proxy's id for the request, for finding its line in the proxy's own log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rid: Option<String>,
}

impl AuditEvent {
    /// A bare event of this kind. The rest is added by the methods below, so a call site in
    /// the gate stays one expression and cannot forget a field it never had to name.
    pub fn new(ts: u64, kind: AuditKind, cred: AuditCredential) -> AuditEvent {
        AuditEvent {
            v: AUDIT_SCHEMA,
            ts,
            kind,
            cred,
            subject: None,
            uuid: None,
            app: None,
            scope: None,
            url: None,
            reason: None,
            sub: None,
            ip: None,
            ua: None,
            rid: None,
        }
    }

    /// Who: the identifier presented, and the roster row it resolved to if it did.
    pub fn by(mut self, subject: &str, uuid: Option<&str>) -> AuditEvent {
        self.subject = Some(subject.to_string());
        self.uuid = uuid.map(str::to_string);
        self
    }

    /// Whose row, where there is a row but no identifier to show for it: a key names its
    /// owner by uuid and nothing else.
    pub fn of(mut self, uuid: &str) -> AuditEvent {
        self.uuid = Some(uuid.to_string());
        self
    }

    /// Which scope answered, when one did. An `Option` and not two `&str` because half the
    /// refusals have no place to name (a veto is about the person, and a URL outside every
    /// area has no application), and a caller that has to say so with an `if` says it in the
    /// middle of a builder chain.
    pub fn at(mut self, place: Option<(&str, &str)>) -> AuditEvent {
        if let Some((app, scope)) = place {
            self.app = Some(app.to_string());
            self.scope = Some(scope.to_string());
        }
        self
    }

    /// Which URL was being reached for.
    pub fn on(mut self, url: Option<&str>) -> AuditEvent {
        self.url = url.map(str::to_string);
        self
    }

    /// Why it ended the way it did, as a code.
    pub fn because(mut self, reason: &str) -> AuditEvent {
        self.reason = Some(reason.to_string());
        self
    }

    /// Which Cognito account the token belonged to, when a token was validated at all.
    pub fn account(mut self, sub: Option<&str>) -> AuditEvent {
        self.sub = sub.map(str::to_string);
        self
    }

    /// Where the request came from. One value for all three, so no call site has to know
    /// which of them this request happened to carry.
    pub fn from(mut self, client: &AuditClient) -> AuditEvent {
        self.ip.clone_from(&client.ip);
        self.ua.clone_from(&client.ua);
        self.rid.clone_from(&client.rid);
        self
    }

    /// Everything on this event a text filter should match, joined. One place, so the page's
    /// filter box and any future one agree on what "matches" means.
    ///
    /// The address and the request id are in it because pasting one is how a reader arrives
    /// here from somewhere else: from a firewall's log, or from the line in nginx's.
    pub fn haystack(&self) -> String {
        let mut s = String::new();
        for part in [
            self.subject.as_deref(),
            self.uuid.as_deref(),
            self.app.as_deref(),
            self.scope.as_deref(),
            self.url.as_deref(),
            self.reason.as_deref(),
            self.sub.as_deref(),
            self.ip.as_deref(),
            self.ua.as_deref(),
            self.rid.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            s.push_str(part);
            s.push(' ');
        }
        if let AuditCredential::Key { id } = &self.cred {
            s.push_str(id);
        }
        s
    }
}

/// The refusal code for a [`Decision`], and the only place one is spelled.
///
/// It is the variant's own name in snake_case, which is not laziness: the audit's vocabulary
/// and the decision's are then the same vocabulary, so a reader that has to explain
/// `not_member` can reuse the words it already uses to explain [`Decision::NotMember`], and a
/// new decision variant that nobody maps here fails to compile.
pub fn decision_reason(d: &Decision) -> &'static str {
    match d {
        Decision::Anonymous { .. } => "anonymous",
        Decision::Granted { .. } => "granted",
        Decision::Vetoed => "vetoed",
        Decision::Excluded { .. } => "excluded",
        Decision::NoApplication => "no_application",
        Decision::NoScope { .. } => "no_scope",
        Decision::Unauthenticated { .. } => "unauthenticated",
        Decision::CredentialRefused { .. } => "credential_refused",
        Decision::NotEnrolled { .. } => "not_enrolled",
        Decision::NotMember { .. } => "not_member",
        Decision::KeyOutOfScope { .. } => "key_out_of_scope",
    }
}

/// The rotated file's path: the live one with `.1` on the end.
pub(crate) fn audit_previous(path: &std::path::Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".1");
    std::path::PathBuf::from(name)
}

/// The mode the audit's files are left in: the gate writes, the `bb-auth` group (which is how
/// `bb-auth-web` reads it) reads, nobody else.
///
/// Set after the fact rather than through `OpenOptions::mode`, which the unit's `UMask=0077`
/// would mask down to 0600 and leave the GUI unable to read a word of it. Best effort: an
/// operator who chose another mode keeps it, since the write succeeding matters more than the
/// bits agreeing with a default.
fn audit_mode(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Only the timestamp of a line, which is all rotation and retention need to know about it.
#[derive(Deserialize)]
struct Stamp {
    ts: u64,
}

/// The timestamp a line carries, or `None` for a line that is not one of ours (a torn tail
/// after a power cut).
pub(crate) fn line_ts(line: &[u8]) -> Option<u64> {
    serde_json::from_slice::<Stamp>(line).ok().map(|s| s.ts)
}

/// The timestamp of the first readable line of a file: its oldest event, since the file is
/// append-ordered. `None` for a file that is missing, empty, or has no readable line near its
/// start.
fn oldest_ts(path: &std::path::Path) -> Option<u64> {
    use std::io::BufRead;
    let f = std::fs::File::open(path).ok()?;
    std::io::BufReader::new(f)
        .split(b'\n')
        .take(16)
        .find_map(|l| l.ok().and_then(|l| line_ts(&l)))
}

/// The timestamp of the last readable line of a file: its newest event.
fn newest_ts(path: &std::path::Path) -> Option<u64> {
    let mut lines = RevLines::open(path).ok()?;
    for _ in 0..16 {
        let line = lines.next_line().ok()??;
        if let Some(ts) = line_ts(&line) {
            return Some(ts);
        }
    }
    None
}

/// Replace `path` with its own bytes from `from` onwards, through a temp file beside it and a
/// rename, so a reader that opened the file a moment ago keeps reading the bytes it opened.
///
/// Streamed rather than read into memory, because a file here can be as large as an operator
/// said a rotation may be, and that can be a gibibyte on a machine with less to spare.
fn keep_from(path: &std::path::Path, from: u64) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut src = std::fs::File::open(path)?;
    src.seek(SeekFrom::Start(from))?;
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp_name);
    let mut dst = std::fs::File::create(&tmp)?;
    std::io::copy(&mut src, &mut dst)?;
    dst.sync_all()?;
    drop(dst);
    audit_mode(&tmp);
    std::fs::rename(&tmp, path)
}

/// Drop every event of `path` older than `since`: the whole file when even its newest is, the
/// lines before the first one that is not otherwise, and nothing when its oldest is not.
///
/// The file is time-ordered, so this is "find the first line to keep and keep everything
/// after it", and a torn line before that point goes with the expired ones.
fn drop_before(path: &std::path::Path, since: u64) -> std::io::Result<()> {
    use std::io::BufRead;
    match oldest_ts(path) {
        None => return Ok(()),
        Some(t) if t >= since => return Ok(()),
        Some(_) => {}
    }
    if newest_ts(path).is_some_and(|t| t < since) {
        return std::fs::remove_file(path);
    }
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    let mut offset = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            return std::fs::remove_file(path);
        }
        if line_ts(line.strip_suffix(b"\n").unwrap_or(&line)).is_some_and(|t| t >= since) {
            return keep_from(path, offset);
        }
        offset += n as u64;
    }
}

/// Keep at most the last `max` bytes of `path`, starting at a line boundary, which is what a
/// retention in space does to a file written under a looser one.
fn keep_tail(path: &std::path::Path, max: u64) -> std::io::Result<()> {
    use std::io::{BufRead, Seek, SeekFrom};
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if len <= max {
        return Ok(());
    }
    // The first whole line at or after the cut: skip the partial one the cut lands in.
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    reader.seek(SeekFrom::Start(len - max))?;
    let mut partial = Vec::new();
    let skipped = reader.read_until(b'\n', &mut partial)? as u64;
    keep_from(path, len - max + skipped)
}

/// The gate's end of the audit file: the one thing in this system that appends, rotates and
/// prunes it.
///
/// It is a type and not a free function because rotation is a check-then-rename and the gate
/// is threaded: two workers that both found the file due would rename it twice and throw away
/// the half between. The mutex is held across the whole append, which costs nothing at the rate
/// these events happen and is what makes the file's line ordering its time ordering, which the
/// reader and the pruning both rely on.
///
/// What it does is two things at two rates, and the split is on purpose. [`AuditWriter::record`]
/// appends and rotates on **size**, because that is the bound that has to hold between one
/// event and the next under a flood. [`AuditWriter::maintain`] rotates on **age** and applies
/// the retention, which only have to hold to within an hour, and must hold even on a deployment
/// that writes nothing for a month: the gate calls it hourly, at startup and on every reload.
pub struct AuditWriter {
    path: std::path::PathBuf,
    lock: std::sync::Mutex<()>,
}

impl AuditWriter {
    pub fn new(path: impl Into<std::path::PathBuf>) -> AuditWriter {
        AuditWriter {
            path: path.into(),
            lock: std::sync::Mutex::new(()),
        }
    }

    /// Where this writer appends, for the startup banner.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Poisoning would mean a previous writer panicked mid-append, which costs at most a torn
    /// line; refusing to write from then on would cost the rest of the audit.
    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Move the live file onto `.1`, replacing whatever was there: only the last one is kept.
    ///
    /// Rename and not truncate: a reader that opened the file a moment ago goes on reading the
    /// bytes it opened, and the events are still there to be read next time under the other
    /// name.
    fn rotate(&self) -> std::io::Result<()> {
        match std::fs::rename(&self.path, audit_previous(&self.path)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    /// Append one event, rotating first if this line would take the live file past the size
    /// `policy` allows.
    ///
    /// Before and not after, so the live file never holds more than that size: which is what
    /// makes [`AuditPolicy::max_bytes`] exact rather than exact give or take a line.
    ///
    /// The error is returned rather than reported, because the wording belongs to whoever has
    /// an operator, and above all because the **caller must not stop**: a full disk, a
    /// directory the unit forgot to declare or a mode nobody fixed must cost the audit and
    /// never the login. The gate says so once and carries on.
    pub fn record(&self, ev: &AuditEvent, policy: &AuditPolicy) -> std::io::Result<()> {
        use std::io::Write;
        let mut line = serde_json::to_string(ev).map_err(std::io::Error::other)?;
        line.push('\n');
        let _guard = self.guard();
        let size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if size > 0 && size + line.len() as u64 > policy.rotate_at_bytes() {
            self.rotate()?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        audit_mode(&self.path);
        f.write_all(line.as_bytes())
    }

    /// Bring both files within `policy` as it stands at `now`: rotate the live file if it is
    /// too big or its oldest event too old, cut `.1` down to the size a rotation may hold, and
    /// drop every event a retention in time has expired.
    ///
    /// The size half is what makes a stricter policy take effect at once rather than one
    /// rotation later: a `.1` written under a looser one would otherwise stand, too big, until
    /// the live file next rotated onto it.
    pub fn maintain(&self, policy: &AuditPolicy, now: u64) -> std::io::Result<()> {
        let _guard = self.guard();
        let prev = audit_previous(&self.path);
        let live_size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let too_big = live_size > policy.rotate_at_bytes();
        let too_old = policy
            .rotate_at_age()
            .zip(oldest_ts(&self.path))
            .is_some_and(|(age, oldest)| oldest < now.saturating_sub(age));
        if live_size > 0 && (too_big || too_old) {
            self.rotate()?;
        }
        keep_tail(&prev, policy.rotate_at_bytes())?;
        keep_tail(&self.path, policy.rotate_at_bytes())?;
        if let Some(since) = policy.keep_since(now) {
            drop_before(&prev, since)?;
            drop_before(&self.path, since)?;
        }
        Ok(())
    }
}

/// How much of a file [`RevLines`] reads at a time.
const REV_BLOCK: u64 = 64 * 1024;

/// The lines of a file, last first, read from its end in blocks: one block of memory plus the
/// longest line, whatever size the file has grown to.
///
/// The audit is read newest first, and a view of "the last day" wants the end of a file that
/// may hold a year. Reading the whole of it to walk it backwards was fine at four mebibytes and
/// is not at the gibibyte a rotation may now be set to, on the machine that serves the page.
pub(crate) struct RevLines {
    file: std::fs::File,
    /// How much of the file, from its start, has not been read yet.
    pos: u64,
    /// Read but not yet handed out, in file order: at most one partial line plus one block.
    buf: Vec<u8>,
    block: u64,
}

impl RevLines {
    fn open(path: &std::path::Path) -> std::io::Result<RevLines> {
        RevLines::with_block(path, REV_BLOCK)
    }

    pub(crate) fn with_block(path: &std::path::Path, block: u64) -> std::io::Result<RevLines> {
        let file = std::fs::File::open(path)?;
        // The length now, not as the file grows: a line appended while this reads belongs to
        // the next read, and reading up to a moving end would hand out half of it.
        let pos = file.metadata()?.len();
        Ok(RevLines {
            file,
            pos,
            buf: Vec::new(),
            block,
        })
    }

    /// The next line back, without its newline, skipping blank ones; `None` at the start.
    pub(crate) fn next_line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        use std::io::{Read, Seek, SeekFrom};
        loop {
            if let Some(i) = self.buf.iter().rposition(|&b| b == b'\n') {
                let line = self.buf.split_off(i + 1);
                self.buf.truncate(i);
                if line.is_empty() {
                    continue;
                }
                return Ok(Some(line));
            }
            if self.pos == 0 {
                return Ok((!self.buf.is_empty()).then(|| std::mem::take(&mut self.buf)));
            }
            let n = self.block.min(self.pos);
            self.pos -= n;
            let mut chunk = vec![0u8; n as usize];
            self.file.seek(SeekFrom::Start(self.pos))?;
            self.file.read_exact(&mut chunk)?;
            chunk.extend_from_slice(&self.buf);
            self.buf = chunk;
        }
    }
}

/// What one read of the audit file returned: the newest events first.
pub struct AuditPage {
    /// Newest first, which is the order the file is read in and the order it is shown in.
    pub events: Vec<AuditEvent>,
    /// There were older events still inside the window when `cap` was reached. The page says
    /// so rather than pretending the history ends there.
    pub more: bool,
    /// Lines that did not parse, which is a torn tail after a power cut or a foreign file.
    /// Counted and reported rather than swallowed: an audit that quietly drops what it cannot
    /// read is worse than one that says how much it could not read.
    pub damaged: usize,
}

/// Read the audit newest-first, stopping at `since` or after `cap` events.
///
/// Both files are read, live then rotated, which is what makes a window that reaches back
/// across a rotation whole. A missing file is an empty page and not an error: that is what a
/// deployment which has never refused anybody looks like, and it must not read as a fault.
pub fn read_audit(
    path: &std::path::Path,
    since: Option<u64>,
    cap: usize,
) -> std::io::Result<AuditPage> {
    let mut page = AuditPage {
        events: Vec::new(),
        more: false,
        damaged: 0,
    };
    for p in [path.to_path_buf(), audit_previous(path)] {
        let mut lines = match RevLines::open(&p) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        // Backwards, because the file is time-ordered and the page wants its end, and from the
        // end in blocks, so that only what is shown is read at all: a "last hour" view costs a
        // few blocks of a file that may hold a year.
        while let Some(line) = lines.next_line()? {
            match serde_json::from_slice::<AuditEvent>(&line) {
                Ok(ev) => {
                    if since.is_some_and(|s| ev.ts < s) {
                        return Ok(page);
                    }
                    if page.events.len() >= cap {
                        page.more = true;
                        return Ok(page);
                    }
                    page.events.push(ev);
                }
                Err(_) => page.damaged += 1,
            }
        }
    }
    Ok(page)
}
