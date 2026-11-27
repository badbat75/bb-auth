use crate::*;

// ---------------------------------------------------------------------------
// URL matching
// ---------------------------------------------------------------------------

/// Match `s` against a URL pattern with two wildcards:
///
/// * `*` — zero or more characters, never `/` — **except** as the pattern's final
///   byte, where it swallows the rest of the input, slashes included.
/// * `&` — exactly one character, never `/`.
///
/// Everything else is a literal byte. The match is anchored at both ends. Because
/// a non-terminal `*` cannot cross `/`, and `://` holds two of them, no wildcard
/// can ever leak across the scheme/host/path boundaries — so the same matcher
/// serves all three components without special-casing them.
///
/// Bottom-up DP over `(pattern suffix, input suffix)`: O(n·m) time and O(m) space.
/// A recursive star-backtracker would be exponential on patterns with many `*`.
pub fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (n, m) = (pat.len(), s.len());
    // `next[j]` = can pat[i+1..] match s[j..]; `cur[j]` = can pat[i..] match s[j..].
    let mut next = vec![false; m + 1];
    let mut cur = vec![false; m + 1];
    next[m] = true; // empty pattern matches empty input

    for i in (0..n).rev() {
        let terminal_star = pat[i] == b'*' && i == n - 1;
        for j in (0..=m).rev() {
            cur[j] = if terminal_star {
                true // devours the remainder, `/` included
            } else if pat[i] == b'*' {
                // zero characters, or one more non-slash character
                next[j] || (j < m && s[j] != b'/' && cur[j + 1])
            } else if pat[i] == b'&' {
                j < m && s[j] != b'/' && next[j + 1]
            } else {
                j < m && s[j] == pat[i] && next[j + 1]
            };
        }
        std::mem::swap(&mut cur, &mut next);
    }
    next[0]
}

/// Lowercase the authority (`scheme://host`) of a URL, leaving the path's case
/// intact. Hosts and schemes are case-insensitive per RFC 3986; paths are not.
pub fn lower_authority(url: &str) -> String {
    let split = match url.find("://") {
        Some(i) => match url[i + 3..].find('/') {
            Some(j) => i + 3 + j, // first '/' after the authority
            None => url.len(),
        },
        None => return url.to_string(),
    };
    let mut out = url[..split].to_ascii_lowercase();
    out.push_str(&url[split..]);
    out
}

/// A compiled URL pattern (a scope's `urls`): normalised bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct UrlPattern {
    pat: Vec<u8>,
}

impl std::fmt::Debug for UrlPattern {
    /// The pattern as it was written. Derived, a `Vec<u8>` of ASCII prints as a list of
    /// numbers, and this type is inside [`Settings`], which tests compare and whose failure
    /// message is the whole value of comparing it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.pat))
    }
}

impl UrlPattern {
    /// Whether this pattern matches `s`. The one entry point — [`glob_match`] is public
    /// only so its grammar can be documented and tested, not so callers can hand it
    /// unnormalised bytes.
    pub fn matches(&self, s: &str) -> bool {
        glob_match(&self.pat, s.as_bytes())
    }

    /// The normalised pattern bytes (authority lowercased). For tests and display.
    pub fn as_bytes(&self) -> &[u8] {
        &self.pat
    }
}

/// Validate and normalise one URL pattern. A malformed pattern is an error rather than a
/// silently-dead rule: skipping it would quietly narrow (or, if it was the only entry,
/// blank out) a scope that someone believed they had written.
pub fn compile_pattern(raw: &str) -> Result<UrlPattern, String> {
    let e = |m: &str| Err(format!("url pattern '{raw}': {m}"));
    let p = raw.trim();
    if p.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return e("contains a control byte");
    }
    let sep = match p.find("://") {
        Some(i) if i > 0 => i,
        Some(_) => return e("empty scheme"),
        None => return e("must be <scheme>://<host>/<path>; use '*://*/*' for every URL"),
    };
    let rest = &p[sep + 3..];
    let slash = match rest.find('/') {
        Some(j) => j,
        None => return e("missing path (use '<scheme>://<host>/*' for the whole host)"),
    };
    if slash == 0 {
        return e("empty host");
    }
    if rest[..slash].contains('@') {
        return e("userinfo '@' is not allowed in the host");
    }
    if p.contains("..") {
        return e("'..' is not allowed");
    }
    Ok(UrlPattern {
        pat: lower_authority(p).into_bytes(),
    })
}

/// Validate a login URL — `BB_AUTH_LOGIN_URL` or an application's `login_url`. Both end
/// up in a `Location:` header, in `X-Auth-Login-URL`, and inside a page, so this is what
/// makes those emissions safe with no per-use check: printable ASCII forbids CR/LF and
/// spaces.
///
/// https-only, and no userinfo `@` or backslash in the authority — the same lookalike
/// tricks [`rd_url_allowed`] rejects, since a login page is where a rejected
/// `rd` lands.
///
/// It is **not** checked against `BB_AUTH_AUTHORIZED_HOSTS`, and cannot be: [`read_access`]
/// reads no env, which is exactly what lets `bb-auth --check-access` validate a file with no
/// config and no network. Moving the check to startup would turn an operator's typo into a
/// fatal boot under `Restart=on-failure` that `--check-access` never saw coming.
pub fn compile_login_url(raw: &str) -> Result<String, String> {
    compile_page_url("login_url", raw)
}

/// The same guard, for any operator-configured URL of a page the gate sends somebody to:
/// today the login page and `gate.denied_url`, the page a refusal lands on.
///
/// [`compile_login_url`] is this function under the name it had when a login page was the
/// only such value. `field` is what the message names, because "denied_url '…': must be an
/// absolute https:// URL" is a sentence an operator can act on, and the same sentence about
/// `login_url` for a value they wrote under another key is one they cannot.
pub fn compile_page_url(field: &str, raw: &str) -> Result<String, String> {
    if raw.trim().is_empty() {
        return Err(format!("{field} '{raw}': empty"));
    }
    page_url_core(raw).map_err(|(raw, fault)| format!("{field} '{raw}': {fault}"))
}

/// [`compile_page_url`]'s checks, answering the typed refusal so `compile_settings` can hand one
/// to the GUI as a code (§13.31 §3). The pair it returns is the text today's sentence quotes and
/// the fault, never the whole sentence: `field` belongs to the caller, which is why the access
/// file's parser and `bb-auth-adm` keep their own names in front of the same tail.
///
/// An empty value is not here. It is the setting being unset, which `compile_settings` skips
/// before calling and which the leaf's own callers answer with their own `empty` sentence, so
/// the enum holds only the faults a value can have (§13.31 §2).
pub(crate) fn page_url_core(raw: &str) -> Result<String, (String, UrlFault)> {
    let u = raw.trim();
    let e = |fault| Err((raw.to_string(), fault));
    if !u.bytes().all(|b| b.is_ascii_graphic()) {
        return e(UrlFault::NotPrintable);
    }
    let rest = match u.strip_prefix("https://") {
        Some(r) => r,
        None => return e(UrlFault::NotHttps),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return e(UrlFault::EmptyHost);
    }
    if authority.contains('@') {
        return e(UrlFault::Userinfo);
    }
    if u.contains('\\') {
        return e(UrlFault::Backslash);
    }
    Ok(u.to_string())
}

/// Validate and normalise one `BB_AUTH_AUTHORIZED_HOSTS` entry: a host-only glob
/// (`badbat75.com`, `*.badbat75.com`, `v&.badbat75.com`). No scheme, no path, no port
/// — [`rd_url_allowed`] strips those from the candidate before matching.
///
/// Env, not access file — but it compiles to the same [`UrlPattern`] and is matched by the
/// same [`glob_match`], which is the point: one wildcard grammar, one implementation.
pub fn compile_host_pattern(raw: &str) -> Result<UrlPattern, String> {
    if raw.trim().is_empty() {
        // The one sentence of this leaf that is not a code (§13.31 §2): `compile_settings` skips
        // a blank entry before it calls this, so the settings file can never produce it, and the
        // enum holds only what is reachable.
        return Err(format!("host pattern '{raw}': empty"));
    }
    host_pattern_core(raw).map_err(|r| r.sentence())
}

/// [`compile_host_pattern`]'s checks, answering the typed refusal (§13.31 §3). The refusal quotes
/// `raw` **as given**, which is what today's sentence printed, and the pattern returned is the
/// trimmed, lowercased one.
pub(crate) fn host_pattern_core(raw: &str) -> Result<UrlPattern, SettingsRefusal> {
    let h = raw.trim().to_ascii_lowercase();
    if h.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(SettingsRefusal::HostControlByte {
            raw: raw.to_string(),
        });
    }
    if h.contains('/') || h.contains(':') {
        return Err(SettingsRefusal::HostNotBare {
            raw: raw.to_string(),
        });
    }
    if h.contains('@') || h.contains("..") {
        return Err(SettingsRefusal::HostAtOrDotDot {
            raw: raw.to_string(),
        });
    }
    Ok(UrlPattern {
        pat: h.into_bytes(),
    })
}

/// True iff `url` is an absolute `https://` URL whose host matches one of `hosts`.
/// Rejects any other scheme, control bytes, userinfo (`@`) and backslashes. A `:port` suffix is
/// tolerated on the candidate and stripped before matching (patterns are bare hosts).
///
/// Matching is the same [`glob_match`] a scope's URL patterns use, so `*.badbat75.com` accepts
/// `mcp.badbat75.com` but neither `evilbadbat75.com` nor `badbat75.com.evil.com` — the literal
/// dot in the pattern is what rules those out. It does *not* accept the bare apex
/// `badbat75.com`; list it explicitly if you want it.
///
/// It lives here, and not beside the `safe_rd` that calls it from the gate, because
/// [`compile_settings`] needs it: a `gate.landing_url` whose host `gate.authorized_hosts` does
/// not cover would be refused by this function at every login and fall back to the sign-in
/// page, so the editor has to be able to ask the same question on the way to disk. By the
/// library's own membership rule, the moment an editor must refuse to *write* a bad value the
/// rule that decides one is shared. `safe_rd` stays in the gate, because that half is HTTP, and
/// it calls this, so the load-time check and the use-time gate cannot drift apart.
pub fn rd_url_allowed(url: &str, hosts: &[UrlPattern]) -> bool {
    // Control bytes are rejected HERE and not only in `safe_rd`, so that the gate is one
    // gate however it is entered. `login_rd` calls this one directly, so the check used to
    // depend on which endpoint the candidate arrived at: a CR/LF in a `?rd=` reached the
    // sign-in page's `data-rd` attribute (escaped, and re-checked before it could become a
    // `Location:`, so it was never exploitable) and the same bytes were refused a few
    // functions away. A guard two callers describe as the same guard has to be the same
    // guard.
    if url.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    let rest = match url.strip_prefix("https://") {
        Some(r) => r,
        None => return false,
    };
    // Authority is everything up to the first '/', '?' or '#'.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return false;
    }
    // Strip an optional ":port" (only when the part after ':' is all digits, so we
    // don't mistake something else for a port).
    let host = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => authority,
    };
    let host = host.to_ascii_lowercase();
    hosts.iter().any(|p| p.matches(&host))
}

/// The user group a scope's `groups` entry references (`"@admins"` ⇒ `Some("admins")`),
/// or `None` for anything else.
///
/// The one place the `@` sigil is spelled out. Both editors call it to find who references
/// what, so a tool and the gate cannot come to disagree about which entries are
/// references: the same reason there is one matcher and one parser.
pub fn group_ref(entry: &str) -> Option<&str> {
    entry.trim().strip_prefix('@')
}

/// A set of URL patterns, and the single matcher every URL check in bb-auth goes
/// through: today that is a scope's `urls`, and nothing else has its own.
///
/// There is no "unrestricted" variant. An absent or empty list matches **nothing**:
/// access is enumerated, never assumed. Blanket coverage is spelled out as the pattern
/// `*://*/*`, which an operator has to mean in order to write.
///
/// Having one type is not tidiness: [`UrlScope::allows`] is where the missing-header
/// and `..` denials live, and a second matcher that forgot either would be a bypass
/// around the first.
#[derive(Clone)]
pub struct UrlScope {
    patterns: Vec<UrlPattern>, // request URL must match one of these; empty = deny all
}

impl UrlScope {
    /// The empty scope: authorizes no URL at all. What an absent list of patterns
    /// resolves to, since access is enumerated and never assumed.
    pub fn deny_all() -> UrlScope {
        UrlScope {
            patterns: Vec::new(),
        }
    }

    /// Compile a scope's `urls` list. Blank entries are dropped; a malformed pattern is
    /// an error, never a silently skipped entry, because a vanished pattern changes which
    /// requests the scope answers for.
    ///
    /// The message names only the pattern; the caller prefixes the application and the
    /// scope, which is what makes it say `mpa/admin: url pattern '…': …`.
    pub fn compile(list: &[String]) -> Result<UrlScope, String> {
        let mut patterns = Vec::with_capacity(list.len());
        for raw in list.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            patterns.push(compile_pattern(raw)?);
        }
        Ok(UrlScope { patterns })
    }

    /// The compiled patterns, for the containment check that keeps a scope inside its
    /// application's area (see `base_covers`).
    pub fn patterns(&self) -> &[UrlPattern] {
        &self.patterns
    }

    /// Whether this scope authorizes nothing at all. Used to warn at load time, and by
    /// `bb-auth-adm` to say so out loud when an edit leaves a user with no way in.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Whether `url` (the original request URL, query/fragment stripped, authority
    /// lowercased) is in scope. A missing URL (`None`) is always a denial: every
    /// credential is scoped, so the reverse proxy must always send the header. `..`
    /// anywhere is rejected — nginx's `$uri` is already normalised, so this only
    /// fires on a misconfigured proxy, and it fires closed.
    pub fn allows(&self, url: Option<&str>) -> bool {
        match url {
            None => false,
            Some(u) => !u.contains("..") && self.patterns.iter().any(|p| p.matches(u)),
        }
    }
}

// ---------------------------------------------------------------------------
// The runtime access table
// ---------------------------------------------------------------------------

/// Which credential classes a [`ScopeRecord`] admits. Absent in the file means both.
///
/// The class is a property of the *place*, not of the credential: "this area is reached
/// by a browser login" and "this area is reached by a machine key" are statements an
/// operator makes about an application, and expressing them here is what let the key
/// stop carrying URLs of its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CredentialSet {
    /// A Cognito id_token bearer, or the session cookie minted from one.
    pub login: bool,
    /// A static `bbk_` key.
    pub api_key: bool,
}

impl Default for CredentialSet {
    /// Both: an absent `credentials` restricts nothing.
    fn default() -> Self {
        CredentialSet {
            login: true,
            api_key: true,
        }
    }
}

/// What a scope asks of the identity behind a request. Compiled from `access`, which is a
/// **required** word in the file with no default: this field decides everything, so a typo
/// must never resolve to the most open value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessKind {
    /// No credential at all. The gate answers `204` with no identity header.
    Anonymous,
    /// Any identity Cognito vouches for, enrolled in `users` or not. This is how someone
    /// who has just registered reaches an onboarding area, and since self-signup is open
    /// it means anyone who can register.
    Authenticated,
    /// The listed users and groups, and nobody else.
    Restricted,
}

/// A resolved scope: a URL area inside an application, and the one policy that holds for
/// it.
///
/// A scope names people, and that is the only place a grant is written. The rule being
/// kept is against *duplication*, not against a direction: a user removed from the roster
/// must not still walk in through a place. So the grant lives on the side of the place and
/// nowhere else, [`ScopeRecord::members`] are references to roster rows, and a reference to
/// a row that does not exist grants nothing.
pub struct ScopeRecord {
    /// Human label, for logging and for `app/scope`. Never empty.
    pub name: String,
    /// The URLs this scope speaks for. Always inside its application's `base`.
    pub urls: UrlScope,
    /// What this scope asks of an identity.
    pub access: AccessKind,
    /// The uuids admitted by an [`AccessKind::Restricted`] scope, with `user_groups`
    /// already expanded, so nothing downstream ever learns that groups exist. Empty for
    /// the other two kinds, where it is not consulted.
    pub members: HashSet<String>,
    /// Which credential classes may exercise this grant. Only meaningful under
    /// [`AccessKind::Restricted`]; the file refuses it on the other two.
    pub credentials: CredentialSet,
    /// Excluded uuids, with `user_groups` already expanded, exactly as `members` is.
    ///
    /// Empty on an [`AccessKind::Anonymous`] scope because the file refuses the field
    /// there; consulted on the other two.
    pub excluded_users: HashSet<String>,
    /// Excluded identifiers that resolve to no roster row, lowercased.
    ///
    /// The scope-local twin of [`Access::denied_identifiers`], and it exists for the same
    /// reason: an [`AccessKind::Authenticated`] scope admits identities that are in no
    /// table, so for them an email is the only exclusion there is. An identifier that
    /// *does* resolve is folded into [`ScopeRecord::excluded_users`] at load.
    pub excluded_identifiers: HashSet<String>,
}

impl ScopeRecord {
    /// Does this scope keep `identifier` out?
    ///
    /// The same two-halves shape as [`Access::vetoes_identifier`], one level down: the
    /// stranger's own email, or the uuid the roster resolves them to. One implementation,
    /// because [`decide`] asks it for a browser login and for a key and an exclusion that
    /// covered one and not the other would be worse than none.
    pub fn excludes_identifier(&self, access: &Access, identifier: &str) -> bool {
        let id = norm_email(identifier);
        self.excluded_identifiers.contains(&id)
            || access
                .by_identifier
                .get(&id)
                .is_some_and(|u| self.excluded_users.contains(u))
    }
}

/// A resolved application: a literal URL area, the login page for it, and its scopes in
/// file order.
///
/// Applications **partition** the URL space. Every `base` is a literal prefix, no two of
/// them overlap (see `base_covers`), and every pattern of every scope lies inside one of
/// them. So at most one application can ever answer for a URL, which is what makes "a URL
/// belongs to one application" a property of the file rather than a convention, and what
/// gives `login_url` a single unambiguous home.
pub struct AppRecord {
    /// `[A-Za-z0-9_-]+`, unique in the file, and the left half of `app/scope`.
    pub name: String,
    /// Literal URL prefixes, authority lowercased. Never empty.
    pub base: Vec<String>,
    /// Login page for this area, overriding `BB_AUTH_LOGIN_URL`. `None` = use the global.
    /// Reaches nginx through `X-Auth-Login-URL`; also names the fallback for a rejected
    /// `rd` and the link on `/auth/session`'s error pages. See [`login_url_for`].
    pub login_url: Option<String>,
    /// Refusal page for this area, overriding `gate.denied_url`. `None` = use the global,
    /// which is itself empty for the gate's own `/auth/denied`. See [`denied_url_for`].
    ///
    /// It is on the application and not on the scope because an area is what a visitor can
    /// name: they were refused *somewhere*, and which of the scopes said no is a fact about
    /// the file that no page may hand a stranger.
    pub denied_url: Option<String>,
    /// **First match wins**, in file order: the first scope whose `urls` cover the request
    /// answers for it, even if it grants nothing. That is what makes a carve-out
    /// expressible, a narrower and stricter scope listed before a broad one, which a union
    /// of grants cannot express at all. It also means a broad scope listed first shadows
    /// everything after it, so the editors lint the order.
    pub scopes: Vec<ScopeRecord>,
}

/// Whether the literal prefix `base` covers `s`: equal, or `s` continues past `base` at a
/// path boundary.
///
/// The boundary is the whole point. A plain `starts_with` would let the area
/// `https://x.com/app` swallow `https://x.com/application`, which is the same trap as a
/// `*` written with no `/` before it. One function serves both jobs that need the rule,
/// so the check that two applications do not overlap and the check that a scope stays
/// inside its own application can never drift apart.
pub fn base_covers(base: &str, s: &str) -> bool {
    if !s.starts_with(base) {
        return false;
    }
    s.len() == base.len() || base.ends_with('/') || s.as_bytes()[base.len()] == b'/'
}

/// The request URL a lookup may be attempted with, or `None`.
///
/// Both levels of resolution deny the same two things, so they say it once here: a missing
/// URL (the reverse proxy did not send the header, and every credential is scoped, so
/// there is nothing to check against) and a URL containing `..` (nginx's `$uri` is already
/// normalised, so this only fires on a misconfigured proxy, and it fires closed).
/// [`UrlScope::allows`] repeats the rule for patterns; this is the same rule for the
/// literal base level, rather than a second one that could drift.
fn sane_url(url: Option<&str>) -> Option<&str> {
    url.filter(|u| !u.contains(".."))
}

/// The login page for `url`: the application whose area covers it, or `global`
/// (`BB_AUTH_LOGIN_URL`).
///
/// There is no ambiguity to resolve here. Areas do not overlap, so at most one
/// application answers, and it answers whether or not any of its scopes covers the URL:
/// a `401` inside an application is exactly when its own login page is wanted.
///
/// Every value returned passed [`compile_login_url`] (the application's at load, the
/// global at startup), so callers may put it in a header or a redirect without checking.
pub fn login_url_for(access: &Access, global: &str, url: Option<&str>) -> String {
    access
        .app_for(url)
        .and_then(|a| a.login_url.as_deref())
        .unwrap_or(global)
        .to_string()
}

/// The refusal page for `url`: the application whose area covers it, or `global`
/// (`gate.denied_url`). [`login_url_for`] one page along, and resolved the same way, for the
/// same reason: areas do not overlap, so at most one application answers.
///
/// This is what makes a per-**host** refusal page expressible, since an area is an absolute
/// prefix and therefore names a host: two applications on two hosts carry two pages. It needs
/// the URL to say so, and the gate only has one on `/auth/denied` if nginx forwards
/// `BB_AUTH_ORIGINAL_URL_HEADER` there, exactly as it must on `/auth/session`. Without it
/// this returns the global, which is a page rather than an error: a refusal that is styled
/// for the wrong area still says no, and failing the whole page over a missing header would
/// answer a refused visitor with nothing at all.
///
/// Every value returned passed [`compile_page_url`] (the application's at load, the global
/// at settings-compile), so callers may put it in a header or a redirect without checking.
pub fn denied_url_for(access: &Access, global: &str, url: Option<&str>) -> String {
    access
        .app_for(url)
        .and_then(|a| a.denied_url.as_deref())
        .unwrap_or(global)
        .to_string()
}

/// A resolved roster row, keyed by uuid in [`Access::by_uuid`].
///
/// A user carries no URL. What they reach is written on the side of the place, in the
/// scopes that list their uuid, which is the whole inversion in one sentence.
pub struct UserRecord {
    /// The canonical identity, and what every reference in the file names.
    pub uuid: String,
    /// The identifiers Cognito can vouch for, lowercased, in file order. The first is the
    /// primary: it is what a single-valued view of this user shows.
    pub emails: Vec<String>,
}

/// A resolved API key, keyed by the bearer's SHA-256 hex in [`Access::by_key_hash`].
pub struct ApiKeyRecord {
    /// Owning user's uuid, for the veto and for the identity handed downstream. A key
    /// *acts as* its user, and it is the only credential with no token to decode.
    pub uuid: String,
    /// Human label, for logging and revocation. Not part of the credential.
    pub key_id: String,
    /// Unix seconds; `None` = never expires.
    pub expires: Option<u64>,
    /// The `app/scope` names this key may exercise, or `None` for all of its owner's.
    ///
    /// A **restriction, never a grant**: it can only subtract from what the owner already
    /// reaches, which is what keeps grants written in exactly one place while still
    /// letting a machine credential carry less authority than the human who owns it.
    pub scopes: Option<HashSet<String>>,
}

/// The runtime access table, built from the access file by [`read_access`].
pub struct Access {
    /// The applications, in file order. They partition the URL space; see [`AppRecord`].
    pub apps: Vec<AppRecord>,
    /// Uuids vetoed on **every** credential and every grant, checked ahead of every one
    /// of them ([`decide`], [`decide_api_key`], and the gate's `/auth/session`).
    ///
    /// It is not redundant with deleting the row: for an enrolled user it is a suspension
    /// rather than a deletion, so their identifiers, group memberships and keys survive
    /// the lockout and re-enabling is one edit.
    pub denied_users: HashSet<String>,
    /// Vetoed identifiers that resolve to no roster row, lowercased.
    ///
    /// This is the only denial that exists for a stranger, and strangers are exactly who
    /// an [`AccessKind::Authenticated`] scope lets in. An identifier that *does* resolve
    /// is folded into [`Access::denied_users`] at load, so denying one email of a user
    /// vetoes the user and every other identifier they have.
    pub denied_identifiers: HashSet<String>,
    /// Lowercased identifier → uuid, many to one. What turns a token claim into an
    /// identity.
    pub by_identifier: HashMap<String, String>,
    /// uuid → roster row.
    pub by_uuid: HashMap<String, UserRecord>,
    /// `sha256(bearer)` hex → key. The raw key is never stored, and this lookup **is**
    /// the verification: finding a matching row would require a SHA-256 second preimage,
    /// so a high-entropy key needs neither a salt nor a constant-time compare.
    pub by_key_hash: HashMap<String, ApiKeyRecord>,
}

impl Access {
    /// The application and scope that speak for `url`, or `None`.
    ///
    /// Two levels, two different rules, on purpose. Applications **partition** the URL
    /// space, so at most one can answer and the order they are written in carries no
    /// meaning. Scopes inside one application are **first match wins** in file order,
    /// which is what makes a carve-out expressible. The dangerous half of first-match,
    /// a broad entry shadowing a narrow one, can now only bite between scopes of the same
    /// application: entries an operator sees together, on one screen, in one form.
    pub fn resolve(&self, url: Option<&str>) -> Option<(&AppRecord, &ScopeRecord)> {
        let app = self.app_for(url)?;
        let scope = app.scopes.iter().find(|s| s.urls.allows(url))?;
        Some((app, scope))
    }

    /// The application whose area covers `url`, or `None`. What names the login page on a
    /// `401`, which is why it does not care whether any scope matched.
    pub fn app_for(&self, url: Option<&str>) -> Option<&AppRecord> {
        let u = sane_url(url)?;
        self.apps
            .iter()
            .find(|a| a.base.iter().any(|b| base_covers(b, u)))
    }

    /// Whether any scope anywhere grants on identity alone. `/auth/session` needs it to
    /// know whether an un-enrolled identity has anywhere to go at all; nothing else may
    /// branch on it.
    pub fn any_authenticated_scope(&self) -> bool {
        self.apps.iter().any(|a| {
            a.scopes
                .iter()
                .any(|s| s.access == AccessKind::Authenticated)
        })
    }

    /// Every scope that lists `uuid`, for "what does this user reach?" in the two editors.
    ///
    /// Membership only: it says nothing about the scopes that would grant this user access
    /// anyway by being anonymous or authenticated, and nothing about whether an earlier
    /// scope in the same application shadows the one found. Both are the caller's lint,
    /// because both are advice to an operator rather than part of the decision.
    pub fn scopes_for(&self, uuid: &str) -> Vec<(&AppRecord, &ScopeRecord)> {
        self.apps
            .iter()
            .flat_map(|a| a.scopes.iter().map(move |s| (a, s)))
            .filter(|(_, s)| s.members.contains(uuid))
            .collect()
    }

    /// Every scope a signed-in `identifier` reaches: the list the self-service page
    /// (`bb-auth-web`'s `/account`) shows a person.
    ///
    /// This is [`decide`]'s rule for a browser login restated as a set rather than as one
    /// answer, so it asks the very helpers [`decide`] asks ([`Access::vetoes_identifier`],
    /// [`ScopeRecord::excludes_identifier`], [`Access::uuid_of`]): a grant rule written
    /// twice is what drifts, and a page promising a scope the gate refuses is worse than a
    /// page saying nothing. An [`AccessKind::Anonymous`] scope is never listed, since it
    /// grants with no credential and so says nothing about this person.
    ///
    /// It takes an identifier, not a uuid, because a stranger has no uuid and yet reaches
    /// every [`AccessKind::Authenticated`] scope, and is kept out of one only by the email
    /// they sign in with. Membership, not a promise about every URL: scopes are first match
    /// wins inside an application, so a listed scope answers only what shadows do not.
    pub fn scopes_reached(&self, identifier: &str) -> Vec<(&AppRecord, &ScopeRecord)> {
        if self.vetoes_identifier(identifier) {
            return Vec::new();
        }
        let uuid = self.uuid_of(identifier);
        self.apps
            .iter()
            .flat_map(|a| a.scopes.iter().map(move |s| (a, s)))
            .filter(|(_, s)| match s.access {
                AccessKind::Anonymous => false,
                AccessKind::Authenticated => true,
                AccessKind::Restricted => {
                    s.credentials.login && uuid.is_some_and(|u| s.members.contains(u))
                }
            })
            .filter(|(_, s)| !s.excludes_identifier(self, identifier))
            .collect()
    }

    /// Every scope a key owned by `uuid` may be narrowed to: the checkboxes the self-service
    /// key form (`bb-auth-web`'s `/account`) offers.
    ///
    /// This is [`decide`]'s rule for a key restated as a set, so it asks the very fields
    /// [`decide`] asks for a [`Subject::Key`] ([`Access::denied_users`],
    /// [`ScopeRecord::credentials`], [`ScopeRecord::members`],
    /// [`ScopeRecord::excluded_users`]): the form's list and the gate's answer are one grant
    /// rule written twice, and a form that offers a scope the gate refuses mints a key that
    /// fails on its very first request. It is the **owner's** reach and never one existing
    /// key's, because a key's own `scopes` is a restriction: a form that offered only what
    /// that key already carries could never widen it back.
    ///
    /// An [`AccessKind::Anonymous`] scope is left out even though [`decide`] grants a key
    /// there: it grants with no credential at all, so narrowing a key to it restricts
    /// nothing, and a checkbox that changes nothing is worse than no checkbox. An
    /// [`AccessKind::Authenticated`] scope is out for the opposite reason: [`decide`] refuses
    /// a key there, because Cognito vouches for no static key of ours.
    ///
    /// A uuid the file denies is offered nothing, ahead of every scope: `denied` outranks
    /// every grant on every credential, and a key is one of them. Membership, not a promise
    /// about every URL: scopes are first match wins inside an application, so a listed scope
    /// answers only what shadows do not.
    pub fn key_scopes_for(&self, uuid: &str) -> Vec<(&AppRecord, &ScopeRecord)> {
        if self.denied_users.contains(uuid) {
            return Vec::new();
        }
        self.apps
            .iter()
            .flat_map(|a| a.scopes.iter().map(move |s| (a, s)))
            .filter(|(_, s)| {
                s.access == AccessKind::Restricted
                    && s.credentials.api_key
                    && s.members.contains(uuid)
                    && !s.excluded_users.contains(uuid)
            })
            .collect()
    }

    /// The uuid this identifier resolves to, matched as the file stores it.
    pub fn uuid_of(&self, identifier: &str) -> Option<&str> {
        self.by_identifier
            .get(&norm_email(identifier))
            .map(|s| s.as_str())
    }

    /// Whether `denied` vetoes this identifier: the identifier itself, or the user it
    /// resolves to.
    ///
    /// One implementation, because [`decide`] and the gate's `/auth/session` both ask it
    /// and a veto that covered one door and not the other would be worse than none.
    pub fn vetoes_identifier(&self, identifier: &str) -> bool {
        let id = norm_email(identifier);
        self.denied_identifiers.contains(&id)
            || self
                .by_identifier
                .get(&id)
                .is_some_and(|u| self.denied_users.contains(u))
    }
}

// ---------------------------------------------------------------------------
// The authorization decision
// ---------------------------------------------------------------------------

/// The subject of a request, as the credential already resolved it.
///
/// The credential **class** is implied by the variant, which is why a scope's
/// [`CredentialSet`] needs no second parameter and cannot be consulted with the wrong one.
pub enum Subject<'a> {
    /// No credential at all. Only an [`AccessKind::Anonymous`] scope grants.
    Anonymous,
    /// An identifier Cognito vouched for (an email today). It may be in no roster row,
    /// which is exactly what an [`AccessKind::Authenticated`] scope is for.
    Identifier(&'a str),
    /// A `bbk_` key that already passed [`decide_api_key`].
    Key(&'a ApiKeyRecord),
}

/// What the access table says about one (subject, URL) pair: the whole grant model as a
/// value. [`decide`] produces it; the gate turns it into a 204/401 and a log line, and
/// `bb-auth-adm can` prints it, so an operator can ask "would this work?" of the same code
/// that will answer the real request.
///
/// Every refusal names where it happened, because with the URL space partitioned the
/// useful question is not "was it granted?" but "which scope answered, and what did it
/// want?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// An `anonymous` scope covers the URL: no credential was needed and none was
    /// consulted.
    Anonymous { app: String, scope: String },
    /// The scope that answered admits this subject.
    Granted { app: String, scope: String },
    /// `denied` vetoes this subject, ahead of every grant and on every credential.
    Vetoed,
    /// The scope that answered lists this subject in its own `excluded`, ahead of its
    /// grant. Distinct from [`Decision::Vetoed`] on purpose: this one is local, so the
    /// same identity may well reach the very next scope, and an operator reading a log
    /// needs to know which of the two shut the door.
    Excluded { app: String, scope: String },
    /// No application's area covers this URL, so nobody reaches it. With no per-user URLs
    /// left, this is the only fail-closed reading, and it is the posture change an
    /// operator has to be told about: a gated location outside every application is a
    /// `401` for everyone, including the person who wrote the file.
    NoApplication,
    /// The application answers for this URL but none of its scopes covers it.
    NoScope { app: String },
    /// The scope wants an identity and the request carried no credential.
    Unauthenticated { app: String, scope: String },
    /// The scope does not admit this class of credential.
    CredentialRefused { app: String, scope: String },
    /// A `restricted` scope, and this identifier is in no roster row.
    NotEnrolled { app: String, scope: String },
    /// Enrolled, but this scope does not list them.
    NotMember { app: String, scope: String },
    /// The owner is admitted, but this key's own `scopes` restriction excludes the scope
    /// that answered.
    KeyOutOfScope { app: String, scope: String },
}

impl Decision {
    /// Whether this decision authorizes the request.
    pub fn granted(&self) -> bool {
        matches!(self, Decision::Anonymous { .. } | Decision::Granted { .. })
    }
}

/// Turn an authenticated (or absent) credential into an authorized one, or say why not.
/// The one rule behind all three credentials.
///
/// The order is the model:
///
/// 1. Resolve the URL to one application and one scope. Nothing outside an application is
///    reachable, by anyone, with any credential.
/// 2. An [`AccessKind::Anonymous`] scope grants immediately, **before** the veto. That is
///    deliberate: the scope grants with no credential at all, so a vetoed client would
///    simply omit theirs and walk in anyway. A veto that is bypassed by sending *less* is
///    not a veto, and offering it would be worse than not offering it, because an operator
///    would believe it.
/// 3. The veto, on every remaining credential: first the file's `denied`, then the
///    answering scope's own `excluded`. Both are refusals *ahead* of the grant, which is
///    what lets one exclude a member of a group without unpicking the group, and what lets
///    one exclude anybody at all from an [`AccessKind::Authenticated`] scope.
/// 4. [`AccessKind::Authenticated`]: any identity Cognito vouches for, enrolled or not. A
///    key is refused here rather than admitted, because Cognito vouches for no static key
///    of ours and this grant is about who Cognito says you are.
/// 5. [`AccessKind::Restricted`]: the credential class, then the roster, then membership,
///    then the key's own restriction.
pub fn decide(access: &Access, subject: &Subject, url: Option<&str>) -> Decision {
    let (app, scope) = match access.resolve(url) {
        Some(found) => found,
        None => {
            return match access.app_for(url) {
                Some(a) => Decision::NoScope {
                    app: a.name.clone(),
                },
                None => Decision::NoApplication,
            }
        }
    };
    let at = || (app.name.clone(), scope.name.clone());
    let (a, s) = at();

    if scope.access == AccessKind::Anonymous {
        return Decision::Anonymous { app: a, scope: s };
    }

    let vetoed = match subject {
        Subject::Anonymous => false,
        Subject::Identifier(id) => access.vetoes_identifier(id),
        Subject::Key(rec) => access.denied_users.contains(&rec.uuid),
    };
    if vetoed {
        return Decision::Vetoed;
    }

    // The scope's own veto, in the same place in the order and for the same reason: ahead
    // of the grant, so it beats a `@group` this subject is in and it beats `authenticated`,
    // which lists nobody there would be to remove them from. It sits *after* the file-level
    // veto so that a `denied` identity is still reported as vetoed rather than as merely
    // excluded from wherever they happened to knock.
    let excluded = match subject {
        Subject::Anonymous => false,
        Subject::Identifier(id) => scope.excludes_identifier(access, id),
        Subject::Key(rec) => scope.excluded_users.contains(&rec.uuid),
    };
    if excluded {
        return Decision::Excluded { app: a, scope: s };
    }

    match scope.access {
        // Handled above, before the veto.
        AccessKind::Anonymous => Decision::Anonymous { app: a, scope: s },
        AccessKind::Authenticated => match subject {
            Subject::Identifier(_) => Decision::Granted { app: a, scope: s },
            Subject::Key(_) => Decision::CredentialRefused { app: a, scope: s },
            Subject::Anonymous => Decision::Unauthenticated { app: a, scope: s },
        },
        AccessKind::Restricted => {
            let uuid = match subject {
                Subject::Anonymous => return Decision::Unauthenticated { app: a, scope: s },
                Subject::Identifier(_) if !scope.credentials.login => {
                    return Decision::CredentialRefused { app: a, scope: s }
                }
                Subject::Key(_) if !scope.credentials.api_key => {
                    return Decision::CredentialRefused { app: a, scope: s }
                }
                Subject::Identifier(id) => match access.uuid_of(id) {
                    Some(u) => u,
                    None => return Decision::NotEnrolled { app: a, scope: s },
                },
                Subject::Key(rec) => rec.uuid.as_str(),
            };
            if !scope.members.contains(uuid) {
                return Decision::NotMember { app: a, scope: s };
            }
            if let Subject::Key(rec) = subject {
                if rec
                    .scopes
                    .as_ref()
                    .is_some_and(|allowed| !allowed.contains(&format!("{a}/{s}")))
                {
                    return Decision::KeyOutOfScope { app: a, scope: s };
                }
            }
            Decision::Granted { app: a, scope: s }
        }
    }
}

/// What the access table says about a `bbk_` bearer, before any URL is considered.
///
/// No `Debug`, deliberately: deriving it would force one onto [`ApiKeyRecord`] and
/// [`Access`], and a table of live credentials is not something a stray `{:?}` should be
/// able to spill into a log.
pub enum KeyDecision<'a> {
    Granted(&'a ApiKeyRecord),
    /// No row for this hash. An [`AccessKind::Authenticated`] scope does **not** rescue
    /// it: that grant is for identities Cognito vouches for, and Cognito vouches for no
    /// static key of ours. An unknown key is not an un-enrolled user, it is nobody, and
    /// there would be no identity to hand back.
    Unknown,
    /// The owning user is vetoed ([`Access::denied_users`]).
    OwnerDenied(&'a ApiKeyRecord),
    Expired(&'a ApiKeyRecord),
}

impl KeyDecision<'_> {
    pub fn granted(&self) -> bool {
        matches!(self, KeyDecision::Granted(_))
    }
}

/// Resolve an API key against the access table, by the SHA-256 hex of the bearer: the
/// lookup, the owner's veto, and the expiry. That is its whole job.
///
/// What the key may then *reach* is [`decide`]'s, through [`Subject::Key`]: the scope that
/// answers is what decides, exactly as it does for a browser login, and a key's own
/// `scopes` restriction is applied there because it is expressed in terms of the scope
/// that answered.
///
/// Taking the *hash* rather than the raw key is what lets an editor evaluate a key it has
/// never seen (the file stores only the hash) through the same code the gate runs. The
/// gate hashes the bearer and calls this; nothing is ever indexed by what the client sent
/// in the clear.
pub fn decide_api_key<'a>(access: &'a Access, key_hash: &str, now: u64) -> KeyDecision<'a> {
    let rec = match access.by_key_hash.get(key_hash) {
        Some(r) => r,
        None => return KeyDecision::Unknown,
    };
    if access.denied_users.contains(&rec.uuid) {
        return KeyDecision::OwnerDenied(rec);
    }
    if rec.expires.is_some_and(|e| now >= e) {
        return KeyDecision::Expired(rec);
    }
    KeyDecision::Granted(rec)
}

// ---------------------------------------------------------------------------
// JSON wire format
// ---------------------------------------------------------------------------

/// Root of the access file — the real access gate, re-checked on every `/auth/validate`
/// and hot-reloaded on SIGHUP.
///
/// ```json
/// { "version": 1,
///   "applications": [
///     { "name": "app1",
///       "base": ["https://app.x.com/app1"],
///       "login_url": "https://signup.x.com/",
///       "scopes": [
///         { "name": "healthz", "urls": ["https://app.x.com/app1/healthz"],
///           "access": "anonymous" },
///         { "name": "admin", "urls": ["https://app.x.com/app1/admin/*"],
///           "access": "restricted", "groups": ["@admins"], "credentials": ["login"] },
///         { "name": "onboarding", "urls": ["https://app.x.com/app1/*"],
///           "access": "authenticated" } ] } ],
///   "user_groups": { "admins": ["8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b"] },
///   "denied": ["spammer@x.com"],
///   "users": [
///     { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b",
///       "emails": ["bob@x.com"],
///       "api_keys": [
///         { "id": "laptop", "key_hash": "<sha256 hex of the bbk_… bearer>",
///           "released": "2026-07-08", "duration": "365d",
///           "scopes": ["app1/admin"] } ] } ] }
/// ```
///
/// The four sections are siblings and answer four different questions: `applications`
/// describe places and who may reach them, `user_groups` names a reusable set of people,
/// `denied` vetoes people, `users` is the roster of identities. Access is enumerated,
/// never assumed: a URL no application covers is reachable by nobody, and a `restricted`
/// scope that lists nobody grants to nobody. Validate a file before shipping it with
/// `bb-auth --check-access <file>`, or `bb-auth-adm check`: the same parser,
/// [`read_access`].
///
/// This type is also the **document model** `bb-auth-adm` edits, hence [`Serialize`] and
/// the `extra` maps: the sections that describe people carry operator documentation
/// (`_comment`, `notes`) that an edit must not eat. [`compile_access`] is what turns a
/// document into the runtime table, so a tool that writes one can ask, before saving,
/// exactly what the gate will make of it.
///
/// The env var (`BB_AUTH_ACCESS_FILE`), the CLI flag (`--check-access`) and the default
/// file name (`access.json`) all say *access*, which is the word this crate uses for the
/// thing everywhere else: [`AccessFile`], [`compile_access`], [`read_access`],
/// [`open_access_file`].
#[derive(Deserialize, Serialize, Default)]
pub struct AccessFile {
    /// The format this file is written in. **Required**, and the only accepted value is
    /// [`ACCESS_FILE_VERSION`].
    ///
    /// It is here so that a mismatch is a sentence rather than a type error three levels
    /// down, and so that every future change of format gets that courtesy for free: a file
    /// this binary cannot read must say so about itself, in one line, before anything else
    /// is made of it.
    #[serde(default)]
    pub version: u32,
    /// The places, and who reaches them. See [`AppRecord`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<AppSpec>,
    /// Named sets of roster uuids: `"admins": ["8f14e45f-…"]`, written `"@admins"` in a
    /// scope's `groups`.
    ///
    /// Abbreviation, never a grant: defining one authorizes nobody until a scope names it.
    /// Deliberately shallow and deliberately strict: a name is `[A-Za-z0-9_-]+` matched
    /// exactly, a group may not reference another group, an unknown reference is fatal, and
    /// every group is validated even when nothing references it (a group that only breaks
    /// the day someone first uses it is a trap `--check-access` never saw). Duplicate JSON
    /// keys are serde's last-wins, as everywhere else in this file.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_groups: BTreeMap<String, Vec<String>>,
    /// Uuids and bare identifiers, vetoed ahead of every grant. See
    /// [`Access::denied_users`] and [`Access::denied_identifiers`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<String>,
    #[serde(default)]
    pub users: Vec<UserSpec>,
    /// Unknown top-level keys, preserved verbatim across an edit: `_comment` above all.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One application: a literal URL area, its login page, and its scopes. Compiles to an
/// [`AppRecord`].
///
/// **Unknown fields are a hard error** here and on [`ScopeSpec`], which is why neither
/// carries an `extra` map and both spell `notes` out as a field. The specs that describe
/// people ignore extras, where an ignored typo denies at worst. These two describe grants
/// and restrictions on grants, so a typo in a future companion field would be dropped in
/// silence and leave the field it was meant to restrict standing alone, failing *open*.
/// `bb-auth --check-access` catches it instead, before the restart.
#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AppSpec {
    /// `[A-Za-z0-9_-]+`, unique in the file. No `/`, so `app/scope` is unambiguous.
    #[serde(default)]
    pub name: String,
    /// The literal URL prefixes this application owns. No wildcards: an area is compared
    /// by string, which is what makes non-overlap cheap to check and impossible to argue
    /// with. Every scope pattern must lie inside one of them.
    #[serde(default)]
    pub base: Vec<String>,
    /// Absolute `https://` login page for this area. Absent means `BB_AUTH_LOGIN_URL`.
    /// Malformed is fatal, like a URL pattern. See [`compile_login_url`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
    /// Absolute `https://` refusal page for this area. Absent means `gate.denied_url`, and
    /// an empty one of those means the gate's own `/auth/denied`. Malformed is fatal, like a
    /// URL pattern. See [`compile_page_url`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_url: Option<String>,
    /// **Order is meaning**: first match wins. See [`AppRecord::scopes`].
    #[serde(default)]
    pub scopes: Vec<ScopeSpec>,
    /// Operator documentation, round-tripped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// One scope inside an application. Compiles to a [`ScopeRecord`].
#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ScopeSpec {
    /// `[A-Za-z0-9_-]+`, unique within its application, and the right half of `app/scope`.
    #[serde(default)]
    pub name: String,
    /// Full `<scheme>://<host>/<path>` patterns, all inside the application's `base`. A
    /// malformed one is fatal; an empty list makes the scope match nothing.
    #[serde(default)]
    pub urls: Vec<String>,
    /// `anonymous`, `authenticated` or `restricted`. **Required, with no default**: see
    /// [`AccessKind`]. Always written out, because it is the security-relevant property of
    /// the record and an operator reading the file should never have to know what an
    /// absent field would have meant.
    #[serde(default)]
    pub access: String,
    /// Roster uuids admitted by a `restricted` scope. Present on any other kind is fatal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<String>>,
    /// `"@name"` references into `user_groups`. Present on a non-`restricted` scope is
    /// fatal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    /// `login` and/or `api_key`; absent means both. Present on a non-`restricted` scope is
    /// fatal. See [`CredentialSet`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<String>>,
    /// Who this scope keeps out, whatever else admits them: a roster uuid, a `"@name"`
    /// group, or a bare email for an identity the roster has never heard of.
    ///
    /// The scope-local twin of the file's `denied`, and it exists for the case that field
    /// cannot express: keeping one person out of *one* place while they keep everything
    /// else. Checked ahead of the grant, so it beats a `@group` membership and it beats
    /// `authenticated` — which is the whole point, since that kind lists nobody to remove
    /// anyone from. Present on an `anonymous` scope is **fatal**: that scope grants with no
    /// credential at all, so an excluded client would simply send none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded: Option<Vec<String>>,
    /// Operator documentation, round-tripped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// One roster entry: an identity, its identifiers, and its keys. Extra fields are ignored
/// and preserved on a rewrite, which is safe here because a row describes a person rather
/// than a grant: an ignored typo denies at worst.
///
/// A user carries no URL. What they reach is written in the scopes that list their uuid,
/// which is what makes deleting a row a complete revocation again: there is no second
/// place expressing the same relation.
#[derive(Deserialize, Serialize, Default)]
pub struct UserSpec {
    /// The canonical identity: a lowercase 8-4-4-4-12 UUID, unique in the file, and what
    /// every reference to this user names.
    ///
    /// References are by uuid rather than by email precisely because references are now
    /// scattered: a scope's `users`, any number of `user_groups`, `denied`. An identifier
    /// changes; the identity does not, so a rename touches one line instead of N.
    #[serde(default)]
    pub uuid: String,
    /// The identifiers Cognito can vouch for, in file order. The first is the primary.
    ///
    /// A list rather than a field because one person can hold more than one address, and
    /// all of them resolve to this same row. An entry that is not [`header_safe_email`] is
    /// warned about and skipped: dropping an identifier is fail-closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_keys: Vec<ApiKeySpec>,
    /// `notes` and anything else an operator wrote here. Round-tripped untouched.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One static API key belonging to a [`UserSpec`]. The `bbk_` bearer itself never
/// appears here, only `key_hash`. Mint keys with `bb-auth-adm key add`.
///
/// **An unknown field here is reported at load**, unlike on [`UserSpec`], and the difference
/// is what the subtree is. A row describing a person can afford to carry an operator's own
/// keys, and an ignored typo there denies at worst. This subtree is nothing but a grant, and
/// its two narrowing fields both fail *open* when a typo drops them: a misspelled `scopes` is
/// a key that reaches everything its owner reaches, and a misspelled `duration` is a key that
/// never expires. Both were silent.
///
/// A warning and not a refusal, which is the one place this departs from `deny_unknown_fields`
/// on [`AppSpec`] and [`ScopeSpec`]: `notes` is a documented thing to write here (`bb-auth-adm
/// key add --note`), so the unknown-field set is not empty by design, and a live file carrying
/// one must not become a fatal load, i.e. a boot loop under `Restart=on-failure`. The warning
/// is printed by [`compile_access`], so `--check-access` and the startup banner both say it.
#[derive(Deserialize, Serialize, Default)]
pub struct ApiKeySpec {
    #[serde(default)]
    pub id: String,
    /// Lowercase hex SHA-256 of the whole `bbk_…` bearer. A malformed value warns and
    /// skips just this key.
    #[serde(default)]
    pub key_hash: String,
    /// `YYYY-MM-DD` the key was issued; the base for `duration`.
    #[serde(default)]
    pub released: String,
    /// `<n>d`, `<n>h`, a bare `<n>` (days), or `never`/`0`/`-`. See [`parse_duration`].
    #[serde(default)]
    pub duration: String,
    /// The `"app/scope"` names this key may exercise. Absent means every scope its owner
    /// is admitted to; present names an unknown application or scope is fatal.
    ///
    /// A restriction, never a grant: see [`ApiKeyRecord::scopes`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// `notes` and anything else written here. Round-tripped untouched, and reported at load
    /// unless it is `notes`: see the type's own documentation for why this one is a warning.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------------------------------------------------------------------------
// Emails, hashes, dates
// ---------------------------------------------------------------------------

/// Is `email` safe to emit verbatim as an HTTP header value?
///
/// Visible ASCII only — no control bytes (CR/LF above all), no space, nothing
/// non-ASCII. This is what lets the gate's `respond_authorized` build `X-Auth-Email` with
/// no per-request check, and it is enforced at the **two** places an email can enter,
/// which between them cover all three credentials:
///
/// * [`compile_access`], at load, for every roster email — the only guard on the API-key
///   path, whose email comes straight off [`ApiKeyRecord`] and never passes through a
///   token claim.
/// * the gate's `validate_id_token`, for every email lifted out of a Cognito claim. An
///   `authenticated` scope emits identities that are in no table, so load time cannot see
///   them; and because that is the only way an email reaches the session cookie, the
///   cookie inherits the property through the HMAC rather than needing its own check.
pub fn header_safe_email(email: &str) -> bool {
    !email.is_empty() && email.bytes().all(|b| b.is_ascii_graphic())
}

/// Does `email` have the shape of an address Cognito could ever vouch for?
///
/// Deliberately pragmatic, not RFC 5322: [`header_safe_email`] first (printable ASCII, so
/// no whitespace and no control bytes), then exactly one `@`, a non-empty local part of
/// anything printable, and a domain of `[A-Za-z0-9-]` labels (no label starting or ending
/// with `-`) joined by `.` — with **at least one dot**, because a Cognito email always
/// carries a TLD. That rejects `not an email` and `bob@example,com` while accepting any
/// address Cognito would ever emit.
///
/// This is an **edit-path** check ([`add_user`], [`add_user_email`], [`add_denied`]) and
/// only there: [`compile_access`] must never learn it, because a live file that loads
/// today has to keep loading (a fatal startup under `Restart=on-failure` is a boot loop).
/// A malformed identifier is fail-closed anyway, since it matches no Cognito claim, but a
/// typo'd one is a dead identifier discovered only when the human it was meant for cannot
/// get in, so the two editors refuse to *create* one.
pub fn well_formed_email(email: &str) -> bool {
    if !header_safe_email(email) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Is `s` a UUID in the one spelling this file format accepts: canonical lowercase
/// 8-4-4-4-12 hex?
///
/// Deliberately strict about case and shape rather than lenient. A uuid is compared by
/// string in five different places (a scope's `users`, a group's members, `denied`, the
/// roster index, a key's owner), and a second accepted spelling would mean two strings
/// that name the same identity and do not compare equal, which is a dangling reference
/// that looks correct in a diff. The version and variant nibbles are not checked: they say
/// how the value was generated, and nothing here depends on that.
pub fn well_formed_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
    })
}

/// SHA-256 of `s`, lowercase hex. Fingerprints an API key for storage/lookup.
pub fn sha256_hex(s: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(s.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Mint a fresh `bbk_` API key: the raw bearer (shown to its owner **once**, never
/// stored) and the `key_hash` that goes in the file.
///
/// 256 bits from the OS CSPRNG, base64url without padding — so the bearer carries no
/// `:`, no whitespace and no padding, and survives a header, a shell and a JSON string
/// untouched. The hash is the only half the file keeps, and [`decide_api_key`]'s lookup
/// of it *is* the verification; losing the raw key means minting a new one.
pub fn mint_api_key() -> Result<(String, String), String> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| format!("no entropy from the OS: {e}"))?;
    let key = format!("{API_KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(secret));
    let hash = sha256_hex(&key);
    Ok((key, hash))
}

/// Days from 1970-01-01 to the civil date (proleptic Gregorian), Howard
/// Hinnant's algorithm. `m` in 1..=12, `d` in 1..=31.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // Mar=0 ..= Feb=11
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// The civil date `days` after 1970-01-01 — the inverse of [`days_from_civil`], same
/// paper. Only `bb-auth-adm` needs it (to print an expiry, and to date a new key), but it
/// belongs next to its inverse, which the round-trip test pins.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parse a `YYYY-MM-DD` date to Unix seconds at 00:00 UTC. Rejects malformed
/// dates and anything before the epoch.
pub fn parse_date_epoch(s: &str) -> Option<u64> {
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, m, d);
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400)
}

/// Format Unix seconds as the `YYYY-MM-DD` the access file speaks (UTC).
pub fn format_date(epoch: u64) -> String {
    let (y, m, d) = civil_from_days((epoch / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Format Unix seconds as `YYYY-MM-DD HH:MM:SS`, as if they were **UTC**, for the audit page.
///
/// It knows nothing about time zones and should not: the audit page shifts the seconds by the
/// offset of whichever zone its reader chose before it calls this, reading that offset out of
/// the host's own zone database. So there is still one formatter, and the zone is a question
/// for the one program that has a reader to ask.
pub fn format_datetime(epoch: u64) -> String {
    let (y, m, d) = civil_from_days((epoch / 86_400) as i64);
    let s = epoch % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        s / 3600,
        (s % 3600) / 60,
        s % 60
    )
}

/// A parsed validity window.
#[derive(Debug, PartialEq, Eq)]
pub enum Dur {
    Never,
    Secs(u64),
}

/// Parse a duration field: `0` / `never` / `-` (or empty) => `Never`; otherwise
/// `<n>d` days, `<n>h` hours, or a bare `<n>` (days). `None` on a malformed value.
pub fn parse_duration(s: &str) -> Option<Dur> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() || s == "0" || s == "never" || s == "-" {
        return Some(Dur::Never);
    }
    let (num, mult) = if let Some(n) = s.strip_suffix('d') {
        (n, 86_400u64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600u64)
    } else {
        (s.as_str(), 86_400u64)
    };
    let n: u64 = num.trim().parse().ok()?;
    Some(Dur::Secs(n.checked_mul(mult)?))
}

/// Compute a key's expiry from its `released`/`duration` fields. `Some(None)` =
/// never expires; `Some(Some(ts))` = Unix-seconds expiry; `None` = malformed
/// (the caller skips the key).
pub fn key_expiry(released: &str, duration: &str) -> Option<Option<u64>> {
    match parse_duration(duration)? {
        Dur::Never => Some(None),
        Dur::Secs(secs) => Some(Some(parse_date_epoch(released)?.checked_add(secs)?)),
    }
}

// ---------------------------------------------------------------------------
// Parsing the access file
// ---------------------------------------------------------------------------

/// Read and parse an access file into its document model, without compiling it. What
/// `bb-auth-adm` edits; the gate goes straight to [`read_access`].
pub fn read_access_file(path: &str) -> Result<AccessFile, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("parse {path}: {e}"))
}

/// Parse the access JSON at `path` into the runtime table: [`read_access_file`] then
/// [`compile_access`]. What the gate loads at startup, re-loads on SIGHUP, and what
/// `bb-auth --check-access` and `bb-auth-adm` validate with.
pub fn read_access(path: &str) -> Result<Access, String> {
    compile_access(&read_access_file(path)?)
}

/// The one spelling a name may have, anywhere in this file: non-empty `[A-Za-z0-9_-]`.
///
/// No `/`, which is what lets `app/scope` be a name in its own right: the string a log
/// line prints, a key's restriction lists, and an editor addresses a scope by.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Validate and normalise one application `base`: a **literal** URL prefix.
///
/// Literal is the load-bearing word. An area is compared by string ([`base_covers`]), and
/// that is what makes "do these two applications overlap?" a question with a cheap and
/// certain answer. Two glob patterns would need an intersection test, and the useful
/// blanket patterns (`*://*/*`) would intersect everything, so the partition could never
/// hold. An application on a wildcard host is therefore not expressible, which is a
/// deliberate cost, not an oversight.
fn compile_base(raw: &str) -> Result<String, String> {
    let e = |m: &str| Err(format!("base '{raw}': {m}"));
    let b = raw.trim();
    if b.is_empty() {
        return e("empty");
    }
    if !b.bytes().all(|c| c.is_ascii_graphic()) {
        return e("must be printable ASCII (no spaces, no control bytes)");
    }
    if b.contains('*') || b.contains('&') {
        return e("must be literal: a base carries no wildcards, it is the area a scope's patterns live inside");
    }
    if b.contains("..") {
        return e("'..' is not allowed");
    }
    let sep = match b.find("://") {
        Some(i) if i > 0 => i,
        Some(_) => return e("empty scheme"),
        None => return e("must be <scheme>://<host>[/<path>]"),
    };
    let rest = &b[sep + 3..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    if host_end == 0 {
        return e("empty host");
    }
    if rest[..host_end].contains('@') {
        return e("userinfo '@' is not allowed in the host");
    }
    Ok(lower_authority(b))
}

/// Compile the `user_groups` section: validate every name and every member, once, up
/// front. Errors are prefixed `user_groups '<name>': …`.
///
/// Unreferenced groups are compiled too, and a bad one is just as fatal: a group that only
/// breaks the day someone first references it is a trap laid for a future edit, and the
/// whole point of `--check-access` is that the file is checked before it is live.
///
/// Groups are flat by construction: an entry that is itself a reference is rejected here,
/// so a scope can splice one in with no recursion, no cycle detection and no order
/// dependence between definitions.
///
/// A member that names no roster row only **warns**. It grants nothing, which is
/// fail-closed, and the two editors lint it: a fatal error there would mean removing a
/// user could brick the gate on its next reload.
fn compile_user_groups(
    raw: &BTreeMap<String, Vec<String>>,
    by_uuid: &HashMap<String, UserRecord>,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut out = BTreeMap::new();
    for (name, list) in raw {
        if !valid_name(name) {
            return Err(format!(
                "user_groups '{name}': a group name must be non-empty and [A-Za-z0-9_-]"
            ));
        }
        let mut members: Vec<String> = Vec::with_capacity(list.len());
        for entry in list.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if let Some(g) = group_ref(entry) {
                return Err(format!(
                    "user_groups '{name}': '@{g}': a group cannot reference another group"
                ));
            }
            let uuid = entry.to_ascii_lowercase();
            if !well_formed_uuid(&uuid) {
                return Err(format!(
                    "user_groups '{name}': '{entry}' is not a uuid (a group lists users by \
                     uuid, in the canonical lowercase 8-4-4-4-12 form)"
                ));
            }
            if !by_uuid.contains_key(&uuid) {
                eprintln!(
                    "[bb-auth] WARNING: user group '{name}' lists {uuid}, which is in no users \
                     entry: that member grants nothing"
                );
            }
            if !members.contains(&uuid) {
                members.push(uuid);
            }
        }
        if members.is_empty() {
            eprintln!(
                "[bb-auth] WARNING: user group '{name}' has no members: a scope naming it admits \
                 nobody through it"
            );
        }
        out.insert(name.clone(), members);
    }
    Ok(out)
}

/// Refuse a file whose format this binary does not read, in a sentence.
///
/// The two arms are worth spelling out separately: a file with no `version` at all is a
/// file nobody declared a format for, while one that names a format this binary does not
/// have is a different mistake with a different fix, and neither should surface as a type
/// mismatch three levels down.
fn check_version(file: &AccessFile) -> Result<(), String> {
    if file.version == ACCESS_FILE_VERSION {
        return Ok(());
    }
    Err(match file.version {
        0 => format!(
            "this file has no 'version'; an access file declares \"version\": \
             {ACCESS_FILE_VERSION}"
        ),
        v => format!(
            "this file declares version {v}; this binary reads version {ACCESS_FILE_VERSION}"
        ),
    })
}

/// The one access-file format this binary reads. See [`AccessFile::version`].
pub const ACCESS_FILE_VERSION: u32 = 1;

/// Compile a parsed access file into the runtime table.
///
/// The order below is not arbitrary: the roster is built first because everything else
/// references it, groups next because scopes splice them, applications next, then keys
/// (whose restrictions name scopes that must exist), and `denied` last, so an identifier
/// can be folded onto the uuid it belongs to.
///
/// **What is fatal and what is skipped** is the one rule to keep. An error that silently
/// changes who reaches what is fatal: a bad `access`, a URL pattern, a base that overlaps
/// another application's, a scope reaching outside its own area, an unknown `@group`, a
/// duplicate identity, a key restriction naming no scope. An error whose only effect is to
/// drop one credential warns and skips it: an unusable email, a malformed `key_hash`, a
/// bad `released`/`duration`, a reference to a user who is not there. The first kind fails
/// closed *loudly*, before the restart, which is what `bb-auth --check-access` is for and
/// what makes a SIGHUP reload keep the old table; the second fails closed quietly, because
/// dropping one credential is exactly what an operator would want it to do.
///
/// Emails are additionally required to be [`header_safe_email`], since every one of them
/// can end up in an identity header.
pub fn compile_access(file: &AccessFile) -> Result<Access, String> {
    check_version(file)?;

    // The roster first: everything below references it, and the dangling-reference
    // warnings need to know which uuids exist.
    let mut by_uuid: HashMap<String, UserRecord> = HashMap::new();
    let mut by_identifier: HashMap<String, String> = HashMap::new();
    for u in &file.users {
        let uuid = u.uuid.trim().to_ascii_lowercase();
        if !well_formed_uuid(&uuid) {
            return Err(format!(
                "users entry '{}': not a uuid (canonical lowercase 8-4-4-4-12; mint one with \
                 bb-auth-adm user add)",
                u.uuid.trim()
            ));
        }
        if by_uuid.contains_key(&uuid) {
            return Err(format!("{uuid} is declared by two users entries"));
        }
        let mut emails = Vec::with_capacity(u.emails.len());
        for raw in &u.emails {
            let e = norm_email(raw);
            if e.is_empty() {
                eprintln!("[bb-auth] WARNING: {uuid}: empty email, skipping");
                continue;
            }
            if !header_safe_email(&e) {
                // Warn and skip: dropping an identifier denies through it, which is
                // fail-closed. `{e:?}` escapes the very control bytes being rejected, so a
                // crafted file cannot forge log lines on its way out.
                eprintln!(
                    "[bb-auth] WARNING: {uuid}: email {e:?} is not printable ASCII, skipping"
                );
                continue;
            }
            // Fatal, not last-wins: two rows claiming one identifier means the row an
            // operator is reading may not be the row in force, which silently changes who
            // reaches what.
            if let Some(other) = by_identifier.get(&e) {
                return Err(format!(
                    "email '{e}' is declared by two users: {other} and {uuid}"
                ));
            }
            by_identifier.insert(e.clone(), uuid.clone());
            emails.push(e);
        }
        if emails.is_empty() {
            eprintln!(
                "[bb-auth] WARNING: {uuid} has no emails: no credential can ever resolve to \
                 this user"
            );
        }
        by_uuid.insert(
            uuid.clone(),
            UserRecord {
                uuid: uuid.clone(),
                emails,
            },
        );
    }

    // Expanded here and nowhere else: every scope below holds plain uuids by the time it
    // is stored, so `decide` and the gate never learn that groups exist.
    let groups = compile_user_groups(&file.user_groups, &by_uuid)?;

    let mut apps: Vec<AppRecord> = Vec::with_capacity(file.applications.len());
    // (base, owning application) for every base seen so far: the partition check.
    let mut areas: Vec<(String, String)> = Vec::new();
    for a in &file.applications {
        let name = a.name.trim().to_string();
        if !valid_name(&name) {
            return Err(format!(
                "application '{name}': a name must be non-empty and [A-Za-z0-9_-]"
            ));
        }
        if apps.iter().any(|x| x.name == name) {
            return Err(format!("two applications are named '{name}'"));
        }
        let mut base = Vec::with_capacity(a.base.len());
        for raw in &a.base {
            let b = compile_base(raw).map_err(|e| format!("application '{name}': {e}"))?;
            if let Some((other, owner)) = areas
                .iter()
                .find(|(o, _)| base_covers(o, &b) || base_covers(&b, o))
            {
                return Err(format!(
                    "application '{name}': base '{b}' overlaps '{other}' (application \
                     '{owner}'). A URL belongs to one application: areas may not contain \
                     one another"
                ));
            }
            areas.push((b.clone(), name.clone()));
            base.push(b);
        }
        if base.is_empty() {
            return Err(format!(
                "application '{name}': no base, so it owns no URLs and nothing in it is \
                 reachable"
            ));
        }
        let login_url = match &a.login_url {
            Some(u) => {
                Some(compile_login_url(u).map_err(|e| format!("application '{name}': {e}"))?)
            }
            None => None,
        };
        let denied_url = match &a.denied_url {
            Some(u) => Some(
                compile_page_url("denied_url", u)
                    .map_err(|e| format!("application '{name}': {e}"))?,
            ),
            None => None,
        };

        let mut scopes: Vec<ScopeRecord> = Vec::with_capacity(a.scopes.len());
        for s in &a.scopes {
            let sname = s.name.trim().to_string();
            let at = format!("{name}/{sname}");
            if !valid_name(&sname) {
                return Err(format!(
                    "application '{name}': scope name '{sname}' must be non-empty and \
                     [A-Za-z0-9_-]"
                ));
            }
            if scopes.iter().any(|x| x.name == sname) {
                return Err(format!(
                    "application '{name}': two scopes are named '{sname}'"
                ));
            }
            let access = match s.access.trim() {
                "anonymous" => AccessKind::Anonymous,
                "authenticated" => AccessKind::Authenticated,
                "restricted" => AccessKind::Restricted,
                "" => {
                    return Err(format!(
                        "{at}: 'access' is required and has no default; it must be \
                         \"anonymous\", \"authenticated\" or \"restricted\""
                    ))
                }
                other => {
                    return Err(format!(
                        "{at}: unknown access '{other}'; it must be \"anonymous\", \
                         \"authenticated\" or \"restricted\""
                    ))
                }
            };
            // The three membership fields belong to `restricted` and to nothing else.
            // Ignoring them elsewhere would let a scope read as if it restricted access
            // while granting to everyone, which is the failing-open shape this format
            // refuses everywhere.
            if access != AccessKind::Restricted {
                let stray = if s.users.is_some() {
                    Some("users")
                } else if s.groups.is_some() {
                    Some("groups")
                } else if s.credentials.is_some() {
                    Some("credentials")
                } else {
                    None
                };
                if let Some(f) = stray {
                    return Err(format!(
                        "{at}: '{f}' means nothing on an access of \"{}\"; it belongs to \
                         \"restricted\"",
                        s.access.trim()
                    ));
                }
            }
            // `excluded` is the one membership-ish field that also belongs to
            // `authenticated` — that kind lists nobody, so an exclusion is the only way to
            // keep one person out of it. On `anonymous` it is refused for the reason the
            // file-level veto is not consulted there either: the scope grants with no
            // credential at all, so an excluded client would simply send none, and a field
            // that reads like a defence while defending nothing is worse than no field.
            if access == AccessKind::Anonymous && s.excluded.is_some() {
                return Err(format!(
                    "{at}: 'excluded' means nothing on an access of \"anonymous\": that scope \
                     grants with no credential at all, so an excluded client would simply send \
                     none. Make the scope \"authenticated\", or narrow its urls"
                ));
            }

            let urls = UrlScope::compile(&s.urls).map_err(|e| format!("{at}: {e}"))?;
            for p in urls.patterns() {
                let raw = String::from_utf8_lossy(p.as_bytes()).into_owned();
                if !base.iter().any(|b| base_covers(b, &raw)) {
                    return Err(format!(
                        "{at}: '{raw}' is outside this application's base ({}). A scope may \
                         only speak for URLs its application owns",
                        base.join(", ")
                    ));
                }
            }
            if urls.is_empty() {
                eprintln!("[bb-auth] WARNING: {at} has no urls: it matches nothing");
            }

            let credentials = match &s.credentials {
                None => CredentialSet::default(),
                Some(list) => {
                    let mut set = CredentialSet {
                        login: false,
                        api_key: false,
                    };
                    for c in list.iter().map(|c| c.trim()).filter(|c| !c.is_empty()) {
                        match c {
                            "login" => set.login = true,
                            "api_key" => set.api_key = true,
                            other => {
                                return Err(format!(
                                    "{at}: unknown credential '{other}'; it must be \"login\" \
                                     (an id_token or the session cookie) or \"api_key\""
                                ))
                            }
                        }
                    }
                    if !set.login && !set.api_key {
                        return Err(format!(
                            "{at}: an empty 'credentials' admits no credential at all, so the \
                             scope is unreachable. Remove the field to admit both"
                        ));
                    }
                    set
                }
            };

            let mut members: HashSet<String> = HashSet::new();
            if access == AccessKind::Restricted {
                for entry in s.users.iter().flatten() {
                    let entry = entry.trim();
                    if entry.is_empty() {
                        continue;
                    }
                    let uuid = entry.to_ascii_lowercase();
                    if !well_formed_uuid(&uuid) {
                        return Err(format!(
                            "{at}: '{entry}' is not a uuid (a scope lists users by uuid, in the \
                             canonical lowercase 8-4-4-4-12 form)"
                        ));
                    }
                    if !by_uuid.contains_key(&uuid) {
                        eprintln!(
                            "[bb-auth] WARNING: {at} lists {uuid}, which is in no users entry: \
                             that reference grants nothing"
                        );
                    }
                    members.insert(uuid);
                }
                for entry in s.groups.iter().flatten() {
                    let entry = entry.trim();
                    if entry.is_empty() {
                        continue;
                    }
                    let g = group_ref(entry).ok_or_else(|| {
                        format!("{at}: '{entry}': a group reference is written '@name'")
                    })?;
                    match groups.get(g) {
                        Some(list) => members.extend(list.iter().cloned()),
                        None => return Err(format!("{at}: unknown user group '@{g}'")),
                    }
                }
                if members.is_empty() {
                    eprintln!(
                        "[bb-auth] WARNING: {at} is restricted and lists nobody: it admits no \
                         one (an anonymous or authenticated scope is how an area is opened)"
                    );
                }
            }

            // Same grammar as `denied`, plus `@group`, and folded the same way: an email
            // the roster resolves becomes the uuid, so excluding one address of a user
            // cannot leave another standing. An entry that is none of the three is refused
            // rather than kept as a string nothing will ever equal — an exclusion that
            // excludes nobody while reading as if it did fails *open*, which is the one
            // shape this format never accepts.
            let mut excluded_users: HashSet<String> = HashSet::new();
            let mut excluded_identifiers: HashSet<String> = HashSet::new();
            for entry in s.excluded.iter().flatten() {
                let e = entry.trim();
                if e.is_empty() {
                    continue;
                }
                if e.starts_with('@') {
                    let g = group_ref(e).ok_or_else(|| {
                        format!("{at}: excluded '{e}': a group reference is written '@name'")
                    })?;
                    match groups.get(g) {
                        Some(list) => excluded_users.extend(list.iter().cloned()),
                        None => return Err(format!("{at}: excluded: unknown user group '@{g}'")),
                    }
                    continue;
                }
                let lower = e.to_ascii_lowercase();
                if well_formed_uuid(&lower) {
                    if !by_uuid.contains_key(&lower) {
                        eprintln!(
                            "[bb-auth] WARNING: {at} excludes {lower}, which is in no users \
                             entry: that exclusion keeps nobody out"
                        );
                    }
                    excluded_users.insert(lower);
                    continue;
                }
                if !e.contains('@') {
                    return Err(format!(
                        "{at}: excluded '{e}': not a uuid, not '@group' and not an email. An \
                         exclusion names a user by uuid, a group by '@name', or an identity the \
                         roster does not know by its email"
                    ));
                }
                let id = norm_email(e);
                match by_identifier.get(&id) {
                    Some(uuid) => {
                        excluded_users.insert(uuid.clone());
                    }
                    None => {
                        excluded_identifiers.insert(id);
                    }
                }
            }

            scopes.push(ScopeRecord {
                name: sname,
                urls,
                access,
                members,
                credentials,
                excluded_users,
                excluded_identifiers,
            });
        }
        if scopes.is_empty() {
            eprintln!(
                "[bb-auth] WARNING: application '{name}' has no scopes: every URL in its area \
                 is denied to everyone"
            );
        }
        apps.push(AppRecord {
            name,
            base,
            login_url,
            denied_url,
            scopes,
        });
    }

    // Keys last: a key's restriction names scopes, so the scopes have to exist first.
    let known_scopes: HashSet<String> = apps
        .iter()
        .flat_map(|a| a.scopes.iter().map(|s| format!("{}/{}", a.name, s.name)))
        .collect();
    let mut by_key_hash = HashMap::new();
    for u in &file.users {
        let uuid = u.uuid.trim().to_ascii_lowercase();
        for k in &u.api_keys {
            let key_id = if k.id.trim().is_empty() {
                "?".to_string()
            } else {
                k.id.trim().to_string()
            };
            // A field nobody here knows. It is `notes` in the ordinary case and a typo in
            // the case worth catching: `scope` for `scopes` widens a key to everything its
            // owner reaches, `expires` for `duration` makes it immortal, and both do it
            // without a word. See [`ApiKeySpec`] for why this warns rather than refuses.
            for name in k.extra.keys().filter(|n| n.as_str() != "notes") {
                eprintln!(
                    "[bb-auth] WARNING: {uuid} key '{key_id}': unknown field '{name}' is \
                     ignored (a misspelled 'scopes' or 'duration' widens the key)"
                );
            }
            let hash = k.key_hash.trim().to_ascii_lowercase();
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                eprintln!("[bb-auth] WARNING: {uuid} key '{key_id}': invalid key_hash, skipping");
                continue;
            }
            let expires = match key_expiry(&k.released, &k.duration) {
                Some(e) => e,
                None => {
                    eprintln!(
                        "[bb-auth] WARNING: {uuid} key '{key_id}': bad released/duration, skipping"
                    );
                    continue;
                }
            };
            // Fatal, unlike the two above: a restriction naming a scope that does not
            // exist fails closed, but it fails closed *silently*, and an operator who
            // mistyped one would find out only when the machine using the key stopped
            // working for no visible reason.
            let scopes = match &k.scopes {
                None => None,
                Some(list) => {
                    let mut set = HashSet::new();
                    for r in list.iter().map(|r| r.trim()).filter(|r| !r.is_empty()) {
                        if !known_scopes.contains(r) {
                            return Err(format!(
                                "{uuid} key '{key_id}': '{r}' names no scope (a restriction is \
                                 written \"application/scope\")"
                            ));
                        }
                        set.insert(r.to_string());
                    }
                    Some(set)
                }
            };
            by_key_hash.insert(
                hash,
                ApiKeyRecord {
                    uuid: uuid.clone(),
                    key_id,
                    expires,
                    scopes,
                },
            );
        }
    }

    // `denied` last, so an identifier can be resolved against the roster and folded into
    // the uuid set: denying one email of a user must veto the user, not one way in.
    let mut denied_users: HashSet<String> = HashSet::new();
    let mut denied_identifiers: HashSet<String> = HashSet::new();
    for raw in &file.denied {
        let d = raw.trim();
        if d.is_empty() {
            continue;
        }
        let lower = d.to_ascii_lowercase();
        if well_formed_uuid(&lower) {
            if !by_uuid.contains_key(&lower) {
                eprintln!(
                    "[bb-auth] WARNING: denied lists {lower}, which is in no users entry: a \
                     stranger has no uuid, so this vetoes nobody"
                );
            }
            denied_users.insert(lower);
            continue;
        }
        // A veto that vetoes nobody while reading as if it did is the one failure this
        // section cannot afford, so an entry that is neither a uuid nor an identifier is
        // refused rather than kept as a string nothing will ever equal.
        if !d.contains('@') {
            return Err(format!(
                "denied '{d}': not a uuid and not an email. A veto names a user by uuid, or \
                 an identity the roster does not know by its email"
            ));
        }
        match by_identifier.get(&lower) {
            Some(uuid) => {
                denied_users.insert(uuid.clone());
            }
            None => {
                denied_identifiers.insert(lower);
            }
        }
    }
    for uuid in &denied_users {
        if by_uuid.contains_key(uuid) {
            eprintln!(
                "[bb-auth] WARNING: {uuid} is in users and in denied: denied wins, on every \
                 credential and every scope"
            );
        }
    }

    Ok(Access {
        apps,
        denied_users,
        denied_identifiers,
        by_identifier,
        by_uuid,
        by_key_hash,
    })
}
