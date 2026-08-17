//! bb-auth-core — **the access file**: its schema, its parser, the URL matcher every
//! check goes through, and the authorization decision itself.
//!
//! This library exists for exactly one reason: there are two programs that must agree,
//! byte for byte, on what an access file *means*.
//!
//! * `bb-auth`, the gate, reads it on every `/auth/validate` ([`read_access`], [`decide`]).
//! * `bb-auth-adm`, the admin CLI, edits it — and must never write a file the gate would
//!   reject, nor believe it granted something the gate will not.
//!
//! A second parser, or a second matcher, would be a second answer to "who may reach
//! what". So there is one of each, and it lives here. The gate keeps everything the
//! access file has no opinion about — HTTP, the session cookie, id_token validation,
//! the nginx contract — in its own single file, and `bb-auth-adm` links nothing of it.
//!
//! The same argument reaches one step further than the meaning of a file: **how an access
//! file is edited and written** ([`AccessWrite`], [`open_access_file`], and the document
//! mutations beside them) is also something more than one program has to get right byte
//! for byte — `bb-auth-adm` today, a web admin next. Validate-before-write, atomic
//! replace, mode and owner preserved: one implementation, here.
//!
//! # What is in an access file
//!
//! Four sibling sections answering four different questions ([`AccessFile`]):
//! `applications` describe places and who may reach them ([`AppRecord`], [`ScopeRecord`]),
//! `user_groups` names a reusable set of people, `denied` vetoes people, `users` is the
//! roster of identities.
//!
//! The model is **application-centric**, and that is the whole shape of it: a grant is
//! written once, on the side of the place. An application owns a literal URL area and a
//! list of named scopes; a scope owns URL patterns and one access policy; a user owns a
//! UUID, identifiers and keys, and no URL at all. Asking "who reaches this application?"
//! and "what does this application expose?" are both one lookup, which is what the
//! previous user-centric shape made a scan of the whole roster.
//!
//! Access is **enumerated, never assumed**: a URL no application covers is reachable by
//! nobody, a scope that lists nobody grants to nobody, and the veto in `denied` outranks
//! every grant on every credential. [`decide`] is that rule, and it is the only one.

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Namespace prefix marking a static API-key bearer credential (vs a Cognito
/// id_token JWT): `Authorization: Bearer bbk_<secret>`.
pub const API_KEY_PREFIX: &str = "bbk_";

/// Current Unix time in seconds, saturating to 0 if the clock predates the epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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

/// A compiled URL pattern (`authorized_urls`, or a site's `urls`): normalised bytes.
#[derive(Clone)]
pub struct UrlPattern {
    pat: Vec<u8>,
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

/// Validate a login URL — `BB_AUTH_LOGIN_URL` or a site's `login_url`. Both end up in a
/// `Location:` header, in `X-Auth-Login-URL`, and inside a page, so this is what makes
/// those emissions safe with no per-use check: printable ASCII forbids CR/LF and spaces.
///
/// https-only, and no userinfo `@` or backslash in the authority — the same lookalike
/// tricks the gate's `rd_url_allowed` rejects, since a login page is where a rejected
/// `rd` lands.
///
/// It is **not** checked against `BB_AUTH_AUTHORIZED_HOSTS`, and cannot be: [`read_access`]
/// reads no env, which is exactly what lets `bb-auth --check-users` validate a file with no
/// config and no network. Moving the check to startup would turn an operator's typo into a
/// fatal boot under `Restart=on-failure` that `--check-users` never saw coming.
pub fn compile_login_url(raw: &str) -> Result<String, String> {
    let e = |m: &str| Err(format!("login_url '{raw}': {m}"));
    let u = raw.trim();
    if u.is_empty() {
        return e("empty");
    }
    if !u.bytes().all(|b| b.is_ascii_graphic()) {
        return e("must be printable ASCII (no spaces, no control bytes)");
    }
    let rest = match u.strip_prefix("https://") {
        Some(r) => r,
        None => return e("must be an absolute https:// URL"),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return e("empty host");
    }
    if authority.contains('@') {
        return e("userinfo '@' is not allowed in the host");
    }
    if u.contains('\\') {
        return e("backslash is not allowed");
    }
    Ok(u.to_string())
}

/// Validate and normalise one `BB_AUTH_AUTHORIZED_HOSTS` entry: a host-only glob
/// (`badbat75.com`, `*.badbat75.com`, `v&.badbat75.com`). No scheme, no path, no port
/// — the gate's `rd_url_allowed` strips those from the candidate before matching.
///
/// Env, not access file — but it compiles to the same [`UrlPattern`] and is matched by the
/// same [`glob_match`], which is the point: one wildcard grammar, one implementation.
pub fn compile_host_pattern(raw: &str) -> Result<UrlPattern, String> {
    let e = |m: &str| Err(format!("host pattern '{raw}': {m}"));
    let h = raw.trim().to_ascii_lowercase();
    if h.is_empty() {
        return e("empty");
    }
    if h.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return e("contains a control byte");
    }
    if h.contains('/') || h.contains(':') {
        return e("must be a bare host — no scheme, port or path");
    }
    if h.contains('@') || h.contains("..") {
        return e("must not contain '@' or '..'");
    }
    Ok(UrlPattern {
        pat: h.into_bytes(),
    })
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
    /// The empty scope: authorizes no URL at all. What an absent `authorized_urls`
    /// resolves to.
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
/// A scope names people, which the sites it replaces were forbidden to do. That rule
/// forbade *duplication*, not direction: it existed so a user removed from the roster
/// could not still walk in through a place. Here the grant is written on the side of the
/// place and nowhere else, so the rule holds in the mirror: [`ScopeRecord::members`] are
/// references to roster rows, and a reference to a row that does not exist grants nothing.
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
/// There is no ambiguity to resolve here any more. Areas do not overlap, so at most one
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
/// useful question is no longer "was it granted?" but "which scope answered, and what did
/// it want?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// An `anonymous` scope covers the URL: no credential was needed and none was
    /// consulted.
    Anonymous { app: String, scope: String },
    /// The scope that answered admits this subject.
    Granted { app: String, scope: String },
    /// `denied` vetoes this subject, ahead of every grant and on every credential.
    Vetoed,
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
/// 3. The veto, on every remaining credential.
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
/// { "version": 3,
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
/// `bb-auth --check-users <file>`, or `bb-auth-adm check`: the same parser,
/// [`read_access`].
///
/// This type is also the **document model** `bb-auth-adm` edits, hence [`Serialize`] and
/// the `extra` maps: the sections that describe people carry operator documentation
/// (`_comment`, `notes`) that an edit must not eat. [`compile_access`] is what turns a
/// document into the runtime table, so a tool that writes one can ask, before saving,
/// exactly what the gate will make of it.
///
/// The env var (`BB_AUTH_USERS_FILE`) and the CLI flag keep their pre-`sites` names: both
/// are contracts with an operator-owned env file that a deploy never rewrites.
#[derive(Deserialize, Serialize, Default)]
pub struct AccessFile {
    /// The format this file is written in. **Required**, and the only accepted value is
    /// `3`.
    ///
    /// It is here so that a version mismatch is a sentence rather than a puzzle. The
    /// older file this format replaces carries no `version` at all and fails on its own
    /// sections anyway (see [`AccessFile::sites`]), but "this file predates bb-auth 3.0,
    /// convert it with `bb-auth-adm migrate`" is a different quality of error from a type
    /// mismatch three levels down, and every future migration gets the same courtesy for
    /// free.
    #[serde(default)]
    pub version: u32,
    /// The places, and who reaches them. See [`AppRecord`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<AppSpec>,
    /// Named sets of roster uuids: `"admins": ["8f14e45f-…"]`, written `"@admins"` in a
    /// scope's `groups`.
    ///
    /// Abbreviation, never a grant: defining one authorizes nobody until a scope names it.
    /// Deliberately shallow and deliberately strict, the reflex the older `url_groups`
    /// carried: a name is `[A-Za-z0-9_-]+` matched exactly, a group may not reference
    /// another group, an unknown reference is fatal, and every group is validated even
    /// when nothing references it (a group that only breaks the day someone first uses it
    /// is a trap `--check-users` never saw). Duplicate JSON keys are serde's last-wins, as
    /// everywhere else in this file.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_groups: BTreeMap<String, Vec<String>>,
    /// Uuids and bare identifiers, vetoed ahead of every grant. See
    /// [`Access::denied_users`] and [`Access::denied_identifiers`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<String>,
    #[serde(default)]
    pub users: Vec<UserSpec>,
    /// The pre-3.0 sites section. Its mere presence is a fatal parse error naming the
    /// converter, exactly as [`UserSpec::enabled_paths`] is: a new binary that silently
    /// ignored it would read an older file as an empty access table, which is a total
    /// lockout dressed up as a successful load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sites: Option<Value>,
    /// The pre-3.0 url_groups section. Fatal if present, for the reason [`AccessFile::sites`]
    /// is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_groups: Option<Value>,
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
/// `bb-auth --check-users` catches it instead, before the restart.
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
    /// Operator documentation, round-tripped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// One roster entry: an identity, its identifiers, and its keys. Extra fields are ignored
/// (and preserved on a rewrite), with two deliberate exceptions.
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
    /// The pre-2.0 path-prefix field. Its mere presence is a fatal parse error rather
    /// than an ignored extra: under the old semantics an unscoped user reached
    /// everything, so silently dropping it would fail *open*. See [`compile_access`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_paths: Option<Value>,
    /// The pre-3.0 per-user scope. Fatal if present, for the same reason: a new binary
    /// that ignored it would silently read an older roster as a set of users who reach
    /// nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_urls: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_keys: Vec<ApiKeySpec>,
    /// `notes` and anything else an operator wrote here. Round-tripped untouched.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One static API key belonging to a [`UserSpec`]. The `bbk_` bearer itself never
/// appears here, only `key_hash`. Mint keys with `bb-auth-adm key add`.
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
    /// Fatal if present, exactly as on [`UserSpec::enabled_paths`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_paths: Option<Value>,
    /// The pre-3.0 per-key scope. Fatal if present, as on [`UserSpec::authorized_urls`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_urls: Option<Value>,
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
/// * the gate's `validate_id_token`, for every email lifted out of a Cognito claim. A
///   `public_auth` site emits identities that are in no table, so load time cannot see
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
    getrandom::getrandom(&mut secret).map_err(|e| format!("no entropy from the OS: {e}"))?;
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
/// `bb-auth --check-users` and `bb-auth-adm` validate with.
pub fn read_access(path: &str) -> Result<Access, String> {
    compile_access(&read_access_file(path)?)
}

/// The one spelling a name may have, anywhere in this file: non-empty `[A-Za-z0-9_-]`.
///
/// No `/`, which is what lets `app/scope` be a name in its own right: the string a log
/// line prints, a key's restriction lists, and an editor addresses a scope by.
fn valid_name(name: &str) -> bool {
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
/// whole point of `--check-users` is that the file is checked before it is live.
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

/// Refuse a file written for an older bb-auth, by name and with the way out.
///
/// Every one of these fields would otherwise be *ignored*, and that is the danger: an
/// older file read by this binary would compile to an access table with no applications
/// and a roster that reaches nothing, which is a total lockout reported as a successful
/// load. The same reflex the pre-2.0 `enabled_paths` field has carried since 2.0, extended
/// to the sections 3.0 replaces.
fn check_legacy(file: &AccessFile) -> Result<(), String> {
    let stale = |what: &str| {
        Err(format!(
            "'{what}' is a pre-3.0 access file field. This binary reads version \
             {ACCESS_FILE_VERSION} (applications and scopes); convert the file with: \
             bb-auth-adm migrate"
        ))
    };
    if file.sites.is_some() {
        return stale("sites");
    }
    if file.url_groups.is_some() {
        return stale("url_groups");
    }
    for u in &file.users {
        let who = if u.uuid.trim().is_empty() {
            "users entry".to_string()
        } else {
            u.uuid.trim().to_string()
        };
        if u.enabled_paths.is_some() {
            return Err(format!(
                "{who}: 'enabled_paths' is no longer supported; access is granted by an \
                 application scope that lists this user"
            ));
        }
        if u.authorized_urls.is_some() {
            return Err(format!("{who}: {}", stale("authorized_urls").unwrap_err()));
        }
        for k in &u.api_keys {
            if k.enabled_paths.is_some() || k.authorized_urls.is_some() {
                return Err(format!(
                    "{who} key '{}': a key carries no urls of its own; it names the scopes it \
                     may exercise. Convert the file with: bb-auth-adm migrate",
                    k.id
                ));
            }
        }
    }
    if file.version != ACCESS_FILE_VERSION {
        return Err(match file.version {
            0 => format!(
                "this file has no 'version'. bb-auth {ACCESS_FILE_VERSION}.x access files \
                 declare \"version\": {ACCESS_FILE_VERSION}"
            ),
            v => format!(
                "this file declares version {v}; this binary reads version \
                 {ACCESS_FILE_VERSION}"
            ),
        });
    }
    Ok(())
}

/// The one access-file format this binary reads. See [`AccessFile::version`].
pub const ACCESS_FILE_VERSION: u32 = 3;

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
/// closed *loudly*, before the restart, which is what `bb-auth --check-users` is for and
/// what makes a SIGHUP reload keep the old table; the second fails closed quietly, because
/// dropping one credential is exactly what an operator would want it to do.
///
/// Emails are additionally required to be [`header_safe_email`], since every one of them
/// can end up in an identity header.
pub fn compile_access(file: &AccessFile) -> Result<Access, String> {
    check_legacy(file)?;

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

            scopes.push(ScopeRecord {
                name: sname,
                urls,
                access,
                members,
                credentials,
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

// ---------------------------------------------------------------------------
// Editing an access file
// ---------------------------------------------------------------------------
//
// The membership rule, one step further than the sections above. Those are what an access
// file *means*; this is how one is edited and written — and it is here for the same reason
// the parser is: two programs must agree on it byte for byte. `bb-auth-adm` today, a web
// admin next. The write order (render → re-parse → compile → replace, atomically, with the
// mode and owner of the file being replaced) is not something either of them may re-invent,
// and neither is what a mutation refuses to do.
//
// Nothing here prints, and nothing here reads a flag or an env var: an operator-facing
// string belongs to whichever program has an operator. What comes back is a
// `Result<_, String>` naming the refusal — its wording is the refusal itself, so every
// caller reports the same reason, and the caller decides where to put it.

/// Open an access file for editing: the document to mutate, and the table the gate would
/// build from it as it stands.
///
/// A file the gate would reject is refused here too — an edit must start from a file that
/// works, or a tool would cheerfully fix one problem while carrying a fatal one to the
/// disk. Both halves come back because compiling is also what *emits* the parser's warnings
/// ("this user reaches nothing"), and an operator should hear each of those once, not once
/// per look.
pub fn open_access_file(path: &str) -> Result<(AccessFile, Access), String> {
    let doc = read_access_file(path)?;
    let access = compile_access(&doc)
        .map_err(|e| format!("{path}: the gate would reject this file as it stands: {e}"))?;
    Ok((doc, access))
}

/// Serialize a document to the exact bytes an access file is written as: pretty JSON plus
/// one trailing newline. The error is serde's own, unadorned.
pub fn render_access_file(doc: &AccessFile) -> Result<String, String> {
    let mut json = serde_json::to_string_pretty(doc).map_err(|e| e.to_string())?;
    json.push('\n');
    Ok(json)
}

/// An edited document, rendered to the exact bytes it would be written as, and already
/// compiled with the gate's own parser.
///
/// This type *is* the write order, made unskippable. The only way to obtain one is
/// [`AccessWrite::prepare`], which compiles; the only thing [`AccessWrite::commit`] puts on
/// disk is the byte string that was compiled; and `write_atomically` is private to this
/// crate so there is no other door. Nothing can slip in between the check and the write,
/// and no tool can write an access file that was not checked — a file the gate refuses at
/// startup is a boot loop under `Restart=on-failure`, and an editor is one of the only two
/// places (with `bb-auth --check-users`) that can catch it in time.
pub struct AccessWrite {
    json: String,
    access: Access,
}

impl AccessWrite {
    /// Render `doc`, then re-parse and compile the rendered text. `Err` means these bytes
    /// must not reach the disk, and says why.
    ///
    /// The round-trip through serde is not paranoia: what is checked has to be the byte
    /// string that lands on disk, not the document it came from.
    pub fn prepare(doc: &AccessFile) -> Result<AccessWrite, String> {
        let json = render_access_file(doc).map_err(|e| format!("cannot serialize: {e}"))?;
        let reparsed: AccessFile =
            serde_json::from_str(&json).map_err(|e| format!("serialized to invalid JSON: {e}"))?;
        let access = compile_access(&reparsed).map_err(|e| format!("refusing to write: {e}"))?;
        Ok(AccessWrite { json, access })
    }

    /// The bytes: what a dry run prints, and exactly what [`AccessWrite::commit`] writes.
    pub fn json(&self) -> &str {
        &self.json
    }

    /// The table the gate will build from those bytes — where a caller reads the counts it
    /// reports back ("N users, N api keys, …").
    pub fn access(&self) -> &Access {
        &self.access
    }

    /// Replace `path` with these bytes. The file must already exist: its mode and owner are
    /// what the replacement inherits.
    pub fn commit(&self, path: &str) -> Result<Written, String> {
        write_atomically(path, &self.json)
    }
}

/// What a completed write hands back — and the proof that there *was* one, which is what
/// [`SealedKey::reveal`] asks for.
pub struct Written {
    /// The copy of the file that was replaced, kept one step back. The gate is stateless,
    /// but a roster is not reconstructible.
    pub backup: std::path::PathBuf,
}

/// Write `content` over `path`: a temp file in the same directory, then a rename.
///
/// Private on purpose: [`AccessWrite::commit`] is the only way in, so nothing can write an
/// access file the gate has not already accepted.
///
/// Mode and owner are copied from the file being replaced, and that is not cosmetic. The
/// live access file is `root:bb-auth 0640`; a rewrite by root that left it `root:root`
/// would be unreadable to the service, and the gate would die on its next start — a lockout
/// dressed up as a successful edit. So a failed `chown` aborts the write rather than warning
/// about it: nothing is renamed, and the old file stays intact.
fn write_atomically(path: &str, content: &str) -> Result<Written, String> {
    let p = std::path::Path::new(path);
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty());
    // One temp name, whoever is writing: two editors racing would then contend for the same
    // temp file rather than each renaming its own over the other's work.
    let tmp = match dir {
        Some(d) => d.join(format!(
            ".{}.bb-auth-adm.tmp",
            p.file_name().unwrap_or_default().to_string_lossy()
        )),
        None => std::path::PathBuf::from(format!(".{path}.bb-auth-adm.tmp")),
    };

    let meta = std::fs::metadata(p).map_err(|e| format!("stat {path}: {e}"))?;
    // Keep one step back. The gate is stateless, but a roster is not reconstructible.
    let bak = format!("{path}.bak");
    std::fs::copy(p, &bak).map_err(|e| format!("backup {bak}: {e}"))?;

    std::fs::write(&tmp, content).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    let restore = |e: String| {
        let _ = std::fs::remove_file(&tmp);
        e
    };
    std::fs::set_permissions(&tmp, meta.permissions())
        .map_err(|e| restore(format!("chmod {}: {e}", tmp.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (uid, gid) = (meta.uid(), meta.gid());
        let c = std::ffi::CString::new(tmp.to_string_lossy().as_bytes())
            .map_err(|e| restore(format!("path: {e}")))?;
        // SAFETY: a NUL-terminated path we just created, and two ids read off the file we
        // are replacing.
        if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
            return Err(restore(format!(
                "cannot restore owner {uid}:{gid} on {} ({}) — not writing, the old file is \
                 untouched. Re-run as root.",
                tmp.display(),
                std::io::Error::last_os_error()
            )));
        }
    }
    std::fs::rename(&tmp, p).map_err(|e| restore(format!("rename onto {path}: {e}")))?;
    Ok(Written {
        backup: std::path::PathBuf::from(bak),
    })
}

// --- lookups over the document ---------------------------------------------

/// Emails are matched the way the gate matches them: trimmed and lowercased.
pub fn norm_email(e: &str) -> String {
    e.trim().to_ascii_lowercase()
}

/// The URL as the gate will see it on `/auth/validate`: query and fragment stripped (nginx
/// sends `$uri`), authority lowercased. Comparing anything else would be answering a
/// different question from the one the gate answers.
///
/// Here rather than in a tool for that reason: it is a statement about *which* URL an
/// access file's patterns are matched against, so every program that asks "would this get
/// in?" — `bb-auth-adm can`, the web admin's tester — has to normalise it identically, the
/// same way they all share one matcher and one [`decide`].
pub fn request_url(url: &str) -> String {
    lower_authority(url.split(['?', '#']).next().unwrap_or(""))
}

/// The roster position of a user named by **either** key: their uuid, or any of their
/// emails.
///
/// Both, on purpose. The file references a user by uuid and only by uuid, but an operator
/// types an email, and a tool that made them paste a uuid to remove a person would be a
/// tool nobody uses. The uuid is tried first: it is the identity, and an email is only a
/// way to find it.
pub fn user_pos(doc: &AccessFile, key: &str) -> Option<usize> {
    let want = norm_email(key);
    doc.users
        .iter()
        .position(|u| u.uuid.trim().to_ascii_lowercase() == want)
        .or_else(|| {
            doc.users
                .iter()
                .position(|u| u.emails.iter().any(|e| norm_email(e) == want))
        })
}

/// The roster row named by uuid or email, to edit in place.
pub fn user_mut<'a>(doc: &'a mut AccessFile, key: &str) -> Result<&'a mut UserSpec, String> {
    match user_pos(doc, key) {
        Some(i) => Ok(&mut doc.users[i]),
        None => Err(format!(
            "no user '{}' (add them with: user add {})",
            key.trim(),
            key.trim()
        )),
    }
}

/// How a user is named back to an operator: their primary email if they have one, else
/// their uuid. Every message about a user goes through here, so a row with no email is
/// still nameable instead of being reported as an empty string.
pub fn user_label(u: &UserSpec) -> String {
    match u
        .emails
        .iter()
        .map(|e| norm_email(e))
        .find(|e| !e.is_empty())
    {
        Some(e) => e,
        None => u.uuid.trim().to_ascii_lowercase(),
    }
}

/// One user's API keys, by `id` (trimmed, case-sensitive: an id is a label, not an
/// address).
pub fn key_mut<'a>(
    doc: &'a mut AccessFile,
    key: &str,
    id: &str,
) -> Result<&'a mut ApiKeySpec, String> {
    let u = user_mut(doc, key)?;
    let owner = user_label(u);
    match u.api_keys.iter().position(|k| k.id.trim() == id.trim()) {
        Some(i) => Ok(&mut u.api_keys[i]),
        None => Err(format!("{owner}: no api key '{id}'")),
    }
}

/// The position of the application named `name`.
pub fn app_pos(doc: &AccessFile, name: &str) -> Option<usize> {
    doc.applications
        .iter()
        .position(|a| a.name.trim() == name.trim())
}

/// The application named `name`, to edit in place.
pub fn app_mut<'a>(doc: &'a mut AccessFile, name: &str) -> Result<&'a mut AppSpec, String> {
    match app_pos(doc, name) {
        Some(i) => Ok(&mut doc.applications[i]),
        None => Err(format!("no application '{}'", name.trim())),
    }
}

/// The position of `scope` inside `app`. A position, not a reference, because scope order
/// is meaning ([`AppRecord::scopes`]) and every caller ends up needing the index.
pub fn scope_pos(app: &AppSpec, scope: &str) -> Option<usize> {
    app.scopes
        .iter()
        .position(|s| s.name.trim() == scope.trim())
}

/// One scope of one application, to edit in place.
pub fn scope_mut<'a>(
    doc: &'a mut AccessFile,
    app: &str,
    scope: &str,
) -> Result<&'a mut ScopeSpec, String> {
    let a = app_mut(doc, app)?;
    match scope_pos(a, scope) {
        Some(i) => Ok(&mut a.scopes[i]),
        None => Err(format!("{}/{}: no such scope", app.trim(), scope.trim())),
    }
}

/// A user group's member list, to edit in place.
pub fn user_group_mut<'a>(
    doc: &'a mut AccessFile,
    name: &str,
) -> Result<&'a mut Vec<String>, String> {
    let name = name.trim();
    doc.user_groups
        .get_mut(name)
        .ok_or_else(|| format!("no user group '@{name}'"))
}

/// Every scope that names `@name`, as `application/scope`.
///
/// [`group_ref`] is what decides whether an entry is a reference, so this cannot drift
/// from what [`compile_access`] expands. The gate would refuse a file with a dangling
/// reference anyway ([`AccessWrite::prepare`] compiles before anything is written), and
/// this is what turns that refusal into a list of places to go and fix.
pub fn user_group_refs(doc: &AccessFile, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for a in &doc.applications {
        for s in &a.scopes {
            if s.groups
                .iter()
                .flatten()
                .any(|g| group_ref(g) == Some(name.trim()))
            {
                out.push(format!("{}/{}", a.name.trim(), s.name.trim()));
            }
        }
    }
    out
}

/// Every place that names `uuid`: scopes as `application/scope`, groups as `@name`.
///
/// What [`remove_user`] sweeps, and what an editor shows before it does. A dangling
/// reference only warns at load, so nothing breaks if one survives; leaving one behind
/// would still be an editor quietly writing a file it knows is wrong.
pub fn user_refs(doc: &AccessFile, uuid: &str) -> Vec<String> {
    let want = norm_email(uuid);
    let mut out = Vec::new();
    for a in &doc.applications {
        for s in &a.scopes {
            if s.users.iter().flatten().any(|u| norm_email(u) == want) {
                out.push(format!("{}/{}", a.name.trim(), s.name.trim()));
            }
        }
    }
    for (name, members) in &doc.user_groups {
        if members.iter().any(|m| norm_email(m) == want) {
            out.push(format!("@{name}"));
        }
    }
    out
}

/// Apply the standard scope edits to an `authorized_urls` field: a full replacement
/// (`set`), then `add` (deduplicated) and `rm`. Returns `true` if anything changed.
///
/// `None` means "absent". For a user that is deny-all; for a key it means "inherit the
/// owner's" — two different things, so `clear` says which one the caller wants an emptied
/// list to collapse to.
pub fn edit_urls(
    urls: &mut Option<Vec<String>>,
    set: Vec<String>,
    add: Vec<String>,
    rm: Vec<String>,
    clear: bool,
) -> bool {
    let mut changed = false;
    if clear {
        *urls = None;
        changed = true;
    }
    if !set.is_empty() {
        *urls = Some(set);
        changed = true;
    }
    if !add.is_empty() {
        let list = urls.get_or_insert_with(Vec::new);
        for u in add {
            if !list.iter().any(|x| x == &u) {
                list.push(u);
                changed = true;
            }
        }
    }
    if !rm.is_empty() {
        if let Some(list) = urls.as_mut() {
            let before = list.len();
            list.retain(|x| !rm.iter().any(|r| r == x));
            changed |= list.len() != before;
        }
    }
    changed
}

/// [`edit_urls`] over a plain list — a site's `urls`, a url group's patterns. There is no
/// "inherit" to fall back to in either, so a cleared list is empty, never absent.
pub fn edit_url_list(
    urls: &mut Vec<String>,
    set: Vec<String>,
    add: Vec<String>,
    rm: Vec<String>,
    clear: bool,
) -> bool {
    let mut opt = Some(std::mem::take(urls));
    let changed = edit_urls(&mut opt, set, add, rm, clear);
    *urls = opt.unwrap_or_default();
    changed
}

// --- document mutations ----------------------------------------------------

/// The refusal every mutation that lets a **new** email into the file makes, in one
/// sentence. Only new values: an address already in the file is never re-checked, so a
/// legacy row does not block the edits around it.
fn check_new_email(email: &str) -> Result<(), String> {
    if well_formed_email(email) {
        return Ok(());
    }
    Err(format!(
        "'{email}' does not look like an email address (LOCAL@DOMAIN with a dotted domain, \
         like bob@example.com) — it could never match a Cognito identity"
    ))
}

/// A fresh identity: 122 random bits from the OS CSPRNG, in the canonical lowercase
/// 8-4-4-4-12 form (a version 4 UUID).
///
/// Minted here rather than typed by an operator, because the value has no meaning to
/// read: it exists to be stable, unique and never reused. The same entropy source that
/// mints an API key, and no new dependency for a value that is sixteen bytes and a
/// format string.
pub fn mint_uuid() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| format!("no entropy from the OS: {e}"))?;
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// Enrol `user`. A uuid is minted when the row carries none, every email is normalised on
/// the way in and must look like one ([`well_formed_email`]): a typo here is a dead
/// identifier that fails closed and is found only by the human it locks out.
///
/// Refuses a row whose uuid or any of whose emails is already in the file. The gate is
/// fatal on both, so this is the same refusal made earlier and with a better sentence.
pub fn add_user(doc: &mut AccessFile, mut user: UserSpec) -> Result<(), String> {
    user.uuid = match user.uuid.trim() {
        "" => mint_uuid()?,
        u => {
            let u = u.to_ascii_lowercase();
            if !well_formed_uuid(&u) {
                return Err(format!(
                    "'{u}' is not a uuid (canonical lowercase 8-4-4-4-12); leave it out and one \
                     is minted"
                ));
            }
            u
        }
    };
    if user_pos(doc, &user.uuid).is_some() {
        return Err(format!("{} is already in users", user.uuid));
    }
    let mut emails = Vec::with_capacity(user.emails.len());
    for raw in &user.emails {
        let e = norm_email(raw);
        check_new_email(&e)?;
        if user_pos(doc, &e).is_some() {
            return Err(format!("{e} already belongs to another user"));
        }
        if emails.contains(&e) {
            return Err(format!("{e} is listed twice"));
        }
        emails.push(e);
    }
    user.emails = emails;
    doc.users.push(user);
    Ok(())
}

/// Give a user another identifier, which must look like an email ([`well_formed_email`])
/// and must belong to nobody yet. `Ok(false)` means they already had it.
///
/// This is what a "rename" became. An identity is the uuid and never changes, so changing
/// how someone signs in is adding an identifier and dropping the old one: two edits the
/// gate validates one by one, and nothing in the file has to be re-pointed either time.
pub fn add_user_email(doc: &mut AccessFile, key: &str, email: &str) -> Result<bool, String> {
    let e = norm_email(email);
    match user_pos(doc, &e) {
        Some(i) if Some(i) == user_pos(doc, key) => return Ok(false),
        Some(_) => return Err(format!("{e} already belongs to another user")),
        None => {}
    }
    check_new_email(&e)?;
    user_mut(doc, key)?.emails.push(e);
    Ok(true)
}

/// Drop one identifier from a user. Refuses the last one: a row nobody can sign in as is
/// a row that only looks like a grant, and the way to retire a user is to remove or veto
/// them.
pub fn remove_user_email(doc: &mut AccessFile, key: &str, email: &str) -> Result<bool, String> {
    let want = norm_email(email);
    let u = user_mut(doc, key)?;
    if !u.emails.iter().any(|e| norm_email(e) == want) {
        return Ok(false);
    }
    if u.emails.len() == 1 {
        return Err(format!(
            "{want} is this user's only email; removing it would leave a row no credential can \
             ever resolve to"
        ));
    }
    u.emails.retain(|e| norm_email(e) != want);
    Ok(true)
}

/// Drop a user's row, every key it owned, and every reference to it. The removed row comes
/// back so a caller can say what went with it.
///
/// The sweep is the point, and it is new: with grants written on the side of the place, a
/// row can be named by any number of scopes and groups. A leftover reference grants
/// nothing (the gate warns and moves on), but an editor that knowingly left one would be
/// writing a file it knows is wrong, and the next person to read that scope would see a
/// member who does not exist.
pub fn remove_user(doc: &mut AccessFile, key: &str) -> Result<(UserSpec, Vec<String>), String> {
    let i = user_pos(doc, key).ok_or_else(|| format!("no user '{}'", key.trim()))?;
    let uuid = doc.users[i].uuid.trim().to_ascii_lowercase();
    let swept = user_refs(doc, &uuid);
    for a in &mut doc.applications {
        for s in &mut a.scopes {
            if let Some(list) = s.users.as_mut() {
                list.retain(|u| norm_email(u) != uuid);
            }
        }
    }
    for members in doc.user_groups.values_mut() {
        members.retain(|m| norm_email(m) != uuid);
    }
    Ok((doc.users.remove(i), swept))
}

/// A freshly minted `bbk_` bearer, sealed until the file that carries its hash is on disk.
///
/// The order is the whole point, and this type is what keeps it: the bearer comes out of
/// [`SealedKey::reveal`] and nowhere else, and `reveal` asks for the [`Written`] receipt of
/// a completed write. Handing it over any earlier would hand out a credential that
/// authorizes nothing if the write then failed — and the raw key exists nowhere to retry
/// from, since the file keeps only `sha256(bearer)` and that lookup *is* the verification.
///
/// No `Debug`, no `Clone`, no `Display`: a bearer leaves through `reveal` or not at all.
#[must_use = "a minted key nobody reveals is a key its owner never gets"]
pub struct SealedKey {
    bearer: String,
}

impl SealedKey {
    /// The raw bearer — to be shown to its owner **once**, and stored nowhere.
    ///
    /// The receipt is not read; being able to produce one is the point. A caller that has
    /// no [`Written`] — a dry run, or a write that failed — has no bearer to hand out, and
    /// that is exactly right: nothing on disk has ever heard of this key.
    pub fn reveal(self, _receipt: &Written) -> String {
        self.bearer
    }
}

/// Mint a `bbk_` bearer and file its hash on `email`'s row as `key`.
///
/// `key.key_hash` is overwritten with [`mint_api_key`]'s — the caller supplies the label,
/// the window and the scope, never the secret. The bearer comes back sealed; see
/// [`SealedKey`] for why it cannot be had before the write.
///
/// Refuses a second key with the same id: an id is what names a key in a log and in
/// `key rotate`, so two of them make a revocation ambiguous.
pub fn add_api_key(
    doc: &mut AccessFile,
    key_owner: &str,
    mut key: ApiKeySpec,
) -> Result<SealedKey, String> {
    let id = key.id.trim().to_string();
    let u = user_mut(doc, key_owner)?;
    let owner = user_label(u);
    if u.api_keys.iter().any(|k| k.id.trim() == id) {
        return Err(format!(
            "{owner} already has a key '{id}' (replace its secret: key rotate {owner} {id})"
        ));
    }
    let (bearer, hash) = mint_api_key()?;
    key.id = id;
    key.key_hash = hash;
    u.api_keys.push(key);
    Ok(SealedKey { bearer })
}

/// Same row, same scope, new secret, re-dated to today — the answer to a leaked key. The
/// old bearer stops working the moment the gate reloads.
pub fn rotate_api_key(doc: &mut AccessFile, email: &str, id: &str) -> Result<SealedKey, String> {
    let k = key_mut(doc, email, id)?;
    let (bearer, hash) = mint_api_key()?;
    k.key_hash = hash;
    k.released = format_date(now());
    Ok(SealedKey { bearer })
}

/// Revoke one key by id, handing back the row that went.
pub fn remove_api_key(
    doc: &mut AccessFile,
    key_owner: &str,
    id: &str,
) -> Result<ApiKeySpec, String> {
    let u = user_mut(doc, key_owner)?;
    let owner = user_label(u);
    let i = u
        .api_keys
        .iter()
        .position(|k| k.id.trim() == id.trim())
        .ok_or_else(|| format!("{owner}: no api key '{id}'"))?;
    Ok(u.api_keys.remove(i))
}

/// Add an application. A name is required and must be free: it is how every other command
/// addresses the record, and it is the left half of every `application/scope`.
///
/// Application order carries no meaning (areas do not overlap, so at most one can ever
/// answer), which is why this appends and there is no move.
pub fn add_application(doc: &mut AccessFile, mut app: AppSpec) -> Result<(), String> {
    app.name = app.name.trim().to_string();
    if !valid_name(&app.name) {
        return Err("an application needs a name of [A-Za-z0-9_-]".into());
    }
    if app_pos(doc, &app.name).is_some() {
        return Err(format!(
            "application '{}' already exists (edit it: app set {})",
            app.name, app.name
        ));
    }
    doc.applications.push(app);
    Ok(())
}

/// Rename an application, refusing a name another one already answers to.
///
/// Every key restriction that named `application/scope` is re-pointed with it: a
/// restriction is written as a string, and leaving one behind would silently narrow a key
/// to a scope that no longer exists.
pub fn rename_application(doc: &mut AccessFile, name: &str, new_name: &str) -> Result<(), String> {
    let i = app_pos(doc, name).ok_or_else(|| format!("no application '{}'", name.trim()))?;
    let new = new_name.trim().to_string();
    if !valid_name(&new) {
        return Err("an application name must be [A-Za-z0-9_-]".into());
    }
    if app_pos(doc, &new).is_some_and(|j| j != i) {
        return Err(format!("application '{new}' already exists"));
    }
    let old = doc.applications[i].name.trim().to_string();
    doc.applications[i].name = new.clone();
    for u in &mut doc.users {
        for k in &mut u.api_keys {
            for r in k.scopes.iter_mut().flatten() {
                if let Some(rest) = r.trim().strip_prefix(&format!("{old}/")) {
                    *r = format!("{new}/{rest}");
                }
            }
        }
    }
    Ok(())
}

/// Drop an application, handing back the record that went. Everything inside it goes with
/// it, so this can take away every way into a URL area at once.
pub fn remove_application(doc: &mut AccessFile, name: &str) -> Result<AppSpec, String> {
    let i = app_pos(doc, name).ok_or_else(|| format!("no application '{}'", name.trim()))?;
    Ok(doc.applications.remove(i))
}

/// Insert a scope into an application at `at` (`None` = last, out of range = last), and
/// hand back where it landed.
///
/// Position is not decoration: scopes are first match wins, so where a scope lands decides
/// which requests it ever sees.
pub fn add_scope(
    doc: &mut AccessFile,
    app: &str,
    mut scope: ScopeSpec,
    at: Option<usize>,
) -> Result<usize, String> {
    scope.name = scope.name.trim().to_string();
    if !valid_name(&scope.name) {
        return Err("a scope needs a name of [A-Za-z0-9_-]".into());
    }
    let a = app_mut(doc, app)?;
    if scope_pos(a, &scope.name).is_some() {
        return Err(format!(
            "{}/{} already exists (edit it: scope set {} {})",
            a.name.trim(),
            scope.name,
            a.name.trim(),
            scope.name
        ));
    }
    let at = at.unwrap_or(a.scopes.len()).min(a.scopes.len());
    a.scopes.insert(at, scope);
    Ok(at)
}

/// Rename a scope, refusing a name its application already answers to, and re-pointing
/// every key restriction that named it.
pub fn rename_scope(
    doc: &mut AccessFile,
    app: &str,
    name: &str,
    new_name: &str,
) -> Result<(), String> {
    let new = new_name.trim().to_string();
    if !valid_name(&new) {
        return Err("a scope name must be [A-Za-z0-9_-]".into());
    }
    let a = app_mut(doc, app)?;
    let app_name = a.name.trim().to_string();
    let i =
        scope_pos(a, name).ok_or_else(|| format!("{app_name}/{}: no such scope", name.trim()))?;
    if scope_pos(a, &new).is_some_and(|j| j != i) {
        return Err(format!("{app_name}/{new} already exists"));
    }
    let old = a.scopes[i].name.trim().to_string();
    a.scopes[i].name = new.clone();
    let (was, now) = (format!("{app_name}/{old}"), format!("{app_name}/{new}"));
    for u in &mut doc.users {
        for k in &mut u.api_keys {
            for r in k.scopes.iter_mut().flatten() {
                if r.trim() == was {
                    *r = now.clone();
                }
            }
        }
    }
    Ok(())
}

/// Move a scope inside its application, from `from` to `to`; a position that does not
/// exist is a no-op.
///
/// Order is meaning: scopes are first match wins, so this changes which scope answers for
/// a URL, and therefore who gets in. It is the one edit that changes behaviour without
/// changing a single field.
pub fn move_scope(doc: &mut AccessFile, app: &str, from: usize, to: usize) -> Result<(), String> {
    let a = app_mut(doc, app)?;
    if from >= a.scopes.len() || to >= a.scopes.len() {
        return Ok(());
    }
    let s = a.scopes.remove(from);
    a.scopes.insert(to, s);
    Ok(())
}

/// Drop one scope, handing back the record that went.
pub fn remove_scope(doc: &mut AccessFile, app: &str, name: &str) -> Result<ScopeSpec, String> {
    let a = app_mut(doc, app)?;
    let app_name = a.name.trim().to_string();
    let i =
        scope_pos(a, name).ok_or_else(|| format!("{app_name}/{}: no such scope", name.trim()))?;
    Ok(a.scopes.remove(i))
}

/// Define a user group. A group is abbreviation, not a grant: defining one authorizes
/// nobody until a scope names it `@name`.
///
/// There is deliberately no rename: a reference names a group by its exact spelling, so
/// renaming one would silently re-point every scope that used it. Add the new name, move
/// the references, drop the old one: three edits the gate re-validates one by one.
pub fn add_user_group(
    doc: &mut AccessFile,
    name: &str,
    members: Vec<String>,
) -> Result<(), String> {
    let name = name.trim().to_string();
    if !valid_name(&name) {
        return Err("a user group needs a name of [A-Za-z0-9_-]".into());
    }
    if doc.user_groups.contains_key(&name) {
        return Err(format!(
            "user group '@{name}' already exists (edit it: group set {name})"
        ));
    }
    doc.user_groups.insert(name, members);
    Ok(())
}

/// Drop a user group, refusing while a scope still references it: the gate would reject
/// the resulting file, and the refusal here says which scopes to fix instead of leaving a
/// write to fail.
pub fn remove_user_group(doc: &mut AccessFile, name: &str) -> Result<Vec<String>, String> {
    let name = name.trim().to_string();
    if !doc.user_groups.contains_key(&name) {
        return Err(format!("no user group '@{name}'"));
    }
    let refs = user_group_refs(doc, &name);
    if !refs.is_empty() {
        return Err(format!(
            "user group '@{name}' is still referenced by {}: the gate would reject the file. \
             Change those scopes first, then remove the group.",
            refs.join(", ")
        ));
    }
    Ok(doc.user_groups.remove(&name).unwrap_or_default())
}

/// Veto whoever `who` names: a uuid, an enrolled user's email, or the email of an identity
/// the roster has never heard of. `Ok(false)` means it was already vetoed.
///
/// An enrolled user is always written down as their **uuid**, whichever way they were
/// named. That is what makes the veto cover every identifier they have, now and later: an
/// email written here would go on vetoing one way in while the person kept another.
///
/// A stranger is written down as the email itself, and that is the whole reason `denied`
/// still accepts one. An `authenticated` scope admits identities in no table, so for them
/// this is the only denial that exists.
///
/// `Err` if the value is neither, because a veto that vetoes nobody while reading as if it
/// did is the one failure this section cannot afford.
pub fn add_denied(doc: &mut AccessFile, who: &str) -> Result<bool, String> {
    let want = norm_email(who);
    let entry = match user_pos(doc, &want) {
        Some(i) => doc.users[i].uuid.trim().to_ascii_lowercase(),
        None if well_formed_uuid(&want) => want,
        None => {
            check_new_email(&want)?;
            want
        }
    };
    if doc.denied.iter().any(|d| norm_email(d) == entry) {
        return Ok(false);
    }
    doc.denied.push(entry);
    Ok(true)
}

/// Lift the veto on everyone listed, by uuid or by email, returning how many rows went.
///
/// An email is resolved the same way [`add_denied`] resolves one, so a veto added as
/// `bob@x.com` and written down as his uuid is lifted by naming either.
pub fn remove_denied(doc: &mut AccessFile, who: &[String]) -> usize {
    let want: Vec<String> = who
        .iter()
        .map(|w| {
            let w = norm_email(w);
            match user_pos(doc, &w) {
                Some(i) => doc.users[i].uuid.trim().to_ascii_lowercase(),
                None => w,
            }
        })
        .collect();
    let before = doc.denied.len();
    doc.denied.retain(|d| !want.contains(&norm_email(d)));
    before - doc.denied.len()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_vector() {
        // canonical SHA-256("abc")
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn mint_api_key_is_namespaced_and_hashed() {
        let (raw, hash) = mint_api_key().unwrap();
        assert!(raw.starts_with(API_KEY_PREFIX));
        assert_eq!(hash, sha256_hex(&raw)); // the file stores only this half
        assert_eq!(hash.len(), 64);
        // A bearer must survive a header, a shell and a JSON string untouched.
        assert!(raw.bytes().all(|b| b.is_ascii_graphic()));
        assert!(!raw.contains(':') && !raw.contains('='));
        // 256 bits of entropy: two mints never collide.
        assert_ne!(raw, mint_api_key().unwrap().0);
    }

    #[test]
    fn parse_date_epoch_basic() {
        assert_eq!(parse_date_epoch("1970-01-01"), Some(0));
        assert_eq!(parse_date_epoch("1970-01-02"), Some(86_400));
        assert_eq!(parse_date_epoch("1972-01-01"), Some(730 * 86_400)); // 1970+1971 = 365*2
        assert!(parse_date_epoch("2026-07-08").is_some());
        assert_eq!(parse_date_epoch("2026-13-01"), None); // bad month
        assert_eq!(parse_date_epoch("2026-07-40"), None); // bad day
        assert_eq!(parse_date_epoch("notadate"), None);
        assert_eq!(parse_date_epoch("1969-12-31"), None); // before epoch
    }

    #[test]
    fn format_date_inverts_parse_date_epoch() {
        for d in ["1970-01-01", "2000-02-29", "2026-07-14", "2099-12-31"] {
            assert_eq!(format_date(parse_date_epoch(d).unwrap()), d);
        }
        // mid-day epochs floor to their date
        assert_eq!(format_date(86_400 + 3_600), "1970-01-02");
    }

    #[test]
    fn parse_duration_variants() {
        assert!(matches!(parse_duration("never"), Some(Dur::Never)));
        assert!(matches!(parse_duration("0"), Some(Dur::Never)));
        assert!(matches!(parse_duration("-"), Some(Dur::Never)));
        assert!(matches!(parse_duration(""), Some(Dur::Never)));
        assert!(matches!(parse_duration("365d"), Some(Dur::Secs(s)) if s == 365 * 86_400));
        assert!(matches!(parse_duration("24h"), Some(Dur::Secs(s)) if s == 24 * 3_600));
        assert!(matches!(parse_duration("7"), Some(Dur::Secs(s)) if s == 7 * 86_400)); // bare = days
        assert!(parse_duration("abc").is_none());
        assert!(parse_duration("10x").is_none());
    }

    #[test]
    fn key_expiry_computes() {
        assert_eq!(key_expiry("2026-01-01", "never"), Some(None));
        assert_eq!(key_expiry("1970-01-01", "1d"), Some(Some(86_400)));
        assert_eq!(key_expiry("1970-01-01", "0"), Some(None)); // 0 = never (date ignored)
        assert_eq!(key_expiry("bad", "1d"), None); // bad date with finite duration
        assert_eq!(key_expiry("2026-01-01", "xyz"), None); // bad duration
    }

    /// Compile one pattern and match `url` against it.
    fn m(pat: &str, url: &str) -> bool {
        compile_pattern(pat).expect("pattern compiles").matches(url)
    }

    #[test]
    fn glob_terminal_star_includes_slash() {
        // `https://pippo/path1/*` => everything under path1, at any depth …
        assert!(m("https://pippo/path1/*", "https://pippo/path1/"));
        assert!(m("https://pippo/path1/*", "https://pippo/path1/a"));
        assert!(m("https://pippo/path1/*", "https://pippo/path1/a/b/c.png"));
        // … but not the bare parent, and not a sibling
        assert!(!m("https://pippo/path1/*", "https://pippo/path1"));
        assert!(!m("https://pippo/path1/*", "https://pippo/path2/a"));
        // the classic prefix footgun, now closed: /mcp/* does not match /mcpEVIL
        assert!(!m("https://pippo/mcp/*", "https://pippo/mcpEVIL"));
    }

    #[test]
    fn glob_nonterminal_star_no_slash() {
        // `…/path1/*/` => exactly one level below path1, trailing slash required
        assert!(m("https://pippo/path1/*/", "https://pippo/path1/a/"));
        assert!(m("https://pippo/path1/*/", "https://pippo/path1/ab/"));
        assert!(!m("https://pippo/path1/*/", "https://pippo/path1/a"));
        assert!(!m("https://pippo/path1/*/", "https://pippo/path1/a/b/"));
    }

    #[test]
    fn glob_middle_star_segment() {
        // one wildcard level, then a fixed subtree, then anything
        let p = "https://pippo/path1/*/images/*";
        assert!(m(p, "https://pippo/path1/a/images/x.png"));
        assert!(m(p, "https://pippo/path1/a/images/sub/y.png"));
        assert!(!m(p, "https://pippo/path1/a/b/images/x.png")); // star can't cross '/'
        assert!(!m(p, "https://pippo/path1/a/other/x.png"));
    }

    #[test]
    fn glob_single_char_amp() {
        assert!(m("https://pippo/v&/*", "https://pippo/v1/x"));
        assert!(m("https://pippo/v&/*", "https://pippo/v9/x"));
        assert!(!m("https://pippo/v&/*", "https://pippo/v10/x")); // one char, not two
        assert!(!m("https://pippo/v&/*", "https://pippo/v/x")); // one char, not zero
    }

    #[test]
    fn glob_wildcard_in_scheme_and_host() {
        // scheme wildcard
        assert!(m("*://mcp.x.com/mcp/*", "https://mcp.x.com/mcp/a"));
        assert!(m("*://mcp.x.com/mcp/*", "http://mcp.x.com/mcp/a"));
        // host wildcard: `*` stops at '/', so it can never spill into the path
        assert!(m("https://*/mcp/*", "https://anything.x.com/mcp/a"));
        assert!(!m("https://*/mcp/*", "https://x.com/other/a"));
        // subdomain wildcard — note `*` crosses dots, so it also spans two labels
        assert!(m("https://*.x.com/*", "https://mcp.x.com/a"));
        assert!(m("https://*.x.com/*", "https://a.b.x.com/a"));
        // suffix lookalikes do not match
        assert!(!m("https://*.x.com/*", "https://evil-x.com/a"));
        assert!(!m("https://*.x.com/*", "https://x.com.evil.net/a"));
        // single-char host wildcard
        assert!(m("https://v&.x.com/*", "https://v1.x.com/a"));
        assert!(!m("https://v&.x.com/*", "https://v10.x.com/a"));
    }

    #[test]
    fn glob_authority_case_insensitive_path_sensitive() {
        let p = compile_pattern("HTTPS://MCP.X.COM/Mcp/*").unwrap();
        // authority lowercased at compile time and at request time
        assert!(p.matches("https://mcp.x.com/Mcp/a"));
        // the path keeps its case on both sides
        assert!(!p.matches("https://mcp.x.com/mcp/a"));
        assert_eq!(
            lower_authority("HTTPS://Host.COM/Path/A"),
            "https://host.com/Path/A"
        );
        assert_eq!(lower_authority("HTTPS://Host.COM"), "https://host.com");
    }

    #[test]
    fn compile_pattern_rejects_malformed() {
        assert!(compile_pattern("mcp.x.com/mcp").is_err()); // no scheme
        assert!(compile_pattern("https://mcp.x.com").is_err()); // no path
        assert!(compile_pattern("https:///mcp").is_err()); // empty host
        assert!(compile_pattern("://mcp.x.com/a").is_err()); // empty scheme
        assert!(compile_pattern("https://u@mcp.x.com/a").is_err()); // userinfo
        assert!(compile_pattern("https://mcp.x.com/../a").is_err()); // traversal
        assert!(compile_pattern("https://mcp.x.com/a\rb").is_err()); // control byte
        assert!(compile_pattern("https://mcp.x.com/*").is_ok());
    }

    #[test]
    fn glob_many_stars_terminates() {
        // The classic exponential case for a recursive star-backtracker: many stars,
        // a long input, and a final byte that can never match. The DP is O(n*m).
        let pat = format!("https://h/{}", "*a".repeat(24));
        let url = format!("https://h/{}b", "a".repeat(400));
        let p = compile_pattern(&pat).unwrap();
        assert!(!p.matches(&url)); // pattern ends in 'a', input in 'b'
    }

    #[test]
    fn url_scope_empty_denies_everything() {
        // No authorized_urls => no access. Both the absent field and an explicit `[]`.
        for s in [UrlScope::deny_all(), UrlScope::compile(&[]).unwrap()] {
            assert!(s.is_empty());
            assert!(!s.allows(Some("https://x/a")));
            assert!(!s.allows(None));
        }
        // whitespace-only entries are dropped, and drop to deny-all
        assert!(UrlScope::compile(&["  ".to_string()]).unwrap().is_empty());
    }

    #[test]
    fn url_scope_star_pattern_grants_everything() {
        // Blanket access is spelled out, never implied.
        let s = UrlScope::compile(&["*://*/*".to_string()]).unwrap();
        assert!(s.allows(Some("https://anything.example.com/at/all")));
        assert!(s.allows(Some("http://h/")));
        assert!(s.allows(Some("https://h/a/b/c.png")));
        assert!(!s.allows(None)); // the header is still mandatory
        assert!(!s.allows(Some("https://h/../etc"))); // and `..` still denied

        // A bare "*" is NOT a sentinel any more — it is a malformed pattern, and the
        // error points at the spelling that works.
        let err = match compile_pattern("*") {
            Ok(_) => panic!("a bare '*' must not compile"),
            Err(e) => e,
        };
        assert!(err.contains("*://*/*"), "{err}");
    }

    #[test]
    fn url_scope_matching() {
        let s = UrlScope::compile(&[
            "https://mcp.x.com/mcp".to_string(),
            "https://mcp.x.com/mcp/*".to_string(),
        ])
        .unwrap();
        assert!(s.allows(Some("https://mcp.x.com/mcp")));
        assert!(s.allows(Some("https://mcp.x.com/mcp/tools")));
        assert!(!s.allows(Some("https://mcp.x.com/mcpEVIL")));
        assert!(!s.allows(Some("https://search.x.com/mcp/tools"))); // wrong host
        assert!(!s.allows(Some("http://mcp.x.com/mcp"))); // wrong scheme
        assert!(!s.allows(None)); // restricted + missing header => fail closed
        assert!(!s.allows(Some("https://mcp.x.com/mcp/../etc"))); // traversal rejected
    }

    #[test]
    fn compile_host_pattern_rejects_non_hosts() {
        assert!(compile_host_pattern("").is_err());
        assert!(compile_host_pattern("https://x.com").is_err()); // scheme
        assert!(compile_host_pattern("x.com/path").is_err()); // path
        assert!(compile_host_pattern("x.com:8443").is_err()); // port
        assert!(compile_host_pattern("u@x.com").is_err()); // userinfo
        assert!(compile_host_pattern("a..b").is_err());
        assert!(compile_host_pattern("*.badbat75.com").is_ok());
        assert!(compile_host_pattern("v&.badbat75.com").is_ok());
        // normalised to lowercase
        assert_eq!(compile_host_pattern("X.COM").unwrap().as_bytes(), b"x.com");
    }

    #[test]
    fn compile_login_url_rejects_unsafe_targets() {
        assert!(compile_login_url("https://login.x.com/").is_ok());
        assert_eq!(
            compile_login_url("  https://login.x.com/?a=1  ").unwrap(),
            "https://login.x.com/?a=1" // trimmed
        );

        assert!(compile_login_url("").is_err());
        assert!(compile_login_url("http://login.x.com/").is_err()); // https only
        assert!(compile_login_url("/relative").is_err());
        assert!(compile_login_url("https://").is_err()); // empty host
        assert!(compile_login_url("https:///nohost").is_err());
        assert!(compile_login_url("https://user@evil.com/").is_err()); // userinfo
        assert!(compile_login_url("https://login.x.com\\@evil.com/").is_err()); // backslash
                                                                                // these are the reason the check exists: they reach a header and a redirect
        assert!(compile_login_url("https://x.com/\r\nSet-Cookie: a=1").is_err());
        assert!(compile_login_url("https://x.com/ b").is_err()); // space
        assert!(compile_login_url("https://xé.com/").is_err()); // non-ascii => h() would panic
    }

    #[test]
    fn header_safe_email_rejects_injection_and_non_ascii() {
        assert!(header_safe_email("alice@example.com"));
        assert!(header_safe_email("a+tag@sub.example.co.uk"));

        assert!(!header_safe_email("")); // respond_authorized asserts on this
        assert!(!header_safe_email("bad\r\nX-Admin: 1@x.com")); // response splitting
        assert!(!header_safe_email("nul\0@x.com"));
        assert!(!header_safe_email("has space@x.com"));
        // to_ascii_lowercase() leaves these bytes intact, so the load-time guard is the
        // only thing keeping them out of a header value.
        assert!(!header_safe_email("béatrice@x.com"));
    }

    // --- the access file ----------------------------------------------------

    /// Write `json` to a uniquely-named temp file so tests can run in parallel.
    pub(crate) fn users_tmp(name: &str, json: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("bb-auth-core-{name}.json"));
        std::fs::write(&p, json).unwrap();
        p
    }

    /// Parse `json` as an access file, through the real parser and a real temp file.
    fn access_of(name: &str, json: &str) -> Access {
        let tmp = users_tmp(name, json);
        let a = read_access(tmp.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&tmp);
        a
    }

    /// The message the gate would refuse `json` with. Matched rather than unwrapped,
    /// because [`Access`] has no `Debug` on purpose.
    fn access_err(name: &str, json: &str) -> String {
        let tmp = users_tmp(name, json);
        let r = read_access(tmp.to_str().unwrap());
        let _ = std::fs::remove_file(&tmp);
        match r {
            Ok(_) => panic!("{name}: expected the gate to refuse this file"),
            Err(e) => e,
        }
    }

    fn doc_of(json: &str) -> AccessFile {
        serde_json::from_str(json).expect("fixture parses")
    }

    fn err_of<T>(r: Result<T, String>) -> String {
        match r {
            Ok(_) => panic!("expected a refusal"),
            Err(e) => e,
        }
    }

    const BOB: &str = "11111111-1111-4111-8111-111111111111";
    const CAROL: &str = "22222222-2222-4222-8222-222222222222";
    const BEARER: &str = "bbk_testkeytestkeytestkey";

    /// Two applications, every access kind, a carve-out that only works because scopes
    /// are first match wins, and a key narrower than its owner.
    fn fixture() -> String {
        r#"{
          "version": 3,
          "applications": [
            { "name": "mpa",
              "base": ["https://app.x.com/mpa"],
              "login_url": "https://signup.x.com/",
              "scopes": [
                { "name": "healthz", "urls": ["https://app.x.com/mpa/healthz"],
                  "access": "anonymous" },
                { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"],
                  "access": "restricted", "groups": ["@admins"], "credentials": ["login"] },
                { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
                  "access": "authenticated" } ] },
            { "name": "mcp",
              "base": ["https://ai.x.com/mcp"],
              "scopes": [
                { "name": "logs", "urls": ["https://ai.x.com/mcp/logs/*"],
                  "access": "restricted", "users": ["BOBUUID"] },
                { "name": "api", "urls": ["https://ai.x.com/mcp/*"],
                  "access": "restricted", "users": ["BOBUUID"],
                  "credentials": ["api_key"] } ] } ],
          "user_groups": { "admins": ["BOBUUID"] },
          "denied": ["spammer@x.com"],
          "users": [
            { "uuid": "BOBUUID", "emails": ["bob@x.com", "bob@old.com"],
              "api_keys": [ { "id": "laptop", "key_hash": "KEYHASH",
                              "released": "2026-01-01", "duration": "never",
                              "scopes": ["mcp/api"] } ] },
            { "uuid": "CAROLUUID", "emails": ["carol@x.com"] } ] }"#
            .replace("BOBUUID", BOB)
            .replace("CAROLUUID", CAROL)
            .replace("KEYHASH", &sha256_hex(BEARER))
    }

    fn fixture_key(a: &Access) -> &ApiKeyRecord {
        match decide_api_key(a, &sha256_hex(BEARER), 1_000) {
            KeyDecision::Granted(r) => r,
            _ => panic!("the fixture key must resolve"),
        }
    }

    // --- the URL partition --------------------------------------------------

    #[test]
    fn base_covers_stops_at_a_path_boundary() {
        assert!(base_covers("https://x.com/app", "https://x.com/app"));
        assert!(base_covers(
            "https://x.com/app",
            "https://x.com/app/deep/er"
        ));
        // The whole reason this is not a `starts_with`: two different areas.
        assert!(!base_covers(
            "https://x.com/app",
            "https://x.com/application"
        ));
        assert!(!base_covers("https://x.com/app", "https://x.com/ap"));
        // A base already ending in `/` needs no boundary of its own.
        assert!(base_covers("https://x.com/", "https://x.com/anything"));
        // Host boundaries are the same rule.
        assert!(!base_covers("https://x.com", "https://x.commerce.com/"));
    }

    #[test]
    fn application_areas_may_not_overlap() {
        let e = access_err(
            "overlap",
            r#"{ "version": 3, "applications": [
                 { "name": "a", "base": ["https://x.com/app"], "scopes": [] },
                 { "name": "b", "base": ["https://x.com/app/inner"], "scopes": [] } ] }"#,
        );
        assert!(e.contains("overlaps"), "{e}");
        assert!(
            e.contains("'a'"),
            "the message must name the other application: {e}"
        );

        // Neighbours that merely share a prefix are fine, which is the boundary rule
        // doing its job.
        let a = access_of(
            "no-overlap",
            r#"{ "version": 3, "applications": [
                 { "name": "a", "base": ["https://x.com/app"], "scopes": [] },
                 { "name": "b", "base": ["https://x.com/application"], "scopes": [] } ] }"#,
        );
        assert_eq!(a.apps.len(), 2);
    }

    #[test]
    fn a_base_must_be_literal() {
        for bad in [
            "https://*.x.com/",
            "https://x.com/a&b",
            "https://x.com/../etc",
            "x.com/app",
        ] {
            let json = format!(
                r#"{{ "version": 3, "applications": [
                     {{ "name": "a", "base": ["{bad}"], "scopes": [] }} ] }}"#
            );
            let e = access_err("bad-base", &json);
            assert!(e.contains("base"), "{bad}: {e}");
        }
    }

    #[test]
    fn a_scope_may_not_reach_outside_its_application() {
        let e = access_err(
            "outside",
            r#"{ "version": 3, "applications": [
                 { "name": "a", "base": ["https://x.com/app"],
                   "scopes": [ { "name": "s", "urls": ["https://x.com/other/*"],
                                 "access": "authenticated" } ] } ] }"#,
        );
        assert!(e.contains("outside this application's base"), "{e}");
        assert!(e.contains("a/s"), "the message must name the scope: {e}");
    }

    #[test]
    fn an_application_needs_a_base() {
        let e = access_err(
            "no-base",
            r#"{ "version": 3, "applications": [ { "name": "a", "scopes": [] } ] }"#,
        );
        assert!(e.contains("no base"), "{e}");
    }

    // --- resolution ---------------------------------------------------------

    #[test]
    fn scopes_resolve_first_match_wins() {
        let a = access_of("first-match", &fixture());
        // The carve-out answers, even though the broad scope after it also covers this.
        let (app, s) = a.resolve(Some("https://ai.x.com/mcp/logs/today")).unwrap();
        assert_eq!((app.name.as_str(), s.name.as_str()), ("mcp", "logs"));
        let (_, s) = a.resolve(Some("https://ai.x.com/mcp/tool")).unwrap();
        assert_eq!(s.name, "api");
    }

    #[test]
    fn reordering_scopes_changes_who_answers() {
        // The same two scopes, broad one first: the carve-out is now unreachable. Order
        // is meaning, which is why an editor lints it and offers a move.
        let a = access_of(
            "shadowed",
            r#"{ "version": 3, "applications": [
                 { "name": "mcp", "base": ["https://ai.x.com/mcp"], "scopes": [
                   { "name": "api", "urls": ["https://ai.x.com/mcp/*"],
                     "access": "authenticated" },
                   { "name": "logs", "urls": ["https://ai.x.com/mcp/logs/*"],
                     "access": "anonymous" } ] } ] }"#,
        );
        let (_, s) = a.resolve(Some("https://ai.x.com/mcp/logs/today")).unwrap();
        assert_eq!(s.name, "api", "the broad scope listed first answers");
    }

    #[test]
    fn resolution_rejects_a_missing_url_and_traversal() {
        let a = access_of("traversal", &fixture());
        assert!(a.resolve(None).is_none());
        assert!(a.app_for(None).is_none());
        assert!(a
            .resolve(Some("https://app.x.com/mpa/../mpa/healthz"))
            .is_none());
        assert_eq!(
            decide(&a, &Subject::Anonymous, None),
            Decision::NoApplication
        );
    }

    // --- the ten decisions --------------------------------------------------

    #[test]
    fn anonymous_scope_grants_with_no_credential() {
        let a = access_of("anon", &fixture());
        let d = decide(
            &a,
            &Subject::Anonymous,
            Some("https://app.x.com/mpa/healthz"),
        );
        assert_eq!(
            d,
            Decision::Anonymous {
                app: "mpa".into(),
                scope: "healthz".into()
            }
        );
        assert!(d.granted());
    }

    #[test]
    fn anonymous_grants_ahead_of_the_veto() {
        // Not an oversight: the scope grants with no credential at all, so a vetoed
        // client would simply omit theirs. A veto bypassed by sending less is not a veto.
        let a = access_of("anon-veto", &fixture());
        let d = decide(
            &a,
            &Subject::Identifier("spammer@x.com"),
            Some("https://app.x.com/mpa/healthz"),
        );
        assert!(d.granted(), "{d:?}");
    }

    #[test]
    fn authenticated_scope_grants_an_unenrolled_identity() {
        let a = access_of("authn", &fixture());
        assert!(a.uuid_of("newcomer@x.com").is_none());
        let d = decide(
            &a,
            &Subject::Identifier("newcomer@x.com"),
            Some("https://app.x.com/mpa/welcome"),
        );
        assert_eq!(
            d,
            Decision::Granted {
                app: "mpa".into(),
                scope: "onboarding".into()
            }
        );
    }

    #[test]
    fn authenticated_scope_never_admits_a_key() {
        let a = access_of("authn-key", &fixture());
        let k = fixture_key(&a);
        let d = decide(&a, &Subject::Key(k), Some("https://app.x.com/mpa/welcome"));
        assert!(matches!(d, Decision::CredentialRefused { .. }), "{d:?}");
    }

    #[test]
    fn restricted_scope_grants_a_member_and_refuses_everyone_else() {
        let a = access_of("restricted", &fixture());
        let url = Some("https://app.x.com/mpa/admin/panel");
        assert!(decide(&a, &Subject::Identifier("bob@x.com"), url).granted());
        // Carol is enrolled but not in @admins.
        assert!(matches!(
            decide(&a, &Subject::Identifier("carol@x.com"), url),
            Decision::NotMember { .. }
        ));
        // A stranger is in no roster row at all.
        assert!(matches!(
            decide(&a, &Subject::Identifier("nobody@x.com"), url),
            Decision::NotEnrolled { .. }
        ));
        // And no credential means no identity to check.
        assert!(matches!(
            decide(&a, &Subject::Anonymous, url),
            Decision::Unauthenticated { .. }
        ));
    }

    #[test]
    fn the_credential_class_is_a_property_of_the_place() {
        let a = access_of("classes", &fixture());
        let k = fixture_key(&a);
        // mcp/api admits api_key only, mpa/admin admits login only. The same member, both
        // times, and the scope is what differs.
        assert!(matches!(
            decide(
                &a,
                &Subject::Identifier("bob@x.com"),
                Some("https://ai.x.com/mcp/tool")
            ),
            Decision::CredentialRefused { .. }
        ));
        assert!(decide(&a, &Subject::Key(k), Some("https://ai.x.com/mcp/tool")).granted());
        assert!(matches!(
            decide(
                &a,
                &Subject::Key(k),
                Some("https://app.x.com/mpa/admin/panel")
            ),
            Decision::CredentialRefused { .. }
        ));
    }

    #[test]
    fn a_key_restriction_subtracts_from_its_owner() {
        let a = access_of("key-scope", &fixture());
        let k = fixture_key(&a);
        // Bob reaches mcp/logs; his key does not, because it named only mcp/api.
        assert!(decide(
            &a,
            &Subject::Identifier("bob@x.com"),
            Some("https://ai.x.com/mcp/logs/x")
        )
        .granted());
        assert!(matches!(
            decide(&a, &Subject::Key(k), Some("https://ai.x.com/mcp/logs/x")),
            Decision::KeyOutOfScope { .. }
        ));
    }

    #[test]
    fn a_key_with_no_restriction_reaches_what_its_owner_reaches() {
        let json = fixture().replace(r#""scopes": ["mcp/api"]"#, r#""notes": "unrestricted""#);
        let a = access_of("key-unrestricted", &json);
        let k = fixture_key(&a);
        assert!(decide(&a, &Subject::Key(k), Some("https://ai.x.com/mcp/logs/x")).granted());
    }

    #[test]
    fn nothing_outside_an_application_is_reachable() {
        let a = access_of("no-app", &fixture());
        for url in [
            "https://elsewhere.com/",
            // Boundary again: a neighbouring path is not inside the area.
            "https://app.x.com/mpa-extra/thing",
        ] {
            assert_eq!(
                decide(&a, &Subject::Identifier("bob@x.com"), Some(url)),
                Decision::NoApplication,
                "{url}"
            );
        }
    }

    #[test]
    fn an_application_with_no_scope_for_the_url_says_so() {
        let a = access_of("no-scope", &fixture());
        // Inside mpa's area, but /mpa/* does not match the bare /mpa.
        assert_eq!(
            decide(
                &a,
                &Subject::Identifier("bob@x.com"),
                Some("https://app.x.com/mpa")
            ),
            Decision::NoScope { app: "mpa".into() }
        );
    }

    // --- the veto -----------------------------------------------------------

    #[test]
    fn denied_vetoes_a_stranger_by_email() {
        let a = access_of("veto-stranger", &fixture());
        assert!(a.denied_identifiers.contains("spammer@x.com"));
        assert_eq!(
            decide(
                &a,
                &Subject::Identifier("spammer@x.com"),
                Some("https://app.x.com/mpa/welcome")
            ),
            Decision::Vetoed
        );
    }

    #[test]
    fn denying_one_email_vetoes_the_whole_user() {
        // Written as an email, folded onto the uuid at load: the other identifier, the
        // group membership and the key all go with it.
        let a = access_of(
            "veto-fold",
            &fixture().replace(
                r#""denied": ["spammer@x.com"]"#,
                r#""denied": ["bob@old.com"]"#,
            ),
        );
        assert!(a.denied_users.contains(BOB));
        for url in [
            "https://app.x.com/mpa/admin/panel",
            "https://ai.x.com/mcp/logs/x",
        ] {
            assert_eq!(
                decide(&a, &Subject::Identifier("bob@x.com"), Some(url)),
                Decision::Vetoed,
                "{url}"
            );
        }
        // And the key it owns, on the path that never sees a token.
        assert!(matches!(
            decide_api_key(&a, &sha256_hex(BEARER), 1_000),
            KeyDecision::OwnerDenied(_)
        ));
    }

    #[test]
    fn a_denied_entry_must_be_a_uuid_or_an_email() {
        let e = access_err(
            "veto-junk",
            r#"{ "version": 3, "denied": ["11111111-1111-4111-8111-11111111111"] }"#,
        );
        assert!(e.contains("not a uuid and not an email"), "{e}");
    }

    // --- keys ---------------------------------------------------------------

    #[test]
    fn an_unknown_key_is_nobody() {
        let a = access_of("key-unknown", &fixture());
        assert!(matches!(
            decide_api_key(&a, &sha256_hex("bbk_nope"), 1_000),
            KeyDecision::Unknown
        ));
    }

    #[test]
    fn an_expired_key_is_refused_before_any_url() {
        let a = access_of(
            "key-expired",
            &fixture().replace(r#""duration": "never""#, r#""duration": "1d""#),
        );
        let released = parse_date_epoch("2026-01-01").unwrap();
        assert!(matches!(
            decide_api_key(&a, &sha256_hex(BEARER), released + 86_401),
            KeyDecision::Expired(_)
        ));
        assert!(decide_api_key(&a, &sha256_hex(BEARER), released + 3_600).granted());
    }

    #[test]
    fn a_key_restriction_naming_no_scope_is_fatal() {
        let e = access_err(
            "key-bad-scope",
            &fixture().replace(r#""scopes": ["mcp/api"]"#, r#""scopes": ["mcp/apy"]"#),
        );
        assert!(e.contains("names no scope"), "{e}");
    }

    #[test]
    fn a_bad_key_hash_only_skips_that_key() {
        let a = access_of(
            "key-bad-hash",
            &fixture().replace(&sha256_hex(BEARER), "not-a-hash"),
        );
        assert!(a.by_key_hash.is_empty());
        // The roster it hangs off is untouched: one bad key must not drop a user.
        assert!(a.by_uuid.contains_key(BOB));
    }

    // --- the roster ---------------------------------------------------------

    #[test]
    fn identifiers_resolve_many_to_one() {
        let a = access_of("identifiers", &fixture());
        assert_eq!(a.uuid_of("bob@x.com"), Some(BOB));
        assert_eq!(
            a.uuid_of("BOB@OLD.COM"),
            Some(BOB),
            "matched case-insensitively"
        );
        assert_eq!(a.by_uuid[BOB].emails, vec!["bob@x.com", "bob@old.com"]);
    }

    #[test]
    fn two_users_may_not_share_an_identifier() {
        let e = access_err(
            "dup-email",
            &fixture().replace(r#""emails": ["carol@x.com"]"#, r#""emails": ["bob@x.com"]"#),
        );
        assert!(e.contains("declared by two users"), "{e}");
    }

    #[test]
    fn two_users_may_not_share_a_uuid() {
        let e = access_err("dup-uuid", &fixture().replace(CAROL, BOB));
        assert!(e.contains("declared by two users entries"), "{e}");
    }

    #[test]
    fn a_malformed_uuid_is_fatal_wherever_it_appears() {
        for (what, json) in [
            (
                "roster",
                r#"{ "version": 3, "users": [ { "uuid": "nope", "emails": ["a@x.com"] } ] }"#,
            ),
            (
                "group",
                r#"{ "version": 3, "user_groups": { "g": ["nope"] } }"#,
            ),
            (
                "scope",
                r#"{ "version": 3, "applications": [ { "name": "a",
                     "base": ["https://x.com/a"], "scopes": [ { "name": "s",
                       "urls": ["https://x.com/a/*"], "access": "restricted",
                       "users": ["nope"] } ] } ] }"#,
            ),
        ] {
            let e = access_err("bad-uuid", json);
            assert!(e.contains("not a uuid"), "{what}: {e}");
        }
    }

    #[test]
    fn an_email_that_could_not_be_a_header_is_skipped_not_fatal() {
        let a = access_of(
            "unsafe-email",
            &fixture().replace(r#""carol@x.com""#, r#""carol@x.com\r\nX-Admin: yes""#),
        );
        assert!(a.uuid_of("carol@x.com").is_none());
        assert!(a.by_uuid.contains_key(CAROL), "the row survives");
    }

    // --- user groups --------------------------------------------------------

    #[test]
    fn a_group_expands_once_and_nothing_downstream_sees_it() {
        let a = access_of("groups", &fixture());
        let (_, admin) = a.resolve(Some("https://app.x.com/mpa/admin/x")).unwrap();
        assert!(admin.members.contains(BOB));
    }

    #[test]
    fn an_unknown_group_is_fatal_and_names_the_referrer() {
        let e = access_err("group-unknown", &fixture().replace("@admins", "@nope"));
        assert!(e.contains("unknown user group '@nope'"), "{e}");
        assert!(e.contains("mpa/admin"), "{e}");
    }

    #[test]
    fn a_group_may_not_reference_a_group() {
        let e = access_err(
            "group-nested",
            r#"{ "version": 3, "user_groups": { "a": ["@b"], "b": [] } }"#,
        );
        assert!(e.contains("cannot reference another group"), "{e}");
    }

    #[test]
    fn a_group_is_validated_even_when_nothing_references_it() {
        // A group that only breaks the day someone first uses it is a trap
        // `--check-users` never saw.
        let e = access_err(
            "group-unused",
            r#"{ "version": 3, "user_groups": { "unused": ["not-a-uuid"] } }"#,
        );
        assert!(e.contains("not a uuid"), "{e}");
    }

    #[test]
    fn a_dangling_reference_grants_nothing() {
        let a = access_of(
            "dangling",
            r#"{ "version": 3,
                 "applications": [ { "name": "a", "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"], "access": "restricted",
                     "users": ["33333333-3333-4333-8333-333333333333"] } ] } ],
                 "users": [ { "uuid": "11111111-1111-4111-8111-111111111111",
                              "emails": ["bob@x.com"] } ] }"#,
        );
        assert!(matches!(
            decide(
                &a,
                &Subject::Identifier("bob@x.com"),
                Some("https://x.com/a/thing")
            ),
            Decision::NotMember { .. }
        ));
    }

    // --- the access word ----------------------------------------------------

    #[test]
    fn access_is_required_and_has_no_default() {
        let e = access_err(
            "no-access",
            r#"{ "version": 3, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"] } ] } ] }"#,
        );
        assert!(e.contains("'access' is required"), "{e}");

        let e = access_err(
            "bad-access",
            r#"{ "version": 3, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"],
                     "access": "anonimous" } ] } ] }"#,
        );
        assert!(e.contains("unknown access 'anonimous'"), "{e}");
    }

    #[test]
    fn membership_fields_belong_only_to_restricted() {
        for field in [
            r#""users": []"#,
            r#""groups": []"#,
            r#""credentials": ["login"]"#,
        ] {
            let json = format!(
                r#"{{ "version": 3, "applications": [ {{ "name": "a",
                     "base": ["https://x.com/a"], "scopes": [
                       {{ "name": "s", "urls": ["https://x.com/a/*"],
                          "access": "authenticated", {field} }} ] }} ] }}"#
            );
            let e = access_err("stray-field", &json);
            assert!(e.contains("belongs to \"restricted\""), "{field}: {e}");
        }
    }

    #[test]
    fn an_empty_credentials_list_is_fatal() {
        let e = access_err(
            "no-creds",
            r#"{ "version": 3, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"],
                     "access": "restricted", "credentials": [] } ] } ] }"#,
        );
        assert!(e.contains("unreachable"), "{e}");
    }

    #[test]
    fn an_unknown_field_in_a_scope_is_fatal() {
        // The one place a typo could fail open, so it is the one place extras are refused.
        let e = access_err(
            "unknown-field",
            r#"{ "version": 3, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"],
                     "access": "restricted", "public_auth": true } ] } ] }"#,
        );
        assert!(e.contains("public_auth"), "{e}");
    }

    // --- the format version -------------------------------------------------

    #[test]
    fn a_pre_3_0_file_is_refused_by_name_and_points_at_the_converter() {
        for json in [
            r#"{ "sites": [] }"#,
            r#"{ "url_groups": {} }"#,
            r#"{ "version": 3, "users": [ { "uuid": "11111111-1111-4111-8111-111111111111",
                 "authorized_urls": ["*://*/*"] } ] }"#,
            r#"{ "version": 3, "users": [ { "uuid": "11111111-1111-4111-8111-111111111111",
                 "api_keys": [ { "id": "k", "authorized_urls": [] } ] } ] }"#,
        ] {
            let e = access_err("legacy", json);
            assert!(e.contains("bb-auth-adm migrate"), "{json}: {e}");
        }
    }

    #[test]
    fn enabled_paths_is_still_refused() {
        let e = access_err(
            "enabled-paths",
            r#"{ "version": 3, "users": [ { "uuid": "11111111-1111-4111-8111-111111111111",
                 "enabled_paths": ["/x"] } ] }"#,
        );
        assert!(e.contains("enabled_paths"), "{e}");
    }

    #[test]
    fn the_version_must_be_the_one_this_binary_reads() {
        let e = access_err("no-version", r#"{ "users": [] }"#);
        assert!(e.contains("no 'version'"), "{e}");
        let e = access_err("future", r#"{ "version": 5 }"#);
        assert!(e.contains("declares version 5"), "{e}");
    }

    // --- the login page -----------------------------------------------------

    #[test]
    fn login_url_falls_back_through_the_application_then_the_global() {
        let a = access_of("login-url", &fixture());
        let g = "https://global.example/";
        // Inside mpa, even on a URL no scope covers: a 401 there still wants mpa's page.
        assert_eq!(
            login_url_for(&a, g, Some("https://app.x.com/mpa")),
            "https://signup.x.com/"
        );
        // mcp declares none, and nothing at all is outside every application.
        assert_eq!(login_url_for(&a, g, Some("https://ai.x.com/mcp/tool")), g);
        assert_eq!(login_url_for(&a, g, None), g);
    }

    #[test]
    fn a_malformed_login_url_is_fatal() {
        let e = access_err(
            "bad-login",
            &fixture().replace("https://signup.x.com/", "http://signup.x.com/"),
        );
        assert!(e.contains("absolute https"), "{e}");
    }

    // --- the round trip -----------------------------------------------------

    #[test]
    fn the_document_round_trips_and_preserves_operator_notes() {
        let json = fixture();
        let doc = doc_of(&json);
        let out = render_access_file(&doc).unwrap();
        let back = doc_of(&out);
        assert_eq!(back.version, ACCESS_FILE_VERSION);
        assert_eq!(back.applications.len(), 2);
        assert_eq!(back.users.len(), 2);
        assert_eq!(
            back.applications[0].scopes[1].groups.as_deref(),
            Some(&["@admins".to_string()][..])
        );
        assert!(out.ends_with('\n'));
        // An older field is absent rather than serialized as null.
        assert!(!out.contains("authorized_urls"), "{out}");
        assert!(!out.contains("\"sites\""), "{out}");
    }

    #[test]
    fn operator_notes_on_a_user_survive_an_edit() {
        let json = fixture().replace(
            r#""emails": ["carol@x.com"]"#,
            r#""emails": ["carol@x.com"], "notes": "on leave""#,
        );
        let doc = doc_of(&json);
        let out = render_access_file(&doc).unwrap();
        assert!(out.contains("on leave"), "{out}");
    }

    // --- uuids --------------------------------------------------------------

    #[test]
    fn well_formed_uuid_is_strict_about_one_spelling() {
        const MIXED: &str = "b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d";
        assert!(well_formed_uuid(BOB));
        assert!(well_formed_uuid(MIXED));
        // One spelling only: two strings naming the same identity that do not compare
        // equal would be a dangling reference that looks right in a diff.
        assert!(!well_formed_uuid(&MIXED.to_ascii_uppercase()));
        assert!(!well_formed_uuid(&BOB.replace('-', "")));
        assert!(!well_formed_uuid(""));
        assert!(!well_formed_uuid("11111111-1111-4111-8111-11111111111g"));
    }

    #[test]
    fn mint_uuid_makes_one_this_file_accepts() {
        let a = mint_uuid().unwrap();
        let b = mint_uuid().unwrap();
        assert!(well_formed_uuid(&a), "{a}");
        assert_ne!(a, b);
        assert_eq!(&a[14..15], "4", "version 4");
    }

    // --- editing the document -----------------------------------------------

    #[test]
    fn add_user_mints_a_uuid_and_refuses_a_taken_email() {
        let mut doc = doc_of(&fixture());
        add_user(
            &mut doc,
            UserSpec {
                emails: vec!["dave@x.com".into()],
                ..Default::default()
            },
        )
        .unwrap();
        let dave = &doc.users[2];
        assert!(well_formed_uuid(&dave.uuid));

        let e = err_of(add_user(
            &mut doc,
            UserSpec {
                emails: vec!["BOB@x.com".into()],
                ..Default::default()
            },
        ));
        assert!(e.contains("already belongs to another user"), "{e}");
    }

    #[test]
    fn add_user_refuses_a_value_that_could_never_be_an_email() {
        let mut doc = doc_of(&fixture());
        let e = err_of(add_user(
            &mut doc,
            UserSpec {
                emails: vec!["not an email".into()],
                ..Default::default()
            },
        ));
        assert!(e.contains("does not look like an email"), "{e}");
    }

    #[test]
    fn a_user_is_found_by_uuid_or_by_any_of_their_emails() {
        let doc = doc_of(&fixture());
        assert_eq!(user_pos(&doc, BOB), Some(0));
        assert_eq!(user_pos(&doc, "bob@old.com"), Some(0));
        assert_eq!(user_pos(&doc, "carol@x.com"), Some(1));
        assert_eq!(user_pos(&doc, "nobody@x.com"), None);
    }

    #[test]
    fn identifiers_are_added_and_dropped_but_never_all_of_them() {
        let mut doc = doc_of(&fixture());
        assert!(add_user_email(&mut doc, BOB, "bob@new.com").unwrap());
        assert!(
            !add_user_email(&mut doc, BOB, "BOB@NEW.COM").unwrap(),
            "idempotent"
        );
        let e = err_of(add_user_email(&mut doc, CAROL, "bob@new.com"));
        assert!(e.contains("already belongs"), "{e}");

        assert!(remove_user_email(&mut doc, BOB, "bob@new.com").unwrap());
        let e = err_of(remove_user_email(&mut doc, CAROL, "carol@x.com"));
        assert!(e.contains("only email"), "{e}");
    }

    #[test]
    fn remove_user_sweeps_every_reference_to_them() {
        let mut doc = doc_of(&fixture());
        let (gone, swept) = remove_user(&mut doc, "bob@x.com").unwrap();
        assert_eq!(gone.uuid, BOB);
        assert!(swept.contains(&"mcp/logs".to_string()), "{swept:?}");
        assert!(swept.contains(&"@admins".to_string()), "{swept:?}");
        // And the file that comes out has no dangling reference left in it.
        assert!(user_refs(&doc, BOB).is_empty());
        let rendered = render_access_file(&doc).unwrap();
        assert!(!rendered.contains(BOB), "{rendered}");
    }

    #[test]
    fn renaming_an_application_repoints_the_keys_that_named_it() {
        let mut doc = doc_of(&fixture());
        rename_application(&mut doc, "mcp", "gateway").unwrap();
        assert_eq!(
            doc.users[0].api_keys[0].scopes.as_deref(),
            Some(&["gateway/api".to_string()][..])
        );
        // And the result still compiles, which is what the re-pointing is for.
        AccessWrite::prepare(&doc).unwrap();
    }

    #[test]
    fn renaming_a_scope_repoints_the_keys_that_named_it() {
        let mut doc = doc_of(&fixture());
        rename_scope(&mut doc, "mcp", "api", "tools").unwrap();
        assert_eq!(
            doc.users[0].api_keys[0].scopes.as_deref(),
            Some(&["mcp/tools".to_string()][..])
        );
        AccessWrite::prepare(&doc).unwrap();
    }

    #[test]
    fn moving_a_scope_changes_who_answers_without_changing_a_field() {
        let mut doc = doc_of(&fixture());
        move_scope(&mut doc, "mcp", 0, 1).unwrap();
        let a = AccessWrite::prepare(&doc).unwrap();
        let (_, s) = a
            .access()
            .resolve(Some("https://ai.x.com/mcp/logs/x"))
            .unwrap();
        assert_eq!(s.name, "api", "the broad scope now answers first");
    }

    #[test]
    fn scope_and_application_names_must_be_free() {
        let mut doc = doc_of(&fixture());
        let e = err_of(add_application(
            &mut doc,
            AppSpec {
                name: "mpa".into(),
                ..Default::default()
            },
        ));
        assert!(e.contains("already exists"), "{e}");
        let e = err_of(add_scope(
            &mut doc,
            "mpa",
            ScopeSpec {
                name: "admin".into(),
                ..Default::default()
            },
            None,
        ));
        assert!(e.contains("already exists"), "{e}");
    }

    #[test]
    fn a_group_cannot_be_removed_while_a_scope_names_it() {
        let mut doc = doc_of(&fixture());
        let e = err_of(remove_user_group(&mut doc, "admins"));
        assert!(e.contains("mpa/admin"), "{e}");
        // Drop the reference and it goes.
        doc.applications[0].scopes[1].groups = None;
        assert_eq!(remove_user_group(&mut doc, "admins").unwrap(), vec![BOB]);
    }

    #[test]
    fn denying_an_enrolled_user_writes_their_uuid() {
        let mut doc = doc_of(&fixture());
        assert!(add_denied(&mut doc, "bob@old.com").unwrap());
        assert!(doc.denied.contains(&BOB.to_string()), "{:?}", doc.denied);
        assert!(
            !add_denied(&mut doc, BOB).unwrap(),
            "already vetoed, by either name"
        );
        assert_eq!(remove_denied(&mut doc, &["bob@x.com".to_string()]), 1);
    }

    #[test]
    fn denying_a_stranger_keeps_the_email() {
        let mut doc = doc_of(&fixture());
        assert!(add_denied(&mut doc, "Nuisance@X.com").unwrap());
        assert!(doc.denied.contains(&"nuisance@x.com".to_string()));
        let e = err_of(add_denied(&mut doc, "not an email"));
        assert!(e.contains("does not look like an email"), "{e}");
    }

    // --- the write order ----------------------------------------------------

    #[test]
    fn access_write_refuses_a_document_the_gate_would_reject() {
        let mut doc = doc_of(&fixture());
        doc.applications[0].scopes[0].access = "anonimous".into();
        let e = err_of(AccessWrite::prepare(&doc));
        assert!(e.contains("refusing to write"), "{e}");
    }

    #[test]
    fn access_write_commits_exactly_the_bytes_it_compiled() {
        let path = users_tmp("commit", &fixture());
        let mut doc = doc_of(&fixture());
        add_user(
            &mut doc,
            UserSpec {
                emails: vec!["dave@x.com".into()],
                ..Default::default()
            },
        )
        .unwrap();
        let w = AccessWrite::prepare(&doc).unwrap();
        let expected = w.json().to_string();
        let receipt = w.commit(path.to_str().unwrap()).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
        assert!(receipt.backup.exists());
        let _ = std::fs::remove_file(&receipt.backup);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_access_file_refuses_a_file_the_gate_would_reject() {
        let path = users_tmp("open-bad", r#"{ "version": 3, "denied": ["nope"] }"#);
        let e = err_of(open_access_file(path.to_str().unwrap()));
        assert!(e.contains("the gate would reject this file"), "{e}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn add_api_key_seals_the_bearer_until_the_file_carries_its_hash() {
        let path = users_tmp("seal", &fixture());
        let mut doc = doc_of(&fixture());
        let sealed = add_api_key(
            &mut doc,
            "carol@x.com",
            ApiKeySpec {
                id: "ci".into(),
                released: "2026-08-17".into(),
                duration: "30d".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let w = AccessWrite::prepare(&doc).unwrap();
        let receipt = w.commit(path.to_str().unwrap()).unwrap();
        // The receipt is what unseals it: a dry run has no bearer to leak.
        let bearer = sealed.reveal(&receipt);
        assert!(bearer.starts_with(API_KEY_PREFIX));
        let a = read_access(path.to_str().unwrap()).unwrap();
        assert!(a.by_key_hash.contains_key(&sha256_hex(&bearer)));
        let _ = std::fs::remove_file(&receipt.backup);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn add_api_key_refuses_a_duplicate_id() {
        let mut doc = doc_of(&fixture());
        let e = err_of(add_api_key(
            &mut doc,
            BOB,
            ApiKeySpec {
                id: "laptop".into(),
                ..Default::default()
            },
        ));
        assert!(e.contains("already has a key 'laptop'"), "{e}");
    }

    #[test]
    fn rotate_api_key_replaces_the_hash_and_redates_the_row() {
        let mut doc = doc_of(&fixture());
        let before = doc.users[0].api_keys[0].key_hash.clone();
        let _sealed = rotate_api_key(&mut doc, "bob@x.com", "laptop").unwrap();
        assert_ne!(doc.users[0].api_keys[0].key_hash, before);
        assert_eq!(doc.users[0].api_keys[0].released, format_date(now()));
    }

    #[test]
    fn scopes_for_lists_where_a_user_is_named() {
        let a = access_of("scopes-for", &fixture());
        let mine: Vec<String> = a
            .scopes_for(BOB)
            .iter()
            .map(|(app, s)| format!("{}/{}", app.name, s.name))
            .collect();
        assert_eq!(mine, vec!["mpa/admin", "mcp/logs", "mcp/api"]);
        assert!(a.scopes_for(CAROL).is_empty());
    }

    #[test]
    fn any_authenticated_scope_is_what_session_asks() {
        let a = access_of("any-authn", &fixture());
        assert!(a.any_authenticated_scope());
        let b = access_of(
            "no-authn",
            r#"{ "version": 3, "applications": [ { "name": "a",
                 "base": ["https://x.com/a"], "scopes": [
                   { "name": "s", "urls": ["https://x.com/a/*"],
                     "access": "restricted" } ] } ] }"#,
        );
        assert!(!b.any_authenticated_scope());
    }
}
