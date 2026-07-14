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
//! # What is in an access file
//!
//! Three sibling sections answering three different questions ([`AccessFile`]):
//! `sites` describe URL areas ([`Sites`]), `denied` vetoes people, `users` is the roster.
//! Access is **enumerated, never assumed**: an absent or empty `authorized_urls` grants
//! nothing, and a URL no site covers is not open. There are exactly two grant sources —
//! the roster's [`UrlScope`] and a `public_auth` [`SiteRecord`] — and one veto that
//! outranks both, on every credential. [`decide`] is that rule.

use std::collections::{HashMap, HashSet};

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

/// A set of URL patterns, and the single matcher every URL check in bb-auth goes
/// through: a user's `authorized_urls`, a key's, and a site's `urls`.
///
/// There is no "unrestricted" variant. An absent or empty list grants **nothing** —
/// access is enumerated, never assumed. Blanket access is spelled out as the pattern
/// `*://*/*`, which an operator has to mean in order to write.
///
/// Sharing one type is not tidiness: [`UrlScope::allows`] is where the missing-header
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

    /// Compile a JSON `authorized_urls` list.
    pub fn compile(list: &[String]) -> Result<UrlScope, String> {
        let mut patterns = Vec::with_capacity(list.len());
        for raw in list.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            patterns.push(compile_pattern(raw)?);
        }
        Ok(UrlScope { patterns })
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

/// A resolved site: a URL area, plus the properties that hold for it.
///
/// A site record describes a **place**, never a person. No field of it may ever name a
/// user — grants to named users live in exactly one place, `users[].authorized_urls`,
/// and expressing the same user↔URL relation twice would mean a user removed from the
/// roster could still walk in through a site. Everything here is a predicate over an
/// anonymous identity, and may only modulate the grant this record itself makes.
pub struct SiteRecord {
    /// Human label, for logging. `"?"` when the file omits it.
    pub name: String,
    /// The URLs this record speaks for.
    pub urls: UrlScope,
    /// Grant the site to **any** identity Cognito vouches for, enrolled in `users` or
    /// not. `false` (the default) grants nothing and is indistinguishable from having
    /// no site at all — it exists to carry future properties.
    pub public_auth: bool,
    /// Login page for this area, overriding `BB_AUTH_LOGIN_URL`. `None` = use the global.
    /// Reaches nginx through `X-Auth-Login-URL`; also names the fallback for a rejected
    /// `rd` and the link on `/auth/session`'s error pages. See [`login_url_for`].
    pub login_url: Option<String>,
}

/// The site table, in file order. **First match wins**: [`Sites::resolve`] hands back the
/// first record whose `urls` cover the request, and that record is then the authority for
/// it — a broad site listed first shadows a narrower one after it, so specific sites go
/// first.
///
/// The ordering rule matters more than one boolean warrants, and that is the point: it is
/// fixed now, while `public_auth` is the only property, rather than after a second field
/// makes "which record answers?" expensive to change. The alternatives are worse.
/// "Most specific wins" needs a specificity order over globs that does not exist
/// (`https://x.com/*` vs `*://x.com/app1` — which?). "Merge every match" would OR the
/// grants together, so a broad site silently opens a narrow one.
///
/// The table only ever **grants**. A URL with no site is not denied, it is simply not
/// open, and the per-user scope decides as before. The only thing that takes access away
/// is [`Access::denied`].
pub struct Sites {
    pub entries: Vec<SiteRecord>,
}

impl Sites {
    /// The site that speaks for `url`, or `None`. Missing header and `..` fall out of
    /// [`UrlScope::allows`], which is why sites reuse it rather than matching directly.
    pub fn resolve(&self, url: Option<&str>) -> Option<&SiteRecord> {
        self.entries.iter().find(|s| s.urls.allows(url))
    }

    /// Whether any site grants `public_auth`. `/auth/session` needs this to know whether
    /// an un-enrolled identity has anywhere to go; nothing else may branch on it.
    pub fn any_public_auth(&self) -> bool {
        self.entries.iter().any(|s| s.public_auth)
    }
}

/// The login page for `url`: the site that speaks for it, or `global` (`BB_AUTH_LOGIN_URL`).
///
/// First-match-wins applies here too — a broad site listed first answers with *its*
/// `login_url` (or, declaring none, with the global) even when a narrower site after it
/// declares one. Same rule, same fix: specific sites go first.
///
/// Every value returned passed [`compile_login_url`] — the site's at load, the global at
/// startup — so callers may put it in a header or a redirect without checking.
pub fn login_url_for(access: &Access, global: &str, url: Option<&str>) -> String {
    access
        .sites
        .resolve(url)
        .and_then(|s| s.login_url.as_deref())
        .unwrap_or(global)
        .to_string()
}

/// A resolved allowlisted user, keyed by lowercased email in [`Access::by_email`].
pub struct UserRecord {
    pub scope: UrlScope,
}

/// A resolved API key, keyed by the bearer's SHA-256 hex in [`Access::by_key_hash`].
pub struct ApiKeyRecord {
    /// Owning user, for logging and for the [`Access::denied`] veto.
    pub email: String,
    /// Human label, for logging and revocation. Not part of the credential.
    pub key_id: String,
    /// Unix seconds; `None` = never expires.
    pub expires: Option<u64>,
    /// The key's own scope, or the owner's if it declared none.
    pub scope: UrlScope,
}

/// The runtime access table, built from the access file by [`read_access`].
pub struct Access {
    /// URL areas and their properties. Grants only; see [`Sites`].
    pub sites: Sites,
    /// Lowercased emails vetoed on **every** credential and every grant, checked before
    /// anything else ([`decide`], [`decide_api_key`], and the gate's `/auth/session`).
    ///
    /// It is not redundant with deleting the user's row. On a `public_auth` site
    /// `by_email` is never consulted, so for an un-enrolled identity this is the only
    /// denial that exists. And for an enrolled one it is a suspension rather than a
    /// deletion: the row, its scope and its keys survive, so re-enabling is one edit.
    pub denied: HashSet<String>,
    /// Lowercased email → user.
    pub by_email: HashMap<String, UserRecord>,
    /// `sha256(bearer)` hex → key. The raw key is never stored, and this lookup **is**
    /// the verification: finding a matching row would require a SHA-256 second preimage,
    /// so a high-entropy key needs neither a salt nor a constant-time compare.
    pub by_key_hash: HashMap<String, ApiKeyRecord>,
}

// ---------------------------------------------------------------------------
// The authorization decision
// ---------------------------------------------------------------------------

/// What the access table says about one (identity, URL) pair — the whole grant model,
/// as a value. [`decide`] produces it; the gate turns it into a 204/401 and a log line,
/// and `bb-auth-adm can` prints it, so an operator can ask "would this work?" of the
/// same code that will answer the real request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// A `public_auth` site covers the URL: an authenticated identity is enough, and the
    /// roster was not consulted at all. Carries the site's name.
    SiteGrant(String),
    /// The roster covers it: enrolled, and the URL is inside `authorized_urls`.
    RosterGrant,
    /// `denied` vetoes this email — ahead of every grant, on every credential.
    Vetoed,
    /// Enrolled, but the URL is outside their scope (an empty scope lands here too).
    OutOfScope,
    /// Not in the roster, and no `public_auth` site speaks for this URL.
    NotEnrolled,
}

impl Decision {
    /// Whether this decision authorizes the request.
    pub fn granted(&self) -> bool {
        matches!(self, Decision::SiteGrant(_) | Decision::RosterGrant)
    }
}

/// Turn an *authenticated* identity into an *authorized* one, or say why not. The rule
/// behind both Cognito-backed credentials (the id_token bearer and the session cookie).
///
/// Three steps, in this order:
///
/// 1. [`Access::denied`] vetoes, ahead of every grant and on every credential.
/// 2. If a site speaks for this URL and grants `public_auth`, the identity is enough —
///    the roster is not consulted, which is the entire point: this is how someone who is
///    not enrolled yet gets in. The first matching site answers even if it grants
///    nothing; see [`Sites`].
/// 3. Otherwise the roster decides, as it always has: listed, and the URL in scope.
///
/// `email` must already be lowercased ([`Access::by_email`] is keyed that way and the
/// lookup is exact) — the gate lowercases it as it comes out of the token claim.
pub fn decide(access: &Access, email: &str, url: Option<&str>) -> Decision {
    if access.denied.contains(email) {
        return Decision::Vetoed;
    }
    if let Some(site) = access.sites.resolve(url) {
        if site.public_auth {
            return Decision::SiteGrant(site.name.clone());
        }
    }
    match access.by_email.get(email) {
        Some(rec) if rec.scope.allows(url) => Decision::RosterGrant,
        Some(_) => Decision::OutOfScope,
        None => Decision::NotEnrolled,
    }
}

/// What the access table says about one (API key, URL) pair. The granted variant hands
/// back the record, whose `email` is the identity the application downstream sees — a key
/// *acts as* its user, and it is the only credential with no token to decode.
///
/// No `Debug`, deliberately — deriving it would force one onto [`ApiKeyRecord`] and
/// [`Access`], and a table of live credentials is not something a stray `{:?}` should be
/// able to spill into a log.
pub enum KeyDecision<'a> {
    Granted(&'a ApiKeyRecord),
    /// No row for this hash. A `public_auth` site does **not** rescue it: that grant is
    /// for identities Cognito vouches for, and Cognito vouches for no static key of ours.
    /// An unknown key is not an un-enrolled user, it is nobody — there would be no email
    /// to hand back.
    Unknown,
    /// The owning user is on [`Access::denied`].
    OwnerDenied(&'a ApiKeyRecord),
    Expired(&'a ApiKeyRecord),
    OutOfScope(&'a ApiKeyRecord),
}

impl KeyDecision<'_> {
    pub fn granted(&self) -> bool {
        matches!(self, KeyDecision::Granted(_))
    }
}

/// Resolve an API key against the access table, by the SHA-256 hex of the bearer.
///
/// Taking the *hash* rather than the raw key is what lets `bb-auth-adm` evaluate a key it
/// has never seen — the file stores only the hash — through the same code the gate runs.
/// The gate hashes the bearer and calls this; nothing is ever indexed by what the client
/// sent in the clear.
pub fn decide_api_key<'a>(
    access: &'a Access,
    key_hash: &str,
    url: Option<&str>,
    now: u64,
) -> KeyDecision<'a> {
    let rec = match access.by_key_hash.get(key_hash) {
        Some(r) => r,
        None => return KeyDecision::Unknown,
    };
    if access.denied.contains(&rec.email) {
        return KeyDecision::OwnerDenied(rec);
    }
    if rec.expires.is_some_and(|e| now >= e) {
        return KeyDecision::Expired(rec);
    }
    if !rec.scope.allows(url) {
        return KeyDecision::OutOfScope(rec);
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
/// { "sites": [
///     { "name": "app1", "urls": ["https://app.x.com/app1",
///                                "https://app.x.com/app1/*"], "public_auth": true }
///   ],
///   "denied": ["spammer@x.com"],
///   "users": [
///     { "email": "bob@x.com",
///       "authorized_urls": ["https://mcp.x.com/mcp/*"],
///       "api_keys": [
///         { "id": "laptop", "key_hash": "<sha256 hex of the bbk_… bearer>",
///           "released": "2026-07-08", "duration": "365d",
///           "authorized_urls": ["https://mcp.x.com/mcp/*"] }
///       ] },
///     { "email": "alice@x.com", "authorized_urls": ["*://*/*"] }
/// ] }
/// ```
///
/// The three sections are siblings and answer three different questions: `sites` describe
/// URL areas, `denied` vetoes people, `users` is the roster. Access is enumerated, never
/// assumed, from either of the two grant sources: a user with no `authorized_urls` reaches
/// nothing, and a URL with no site is not open. "Everything" is the explicit pattern
/// `*://*/*`. Validate a file before shipping it with `bb-auth --check-users <file>`, or
/// `bb-auth-adm check` — the same parser, [`read_access`].
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<SiteSpec>,
    /// Lowercased on load. See [`Access::denied`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<String>,
    #[serde(default)]
    pub users: Vec<UserSpec>,
    /// Unknown top-level keys, preserved verbatim across an edit — `_comment` above all.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One site entry. Compiles to a [`SiteRecord`].
///
/// Unlike every other spec here, **unknown fields are a hard error** — and so this is the
/// one spec with no `extra` map. The others carry documentation (`_comment`, `notes`) and
/// describe people, where an ignored typo denies at worst. A site's fields are grants and
/// restrictions on a grant, so the day `public_auth` gains a `require_email_domain`
/// companion, a typo in the companion would be silently dropped and leave `public_auth:
/// true` standing naked — failing *open*. `bb-auth --check-users` catches it instead,
/// before the restart. Same reasoning as [`UserSpec::enabled_paths`], applied ahead of the
/// field that will need it.
#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SiteSpec {
    /// For logs. Absent or empty ⇒ `"?"`.
    #[serde(default)]
    pub name: String,
    /// Full `<scheme>://<host>/<path>` patterns, like `authorized_urls`. A malformed one
    /// is fatal; an empty list makes the record match nothing.
    #[serde(default)]
    pub urls: Vec<String>,
    /// See [`SiteRecord::public_auth`]. Always written out, even when false: it is the
    /// site's security-relevant property, and an operator reading the file should not have
    /// to know that its absence means "closed".
    #[serde(default)]
    pub public_auth: bool,
    /// Absolute `https://` login page for this area. Absent ⇒ `BB_AUTH_LOGIN_URL`.
    /// Malformed ⇒ fatal, like a URL pattern. See [`compile_login_url`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
}

/// One user entry. Extra fields are ignored (and preserved on a rewrite), with one
/// deliberate exception.
#[derive(Deserialize, Serialize, Default)]
pub struct UserSpec {
    pub email: String,
    /// Absent **or** empty ⇒ this user reaches nothing ([`UrlScope::deny_all`]).
    /// Blanket access is the explicit pattern `*://*/*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_urls: Option<Vec<String>>,
    /// The pre-2.0 path-prefix field. Its mere presence is a fatal parse error rather
    /// than an ignored extra: under the old semantics an unscoped user reached
    /// everything, so silently dropping it would fail *open*. See [`compile_access`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_paths: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_keys: Vec<ApiKeySpec>,
    /// `notes` and anything else an operator wrote here. Round-tripped untouched.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One static API key belonging to a [`UserSpec`]. The `bbk_` bearer itself never
/// appears here — only `key_hash`. Mint keys with `bb-auth-adm key add`.
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
    /// Absent ⇒ inherit the owning user's scope; present (even empty) ⇒ this key's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_urls: Option<Vec<String>>,
    /// Fatal if present, exactly as on [`UserSpec::enabled_paths`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_paths: Option<Value>,
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

/// Compile a parsed access file into the runtime table. An unknown field on a [`SiteSpec`],
/// a residual `enabled_paths`, or a malformed URL pattern are hard errors (so a SIGHUP
/// reload keeps the old table); an individual malformed *key* is warned about and skipped
/// so one bad `key_hash` can't drop every user.
///
/// Scope errors are deliberately fatal rather than skip-with-warning: a dropped
/// scope entry silently changes who can reach what. `bb-auth --check-users` exists
/// so a deploy can catch that before restarting the service, and `bb-auth-adm` runs it on
/// every edit *before* writing, so it cannot save a file that would brick the gate.
///
/// Emails are additionally required to be [`header_safe_email`], since every one of
/// them can end up in `X-Auth-Email`.
pub fn compile_access(file: &AccessFile) -> Result<Access, String> {
    // Sites, in file order — `Sites::resolve` is first-match-wins, so the order is part
    // of the meaning. A malformed pattern is fatal, exactly as in a user's scope.
    let mut entries = Vec::with_capacity(file.sites.len());
    for s in &file.sites {
        let name = match s.name.trim() {
            "" => "?".to_string(),
            n => n.to_string(),
        };
        let urls = UrlScope::compile(&s.urls).map_err(|e| format!("site '{name}': {e}"))?;
        if urls.is_empty() {
            eprintln!("[bb-auth] WARNING: site '{name}' has no urls — it matches nothing");
        }
        let login_url = match &s.login_url {
            Some(u) => Some(compile_login_url(u).map_err(|e| format!("site '{name}': {e}"))?),
            None => None,
        };
        entries.push(SiteRecord {
            name,
            urls,
            public_auth: s.public_auth,
            login_url,
        });
    }
    let sites = Sites { entries };

    let denied: HashSet<String> = file
        .denied
        .iter()
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .collect();

    let mut by_email = HashMap::new();
    let mut by_key_hash = HashMap::new();
    for u in &file.users {
        let email = u.email.trim().to_ascii_lowercase();
        if email.is_empty() {
            eprintln!("[bb-auth] WARNING: users entry with empty email, skipping");
            continue;
        }
        if !header_safe_email(&email) {
            // Warn-and-skip like an empty email: dropping a user denies them, which is
            // fail-closed. `{email:?}` escapes the very control bytes we are rejecting,
            // so a crafted file cannot forge log lines on its way out.
            eprintln!("[bb-auth] WARNING: users entry {email:?} is not printable ASCII, skipping");
            continue;
        }
        if u.enabled_paths.is_some() {
            return Err(format!(
                "{email}: 'enabled_paths' is no longer supported; use 'authorized_urls' \
                 with full <scheme>://<host>/<path> patterns"
            ));
        }
        let user_scope = match &u.authorized_urls {
            Some(list) => UrlScope::compile(list).map_err(|e| format!("{email}: {e}"))?,
            None => UrlScope::deny_all(),
        };
        if user_scope.is_empty() {
            eprintln!(
                "[bb-auth] WARNING: {email} has no authorized_urls — every request from this \
                 user is denied (use [\"*://*/*\"] to grant every URL)"
            );
        }
        if denied.contains(&email) {
            eprintln!(
                "[bb-auth] WARNING: {email} is listed in users and in denied — denied wins, \
                 on every credential and every site"
            );
        }
        for k in &u.api_keys {
            if k.enabled_paths.is_some() {
                return Err(format!(
                    "{email} key '{}': 'enabled_paths' is no longer supported; use 'authorized_urls'",
                    k.id
                ));
            }
            let hash = k.key_hash.trim().to_ascii_lowercase();
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                eprintln!(
                    "[bb-auth] WARNING: {email} key '{}': invalid key_hash, skipping",
                    k.id
                );
                continue;
            }
            let expires = match key_expiry(&k.released, &k.duration) {
                Some(e) => e,
                None => {
                    eprintln!(
                        "[bb-auth] WARNING: {email} key '{}': bad released/duration, skipping",
                        k.id
                    );
                    continue;
                }
            };
            let scope = match &k.authorized_urls {
                Some(list) => {
                    UrlScope::compile(list).map_err(|e| format!("{email} key '{}': {e}", k.id))?
                }
                None => user_scope.clone(),
            };
            let key_id = if k.id.trim().is_empty() {
                "?".to_string()
            } else {
                k.id.trim().to_string()
            };
            by_key_hash.insert(
                hash,
                ApiKeyRecord {
                    email: email.clone(),
                    key_id,
                    expires,
                    scope,
                },
            );
        }
        by_email.insert(email, UserRecord { scope: user_scope });
    }
    Ok(Access {
        sites,
        denied,
        by_email,
        by_key_hash,
    })
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

    /// `read_access(path).unwrap_err()` without forcing `Debug` onto `Access`.
    fn users_err(path: &std::path::Path) -> String {
        match read_access(path.to_str().unwrap()) {
            Ok(_) => panic!("expected {} to be rejected", path.display()),
            Err(e) => e,
        }
    }

    /// The same, straight from a JSON literal.
    fn access_err(name: &str, json: &str) -> String {
        let tmp = users_tmp(name, json);
        let e = users_err(&tmp);
        let _ = std::fs::remove_file(&tmp);
        e
    }

    #[test]
    fn read_access_parses_authorized_urls() {
        let hash = sha256_hex("bbk_secret");
        let other = sha256_hex("bbk_two");
        let json = format!(
            r#"{{
              "users": [
                {{ "email": "Alice@Example.com" }},
                {{ "email": "carol@x.com", "authorized_urls": ["*://*/*"] }},
                {{ "email": "bob@x.com", "authorized_urls": ["https://mcp.x.com/mcp/*"],
                   "api_keys": [
                     {{ "id": "laptop", "key_hash": "{hash}", "released": "1970-01-01",
                        "duration": "1d",
                        "authorized_urls": ["https://mcp.x.com/mcp/foo/*"], "notes": "ignored" }},
                     {{ "id": "nolimit", "key_hash": "{other}", "released": "2026-01-01",
                        "duration": "never" }}
                   ] }}
              ]
            }}"#
        );
        let tmp = users_tmp("ok", &json);
        let u = read_access(tmp.to_str().unwrap()).unwrap();

        // no `sites` / `denied` sections => today's behaviour, bit for bit
        assert!(u.sites.entries.is_empty());
        assert!(!u.sites.any_public_auth());
        assert!(u.sites.resolve(Some("https://mcp.x.com/mcp")).is_none());
        assert!(u.denied.is_empty());

        assert!(u.by_email.contains_key("alice@example.com")); // lowercased
        assert!(u.by_email.contains_key("bob@x.com"));
        // listed but with no authorized_urls => reaches nothing
        assert!(u.by_email["alice@example.com"].scope.is_empty());
        assert!(!u.by_email["alice@example.com"]
            .scope
            .allows(Some("https://anything/")));
        // the explicit blanket grant
        assert!(u.by_email["carol@x.com"]
            .scope
            .allows(Some("https://anything/at/all")));
        assert_eq!(u.by_key_hash.len(), 2);

        let rec = u.by_key_hash.get(&hash).unwrap();
        assert_eq!(rec.email, "bob@x.com");
        assert_eq!(rec.key_id, "laptop");
        assert_eq!(rec.expires, Some(86_400)); // 1970-01-01 + 1d
        assert!(rec.scope.allows(Some("https://mcp.x.com/mcp/foo/bar")));
        assert!(!rec.scope.allows(Some("https://mcp.x.com/mcp/other"))); // narrower than user

        // key with no authorized_urls inherits the user's scope
        let inherit = u.by_key_hash.get(&other).unwrap();
        assert_eq!(inherit.expires, None);
        assert!(inherit.scope.allows(Some("https://mcp.x.com/mcp/anything")));
        assert!(!inherit.scope.allows(Some("https://mcp.x.com/nope")));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_access_rejects_enabled_paths() {
        // A pre-2.0 file must fail loudly: silently ignoring the field would leave
        // the user unscoped (fail-open).
        let tmp = users_tmp(
            "legacy",
            r#"{ "users": [ { "email": "bob@x.com", "enabled_paths": ["/mcp/"] } ] }"#,
        );
        let err = users_err(&tmp);
        assert!(err.contains("enabled_paths"), "{err}");
        assert!(err.contains("authorized_urls"), "{err}");
        let _ = std::fs::remove_file(&tmp);

        // …including when it hides on a key rather than the user
        let hash = sha256_hex("bbk_x");
        let tmp = users_tmp(
            "legacy-key",
            &format!(
                r#"{{ "users": [ {{ "email": "bob@x.com", "api_keys": [
                     {{ "id": "k", "key_hash": "{hash}", "released": "2026-01-01",
                        "duration": "never", "enabled_paths": ["/mcp/"] }} ] }} ] }}"#
            ),
        );
        let err = users_err(&tmp);
        assert!(err.contains("enabled_paths"), "{err}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_access_rejects_malformed_url() {
        let tmp = users_tmp(
            "badurl",
            r#"{ "users": [ { "email": "bob@x.com", "authorized_urls": ["/mcp/"] } ] }"#,
        );
        let err = users_err(&tmp);
        assert!(err.contains("bob@x.com"), "{err}");
        assert!(err.contains("<scheme>://<host>/<path>"), "{err}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_access_skips_header_unsafe_email() {
        // A CR in an email is a response-splitting gadget once it reaches
        // X-Auth-Email, so the entry is dropped — and with it every key it owns,
        // which would otherwise resolve to an email that never passed the guard.
        let hash = sha256_hex("bbk_evil");
        let json = format!(
            r#"{{ "users": [
                {{ "email": "ok@x.com", "authorized_urls": ["https://x.com/*"] }},
                {{ "email": "béatrice@x.com", "authorized_urls": ["https://x.com/*"] }},
                {{ "email": "bad\r\nX-Admin: 1@x.com",
                   "authorized_urls": ["https://x.com/*"],
                   "api_keys": [ {{ "id": "k", "key_hash": "{hash}",
                                    "released": "2026-01-01", "duration": "never" }} ] }}
              ] }}"#
        );
        let tmp = users_tmp("unsafe-email", &json);
        let u = read_access(tmp.to_str().unwrap()).unwrap();

        assert!(u.by_email.contains_key("ok@x.com"));
        assert_eq!(u.by_email.len(), 1, "both unsafe entries must be skipped");
        assert!(
            u.by_key_hash.is_empty(),
            "a skipped user must not leave a live key behind"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    // --- sites + denied -----------------------------------------------------

    /// One `public_auth` site over /app1, one plain user confined to /other.
    pub(crate) const SITES_JSON: &str = r#"{
      "sites": [
        { "name": "app1",
          "urls": ["https://app.x.com/app1", "https://app.x.com/app1/*"],
          "public_auth": true }
      ],
      "denied": ["  Spammer@X.com  ", ""],
      "users": [
        { "email": "bob@x.com", "authorized_urls": ["https://app.x.com/other/*"] },
        { "email": "spammer@x.com", "authorized_urls": ["*://*/*"] }
      ]
    }"#;

    #[test]
    fn read_access_parses_sites_and_denied() {
        let a = access_of("sites", SITES_JSON);

        assert_eq!(a.sites.entries.len(), 1);
        assert!(a.sites.any_public_auth());
        let site = a.sites.resolve(Some("https://app.x.com/app1/x")).unwrap();
        assert_eq!(site.name, "app1");
        assert!(site.public_auth);
        // bare /app1 needs its own pattern — a non-terminal `*` never crosses `/`
        assert_eq!(
            a.sites
                .resolve(Some("https://app.x.com/app1"))
                .unwrap()
                .name,
            "app1"
        );
        assert!(a.sites.resolve(Some("https://app.x.com/app2")).is_none());

        // `denied` is trimmed + lowercased, and empties are dropped
        assert!(a.denied.contains("spammer@x.com"));
        assert_eq!(a.denied.len(), 1);
    }

    #[test]
    fn public_auth_site_grants_an_unenrolled_identity() {
        let a = access_of("sites-grant", SITES_JSON);
        let app1 = Some("https://app.x.com/app1/thing");

        // nobody's in the table, and that is the whole point
        assert!(!a.by_email.contains_key("newcomer@x.com"));
        assert_eq!(
            decide(&a, "newcomer@x.com", app1),
            Decision::SiteGrant("app1".into())
        );
        // off the site, the roster decides as before
        assert_eq!(
            decide(&a, "newcomer@x.com", Some("https://app.x.com/other/x")),
            Decision::NotEnrolled
        );
        assert_eq!(
            decide(&a, "bob@x.com", Some("https://app.x.com/other/x")),
            Decision::RosterGrant
        );
        // an enrolled user out of their own scope still walks into the open site
        assert!(decide(&a, "bob@x.com", app1).granted());
    }

    #[test]
    fn denied_outranks_every_grant() {
        let a = access_of("sites-denied", SITES_JSON);
        // spammer is enrolled with `*://*/*` — the veto beats the roster …
        assert_eq!(
            decide(&a, "spammer@x.com", Some("https://app.x.com/other/x")),
            Decision::Vetoed
        );
        // … and it beats a public_auth site, which never consults the roster at all
        assert_eq!(
            decide(&a, "spammer@x.com", Some("https://app.x.com/app1")),
            Decision::Vetoed
        );
    }

    #[test]
    fn public_auth_site_never_rescues_an_unknown_api_key() {
        // A key is not an identity Cognito vouches for: unknown stays unknown, even on an
        // open site. And a known key dies with its owner's veto.
        let hash = sha256_hex("bbk_spam");
        let json = format!(
            r#"{{ "sites": [ {{ "name": "app1", "urls": ["https://app.x.com/app1/*"],
                                "public_auth": true }} ],
                  "denied": ["spammer@x.com"],
                  "users": [ {{ "email": "spammer@x.com", "authorized_urls": ["*://*/*"],
                     "api_keys": [ {{ "id": "k", "key_hash": "{hash}",
                                      "released": "2026-01-01", "duration": "never" }} ] }} ] }}"#
        );
        let a = access_of("sites-apikey", &json);
        let app1 = Some("https://app.x.com/app1/x");

        assert!(matches!(
            decide_api_key(&a, &sha256_hex("bbk_unknown"), app1, now()),
            KeyDecision::Unknown
        ));
        assert!(matches!(
            decide_api_key(&a, &hash, app1, now()),
            KeyDecision::OwnerDenied(_)
        ));
    }

    #[test]
    fn api_key_expiry_and_scope() {
        let hash = sha256_hex("bbk_k");
        let json = format!(
            r#"{{ "users": [ {{ "email": "bob@x.com",
                   "authorized_urls": ["https://mcp.x.com/mcp/*"],
                   "api_keys": [ {{ "id": "laptop", "key_hash": "{hash}",
                                    "released": "1970-01-01", "duration": "1d" }} ] }} ] }}"#
        );
        let a = access_of("key-expiry", &json);
        let in_scope = Some("https://mcp.x.com/mcp/tools");

        // one second before the 1970-01-02 expiry it is live, one second after it is not
        assert!(decide_api_key(&a, &hash, in_scope, 86_399).granted());
        assert!(matches!(
            decide_api_key(&a, &hash, in_scope, 86_400),
            KeyDecision::Expired(_)
        ));
        // and it inherits the owner's scope, which does not reach here
        assert!(matches!(
            decide_api_key(&a, &hash, Some("https://mcp.x.com/other"), 0),
            KeyDecision::OutOfScope(_)
        ));
        // a granted key hands back its owner — the identity the application sees
        match decide_api_key(&a, &hash, in_scope, 0) {
            KeyDecision::Granted(rec) => assert_eq!(rec.email, "bob@x.com"),
            _ => panic!("expected the key to be granted"),
        }
    }

    #[test]
    fn site_resolve_is_first_match_wins() {
        // A broad site listed first answers for everything under it — including the
        // narrower public_auth site after it, which therefore never opens. Order is
        // meaning; specific sites go first.
        let json = r#"{ "sites": [
            { "name": "everything", "urls": ["https://app.x.com/*"] },
            { "name": "app1", "urls": ["https://app.x.com/app1/*"], "public_auth": true }
          ] }"#;
        let a = access_of("sites-order", json);
        assert_eq!(
            a.sites
                .resolve(Some("https://app.x.com/app1/x"))
                .unwrap()
                .name,
            "everything"
        );
        assert_eq!(
            decide(&a, "newcomer@x.com", Some("https://app.x.com/app1/x")),
            Decision::NotEnrolled
        );

        // reversed, app1 answers for itself and grants
        let json = r#"{ "sites": [
            { "name": "app1", "urls": ["https://app.x.com/app1/*"], "public_auth": true },
            { "name": "everything", "urls": ["https://app.x.com/*"] }
          ] }"#;
        let a = access_of("sites-order2", json);
        assert_eq!(
            a.sites
                .resolve(Some("https://app.x.com/app1/x"))
                .unwrap()
                .name,
            "app1"
        );
        assert!(decide(&a, "newcomer@x.com", Some("https://app.x.com/app1/x")).granted());
        // and `everything` still answers — granting nothing — for the rest
        assert_eq!(
            a.sites.resolve(Some("https://app.x.com/z")).unwrap().name,
            "everything"
        );
        assert!(!decide(&a, "newcomer@x.com", Some("https://app.x.com/z")).granted());
    }

    #[test]
    fn site_resolve_rejects_traversal_and_a_missing_url() {
        // Sites match through UrlScope::allows precisely so these two denials cannot be
        // forgotten on this path: a `..` URL resolving to a public_auth site would be a
        // traversal straight past every scope.
        let a = access_of("sites-traversal", SITES_JSON);
        assert!(a
            .sites
            .resolve(Some("https://app.x.com/app1/../admin"))
            .is_none());
        assert!(a.sites.resolve(None).is_none());
        assert!(!decide(
            &a,
            "newcomer@x.com",
            Some("https://app.x.com/app1/../admin")
        )
        .granted());
        assert!(!decide(&a, "newcomer@x.com", None).granted());
    }

    #[test]
    fn a_site_that_grants_nothing_is_invisible() {
        // public_auth:false == no site at all, today. It exists to carry future fields.
        let a = access_of(
            "site-inert",
            r#"{ "sites": [ { "name": "app1", "urls": ["https://app.x.com/app1/*"] } ],
                 "users": [ { "email": "b@x.com", "authorized_urls": ["https://app.x.com/app1/*"] } ] }"#,
        );
        assert!(!a.sites.any_public_auth());
        assert!(!decide(&a, "newcomer@x.com", Some("https://app.x.com/app1/x")).granted());
        // the roster is untouched by the site's presence
        assert!(decide(&a, "b@x.com", Some("https://app.x.com/app1/x")).granted());
    }

    #[test]
    fn read_access_rejects_a_malformed_site_url() {
        // Fatal, exactly like a user's scope: a dropped site pattern silently changes who
        // reaches what.
        let err = access_err(
            "site-badurl",
            r#"{ "sites": [ { "name": "app1", "urls": ["/app1/*"] } ] }"#,
        );
        assert!(err.contains("app1"), "{err}");
        assert!(err.contains("<scheme>://<host>/<path>"), "{err}");
    }

    #[test]
    fn read_access_rejects_an_unknown_site_field() {
        // The day `public_auth` gains a `require_email_domain` companion, a typo in it
        // must not silently leave `public_auth: true` standing alone.
        let err = access_err(
            "site-typo",
            r#"{ "sites": [ { "name": "app1", "urls": ["https://app.x.com/app1/*"],
                              "public_auth": true, "require_email_domains": "x.com" } ] }"#,
        );
        assert!(err.contains("require_email_domains"), "{err}");

        // …while the sections that describe people keep ignoring extras
        let a = access_of(
            "user-extra",
            r#"{ "_comment": "hi", "users": [ { "email": "b@x.com", "notes": "ok",
                 "authorized_urls": ["https://x.com/*"] } ] }"#,
        );
        assert!(a.by_email.contains_key("b@x.com"));
    }

    #[test]
    fn read_access_rejects_a_malformed_site_login_url() {
        let err = access_err(
            "site-badlogin",
            r#"{ "sites": [ { "name": "app1", "urls": ["https://app.x.com/app1/*"],
                              "login_url": "http://login.x.com/" } ] }"#,
        );
        assert!(err.contains("app1"), "{err}");
        assert!(err.contains("https://"), "{err}");
    }

    #[test]
    fn login_url_falls_back_through_site_then_global() {
        let json = r#"{ "sites": [
            { "name": "app1", "urls": ["https://app.x.com/app1/*"], "public_auth": true,
              "login_url": "https://signup.x.com/" },
            { "name": "plain", "urls": ["https://app.x.com/plain/*"] }
          ] }"#;
        let a = access_of("sites-login", json);
        let global = "https://login.x.com/";

        // the site that speaks for the URL names its own login page …
        assert_eq!(
            login_url_for(&a, global, Some("https://app.x.com/app1/x")),
            "https://signup.x.com/"
        );
        // … a site declaring none falls back to the global …
        assert_eq!(
            login_url_for(&a, global, Some("https://app.x.com/plain/x")),
            global
        );
        // … and so does a URL no site covers, or no URL at all
        assert_eq!(
            login_url_for(&a, global, Some("https://app.x.com/elsewhere")),
            global
        );
        assert_eq!(login_url_for(&a, global, None), global);

        // Every value is header-safe by construction — respond_unauthorized asserts it.
        for u in ["https://app.x.com/app1/x", "https://app.x.com/elsewhere"] {
            let l = login_url_for(&a, global, Some(u));
            assert!(l.bytes().all(|b| b.is_ascii_graphic()), "{l}");
        }
    }

    // --- the document model (what bb-auth-adm edits) -------------------------

    #[test]
    fn access_file_round_trips_and_preserves_operator_notes() {
        // An edit must not eat the documentation an operator wrote. Unknown keys on the
        // root, on a user and on a key survive a parse → serialize cycle; the gate
        // ignores them, `bb-auth-adm` hands them back.
        let json = r#"{
          "_comment": ["a note to the next operator"],
          "sites": [ { "name": "app1", "urls": ["https://app.x.com/app1/*"],
                       "public_auth": true } ],
          "denied": ["spammer@x.com"],
          "users": [ { "email": "bob@x.com", "authorized_urls": ["https://x.com/*"],
                       "notes": "keep me",
                       "api_keys": [ { "id": "laptop", "key_hash": "aa", "released": "2026-01-01",
                                       "duration": "365d", "notes": "and me" } ] } ]
        }"#;
        let doc: AccessFile = serde_json::from_str(json).unwrap();
        assert_eq!(doc.extra["_comment"][0], "a note to the next operator");
        assert_eq!(doc.users[0].extra["notes"], "keep me");
        assert_eq!(doc.users[0].api_keys[0].extra["notes"], "and me");

        let out = serde_json::to_string(&doc).unwrap();
        let back: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(back["_comment"][0], "a note to the next operator");
        assert_eq!(back["users"][0]["notes"], "keep me");
        assert_eq!(back["users"][0]["api_keys"][0]["notes"], "and me");
        // a site's public_auth is always written out, even when false — it is the
        // security-relevant field, and its absence must not have to be inferred
        assert_eq!(back["sites"][0]["public_auth"], true);
        // and nothing we did not put there appears: no nulls for absent options
        assert!(back["users"][0].get("enabled_paths").is_none());
        assert!(back["sites"][0].get("login_url").is_none());

        // An empty roster serializes to `"users": []`, never to a missing key: the file
        // is still a well-formed access file that the gate will load (granting nobody).
        let empty = serde_json::to_string(&AccessFile::default()).unwrap();
        assert_eq!(empty, r#"{"users":[]}"#);
        assert!(compile_access(&serde_json::from_str(&empty).unwrap()).is_ok());
    }

    #[test]
    fn compile_access_is_what_check_users_runs() {
        // The point of the document model: what a tool is about to write can be handed to
        // the very parser the gate will use, before it hits the disk.
        let mut doc = AccessFile::default();
        doc.users.push(UserSpec {
            email: "bob@x.com".into(),
            authorized_urls: Some(vec!["https://x.com/*".into()]),
            ..Default::default()
        });
        assert!(compile_access(&doc)
            .unwrap()
            .by_email
            .contains_key("bob@x.com"));

        // …and a malformed scope is caught there, not at the next restart
        doc.users[0].authorized_urls = Some(vec!["/x".into()]);
        match compile_access(&doc) {
            Ok(_) => panic!("a malformed scope must not compile"),
            Err(e) => assert!(e.contains("bob@x.com"), "{e}"),
        }
    }
}
