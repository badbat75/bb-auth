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
//! `url_groups` names a reusable set of URLs ([`UrlGroups`]), `sites` describe URL areas
//! ([`Sites`]), `denied` vetoes people, `users` is the roster.
//! Access is **enumerated, never assumed**: an absent or empty `authorized_urls` grants
//! nothing, and a URL no site covers is not open. There are exactly two grant sources —
//! the roster's [`UrlScope`] and a `public_auth` [`SiteRecord`] — and one veto that
//! outranks both, on every credential. [`decide`] is that rule.

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

/// Compiled [`AccessFile::url_groups`]: a group name → the patterns it stands for.
///
/// A group is abbreviation, nothing more. Any URL-pattern list — a user's or a key's
/// `authorized_urls`, a site's `urls` — may name one with `@name`, and
/// [`UrlScope::compile_with_groups`] splices that group's patterns in at load. Nothing
/// downstream of [`compile_access`] ever sees a reference: [`Access`], [`decide`] and the
/// gate work on flat patterns exactly as they did before groups existed.
///
/// A [`BTreeMap`] because group order carries no meaning — sorted is the one order that
/// survives a round-trip through `bb-auth-adm` unchanged.
pub type UrlGroups = BTreeMap<String, Vec<UrlPattern>>;

/// The group a URL-pattern list entry references (`"@mcp"` ⇒ `Some("mcp")`), or `None`
/// for a plain pattern.
///
/// The one place the `@` sigil is spelled out. `bb-auth-adm` calls it to find who
/// references what, so the tool and the gate cannot come to disagree about which entries
/// are references — the same reason there is one matcher and one parser.
pub fn group_ref(entry: &str) -> Option<&str> {
    entry.trim().strip_prefix('@')
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

    /// Compile a JSON `authorized_urls` list with no [`UrlGroups`] in scope — so every
    /// `@name` entry in it is, correctly, an unknown group. [`compile_access`] always
    /// goes through [`UrlScope::compile_with_groups`]; this is for callers that have a
    /// list and no file, such as `bb-auth-adm`'s site-shadowing lint.
    pub fn compile(list: &[String]) -> Result<UrlScope, String> {
        UrlScope::compile_with_groups(list, &UrlGroups::new())
    }

    /// Compile a URL-pattern list, expanding `@name` entries against `groups`.
    ///
    /// The expansion is a splice: a reference contributes that group's already-compiled
    /// patterns and nothing else, so the result is as flat as a list that never mentioned
    /// a group, and the three lists that can carry a reference (a user's scope, a key's,
    /// a site's `urls`) all reach it through here.
    ///
    /// An unknown reference is an **error**, never a dropped entry — the same reflex as a
    /// malformed pattern, because a silently skipped entry changes who can reach what.
    /// The message names only the group; the caller prefixes the referrer, which is what
    /// makes it say `bob@x.com: unknown url group '@mcp'`.
    pub fn compile_with_groups(list: &[String], groups: &UrlGroups) -> Result<UrlScope, String> {
        let mut patterns = Vec::with_capacity(list.len());
        for raw in list.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            match group_ref(raw) {
                Some(name) => match groups.get(name) {
                    Some(g) => patterns.extend(g.iter().cloned()),
                    None => return Err(format!("unknown url group '@{name}'")),
                },
                None => patterns.push(compile_pattern(raw)?),
            }
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
/// { "url_groups": { "mcp": ["https://mcp.x.com/mcp", "https://mcp.x.com/mcp/*"] },
///   "sites": [
///     { "name": "app1", "urls": ["https://app.x.com/app1",
///                                "https://app.x.com/app1/*"], "public_auth": true }
///   ],
///   "denied": ["spammer@x.com"],
///   "users": [
///     { "email": "bob@x.com",
///       "authorized_urls": ["@mcp"],
///       "api_keys": [
///         { "id": "laptop", "key_hash": "<sha256 hex of the bbk_… bearer>",
///           "released": "2026-07-08", "duration": "365d",
///           "authorized_urls": ["@mcp"] }
///       ] },
///     { "email": "alice@x.com", "authorized_urls": ["*://*/*"] }
/// ] }
/// ```
///
/// The four sections are siblings and answer four different questions: `url_groups` names
/// a reusable set of URLs, `sites` describe URL areas, `denied` vetoes people, `users` is
/// the roster. Access is enumerated, never assumed, from either of the two grant sources:
/// a user with no `authorized_urls` reaches nothing, and a URL with no site is not open.
/// "Everything" is the explicit pattern `*://*/*`. Validate a file before shipping it with
/// `bb-auth --check-users <file>`, or `bb-auth-adm check` — the same parser,
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
    /// Named URL-pattern groups: `"mcp": ["https://mcp.x.com/mcp/*"]`. Any URL-pattern
    /// list — a user's or a key's `authorized_urls`, a site's `urls` — names one as
    /// `"@mcp"`, and [`compile_access`] splices its patterns in at load ([`UrlGroups`]).
    ///
    /// Deliberately shallow, and deliberately strict: a name is `[A-Za-z0-9_-]+` matched
    /// exactly (case-sensitive), a group may not reference another group, an unknown
    /// reference is fatal, and every group's patterns are validated even when nothing
    /// references them. All of it is the same reflex as a malformed pattern — an entry
    /// that silently vanished would change who can reach what. Duplicate JSON keys are
    /// serde's last-wins, as everywhere else in this file.
    ///
    /// First, so a document reads its definitions before their uses. An **older** binary
    /// preserves the section (it lands in `extra`) but does not understand it: each
    /// `@name` entry fails [`compile_pattern`], which is a fatal load rather than a
    /// partial grant. Fail-closed — and the reason to deploy the binary before the file.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub url_groups: BTreeMap<String, Vec<String>>,
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

/// A site's name as everything that speaks of one spells it: trimmed, and `"?"` when the
/// file leaves it out. [`compile_access`] stamps it into [`SiteRecord::name`] for the
/// gate's logs, and every tool that lists or reports a site says the same thing.
pub fn site_name(s: &SiteSpec) -> String {
    match s.name.trim() {
        "" => "?".to_string(),
        n => n.to_string(),
    }
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

/// Compile the `url_groups` section: validate every name and every pattern, once, up
/// front. Errors are prefixed `url_groups '<name>': …`.
///
/// Unreferenced groups are compiled too, and a bad one is just as fatal — a group that
/// only breaks the day someone first references it is a trap laid for a future edit, and
/// the whole point of `--check-users` is that the file is checked before it is live.
///
/// Groups are flat by construction: an entry that is itself a reference is rejected here,
/// so [`UrlScope::compile_with_groups`] can splice with no recursion, no cycle detection
/// and no order dependence between definitions.
fn compile_url_groups(raw: &BTreeMap<String, Vec<String>>) -> Result<UrlGroups, String> {
    let mut out = UrlGroups::new();
    for (name, list) in raw {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(format!(
                "url_groups '{name}': a group name must be non-empty and [A-Za-z0-9_-]"
            ));
        }
        let mut patterns = Vec::with_capacity(list.len());
        for entry in list.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if let Some(g) = group_ref(entry) {
                return Err(format!(
                    "url_groups '{name}': '@{g}' — a group cannot reference another group"
                ));
            }
            patterns.push(compile_pattern(entry).map_err(|e| format!("url_groups '{name}': {e}"))?);
        }
        if patterns.is_empty() {
            eprintln!(
                "[bb-auth] WARNING: url group '{name}' has no urls — a reference to it grants \
                 nothing"
            );
        }
        out.insert(name.clone(), patterns);
    }
    Ok(out)
}

/// Compile a parsed access file into the runtime table. An unknown field on a [`SiteSpec`],
/// a residual `enabled_paths`, a malformed URL pattern or a dangling `@group` reference are
/// hard errors (so a SIGHUP reload keeps the old table); an individual malformed *key* is
/// warned about and skipped so one bad `key_hash` can't drop every user.
///
/// Scope errors are deliberately fatal rather than skip-with-warning: a dropped
/// scope entry silently changes who can reach what. `bb-auth --check-users` exists
/// so a deploy can catch that before restarting the service, and `bb-auth-adm` runs it on
/// every edit *before* writing, so it cannot save a file that would brick the gate.
///
/// Emails are additionally required to be [`header_safe_email`], since every one of
/// them can end up in `X-Auth-Email`.
pub fn compile_access(file: &AccessFile) -> Result<Access, String> {
    // Expanded here and nowhere else: every scope below is flat by the time it is stored,
    // so `decide` and the gate never learn that groups exist.
    let groups = compile_url_groups(&file.url_groups)?;

    // Sites, in file order — `Sites::resolve` is first-match-wins, so the order is part
    // of the meaning. A malformed pattern is fatal, exactly as in a user's scope.
    let mut entries = Vec::with_capacity(file.sites.len());
    for s in &file.sites {
        let name = site_name(s);
        let urls = UrlScope::compile_with_groups(&s.urls, &groups)
            .map_err(|e| format!("site '{name}': {e}"))?;
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
            Some(list) => {
                UrlScope::compile_with_groups(list, &groups).map_err(|e| format!("{email}: {e}"))?
            }
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
                Some(list) => UrlScope::compile_with_groups(list, &groups)
                    .map_err(|e| format!("{email} key '{}': {e}", k.id))?,
                // The owner's scope, already expanded — a key inherits patterns, never a
                // reference to re-resolve.
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

/// The roster position of `email`, matched as [`norm_email`] matches.
pub fn user_pos(doc: &AccessFile, email: &str) -> Option<usize> {
    let want = norm_email(email);
    doc.users.iter().position(|u| norm_email(&u.email) == want)
}

/// The roster row for `email`, to edit in place.
pub fn user_mut<'a>(doc: &'a mut AccessFile, email: &str) -> Result<&'a mut UserSpec, String> {
    match user_pos(doc, email) {
        Some(i) => Ok(&mut doc.users[i]),
        None => Err(format!(
            "no user '{}' (add them with: user add {})",
            email.trim(),
            email.trim()
        )),
    }
}

/// One of `email`'s API keys, by its `id` (trimmed, case-sensitive — an id is a label, not
/// an address).
pub fn key_mut<'a>(
    doc: &'a mut AccessFile,
    email: &str,
    id: &str,
) -> Result<&'a mut ApiKeySpec, String> {
    let owner = norm_email(email);
    let u = user_mut(doc, email)?;
    match u.api_keys.iter().position(|k| k.id.trim() == id.trim()) {
        Some(i) => Ok(&mut u.api_keys[i]),
        None => Err(format!("{owner}: no api key '{id}'")),
    }
}

/// The position of the site named `name`. A position, not a reference, because site order
/// is meaning ([`Sites`]) and every caller ends up needing the index.
pub fn site_pos(doc: &AccessFile, name: &str) -> Option<usize> {
    doc.sites.iter().position(|s| s.name.trim() == name.trim())
}

/// A url group's pattern list, to edit in place.
pub fn url_group_mut<'a>(
    doc: &'a mut AccessFile,
    name: &str,
) -> Result<&'a mut Vec<String>, String> {
    let name = name.trim();
    doc.url_groups
        .get_mut(name)
        .ok_or_else(|| format!("no url group '@{name}'"))
}

/// Everything that names `@name`: users by email, keys as `email/id`, sites as
/// `site 'NAME'`.
///
/// [`group_ref`] is what decides whether an entry is a reference, so this cannot drift from
/// what [`compile_access`] expands. The gate would refuse a file with a dangling reference
/// anyway — [`AccessWrite::prepare`] compiles before anything is written — and this is what
/// turns that refusal into a list of places to go and fix.
pub fn url_group_refs(doc: &AccessFile, name: &str) -> Vec<String> {
    let names = |urls: &[String]| urls.iter().any(|u| group_ref(u) == Some(name));
    let mut out = Vec::new();
    for s in &doc.sites {
        if names(&s.urls) {
            out.push(format!("site '{}'", site_name(s)));
        }
    }
    for u in &doc.users {
        if u.authorized_urls.as_deref().is_some_and(names) {
            out.push(norm_email(&u.email));
        }
        for k in &u.api_keys {
            if k.authorized_urls.as_deref().is_some_and(names) {
                out.push(format!("{}/{}", norm_email(&u.email), k.id.trim()));
            }
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

/// Enrol `user`, whose email is normalised on the way in. Refuses a second row for an
/// address that is already on the roster: the gate builds a `HashMap`, so a duplicate is
/// not an error there — the last row silently wins, and the one an operator is reading may
/// not be the one in force.
pub fn add_user(doc: &mut AccessFile, mut user: UserSpec) -> Result<(), String> {
    user.email = norm_email(&user.email);
    if user_pos(doc, &user.email).is_some() {
        return Err(format!(
            "{} is already in users (edit them: user set {})",
            user.email, user.email
        ));
    }
    doc.users.push(user);
    Ok(())
}

/// Give `email`'s row a new address.
///
/// The collision is checked before the row is even located: "that address is taken" is the
/// more useful complaint of the two, and it is the one an operator hears today.
pub fn rename_user(doc: &mut AccessFile, email: &str, new_email: &str) -> Result<(), String> {
    let new = norm_email(new_email);
    if new != norm_email(email) && user_pos(doc, &new).is_some() {
        return Err(format!("{new} is already in users"));
    }
    user_mut(doc, email)?.email = new;
    Ok(())
}

/// Drop `email`'s row, and with it every key it owned — a key is a grant *tied to a user*,
/// and an orphan would be a credential with nobody to answer for it. The removed row comes
/// back so a caller can say what went with it.
///
/// Removing a user does **not** keep them off a `public_auth` site: there the roster is
/// never consulted. That is what [`Access::denied`] is for.
pub fn remove_user(doc: &mut AccessFile, email: &str) -> Result<UserSpec, String> {
    let i = user_pos(doc, email).ok_or_else(|| format!("no user '{}'", norm_email(email)))?;
    Ok(doc.users.remove(i))
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
    email: &str,
    mut key: ApiKeySpec,
) -> Result<SealedKey, String> {
    let id = key.id.trim().to_string();
    let owner = norm_email(email);
    let u = user_mut(doc, email)?;
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
pub fn remove_api_key(doc: &mut AccessFile, email: &str, id: &str) -> Result<ApiKeySpec, String> {
    let owner = norm_email(email);
    let u = user_mut(doc, email)?;
    let i = u
        .api_keys
        .iter()
        .position(|k| k.id.trim() == id.trim())
        .ok_or_else(|| format!("{owner}: no api key '{id}'"))?;
    Ok(u.api_keys.remove(i))
}

/// Insert a site at `at` (`None` = last, out of range = last), and hand back where it
/// landed. A name is required and must be free: it is how every other command addresses
/// the record.
///
/// A site describes a **place**, never a person — there is no argument here that names a
/// user, and there never may be one ([`SiteRecord`]).
pub fn add_site(
    doc: &mut AccessFile,
    mut site: SiteSpec,
    at: Option<usize>,
) -> Result<usize, String> {
    site.name = site.name.trim().to_string();
    if site.name.is_empty() {
        return Err("a site needs a name".into());
    }
    if site_pos(doc, &site.name).is_some() {
        return Err(format!(
            "site '{}' already exists (edit it: site set {})",
            site.name, site.name
        ));
    }
    let at = at.unwrap_or(doc.sites.len()).min(doc.sites.len());
    doc.sites.insert(at, site);
    Ok(at)
}

/// Rename a site, refusing a name another record already answers to.
pub fn rename_site(doc: &mut AccessFile, name: &str, new_name: &str) -> Result<(), String> {
    let i = site_pos(doc, name).ok_or_else(|| format!("no site '{}'", name.trim()))?;
    let new = new_name.trim().to_string();
    if site_pos(doc, &new).is_some_and(|j| j != i) {
        return Err(format!("site '{new}' already exists"));
    }
    doc.sites[i].name = new;
    Ok(())
}

/// Move the site at `from` to position `to`; a position that does not exist is a no-op.
///
/// Order is meaning: [`Sites::resolve`] is first-match-wins, so this changes which record
/// answers for a URL — and therefore who gets in, and which login page a `401` names.
pub fn move_site(doc: &mut AccessFile, from: usize, to: usize) {
    if from >= doc.sites.len() || to >= doc.sites.len() {
        return;
    }
    let s = doc.sites.remove(from);
    doc.sites.insert(to, s);
}

/// Drop a site, handing back the record that went — a `public_auth` one takes an unenrolled
/// identity's only way in with it.
pub fn remove_site(doc: &mut AccessFile, name: &str) -> Result<SiteSpec, String> {
    let i = site_pos(doc, name).ok_or_else(|| format!("no site '{}'", name.trim()))?;
    Ok(doc.sites.remove(i))
}

/// Define a url group. A group is abbreviation, not a grant: defining one authorizes nobody
/// until some urls list names it `@name`.
///
/// There is deliberately no rename: a reference names a group by its exact spelling, so
/// renaming one would silently re-point every list that used it. Add the new name, move the
/// references, drop the old one — three edits the gate re-validates one by one.
pub fn add_url_group(doc: &mut AccessFile, name: &str, urls: Vec<String>) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("a url group needs a name".into());
    }
    if doc.url_groups.contains_key(&name) {
        return Err(format!(
            "url group '@{name}' already exists (edit it: url-group set {name})"
        ));
    }
    doc.url_groups.insert(name, urls);
    Ok(())
}

/// Drop a url group, refusing while anything still references it — the gate would reject
/// the resulting file ([`UrlScope::compile_with_groups`]), and the refusal here says which
/// lists to fix instead of leaving a write to fail.
pub fn remove_url_group(doc: &mut AccessFile, name: &str) -> Result<Vec<String>, String> {
    let name = name.trim().to_string();
    if !doc.url_groups.contains_key(&name) {
        return Err(format!("no url group '@{name}'"));
    }
    let refs = url_group_refs(doc, &name);
    if !refs.is_empty() {
        return Err(format!(
            "url group '@{name}' is still referenced by {} — the gate would reject the file. \
             Change those lists first, then remove the group.",
            refs.join(", ")
        ));
    }
    Ok(doc.url_groups.remove(&name).unwrap_or_default())
}

/// Veto `email`, normalised. `false` = it was already there (or empty), and nothing changed.
///
/// Not the same as deleting the user's row: on a `public_auth` site the roster is never
/// consulted, so for an un-enrolled identity this is the only denial there is — and for an
/// enrolled one it is a suspension, since their scope and keys survive it.
pub fn add_denied(doc: &mut AccessFile, email: &str) -> bool {
    let e = norm_email(email);
    if e.is_empty() || doc.denied.iter().any(|d| norm_email(d) == e) {
        return false;
    }
    doc.denied.push(e);
    true
}

/// Lift the veto on every listed email, returning how many rows went.
pub fn remove_denied(doc: &mut AccessFile, emails: &[String]) -> usize {
    let want: Vec<String> = emails.iter().map(|e| norm_email(e)).collect();
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

    // --- url groups ---------------------------------------------------------

    #[test]
    fn url_groups_expand_in_user_scope() {
        let a = access_of(
            "groups-user",
            r#"{ "url_groups": { "mcp": ["https://mcp.x.com/mcp", "https://mcp.x.com/mcp/*"] },
                 "users": [ { "email": "bob@x.com",
                              "authorized_urls": ["@mcp", "https://other.x.com/*"] } ] }"#,
        );
        let s = &a.by_email["bob@x.com"].scope;
        assert!(s.allows(Some("https://mcp.x.com/mcp")));
        assert!(s.allows(Some("https://mcp.x.com/mcp/tools")));
        assert!(s.allows(Some("https://other.x.com/a"))); // the plain entry beside it
        assert!(!s.allows(Some("https://mcp.x.com/elsewhere")));
        assert_eq!(
            decide(&a, "bob@x.com", Some("https://mcp.x.com/mcp/tools")),
            Decision::RosterGrant
        );
        assert_eq!(
            decide(&a, "bob@x.com", Some("https://mcp.x.com/elsewhere")),
            Decision::OutOfScope
        );
    }

    #[test]
    fn url_groups_expand_in_a_key_scope_and_in_what_it_inherits() {
        let own = sha256_hex("bbk_own");
        let inherited = sha256_hex("bbk_inherit");
        let a = access_of(
            "groups-key",
            &format!(
                r#"{{ "url_groups": {{ "mcp": ["https://mcp.x.com/mcp/*"],
                                       "admin": ["https://mcp.x.com/admin/*"] }},
                      "users": [ {{ "email": "bob@x.com", "authorized_urls": ["@mcp"],
                        "api_keys": [
                          {{ "id": "own", "key_hash": "{own}", "released": "2026-01-01",
                             "duration": "never", "authorized_urls": ["@admin"] }},
                          {{ "id": "inherit", "key_hash": "{inherited}",
                             "released": "2026-01-01", "duration": "never" }}
                        ] }} ] }}"#
            ),
        );
        // its own list expands independently of the owner's
        let k = &a.by_key_hash[&own].scope;
        assert!(k.allows(Some("https://mcp.x.com/admin/x")));
        assert!(!k.allows(Some("https://mcp.x.com/mcp/x")));
        // and a key with no list inherits the owner's *expanded* scope
        let i = &a.by_key_hash[&inherited].scope;
        assert!(i.allows(Some("https://mcp.x.com/mcp/x")));
        assert!(!i.allows(Some("https://mcp.x.com/admin/x")));
        assert!(decide_api_key(&a, &inherited, Some("https://mcp.x.com/mcp/x"), now()).granted());
    }

    #[test]
    fn url_groups_expand_in_a_site() {
        let a = access_of(
            "groups-site",
            r#"{ "url_groups": { "onboarding": ["https://app.x.com/welcome",
                                                "https://app.x.com/welcome/*"] },
                 "sites": [ { "name": "signup", "urls": ["@onboarding"],
                              "public_auth": true } ] }"#,
        );
        // an un-enrolled identity walks in, exactly as with the patterns spelled out
        assert_eq!(
            decide(
                &a,
                "newcomer@x.com",
                Some("https://app.x.com/welcome/step1")
            ),
            Decision::SiteGrant("signup".into())
        );
        assert_eq!(
            decide(&a, "newcomer@x.com", Some("https://app.x.com/welcome")),
            Decision::SiteGrant("signup".into())
        );
        assert_eq!(
            decide(&a, "newcomer@x.com", Some("https://app.x.com/elsewhere")),
            Decision::NotEnrolled
        );
    }

    #[test]
    fn url_groups_unknown_reference_is_fatal_and_names_the_referrer() {
        // Fatal like a malformed pattern: a dropped entry silently changes who reaches
        // what, and the message has to say which list to go and fix.
        let err = access_err(
            "groups-unknown-user",
            r#"{ "users": [ { "email": "bob@x.com", "authorized_urls": ["@mcp"] } ] }"#,
        );
        assert!(err.contains("bob@x.com"), "{err}");
        assert!(err.contains("unknown url group '@mcp'"), "{err}");

        let err = access_err(
            "groups-unknown-site",
            r#"{ "sites": [ { "name": "mpa", "urls": ["@x"] } ] }"#,
        );
        assert!(err.contains("site 'mpa'"), "{err}");
        assert!(err.contains("unknown url group '@x'"), "{err}");

        let hash = sha256_hex("bbk_g");
        let err = access_err(
            "groups-unknown-key",
            &format!(
                r#"{{ "users": [ {{ "email": "bob@x.com", "api_keys": [
                     {{ "id": "laptop", "key_hash": "{hash}", "released": "2026-01-01",
                        "duration": "never", "authorized_urls": ["@mcp"] }} ] }} ] }}"#
            ),
        );
        assert!(err.contains("bob@x.com key 'laptop'"), "{err}");
        assert!(err.contains("unknown url group '@mcp'"), "{err}");
    }

    #[test]
    fn url_groups_nested_reference_is_fatal() {
        // Flat by construction: no recursion, no cycles, no order between definitions.
        let err = access_err(
            "groups-nested",
            r#"{ "url_groups": { "a": ["https://x.com/*"], "b": ["@a"] } }"#,
        );
        assert!(err.contains("url_groups 'b'"), "{err}");
        assert!(err.contains("cannot reference another group"), "{err}");
    }

    #[test]
    fn url_groups_bad_name_is_fatal() {
        for json in [
            r#"{ "url_groups": { "bad name": ["https://x.com/*"] } }"#,
            r#"{ "url_groups": { "": ["https://x.com/*"] } }"#,
            r#"{ "url_groups": { "mcp/x": ["https://x.com/*"] } }"#,
        ] {
            let err = access_err("groups-badname", json);
            assert!(err.contains("url_groups"), "{err}");
            assert!(err.contains("[A-Za-z0-9_-]"), "{err}");
        }
        assert!(compile_access(
            &serde_json::from_str(r#"{ "url_groups": { "mcp-v2_1": ["https://x.com/*"] } }"#)
                .unwrap()
        )
        .is_ok());
    }

    #[test]
    fn url_groups_are_validated_even_when_unreferenced() {
        // A group that only breaks the day someone first references it is a trap laid
        // for a future edit — `--check-users` has to see it now.
        let err = access_err(
            "groups-unreferenced-bad",
            r#"{ "url_groups": { "mcp": ["/mcp/"] },
                 "users": [ { "email": "b@x.com", "authorized_urls": ["*://*/*"] } ] }"#,
        );
        assert!(err.contains("url_groups 'mcp'"), "{err}");
        assert!(err.contains("<scheme>://<host>/<path>"), "{err}");
    }

    #[test]
    fn url_groups_empty_group_grants_nothing() {
        let a = access_of(
            "groups-empty",
            r#"{ "url_groups": { "todo": [] },
                 "users": [ { "email": "b@x.com", "authorized_urls": ["@todo"] } ] }"#,
        );
        assert!(a.by_email["b@x.com"].scope.is_empty());
        assert_eq!(
            decide(&a, "b@x.com", Some("https://x.com/a")),
            Decision::OutOfScope
        );
    }

    #[test]
    fn url_groups_absent_changes_nothing() {
        // The regression that matters: a file that mentions no group compiles, decides
        // and serializes exactly as it did before groups existed.
        let a = access_of("groups-absent", SITES_JSON);
        assert_eq!(
            decide(&a, "bob@x.com", Some("https://app.x.com/other/x")),
            Decision::RosterGrant
        );
        assert_eq!(
            decide(&a, "newcomer@x.com", Some("https://app.x.com/app1")),
            Decision::SiteGrant("app1".into())
        );

        let doc: AccessFile = serde_json::from_str(SITES_JSON).unwrap();
        assert!(doc.url_groups.is_empty());
        let out = serde_json::to_string(&doc).unwrap();
        assert!(!out.contains("url_groups"), "{out}");
    }

    #[test]
    fn url_groups_round_trip_through_the_document_model() {
        let json = r#"{ "url_groups": { "mcp": ["https://mcp.x.com/mcp/*"],
                                        "admin": ["https://x.com/admin/*"] },
                        "users": [ { "email": "bob@x.com", "authorized_urls": ["@mcp"] } ] }"#;
        let doc: AccessFile = serde_json::from_str(json).unwrap();
        assert_eq!(
            doc.url_groups["mcp"],
            vec!["https://mcp.x.com/mcp/*".to_string()]
        );

        let out = serde_json::to_string(&doc).unwrap();
        // definitions before uses, and sorted: a BTreeMap has no order to lose
        assert!(out.starts_with(r#"{"url_groups":{"admin":"#), "{out}");
        // a reference is stored as written — nothing expands it on the way to disk
        assert!(out.contains(r#""authorized_urls":["@mcp"]"#), "{out}");
        let back: AccessFile = serde_json::from_str(&out).unwrap();
        assert_eq!(back.url_groups, doc.url_groups);
        assert!(compile_access(&back).is_ok());

        // What an older binary makes of the same file: it keeps the section (unknown
        // top-level keys land in `extra`) and refuses to load, because a reference is
        // not a URL pattern. Fail-closed, never a partial grant.
        assert!(compile_pattern("@mcp").is_err());
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

    // --- editing an access file ---------------------------------------------

    /// One user, one key, one group, two sites — every shape an edit can reach, with the
    /// trimming and casing an operator's hand leaves behind.
    const EDIT_JSON: &str = r#"{
      "_comment": "hands off",
      "url_groups": { "mcp": ["https://mcp.x.com/mcp/*"] },
      "sites": [
        { "name": "app1", "urls": ["https://app.x.com/app1/*"], "public_auth": true },
        { "name": " spaced ", "urls": ["https://app.x.com/two/*"] }
      ],
      "denied": ["spammer@x.com"],
      "users": [
        { "email": "Bob@X.com", "authorized_urls": ["@mcp"],
          "api_keys": [ { "id": " laptop ", "key_hash": "aa", "released": "2026-01-01",
                          "duration": "365d" } ] }
      ]
    }"#;

    /// The document model straight from JSON — the edits that never touch a file.
    fn doc_of(json: &str) -> AccessFile {
        serde_json::from_str(json).unwrap()
    }

    /// `unwrap_err` for the mutations whose success value has no `Debug`. None of the specs
    /// derive one, and [`Access`] deliberately does not either.
    fn err_of<T>(r: Result<T, String>) -> String {
        match r {
            Ok(_) => panic!("expected a refusal"),
            Err(e) => e,
        }
    }

    #[test]
    fn the_lookups_trim_and_lowercase_like_the_gate() {
        let mut doc = doc_of(EDIT_JSON);
        assert_eq!(norm_email("  Bob@X.com "), "bob@x.com");
        assert_eq!(user_pos(&doc, " BOB@x.com "), Some(0));
        assert_eq!(user_pos(&doc, "nobody@x.com"), None);
        // the lookup normalises; the row keeps whatever spelling the file gave it
        assert_eq!(user_mut(&mut doc, "BOB@X.com").unwrap().email, "Bob@X.com");
        assert!(err_of(user_mut(&mut doc, " ghost@x.com ")).contains("no user 'ghost@x.com'"));

        // a key id is a label, not an address: trimmed, but matched case-sensitively
        assert_eq!(
            key_mut(&mut doc, "bob@x.com", " laptop ")
                .unwrap()
                .id
                .trim(),
            "laptop"
        );
        assert!(key_mut(&mut doc, "bob@x.com", "LAPTOP").is_err());
        assert!(
            err_of(key_mut(&mut doc, "BOB@x.com", "nope")).contains("bob@x.com: no api key 'nope'")
        );

        assert_eq!(site_pos(&doc, "spaced"), Some(1));
        assert_eq!(site_name(&doc.sites[1]), "spaced");
        assert_eq!(site_name(&SiteSpec::default()), "?");
        assert_eq!(url_group_mut(&mut doc, " mcp ").unwrap().len(), 1);
        assert!(err_of(url_group_mut(&mut doc, "nope")).contains("no url group '@nope'"));
    }

    #[test]
    fn edit_urls_sets_adds_deduplicates_removes_and_clears() {
        let a = || "https://x.com/a/*".to_string();
        let b = || "https://x.com/b/*".to_string();
        let no: Vec<String> = Vec::new();

        // a full replacement wins over what was there
        let mut urls = Some(vec![a()]);
        assert!(edit_urls(
            &mut urls,
            vec![b()],
            no.clone(),
            no.clone(),
            false
        ));
        assert_eq!(urls, Some(vec![b()]));
        // add appends, and says so — or says nothing changed, which is what "no-op" means
        assert!(edit_urls(
            &mut urls,
            no.clone(),
            vec![a()],
            no.clone(),
            false
        ));
        assert_eq!(urls, Some(vec![b(), a()]));
        assert!(!edit_urls(
            &mut urls,
            no.clone(),
            vec![a()],
            no.clone(),
            false
        ));
        assert!(!edit_urls(
            &mut urls,
            no.clone(),
            no.clone(),
            vec!["https://x.com/z/*".to_string()],
            false
        ));
        assert!(edit_urls(
            &mut urls,
            no.clone(),
            no.clone(),
            vec![b()],
            false
        ));
        assert_eq!(urls, Some(vec![a()]));

        // cleared is *absent*: deny-all for a user, "inherit the owner's" for a key
        assert!(edit_urls(
            &mut urls,
            no.clone(),
            no.clone(),
            no.clone(),
            true
        ));
        assert_eq!(urls, None);
        assert!(edit_urls(
            &mut urls,
            no.clone(),
            vec![a()],
            no.clone(),
            true
        ));
        assert_eq!(urls, Some(vec![a()]));

        // a plain list has no absent state to fall back to, so cleared is empty
        let mut list = vec![a()];
        assert!(edit_url_list(
            &mut list,
            no.clone(),
            no.clone(),
            no.clone(),
            true
        ));
        assert!(list.is_empty());
        assert!(edit_url_list(&mut list, vec![b()], no.clone(), no, false));
        assert_eq!(list, vec![b()]);
    }

    #[test]
    fn open_access_file_refuses_a_file_the_gate_would_reject() {
        // An edit has to start from a file that works, or a tool would cheerfully fix one
        // problem while carrying a fatal one to the disk.
        let path = users_tmp(
            "edit-open-bad",
            r#"{ "users": [ { "email": "b@x.com", "authorized_urls": ["@nope"] } ] }"#,
        );
        let err = err_of(open_access_file(path.to_str().unwrap()));
        assert!(
            err.contains("the gate would reject this file as it stands"),
            "{err}"
        );
        assert!(err.contains("unknown url group '@nope'"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn access_write_refuses_a_document_the_gate_would_reject() {
        let path = users_tmp("edit-reject", EDIT_JSON);
        let p = path.to_str().unwrap().to_string();
        let before = std::fs::read_to_string(&path).unwrap();

        let (mut doc, _) = open_access_file(&p).unwrap();
        doc.users[0].authorized_urls = Some(vec!["@nope".into()]);
        let err = err_of(AccessWrite::prepare(&doc));
        assert!(err.starts_with("refusing to write:"), "{err}");
        assert!(err.contains("unknown url group '@nope'"), "{err}");

        // The check is ahead of the disk in every sense: the file is byte-for-byte what it
        // was, and not even a backup was taken.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert!(!std::path::Path::new(&format!("{p}.bak")).exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn access_write_commits_exactly_the_bytes_it_compiled() {
        let path = users_tmp("edit-commit", EDIT_JSON);
        let p = path.to_str().unwrap().to_string();
        let before = std::fs::read_to_string(&path).unwrap();

        let (mut doc, _) = open_access_file(&p).unwrap();
        add_user(
            &mut doc,
            UserSpec {
                email: "  Carol@X.com  ".into(),
                authorized_urls: Some(vec!["https://x.com/c/*".into()]),
                ..Default::default()
            },
        )
        .unwrap();

        let write = AccessWrite::prepare(&doc).unwrap();
        assert_eq!(write.access().by_email.len(), 2); // the counts a caller reports
        let written = write.commit(&p).unwrap();

        // what landed is the byte string that was compiled, newline-terminated
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, write.json());
        assert!(on_disk.ends_with("}\n"));
        // it parses back to the same document — the operator's `_comment` included — and
        // re-rendering it is a fixed point, so a show/save round-trip changes no bytes
        let back: AccessFile = serde_json::from_str(&on_disk).unwrap();
        assert_eq!(back.extra["_comment"], "hands off");
        assert_eq!(render_access_file(&back).unwrap(), on_disk);
        assert!(compile_access(&back)
            .unwrap()
            .by_email
            .contains_key("carol@x.com"));
        // and the file it replaced is one step back
        assert_eq!(std::fs::read_to_string(&written.backup).unwrap(), before);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&written.backup);
    }

    #[test]
    fn add_api_key_seals_the_bearer_until_the_file_carries_its_hash() {
        let path = users_tmp(
            "edit-mint",
            r#"{ "users": [ { "email": "bob@x.com", "authorized_urls": ["https://x.com/*"] } ] }"#,
        );
        let p = path.to_str().unwrap().to_string();
        let (mut doc, _) = open_access_file(&p).unwrap();

        let sealed = add_api_key(
            &mut doc,
            " BOB@x.com ",
            ApiKeySpec {
                id: " laptop ".into(),
                released: "2026-01-01".into(),
                duration: "365d".into(),
                ..Default::default()
            },
        )
        .unwrap();
        // the document carries the hash; the bearer is still in nobody's hands
        let hash = doc.users[0].api_keys[0].key_hash.clone();
        assert_eq!(hash.len(), 64);
        assert_eq!(doc.users[0].api_keys[0].id, "laptop");

        // a second key with that id is refused, and mints nothing
        let err = err_of(add_api_key(
            &mut doc,
            "bob@x.com",
            ApiKeySpec {
                id: "laptop".into(),
                ..Default::default()
            },
        ));
        assert!(
            err.contains("bob@x.com already has a key 'laptop'"),
            "{err}"
        );
        assert_eq!(doc.users[0].api_keys.len(), 1);

        // Only a completed write opens it — `reveal` takes the receipt, so there is no
        // order in which a caller holds the bearer and the file does not hold its hash.
        let written = AccessWrite::prepare(&doc).unwrap().commit(&p).unwrap();
        let bearer = sealed.reveal(&written);
        assert!(bearer.starts_with(API_KEY_PREFIX));
        assert_eq!(sha256_hex(&bearer), hash);
        // and the gate, reading what was written, grants that very bearer
        let access = read_access(&p).unwrap();
        assert!(decide_api_key(&access, &hash, Some("https://x.com/a"), 0).granted());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&written.backup);
    }

    #[test]
    fn rotate_api_key_replaces_the_hash_and_redates_the_row() {
        let mut doc = doc_of(EDIT_JSON);
        let before = doc.users[0].api_keys[0].key_hash.clone();
        let _sealed = rotate_api_key(&mut doc, "BOB@X.com", " laptop ").unwrap();

        let k = &doc.users[0].api_keys[0];
        assert_ne!(k.key_hash, before);
        assert_eq!(k.key_hash.len(), 64);
        assert_eq!(k.released, format_date(now())); // the window restarts today
        assert_eq!(k.duration, "365d"); // same row, same window, same scope
        assert_eq!(k.id.trim(), "laptop");
        assert!(rotate_api_key(&mut doc, "bob@x.com", "nope").is_err());
        assert!(rotate_api_key(&mut doc, "ghost@x.com", "laptop").is_err());
    }

    #[test]
    fn add_user_and_add_site_refuse_a_duplicate() {
        let mut doc = doc_of(EDIT_JSON);
        // The gate builds a HashMap, so a duplicate is not an error there — the last row
        // silently wins, and the one an operator is reading may not be the one in force.
        let err = err_of(add_user(
            &mut doc,
            UserSpec {
                email: "  BOB@x.com ".into(),
                ..Default::default()
            },
        ));
        assert!(err.contains("bob@x.com is already in users"), "{err}");
        assert_eq!(doc.users.len(), 1);
        add_user(
            &mut doc,
            UserSpec {
                email: " Carol@X.com ".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(doc.users[1].email, "carol@x.com"); // normalised on the way in

        let named = |n: &str| SiteSpec {
            name: n.into(),
            ..Default::default()
        };
        assert!(err_of(add_site(&mut doc, named("  "), None)).contains("a site needs a name"));
        assert!(err_of(add_site(&mut doc, named(" app1 "), None))
            .contains("site 'app1' already exists"));
        // a position: `None` is last, out of range is last, and the name is trimmed
        assert_eq!(add_site(&mut doc, named(" first "), Some(0)).unwrap(), 0);
        assert_eq!(doc.sites[0].name, "first");
        assert_eq!(add_site(&mut doc, named("last"), Some(99)).unwrap(), 3);
        assert_eq!(site_pos(&doc, "last"), Some(3));
    }

    #[test]
    fn rename_user_refuses_a_collision_before_it_looks_for_the_row() {
        let mut doc = doc_of(EDIT_JSON);
        add_user(
            &mut doc,
            UserSpec {
                email: "carol@x.com".into(),
                ..Default::default()
            },
        )
        .unwrap();
        // "that address is taken" is the more useful of the two complaints, so it comes
        // first — even when the row being renamed does not exist either.
        let err = err_of(rename_user(&mut doc, "ghost@x.com", "Carol@X.com"));
        assert!(err.contains("carol@x.com is already in users"), "{err}");
        assert!(err_of(rename_user(&mut doc, "ghost@x.com", "ghost2@x.com"))
            .contains("no user 'ghost@x.com'"));

        rename_user(&mut doc, "BOB@x.com", "  Bobby@X.com ").unwrap();
        assert_eq!(doc.users[0].email, "bobby@x.com");
        assert_eq!(doc.users[0].api_keys.len(), 1); // the row keeps its keys and its scope
        rename_user(&mut doc, "bobby@x.com", "bobby@x.com").unwrap(); // to itself: allowed
    }

    #[test]
    fn remove_user_hands_back_the_row_and_the_keys_that_went_with_it() {
        let mut doc = doc_of(EDIT_JSON);
        let u = remove_user(&mut doc, " BOB@X.com ").unwrap();
        // a key is a grant tied to a user; an orphan would answer to nobody
        assert_eq!(u.api_keys.len(), 1);
        assert!(doc.users.is_empty());
        assert!(err_of(remove_user(&mut doc, "bob@x.com")).contains("no user 'bob@x.com'"));
        // …and the removal is not a lockout: that site is public_auth, so `denied` is the
        // only thing that would keep them out of it.
        assert!(compile_access(&doc).unwrap().sites.any_public_auth());
    }

    #[test]
    fn remove_site_and_remove_api_key_hand_back_what_went() {
        let mut doc = doc_of(EDIT_JSON);
        let s = remove_site(&mut doc, " app1 ").unwrap();
        assert!(s.public_auth); // the caller has to be able to say what it opened
        assert_eq!(doc.sites.len(), 1);
        assert!(err_of(remove_site(&mut doc, "app1")).contains("no site 'app1'"));

        let k = remove_api_key(&mut doc, "BOB@X.com", " laptop ").unwrap();
        assert_eq!(k.id.trim(), "laptop");
        assert!(doc.users[0].api_keys.is_empty());
        assert!(err_of(remove_api_key(&mut doc, "bob@x.com", "laptop"))
            .contains("bob@x.com: no api key 'laptop'"));
    }

    #[test]
    fn remove_url_group_refuses_while_something_references_it() {
        let mut doc = doc_of(EDIT_JSON);
        assert_eq!(url_group_refs(&doc, "mcp"), vec!["bob@x.com".to_string()]);
        let err = err_of(remove_url_group(&mut doc, " mcp "));
        assert!(err.contains("still referenced by bob@x.com"), "{err}");
        assert!(doc.url_groups.contains_key("mcp"));

        // the scanner names sites and keys too — a refusal is only useful if it says where
        doc.sites[0].urls.push("@mcp".into());
        doc.users[0].api_keys[0].authorized_urls = Some(vec!["@mcp".into()]);
        assert_eq!(
            url_group_refs(&doc, "mcp"),
            vec![
                "site 'app1'".to_string(),
                "bob@x.com".to_string(),
                "bob@x.com/laptop".to_string()
            ]
        );

        // once nothing names it, it goes — and its patterns come back
        doc.sites[0].urls.pop();
        doc.users[0].api_keys[0].authorized_urls = None;
        doc.users[0].authorized_urls = Some(vec!["https://x.com/*".into()]);
        assert_eq!(
            remove_url_group(&mut doc, "mcp").unwrap(),
            vec!["https://mcp.x.com/mcp/*".to_string()]
        );
        assert!(err_of(remove_url_group(&mut doc, "mcp")).contains("no url group '@mcp'"));

        // adding one back is refused while the name is taken, and needs a name at all
        add_url_group(&mut doc, " mcp ", vec!["https://mcp.x.com/mcp/*".into()]).unwrap();
        assert!(err_of(add_url_group(&mut doc, "mcp", vec![])).contains("already exists"));
        assert!(err_of(add_url_group(&mut doc, "  ", vec![])).contains("a url group needs a name"));
    }

    #[test]
    fn move_site_reorders_and_ignores_a_position_that_does_not_exist() {
        // Order is meaning: first match wins, so a move changes who answers for a URL.
        let mut doc = doc_of(
            r#"{ "sites": [
                   { "name": "app1", "urls": ["https://app.x.com/app1/*"], "public_auth": true },
                   { "name": "broad", "urls": ["https://app.x.com/*"] } ] }"#,
        );
        let at = Some("https://app.x.com/app1/x");
        assert!(decide(&compile_access(&doc).unwrap(), "new@x.com", at).granted());

        move_site(&mut doc, 1, 0); // the broad record now answers, and it grants nothing
        assert_eq!(site_name(&doc.sites[0]), "broad");
        assert!(!decide(&compile_access(&doc).unwrap(), "new@x.com", at).granted());

        // a position that does not exist is a no-op, never a panic and never a reshuffle
        move_site(&mut doc, 9, 0);
        move_site(&mut doc, 0, 9);
        assert_eq!(site_name(&doc.sites[0]), "broad");
    }

    #[test]
    fn denied_edits_normalize_the_email() {
        let mut doc = doc_of(EDIT_JSON);
        assert!(add_denied(&mut doc, "  NEW@X.com  "));
        assert_eq!(
            doc.denied,
            vec!["spammer@x.com".to_string(), "new@x.com".to_string()]
        );
        // already vetoed, in any spelling — and an empty entry is not a veto
        assert!(!add_denied(&mut doc, "New@x.com"));
        assert!(!add_denied(&mut doc, "   "));
        assert_eq!(doc.denied.len(), 2);

        assert_eq!(
            remove_denied(&mut doc, &["NEW@x.com".into(), "nobody@x.com".into()]),
            1
        );
        assert_eq!(remove_denied(&mut doc, &["nobody@x.com".into()]), 0);
        assert_eq!(doc.denied, vec!["spammer@x.com".to_string()]);
    }
}
