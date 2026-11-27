//! bb-auth-core, **the files bb-auth's programs share**: the access file above all, plus
//! the settings file beside it. Their schemas, their parsers, the URL matcher every check
//! goes through, and the authorization decision itself.
//!
//! This library exists for exactly one reason: there are programs that must agree, byte for
//! byte, on what a shared file *means*.
//!
//! * `bb-auth`, the gate, reads both ([`read_access`], [`decide`], [`read_settings`]).
//! * `bb-auth-adm`, the admin CLI, edits both, and must never write a file the gate would
//!   reject, nor believe it granted something the gate will not.
//! * `bb-auth-web`, the admin GUI, edits both through the same door.
//!
//! A second parser, or a second matcher, would be a second answer to "who may reach
//! what". So there is one of each, and it lives here. The gate keeps everything neither file
//! has an opinion about — HTTP, the session cookie, id_token validation, the nginx
//! contract — in its own single file, and neither admin tool links any of it.
//!
//! The same argument reaches one step further than the meaning of a file: **how one is
//! edited and written** ([`AccessWrite`], [`SettingsWrite`], [`open_access_file`], and the
//! document mutations beside them) is also something more than one program has to get right
//! byte for byte. Validate-before-write, atomic replace, mode and owner preserved: one
//! implementation, here.
//!
//! # Two files, and the line between them
//!
//! The access file answers **who reaches what**. The settings file holds the handful of
//! values that change *how the gate answers* and that must take effect **without a restart**,
//! and it is a file, rather than more env vars, for one mechanical reason: a process cannot
//! re-read its own environment. See the settings-file section for the three-part rule that
//! decides which of the two a setting belongs in, and why the rest of bb-auth's configuration
//! is in neither.
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
fn page_url_core(raw: &str) -> Result<String, (String, UrlFault)> {
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
fn host_pattern_core(raw: &str) -> Result<UrlPattern, SettingsRefusal> {
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
/// places (with `bb-auth --check-access`) that can catch it in time.
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

    /// Create `path` with these bytes, and only if it does not exist yet.
    ///
    /// The other half of "there is one door". The two `init` commands used to write their
    /// first file with `std::fs::write` and a `chmod` of their own, which is a second way to
    /// put bytes in a place the gate will read: not compiled through the parser, not atomic,
    /// and preceded by an `exists()` check that is a race against itself. Today's payload is
    /// a default document and nothing is wrong with it; the invariant is stated absolutely
    /// so that nobody has to re-derive whether a *particular* instance is safe, and the next
    /// "create from a template" command would copy the shape it found.
    ///
    /// `create_new` is what makes the refusal-to-overwrite an operation of the filesystem
    /// rather than a check the caller does first. The mode is `0640` from the start: the gate
    /// reads this file as a group member and must not be the only one that can, and nobody
    /// else has any business reading it. The owner is left to whoever runs the tool, which is
    /// how the packages arrange it.
    pub fn create(&self, path: &str) -> Result<(), String> {
        create_new_file(path, &self.json)
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
///
/// The temp file is **unique per write**, and the durability is explicit:
///
/// * A shared temp name was the previous shape, on the argument that racing editors should
///   contend for one file rather than each rename its own over the other's work. That
///   argument describes a lost update, which is what the GUI's `rev` check catches; what a
///   shared name buys instead is two writers interleaving their bytes into a file *neither*
///   wrote, which both then rename. A file that does not parse is a fatal startup, i.e. a
///   boot loop, so the cheap answer is a name nobody else can be using.
/// * `sync_all` on the temp file and then on the directory, because "atomic" here means a
///   reader sees the old file or the new one, and says nothing about a machine that loses
///   power between the rename and the writeback. This file is the only current copy of the
///   access list; two `fsync`s per edit is nothing next to reconstructing it.
fn write_atomically(path: &str, content: &str) -> Result<Written, String> {
    let p = std::path::Path::new(path);
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty());
    // Unique per write: pid and a counter, which no other process and no other thread of
    // this one can be holding.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let unique = format!(
        "{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let tmp = match dir {
        Some(d) => d.join(format!(
            ".{}.bb-auth.{unique}.tmp",
            p.file_name().unwrap_or_default().to_string_lossy()
        )),
        None => std::path::PathBuf::from(format!(".{path}.bb-auth.{unique}.tmp")),
    };

    let meta = std::fs::metadata(p).map_err(|e| format!("stat {path}: {e}"))?;
    // Keep one step back. The gate is stateless, but a roster is not reconstructible.
    let bak = format!("{path}.bak");
    std::fs::copy(p, &bak).map_err(|e| format!("backup {bak}: {e}"))?;

    let restore = |e: String| {
        let _ = std::fs::remove_file(&tmp);
        e
    };
    {
        use std::io::Write;
        let mut f =
            std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(content.as_bytes())
            .map_err(|e| restore(format!("write {}: {e}", tmp.display())))?;
        // Before the rename, not after: a rename that lands ahead of the data is how an
        // atomic replace ends up publishing an empty file.
        f.sync_all()
            .map_err(|e| restore(format!("fsync {}: {e}", tmp.display())))?;
    }
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
    // The rename itself is a directory operation, so the directory is what has to be durable
    // for it to survive a power cut. Best effort: on a filesystem that will not open a
    // directory for reading, an unsynced rename is still an improvement on no rename, and
    // failing an edit that has already landed would be the worse answer.
    if let Some(d) = dir {
        if let Ok(h) = std::fs::File::open(d) {
            let _ = h.sync_all();
        }
    }
    Ok(Written {
        backup: std::path::PathBuf::from(bak),
    })
}

/// Create `path` with `content`, refusing to touch a file that is already there.
///
/// Private, beside [`write_atomically`], for the same reason: [`AccessWrite::create`] and
/// [`SettingsWrite::create`] are the only callers, so a first file goes through the same
/// compile-then-write order every later edit does.
///
/// `create_new` makes "only if absent" the filesystem's answer rather than a caller's
/// `exists()` a moment earlier, which is a check whose result can already be stale when it
/// is read.
fn create_new_file(path: &str, content: &str) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // From the first byte, not after a `chmod`: between the two there is a window where
        // the file is world-readable, and what goes in it is an access list.
        opts.mode(0o640);
    }
    let mut f = opts.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => {
            format!("{path} already exists: refusing to overwrite it")
        }
        _ => format!("create {path}: {e}"),
    })?;
    f.write_all(content.as_bytes())
        .map_err(|e| format!("write {path}: {e}"))?;
    f.sync_all().map_err(|e| format!("fsync {path}: {e}"))?;
    Ok(())
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
    let names = |list: &Option<Vec<String>>| {
        list.iter()
            .flatten()
            .any(|g| group_ref(g) == Some(name.trim()))
    };
    for a in &doc.applications {
        for s in &a.scopes {
            let at = format!("{}/{}", a.name.trim(), s.name.trim());
            if names(&s.groups) {
                out.push(at.clone());
            }
            // An `excluded` reference counts every bit as much: `compile_access` refuses an
            // unknown group there too, so removing a group a scope excludes would produce a
            // file the gate rejects, which is exactly what this list exists to prevent.
            if names(&s.excluded) {
                out.push(format!("{at} ({EXCLUDED_REF})"));
            }
        }
    }
    out
}

/// How [`user_refs`] and [`user_group_refs`] mark a reference that keeps someone *out*
/// rather than letting them in. Display only, and one constant so the two agree.
pub const EXCLUDED_REF: &str = "excluded";

/// Resolve one entry an operator typed into a scope's `excluded`, the way the file spells it:
/// an enrolled person becomes their **uuid**, a group stays `@name`, and an email the roster
/// has never heard of stays itself.
///
/// Here, and not in each editor, because it is a statement about what an entry in that field
/// *means*, which is the library's membership test exactly as `decide` and `glob_match` are.
/// The two editors had one each and they had already drifted: the CLI accepted any `@token`
/// as a group, the GUI checked the grammar and that the group existed, so the same file was
/// refused at one form and written by the other.
///
/// A stranger's email is kept rather than refused, and that is the whole point of the field
/// on an `authenticated` scope: that scope admits exactly the people who are in no roster
/// row, so an exclusion that could only name enrolled people would be useless where it is
/// needed most. Anyone the roster *does* know is written as their uuid, so one exclusion
/// covers every identifier they have.
pub fn parse_exclusion(doc: &AccessFile, entry: &str) -> Result<String, String> {
    let raw = entry.trim();
    if raw.starts_with('@') {
        let g = group_ref(raw)
            .filter(|g| !g.is_empty())
            .ok_or_else(|| format!("'{raw}': a group reference is written '@name'"))?;
        if !doc.user_groups.contains_key(g) {
            return Err(format!("'{raw}': no user group '@{g}'"));
        }
        return Ok(raw.to_string());
    }
    if let Some(i) = user_pos(doc, raw) {
        return Ok(doc.users[i].uuid.trim().to_ascii_lowercase());
    }
    if raw.contains('@') {
        return Ok(norm_email(raw));
    }
    Err(format!(
        "'{raw}': not a user, not '@group' and not an email. An exclusion names somebody \
         enrolled, a group, or a stranger by their email"
    ))
}

/// The earlier scope of the same application that makes scope `urls` dead, if there is one:
/// its index, for a message that can name it.
///
/// Scopes are **first match wins in file order**, so a scope whose every pattern is already
/// answered by something above it never speaks, whatever it grants. That is a lint and never
/// an error: it is also how a carve-out is written the wrong way round, and telling an
/// operator which line to move is the whole value of it.
///
/// A heuristic, deliberately. Matching one glob against another has no exact answer
/// (`https://x.com/*` and `*://x.com/app1` cover each other partially), so this asks each of
/// the later scope's own pattern *strings* of the earlier scopes' compiled matchers, which
/// catches the case that actually happens: something broad listed first. Coverage may be
/// **joint**, i.e. each pattern answered by a different earlier scope, because that is what
/// first-match does; the index returned is the scope that answers the first pattern, which is
/// where an operator will look. The CLI used to require one earlier scope to cover the whole
/// list and the GUI did not, so a file was reported dead in one tool and clean in the other.
pub fn shadowing_scope(earlier: &[ScopeSpec], urls: &[String]) -> Option<usize> {
    let mine: Vec<&str> = urls
        .iter()
        .map(|u| u.trim())
        .filter(|u| !u.is_empty())
        .collect();
    if mine.is_empty() || earlier.is_empty() {
        return None;
    }
    // A scope whose patterns do not compile is skipped rather than assumed to cover
    // everything: the parser refuses that file anyway, and a lint must not accuse a scope on
    // the strength of a broken one above it.
    let compiled: Vec<Option<UrlScope>> = earlier
        .iter()
        .map(|s| UrlScope::compile(&s.urls).ok())
        .collect();
    let covering = |u: &str| {
        compiled
            .iter()
            .position(|c| c.as_ref().is_some_and(|c| c.allows(Some(u))))
    };
    let first = covering(mine[0])?;
    mine[1..]
        .iter()
        .all(|u| covering(u).is_some())
        .then_some(first)
}

/// Every place that names `uuid`: scopes as `application/scope`, groups as `@name`.
///
/// What [`remove_user`] sweeps, and what an editor shows before it does. A dangling
/// reference only warns at load, so nothing breaks if one survives; leaving one behind
/// would still be an editor quietly writing a file it knows is wrong.
pub fn user_refs(doc: &AccessFile, uuid: &str) -> Vec<String> {
    let want = norm_email(uuid);
    let mut out = Vec::new();
    let names = |list: &Option<Vec<String>>| list.iter().flatten().any(|u| norm_email(u) == want);
    for a in &doc.applications {
        for s in &a.scopes {
            let at = format!("{}/{}", a.name.trim(), s.name.trim());
            if names(&s.users) {
                out.push(at.clone());
            }
            // Marked, because the two say opposite things about the same row and a sweep
            // that reported them alike would read as if the user had been let in there.
            if names(&s.excluded) {
                out.push(format!("{at} ({EXCLUDED_REF})"));
            }
        }
    }
    for (name, members) in &doc.user_groups {
        if members.iter().any(|m| norm_email(m) == want) {
            out.push(format!("@{name}"));
        }
    }
    // The veto, marked like an exclusion and for the same reason: it is a reference that
    // keeps this person *out*, and a sweep that listed it beside a scope's members would
    // read as if they had been let in there. [`remove_user`] rewrites rather than drops it.
    if doc.denied.iter().any(|d| norm_email(d) == want) {
        out.push(format!("denied ({EXCLUDED_REF})"));
    }
    out
}

/// Apply the standard list edits to an optional list field: a full replacement (`set`),
/// then `add` (deduplicated) and `rm`. Returns `true` if anything changed.
///
/// `None` means "absent", which does not mean the same thing in every field it is used on:
/// on a key's `scopes` it is "every scope the owner reaches", on a scope's own lists it is
/// nobody. So `clear` says which one the caller wants an emptied list to collapse to.
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

/// [`edit_urls`] over a plain list: an application's `base`, a scope's `urls`, a group's
/// members. There is no "inherit" to fall back to in any of them, so a cleared list is
/// empty, never absent.
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
/// sentence. Only new values: an address already in the file is never re-checked, so a row
/// this check would refuse does not block the edits around it.
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
    getrandom::fill(&mut b).map_err(|e| format!("no entropy from the OS: {e}"))?;
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
    // The primary email, taken before anything is swept, because both rewrites below need it:
    // it is the spelling this file uses for an identity the roster does not know, and the
    // identity being removed is about to become exactly that.
    let primary = doc.users[i]
        .emails
        .iter()
        .map(|e| norm_email(e))
        .find(|e| !e.is_empty());
    for a in &mut doc.applications {
        for s in &mut a.scopes {
            if let Some(list) = s.users.as_mut() {
                list.retain(|u| norm_email(u) != uuid);
            }
            // An exclusion is REWRITTEN to that email, not swept, for the reason `denied`
            // below gives: it is a veto, and dropping it lifts it. The sequence is ordinary
            // housekeeping (keep somebody out of one area, tidy the roster afterwards), and
            // with an `authenticated` scope anywhere in the file that person re-registers on
            // Cognito under the same email and walks straight back into the scope they were
            // just shut out of. A row with no email has no stranger spelling to leave behind,
            // so its entry is dropped as it always was.
            if let Some(list) = s.excluded.as_mut() {
                match &primary {
                    Some(email) => {
                        // In place, so the entry keeps its position, and only once: a list
                        // that already names this email, or a second uuid entry, keeps one
                        // line, since two strings naming one identity is the look a stale
                        // reference must not have.
                        let mut written = list.iter().any(|u| norm_email(u) == *email);
                        list.retain_mut(|u| {
                            if norm_email(u) != uuid {
                                return true;
                            }
                            if written {
                                return false;
                            }
                            written = true;
                            *u = email.clone();
                            true
                        });
                    }
                    None => list.retain(|u| norm_email(u) != uuid),
                }
            }
        }
    }
    for members in doc.user_groups.values_mut() {
        members.retain(|m| norm_email(m) != uuid);
    }
    // The veto is REWRITTEN, not swept, and it is the one reference that must not simply go.
    //
    // Every other reference to a removed row is a grant, and a grant naming nobody is a line
    // to delete. `denied` is the opposite: dropping it *lifts* a suspension. The sequence is
    // ordinary housekeeping (suspend somebody, tidy the roster afterwards), and with an
    // `authenticated` scope anywhere in the file the same person then re-registers with
    // Cognito and walks straight back in, which is precisely the walk-back-in the sweep of
    // the other references exists to prevent.
    //
    // So a user veto becomes a stranger veto for the same person: their primary email, which
    // is the spelling `denied` uses for an identity the file has never heard of, and which is
    // exactly what this identity is about to become.
    if let Some(email) = primary {
        for d in doc.denied.iter_mut() {
            if norm_email(d) == uuid {
                *d = email.clone();
            }
        }
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
// The settings file
// ---------------------------------------------------------------------------
//
// The second file this crate owns, and the reason it is a file at all: **everything in it
// takes effect without a restart**. A process cannot re-read its own environment: systemd
// loads `EnvironmentFile=` once, at `ExecStart`, so a setting that must change while the
// gate keeps serving cannot live in an env var, whatever else recommends one. That is the
// whole argument, and it is what is left in `bb-auth.env`: the listener, the worker count,
// the HMAC key, the cookie's name, the path of the access file, and the original-URL header.
//
// The membership rule here is as narrow as the access file's, and deliberately so. A
// setting belongs in this file iff all three hold:
//
// 1. it is read **per request**, so a new value takes effect on the next one: no socket to
//    rebind, no credential to re-issue, no cache to invalidate;
// 2. a wrong value **cannot lock the operator out irreversibly**. The test is not "cannot
//    break a login", since several of these can; it is whether the person who made the edit
//    can still undo it. Nothing here invalidates a cookie, so a bad save leaves every session
//    already minted standing, including the one the editor is holding, and `bb-auth-adm` over
//    SSH is the way back if not. `BB_AUTH_ORIGINAL_URL_HEADER` fails that outright, and
//    `_COOKIE_NAME` fails it by orphaning every cookie already issued;
// 3. it is **not a secret**. The one credential in the system stays in the gate's env file,
//    which no other service reads and no editor writes.
//
// Eighteen settings pass, in three sections, and the file is shaped like what reads them:
// `gate` is the thirteen the gate answers with, `web` is the one the GUI's own door is made
// of, and `ui` is the four that say how a page looks.
//
// **Three of them arrived last and not one passes cleanly**, which belongs here rather than
// in each field's own doc, because what they have in common is the argument they cost.
// `issuer` fails part 1: it is read once, to fetch a JWKS, so a reload has to re-fetch and
// then swap keys and settings together or neither. `cookie_domain` fails part 2 in a way
// nothing else here does: it cannot log anybody out, it does something worse, which is orphan
// every cookie already issued so that a logout stops clearing them, and both editors make it
// a two-step for that reason alone. And `authorized_hosts` was the boundary that made
// `login_url` safe in a file an administrator edits from a browser: the file said where
// people sign in, the environment said which hosts a redirect could land on, and only the
// second was a security boundary. With both in here that sentence is retired, and what
// replaces it covers all three: **this file is trusted as much as the gate itself**, because
// whoever can write it can already write the access file beside it and the admin list inside
// it. What the move buys, and what was not expressible while these lived in two places, is
// that `cookie_domain` must reach every host in `authorized_hosts` or the file is refused. The `ui` four pass the middle part for a reason
// worth stating, because they are the ones that look like they should not: the built-in
// stylesheet is COMPLETE, so an override is only ever an addition to a page that already
// works, and the worst a wrong value there achieves is an unstyled page rather than a closed
// door. They are also the one section BOTH services read, which is what makes one save
// restyle the sign-in page and the admin interface together.
//
// Each service reads its own section and ignores the other's; both go through
// [`compile_settings`], so an edit made by either is one the other would also accept.
//
// The write path is the access file's, unchanged and for the same reason: [`SettingsWrite`]
// is [`AccessWrite`] with a different document, `commit` writes exactly the bytes `prepare`
// compiled, and `write_atomically` stays private so there is no other door.

/// The settings file's `version`. Exactly one accepted value, like the access file's.
pub const SETTINGS_VERSION: u32 = 3;

/// The file name [`default_settings_path`] builds, and the one the packages create.
pub const DEFAULT_SETTINGS_FILE: &str = "settings.json";

/// Where the settings file lives when nothing names it: beside the access file.
///
/// A derived default rather than a second required env var, and that is a lockout argument
/// rather than a convenience: a required variable missing from an operator-owned env file is
/// a fatal startup, and under `Restart=on-failure` a fatal startup is a boot loop. An upgrade
/// that needs no edit to `bb-auth.env` cannot cause one.
/// String surgery rather than [`std::path::Path::join`], and deliberately: the value is
/// echoed back in the startup banner and in every error message about the file, so it must
/// read the way the operator wrote the access path, with the separator they used. Joining
/// through `Path` would rewrite a POSIX path with a backslash when this code is compiled on
/// Windows, which is where it is developed.
pub fn default_settings_path(access_path: &str) -> String {
    match access_path.rfind(['/', '\\']) {
        Some(i) => format!("{}{DEFAULT_SETTINGS_FILE}", &access_path[..=i]),
        None => DEFAULT_SETTINGS_FILE.to_string(),
    }
}

/// The wire name of the header a `401` carries this area's login page in.
///
/// The nginx contract around it is documented on the gate's own `LOGIN_URL_HEADER`, which is
/// this constant: the gate is where that contract belongs. The *string* is here because
/// [`compile_profile_claims`] has to reserve the name, and a claim that quietly stole it
/// would be discovered at runtime, on a header nginx already trusts.
pub const LOGIN_URL_HEADER: &str = "X-Auth-Login-URL";

/// The wire name of the header naming the authorized identity, and what every application
/// behind this gate already reads.
///
/// Here for the same reason [`LOGIN_URL_HEADER`] is, plus one: it is what `bb-auth-web` reads
/// its own administrator's identity out of, so three programs now name it and exactly one
/// should spell it. The nginx wiring is on the gate's constant of the same name.
pub const IDENTITY_HEADER: &str = "X-Auth-Email";

/// The wire name of the header that names **the Cognito user a session is**, and only when
/// that user is one of the pool's own (a native sign-in, no `identities` on the token).
///
/// It is here for the same reason [`IDENTITY_HEADER`] is, plus one: the gate emits it,
/// `bb-auth-web` reads it, and [`compile_profile_claims`] reserves it, so three uses need
/// exactly one spelling. `bb-auth-web` needs it for the profile edit of docs/ARCHITECTURE.md
/// §13.25: that edit must act on the session's own Cognito user, and no email says which one
/// that is. A pool holds a native user and a federated one under the same address, and an edit
/// driven by the email wrote the native twin of a person signed in through a provider, then
/// told them their profile was saved.
///
/// It is **not** an identity attribute and **not** a profile claim. Those are the operator's
/// choice, derived from the roster or self-asserted by the user; this is a fact of the
/// credential that another program's correctness depends on, so an operator switch that
/// could turn it off would silently turn the edit off with it. Reserving the name here is
/// what stops a configured claim from deriving it and answering it with a value the user
/// typed.
pub const NATIVE_USERNAME_HEADER: &str = "X-Auth-Native-Username";

/// The path of the sign-in page the gate serves itself, spelled once because **two programs
/// write one URL**.
///
/// The gate answers a logout, a `401` and an empty `gate.login_url` with this path, and
/// `bb-auth-web` builds the deletion flow's logout `rd` out of it and
/// [`LOGIN_NOTICE_ACCOUNT_DELETED`] (docs/ARCHITECTURE.md §13.32 §1). A constant in each
/// program is two strings that have to agree by eye, and the way they disagree is silent:
/// every browser mid-deletion is sent to a `404`, and the flow's only explanation of itself
/// never appears. The `rd` is relative because `bb-auth-web` knows neither its scheme nor its
/// host, and a path is the shape the gate's own `global_login` answers with for the same
/// reason.
pub const GATE_LOGIN_PATH: &str = "/auth/login";

/// The one notice code the sign-in page understands: arriving at the gate's login page with
/// `?notice=account-deleted` shows one fixed paragraph (docs/ARCHITECTURE.md §13.32 §1,
/// §13.33), the sign-in page of the estate answering "what just happened to my account".
///
/// The code is **fixed, a closed set of one**, and that is what keeps the notice carrying no
/// request data: the query value is compared to this constant byte for byte (case-sensitive,
/// so no casing trick widens the set), and the page's only two changes are the fixed strings
/// `hidden` and `aria-describedby="notice"`. No byte of the query reaches the page, so
/// AGENTS.md's "request data reaches a page in exactly one place, `data-rd`" stays true in
/// substance: a code selects an element, nothing is reflected. A second notice is a second
/// code, a second fixed paragraph and a second dictionary entry per arm, never a value
/// rendered out of the request.
///
/// It lives here, beside [`GATE_LOGIN_PATH`], for the library's membership rule: `bb-auth-web`
/// writes this code into the logout `rd` of a completed deletion and the gate reads it back
/// out of the query string that lands on, and the way the two drift apart is silent (the
/// person lands signed out with no explanation).
pub const LOGIN_NOTICE_ACCOUNT_DELETED: &str = "account-deleted";

/// What this build was made from: a `git describe --always --dirty --tags`, or `unknown`.
///
/// Read from `BB_AUTH_BUILD` at compile time, which is what `scripts/build.sh` and
/// `scripts/package.sh` set from the checkout they are building. `option_env!` and not
/// `env!` because a plain `cargo build` on a workstation sets nothing and must still
/// compile: it then reports `unknown`, which is honest.
///
/// It is the **commit** and nothing else (`g0a8d129`, plus `-dirty` when the tree was not
/// committed), because the version half of the identity is already compiled in by cargo and
/// must not be spelled a second time by a shell script that could get it wrong.
/// [`version_id`] is what puts the two together.
///
/// It is in the library because all three programs print it, and because a version string
/// that meant different things in different binaries of one release would be worse than
/// none. There is deliberately no build script: a `build.rs` that shells out to `git` is a
/// compile-time dependency on a program the build does not otherwise need, and the two
/// scripts that produce a release already know the answer.
pub const BUILD: &str = match option_env!("BB_AUTH_BUILD") {
    Some(b) => b,
    None => "unknown",
};

/// What this build **is**: `v1.99.1-g0a8d129`, or `…-dirty`, or `…-unknown` for a plain
/// `cargo build` that no release script set anything for.
///
/// One string, where this used to be two facts side by side. The old shape printed the crate
/// version and then `git describe`'s output, and **`git describe` anchors on the last tag**:
/// a release candidate is deliberately never tagged, so on the host it read
/// `1.99.1 (v1.0.0-18-g0a8d129)` — the true version, followed by a string that opens with a
/// version eighteen commits and one minor number out of date. Read quickly, it said `v1.0.0`.
///
/// So the version comes from cargo, which cannot be wrong about it, the commit comes from
/// [`BUILD`], and they are joined here. It still answers both questions the old pair
/// answered: `dpkg-query -W` agrees with the version prefix, and the suffix is what an
/// incident needs, since an untagged build's only handle is its commit.
pub fn version_id() -> String {
    format!("v{}-{BUILD}", env!("CARGO_PKG_VERSION"))
}

/// The one line every program answers `--version` with, and the one the gate opens its
/// journal with.
pub fn version_line(program: &str) -> String {
    format!("{program} {}", version_id())
}

/// Claim names bb-auth consumes itself, and so cannot propagate.
///
/// The gate's `Claims` deserializes these into typed fields, and `#[serde(flatten)]` never
/// sees a key a typed field already took, so configuring one of them would propagate
/// nothing, silently and forever. Rejecting them at compile time turns that into an error a
/// form can show.
pub const RESERVED_CLAIMS: [&str; 4] = ["email", "email_verified", "token_use", "identities"];

/// Whether the `email_verified` claim is truthy. Cognito types it as a bool, but some
/// federated flows stringify it, so `"true"` counts. Anything else is false.
///
/// It lives in the library because the gate is not the only program that will validate a
/// token: `bb-auth-web` starts to (docs/ARCHITECTURE.md §13.22, slice 5b), and what
/// Cognito's `email_verified` means must not have two answers.
pub fn email_verified_true(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Every identity attribute the gate knows how to emit.
///
/// The **set** an installation emits is configuration ([`GateSettings::identity_attrs`]); the
/// derivation from an attribute name to a header is code, exactly as it is for a profile
/// claim, so an operator names an attribute and never a header.
///
/// The set of *possible* names is this array, and it being finite is the security argument.
/// `proxy_set_header` overrides only the names it lists, so nginx must clear every header the
/// gate could ever emit, **including the ones this installation has turned off**: an identity
/// header nginx does not clear is one a client can send. An operator who turns an attribute on
/// later must add nothing to nginx, because the clear was already there, which is exactly
/// what makes this setting safe to change at runtime.
///
/// It is also the reason a new attribute is a code change: `phone` will be a fourth
/// credential's worth of work in the gate's `validate_id_token`, not a string an operator may
/// invent.
pub const IDENTITY_ATTRS: [&str; 2] = ["uuid", "email"];

/// Whether `s` is a syntactically valid profile-claim name: non-empty and `[A-Za-z0-9_:-]`
/// only.
///
/// Shared by [`compile_profile_claims`] (config) and the gate's `decode_claims_segment` (a
/// cookie's claim blob), so a cookie can never carry a key that no config could have produced.
pub fn claim_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':' || b == b'-')
}

/// Derive a claim's response header. See [`ProfileClaim`] for the rule and why it is code
/// rather than config. Assumes `claim` passed [`compile_profile_claims`]'s checks.
pub fn derive_profile_header(claim: &str) -> String {
    let normalized = claim.replace([':', '_'], "-");
    let mut out = String::from("X-Auth-");
    for (i, token) in normalized.split('-').enumerate() {
        if i > 0 {
            out.push('-');
        }
        let mut chars = token.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars.map(|c| c.to_ascii_lowercase()));
        }
    }
    out
}

/// One configured OIDC profile claim, and the response header derived from its name.
///
/// The **set** is configuration ([`GateSettings::profile_claims`], empty by default); the
/// **derivation** is code, and fixed. That split is the whole point: an operator names a
/// claim, never a header, so the two can never disagree and no header name is attacker- or
/// typo-reachable.
///
/// Derivation: map `_` and `:` to `-`, title-case each `-`-separated token, prefix `X-Auth-`.
/// So `given_name` → `X-Auth-Given-Name` and `custom:department` → `X-Auth-Custom-Department`.
/// Because [`compile_profile_claims`] admits only `[A-Za-z0-9_:-]`, a derived header is always
/// `[A-Za-z0-9-]+`: a valid header token by construction.
///
/// The **value** is emitted percent-encoded per RFC 3986 by the gate, whose `pct_encode`
/// produces printable ASCII for *any* input; that construction, not a validator, is what makes
/// emitting a self-asserted value safe. An absent claim **omits its header entirely**, never
/// sends it empty.
///
/// These are **self-asserted profile attributes**: any Cognito user, verified email or not,
/// writes their own, so they are display hints and nothing may key on them. They authorize
/// nothing, no field of the access file mentions them, and they are never logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileClaim {
    /// The OIDC claim name, exactly as it appears in the id_token.
    pub claim: String,
    /// The response header derived from it. See the type doc.
    pub header: String,
}

/// Compile a list of OIDC claim names into the claims to capture and the headers to emit.
/// Empty (the default) means none: profile propagation is opt-in.
///
/// Every rejection is an error rather than a skipped entry, because a silently dropped claim
/// is a header an application waits for forever. In the gate that is a fatal load; in an
/// editor it is a refusal shown on the field, and nothing is written.
///
/// Rejects, naming the entry: a name outside `[A-Za-z0-9_:-]`; an empty token around a
/// separator (`:dept`, `dept:`, `a--b`), which would derive a header with an empty component;
/// a claim in [`RESERVED_CLAIMS`]; and a derived header that collides case-insensitively with
/// **any possible** identity header, with [`LOGIN_URL_HEADER`], with
/// [`NATIVE_USERNAME_HEADER`], or with another entry's (which also catches a repeated claim,
/// and spellings that differ only in case or separator).
pub fn compile_profile_claims(list: &[String]) -> Result<Vec<ProfileClaim>, String> {
    profile_claims_core(list).map_err(|r| r.sentence())
}

/// [`compile_profile_claims`]'s checks, answering the typed refusal so `compile_settings` can
/// hand one to the GUI as a code (§13.31 §3). The `String` wrapper is what the access file's
/// parser and the CLI's flag-named pre-checks call, and it prints the variant's own sentence,
/// byte for byte as before: the prefix `profile_claims` belongs to the settings file, and a
/// caller that names the value differently has no opinion about it.
fn profile_claims_core(list: &[String]) -> Result<Vec<ProfileClaim>, SettingsRefusal> {
    let mut out: Vec<ProfileClaim> = Vec::new();
    for raw in list {
        let claim = raw.trim();
        if claim.is_empty() {
            continue;
        }
        if !claim_name_ok(claim) {
            return Err(SettingsRefusal::ClaimCharset {
                claim: claim.to_string(),
            });
        }
        if claim.replace([':', '_'], "-").split('-').any(str::is_empty) {
            return Err(SettingsRefusal::ClaimEmptyPart {
                claim: claim.to_string(),
            });
        }
        if RESERVED_CLAIMS.contains(&claim) {
            return Err(SettingsRefusal::ClaimConsumed {
                claim: claim.to_string(),
            });
        }
        let header = derive_profile_header(claim);
        // Every *possible* identity header is reserved, not merely the ones this installation
        // emits: turning an attribute on tomorrow must not collide with a claim configured
        // today, because that discovery would happen at runtime, on a header an application
        // already trusts.
        let reserved = IDENTITY_ATTRS
            .iter()
            .map(|a| derive_profile_header(a))
            .chain(
                [LOGIN_URL_HEADER, NATIVE_USERNAME_HEADER]
                    .iter()
                    .map(|r| r.to_string()),
            );
        for r in reserved {
            if header.eq_ignore_ascii_case(&r) {
                return Err(SettingsRefusal::ClaimHeaderReserved {
                    claim: claim.to_string(),
                    header,
                });
            }
        }
        if let Some(prev) = out.iter().find(|p| p.header.eq_ignore_ascii_case(&header)) {
            return Err(SettingsRefusal::ClaimsCollide {
                first: prev.claim.clone(),
                second: claim.to_string(),
                header,
            });
        }
        out.push(ProfileClaim {
            claim: claim.to_string(),
            header,
        });
    }
    Ok(out)
}

/// One configured identity attribute, and the response header derived from its name.
///
/// The same split as [`ProfileClaim`], for the same reason: the **set** is configuration
/// ([`GateSettings::identity_attrs`], `email` by default), the **derivation** is code. The
/// derivation is literally the same function, so `uuid` becomes `X-Auth-Uuid` and `email`
/// becomes [`IDENTITY_HEADER`].
///
/// These are **not** profile claims, and the difference is the whole point of the split. An
/// identity attribute is what the access file decided a request belongs to: it is checked, it
/// is what `denied` vetoes, and an application may key its own records on it. A profile claim
/// is self-asserted decoration nothing may key on.
///
/// A multi-valued attribute is emitted **space-separated**, and that is safe by construction
/// rather than by convention: every identifier passed [`header_safe_email`], which requires
/// printable ASCII, and a space is not printable ASCII. A comma would not do, because
/// [`well_formed_email`] allows one in a local part.
///
/// An absent attribute **omits its header** rather than sending it empty: nginx reads an unset
/// variable as no header at all, so present-and-empty is a distinction the application cannot
/// make. An identity granted by an `authenticated` scope is in no roster row, so it has no
/// `uuid` to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityAttr {
    /// The attribute name, one of [`IDENTITY_ATTRS`].
    pub attr: String,
    /// The response header derived from it.
    pub header: String,
}

/// Compile the identity attributes a `204` names. Default `email`, which is exactly what every
/// version before the settings file emitted.
///
/// Fatal on every rejection, and fatal on an **empty** list above all: an authorized `204` that
/// names nobody is an application silently losing its identity, and silence is the one failure
/// mode this gate does not accept. Unknown names are rejected against [`IDENTITY_ATTRS`] rather
/// than passed through, so a typo cannot quietly turn an attribute off.
pub fn compile_identity_attrs(list: &[String]) -> Result<Vec<IdentityAttr>, String> {
    identity_attrs_core(list).map_err(|r| r.sentence())
}

/// [`compile_identity_attrs`]'s checks, answering the typed refusal (§13.31 §3), with the same
/// split as [`compile_profile_claims`]: the settings file adds the `identity_attrs` prefix, the
/// leaf's other callers print this sentence alone.
fn identity_attrs_core(list: &[String]) -> Result<Vec<IdentityAttr>, SettingsRefusal> {
    // The one place the derivation and the documented constant are checked against each other.
    // Every application behind this gate reads `X-Auth-Email`, and every nginx snippet in the
    // README names it literally, so a change to the derivation must not be allowed to rename it
    // in silence.
    assert_eq!(derive_profile_header("email"), IDENTITY_HEADER);
    let mut out: Vec<IdentityAttr> = Vec::new();
    for raw in list {
        let attr = raw.trim();
        if attr.is_empty() {
            continue;
        }
        if !IDENTITY_ATTRS.contains(&attr) {
            return Err(SettingsRefusal::AttrUnknown {
                attr: attr.to_string(),
            });
        }
        if out.iter().any(|a| a.attr == attr) {
            return Err(SettingsRefusal::AttrTwice {
                attr: attr.to_string(),
            });
        }
        out.push(IdentityAttr {
            attr: attr.to_string(),
            header: derive_profile_header(attr),
        });
    }
    if out.is_empty() {
        return Err(SettingsRefusal::AttrNone);
    }
    Ok(out)
}

/// The shortest session lifetime that is not a login loop.
///
/// A cookie is minted with this as its `Max-Age` and the same value inside the signed
/// message, so a tiny one means the browser presents an expired cookie moments after the login
/// page handed it over, which looks exactly like a broken login rather than a bad setting. A
/// minute is arbitrary; being non-zero is not.
pub const MIN_SESSION_TTL: u64 = 60;

/// The longest lifetime a browser will actually honour: 400 days, the cap Chrome (and Safari,
/// lower) applies to `Max-Age` regardless of what the header says. Beyond it the value is not
/// wrong, it is merely fiction, so this is a warning rather than a refusal.
pub const MAX_HONOURED_SESSION_TTL: u64 = 400 * 86_400;

/// The longest lifetime that is arithmetic rather than fiction: a hundred years.
///
/// Past [`MAX_HONOURED_SESSION_TTL`] a value is merely ignored by the browser, which is worth
/// a warning and nothing more. Past *this* it stops being a number the gate can work with: it
/// is added to the wall clock to make the cookie's `exp` and cast to `i64` for its `Max-Age`,
/// and near `u64::MAX` both of those wrap into a cookie that is already expired, which is the
/// login loop [`MIN_SESSION_TTL`] exists to prevent, reached from the other end. A ceiling
/// three orders of magnitude past any real session leaves the setting's honest range
/// untouched and takes the arithmetic out of reach.
pub const MAX_SESSION_TTL: u64 = 100 * 365 * 86_400;

/// The gate's half of the settings file: what it answers a request with.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateSettings {
    /// OIDC claim names to capture from an id_token and hand to the application. Empty by
    /// default: profile propagation is opt-in. See [`ProfileClaim`].
    ///
    /// Order is the operator's, and is the order the headers come out in. Removing one stops
    /// it being emitted at once, from cookies that still carry it; adding one appears at each
    /// holder's next sign-in, because the value rides inside the cookie. Neither is a
    /// cookie-format change and neither logs anybody out.
    #[serde(default)]
    pub profile_claims: Vec<String>,
    /// Which identity attributes a `204` names. `["email"]` by default. See [`IdentityAttr`].
    #[serde(default = "default_identity_attrs")]
    pub identity_attrs: Vec<String>,
    /// Relax the `email_verified` requirement, but ONLY for federated (social) logins, never
    /// for native Cognito users, whose self-signup is open and whose unverified email is
    /// therefore attacker-controlled.
    #[serde(default)]
    pub allow_unverified_social: bool,
    /// The Cognito **app client the email flow uses**: the `client_id` the sign-in page runs
    /// `USER_AUTH` against, and the first audience a token is accepted for.
    ///
    /// **Empty is tolerated and means no login can complete**, which is the state a fresh
    /// install is in before an operator says which app client this deployment is. It is a
    /// warning and not a refusal for the reason `web.admins` is one: a package creates this
    /// file, and a gate that refused to start over a value the install cannot know would be a
    /// boot loop on every first install. Sessions already minted keep working either way,
    /// since this is read when a token is validated and never when a cookie is.
    ///
    /// It is the one setting here that can stop **new** logins, so where it sits against the
    /// three-part rule is worth stating rather than assuming. It is read per request; it is
    /// not a secret, since the sign-in page emits it into its own script; and while a wrong
    /// value does shut the door on new logins, it shuts it in the one way that is recoverable
    /// from the wrong side: no cookie is invalidated, so whoever made the edit still holds a
    /// session and can undo it, and `bb-auth-adm` over SSH is the way back if not. What it
    /// must never become is a way to reach another *pool*: `BB_AUTH_COGNITO_ISSUER` stays in
    /// the environment, so this file can only ever choose among the app clients of the pool
    /// the gate already trusts.
    #[serde(default)]
    pub client_id: String,
    /// **Where people sign in**: the page a `401` names, and the page a rejected redirect
    /// target falls back to. Absolute https, validated by [`compile_login_url`].
    ///
    /// Empty means *this gate's own* `/auth/login`, on whatever host the request arrived at,
    /// which is the only page it can promise exists. That default is what makes the value
    /// optional at all: the gate serves the sign-in page itself now, so naming one is
    /// how an operator points somewhere *else*, not how they get one.
    ///
    /// It is a setting and not an env var by the same argument as [`GateSettings::client_id`],
    /// and it is the other value here that can stop **new** logins if it is wrong: it cannot
    /// invalidate a cookie, so whoever made the edit still holds a session and can undo it.
    /// What keeps it from being a redirect gadget is unchanged and stays in the environment:
    /// `BB_AUTH_AUTHORIZED_HOSTS` is the only authority on where a post-login redirect may
    /// land, and it is not in this file.
    #[serde(default)]
    pub login_url: String,
    /// **Where a refusal lands**: the page `/auth/denied` stands in for. Absolute https,
    /// validated by [`compile_page_url`].
    ///
    /// Empty means the gate's own `/auth/denied`, which is the page it builds itself out of
    /// the `ui` section, so this is how an operator points somewhere *else* rather than how
    /// they get a page at all. It is the only value here that no login depends on: it is read
    /// when somebody has already been refused, so the worst a wrong one can do is send that
    /// person to a page that is not there, and no cookie, no scope and no grant is touched.
    /// A gate whose `/auth/denied` answers `302` to it is the one redirect in this design
    /// nginx does not perform itself, and it exists because nginx cannot proxy to a host the
    /// settings file names without a resolver and a rewrite of the recipe.
    #[serde(default)]
    pub denied_url: String,
    /// **Where a sign-in lands when nobody named a place**: what `safe_rd` answers when
    /// `/auth/session` arrives with no `rd`. Absolute https, validated by [`compile_page_url`],
    /// and its host must be one `gate.authorized_hosts` covers, or [`compile_settings`] refuses
    /// the file.
    ///
    /// Empty, the default, is the **caller's root**, exactly as before this setting existed: the
    /// host the sign-in page was served from, which on a host that serves only the sign-in page
    /// is a page nobody chose, and often the sign-in page again. Naming one is how an operator
    /// says where a login ends when the visitor, the `401` round trip and the `Referer` all said
    /// nothing. A present `rd` still wins, and a *rejected* `rd` still falls back to the sign-in
    /// page, so the one path this touches is the one that had no answer.
    ///
    /// It passes the settings file's three-part rule cleanly, and that is why it is **not** a
    /// guarded change: it is read per request, after the token is verified and the cookie built;
    /// it decides only where a browser that is already signed in is sent, so the worst a wrong
    /// value achieves is a `403` or a `404` landing, the cookie is set either way, and whoever
    /// made the edit still holds a session to undo it with; and it is a `Location:` a browser
    /// follows, not a secret.
    ///
    /// It is the one value in this section written **only when set**, because `GateSettings`
    /// refuses unknown keys and an older binary therefore refuses a file that carries it: an
    /// editor that never touched it never writes the key, so a host that does not use this
    /// setting can roll back to an older binary with no step at all.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub landing_url: String,
    /// The Cognito **hosted-UI domain**, as a bare host with no scheme and no path, e.g.
    /// `pool.auth.eu-central-1.amazoncognito.com`. Empty means this deployment offers no
    /// social sign-in at all.
    ///
    /// It is configured rather than derived because a pool's hosted UI can sit on a custom
    /// domain, so the issuer does not give it away.
    #[serde(default)]
    pub oauth_domain: String,
    /// The `redirect_uri` a social sign-in comes back to, which Cognito compares **byte for
    /// byte** with the one registered on each app client below. Normally `/auth/callback` on
    /// the host that serves the sign-in page. Empty means no social sign-in.
    #[serde(default)]
    pub social_callback_url: String,
    /// Which social sign-in buttons the page offers, in the order they appear, and **the app
    /// client each one runs through**. Empty offers none, which is the whole point: a
    /// provider is offered because somebody listed it, never because a deployment happens to
    /// federate it.
    ///
    /// The app client is per button rather than per deployment because Cognito federates per
    /// app client: which identity providers a client offers is a property of that client, so
    /// two providers may perfectly well live on two of them, and one value for all of them
    /// would have made that arrangement inexpressible. Each has to be registered with the
    /// `social_callback_url` above, which is Amazon's rule and not this file's.
    ///
    /// Every audience the gate accepts comes from here and from [`GateSettings::client_id`],
    /// which is what makes this file the whole answer to "which app clients is this gate part
    /// of". The pool they belong to is `BB_AUTH_COGNITO_ISSUER` and stays in the environment.
    #[serde(default)]
    pub social_buttons: Vec<SocialButtonSpec>,
    /// Narrows the relaxation above to these IdPs, matched case-insensitively against the
    /// token's `identities[].providerName`. Empty = any federated provider.
    ///
    /// Not to be confused with [`GateSettings::social_buttons`] above, which decides what is
    /// *offered*; this one decides whose unverified email is *accepted*.
    #[serde(default)]
    pub social_providers: Vec<String>,
    /// The session cookie's lifetime in seconds. Affects cookies minted from now on and no
    /// others, which is what keeps changing it out of the logout business.
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    /// The Cognito **user pool**: the `iss` every id_token must carry, and the host its JWKS
    /// is fetched from. Absolute https, no trailing slash. Empty means no login can complete.
    ///
    /// It is the one setting in this file that is **not read per request**, so it is here in
    /// spite of the membership rule rather than because of it, and the cost is paid in the
    /// reload: a SIGHUP that sees a new value fetches that issuer's JWKS first and swaps the
    /// keys and the settings together, or swaps neither. Half of that pair applied is a gate
    /// checking this pool's tokens against the other pool's keys, which is every login
    /// failing on a signature.
    ///
    /// What it costs is stated with the other two at the top of this section: it used to be
    /// the reason the app clients were safe in a file a browser can edit (the file could only
    /// choose among the clients of a pool the environment already trusted), and that sentence
    /// is now retired rather than quietly untrue.
    #[serde(default)]
    pub issuer: String,
    /// The session cookie's `Domain`, with or without a leading dot. Empty is a **host-only**
    /// cookie, which only serves a deployment where the gate and the application are one
    /// host; a parent domain is what makes one session cover every service behind the gate.
    ///
    /// **Changing it does not log anybody out, and that is the problem.** A browser matches a
    /// clearing `Set-Cookie` on `(name, Domain, Path)`, so every cookie already issued under
    /// the old domain stays valid for its full lifetime and `/auth/logout` can no longer
    /// clear it: a logout that silently succeeds at nothing, for everybody who signed in
    /// before the edit. The way back is to put the old value back, which makes those cookies
    /// clearable again. Both editors therefore make this a **two-step** with the consequences
    /// on screen, which is the one place in this file where saying it once is not enough.
    #[serde(default)]
    pub cookie_domain: String,
    /// The hosts a post-login `rd` may land on, as host globs (`badbat75.com`,
    /// `*.badbat75.com`). The **only** authority on where a redirect may go: see
    /// [`compile_host_pattern`], and note that `*.x.com` does not match the apex `x.com`,
    /// which has to be listed.
    ///
    /// Empty refuses every redirect target there is, so every login lands on the sign-in page
    /// instead of where the visitor was going. That is useless but fail-closed, and it is
    /// tolerated for the reason an empty `client_id` is: a package creates this file and
    /// cannot know the answer, and a gate that refused to start over it would be a boot loop
    /// on every first install.
    ///
    /// It sits beside [`GateSettings::login_url`] now, which used to be the thing it guarded.
    /// What compensates is the check that only became possible once the two were in one file:
    /// [`GateSettings::cookie_domain`] must reach every host listed here, or
    /// [`compile_settings`] refuses the file. A host the cookie cannot reach is a redirect
    /// into a `401`, a bounce back to the sign-in page, and a loop with nothing in the
    /// journal to say why.
    #[serde(default)]
    pub authorized_hosts: Vec<String>,
}

fn default_identity_attrs() -> Vec<String> {
    vec!["email".to_string()]
}

fn default_session_ttl() -> u64 {
    2_592_000
}

impl Default for GateSettings {
    /// Hand-written, and it must stay in step with the `serde(default = …)` above: a derived
    /// `Default` would give an empty attribute list (fatal) and a zero TTL (a login loop),
    /// which is the wrong answer to a section somebody left out.
    fn default() -> Self {
        GateSettings {
            profile_claims: Vec::new(),
            identity_attrs: default_identity_attrs(),
            allow_unverified_social: false,
            // Empty on purpose: a fresh file names no app client, offers no social sign-in,
            // and a button exists because somebody wrote one.
            client_id: String::new(),
            login_url: String::new(),
            denied_url: String::new(),
            landing_url: String::new(),
            oauth_domain: String::new(),
            social_callback_url: String::new(),
            social_buttons: Vec::new(),
            social_providers: Vec::new(),
            session_ttl_secs: default_session_ttl(),
            // Empty for the same reason, one step further: a fresh file names no pool, no
            // cookie domain and no redirect target, and says so loudly rather than guessing.
            issuer: String::new(),
            cookie_domain: String::new(),
            authorized_hosts: Vec::new(),
        }
    }
}

/// The audit's section of the settings file: which headers it believes about where a request
/// came from, when its live file rotates, and how much of it is kept.
///
/// A section of its own rather than four more fields of `gate`, although the gate is what
/// reads it, because it answers a different question from the rest of `gate`: not how a
/// request is answered but what is written down about it afterwards. It is also the section an
/// older binary can be handed without refusing the file, since an unknown key at the top level
/// is preserved rather than refused.
///
/// All four pass the three-part rule, and say so rather than assume it. Each is read when an
/// event is recorded or the files are maintained, which is per request or hourly and never
/// once at startup; none can close a door, since the audit is written after the decision and
/// can fail without costing a login; and none is a secret.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditSettings {
    /// The request header the **client's address** is read from: `X-Real-IP` in the README's
    /// recipe, which Debian's `proxy_params` already sets. Empty, the default, records no
    /// address at all.
    ///
    /// **Off unless named, because naming it is a promise about nginx that this file cannot
    /// check.** The gate listens on loopback and never sees a client itself, and nginx hands a
    /// client's own headers through untouched unless a `proxy_set_header` overwrites them. On
    /// a location that forgets to, the address in the audit is whatever the client chose to
    /// say, which is worse than none: an audit that can be told a lie is an audit that tells
    /// one. So it is switched on by whoever wires nginx, in the same edit.
    ///
    /// A list is accepted and its **last** entry is taken, which makes `X-Forwarded-For` usable
    /// as well: `$proxy_add_x_forwarded_for` appends the address nginx saw to whatever the
    /// client sent, so the last entry is nginx's and everything before it is the client's
    /// word. A value that is not an address is not recorded.
    #[serde(default)]
    pub client_ip_header: String,
    /// The request header nginx's **id for the request** is read from: `X-Request-ID`, set
    /// from `$request_id`, in the README's recipe. Empty, the default, records none.
    ///
    /// It is the audit's way to everything it deliberately does not hold. nginx's access log
    /// has the request line, the status, the byte count and the referrer for every request,
    /// and with `$request_id` in its `log_format` one search for this value finds the line an
    /// audit row is about. Off unless named for the reason the address is: a header nginx does
    /// not overwrite is the client's, and an id the client chose points at somebody else's line.
    #[serde(default)]
    pub request_id_header: String,
    /// When the live file moves onto `.1`, replacing the one before: an amount and a unit, of
    /// space (`4 MiB`, `1 GiB`) or of time (`1 month`, the age of the file's oldest event).
    /// Empty means [`AUDIT_MAX_BYTES`]. See [`AuditPolicy`].
    #[serde(default)]
    pub rotation: String,
    /// How much of the audit is kept at most, across both files: of time (`6 months`: no event
    /// older than that stays on disk, whichever file it is in) or of space (`64 MiB`: the two
    /// files together never exceed it). Empty keeps what the rotation keeps and nothing less.
    ///
    /// A retention in time is the one to reach for when the question is personal data: an
    /// address is kept for as long as it says and not for as long as the bytes happen to last,
    /// which on a quiet deployment is years.
    #[serde(default)]
    pub retention: String,
}

/// The GUI's half of the settings file: who may open its door.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebSettings {
    /// The emails allowed to use `bb-auth-web`, matched against the identity nginx injects.
    ///
    /// **Never empty**, and never "everyone": it is the backstop that keeps an `anonymous` or
    /// `authenticated` scope covering the admin URL from handing the admin surface to any
    /// Cognito account. It is enforced where it can be acted on: `bb-auth-web` refuses to
    /// serve without it, and both editors refuse to write an empty list, rather than here,
    /// because the *gate* has no business failing to start over a list it never reads.
    #[serde(default)]
    pub admins: Vec<String>,
}

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
fn audit_section_core(rotation: &str, retention: &str) -> Result<AuditPolicy, SettingsRefusal> {
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
fn audit_previous(path: &std::path::Path) -> std::path::PathBuf {
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
fn line_ts(line: &[u8]) -> Option<u64> {
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
struct RevLines {
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

    fn with_block(path: &std::path::Path, block: u64) -> std::io::Result<RevLines> {
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
    fn next_line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
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

// ---------------------------------------------------------------------------
// The presentation contract
// ---------------------------------------------------------------------------
//
// What follows is here on the library's own membership rule, and it is worth saying out
// loud because a stylesheet is not a file on disk that two programs parse. The gate's login
// page and `bb-auth-web`'s admin GUI must agree, byte for byte, on what `--accent` names,
// on where an operator's own stylesheet is allowed to land in the cascade, and on how a page
// declares which arm of the palette it starts in. Two answers to any of those and
// `ui.stylesheet_url` restyles one surface while the other stands in a different palette.
//
// The same argument reaches one step further than the palette, and it took a live comparison
// of the two surfaces to see how far. A shared vocabulary of colours does not stop a button
// from being a rounded rectangle on one page and a lozenge on the other, a field from being
// 12px tall here and 7px there, or a message box from being tinted here and outlined there.
// Each of those is one program's author changing the file in front of them, which is drift
// nobody can see from inside either file. So the COMPONENTS are shared too ([`BASE_CSS`]),
// and the rule for what that means is mechanical: a THING (a button, a field, a card, a tag,
// a message) is defined once, for both; an ARRANGEMENT of things is not.
//
// What is NOT here, therefore: the two layouts. The admin's header, tabs, tables and phone
// stacking are the GUI's; the centred auth card, its steps and its social buttons are the
// gate's. Both read the tokens and the components below and define no colour of their own.

/// The palette every HTML surface in this project paints itself from, compiled in from
/// `src/assets/theme.css`.
///
/// It defines custom properties and nothing else. It is emitted **first**, ahead of
/// [`BASE_CSS`], ahead of each program's own layout and ahead of any override, so the cascade
/// order is always: tokens, components, layout, operator.
pub const THEME_CSS: &str = include_str!("assets/theme.css");

/// The components every HTML surface in this project is built from, compiled in from
/// `src/assets/base.css`: the document, the type scale, the card, the state boxes, the
/// fields, the buttons, the pills, the tags and the spinner.
///
/// It is what makes "the sign-in page and the admin interface are one product" a property of
/// the code rather than an intention: a control's shape, size and behaviour are written once
/// and both programs emit the same bytes. It reads its values from [`THEME_CSS`] and defines
/// no literal of its own, so an operator's `ui.stylesheet_url` still restyles everything by
/// redefining tokens alone.
///
/// Emitted immediately after [`THEME_CSS`] and immediately before whichever layout the page
/// belongs to, which is what lets a layout override a component where the page's own
/// arrangement forces it (the auth card's elevation, the admin's compact filter row) without
/// either of them being able to restyle a control for everybody.
pub const BASE_CSS: &str = include_str!("assets/base.css");

/// How long a brand name may be. Long enough for a real product name, short enough that it
/// cannot push a login card's header off a phone: the value is emitted into a page, not into
/// a header, so this is a layout bound rather than a safety one.
pub const MAX_BRAND_NAME: usize = 64;

/// Which arm of [`THEME_CSS`] a page starts in.
///
/// `System` is the absence of a choice and emits no attribute at all, which is what leaves
/// `prefers-color-scheme` deciding. The other two are an explicit choice and outrank the
/// media query by specificity alone, with no script involved. `bb-auth-web` lets an
/// administrator override this per browser with a cookie; the gate's pages have no such
/// state and take it as given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum UiTheme {
    /// Follow the browser and the OS.
    #[default]
    System,
    Light,
    Dark,
}

impl UiTheme {
    /// The wire spelling: what the settings file holds and what an editor prints.
    pub fn code(self) -> &'static str {
        match self {
            UiTheme::System => "system",
            UiTheme::Light => "light",
            UiTheme::Dark => "dark",
        }
    }

    /// The `data-theme` attribute for `<html>`, or `None` for `System`, whose whole meaning
    /// is that the attribute is absent.
    pub fn attr(self) -> Option<&'static str> {
        match self {
            UiTheme::System => None,
            UiTheme::Light => Some("light"),
            UiTheme::Dark => Some("dark"),
        }
    }

    /// Parse a wire spelling; `None` is "not one of the three". An empty string is `System`,
    /// because that is a setting left unset rather than a value spelled wrong, and every
    /// caller turns the `None` into a refusal: a misspelled theme that quietly became
    /// `system` is a setting an operator would go on believing they had set.
    pub fn parse(s: &str) -> Option<UiTheme> {
        match s.trim().to_ascii_lowercase().as_str() {
            "system" | "" => Some(UiTheme::System),
            "light" => Some(UiTheme::Light),
            "dark" => Some(UiTheme::Dark),
            _ => None,
        }
    }
}

/// Escape the HTML-significant characters for safe interpolation into a page or into a
/// double-quoted attribute.
///
/// Named-entity form so one function serves both contexts. It is in the library because both
/// HTML-emitting programs need it and there must not be two answers to "what is escaped":
/// `bb-auth-web` reaches it through `maud`, which escapes its own interpolations, and calls
/// this only where it hands a whole attribute value over.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// The `<link>` that loads an operator's own stylesheet, or the empty string when none is
/// configured.
///
/// One function for both programs, because the *position* is the contract: this is emitted
/// after the built-in `<style>`, so an override wins by source order alone and needs no
/// `!important` and no knowledge of the layout it is restyling. The URL has already passed
/// [`compile_asset_url`], which forbids the quote characters outright; it is escaped here
/// as well, because "already validated" is a property of today's callers and escaping is a
/// property of the emission.
pub fn stylesheet_link(url: Option<&str>) -> String {
    match url {
        Some(u) => format!("<link rel=\"stylesheet\" href=\"{}\">", html_escape(u)),
        None => String::new(),
    }
}

/// The response headers every HTML page either program serves carries, and the one place
/// that set is decided.
///
/// It is here for the reason [`BASE_CSS`] is. Two programs emit pages now, and "what does an
/// HTML response carry" had two answers: the gate sent `X-Frame-Options` and no `nosniff`,
/// the GUI sent `nosniff` and no `X-Frame-Options`. Nobody chose that; each file was edited
/// by somebody looking at that file. The consequence is not cosmetic like a mismatched
/// radius: the page that could be framed was the one whose forms delete users.
///
/// A caller emits these on every HTML response and adds a
/// [`Content-Security-Policy`](page_csp) of its own, which is per page because its sources
/// are.
pub const PAGE_SECURITY_HEADERS: [(&str, &str); 4] = [
    // A page here is a snapshot of a file that is being edited under it, or of one attempt
    // at a login: a cached copy is a page that is right about a request nobody is making any
    // more.
    ("Cache-Control", "no-store"),
    // A browser guessing at a content type is a browser deciding something we already know.
    ("X-Content-Type-Options", "nosniff"),
    // A login form, or a delete button, in somebody else's frame is a clickjacking target,
    // and each service says so itself rather than trusting the proxy in front of it to have
    // said it. `frame-ancestors` in the CSP is the modern spelling and is emitted too; this
    // one costs a header and covers what does not implement it.
    ("X-Frame-Options", "DENY"),
    // These URLs carry an `rd`, a uuid, a key id or an email. None of it has business
    // travelling to a third-party host in a `Referer`, and the gate reads that header as a
    // redirect candidate itself, which is one more reason not to hand other people's out.
    ("Referrer-Policy", "no-referrer"),
];

/// A `'sha256-…'` CSP source expression for a piece of inline content, exactly as a browser
/// computes it: SHA-256 of the bytes between the tags, standard base64.
///
/// The alternative to a nonce, and the better one wherever the content is a compile-time
/// constant: there is nothing to generate per response, nothing to thread through a renderer,
/// and no way for the policy and the page to disagree, because both are derived from the same
/// `&str`. It is a hash and not a copy, so a stale value cannot survive an edit to the
/// content: the browser recomputes it and refuses to apply a block that changed.
///
/// **Newlines are normalised to LF first, and that is not a nicety.** An HTML parser
/// normalises the document's newlines before anything else sees it, so what a browser hashes
/// is the block with every CRLF already collapsed. This repository is developed on Windows
/// with `core.autocrlf=true`, so the working tree's stylesheets have CRLF, `include_str!`
/// embeds them verbatim, and the release is cross-compiled from that same tree: without this
/// line the served page and the policy that describes it disagree on every build made here,
/// the browser refuses the whole stylesheet, and the admin interface renders as unstyled
/// markup with nothing in the journal and nothing in any test. It costs one pass over a
/// compile-time constant and is a no-op wherever the checkout is LF.
pub fn csp_hash(content: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    let normalized = content.replace("\r\n", "\n");
    format!(
        "'sha256-{}'",
        STANDARD.encode(Sha256::digest(normalized.as_bytes()))
    )
}

/// The CSP source for one of the two operator-supplied asset URLs: its origin when it is
/// absolute, `'self'` when it is root-relative, and nothing at all when it is unset.
///
/// [`compile_asset_url`] has already reduced the shapes to those three, which is what makes
/// this a `split` rather than a URL parser.
fn csp_asset_source(url: Option<&str>) -> Option<String> {
    let u = url?;
    match u.strip_prefix("https://") {
        Some(rest) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            (!authority.is_empty()).then(|| format!("https://{authority}"))
        }
        None => Some("'self'".to_string()),
    }
}

/// The `form-action` source list for a page whose forms are answered with a redirect into the
/// estate: `'self'` plus the cookie's domain and every host under it.
///
/// The source is the **cookie domain** and deliberately not [`GateSettings::authorized_hosts`],
/// which is the list that actually decides where a login may land. Two reasons, and the second
/// is why the obvious choice is the wrong one. [`compile_settings`] already refuses a file
/// whose authorized hosts are not all covered by the cookie domain, so this is by construction
/// a superset of every host a login can legitimately reach, and it is the same boundary the
/// file already reasons about. And [`compile_host_pattern`] admits globs that a CSP
/// host-source cannot express at all (`*bat75.com`, `a.*.com`), so building the directive out
/// of those would mean silently dropping the entries that do not translate, which is this bug
/// again for whoever wrote one. [`compile_cookie_domain`], by contrast, has already vouched
/// for a bare domain with no scheme, no port, no path and no glob, so the value drops into a
/// source expression with nothing left to escape or check.
///
/// An empty domain keeps `'self'`, and that is the right answer rather than a fallback: with
/// no `Domain` the session cookie is host-only, so a cross-host landing would arrive with no
/// session at all and there is nothing here worth permitting.
///
/// **This is not the authorization boundary and is not being asked to be one.** `safe_rd` in
/// the gate still decides where a login may go, against `authorized_hosts`, exactly as before;
/// all this directive has to do is stop cancelling a redirect the gate has already approved.
pub fn estate_form_action(cookie_domain: Option<&str>) -> String {
    match cookie_domain
        .map(cookie_domain_host)
        .filter(|d| !d.is_empty())
    {
        Some(d) => format!("'self' https://{d} https://*.{d}"),
        None => "'self'".to_string(),
    }
}

/// Assemble the `Content-Security-Policy` for a page either program serves.
///
/// The shape is `default-src 'none'` plus exactly what the page needs, which is short because
/// these pages are built to be complete on their own: the palette, the components and the
/// layout are inline, and the only external references a deployment can add are the two
/// [`UiSettings`] URLs, both already validated by [`compile_asset_url`] and both optional.
/// So the policy writes itself out of the settings, and an operator who sets neither gets a
/// page that may load nothing from anywhere.
///
/// The three arguments the caller supplies are the three things this file cannot know:
///
/// * `script_src` is what the page's own scripting is allowed to be. A nonce where the script
///   is assembled per response (the sign-in page substitutes configuration into it), a
///   [`csp_hash`] where it is a constant, `'none'` where there is no script at all.
/// * `style_src` is the same question for the inline `<style>` block that carries
///   [`THEME_CSS`], [`BASE_CSS`] and the caller's own layout. The operator's stylesheet is
///   appended to it here, because *that* source is this function's business.
/// * `form_action` is where the page's forms may **end up**, which is not the same question as
///   where they post. Chromium applies this directive to every hop of a form submission, the
///   redirect the response carries included, so a page that posts to its own origin and is
///   answered with a `302` onto another host of the estate needs that host named here or the
///   browser cancels the navigation. That is not hypothetical: it is what a hardcoded `'self'`
///   did to every Chromium login in a multi-host deployment, and it did it in the worst shape
///   available, since the session was already minted and the person was left watching a
///   spinner on a page that had succeeded. [`estate_form_action`] derives the answer for a
///   page that redirects, `'self'` is right for a form that lands on its own origin, and
///   `'none'` for a page that carries no form at all.
///
/// `connect` is for the hosts a page's script legitimately talks to: the gate's sign-in page
/// speaks to Cognito, and nothing else here speaks to anything. The two asset URLs are passed
/// rather than the whole [`Settings`], because one caller renders a page from a settings file
/// it has just read and the other from a snapshot of four fields, and this needs neither.
///
/// **`font-src` follows the stylesheet, and only the stylesheet.** A token file that changes
/// the estate's typeface has to be able to bring its `@font-face` with it, and there is only
/// one honest place for those files to live: the host the stylesheet itself came from, which
/// is a host this deployment has already named. So the origin that may serve the CSS may
/// serve its fonts, plus `data:` for a face embedded in the file. A third-party font host is
/// deliberately out of reach: it would be a second external host on the page whose whole
/// argument is that it needs none, and self-hosting a font beside the stylesheet costs a
/// copy. With no stylesheet configured the answer is `'none'`, because the built-in CSS asks
/// for no font at all: it names system faces, which are not fetched.
///
/// One thing this cannot do for the operator: a font is fetched in CORS mode even from a
/// host the policy allows, so the file has to be served with `Access-Control-Allow-Origin`.
/// A policy that permits it and a server that does not is a font that silently never
/// arrives.
///
/// This is worth having on a login page more than anywhere else in the estate. It is the one
/// page whose whole job is to hold a credential for a moment, the one page a deployment can
/// point at an external stylesheet, and the page where a future templating slip would be
/// worth the most to whoever found it. `default-src 'none'` is what makes all three cost
/// nothing.
pub fn page_csp(
    script_src: &str,
    style_src: &str,
    form_action: &str,
    stylesheet_url: Option<&str>,
    logo_url: Option<&str>,
    connect: &[&str],
) -> String {
    let mut style = style_src.to_string();
    if let Some(s) = csp_asset_source(stylesheet_url) {
        style.push(' ');
        style.push_str(&s);
    }
    // Whatever may serve the stylesheet may serve its fonts, and nothing else may. `data:`
    // for a face embedded in the file itself, which is the other way a token file travels
    // with its typeface.
    let font = match csp_asset_source(stylesheet_url) {
        Some(s) => format!("{s} data:"),
        None => "'none'".to_string(),
    };
    // `data:` because a logo is the one asset small enough that a deployment may reasonably
    // inline it rather than serve it, and an image URI cannot script.
    let img = match csp_asset_source(logo_url) {
        Some(s) => format!("{s} data:"),
        None => "data:".to_string(),
    };
    let connect_src = if connect.is_empty() {
        "'none'".to_string()
    } else {
        connect.join(" ")
    };
    format!(
        "default-src 'none'; script-src {script_src}; style-src {style}; img-src {img}; \
         font-src {font}; connect-src {connect_src}; form-action {form_action}; \
         frame-ancestors 'none'; base-uri 'none'"
    )
}

/// Where the browser says a request came from, which is the input to every CSRF decision
/// either program makes.
///
/// The classification is shared; the **policy is not**, and that separation is the point.
/// Both programs accept `POST`s from forms they rendered themselves, so there must not be two
/// answers to "where did this come from" (the GUI had one, the gate had none, which left
/// `/auth/session` minting a session cookie for a cross-site form post that `SameSite=Lax`
/// does nothing about: that attribute governs when a cookie is *sent*, never who may cause
/// one to be *set*). But what each program then does about a `same-site` request is genuinely
/// its own business, and writing one function that decided it for both would be the wrong
/// kind of sharing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestSite {
    /// Same scheme, host and port as the page: a form submitting to its own origin.
    SameOrigin,
    /// The same registrable domain, a different origin. Only a browser can tell us this;
    /// there is no public-suffix list here to work it out from `Origin` alone.
    SameSite,
    /// Another site entirely. This is the one every caller refuses.
    CrossSite,
    /// The browser said nothing usable: no `Sec-Fetch-Site` and no `Origin`, or a
    /// user-initiated navigation with no originating document at all (`none`). Not a form
    /// submission from a page of ours, whatever else it is.
    Unknown,
}

/// Classify a request by what the browser told us about its origin.
///
/// Two sources, in the order they deserve to be believed:
///
/// * **`Sec-Fetch-Site`** is set by the browser on every request and cannot be set by a page,
///   so where it exists it is the whole answer.
/// * **`Origin`** is the fallback, and only its **host** is compared, against the `Host:`
///   header's. Not the scheme: both binaries speak plain HTTP behind a TLS-terminating nginx,
///   so the browser's `https://…` origin can never equal a scheme reconstructed here, and
///   comparing one would refuse every honest request. The port travels with the host in both
///   headers, so comparing the authority as written is right in the default-port case *and*
///   the explicit-port one. This arm needs nginx to forward `Host`, which the deployment
///   examples now show; a mismatch here can only report [`RequestSite::CrossSite`], because
///   distinguishing a sibling host from a stranger needs a public-suffix list.
pub fn request_site(
    sec_fetch_site: Option<&str>,
    origin: Option<&str>,
    host: Option<&str>,
) -> RequestSite {
    if let Some(sfs) = sec_fetch_site {
        let s = sfs.trim();
        return if s.eq_ignore_ascii_case("same-origin") {
            RequestSite::SameOrigin
        } else if s.eq_ignore_ascii_case("same-site") {
            RequestSite::SameSite
        } else if s.eq_ignore_ascii_case("cross-site") {
            RequestSite::CrossSite
        } else {
            // `none`, and anything a future browser invents.
            RequestSite::Unknown
        };
    }
    match (origin, host) {
        (Some(o), Some(hst)) => {
            let authority = o
                .trim()
                .split_once("://")
                .map(|(_, rest)| rest.trim_end_matches('/'));
            match authority {
                Some(a) if !a.is_empty() && a.eq_ignore_ascii_case(hst.trim()) => {
                    RequestSite::SameOrigin
                }
                Some(a) if !a.is_empty() => RequestSite::CrossSite,
                _ => RequestSite::Unknown,
            }
        }
        _ => RequestSite::Unknown,
    }
}

/// Validate a URL a page will load an asset from: [`UiSettings::stylesheet_url`] and
/// [`UiSettings::logo_url`].
///
/// Two shapes, and only two. An absolute `https://` URL, held to exactly what
/// [`compile_login_url`] holds a login page to, because it lands in the same kind of place:
/// inside an attribute on a page one of these programs emits. Or a root-relative path
/// (`/css/theme.css`), which is the better answer when the file is served by the same vhost,
/// since it needs nothing of the deployment's hostname and nothing of a cross-origin CSP.
///
/// Empty is not an error, it is the setting being unset: `Ok(None)`, and the built-in
/// stylesheet stands alone. That is deliberate and load-bearing. A page must never *need* a
/// second host to be up in order to be usable, so an override is an addition to a complete
/// page and never the page itself.
///
/// Printable ASCII forbids the CR/LF and the spaces; the quote characters and the angle
/// brackets are refused outright so the value cannot break out of the attribute it is
/// emitted into. That is belt and braces over the escaping in [`stylesheet_link`], and it is
/// the belt worth having: this string is written by an administrator through a GUI, which is
/// one hop further from the code than an env var is.
pub fn compile_asset_url(field: &str, raw: &str) -> Result<Option<String>, String> {
    asset_url_core(raw).map_err(|(raw, fault)| format!("{field} '{raw}': {fault}"))
}

/// [`compile_asset_url`]'s checks, answering the typed refusal (§13.31 §3), with the same split
/// as [`page_url_core`]: the pair is the text today's sentence quotes, which here is the
/// **trimmed** value the leaf printed, and the fault. Empty is `Ok(None)`, the setting unset,
/// and so is never a refusal.
fn asset_url_core(raw: &str) -> Result<Option<String>, (String, UrlFault)> {
    let u = raw.trim();
    if u.is_empty() {
        return Ok(None);
    }
    let e = |fault| Err((u.to_string(), fault));
    if !u.bytes().all(|b| b.is_ascii_graphic()) {
        return e(UrlFault::NotPrintable);
    }
    if u.contains('"') || u.contains('\'') || u.contains('<') || u.contains('>') {
        return e(UrlFault::Quote);
    }
    if u.contains('\\') {
        return e(UrlFault::Backslash);
    }
    if let Some(rest) = u.strip_prefix("https://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() {
            return e(UrlFault::EmptyHost);
        }
        if authority.contains('@') {
            return e(UrlFault::Userinfo);
        }
        return Ok(Some(u.to_string()));
    }
    // A single leading slash. `//host/path` is protocol-relative, which is an absolute URL
    // wearing a relative URL's clothes, and the one shape somebody writes by accident.
    if u.starts_with('/') && !u.starts_with("//") {
        return Ok(Some(u.to_string()));
    }
    e(UrlFault::NotHttpsOrRooted)
}

/// Validate a brand name: the product name a login page puts under its logo.
///
/// It is HTML-escaped where it is emitted, so this is not the safety boundary; it is the
/// quality one. Control characters are refused because they are never intended, and the
/// length is bounded because the value is laid out, not merely stored. Empty means unset,
/// and each page falls back to whatever it calls itself.
pub fn compile_brand_name(raw: &str) -> Result<Option<String>, String> {
    brand_name_core(raw).map_err(|r| r.sentence())
}

/// [`compile_brand_name`]'s checks, answering the typed refusal (§13.31 §3). The refusal quotes
/// the **trimmed** value, which is what today's sentence printed, and the length it names is a
/// count of **characters**, because the bound is on what a page lays out and not on what the file
/// stores. Empty is `Ok(None)`, the setting unset, so it is never a refusal.
fn brand_name_core(raw: &str) -> Result<Option<String>, SettingsRefusal> {
    let n = raw.trim();
    if n.is_empty() {
        return Ok(None);
    }
    if n.chars().any(|c| c.is_control()) {
        return Err(SettingsRefusal::BrandControl {
            name: n.to_string(),
        });
    }
    let chars = n.chars().count();
    if chars > MAX_BRAND_NAME {
        return Err(SettingsRefusal::BrandTooLong { chars });
    }
    Ok(Some(n.to_string()))
}

/// The look, shared by both services: the section that says how a page presents itself, and
/// never who may see one.
///
/// Every field in it passes the three-part rule the settings file exists for. Each is read
/// **per request**, when a page is rendered. None can lock anybody out: the worst a wrong
/// value here achieves is an unstyled page or a missing logo, because the built-in
/// stylesheet is complete on its own and an override is only ever an addition to it. And
/// none is a secret. A value that fails any of the three belongs in `bb-auth.env`, however
/// convenient it would be to edit it from a GUI.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UiSettings {
    /// A stylesheet to load after the built-in one, or empty for none.
    ///
    /// It is expected to redefine the custom properties in [`THEME_CSS`] and nothing else:
    /// that is what makes one file restyle the gate's pages and the admin GUI at once,
    /// without knowing what either page is made of. It is emitted as an ordinary `<link>`,
    /// so a host that does not answer costs the page its palette and nothing else.
    #[serde(default)]
    pub stylesheet_url: String,
    /// A logo for the gate's login page, or empty for none, in which case the page shows the
    /// brand name alone.
    #[serde(default)]
    pub logo_url: String,
    /// The product name a page introduces itself with. Empty means each page falls back to
    /// its own name, which is what a deployment nobody has told a brand should show.
    #[serde(default)]
    pub brand_name: String,
    /// Which arm of the palette a page starts in: `system` (the default), `light` or `dark`.
    ///
    /// The gate's pages have nowhere to keep a per-visitor choice, so for them this is the
    /// whole answer. `bb-auth-web` treats it as the default an administrator's own cookie
    /// then overrides, which is why a deployment that pins `dark` here still leaves one free
    /// to work in light.
    #[serde(default)]
    pub theme: String,
}

/// A settings file as it is written: three sections, a version, and whatever else was in it.
///
/// The sections answer four different questions, which is why they are four and not one:
/// `gate` is how the gate answers a request, `audit` is what it writes down about one and for
/// how long, `web` is who may use the GUI, and `ui` is how a page looks to whoever reaches one.
/// `ui` is the one *both* programs render from, and `audit` the one both read (the gate to
/// write the audit, the GUI to show no more of it than the retention keeps).
///
/// Unknown keys are rejected inside each section, for the reason [`AppSpec`] rejects them,
/// a typo in a setting that narrows behaviour must not be dropped in silence, and preserved
/// at the top level, where `_comment` is the only thing anyone puts.
#[derive(Deserialize, Serialize, Default)]
pub struct SettingsFile {
    /// The format this file is written in. The only accepted value is [`SETTINGS_VERSION`].
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub gate: GateSettings,
    #[serde(default)]
    pub audit: AuditSettings,
    #[serde(default)]
    pub web: WebSettings,
    #[serde(default)]
    pub ui: UiSettings,
    /// Unknown top-level keys, preserved verbatim across an edit.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The settings as the two services use them: names resolved to headers, lists normalised,
/// every refusal already made.
///
/// One compiled type for both, rather than one each, so that "would the other program accept
/// this?" is not a question an editor has to answer for itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// See [`GateSettings::profile_claims`].
    pub profile_claims: Vec<ProfileClaim>,
    /// See [`GateSettings::identity_attrs`]. Never empty.
    pub identity_attrs: Vec<IdentityAttr>,
    /// See [`GateSettings::allow_unverified_social`].
    pub allow_unverified_social: bool,
    /// `None` = any federated provider, which is what an empty list means.
    pub social_providers: Option<Vec<String>>,
    /// See [`GateSettings::client_id`]. May be empty, which is a deployment that cannot
    /// complete a login yet; the gate says so at startup rather than refusing to start.
    pub client_id: String,
    /// Every app client a token may be minted for: [`Settings::client_id`] first, then each
    /// button's, deduplicated and in file order. **Derived, never configured**, which is what
    /// removed the last list in this system that had to agree with another one by hand.
    ///
    /// Empty when no app client is named at all, and that is a state to keep working rather
    /// than to refuse: `aud` is a required claim, so an empty list accepts no token, which is
    /// the honest reading of a deployment that has not said which app clients it is part of.
    pub audiences: Vec<String>,
    /// See [`GateSettings::login_url`]. Empty = the gate's own `/auth/login`, and the gate
    /// is where that default is applied, because only it knows the path it serves.
    pub login_url: String,
    /// See [`GateSettings::denied_url`]. Empty = the gate's own `/auth/denied`, and the gate
    /// applies that default too, for the same reason.
    pub denied_url: String,
    /// See [`GateSettings::landing_url`]. Empty = the caller's root, and the gate is where that
    /// default is applied, because only it knows the origin of the request that logged in.
    pub landing_url: String,
    /// See [`GateSettings::oauth_domain`]. `None` = no social sign-in.
    pub oauth_domain: Option<String>,
    /// See [`GateSettings::social_callback_url`]. `None` = no social sign-in.
    pub social_callback_url: Option<String>,
    /// See [`GateSettings::social_buttons`]. Empty = the sign-in page offers no social button
    /// at all: no divider, no button, nothing hinting at a way in this page is not offering.
    /// Never non-empty without the two above, which [`compile_settings`] enforces.
    pub social_buttons: Vec<SocialButton>,
    /// See [`GateSettings::session_ttl_secs`].
    pub session_ttl: u64,
    /// See [`GateSettings::issuer`], trailing slash removed. Empty accepts no token at all.
    pub issuer: String,
    /// See [`GateSettings::cookie_domain`], lowercased and kept exactly as written, leading
    /// dot and all, because that is what goes into the header. `None` = a host-only cookie.
    pub cookie_domain: Option<String>,
    /// See [`GateSettings::authorized_hosts`], compiled. Empty refuses every redirect target.
    pub authorized_hosts: Vec<UrlPattern>,
    /// See [`AuditSettings::client_ip_header`]. `None` = no address is recorded.
    pub client_ip_header: Option<String>,
    /// See [`AuditSettings::request_id_header`]. `None` = no request id is recorded.
    pub request_id_header: Option<String>,
    /// [`AuditSettings::rotation`] and [`AuditSettings::retention`], compiled into the one
    /// thing both programs need of them.
    pub audit_policy: AuditPolicy,
    /// See [`WebSettings::admins`], normalised with [`norm_email`] and deduplicated. May be
    /// empty here; `bb-auth-web` is where that is fatal.
    pub admins: Vec<String>,
    /// See [`UiSettings::stylesheet_url`]. `None` = no override, and the built-in stylesheet
    /// is the whole answer.
    pub stylesheet_url: Option<String>,
    /// See [`UiSettings::logo_url`].
    pub logo_url: Option<String>,
    /// See [`UiSettings::brand_name`]. `None` = each page falls back to its own name.
    pub brand_name: Option<String>,
    /// See [`UiSettings::theme`].
    pub theme: UiTheme,
}

impl Settings {
    /// Whether `email` (already [`norm_email`]-normalised) may use the GUI.
    pub fn is_admin(&self, email: &str) -> bool {
        self.admins.iter().any(|a| a == email)
    }

    /// The Cognito JSON API endpoint a browser-side client talks to: the issuer's origin,
    /// since the pool id is the only part of an issuer URL that is not it.
    ///
    /// **Derived and never configured**: a page that named its own endpoint could name a
    /// pool this deployment does not validate against, and the symptom would be a login
    /// that succeeds in the browser and is refused by the gate a redirect later. Computed
    /// per use rather than held, because the issuer is a setting and a held copy would be
    /// the stale half of a reload.
    ///
    /// It lives in the library because the gate is not the only program that needs the
    /// answer: the gate stamps it into the sign-in page it serves, and `bb-auth-web` will
    /// call Cognito itself (docs/ARCHITECTURE.md §13.22, slice 5b), so a second answer to
    /// "where does this pool's API live" is exactly the drift this library exists to end.
    ///
    /// Empty when the issuer has no origin: a page must never be handed a bare "/" to
    /// post a credential to.
    pub fn cognito_endpoint(&self) -> String {
        match self.issuer.find("://") {
            Some(i) => {
                let rest = &self.issuer[i + 3..];
                let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                if end == 0 {
                    String::new()
                } else {
                    format!("{}/", &self.issuer[..i + 3 + end])
                }
            }
            None => String::new(),
        }
    }
}

/// The social identity providers this project knows by name, as `(identity_provider, label)`.
///
/// Two programs have an opinion about this list now, which is what puts it here rather than
/// in either of them: the gate draws a button per enabled provider, and the admin GUI offers
/// a checkbox per provider to enable. A second table would mean a provider an operator can
/// switch on and no button, or a button whose name the switch spells differently, and the
/// spelling is not cosmetic: the first field is what Cognito is sent as `identity_provider`,
/// and Amazon matches it exactly.
///
/// What is NOT here is the icon, which stays in the gate beside the pages that draw it: an
/// inline SVG is presentation, the admin GUI has no use for one, and the membership rule is
/// about what more than one program must agree on rather than about keeping like with like.
///
/// **`MicrosoftPersonal` is the personal-account provider**, the one behind an `outlook.com`
/// or `hotmail.com` address, and it is deliberately not the work-and-school one: an Entra ID
/// tenant is a different provider, configured separately on the user pool under whatever name
/// its administrator gave it, and offering the two under one label would be telling somebody
/// their work account will work when it will not.
///
/// A pool may federate a provider this table has never heard of, which is why nothing here is
/// a whitelist: [`compile_social_buttons`] takes any well-formed name, the gate labels an
/// unknown one with the name itself, and the GUI shows it as a checkbox of its own so that
/// enabling it from `bb-auth-adm` does not make the page unable to represent the file.
pub const SOCIAL_IDPS: [(&str, &str); 2] =
    [("Google", "Google"), ("MicrosoftPersonal", "Microsoft")];

/// What a person calls `name`, or the name itself when this project has never heard of it.
pub fn social_idp_label(name: &str) -> &str {
    SOCIAL_IDPS
        .iter()
        .find(|(idp, _)| idp.eq_ignore_ascii_case(name))
        .map(|(_, label)| *label)
        .unwrap_or(name)
}

/// One social sign-in button as the file writes it: the provider, and the app client it runs
/// through.
///
/// The bare-string arm is the shape this field had before the app clients moved into this
/// file, and it exists to be **refused with a sentence** rather than to be supported. A type
/// error three levels down would say `invalid type: string` about a file somebody's previous
/// version wrote, which is the least useful moment to be terse; this is the same reflex the
/// access file's `version` check has.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum SocialButtonSpec {
    /// `{ "idp": "Google", "audience": "…" }`, the only shape that compiles.
    Wired(WiredButton),
    /// `"Google"`, written by a version that had one app client for every button.
    Name(String),
}

/// The object arm of [`SocialButtonSpec`].
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WiredButton {
    /// Cognito's own `identity_provider` name, e.g. `Google`.
    pub idp: String,
    /// The app client this provider is federated by, and the `aud` its tokens carry.
    #[serde(default)]
    pub audience: String,
}

/// One social sign-in button, compiled: both halves present and well formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocialButton {
    /// Cognito's own `identity_provider` name.
    pub idp: String,
    /// The app client the hosted UI is handed and the callback exchanges its code with.
    pub audience: String,
}

/// Validate one Cognito app client id, for the setting `what` names.
///
/// Empty is not a refusal here: it is the caller that decides whether an absent app client is
/// a warning (the email flow's, on a file a package just created) or an error (a button's,
/// which cannot be drawn without one).
///
/// The charset is the `identity_provider` one, and it carries more weight than it does there.
/// This value is substituted into the sign-in page as a JavaScript string literal, into an
/// HTML attribute on a button, and into the query string of Cognito's authorize URL, so
/// restricting it to letters, digits, `.`, `_` and `-` is what makes all three safe by
/// construction rather than by escaping: the same argument the gate's `env_page_value` makes
/// for the values these arrived as until they became settings. A Cognito app client id is 26
/// lowercase alphanumerics, so nothing this refuses could have been one.
/// The tail of an app client id refusal, byte for byte as the leaf spelled it before
/// [`SettingsRefusal::AppClientId`] existed (§13.31 §2 row 12). It is a `const` because two
/// callers print it under two different names: the enum's `sentence()` spells the settings key
/// and the button's name, and this leaf's wrapper spells whatever its caller names (`client_id`,
/// the CLI's `--client-id`, the GUI's `audience`), so the tail must have exactly one home.
const APP_CLIENT_TAIL: &str = "is not an app client id, which is letters, digits, '.', '_' and '-'";

pub fn compile_app_client_id(what: &str, raw: &str) -> Result<String, String> {
    app_client_id_core(raw)
        // The caller's name in front of the shared tail: the CLI calls this leaf with its own
        // flag and the GUI with its own field name, and neither is a settings key, so the
        // variant's own sentence, which names `client_id`, is not what these callers print
        // (§13.31 §3).
        .map_err(|_| format!("{what}: '{}' {APP_CLIENT_TAIL}", raw.trim()))
}

/// [`compile_app_client_id`]'s checks, answering the typed refusal (§13.31 §3). The refusal
/// carries the **trimmed** id, which is what today's sentence quoted. Empty is
/// `Ok(String::new())`, the setting unset, and so is never a refusal.
fn app_client_id_core(raw: &str) -> Result<String, SettingsRefusal> {
    let id = raw.trim();
    if id.is_empty() {
        return Ok(String::new());
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(SettingsRefusal::AppClientId {
            button: None,
            id: id.to_string(),
        });
    }
    Ok(id.to_string())
}

/// Validate the hosted-UI domain: a bare host, which is what the two OAuth URLs are built out
/// of.
///
/// No scheme and no path, and that is checked rather than stripped, because a value that
/// carries either was written by somebody who meant a URL and would otherwise be turned into
/// one that quietly resolves somewhere else.
pub fn compile_oauth_domain(raw: &str) -> Result<String, String> {
    oauth_domain_core(raw).map_err(|r| r.sentence())
}

/// [`compile_oauth_domain`]'s checks, answering the typed refusal (§13.31 §3). The refusal quotes
/// the **trimmed** value, which is what today's sentence printed, and an empty one is
/// `Ok(String::new())`, the setting unset, so it is never a refusal.
fn oauth_domain_core(raw: &str) -> Result<String, SettingsRefusal> {
    let d = raw.trim();
    if d.is_empty() {
        return Ok(String::new());
    }
    if !d
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || d.starts_with('.')
        || d.ends_with('.')
    {
        return Err(SettingsRefusal::OauthDomainNotBare { raw: d.to_string() });
    }
    Ok(d.to_string())
}

/// Validate the Cognito issuer: the absolute https URL an id_token's `iss` must equal, with
/// any trailing slash removed.
///
/// The same guard [`compile_login_url`] applies, for a longer list of reasons: this value is
/// fetched from over the network, compared byte for byte against a token claim, and emitted
/// into the sign-in page's `connect-src` as the one origin that page's script may talk to.
/// Printable ASCII is what makes the last of those safe with no escaping at all.
///
/// A query or a fragment is refused rather than trimmed. Cognito's `iss` is an origin and a
/// pool id and nothing else, so a value carrying either was written by somebody who meant a
/// different URL, and trimming it would build a JWKS URL they never asked for.
pub fn compile_issuer(raw: &str) -> Result<String, String> {
    issuer_core(raw).map_err(|(raw, fault)| format!("issuer '{raw}': {fault}"))
}

/// [`compile_issuer`]'s checks, answering the typed refusal (§13.31 §3). The value it quotes is
/// `raw` as given, which is what today's sentence printed, and the trailing-slash trim happens
/// here, so `"https://"` is refused as not https, exactly as before. An empty issuer is
/// `Ok(String::new())`, the setting unset, and the gate says so loudly at startup rather than
/// refusing to boot.
fn issuer_core(raw: &str) -> Result<String, (String, UrlFault)> {
    let u = raw.trim().trim_end_matches('/');
    let e = |fault| Err((raw.to_string(), fault));
    if u.is_empty() {
        return Ok(String::new());
    }
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
    if authority.contains('@') || u.contains('\\') {
        return e(UrlFault::UserinfoOrBackslash);
    }
    if u.contains('?') || u.contains('#') {
        return e(UrlFault::QueryOrFragment);
    }
    Ok(u.to_string())
}

/// Validate the session cookie's `Domain`: a bare domain, optionally with the leading dot
/// RFC 6265 ignores, and never a scheme, a port or a path.
///
/// A single label is refused with a sentence of its own, because it is the mistake that looks
/// most like it should work: a browser will not store a cookie for `com` (a public suffix) and
/// has no use for one on a bare hostname that is not the request's own. What is wanted there
/// is the registrable domain the services share.
pub fn compile_cookie_domain(raw: &str) -> Result<String, String> {
    cookie_domain_core(raw).map_err(|r| r.sentence())
}

/// [`compile_cookie_domain`]'s checks, answering the typed refusal (§13.31 §3). The refusal
/// quotes `raw` **as given**, which is what today's sentence printed, and the value returned is
/// the trimmed, lowercased one. Empty is `Ok(String::new())`, the setting unset.
fn cookie_domain_core(raw: &str) -> Result<String, SettingsRefusal> {
    let d = raw.trim().to_ascii_lowercase();
    if d.is_empty() {
        return Ok(String::new());
    }
    let bare = d.strip_prefix('.').unwrap_or(&d);
    if bare.is_empty()
        || !bare
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || bare.starts_with('-')
        || bare.starts_with('.')
        || bare.ends_with('.')
        || bare.ends_with('-')
        || bare.contains("..")
    {
        return Err(SettingsRefusal::CookieDomainNotBare {
            raw: raw.to_string(),
        });
    }
    if !bare.contains('.') {
        return Err(SettingsRefusal::CookieDomainSingleLabel {
            raw: raw.to_string(),
        });
    }
    Ok(d)
}

/// The request headers an audit value may never be read from, because each carries a
/// credential. Compared case-insensitively, as header names are.
const CREDENTIAL_HEADERS: [&str; 3] = ["Authorization", "Proxy-Authorization", "Cookie"];

/// Validate the name of a request header the audit reads a value out of, for the setting
/// `what` names: empty, which is the setting switched off, or a header name that is not a
/// credential.
///
/// The charset is letters, digits and `-`, which is narrower than RFC 9110's token and is
/// every header name anybody actually writes. The underscore is the one that matters: nginx
/// drops a request header with one in its name unless `underscores_in_headers` says otherwise,
/// so a name that allowed it would allow a setting that reads nothing, in silence.
///
/// The credential headers are refused by name, and the reason is the request id rather than
/// the address. An address is parsed and whatever is not one is dropped, so naming
/// `Authorization` there would only record nothing; but a request id is written down as it
/// arrives, and naming a header that carries a credential would put that credential into a file
/// an administrator reads, which is the one thing this system never does with a bearer.
pub fn compile_audit_header(what: &str, raw: &str) -> Result<String, String> {
    // The caller's name in front of the shared tail: `bb-auth-adm` calls this leaf with its own
    // flag and the GUI with its own field name, and neither is a settings key, so the variant's
    // own sentence, which names `audit.client_ip_header`, is not what these callers print
    // (§13.31 §3).
    audit_header_core(raw).map_err(|(name, fault)| format!("{what}: '{name}' {fault}"))
}

/// [`compile_audit_header`]'s checks, answering the typed refusal's parts (§13.31 §3). The pair
/// it returns is the name **trimmed**, which is what today's sentence quoted, and the fault: the
/// setting's name belongs to the caller, which is why the CLI keeps its flag name in front of
/// the same tail. An empty value is the setting switched off, and is `Ok(String::new())`.
fn audit_header_core(raw: &str) -> Result<String, (String, HeaderFault)> {
    let name = raw.trim();
    if name.is_empty() {
        return Ok(String::new());
    }
    if name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err((name.to_string(), HeaderFault::NotAName));
    }
    if CREDENTIAL_HEADERS
        .iter()
        .any(|c| c.eq_ignore_ascii_case(name))
    {
        return Err((name.to_string(), HeaderFault::Credential));
    }
    Ok(name.to_string())
}

/// Compile `audit.rotation` and `audit.retention` into a policy, or say why not.
///
/// Empty is a default and not a refusal for both: a rotation nobody wrote is
/// [`AUDIT_MAX_BYTES`], and a retention nobody wrote is no limit beyond the rotation's own,
/// which is what the audit did before either was a setting. Each message names the setting it
/// is about, because the one sentence [`AuditPolicy::new`] can add is about the pair.
pub fn compile_audit_policy(rotation: &str, retention: &str) -> Result<AuditPolicy, String> {
    // `Display` is the prefixed sentence, which is byte for byte what this function printed
    // when it built the prefixes itself: `audit.rotation: …` / `audit.retention: …` for a limit,
    // `audit: …` for the pair, which is the prefix `bb-auth-adm` swaps for its own flags
    // (§13.31 §3).
    audit_section_core(rotation, retention).map_err(|r| r.to_string())
}

/// What a `Domain=` attribute actually reaches: the value without the optional leading dot,
/// which RFC 6265 ignores. The one place that dot is taken off, so nothing compares two
/// spellings of one domain and calls them different.
pub fn cookie_domain_host(domain: &str) -> &str {
    domain.strip_prefix('.').unwrap_or(domain)
}

/// Whether a cookie on `domain` is sent to every host `pattern` can match.
///
/// Textual rather than a glob intersection, and sound because a host pattern's suffix is
/// literal: everything `*.x.com` matches ends in `.x.com`, so a cookie on `x.com` reaches all
/// of it. The dot carries the whole check on both sides. `*x.com`, written without one, is
/// **not** covered and must not be, since it matches `evilx.com`, which no cookie on `x.com`
/// is ever sent to.
pub fn cookie_domain_covers(domain: &str, pattern: &str) -> bool {
    let d = cookie_domain_host(domain);
    let p = pattern.trim().to_ascii_lowercase();
    p == d || p.ends_with(&format!(".{d}"))
}

/// A setting whose change can stop people getting in, and which both editors therefore make a
/// **two-step** rather than a save.
///
/// Which fields these are is in this crate for the crate's own membership rule: two programs
/// edit this file, and one that wrote in silence what the other stopped to ask about would
/// make the guard a property of which editor you happened to open. The *wording* is not here.
/// That has an operator on the other end, so the CLI prints sentences and the GUI renders a
/// panel in two languages, and neither belongs in a library.
///
/// **It is five and not fifteen on purpose.** A confirmation that fires on every save is a
/// button people learn to click without reading, which is worse than no confirmation at all
/// because it is also an alibi. What earns a place here is the pair of properties that makes a
/// confirmation the right instrument in the first place: the value can stop a **new** login,
/// and it invalidates no cookie, so whoever made the edit still holds a session and can undo
/// it. The `ui` four cost a palette; the social wiring costs one way in of several; neither is
/// this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardedSetting {
    /// The pool. Every id_token is then checked against another issuer's `iss` and keys.
    Issuer,
    /// The email flow's app client. Every id_token is refused for its audience.
    ClientId,
    /// Where a `401` sends a browser. A wrong one is a sign-in page that is not there.
    LoginUrl,
    /// The cookie's `Domain`, and the only one here that does something worse than shut a
    /// door: see [`GateSettings::cookie_domain`].
    CookieDomain,
    /// Where a post-login redirect may land. Only a **removal** is guarded.
    AuthorizedHosts,
}

impl GuardedSetting {
    /// The field's name in the file, which is also the name both editors post it under.
    pub fn field(self) -> &'static str {
        match self {
            GuardedSetting::Issuer => "issuer",
            GuardedSetting::ClientId => "client_id",
            GuardedSetting::LoginUrl => "login_url",
            GuardedSetting::CookieDomain => "cookie_domain",
            GuardedSetting::AuthorizedHosts => "authorized_hosts",
        }
    }
}

/// Which guarded settings `new` changes relative to `old`: what an editor must confirm before
/// writing, and empty when there is nothing to stop for.
///
/// Two rules keep this quiet enough to be read, and both say the same thing: **a confirmation
/// is about what is taken away, never about what is set for the first time.** A field that was
/// empty and now is not can only be a deployment being finished, so it passes; a field that
/// had a value passes only if the value is unchanged. And for the host list, only a **removal**
/// counts: adding a host cannot stop a login, it widens where one may land, which is a
/// different conversation and one [`compile_settings`] already has with `cookie_domain`.
///
/// Comparison is on the normalised value, so a leading dot, a trailing slash, surrounding
/// space or a change of case is not a change. Two editors that disagreed about that would
/// disagree about when to ask.
pub fn guarded_changes(old: &GateSettings, new: &GateSettings) -> Vec<GuardedSetting> {
    let mut out = Vec::new();
    let scalar = |o: &str, n: &str| {
        let (o, n) = (o.trim(), n.trim());
        !o.is_empty() && o != n
    };
    if scalar(
        old.issuer.trim_end_matches('/'),
        new.issuer.trim().trim_end_matches('/'),
    ) {
        out.push(GuardedSetting::Issuer);
    }
    if scalar(&old.client_id, &new.client_id) {
        out.push(GuardedSetting::ClientId);
    }
    if scalar(&old.login_url, &new.login_url) {
        out.push(GuardedSetting::LoginUrl);
    }
    if scalar(
        cookie_domain_host(&old.cookie_domain.trim().to_ascii_lowercase()),
        cookie_domain_host(&new.cookie_domain.trim().to_ascii_lowercase()),
    ) {
        out.push(GuardedSetting::CookieDomain);
    }
    let host_set = |v: &[String]| -> Vec<String> {
        v.iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect()
    };
    let (before, after) = (
        host_set(&old.authorized_hosts),
        host_set(&new.authorized_hosts),
    );
    if before.iter().any(|h| !after.contains(h)) {
        out.push(GuardedSetting::AuthorizedHosts);
    }
    out
}

/// Validate the social sign-in buttons: a provider and an app client each.
///
/// **Fatal on a bad entry, like a claim name and for the same reason.** A silently skipped
/// entry here is a button an operator configured, cannot see, and has nowhere to look for:
/// there is no error, no log line at the moment it matters, and the page simply does not
/// offer what the file says it offers. Refusing the file says it once, in the editor, before
/// it is live. An entry with no app client is one of those: it could not draw a button, so it
/// is refused rather than dropped.
///
/// The charset is Cognito's own for an `identity_provider`: letters, digits, and `._-`. It is
/// not a list of known providers, because a user pool may federate a SAML or OIDC provider
/// under any name its administrator chose, and this file has no way to know which. What it
/// can refuse is a value that could never be one: a space, a quote, an angle bracket, a
/// percent sign. That value would land in a query parameter and in an HTML attribute, and
/// while both are escaped where they are emitted, a name that cannot work is worth catching
/// where it is written rather than where it fails.
///
/// Duplicates are refused rather than deduplicated: two buttons for one provider is not what
/// anybody meant, and quietly dropping one would hide a copy-paste from an operator who is
/// looking straight at the list.
///
/// This leaf answers the typed [`SettingsRefusal`] itself, with no `String` wrapper beside it:
/// `compile_settings` is its only caller, so the refusal built here is the refusal the file is
/// refused with, and there is no other caller whose words a wrapper would have to serve
/// (docs/ARCHITECTURE.md §13.31 §3).
pub fn compile_social_buttons(
    raw: &[SocialButtonSpec],
) -> Result<Vec<SocialButton>, SettingsRefusal> {
    let mut out: Vec<SocialButton> = Vec::with_capacity(raw.len());
    for entry in raw {
        let wired = match entry {
            SocialButtonSpec::Wired(w) => w,
            // The pre-2 shape, answered with the sentence a type error could not have said.
            SocialButtonSpec::Name(n) => {
                return Err(SettingsRefusal::ButtonBareName { name: n.clone() })
            }
        };
        let name = wired.idp.trim();
        if name.is_empty() {
            return Err(SettingsRefusal::ButtonNoIdp);
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        {
            return Err(SettingsRefusal::ButtonIdpCharset {
                idp: name.to_string(),
            });
        }
        if out.iter().any(|k| k.idp.eq_ignore_ascii_case(name)) {
            return Err(SettingsRefusal::ButtonTwice {
                idp: name.to_string(),
            });
        }
        // The shared app client core, with this button's name put on its refusal: the variant's
        // sentence spells `client_id`, which is the setting the core answers for, and a button's
        // audience is not that (§13.31 §3). Empty is `Ok("")` there, so the empty audience is
        // this leaf's own refusal, one check below.
        let audience = app_client_id_core(&wired.audience).map_err(|r| match r {
            SettingsRefusal::AppClientId { id, .. } => SettingsRefusal::AppClientId {
                button: Some(name.to_string()),
                id,
            },
            other => other,
        })?;
        if audience.is_empty() {
            return Err(SettingsRefusal::ButtonNoAudience {
                idp: name.to_string(),
            });
        }
        out.push(SocialButton {
            idp: name.to_string(),
            audience,
        });
    }
    Ok(out)
}

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
    fn prefix(&self) -> Option<&'static str> {
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
    fn sentence(&self) -> String {
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

/// Why [`SettingsWrite::prepare`] will not put a settings document on the disk: the two serde
/// failures on our own structs, and the refusal [`compile_settings`] makes.
///
/// Its `Display` is the sentence `bb-auth-adm` prints today, `refusing to write:` included, and
/// [`From<PrepareError> for String`] is the one thing that lets that CLI print it without
/// changing a line (docs/ARCHITECTURE.md §13.31 §3). The GUI does not use the sentence: it maps
/// the refusal's [`SettingsRefusal::code`] to a `K` key, in slice S8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrepareError {
    /// The document would not serialize: serde on our own structs, never seen.
    Serialize(String),
    /// The bytes it wrote do not re-parse: same, and the reason the check exists at all.
    Reparse(String),
    /// The compiled settings refuse these bytes, for a reason the settings file owns.
    Refused(SettingsRefusal),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(e) => write!(f, "cannot serialize: {e}"),
            Self::Reparse(e) => write!(f, "serialized to invalid JSON: {e}"),
            Self::Refused(r) => write!(f, "refusing to write: {r}"),
        }
    }
}

impl From<PrepareError> for String {
    fn from(e: PrepareError) -> String {
        e.to_string()
    }
}

/// The `map_err` that turns a URL leaf's `(raw, fault)` pair into [`SettingsRefusal::Url`] for
/// one setting, so the six URL settings of this function name themselves without six copies of
/// the same arm (§13.31 §3).
fn url_refusal(key: SettingKey) -> impl FnOnce((String, UrlFault)) -> SettingsRefusal {
    move |(raw, fault)| SettingsRefusal::Url { key, raw, fault }
}

/// The `map_err` that turns the audit header leaf's `(name, fault)` pair into
/// [`SettingsRefusal::AuditHeader`] for one of the two audit settings, the sibling of
/// [`url_refusal`] (§13.31 §3).
fn header_refusal(key: SettingKey) -> impl FnOnce((String, HeaderFault)) -> SettingsRefusal {
    move |(name, fault)| SettingsRefusal::AuditHeader { key, name, fault }
}

/// Turn a settings document into the compiled settings, or say why it cannot be one.
///
/// Fatal, with the same reflex the access file's parser has: what changes behaviour is an
/// error, what merely drops one entry is a warning. So a bad claim name, an unknown identity
/// attribute, an empty attribute list, a wrong `version` and a nonsensical TTL all refuse the
/// file; a malformed admin email is warned about and skipped, which fails closed (one fewer
/// administrator) exactly as a malformed roster identifier does.
///
/// The gate reads only the `gate` half and the GUI only the `web` half, but both compile the
/// whole file: an editor that validated only its own section could write one the other
/// refuses, and the point of a shared parser is that it cannot.
pub fn compile_settings(file: &SettingsFile) -> Result<Settings, SettingsRefusal> {
    if file.version != SETTINGS_VERSION {
        // Explanatory for the one version that exists in the wild, terse for anything else:
        // a file that says 1 was written before the Cognito app clients moved into it, and
        // its `social_client_id` and bare-name buttons cannot be read into this shape without
        // guessing which client each button belonged to.
        return Err(SettingsRefusal::Version {
            found: file.version,
        });
    }
    let profile_claims = profile_claims_core(&file.gate.profile_claims)?;
    let identity_attrs = identity_attrs_core(&file.gate.identity_attrs)?;

    let ttl = file.gate.session_ttl_secs;
    if ttl < MIN_SESSION_TTL {
        return Err(SettingsRefusal::TtlBelowFloor { ttl });
    }
    if ttl > MAX_HONOURED_SESSION_TTL {
        eprintln!(
            "[bb-auth] WARNING: session_ttl_secs {ttl} exceeds the {MAX_HONOURED_SESSION_TTL}s \
             (400 day) cap browsers apply to Max-Age; the excess is fiction"
        );
    }
    if ttl > MAX_SESSION_TTL {
        // The floor is a refusal and the browser cap is a warning, which left the top end
        // with no refusal at all: this value is added to the wall clock for the cookie's
        // `exp` and cast to `i64` for its `Max-Age`, so far enough out it wraps and mints a
        // cookie that expired in the past. That is the login loop the floor exists to
        // prevent, arrived at from the other end, and it is reachable from a GUI field.
        return Err(SettingsRefusal::TtlAboveCeiling { ttl });
    }

    let providers: Vec<String> = file
        .gate
        .social_providers
        .iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if !providers.is_empty() && !file.gate.allow_unverified_social {
        eprintln!(
            "[bb-auth] WARNING: social_providers lists {} provider(s) but \
             allow_unverified_social is off, so it narrows nothing",
            providers.len()
        );
    }

    // The app clients, and the audience list they derive. Nothing else in this system says
    // which app clients the gate is part of, which is what makes the derivation safe: there
    // is no second list to disagree with.
    let client_id = app_client_id_core(&file.gate.client_id)?;
    let login_url = match file.gate.login_url.trim() {
        "" => String::new(),
        raw => page_url_core(raw).map_err(url_refusal(SettingKey::LoginUrl))?,
    };
    let denied_url = match file.gate.denied_url.trim() {
        "" => String::new(),
        raw => page_url_core(raw).map_err(url_refusal(SettingKey::DeniedUrl))?,
    };
    let landing_url = match file.gate.landing_url.trim() {
        "" => String::new(),
        raw => page_url_core(raw).map_err(url_refusal(SettingKey::LandingUrl))?,
    };
    let issuer = issuer_core(&file.gate.issuer).map_err(url_refusal(SettingKey::Issuer))?;
    let cookie_domain = cookie_domain_core(&file.gate.cookie_domain)?;
    let mut authorized_hosts: Vec<UrlPattern> =
        Vec::with_capacity(file.gate.authorized_hosts.len());
    for raw in &file.gate.authorized_hosts {
        if raw.trim().is_empty() {
            continue;
        }
        authorized_hosts.push(host_pattern_core(raw)?);
    }
    // The check that only became possible once these two stopped living in different files,
    // and the reason the move is worth what it cost. A host the cookie cannot reach is not a
    // subtle misconfiguration: the login succeeds, the redirect lands, the browser sends no
    // session cookie, nginx answers 401, and the browser goes back to the sign-in page it
    // just came from, for ever, with nothing anywhere saying why.
    if !cookie_domain.is_empty() {
        let stray: Vec<String> = file
            .gate
            .authorized_hosts
            .iter()
            .map(|h| h.trim())
            .filter(|h| !h.is_empty() && !cookie_domain_covers(&cookie_domain, h))
            .map(str::to_string)
            .collect();
        if !stray.is_empty() {
            return Err(SettingsRefusal::HostsOutsideCookieDomain {
                hosts: stray,
                cookie_domain: cookie_domain.clone(),
            });
        }
    }
    // The same reflex one field along, and the reason `rd_url_allowed` lives in this library:
    // a landing page outside the redirect scope is refused by it at every login, so the login
    // falls back to the sign-in page, which is the loop this setting was added to end with a
    // setting standing beside it saying it is fixed. Silent is the half that costs an afternoon,
    // so the file refuses it on the way to disk, where both editors can still say so.
    if !landing_url.is_empty()
        && (authorized_hosts.is_empty() || !rd_url_allowed(&landing_url, &authorized_hosts))
    {
        return Err(SettingsRefusal::LandingOffHosts);
    }
    let oauth_domain = oauth_domain_core(&file.gate.oauth_domain)?;
    let social_callback_url = match asset_url_core(&file.gate.social_callback_url)
        .map_err(url_refusal(SettingKey::SocialCallbackUrl))?
    {
        Some(u) if !u.starts_with("https://") => return Err(SettingsRefusal::CallbackNotHttps),
        other => other,
    };
    let social_buttons = compile_social_buttons(&file.gate.social_buttons)?;
    // A button with nowhere to send the browser, or nowhere for it to come back to, is the
    // half-configured social sign-in that used to be a fatal startup when this lived in the
    // environment. It is still refused, one level earlier: in the editor, on the file.
    if !social_buttons.is_empty() && (oauth_domain.is_empty() || social_callback_url.is_none()) {
        return Err(SettingsRefusal::SocialHalfConfigured {
            buttons: social_buttons.len(),
        });
    }
    let mut audiences: Vec<String> = Vec::with_capacity(1 + social_buttons.len());
    if !client_id.is_empty() {
        audiences.push(client_id.clone());
    }
    for b in &social_buttons {
        if !audiences.contains(&b.audience) {
            audiences.push(b.audience.clone());
        }
    }

    // What the audit reads where a request came from out of. One header for both is refused
    // with a sentence rather than accepted: it could only ever be a slip, since no header
    // carries an address and an id at once, and one of the two settings would then record
    // nothing while looking configured.
    let client_ip_header = audit_header_core(&file.audit.client_ip_header)
        .map_err(header_refusal(SettingKey::ClientIpHeader))?;
    let request_id_header = audit_header_core(&file.audit.request_id_header)
        .map_err(header_refusal(SettingKey::RequestIdHeader))?;
    if !client_ip_header.is_empty() && client_ip_header.eq_ignore_ascii_case(&request_id_header) {
        return Err(SettingsRefusal::AuditHeadersSame {
            name: client_ip_header,
        });
    }
    let audit_policy = audit_section_core(&file.audit.rotation, &file.audit.retention)?;

    let mut admins: Vec<String> = Vec::new();
    for raw in &file.web.admins {
        let e = norm_email(raw);
        if e.is_empty() {
            continue;
        }
        // The same rule the roster's identifiers are held to, and skipped for the same reason:
        // an entry that could never match the identity nginx injects is one administrator
        // fewer, which is the safe direction to be wrong in.
        if !header_safe_email(&e) || !well_formed_email(&e) {
            eprintln!("[bb-auth] WARNING: web.admins: '{e}' is not an email, skipping");
            continue;
        }
        if !admins.contains(&e) {
            admins.push(e);
        }
    }

    // The look. Fatal on a bad value, with the same reflex the claim list is held to and for
    // the same reason: a stylesheet URL silently dropped is a deployment that goes on looking
    // wrong with nothing anywhere saying why. It cannot lock anybody out, which is what earns
    // it a place in this file at all, but "cannot lock anybody out" is not "may be wrong in
    // silence".
    let stylesheet_url =
        asset_url_core(&file.ui.stylesheet_url).map_err(url_refusal(SettingKey::StylesheetUrl))?;
    let logo_url = asset_url_core(&file.ui.logo_url).map_err(url_refusal(SettingKey::LogoUrl))?;
    let brand_name = brand_name_core(&file.ui.brand_name)?;
    let theme = UiTheme::parse(&file.ui.theme).ok_or_else(|| SettingsRefusal::ThemeUnknown {
        raw: file.ui.theme.trim().to_string(),
    })?;

    Ok(Settings {
        profile_claims,
        identity_attrs,
        allow_unverified_social: file.gate.allow_unverified_social,
        social_providers: (!providers.is_empty()).then_some(providers),
        client_id,
        audiences,
        login_url,
        denied_url,
        landing_url,
        oauth_domain: (!oauth_domain.is_empty()).then_some(oauth_domain),
        social_callback_url,
        social_buttons,
        session_ttl: ttl,
        issuer,
        cookie_domain: (!cookie_domain.is_empty()).then_some(cookie_domain),
        authorized_hosts,
        client_ip_header: (!client_ip_header.is_empty()).then_some(client_ip_header),
        request_id_header: (!request_id_header.is_empty()).then_some(request_id_header),
        audit_policy,
        admins,
        stylesheet_url,
        logo_url,
        brand_name,
        theme,
    })
}

/// Read and parse a settings file, without compiling it.
pub fn read_settings_file(path: &str) -> Result<SettingsFile, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("{path}: {e}"))
}

/// Read, parse and compile a settings file: what the gate does at startup and on every
/// SIGHUP, and what `--check-settings` reports on.
pub fn read_settings(path: &str) -> Result<Settings, String> {
    let file = read_settings_file(path)?;
    compile_settings(&file).map_err(|e| format!("{path}: {e}"))
}

/// Open a settings file for editing: the document to mutate, and what the services would make
/// of it as it stands.
///
/// A file either service would reject is refused here too, for the reason [`open_access_file`]
/// refuses one: an edit must start from a file that works, or a tool would cheerfully fix one
/// problem while carrying a fatal one to the disk.
pub fn open_settings_file(path: &str) -> Result<(SettingsFile, Settings), String> {
    let doc = read_settings_file(path)?;
    let settings = compile_settings(&doc)
        .map_err(|e| format!("{path}: the gate would reject this file as it stands: {e}"))?;
    Ok((doc, settings))
}

/// Serialize a settings document to the exact bytes it is written as: pretty JSON plus one
/// trailing newline, the same shape an access file is written in.
pub fn render_settings_file(doc: &SettingsFile) -> Result<String, String> {
    let mut json = serde_json::to_string_pretty(doc).map_err(|e| e.to_string())?;
    json.push('\n');
    Ok(json)
}

/// An edited settings document, rendered to the exact bytes it would be written as, and
/// already compiled.
///
/// [`AccessWrite`] for the other file, and the same rule made unskippable the same way:
/// [`SettingsWrite::prepare`] compiles, [`SettingsWrite::commit`] writes only what was
/// compiled, and `write_atomically` is private to this crate so there is no other door. The
/// stakes are lower than the access file's by exactly one step: a settings file the gate
/// refuses is a *reload* it declines, not a boot loop, because the running table survives,
/// but a restart would still meet it, so the check stays where it cannot be skipped.
#[derive(Debug)]
pub struct SettingsWrite {
    json: String,
    settings: Settings,
}

impl SettingsWrite {
    /// Render `doc`, then re-parse and compile the rendered text. `Err` means these bytes must
    /// not reach the disk, and says why: [`PrepareError`], whose `Display` is the sentence the
    /// CLI prints, prefix included.
    pub fn prepare(doc: &SettingsFile) -> Result<SettingsWrite, PrepareError> {
        let json = render_settings_file(doc).map_err(PrepareError::Serialize)?;
        let reparsed: SettingsFile =
            serde_json::from_str(&json).map_err(|e| PrepareError::Reparse(e.to_string()))?;
        let settings = compile_settings(&reparsed).map_err(PrepareError::Refused)?;
        Ok(SettingsWrite { json, settings })
    }

    /// The bytes: what a dry run prints, and exactly what [`SettingsWrite::commit`] writes.
    pub fn json(&self) -> &str {
        &self.json
    }

    /// What the services will make of those bytes.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Replace `path` with these bytes. The file must already exist: its mode and owner are
    /// what the replacement inherits.
    pub fn commit(&self, path: &str) -> Result<Written, String> {
        write_atomically(path, &self.json)
    }

    /// Create `path` with these bytes, and only if it does not exist yet. See
    /// [`AccessWrite::create`], which is the same operation on the other file and carries the
    /// reasoning.
    pub fn create(&self, path: &str) -> Result<(), String> {
        create_new_file(path, &self.json)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
