//! bb-auth — a minimal, service-agnostic auth gate for nginx `auth_request`.
//!
//! Authorization-code OIDC proxies drive the login themselves and cannot accept a
//! token the client already holds. bb-auth is built for the opposite: it takes a
//! Cognito **id_token** that a browser-side login page already obtained (the
//! `USER_AUTH` flow on a public app client), validates it, and exchanges it for an
//! HMAC-signed session cookie. That is what makes "auto-login right after
//! registration, with no second OTP" possible. Everything else is wired
//! per-deployment through `BB_AUTH_*` env vars ([`Config::from_env`]).
//!
//! # Endpoints
//!
//! All under `/auth/`, fronted by nginx on the protected host.
//!
//! | Method | Path | Caller | Behaviour |
//! |--------|------|--------|-----------|
//! | `GET`  | `/auth/validate` | nginx `auth_request`, loopback | 204 if a credential authorizes the request, else 401 |
//! | `POST` | `/auth/session`  | browser | validate the posted `id_token`, set the cookie, 302 → `rd` |
//! | `GET`  | `/auth/logout`   | browser | clear the cookie, 302 → the login page |
//! | `GET`  | `/auth/healthz`  | local   | 200 `ok` |
//!
//! # Authorization model
//!
//! [`handle_validate`] accepts three credentials, tried in this order:
//!
//! 1. `Authorization: Bearer bbk_…` — a static API key, resolved by SHA-256 of the
//!    bearer against the users file.
//! 2. `Authorization: Bearer <id_token>` — a raw Cognito id_token, validated exactly
//!    as on `/auth/session`. Lets programmatic clients (e.g. MCP) skip the cookie flow.
//! 3. the session cookie.
//!
//! A Cognito-signed id_token is unforgeable, but holding one is **not** sufficient:
//! Cognito self-signup is open, so every credential must additionally resolve to an
//! entry in the users file ([`read_users`]) *and* the request URL must fall inside
//! that entry's [`UrlScope`]. Both are re-checked on every request, so deleting a
//! user or a single API key and reloading denies even a still-unexpired cookie.
//!
//! Bearers are stateless — they issue no cookie — and a failed bearer falls through
//! to the cookie check, so a stray `Authorization` header never blocks a valid cookie.

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tiny_http::{Header, Request, Response, Server, StatusCode};

type HmacSha256 = Hmac<Sha256>;

/// Cap on the `/auth/session` request body. Cognito id_tokens run 1–3 KB; the limit
/// is generous and exists only to bound the memory a single request can claim.
const MAX_BODY: u64 = 64 * 1024;

/// Active session-cookie format tag, and the wire format it names:
///
/// ```text
/// cookie = "bb2" "." keyid "." exp "." b64url(email) "." b64url(sig)
/// sig    = HMAC_SHA256("bb2." keyid "." exp "." b64url(email), key[keyid])
/// ```
///
/// The key id is stamped into the cookie so the signing key can roll over with zero
/// downtime: during a rotation every accepted id still verifies, while only the
/// active key signs new cookies.
///
/// This is a wire format with live clients. Changing the serialization — or the bytes
/// that go into `sig` — invalidates every cookie in the wild and logs out every user.
/// [`make_session`], [`verify_session`] and their tests pin it.
const COOKIE_VERSION: &str = "bb2";

/// Legacy, verify-only cookie format tag:
///
/// ```text
/// cookie = "bb1" "." exp "." b64url(email) "." b64url(sig)
/// sig    = HMAC_SHA256("bb1." exp "." b64url(email), key)
/// ```
///
/// It carries no key id, so [`verify_session`] tries every accepted key. Kept so the
/// `bb2` rollout logged nobody out; nothing mints `bb1` cookies any more.
const COOKIE_VERSION_LEGACY: &str = "bb1";

/// Namespace prefix marking a static API-key bearer credential (vs a Cognito
/// id_token JWT): `Authorization: Bearer bbk_<secret>`.
const API_KEY_PREFIX: &str = "bbk_";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// A cookie key id must not contain '.', otherwise `splitn(5, '.')` on a cookie
/// would be ambiguous. Allow `[A-Za-z0-9_-]+`.
fn valid_keyid(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// HMAC signing keys: an active (signing) key plus a set of accepted
/// (verify-only) keys, all addressed by id. Stamping the key id into the cookie
/// lets the signing key roll over with zero downtime — accept multiple ids for
/// verification while only the active key signs new cookies.
struct HmacKeys {
    by_id: HashMap<String, Vec<u8>>,
    active_id: String,
}

impl HmacKeys {
    /// The key new cookies are signed with. Infallible: [`Config::from_env`] always
    /// inserts the active key under `active_id`.
    fn active(&self) -> &[u8] {
        self.by_id
            .get(&self.active_id)
            .expect("active HMAC key present")
    }
}

/// Runtime configuration, read once from the environment at startup. Every field is
/// a `BB_AUTH_*` env var; a missing required one is a fatal exit. Because it is read
/// once, a config change needs `systemctl restart`, not `reload` (which only re-reads
/// the users file).
struct Config {
    /// `BB_AUTH_LISTEN`, the loopback address the gate binds. Default `127.0.0.1:4181`.
    listen: String,
    /// Session-cookie signing/verifying keys, from `BB_AUTH_HMAC_KEY{,_ID}` and
    /// `BB_AUTH_HMAC_ACCEPTED_KEYS`.
    hmac_keys: HmacKeys,
    /// `BB_AUTH_COGNITO_ISSUER`, with no trailing slash. The JWKS URL is derived from it.
    issuer: String,
    /// Accepted token audiences (Cognito app client ids). Always contains
    /// `BB_AUTH_CLIENT_ID` at index 0; `BB_AUTH_AUDIENCES` appends extras (e.g. a
    /// separate social-login client). A token is accepted if its `aud` matches any entry.
    audiences: Vec<String>,
    /// Relax the `email_verified` requirement, but ONLY for federated (social) logins —
    /// never for native Cognito users. Cognito often cannot verify the email of a social
    /// sign-up (Google/Apple/…), so it stamps `email_verified=false` even though the IdP
    /// itself asserted the address. Off by default. See [`unverified_social_ok`].
    allow_unverified_social: bool,
    /// Optional provider allowlist narrowing [`Config::allow_unverified_social`], matched
    /// case-insensitively against the token's `identities[].providerName`. `None` = any
    /// federated provider. Restrict it to IdPs that actually verify the email.
    social_providers: Option<Vec<String>>,
    /// `BB_AUTH_COOKIE_NAME`, the session cookie's name. Default `bb_session`.
    cookie_name: String,
    /// `BB_AUTH_COOKIE_DOMAIN`. `None` = a host-only cookie (per-service login); a parent
    /// domain (`.example.com`) shares one session across every service behind the gate.
    cookie_domain: Option<String>,
    /// `BB_AUTH_SESSION_TTL_SECS`, the cookie's lifetime in seconds.
    session_ttl: u64,
    /// Hosts a post-login `rd` may land on (`BB_AUTH_AUTHORIZED_HOSTS`), as globs matched
    /// against the host alone, e.g. `badbat75.com,*.badbat75.com`.
    ///
    /// This is the *only* authority for [`safe_rd`]. There is no canonical service base
    /// URL: one gate fronts several hosts, and which one is in play is decided by the
    /// caller. Enumerate the apex explicitly — `*.x.com` does not match `x.com`. Pair it
    /// with `BB_AUTH_COOKIE_DOMAIN=.<domain>` to share the session cookie across siblings.
    authorized_hosts: Vec<UrlPattern>,
    /// `BB_AUTH_LOGIN_URL`, e.g. `https://login.example.com/`. Where a 401, a logout, and
    /// every rejected `rd` land.
    login_url: String,
    /// Name of the request header carrying the original request URL — scheme, host and
    /// normalised path. `BB_AUTH_ORIGINAL_URL_HEADER`, default `X-Original-URL`.
    ///
    /// It drives per-user/per-key URL scoping on `/auth/validate`, and on `/auth/session`
    /// it tells bb-auth which host the login is happening on, so a relative `rd` resolves
    /// against the caller. nginx must set it on both, with the host hardcoded per server
    /// block so a spoofed `Host:` cannot widen a scope. Inside an `auth_request`
    /// subrequest `$uri` is the subrequest's own URI, so the gated location has to stash
    /// the real one first:
    ///
    /// ```text
    /// location / {
    ///     set $bb_url https://app.example.com$uri;   # rewrite phase, before auth_request
    ///     auth_request /internal/auth-gate;
    /// }
    /// location = /internal/auth-gate {
    ///     proxy_set_header X-Original-URL $bb_url;
    /// }
    /// ```
    ///
    /// `$uri`, never `$request_uri`: the latter is undecoded and carries the query
    /// string, so `/app/%2e%2e/admin` would match an `/app/*` scope while nginx serves
    /// `/admin`. A gated location that forgets the `set` sends no header and is denied.
    original_url_header: String,
    /// `BB_AUTH_WORKERS`, the number of blocking request threads. At least 1.
    workers: usize,
}

/// Read an env var, falling back to `default` when unset.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read a required env var, or exit(1). There is no safe default for any of these.
fn env_req(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        eprintln!("[bb-auth] FATAL: missing required env var {key}");
        std::process::exit(1);
    })
}

/// Parse a boolean env var. Truthy: `1`/`true`/`yes`/`on` (case-insensitive);
/// anything else (incl. unset) is false.
fn env_flag(key: &str) -> bool {
    matches!(
        env_or(key, "").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

impl Config {
    /// Build the config from the `BB_AUTH_*` env vars, exiting on the first fatal
    /// problem: a missing required var, a short HMAC key, a malformed key id, or an
    /// empty/unparseable `BB_AUTH_AUTHORIZED_HOSTS`.
    fn from_env() -> Self {
        let active_key = env_req("BB_AUTH_HMAC_KEY").into_bytes();
        if active_key.len() < 32 {
            eprintln!("[bb-auth] FATAL: BB_AUTH_HMAC_KEY must be >= 32 bytes");
            std::process::exit(1);
        }
        let active_id = env_or("BB_AUTH_HMAC_KEY_ID", "default");
        if !valid_keyid(&active_id) {
            eprintln!(
                "[bb-auth] FATAL: BB_AUTH_HMAC_KEY_ID must be non-empty and contain only [A-Za-z0-9_-]"
            );
            std::process::exit(1);
        }

        // Accepted (verify-only) keys, `id:key` comma-separated. The key is the
        // raw env bytes (an `openssl rand -base64 48` string; base64 never
        // contains ',' or ':'). The active key is inserted LAST so it wins on
        // an id collision with an accepted entry.
        let mut by_id: HashMap<String, Vec<u8>> = HashMap::new();
        for entry in env_or("BB_AUTH_HMAC_ACCEPTED_KEYS", "").split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (id, key) = match entry.split_once(':') {
                Some((a, b)) => (a.trim(), b.trim()),
                None => {
                    eprintln!(
                        "[bb-auth] FATAL: BB_AUTH_HMAC_ACCEPTED_KEYS entry '{entry}' is not 'id:key'"
                    );
                    std::process::exit(1);
                }
            };
            if !valid_keyid(id) {
                eprintln!(
                    "[bb-auth] FATAL: BB_AUTH_HMAC_ACCEPTED_KEYS id '{id}' must contain only [A-Za-z0-9_-]"
                );
                std::process::exit(1);
            }
            if key.len() < 32 {
                eprintln!(
                    "[bb-auth] FATAL: BB_AUTH_HMAC_ACCEPTED_KEYS key '{id}' must be >= 32 bytes"
                );
                std::process::exit(1);
            }
            by_id.insert(id.to_string(), key.as_bytes().to_vec());
        }
        by_id.insert(active_id.clone(), active_key);

        let issuer = env_req("BB_AUTH_COGNITO_ISSUER")
            .trim_end_matches('/')
            .to_string();
        let cookie_domain = match env_or("BB_AUTH_COOKIE_DOMAIN", "") {
            s if s.is_empty() => None,
            s => Some(s),
        };
        // The redirect scope: which hosts a post-login `rd` may land on. Required —
        // there is no default, and an empty list would make every login bounce back to
        // the login page.
        let authorized_hosts: Vec<UrlPattern> = env_req("BB_AUTH_AUTHORIZED_HOSTS")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|h| {
                compile_host_pattern(h).unwrap_or_else(|e| {
                    eprintln!("[bb-auth] FATAL: BB_AUTH_AUTHORIZED_HOSTS: {e}");
                    std::process::exit(1);
                })
            })
            .collect();
        if authorized_hosts.is_empty() {
            eprintln!("[bb-auth] FATAL: BB_AUTH_AUTHORIZED_HOSTS is empty");
            std::process::exit(1);
        }

        // `client_id` is always an accepted audience; `BB_AUTH_AUDIENCES`
        // (comma-separated) appends extra app-client ids — a Cognito id_token is
        // accepted if its `aud` matches ANY of them. Unset => only `client_id`
        // (backward-compatible). Deduplicated, order-preserving.
        let client_id = env_req("BB_AUTH_CLIENT_ID");
        let mut audiences = vec![client_id.clone()];
        for extra in env_or("BB_AUTH_AUDIENCES", "").split(',') {
            let extra = extra.trim();
            if !extra.is_empty() && !audiences.iter().any(|a| a == extra) {
                audiences.push(extra.to_string());
            }
        }

        // Social-login relaxation of `email_verified` (see Config fields).
        let allow_unverified_social = env_flag("BB_AUTH_ALLOW_UNVERIFIED_SOCIAL");
        let social_providers: Vec<String> = env_or("BB_AUTH_SOCIAL_PROVIDERS", "")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let social_providers = if social_providers.is_empty() {
            None
        } else {
            Some(social_providers)
        };

        Config {
            listen: env_or("BB_AUTH_LISTEN", "127.0.0.1:4181"),
            hmac_keys: HmacKeys { by_id, active_id },
            issuer,
            audiences,
            allow_unverified_social,
            social_providers,
            cookie_name: env_or("BB_AUTH_COOKIE_NAME", "bb_session"),
            cookie_domain,
            session_ttl: env_or("BB_AUTH_SESSION_TTL_SECS", "2592000")
                .parse()
                .unwrap_or(2_592_000),
            authorized_hosts,
            login_url: env_req("BB_AUTH_LOGIN_URL"),
            original_url_header: env_or("BB_AUTH_ORIGINAL_URL_HEADER", "X-Original-URL"),
            workers: env_or("BB_AUTH_WORKERS", "4").parse().unwrap_or(4).max(1),
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Cognito's public signing keys, by `kid`, with the time of the last successful fetch.
struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    last_refresh: Instant,
}

/// Everything a worker thread needs. Shared immutably behind an [`Arc`]; the two
/// mutable parts are the hot-reloadable users table and the JWKS cache.
struct State {
    cfg: Config,
    /// The access gate: allowlisted users and their API keys, both indexed. Swapped
    /// wholesale on SIGHUP by `reload_users` (POSIX only, hence not linked here).
    users: RwLock<Users>,
    /// Path to re-read on SIGHUP. Only the POSIX reload path needs it.
    #[cfg(unix)]
    users_path: String,
    jwks: RwLock<JwksCache>,
    /// Serializes JWKS refreshers, so a `kid` miss under load triggers one fetch, not
    /// one per worker. See [`refresh_jwks_if_due`].
    jwks_refresh: Mutex<()>,
}

/// Current Unix time in seconds, saturating to 0 if the clock predates the epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Users table
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
fn glob_match(pat: &[u8], s: &[u8]) -> bool {
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

/// The `scheme://host` prefix of an absolute URL, with no trailing slash. `None` if
/// `url` is not absolute or carries an empty authority. Used to learn which host a
/// login is happening on, so a relative `rd` can resolve against the caller.
fn origin_of(url: &str) -> Option<String> {
    let i = url.find("://")?;
    let rest = &url[i + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(url[..i + 3 + end].to_string())
}

/// Lowercase the authority (`scheme://host`) of a URL, leaving the path's case
/// intact. Hosts and schemes are case-insensitive per RFC 3986; paths are not.
fn lower_authority(url: &str) -> String {
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

/// A compiled `authorized_urls` entry: normalised pattern bytes.
#[derive(Clone)]
struct UrlPattern {
    pat: Vec<u8>,
}

/// Validate and normalise one `authorized_urls` entry. A malformed pattern is an
/// error rather than a silently-dead rule: skipping it would quietly narrow (or, if
/// it was the only entry, blank out) a scope that someone believed they had written.
fn compile_pattern(raw: &str) -> Result<UrlPattern, String> {
    let e = |m: &str| Err(format!("authorized_urls entry '{raw}': {m}"));
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

/// Validate and normalise one `BB_AUTH_AUTHORIZED_HOSTS` entry: a host-only glob
/// (`badbat75.com`, `*.badbat75.com`, `v&.badbat75.com`). No scheme, no path, no port
/// — `rd_url_allowed` strips those from the candidate before matching.
fn compile_host_pattern(raw: &str) -> Result<UrlPattern, String> {
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

/// Allowed request-URL scope for a user or key: the patterns it may reach.
///
/// There is no "unrestricted" variant. An absent or empty `authorized_urls` grants
/// **nothing** — access is enumerated, never assumed. Blanket access is spelled out
/// as the pattern `*://*/*`, which an operator has to mean in order to write.
#[derive(Clone)]
struct UrlScope {
    patterns: Vec<UrlPattern>, // request URL must match one of these; empty = deny all
}

impl UrlScope {
    /// The empty scope: authorizes no URL at all. What an absent `authorized_urls`
    /// resolves to.
    fn deny_all() -> UrlScope {
        UrlScope {
            patterns: Vec::new(),
        }
    }

    /// Compile a JSON `authorized_urls` list.
    fn compile(list: &[String]) -> Result<UrlScope, String> {
        let mut patterns = Vec::with_capacity(list.len());
        for raw in list.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            patterns.push(compile_pattern(raw)?);
        }
        Ok(UrlScope { patterns })
    }

    /// Whether this scope authorizes nothing at all. Only used to warn at load time.
    fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Whether `url` (the original request URL, query/fragment stripped, authority
    /// lowercased) is in scope. A missing URL (`None`) is always a denial: every
    /// credential is scoped, so the reverse proxy must always send the header. `..`
    /// anywhere is rejected — nginx's `$uri` is already normalised, so this only
    /// fires on a misconfigured proxy, and it fires closed.
    fn allows(&self, url: Option<&str>) -> bool {
        match url {
            None => false,
            Some(u) => {
                !u.contains("..")
                    && self
                        .patterns
                        .iter()
                        .any(|p| glob_match(&p.pat, u.as_bytes()))
            }
        }
    }
}

/// A resolved allowlisted user, keyed by lowercased email in [`Users::by_email`].
struct UserRecord {
    scope: UrlScope,
}

/// A resolved API key, keyed by the bearer's SHA-256 hex in [`Users::by_key_hash`].
struct ApiKeyRecord {
    /// Owning user, for logging.
    email: String,
    /// Human label, for logging and revocation. Not part of the credential.
    key_id: String,
    /// Unix seconds; `None` = never expires.
    expires: Option<u64>,
    /// The key's own scope, or the owner's if it declared none.
    scope: UrlScope,
}

/// The two runtime indices built from the users file by [`read_users`].
struct Users {
    /// Lowercased email → user.
    by_email: HashMap<String, UserRecord>,
    /// `sha256(bearer)` hex → key. The raw key is never stored, and this lookup **is**
    /// the verification: finding a matching row would require a SHA-256 second preimage,
    /// so a high-entropy key needs neither a salt nor a constant-time compare.
    by_key_hash: HashMap<String, ApiKeyRecord>,
}

// --- JSON wire format (only the fields we consume; extras are ignored) ---

/// Root of the users file (`BB_AUTH_USERS_FILE`) — the real access gate, re-checked on
/// every `/auth/validate` and hot-reloaded on SIGHUP.
///
/// ```json
/// { "users": [
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
/// Access is enumerated, never assumed: a user with no `authorized_urls` reaches
/// nothing. "Everything" is the explicit pattern `*://*/*`. Validate a file before
/// shipping it with `bb-auth --check-users <file>` ([`check_users`]).
#[derive(Deserialize)]
struct UsersFile {
    #[serde(default)]
    users: Vec<UserSpec>,
}

/// One user entry. Extra fields are ignored, with one deliberate exception.
#[derive(Deserialize)]
struct UserSpec {
    email: String,
    /// Absent **or** empty ⇒ this user reaches nothing ([`UrlScope::deny_all`]).
    /// Blanket access is the explicit pattern `*://*/*`.
    #[serde(default)]
    authorized_urls: Option<Vec<String>>,
    /// The pre-2.0 path-prefix field. Its mere presence is a fatal parse error rather
    /// than an ignored extra: under the old semantics an unscoped user reached
    /// everything, so silently dropping it would fail *open*. See [`read_users`].
    #[serde(default)]
    enabled_paths: Option<serde_json::Value>,
    #[serde(default)]
    api_keys: Vec<ApiKeySpec>,
}

/// One static API key belonging to a [`UserSpec`]. The `bbk_` bearer itself never
/// appears here — only `key_hash`. Mint keys with `tools/bb-apikey.py`.
#[derive(Deserialize)]
struct ApiKeySpec {
    #[serde(default)]
    id: String,
    /// Lowercase hex SHA-256 of the whole `bbk_…` bearer. A malformed value warns and
    /// skips just this key.
    #[serde(default)]
    key_hash: String,
    /// `YYYY-MM-DD` the key was issued; the base for `duration`.
    #[serde(default)]
    released: String,
    /// `<n>d`, `<n>h`, a bare `<n>` (days), or `never`/`0`/`-`. See [`parse_duration`].
    #[serde(default)]
    duration: String,
    /// Absent ⇒ inherit the owning user's scope; present (even empty) ⇒ this key's own.
    #[serde(default)]
    authorized_urls: Option<Vec<String>>,
    /// Fatal if present, exactly as on [`UserSpec::enabled_paths`].
    #[serde(default)]
    enabled_paths: Option<serde_json::Value>,
}

/// SHA-256 of `s`, lowercase hex. Fingerprints an API key for storage/lookup.
fn sha256_hex(s: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(s.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    hex
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

/// Parse a `YYYY-MM-DD` date to Unix seconds at 00:00 UTC. Rejects malformed
/// dates and anything before the epoch.
fn parse_date_epoch(s: &str) -> Option<u64> {
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

/// A parsed validity window.
enum Dur {
    Never,
    Secs(u64),
}

/// Parse a duration field: `0` / `never` / `-` (or empty) => `Never`; otherwise
/// `<n>d` days, `<n>h` hours, or a bare `<n>` (days). `None` on a malformed value.
fn parse_duration(s: &str) -> Option<Dur> {
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
fn key_expiry(released: &str, duration: &str) -> Option<Option<u64>> {
    match parse_duration(duration)? {
        Dur::Never => Some(None),
        Dur::Secs(secs) => Some(Some(parse_date_epoch(released)?.checked_add(secs)?)),
    }
}

/// Parse the users JSON into the two runtime indices. Structurally-invalid JSON, a
/// residual `enabled_paths`, or a malformed URL pattern are hard errors (so a SIGHUP
/// reload keeps the old table); an individual malformed *key* is warned about and
/// skipped so one bad `key_hash` can't drop every user.
///
/// Scope errors are deliberately fatal rather than skip-with-warning: a dropped
/// scope entry silently changes who can reach what. `bb-auth --check-users` exists
/// so a deploy can catch that before restarting the service.
fn read_users(path: &str) -> Result<Users, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let file: UsersFile =
        serde_json::from_str(&content).map_err(|e| format!("parse {path}: {e}"))?;
    let mut by_email = HashMap::new();
    let mut by_key_hash = HashMap::new();
    for u in &file.users {
        let email = u.email.trim().to_ascii_lowercase();
        if email.is_empty() {
            eprintln!("[bb-auth] WARNING: users entry with empty email, skipping");
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
    Ok(Users {
        by_email,
        by_key_hash,
    })
}

/// Initial users load: a missing/unreadable/invalid file is fatal (no safe
/// default exists at startup); an empty user set warns but is allowed.
fn load_users(path: &str) -> Users {
    match read_users(path) {
        Ok(u) => {
            if u.by_email.is_empty() {
                eprintln!("[bb-auth] WARNING: users file {path} has no users — nobody can sign in");
            }
            u
        }
        Err(e) => {
            eprintln!("[bb-auth] FATAL: cannot read users file: {e}");
            std::process::exit(1);
        }
    }
}

/// Hot-reload the users table from disk (SIGHUP). On read/parse failure, keep the
/// current table and log — never nuke the live table on a transient error.
#[cfg(unix)]
fn reload_users(state: &State) {
    match read_users(&state.users_path) {
        Ok(new) => {
            let (u, k) = (new.by_email.len(), new.by_key_hash.len());
            *state.users.write().unwrap() = new; // fail-safe: atomic swap
            eprintln!("[bb-auth] users reloaded (SIGHUP): {u} users, {k} api keys");
        }
        Err(e) => eprintln!("[bb-auth] users reload FAILED, keeping current set: {e}"),
    }
}

/// Spawn the SIGHUP -> users-reload thread. SIGHUP is POSIX-only, so this is a
/// no-op on non-unix hosts (where the table simply reloads across a restart).
#[cfg(unix)]
fn spawn_users_reload_handler(state: &Arc<State>) {
    use signal_hook::consts::SIGHUP;
    use signal_hook::iterator::Signals;

    let sig_state = Arc::clone(state);
    std::thread::spawn(move || {
        let mut signals = match Signals::new([SIGHUP]) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[bb-auth] SIGHUP handler init failed: {e}");
                return;
            }
        };
        for _ in signals.forever() {
            reload_users(&sig_state);
        }
    });
}

#[cfg(not(unix))]
fn spawn_users_reload_handler(_state: &Arc<State>) {}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

/// Fetch and parse the issuer's JWKS, keyed by `kid`. Unusable individual keys are
/// skipped with a warning; an empty result is an error. Outbound HTTPS only — bb-auth
/// never sends anything to Cognito and holds no client secret.
fn fetch_jwks(issuer: &str) -> Result<HashMap<String, DecodingKey>, String> {
    let url = format!("{issuer}/.well-known/jwks.json");
    let body = ureq::get(&url)
        .timeout(Duration::from_secs(10))
        .call()
        .map_err(|e| format!("jwks GET {url}: {e}"))?
        .into_string()
        .map_err(|e| format!("jwks read: {e}"))?;
    let set: JwkSet = serde_json::from_str(&body).map_err(|e| format!("jwks parse: {e}"))?;
    let mut map = HashMap::new();
    for jwk in &set.keys {
        if let Some(kid) = jwk.common.key_id.clone() {
            match DecodingKey::from_jwk(jwk) {
                Ok(k) => {
                    map.insert(kid, k);
                }
                Err(e) => eprintln!("[bb-auth] skipping unusable JWK: {e}"),
            }
        }
    }
    if map.is_empty() {
        return Err("jwks contained no usable keys".into());
    }
    Ok(map)
}

/// Refresh the JWKS cache if the last refresh is older than 60 s, using
/// double-checked locking so concurrent workers don't all hammer Cognito when a
/// `kid` misses. The network fetch happens with NO jwks lock held. On failure
/// `last_refresh` is intentionally left stale so the next request retries
/// immediately.
fn refresh_jwks_if_due(state: &State) {
    let due = state.jwks.read().unwrap().last_refresh.elapsed() > Duration::from_secs(60);
    if !due {
        return;
    }
    let _guard = state.jwks_refresh.lock().unwrap(); // serialize refreshers
    let still_due = state.jwks.read().unwrap().last_refresh.elapsed() > Duration::from_secs(60);
    if !still_due {
        return;
    }
    match fetch_jwks(&state.cfg.issuer) {
        Ok(new) => {
            let mut c = state.jwks.write().unwrap();
            c.keys = new;
            c.last_refresh = Instant::now();
        }
        Err(e) => eprintln!("[bb-auth] JWKS refresh failed: {e}"),
    }
}

/// Return the decoding key for `kid`, refreshing the JWKS at most once per minute
/// if the kid is unknown (handles Cognito key rotation).
fn decoding_key(state: &State, kid: &str) -> Option<DecodingKey> {
    {
        let c = state.jwks.read().unwrap();
        if let Some(k) = c.keys.get(kid) {
            return Some(k.clone());
        }
    }
    refresh_jwks_if_due(state);
    state.jwks.read().unwrap().keys.get(kid).cloned()
}

// ---------------------------------------------------------------------------
// id_token validation
// ---------------------------------------------------------------------------

/// The id_token claims bb-auth consumes. `exp`, `aud` and `iss` are enforced by
/// `jsonwebtoken` before this is deserialized.
#[derive(Deserialize)]
struct Claims {
    email: Option<String>,
    /// Cognito sends this as a bool or as the string `"true"`; see [`email_verified_true`].
    #[serde(default)]
    email_verified: serde_json::Value,
    /// Must be `"id"` — an access_token must not be usable as a credential here.
    token_use: Option<String>,
    /// Non-empty only for federated/social logins; absent for native Cognito users.
    /// Each entry names the upstream IdP via `providerName`. This is what lets the
    /// `email_verified` relaxation target social logins only.
    #[serde(default)]
    identities: Vec<Identity>,
}

/// One entry of the Cognito `identities` claim. Only `providerName` is needed
/// (e.g. `Google`, `SignInWithApple`, `Facebook`); other fields are ignored.
#[derive(Deserialize)]
struct Identity {
    #[serde(rename = "providerName")]
    provider_name: Option<String>,
}

/// Whether the `email_verified` claim is truthy. Cognito types it as a bool, but some
/// federated flows stringify it, so `"true"` counts. Anything else is false.
fn email_verified_true(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Whether an `email_verified=false` token may still be accepted under the
/// social-login relaxation. Requires the feature to be enabled AND the token to
/// carry a federated `identities` entry from an accepted provider. A native
/// Cognito user (no `identities`) is never relaxed: self-signup is open, so an
/// unverified native email is attacker-controlled and must stay rejected.
fn unverified_social_ok(
    allow: bool,
    providers: &Option<Vec<String>>,
    identities: &[Identity],
) -> bool {
    if !allow || identities.is_empty() {
        return false;
    }
    match providers {
        None => true, // any federated provider
        Some(allowed) => identities.iter().any(|id| {
            id.provider_name
                .as_deref()
                .is_some_and(|p| allowed.iter().any(|a| a.eq_ignore_ascii_case(p)))
        }),
    }
}

/// Comma-joined `providerName`s of a token's federated identities, for logging.
fn social_provider_names(identities: &[Identity]) -> String {
    identities
        .iter()
        .map(|id| id.provider_name.as_deref().unwrap_or("?"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Fully validate a Cognito id_token, returning the lowercased verified email.
///
/// Enforces all of: `alg == RS256`, a known `kid`, the signature, `exp` (required,
/// 60 s leeway), `iss`, `aud` against [`Config::audiences`], `token_use == "id"`, and a
/// truthy `email_verified`. The single sanctioned exception to the last one is
/// [`unverified_social_ok`].
fn validate_id_token(token: &str, state: &State) -> Result<String, String> {
    let header = decode_header(token).map_err(|e| format!("bad token header: {e}"))?;
    if header.alg != Algorithm::RS256 {
        return Err(format!("unexpected alg {:?}", header.alg));
    }
    let kid = header.kid.ok_or("token has no kid")?;
    let key = decoding_key(state, &kid).ok_or("unknown signing key (kid)")?;

    let mut v = Validation::new(Algorithm::RS256);
    let aud: Vec<&str> = state.cfg.audiences.iter().map(String::as_str).collect();
    v.set_audience(&aud);
    v.set_issuer(&[&state.cfg.issuer]);
    v.set_required_spec_claims(&["exp", "aud", "iss"]);
    v.validate_exp = true;
    v.leeway = 60;

    let data = decode::<Claims>(token, &key, &v).map_err(|e| format!("token invalid: {e}"))?;
    let c = data.claims;

    if c.token_use.as_deref() != Some("id") {
        return Err("token_use is not 'id'".into());
    }
    let email = c.email.ok_or("token has no email")?.to_ascii_lowercase();
    if !email_verified_true(&c.email_verified) {
        // Strict by default. The only exception is a social login whose email
        // Cognito couldn't verify itself — and only when explicitly enabled.
        if !unverified_social_ok(
            state.cfg.allow_unverified_social,
            &state.cfg.social_providers,
            &c.identities,
        ) {
            return Err("email not verified".into());
        }
        eprintln!(
            "[bb-auth] accepting unverified email via social login [{}]: {email}",
            social_provider_names(&c.identities)
        );
    }
    Ok(email)
}

// ---------------------------------------------------------------------------
// Session cookie (HMAC-signed) — wire format on COOKIE_VERSION{,_LEGACY}
// ---------------------------------------------------------------------------

/// HMAC-SHA256 of `msg` under `key`, base64url without padding.
fn sign(key: &[u8], msg: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Constant-time HMAC check of one candidate key against a base64url signature.
/// Decode/key-length failures return `false` so callers treat a malformed cookie
/// uniformly as "doesn't verify".
fn sig_matches(key: &[u8], msg: &str, sig_b64: &str) -> bool {
    let expected = match URL_SAFE_NO_PAD.decode(sig_b64) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(msg.as_bytes());
    mac.verify_slice(&expected).is_ok() // constant-time
}

/// Common cookie tail: enforce expiry and decode + lower-case the email payload.
fn finish_session(exp: u64, eb: &str) -> Option<String> {
    if exp <= now() {
        return None;
    }
    let email = String::from_utf8(URL_SAFE_NO_PAD.decode(eb).ok()?).ok()?;
    Some(email.to_ascii_lowercase())
}

/// Mint a session cookie for `email`, valid for `ttl` seconds, signed with the active
/// key in the [`COOKIE_VERSION`] format.
fn make_session(email: &str, ttl: u64, keys: &HmacKeys) -> String {
    let exp = now() + ttl;
    let eb = URL_SAFE_NO_PAD.encode(email.as_bytes());
    let msg = format!("{COOKIE_VERSION}.{}.{exp}.{eb}", keys.active_id);
    let sig = sign(keys.active(), &msg);
    format!("{msg}.{sig}")
}

/// Verify a session cookie — version, key id, signature (constant-time) and expiry —
/// returning the lowercased email it carries. Accepts both [`COOKIE_VERSION`] and
/// [`COOKIE_VERSION_LEGACY`]. `None` on anything that does not verify.
fn verify_session(val: &str, keys: &HmacKeys) -> Option<String> {
    let parts: Vec<&str> = val.splitn(5, '.').collect();
    match parts.as_slice() {
        [v, keyid, exp_s, eb, sig] if *v == COOKIE_VERSION => {
            let key = keys.by_id.get(*keyid)?;
            let exp: u64 = exp_s.parse().ok()?;
            let msg = format!("{v}.{keyid}.{exp_s}.{eb}");
            if !sig_matches(key, &msg, sig) {
                return None;
            }
            finish_session(exp, eb)
        }
        [v, exp_s, eb, sig] if *v == COOKIE_VERSION_LEGACY => {
            let exp: u64 = exp_s.parse().ok()?;
            let msg = format!("{v}.{exp_s}.{eb}");
            // Legacy: try every accepted key (all are ours; an attacker has none,
            // so the timing leak about which key matched is harmless).
            if !keys.by_id.values().any(|k| sig_matches(k, &msg, sig)) {
                return None;
            }
            finish_session(exp, eb)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// First request header matching `name`, compared case-insensitively.
fn header_value<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    // HeaderField::equiv requires a &'static str, so compare case-insensitively
    // against the field's string form (header names are ASCII).
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

/// Extract the token from an `Authorization` header value of the form
/// `Bearer <token>`. The scheme is matched case-insensitively; the token is
/// trimmed. Returns `None` if the value is not a non-empty bearer credential.
fn parse_bearer(auth: &str) -> Option<&str> {
    let (scheme, token) = auth.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

/// Pull one cookie's value out of a `Cookie:` header.
fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(name) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

/// Build a response header. Panics only on a caller-side bug (non-ASCII name/value);
/// every call site passes constants or already-sanitised values.
fn h(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("valid header")
}

/// Render a `Set-Cookie` value. `max_age = 0` expires the cookie (logout). Always
/// `HttpOnly` + `Secure` + `SameSite=Lax`, so JS cannot read it and it still rides
/// top-level navigations back to the service.
fn build_cookie(cfg: &Config, value: &str, max_age: i64) -> String {
    let mut c = format!(
        "{}={}; Max-Age={}; Path=/; HttpOnly; Secure; SameSite=Lax",
        cfg.cookie_name, value, max_age
    );
    if let Some(d) = &cfg.cookie_domain {
        c.push_str(&format!("; Domain={d}"));
    }
    c
}

/// Validate the post-login redirect target against open-redirect and
/// response-splitting abuse.
///
/// There is no canonical service base URL — one gate fronts several hosts, and which
/// one is in play is decided by the caller. So `caller_origin` (the `scheme://host` of
/// the `/auth/session` request, learned from `BB_AUTH_ORIGINAL_URL_HEADER`) is what a
/// relative `rd` resolves against, and `hosts` (`BB_AUTH_AUTHORIZED_HOSTS`) is the sole
/// authority on where a redirect may land.
///
/// Every candidate — absolute, relative, or the no-`rd` default — goes through the
/// same `rd_url_allowed` gate, so even a spoofed caller origin cannot produce an
/// off-domain redirect. Anything rejected falls back to `login_url`. A leading `//evil`
/// or `/\evil` is not treated as a path (browsers normalise `/\` to `//`, i.e. an
/// off-host redirect). Any control byte, including CR/LF, is rejected outright, so
/// attacker-supplied bytes can never reach the `Location` header (no response
/// splitting).
fn safe_rd(
    rd: Option<&str>,
    caller_origin: Option<&str>,
    hosts: &[UrlPattern],
    login_url: &str,
) -> String {
    let fallback = || login_url.to_string();
    let candidate = match rd {
        // No `rd`: land on the root of whichever host the login happened on.
        None | Some("") => match caller_origin {
            Some(o) => format!("{o}/"),
            None => return fallback(),
        },
        Some(r) => {
            if r.bytes().any(|b| b < 0x20 || b == 0x7f) {
                return fallback();
            }
            if r.starts_with('/') && !r.starts_with("//") && !r.starts_with("/\\") {
                // Same-host absolute path — resolve against the caller.
                match caller_origin {
                    Some(o) => format!("{o}{r}"),
                    None => return fallback(),
                }
            } else {
                r.to_string()
            }
        }
    };
    if rd_url_allowed(&candidate, hosts) {
        candidate
    } else {
        fallback()
    }
}

/// True iff `url` is an absolute `https://` URL whose host matches one of `hosts`.
/// Rejects any other scheme, userinfo (`@`) and backslashes. A `:port` suffix is
/// tolerated on the candidate and stripped before matching (patterns are bare hosts).
///
/// Matching is the same glob as `authorized_urls`, so `*.badbat75.com` accepts
/// `mcp.badbat75.com` but neither `evilbadbat75.com` nor `badbat75.com.evil.com` —
/// the literal dot in the pattern is what rules those out. It does *not* accept the
/// bare apex `badbat75.com`; list it explicitly if you want it.
fn rd_url_allowed(url: &str, hosts: &[UrlPattern]) -> bool {
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
    hosts.iter().any(|p| glob_match(&p.pat, host.as_bytes()))
}

/// Respond with a bare status code and no body — what `auth_request` consumes.
fn respond_empty(req: Request, status: u16) {
    let _ = req.respond(Response::empty(StatusCode(status)));
}

/// Respond `302 Location: …`, optionally setting or clearing the session cookie.
/// `location` must already have passed [`safe_rd`].
fn respond_redirect(req: Request, location: &str, set_cookie: Option<&str>) {
    let mut resp = Response::empty(StatusCode(302)).with_header(h("Location", location));
    if let Some(sc) = set_cookie {
        resp = resp.with_header(h("Set-Cookie", sc));
    }
    let _ = req.respond(resp);
}

/// Respond with the minimal styled error page the browser sees on a failed
/// `/auth/session`. Every interpolated value is escaped by [`html_escape`].
fn respond_html(req: Request, status: u16, title: &str, msg: &str, login_url: &str) {
    // Escape everything we interpolate: today the inputs are constants / a
    // trusted env value, but there is no structural guarantee a future caller
    // won't pass request data, so never emit raw bytes into the page.
    let title = html_escape(title);
    let msg = html_escape(msg);
    let login_url = html_escape(login_url);
    let body = format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
<title>{title}</title>\
<style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#16161b;color:#e8e8ee;\
display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center;text-align:center}}\
.c{{max-width:420px;padding:32px}}h1{{font-size:1.3rem}}a{{color:#5b78ff}}p{{color:#9a9aa8}}</style>\
<div class=c><h1>{title}</h1><p>{msg}</p><p><a href=\"{login_url}\">&larr; Torna all'accesso</a></p></div>"
    );
    let resp = Response::from_string(body)
        .with_status_code(StatusCode(status))
        .with_header(h("Content-Type", "text/html; charset=utf-8"));
    let _ = req.respond(resp);
}

/// Escape the HTML-significant characters for safe interpolation into a page /
/// attribute. Named-entity form so the output is safe in both text and
/// double-quoted attribute contexts.
fn html_escape(s: &str) -> String {
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// The original request URL nginx is guarding, from the configured header, with any
/// query/fragment stripped and the authority lowercased. `None` if the header is
/// absent (which a restricted scope treats as a denial).
fn original_url(req: &Request, cfg: &Config) -> Option<String> {
    header_value(req, &cfg.original_url_header)
        .map(|u| lower_authority(u.split(['?', '#']).next().unwrap_or("")))
}

/// Resolve a `bbk_` API-key bearer against the users table: it must be known, not
/// expired, and in URL scope. Logs the reason on rejection.
fn bearer_apikey_ok(state: &State, token: &str, url: Option<&str>) -> bool {
    let users = state.users.read().unwrap();
    let rec = match users.by_key_hash.get(&sha256_hex(token)) {
        Some(r) => r,
        None => {
            eprintln!("[bb-auth] api key rejected: unknown");
            return false;
        }
    };
    if rec.expires.is_some_and(|e| now() >= e) {
        eprintln!(
            "[bb-auth] api key rejected: expired [{} {}]",
            rec.email, rec.key_id
        );
        return false;
    }
    if !rec.scope.allows(url) {
        eprintln!(
            "[bb-auth] api key denied: url {} out of scope [{} {}]",
            url.unwrap_or("<none>"),
            rec.email,
            rec.key_id
        );
        return false;
    }
    true
}

/// A user (email) is authorized if present in the table and the request URL is in
/// their scope. Shared by the id_token-bearer and cookie paths.
fn user_scope_ok(state: &State, email: &str, url: Option<&str>) -> bool {
    let users = state.users.read().unwrap();
    match users.by_email.get(email) {
        Some(rec) if rec.scope.allows(url) => true,
        Some(_) => {
            eprintln!(
                "[bb-auth] denied: url {} out of scope for {email}",
                url.unwrap_or("<none>")
            );
            false
        }
        None => {
            eprintln!("[bb-auth] denied: {email} not in users table");
            false
        }
    }
}

/// `GET /auth/validate` — the nginx `auth_request` endpoint. 204 if any credential
/// authorizes this request, 401 otherwise. Never issues a cookie.
///
/// Credentials are tried in the order documented on the crate: `bbk_` API key, raw
/// id_token, then the session cookie. Each must resolve to a user in the table *and*
/// put the request URL inside that credential's [`UrlScope`].
fn handle_validate(req: Request, state: &State) {
    let cfg = &state.cfg;
    // Original request URL (for per-user / per-key URL scoping), captured now as an
    // owned value so the request can be consumed when we respond.
    let url = original_url(&req, cfg);

    // Bearer path: programmatic clients (e.g. MCP) present `Authorization: Bearer
    // <cred>`. A `bbk_` credential is a static API key resolved against the users
    // table; anything else is a raw Cognito id_token validated exactly like
    // /auth/session, then matched to a user. Either way the request URL must be in
    // scope. A failed bearer falls through to the cookie check so a stray
    // Authorization header never blocks an otherwise-valid cookie.
    if let Some(token) = header_value(&req, "Authorization").and_then(parse_bearer) {
        let granted = if token.starts_with(API_KEY_PREFIX) {
            bearer_apikey_ok(state, token, url.as_deref())
        } else {
            match validate_id_token(token, state) {
                Ok(email) => user_scope_ok(state, &email, url.as_deref()),
                Err(e) => {
                    eprintln!("[bb-auth] bearer rejected: {e}");
                    false
                }
            }
        };
        if granted {
            respond_empty(req, 204);
            return;
        }
    }

    let ok = header_value(&req, "Cookie")
        .and_then(|c| cookie_value(c, &cfg.cookie_name).map(str::to_string))
        .and_then(|v| verify_session(&v, &cfg.hmac_keys))
        .map(|email| user_scope_ok(state, &email, url.as_deref()))
        .unwrap_or(false);
    respond_empty(req, if ok { 204 } else { 401 });
}

/// `POST /auth/session` — exchange a browser-obtained `id_token` for a session cookie,
/// then `302` to `rd`.
///
/// 400 on a missing token, 401 on an invalid one, 403 when the verified email is not in
/// the users table. The redirect target is always laundered through [`safe_rd`].
fn handle_session(mut req: Request, state: &State) {
    let cfg = &state.cfg;

    let mut buf = Vec::new();
    if req
        .as_reader()
        .take(MAX_BODY)
        .read_to_end(&mut buf)
        .is_err()
    {
        respond_html(req, 400, "Errore", "Richiesta non valida.", &cfg.login_url);
        return;
    }
    let form: HashMap<String, String> = form_urlencoded::parse(&buf).into_owned().collect();

    let id_token = match form.get("id_token") {
        Some(t) if !t.is_empty() => t,
        _ => {
            respond_html(req, 400, "Errore", "Token mancante.", &cfg.login_url);
            return;
        }
    };

    let email = match validate_id_token(id_token, state) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[bb-auth] session rejected: {e}");
            respond_html(
                req,
                401,
                "Accesso non riuscito",
                "Il token di accesso non è valido o è scaduto. Riprova.",
                &cfg.login_url,
            );
            return;
        }
    };

    if !state.users.read().unwrap().by_email.contains_key(&email) {
        eprintln!("[bb-auth] session denied: {email} not in users table");
        respond_html(
            req,
            403,
            "Accesso non autorizzato",
            "Questo indirizzo email non è abilitato all'accesso.",
            &cfg.login_url,
        );
        return;
    }

    // Which host is this login happening on? nginx tells us, the same way it does on
    // /auth/validate. A relative `rd` resolves against it; without it we can only fall
    // back to the login page.
    let caller_url = original_url(&req, cfg);
    let caller_origin = caller_url.as_deref().and_then(origin_of);
    let rd = safe_rd(
        form.get("rd").map(String::as_str),
        caller_origin.as_deref(),
        &cfg.authorized_hosts,
        &cfg.login_url,
    );
    let cookie = build_cookie(
        cfg,
        &make_session(&email, cfg.session_ttl, &cfg.hmac_keys),
        cfg.session_ttl as i64,
    );
    eprintln!("[bb-auth] session granted: {email} -> {rd}");
    respond_redirect(req, &rd, Some(&cookie));
}

/// `GET /auth/logout` — expire the session cookie and `302` to the login page.
///
/// Clears the bb-auth cookie only; the Cognito refresh token the login page may hold is
/// out of scope. A cross-site navigation is ignored (CSRF logout).
fn handle_logout(req: Request, state: &State) {
    let cfg = &state.cfg;
    // Block cross-site CSRF logout: a navigation triggered from another origin
    // carries `Sec-Fetch-Site: cross-site`. Only clear the cookie on a direct
    // or same-site navigation. If the header is absent (older browsers) we
    // still clear, so legitimate logout never breaks — worst case on a legacy
    // browser is a forced re-login, which is low-impact.
    let cross_site = header_value(&req, "Sec-Fetch-Site")
        .map(|v| v.eq_ignore_ascii_case("cross-site"))
        .unwrap_or(false);
    let cookie = if cross_site {
        None
    } else {
        Some(build_cookie(cfg, "", 0))
    };
    respond_redirect(req, &cfg.login_url, cookie.as_deref());
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

/// `bb-auth --check-users <file>`: parse a users file with the real parser and exit
/// 0 (with a summary) or 1 (with the error). Reads no env and touches no network, so
/// a deploy can validate the file that is *about* to go live — a rejected scope is a
/// fatal startup error, and with `Restart=on-failure` that would be a boot loop.
fn check_users(path: &str) -> ! {
    match read_users(path) {
        Ok(u) => {
            println!(
                "[bb-auth] {path}: OK — {} users, {} api keys",
                u.by_email.len(),
                u.by_key_hash.len()
            );
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[bb-auth] {path}: INVALID — {e}");
            std::process::exit(1);
        }
    }
}

/// Parse argv (only `--check-users`), build the config, load the users table, prime the
/// JWKS, then serve forever on a fixed pool of blocking worker threads.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--check-users") => match args.get(1) {
            Some(p) => check_users(p),
            None => {
                eprintln!("usage: bb-auth --check-users <users.json>");
                std::process::exit(2);
            }
        },
        Some(other) => {
            eprintln!("[bb-auth] unknown argument '{other}' (only --check-users is accepted)");
            std::process::exit(2);
        }
        None => {}
    }

    let cfg = Config::from_env();
    let users_path = env_req("BB_AUTH_USERS_FILE");
    let users = load_users(&users_path);

    let initial = fetch_jwks(&cfg.issuer).unwrap_or_else(|e| {
        eprintln!("[bb-auth] FATAL: initial JWKS fetch failed: {e}");
        std::process::exit(1);
    });

    let listen = cfg.listen.clone();
    let workers = cfg.workers;
    let user_n = users.by_email.len();
    let key_n = users.by_key_hash.len();

    let state = Arc::new(State {
        cfg,
        users: RwLock::new(users),
        #[cfg(unix)]
        users_path,
        jwks: RwLock::new(JwksCache {
            keys: initial,
            last_refresh: Instant::now(),
        }),
        jwks_refresh: Mutex::new(()),
    });

    // Hot-reload the users table on SIGHUP (systemctl reload bb-auth). Failures
    // keep the current table; no one is logged out by a transient disk error.
    // POSIX-only; no-op on non-unix hosts.
    spawn_users_reload_handler(&state);

    let server = Arc::new(Server::http(&listen).unwrap_or_else(|e| {
        eprintln!("[bb-auth] FATAL: cannot bind {listen}: {e}");
        std::process::exit(1);
    }));

    eprintln!(
        "[bb-auth] listening on {listen} | issuer={} | aud={} | users={user_n} | api_keys={key_n} | workers={workers}",
        state.cfg.issuer,
        state.cfg.audiences.join(",")
    );
    if state.cfg.allow_unverified_social {
        let scope = match &state.cfg.social_providers {
            Some(p) => p.join(","),
            None => "any provider".to_string(),
        };
        eprintln!(
            "[bb-auth] WARNING: accepting unverified emails for social logins [{scope}] (BB_AUTH_ALLOW_UNVERIFIED_SOCIAL)"
        );
    }

    let mut handles = Vec::new();
    for _ in 0..workers {
        let server = Arc::clone(&server);
        let state = Arc::clone(&state);
        handles.push(std::thread::spawn(move || loop {
            let req = match server.recv() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[bb-auth] recv error: {e}");
                    continue;
                }
            };
            let method = req.method().as_str().to_string();
            let path = req.url().split('?').next().unwrap_or("").to_string();
            match (method.as_str(), path.as_str()) {
                ("GET", "/auth/validate") => handle_validate(req, &state),
                ("POST", "/auth/session") => handle_session(req, &state),
                ("GET", "/auth/logout") => handle_logout(req, &state),
                ("GET", "/auth/healthz") => {
                    let _ = req.respond(Response::from_string("ok"));
                }
                _ => respond_empty(req, 404),
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_one() -> HmacKeys {
        let mut by_id = HashMap::new();
        by_id.insert("k1".to_string(), vec![0x42u8; 32]);
        HmacKeys {
            by_id,
            active_id: "k1".to_string(),
        }
    }
    fn keys_two() -> HmacKeys {
        let mut by_id = HashMap::new();
        by_id.insert("k1".to_string(), vec![0x11u8; 32]);
        by_id.insert("k2".to_string(), vec![0x22u8; 32]);
        HmacKeys {
            by_id,
            active_id: "k1".to_string(),
        }
    }

    #[test]
    fn session_roundtrip_bb2() {
        let k = keys_one();
        let c = make_session("Foo@Bar.com", 3600, &k);
        assert!(c.starts_with("bb2.k1."));
        assert_eq!(verify_session(&c, &k), Some("foo@bar.com".to_string()));
    }

    #[test]
    fn session_tampered_sig_rejected() {
        let k = keys_one();
        let mut c = make_session("a@b.com", 3600, &k);
        let last = c.len() - 1;
        let alt = if c.as_bytes()[last] == b'A' { 'B' } else { 'A' };
        c.replace_range(last.., &alt.to_string());
        assert_eq!(verify_session(&c, &k), None);
    }

    #[test]
    fn session_expired_rejected() {
        let k = keys_one();
        let c = make_session("a@b.com", 0, &k); // exp == now
        assert_eq!(verify_session(&c, &k), None);
    }

    #[test]
    fn session_unknown_keyid_rejected() {
        let k = keys_one(); // only k1
        let exp = now() + 3600;
        let eb = URL_SAFE_NO_PAD.encode(b"a@b.com");
        let msg = format!("bb2.k9.{exp}.{eb}");
        let sig = sign(&k.by_id["k1"], &msg);
        let c = format!("{msg}.{sig}");
        assert_eq!(verify_session(&c, &k), None);
    }

    #[test]
    fn session_routes_to_accepted_key() {
        let k = keys_two(); // k1 active, k2 accepted
        let exp = now() + 3600;
        let eb = URL_SAFE_NO_PAD.encode(b"x@y.com");
        let msg = format!("bb2.k2.{exp}.{eb}");
        let sig = sign(&k.by_id["k2"], &msg);
        let c = format!("{msg}.{sig}");
        assert_eq!(verify_session(&c, &k), Some("x@y.com".to_string()));
    }

    #[test]
    fn legacy_bb1_verifies_against_active_key() {
        let k = keys_one();
        let exp = now() + 3600;
        let eb = URL_SAFE_NO_PAD.encode(b"old@a.com");
        let msg = format!("bb1.{exp}.{eb}");
        let sig = sign(&k.by_id["k1"], &msg);
        let c = format!("{msg}.{sig}");
        assert_eq!(verify_session(&c, &k), Some("old@a.com".to_string()));
    }

    #[test]
    fn legacy_bb1_rejected_when_no_key_matches() {
        let k = keys_one();
        let exp = now() + 3600;
        let eb = URL_SAFE_NO_PAD.encode(b"old@a.com");
        let msg = format!("bb1.{exp}.{eb}");
        let foreign = vec![0x99u8; 32];
        let sig = sign(&foreign, &msg);
        let c = format!("{msg}.{sig}");
        assert_eq!(verify_session(&c, &k), None);
    }

    #[test]
    fn malformed_cookies_rejected() {
        let k = keys_one();
        for bad in [
            "",
            "bb1",
            "bb1.x.y",
            "bb2.k1.x.y",
            "zzz.a.b.c",
            "bb1.notanum.aaa.sig",
            "bb2.k1.99999.!!!.AAAA",
        ] {
            assert_eq!(verify_session(bad, &k), None, "should reject: {bad:?}");
        }
    }

    #[test]
    fn email_verified_truthy_variants() {
        assert!(email_verified_true(&serde_json::json!(true)));
        assert!(email_verified_true(&serde_json::json!("true")));
        assert!(email_verified_true(&serde_json::json!("TRUE")));
        assert!(!email_verified_true(&serde_json::json!(false)));
        assert!(!email_verified_true(&serde_json::json!("false")));
        assert!(!email_verified_true(&serde_json::json!("1")));
        assert!(!email_verified_true(&serde_json::json!(null)));
    }

    fn idents(names: &[&str]) -> Vec<Identity> {
        names
            .iter()
            .map(|n| Identity {
                provider_name: Some((*n).to_string()),
            })
            .collect()
    }

    #[test]
    fn unverified_social_off_by_default() {
        // Feature disabled: never relax, even for a clear social identity.
        assert!(!unverified_social_ok(false, &None, &idents(&["Google"])));
    }

    #[test]
    fn unverified_social_native_user_never_relaxed() {
        // No `identities` claim => native Cognito user => always strict.
        assert!(!unverified_social_ok(true, &None, &[]));
    }

    #[test]
    fn unverified_social_any_provider_when_unrestricted() {
        assert!(unverified_social_ok(true, &None, &idents(&["Google"])));
        assert!(unverified_social_ok(true, &None, &idents(&["Facebook"])));
    }

    #[test]
    fn unverified_social_provider_allowlist_enforced() {
        let allowed = Some(vec!["Google".to_string(), "SignInWithApple".to_string()]);
        assert!(unverified_social_ok(true, &allowed, &idents(&["Google"])));
        // Case-insensitive match against providerName.
        assert!(unverified_social_ok(true, &allowed, &idents(&["google"])));
        assert!(unverified_social_ok(
            true,
            &allowed,
            &idents(&["SignInWithApple"])
        ));
        // A provider not on the list is rejected.
        assert!(!unverified_social_ok(
            true,
            &allowed,
            &idents(&["Facebook"])
        ));
        // Any matching entry in a multi-identity token suffices.
        assert!(unverified_social_ok(
            true,
            &allowed,
            &idents(&["Facebook", "Google"])
        ));
    }

    #[test]
    fn social_provider_names_joins() {
        assert_eq!(
            social_provider_names(&idents(&["Google", "Facebook"])),
            "Google,Facebook"
        );
        assert_eq!(
            social_provider_names(&[Identity {
                provider_name: None
            }]),
            "?"
        );
    }

    #[test]
    fn claims_parse_identities_present_and_absent() {
        // Federated token carries `identities`; native token omits it.
        let social: Claims = serde_json::from_value(serde_json::json!({
            "email": "u@x.com",
            "email_verified": false,
            "token_use": "id",
            "identities": [{"providerName": "Google", "userId": "1", "primary": "true"}]
        }))
        .unwrap();
        assert_eq!(social.identities.len(), 1);
        assert_eq!(
            social.identities[0].provider_name.as_deref(),
            Some("Google")
        );

        let native: Claims = serde_json::from_value(serde_json::json!({
            "email": "u@x.com",
            "email_verified": true,
            "token_use": "id"
        }))
        .unwrap();
        assert!(native.identities.is_empty());
    }

    #[test]
    fn cookie_value_parses_named() {
        let h = "a=1; bb_session=bb2.k1.1.aaa.bbb; c=2";
        assert_eq!(cookie_value(h, "bb_session"), Some("bb2.k1.1.aaa.bbb"));
        assert_eq!(cookie_value("bb_session_extra=x", "bb_session"), None);
        assert_eq!(cookie_value("", "bb_session"), None);
    }

    #[test]
    fn parse_bearer_extracts_token() {
        assert_eq!(parse_bearer("Bearer abc.def.ghi"), Some("abc.def.ghi"));
        assert_eq!(parse_bearer("bearer abc"), Some("abc")); // scheme case-insensitive
        assert_eq!(parse_bearer("BEARER   abc  "), Some("abc")); // token trimmed
        assert_eq!(parse_bearer("Basic abc"), None); // wrong scheme
        assert_eq!(parse_bearer("Bearer"), None); // no token
        assert_eq!(parse_bearer("Bearer "), None); // empty token
        assert_eq!(parse_bearer("Bearertoken"), None); // needs a space separator
        assert_eq!(parse_bearer(""), None);
    }

    #[test]
    fn sha256_hex_known_vector() {
        // canonical SHA-256("abc")
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
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
        let p = compile_pattern(pat).expect("pattern compiles");
        glob_match(&p.pat, url.as_bytes())
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
        assert!(glob_match(&p.pat, b"https://mcp.x.com/Mcp/a"));
        // the path keeps its case on both sides
        assert!(!glob_match(&p.pat, b"https://mcp.x.com/mcp/a"));
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
        assert!(!glob_match(&p.pat, url.as_bytes())); // pattern ends in 'a', input in 'b'
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

    /// Write `json` to a uniquely-named temp file so tests can run in parallel.
    fn users_tmp(name: &str, json: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("bb-auth-users-{name}.json"));
        std::fs::write(&p, json).unwrap();
        p
    }

    /// `read_users(path).unwrap_err()` without forcing `Debug` onto `Users`.
    fn users_err(path: &std::path::Path) -> String {
        match read_users(path.to_str().unwrap()) {
            Ok(_) => panic!("expected {} to be rejected", path.display()),
            Err(e) => e,
        }
    }

    #[test]
    fn read_users_parses_authorized_urls() {
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
        let u = read_users(tmp.to_str().unwrap()).unwrap();

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
    fn read_users_rejects_enabled_paths() {
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
    fn read_users_rejects_malformed_url() {
        let tmp = users_tmp(
            "badurl",
            r#"{ "users": [ { "email": "bob@x.com", "authorized_urls": ["/mcp/"] } ] }"#,
        );
        let err = users_err(&tmp);
        assert!(err.contains("bob@x.com"), "{err}");
        assert!(err.contains("<scheme>://<host>/<path>"), "{err}");
        let _ = std::fs::remove_file(&tmp);
    }

    /// The usual deployment: the apex plus every subdomain, enumerated.
    fn bb_hosts() -> Vec<UrlPattern> {
        ["badbat75.com", "*.badbat75.com"]
            .iter()
            .map(|h| compile_host_pattern(h).unwrap())
            .collect()
    }
    const LOGIN: &str = "https://login.badbat75.com/";
    const CALLER: &str = "https://search.badbat75.com";

    #[test]
    fn origin_of_extracts_scheme_and_host() {
        assert_eq!(
            origin_of("https://app.example.com/auth/session").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(
            origin_of("https://app.example.com").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(origin_of("/just/a/path"), None);
        assert_eq!(origin_of("https:///nohost"), None);
    }

    #[test]
    fn safe_rd_resolves_relative_against_the_caller() {
        let h = bb_hosts();
        // a relative rd lands on whichever host the login happened on …
        assert_eq!(
            safe_rd(Some("/preferences"), Some(CALLER), &h, LOGIN),
            "https://search.badbat75.com/preferences"
        );
        assert_eq!(
            safe_rd(Some("/q?x=1"), Some("https://mcp.badbat75.com"), &h, LOGIN),
            "https://mcp.badbat75.com/q?x=1"
        );
        // … and with no rd at all, on that host's root
        assert_eq!(
            safe_rd(None, Some(CALLER), &h, LOGIN),
            "https://search.badbat75.com/"
        );
        assert_eq!(
            safe_rd(Some(""), Some(CALLER), &h, LOGIN),
            "https://search.badbat75.com/"
        );
        // no caller origin (nginx didn't send the header) => the login page
        assert_eq!(safe_rd(Some("/preferences"), None, &h, LOGIN), LOGIN);
        assert_eq!(safe_rd(None, None, &h, LOGIN), LOGIN);
    }

    #[test]
    fn safe_rd_allows_authorized_hosts() {
        let h = bb_hosts();
        for rd in [
            "https://mcp.badbat75.com/mcp/foo",
            "https://search.badbat75.com/q?x=1",
            "https://badbat75.com/", // the apex, listed explicitly
        ] {
            assert_eq!(safe_rd(Some(rd), Some(CALLER), &h, LOGIN), rd, "rd={rd}");
        }
    }

    #[test]
    fn safe_rd_blocks_open_redirect_and_splitting() {
        let h = bb_hosts();
        let f = |rd: &str| safe_rd(Some(rd), Some(CALLER), &h, LOGIN);
        // scheme-relative + backslash variant (browsers normalise `/\` -> `//`)
        assert_eq!(f("//evil.com"), LOGIN);
        assert_eq!(f("/\\evil.com"), LOGIN);
        // response splitting via CRLF / control bytes
        assert_eq!(f("/\r\nSet-Cookie: x=1"), LOGIN);
        assert_eq!(f("/x\x00y"), LOGIN);
        assert_eq!(f("/q\x7f"), LOGIN);
        // off-host absolute URL
        assert_eq!(f("https://evil.com/"), LOGIN);
    }

    #[test]
    fn safe_rd_rejects_lookalikes_and_tricks() {
        let h = bb_hosts();
        let f = |rd: &str| safe_rd(Some(rd), Some(CALLER), &h, LOGIN);
        assert_eq!(f("https://evilbadbat75.com/"), LOGIN); // suffix without the dot
        assert_eq!(f("https://badbat75.com.evil.com/"), LOGIN); // base as a left label
        assert_eq!(f("https://mcp.badbat75.com@evil.com/"), LOGIN); // userinfo: real host is evil.com
        assert_eq!(f("https://mcp.badbat75.com\\@evil.com/"), LOGIN); // backslash in authority
        assert_eq!(f("http://mcp.badbat75.com/"), LOGIN); // non-https
        assert_eq!(f("//mcp.badbat75.com/"), LOGIN); // scheme-relative

        // A spoofed caller origin cannot smuggle a redirect either: the resolved
        // candidate goes through the same host gate.
        assert_eq!(
            safe_rd(Some("/x"), Some("https://evil.com"), &h, LOGIN),
            LOGIN
        );
    }

    #[test]
    fn rd_url_allowed_matches_host_only() {
        let h = bb_hosts();
        assert!(rd_url_allowed("https://mcp.badbat75.com/x", &h));
        assert!(rd_url_allowed("https://badbat75.com", &h));
        assert!(rd_url_allowed("https://a.b.badbat75.com/x?y=1", &h)); // `*` crosses dots
        assert!(rd_url_allowed("https://mcp.badbat75.com:8443/x", &h)); // port stripped
        assert!(rd_url_allowed("https://MCP.BadBat75.com/x", &h)); // case-insensitive
                                                                   // path/query containing the base must NOT count
        assert!(!rd_url_allowed("https://evil.com/.badbat75.com", &h));
        assert!(!rd_url_allowed("https://evil.com/?x=badbat75.com", &h));
        assert!(!rd_url_allowed("http://mcp.badbat75.com/", &h));
        assert!(!rd_url_allowed("https://badbat75.com.evil.com/", &h));

        // The apex is NOT implied by the wildcard — it has to be listed.
        let only_sub = vec![compile_host_pattern("*.badbat75.com").unwrap()];
        assert!(rd_url_allowed("https://mcp.badbat75.com/", &only_sub));
        assert!(!rd_url_allowed("https://badbat75.com/", &only_sub));
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
        assert_eq!(
            compile_host_pattern("X.COM").unwrap().pat,
            b"x.com".to_vec()
        );
    }

    #[test]
    fn html_escape_escapes_special_chars() {
        assert_eq!(html_escape("plain"), "plain");
        assert_eq!(html_escape("a<b>&c\"'d"), "a&lt;b&gt;&amp;c&quot;&#39;d");
        // attribute-context safety: a crafted login url can't break out
        assert_eq!(
            html_escape("https://x/\" onmouseover=\"alert(1)"),
            "https://x/&quot; onmouseover=&quot;alert(1)"
        );
    }
}
