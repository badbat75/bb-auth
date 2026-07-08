//! bb-auth — minimal, service-agnostic auth gate.
//!
//! It fronts any web service via nginx `auth_request` and is wired per-deployment
//! entirely through the BB_AUTH_* env vars. Unlike authorization-code OIDC proxies
//! (which drive the login themselves and cannot accept client-obtained tokens),
//! bb-auth accepts a Cognito **id_token** that a browser-side login page obtained
//! (USER_AUTH flow on the public client), validates it, and turns it into an
//! HMAC-signed session cookie. This is what makes "auto-login right after
//! registration, no second OTP" possible.
//!
//! Endpoints (all under /auth/, fronted by nginx on the protected service host):
//!   GET  /auth/validate  — internal; nginx `auth_request`. 204 if the session
//!                          cookie is valid AND its email is on the allowlist, else 401.
//!                          Also accepts `Authorization: Bearer <cred>` for
//!                          programmatic clients (e.g. MCP clients) that can't run
//!                          the browser cookie flow: `<cred>` is either a raw Cognito
//!                          id_token (validated exactly like /auth/session), or a
//!                          static `bbk_` API key from the JSON users table (tied to a
//!                          user, with its own expiry and allowed-path scope).
//!                          Every credential is additionally checked against the
//!                          requesting user's / key's allowed path prefixes.
//!   POST /auth/session   — public; body `id_token=...&rd=...`. Validates the
//!                          id_token fully, sets the session cookie, 302 → rd.
//!   GET  /auth/logout    — public; clears the cookie, 302 → login page.
//!   GET  /auth/healthz   — 200 "ok".
//!
//! Security model: a valid Cognito-signed id_token is unforgeable, so possession
//! of one for an allowlisted email is the credential. The allowlist is the real
//! access gate (Cognito self-signup is open) and is re-checked on every /validate,
//! so removing an email + SIGHUP (or restart) denies even existing cookies.

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

const MAX_BODY: u64 = 64 * 1024; // id_tokens are ~1-3 KB; cap generously.
const COOKIE_VERSION: &str = "bb2";
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
    fn active(&self) -> &[u8] {
        self.by_id
            .get(&self.active_id)
            .expect("active HMAC key present")
    }
}

struct Config {
    listen: String,
    hmac_keys: HmacKeys,
    issuer: String,
    // Accepted token audiences (Cognito app client ids). Always contains
    // `BB_AUTH_CLIENT_ID`; `BB_AUTH_AUDIENCES` appends extras (e.g. a social-login
    // client). A token is accepted if its `aud` matches any entry. [0] is the
    // primary client_id.
    audiences: Vec<String>,
    // Relax the `email_verified` requirement, but ONLY for federated (social)
    // logins — never for native Cognito users. Cognito often can't verify the
    // email of a social sign-up (Google/Apple/etc.), so it stamps
    // `email_verified=false` even though the IdP itself asserted the address.
    // Off by default (strict). See `unverified_social_ok`.
    allow_unverified_social: bool,
    // Optional provider allowlist for the relaxation above (matched
    // case-insensitively against the token's `identities[].providerName`).
    // `None` = any federated provider; `Some([..])` = only these. Restrict this
    // to IdPs that actually verify the email (e.g. Google, SignInWithApple).
    social_providers: Option<Vec<String>>,
    cookie_name: String,
    cookie_domain: Option<String>,
    session_ttl: u64,
    search_url: String, // canonical service base (BB_AUTH_SEARCH_URL), e.g. https://app.example.com/
    // Optional parent domain (no leading dot, e.g. "example.com") enabling cross-
    // service SSO: an absolute https `rd` whose host is this domain or a subdomain
    // of it is accepted by `safe_rd`, so one login can redirect back to any sibling
    // service behind the gate. `None` (unset) = only `search_url` + same-host paths.
    // Pair with BB_AUTH_COOKIE_DOMAIN=.<domain> so the session cookie is shared.
    rd_base_domain: Option<String>,
    login_url: String, // login page (BB_AUTH_LOGIN_URL), e.g. https://login.example.com/
    // Request header carrying the original request URI on the nginx `auth_request`
    // subrequest (default `X-Original-URI`), used for per-user/per-key path scoping.
    // nginx must set it: `proxy_set_header X-Original-URI $uri;` (normalised path).
    original_uri_header: String,
    workers: usize,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

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
        let mut search_url = env_req("BB_AUTH_SEARCH_URL");
        if !search_url.ends_with('/') {
            search_url.push('/');
        }
        // Cross-service SSO redirect scope. Accept ".example.com" or "example.com";
        // normalise to a bare, lowercased "example.com". Empty => None.
        let rd_base_domain = match env_or("BB_AUTH_RD_BASE_DOMAIN", "")
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
        {
            s if s.is_empty() => None,
            s => Some(s),
        };

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
            search_url,
            rd_base_domain,
            login_url: env_req("BB_AUTH_LOGIN_URL"),
            original_uri_header: env_or("BB_AUTH_ORIGINAL_URI_HEADER", "X-Original-URI"),
            workers: env_or("BB_AUTH_WORKERS", "4").parse().unwrap_or(4).max(1),
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    last_refresh: Instant,
}

struct State {
    cfg: Config,
    users: RwLock<Users>, // allowlisted emails + their static API keys, indexed
    #[cfg(unix)]
    users_path: String, // needed by the SIGHUP reload path
    jwks: RwLock<JwksCache>,
    jwks_refresh: Mutex<()>, // serializes JWKS refreshers (double-checked locking)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Users table (JSON: allowlisted emails + their static API keys)
//
// One file (BB_AUTH_USERS_FILE) describes every user, each with an optional path
// scope and zero or more static `bbk_` API keys. It replaces the old flat email
// allowlist and stays the real access gate, hot-reloaded on SIGHUP:
//
//   { "users": [
//       { "email": "bob@x.com",
//         "enabled_paths": ["/mcp/"],           // user-level scope; omit/["*"] = all
//         "api_keys": [
//           { "id": "laptop", "key_hash": "<sha256 hex of the bbk_… bearer>",
//             "released": "2026-07-08", "duration": "365d",
//             "enabled_paths": ["/mcp/"] }       // omit => inherit the user scope
//         ] },
//       { "email": "alice@x.com" }               // plain user: cookie only, all paths
//   ] }
//
// Keys are indexed by the SHA-256 (hex) of the whole bearer — the raw key is
// never stored. High-entropy random keys make a plain (unsalted) hash + a
// non-constant-time map lookup safe: finding a matching row requires a SHA-256
// second preimage, so the lookup itself is the verification. `id` is a human
// label (logs / revocation), not part of the credential.
// ---------------------------------------------------------------------------

/// Allowed request-path scope for a user or key.
#[derive(Clone)]
enum PathScope {
    All,                   // no restriction (empty list or a "*" entry)
    Prefixes(Vec<String>), // request path must start with one of these
}

impl PathScope {
    /// Build a scope from a JSON `enabled_paths` list: empty (after trimming) or
    /// containing `"*"` => `All`; otherwise the non-empty prefixes.
    fn from_list(list: &[String]) -> PathScope {
        let cleaned: Vec<String> = list
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if cleaned.is_empty() || cleaned.iter().any(|p| p == "*") {
            PathScope::All
        } else {
            PathScope::Prefixes(cleaned)
        }
    }

    /// Whether `path` (the original request URI, query stripped) is in scope.
    /// A missing path (`None`) is allowed only for `All`; a restricted scope with
    /// no known path fails closed. `..` in a restricted path is rejected outright.
    fn allows(&self, path: Option<&str>) -> bool {
        match self {
            PathScope::All => true,
            PathScope::Prefixes(prefixes) => match path {
                None => false,
                Some(p) => !p.contains("..") && prefixes.iter().any(|pre| p.starts_with(pre)),
            },
        }
    }
}

/// A resolved allowlisted user (keyed elsewhere by lowercased email).
struct UserRecord {
    paths: PathScope,
}

/// A resolved API key (keyed elsewhere by the bearer's SHA-256 hex).
struct ApiKeyRecord {
    email: String,        // owning user, for logging
    key_id: String,       // label, for logging / revocation
    expires: Option<u64>, // Unix seconds; None = never
    paths: PathScope,
}

/// The two runtime indices built from the users file.
struct Users {
    by_email: HashMap<String, UserRecord>, // lowercased email -> user
    by_key_hash: HashMap<String, ApiKeyRecord>, // sha256(bearer) hex -> key
}

// --- JSON wire format (only the fields we consume; extras are ignored) ---

#[derive(Deserialize)]
struct UsersFile {
    #[serde(default)]
    users: Vec<UserSpec>,
}

#[derive(Deserialize)]
struct UserSpec {
    email: String,
    #[serde(default)]
    enabled_paths: Vec<String>,
    #[serde(default)]
    api_keys: Vec<ApiKeySpec>,
}

#[derive(Deserialize)]
struct ApiKeySpec {
    #[serde(default)]
    id: String,
    #[serde(default)]
    key_hash: String,
    #[serde(default)]
    released: String,
    #[serde(default)]
    duration: String,
    // Absent => inherit the user's scope; present => this key's own scope.
    #[serde(default)]
    enabled_paths: Option<Vec<String>>,
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

/// Parse the users JSON into the two runtime indices. Structurally-invalid JSON
/// is a hard error (so a reload keeps the old table); an individual malformed key
/// is warned about and skipped so one typo can't drop every user.
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
        let user_paths = PathScope::from_list(&u.enabled_paths);
        for k in &u.api_keys {
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
            let paths = match &k.enabled_paths {
                Some(list) => PathScope::from_list(list),
                None => user_paths.clone(),
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
                    paths,
                },
            );
        }
        by_email.insert(email, UserRecord { paths: user_paths });
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

#[derive(Deserialize)]
struct Claims {
    email: Option<String>,
    #[serde(default)]
    email_verified: serde_json::Value,
    token_use: Option<String>,
    // Present (non-empty) only for federated/social logins; absent for native
    // Cognito users. Each entry names the upstream IdP via `providerName`. This
    // is what lets the relaxation target social logins only.
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

/// Fully validate a Cognito id_token. Returns the (lowercased) verified email.
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
// Session cookie (HMAC-signed)
//
// Active (signed) format — `bb2`:
//   bb2.<keyid>.<exp>.<b64url(email)>.<b64url(HMAC_SHA256("bb2.<keyid>.<exp>.<b64url(email)>", key[keyid]))>
// The key id is stamped in so the active signing key can roll over with zero
// downtime: during rotation, accept multiple ids for verification while only the
// active one signs new cookies.
//
// Legacy verify-only format — `bb1` (kept so the bb2 rollout doesn't log anyone
// out; cookies signed before the migration still verify):
//   bb1.<exp>.<b64url(email)>.<b64url(HMAC_SHA256("bb1.<exp>.<b64url(email)>"))>
// Signed under the single old key; verified by trying every accepted key.
// ---------------------------------------------------------------------------

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

/// Mint a `bb2` session cookie for `email`, valid for `ttl` seconds, signed with
/// the active key.
fn make_session(email: &str, ttl: u64, keys: &HmacKeys) -> String {
    let exp = now() + ttl;
    let eb = URL_SAFE_NO_PAD.encode(email.as_bytes());
    let msg = format!("{COOKIE_VERSION}.{}.{exp}.{eb}", keys.active_id);
    let sig = sign(keys.active(), &msg);
    format!("{msg}.{sig}")
}

/// Verify a session cookie: version (`bb2` active, `bb1` legacy), key id,
/// signature (constant-time) and expiry. Returns the lowercased email it carries.
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

fn h(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("valid header")
}

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
/// Allowed: an absolute URL under the canonical search URL, or a same-host
/// absolute path. A leading `//evil` or `/\evil` is rejected (browsers
/// normalise a leading `/\` to `//`, i.e. an off-host redirect). Any control
/// byte, including CR/LF, causes a fall-back to the search URL, so
/// attacker-supplied bytes can never reach the `Location` header (no response
/// splitting).
fn safe_rd(rd: Option<&str>, search_url: &str, rd_base_domain: Option<&str>) -> String {
    let r = match rd {
        Some(r) if !r.is_empty() => r,
        _ => return search_url.to_string(),
    };
    if r.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return search_url.to_string();
    }
    // Absolute URL under the canonical service base — always allowed.
    if r.starts_with(search_url) {
        return r.to_string();
    }
    // Cross-service SSO: an absolute https URL whose host is (a subdomain of) the
    // configured base domain. Guarded strictly (https-only, host-suffix match,
    // no userinfo/backslash) so it can't become an open redirect.
    if let Some(base) = rd_base_domain {
        if rd_host_allowed(r, base) {
            return r.to_string();
        }
    }
    // Same-host absolute path — resolve against the canonical service base.
    if r.starts_with('/') && !r.starts_with("//") && !r.starts_with("/\\") {
        return format!("{}{}", search_url.trim_end_matches('/'), r);
    }
    search_url.to_string()
}

/// True iff `url` is an absolute `https://` URL whose host equals `base_domain`
/// or is a subdomain of it (`host == base` or `host` ends with `".<base>"`).
/// Rejects any other scheme, userinfo (`@`), backslashes, and hosts that merely
/// *contain* the base (`evilbadbat75.com`, `badbat75.com.evil.com`) — the leading
/// dot in the suffix check is what prevents those. Port suffixes are tolerated.
fn rd_host_allowed(url: &str, base_domain: &str) -> bool {
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
    let base = base_domain.to_ascii_lowercase();
    host == base || host.ends_with(&format!(".{base}"))
}

fn respond_empty(req: Request, status: u16) {
    let _ = req.respond(Response::empty(StatusCode(status)));
}

fn respond_redirect(req: Request, location: &str, set_cookie: Option<&str>) {
    let mut resp = Response::empty(StatusCode(302)).with_header(h("Location", location));
    if let Some(sc) = set_cookie {
        resp = resp.with_header(h("Set-Cookie", sc));
    }
    let _ = req.respond(resp);
}

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

/// The original request path nginx is guarding, from the configured header, with
/// any query/fragment stripped. `None` if the header is absent.
fn original_path(req: &Request, cfg: &Config) -> Option<String> {
    header_value(req, &cfg.original_uri_header)
        .map(|u| u.split(['?', '#']).next().unwrap_or("").to_string())
}

/// Resolve a `bbk_` API-key bearer against the users table: it must be known, not
/// expired, and in path scope. Logs the reason on rejection.
fn bearer_apikey_ok(state: &State, token: &str, path: Option<&str>) -> bool {
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
    if !rec.paths.allows(path) {
        eprintln!(
            "[bb-auth] api key denied: path {} out of scope [{} {}]",
            path.unwrap_or("<none>"),
            rec.email,
            rec.key_id
        );
        return false;
    }
    true
}

/// A user (email) is authorized if present in the table and the request path is in
/// their scope. Shared by the id_token-bearer and cookie paths.
fn user_path_ok(state: &State, email: &str, path: Option<&str>) -> bool {
    let users = state.users.read().unwrap();
    match users.by_email.get(email) {
        Some(rec) if rec.paths.allows(path) => true,
        Some(_) => {
            eprintln!(
                "[bb-auth] denied: path {} out of scope for {email}",
                path.unwrap_or("<none>")
            );
            false
        }
        None => {
            eprintln!("[bb-auth] denied: {email} not in users table");
            false
        }
    }
}

fn handle_validate(req: Request, state: &State) {
    let cfg = &state.cfg;
    // Original request path (for per-user / per-key path scoping), captured now as
    // an owned value so the request can be consumed when we respond.
    let path = original_path(&req, cfg);

    // Bearer path: programmatic clients (e.g. MCP) present `Authorization: Bearer
    // <cred>`. A `bbk_` credential is a static API key resolved against the users
    // table; anything else is a raw Cognito id_token validated exactly like
    // /auth/session, then matched to a user. Either way the request path must be in
    // scope. A failed bearer falls through to the cookie check so a stray
    // Authorization header never blocks an otherwise-valid cookie.
    if let Some(token) = header_value(&req, "Authorization").and_then(parse_bearer) {
        let granted = if token.starts_with(API_KEY_PREFIX) {
            bearer_apikey_ok(state, token, path.as_deref())
        } else {
            match validate_id_token(token, state) {
                Ok(email) => user_path_ok(state, &email, path.as_deref()),
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
        .map(|email| user_path_ok(state, &email, path.as_deref()))
        .unwrap_or(false);
    respond_empty(req, if ok { 204 } else { 401 });
}

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
        eprintln!("[bb-auth] session denied (not allowlisted): {email}");
        respond_html(
            req,
            403,
            "Accesso non autorizzato",
            "Questo indirizzo email non è abilitato all'accesso.",
            &cfg.login_url,
        );
        return;
    }

    let rd = safe_rd(
        form.get("rd").map(String::as_str),
        &cfg.search_url,
        cfg.rd_base_domain.as_deref(),
    );
    let cookie = build_cookie(
        cfg,
        &make_session(&email, cfg.session_ttl, &cfg.hmac_keys),
        cfg.session_ttl as i64,
    );
    eprintln!("[bb-auth] session granted: {email} -> {rd}");
    respond_redirect(req, &rd, Some(&cookie));
}

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

fn main() {
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

    #[test]
    fn path_scope_matching() {
        let all = PathScope::from_list(&[]);
        assert!(matches!(all, PathScope::All));
        assert!(matches!(
            PathScope::from_list(&["*".to_string()]),
            PathScope::All
        ));
        // All allows anything, even without a known path
        assert!(all.allows(None));
        assert!(all.allows(Some("/whatever")));

        let p = PathScope::from_list(&["/mcp/".to_string(), "/api/".to_string()]);
        assert!(p.allows(Some("/mcp/foo")));
        assert!(p.allows(Some("/api/x")));
        assert!(!p.allows(Some("/other")));
        assert!(!p.allows(None)); // restricted + missing path => fail closed
        assert!(!p.allows(Some("/mcp/../secret"))); // path traversal rejected

        // whitespace/empties are cleaned out; a "*" among prefixes means All
        assert!(matches!(
            PathScope::from_list(&["  ".to_string(), "/x".to_string(), "*".to_string()]),
            PathScope::All
        ));
    }

    #[test]
    fn read_users_parses_json() {
        let key = "bbk_secret";
        let hash = sha256_hex(key);
        let other = sha256_hex("bbk_two");
        let json = format!(
            r#"{{
              "users": [
                {{ "email": "Alice@Example.com" }},
                {{ "email": "bob@x.com", "enabled_paths": ["/mcp/"],
                   "api_keys": [
                     {{ "id": "laptop", "key_hash": "{hash}", "released": "1970-01-01",
                        "duration": "1d", "enabled_paths": ["/mcp/foo/"], "notes": "ignored" }},
                     {{ "id": "nolimit", "key_hash": "{other}", "released": "2026-01-01",
                        "duration": "never" }}
                   ] }}
              ]
            }}"#
        );
        let tmp = std::env::temp_dir().join("bb-auth-users-test.json");
        std::fs::write(&tmp, json).unwrap();
        let u = read_users(tmp.to_str().unwrap()).unwrap();

        assert!(u.by_email.contains_key("alice@example.com")); // lowercased
        assert!(u.by_email.contains_key("bob@x.com"));
        assert!(matches!(
            u.by_email["alice@example.com"].paths,
            PathScope::All
        ));
        assert_eq!(u.by_key_hash.len(), 2);

        let rec = u.by_key_hash.get(&hash).unwrap();
        assert_eq!(rec.email, "bob@x.com");
        assert_eq!(rec.key_id, "laptop");
        assert_eq!(rec.expires, Some(86_400)); // 1970-01-01 + 1d
        assert!(rec.paths.allows(Some("/mcp/foo/bar")));
        assert!(!rec.paths.allows(Some("/mcp/other"))); // key scope is narrower than user

        // key with no enabled_paths inherits the user's ["/mcp/"] scope
        let inherit = u.by_key_hash.get(&other).unwrap();
        assert_eq!(inherit.expires, None);
        assert!(inherit.paths.allows(Some("/mcp/anything")));
        assert!(!inherit.paths.allows(Some("/nope")));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn safe_rd_allows_search_url_prefix_and_paths() {
        let s = "https://app.example.com/";
        assert_eq!(
            safe_rd(Some("https://app.example.com/q?x=1"), s, None),
            "https://app.example.com/q?x=1"
        );
        assert_eq!(
            safe_rd(Some("/search?q=1"), s, None),
            "https://app.example.com/search?q=1"
        );
        assert_eq!(safe_rd(None, s, None), s);
        assert_eq!(safe_rd(Some(""), s, None), s);
    }

    #[test]
    fn safe_rd_blocks_open_redirect_and_splitting() {
        let s = "https://app.example.com/";
        // scheme-relative + backslash variant (browsers normalise `/\` -> `//`)
        assert_eq!(safe_rd(Some("//evil.com"), s, None), s);
        assert_eq!(safe_rd(Some("/\\evil.com"), s, None), s);
        // response splitting via CRLF / control bytes
        assert_eq!(safe_rd(Some("/\r\nSet-Cookie: x=1"), s, None), s);
        assert_eq!(safe_rd(Some("/x\x00y"), s, None), s);
        assert_eq!(safe_rd(Some("/q\x7f"), s, None), s);
        // off-host absolute URL
        assert_eq!(safe_rd(Some("https://evil.com/"), s, None), s);
    }

    #[test]
    fn safe_rd_sso_allows_sibling_subdomains() {
        let s = "https://search.badbat75.com/";
        let base = Some("badbat75.com");
        // sibling service under the same base domain
        assert_eq!(
            safe_rd(Some("https://mcp.badbat75.com/mcp/foo"), s, base),
            "https://mcp.badbat75.com/mcp/foo"
        );
        // the canonical service itself (also allowed via the prefix rule)
        assert_eq!(
            safe_rd(Some("https://search.badbat75.com/q?x=1"), s, base),
            "https://search.badbat75.com/q?x=1"
        );
        // the apex domain
        assert_eq!(
            safe_rd(Some("https://badbat75.com/"), s, base),
            "https://badbat75.com/"
        );
        // relative paths still resolve against the canonical base
        assert_eq!(
            safe_rd(Some("/preferences"), s, base),
            "https://search.badbat75.com/preferences"
        );
    }

    #[test]
    fn safe_rd_sso_rejects_lookalikes_and_tricks() {
        let s = "https://search.badbat75.com/";
        let base = Some("badbat75.com");
        // suffix-without-dot lookalike
        assert_eq!(safe_rd(Some("https://evilbadbat75.com/"), s, base), s);
        // base as a left label of another domain
        assert_eq!(safe_rd(Some("https://badbat75.com.evil.com/"), s, base), s);
        // userinfo trick: real host is evil.com
        assert_eq!(
            safe_rd(Some("https://mcp.badbat75.com@evil.com/"), s, base),
            s
        );
        // backslash in authority
        assert_eq!(
            safe_rd(Some("https://mcp.badbat75.com\\@evil.com/"), s, base),
            s
        );
        // non-https scheme
        assert_eq!(safe_rd(Some("http://mcp.badbat75.com/"), s, base), s);
        // scheme-relative is still blocked even with a base configured
        assert_eq!(safe_rd(Some("//mcp.badbat75.com/"), s, base), s);
    }

    #[test]
    fn rd_host_allowed_matches_host_only() {
        assert!(rd_host_allowed(
            "https://mcp.badbat75.com/x",
            "badbat75.com"
        ));
        assert!(rd_host_allowed("https://badbat75.com", "badbat75.com"));
        assert!(rd_host_allowed(
            "https://a.b.badbat75.com/x?y=1",
            "badbat75.com"
        ));
        assert!(rd_host_allowed(
            "https://mcp.badbat75.com:8443/x",
            "badbat75.com"
        ));
        // path/query containing the base must NOT count
        assert!(!rd_host_allowed(
            "https://evil.com/.badbat75.com",
            "badbat75.com"
        ));
        assert!(!rd_host_allowed(
            "https://evil.com/?x=badbat75.com",
            "badbat75.com"
        ));
        assert!(!rd_host_allowed("http://mcp.badbat75.com/", "badbat75.com"));
        assert!(!rd_host_allowed(
            "https://badbat75.com.evil.com/",
            "badbat75.com"
        ));
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
