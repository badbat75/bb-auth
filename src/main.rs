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
//!   POST /auth/session   — public; body `id_token=...&rd=...`. Validates the
//!                          id_token fully, sets the session cookie, 302 → rd.
//!   GET  /auth/logout    — public; clears the cookie, 302 → login page.
//!   GET  /auth/healthz   — 200 "ok".
//!
//! Security model: a valid Cognito-signed id_token is unforgeable, so possession
//! of one for an allowlisted email is the credential. The allowlist is the real
//! access gate (Cognito self-signup is open) and is re-checked on every /validate,
//! so removing an email + SIGHUP (or restart) denies even existing cookies.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::Sha256;
use tiny_http::{Header, Request, Response, Server, StatusCode};

type HmacSha256 = Hmac<Sha256>;

const MAX_BODY: u64 = 64 * 1024; // id_tokens are ~1-3 KB; cap generously.
const COOKIE_VERSION: &str = "bb2";
const COOKIE_VERSION_LEGACY: &str = "bb1";

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
    client_id: String,
    cookie_name: String,
    cookie_domain: Option<String>,
    session_ttl: u64,
    search_url: String, // canonical service base (BB_AUTH_SEARCH_URL), e.g. https://app.example.com/
    login_url: String,  // login page (BB_AUTH_LOGIN_URL), e.g. https://login.example.com/
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
        Config {
            listen: env_or("BB_AUTH_LISTEN", "127.0.0.1:4181"),
            hmac_keys: HmacKeys { by_id, active_id },
            issuer,
            client_id: env_req("BB_AUTH_CLIENT_ID"),
            cookie_name: env_or("BB_AUTH_COOKIE_NAME", "bb_session"),
            cookie_domain,
            session_ttl: env_or("BB_AUTH_SESSION_TTL_SECS", "2592000")
                .parse()
                .unwrap_or(2_592_000),
            search_url,
            login_url: env_req("BB_AUTH_LOGIN_URL"),
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
    allowlist: RwLock<HashSet<String>>, // lowercased emails
    #[cfg(unix)]
    allowlist_path: String, // needed by the SIGHUP reload path
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
// Allowlist
// ---------------------------------------------------------------------------

/// Parse the allowlist file into a set of lowercased emails. Comments (`#`) and
/// blank lines are ignored. Returns an error instead of exiting so a runtime
/// SIGHUP reload can fail soft (keep the old set).
fn read_allowlist(path: &str) -> Result<HashSet<String>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_ascii_lowercase())
        .collect())
}

/// Initial allowlist load: a missing/unreadable file is fatal (no safe default
/// exists at startup); an empty file warns but is allowed.
fn load_allowlist(path: &str) -> HashSet<String> {
    match read_allowlist(path) {
        Ok(s) => {
            if s.is_empty() {
                eprintln!("[bb-auth] WARNING: allowlist {path} is empty — nobody can sign in");
            }
            s
        }
        Err(e) => {
            eprintln!("[bb-auth] FATAL: cannot read allowlist: {e}");
            std::process::exit(1);
        }
    }
}

/// Hot-reload the allowlist from disk (SIGHUP). On read failure, keep the
/// current set and log — never nuke the live allowlist on a transient error.
#[cfg(unix)]
fn reload_allowlist(state: &State) {
    match read_allowlist(&state.allowlist_path) {
        Ok(new) => {
            let n = new.len();
            *state.allowlist.write().unwrap() = new; // fail-safe: atomic swap
            eprintln!("[bb-auth] allowlist reloaded (SIGHUP): {n} entries");
        }
        Err(e) => eprintln!("[bb-auth] allowlist reload FAILED, keeping current set: {e}"),
    }
}

/// Spawn the SIGHUP -> allowlist-reload thread. SIGHUP is POSIX-only, so this is
/// a no-op on non-unix hosts (where the allowlist simply reloads across a restart).
#[cfg(unix)]
fn spawn_allowlist_reload_handler(state: &Arc<State>) {
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
            reload_allowlist(&sig_state);
        }
    });
}

#[cfg(not(unix))]
fn spawn_allowlist_reload_handler(_state: &Arc<State>) {}

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
}

fn email_verified_true(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
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
    v.set_audience(&[&state.cfg.client_id]);
    v.set_issuer(&[&state.cfg.issuer]);
    v.set_required_spec_claims(&["exp", "aud", "iss"]);
    v.validate_exp = true;
    v.leeway = 60;

    let data = decode::<Claims>(token, &key, &v).map_err(|e| format!("token invalid: {e}"))?;
    let c = data.claims;

    if c.token_use.as_deref() != Some("id") {
        return Err("token_use is not 'id'".into());
    }
    if !email_verified_true(&c.email_verified) {
        return Err("email not verified".into());
    }
    let email = c.email.ok_or("token has no email")?;
    Ok(email.to_ascii_lowercase())
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
fn safe_rd(rd: Option<&str>, search_url: &str) -> String {
    let r = match rd {
        Some(r) if !r.is_empty() => r,
        _ => return search_url.to_string(),
    };
    if r.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return search_url.to_string();
    }
    if r.starts_with(search_url) {
        return r.to_string();
    }
    if r.starts_with('/') && !r.starts_with("//") && !r.starts_with("/\\") {
        return format!("{}{}", search_url.trim_end_matches('/'), r);
    }
    search_url.to_string()
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

fn handle_validate(req: Request, state: &State) {
    let cfg = &state.cfg;
    let ok = header_value(&req, "Cookie")
        .and_then(|c| cookie_value(c, &cfg.cookie_name).map(str::to_string))
        .and_then(|v| verify_session(&v, &cfg.hmac_keys))
        .map(|email| state.allowlist.read().unwrap().contains(&email))
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

    if !state.allowlist.read().unwrap().contains(&email) {
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

    let rd = safe_rd(form.get("rd").map(String::as_str), &cfg.search_url);
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
    let allowlist_path = env_req("BB_AUTH_ALLOWLIST_FILE");
    let allowlist = load_allowlist(&allowlist_path);

    let initial = fetch_jwks(&cfg.issuer).unwrap_or_else(|e| {
        eprintln!("[bb-auth] FATAL: initial JWKS fetch failed: {e}");
        std::process::exit(1);
    });

    let listen = cfg.listen.clone();
    let workers = cfg.workers;
    let allow_n = allowlist.len();

    let state = Arc::new(State {
        cfg,
        allowlist: RwLock::new(allowlist),
        #[cfg(unix)]
        allowlist_path,
        jwks: RwLock::new(JwksCache {
            keys: initial,
            last_refresh: Instant::now(),
        }),
        jwks_refresh: Mutex::new(()),
    });

    // Hot-reload the allowlist on SIGHUP (systemctl reload bb-auth). Failures
    // keep the current set; no one is logged out by a transient disk error.
    // POSIX-only; no-op on non-unix hosts.
    spawn_allowlist_reload_handler(&state);

    let server = Arc::new(Server::http(&listen).unwrap_or_else(|e| {
        eprintln!("[bb-auth] FATAL: cannot bind {listen}: {e}");
        std::process::exit(1);
    }));

    eprintln!(
        "[bb-auth] listening on {listen} | issuer={} | aud={} | allowlist={} entries | workers={workers}",
        state.cfg.issuer, state.cfg.client_id, allow_n
    );

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

    #[test]
    fn cookie_value_parses_named() {
        let h = "a=1; bb_session=bb2.k1.1.aaa.bbb; c=2";
        assert_eq!(cookie_value(h, "bb_session"), Some("bb2.k1.1.aaa.bbb"));
        assert_eq!(cookie_value("bb_session_extra=x", "bb_session"), None);
        assert_eq!(cookie_value("", "bb_session"), None);
    }

    #[test]
    fn read_allowlist_parses() {
        let tmp = std::env::temp_dir().join("bb-auth-allowlist-test.txt");
        std::fs::write(&tmp, "# comment\n\n  \nFoo@Bar.com\n baz@qux.com\n").unwrap();
        let s = read_allowlist(tmp.to_str().unwrap()).unwrap();
        assert_eq!(s.len(), 2);
        assert!(s.contains("foo@bar.com"));
        assert!(s.contains("baz@qux.com"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn safe_rd_allows_search_url_prefix_and_paths() {
        let s = "https://app.example.com/";
        assert_eq!(
            safe_rd(Some("https://app.example.com/q?x=1"), s),
            "https://app.example.com/q?x=1"
        );
        assert_eq!(
            safe_rd(Some("/search?q=1"), s),
            "https://app.example.com/search?q=1"
        );
        assert_eq!(safe_rd(None, s), s);
        assert_eq!(safe_rd(Some(""), s), s);
    }

    #[test]
    fn safe_rd_blocks_open_redirect_and_splitting() {
        let s = "https://app.example.com/";
        // scheme-relative + backslash variant (browsers normalise `/\` -> `//`)
        assert_eq!(safe_rd(Some("//evil.com"), s), s);
        assert_eq!(safe_rd(Some("/\\evil.com"), s), s);
        // response splitting via CRLF / control bytes
        assert_eq!(safe_rd(Some("/\r\nSet-Cookie: x=1"), s), s);
        assert_eq!(safe_rd(Some("/x\x00y"), s), s);
        assert_eq!(safe_rd(Some("/q\x7f"), s), s);
        // off-host absolute URL
        assert_eq!(safe_rd(Some("https://evil.com/"), s), s);
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
