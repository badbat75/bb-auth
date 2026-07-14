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
//! | `GET`  | `/auth/validate` | nginx `auth_request`, loopback | 204 + [`IDENTITY_HEADER`] if a credential authorizes the request, else 401 |
//! | `POST` | `/auth/session`  | browser | validate the posted `id_token`, set the cookie, 302 → `rd` |
//! | `GET`  | `/auth/logout`   | browser | clear the cookie, 302 → the login page |
//! | `GET`  | `/auth/healthz`  | local   | 200 `ok` |
//!
//! # Authorization model
//!
//! [`handle_validate`] accepts three credentials, tried in this order:
//!
//! 1. `Authorization: Bearer bbk_…` — a static API key, resolved by SHA-256 of the
//!    bearer against the access file.
//! 2. `Authorization: Bearer <id_token>` — a raw Cognito id_token, validated exactly
//!    as on `/auth/session`. Lets programmatic clients (e.g. MCP) skip the cookie flow.
//! 3. the session cookie.
//!
//! A Cognito-signed id_token is unforgeable, but holding one is **not** authorization:
//! Cognito self-signup is open. A request is authorized when the credential resolves to
//! an identity and *some* grant in the access file ([`read_access`]) covers the request
//! URL. There are exactly two grant sources, and both are re-checked on every request:
//!
//! * **the roster** — an entry in `users`, whose [`UrlScope`](bb_auth_core::UrlScope) must cover the URL. This
//!   is the only grant an API key can use. Deleting a user or a key and reloading denies
//!   even a still-unexpired cookie.
//! * **a `public_auth` site** — a URL area open to *any* identity Cognito vouches for,
//!   enrolled or not ([`SiteRecord`](bb_auth_core::SiteRecord)). Only the two Cognito-backed credentials reach it;
//!   an unknown API key stays unknown.
//!
//! Sites only ever grant. The one thing that takes away is `denied`, a veto by email that
//! outranks both sources on every credential ([`authorize`]).
//!
//! Bearers are stateless — they issue no cookie — and a failed bearer falls through
//! to the cookie check, so a stray `Authorization` header never blocks a valid cookie.
//!
//! # Identity propagation
//!
//! All three credentials resolve to the same thing: an email. A `204` hands it back in
//! [`IDENTITY_HEADER`], which nginx lifts out of the subrequest with `auth_request_set`
//! and injects into the request it proxies — that is how the application learns who is
//! calling. On a `public_auth` site that email may name someone with no entry anywhere:
//! it is an *authenticated* identity, and enrolling it is the application's business.
//!
//! An application must not try to read the identity itself. There is usually nothing
//! to read: the session cookie is not a JWT and carries only the email, and a `bbk_`
//! key has no token at all, so decoding a claim would work for exactly one of the
//! three credentials. It would not be safe either — self-signup means a valid
//! id_token proves identity, never authorization. The header is trustworthy only in
//! so far as the application is unreachable except through nginx.

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::Sha256;
use tiny_http::{Header, Request, Response, Server, StatusCode};

// The access file — schema, parser, URL matcher and the grant model — is shared with
// `bb-auth-adm`, which edits the very file this reads. One parser, one matcher, one
// answer to "who may reach what": see the [`bb_auth_core`] crate docs. Everything the
// access file has no opinion about — HTTP, the cookie, id_token validation, the nginx
// contract — stays here, in one file, read top to bottom.
use bb_auth_core::{
    compile_host_pattern, compile_login_url, decide, decide_api_key, header_safe_email,
    login_url_for, lower_authority, now, read_access, sha256_hex, Access, Decision, KeyDecision,
    UrlPattern, API_KEY_PREFIX,
};

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

/// Response header naming the authenticated user on a `204` from `/auth/validate`.
///
/// nginx lifts it out of the `auth_request` subrequest and re-injects it into the
/// request it proxies to the application:
///
/// ```text
/// location / {
///     set $bb_url https://app.example.com$uri;   # rewrite phase, before auth_request
///     auth_request     /internal/auth-gate;
///     auth_request_set $bb_email $upstream_http_x_auth_email;
///
///     proxy_set_header X-Auth-Email     $bb_email;   # whatever name the app reads
///     proxy_set_header X-Forwarded-User "";          # clear the names we do NOT set
///     proxy_set_header Remote-User      "";
///     proxy_pass http://127.0.0.1:9000;
/// }
/// ```
///
/// `auth_request_set` belongs in the gated location, not in the gate's own location.
/// The name the application reads is nginx's choice — it renames on the way through —
/// so this end stays fixed and unconfigurable.
///
/// `proxy_set_header` overwrites whatever the client sent, and nginx omits the header
/// entirely when the variable is empty, so an unauthenticated request can never smuggle
/// one in. That only covers names nginx sets, hence the explicit clearing of any other
/// name the application might also trust. And none of it means anything unless the
/// application is unreachable except through nginx.
const IDENTITY_HEADER: &str = "X-Auth-Email";

/// Response header naming the login page on a `401` from `/auth/validate` — the site's
/// `login_url`, or `BB_AUTH_LOGIN_URL` when it declares none ([`login_url_for`]).
///
/// bb-auth never redirects a gated request itself: it answers `401` and nginx decides.
/// This header is how nginx learns *which* login page, per site rather than per server
/// block. The `auth_request_set` copies it into a request variable, which is what keeps a
/// later `proxy_pass` from clobbering `$upstream_http_*`:
///
/// ```text
/// map $bb_login $bb_login_safe {          # http{} level
///     ""      https://login.example.com/; # = BB_AUTH_LOGIN_URL
///     default $bb_login;
/// }
/// location /app1 {
///     set $bb_url https://app.example.com$uri;
///     auth_request     /internal/auth-gate;
///     auth_request_set $bb_login $upstream_http_x_auth_login_url;
///     error_page 401 = @bb_signin;
///     …
/// }
/// location @bb_signin { return 302 $bb_login_safe?rd=$scheme://$host$request_uri; }
/// ```
///
/// The `map` is load-bearing: an unset `$bb_login` — an older gate, or a location missing
/// the `auth_request_set` — turns `return 302 $bb_login?rd=…` into a *relative*
/// `Location: ?rd=…`, which sends the browser back to the gated path it just failed on.
///
/// The gate can name the login page here because a `401` happens *on* a gated URL, so the
/// site resolves. `/auth/logout` has no such luck — see [`handle_logout`].
///
/// Emitting it is safe without a per-request check: every candidate passed
/// [`compile_login_url`] at load, which requires printable ASCII.
const LOGIN_URL_HEADER: &str = "X-Auth-Login-URL";

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
    /// `BB_AUTH_LOGIN_URL`, e.g. `https://login.example.com/`. Where a logout and every
    /// rejected `rd` land, and what a `401` names in [`LOGIN_URL_HEADER`] — unless the
    /// site that speaks for the URL overrides it ([`login_url_for`]). Validated by
    /// [`compile_login_url`] at startup.
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
            // The global fallback for every site that declares no `login_url`. Validated
            // with the same parser, so nothing that reaches a header or a page can carry
            // a CR/LF — including the value `safe_rd` falls back to.
            login_url: compile_login_url(&env_req("BB_AUTH_LOGIN_URL")).unwrap_or_else(|e| {
                eprintln!("[bb-auth] FATAL: BB_AUTH_LOGIN_URL: {e}");
                std::process::exit(1);
            }),
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
/// mutable parts are the hot-reloadable access table and the JWKS cache.
struct State {
    cfg: Config,
    /// The access gate: sites, the denied veto, allowlisted users and their API keys.
    /// Swapped wholesale on SIGHUP by `reload_access` (POSIX only, hence not linked here).
    access: RwLock<Access>,
    /// Path to re-read on SIGHUP. Only the POSIX reload path needs it.
    #[cfg(unix)]
    access_path: String,
    jwks: RwLock<JwksCache>,
    /// Serializes JWKS refreshers, so a `kid` miss under load triggers one fetch, not
    /// one per worker. See [`refresh_jwks_if_due`].
    jwks_refresh: Mutex<()>,
}

// ---------------------------------------------------------------------------
// Access table — the model, the parser and the matcher live in [`bb_auth_core`];
// what follows is only how the gate loads and reloads them.
// ---------------------------------------------------------------------------

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

/// Initial access load: a missing/unreadable/invalid file is fatal (no safe
/// default exists at startup); a table that grants nobody anything warns but is allowed.
fn load_access(path: &str) -> Access {
    match read_access(path) {
        Ok(a) => {
            if a.by_email.is_empty() && !a.sites.any_public_auth() {
                eprintln!(
                    "[bb-auth] WARNING: access file {path} has no users and no public_auth site \
                     — nobody can sign in"
                );
            }
            a
        }
        Err(e) => {
            eprintln!("[bb-auth] FATAL: cannot read access file: {e}");
            std::process::exit(1);
        }
    }
}

/// Hot-reload the access table from disk (SIGHUP). On read/parse failure, keep the
/// current table and log — never nuke the live table on a transient error.
#[cfg(unix)]
fn reload_access(state: &State) {
    match read_access(&state.access_path) {
        Ok(new) => {
            let (u, k) = (new.by_email.len(), new.by_key_hash.len());
            let (s, d) = (new.sites.entries.len(), new.denied.len());
            *state.access.write().unwrap() = new; // fail-safe: atomic swap
            eprintln!(
                "[bb-auth] access reloaded (SIGHUP): {u} users, {k} api keys, {s} sites, {d} denied"
            );
        }
        Err(e) => eprintln!("[bb-auth] access reload FAILED, keeping current set: {e}"),
    }
}

/// Spawn the SIGHUP -> access-reload thread. SIGHUP is POSIX-only, so this is a
/// no-op on non-unix hosts (where the table simply reloads across a restart).
#[cfg(unix)]
fn spawn_access_reload_handler(state: &Arc<State>) {
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
            reload_access(&sig_state);
        }
    });
}

#[cfg(not(unix))]
fn spawn_access_reload_handler(_state: &Arc<State>) {}

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
/// 60 s leeway), `iss`, `aud` against [`Config::audiences`], `token_use == "id"`,
/// [`header_safe_email`], and a truthy `email_verified`. The single sanctioned exception
/// to the last one is [`unverified_social_ok`].
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
    // A `public_auth` site emits identities that appear in no table, so `read_access`
    // never sees this email. It goes into IDENTITY_HEADER and, via `make_session`, into
    // the cookie — a CR/LF here would be a response-splitting gadget. `{email:?}` escapes
    // the very bytes being rejected, so a crafted token cannot forge a log line either.
    if !header_safe_email(&email) {
        return Err(format!("token email is not printable ASCII: {email:?}"));
    }
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

/// The percent-decoded value of query parameter `name` in a request target such as
/// `/auth/logout?rd=%2Fapp1`. `None` when there is no query or no such parameter.
/// Decoding is `form_urlencoded`, the same parser `/auth/session` reads its body with.
fn query_param(target: &str, name: &str) -> Option<String> {
    let (_, query) = target.split_once('?')?;
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
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
    hosts.iter().any(|p| p.matches(&host))
}

/// Respond with a bare status code and no body — what `auth_request` consumes.
fn respond_empty(req: Request, status: u16) {
    let _ = req.respond(Response::empty(StatusCode(status)));
}

/// Respond `204` to an authorized `auth_request`, naming the user in [`IDENTITY_HEADER`].
///
/// `email` always passed [`header_safe_email`], by one of two disjoint routes, so [`h`]
/// cannot panic here:
///
/// * it is a key of [`Access::by_email`] — the API-key path reads it off the record, and
///   the roster branch of [`authorize`] returns the very string that just matched a key by
///   exact `HashMap` lookup. Every such key was checked by [`read_access`] at load.
/// * or it came out of [`validate_id_token`], which checks it there — the only route for
///   an identity granted by a `public_auth` site, which is in no table to have been
///   checked at load. The cookie carries it back unchanged under the HMAC.
///
/// The assert pins both halves. It is what stands between a case-insensitive `by_email`
/// lookup added later, or a fourth credential that skips `validate_id_token`, and a
/// panicking worker thread.
fn respond_authorized(req: Request, email: &str) {
    debug_assert!(
        header_safe_email(email),
        "identity must be header-safe: {email:?}"
    );
    let resp = Response::empty(StatusCode(204)).with_header(h(IDENTITY_HEADER, email));
    let _ = req.respond(resp);
}

/// Respond `401` to a rejected `auth_request`, naming the login page in
/// [`LOGIN_URL_HEADER`] so nginx can redirect there. `login_url` came from
/// [`login_url_for`], hence passed [`compile_login_url`], hence cannot make [`h`] panic.
fn respond_unauthorized(req: Request, login_url: &str) {
    debug_assert!(
        login_url.bytes().all(|b| b.is_ascii_graphic()),
        "login url must be header-safe: {login_url:?}"
    );
    let resp = Response::empty(StatusCode(401)).with_header(h(LOGIN_URL_HEADER, login_url));
    let _ = req.respond(resp);
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
<div class=c><h1>{title}</h1><p>{msg}</p><p><a href=\"{login_url}\">&larr; Back to sign-in</a></p></div>"
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

/// Resolve a `bbk_` API-key bearer against the access table: its owner must not be
/// vetoed, and the key must be known, unexpired, and in URL scope. Logs the reason on
/// rejection.
///
/// The rule itself is [`decide_api_key`], which takes the *hash*: `sha256(bearer)` is
/// computed here and is the only thing ever looked up, so nothing is indexed by what the
/// client sent in the clear. This wrapper is the gate's half — the logging, and the
/// wall-clock [`now`] the decision is measured against.
///
/// Returns the owning user's email — a key *acts as* its user, so that is the identity
/// the application downstream sees. It is also the only path with no token to decode.
///
/// A `public_auth` site does **not** rescue an unknown key. That grant is for identities
/// Cognito vouches for, and Cognito vouches for no static key of ours: an unknown key is
/// not an un-enrolled user, it is nobody, and there would be no email to hand back.
fn bearer_apikey_email(access: &Access, token: &str, url: Option<&str>) -> Option<String> {
    let at = || url.unwrap_or("<none>");
    match decide_api_key(access, &sha256_hex(token), url, now()) {
        KeyDecision::Granted(rec) => Some(rec.email.clone()),
        KeyDecision::Unknown => {
            eprintln!("[bb-auth] api key rejected: unknown");
            None
        }
        KeyDecision::OwnerDenied(rec) => {
            eprintln!(
                "[bb-auth] api key denied: owner is denied [{} {}]",
                rec.email, rec.key_id
            );
            None
        }
        KeyDecision::Expired(rec) => {
            eprintln!(
                "[bb-auth] api key rejected: expired [{} {}]",
                rec.email, rec.key_id
            );
            None
        }
        KeyDecision::OutOfScope(rec) => {
            eprintln!(
                "[bb-auth] api key denied: url {} out of scope [{} {}]",
                at(),
                rec.email,
                rec.key_id
            );
            None
        }
    }
}

/// Turn an *authenticated* identity into an *authorized* one, or `None`. Shared by the
/// id_token-bearer and cookie paths — the two credentials Cognito vouches for.
///
/// The rule is [`decide`], and it lives in the library because `bb-auth-adm can` asks the
/// same question of the same code. What stays here is what only a request has: the log
/// line naming the reason.
///
/// Takes `email` by value and hands it back on success — on *both* grant branches, so the
/// string returned is the one that came in. On the roster branch that is byte-identical to
/// the [`Access::by_email`] key (both sides lowercased, `HashMap::get` is exact-match); on
/// the `public_auth` branch it is whatever [`validate_id_token`] returned.
/// [`respond_authorized`] relies on exactly that pair of facts.
fn authorize(access: &Access, email: String, url: Option<&str>) -> Option<String> {
    match decide(access, &email, url) {
        Decision::SiteGrant(site) => {
            eprintln!("[bb-auth] granted via site '{site}' (public_auth): {email}");
            Some(email)
        }
        Decision::RosterGrant => Some(email),
        Decision::Vetoed => {
            eprintln!("[bb-auth] denied: {email} is on the denied list");
            None
        }
        Decision::OutOfScope => {
            eprintln!(
                "[bb-auth] denied: url {} out of scope for {email}",
                url.unwrap_or("<none>")
            );
            None
        }
        Decision::NotEnrolled => {
            eprintln!("[bb-auth] denied: {email} not in users table");
            None
        }
    }
}

/// `GET /auth/validate` — the nginx `auth_request` endpoint. 204 plus the authorized
/// user in [`IDENTITY_HEADER`] if any credential authorizes this request, else 401 plus
/// this area's login page in [`LOGIN_URL_HEADER`]. Never issues a cookie, and never
/// redirects: nginx turns the 401 into a redirect, which is why the header exists.
///
/// Credentials are tried in the order documented on the crate: `bbk_` API key, raw
/// id_token, then the session cookie. A key must resolve to a user in the roster and put
/// the URL inside its [`UrlScope`](bb_auth_core::UrlScope); the two Cognito credentials go through [`authorize`],
/// which also honours `public_auth` sites and the `denied` veto. Whichever one wins, the
/// identity handed back is an email — see [`respond_authorized`].
fn handle_validate(req: Request, state: &State) {
    let cfg = &state.cfg;
    // Original request URL (for site resolution and per-user / per-key URL scoping),
    // captured now as an owned value so the request can be consumed when we respond.
    let url = original_url(&req, cfg);

    // Bearer path: programmatic clients (e.g. MCP) present `Authorization: Bearer
    // <cred>`. A `bbk_` credential is a static API key resolved against the access
    // table; anything else is a raw Cognito id_token validated exactly like
    // /auth/session, then authorized like a cookie. A failed bearer falls through to the
    // cookie check so a stray Authorization header never blocks an otherwise-valid cookie.
    if let Some(token) = header_value(&req, "Authorization").and_then(parse_bearer) {
        let granted = if token.starts_with(API_KEY_PREFIX) {
            bearer_apikey_email(&state.access.read().unwrap(), token, url.as_deref())
        } else {
            match validate_id_token(token, state) {
                Ok(email) => authorize(&state.access.read().unwrap(), email, url.as_deref()),
                Err(e) => {
                    eprintln!("[bb-auth] bearer rejected: {e}");
                    None
                }
            }
        };
        if let Some(email) = granted {
            respond_authorized(req, &email);
            return;
        }
    }

    let granted = header_value(&req, "Cookie")
        .and_then(|c| cookie_value(c, &cfg.cookie_name).map(str::to_string))
        .and_then(|v| verify_session(&v, &cfg.hmac_keys))
        .and_then(|email| authorize(&state.access.read().unwrap(), email, url.as_deref()));
    match granted {
        Some(email) => respond_authorized(req, &email),
        None => {
            // Which login page nginx should send them to. Resolved from the site even
            // though no site granted anything: `login_url` says where this area's users
            // sign in, not who may enter.
            let login = login_url_for(
                &state.access.read().unwrap(),
                &cfg.login_url,
                url.as_deref(),
            );
            respond_unauthorized(req, &login)
        }
    }
}

/// `POST /auth/session` — exchange a browser-obtained `id_token` for a session cookie,
/// then `302` to `rd`.
///
/// 400 on a missing token, 401 on an invalid one, 403 when the verified email has nowhere
/// it could possibly go. The redirect target is always laundered through [`safe_rd`].
///
/// The cookie is identity, not authorization: it grants nothing on its own, and every
/// request it accompanies is re-authorized by [`handle_validate`]. So the 403 here is a
/// courtesy — it tells someone at the login page that they are not enrolled, rather than
/// letting them bounce off a 401 later. It has to soften once any `public_auth` site
/// exists, because then an un-enrolled identity *does* have somewhere to go and refusing
/// the cookie would make that site unreachable from a browser. Guessing at `rd` instead
/// would be worse: it is the post-login destination, not the URL that triggered the login,
/// and [`safe_rd`] may already have replaced it with the login page.
fn handle_session(mut req: Request, state: &State) {
    let cfg = &state.cfg;

    // Which host this login is happening on, and hence which site's login page an error
    // page should link back to. nginx sets the header here too, not just on the gate.
    let caller_url = original_url(&req, cfg);
    let login = login_url_for(
        &state.access.read().unwrap(),
        &cfg.login_url,
        caller_url.as_deref(),
    );

    let mut buf = Vec::new();
    if req
        .as_reader()
        .take(MAX_BODY)
        .read_to_end(&mut buf)
        .is_err()
    {
        respond_html(req, 400, "Error", "Invalid request.", &login);
        return;
    }
    let form: HashMap<String, String> = form_urlencoded::parse(&buf).into_owned().collect();

    let id_token = match form.get("id_token") {
        Some(t) if !t.is_empty() => t,
        _ => {
            respond_html(req, 400, "Error", "Missing token.", &login);
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
                "Sign-in failed",
                "The access token is invalid or has expired. Please try again.",
                &login,
            );
            return;
        }
    };

    // Booleans, not a held guard: `respond_html` consumes `req`, and the lock has no
    // business being alive while we write a response.
    let (vetoed, enrolled, any_open) = {
        let access = state.access.read().unwrap();
        (
            access.denied.contains(&email),
            access.by_email.contains_key(&email),
            access.sites.any_public_auth(),
        )
    };
    if vetoed || !(enrolled || any_open) {
        let why = if vetoed {
            "denied"
        } else {
            "not in users table"
        };
        eprintln!("[bb-auth] session denied: {email} {why}");
        respond_html(
            req,
            403,
            "Access not authorized",
            "This email address is not allowed to sign in.",
            &login,
        );
        return;
    }

    // Which host is this login happening on? nginx told us above, the same way it does on
    // /auth/validate. A relative `rd` resolves against it; without it we can only fall
    // back to the login page.
    let caller_origin = caller_url.as_deref().and_then(origin_of);
    let rd = safe_rd(
        form.get("rd").map(String::as_str),
        caller_origin.as_deref(),
        &cfg.authorized_hosts,
        &login,
    );
    let cookie = build_cookie(
        cfg,
        &make_session(&email, cfg.session_ttl, &cfg.hmac_keys),
        cfg.session_ttl as i64,
    );
    eprintln!("[bb-auth] session granted: {email} -> {rd}");
    respond_redirect(req, &rd, Some(&cookie));
}

/// `GET /auth/logout[?rd=…]` — expire the session cookie and `302` away.
///
/// Clears the bb-auth cookie only; the Cognito refresh token the login page may hold is
/// out of scope. A cross-site navigation is ignored (CSRF logout).
///
/// **Where it lands is the caller's choice, not a site's.** A logout happens *at*
/// `/auth/logout`, which no site's `urls` cover — the gate cannot tell which area you are
/// leaving, so there is nothing for a per-site landing page to resolve against. (Contrast
/// [`LOGIN_URL_HEADER`]: a `401` happens *on* a gated URL, so the site resolves.) The one
/// party that does know is whoever wrote the logout link, so they say it:
///
/// ```html
/// <a href="/auth/logout?rd=/app1/goodbye">Sign out</a>
/// ```
///
/// `rd` goes through [`safe_rd`] exactly as on `/auth/session`, so it buys no new
/// open-redirect surface. With no `rd` the browser lands on the login page — *not* on the
/// caller's root, which is what `safe_rd` would default to and is the wrong end for a
/// logout. A relative `rd` needs `BB_AUTH_ORIGINAL_URL_HEADER` on this location too; if
/// nginx omits it the redirect falls back to the login page, which is fail-soft.
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

    let caller_url = original_url(&req, cfg);
    let login = login_url_for(
        &state.access.read().unwrap(),
        &cfg.login_url,
        caller_url.as_deref(),
    );
    let rd = query_param(req.url(), "rd").filter(|v| !v.is_empty());
    let target = match rd {
        Some(rd) => safe_rd(
            Some(&rd),
            caller_url.as_deref().and_then(origin_of).as_deref(),
            &cfg.authorized_hosts,
            &login,
        ),
        None => login,
    };
    respond_redirect(req, &target, cookie.as_deref());
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

/// `bb-auth --check-users <file>`: parse an access file with the real parser and exit
/// 0 (with a summary) or 1 (with the error). Reads no env and touches no network, so
/// a deploy can validate the file that is *about* to go live — a rejected scope, an
/// unknown site field, or a residual `enabled_paths` is a fatal startup error, and with
/// `Restart=on-failure` that would be a boot loop.
fn check_users(path: &str) -> ! {
    match read_access(path) {
        Ok(a) => {
            let open: Vec<&str> = a
                .sites
                .entries
                .iter()
                .filter(|s| s.public_auth)
                .map(|s| s.name.as_str())
                .collect();
            println!(
                "[bb-auth] {path}: OK — {} users, {} api keys, {} sites, {} denied",
                a.by_email.len(),
                a.by_key_hash.len(),
                a.sites.entries.len(),
                a.denied.len()
            );
            if !open.is_empty() {
                println!(
                    "[bb-auth] {path}: public_auth sites (any authenticated identity, enrolled \
                     or not): {}",
                    open.join(", ")
                );
            }
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[bb-auth] {path}: INVALID — {e}");
            std::process::exit(1);
        }
    }
}

/// Parse argv (only `--check-users`), build the config, load the access table, prime the
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
    let access_path = env_req("BB_AUTH_USERS_FILE");
    let access = load_access(&access_path);

    let initial = fetch_jwks(&cfg.issuer).unwrap_or_else(|e| {
        eprintln!("[bb-auth] FATAL: initial JWKS fetch failed: {e}");
        std::process::exit(1);
    });

    let listen = cfg.listen.clone();
    let workers = cfg.workers;
    let user_n = access.by_email.len();
    let key_n = access.by_key_hash.len();
    let site_n = access.sites.entries.len();
    let denied_n = access.denied.len();
    let open_sites: Vec<String> = access
        .sites
        .entries
        .iter()
        .filter(|s| s.public_auth)
        .map(|s| s.name.clone())
        .collect();

    let state = Arc::new(State {
        cfg,
        access: RwLock::new(access),
        #[cfg(unix)]
        access_path,
        jwks: RwLock::new(JwksCache {
            keys: initial,
            last_refresh: Instant::now(),
        }),
        jwks_refresh: Mutex::new(()),
    });

    // Hot-reload the access table on SIGHUP (systemctl reload bb-auth). Failures
    // keep the current table; no one is logged out by a transient disk error.
    // POSIX-only; no-op on non-unix hosts.
    spawn_access_reload_handler(&state);

    let server = Arc::new(Server::http(&listen).unwrap_or_else(|e| {
        eprintln!("[bb-auth] FATAL: cannot bind {listen}: {e}");
        std::process::exit(1);
    }));

    eprintln!(
        "[bb-auth] listening on {listen} | issuer={} | aud={} | users={user_n} | api_keys={key_n} | sites={site_n} | denied={denied_n} | workers={workers}",
        state.cfg.issuer,
        state.cfg.audiences.join(",")
    );
    if !open_sites.is_empty() {
        // Cognito self-signup is open, so this really is "anyone who can register".
        eprintln!(
            "[bb-auth] WARNING: public_auth sites reachable by ANY authenticated identity, \
             enrolled or not [{}]",
            open_sites.join(",")
        );
    }
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
    fn query_param_decodes_rd() {
        assert_eq!(
            query_param("/auth/logout?rd=%2Fapp1%2Fbye", "rd").as_deref(),
            Some("/app1/bye")
        );
        assert_eq!(
            query_param("/auth/logout?a=1&rd=https%3A%2F%2Fx.com%2Fz&b=2", "rd").as_deref(),
            Some("https://x.com/z")
        );
        assert_eq!(query_param("/auth/logout?rd=", "rd").as_deref(), Some(""));
        assert_eq!(query_param("/auth/logout?a=1", "rd"), None);
        assert_eq!(query_param("/auth/logout", "rd"), None);
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
    fn html_escape_escapes_special_chars() {
        assert_eq!(html_escape("plain"), "plain");
        assert_eq!(html_escape("a<b>&c\"'d"), "a&lt;b&gt;&amp;c&quot;&#39;d");
        // attribute-context safety: a crafted login url can't break out
        assert_eq!(
            html_escape("https://x/\" onmouseover=\"alert(1)"),
            "https://x/&quot; onmouseover=&quot;alert(1)"
        );
    }

    // --- the two wrappers over the grant model ------------------------------
    //
    // The rule itself (`decide` / `decide_api_key`, sites, `denied`, scopes, expiry) is
    // pinned in bb_auth_core's tests. What is the gate's own is the mapping to what a
    // response needs — and one property those tests cannot see: that the identity handed
    // back is the very string that came in, which is what `respond_authorized`'s
    // debug_assert stands on.

    /// A live access table, via a real temp file and the real parser.
    fn access_of(name: &str, json: &str) -> Access {
        let p = std::env::temp_dir().join(format!("bb-auth-gate-{name}.json"));
        std::fs::write(&p, json).unwrap();
        let a = read_access(p.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&p);
        a
    }

    #[test]
    fn authorize_hands_back_the_identity_it_was_given() {
        let a = access_of(
            "authorize",
            r#"{ "sites": [ { "name": "app1", "urls": ["https://app.x.com/app1/*"],
                              "public_auth": true } ],
                 "denied": ["spammer@x.com"],
                 "users": [ { "email": "bob@x.com",
                              "authorized_urls": ["https://app.x.com/other/*"] } ] }"#,
        );
        let other = Some("https://app.x.com/other/x");
        let app1 = Some("https://app.x.com/app1/x");

        // the roster branch: the string back is the key that matched, header-safe by
        // construction because `read_access` checked it at load …
        let got = authorize(&a, "bob@x.com".to_string(), other).unwrap();
        assert_eq!(got, "bob@x.com");
        assert!(header_safe_email(&got));
        // … and the public_auth branch: nobody in any table, the string is the caller's,
        // header-safe because `validate_id_token` checked it there. Both are the input.
        let got = authorize(&a, "newcomer@x.com".to_string(), app1).unwrap();
        assert_eq!(got, "newcomer@x.com");
        assert!(header_safe_email(&got));

        // and the denials map to None, veto first
        assert_eq!(authorize(&a, "spammer@x.com".to_string(), app1), None);
        assert_eq!(
            authorize(&a, "bob@x.com".to_string(), app1).as_deref(),
            Some("bob@x.com")
        );
        assert_eq!(authorize(&a, "newcomer@x.com".to_string(), other), None);
        assert_eq!(authorize(&a, "bob@x.com".to_string(), None), None);
    }

    #[test]
    fn bearer_apikey_email_returns_the_owner() {
        // The gate hashes the bearer; the file holds only the hash. A key acts as its
        // user, so the identity handed back is the owner's — the one email on this path
        // that never passed through a token claim, and so is guarded at load instead.
        let key = "bbk_secret";
        let json = format!(
            r#"{{ "users": [ {{ "email": "bot@x.com",
                   "authorized_urls": ["https://mcp.x.com/mcp/*"],
                   "api_keys": [ {{ "id": "laptop", "key_hash": "{}",
                                    "released": "2026-01-01", "duration": "never" }} ] }} ] }}"#,
            sha256_hex(key)
        );
        let a = access_of("apikey", &json);
        let in_scope = Some("https://mcp.x.com/mcp/tools");

        let got = bearer_apikey_email(&a, key, in_scope).unwrap();
        assert_eq!(got, "bot@x.com");
        assert!(header_safe_email(&got));

        assert_eq!(bearer_apikey_email(&a, "bbk_nope", in_scope), None);
        assert_eq!(
            bearer_apikey_email(&a, key, Some("https://mcp.x.com/other")),
            None
        );
        assert_eq!(bearer_apikey_email(&a, key, None), None); // no header => denied
    }
}
