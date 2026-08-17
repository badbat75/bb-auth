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
//! | `GET`  | `/auth/validate` | nginx `auth_request`, loopback | 204 + [`IDENTITY_HEADER`] (+ one header per configured [`ProfileClaim`] the credential carries) if a credential authorizes the request, else 401 |
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
//! Cognito self-signup is open. A request is authorized when the URL resolves to a scope
//! in the access file ([`read_access`]) and that scope admits the credential. The access
//! file is application-centric: applications partition the URL space, and the scope that
//! answers is the first one, in file order, whose patterns cover the request
//! ([`Access::resolve`](bb_auth_core::Access::resolve)). Every scope says what it wants of
//! an identity ([`AccessKind`]):
//!
//! * **`anonymous`** — no credential at all. The `204` names nobody.
//! * **`authenticated`** — any identity Cognito vouches for, enrolled or not. Only the two
//!   Cognito-backed credentials reach it; an unknown API key stays unknown, because
//!   Cognito vouches for no static key of ours.
//! * **`restricted`** — the users and groups the scope lists, and only through the
//!   credential classes it admits. An API key may narrow itself further to a named set of
//!   scopes.
//!
//! **A URL no application covers is reachable by nobody.** Scopes only ever grant; the one
//! thing that takes away is `denied`, a veto that outranks every grant on every credential
//! ([`authorize`]). All of it is re-checked on every request, so deleting a user or a key
//! and reloading denies even a still-unexpired cookie.
//!
//! Bearers are stateless — they issue no cookie — and a failed bearer falls through
//! to the cookie check, so a stray `Authorization` header never blocks a valid cookie.
//!
//! # Identity propagation
//!
//! All three credentials resolve to the same thing: an email. A `204` hands it back in
//! [`IDENTITY_HEADER`], which nginx lifts out of the subrequest with `auth_request_set`
//! and injects into the request it proxies — that is how the application learns who is
//! calling. On an `authenticated` scope that email may name someone with no entry
//! anywhere: it is an *authenticated* identity, and enrolling it is the application's
//! business. Which attributes go out is the settings file's `identity_attrs` ([`IdentityAttr`]);
//! `email` is the default and the header every application already reads.
//!
//! The two Cognito-backed credentials can also carry **profile claims** — whichever OIDC
//! claims the settings file's `profile_claims` names, each in a header derived from its own name
//! ([`ProfileClaim`]), percent-encoded — so an application has a display name without
//! parsing one out of the email. Off by default, and always optional: a token that asserts
//! no such claim, and every API key, omit the header rather than send it empty. They are
//! *self-asserted* — any Cognito user edits their own profile — so they are display hints,
//! never an authorization input. The identity is, and stays, the email.
//!
//! An application must not try to read the identity itself. There is usually nothing
//! to read: the session cookie is not a JWT (it carries the email and the profile claims
//! captured at login, nothing else), and a `bbk_` key has no token at all, so decoding a
//! claim would work for exactly one of the three credentials. It would not be safe either —
//! self-signup means a valid id_token proves identity, never authorization. The headers are
//! trustworthy only in so far as the application is unreachable except through nginx.
//!
//! # Where the configuration lives
//!
//! Three places, and which one a setting is in is decided by one question: what does it cost
//! to change it?
//!
//! * **`bb-auth.env`**, read once at `ExecStart` ([`Config`]). Everything a change to costs a
//!   restart or a re-login: the listener and the worker count, the HMAC keys (the only secret
//!   in the system), the Cognito trust roots, the cookie's name and domain, and the three that
//!   *are* the lockout if they are wrong: `BB_AUTH_LOGIN_URL`, `BB_AUTH_AUTHORIZED_HOSTS`,
//!   `BB_AUTH_ORIGINAL_URL_HEADER`.
//! * **the settings file** (`BB_AUTH_SETTINGS_FILE`, [`bb_auth_core::Settings`]), re-read on
//!   SIGHUP and held in [`State::settings`]. The five that are read per request, cannot lock
//!   anybody out, and are not secret. They are in a file rather than the environment because a
//!   process cannot re-read its own environment: that, and not taste, is why the split exists.
//! * **the access file** ([`bb_auth_core::Access`]), re-read on SIGHUP: who reaches what.
//!
//! Both files are validated by the parser their editors use, both reload **fail-soft** (a
//! broken file keeps what is already live), and `--check-access` / `--check-settings` are the
//! two commands that catch either before a restart meets it.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
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
    claim_name_ok, compile_host_pattern, compile_login_url, decide, decide_api_key,
    default_settings_path, header_safe_email, login_url_for, lower_authority, now, read_access,
    read_settings, sha256_hex, Access, AccessKind, ApiKeyRecord, Decision, IdentityAttr,
    KeyDecision, ProfileClaim, Settings, Subject, UrlPattern, API_KEY_PREFIX,
};

type HmacSha256 = Hmac<Sha256>;

/// Cap on the `/auth/session` request body. Cognito id_tokens run 1–3 KB; the limit
/// is generous and exists only to bound the memory a single request can claim.
const MAX_BODY: u64 = 64 * 1024;

/// Cap on one profile-claim value captured into the session cookie, in raw UTF-8 bytes.
///
/// Cognito allows a profile attribute up to 2048 bytes; a display value beyond this one is
/// not one. Over-long values are dropped rather than truncated ([`clean_claim`]) — a
/// mangled name is worse than none, and the header is simply omitted.
///
/// It is also the per-claim term in the cookie-size budget. A claim costs at most
/// `4/3 × (2 × MAX_CLAIM_VALUE_BYTES + len(name) + 6)` bytes of base64 — the factor two
/// because JSON escaping can double a value — so ≈ 700 bytes each, against the ~4 KB a
/// browser will store. [`worst_case_cookie_bytes`] does that arithmetic at startup and
/// warns; configuring more than a handful of claims is what makes it matter.
const MAX_CLAIM_VALUE_BYTES: usize = 256;

/// Active session-cookie format tag, and the wire format it names:
///
/// ```text
/// cookie = "bb1" "." keyid "." exp "." b64url(email) "." b64url(claims_json) "." b64url(sig)
/// sig    = HMAC_SHA256("bb1." keyid "." exp "." b64url(email) "." b64url(claims_json), key[keyid])
/// ```
///
/// The field count is fixed at six. Neither the base64url alphabet nor a key id
/// ([`valid_keyid`]) contains `.`, so splitting on it is unambiguous; extra dots fold into
/// the signature element, which then fails to verify. The version tag is inside the signed
/// bytes, so no cookie can be replayed as another format.
///
/// `claims_json` is a JSON object of the profile claims the token asserted — claim name to
/// value, e.g. `{"family_name":"Byron","given_name":"Ada"}` — serialized from a
/// `BTreeMap`, hence with sorted keys. **No claims is the empty segment**, never `"{}"`.
/// Values are raw UTF-8 and are **not** lowercased: they are display values and the case is
/// theirs. They are percent-encoded only on the way out ([`ProfileClaim`]).
///
/// The blob is **self-describing** — it names its own claims — and that is the point.
/// the claim list is config, a cookie lives up to a month, and positional
/// segments would let an edit to that list silently reinterpret a live cookie's values
/// under someone else's claim name. It also means changing the list is *not* a format
/// change: old cookies keep verifying, claims dropped from the config stop being emitted
/// ([`profile_headers`]), and claims added to it simply appear at the next login.
///
/// Verification signs and checks the segment **as received** and only then parses it —
/// nothing is ever re-serialized for comparison, so no canonicalization question arises.
/// Keep it that way. (The `BTreeMap` ordering makes minting deterministic; the signature
/// does not depend on it.)
///
/// The key id is stamped into the cookie so the signing *key* can roll over with zero
/// downtime: during a rotation every accepted id still verifies, while only the active key
/// signs new cookies. That is the mechanism that must never log anyone out, and it is
/// untouched by a format change.
///
/// **This is the only format [`verify_session`] accepts**, and there is deliberately no
/// verify-only arm for any other tag: a version bump costs each user one trip through the
/// login page (the browser still holds its Cognito session, so it is a re-authentication and
/// not a re-enrolment), which is cheaper than keeping an arm, its tests and its reasoning
/// alive for every format that has ever existed. So changing the serialization, or the bytes
/// that go into `sig`, does log out every live session: bump the tag, never reuse one, expect
/// the re-auth, and do not ship it in the middle of something. [`make_session`],
/// [`verify_session`] and their tests pin the format.
const COOKIE_VERSION: &str = "bb1";

/// Response header naming the authenticated user on a `204` from `/auth/validate`.
///
/// nginx lifts it out of the `auth_request` subrequest and re-injects it into the
/// request it proxies to the application:
///
/// ```text
/// location / {
///     set $bb_url https://app.example.com$uri;   # rewrite phase, before auth_request
///     auth_request     /internal/auth-gate;
///     auth_request_set $bb_email  $upstream_http_x_auth_email;
///     auth_request_set $bb_given  $upstream_http_x_auth_given_name;   # optional …
///     auth_request_set $bb_family $upstream_http_x_auth_family_name;  # … see below
///
///     proxy_set_header X-Auth-Email       $bb_email;   # whatever name the app reads
///     proxy_set_header X-Auth-Given-Name  $bb_given;   # only where the app wants them
///     proxy_set_header X-Auth-Family-Name $bb_family;
///     proxy_set_header X-Forwarded-User   "";          # clear the names we do NOT set
///     proxy_set_header Remote-User        "";
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
///
/// The two name lines are the derived headers of the example config
/// `profile_claims: [given_name, family_name]`; a different claim list means different
/// variables, mechanically named ([`ProfileClaim`] — `custom:department` would be
/// `$upstream_http_x_auth_custom_department`). They are optional and additive: a location
/// that lifts only `$bb_email` keeps seeing exactly what it saw before. But the
/// empty-variable rule is also the *clear* — an application that trusts a profile header
/// behind a location that does not `proxy_set_header` it would be reading whatever the
/// client sent, so set them or clear them explicitly, like `X-Forwarded-User` above.
///
/// The *string* lives on [`bb_auth_core::IDENTITY_HEADER`], because `compile_identity_attrs`
/// checks its own derivation against it and `bb-auth-web` reads its administrator out of it;
/// the nginx contract above is this end of it, and stays here.
const IDENTITY_HEADER: &str = bb_auth_core::IDENTITY_HEADER;

/// Response header naming the login page on a `401` from `/auth/validate`: the
/// application's `login_url`, or `BB_AUTH_LOGIN_URL` when it declares none
/// ([`login_url_for`]).
///
/// bb-auth never redirects a gated request itself: it answers `401` and nginx decides.
/// This header is how nginx learns *which* login page, per application rather than per server
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
/// The `map` is load-bearing: an unset `$bb_login` (a location missing the
/// `auth_request_set`) turns `return 302 $bb_login?rd=…` into a *relative*
/// `Location: ?rd=…`, which sends the browser back to the gated path it just failed on.
///
/// The gate can name the login page here because a `401` happens *on* a gated URL, so the
/// application resolves. `/auth/logout` has no such luck: see [`handle_logout`].
///
/// Emitting it is safe without a per-request check: every candidate passed
/// [`compile_login_url`] at load, which requires printable ASCII.
const LOGIN_URL_HEADER: &str = "X-Auth-Login-URL";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// A cookie key id must not contain '.', otherwise `splitn(6, '.')` on a cookie
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

/// Upper bound on the session cookie's size, in bytes, for a given claim set — what the
/// startup warning is measured against.
///
/// A browser stores about 4 KB per cookie and drops the rest **silently**, which would show
/// up as a login loop rather than an error, so the arithmetic is worth doing at startup.
/// Per claim: its name, its value at [`MAX_CLAIM_VALUE_BYTES`] and doubled (JSON escaping
/// can escape every byte), plus the six bytes of JSON syntax around them — then base64.
/// Real names are nowhere near the cap; this bounds the pathological case.
fn worst_case_cookie_bytes(claims: &[ProfileClaim]) -> usize {
    // Everything outside the claims segment: the tag, a key id, an expiry, a base64
    // email and a base64 signature, with their dots. Generous and constant.
    const FIXED: usize = 256;
    if claims.is_empty() {
        return FIXED;
    }
    let json = 2 + claims
        .iter()
        .map(|c| c.claim.len() + 2 * MAX_CLAIM_VALUE_BYTES + 6)
        .sum::<usize>();
    FIXED + json.div_ceil(3) * 4
}

/// Runtime configuration, read once from the environment at startup. Every field is
/// a `BB_AUTH_*` env var; a missing required one is a fatal exit. Because it is read
/// once, a change to any of it needs `systemctl restart`, not `reload` (which re-reads
/// the access file and the settings file, and nothing else).
///
/// Read once is also the reason a setting is *here* rather than in the settings file: a
/// process cannot re-read its own environment, because systemd loads `EnvironmentFile=`
/// once, at `ExecStart`, so a `SIGHUP` handler asking `std::env::var` would be handed the
/// values it started with. What lives here is therefore everything that fails at least one
/// part of the settings file's membership rule ([`bb_auth_core::Settings`]: read per
/// request, harmless to get wrong, not a secret). The listener and the worker count are a
/// rebind; the HMAC keys are the secret; the Cognito trust roots and the cookie's name and
/// domain let nobody in or log everybody out; and `BB_AUTH_LOGIN_URL`,
/// `BB_AUTH_AUTHORIZED_HOSTS` and `BB_AUTH_ORIGINAL_URL_HEADER` *are* the lockout.
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
    /// `BB_AUTH_COOKIE_NAME`, the session cookie's name. Default `bb_session`.
    cookie_name: String,
    /// `BB_AUTH_COOKIE_DOMAIN`. `None` = a host-only cookie (per-service login); a parent
    /// domain (`.example.com`) shares one session across every service behind the gate.
    cookie_domain: Option<String>,
    /// Hosts a post-login `rd` may land on (`BB_AUTH_AUTHORIZED_HOSTS`), as globs matched
    /// against the host alone, e.g. `badbat75.com,*.badbat75.com`.
    ///
    /// This is the *only* authority for [`safe_rd`]. There is no canonical service base
    /// URL: one gate fronts several hosts, and which one is in play is decided by the
    /// caller. Enumerate the apex explicitly — `*.x.com` does not match `x.com`. Pair it
    /// with `BB_AUTH_COOKIE_DOMAIN=.<domain>` to share the session cookie across siblings.
    authorized_hosts: Vec<UrlPattern>,
    /// `BB_AUTH_LOGIN_URL`, e.g. `https://login.example.com/`. Where a logout and every
    /// rejected `rd` land, and what a `401` names in [`LOGIN_URL_HEADER`], unless the
    /// application that speaks for the URL overrides it ([`login_url_for`]). Validated by
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
        // accepted if its `aud` matches ANY of them. Unset => only `client_id`.
        // Deduplicated, order-preserving.
        let client_id = env_req("BB_AUTH_CLIENT_ID");
        let mut audiences = vec![client_id.clone()];
        for extra in env_or("BB_AUTH_AUDIENCES", "").split(',') {
            let extra = extra.trim();
            if !extra.is_empty() && !audiences.iter().any(|a| a == extra) {
                audiences.push(extra.to_string());
            }
        }

        Config {
            listen: env_or("BB_AUTH_LISTEN", "127.0.0.1:4181"),
            hmac_keys: HmacKeys { by_id, active_id },
            issuer,
            audiences,
            cookie_name: env_or("BB_AUTH_COOKIE_NAME", "bb_session"),
            cookie_domain,
            authorized_hosts,
            // The global fallback for every application that declares no `login_url`. Validated
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
    /// The access gate: the applications and their scopes, the denied veto, the roster
    /// and its API keys.
    /// Swapped wholesale on SIGHUP by `reload_access` (POSIX only, hence not linked here).
    access: RwLock<Access>,
    /// The five settings that are read per request rather than per process, swapped on the
    /// same SIGHUP and by the same rule: a reload that fails keeps what is already live.
    ///
    /// Behind a lock for exactly the reason the access table is: an operator edits the file
    /// and expects the next request to answer differently, without a restart and without
    /// anybody being logged out. See [`bb_auth_core::Settings`] for what belongs in it.
    settings: RwLock<Settings>,
    /// Paths to re-read on SIGHUP. Only the POSIX reload path needs them.
    #[cfg(unix)]
    access_path: String,
    #[cfg(unix)]
    settings_path: String,
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
            if a.apps.is_empty() {
                eprintln!(
                    "[bb-auth] WARNING: access file {path} has no applications, so every gated \
                     URL is denied to everyone"
                );
            } else if a.by_uuid.is_empty() && !a.any_authenticated_scope() {
                eprintln!(
                    "[bb-auth] WARNING: access file {path} has no users and no authenticated \
                     scope: nobody can sign in"
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

/// Initial settings load, with the same rule the access file gets: a missing, unreadable or
/// invalid file is fatal, because there is no safe default for "what does a `204` name".
///
/// The file is created by the package and edited by both editors, so its absence is somebody
/// having deleted it, not a fresh install, and starting on built-in defaults would mean an
/// installation quietly emitting fewer headers than it was configured to.
fn load_settings(path: &str) -> Settings {
    match read_settings(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bb-auth] FATAL: cannot read settings file: {e}");
            eprintln!(
                "[bb-auth]   Check it with `bb-auth --check-settings {path}`, or write a fresh \
                 one with `bb-auth-adm settings init -f {path}`."
            );
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
            let (u, k) = (new.by_uuid.len(), new.by_key_hash.len());
            let a = new.apps.len();
            let s: usize = new.apps.iter().map(|x| x.scopes.len()).sum();
            let d = new.denied_users.len() + new.denied_identifiers.len();
            *state.access.write().unwrap() = new; // fail-safe: atomic swap
            eprintln!(
                "[bb-auth] access reloaded (SIGHUP): {a} applications, {s} scopes, {u} users, \
                 {k} api keys, {d} denied"
            );
        }
        Err(e) => eprintln!("[bb-auth] access reload FAILED, keeping current set: {e}"),
    }
}

/// Hot-reload the settings from disk (SIGHUP), by exactly the access table's rule: swap on
/// success, keep what is live on failure.
///
/// Fail-soft is what makes the whole arrangement safe to hand to a GUI. A settings file that
/// does not compile is a reload the gate declines, not a gate that stops answering, so the
/// worst an editor can do between two saves is leave the previous values in force, and say so
/// in the journal.
#[cfg(unix)]
fn reload_settings(state: &State) {
    match read_settings(&state.settings_path) {
        Ok(new) => {
            let c = new.profile_claims.len();
            let a = new
                .identity_attrs
                .iter()
                .map(|x| x.attr.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let ttl = new.session_ttl;
            *state.settings.write().unwrap() = new; // fail-safe: atomic swap
            eprintln!(
                "[bb-auth] settings reloaded (SIGHUP): identity={a}, {c} profile claims, \
                 session_ttl={ttl}s"
            );
        }
        Err(e) => eprintln!("[bb-auth] settings reload FAILED, keeping current ones: {e}"),
    }
}

/// Spawn the SIGHUP -> reload thread, for both files. SIGHUP is POSIX-only, so this is a
/// no-op on non-unix hosts (where the tables simply reload across a restart).
///
/// One signal for two files, because there is one thing an operator wants when they send it:
/// make what is on disk live. Each file is reloaded independently and each failure is its own
/// line, so a broken settings file cannot cost an access-file edit its reload.
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
            reload_settings(&sig_state);
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
    // The timeout is a property of the agent, not of the request, so it is built here
    // rather than set per call: one fetch, one agent, no connection pool to outlive it.
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .new_agent();
    let body = agent
        .get(&url)
        .call()
        .map_err(|e| format!("jwks GET {url}: {e}"))?
        .body_mut()
        .read_to_string()
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

/// What a token-backed credential resolves to: the authorized email, plus whichever
/// configured profile claims the token asserted — they ride along to
/// [`respond_authorized`] and into the session cookie.
///
/// The email is the identity — it is what every grant decision is made about, and the only
/// field the access file has an opinion on. The claims are decoration: optional,
/// self-asserted, and never an input to [`authorize`]. Keeping them out of the decision is
/// what keeps `bb-auth-adm can` answering the same question the gate does.
///
/// The map is keyed by claim name, not by header, and holds only claims that were
/// configured *when it was built* — a cookie outlives a config change, so
/// [`profile_headers`] decides what to emit against the current [`Config`], never this.
/// `BTreeMap` for a deterministic serialization ([`COOKIE_VERSION`]) and free equality.
#[derive(Debug, PartialEq, Eq)]
struct UserIdentity {
    email: String,
    claims: BTreeMap<String, String>,
}

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
    /// Every other claim in the token, by name — where the configured profile claims are
    /// looked up ([`bb_auth_core::GateSettings::profile_claims`]).
    ///
    /// Values stay raw `serde_json::Value`s, not `String`s, for the same reason
    /// `email_verified` above does: a federated IdP whose attribute mapping emits a
    /// non-string must cost the user that *claim*, never their login — a type error here
    /// would fail `decode` and reject the whole token. [`clean_claim`] drops what it
    /// cannot use.
    ///
    /// `flatten` collects only what no typed field above already took, which is exactly
    /// why those four names are in [`bb_auth_core::RESERVED_CLAIMS`]: configuring one would look up a
    /// key that can never be here.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
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

/// Whether a profile-claim value is one bb-auth would keep: non-empty, at most
/// [`MAX_CLAIM_VALUE_BYTES`] raw UTF-8 bytes, no control character, and already trimmed.
///
/// Shared by [`clean_claim`] (capture, where the trim test is vacuous) and
/// [`decode_claims_segment`] (a cookie's claim blob, where it is not): a value that
/// verifies but could not have been minted fails the cookie.
fn claim_value_ok(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_CLAIM_VALUE_BYTES
        && !v.chars().any(char::is_control)
        && v.trim() == v
}

/// Capture hygiene for a profile claim — the one point a claim value enters bb-auth,
/// exactly as [`header_safe_email`] in [`validate_id_token`] is for an email out of a
/// claim. The cookie then inherits whatever this returns, under the HMAC.
///
/// `None` — the header is simply omitted — when the claim is not a string or fails
/// [`claim_value_ok`]. Over-long values are dropped, not truncated: a mangled name is worse
/// than none. Never lowercased, unlike the email — a name's case belongs to its owner.
///
/// Emission safety does **not** rest on this: [`pct_encode`] makes any bytes header-safe,
/// including the control characters rejected here. This bounds quality and cookie size.
fn clean_claim(v: &serde_json::Value) -> Option<String> {
    let t = v.as_str()?.trim();
    claim_value_ok(t).then(|| t.to_string())
}

/// Fully validate a Cognito id_token, returning the verified identity: the lowercased
/// email, plus whichever [`bb_auth_core::GateSettings::profile_claims`] the token asserts ([`clean_claim`]).
///
/// Enforces all of: `alg == RS256`, a known `kid`, the signature, `exp` (required,
/// 60 s leeway), `iss`, `aud` against [`Config::audiences`], `token_use == "id"`,
/// [`header_safe_email`], and a truthy `email_verified`. The single sanctioned exception
/// to the last one is [`unverified_social_ok`].
///
/// The profile claims are subject to none of that. They are not an identity and authorize
/// nothing, they need no `header_safe_email` (the encoder at emission is what makes them
/// safe), and `allow_unverified_social` does not change their standing — a profile
/// attribute is self-asserted on *every* token, whatever the email's verification status.
fn validate_id_token(token: &str, state: &State) -> Result<UserIdentity, String> {
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
    // An `authenticated` scope emits identities that appear in no table, so `read_access`
    // never sees this email. It goes into IDENTITY_HEADER and, via `make_session`, into
    // the cookie — a CR/LF here would be a response-splitting gadget. `{email:?}` escapes
    // the very bytes being rejected, so a crafted token cannot forge a log line either.
    if !header_safe_email(&email) {
        return Err(format!("token email is not printable ASCII: {email:?}"));
    }
    // One read of the live settings for the whole of this token: the relaxation and the claim
    // list are one operator decision, and a reload landing between the two halves would apply
    // half of it.
    let settings = state.settings.read().unwrap();
    if !email_verified_true(&c.email_verified) {
        // Strict by default. The only exception is a social login whose email
        // Cognito couldn't verify itself — and only when explicitly enabled.
        if !unverified_social_ok(
            settings.allow_unverified_social,
            &settings.social_providers,
            &c.identities,
        ) {
            return Err("email not verified".into());
        }
        eprintln!(
            "[bb-auth] accepting unverified email via social login [{}]: {email}",
            social_provider_names(&c.identities)
        );
    }
    // Whatever the operator asked for, and only that: an unconfigured claim is never
    // looked at, let alone carried.
    let mut claims = BTreeMap::new();
    for pc in &settings.profile_claims {
        if let Some(v) = c.extra.get(&pc.claim).and_then(clean_claim) {
            claims.insert(pc.claim.clone(), v);
        }
    }
    Ok(UserIdentity { email, claims })
}

// ---------------------------------------------------------------------------
// Session cookie (HMAC-signed) — wire format on COOKIE_VERSION
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

/// Cookie payload tail: enforce expiry and decode + lower-case the email segment.
fn finish_session(exp: u64, eb: &str) -> Option<String> {
    if exp <= now() {
        return None;
    }
    let email = String::from_utf8(URL_SAFE_NO_PAD.decode(eb).ok()?).ok()?;
    Some(email.to_ascii_lowercase())
}

/// Decode the profile-claims segment of a [`COOKIE_VERSION`] cookie.
///
/// An empty segment is an empty map: the credential carried no claim, which is the default
/// case. Anything else must be a JSON object of strings that this gate could itself have
/// minted — every key passing [`claim_name_ok`] and every value [`claim_value_ok`], and
/// never the object `{}` (which we encode as the empty segment). `None` on any other
/// shape, on invalid base64url, or on bytes that are not UTF-8, and that fails the **whole
/// cookie**. A signature that verifies over bytes we could not have minted is either a bug
/// here or a compromised key, and both call for fail-closed — the same posture
/// [`finish_session`] takes on the email.
///
/// What it deliberately does *not* check is the current configuration: a cookie legitimately
/// outlives an edit to the claim list and may carry a claim no longer listed.
/// Filtering to the live config is emission's job ([`profile_headers`]), not verification's.
fn decode_claims_segment(seg: &str) -> Option<BTreeMap<String, String>> {
    if seg.is_empty() {
        return Some(BTreeMap::new());
    }
    let raw = URL_SAFE_NO_PAD.decode(seg).ok()?;
    // Any non-object, or a value that is not a string, fails here.
    let claims: BTreeMap<String, String> = serde_json::from_slice(&raw).ok()?;
    if claims.is_empty() {
        return None;
    }
    claims
        .iter()
        .all(|(k, v)| claim_name_ok(k) && claim_value_ok(v))
        .then_some(claims)
}

/// Mint a session cookie for `ident`, valid for `ttl` seconds, signed with the active
/// key in the [`COOKIE_VERSION`] format. An identity with no profile claims gets the
/// empty segment, so the field count never varies.
fn make_session(ident: &UserIdentity, ttl: u64, keys: &HmacKeys) -> String {
    let exp = now() + ttl;
    let b64 = |s: &str| URL_SAFE_NO_PAD.encode(s.as_bytes());
    let eb = b64(&ident.email);
    let cb = if ident.claims.is_empty() {
        String::new()
    } else {
        b64(&serde_json::to_string(&ident.claims).expect("a map of strings serializes"))
    };
    let msg = format!("{COOKIE_VERSION}.{}.{exp}.{eb}.{cb}", keys.active_id);
    let sig = sign(keys.active(), &msg);
    format!("{msg}.{sig}")
}

/// Verify a session cookie — version, key id, signature (constant-time) and expiry —
/// returning the identity it carries, with the email lowercased. `None` on anything that
/// does not verify.
///
/// The signature is checked over the segments **as received**, before the claims blob is
/// parsed; nothing is re-serialized to compare. [`COOKIE_VERSION`] is the **only** format
/// accepted: a cookie carrying any other tag is not distinguished from junk, and its holder
/// is sent back through the login page. See that constant for why exactly one is accepted.
fn verify_session(val: &str, keys: &HmacKeys) -> Option<UserIdentity> {
    let parts: Vec<&str> = val.splitn(6, '.').collect();
    match parts.as_slice() {
        [v, keyid, exp_s, eb, cb, sig] if *v == COOKIE_VERSION => {
            let key = keys.by_id.get(*keyid)?;
            let exp: u64 = exp_s.parse().ok()?;
            let msg = format!("{v}.{keyid}.{exp_s}.{eb}.{cb}");
            if !sig_matches(key, &msg, sig) {
                return None;
            }
            let email = finish_session(exp, eb)?;
            Some(UserIdentity {
                email,
                claims: decode_claims_segment(cb)?,
            })
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

/// Percent-encode `s` per RFC 3986: every byte outside the unreserved set
/// `[A-Za-z0-9-._~]` becomes `%XX` with uppercase hex. That includes the space (`%20`,
/// *not* `+`) and every byte of a multibyte UTF-8 character, so `Niccolò` comes out as
/// `Niccol%C3%B2` and `%` itself as `%25`.
///
/// The output is printable ASCII for **any** input, control bytes and all. That
/// construction is what lets [`respond_authorized`] pass a claim value straight to [`h`] —
/// which panics on a non-ASCII value, in a process built with `panic = "abort"` — without
/// validating anything per request. See [`ProfileClaim`].
///
/// Hand-rolled on purpose: this is the whole of RFC 3986's encoding rule, and a crate for
/// it would be a dependency to audit and cross-compile for no gain. `form_urlencoded` is
/// already in the tree but is the wrong grammar — it emits `+` for a space.
fn pct_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// Render a `Set-Cookie` value. `max_age = 0` expires the cookie (logout). Always
/// `HttpOnly` + `Secure` + `SameSite=Lax`, so JS cannot read it and it still rides
/// top-level navigations back to the service.
///
/// Minting and clearing go through this one function, which is what makes a **single logout
/// endpoint serve every vhost**: a browser matches a `Set-Cookie` against the cookie it
/// stored by `(name, Domain, Path)`, so the expiring cookie has to name the same triple the
/// minted one did. It does, because both are built here. With `BB_AUTH_COOKIE_DOMAIN` set
/// to a parent domain the session is one cookie for the whole estate, and clearing it from
/// any host under that domain signs the browser out of all of them: see [`handle_logout`].
/// Give the clear a different `Domain` or `Path` than the mint and it stops matching, the
/// browser keeps the cookie it had, and the logout silently succeeds at nothing.
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
/// Matching is the same [`bb_auth_core::glob_match`] a scope's URL patterns use, so
/// `*.badbat75.com` accepts `mcp.badbat75.com` but neither `evilbadbat75.com` nor
/// `badbat75.com.evil.com` — the literal dot in the pattern is what rules those out. It does
/// *not* accept the bare apex `badbat75.com`; list it explicitly if you want it.
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

/// The profile headers a `204` should carry: one per configured [`ProfileClaim`] the
/// identity actually has, value percent-encoded, in configuration order.
///
/// **The live configuration is the authority, not the credential.** A cookie outlives an
/// edit to the claim list, so it may carry a claim that has since been removed —
/// which emits nothing — or lack one that has since been added, which omits that header
/// until its holder next signs in. Emitting a header for a claim nobody configured would
/// hand the application a value no current config accounts for.
///
/// An absent claim omits its header entirely: nginx reads an empty variable as "no header",
/// so present-and-empty would be a distinction the application cannot make. That is why
/// this returns only what it found, and why an empty value cannot reach it
/// ([`claim_value_ok`] rejects one at both capture and cookie-verification).
fn profile_headers<'a>(
    claims: &'a [ProfileClaim],
    carried: &BTreeMap<String, String>,
) -> Vec<(&'a str, String)> {
    claims
        .iter()
        .filter_map(|pc| {
            carried
                .get(&pc.claim)
                .map(|v| (pc.header.as_str(), pct_encode(v)))
        })
        .collect()
}

/// The identity a granted request hands downstream: what the access file decided this
/// request *is*, resolved once, so every configured [`IdentityAttr`] reads off one value.
///
/// `uuid` is `None` for an identity granted by an `authenticated` scope, which is in no
/// roster row at all: that is the whole point of such a scope, and enrolling them is the
/// application's business. `emails` then holds the single identifier the credential
/// carried, so `X-Auth-Email` says the same thing it always did.
struct Authorized {
    uuid: Option<String>,
    emails: Vec<String>,
    claims: BTreeMap<String, String>,
}

/// What a granted request carries. An `anonymous` scope authorizes with **no identity at
/// all**, and the `204` then names nobody: no identity header, no profile header, nothing
/// for an application to key on. That is not an omission, it is what the scope says.
enum Granted {
    Anonymous,
    Identity(Authorized),
}

/// The identity headers to emit, in the operator's configured order.
///
/// Multiple values are joined with a **space**, which is unambiguous by construction: every
/// identifier passed [`header_safe_email`], which requires printable ASCII, and a space is
/// not printable ASCII. An attribute with no value **omits its header** rather than sending
/// an empty one, exactly as a profile claim does, because nginx cannot tell an empty
/// variable from an absent one.
fn identity_headers<'a>(attrs: &'a [IdentityAttr], who: &Authorized) -> Vec<(&'a str, String)> {
    attrs
        .iter()
        .filter_map(|a| {
            let value = match a.attr.as_str() {
                "uuid" => who.uuid.clone()?,
                "email" if !who.emails.is_empty() => who.emails.join(" "),
                _ => return None,
            };
            Some((a.header.as_str(), value))
        })
        .collect()
}

/// Respond `204` to an authorized `auth_request`, naming the identity in the configured
/// [`IdentityAttr`] headers ([`identity_headers`]) and, for each configured
/// [`ProfileClaim`] the credential carried, its value in the header derived from that
/// claim ([`profile_headers`]).
///
/// An `anonymous` scope authorizes with no identity at all, so the `204` carries no header
/// whatsoever. Everything below is about the case where there *is* an identity.
///
/// Every identifier emitted passed [`header_safe_email`], by one of two disjoint routes,
/// so [`h`] cannot panic here:
///
/// * it came off a roster row, which the API-key path reads through its owner's uuid and
///   the login path reads through [`Access::uuid_of`](bb_auth_core::Access::uuid_of).
///   Every identifier on a row was checked by [`read_access`] at load, and one that failed
///   was skipped there.
/// * or it came out of [`validate_id_token`], which checks it there: the only route for an
///   identity granted by an `authenticated` scope, which is in no table to have been
///   checked at load. The cookie carries it back unchanged under the HMAC.
///
/// A uuid needs no such argument, being hex and dashes by [`well_formed_uuid`](bb_auth_core::well_formed_uuid).
/// The first assert pins the lot, and it is what stands between a fourth credential that
/// skips both routes and a panicking worker thread. It admits the space that joins a
/// multi-valued attribute, which is the one byte the identifiers themselves can never
/// contain.
///
/// The profile claims need no such argument either: their header names are derived from an
/// `[A-Za-z0-9_:-]` claim name and their values go through [`pct_encode`], which emits
/// printable ASCII whatever it is handed — so safety is a property of the construction, not
/// of where the value came from. The second assert pins *that*: it is what would catch a
/// later change emitting a raw value, or a header name that stopped being a token.
fn respond_authorized(req: Request, granted: &Granted, settings: &Settings) {
    // The derivation lives in the library; the wire name every nginx snippet in this repo
    // clears literally is [`IDENTITY_HEADER`], here. This is where the two are held against
    // each other, so a change to the derivation cannot rename the header in silence.
    debug_assert!(
        settings
            .identity_attrs
            .iter()
            .all(|a| a.attr != "email" || a.header == IDENTITY_HEADER),
        "the email attribute must derive {IDENTITY_HEADER}"
    );
    let mut resp = Response::empty(StatusCode(204));
    if let Granted::Identity(who) = granted {
        for (name, value) in identity_headers(&settings.identity_attrs, who) {
            debug_assert!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                "identity header must be printable: {name:?}: {value:?}"
            );
            resp = resp.with_header(h(name, &value));
        }
        for (name, enc) in profile_headers(&settings.profile_claims, &who.claims) {
            debug_assert!(
                !enc.is_empty()
                    && enc.bytes().all(|b| b.is_ascii_graphic())
                    && name.bytes().all(|b| b.is_ascii_graphic()),
                "encoded claim must be non-empty printable ASCII: {name:?}: {enc:?}"
            );
            resp = resp.with_header(h(name, &enc));
        }
    }
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
/// the application downstream sees. It is also the only path with no token to decode, and
/// so the only one that can never carry a profile claim: every [`ProfileClaim`] header is
/// omitted for every API key, whatever the configuration.
///
/// An `authenticated` scope does **not** rescue an unknown key. That grant is for
/// identities Cognito vouches for, and Cognito vouches for no static key of ours: an
/// unknown key is not an un-enrolled user, it is nobody, and there would be no identity to
/// hand back.
fn bearer_apikey<'a>(access: &'a Access, token: &str) -> Option<&'a ApiKeyRecord> {
    match decide_api_key(access, &sha256_hex(token), now()) {
        KeyDecision::Granted(rec) => Some(rec),
        KeyDecision::Unknown => {
            eprintln!("[bb-auth] api key rejected: unknown");
            None
        }
        KeyDecision::OwnerDenied(rec) => {
            eprintln!(
                "[bb-auth] api key denied: owner is denied [{} {}]",
                rec.uuid, rec.key_id
            );
            None
        }
        KeyDecision::Expired(rec) => {
            eprintln!(
                "[bb-auth] api key rejected: expired [{} {}]",
                rec.uuid, rec.key_id
            );
            None
        }
    }
}

/// Ask the access file whether this subject may have this URL, and say why not.
///
/// The rule is [`decide`], and it lives in the library because `bb-auth-adm can` asks the
/// same question of the same code. What stays here is what only a request has: the wall
/// clock, and the log line naming the reason. Keep it that thin, or the two stop agreeing.
///
/// `who` names the credential in the log: an identifier for a login, a key id and its
/// owner for a `bbk_`. It is only ever logged, never matched on.
fn authorize(access: &Access, subject: &Subject, url: Option<&str>, who: &str) -> bool {
    let at = || url.unwrap_or("<none>");
    match decide(access, subject, url) {
        // An anonymous scope is the steady state of a health endpoint, so it is not
        // logged: a line per poll would bury everything that matters.
        Decision::Anonymous { .. } => true,
        Decision::Granted { app, scope } => {
            // The one grant worth a line: somebody Cognito vouches for, who is in no
            // roster row, just walked in. That is what an `authenticated` scope is for,
            // and an operator should be able to see it happening.
            if let Subject::Identifier(id) = subject {
                if access.uuid_of(id).is_none() {
                    eprintln!(
                        "[bb-auth] granted via {app}/{scope} to an un-enrolled identity: {id}"
                    );
                }
            }
            true
        }
        Decision::Vetoed => {
            eprintln!("[bb-auth] denied: {who} is on the denied list");
            false
        }
        Decision::Excluded { app, scope } => {
            eprintln!("[bb-auth] denied: {app}/{scope} excludes {who}");
            false
        }
        Decision::NoApplication => {
            eprintln!("[bb-auth] denied: no application covers {} [{who}]", at());
            false
        }
        Decision::NoScope { app } => {
            eprintln!(
                "[bb-auth] denied: application '{app}' has no scope for {} [{who}]",
                at()
            );
            false
        }
        Decision::Unauthenticated { app, scope } => {
            eprintln!("[bb-auth] denied: {app}/{scope} needs an identity");
            false
        }
        Decision::CredentialRefused { app, scope } => {
            eprintln!("[bb-auth] denied: {app}/{scope} does not admit this credential [{who}]");
            false
        }
        Decision::NotEnrolled { app, scope } => {
            eprintln!("[bb-auth] denied: {who} is in no users entry [{app}/{scope}]");
            false
        }
        Decision::NotMember { app, scope } => {
            eprintln!("[bb-auth] denied: {app}/{scope} does not list {who}");
            false
        }
        Decision::KeyOutOfScope { app, scope } => {
            eprintln!("[bb-auth] denied: this key may not exercise {app}/{scope} [{who}]");
            false
        }
    }
}

/// The identity an API key acts as: its owner's row. A key carries no token, so it can
/// never bring a profile claim with it, whatever the configuration.
fn key_identity(access: &Access, rec: &ApiKeyRecord) -> Authorized {
    Authorized {
        uuid: Some(rec.uuid.clone()),
        emails: access
            .by_uuid
            .get(&rec.uuid)
            .map(|u| u.emails.clone())
            .unwrap_or_default(),
        claims: BTreeMap::new(),
    }
}

/// Authorize a Cognito-backed credential (the id_token bearer or the session cookie) and
/// assemble what a grant hands downstream.
///
/// The identifier the credential carried is resolved against the roster **here**, and not
/// inside [`decide`]: the access file has no opinion about profile claims, so nothing about
/// them may reach the decision, or `bb-auth-adm can` would stop answering the same question
/// as the gate. This is re-assembly, not policy.
///
/// An identity in no roster row is not an error: an `authenticated` scope exists precisely
/// to admit one. It simply has no `uuid` to hand downstream, and the identifier it signed
/// in with is the only email there is.
fn authorize_login(access: &Access, ident: UserIdentity, url: Option<&str>) -> Option<Granted> {
    let UserIdentity { email, claims } = ident;
    if !authorize(access, &Subject::Identifier(&email), url, &email) {
        return None;
    }
    let uuid = access.uuid_of(&email).map(str::to_string);
    let emails = match &uuid {
        Some(u) => access.by_uuid[u].emails.clone(),
        None => vec![email],
    };
    Some(Granted::Identity(Authorized {
        uuid,
        emails,
        claims,
    }))
}

/// `GET /auth/validate` — the nginx `auth_request` endpoint. 204 plus the authorized
/// user in [`IDENTITY_HEADER`] if any credential authorizes this request, else 401 plus
/// this area's login page in [`LOGIN_URL_HEADER`]. Never issues a cookie, and never
/// redirects: nginx turns the 401 into a redirect, which is why the header exists.
///
/// Credentials are tried in the order documented on the crate: `bbk_` API key, raw
/// id_token, then the session cookie. A key must resolve to a user in the roster and put
/// the URL inside its [`UrlScope`](bb_auth_core::UrlScope); the two Cognito credentials go through [`authorize`],
/// which also honours `anonymous` and `authenticated` scopes and the `denied` veto.
/// Whichever one wins, the
/// identity handed back is an email — plus, for the two token-backed credentials, whatever
/// configured profile claims came with it. See [`respond_authorized`].
fn handle_validate(req: Request, state: &State) {
    let cfg = &state.cfg;
    // Original request URL (for application resolution and per-scope URL matching),
    // captured now as an owned value so the request can be consumed when we respond.
    let url = original_url(&req, cfg);

    // Bearer path: programmatic clients (e.g. MCP) present `Authorization: Bearer
    // <cred>`. A `bbk_` credential is a static API key resolved against the access
    // table; anything else is a raw Cognito id_token validated exactly like
    // /auth/session, then authorized like a cookie. A failed bearer falls through to the
    // cookie check so a stray Authorization header never blocks an otherwise-valid cookie.
    if let Some(token) = header_value(&req, "Authorization").and_then(parse_bearer) {
        let granted = if token.starts_with(API_KEY_PREFIX) {
            // A key acts as its user and carries no token, so no claims come with it.
            let access = state.access.read().unwrap();
            bearer_apikey(&access, token).and_then(|rec| {
                let who = format!("key '{}' of {}", rec.key_id, rec.uuid);
                authorize(&access, &Subject::Key(rec), url.as_deref(), &who)
                    .then(|| Granted::Identity(key_identity(&access, rec)))
            })
        } else {
            match validate_id_token(token, state) {
                Ok(ident) => authorize_login(&state.access.read().unwrap(), ident, url.as_deref()),
                Err(e) => {
                    eprintln!("[bb-auth] bearer rejected: {e}");
                    None
                }
            }
        };
        if let Some(granted) = granted {
            respond_authorized(req, &granted, &state.settings.read().unwrap());
            return;
        }
    }

    let granted = header_value(&req, "Cookie")
        .and_then(|c| cookie_value(c, &cfg.cookie_name).map(str::to_string))
        .and_then(|v| verify_session(&v, &cfg.hmac_keys))
        .and_then(|ident| authorize_login(&state.access.read().unwrap(), ident, url.as_deref()));
    if let Some(granted) = granted {
        respond_authorized(req, &granted, &state.settings.read().unwrap());
        return;
    }

    // No credential authorized this request. An `anonymous` scope grants anyway, to
    // anybody, which is what it is for. Asked through [`decide`] rather than [`authorize`]
    // so the refusal is not logged twice: a request with no credential at all is the
    // ordinary case on a gated URL, not an event.
    let (anonymous, login) = {
        let access = state.access.read().unwrap();
        (
            decide(&access, &Subject::Anonymous, url.as_deref()).granted(),
            // Which login page nginx should send them to. Resolved from the application
            // even though nothing granted: `login_url` says where this area's users sign
            // in, not who may enter.
            login_url_for(&access, &cfg.login_url, url.as_deref()),
        )
    };
    if anonymous {
        respond_authorized(req, &Granted::Anonymous, &state.settings.read().unwrap());
    } else {
        respond_unauthorized(req, &login)
    }
}

/// `POST /auth/session` — exchange a browser-obtained `id_token` for a session cookie,
/// then `302` to `rd`.
///
/// 400 on a missing token, 401 on an invalid one, 403 when the verified email has nowhere
/// it could possibly go. The redirect target is always laundered through [`safe_rd`].
///
/// This is also the only moment a profile claim is readable: the cookie carries whatever
/// the token asserted and the config asked for ([`make_session`]), which is what lets a
/// later `/auth/validate` name the person with no token in hand. The log line stays
/// email-only — a name is PII the log does not need.
///
/// The cookie is identity, not authorization: it grants nothing on its own, and every
/// request it accompanies is re-authorized by [`handle_validate`]. So the 403 here is a
/// courtesy — it tells someone at the login page that they are not enrolled, rather than
/// letting them bounce off a 401 later. It has to soften once any `authenticated` scope
/// exists, because then an un-enrolled identity *does* have somewhere to go and refusing
/// the cookie would make that area unreachable from a browser. Guessing at `rd` instead
/// would be worse: it is the post-login destination, not the URL that triggered the login,
/// and [`safe_rd`] may already have replaced it with the login page.
fn handle_session(mut req: Request, state: &State) {
    let cfg = &state.cfg;

    // Which host this login is happening on, and hence which application's login page an error
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

    let ident = match validate_id_token(id_token, state) {
        Ok(i) => i,
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
            access.vetoes_identifier(&ident.email),
            access.uuid_of(&ident.email).is_some(),
            access.any_authenticated_scope(),
        )
    };
    if vetoed || !(enrolled || any_open) {
        let why = if vetoed {
            "denied"
        } else {
            "not in users table"
        };
        // Profile claims are never logged: they are PII the log line does not need, and
        // the email already identifies it.
        eprintln!("[bb-auth] session denied: {} {why}", ident.email);
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
    // The lifetime the cookie is minted with is read now, not at startup: an edit to it
    // applies to sessions from here on and to no cookie already in a browser, which is what
    // keeps changing it out of the logout business.
    let ttl = state.settings.read().unwrap().session_ttl;
    let cookie = build_cookie(cfg, &make_session(&ident, ttl, &cfg.hmac_keys), ttl as i64);
    eprintln!("[bb-auth] session granted: {} -> {rd}", ident.email);
    respond_redirect(req, &rd, Some(&cookie));
}

/// `GET /auth/logout[?rd=…]` — expire the session cookie and `302` away.
///
/// Clears the bb-auth cookie only; the Cognito refresh token the login page may hold is
/// out of scope. A cross-site navigation is ignored (CSRF logout).
///
/// **Where it lands is the caller's choice, not an application's.** A logout happens *at*
/// `/auth/logout`, which lies inside no application's area, so the gate cannot tell which
/// one you are leaving and a per-area landing page would have nothing to resolve against.
/// (Contrast [`LOGIN_URL_HEADER`]: a `401` happens *on* a gated URL, so the application
/// resolves.) The one party that does know is whoever wrote the logout link, so they say it:
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
///
/// **One endpoint is enough for every vhost**, which is worth knowing before wiring this
/// into nginx once per service. Nothing here reads the request's host: the handler expires
/// a cookie and redirects, so under a `BB_AUTH_COOKIE_DOMAIN` shared by the whole estate
/// the clear applies to all of it ([`build_cookie`]) and one mounted location does the job
/// for every service behind the gate, with each `Sign out` link naming it absolutely. Two
/// conditions, both structural. The location must not itself be gated: an `auth_request` on
/// it would answer a logged-out visitor with the login page instead of clearing anything.
/// And the link must stay **same-site**, because the CSRF guard above ignores a cross-site
/// navigation, so a service on a different registrable domain than the endpoint is not
/// covered by it and keeps its own.
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

/// `bb-auth --check-access <file>`: parse an access file with the real parser and exit
/// 0 (with a summary) or 1 (with the error). Reads no env and touches no network, so
/// a deploy can validate the file that is *about* to go live: a rejected scope, or an
/// unknown field anywhere in the application tree, is a fatal startup error, and with
/// `Restart=on-failure` that would be a boot loop.
fn check_access(path: &str) -> ! {
    match read_access(path) {
        Ok(a) => {
            let scopes: usize = a.apps.iter().map(|x| x.scopes.len()).sum();
            println!(
                "[bb-auth] {path}: OK: {} applications, {scopes} scopes, {} users, {} api keys, \
                 {} denied",
                a.apps.len(),
                a.by_uuid.len(),
                a.by_key_hash.len(),
                a.denied_users.len() + a.denied_identifiers.len()
            );
            // The two kinds of scope that grant without being listed anywhere are the ones
            // worth printing: they are what an operator most often did not mean to leave
            // open, and they are invisible in a roster.
            let open = |kind: AccessKind| -> Vec<String> {
                a.apps
                    .iter()
                    .flat_map(|x| x.scopes.iter().map(move |s| (x, s)))
                    .filter(|(_, s)| s.access == kind)
                    .map(|(x, s)| format!("{}/{}", x.name, s.name))
                    .collect()
            };
            for (kind, what) in [
                (AccessKind::Anonymous, "anonymous (no credential at all)"),
                (
                    AccessKind::Authenticated,
                    "authenticated (any identity Cognito vouches for, enrolled or not)",
                ),
            ] {
                let names = open(kind);
                if !names.is_empty() {
                    println!("[bb-auth] {path}: {what}: {}", names.join(", "));
                }
            }
            // The area every gated URL must fall inside, so an operator can compare it
            // with what nginx actually gates.
            for app in &a.apps {
                println!(
                    "[bb-auth] {path}: '{}' owns {}",
                    app.name,
                    app.base.join(", ")
                );
            }
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[bb-auth] INVALID {path}: {e}");
            std::process::exit(1);
        }
    }
}

/// Validate a settings file with the parser both services use, print what it says, exit 0/1.
///
/// The same job `--check-access` does for the other file, and it earns its place for a
/// narrower reason: a settings file the gate refuses only costs a *reload* while the service
/// is running, but the next restart meets it, and a restart that fails under
/// `Restart=on-failure` is a boot loop. `scripts/deploy.sh` runs this before it restarts
/// anything.
///
/// It reads no env and needs no config, exactly as `--check-access` does, so it is runnable
/// on a workstation against a file that is going nowhere near a host yet.
fn check_settings(path: &str) -> ! {
    match read_settings(path) {
        Ok(s) => {
            println!(
                "[bb-auth] {path}: OK: identity {}, {} profile claim(s), session_ttl {}s",
                s.identity_attrs
                    .iter()
                    .map(|a| format!("{} ({})", a.attr, a.header))
                    .collect::<Vec<_>>()
                    .join(", "),
                s.profile_claims.len(),
                s.session_ttl
            );
            for c in &s.profile_claims {
                println!("[bb-auth] {path}: claim '{}' -> {}", c.claim, c.header);
            }
            if s.allow_unverified_social {
                let scope = match &s.social_providers {
                    Some(p) => p.join(", "),
                    None => "any provider".to_string(),
                };
                println!(
                    "[bb-auth] {path}: accepting unverified emails for social logins [{scope}]"
                );
            }
            // Named, not counted: this list is the GUI's whole door, and an operator reading
            // a check should see whether their own address is on it.
            println!(
                "[bb-auth] {path}: bb-auth-web administrators: {}",
                match s.admins.len() {
                    0 => "(none: bb-auth-web will refuse to serve)".to_string(),
                    _ => s.admins.join(", "),
                }
            );
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[bb-auth] INVALID {path}: {e}");
            std::process::exit(1);
        }
    }
}

/// Parse argv (`--check-access`, `--check-settings`), build the config, load both files,
/// prime the JWKS, then serve forever on a fixed pool of blocking worker threads.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = args.first().map(String::as_str);
    match flag {
        Some(f @ ("--check-access" | "--check-settings")) => match args.get(1) {
            Some(p) if f == "--check-access" => check_access(p),
            Some(p) => check_settings(p),
            None => {
                eprintln!("usage: bb-auth {f} <file.json>");
                std::process::exit(2);
            }
        },
        Some(other) => {
            eprintln!(
                "[bb-auth] unknown argument '{other}' (only --check-access and --check-settings \
                 are accepted)"
            );
            std::process::exit(2);
        }
        None => {}
    }

    let cfg = Config::from_env();
    let access_path = env_req("BB_AUTH_ACCESS_FILE");
    let access = load_access(&access_path);
    // Optional, and defaulted from the access file's own directory: see
    // `bb_auth_core::default_settings_path` for why making a second variable *required*
    // would be a boot loop waiting on an env file nobody had a reason to edit.
    let settings_path = std::env::var("BB_AUTH_SETTINGS_FILE")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| default_settings_path(&access_path));
    let settings = load_settings(&settings_path);

    let initial = fetch_jwks(&cfg.issuer).unwrap_or_else(|e| {
        eprintln!("[bb-auth] FATAL: initial JWKS fetch failed: {e}");
        std::process::exit(1);
    });

    let listen = cfg.listen.clone();
    let workers = cfg.workers;
    let user_n = access.by_uuid.len();
    let key_n = access.by_key_hash.len();
    let app_n = access.apps.len();
    let scope_n: usize = access.apps.iter().map(|a| a.scopes.len()).sum();
    let denied_n = access.denied_users.len() + access.denied_identifiers.len();
    // The scopes that grant without listing anybody: what an operator most needs to see
    // once, at startup, because no roster shows them.
    let open_scopes: Vec<String> = access
        .apps
        .iter()
        .flat_map(|a| a.scopes.iter().map(move |s| (a, s)))
        .filter(|(_, s)| s.access != AccessKind::Restricted)
        .map(|(a, s)| {
            let kind = match s.access {
                AccessKind::Anonymous => "anonymous",
                _ => "authenticated",
            };
            format!("{}/{} ({kind})", a.name, s.name)
        })
        .collect();

    let state = Arc::new(State {
        cfg,
        access: RwLock::new(access),
        settings: RwLock::new(settings),
        #[cfg(unix)]
        access_path,
        #[cfg(unix)]
        settings_path: settings_path.clone(),
        jwks: RwLock::new(JwksCache {
            keys: initial,
            last_refresh: Instant::now(),
        }),
        jwks_refresh: Mutex::new(()),
    });

    // Hot-reload both files on SIGHUP (systemctl reload bb-auth). Failures
    // keep the current tables; no one is logged out by a transient disk error.
    // POSIX-only; no-op on non-unix hosts.
    spawn_access_reload_handler(&state);

    let server = Arc::new(Server::http(&listen).unwrap_or_else(|e| {
        eprintln!("[bb-auth] FATAL: cannot bind {listen}: {e}");
        std::process::exit(1);
    }));

    // Read once for the banner, through the same lock every request reads: what is printed is
    // what is live, not what a file said a moment ago.
    let settings = state.settings.read().unwrap();
    let identity_attrs = settings
        .identity_attrs
        .iter()
        .map(|a| a.attr.as_str())
        .collect::<Vec<_>>()
        .join(",");
    // Claim *names* are configuration, so they belong in the banner; claim *values* are
    // PII and are never logged, here or anywhere.
    let claim_names = if settings.profile_claims.is_empty() {
        "(none)".to_string()
    } else {
        settings
            .profile_claims
            .iter()
            .map(|c| c.claim.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    eprintln!(
        "[bb-auth] listening on {listen} | issuer={} | aud={} | apps={app_n} | scopes={scope_n} | users={user_n} | api_keys={key_n} | denied={denied_n} | identity={identity_attrs} | claims={claim_names} | workers={workers}",
        state.cfg.issuer,
        state.cfg.audiences.join(","),
    );
    // A browser silently drops a cookie over ~4 KB, which would look like a login loop
    // rather than an error. Warn while it is still a config question.
    let worst = worst_case_cookie_bytes(&settings.profile_claims);
    if worst > 3072 {
        eprintln!(
            "[bb-auth] WARNING: {} profile claims can mint a session cookie of up to ~{worst} bytes, \
             near the ~4 KB a browser will store (profile_claims in {settings_path})",
            settings.profile_claims.len()
        );
    }
    if !open_scopes.is_empty() {
        // Cognito self-signup is open, so `authenticated` really is "anyone who can
        // register"; `anonymous` is everyone, credential or not.
        eprintln!(
            "[bb-auth] WARNING: scopes that grant without listing anybody [{}]",
            open_scopes.join(",")
        );
    }
    if settings.allow_unverified_social {
        let scope = match &settings.social_providers {
            Some(p) => p.join(","),
            None => "any provider".to_string(),
        };
        eprintln!(
            "[bb-auth] WARNING: accepting unverified emails for social logins [{scope}] \
             (allow_unverified_social in {settings_path})"
        );
    }
    // Held only for the banner. Dropped before the workers start, so nothing below this line
    // can hold a read lock across a request and starve the SIGHUP swap.
    drop(settings);

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

    /// An identity with no claims: every login under the default (empty)
    /// the settings file's `profile_claims`.
    fn ident(email: &str) -> UserIdentity {
        UserIdentity {
            email: email.to_string(),
            claims: BTreeMap::new(),
        }
    }
    /// An identity carrying an arbitrary claim set.
    fn ident_claims(email: &str, claims: &[(&str, &str)]) -> UserIdentity {
        UserIdentity {
            email: email.to_string(),
            claims: claims
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }
    /// An identity carrying the two claims a display name is usually built from.
    fn ident_full(email: &str, given: &str, family: &str) -> UserIdentity {
        ident_claims(email, &[("given_name", given), ("family_name", family)])
    }
    /// A compiled claim list, written comma-separated for brevity. The compiler itself, and
    /// everything it refuses, is the library's and is tested there; what these tests need is
    /// a list to emit from.
    fn claims(spec: &str) -> Vec<ProfileClaim> {
        let list: Vec<String> = spec.split(',').map(str::to_string).collect();
        bb_auth_core::compile_profile_claims(&list).unwrap()
    }

    /// The claim set behind a first-and-last-name greeting, which is what most deployments
    /// configure and therefore the size the cookie budget is judged against.
    fn claims_cfg() -> Vec<ProfileClaim> {
        claims("given_name,family_name")
    }

    /// A JWKS holding one RSA public key, and an id_token signed by its private half. Both
    /// were generated once, offline, and are fixtures rather than secrets: the private half
    /// was thrown away, so the only thing this key can do is verify this token. `exp` is in
    /// 2100 because the point is the signature, not the clock.
    const TEST_JWKS: &str = r#"{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"bb-auth-test","e":"AQAB","n":"nmAtxmXBaFrRJyUe6i5CSQEPTq-80tfKKzO5jXg58t_KsovozqKu9dVzcJXh44gtXaoxbqPmVtj8Nn8sjC1G-kbF-MM4zQQ_F0z2S23Xkcz5-u0emQpt3ZPMRmkfQBsZs6Y_7qZT6ovm0RMRtEvOwJ1g1AFRp72saVt3lPlT9aMXDL0JN7GU1ytnNpYtn4C3u-UpnN9uxcGLYx3ULptmI3BK0s-zvVMzfxKSSvS_zvIfMxeJjAxrYmh1-cZifJsLGVuSQCcUeiCHP6kYxL_-sJjgb3H8tHeZVB4xjUzlkpKFiAKUmE5l39Rqbgxmq_bBLP2GvLAUBIjGV27r7bVriw"}]}"#;
    const TEST_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtdGVzdCJ9.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6InJzMjU2QGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImdpdmVuX25hbWUiOiJBZGEifQ.EsoTSyILbHFsucRSARUt4qahpK5R6rPlteCq1sUQ8gMoAqneJwJ8YXeFZmVFh3bCRlmgA0q4ygyXKMh_1ltNi8bfOoLtSCJBV-w-PrKeFRq1khEFfskIvWirsiVgzo5BK0DDj74dEFdG2zz7f_YAkln3indvFv1RbULDYfStID8F4WViQJP02nG4LdJiR4tihjw9E7f6Q7iMUeUw6a8axkWy1vtykzZptf_QNO2knyaAbOSNRd8hNbiYnid0VvbzrbxRFkvlzOSmiPwuab1kKW1H5AqGK0gN9eZTbOFKizVzajXHgcY7joRziYXI-86LZwRUHAAuAE-Jul82pMxDeQ";

    /// The JWKS parse and the RS256 verification, which every login runs and which nothing
    /// else here covers: the rest of the suite starts from a [`UserIdentity`] that already
    /// exists. The `Validation` is built exactly as [`validate_id_token`] builds it, so this
    /// exercises the gate's own configuration and not a lenient one.
    ///
    /// It exists because that coverage gap has already cost a production outage.
    /// `jsonwebtoken` selects its crypto provider from a **feature**, and compiles happily
    /// with none: it then installs a provider whose verifier factory is a `panic!`. Nothing
    /// says so until the first signature is checked, and under `panic = "abort"` that is not
    /// a failed login but a dead process, which `Restart=on-failure` turns into a restart
    /// loop. A test that only built a `DecodingKey` would have missed it, because the JWKS
    /// fetch and `from_jwk` never reach the provider; the verification is the whole point.
    #[test]
    fn rsa_signature_verification_works() {
        let set: JwkSet = serde_json::from_str(TEST_JWKS).expect("the JWKS must parse");
        let key = DecodingKey::from_jwk(&set.keys[0]).expect("the JWK must become a key");

        let mut v = Validation::new(Algorithm::RS256);
        v.set_audience(&["testclient"]);
        v.set_issuer(&["https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TESTPOOL"]);
        v.set_required_spec_claims(&["exp", "aud", "iss"]);
        v.validate_exp = true;
        v.leeway = 60;

        let data = decode::<Claims>(TEST_TOKEN, &key, &v).expect("a valid RS256 token verifies");
        assert_eq!(data.claims.email.as_deref(), Some("rs256@example.com"));
        assert_eq!(data.claims.token_use.as_deref(), Some("id"));
        // The profile claim rides in `extra`, which is what proves `flatten` still collects
        // what no typed field above took.
        assert_eq!(
            data.claims.extra.get("given_name").and_then(|v| v.as_str()),
            Some("Ada")
        );

        // The other half, and the one that says this is a signature check rather than a
        // decoder: one flipped base64 digit in the signature, the signed message untouched.
        let (msg, sig) = TEST_TOKEN.rsplit_once('.').expect("a JWT has three segments");
        assert!(sig.starts_with('E'), "fixture drifted: {sig}");
        let forged = format!("{msg}.F{}", &sig[1..]);
        assert!(
            decode::<Claims>(&forged, &key, &v).is_err(),
            "a forged signature must not verify"
        );
    }

    #[test]
    fn worst_case_cookie_bytes_grows_and_trips_the_warning() {
        let none = worst_case_cookie_bytes(&[]);
        let two = worst_case_cookie_bytes(&claims_cfg());
        assert!(two > none, "a claim must cost something");
        // The threshold `main` warns at. A couple of claims is comfortable; a handful of
        // max-length ones is not, which is the whole point of warning.
        assert!(two <= 3072, "the usual pair must not warn: {two}");
        let many = claims("a,b,c,d,e,f,g,h");
        assert!(
            worst_case_cookie_bytes(&many) > 3072,
            "eight claims must warn"
        );
    }

    #[test]
    fn session_roundtrip() {
        let k = keys_one();
        // Non-ASCII and an apostrophe: the cookie is binary-safe (base64) where the header
        // is not, so this is the roundtrip that has to survive untouched.
        let c = make_session(
            &ident_full("Foo@Bar.com", "Niccolò", "de' Medici"),
            3600,
            &k,
        );
        assert!(c.starts_with("bb1.k1."));
        // The email lowercases; the claim values do not — their case is the user's.
        assert_eq!(
            verify_session(&c, &k),
            Some(ident_full("foo@bar.com", "Niccolò", "de' Medici"))
        );
    }

    #[test]
    fn session_roundtrip_no_claims() {
        let k = keys_one();
        let c = make_session(&ident("a@b.com"), 3600, &k);
        // No claims is the empty segment, not a missing field and not "{}": the count
        // never varies, and the default config costs no cookie bytes.
        assert_eq!(c.split('.').count(), 6, "field count is fixed: {c}");
        assert_eq!(
            c.split('.').nth(4),
            Some(""),
            "empty segment, never {{}}: {c}"
        );
        assert_eq!(verify_session(&c, &k), Some(ident("a@b.com")));
    }

    #[test]
    fn session_roundtrip_json_special_chars() {
        // The blob is JSON, so a value containing a quote or a backslash goes through
        // escaping and must come back byte-identical.
        let k = keys_one();
        let id = ident_claims("a@b.com", &[("nickname", r#"a"b\c/d"#)]);
        let c = make_session(&id, 3600, &k);
        assert_eq!(verify_session(&c, &k), Some(id));
    }

    #[test]
    fn session_claims_are_signed() {
        let k = keys_one();
        let c = make_session(&ident_full("a@b.com", "Ada", "Byron"), 3600, &k);
        let p: Vec<&str> = c.split('.').collect();
        // Substitute a well-formed claims blob, keep the signature: the blob is inside the
        // signed bytes, so this must not verify.
        let forged = URL_SAFE_NO_PAD.encode(r#"{"given_name":"Eve"}"#);
        let cookie = format!("{}.{}.{}.{}.{forged}.{}", p[0], p[1], p[2], p[3], p[5]);
        assert_eq!(verify_session(&cookie, &k), None);
        // Dropping the blob entirely is no better.
        let stripped = format!("{}.{}.{}.{}..{}", p[0], p[1], p[2], p[3], p[5]);
        assert_eq!(verify_session(&stripped, &k), None);
    }

    #[test]
    fn session_bad_claims_segment_fails_closed() {
        let k = keys_one();
        let exp = now() + 3600;
        let eb = URL_SAFE_NO_PAD.encode(b"a@b.com");
        let b64 = |s: &str| URL_SAFE_NO_PAD.encode(s.as_bytes());
        let over = "x".repeat(MAX_CLAIM_VALUE_BYTES + 1);
        // Every one of these is *correctly signed*. We could never have minted it, so it is
        // a bug or a compromised key — either way reject the cookie, not just the claim.
        for seg in [
            "!!!".to_string(),                    // not base64url
            URL_SAFE_NO_PAD.encode([0xff, 0xfe]), // not UTF-8
            b64("[]"),                            // not an object
            b64("\"x\""),                         // ditto
            b64("{}"),                            // we mint the empty segment
            b64(r#"{"a":1}"#),                    // value not a string
            b64(r#"{"a":null}"#),                 // ditto
            b64(r#"{"a":""}"#),                   // would emit an empty header
            b64(&format!(r#"{{"a":"{over}"}}"#)), // over the value cap
            b64(r#"{"a":"one\ntwo"}"#),           // control character
            b64(r#"{"a":" Ada"}"#),               // not trim-stable
            b64(r#"{"bad key!":"Ada"}"#),         // key no config could produce
        ] {
            let msg = format!("bb1.k1.{exp}.{eb}.{seg}");
            let sig = sign(&k.by_id["k1"], &msg);
            assert_eq!(
                verify_session(&format!("{msg}.{sig}"), &k),
                None,
                "should reject: {seg}"
            );
        }
    }

    #[test]
    fn session_tampered_sig_rejected() {
        let k = keys_one();
        let mut c = make_session(&ident("a@b.com"), 3600, &k);
        let last = c.len() - 1;
        let alt = if c.as_bytes()[last] == b'A' { 'B' } else { 'A' };
        c.replace_range(last.., &alt.to_string());
        assert_eq!(verify_session(&c, &k), None);
    }

    #[test]
    fn session_expired_rejected() {
        let k = keys_one();
        let c = make_session(&ident("a@b.com"), 0, &k); // exp == now
        assert_eq!(verify_session(&c, &k), None);
    }

    #[test]
    fn session_unknown_keyid_rejected() {
        let k = keys_one(); // only k1
        let exp = now() + 3600;
        let eb = URL_SAFE_NO_PAD.encode(b"a@b.com");
        let msg = format!("bb1.k9.{exp}.{eb}.");
        let sig = sign(&k.by_id["k1"], &msg);
        let c = format!("{msg}.{sig}");
        assert_eq!(verify_session(&c, &k), None);
    }

    #[test]
    fn session_routes_to_accepted_key() {
        let k = keys_two(); // k1 active, k2 accepted
        let exp = now() + 3600;
        let eb = URL_SAFE_NO_PAD.encode(b"x@y.com");
        let cb = URL_SAFE_NO_PAD.encode(r#"{"given_name":"Ada"}"#);
        let msg = format!("bb1.k2.{exp}.{eb}.{cb}");
        let sig = sign(&k.by_id["k2"], &msg);
        let c = format!("{msg}.{sig}");
        assert_eq!(
            verify_session(&c, &k),
            Some(ident_claims("x@y.com", &[("given_name", "Ada")]))
        );
    }

    #[test]
    fn foreign_cookie_versions_are_rejected() {
        // The tag is inside the signed bytes and exactly one value of it has an arm, so a
        // live key signing the cookie is not enough: the tag has to be ours. That is what
        // makes a future format bump a clean break rather than an ambiguity, and it is the
        // contract, so it is pinned.
        let k = keys_one();
        let exp = now() + 3600;
        let eb = URL_SAFE_NO_PAD.encode(b"a@b.com");
        let cb = URL_SAFE_NO_PAD.encode(r#"{"given_name":"Ada"}"#);
        for msg in [
            format!("bb2.k1.{exp}.{eb}.{cb}"), // our shape, a tag we never mint
            format!("bb9.k1.{exp}.{eb}."),     // ditto, with no claims
            format!("xx1.k1.{exp}.{eb}.{cb}"), // another namespace entirely
            format!("bb1.{exp}.{eb}"),         // our tag, too few fields
            format!("bb1.k1.{exp}.{eb}.{cb}.x"), // our tag, one field too many
        ] {
            let sig = sign(&k.by_id["k1"], &msg);
            let c = format!("{msg}.{sig}");
            assert_eq!(verify_session(&c, &k), None, "should reject: {c}");
        }
    }

    #[test]
    fn malformed_cookies_rejected() {
        let k = keys_one();
        for bad in [
            "",
            "bb1",
            "bb1.k1",
            "bb1.k1.9.aa",             // too few fields
            "bb1.k1.99999.!!!.AAAA",   // five: one short
            "bb1.k1.9.aa.bb.cc.dd",    // seven: the extra folds into sig, which then fails
            "bb1.k1.notanum.aa.bb.cc", // right shape, exp is not a number
            "bb1.k1.99999.!!!.bb.cc",  // right shape, the email is not base64url
            "zzz.a.b.c",               // no arm matches a tag we do not mint
            "bb9.k1.9.aa.bb.cc",       // ditto, even wearing our shape
        ] {
            assert_eq!(verify_session(bad, &k), None, "should reject: {bad:?}");
        }
    }

    #[test]
    fn profile_headers_follow_the_live_config() {
        let cfg = claims_cfg();
        // A cookie minted under a wider config: `nickname` is no longer configured, so it
        // emits nothing — the live config is the authority, not the credential.
        let stale = ident_claims(
            "a@b.com",
            &[("given_name", "Ada"), ("nickname", "The Countess")],
        );
        assert_eq!(
            profile_headers(&cfg, &stale.claims),
            vec![("X-Auth-Given-Name", "Ada".to_string())]
        );
        // A configured claim the identity lacks omits its header rather than sending it
        // empty; order follows the config, not the map.
        assert_eq!(
            profile_headers(&cfg, &ident_full("a@b.com", "Ada", "Byron").claims),
            vec![
                ("X-Auth-Given-Name", "Ada".to_string()),
                ("X-Auth-Family-Name", "Byron".to_string()),
            ]
        );
        // No config, nothing emitted, whatever the identity carries.
        assert!(profile_headers(&[], &stale.claims).is_empty());
        // And the value goes out percent-encoded.
        assert_eq!(
            profile_headers(&cfg, &ident_full("a@b.com", "Niccolò", "de' Medici").claims),
            vec![
                ("X-Auth-Given-Name", "Niccol%C3%B2".to_string()),
                ("X-Auth-Family-Name", "de%27%20Medici".to_string()),
            ]
        );
    }

    #[test]
    fn pct_encode_unreserved_untouched() {
        // RFC 3986's unreserved set passes through byte for byte, which is what keeps a
        // plain "Rossi" readable in a log.
        assert_eq!(pct_encode("AZaz09-._~Rossi"), "AZaz09-._~Rossi".to_string());
    }

    #[test]
    fn pct_encode_space_utf8_and_symbols() {
        assert_eq!(pct_encode("Mary Jane"), "Mary%20Jane"); // %20, never '+'
        assert_eq!(pct_encode("Niccolò"), "Niccol%C3%B2"); // per UTF-8 byte
        assert_eq!(pct_encode("%"), "%25"); // the escape escapes itself
        assert_eq!(pct_encode("+"), "%2B"); // so '+' can only mean a literal plus
        assert_eq!(pct_encode("de' Medici"), "de%27%20Medici");
        assert_eq!(pct_encode("a\r\nb"), "a%0D%0Ab"); // no response splitting
        assert_eq!(pct_encode(""), "");
    }

    #[test]
    fn pct_encode_output_always_ascii_graphic() {
        // The property `respond_authorized` leans on instead of a per-request check: for
        // *any* input — control bytes, DEL, multibyte — the output is printable ASCII, so
        // `h()` cannot panic.
        let mut s: String = (0u8..=0x7f).map(|b| b as char).collect();
        s.push_str("Niccolò Ægir 日本語 🙂");
        let enc = pct_encode(&s);
        assert!(
            enc.bytes().all(|b| b.is_ascii_graphic()),
            "not header-safe: {enc:?}"
        );
    }

    #[test]
    fn clean_claim_hygiene() {
        use serde_json::json;
        // captured, trimmed, case and UTF-8 preserved
        assert_eq!(
            clean_claim(&json!("  Niccolò  ")).as_deref(),
            Some("Niccolò")
        );
        assert_eq!(
            clean_claim(&json!("de' Medici")).as_deref(),
            Some("de' Medici")
        );
        // nothing worth a header
        assert_eq!(clean_claim(&json!("")), None);
        assert_eq!(clean_claim(&json!("   ")), None);
        assert_eq!(clean_claim(&json!("Ada\rByron")), None); // control char
                                                             // dropped, not truncated, at the byte cap
        let max = "x".repeat(MAX_CLAIM_VALUE_BYTES);
        assert_eq!(clean_claim(&json!(max)).as_deref(), Some(max.as_str()));
        assert_eq!(
            clean_claim(&json!("x".repeat(MAX_CLAIM_VALUE_BYTES + 1))),
            None
        );
        // a non-string claim costs the claim, never the token
        for v in [
            json!(42),
            json!(true),
            json!(null),
            json!(["Ada"]),
            json!({}),
        ] {
            assert_eq!(clean_claim(&v), None, "should ignore: {v}");
        }
    }

    #[test]
    fn claim_value_ok_is_what_a_cookie_may_carry() {
        // The predicate verification shares with capture — where the trim test, vacuous on
        // capture, is what rejects a value we could not have minted.
        assert!(claim_value_ok("Ada"));
        assert!(claim_value_ok("de' Medici"));
        assert!(!claim_value_ok(""));
        assert!(!claim_value_ok(" Ada"));
        assert!(!claim_value_ok("Ada "));
        assert!(!claim_value_ok("Ada\nByron"));
        assert!(claim_value_ok(&"x".repeat(MAX_CLAIM_VALUE_BYTES)));
        assert!(!claim_value_ok(&"x".repeat(MAX_CLAIM_VALUE_BYTES + 1)));
    }

    #[test]
    fn claims_parse_profile_claims_present_absent_and_mistyped() {
        let parse = |s: &str| serde_json::from_str::<Claims>(s).expect("claims must parse");

        let c = parse(r#"{"email":"a@b.com","given_name":"Ada","family_name":"Byron"}"#);
        assert_eq!(
            c.extra.get("given_name").and_then(clean_claim).as_deref(),
            Some("Ada")
        );
        assert_eq!(
            c.extra.get("family_name").and_then(clean_claim).as_deref(),
            Some("Byron")
        );

        let c = parse(r#"{"email":"a@b.com"}"#);
        assert!(c.extra.get("given_name").is_none());

        // The reason `extra` holds `Value`s and not `String`s: a badly mapped IdP attribute
        // must cost the user that claim, not their login. `parse` not panicking *is* the
        // assertion.
        let c = parse(r#"{"email":"a@b.com","given_name":42,"family_name":["Byron"]}"#);
        assert_eq!(c.extra.get("given_name").and_then(clean_claim), None);
        assert_eq!(c.extra.get("family_name").and_then(clean_claim), None);
    }

    #[test]
    fn claims_the_gate_consumes_never_reach_extra() {
        // Why `RESERVED_CLAIMS` exists: `flatten` never sees a key a typed field took, so
        // configuring one of these would look up a claim that can never be there.
        let c = serde_json::from_str::<Claims>(
            r#"{"email":"a@b.com","email_verified":true,"token_use":"id","identities":[]}"#,
        )
        .expect("claims must parse");
        for reserved in bb_auth_core::RESERVED_CLAIMS {
            assert!(
                c.extra.get(reserved).is_none(),
                "{reserved} must not be in extra"
            );
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
        let h = "a=1; bb_session=bb1.k1.1.aaa...bbb; c=2";
        assert_eq!(cookie_value(h, "bb_session"), Some("bb1.k1.1.aaa...bbb"));
        assert_eq!(cookie_value("bb_session_extra=x", "bb_session"), None);
        assert_eq!(cookie_value("", "bb_session"), None);
    }

    /// Only two fields matter to `build_cookie`; the rest are placeholders so the literal
    /// compiles.
    fn cookie_cfg(domain: Option<&str>) -> Config {
        Config {
            listen: "127.0.0.1:4181".to_string(),
            hmac_keys: keys_one(),
            issuer: "https://issuer.invalid".to_string(),
            audiences: vec!["client".to_string()],
            cookie_name: "bb_session".to_string(),
            cookie_domain: domain.map(str::to_string),
            authorized_hosts: bb_hosts(),
            login_url: LOGIN.to_string(),
            original_url_header: "X-Original-URL".to_string(),
            workers: 1,
        }
    }

    /// The line a single, estate-wide logout endpoint stands on: a browser matches a
    /// `Set-Cookie` against what it stored by `(name, Domain, Path)`, so the expiring cookie
    /// must name the same triple the minted one did. Make the clear host-only while the mint
    /// is domain-wide and it misses in silence — the browser keeps the domain cookie, the
    /// logout reports success, and every other host stays signed in.
    #[test]
    fn clearing_a_cookie_targets_the_same_cookie_it_minted() {
        let cfg = cookie_cfg(Some(".badbat75.com"));
        let minted = build_cookie(&cfg, "bb1.k1.9999999999.ZWI.", 2_592_000);
        let cleared = build_cookie(&cfg, "", 0);
        for attr in [
            "bb_session=",
            "Path=/",
            "Domain=.badbat75.com",
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
        ] {
            assert!(minted.contains(attr), "mint lost {attr}: {minted}");
            assert!(cleared.contains(attr), "clear lost {attr}: {cleared}");
        }
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        assert!(!minted.contains("Max-Age=0"), "{minted}");

        // Host-only deployment (no cookie domain): neither carries a Domain, so the two
        // still address one cookie. What must never happen is one of them carrying it.
        let host_only = cookie_cfg(None);
        assert!(!build_cookie(&host_only, "v", 60).contains("Domain"));
        assert!(!build_cookie(&host_only, "", 0).contains("Domain"));
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
    // The rule itself (`decide` / `decide_api_key`, applications, `denied`, scopes, expiry) is
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

    const BOB: &str = "11111111-1111-4111-8111-111111111111";

    /// One `authenticated` area, one `restricted` area, one veto, one key.
    fn gate_access(name: &str) -> Access {
        let key_hash = sha256_hex("bbk_secret");
        access_of(
            name,
            &format!(
                r#"{{ "version": 1,
                     "applications": [
                       {{ "name": "app1", "base": ["https://app.x.com/app1"], "scopes": [
                          {{ "name": "open", "urls": ["https://app.x.com/app1/*"],
                             "access": "authenticated" }} ] }},
                       {{ "name": "other", "base": ["https://app.x.com/other"], "scopes": [
                          {{ "name": "team", "urls": ["https://app.x.com/other/*"],
                             "access": "restricted", "users": ["{BOB}"] }} ] }},
                       {{ "name": "pub", "base": ["https://app.x.com/pub"], "scopes": [
                          {{ "name": "health", "urls": ["https://app.x.com/pub/*"],
                             "access": "anonymous" }} ] }} ],
                     "denied": ["spammer@x.com"],
                     "users": [ {{ "uuid": "{BOB}", "emails": ["bob@x.com", "bob@old.com"],
                        "api_keys": [ {{ "id": "laptop", "key_hash": "{key_hash}",
                                         "released": "2026-01-01", "duration": "never" }} ] }} ] }}"#
            ),
        )
    }

    #[test]
    fn authorize_login_resolves_the_identity_it_hands_downstream() {
        let a = gate_access("authorize");
        let other = Some("https://app.x.com/other/x");
        let app1 = Some("https://app.x.com/app1/x");

        // Enrolled: the identity carries the uuid and every identifier the row has, not
        // just the one that signed in. That is what makes `X-Auth-Email` stable.
        let got = authorize_login(&a, ident("bob@old.com"), other).unwrap();
        match got {
            Granted::Identity(who) => {
                assert_eq!(who.uuid.as_deref(), Some(BOB));
                assert_eq!(who.emails, vec!["bob@x.com", "bob@old.com"]);
                assert!(who.emails.iter().all(|e| header_safe_email(e)));
            }
            Granted::Anonymous => panic!("a credential must not resolve to an anonymous grant"),
        }

        // An `authenticated` scope: nobody in any table, so no uuid, and the only email
        // there is is the one the token vouched for. Header-safe because
        // `validate_id_token` checked it there.
        let got = authorize_login(&a, ident("newcomer@x.com"), app1).unwrap();
        match got {
            Granted::Identity(who) => {
                assert_eq!(who.uuid, None);
                assert_eq!(who.emails, vec!["newcomer@x.com"]);
            }
            Granted::Anonymous => panic!("a credential must not resolve to an anonymous grant"),
        }

        // And the denials. The veto comes first, then membership, then the missing header.
        assert!(authorize_login(&a, ident("spammer@x.com"), app1).is_none());
        assert!(authorize_login(&a, ident("newcomer@x.com"), other).is_none());
        assert!(authorize_login(&a, ident("bob@x.com"), None).is_none());
        // Nothing outside every application is reachable, by anyone.
        assert!(
            authorize_login(&a, ident("bob@x.com"), Some("https://app.x.com/elsewhere")).is_none()
        );
    }

    #[test]
    fn authorize_login_passes_claims_through_untouched() {
        // The profile claims must survive the grant decision without influencing it: the
        // access file has no opinion about them, and `bb-auth-adm can` has to keep
        // answering the same question the gate does.
        let a = gate_access("authorize-claims");
        let carried = |g: Option<Granted>| match g {
            Some(Granted::Identity(who)) => who.claims,
            _ => panic!("expected a granted identity"),
        };
        assert_eq!(
            carried(authorize_login(
                &a,
                ident_full("bob@x.com", "Bob", "Rossi"),
                Some("https://app.x.com/other/x")
            )),
            ident_full("bob@x.com", "Bob", "Rossi").claims
        );
        // The same, where the identity is in no table at all.
        assert_eq!(
            carried(authorize_login(
                &a,
                ident_full("new@x.com", "Niccolò", "de' Medici"),
                Some("https://app.x.com/app1/x")
            )),
            ident_full("new@x.com", "Niccolò", "de' Medici").claims
        );
        // And a claim never rescues a denial.
        assert!(authorize_login(
            &a,
            ident_full("spammer@x.com", "S", "P"),
            Some("https://app.x.com/app1/x")
        )
        .is_none());
    }

    #[test]
    fn bearer_apikey_resolves_to_its_owner() {
        // The gate hashes the bearer; the file holds only the hash. A key acts as its
        // user, so the identity handed back is the owner's row: the one identity on this
        // path that never passed through a token claim, and so is guarded at load instead.
        let a = gate_access("apikey");
        let rec = bearer_apikey(&a, "bbk_secret").unwrap();
        assert_eq!(rec.uuid, BOB);

        let who = key_identity(&a, rec);
        assert_eq!(who.uuid.as_deref(), Some(BOB));
        assert_eq!(who.emails, vec!["bob@x.com", "bob@old.com"]);
        // A key has no token, so it can never carry a profile claim.
        assert!(who.claims.is_empty());

        assert!(bearer_apikey(&a, "bbk_nope").is_none());
    }

    #[test]
    fn a_key_is_refused_where_the_scope_admits_only_a_login() {
        let a = access_of(
            "key-class",
            &format!(
                r#"{{ "version": 1,
                     "applications": [ {{ "name": "app", "base": ["https://x.com/a"],
                       "scopes": [ {{ "name": "s", "urls": ["https://x.com/a/*"],
                         "access": "restricted", "users": ["{BOB}"],
                         "credentials": ["login"] }} ] }} ],
                     "users": [ {{ "uuid": "{BOB}", "emails": ["bob@x.com"],
                       "api_keys": [ {{ "id": "k", "key_hash": "{}",
                                        "released": "2026-01-01", "duration": "never" }} ] }} ] }}"#,
                sha256_hex("bbk_secret")
            ),
        );
        let url = Some("https://x.com/a/thing");
        let rec = bearer_apikey(&a, "bbk_secret").unwrap();
        assert!(!authorize(&a, &Subject::Key(rec), url, "key"));
        // The same person, through a browser login, is admitted.
        assert!(authorize_login(&a, ident("bob@x.com"), url).is_some());
    }

    #[test]
    fn an_anonymous_scope_grants_with_no_credential_at_all() {
        let a = gate_access("anon");
        let url = Some("https://app.x.com/pub/healthz");
        assert!(decide(&a, &Subject::Anonymous, url).granted());
        // And it grants ahead of the veto, because a vetoed client would simply send
        // nothing and be granted anyway.
        assert!(decide(&a, &Subject::Identifier("spammer@x.com"), url).granted());
        // Elsewhere, no credential is no entry.
        assert!(!decide(&a, &Subject::Anonymous, Some("https://app.x.com/app1/x")).granted());
    }

    // --- the identity headers ------------------------------------------------

    fn attrs(spec: &str) -> Vec<IdentityAttr> {
        let list: Vec<String> = spec.split(',').map(str::to_string).collect();
        bb_auth_core::compile_identity_attrs(&list).unwrap()
    }

    #[test]
    fn identity_headers_join_with_a_space_and_omit_what_is_absent() {
        let who = Authorized {
            uuid: Some(BOB.to_string()),
            emails: vec!["bob@x.com".into(), "bob@old.com".into()],
            claims: BTreeMap::new(),
        };
        assert_eq!(
            identity_headers(&attrs("uuid,email"), &who),
            vec![
                ("X-Auth-Uuid", BOB.to_string()),
                (IDENTITY_HEADER, "bob@x.com bob@old.com".to_string()),
            ]
        );
        // A space can never appear inside an identifier, which is what makes the join
        // unambiguous; a comma could, so it is not used.
        assert!(who.emails.iter().all(|e| header_safe_email(e)));

        // An identity granted by an `authenticated` scope has no uuid: the header is
        // omitted, never sent empty, because nginx cannot tell those apart.
        let stranger = Authorized {
            uuid: None,
            emails: vec!["new@x.com".into()],
            claims: BTreeMap::new(),
        };
        assert_eq!(
            identity_headers(&attrs("uuid,email"), &stranger),
            vec![(IDENTITY_HEADER, "new@x.com".to_string())]
        );
        // Order follows the configuration, not the struct.
        assert_eq!(
            identity_headers(&attrs("email,uuid"), &who)[0].0,
            IDENTITY_HEADER
        );
    }
}
