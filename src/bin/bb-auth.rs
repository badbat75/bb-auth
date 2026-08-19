//! bb-auth — a minimal, service-agnostic auth gate for nginx `auth_request`.
//!
//! Authorization-code OIDC proxies drive the login themselves and cannot accept a
//! token the client already holds. bb-auth is built for the opposite: it takes a
//! Cognito **id_token** that a browser-side login page already obtained (the
//! `USER_AUTH` flow on a public app client), validates it, and exchanges it for an
//! HMAC-signed session cookie. That is what makes "auto-login right after
//! registration, with no second OTP" possible. Everything else is wired
//! per-deployment through `BB_AUTH_*` env vars ([`Config::from_env`]) and the settings
//! file beside the access file ([`read_settings`]), which is where anything that must
//! change without a restart lives.
//!
//! # Endpoints
//!
//! All under `/auth/`, fronted by nginx on the protected host.
//!
//! | Method | Path | Caller | Behaviour |
//! |--------|------|--------|-----------|
//! | `GET`  | `/auth/validate` | nginx `auth_request`, loopback | 204 + [`IDENTITY_HEADER`] (+ one header per configured [`ProfileClaim`] the credential carries) if a credential authorizes the request, else 401 |
//! | `GET`, `HEAD` | `/auth/login` | browser | the sign-in page ([`LOGIN_HTML`]), which runs the Cognito flow and POSTs the id_token back to `/auth/session`, landing on `?rd=` or, failing that, on the [`REFERER_HEADER`] ([`rd_candidate`]) |
//! | `GET`, `HEAD` | `/auth/callback` | browser | the social sign-in callback ([`CALLBACK_HTML`]); `404` unless [`social_ready`] says this deployment has a social sign-in |
//! | `POST` | `/auth/session`  | browser | validate the posted `id_token`, set the cookie, 302 → `rd` |
//! | `GET`  | `/auth/logout`   | browser | clear the cookie, 302 → `?rd=`, else the [`REFERER_HEADER`] ([`rd_candidate`]), else the login page |
//! | `GET`  | `/auth/healthz`  | local   | 200 `ok` |
//!
//! The first is the only one nginx gates. The other five must be reachable without a
//! credential, and the two pages most of all: a sign-in page behind an `auth_request` answers
//! a signed-out visitor with itself, forever.
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
//!   in the system), the Cognito trust roots, the cookie's name and domain, the
//!   and the two that *are* the lockout if they are wrong: `BB_AUTH_AUTHORIZED_HOSTS` and
//!   `BB_AUTH_ORIGINAL_URL_HEADER`. **The Cognito app clients are not here**: they are
//!   `gate.client_id` and the audience of each `gate.social_buttons` entry in the settings
//!   file, and so is `gate.login_url`, because all three programs have an opinion about them
//!   and an env var is readable only by the process that was started with it.
//! * **the settings file** (`BB_AUTH_SETTINGS_FILE`, [`bb_auth_core::Settings`]), re-read on
//!   SIGHUP and held in [`State::settings`]. The ones that are read per request, cannot lock
//!   anybody out, and are not secret: the five the gate answers with, and the `ui` section
//!   that says how the pages above look ([`look_subs`]), which `bb-auth-web` reads too. They
//!   are in a file rather than the environment because a process cannot re-read its own
//!   environment: that, and not taste, is why the split exists.
//! * **the access file** ([`bb_auth_core::Access`]), re-read on SIGHUP: who reaches what.
//!
//! Both files are validated by the parser their editors use, both reload **fail-soft** (a
//! broken file keeps what is already live), and `--check-access` / `--check-settings` are the
//! two commands that catch either before a restart meets it.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::Sha256;
use tiny_http::{Header, Request, Response, ResponseBox, Server, StatusCode};

// The access file — schema, parser, URL matcher and the grant model — is shared with
// `bb-auth-adm`, which edits the very file this reads. One parser, one matcher, one
// answer to "who may reach what": see the [`bb_auth_core`] crate docs. Everything the
// access file has no opinion about — HTTP, the cookie, id_token validation, the nginx
// contract — stays here, in one file, read top to bottom.
use bb_auth_core::{
    claim_name_ok, decide, decide_api_key, default_settings_path, header_safe_email, html_escape,
    login_url_for, now, page_csp, read_access, read_settings, request_site, request_url,
    sha256_hex, social_idp_label, stylesheet_link, version_line, Access, AccessKind, ApiKeyRecord,
    Decision, IdentityAttr, KeyDecision, ProfileClaim, RequestSite, Settings, SocialButton,
    Subject, UrlPattern, API_KEY_PREFIX, BASE_CSS, PAGE_SECURITY_HEADERS, THEME_CSS,
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
/// [`bb_auth_core::compile_login_url`] at load, which requires printable ASCII.
const LOGIN_URL_HEADER: &str = "X-Auth-Login-URL";

/// The standard `Referer`: where a browser says it came from, and the second and last thing
/// [`rd_candidate`] asks when a link carries no `?rd=`. Misspelled since RFC 1945 in 1996 and
/// never corrected; RFC 9110 section 10.1.3 is where it lives now, and the correctly spelled
/// relatives are somebody else's (the `Referrer-Policy` response header, `document.referrer`
/// in the page).
///
/// It is **a backup and never the mechanism**, and the reason is that nobody configured it.
/// It is absent whenever the page that linked here sent `Referrer-Policy: no-referrer`,
/// whenever a privacy tool or a proxy stripped it, and whenever somebody typed the URL or
/// used a bookmark; cross-origin it arrives trimmed to a bare origin, because
/// `strict-origin-when-cross-origin` is the browsers' default. On a logout it also names the
/// page the person was just on, which is often one they may no longer see, so they land
/// there, get a `401`, and reach the login page one hop later. None of that is worth
/// depending on, and all of it is worth having when a link forgot to say anything: a `?rd=`
/// is what a link says when it means something specific, and this is what is left when it
/// says nothing at all.
///
/// The gate reads it and never emits it, and it is the only header of anyone else's that it
/// treats as a redirect target, which is why it goes through the very gate a `?rd=` goes
/// through and is trusted for nothing beyond passing it ([`safe_rd`] on the way out of a
/// logout, [`rd_url_allowed`] before the sign-in page carries it). A link from outside
/// `BB_AUTH_AUTHORIZED_HOSTS` is therefore not a redirect anywhere, and a client setting the
/// header by hand gains nothing but a landing page inside the estate it is signing in to or
/// out of.
const REFERER_HEADER: &str = "Referer";

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
    /// `BB_AUTH_COOKIE_NAME`, the session cookie's name. Default `bb_session`.
    ///
    /// The cookie's *domain* is not here: it is `gate.cookie_domain` in the settings file.
    /// The name stays because renaming it orphans every cookie already issued with no way to
    /// clear them, and unlike the domain there is no reason anyone would ever change it.
    cookie_name: String,
    /// `BB_AUTH_LOGIN_URL`, e.g. `https://login.example.com/`. Where a logout and every
    /// rejected `rd` land, and what a `401` names in [`LOGIN_URL_HEADER`], unless the

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

/// The Cognito JSON API endpoint the sign-in page talks to: the live issuer's origin, since
/// the pool id is the only part of an issuer URL that is not it.
///
/// **Derived and never configured**, which is the whole argument for serving the sign-in page
/// from here: a page that named its own endpoint could name a pool this gate does not validate
/// against, and the symptom would be a login that succeeds in the browser and is refused by
/// the gate a redirect later. It is computed per use rather than held, because the issuer is a
/// setting now and a held copy would be the stale half of a reload.
fn cognito_endpoint(settings: &Settings) -> String {
    match origin_of(&settings.issuer) {
        Some(o) => format!("{o}/"),
        None => String::new(),
    }
}

/// Read an env var, falling back to `default` when unset.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// How much the gate says about individual requests.
///
/// There is no logging framework here and there should not be one: the journal is the log,
/// `eprintln!` is the API, and what an operator actually needs is one knob for the volume.
/// Two lines in the request path name an identity on *every* request that carries one, which
/// on a busy `authenticated` area is a journal full of the same address; the other end of the
/// same problem is an operator who wants those lines and cannot get more.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum LogLevel {
    /// Startup, configuration, reloads, failures, and nothing about a single request. A
    /// refused request is not an event at this level: on a gated URL it is the ordinary case.
    Error,
    /// The default, and what the gate has always done, minus the repetition: denials, grants
    /// worth noticing, and the per-identity lines deduplicated by [`first_in_window`].
    Info,
    /// The same lines with no deduplication at all, which is what you want for ten minutes
    /// while working out why one person cannot get in.
    Debug,
}

/// The configured level, read once at startup. A `OnceLock` and not a field of [`Config`]
/// because [`authorize`] is handed an access table and a subject, not the configuration, and
/// threading a log level through the decision path would put it somewhere it has no business
/// being.
static LOG_LEVEL: OnceLock<LogLevel> = OnceLock::new();

/// Is the configured level at least `want`? Defaults to [`LogLevel::Info`] before `main` has
/// set it, so a unit test logs exactly as the service does.
fn logs(want: LogLevel) -> bool {
    *LOG_LEVEL.get().unwrap_or(&LogLevel::Info) >= want
}

/// How long one identity's per-request line stays quiet after it is printed.
const LOG_DEDUPE_WINDOW: Duration = Duration::from_secs(300);

/// How many distinct keys the dedupe table holds before it is emptied. A cap and not an
/// eviction policy: this is a log filter, and the worst a wipe costs is one repeated line.
const LOG_DEDUPE_MAX: usize = 1024;

/// Keys already logged, and when. See [`first_in_window`].
static RECENT_LOGS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

/// Is this the first time `key` has been seen in [`LOG_DEDUPE_WINDOW`]?
///
/// The per-request identity lines are worth keeping and not worth repeating: an un-enrolled
/// identity walking into an `authenticated` area is something an operator should see, and
/// seeing it once every five minutes says exactly as much as seeing it on every request while
/// costing a journal nobody can read. [`LogLevel::Debug`] turns the filter off, which is the
/// answer when the repetition is the information.
fn first_in_window(key: &str) -> bool {
    if logs(LogLevel::Debug) {
        return true;
    }
    let Ok(mut seen) = RECENT_LOGS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
    else {
        return true;
    };
    let now = Instant::now();
    if let Some(t) = seen.get(key) {
        if now.duration_since(*t) < LOG_DEDUPE_WINDOW {
            return false;
        }
    }
    if seen.len() >= LOG_DEDUPE_MAX {
        seen.clear();
    }
    seen.insert(key.to_string(), now);
    true
}

/// Is this listen address on the loopback interface, which is what every deployment note in
/// this repository assumes?
///
/// Textual on purpose: the value is a `host:port` string handed to `Server::http`, and what
/// is worth reporting is what an operator wrote in the env file. An unresolvable name is not
/// loopback as far as this is concerned, which errs towards saying something.
fn listen_is_loopback(listen: &str) -> bool {
    let host = match listen.rsplit_once(':') {
        // `[::1]:8080`, the only shape where the last colon is not the port separator's.
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => h,
        _ => listen,
    };
    let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    host == "localhost" || host == "::1" || host.starts_with("127.")
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

        Config {
            listen: env_or("BB_AUTH_LISTEN", "127.0.0.1:4181"),
            hmac_keys: HmacKeys { by_id, active_id },
            cookie_name: env_or("BB_AUTH_COOKIE_NAME", "bb_session"),
            original_url_header: env_or("BB_AUTH_ORIGINAL_URL_HEADER", "X-Original-URL"),
            workers: env_or("BB_AUTH_WORKERS", "4").parse().unwrap_or(4).max(1),
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Cognito's public signing keys, by `kid`, with the time of the last successful fetch and
/// the issuer they came from.
///
/// The issuer is in here because it is a setting now, so "are these the right keys?" stopped
/// being answerable from the process's own configuration. Holding it beside the keys is what
/// lets a reload notice the pool changed, and what stops this pool's tokens from ever being
/// checked against the other one's keys.
struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    last_refresh: Instant,
    issuer: String,
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
///
/// The path is a parameter, and the reason is testability rather than taste: this is the
/// promise the whole arrangement rests on (a GUI may edit a live file because the worst a
/// bad save costs is a declined reload), it is `cfg(unix)` so it never even compiles on the
/// development host, and it had no test on any platform. With the path passed in, the
/// fail-soft half can be exercised against a temp file that does not parse, on any machine
/// where this code exists at all.
#[cfg(unix)]
fn reload_access(state: &State) {
    reload_access_from(state, &state.access_path);
}

/// [`reload_access`] against a named file.
#[cfg(unix)]
fn reload_access_from(state: &State, path: &str) {
    match read_access(path) {
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
    reload_settings_from(state, &state.settings_path);
}

/// [`reload_settings`] against a named file. Split for the reason [`reload_access_from`] is.
#[cfg(unix)]
fn reload_settings_from(state: &State, path: &str) {
    match read_settings(path) {
        Ok(new) => {
            // The pool is a setting, and it is the one that cannot simply be swapped: the
            // keys in hand belong to the old issuer, and a gate holding half of this pair
            // checks one pool's tokens against the other's keys, which is every login failing
            // on a signature it cannot explain. So the fetch happens first and the swap is
            // all or nothing, in the same fail-soft direction as everything else here: a new
            // issuer that does not answer leaves the old settings AND the old keys live.
            let live_issuer = state.jwks.read().unwrap().issuer.clone();
            if !new.issuer.is_empty() && new.issuer != live_issuer {
                match fetch_jwks(&new.issuer) {
                    Ok(keys) => {
                        let mut c = state.jwks.write().unwrap();
                        c.keys = keys;
                        c.last_refresh = Instant::now();
                        c.issuer = new.issuer.clone();
                        eprintln!("[bb-auth] issuer changed, JWKS refetched: {}", new.issuer);
                    }
                    Err(e) => {
                        eprintln!(
                            "[bb-auth] settings reload FAILED, keeping current ones: the new \
                             issuer {} did not answer ({e}), and swapping it without its keys \
                             would refuse every login",
                            new.issuer
                        );
                        return;
                    }
                }
            }
            let c = new.profile_claims.len();
            let a = new
                .identity_attrs
                .iter()
                .map(|x| x.attr.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let ttl = new.session_ttl;
            // Said before the swap, because it is about the values that are about to become
            // live, and because it reads as the reason for the line below it.
            let social = social_state(&new);
            *state.settings.write().unwrap() = new; // fail-safe: atomic swap
            eprintln!(
                "[bb-auth] settings reloaded (SIGHUP): identity={a}, {c} profile claims, \
                 session_ttl={ttl}s, social={social}"
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

/// How long a JWKS fetch may take before it is abandoned.
///
/// It is deliberately shorter than nginx's `auth_request` read timeout (60 s by default,
/// and commonly lowered): a request that is already waiting on the issuer must fail *here*,
/// with a worker freed, rather than out there with the worker still held. The fetch is one
/// small document from a CDN-backed endpoint, so three seconds is generous for the honest
/// case and short for the case this constant exists for, which is the issuer being slow.
const JWKS_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the cache is considered fresh: the interval a *successful* fetch buys.
const JWKS_TTL: Duration = Duration::from_secs(60);

/// How long a *failed* fetch buys, and why there is such a thing at all.
///
/// A failure used to leave `last_refresh` untouched so the next request retried
/// immediately, which reads as eager and behaves as a stampede: with the issuer down, every
/// request carrying an unknown `kid` starts its own fetch and holds a worker for
/// [`JWKS_TIMEOUT`] doing it. An unauthenticated client can produce those requests at will,
/// so the eager retry is also the cheapest way to take the gate off the air. Ten seconds is
/// short enough that a real key rotation is picked up promptly and long enough that a dead
/// issuer costs one worker per ten seconds instead of all of them.
const JWKS_NEGATIVE_TTL: Duration = Duration::from_secs(10);

/// Fetch and parse the issuer's JWKS, keyed by `kid`. Unusable individual keys are
/// skipped with a warning; an empty result is an error. Outbound HTTPS only — bb-auth
/// never sends anything to Cognito and holds no client secret.
fn fetch_jwks(issuer: &str) -> Result<HashMap<String, DecodingKey>, String> {
    let url = format!("{issuer}/.well-known/jwks.json");
    // The timeout is a property of the agent, not of the request, so it is built here
    // rather than set per call: one fetch, one agent, no connection pool to outlive it.
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(JWKS_TIMEOUT))
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

/// Refresh the JWKS cache if the last refresh is older than [`JWKS_TTL`], using
/// double-checked locking so concurrent workers don't all hammer Cognito when a `kid`
/// misses. The network fetch happens with NO jwks lock held.
///
/// **At most one worker is ever inside the fetch, and no worker ever waits for it.** The
/// refresh mutex is taken with `try_lock`, so a worker that finds a refresh already running
/// answers from the map it has instead of queueing behind a network call. That is the whole
/// point: an unknown `kid` is client-supplied, so anyone can aim requests at this path, and
/// a blocking lock plus a slow issuer is `BB_AUTH_WORKERS` workers all parked on
/// one socket while cookie-carrying requests that need no key at all go unserved. Losing the
/// race costs the loser one stale answer, which for a genuinely rotated key is one `401` and
/// a retry a moment later.
///
/// A failure advances `last_refresh` by [`JWKS_NEGATIVE_TTL`] rather than leaving it stale,
/// for the same reason: the eager retry it replaced turned a dead issuer into an unbounded
/// stream of 3-second fetches.
fn refresh_jwks_if_due(state: &State) {
    let issuer = state.settings.read().unwrap().issuer.clone();
    if issuer.is_empty() {
        return;
    }
    let due = {
        let c = state.jwks.read().unwrap();
        c.last_refresh.elapsed() > JWKS_TTL || c.issuer != issuer
    };
    if !due {
        return;
    }
    // Never block: whoever holds this is already doing the fetch we would do.
    let Ok(_guard) = state.jwks_refresh.try_lock() else {
        return;
    };
    let still_due = {
        let c = state.jwks.read().unwrap();
        c.last_refresh.elapsed() > JWKS_TTL || c.issuer != issuer
    };
    if !still_due {
        return;
    }
    match fetch_jwks(&issuer) {
        Ok(new) => {
            let mut c = state.jwks.write().unwrap();
            c.keys = new;
            c.last_refresh = Instant::now();
            c.issuer = issuer;
        }
        Err(e) => {
            eprintln!("[bb-auth] JWKS refresh failed: {e}");
            // Pretend the failed attempt was a success that happened
            // `JWKS_TTL - JWKS_NEGATIVE_TTL` ago, so the next attempt is due in
            // `JWKS_NEGATIVE_TTL`. `checked_sub` because an `Instant` that early does not
            // exist on a machine that just booted, where the eager retry is harmless anyway.
            let mut c = state.jwks.write().unwrap();
            if let Some(t) = Instant::now().checked_sub(JWKS_TTL - JWKS_NEGATIVE_TTL) {
                c.last_refresh = t;
            }
        }
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
/// 60 s leeway), `iss`, `aud` against [`bb_auth_core::Settings::audiences`],
/// `token_use == "id"`,
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

    // One read of the live settings for the whole of this token: the audiences, the
    // relaxation and the claim list are one operator decision, and a reload landing between
    // any two of them would apply half of it.
    let settings = state.settings.read().unwrap();
    let mut v = Validation::new(Algorithm::RS256);
    // The app clients this deployment is part of, from that file: `client_id` and every
    // button's audience. A file that names none accepts no token, which is the honest reading
    // of a gate nobody has told which app client it belongs to, and it is a state a fresh
    // install passes through rather than one an editor can write.
    let aud: Vec<&str> = settings.audiences.iter().map(String::as_str).collect();
    v.set_audience(&aud);
    // The pool, out of the same read. Said here rather than left to an empty `set_issuer`,
    // so a deployment nobody has named a Cognito for reads as the configuration gap it is
    // instead of as a token that failed validation.
    if settings.issuer.is_empty() {
        return Err("no issuer is configured, so no token can be validated".into());
    }
    v.set_issuer(&[settings.issuer.as_str()]);
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
        // Deduplicated for the reason the un-enrolled grant line is: this runs on every
        // bearer-carrying request, not only at the login that created the session.
        if logs(LogLevel::Info) && first_in_window(&format!("unverified:{email}")) {
            eprintln!(
                "[bb-auth] accepting unverified email via social login [{}]: {email}",
                social_provider_names(&c.identities)
            );
        }
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
///
/// The identifier is re-checked with [`header_safe_email`] on the way *in*, exactly as
/// [`decode_claims_segment`] re-derives its own minting invariants rather than trusting that
/// a signature implies them. It is the one field of the cookie that goes straight out again
/// as a header, so it is the field where "this cannot happen" is worth the two lines it costs
/// to stop happening: a signature verifying over bytes we could not have minted is either a
/// bug here or a compromised key, and both call for the same fail-closed answer the claims
/// segment gives.
fn finish_session(exp: u64, eb: &str) -> Option<String> {
    if exp <= now() {
        return None;
    }
    let email = String::from_utf8(URL_SAFE_NO_PAD.decode(eb).ok()?).ok()?;
    let email = email.to_ascii_lowercase();
    header_safe_email(&email).then_some(email)
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
    // Saturating, though `compile_settings` already refuses a `session_ttl_secs` anywhere
    // near the wrap: this is the arithmetic whose overflow mints a cookie that expired
    // before it was handed over, and it costs nothing to make it structurally impossible
    // rather than impossible by the settings file alone.
    let exp = now().saturating_add(ttl);
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
fn build_cookie(cfg: &Config, settings: &Settings, value: &str, max_age: i64) -> String {
    let mut c = format!(
        "{}={}; Max-Age={}; Path=/; HttpOnly; Secure; SameSite=Lax",
        cfg.cookie_name, value, max_age
    );
    if let Some(d) = &settings.cookie_domain {
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
/// Rejects any other scheme, control bytes, userinfo (`@`) and backslashes. A `:port` suffix is
/// tolerated on the candidate and stripped before matching (patterns are bare hosts).
///
/// Matching is the same [`bb_auth_core::glob_match`] a scope's URL patterns use, so
/// `*.badbat75.com` accepts `mcp.badbat75.com` but neither `evilbadbat75.com` nor
/// `badbat75.com.evil.com` — the literal dot in the pattern is what rules those out. It does
/// *not* accept the bare apex `badbat75.com`; list it explicitly if you want it.
fn rd_url_allowed(url: &str, hosts: &[UrlPattern]) -> bool {
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

/// What a granted request carries.
///
/// [`Granted::Anonymous`] names nobody: no identity header, no profile header, nothing for an
/// application to key on. That is not an omission, it is what an `anonymous` scope says, and
/// it is what a request with no credential at all gets on one.
///
/// A request that *did* carry a credential is still named on such a scope, which is worth
/// being explicit about because it makes the header bimodal: the same URL answers with
/// `X-Auth-Email` for a signed-in visitor and without it for everybody else. The area is open
/// either way, so this is decoration and never authorization, and an application on an
/// `anonymous` scope must treat the header as "if you know who this is, say so" rather than
/// as a condition of service. The one caller never named is a **vetoed** one
/// ([`authorize_login`]): `denied` cannot close an area that is open with no credential at
/// all, but it can and does stop the gate from introducing that person to the application
/// behind it.
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
///
/// The profile claims need no such argument either: their header names are derived from an
/// `[A-Za-z0-9_:-]` claim name and their values go through [`pct_encode`], which emits
/// printable ASCII whatever it is handed — so safety is a property of the construction, not
/// of where the value came from.
///
/// **Both checks are made anyway, at run time, in release.** They used to be `debug_assert!`s,
/// which is the one shape a guard must not have here: `[profile.release]` compiles those out,
/// so what actually shipped was [`h`]'s `expect`, and with `panic = "abort"` under
/// `Restart=on-failure` a value that slipped through would take the process down and keep
/// taking it down. The argument above says neither check can fire today; it is a fourth
/// credential added later that they exist for, and then the right answer is one header
/// missing and a line in the journal, not a gate that stops answering.
fn respond_authorized(req: Request, granted: &Granted, state: &State) {
    // The settings lock is taken here and released before the socket write, which is why
    // this takes the `State` and not a `&Settings`: the three call sites used to pass
    // `&state.settings.read().unwrap()`, and a temporary guard in an argument lives to the
    // end of the *statement*, so every one of them held a read lock across `req.respond`.
    // `main`'s own comment says nothing below it may do that, because a SIGHUP swap waits
    // for the last reader and a slow client would make it wait for the network.
    let resp = {
        let settings = state.settings.read().unwrap();
        authorized_response(granted, &settings)
    };
    let _ = req.respond(resp);
}

/// The `204` itself, built while the settings lock is held and sent after it is not.
fn authorized_response(granted: &Granted, settings: &Settings) -> ResponseBox {
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
            // A `debug_assert!` was the whole guard here, and `[profile.release]` compiles
            // that out: what shipped was `h()`'s `expect`, i.e. a panicking worker, and with
            // `panic = "abort"` and `Restart=on-failure` a restart loop. The property still
            // holds by construction (both routes into an identity check it), so this can
            // only ever fire on a fourth route somebody adds later. It costs one scan of a
            // short string and it turns that mistake into a header nobody gets rather than a
            // gate nobody gets through. The space is admitted because it is what joins a
            // multi-valued attribute, and it is the one byte an identifier cannot contain.
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                eprintln!("[bb-auth] BUG: unsafe identity header {name}, omitted");
                continue;
            }
            resp = resp.with_header(h(name, &value));
        }
        for (name, enc) in profile_headers(&settings.profile_claims, &who.claims) {
            // Same reasoning, one step weaker: `pct_encode` emits printable ASCII whatever
            // it is handed, so this can only catch a later change that emits a value raw.
            if enc.is_empty()
                || !enc.bytes().all(|b| b.is_ascii_graphic())
                || !name.bytes().all(|b| b.is_ascii_graphic())
            {
                eprintln!("[bb-auth] BUG: unsafe claim header {name}, omitted");
                continue;
            }
            resp = resp.with_header(h(name, &enc));
        }
    }
    resp.boxed()
}

/// Respond `401` to a rejected `auth_request`, naming the login page in
/// [`LOGIN_URL_HEADER`] so nginx can redirect there. `login_url` came from
/// [`login_url_for`], hence passed [`bb_auth_core::compile_login_url`] or is
/// [`OWN_LOGIN_PATH`], hence cannot make [`h`] panic.
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
///
/// `no-store` for the same reason the pages carry it, and with more at stake: these two
/// redirects are the ones that carry the `Set-Cookie`, so a cache or a browser that kept one
/// would be keeping a whole session, and the logout's redirect is a cookie *clear* that must
/// never be served from a store either. A `302` is not cacheable by default, which is exactly
/// the kind of default worth not depending on for this.
fn respond_redirect(req: Request, location: &str, set_cookie: Option<&str>) {
    let mut resp = Response::empty(StatusCode(302))
        .with_header(h("Location", location))
        .with_header(h("Cache-Control", "no-store"));
    if let Some(sc) = set_cookie {
        resp = resp.with_header(h("Set-Cookie", sc));
    }
    let _ = req.respond(resp);
}

// ---------------------------------------------------------------------------
// The gate's own pages
// ---------------------------------------------------------------------------
//
// Three HTML surfaces, and every one of them is complete on its own: the sign-in page, the
// social callback that finishes an OAuth leg, and the error page a failed `/auth/session`
// lands on. Nothing here fetches a stylesheet, a font or a script from another host, because
// the situation these pages exist for is the one where somebody cannot get in, and a sign-in
// page that needs a CDN to be up has picked exactly the wrong moment to have a dependency.
//
// The look is `bb_auth_core::THEME_CSS` (the palette) plus `bb_auth_core::BASE_CSS` (the
// components) plus [`AUTH_CSS`] (this arrangement of them), in that order, and an operator's
// own stylesheet (`ui.stylesheet_url`) loads after all three. The first two are the same
// bytes `bb-auth-web` emits, which is what makes these pages and the admin interface one
// product rather than two that were once made to match. See the presentation contract in the
// library.

/// How these pages ARRANGE the shared components: one centred card, the steps inside it, and
/// the few things only a sign-in page has (the language toggle, the identity-provider
/// buttons, the divider). What a card, a field, a button or a message box is made of is
/// `BASE_CSS`, and what a colour is worth is `THEME_CSS`; this file defines neither, which is
/// what the operator's stylesheet relies on.
const AUTH_CSS: &str = include_str!("../assets/auth.css");

/// The sign-in page, served at `GET /auth/login`.
///
/// **Why the gate serves it.** bb-auth is built for the flow where a page runs Cognito
/// `USER_AUTH` in the browser and POSTs the resulting id_token to `/auth/session`. That page
/// needs the app-client id, the issuer's endpoint and the list of hosts a post-login `rd` may
/// land on, and the gate already holds all three **as the values it validates against**: the
/// client id is one it accepts as an audience ([`bb_auth_core::Settings::audiences`]), the endpoint is derived from
/// the issuer whose signature it verifies ([`cognito_endpoint`]), and the hosts are
/// what [`safe_rd`] enforces. Served from here, the page and the gate cannot disagree about
/// any of them; served from a static host, every one of the three is a second copy.
///
/// **The flow it runs**, all in the page, against the unauthenticated Cognito JSON API with a
/// public app client and no secret:
///
/// 1. email → `InitiateAuth(USER_AUTH, PREFERRED_CHALLENGE=EMAIL_OTP)`. A known user gets an
///    `EMAIL_OTP` challenge and the code step; `UserNotFoundException` branches to sign-up.
///    That branch is why the app client must stay at `prevent_user_existence_errors=LEGACY`:
///    otherwise Cognito answers a fake challenge for unknown users and there is nothing to
///    branch on.
/// 2. signing in: `RespondToAuthChallenge(EMAIL_OTP)` → tokens. Signing up: `SignUp` →
///    `ConfirmSignUp`, whose `Session` is exchanged for tokens with **no second OTP**
///    (Cognito auto sign-in). That is the whole reason this gate takes an id_token instead of
///    driving an authorization-code flow itself.
/// 3. a top-level form POST of the id_token to `/auth/session`, same origin, which answers
///    `302` to `rd`.
///
/// **Substitution** is `__BB_*__` placeholders through [`render_page`], never `format!`: the
/// file is thick with the `{}` of JavaScript and CSS, and each one would have to be doubled
/// in a file that everything else reads as JavaScript and CSS. Every value substituted in is
/// either a value the settings parser vouched for (an app client id, an OAuth domain: see
/// [`bb_auth_core::compile_app_client_id`], printable ASCII with no quotes) or is
/// HTML-escaped on the way in. Request data reaches the page in exactly one place, `data-rd`
/// on `<body>`, as an escaped attribute and never as JavaScript source.
const LOGIN_HTML: &str = include_str!("../assets/login.html");

/// The social callback, served at `GET /auth/callback`, and only when `BB_AUTH_SOCIAL_*` is
/// configured: with no social client there is no OAuth leg to finish.
///
/// It is here for the same reason [`LOGIN_HTML`] is, plus one of its own: this URL is
/// registered on the Cognito app client as `redirect_uri`, and the value baked into the page
/// must match it **exactly** or the exchange fails with `redirect_mismatch`. Both now come
/// from one place, `BB_AUTH_SOCIAL_CALLBACK_URL`.
///
/// Cognito redirects here with `?code=…&state=…`; the page exchanges the code and the PKCE
/// verifier the sign-in page left in `sessionStorage` for tokens, and then delivers the
/// id_token exactly as the sign-in page does. One extra step in the middle: a federated IdP
/// that omits `given_name`/`family_name` (personal Microsoft accounts, notably) lands here
/// with empty name claims, so the page offers a small profile form, writes the answer back
/// with `UpdateUserAttributes`, and refreshes the id_token before delivering it. Nothing on
/// this page comes from the request: the code and the state are read by its own script.
const CALLBACK_HTML: &str = include_str!("../assets/callback.html");

/// What the pages call themselves when `ui.brand_name` says nothing. The binary's own name:
/// an unconfigured deployment should look unconfigured rather than borrow somebody's brand.
const DEFAULT_BRAND: &str = "bb-auth";

/// The mark this page draws beside a provider's name, as `(Cognito identity_provider, icon)`.
///
/// The names and the labels are the library's [`bb_auth_core::SOCIAL_IDPS`], because the admin GUI offers a
/// switch per provider and the two must agree on what each one is called. The icon is not
/// shared: it is an inline SVG on a page, the GUI has no use for one, and the membership rule
/// is about what more than one program must agree on rather than about keeping like with
/// like.
///
/// The *set* is code and the *choice* is configuration, the same split
/// `derive_profile_header` makes for claims. A provider this table has never heard of still
/// gets a button, labelled with its own name and with no icon, because a pool may federate an
/// IdP nobody here anticipated and refusing to draw it would be worse than drawing it plainly.
///
/// The icons are inline SVG for the reason everything else on these pages is inline: an
/// `<img>` would be a second request, to a host that is not this one, on the page that most
/// needs to work when something else is down.
const IDP_ICONS: [(&str, &str); 2] = [
    (
        "Google",
        r##"<svg viewBox="0 0 48 48" aria-hidden="true"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.4 29.3 35 24 35c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34.3 6.1 29.4 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.3-.4-3.5z"/><path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34.3 6.1 29.4 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 10-2 13.6-5.2l-6.3-5.3C29.2 35 26.7 36 24 36c-5.3 0-9.7-2.6-11.3-7l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.1-4 5.5l6.3 5.3C41.9 36.4 44 30.8 44 24c0-1.3-.1-2.3-.4-3.5z"/></svg>"##,
    ),
    (
        "MicrosoftPersonal",
        r##"<svg viewBox="0 0 23 23" aria-hidden="true"><path fill="#F25022" d="M1 1h10v10H1z"/><path fill="#7FBA00" d="M12 1h10v10H12z"/><path fill="#00A4EF" d="M1 12h10v10H1z"/><path fill="#FFB900" d="M12 12h10v10H12z"/></svg>"##,
    ),
];

/// Substitute `__BB_*__` placeholders into one of the page templates.
///
/// A scanner rather than `str::replace` in a loop, and that is a safety property and not a
/// performance one: **a substituted value is never rescanned**, so a brand name or a URL that
/// happens to contain `__BB_HEAD__` is text on the page and not a second substitution. It is
/// also why the templates are placeholders at all rather than a `format!` string: they are
/// thick with the `{}` of JavaScript and CSS, and every one of those would have to be
/// doubled, in a file that is also read as JavaScript and CSS by everything else that opens
/// it.
///
/// An unknown `__BB_` sequence is left standing, which is deliberate: it renders visibly on
/// the page and in the test that reads it, rather than disappearing into a page that is
/// quietly missing something.
fn render_page(template: &str, subs: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(template.len() + 4096);
    let mut rest = template;
    while let Some(i) = rest.find("__BB_") {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        // The LONGEST match, not the first: no key today is a prefix of another, but
        // `__BB_CLIENT_ID__` beside a future `__BB_CLIENT_ID_HINT__` would substitute the
        // short one and leave `_HINT__` sitting on the page. Picking the longest makes the
        // table order irrelevant, which is what a caller assembling it with `push` expects.
        match subs
            .iter()
            .filter(|(k, _)| tail.starts_with(*k))
            .max_by_key(|(k, _)| k.len())
        {
            Some((k, v)) => {
                out.push_str(v);
                rest = &tail[k.len()..];
            }
            None => {
                out.push_str("__BB_");
                rest = &tail["__BB_".len()..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// A `Content-Security-Policy` nonce for one response: 128 bits from the OS CSPRNG,
/// base64url.
///
/// Per response and unguessable, which is what a nonce is for: the policy names it, the two
/// inline blocks of the page carry it, and script an attacker gets onto the page by any means
/// does not. Random rather than a [`bb_auth_core::csp_hash`] of the content, because the sign-in page's
/// script is assembled per render out of the configuration and hashing it would mean hashing
/// the rendered output back out of the document.
///
/// `getrandom` is already how `bb-auth-adm` mints an API key, so this is the OS entropy source
/// the crate already depends on and no new one. A failure to read entropy is fatal for the
/// same reason it is there: a predictable nonce is a policy that has stopped being one, and
/// this is a machine where `/dev/urandom` not answering is not a survivable condition.
fn csp_nonce() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS CSPRNG");
    URL_SAFE_NO_PAD.encode(b)
}

/// The substitutions every page of the gate's shares: the head, the theme, the brand and the
/// logo. All four come from the settings file, so all four are live on the next request.
///
/// `nonce` is the one value that is neither settings nor configuration: it belongs to this
/// response alone and goes on both inline blocks the page carries, so that the
/// [`page_csp`] the same handler builds can name it.
fn look_subs(settings: &Settings, nonce: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "__BB_NONCE__",
            // Base64url by construction, so there is nothing here that could break out of
            // the attribute it lands in; escaped anyway, because that is a property of the
            // emission and not of today's caller.
            html_escape(nonce),
        ),
        (
            "__BB_HEAD__",
            format!(
                "  <style nonce=\"{}\">{THEME_CSS}{BASE_CSS}{AUTH_CSS}</style>\n  {}",
                html_escape(nonce),
                stylesheet_link(settings.stylesheet_url.as_deref())
            ),
        ),
        (
            "__BB_THEME_ATTR__",
            match settings.theme.attr() {
                Some(a) => format!(" data-theme=\"{a}\""),
                None => String::new(),
            },
        ),
        (
            "__BB_BRAND__",
            html_escape(settings.brand_name.as_deref().unwrap_or(DEFAULT_BRAND)),
        ),
        (
            // Decorative, so `alt` is empty on purpose: the heading beside it already says
            // the name, and a screen reader announcing it twice is worse than not at all.
            "__BB_LOGO__",
            match settings.logo_url.as_deref() {
                Some(u) => format!("      <img src=\"{}\" alt=\"\">", html_escape(u)),
                None => String::new(),
            },
        ),
    ]
}

/// Cognito's two hosted-UI endpoints for a domain: where a browser is sent, and where the
/// callback exchanges its code. Derived rather than configured, so the two can never name
/// different pools, which is the same argument `cognito_endpoint` is derived under.
fn oauth_urls(domain: &str) -> (String, String) {
    (
        format!("https://{domain}/oauth2/authorize"),
        format!("https://{domain}/oauth2/token"),
    )
}

/// The social sign-in this deployment offers right now: the hosted-UI domain and the
/// `redirect_uri`, or `None` when it offers none.
///
/// Both halves come from the settings file, and [`bb_auth_core::compile_settings`] has
/// already refused a file that names buttons without them, so this is a question about
/// whether social sign-in is configured at all and never about whether it is coherent. The
/// per-button app client is on the button, because Cognito federates per app client.
fn social_ready(settings: &Settings) -> Option<(&str, &str)> {
    match (&settings.oauth_domain, &settings.social_callback_url) {
        (Some(d), Some(c)) => Some((d.as_str(), c.as_str())),
        _ => None,
    }
}

/// What social sign-in is doing, in one phrase, for the startup banner: the providers and the
/// app client each runs through, or the reason there is nothing to draw.
fn social_state(settings: &Settings) -> String {
    let Some((domain, callback)) = social_ready(settings) else {
        return "(off: no oauth_domain and no social_callback_url)".to_string();
    };
    if settings.social_buttons.is_empty() {
        return format!("(off: {domain} is configured but no button is)");
    }
    let wired: Vec<String> = settings
        .social_buttons
        .iter()
        .map(|b| format!("{} as {}", b.idp, b.audience))
        .collect();
    format!("{} via {callback}", wired.join(", "))
}

/// The social block of the sign-in page: a divider and one button per configured provider, or
/// nothing at all.
///
/// Nothing at all is the important half. With no `BB_AUTH_SOCIAL_*` configured the divider
/// goes too, and the page's own script finds no `[data-idp]` to bind, so there is no branch
/// anywhere saying "if social is off" — the markup simply is not there.
fn social_block(buttons: &[SocialButton]) -> String {
    // An empty list is the same page as no social configuration at all, which is deliberate:
    // there is one way for the section to be absent, not two that look different.
    if buttons.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for b in buttons {
        // The label is the library's, so a person reads the same word here and in the row of
        // the admin table that enabled it; the icon is this page's, and a provider it has
        // never heard of simply has none.
        let label = social_idp_label(&b.idp);
        let icon = IDP_ICONS
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&b.idp))
            .map(|(_, svg)| *svg)
            .unwrap_or("");
        // The app client rides on the button because it is the button's: the script reads it
        // when this one is clicked and stores it for the callback, which is what lets two
        // providers sign in through two different app clients on one page.
        out.push_str(&format!(
            "        <button type=\"button\" class=\"social-btn\" data-idp=\"{idp}\" data-client-id=\"{aud}\">\n\
             \x20         {icon}\n\
             \x20         <span data-i18n=\"btn_social\" data-i18n-arg=\"{label}\">Continue with {label}</span>\n\
             \x20       </button>\n",
            idp = html_escape(&b.idp),
            aud = html_escape(&b.audience),
            label = html_escape(label),
        ));
    }
    format!(
        "      <div class=\"divider\"><span data-i18n=\"or\">or</span></div>\n\
         \x20     <div class=\"social\">\n{out}      </div>"
    )
}

/// Serve `GET /auth/login`.
///
/// The one request-supplied value on the page is `rd`, and it is validated **here**, against
/// the same `BB_AUTH_AUTHORIZED_HOSTS` [`safe_rd`] enforces on the way back out. A rejected
/// one becomes the empty string rather than an error: the person came here to sign in, and
/// sending them away over a bad redirect target would be answering a question they did not
/// ask. It reaches the page as an escaped HTML attribute and never as JavaScript source.
///
/// Absolute URLs only, which is what [`rd_url_allowed`] takes. A relative `rd` cannot be
/// resolved here without knowing which host the browser is on, and this page deliberately
/// does not depend on nginx setting `BB_AUTH_ORIGINAL_URL_HEADER` on its location: the
/// login page must be the one location that is impossible to get wrong.
///
/// With no `rd` at all (somebody opened the sign-in page themselves instead of being bounced
/// here off a `401`), [`REFERER_HEADER`] answers in its place, through the same check: the
/// browser says where this visitor came from, and after signing in they go back there. It is
/// a guess and it is allowed to fail, which is the point of it being second: with nothing
/// usable the page carries no `rd`, `/auth/session` falls back to the caller's root, and the
/// login still works.
fn handle_login(req: Request, state: &State) {
    let nonce = csp_nonce();
    // The page's script speaks to exactly one host, the issuer's own API endpoint, and the
    // social leg is a top-level navigation rather than a fetch. One read covers all of it,
    // the redirect scope included: where a login may land and where its page may talk are one
    // operator decision, and a reload between the two would apply half of it.
    let (page, csp) = {
        let settings = state.settings.read().unwrap();
        let rd = login_rd(
            query_param(req.url(), "rd").as_deref(),
            header_value(&req, REFERER_HEADER),
            &settings.authorized_hosts,
        );
        let endpoint = cognito_endpoint(&settings);
        let page = login_page(&settings, &rd, &nonce);
        let csp = gate_csp(&settings, &nonce, &[&endpoint]);
        (page, csp)
    };
    respond_page(req, 200, page, &csp);
}

/// Where a browser endpoint is told to send somebody: the link's own `?rd=`, else
/// [`REFERER_HEADER`]. `None` when neither said anything, which is the caller's own business
/// to answer.
///
/// The order is who wrote each one. A `?rd=` was written for *this* link and means something
/// specific; the `Referer` was written by the browser about a link that meant nothing in
/// particular, so it is a courtesy and never a contract (see the constant for the several
/// ways it simply is not there).
///
/// An empty value is treated as absent, because that is what a link rendering `?rd=` from an
/// empty template variable produces. What does **not** happen is falling through on a
/// *rejected* candidate: whoever spoke first is answered on its own merits, and if its value
/// does not pass the caller's guard the caller's own default applies. Otherwise a crafted
/// `?rd=` would silently promote the `Referer`, and the person would land somewhere no part
/// of the request asked for.
fn rd_candidate<'a>(rd: Option<&'a str>, referer: Option<&'a str>) -> Option<&'a str> {
    [rd, referer].into_iter().flatten().find(|v| !v.is_empty())
}

/// The `rd` the sign-in page is given: [`rd_candidate`]'s two, and only if
/// [`rd_url_allowed`] takes it. The empty string means the page carries none and
/// `/auth/session` will decide where the login lands.
///
/// The chain is [`logout_target`]'s. What differs is the failure: a rejected candidate here
/// is dropped rather than replaced, because this page's job is to sign somebody in and
/// refusing to render it over a bad redirect target answers a question nobody asked. And
/// absolute URLs only, which is the shape a cross-origin `Referer` already arrives in.
fn login_rd(rd: Option<&str>, referer: Option<&str>, hosts: &[UrlPattern]) -> String {
    rd_candidate(rd, referer)
        .filter(|r| rd_url_allowed(r, hosts))
        .unwrap_or_default()
        .to_string()
}

/// Render the sign-in page. Separate from [`handle_login`] so that what the page says can be
/// asserted without a socket, which is the only way a test can read a page this size.
fn login_page(settings: &Settings, rd: &str, nonce: &str) -> String {
    let mut subs = look_subs(settings, nonce);
    subs.push(("__BB_RD__", html_escape(rd)));
    subs.push(("__BB_ENDPOINT__", cognito_endpoint(settings)));
    // The app client the email flow runs against. Empty is a deployment nobody has told
    // which app client it is, and the page then cannot complete a login: the gate says so at
    // startup rather than here, because a page is the wrong place to explain a config gap.
    subs.push(("__BB_CLIENT_ID__", settings.client_id.clone()));
    // The social half, asked once. Each button carries its own app client, so there is no
    // page-wide client id any more: what is page-wide is where the browser is sent and where
    // it comes back to.
    let social = social_ready(settings);
    subs.push((
        "__BB_AUTHORIZE_URL__",
        social
            .map(|(domain, _)| oauth_urls(domain).0)
            .unwrap_or_default(),
    ));
    subs.push((
        "__BB_CALLBACK_URL__",
        social.map(|(_, cb)| cb.to_string()).unwrap_or_default(),
    ));
    subs.push((
        "__BB_SOCIAL_BUTTONS__",
        social_block(&settings.social_buttons),
    ));
    render_page(LOGIN_HTML, &subs)
}

/// The sign-in page this gate serves itself, as a path.
///
/// It is what [`global_login`] answers with when the settings file names none, and a path
/// rather than a URL because the gate knows neither its own scheme nor its own host: a
/// relative `Location` resolves against whatever vhost the request arrived at, which is the
/// one place a sign-in page is certainly reachable from.
const OWN_LOGIN_PATH: &str = "/auth/login";

/// Where people sign in, for an application that names no page of its own: the settings
/// file's value, or this gate's own page.
///
/// Never empty, which is what lets every caller emit it into a header or a `Location` with no
/// second check: `compile_login_url` vouched for the configured value at load, and the
/// default is a constant.
fn global_login(settings: &Settings) -> &str {
    match settings.login_url.as_str() {
        "" => OWN_LOGIN_PATH,
        url => url,
    }
}

/// Serve `GET /auth/callback`, the page that finishes a social sign-in.
///
/// A `404` when this deployment has no social sign-in at all, because then there is no OAuth
/// leg for it to finish and a page that offers to retry one would be a lie. It takes nothing
/// from the request: the code and the state are read by its own script, and the PKCE verifier
/// **and the app client the login page picked** are in `sessionStorage` where that page left
/// them. That is what lets one callback finish a leg started through any of several app
/// clients: the page that chose one is the page that remembers it.
fn handle_callback(req: Request, state: &State) {
    let nonce = csp_nonce();
    // This page's script POSTs to the token endpoint of the OAuth domain and then hands the
    // id_token to `/auth/session`, which `form-action 'self'` already covers. Rendered under
    // the read lock and answered outside it, so the 404 arm and the 200 arm hold it for the
    // same short moment.
    let rendered = {
        let settings = state.settings.read().unwrap();
        social_ready(&settings).map(|(domain, callback)| {
            let (_, token_url) = oauth_urls(domain);
            let page = callback_page(&token_url, callback, &settings, &nonce);
            let token_origin = origin_of(&token_url).unwrap_or_default();
            let endpoint = cognito_endpoint(&settings);
            let csp = gate_csp(&settings, &nonce, &[&endpoint, &token_origin]);
            (page, csp)
        })
    };
    match rendered {
        Some((page, csp)) => respond_page(req, 200, page, &csp),
        None => respond_empty(req, 404),
    }
}

/// Render the callback page. Split from its handler for the reason [`login_page`] is.
fn callback_page(token_url: &str, callback_url: &str, settings: &Settings, nonce: &str) -> String {
    let mut subs = look_subs(settings, nonce);
    subs.push(("__BB_ENDPOINT__", cognito_endpoint(settings)));
    subs.push(("__BB_TOKEN_URL__", token_url.to_string()));
    // No app client here on purpose: the one to exchange with is whichever the clicked button
    // named, and only the page that clicked it knows that.
    subs.push(("__BB_CALLBACK_URL__", callback_url.to_string()));
    render_page(CALLBACK_HTML, &subs)
}

/// This page's `Content-Security-Policy`: [`page_csp`] with the same `nonce` on both inline
/// blocks, plus the origins this particular page's script talks to.
///
/// One place, so the three pages cannot end up with three policies. The nonce covers the
/// `<style>` [`look_subs`] builds and the `<script>` the template carries, which between them
/// are everything either page executes: there is no second script, no external one, and
/// nothing loaded from anywhere the settings did not name.
fn gate_csp(settings: &Settings, nonce: &str, connect: &[&str]) -> String {
    let src = format!("'nonce-{nonce}'");
    page_csp(
        &src,
        &src,
        settings.stylesheet_url.as_deref(),
        settings.logo_url.as_deref(),
        connect,
    )
}

/// Respond with a whole HTML document.
///
/// The headers are [`PAGE_SECURITY_HEADERS`], which the admin GUI sends too and which is
/// where the reasoning for each of them lives, plus this page's own policy. A login page is
/// the page in the estate most worth spending a CSP on: it is the one whose entire job is to
/// hold a credential for a moment, and the one a deployment can point at an external
/// stylesheet through a GUI field.
fn respond_page(req: Request, status: u16, body: String, csp: &str) {
    let mut resp = Response::from_string(body)
        .with_status_code(StatusCode(status))
        .with_header(h("Content-Type", "text/html; charset=utf-8"))
        .with_header(h("Content-Security-Policy", csp));
    for (k, v) in PAGE_SECURITY_HEADERS {
        resp.add_header(h(k, v));
    }
    let _ = req.respond(resp);
}

/// Respond with the error page the browser sees on a failed `/auth/session`: the same card,
/// the same palette and the same operator stylesheet as the sign-in page it offers to go
/// back to.
///
/// Every interpolated value is escaped by [`html_escape`]. Today the inputs are constants and
/// a validated env value, but there is no structural guarantee a future caller will not pass
/// request data, so nothing is emitted raw.
fn respond_html(req: Request, state: &State, status: u16, title: &str, msg: &str, login_url: &str) {
    let nonce = csp_nonce();
    let settings = state.settings.read().unwrap();
    let head = look_subs(&settings, &nonce)
        .into_iter()
        .find(|(k, _)| *k == "__BB_HEAD__")
        .map(|(_, v)| v)
        .unwrap_or_default();
    let theme = match settings.theme.attr() {
        Some(a) => format!(" data-theme=\"{a}\""),
        None => String::new(),
    };
    // This page has no script of its own and nothing to say to Cognito: it is a sentence and
    // a link back. `'none'` rather than the nonce, because a policy that permits what the
    // page does not do is a policy with nothing left to enforce.
    let csp = page_csp(
        "'none'",
        &format!("'nonce-{nonce}'"),
        settings.stylesheet_url.as_deref(),
        settings.logo_url.as_deref(),
        &[],
    );
    drop(settings);
    let title = html_escape(title);
    let msg = html_escape(msg);
    let login_url = html_escape(login_url);
    let body = format!(
        "<!doctype html>\n<html lang=\"en\"{theme}>\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <title>{title}</title>\n{head}\n</head>\n\
         <body><main class=\"card\">\n\
         <div class=\"brand\"><h1>{title}</h1></div>\n\
         <p class=\"status\">{msg}</p>\n\
         <p class=\"center hint\"><a href=\"{login_url}\">&larr; Back to sign-in</a></p>\n\
         </main></body>\n</html>\n"
    );
    respond_page(req, status, body, &csp);
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// The original request URL nginx is guarding, from the configured header, normalised by
/// [`request_url`]. `None` if the header is absent (which a restricted scope treats as a
/// denial).
///
/// The normalisation is the library's and not a copy of it, which matters more here than
/// anywhere else it is called: [`request_url`] is what `bb-auth-adm can` and the admin GUI's
/// access check run their URL through, and the whole value of those two is that they answer
/// the question *this* function asks. They were byte-identical expressions in two files,
/// which is the state a shared rule is in just before it stops being one.
fn original_url(req: &Request, cfg: &Config) -> Option<String> {
    header_value(req, &cfg.original_url_header).map(request_url)
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
    // Every refusal reads the same and returns the same, so it is written once. It is quiet
    // at `LogLevel::Error`, where a `401` on a gated URL is the ordinary case rather than an
    // event: that is the level for a gate in front of something the public browses.
    let deny = |why: std::fmt::Arguments| -> bool {
        if logs(LogLevel::Info) {
            eprintln!("[bb-auth] denied: {why}");
        }
        false
    };
    match decide(access, subject, url) {
        // An anonymous scope is the steady state of a health endpoint, so it is not
        // logged: a line per poll would bury everything that matters.
        Decision::Anonymous { .. } => true,
        Decision::Granted { app, scope } => {
            // The one grant worth a line: somebody Cognito vouches for, who is in no
            // roster row, just walked in. That is what an `authenticated` scope is for,
            // and an operator should be able to see it happening.
            if let Subject::Identifier(id) = subject {
                // Once per identity per window: it says the same thing on the hundredth
                // request as on the first, and this fires on every request that carries a
                // credential into an `authenticated` area.
                if access.uuid_of(id).is_none() && logs(LogLevel::Info) && first_in_window(id) {
                    eprintln!(
                        "[bb-auth] granted via {app}/{scope} to an un-enrolled identity: {id}"
                    );
                }
            }
            true
        }
        Decision::Vetoed => deny(format_args!("{who} is on the denied list")),
        Decision::Excluded { app, scope } => deny(format_args!("{app}/{scope} excludes {who}")),
        Decision::NoApplication => deny(format_args!("no application covers {} [{who}]", at())),
        Decision::NoScope { app } => deny(format_args!(
            "application '{app}' has no scope for {} [{who}]",
            at()
        )),
        Decision::Unauthenticated { app, scope } => {
            deny(format_args!("{app}/{scope} needs an identity"))
        }
        Decision::CredentialRefused { app, scope } => deny(format_args!(
            "{app}/{scope} does not admit this credential [{who}]"
        )),
        Decision::NotEnrolled { app, scope } => {
            deny(format_args!("{who} is in no users entry [{app}/{scope}]"))
        }
        Decision::NotMember { app, scope } => {
            deny(format_args!("{app}/{scope} does not list {who}"))
        }
        Decision::KeyOutOfScope { app, scope } => deny(format_args!(
            "this key may not exercise {app}/{scope} [{who}]"
        )),
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
    // A vetoed identity is never named downstream, and reaching this line means one just
    // was authorized: `denied` outranks every grant except an `anonymous` scope, which
    // grants before it and to everybody. So the request is genuinely authorized and the
    // person genuinely has no business being introduced to the application behind it. The
    // area is open to anyone with no credential at all, so answering as that is exactly
    // what the scope says, and it is what a client under this veto would get by simply not
    // sending their cookie.
    if access.vetoes_identifier(&email) {
        return Some(Granted::Anonymous);
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
            respond_authorized(req, &granted, state);
            return;
        }
    }

    let granted = header_value(&req, "Cookie")
        .and_then(|c| cookie_value(c, &cfg.cookie_name).map(str::to_string))
        .and_then(|v| verify_session(&v, &cfg.hmac_keys))
        .and_then(|ident| authorize_login(&state.access.read().unwrap(), ident, url.as_deref()));
    if let Some(granted) = granted {
        respond_authorized(req, &granted, state);
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
            login_url_for(
                &access,
                global_login(&state.settings.read().unwrap()),
                url.as_deref(),
            ),
        )
    };
    if anonymous {
        respond_authorized(req, &Granted::Anonymous, state);
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
        global_login(&state.settings.read().unwrap()),
        caller_url.as_deref(),
    );

    // Where did this POST come from? A session cookie is minted here, and minting one for
    // somebody else's form is login CSRF: an attacker registers with Cognito (self-signup is
    // open, so their token costs nothing), auto-submits a top-level form carrying it, and the
    // victim then browses the whole cookie domain as the attacker. `SameSite=Lax` is not a
    // defence against it, because it governs when the cookie is *sent* and not who may cause
    // one to be *set*.
    //
    // `same-site` passes as well as `same-origin`, which is deliberate and is the one place
    // this differs from `bb-auth-web`'s door: `BB_AUTH_LOGIN_URL` may name a sign-in page an
    // operator serves themselves, on a sibling host of the same estate, and that page has
    // always been able to POST here. The cookie's own `Domain` is the site, so a page inside
    // it is inside the trust boundary already. `cross-site` and a browser that says nothing
    // are refused: neither is a form of ours being submitted.
    let site = request_site(
        header_value(&req, "Sec-Fetch-Site"),
        header_value(&req, "Origin"),
        header_value(&req, "Host"),
    );
    if !matches!(site, RequestSite::SameOrigin | RequestSite::SameSite) {
        eprintln!("[bb-auth] session refused: {site:?} POST to /auth/session");
        respond_html(
            req,
            state,
            403,
            "Sign-in failed",
            "This sign-in did not come from the sign-in page. Please start again.",
            &login,
        );
        return;
    }

    let mut buf = Vec::new();
    if req
        .as_reader()
        .take(MAX_BODY)
        .read_to_end(&mut buf)
        .is_err()
    {
        respond_html(req, state, 400, "Error", "Invalid request.", &login);
        return;
    }
    let form: HashMap<String, String> = form_urlencoded::parse(&buf).into_owned().collect();

    let id_token = match form.get("id_token") {
        Some(t) if !t.is_empty() => t,
        _ => {
            respond_html(req, state, 400, "Error", "Missing token.", &login);
            return;
        }
    };

    let ident = match validate_id_token(id_token, state) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("[bb-auth] session rejected: {e}");
            respond_html(
                req,
                state,
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
            state,
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
    // One read for where this login may land, how long it lasts and which domain its cookie
    // carries. All three are read NOW rather than at startup, which for the lifetime is what
    // keeps an edit to it out of the logout business (it applies to sessions from here on and
    // to no cookie already in a browser) and for the other two is simply where they live.
    let (rd, cookie) = {
        let settings = state.settings.read().unwrap();
        let rd = safe_rd(
            form.get("rd").map(String::as_str),
            caller_origin.as_deref(),
            &settings.authorized_hosts,
            &login,
        );
        let ttl = settings.session_ttl;
        let cookie = build_cookie(
            cfg,
            &settings,
            &make_session(&ident, ttl, &cfg.hmac_keys),
            ttl as i64,
        );
        (rd, cookie)
    };
    eprintln!("[bb-auth] session granted: {} -> {rd}", ident.email);
    respond_redirect(req, &rd, Some(&cookie));
}

/// Where a logout lands: [`rd_candidate`]'s two, and the login page when neither spoke.
/// Whichever answers is request-supplied data landing in a `Location:`, so it goes through
/// the one [`safe_rd`] gate and is trusted for nothing but passing it.
///
/// A `Referer` here names the page the person was on, which after a logout is often a page
/// they may no longer see: they land on it, get a `401`, and reach the login page one hop
/// later. That is the price of a backup nobody configured, and the answer for anyone who
/// minds the hop is to write the `?rd=` on the link, which is the only thing that can name a
/// landing place on purpose.
///
/// The last arm is why this is a function rather than a `safe_rd` call: with no candidate at
/// all `safe_rd` defaults to the caller's root, which is the area the browser has just been
/// signed out of and where its next request is that same `401`. A logout ends at the login
/// page instead.
fn logout_target(
    rd: Option<&str>,
    referer: Option<&str>,
    caller_origin: Option<&str>,
    hosts: &[UrlPattern],
    login_url: &str,
) -> String {
    match rd_candidate(rd, referer) {
        Some(candidate) => safe_rd(Some(candidate), caller_origin, hosts, login_url),
        None => login_url.to_string(),
    }
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
/// open-redirect surface. A relative `rd` needs `BB_AUTH_ORIGINAL_URL_HEADER` on this
/// location too; if nginx omits it the redirect falls back to the login page, which is
/// fail-soft.
///
/// A link that says nothing is the common case, and there the browser's own
/// [`REFERER_HEADER`] answers instead, through the same guard: not because it is reliable,
/// but because it is free and it is the only thing left that knows where the person was.
/// With neither, the browser lands on the login page, *not* on the caller's root, which is
/// what `safe_rd` would default to and is the wrong end for a logout. [`logout_target`] is
/// that order.
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
    // One read, and it ends before the access table is touched. Holding both locks at once,
    // in an order nothing else in this file uses, is the only way these two could ever
    // deadlock against a waiting SIGHUP writer, and a logout is far too rare for the copy to
    // be worth thinking about.
    let (cookie, global, hosts) = {
        let settings = state.settings.read().unwrap();
        let cookie = if cross_site {
            None
        } else {
            Some(build_cookie(cfg, &settings, "", 0))
        };
        (
            cookie,
            global_login(&settings).to_string(),
            settings.authorized_hosts.clone(),
        )
    };

    let caller_url = original_url(&req, cfg);
    let login = login_url_for(
        &state.access.read().unwrap(),
        &global,
        caller_url.as_deref(),
    );
    let target = logout_target(
        query_param(req.url(), "rd").as_deref(),
        header_value(&req, REFERER_HEADER),
        caller_url.as_deref().and_then(origin_of).as_deref(),
        &hosts,
        &login,
    );
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
            // The app clients, which are also the audiences: a Cognito id_token carries the
            // app client it was minted for in `aud`, so naming an app client here IS saying
            // which tokens the gate accepts. Printed rather than judged: whether Cognito has
            // ever heard of one of these is not a question a file can answer.
            println!(
                "[bb-auth] {path}: sign-in page: {}",
                match s.login_url.as_str() {
                    "" => "(none: the gate's own /auth/login, on the calling host)",
                    url => url,
                }
            );
            println!(
                "[bb-auth] {path}: email app client: {}",
                match s.client_id.as_str() {
                    "" => "(none: no login can complete)",
                    id => id,
                }
            );
            println!(
                "[bb-auth] {path}: accepted audiences: {}",
                match s.audiences.len() {
                    0 => "(none)".to_string(),
                    _ => s.audiences.join(", "),
                }
            );
            match (&s.oauth_domain, &s.social_callback_url) {
                (Some(d), Some(c)) => {
                    println!("[bb-auth] {path}: social sign-in via {d}, back to {c}")
                }
                _ => println!("[bb-auth] {path}: social sign-in: (off)"),
            }
            for b in &s.social_buttons {
                println!(
                    "[bb-auth] {path}: button '{}' through app client {}",
                    b.idp, b.audience
                );
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
            // The look, and the stylesheet by name: it is the one setting whose effect an
            // operator cannot see from the host, since whether it loads is the browser's
            // business and a page that fails to load one looks like a page that has none.
            println!(
                "[bb-auth] {path}: pages: brand '{}', theme {}, stylesheet {}, logo {}",
                s.brand_name.as_deref().unwrap_or(DEFAULT_BRAND),
                s.theme.code(),
                s.stylesheet_url.as_deref().unwrap_or("(built-in only)"),
                s.logo_url.as_deref().unwrap_or("(none)"),
            );
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[bb-auth] INVALID {path}: {e}");
            std::process::exit(1);
        }
    }
}

/// Every env var the gate refuses to start without: [`env_req`]'s callers, in one list.
///
/// It exists so that the check can be run *before* the start rather than discovered by it.
/// A missing variable is a fatal startup, and a fatal startup under `Restart=on-failure` is
/// a boot loop, so `deploy/debian/bb-auth/postinst` looks for these before it restarts
/// anything. It used to look for them with a list of its own, hand-maintained in shell
/// beside this one in Rust, with nothing tying the two together: the seventh required
/// variable would have defeated the preflight in silence. Now the postinst asks the binary
/// (`--check-env`), and `the_required_env_list_matches_the_code` is what keeps this list
/// honest about its own callers.
const REQUIRED_ENV: [&str; 2] = ["BB_AUTH_HMAC_KEY", "BB_AUTH_ACCESS_FILE"];

/// Variables this gate once read and no longer does, with where the value went.
///
/// A variable that is set and read by nobody is worse than one that was never there: an
/// operator can see it, believe it, and edit it for an afternoon. This list is what lets
/// `--check-env` say so during the upgrade that retired it, on the host, before the postinst
/// restarts anything. Entries can be dropped once no deployment could still carry them.
const RETIRED_ENV: [(&str, &str); 12] = [
    ("BB_AUTH_COGNITO_ISSUER", "gate.issuer in the settings file"),
    ("BB_AUTH_COOKIE_DOMAIN", "gate.cookie_domain"),
    (
        "BB_AUTH_AUTHORIZED_HOSTS",
        "gate.authorized_hosts, as a list",
    ),
    ("BB_AUTH_CLIENT_ID", "gate.client_id in the settings file"),
    ("BB_AUTH_LOGIN_URL", "gate.login_url"),
    (
        "BB_AUTH_AUDIENCES",
        "derived: the app clients gate.client_id and gate.social_buttons name",
    ),
    ("BB_AUTH_OAUTH_DOMAIN", "gate.oauth_domain"),
    (
        "BB_AUTH_SOCIAL_CLIENT_ID",
        "the audience of each gate.social_buttons entry",
    ),
    ("BB_AUTH_SOCIAL_CALLBACK_URL", "gate.social_callback_url"),
    (
        "BB_AUTH_SOCIAL_IDPS",
        "the idp of each gate.social_buttons entry",
    ),
    ("BB_AUTH_SESSION_TTL_SECS", "gate.session_ttl_secs"),
    (
        "BB_AUTH_ALLOW_UNVERIFIED_SOCIAL",
        "gate.allow_unverified_social",
    ),
];

/// A JWKS holding one RSA public key, and an id_token signed by its private half. Both were
/// generated once, offline, and are fixtures rather than secrets: the private half was thrown
/// away, so the only thing this key can do is verify this token. `exp` is in 2100 because the
/// point is the signature, not the clock.
const SELF_TEST_JWKS: &str = r#"{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"bb-auth-test","e":"AQAB","n":"nmAtxmXBaFrRJyUe6i5CSQEPTq-80tfKKzO5jXg58t_KsovozqKu9dVzcJXh44gtXaoxbqPmVtj8Nn8sjC1G-kbF-MM4zQQ_F0z2S23Xkcz5-u0emQpt3ZPMRmkfQBsZs6Y_7qZT6ovm0RMRtEvOwJ1g1AFRp72saVt3lPlT9aMXDL0JN7GU1ytnNpYtn4C3u-UpnN9uxcGLYx3ULptmI3BK0s-zvVMzfxKSSvS_zvIfMxeJjAxrYmh1-cZifJsLGVuSQCcUeiCHP6kYxL_-sJjgb3H8tHeZVB4xjUzlkpKFiAKUmE5l39Rqbgxmq_bBLP2GvLAUBIjGV27r7bVriw"}]}"#;

/// The token [`SELF_TEST_JWKS`] verifies. `aud=testclient`, `iss=…eu-central-1_TESTPOOL`.
const SELF_TEST_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtdGVzdCJ9.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6InJzMjU2QGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImdpdmVuX25hbWUiOiJBZGEifQ.EsoTSyILbHFsucRSARUt4qahpK5R6rPlteCq1sUQ8gMoAqneJwJ8YXeFZmVFh3bCRlmgA0q4ygyXKMh_1ltNi8bfOoLtSCJBV-w-PrKeFRq1khEFfskIvWirsiVgzo5BK0DDj74dEFdG2zz7f_YAkln3indvFv1RbULDYfStID8F4WViQJP02nG4LdJiR4tihjw9E7f6Q7iMUeUw6a8axkWy1vtykzZptf_QNO2knyaAbOSNRd8hNbiYnid0VvbzrbxRFkvlzOSmiPwuab1kKW1H5AqGK0gN9eZTbOFKizVzajXHgcY7joRziYXI-86LZwRUHAAuAE-Jul82pMxDeQ";

/// The `Validation` [`self_test`] verifies under: exactly what [`validate_id_token`] builds,
/// pointed at the fixture's own issuer and audience, so the self-test exercises the gate's
/// configuration of the verifier and not a lenient one.
fn self_test_validation() -> Validation {
    let mut v = Validation::new(Algorithm::RS256);
    v.set_audience(&["testclient"]);
    v.set_issuer(&["https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TESTPOOL"]);
    v.set_required_spec_claims(&["exp", "aud", "iss"]);
    v.validate_exp = true;
    v.leeway = 60;
    v
}

/// `bb-auth --self-test`: prove *this binary* can verify an RS256 signature, and exit 0/1.
///
/// It is the answer to a deploy that reports success on a gate that cannot log anybody in.
/// `jsonwebtoken` picks its crypto provider from a feature and compiles happily with none,
/// installing a verifier factory that is a `panic!`; the gate then starts clean, because the
/// JWKS fetch and `DecodingKey::from_jwk` never reach the provider, and dies on the first
/// real login. Every runtime check `scripts/verify.sh` had (a healthz, a 401, a `listening
/// on` line) is green on exactly that build, and a restart loop even produces a *fresher*
/// journal line than a healthy process does.
///
/// So this runs the one thing those checks cannot: the verification itself, against an
/// embedded key, with no env, no config file and no network. `rsa_signature_verification_works`
/// is the same check in the test suite; this one is available on the host, after the install,
/// on the bytes that are actually running.
fn self_test() -> ! {
    let set: JwkSet = match serde_json::from_str(SELF_TEST_JWKS) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bb-auth] SELF-TEST FAILED: the JWKS fixture did not parse: {e}");
            std::process::exit(1);
        }
    };
    let Ok(key) = DecodingKey::from_jwk(&set.keys[0]) else {
        eprintln!("[bb-auth] SELF-TEST FAILED: the JWK did not become a decoding key");
        std::process::exit(1);
    };
    let v = self_test_validation();

    // The half that catches a build with no crypto provider: with one, this returns; with
    // none, the verifier factory panics and `panic = "abort"` makes that a non-zero exit,
    // which is the same verdict by a louder route.
    let data = match decode::<Claims>(SELF_TEST_TOKEN, &key, &v) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[bb-auth] SELF-TEST FAILED: a valid RS256 token did not verify: {e}");
            std::process::exit(1);
        }
    };
    if data.claims.email.as_deref() != Some("rs256@example.com")
        || data.claims.token_use.as_deref() != Some("id")
    {
        eprintln!("[bb-auth] SELF-TEST FAILED: the token verified but decoded to the wrong claims");
        std::process::exit(1);
    }
    // The half that says this is a signature check and not a decoder: one flipped base64
    // digit in the signature, the signed message untouched.
    let (msg, sig) = SELF_TEST_TOKEN
        .rsplit_once('.')
        .expect("the fixture is a three-segment JWT");
    let forged = format!("{msg}.F{}", &sig[1..]);
    if decode::<Claims>(&forged, &key, &v).is_ok() {
        eprintln!("[bb-auth] SELF-TEST FAILED: a forged signature verified");
        std::process::exit(1);
    }
    println!(
        "[bb-auth] self-test OK: {} verifies RS256 (JWKS parse, signature accepted, forgery \
         refused)",
        version_line("bb-auth")
    );
    std::process::exit(0);
}

/// `bb-auth --check-env <file>`: does this env file name everything the gate refuses to start
/// without? Exit 0/1, and never a start.
///
/// The grammar is systemd's `EnvironmentFile=`, read the way systemd reads it and no further:
/// comments, blank lines, `KEY=VALUE`, optional surrounding quotes. It deliberately does not
/// validate the *values* (that is what the gate's own startup does, and what
/// `--check-access` and `--check-settings` do for the two files): it answers the one question
/// a package can ask before it restarts a service, which is whether the answer will be
/// "missing required env var".
fn check_env(path: &str) -> ! {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[bb-auth] INVALID {path}: {e}");
            std::process::exit(1);
        }
    };
    let mut present: Vec<&str> = Vec::new();
    for line in body.lines() {
        let l = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches(['"', '\'']);
        if !v.is_empty() {
            present.push(k.trim());
        }
    }
    // Variables that are set and read by nobody, said where the deploy will show them: this
    // check runs from the postinst, before the restart, which is the moment an operator is
    // still looking at the upgrade that moved them.
    for (name, went) in RETIRED_ENV {
        if present.contains(&name) {
            println!(
                "[bb-auth] {path}: WARNING: {name} is set and is NO LONGER READ ({went}). \
                 Delete it from this file"
            );
        }
    }
    let missing: Vec<&str> = REQUIRED_ENV
        .iter()
        .copied()
        .filter(|r| !present.contains(r))
        .collect();
    if missing.is_empty() {
        println!(
            "[bb-auth] {path}: OK: all {} required variables are set",
            REQUIRED_ENV.len()
        );
        std::process::exit(0);
    }
    eprintln!(
        "[bb-auth] INVALID {path}: missing or empty: {}",
        missing.join(", ")
    );
    std::process::exit(1);
}

/// What `--help` says, and the whole argument surface in one place.
const USAGE: &str = "\
usage: bb-auth [OPTION]
  (no argument)              serve, configured from the BB_AUTH_* environment
  --check-access <file>      validate an access file with the gate's own parser
  --check-settings <file>    validate a settings file with the parser all three programs use
  --check-env <file>         is every required BB_AUTH_* variable set in this env file?
  --self-test                verify an RS256 signature with an embedded key (no env, no network)
  --version                  print the version and the commit this binary was built from
  --help                     this";

/// Parse argv, build the config, load both files, prime the JWKS, then serve forever on a
/// fixed pool of blocking worker threads.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = args.first().map(String::as_str);
    match flag {
        Some(f @ ("--check-access" | "--check-settings" | "--check-env")) => match args.get(1) {
            Some(p) if f == "--check-access" => check_access(p),
            Some(p) if f == "--check-settings" => check_settings(p),
            Some(p) => check_env(p),
            None => {
                eprintln!("usage: bb-auth {f} <file>");
                std::process::exit(2);
            }
        },
        Some("--self-test") => self_test(),
        // Provenance, and the reason it is worth a flag: a `.deb` version says 1.1.0-1 for a
        // clean release, a dirty tree and a hand-patched experiment alike, and the answer to
        // "what is actually running" cannot be a guess during an incident.
        Some("--version") => {
            println!("{}", version_line("bb-auth"));
            std::process::exit(0);
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            std::process::exit(0);
        }
        Some(other) => {
            eprintln!("[bb-auth] unknown argument '{other}'\n{USAGE}");
            std::process::exit(2);
        }
        None => {}
    }

    // Before anything else that logs. An unrecognised value is a warning and the default,
    // never a refusal to start: nothing about how loud the journal is can be worth a boot
    // loop.
    let level = match env_or("BB_AUTH_LOG_LEVEL", "info")
        .trim()
        .to_ascii_lowercase()[..]
        .as_ref()
    {
        "error" => LogLevel::Error,
        "info" | "" => LogLevel::Info,
        "debug" => LogLevel::Debug,
        other => {
            eprintln!(
                "[bb-auth] WARNING: BB_AUTH_LOG_LEVEL '{other}' is not error|info|debug, using info"
            );
            LogLevel::Info
        }
    };
    let _ = LOG_LEVEL.set(level);

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

    // The pool's signing keys. A configured issuer that does not answer is still **fatal**,
    // which is what makes reaching the `listening on` line below proof that the fetch, the
    // parse and every `from_jwk` worked. An issuer that is not configured at all is not
    // fatal, for the reason an empty `client_id` is not: a package creates this file and
    // cannot know the value, and refusing to start over it would be a boot loop on every
    // first install. That case is loud further down instead.
    let initial_issuer = settings.issuer.clone();
    let initial = if initial_issuer.is_empty() {
        HashMap::new()
    } else {
        fetch_jwks(&initial_issuer).unwrap_or_else(|e| {
            eprintln!("[bb-auth] FATAL: initial JWKS fetch failed: {e}");
            std::process::exit(1);
        })
    };

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
            issuer: initial_issuer,
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
    // The version and the commit lead the line, because this is the first thing anyone reads
    // in `journalctl -u bb-auth` and "which build is this?" is the first thing they need. A
    // `-dirty` suffix here is the only place a host ever says the deployed bytes were never
    // committed.
    eprintln!(
        "[bb-auth] {} listening on {listen} | issuer={} | aud={} | apps={app_n} | scopes={scope_n} | users={user_n} | api_keys={key_n} | denied={denied_n} | identity={identity_attrs} | claims={claim_names} | workers={workers}",
        version_line("bb-auth"),
        match settings.issuer.as_str() {
            "" => "(none: no pool is configured, so no token can be validated)",
            i => i,
        },
        match settings.audiences.len() {
            0 => "(none: no app client is configured, so no login can complete)".to_string(),
            _ => settings.audiences.join(","),
        },
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
    // The sign-in page it now serves itself, and what it offers on it. Worth a line of its
    // own because both halves are easy to get wrong from outside: nginx has to leave
    // /auth/login and /auth/callback ungated, and a social button that is drawn is a button
    // whose app client and callback URL Cognito has to agree with.
    eprintln!(
        "[bb-auth] pages: /auth/login and /auth/callback (leave both UNGATED in nginx) | \
         cognito={} | client={} | login={} | social={}",
        cognito_endpoint(&settings),
        settings.client_id,
        global_login(&settings),
        social_state(&settings)
    );
    // The one setting whose absence stops every new login. Loud, because the symptom is a
    // sign-in page that looks fine and a token the gate then refuses for its audience, and
    // because a package creates this file empty: a fresh install is expected to meet this
    // line once and never again.
    if settings.client_id.is_empty() {
        eprintln!(
            "[bb-auth] WARNING: gate.client_id names no app client, so NO LOGIN CAN COMPLETE              (every id_token is refused for its audience). Set it with: bb-auth-adm settings              set --client-id <app client id>"
        );
    }
    // The other two that stop a login before it starts, said as loudly and for the same
    // reason: a package creates this file with none of them, so a first install is expected
    // to meet these lines, and every one of them names the command that ends it.
    if settings.issuer.is_empty() {
        eprintln!(
            "[bb-auth] WARNING: gate.issuer names no Cognito user pool, so NO TOKEN CAN BE \
             VALIDATED. Set it with: bb-auth-adm settings set --issuer <issuer url>"
        );
    }
    if settings.authorized_hosts.is_empty() {
        eprintln!(
            "[bb-auth] WARNING: gate.authorized_hosts is empty, so EVERY post-login redirect \
             is refused and every login lands back on the sign-in page. Set it with: \
             bb-auth-adm settings set --authorized-hosts <host,host>"
        );
    }
    // Held only for the banner. Dropped before the workers start, so nothing below this line
    // can hold a read lock across a request and starve the SIGHUP swap.
    drop(settings);

    // A login page outside BB_AUTH_AUTHORIZED_HOSTS: a warning, never a refusal.
    //
    // `login_url_for` feeds a `Location:` (the logout's default, and `safe_rd`'s fallback),
    // which makes an application's `login_url` the one redirect target that never passes the
    // hosts list the manual calls the only authority on them. Anyone on `web.admins` can set
    // it through a browser, so it is worth saying out loud once, here, where an operator can
    // see it. It stays a warning for the reason `read_access` reads no env at all: making it
    // fatal would turn a typo in a file into a boot loop that `--check-access` never saw,
    // because `--check-access` has no hosts list to check against.
    {
        let hosts = state.settings.read().unwrap().authorized_hosts.clone();
        let access = state.access.read().unwrap();
        let stray: Vec<String> = access
            .apps
            .iter()
            .filter_map(|a| {
                let u = a.login_url.as_deref()?;
                (!rd_url_allowed(u, &hosts)).then(|| format!("{}: {u}", a.name))
            })
            .collect();
        if !stray.is_empty() {
            eprintln!(
                "[bb-auth] WARNING: login_url outside gate.authorized_hosts, so a 401 and a \
                 logout can send a browser off the estate [{}]",
                stray.join(", ")
            );
        }
    }

    // A gate on a public interface: a warning, and for the same reason the one above is.
    //
    // Everything about this service assumes nginx in front of it: it speaks plain HTTP, it
    // trusts `BB_AUTH_ORIGINAL_URL_HEADER` completely, and `/auth/validate` is meant to be
    // reachable by the proxy alone. A bind that is not loopback is occasionally deliberate
    // (a container whose proxy is on another host), which is exactly why this cannot be
    // fatal: refusing to start is the failure mode this codebase spends the most effort
    // avoiding.
    if !listen_is_loopback(&listen) {
        eprintln!(
            "[bb-auth] WARNING: listening on {listen}, which is not loopback: this service \
             trusts its reverse proxy for the request URL and speaks plain HTTP, so anything \
             that can reach this port can ask it about any URL"
        );
    }

    let mut handles = Vec::new();
    for _ in 0..workers {
        let server = Arc::clone(&server);
        let state = Arc::clone(&state);
        handles.push(std::thread::spawn(move || loop {
            // A `recv()` error is FATAL, and the `continue` that used to be here was the
            // worst of the three possible answers. `tiny_http` reports at most one error
            // per listener: its accept loop pushes the error and *breaks*, so the listening
            // socket is gone and every worker that loops back around blocks forever on a
            // queue nothing will ever fill again. The process stays alive with no listener,
            // which is precisely the state systemd cannot see: `Restart=on-failure` never
            // fires, `/auth/healthz` does not answer, and every gated request behind nginx
            // fails until somebody restarts it by hand. Exiting turns an invisible outage
            // into a restart, which is what the unit is configured for.
            let req = match server.recv() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[bb-auth] FATAL: accept failed, the listener is gone: {e}");
                    std::process::exit(1);
                }
            };
            route(req, &state);
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
}

/// The router: one request to one handler, and the only place a method and a path decide
/// anything.
///
/// A function rather than a `match` inside the worker loop so that a test can drive it over
/// a real socket. That is not a cosmetic split: every request-shaped property of this
/// service (what a `401` carries, what a cross-site `POST` gets, what headers a page comes
/// back with, whether `HEAD` on the sign-in page works at all) is invisible to a test that
/// can only call a handler's inner half, and those are exactly the properties nginx and a
/// browser depend on.
fn route(req: Request, state: &State) {
    let method = req.method().as_str().to_string();
    let path = req.url().split('?').next().unwrap_or("").to_string();
    match (method.as_str(), path.as_str()) {
        ("GET", "/auth/validate") => handle_validate(req, state),
        ("POST", "/auth/session") => handle_session(req, state),
        ("GET", "/auth/logout") => handle_logout(req, state),
        // The two pages, and the two locations nginx must leave UNGATED: a sign-in page
        // behind an `auth_request` answers a signed-out visitor with itself, forever.
        //
        // `HEAD` as well as `GET`, and these are the only two routes that take it. Not for
        // tidiness: these URLs REPLACED files nginx served off disk, and nginx answers `HEAD`
        // on a file. Every probe, uptime check and `curl -I` an operator already points at
        // the sign-in page has to keep working across that move, or the cutover breaks
        // something nobody was watching. tiny_http suppresses the body itself, so the handler
        // needs to know nothing about it.
        ("GET" | "HEAD", "/auth/login") => handle_login(req, state),
        ("GET" | "HEAD", "/auth/callback") => handle_callback(req, state),
        ("GET", "/auth/healthz") => {
            let _ = req.respond(Response::from_string("ok"));
        }
        _ => respond_empty(req, 404),
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
        let set: JwkSet = serde_json::from_str(SELF_TEST_JWKS).expect("the JWKS must parse");
        let key = DecodingKey::from_jwk(&set.keys[0]).expect("the JWK must become a key");
        let v = self_test_validation();

        let data =
            decode::<Claims>(SELF_TEST_TOKEN, &key, &v).expect("a valid RS256 token verifies");
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
        let (msg, sig) = SELF_TEST_TOKEN
            .rsplit_once('.')
            .expect("a JWT has three segments");
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

    /// Only the cookie's name matters to `build_cookie` now; the rest are placeholders so
    /// the literal compiles. Its *domain* is in the settings beside it: see `cookie_settings`.
    fn cookie_cfg() -> Config {
        Config {
            listen: "127.0.0.1:4181".to_string(),
            hmac_keys: keys_one(),
            cookie_name: "bb_session".to_string(),
            original_url_header: "X-Original-URL".to_string(),
            workers: 1,
        }
    }

    /// Compiled settings carrying just a cookie domain, which is the other half of what
    /// `build_cookie` reads.
    fn cookie_settings(domain: Option<&str>) -> Settings {
        bb_auth_core::compile_settings(&bb_auth_core::SettingsFile {
            version: bb_auth_core::SETTINGS_VERSION,
            gate: bb_auth_core::GateSettings {
                cookie_domain: domain.unwrap_or_default().to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap()
    }

    /// The line a single, estate-wide logout endpoint stands on: a browser matches a
    /// `Set-Cookie` against what it stored by `(name, Domain, Path)`, so the expiring cookie
    /// must name the same triple the minted one did. Make the clear host-only while the mint
    /// is domain-wide and it misses in silence — the browser keeps the domain cookie, the
    /// logout reports success, and every other host stays signed in.
    #[test]
    fn clearing_a_cookie_targets_the_same_cookie_it_minted() {
        let cfg = cookie_cfg();
        let st = cookie_settings(Some(".badbat75.com"));
        let minted = build_cookie(&cfg, &st, "bb1.k1.9999999999.ZWI.", 2_592_000);
        let cleared = build_cookie(&cfg, &st, "", 0);
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
        let host_only = cookie_settings(None);
        assert!(!build_cookie(&cfg, &host_only, "v", 60).contains("Domain"));
        assert!(!build_cookie(&cfg, &host_only, "", 0).contains("Domain"));
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
    /// The estate these tests are set on. One list, because the hosts are a setting now and
    /// a fixture that compiled them separately from the one it writes into a settings file
    /// would be testing two estates that happen to agree.
    const BB_HOSTS: [&str; 2] = ["badbat75.com", "*.badbat75.com"];
    fn bb_hosts() -> Vec<UrlPattern> {
        BB_HOSTS
            .iter()
            .map(|h| bb_auth_core::compile_host_pattern(h).unwrap())
            .collect()
    }
    /// The pool the fixture token was minted by, and therefore the only issuer that can
    /// validate it. A setting now, so every fixture that reaches a token or renders a page
    /// carries it.
    const TEST_ISSUER: &str =
        "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TESTPOOL";
    const LOGIN: &str = "https://login.badbat75.com/";
    /// The two OAuth endpoints `social_settings`'s domain derives, spelled out where a page
    /// test needs them without a settings file in hand.
    const TOKEN_URL: &str = "https://pool.auth.eu-central-1.amazoncognito.com/oauth2/token";
    const CALLBACK_URL: &str = "https://auth.badbat75.com/auth/callback";
    const CALLER: &str = "https://search.badbat75.com";

    // --- the gate's own pages -----------------------------------------------

    /// Compiled settings that enable the given social buttons, which is what decides whether
    /// the sign-in page offers any: the env group only says what the pool federates.
    fn settings_with_buttons(buttons: &[(&str, &str)]) -> Settings {
        social_settings("pool.auth.eu-central-1.amazoncognito.com", buttons)
    }

    /// Compiled settings for a deployment whose social sign-in is wired to `domain`, with one
    /// button per `(identity_provider, app client)` pair. An empty `domain` is a deployment
    /// with no social sign-in at all, which the compiler only accepts with no buttons.
    fn social_settings(domain: &str, buttons: &[(&str, &str)]) -> Settings {
        bb_auth_core::compile_settings(&bb_auth_core::SettingsFile {
            version: bb_auth_core::SETTINGS_VERSION,
            gate: bb_auth_core::GateSettings {
                issuer: TEST_ISSUER.to_string(),
                client_id: "email-client".to_string(),
                oauth_domain: domain.to_string(),
                social_callback_url: if domain.is_empty() {
                    String::new()
                } else {
                    "https://auth.badbat75.com/auth/callback".to_string()
                },
                social_buttons: buttons
                    .iter()
                    .map(|(idp, aud)| {
                        bb_auth_core::SocialButtonSpec::Wired(bb_auth_core::WiredButton {
                            idp: idp.to_string(),
                            audience: aud.to_string(),
                        })
                    })
                    .collect(),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap()
    }

    /// Compiled settings with only the `ui` section set, which is all these pages read of
    /// their own, plus the pool: the endpoint the page's script talks to is derived from it,
    /// so a page fixture without one renders a page that can reach nothing.
    fn ui_settings(ui: bb_auth_core::UiSettings) -> Settings {
        bb_auth_core::compile_settings(&bb_auth_core::SettingsFile {
            version: bb_auth_core::SETTINGS_VERSION,
            gate: bb_auth_core::GateSettings {
                issuer: TEST_ISSUER.to_string(),
                ..Default::default()
            },
            ui,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn render_page_substitutes_once_and_leaves_an_unknown_placeholder_standing() {
        let subs = [
            ("__BB_A__", "<b>".to_string()),
            // A value that contains another placeholder: it must land as text, never be
            // substituted a second time, or a brand name could rewrite the page around it.
            ("__BB_B__", "__BB_A__".to_string()),
        ];
        assert_eq!(render_page("x __BB_A__ y", &subs), "x <b> y");
        assert_eq!(render_page("__BB_B__", &subs), "__BB_A__");
        // Unknown placeholders survive verbatim: a template that lost a substitution says so
        // on the page instead of quietly rendering a gap.
        assert_eq!(render_page("__BB_NOPE__", &subs), "__BB_NOPE__");
        assert_eq!(render_page("no placeholders", &subs), "no placeholders");
    }

    #[test]
    fn the_login_page_is_whole_self_contained_and_escapes_its_one_request_value() {
        let page = login_page(
            &settings_with_buttons(&[("Google", "google-client"), ("Okta", "okta-client")]),
            "https://search.badbat75.com/?q=a\"b",
            "n0nce",
        );
        // Every placeholder was answered.
        assert!(!page.contains("__BB_"), "unsubstituted placeholder left");
        // The palette and the layout are IN the page: no stylesheet, script or font is
        // fetched from anywhere, which is the property this page exists to have.
        assert!(page.contains("--accent:"), "the palette is not inlined");
        assert!(page.contains(".card{"), "the layout is not inlined");
        assert!(
            !page.contains("<link"),
            "unconfigured, so nothing may be linked"
        );
        assert!(!page.contains("src=\"http"), "no external script or image");
        // The one request-supplied value is an escaped attribute, never JavaScript source.
        assert!(
            page.contains(r#"data-rd="https://search.badbat75.com/?q=a&quot;b""#),
            "{page}"
        );
        // The client id is the one the gate validates as an audience, by construction.
        assert!(
            page.contains(r#"var CLIENT_ID = "email-client";"#),
            "{page}"
        );
        assert!(
            page.contains(r#"var ENDPOINT = "https://cognito-idp.eu-central-1.amazonaws.com/";"#)
        );
        // A known provider gets its icon, an unknown one gets a button anyway.
        assert!(page.contains(r#"data-idp="Google""#), "{page}");
        assert!(page.contains(r#"data-idp="Okta""#), "{page}");
        assert!(
            page.contains("data-i18n-arg=\"Okta\">Continue with Okta<"),
            "{page}"
        );
    }

    /// A provider is offered because somebody enabled it, and for no other reason.
    ///
    /// The env group says what this deployment's app client federates and the settings say
    /// what the page offers today, so a button needs both. The middle case below is the one
    /// most worth a test: enabling something the pool does not federate must not draw a
    /// button, because that button leads to Cognito explaining the mistake in Amazon's words
    /// on Amazon's page, one redirect from somebody who was only trying to sign in.
    #[test]
    fn every_button_carries_its_own_app_client() {
        // Two providers, two app clients: the arrangement a single client id could not
        // express, and the reason the audience sits on the row rather than on the file.
        let page = login_page(
            &settings_with_buttons(&[("Google", "google-client"), ("Okta", "okta-client")]),
            "",
            "n0nce",
        );
        assert!(
            page.contains(r#"data-idp="Google" data-client-id="google-client""#),
            "{page}"
        );
        assert!(
            page.contains(r#"data-idp="Okta" data-client-id="okta-client""#),
            "{page}"
        );
        assert!(page.contains(r#"class="divider""#), "the section is there");
        // The email flow's own app client is the page's, and it is a different value.
        assert!(
            page.contains(r#"var CLIENT_ID = "email-client";"#),
            "{page}"
        );

        // File order is display order, because it is the operator's order.
        let both = login_page(
            &settings_with_buttons(&[("Okta", "okta-client"), ("Google", "google-client")]),
            "",
            "n0nce",
        );
        let okta = both.find(r#"data-idp="Okta""#).expect("okta");
        let google = both.find(r#"data-idp="Google""#).expect("google");
        assert!(okta < google, "the settings order is the display order");
    }

    #[test]
    fn with_no_social_wiring_the_page_has_no_social_markup_at_all() {
        // No hosted-UI domain, which is the only way a file can say "no social sign-in":
        // `compile_settings` refuses buttons without one, so there is one such state and not
        // two that look different.
        let page = login_page(&social_settings("", &[]), "", "n0nce");
        assert!(!page.contains("data-idp="), "{page}");
        assert!(!page.contains(r#"class="divider""#), "{page}");
        assert!(page.contains(r#"var AUTHORIZE_URL = "";"#), "{page}");
        assert!(page.contains(r#"var CALLBACK_URL = "";"#), "{page}");
    }

    #[test]
    fn the_audiences_are_the_app_clients_the_file_names() {
        // Nothing else in the system says which app clients this gate is part of, so the
        // list is derived rather than kept in step by hand: the email flow's, then each
        // button's, deduplicated and in file order.
        let s = settings_with_buttons(&[("Google", "google-client"), ("Okta", "okta-client")]);
        assert_eq!(
            s.audiences,
            ["email-client", "google-client", "okta-client"]
        );

        // Two buttons through one app client name it once.
        let shared = settings_with_buttons(&[("Google", "one-client"), ("Okta", "one-client")]);
        assert_eq!(shared.audiences, ["email-client", "one-client"]);
    }

    #[test]
    fn a_rejected_rd_is_dropped_rather_than_carried_to_the_page() {
        // `handle_login` filters with the same `rd_url_allowed` `safe_rd` uses; this pins the
        // pairing that makes the two agree.
        let hosts = bb_hosts();
        assert!(rd_url_allowed("https://search.badbat75.com/x", &hosts));
        assert!(!rd_url_allowed("https://evil.example.com/", &hosts));
        let page = login_page(
            &ui_settings(bb_auth_core::UiSettings::default()),
            "",
            "n0nce",
        );
        assert!(page.contains(r#"data-rd=""#), "{page}");
    }

    #[test]
    fn the_operator_stylesheet_is_linked_after_the_built_in_one_on_every_page() {
        let ui = bb_auth_core::UiSettings {
            stylesheet_url: "https://assets.badbat75.com/css/theme.css".to_string(),
            logo_url: "/img/logo.png".to_string(),
            brand_name: "BadBat75".to_string(),
            theme: "dark".to_string(),
        };
        let settings = ui_settings(ui);
        for page in [
            login_page(&settings, "", "n0nce"),
            callback_page(TOKEN_URL, CALLBACK_URL, &settings, "n0nce"),
        ] {
            let style = page.find("<style ").expect("the built-in stylesheet");
            let tokens = page.find("--accent:").expect("the palette");
            let components = page.find(".pill{").expect("the shared components");
            let layout = page
                .find(".lang-toggle{")
                .expect("this page's own arrangement");
            let link = page.find("<link rel=\"stylesheet\"").expect("the override");
            // Order is the contract, and it is four deep: the palette, the components that
            // read it, this page's arrangement of them, then the override, which wins by
            // source order and therefore needs no `!important` and no knowledge of what it is
            // overriding. The first two are the same bytes bb-auth-web emits, which is what
            // makes the sign-in page and the admin interface one product rather than two that
            // were once made to match.
            assert!(
                style < tokens && tokens < components && components < layout && layout < link,
                "the override must come after the built-in one"
            );
            assert!(page.contains(r#"data-theme="dark""#), "{page}");
            assert!(page.contains("<h1>BadBat75</h1>"), "{page}");
            assert!(
                page.contains(r#"<img src="/img/logo.png" alt="">"#),
                "{page}"
            );
        }
    }

    #[test]
    fn the_callback_page_names_the_registered_redirect_uri_and_no_app_client() {
        let page = callback_page(
            TOKEN_URL,
            CALLBACK_URL,
            &ui_settings(bb_auth_core::UiSettings::default()),
            "n0nce",
        );
        assert!(!page.contains("__BB_"), "unsubstituted placeholder left");
        // The value Cognito compares byte for byte with the client's registered callback.
        assert!(page.contains(r#"var CALLBACK_URL = "https://auth.badbat75.com/auth/callback";"#));
        // And no app client of its own: it exchanges with whichever one the button that
        // started this leg named, which only sessionStorage knows.
        assert!(page.contains(r#"var SOCIAL_CLIENT_ID = "";"#), "{page}");
        assert!(
            page.contains(r#"sessionStorage.getItem("bb_social_client")"#),
            "{page}"
        );
    }

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
    fn rd_candidate_is_the_link_then_the_browser() {
        let (rd, refr) = (Some("rd"), Some("refr"));
        assert_eq!(rd_candidate(rd, refr), Some("rd"));
        assert_eq!(rd_candidate(None, refr), Some("refr"));
        assert_eq!(rd_candidate(rd, None), Some("rd"));
        assert_eq!(rd_candidate(None, None), None);
        // An empty value is what a template renders from an empty variable, so it counts as
        // nothing said and the Referer answers.
        assert_eq!(rd_candidate(Some(""), refr), Some("refr"));
        assert_eq!(rd_candidate(Some(""), Some("")), None);
    }

    #[test]
    fn login_rd_falls_back_to_the_referer() {
        let h = bb_hosts();
        let f = |rd: Option<&str>, r: Option<&str>| login_rd(rd, r, &h);
        let came_from = "https://search.badbat75.com/q";
        // The link's own rd wins; the Referer answers when there is none, or an empty one.
        assert_eq!(
            f(Some("https://mcp.badbat75.com/x"), Some(came_from)),
            "https://mcp.badbat75.com/x"
        );
        assert_eq!(f(None, Some(came_from)), came_from);
        assert_eq!(f(Some(""), Some(came_from)), came_from);
        assert_eq!(f(None, None), "");
        // Same gate as an rd, and a rejected candidate leaves the page with no rd at all
        // rather than sending the person away: they came here to sign in.
        assert_eq!(f(None, Some("https://evil.com/")), ""); // a link from anywhere
        assert_eq!(f(None, Some("http://mcp.badbat75.com/")), "");
        assert_eq!(f(None, Some("/relative")), ""); // absolute URLs only, on this page
                                                    // Whoever spoke first is answered on its own merits: a rejected rd does not promote
                                                    // the Referer, or a crafted link would choose which of the two is read.
        assert_eq!(f(Some("https://evil.com/"), Some(came_from)), "");
    }

    #[test]
    fn logout_target_prefers_the_link_then_the_referer() {
        let h = bb_hosts();
        let f = |rd: Option<&str>, r: Option<&str>| logout_target(rd, r, Some(CALLER), &h, LOGIN);
        let came_from = "https://search.badbat75.com/q";
        // The rd was written for this link, so it wins over the browser's account of where
        // the person came from.
        assert_eq!(
            f(Some("/bye"), Some(came_from)),
            "https://search.badbat75.com/bye"
        );
        assert_eq!(f(None, Some(came_from)), came_from);
        assert_eq!(f(Some(""), Some(came_from)), came_from);
        // A relative candidate resolves against the caller, exactly as a relative rd does.
        assert_eq!(f(None, Some("/bye")), "https://search.badbat75.com/bye");
        // Neither: the login page, never safe_rd's caller-root default, which would send the
        // browser back into the area it was just signed out of.
        assert_eq!(f(None, None), LOGIN);
        assert_eq!(f(Some(""), Some("")), LOGIN);
        assert_eq!(logout_target(None, None, None, &h, LOGIN), LOGIN);
    }

    #[test]
    fn logout_target_guards_the_referer_like_an_rd() {
        let h = bb_hosts();
        let f = |r: &str| logout_target(None, Some(r), Some(CALLER), &h, LOGIN);
        assert_eq!(f("https://evil.com/"), LOGIN); // off-host: a link from anywhere
        assert_eq!(f("//evil.com"), LOGIN); // scheme-relative
        assert_eq!(f("http://mcp.badbat75.com/"), LOGIN); // not https
        assert_eq!(f("https://mcp.badbat75.com@evil.com/"), LOGIN); // userinfo
        assert_eq!(f("/\r\nSet-Cookie: x=1"), LOGIN); // response splitting
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
        let only_sub = vec![bb_auth_core::compile_host_pattern("*.badbat75.com").unwrap()];
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
        // Unique per call, not per `name`: several tests ask for the same fixture and the
        // suite runs them on different threads, so a shared filename is one test writing the
        // file another is reading.
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("bb-auth-gate-{name}-{n}.json"));
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
    // --- the token verifier, over real signatures ---------------------------
    //
    // A second offline RSA key, generated once and thrown away, and a token per branch of
    // `validate_id_token`. `SELF_TEST_TOKEN` proves a signature verifies at all; these prove
    // what the gate does with a token whose signature is *fine* and whose claims are not,
    // which is every check between the verifier and the identity. Before this, the whole
    // group of them (`alg`, a missing `kid`, `token_use`, `exp`, `aud`, the email's shape)
    // was reachable only through a live Cognito.

    const IT_JWKS: &str = r#"{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"bb-auth-it","e":"AQAB","n":"rugOpI1NhVG8CKJbf8LFMFjw-Goe26G5YJLb7-VTWg3VLG_-Qy2kQEW-aPIX_RgDZ9VcoU06LT6ZAAa142TGZYarzE8RsGqTgDVS6uiJEeeCy_mztxMcKXUoE45enGhbESY1-j9VZPvNMb-7Oearl-EqKeprpJYV2-SxYY9QRtJFJR4rKxberyssan4PkN2hlS128Z5Kd4TepQLU5RlIm6tPTZaP81fKF_rB6YNvHDyAofEVcK0s3YH6a5CI1FDPWbK9VssTmDnlzPVoSdd56Haq4kH2NbxrybK3OOStROluoS_Q0Ejzsg_JTcqjofuNKRiLd8itgYti2FMstsKkbQ"}]}"#;
    const IT_TOKEN_OK: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJnaXZlbl9uYW1lIjoiQWRhIiwiZmFtaWx5X25hbWUiOiJMb3ZlbGFjZSJ9.AsSpalg5hcJwwVL5Nh03f98i0xsz-Th4NJM5aFk9Wv7yRbBUq1zuYq6ZNZdOtpgKa19j3zTR3NsRETnHhWVZhGLRvSCluY_zyEGzgwO_D1cBwtDjc5XGqehOux-torQKaXryxWlhd2um3RyJt5KuBIUaCTuZsnRb4ghQBdYVBg7nmRwfXnFTCB-HWYwh_VaklGKpe0kaHfvv1ttp3oWdt37CCFT3CRXPQi2UNMxW53SeIk6UPrhEX2d9gNjRBMidno2ALMXxA6L4ku5G1bPEfj9HbkqArSNCJHCPtQMhH1WUB2iqZrMA6q78imDaFjI31uc5uzdIpt4FUda35NeQxA";
    const IT_TOKEN_ACCESS: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MTAwMDAwMDAwMCwiZW1haWwiOiJhZGFAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UifQ.BcXSfueCjbuy0ICSd9mXlm3vwI1ywkym7x2KdABO5aYYeP2l9_2A7WCmNOFDpPeDcDUD-8rT3hpBsKeckfl0-CgxwyIQ8UClRhC3GbGjKFEuA_65ieaxz1CfruCEItlpFpE-zb3YUc89Yk6-dVbGI45k-0UhWK6I91Hn-R5hliZoauYgq2CCIxDfRRE2-bOKJvsBVgc3xrYDQts8Wq8M8lsmQn-OfycFWAtG3shOw8ujrr4nLGvycy2A9hffOsXJyV-sPtC_Oj_jtufHv_nW1KnVVxzcQj6QQFO3_s0BMyTyfTZSRD7I7_7OqNZ-N0GfCjMeza6uxWcQQ7Y4KDh0NA";
    const IT_TOKEN_UNVERIFIED: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UifQ.owL1LWxaPNuK4do4S1T23b9Zywk7Fhfq178Nx9f0MO4R3qZKhtG10Z_E1bOqBK6hjy1T5hmbtUdg8FIwHg10OVWjbnW_m8Fzk7v-MWLnOgd5kLVwnsyWX8NgIAmo1dSb0-P3xV6C2HpCtFnZPhR98fGxXJUIf5HLr31Hi86VNJNG8-nMU3F2Iqy1vdeMBwcrSkMhlmZZO4n1rE0cR9DvUY9ixfEfr81sR9vTc4mpnXIwT-aViOP-s9Ovrq4gJCNz5os4IYJQkEwNVH8xO9tuXcx5zL-S2Rwfoqg6kv4Azk7gD4x4PCWbff2NsjTtS1fGxCwICQDhEmr46T2sitee8Q";
    const IT_TOKEN_SOCIAL: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UiLCJpZGVudGl0aWVzIjpbeyJwcm92aWRlck5hbWUiOiJHb29nbGUiLCJ1c2VySWQiOiIxIn1dfQ.f2CwAFGvK0AfVpkTQytWw-4mpt8i8Z5hbuO75hAbyKqTjlsvQBBIhcErgD_tRwJube7S9TN459arezyk79QX85Pa0lBA5fnzF-k83GYkDjA7HXF0f7P7HhAWBuw2AuiRYC7qWnlusVlCC2SGDVDlLcCb0tw_2Oou5XQBkHkQjxeIK9rCIZXOHqaPyflIQulDr1w0ptSy3DL1LElmMW9XpnoMd4wxqll494UvMwxh8sBFfQdgQs2ifPk6lrMT_TCgGS9BsYIL-GaryRn3aTe4_F0YWybfZ9LYB7S_4-F4fj1nSrt52aHz_F2umidLs7tP57qVE40Pg6JJwB__0gkh5g";
    const IT_TOKEN_SOCIAL_APPLE: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UiLCJpZGVudGl0aWVzIjpbeyJwcm92aWRlck5hbWUiOiJTaWduSW5XaXRoQXBwbGUiLCJ1c2VySWQiOiIxIn1dfQ.ZlwHhtX6ywtueOn8mDVKWufBPGGfIe5mViVVLw6mAYjX7_D-ghN-PZ7tRfrtebas5EMO8rQPVfk0hXxnt-9Eho9yWYTMtBz5kjX8eNBu409oC20gH-44-K2KPyl56vfJHbaCATzVArO6fJcSnbX_Z9T1doU1FuLMr89NhHtnnpTaoIZDsvTZCp-cMQsdlRicTtzhieuARyNFCH50quBsTzIy071BqClgYSCQ7a3z_f7o8-ZU2bKDWVM-XuwQFvc6JovnS9MF3Ds8W0zRXamh7oCz1zgEekmE6CpB172xTKa8DO6bIcgPzpFSyZzJlwF34-Udse-gm0VpxiUe2eKZGg";
    const IT_TOKEN_BAD_EMAIL: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYVxyXG5YLUF1dGgtQWRtaW46IDFAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UifQ.AbRKWpldAZsycR7s2aSyFo237MRDl10rRwDiCQ0JKvlBhIv4Uu31aal9pF8x0nDBAEKhcf0Djo1w2mCdoxhah3jOmKzYL9GL-N6gHzblS2uitZ-JkWKk0Azio9weNKp6_s5Ss_KsOwbHHsvOdYySnnbtI_PkRj9-wFwFtjX60NmP1G5YVl2CP5gXfuk_enAPFTbuyDcrJtFs5-8emWhVIkzZYO80OZhXRW3yJVtnrfVaJxkd3mfPYooBVEIt4O0UVIMlVFgGD4BTlejVbr7Zw-f0rjWCYvlE5MYziiCGFiEfN7VO7KQfSsmFpL8VBbcpHKfdhv6_VnpQrRc_OYRe6A";
    const IT_TOKEN_EXPIRED: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6MTAwMDAwMDA2MCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJnaXZlbl9uYW1lIjoiQWRhIiwiZmFtaWx5X25hbWUiOiJMb3ZlbGFjZSJ9.k5DFscI5iwnSuBjW_9Uw9QhjS4PJHcrgn7MdlQjGGTfSkIg3XqvUEcSNMHlegVOryhEHavcSxwmsXxxdRGADTEQwa6xxyY9hKtG7J2rDM9cbbghk4sxF_PIAjC5g6xgyYVf731YVt-qHPzMmhRE0P_A7DaLtGaVcvHjT07txbN8B_9SBcP7zU3KJfRJVU9KiQb0zjTS7TgUfddQQPz9fk8DHFlsOA-oFvPtmsDFwUnEhZQ5aJ62Q6d9ak2RnJbYYGVor_Q77MTxdGkkSHMM9L0gm0veh6vW9J6C3jQQ9CuseimBZqiHvM5wL7WgP88_P1TDBzb2JostBwIJv6Mn2DQ";
    const IT_TOKEN_WRONG_AUD: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InNvbWVvbmUtZWxzZSIsInRva2VuX3VzZSI6ImlkIiwiZXhwIjo0MTAyNDQ0ODAwLCJpYXQiOjEwMDAwMDAwMDAsImVtYWlsIjoiYWRhQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImdpdmVuX25hbWUiOiJBZGEiLCJmYW1pbHlfbmFtZSI6IkxvdmVsYWNlIn0.ivJ9pHR_DS5aXQ_NB5zTUy4hKQ8yZYtEwf6dOjYVcU0wXHiUS5rygH4ENPwEZ45WHnr-KLMl8v9FRRMLTCl_hvCPwGwZtgc5y61W9Qn4WIkZKAH3gpCgbtAh3KbK1CZh0PsaGMhPWqBSJexKPvH72aceE60ZySeJyGf3vI6X16vzcaOCO9RUxHm7-X8_yps9a8heJWc2UJU8KVjJQAbK6z-hN2SjqzT8eMgQF-DgbXSM_CFUo1QFg_niZDcp6FZOP5KaFKtZXRVVfB-QfBrn17K3foIIYfuqFOorHuUfxMjPeHs6arZrzpxHrlSWTlfzMP5cAlZPSQ39vCUeFrzyvA";
    const IT_TOKEN_NO_EMAIL: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJiLWF1dGgtaXQifQ.eyJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmV1LWNlbnRyYWwtMS5hbWF6b25hd3MuY29tL2V1LWNlbnRyYWwtMV9URVNUUE9PTCIsImF1ZCI6InRlc3RjbGllbnQiLCJ0b2tlbl91c2UiOiJpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxMDAwMDAwMDAwLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6IkFkYSIsImZhbWlseV9uYW1lIjoiTG92ZWxhY2UifQ.HQg4OhQXErFEdSM8IQqXuW4PPsIBUTY_YClLP103dfL_8jVBWSBAqXLgPkXT_WdbGKGasf06o4coaU4zIzCEY734mGjJomQpU8x5NxDWUcw-skODFHXh8Xeadglx7aKaZ1HF70uBHwO8gIG-es1zcxPmcM7DWCsBiBJeTa-d6hVVYpGEYmxhuvEKbNSebMhxzeD9m6I-lZB_vSS7PcHjRvPE8492jUwCVjVXFFGjOQRuNylOChNkC9b-o6AXO9d6L3Sp2wqIPdscW7Qn0nenx7vieMp5_rXl4XvePxncsEa-ViOSNyKLmDgLrzplv0HUt5SJKJFEyMmhFSnEhcyj2w";

    /// A state whose JWKS already holds the fixture key, so nothing here touches the
    /// network. `last_refresh` is *now* on purpose: an unknown `kid` must not become a
    /// fetch, and this is what keeps these tests offline.
    fn token_state(settings: Settings) -> State {
        let set: JwkSet = serde_json::from_str(IT_JWKS).expect("fixture JWKS parses");
        let mut keys = HashMap::new();
        keys.insert(
            "bb-auth-it".to_string(),
            DecodingKey::from_jwk(&set.keys[0]).expect("fixture JWK becomes a key"),
        );
        // The issuer these keys belong to is the settings', so the cache is seeded with
        // whatever the fixture settings name: a cache that disagreed with them would trigger
        // a refetch against a pool no test has a server for.
        let issuer = settings.issuer.clone();
        State {
            cfg: cookie_cfg(),
            access: RwLock::new(gate_access("token")),
            settings: RwLock::new(settings),
            #[cfg(unix)]
            access_path: String::new(),
            #[cfg(unix)]
            settings_path: String::new(),
            jwks: RwLock::new(JwksCache {
                keys,
                last_refresh: Instant::now(),
                issuer,
            }),
            jwks_refresh: Mutex::new(()),
        }
    }

    /// Compiled settings from a gate section written as JSON, which is how an operator
    /// writes them and therefore what these tests should be exercising.
    fn gate_settings(gate: &str) -> Settings {
        let mut file: bb_auth_core::SettingsFile = serde_json::from_str(&format!(
            r#"{{ "version": {}, "gate": {gate} }}"#,
            bb_auth_core::SETTINGS_VERSION
        ))
        .unwrap();
        // The app client the fixture token was minted for, and therefore the only audience
        // these tests accept. It is a setting now, so a gate section that does not mention it
        // gets the fixture's rather than an empty audience list and a token nobody accepts.
        if file.gate.client_id.is_empty() {
            file.gate.client_id = "testclient".to_string();
        }
        // Where people sign in is a setting too now, and every test that reads a 401 or a
        // logout expects the configured page rather than the gate's own default.
        if file.gate.login_url.is_empty() {
            file.gate.login_url = LOGIN.to_string();
        }
        // And so are the pool and the estate, which between them decide whether a token
        // validates at all and whether a login may land anywhere but the sign-in page.
        if file.gate.issuer.is_empty() {
            file.gate.issuer = TEST_ISSUER.to_string();
        }
        if file.gate.authorized_hosts.is_empty() {
            file.gate.authorized_hosts = BB_HOSTS.iter().map(|h| h.to_string()).collect();
        }
        bb_auth_core::compile_settings(&file).unwrap()
    }

    /// Swap the *header* of a signed token, which is what a client attacking a verifier's
    /// algorithm agility does. The signature is left over the original message, so anything
    /// that reaches the signature check refuses it anyway; what this exercises is that it
    /// never gets that far.
    fn with_header(token: &str, header_json: &str) -> String {
        let rest: Vec<&str> = token.split('.').skip(1).collect();
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header_json.as_bytes()),
            rest.join(".")
        )
    }

    #[test]
    fn a_good_token_yields_the_identity_and_only_the_configured_claims() {
        let st = token_state(gate_settings(r#"{ "profile_claims": ["given_name"] }"#));
        let id = validate_id_token(IT_TOKEN_OK, &st).expect("a valid token verifies");
        assert_eq!(id.email, "ada@example.com");
        assert_eq!(id.claims.get("given_name").map(String::as_str), Some("Ada"));
        // `family_name` is in the token and is not configured, so it is not captured: the
        // cookie carries what the operator asked for and nothing else.
        assert_eq!(id.claims.len(), 1);
    }

    #[test]
    fn each_token_check_refuses_on_its_own() {
        let st = token_state(gate_settings("{}"));
        let why = |t: &str| validate_id_token(t, &st).unwrap_err();

        // alg: refused before the signature is even looked up, which is the point of
        // checking it at all.
        assert!(why(&with_header(
            IT_TOKEN_OK,
            r#"{"alg":"HS256","kid":"bb-auth-it"}"#
        ))
        .contains("unexpected alg"));
        // A missing kid, and an unknown one. Neither may reach the network here: the cache
        // was just refreshed, so `refresh_jwks_if_due` returns without a fetch.
        assert!(why(&with_header(IT_TOKEN_OK, r#"{"alg":"RS256"}"#)).contains("no kid"));
        assert!(
            why(&with_header(IT_TOKEN_OK, r#"{"alg":"RS256","kid":"nope"}"#))
                .contains("unknown signing key")
        );
        // token_use is the single check between an access_token and a session cookie.
        assert!(why(IT_TOKEN_ACCESS).contains("token_use"));
        // exp and aud are `jsonwebtoken`'s, through the `Validation` this gate builds.
        assert!(why(IT_TOKEN_EXPIRED).contains("token invalid"));
        assert!(why(IT_TOKEN_WRONG_AUD).contains("token invalid"));
        // The identity must be header-safe: this one carries a CR/LF, which downstream
        // would be a response-splitting gadget.
        assert!(why(IT_TOKEN_BAD_EMAIL).contains("printable ASCII"));
        assert!(why(IT_TOKEN_NO_EMAIL).contains("no email"));
        // And the default posture on an unverified email, with no relaxation configured.
        assert!(why(IT_TOKEN_UNVERIFIED).contains("not verified"));
    }

    #[test]
    fn the_unverified_relaxation_reaches_social_logins_only_and_narrows_by_provider() {
        // Off: even a federated token is refused, which is the default every deployment
        // starts on.
        let st = token_state(gate_settings("{}"));
        assert!(validate_id_token(IT_TOKEN_SOCIAL, &st).is_err());

        // On, unrestricted: any federated provider, but still never a native user.
        let st = token_state(gate_settings(r#"{ "allow_unverified_social": true }"#));
        assert_eq!(
            validate_id_token(IT_TOKEN_SOCIAL, &st).unwrap().email,
            "ada@example.com"
        );
        assert!(validate_id_token(IT_TOKEN_UNVERIFIED, &st).is_err());

        // On, narrowed: the provider list is the whole of it.
        let st = token_state(gate_settings(
            r#"{ "allow_unverified_social": true, "social_providers": ["Google"] }"#,
        ));
        assert!(validate_id_token(IT_TOKEN_SOCIAL, &st).is_ok());
        assert!(validate_id_token(IT_TOKEN_SOCIAL_APPLE, &st).is_err());
    }

    // --- the router, over a real socket -------------------------------------
    //
    // What a handler puts on the wire is not what its inner half returns, and the wire is
    // what nginx and a browser read. These bind a port, run one worker of `route`, and speak
    // HTTP to it, which is the harness `bb-auth-web`'s tests have always had and the gate's
    // have not.

    /// Start the router on a loopback port and return its base URL. The thread is left
    /// running: the test process exits soon enough, and a shutdown protocol would be more
    /// code than the thing it guards.
    fn serve(state: State) -> String {
        let server = Server::http("127.0.0.1:0").expect("a loopback port");
        let base = format!("http://{}", server.server_addr());
        let state = Arc::new(state);
        std::thread::spawn(move || {
            while let Ok(req) = server.recv() {
                route(req, &state);
            }
        });
        base
    }

    /// The client half: no redirect following (the redirects *are* the assertion) and a
    /// short timeout, so a hung handler fails one test instead of the suite.
    fn agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .new_agent()
    }

    #[test]
    fn the_router_answers_every_documented_endpoint() {
        let base = serve(token_state(gate_settings("{}")));
        let a = agent();

        // healthz, which is what `verify.sh` reads.
        let mut r = a.get(format!("{base}/auth/healthz")).call().unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.body_mut().read_to_string().unwrap(), "ok");

        // An unknown path is a 404 and never a page.
        assert_eq!(a.get(format!("{base}/nope")).call().unwrap().status(), 404);

        // A gated request with no credential: 401 naming this area's login page, which is
        // the header nginx lifts with `auth_request_set`.
        let r = a
            .get(format!("{base}/auth/validate"))
            .header("X-Original-URL", "https://app.x.com/other/x")
            .call()
            .unwrap();
        assert_eq!(r.status(), 401);
        assert_eq!(r.headers().get(LOGIN_URL_HEADER).unwrap(), LOGIN);

        // An `anonymous` scope: 204, and it names nobody.
        let r = a
            .get(format!("{base}/auth/validate"))
            .header("X-Original-URL", "https://app.x.com/pub/health")
            .call()
            .unwrap();
        assert_eq!(r.status(), 204);
        assert!(r.headers().get(IDENTITY_HEADER).is_none());

        // A cookie this gate minted, on the area its owner is listed in: 204 naming them.
        let cookie = make_session(&ident("bob@x.com"), 3600, &keys_one());
        let r = a
            .get(format!("{base}/auth/validate"))
            .header("X-Original-URL", "https://app.x.com/other/x")
            .header("Cookie", format!("bb_session={cookie}"))
            .call()
            .unwrap();
        assert_eq!(r.status(), 204);
        // Every identifier on the row, space-joined: the header names the person, not the
        // address they happened to sign in with.
        assert_eq!(
            r.headers().get(IDENTITY_HEADER).unwrap(),
            "bob@x.com bob@old.com"
        );

        // A `bbk_` key, which is the third credential and the one no token backs.
        let r = a
            .get(format!("{base}/auth/validate"))
            .header("X-Original-URL", "https://app.x.com/other/x")
            .header("Authorization", "Bearer bbk_secret")
            .call()
            .unwrap();
        assert_eq!(r.status(), 204);
        assert_eq!(
            r.headers().get(IDENTITY_HEADER).unwrap(),
            "bob@x.com bob@old.com"
        );

        // A gated request with no `X-Original-URL` resolves to no application at all, which
        // is the fail-closed posture the whole nginx contract rests on.
        let r = a.get(format!("{base}/auth/validate")).call().unwrap();
        assert_eq!(r.status(), 401);
    }

    #[test]
    fn a_session_post_from_another_site_is_refused_before_the_token_is_read() {
        let base = serve(token_state(gate_settings("{}")));
        let a = agent();
        let post = |site: Option<&str>| {
            let mut req = a.post(format!("{base}/auth/session"));
            if let Some(s) = site {
                req = req.header("Sec-Fetch-Site", s);
            }
            req.send_form([("id_token", IT_TOKEN_OK)]).unwrap()
        };
        // The attack: an attacker's own valid token, auto-submitted from their page. The
        // victim would otherwise browse the whole cookie domain as them.
        let r = post(Some("cross-site"));
        assert_eq!(r.status(), 403);
        assert!(r.headers().get("Set-Cookie").is_none());
        // A client that says nothing about where it came from is not a browser submitting
        // one of our forms.
        let r = post(None);
        assert_eq!(r.status(), 403);
        assert!(r.headers().get("Set-Cookie").is_none());
        // Same-site passes the door: `BB_AUTH_LOGIN_URL` may name a page an operator serves
        // on a sibling host, and that page has always been able to post here.
        assert_ne!(post(Some("same-site")).status(), 403);
    }

    #[test]
    fn the_session_endpoint_mints_a_cookie_and_lands_on_the_rd() {
        let base = serve(token_state(gate_settings("{}")));
        let r = agent()
            .post(format!("{base}/auth/session"))
            .header("Sec-Fetch-Site", "same-origin")
            .send_form([
                ("id_token", IT_TOKEN_OK),
                ("rd", "https://search.badbat75.com/x"),
            ])
            .unwrap();
        assert_eq!(r.status(), 302);
        assert_eq!(
            r.headers().get("Location").unwrap(),
            "https://search.badbat75.com/x"
        );
        // The cookie itself, and the header that keeps the response carrying it out of a
        // cache.
        let sc = r.headers().get("Set-Cookie").unwrap().to_str().unwrap();
        assert!(sc.starts_with("bb_session=bb1."), "{sc}");
        assert!(sc.contains("HttpOnly") && sc.contains("Secure"), "{sc}");
        assert_eq!(r.headers().get("Cache-Control").unwrap(), "no-store");

        // A token that does not validate gets no cookie and an error page, not a redirect.
        let r = agent()
            .post(format!("{base}/auth/session"))
            .header("Sec-Fetch-Site", "same-origin")
            .send_form([("id_token", IT_TOKEN_BAD_EMAIL)])
            .unwrap();
        assert_eq!(r.status(), 401);
        assert!(r.headers().get("Set-Cookie").is_none());

        // And a body that carries no token at all is a 400, which is the shape a broken
        // sign-in page produces.
        let r = agent()
            .post(format!("{base}/auth/session"))
            .header("Sec-Fetch-Site", "same-origin")
            .send_form([("rd", "https://search.badbat75.com/x")])
            .unwrap();
        assert_eq!(r.status(), 400);
    }

    #[test]
    fn the_sign_in_page_carries_its_policy_and_the_nonce_it_names() {
        let base = serve(token_state(gate_settings("{}")));
        let mut r = agent().get(format!("{base}/auth/login")).call().unwrap();
        assert_eq!(r.status(), 200);
        for (k, v) in PAGE_SECURITY_HEADERS {
            assert_eq!(r.headers().get(k).unwrap(), v, "missing {k}");
        }
        let csp = r
            .headers()
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let body = r.body_mut().read_to_string().unwrap();
        // The policy is only a policy if the page's own two blocks carry the nonce it names,
        // and if nothing else can execute.
        let nonce = csp
            .split("'nonce-")
            .nth(1)
            .and_then(|t| t.split('\'').next())
            .expect("a nonce in the policy")
            .to_string();
        assert!(csp.starts_with("default-src 'none';"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(csp.contains("form-action 'self'"), "{csp}");
        assert!(
            body.contains(&format!("<script nonce=\"{nonce}\">")),
            "the script must carry the policy's nonce"
        );
        assert!(
            body.contains(&format!("<style nonce=\"{nonce}\">")),
            "the stylesheet must carry the policy's nonce"
        );
        // A second response must not be able to reuse the first one's nonce.
        let mut r2 = agent().get(format!("{base}/auth/login")).call().unwrap();
        assert!(!r2.body_mut().read_to_string().unwrap().contains(&nonce));

        // `HEAD`, which nginx answered on the file this URL replaced.
        assert_eq!(
            agent()
                .head(format!("{base}/auth/login"))
                .call()
                .unwrap()
                .status(),
            200
        );
    }

    /// A deployment that sets the two `ui` URLs: the page asks for them and the policy lets
    /// them through, which only holds if both are derived from the same two settings.
    ///
    /// The failure this exists for is silent from every angle: the header is there, the
    /// `<link>` and the `<img>` are there, the asset host is up, and the browser fetches
    /// neither, because the policy names a different host or none. Nothing in the response
    /// says so; the operator sees a login page rendered as bare HTML and no logo, which is
    /// what an unreachable asset host looks like too.
    #[test]
    fn a_configured_stylesheet_and_logo_are_in_the_page_and_in_the_policy() {
        let ui = bb_auth_core::UiSettings {
            stylesheet_url: "https://assets.badbat75.com/css/theme.css".to_string(),
            logo_url: "https://assets.badbat75.com/img/logo.svg".to_string(),
            brand_name: "BadBat75".to_string(),
            theme: "dark".to_string(),
        };
        let base = serve(token_state(ui_settings(ui)));
        let mut r = agent().get(format!("{base}/auth/login")).call().unwrap();
        assert_eq!(r.status(), 200);
        let csp = r
            .headers()
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let body = r.body_mut().read_to_string().unwrap();

        // The page asks for both, by their full URL.
        assert!(
            body.contains(
                r#"<link rel="stylesheet" href="https://assets.badbat75.com/css/theme.css">"#
            ),
            "the operator's stylesheet must be linked: {body}"
        );
        assert!(
            body.contains(r#"<img src="https://assets.badbat75.com/img/logo.svg" alt="">"#),
            "the operator's logo must be in the page"
        );
        // And the policy admits that host for both, by origin and not by path.
        assert!(
            csp.contains("https://assets.badbat75.com;")
                || csp.contains("https://assets.badbat75.com "),
            "{csp}"
        );
        for directive in ["style-src", "img-src"] {
            let d = csp
                .split(';')
                .map(str::trim)
                .find(|d| d.starts_with(directive))
                .unwrap_or_else(|| panic!("{directive} in {csp}"));
            assert!(
                d.contains("https://assets.badbat75.com"),
                "{directive} must admit the host the page asks: {d}"
            );
        }
        // The inline blocks are still nonce-covered, so adding an external host does not
        // quietly relax what the page itself may run.
        assert!(csp.contains("script-src 'nonce-"), "{csp}");
        assert!(!csp.contains("unsafe-inline"), "{csp}");
    }

    #[test]
    fn with_no_login_url_configured_the_gate_names_its_own_page() {
        // The default that makes the setting optional: since the gate serves the sign-in page
        // itself, naming one is how an operator points somewhere ELSE. A path and not a URL,
        // because this process knows neither its own scheme nor its own host.
        let mut file: bb_auth_core::SettingsFile = serde_json::from_str(&format!(
            r#"{{ "version": {}, "gate": {{ "client_id": "testclient" }} }}"#,
            bb_auth_core::SETTINGS_VERSION
        ))
        .unwrap();
        file.gate.login_url = String::new();
        let settings = bb_auth_core::compile_settings(&file).unwrap();
        assert_eq!(global_login(&settings), "/auth/login");

        let base = serve(token_state(settings));
        let r = agent().get(format!("{base}/auth/logout")).call().unwrap();
        assert_eq!(r.headers().get("Location").unwrap(), "/auth/login");
    }

    #[test]
    fn a_logout_clears_the_cookie_and_only_refuses_a_cross_site_one() {
        let base = serve(token_state(gate_settings("{}")));
        let r = agent().get(format!("{base}/auth/logout")).call().unwrap();
        assert_eq!(r.status(), 302);
        // No `rd`, no `Referer`: the login page, never `safe_rd`'s caller-root default.
        assert_eq!(r.headers().get("Location").unwrap(), LOGIN);
        let sc = r.headers().get("Set-Cookie").unwrap().to_str().unwrap();
        assert!(sc.starts_with("bb_session=;"), "{sc}");
        assert!(sc.contains("Max-Age=0"), "{sc}");

        // Cross-site: still a redirect, deliberately, but nothing is cleared.
        let r = agent()
            .get(format!("{base}/auth/logout"))
            .header("Sec-Fetch-Site", "cross-site")
            .call()
            .unwrap();
        assert_eq!(r.status(), 302);
        assert!(r.headers().get("Set-Cookie").is_none());
    }

    /// The list `--check-env` answers with, against the calls that actually make a variable
    /// required. `deploy/debian/bb-auth/postinst` used to keep a second copy of this in
    /// shell; it now asks the binary, and this is what keeps the binary honest.
    #[test]
    fn the_required_env_list_matches_the_code() {
        let src = include_str!("bb-auth.rs");
        let called: std::collections::BTreeSet<&str> = src
            .match_indices("env_req(\"")
            .map(|(i, m)| {
                let rest = &src[i + m.len()..];
                &rest[..rest.find('"').expect("a closed string literal")]
            })
            .collect();
        let listed: std::collections::BTreeSet<&str> = REQUIRED_ENV.iter().copied().collect();
        assert_eq!(
            called, listed,
            "REQUIRED_ENV and the env_req call sites have drifted"
        );
    }

    /// The fail-soft promise, which is what makes it safe to let a GUI edit a live file:
    /// a reload that cannot parse the file keeps what is already in memory.
    ///
    /// Unix only, because SIGHUP is; that is also why this went untested for so long, since
    /// the development host is Windows and the code is not even compiled there. Run it under
    /// WSL (`wsl -e bash -lc 'cd /mnt/c/... && cargo test'`) before a release.
    #[cfg(unix)]
    #[test]
    fn a_reload_that_cannot_parse_keeps_what_is_live() {
        let st = token_state(gate_settings("{}"));
        let before = st.access.read().unwrap().apps.len();
        assert!(before > 0, "the fixture has applications");

        let dir = std::env::temp_dir();
        let bad = dir.join("bb-auth-reload-bad.json");
        std::fs::write(&bad, "{ not json at all").unwrap();
        reload_access_from(&st, bad.to_str().unwrap());
        assert_eq!(
            st.access.read().unwrap().apps.len(),
            before,
            "a broken file must not empty the live table"
        );

        // A file the parser refuses for a rule reason, not a syntax one: same answer.
        std::fs::write(&bad, r#"{ "version": 99 }"#).unwrap();
        reload_access_from(&st, bad.to_str().unwrap());
        assert_eq!(st.access.read().unwrap().apps.len(), before);

        // And a good file does land.
        let good = dir.join("bb-auth-reload-good.json");
        std::fs::write(
            &good,
            r#"{ "version": 1, "applications": [
                 { "name": "only", "base": ["https://x.com/only"], "scopes": [
                   { "name": "all", "urls": ["https://x.com/only/*"], "access": "anonymous" } ] } ] }"#,
        )
        .unwrap();
        reload_access_from(&st, good.to_str().unwrap());
        assert_eq!(st.access.read().unwrap().apps.len(), 1);

        // The settings file, by the same rule.
        let ttl = st.settings.read().unwrap().session_ttl;
        let bad_s = dir.join("bb-auth-reload-bad-settings.json");
        std::fs::write(
            &bad_s,
            r#"{ "version": 1, "gate": { "identity_attrs": [] } }"#,
        )
        .unwrap();
        reload_settings_from(&st, bad_s.to_str().unwrap());
        assert_eq!(
            st.settings.read().unwrap().session_ttl,
            ttl,
            "a settings file the gate refuses must leave the live values alone"
        );

        for f in [bad, good, bad_s] {
            let _ = std::fs::remove_file(f);
        }
    }

    #[test]
    fn a_listen_address_is_recognised_as_loopback_or_not() {
        for ok in [
            "127.0.0.1:4181",
            "localhost:4181",
            "[::1]:4181",
            "127.0.0.1",
        ] {
            assert!(listen_is_loopback(ok), "{ok}");
        }
        for no in [
            "0.0.0.0:4181",
            "10.0.0.5:4181",
            "auth.badbat75.com:80",
            "[::]:80",
        ] {
            assert!(!listen_is_loopback(no), "{no}");
        }
    }
}
