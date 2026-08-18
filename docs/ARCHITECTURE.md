# bb-auth — Architecture

Minimal **auth gate**. It accepts a Cognito `id_token` that a browser-side login
page obtained and turns it into an HMAC-signed session cookie that nginx enforces
via `auth_request`. The service is generic — it fronts any web service and is
wired per-deployment through `BB_AUTH_*` env vars **and a settings file** (§8a), which
holds what must change with no restart.

This document describes the **service**. The end-to-end login sequence (browser,
Cognito, nginx, bb-auth) is documented separately in
[`AUTHENTICATION_FLOW.md`](./AUTHENTICATION_FLOW.md).

---

## 1. Why it exists

Authorization-code OIDC proxies (e.g. oauth2-proxy) only speak the OIDC
**authorization-code** flow: they redirect the browser to the IdP's hosted login
and exchange the returned code themselves. They **cannot accept a token the
browser already obtained**.

bb-auth assumes the opposite: a login page drives the Cognito `USER_AUTH` flow
directly on the public client. The key UX this unlocks is **auto-login right
after registration, with no second OTP**: a new user is `SignUp` →
`ConfirmSignUp` → `InitiateAuth(Session)` in one flow and ends up holding an
`id_token`. bb-auth takes that client-obtained token, validates it, and issues
the session cookie that grants access to the protected service.

---

## 2. Component view

```text
                           ┌──────────────────────── service host ────────────────────────┐
                           │                                                               │
  browser ─── HTTPS ─────▶ │  nginx :443  (the protected service)                          │
                           │   │                                                           │
                           │   ├─ auth_request ─▶ /internal/auth-gate ─▶ 127.0.0.1:4181/auth/validate
                           │   │     (401 ─▶ 302 <login-page>/?rd=<original>)               │
                           │   │                                                           │
                           │   ├─ POST /auth/session  ─▶ bb-auth (validate id_token → Set-Cookie)
                           │   ├─ GET  /auth/logout   ─▶ bb-auth (clear cookie)             │
                           │   └─ everything else     ─▶ upstream app  (only if gate == 204)│
                           │                                                               │
                           │  bb-auth :4181  (loopback only)  ◀── this service             │
                           └───────────────────────────────────────────────────────────────┘
                                                    │
                                                    └─ HTTPS (JWKS fetch) ─▶ cognito-idp.<region>.amazonaws.com
```

Three actors outside bb-auth itself:

| Actor | Role |
|-------|------|
| **nginx** | Edge TLS terminator. Runs `auth_request` against bb-auth on every protected request; maps `401` to a redirect to the login page. |
| **Login page** | Browser-side email-first UI that performs the Cognito `USER_AUTH` flow and then top-level `POST`s the resulting `id_token` to `/auth/session`. |
| **AWS Cognito** | Issues and RS256-signs the `id_token`. bb-auth only reads its public JWKS — it holds no Cognito secret. |

---

## 3. Code structure

One crate, four targets. The seam is the **access file** (and, since 3.1, the settings
file and the presentation contract beside it, for the same reason and by the same rule):
its schema, its parser, its matcher and its grant model are the one thing two programs
must agree on byte for byte, so they live in a library both link. Everything else about
the gate is the gate's, and stays in one file.

| Target | What it is |
|--------|------------|
| `src/lib.rs` (`bb_auth_core`) | **The access file.** Schema (`AccessFile`), parser (`compile_access`), URL matcher (`glob_match` / `UrlScope`), the two-level resolution (`Access::resolve`, `base_covers`), the grant model (`decide`, `decide_api_key`), identity and key minting (`mint_uuid`, `mint_api_key`), and how a file is edited and written (`open_access_file`, `AccessWrite`, the document mutations). Plus the settings file, and **the presentation contract** (`THEME_CSS` from `src/assets/theme.css`, `BASE_CSS` from `src/assets/base.css`, `UiTheme`, `stylesheet_link`, `html_escape`, `compile_asset_url`): the palette two programs paint from **and the components they build out of it**, on the same membership rule as everything else here. A thing (a button, a field, a card, a tag, a message) is defined once for both; how a page arranges those things is not. Reads no env, opens no socket, holds no HTTP, prints nothing. |
| `src/bin/bb-auth.rs` (`bb-auth`) | **The gate**, still a single file read top to bottom: HTTP, config, the session cookie, id_token validation, the nginx contract, and the three pages it serves out of `src/assets/` (sign-in, social callback, error). |
| `src/bin/bb-auth-adm.rs` (`bb-auth-adm`) | **The access-file admin CLI.** CRUD over `applications` / `scopes` / `user_groups` / `denied` / `users` / `api_keys`, key minting and rotation, and `can EMAIL URL` — which calls the library's `decide`, so it answers the question the gate will answer. Every edit and every write is a library call (`AccessWrite`), so it cannot save a file the gate would reject; what is left here is flags, warnings and the wording of a verdict. See §12. |
| `src/bin/bb-auth-web.rs` (`bb-auth-web`) | **The access-file admin GUI**: server-rendered (`maud`; no page needs JavaScript, the one inline handler is a Settings-menu shortcut with a `<noscript>` submit behind it) over the library, read *and* write — CRUD through `AccessWrite` alone, `POST`-only mutations behind a same-origin check and a `rev` (sha256-of-file) concurrency check. Loopback behind nginx `auth_request`, identity from the `X-Auth-Email` nginx injects plus its own administrator allowlist (`web.admins` in the settings file, read fresh on every request and editable from its own Settings tab). Links the library, none of the gate. |

Inside `src/bin/bb-auth.rs`, in file order:

| Section | Purpose |
|---------|---------|
| `Config` / `from_env` | The env-var half of the configuration; fatal-`exit`s on a missing required value or a too-short HMAC key. The other half is `State::settings`, re-read on `SIGHUP`; see §8a. |
| `State` / `JwksCache` | Shared state behind `Arc`: config, a `RwLock<Access>` access table, a `RwLock` JWKS cache, and a `Mutex` serializing JWKS refreshes. |
| `load_access` / `reload_access` | Wrap the library's `read_access`, which parses the JSON access file (`BB_AUTH_ACCESS_FILE`) into the applications and their scopes, the two `denied` sets, and three indices: identifiers (`by_identifier`), the roster (`by_uuid`) and `bbk_` API keys (`by_key_hash`); identifiers lowercased. `load_access` aborts startup if unreadable (warns if nothing is granted); `reload_access` swaps the table live on `SIGHUP`, keeping the old table on error. See §12. |
| `authorize` / `bearer_apikey` | Thin wrappers over the library's `decide` / `decide_api_key`: they add the log line naming the reason, and the wall clock a key's expiry is measured against. The rule itself is in the library, which is what lets `bb-auth-adm can` be truthful. `authorize_login` resolves the identifier to a roster row and re-attaches the profile claims after the decision, which never sees them. See §12. |
| `check_access` | The `bb-auth --check-access <file>` mode: parse and exit `0`/`1`, no env and no network. Lets a deploy reject an access file before restarting onto it. |
| `fetch_jwks` / `refresh_jwks_if_due` / `decoding_key` | `GET {issuer}/.well-known/jwks.json` via `ureq`+rustls; cache keyed by `kid`, refreshed at most once per 60 s, deduped across workers by double-checked locking. |
| `validate_id_token` | Full JWT validation (see §6). Returns a `UserIdentity`: the verified, lowercased email plus whichever configured profile claims the token asserted (`clean_claim`). |
| `make_session` / `verify_session` | HMAC-SHA256 signed cookie (see §7). |
| HTTP helpers | Header/cookie parsing, cookie building, open-redirect `safe_rd`, `pct_encode`, response builders. |
| The pages | `LOGIN_HTML`, `CALLBACK_HTML` and `AUTH_CSS`, `include_str!`-ed from `src/assets/`, filled by `render_page` over `__BB_*__` placeholders (single-pass, so a substituted value is never rescanned) and dressed by `look_subs` from the settings file's `ui` section. The head emits `THEME_CSS`, then `BASE_CSS`, then `AUTH_CSS`, then the operator's link: the first two are the same bytes `bb-auth-web` emits, so these pages and the admin interface are one product by construction rather than by intention, and `AUTH_CSS` only says how this page arranges them. Self-contained: the palette, the components, the arrangement, the script and both languages are in the document, and the only external references are an operator's optional stylesheet and logo. `env_page_value` is what makes a config value safe to emit raw. |
| `handle_validate` / `handle_session` / `handle_logout` / `handle_login` / `handle_callback` | The five real handlers (plus `/auth/healthz` inline). `/auth/validate` resolves a cookie or bearer credential to an identity, authorizes the request URL against it, and returns the identity in one header per configured attribute, plus one per configured profile claim the credential carried (`bearer_apikey` / `authorize` / `authorize_login` / `original_url` / `identity_headers` / `profile_headers` / `respond_authorized`). The last two render the pages above and are the two locations nginx must leave ungated. |
| `main` | Build config/state, prime JWKS, spawn the worker thread pool, route requests. |

And in `src/lib.rs`:

| Section | Purpose |
|---------|---------|
| `glob_match` / `compile_pattern` / `UrlScope` | The one URL matcher: every scope's `urls` goes through it. Validates and normalises patterns at load, then matches a request URL with `*` / `&` wildcards, denying a missing URL and any `..`. See §12. |
| `AppRecord` / `ScopeRecord` / `Access::resolve` / `base_covers` | The two levels: applications partition the URL space by literal area (so at most one answers, and `base_covers` compares at a path boundary), and scopes inside one are first-match-wins in file order. `login_url_for` names the area's login page. See §12. |
| `compile_login_url` | Validates `BB_AUTH_LOGIN_URL` and every application's `login_url`: printable ASCII, absolute `https://`, no userinfo `@`, no backslash. What makes emitting them in `X-Auth-Login-URL`, a `Location:` and a page safe with no per-use check. |
| `decide` / `decide_api_key` / `Subject` | The grant model as a value (`Decision` / `KeyDecision`): resolve the URL, an `anonymous` scope grants ahead of the veto, then `denied`, then the scope's kind, the credential class, the roster, membership and the key's own restriction. The single authorization point, shared by the gate and both editors. See §12. |
| `AccessFile` / `compile_access` / `read_access` | The document model (what `bb-auth-adm` edits, `notes` and `_comment` round-tripping untouched) and the parser that turns it into the runtime table. |
| `mint_api_key` | 256 bits from the OS CSPRNG, `bbk_` + base64url; returns the bearer and the `sha256` the file stores. |
| `open_access_file` / `AccessWrite` / the document mutations | **Editing an access file** — here rather than in a tool because `bb-auth-adm` and `bb-auth-web` must do it identically. Open (refusing a file the gate would reject), the lookups and mutations behind every CRUD command (`add_user`, `add_user_email`, `add_api_key`, `add_application`, `add_scope`, `move_scope`, `remove_user_group`, `add_denied`, `edit_urls`, …), and the write: render → re-parse → `compile_access` → atomic temp+rename, preserving mode and owner. `AccessWrite::prepare` is the only way to obtain bytes and `commit` writes exactly those, with `write_atomically` private, so the check cannot be skipped; a minted bearer comes back as a `SealedKey` that only opens against the `Written` receipt of a completed write. |

---

## 4. Runtime model

- **No async runtime.** `tiny_http` is blocking + threaded. This keeps the binary
  small and resident memory low, so it runs comfortably on constrained hosts.
- **Thread pool:** `BB_AUTH_WORKERS` threads (default 4), each looping on
  `server.recv()` and dispatching on `(method, path)`. State is shared via
  `Arc<State>`; the JWKS cache and the access table are each behind a `RwLock`, and a
  `Mutex` serializes JWKS refreshers (double-checked locking — see §6).
- **Stateless sessions:** there is **no server-side session store**. The session
  is fully carried by the HMAC cookie, so any worker can validate any request and
  a restart does not log anyone out (cookies are time-bound, not server-bound).
- **Access table is hot-reloadable:** it lives in a `RwLock<Access>` and is re-read
  from disk on `SIGHUP` (`systemctl reload bb-auth`) — edit + reload applies
  changes live without dropping sessions. A restart still works too. Every
  credential is re-checked against the table on every `/auth/validate`, so removing
  a user (or one of their API keys) denies it immediately even for a still-valid
  cookie or unexpired key.

---

## 5. Endpoints

The table below is a **second copy** of the one on `bb-auth`'s crate root (`cargo doc
--no-deps`), which is where the endpoint contract belongs and where it is maintained: this
one exists because this document is read end to end and a reader should not have to leave
it. When the two disagree, the crate root is right, and this one is what needs fixing. The
same goes for README's operator-facing version.

| Method | Path | Caller | Behavior |
|--------|------|--------|----------|
| `GET` | `/auth/validate` | nginx only (`auth_request`) | `204` naming the identity in one header per `identity_attrs` entry (default `X-Auth-Email`) if an accepted credential authorizes the request URL, otherwise `401` + `X-Auth-Login-URL: <this area's login page>`. A `204` also carries one header per `profile_claims` entry the credential knows (percent-encoded; omitted otherwise). Accepts (in order) an `Authorization: Bearer bbk_…` static API key, an `Authorization: Bearer <id_token>`, or the session cookie, and then no credential at all, which only an `anonymous` scope grants. A request with no credential names nobody; one that carried a valid credential is still named, so the header is bimodal on such a scope and an application there must treat it as "if you know who this is, say so". A **vetoed** identity is never named. See §12. |
| `GET`, `HEAD` | `/auth/login[?rd=…]` | browser | The sign-in page: runs the Cognito `USER_AUTH` flow in the browser and POSTs the resulting id_token to `/auth/session`. Self-contained (palette, layout, script and both languages in the document; only the operator's optional stylesheet and logo are external). `rd` is validated here with the same `rd_url_allowed` `safe_rd` uses and dropped if it fails; with none, the browser's `Referer` answers in its place, through that same check and absolute-only, since this page resolves nothing against nginx. Social buttons appear only when `BB_AUTH_SOCIAL_*` is configured. |
| `GET`, `HEAD` | `/auth/callback` | browser | Finishes a social sign-in: exchanges the OAuth code and the PKCE verifier for tokens, offers a profile form when the IdP sent no names, and delivers the id_token exactly as the sign-in page does. `404` when no social client is configured. |
| `POST` | `/auth/session` | browser | Body `application/x-www-form-urlencoded`: `id_token=…&rd=…`. Fully validates the id_token; on success sets the session cookie and `302`s to `rd` (open-redirect guarded). |
| `GET` | `/auth/logout[?rd=…]` | browser | Sets an expired (Max-Age=0) cookie and `302` → `rd` (same `safe_rd` guard), or, with no `rd`, the browser's `Referer` (same guard), and failing both the login page. Cross-site requests (`Sec-Fetch-Site: cross-site`) are ignored (no cookie clear) to block CSRF-forced logout. Reads nothing about the host it was called on, and the expiring cookie carries the same `Domain` as the minted one, so under a shared `BB_AUTH_COOKIE_DOMAIN` one mounted location logs the browser out of every vhost: see README "One logout endpoint for every vhost". |
| `GET` | `/auth/healthz` | local | `200 ok`. Liveness probe. |

`/auth/validate` is never exposed publicly; nginx reaches it over loopback
through the `internal` `/internal/auth-gate` location. `/auth/session`, `/auth/logout`,
`/auth/login` and `/auth/callback` are the public bb-auth routes, and all four must be
**ungated** in nginx. The two pages most of all: a sign-in page behind an `auth_request`
answers a signed-out visitor with itself, forever.

---

## 6. id_token validation (`validate_id_token`)

A Cognito-signed `id_token` is the credential. bb-auth validates it fully before
ever issuing a cookie:

1. **Algorithm:** header `alg` must be `RS256` (rejects `none` / symmetric algs).
2. **Key lookup:** `kid` from header → JWKS cache; on a miss, refresh JWKS if the
   last refresh was > 60 s ago (handles IdP key rotation). Refreshes are
   deduped with double-checked locking (`Mutex`-guarded) so concurrent workers
   don't all fetch in parallel on a cold/stale cache.
3. **Signature + standard claims** via `jsonwebtoken`:
   - `exp` validated (60 s leeway), `iss == BB_AUTH_COGNITO_ISSUER`,
     `aud` ∈ accepted audiences (`BB_AUTH_CLIENT_ID` plus any `BB_AUTH_AUDIENCES`);
     `exp`/`aud`/`iss` are mandatory.
4. **Cognito-specific claims:** `token_use == "id"` (rejects access tokens) and
   `email_verified` truthy (accepts JSON `true` or the string `"true"`).
   - **Social-login exception** (off by default): when
     `allow_unverified_social` is enabled, a token with
     `email_verified=false` is still accepted **iff** it carries a federated
     `identities` entry (a social login — Cognito often can't verify a social
     sign-up's email even though the IdP asserted it). `social_providers`
     can narrow this to specific `providerName`s. **Native** Cognito users (no
     `identities` claim) are never relaxed: self-signup is open, so an unverified
     native email is attacker-controlled. See `unverified_social_ok`.
5. Returns the `email` claim, lowercased, together with whichever
   `profile_claims` the token asserts — trimmed, ≤ 256 raw UTF-8 bytes, free of
   control characters, and **not** lowercased (`clean_claim`). Anything else about one
   (missing, empty, over-long, or not even a string) drops that single claim and nothing
   else: they are not an identity, they authorize nothing, and a badly mapped IdP
   attribute must never cost someone their login. An unconfigured claim is never even
   looked at. They are also unaffected by the social-login exception above — a profile
   attribute is self-asserted on every token.

Failure on any step → the session request is rejected with `401` (token
invalid/expired) or `403` (email not in the access table).

---

## 7. Session cookie

One format, carrying an `exp`, the base64url-encoded email, a base64url-encoded JSON
object of profile claims, and a base64url HMAC-SHA256 tag:

```text
bb1.<keyid>.<exp>.<b64url(email)>.<b64url(claims_json)>.<b64url(sig)>
sig = HMAC_SHA256("bb1.<keyid>.<exp>.<b64url(email)>.<b64url(claims_json)>", key[keyid])
```

- **`bb1`** — the **only** accepted format. The **key id** (`<keyid>`) is
  stamped in so the signing key can roll over with zero downtime: the verifier looks up
  the key by id in the accepted set (`BB_AUTH_HMAC_KEY` active +
  `BB_AUTH_HMAC_ACCEPTED_KEYS`).
- **No verify-only arm.** A tag the gate does not know is not distinguished from junk, so
  changing the serialization or the signed bytes logs every live session out, once, and
  the holder walks back through the login page: a re-authentication against a Cognito
  session the browser still has, not a re-enrolment. That is the accepted price of never
  carrying more than one arm, its tests and its reasoning. Key *rotation* is the separate
  axis that must never log anybody out, and does not.
- **Profile claims** — `claims_json` is a JSON object mapping claim name to value
  (`{"family_name":"Byron","given_name":"Ada"}`, sorted keys), raw UTF-8 under the
  base64, so the cookie is binary-safe where a header is not; percent-encoded only on
  emission (§12). No claims is the **empty segment**, never `{}`: six fields, always. It
  is inside the signed bytes, so a claim cannot be swapped or forged, and a blob that is
  not an object of well-formed values fails the whole cookie (fail-closed — we could not
  have minted it). Each value is capped at 256 bytes.
- **The blob is self-describing, and that is what makes the claim list configurable.** A
  cookie lives up to a month; positional segments would let an edit to
  the claim list reinterpret a live cookie's values under a different claim
  name. So changing that list is *not* a format change — nobody is logged out, a claim
  removed from it stops being emitted from cookies that still carry it (`profile_headers`
  filters against the live config), and one added appears at the next sign-in. Two claims
  keep the cookie ≲ 1 KB against the browsers' ~4 KB; the gate warns at startup when a
  configured set could approach the limit.
- **`exp`** — Unix epoch seconds, `now + session_ttl`; rejected when `exp <= now`.
- **HMAC-SHA256** over the cookie prefix up to (but not including) the signature.
  Verification is constant-time (`Mac::verify_slice`).
- **Attributes:** `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, host-only on
  the service host (a `Domain` can be set via `BB_AUTH_COOKIE_DOMAIN` but is
  empty by default).
- **TTL:** ~30 days (`gate.session_ttl_secs`, §8a).

Because the cookie is self-contained and key addressed, **key rotation
invalidates nobody**: the new key is added as verify-only, then flipped to
active, then the old one is dropped after a TTL. See README "Key rotation". Skipping
that window is the inverse of it, and the only way to invalidate every session at once,
since there is no session store to purge: see README "Revoking every session at once".
De-authorizing an email is separate from signatures: remove the user from the
access file (or add them to `denied`) and reload/restart — the next `/auth/validate`
for that cookie returns `401` even though the cookie signature is still valid. On a
`authenticated` scope the roster is not consulted, so there `denied` is the only lever.

---

## 8. Configuration

Two places, and which one a setting is in is decided by one question: what does changing it
cost?

**`bb-auth.env`** (see `deploy/bb-auth.env.example`) holds everything a change to costs a
restart or a re-login. Required vars cause a fatal exit if missing.

**The settings file** (see `deploy/settings.example.json`, and §8a below) holds everything
that is read per request, cannot lock anybody out when it is wrong, and holds no secret. It
is a file rather than more environment for one mechanical reason: **a process cannot
re-read its own environment**. systemd loads `EnvironmentFile=` once, at `ExecStart`, so
nothing in an env file can ever take effect without a restart.

| Variable | Required | Default | Notes |
|----------|:--------:|---------|-------|
| `BB_AUTH_HMAC_KEY` | yes | — | Active session-signing secret. **≥ 32 bytes.** Generated once at deploy time; the only secret in the system. |
| `BB_AUTH_HMAC_KEY_ID` | no | `default` | Key id stamped into new cookies. Must match `[A-Za-z0-9_-]+` (no `.`). Bump on rotation so older keys can still verify. |
| `BB_AUTH_HMAC_ACCEPTED_KEYS` | no | empty | Comma-separated `id:key` entries accepted for verification during rotation (`key` = `openssl rand -base64 48`). Active key always verifies; this is for previous keys. |
| `BB_AUTH_COGNITO_ISSUER` | yes | — | The Cognito user-pool issuer URL, `https://cognito-idp.<region>.amazonaws.com/<user-pool-id>`. Trailing `/` stripped. JWKS URL is derived from this. |
| `BB_AUTH_CLIENT_ID` | yes | — | The public app client used by the login page; always an accepted `id_token.aud`. |
| `BB_AUTH_AUDIENCES` | no | empty | Comma-separated extra accepted `aud`s (Cognito app client ids), e.g. a separate social-login client. `BB_AUTH_CLIENT_ID` is always accepted; a token is valid if its `aud` matches any. Read at startup → needs `restart`, not `reload`. |
| `BB_AUTH_ACCESS_FILE` | yes | — | Path to the JSON access file (`applications`, `user_groups`, `denied`, and the roster of users with their `bbk_` API keys; see §12). Loaded at startup, hot-reloaded on `SIGHUP`. The name is a contract with the operator-owned env file a deploy never rewrites. |
| `BB_AUTH_ORIGINAL_URL_HEADER` | no | `X-Original-URL` | Request header carrying the original request URL (scheme + host + normalised path). Set by nginx on the `auth_request` subrequest (from a `$bb_url` captured in the gated location — **not** from `$uri`, see §12) **and** on `/auth/session` (there a plain `https://app.example.com$uri` is correct). Drives URL scoping, and on `/auth/session` tells bb-auth which host the login is on. Query/fragment are stripped; missing ⇒ fail closed. |
| `BB_AUTH_LISTEN` | no | `127.0.0.1:4181` | Bind address. Loopback only — nginx fronts it. |
| `BB_AUTH_COOKIE_NAME` | no | `bb_session` | |
| `BB_AUTH_COOKIE_DOMAIN` | no | empty → host-only | Set to a parent domain for cross-service SSO. |
| `BB_AUTH_AUTHORIZED_HOSTS` | yes | — | Comma-separated host globs a post-login `rd` may land on, e.g. `example.com,*.example.com`. The sole authority for the `rd` guard (see §8b). `*.x.com` does not match the apex `x.com`. |
| `BB_AUTH_LOGIN_URL` | yes | — | Where `401`/logout send the user (the login page), and where a rejected `rd` falls back to. |
| `BB_AUTH_SETTINGS_FILE` | no | `settings.json` beside the access file | Path to the settings file (§8a). Re-read on `SIGHUP` like the access file, fail-soft on both. A missing file is a fatal startup. |
| `BB_AUTH_OAUTH_DOMAIN` | no | empty | The Cognito hosted-UI domain, as a bare host. One of the four `BB_AUTH_SOCIAL_*`/OAuth values that enable social sign-in on `/auth/login`: **all four or none**, and half of them is a fatal startup. |
| `BB_AUTH_SOCIAL_CLIENT_ID` | no | empty | The app client the hosted UI and the PKCE exchange use. Must also be an accepted audience (`BB_AUTH_AUDIENCES`), which is checked at startup: without it every social login succeeds at Cognito and is refused here a redirect later. |
| `BB_AUTH_SOCIAL_CALLBACK_URL` | no | empty | The `redirect_uri`, which must match the one registered on that app client **exactly**. Normally `/auth/callback` on the host serving the sign-in page. |
| `BB_AUTH_SOCIAL_IDPS` | no | empty | Comma-separated Cognito `identity_provider` names, in the order their buttons appear. `Google` and `MicrosoftPersonal` come with an icon; any other name still gets a button, labelled with the name. |
| `BB_AUTH_WORKERS` | no | `4` | Thread pool size (min 1). |

The admin GUI is a separate service with a separate env file
(`deploy/bb-auth-web.env.example`, installed as `etc/bb-auth-web.env`): `BB_AUTH_ACCESS_FILE`
and `BB_AUTH_SETTINGS_FILE`, the same names for the same files, plus `BB_AUTH_WEB_LISTEN`,
`BB_AUTH_WEB_BASE_PATH`, `BB_AUTH_WEB_DEFAULT_LANG`, `BB_AUTH_WEB_LOGOUT_URL` (unset means
the header carries no Sign out control at all) and `BB_AUTH_WEB_ALLOW_NONLOOPBACK` (a
non-loopback listen address is otherwise a fatal startup, because this service's only
credential is a header nginx sets). It holds no secret at all, and its
administrator allowlist is not an env var: it is `web.admins` in the settings file, read
fresh on every request, because this is the one service that can edit it.

### 8a. The settings file

`compile_settings` (in the library, so all three programs agree on it) turns it into
`Settings`. Three sections: `gate` and `web` are one per service, and `ui` is the one both
read. Each service ignores what is not its own, and all of it goes through the same parser,
so an edit made by either is one the other would accept.

| Setting | Default | Notes |
|---------|---------|-------|
| `gate.profile_claims` | `[]` → none | OIDC claim names to propagate to the app on a `204`, each in a header derived from its own name (`given_name` → `X-Auth-Given-Name`; see §12). Any unusable entry is refused, never skipped. Changing it logs nobody out: a claim removed stops being emitted at once, one added appears at the holder's next sign-in. |
| `gate.identity_attrs` | `["email"]` | Which identity attributes a `204` names (§12). `email` and `uuid` are the only two that exist. **Empty is refused**: a `204` that names nobody breaks every application behind the gate, in silence. |
| `gate.allow_unverified_social` | `false` | Accepts `email_verified=false` tokens **only** for federated/social logins (those carrying an `identities` claim); native Cognito users stay strict. |
| `gate.social_providers` | `[]` → any | `providerName`s (case-insensitive, e.g. `Google`, `SignInWithApple`) the relaxation above applies to. No effect unless it is on. |
| `gate.session_ttl_secs` | `2592000` (30 d) | Applies to cookies minted from then on and to none already in a browser, so changing it logs nobody out. Below 60s is refused (a login loop); above 400 days is warned about (the cap browsers apply to `Max-Age`). |
| `web.admins` | `[]` | Who may use `bb-auth-web`, matched against the `X-Auth-Email` nginx injects. **Never empty**: the binary refuses to serve without one and both editors refuse to write an empty list. The gate ignores this section. |
| `ui.stylesheet_url` | `""` → none | A stylesheet loaded **after** each program's built-in one, so it wins by source order. Absolute `https://`, or a path starting with `/` on this host. Read by both services, which is what makes one file restyle the gate's pages and the whole GUI together. Expected to redefine the custom properties in `THEME_CSS` and nothing else. |
| `ui.logo_url` | `""` → none | Shown on the sign-in page above the name. Same two shapes. |
| `ui.brand_name` | `""` | What the sign-in page calls this deployment; empty falls back to each page's own name. |
| `ui.theme` | `"system"` | `system`, `light` or `dark`: which palette a page starts in. For the gate's pages it is the whole answer (they keep no per-visitor state); in `bb-auth-web` it is the default an administrator's own Settings menu overrides. |

The `ui` four pass the "cannot lock anybody out" test for one structural reason: **both
binaries already carry a complete stylesheet**, so an override is an addition to a working
page and never the page itself. The worst a wrong value there achieves is a page in the
wrong colours, and a stylesheet host that is down costs nothing but its palette.

What is **not** in it is the point of it. The listener and the worker count need a rebind;
the HMAC key is the secret; the Cognito trust roots, the cookie's name and its domain change
who can log in or log everyone out; the `BB_AUTH_SOCIAL_*` group is a sign-in that cannot
complete when it is wrong; and `BB_AUTH_LOGIN_URL`, `BB_AUTH_AUTHORIZED_HOSTS` and
`BB_AUTH_ORIGINAL_URL_HEADER` *are* the lockout when they are wrong. All of those stay in the
env file, where changing one is a deliberate act with a restart attached. That the sign-in
page's *look* is hot while its *Cognito wiring* is not is the rule working: one cannot shut
anybody out, and the other is the only way to.

Edited with `bb-auth-adm settings …` or from `bb-auth-web`'s Settings tab, through the same
validate-before-write the access file gets (`SettingsWrite`). Checked by hand with
`bb-auth --check-settings <file>`; `scripts/verify.sh` and the gate's `postinst` both run it.
Unknown keys **inside a section** are a hard error, for the reason a misspelled scope field
is one; unknown keys at the top level are preserved, which is where `_comment` lives.

### 8b. Where the post-login redirect may land (`safe_rd`)

There is no canonical service base URL: one gate fronts several hosts, and which one is
in play is decided by the caller. `safe_rd` therefore takes two inputs beyond the `rd`
itself — the **caller origin** (`scheme://host` of the `/auth/session` request, from
`BB_AUTH_ORIGINAL_URL_HEADER`) and **`BB_AUTH_AUTHORIZED_HOSTS`**, the only authority on
where a redirect may land.

| `rd` | resolves to |
|---|---|
| absent / empty | the caller's root, `https://<caller-host>/` |
| `/preferences` (absolute path) | `https://<caller-host>/preferences` |
| `https://sibling.example.com/x` | itself, if the host matches a pattern |
| anything else, or a rejected host | `BB_AUTH_LOGIN_URL` |

Every candidate — including one resolved against the caller — passes through the same
`rd_url_allowed` gate, so even a spoofed caller origin cannot produce an off-domain
redirect. The gate is https-only and rejects userinfo (`@`), backslashes, `//evil`,
`/\evil` and any control byte (CR/LF ⇒ no response splitting), stripping a `:port`
before matching the host with the same glob a scope's `urls` use. Lookalikes such
as `evilexample.com` and `example.com.evil.com` do not match `*.example.com`, because
the pattern's literal dot must be present — and the apex `example.com` doesn't either,
so list it explicitly.

---

## 9. Dependencies & build

The dependency set is deliberately **pure-Rust / `ring`-based** so the cross-compile
needs only the GNU toolchain — no system OpenSSL or cert store:

| Crate | Use |
|-------|-----|
| `tiny_http` | Blocking, threaded HTTP server. |
| `ureq` (+`tls`/rustls, bundled Mozilla roots) | JWKS fetch; no system cert store. |
| `jsonwebtoken` (`ring`) | RS256 id_token verification. |
| `hmac` / `sha2` | Session cookie signing. |
| `base64` | URL-safe encoding in the cookie. |
| `form_urlencoded` | Parsing the `/auth/session` POST body. |
| `serde` / `serde_json` | Claims + JWKS deserialization. |

**Release profile** (`Cargo.toml`): `opt-level="z"`, LTO, single codegen unit,
`panic="abort"`, stripped — optimized for binary size.

**Cross-compile** (`scripts/build.sh`, run on Linux or WSL): targets
`aarch64-unknown-linux-gnu` by default (edit for another target). The script
copies sources into a fast local filesystem, builds the stripped binary into
`dist/bb-auth`, and prints the max GLIBC symbol required — match that to the
target host's glibc.

---

## 10. Running it

bb-auth is one binary plus two files (env + access file). Its operational contract:

- **Runs as a non-privileged service** — a dedicated system user, no login, no home.
- **Loopback only**, behind a TLS-terminating reverse proxy that performs the
  `auth_request` and the `401 → login-page` redirect.
- **Env file** holds the config and the HMAC secret; keep it readable only by the
  service user (e.g. `0640 root:bb-auth`). The secret should be generated once and
  preserved across redeploys so existing cookies keep verifying.
- **Access file** holds the access list: the applications and their scopes, plus the
  roster of users with their `bbk_` API keys (JSON); editable + `SIGHUP` to apply live.

The layout, separated by role:

```text
<install-dir>/
├── bin/bb-auth          # binary (read-only to the service)
├── bin/bb-auth-adm      # admin CLI      — optional, installed only if staged
├── bin/bb-auth-web      # admin GUI      — optional, installed only if staged
├── etc/bb-auth.env      # config + HMAC key (service-user readable only)
├── etc/bb-auth-web.env  # the GUI's config (no secret) — with the GUI
└── var/lib/access.json   # access list: emails + API keys + URL scopes
<systemd-unit-dir>/bb-auth.service
<systemd-unit-dir>/bb-auth-web.service           # with the GUI
<systemd-unit-dir>/bb-auth-reload.{path,service} # with the GUI
```

Nothing under the tree is ever written by **the gate** (sessions are stateless), so
the whole prefix stays read-only to it and no `StateDirectory` is needed despite the
`var/lib` name. The admin tools write `var/lib/access.json`, and they do it from
outside the gate's namespace: `bb-auth-adm` as root, `bb-auth-web` as its own service
user under its own unit (see below).

The install is a Debian package, `bb-auth`, and its `postinst` is what does all of
this (idempotent, because dpkg runs it again on every install): it creates the system
user/group, and on a **first** install writes `bb-auth.env` from the shipped template
with a freshly generated `BB_AUTH_HMAC_KEY`, plus an empty `access.json` that authorizes
nobody. Neither file is part of the package, which is precisely why a later install
cannot touch either: dpkg does not clobber files it does not ship, so the key survives
and every session cookie with it. It never edits a preserved `bb-auth.env`: instead it
validates it (every required var present, and `BB_AUTH_ACCESS_FILE` pointing at the file
this package creates) alongside the access file itself (`bb-auth --check-access`), and a
failure there exits non-zero **before** the restart, leaving the running process
serving, so a bad config can never become a `Restart=on-failure` boot loop. A first
install ends without starting the gate at all, since its env is still a template.

`scripts/deploy.sh` is the host-side driver around that (`dpkg -i` in one transaction,
an optional staged `access.json`, then `scripts/verify.sh`), and `scripts/deploy.ps1`
builds the packages and drives it over SSH.

### The admin GUI's unit, and who owns the access file

`bb-auth-web` is its own package, installed only when it is asked for, and everything
about it follows from that: the
`bb-auth-web` user, `bb-auth-web.service`, `etc/bb-auth-web.env` (operator-owned and
validated exactly like the gate's — the settings file naming an administrator, `BB_AUTH_ACCESS_FILE`
naming the file this deploy installs), and the ownership migration below. A deploy that
does not carry it does none of this.

It is the one thing here that **writes** the access file, so the file changes hands with
it: `var/lib/` becomes `bb-auth-web:bb-auth 0750` and `access.json`
`bb-auth-web:bb-auth 0640`. The gate reads it through the `bb-auth` group and its unit is
unchanged. Two properties of the library's writer force that shape — it replaces the file
with a temp file renamed into place (so write permission is needed on the *directory*),
and it restores the replaced file's mode and owner before renaming (so an unprivileged
writer must already own the file and be a member of its group, hence
`SupplementaryGroups=bb-auth`). Because the owner is *preserved* rather than reset,
`sudo bb-auth-adm` keeps working unchanged and leaves the file `bb-auth-web:bb-auth` too.

`bb-auth-reload.path` watches `access.json` with `PathChanged=` and runs `systemctl reload
bb-auth` when it is replaced — the `rename(2)` both editors end with is seen as
`IN_MOVED_TO` on the watched directory. It ships with the GUI because the GUI cannot
signal the gate itself; a CLI operator reloading by hand as well merely reloads twice.

### systemd hardening

The unit (`deploy/bb-auth.service`) runs under a dedicated user with aggressive
restrictions:

`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, `ProtectClock/Hostname/KernelTunables/Modules/Logs`,
`ProtectControlGroups`, `RestrictNamespaces/Realtime/SUIDSGID`,
`LockPersonality`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_INET
AF_INET6 AF_UNIX AF_NETLINK` (loopback bind + outbound HTTPS to Cognito +
resolver), `SystemCallFilter=@system-service`, empty `CapabilityBoundingSet`,
`ReadOnlyPaths=<install-dir>` (the whole tree), `UMask=0077`.

`deploy/bb-auth-web.service` mirrors that list, with the two differences its job forces:
`ReadWritePaths=<install-dir>/var/lib` is the single hole in the otherwise read-only tree
(`ProtectSystem=strict` already covers the rest, so it carries no `ReadOnlyPaths=` of its
own), and `SupplementaryGroups=bb-auth` is what lets the write restore the file's group.
`SystemCallFilter=@system-service` is kept as-is deliberately: it contains `@chown` and
`copy_file_range`, which the writer needs — a narrower set would turn every save into an
`EPERM` indistinguishable from a permissions bug.

---

## 11. Security model & notes

- **The id_token is the credential.** A Cognito-signed `id_token` is unforgeable;
  possession of one for an allowlisted, `email_verified` address is proof of
  identity. bb-auth holds no Cognito secret — it only reads public JWKS.
- **The access file is the real access gate.** Cognito self-signup is open by
  design (to enable frictionless registration). Anyone can get an `id_token`, but
  only emails the access file admits get a session cookie, and the check is
  repeated on every `/auth/validate` (see §12) — as is each `bbk_` API key and the
  request-URL scope.
- **Why `email_verified` is mandatory for native users.** Self-signup being open,
  if an unverified native email were accepted, anyone could register
  `boss@company.com` without controlling it and inherit that email's allowlist
  entry. `allow_unverified_social` relaxes this **only** for federated
  logins, where the email is asserted by the upstream IdP rather than self-claimed
  — and is best narrowed (via `social_providers`) to IdPs that actually
  verify the email (Google, Apple). Leaving it off keeps the strict invariant.
- **`rd` is open-redirect-guarded:** it must resolve to an `https://` URL whose host
  matches `BB_AUTH_AUTHORIZED_HOSTS` — an absolute path resolves against the caller's
  host, and no `//` or `/\` counts as a path (browsers normalise the latter to a
  scheme-relative off-host redirect). Any control byte (incl. CR/LF) is also rejected,
  so attacker-supplied bytes can never reach the `Location` header (no response
  splitting). See §8b.
- **Body size** capped at 64 KiB (`MAX_BODY`) — id_tokens are 1–3 KB.
- **Login-CSRF** (an attacker POSTing *their* token to log a victim into the
  attacker's account) is theoretically possible but low-impact for a read gate;
  accepted. Revisit with a state/nonce if the gate ever fronts something
  sensitive.
- **No TLS in-process:** bb-auth speaks plain HTTP on loopback; the reverse proxy
  terminates TLS. It binds `127.0.0.1` only and is not exposed directly.

---

## 12. Access file: applications, scopes, users & keys

Access is described by a single JSON file (`BB_AUTH_ACCESS_FILE`, installed as
`/opt/bb-auth/var/lib/access.json`), loaded at startup and hot-reloaded on `SIGHUP`. It is
the real access gate (`read_access` / `Access`), and it is **application-centric**: a grant
is written once, on the side of the place.

```json
{ "version": 1,
  "applications": [
    { "name": "app1",
      "base": ["https://app.example.com/app1"],
      "login_url": "https://signup.example.com/",
      "scopes": [
        { "name": "healthz", "urls": ["https://app.example.com/app1/healthz"],
          "access": "anonymous" },
        { "name": "admin", "urls": ["https://app.example.com/app1/admin/*"],
          "access": "restricted", "groups": ["@admins"], "credentials": ["login"],
          "excluded": ["c1d2e3f4-5a6b-4c7d-8e9f-0a1b2c3d4e5f"] },
        { "name": "everything", "urls": ["https://app.example.com/app1",
                                         "https://app.example.com/app1/*"],
          "access": "authenticated", "excluded": ["nuisance@example.com"] } ] } ],
  "user_groups": { "admins": ["8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b"] },
  "denied": ["spammer@example.com"],
  "users": [
    { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b",
      "emails": ["you@example.com"],
      "api_keys": [
        { "id": "laptop", "key_hash": "<sha256 hex of the bbk_… bearer>",
          "released": "2026-07-08", "duration": "365d",
          "scopes": ["app1/admin"] } ] } ] }
```

The four sections answer four different questions. `applications` describe **places and who
reaches them**, `user_groups` names a **reusable set of people**, `denied` vetoes **people**,
`users` is the **roster of identities**. A request is authorized when the URL resolves to a
scope and that scope admits the credential, and the identity is not `denied`. All of it is
re-checked on every `/auth/validate`.

At load the file is parsed behind `RwLock<Access>` into the applications (each with its
literal area and its scopes in file order), `denied` in two halves (vetoed uuids and vetoed
identifiers that resolve to nobody), and three indices: `by_identifier` (lowercased email →
uuid, many to one), `by_uuid` (uuid → `UserRecord`), and `by_key_hash` (`sha256(bearer)` hex
→ `ApiKeyRecord`).

What is fatal and what is skipped follows one rule: **an error that changes who reaches what
is fatal; an error whose only effect is to drop one credential warns and skips**. Fatal, so
that a startup exits and a `SIGHUP` keeps the live table: a malformed pattern, an `access`
that is absent or misspelled, a membership field on a scope that is not `restricted`, an
unknown field anywhere in the application/scope tree, a non-literal or overlapping `base`, a
scope pattern outside its own application's base, a malformed uuid, two rows claiming one
uuid or one identifier, a key restriction naming a scope that does not exist, and anything
wrong about a `@group` reference. Warned and skipped:
a bad `key_hash` or `released`/`duration`, an identifier that could not be a header value,
and a dangling reference (a well-formed uuid matching no roster row), which grants nothing
and which both editors lint. `bb-auth --check-access <file>` runs exactly this parser and
exits `0`/`1`, which is how the package's `postinst` refuses to restart the service onto a
file that would not boot, and how `scripts/deploy.sh` refuses to install a staged one.

### Applications, and the URL partition

An application owns a **literal** URL area: `base` is a list of prefixes with no wildcards
in them, and every pattern of every scope must lie inside one of them. **No two applications
may overlap**, anywhere in the file. Together those two rules make applications a partition
of the URL space: at most one application can ever answer for a URL, so their order in the
file carries no meaning at all, and `login_url` has a single unambiguous home.

Both checks go through one function, `base_covers`, which is why "does this application own
that URL?" and "does this scope stay inside its own application?" cannot drift apart. It
compares at a **path boundary**: `https://x.com/app` covers `https://x.com/app` and
`https://x.com/app/deep`, but **not** `https://x.com/application`. That is the same trap as
a `*` written with no `/` before it, and a plain `starts_with` would fall straight into it.

The area being literal is what makes non-overlap a string comparison instead of a
glob-intersection test, and it is what makes the partition hold at all: the useful blanket
patterns (`*://*/*`) would intersect everything. The cost is deliberate and worth stating: an
application on a wildcard host (`https://*.x.com/`) is not expressible.

**A URL no application covers is reachable by nobody**, with any credential. Grants are
written on the side of the place and nowhere else, so this is the only fail-closed reading,
and it is worth an operator hearing out loud: a gated location outside every area is a
`401` for everyone, including the person who wrote the file.
`--check-access` prints each application's area so it can be compared with what nginx
actually gates.

### Scopes, and first match wins

Inside one application, `Access::resolve` hands back the **first** scope whose `urls` cover
the request, in file order, and that scope answers even if it grants nothing. Order is
meaning, which is what `bb-auth-adm scope mv` and the GUI's move buttons exist for.

First-match is what makes a **carve-out** expressible: a narrower, stricter scope listed
before a broad one, as `healthz` and `admin` are above. A union of grants cannot express
that at all, because the broad scope would go on granting. The dangerous half of first-match
(a broad entry silently shadowing a narrow one) is real, but it can only bite between
scopes of the same application: entries an operator sees together, on one screen, in one
form, and which `bb-auth-adm check` lints.

### The three access kinds

`access` is **required and has no default**, because it decides everything and a typo must
never resolve to the most open value:

- **`anonymous`**, no credential at all. To a request that presents none the gate answers `204` and names nobody: no
  identity header, nothing for an application to key on. A request that *did* carry a valid
  credential is still named, which makes the header bimodal on such a scope: it is decoration
  there, never a condition of service. Note that `denied` does **not**
  reach here as an access decision, and the reason is not an oversight: the scope grants with
  no credential, so a vetoed client would simply omit theirs. A veto bypassed by sending
  *less* is not a veto. What the veto does still do is stop the gate **naming** that person
  to the application behind it.
- **`authenticated`** — any identity Cognito vouches for, enrolled or not. An un-enrolled
  user gets a `204` and the app receives their identity, which is how an onboarding page
  enrolls them. Since Cognito self-signup is open, this means *anyone who can register*: the
  right grant for a signup area and the wrong one for everything else. It reaches only the
  two Cognito-backed credentials; an unknown `bbk_` key stays unknown, because Cognito
  vouches for no static key of ours and there would be no identity to hand back.
- **`restricted`** — the uuids in `users` and the groups in `groups`, and nobody else.

`users`, `groups` and `credentials` are legal **only** under `restricted`. Ignoring them
elsewhere would let a scope read as if it restricted access while granting to everyone,
which is the failing-open shape this format refuses everywhere else too. `excluded` is the
one that also belongs to `authenticated` — see below.

### Credential classes (`credentials`)

A `restricted` scope may say which classes of credential exercise it: `login` (a Cognito
id_token bearer, or the session cookie minted from one) and/or `api_key` (a `bbk_` key).
Absent means both, and an empty list is a fatal error rather than a scope reachable by
nothing.

This is a property of the **place**, not of the credential: "this area is reached by a
browser login" and "this area is reached by a machine key" are statements an operator makes
about an application. Expressing them here is what keeps a key from carrying URLs of its
own.

### The scope's own veto (`excluded`)

`denied` shuts an identity out everywhere. `excluded` shuts them out of **one scope**, and
it is checked *before* that scope grants (`decide`, `ScopeRecord::excludes_identifier`). The
placement is the feature: it beats a `@group` the subject is in, so one member can be kept
out of one place without the group being unpicked, and it beats `authenticated`, which lists
nobody and so has nobody to remove.

It takes the same spellings `denied` takes, plus groups: a **uuid**, a **`"@name"`**, or a
bare **email** for an identity the roster has never heard of. An email that resolves is
folded onto its uuid at load, so excluding one address of a user cannot leave another
standing. An entry that is none of the three is a fatal load error, and so is an unknown
`@name`: an exclusion that excludes nobody while reading as if it did fails *open*.

Two orderings are pinned. `denied` is reported **ahead** of it — `Decision::Vetoed` before
`Decision::Excluded` — because a log line must say the identity is out everywhere rather
than only here. And the field is **fatal on `anonymous`**, for exactly the reason the
file-level veto does not reach that kind: the scope grants with no credential at all, so an
excluded client would simply send none.

`user_refs` and `user_group_refs` count an exclusion as a reference, marked `(excluded)`,
and `remove_user` sweeps what they list, so
`remove_user` sweeps it and `remove_user_group` refuses while one still names the group.

### A scope names people, and that is the only place a grant is written

A grant is written on the side of the place, and nowhere else. The rule that protects is
against **duplication**, and it exists so that a user removed from the roster cannot still
walk in through a place. It needs two halves to hold:

- `ScopeRecord::members` are **references to roster rows**. A reference to a row that does
  not exist grants nothing.
- `remove_user` **sweeps** every scope and every group that named the row it removes, and
  hands back the list of what it swept.

Without both, a deleted user who re-registers on Cognito would walk back in through a
dangling reference.

### User groups (`user_groups`)

A group is **abbreviation, never a grant**: `"admins": [...]` authorizes nobody until a
scope names it as `"@admins"`. Expansion happens **once, at load** (`compile_access`), so
`Access`, `decide` and the gate never see a reference; a scope's `members` is a flat set of
uuids by the time anything reads it.

Names are `[A-Za-z0-9_-]+` and match exactly. Fatal, all for the reason a malformed pattern
is: a bad name, a member that is itself a reference (groups are flat by construction, so
there is no recursion or cycle to detect), a member that is not a well-formed uuid, and an
unknown `@name`, whose message names the referrer (`mpa/admin: unknown user group '@nope'`).
Every group is validated even when nothing references it, so a broken one cannot lie in wait
for the edit that first uses it. A member that names no roster row only warns.

### Users, identifiers and uuids

A user is a **uuid** (canonical lowercase 8-4-4-4-12) plus a list of `emails` plus its API
keys, and carries no URL. Every reference in the file is by uuid, and the emails are the
identifiers Cognito can vouch for: `by_identifier` resolves any of them to the same row,
many to one. Changing how someone signs in is therefore one edit to one row, instead of a
sweep over every scope and group that names them; and both editors accept an email wherever
they accept a uuid, so an operator never has to type one.

Two rows may not claim the same uuid, nor the same identifier. Today a duplicate email would
silently last-win through a `HashMap` insert, which means the row an operator is reading may
not be the row in force: it is a fatal load error instead.

### `denied` — the veto

Refused ahead of every grant, on every credential: the id_token and cookie paths, the
API-key path (its owner), and cookie issuance (`handle_session`). Two kinds of entry:

- a **uuid**, which vetoes the user and every identifier they hold. An email that resolves
  to a roster row is folded onto its uuid at load, so denying one address cannot leave
  another standing.
- a bare **email**, which vetoes an identity the file has never heard of. That is not
  decoration: an `authenticated` scope admits identities that are in no table, so for them
  this is the **only** denial that exists.

An entry that is neither is a fatal load error, because a veto that vetoes nobody while
reading as if it did is the one failure this section cannot afford. For an enrolled user the
veto is a *suspension* rather than a deletion: the row, its group memberships and its keys
survive, so re-enabling is one edit.

### Static API keys (`bbk_`)

A programmatic client (e.g. an MCP client that can't run the browser cookie flow)
authenticates with `Authorization: Bearer bbk_<secret>`. Keys are minted out of band
(`bb-auth-adm key add`) and only their **SHA-256 hex fingerprint** (`key_hash`) is stored:
the raw `bbk_…` bearer is shown once and never persisted. `/auth/validate` looks a bearer up
by `sha256(bearer)` in `by_key_hash`; the lookup itself is the verification (forging a
matching preimage of a high-entropy random key is infeasible, so no constant-time compare is
needed).

`decide_api_key` checks three things and stops: the hash resolves, the owner is not denied,
the key has not expired. What the key may then *reach* is `decide`'s, through
`Subject::Key`: the scope that answers decides, exactly as it does for a browser login.

- **`key_hash`** — `sha256_hex("bbk_<secret>")`, 64 lowercase hex chars.
- **`released` / `duration`** — expiry = `released` (`YYYY-MM-DD`) + `duration`, where
  `duration` is `<n>d` (days), `<n>h` (hours), a bare `<n>` (days), or `0` / `never`.
- **`scopes`** — a list of `"application/scope"` names, and a **restriction, never a
  grant**: it can only subtract from what the owner already reaches. Absent means all of
  them. This is what lets a machine credential carry less authority than the human who owns
  it while grants stay written in exactly one place. A name that matches no scope is a fatal
  load error: the restriction would fail closed, but it would fail closed *silently*, and an
  operator who mistyped one would find out only when the machine stopped working for no
  visible reason.

### Per-application login page, and why logout has none

An application's `login_url` overrides `BB_AUTH_LOGIN_URL` for its whole area
(`login_url_for`); it names the login page on `/auth/validate`'s `401`, the fallback for a
rejected `rd`, and the link on `/auth/session`'s error pages. There is no ambiguity to
resolve: areas do not overlap, so at most one application answers, and it answers
whether or not any of its scopes covers the URL. A `401` inside an application is exactly
when its own login page is wanted.

bb-auth never redirects a gated request: it answers `401` and nginx decides. So the login
page reaches nginx as a **response header**, `X-Auth-Login-URL` (`LOGIN_URL_HEADER`), lifted
by `auth_request_set` into a request variable (which is what stops a later `proxy_pass` from
clobbering `$upstream_http_*`):

```nginx
map $bb_login $bb_login_safe {          # http{} level
    ""      https://login.example.com/; # = BB_AUTH_LOGIN_URL
    default $bb_login;
}
location /app1 {
    set $bb_url https://app.example.com$uri;
    auth_request     /internal/auth-gate;
    auth_request_set $bb_login $upstream_http_x_auth_login_url;
    error_page 401 = @bb_signin;
}
location @bb_signin { return 302 $bb_login_safe?rd=$scheme://$host$request_uri; }
```

`auth_request_set` reads the subrequest's response headers even when it answered `401`,
which is what makes this work at all. The `map` is not decoration: an unset `$bb_login` (a
gated location that omits the `auth_request_set`) would make
`return 302 $bb_login?rd=…` emit a *relative* `Location: ?rd=…`, sending the browser back to
the gated path it just failed on. A redirect loop. The default arm degrades to the global
login page instead.

Both the global and the per-application value pass `compile_login_url` at load: printable
ASCII, absolute `https://`, no userinfo `@`, no backslash. That is what lets the gate emit
them into a header, a `Location:` and a page with no per-use check; a CR/LF would otherwise
be a response-splitting gadget, and `h()` panics on a non-ASCII header value. It is **not**
checked against `BB_AUTH_AUTHORIZED_HOSTS`, and cannot be: `read_access` reads no env, which
is precisely what lets `--check-access` validate a file with no config and no network. Moving
that check to startup would turn an operator's typo into a fatal boot under
`Restart=on-failure` that `--check-access` never saw.

There is deliberately **no per-area logout landing page**. The gate can name a login page on
a `401` because the `401` happens *on* a gated URL, so the application resolves. A logout
happens at `/auth/logout`, which is inside no application's area: nothing resolves, and a
`logout_url` field would be unreachable in practice. The party that knows which area you are
leaving is whoever wrote the logout link, so `handle_logout` reads `?rd=` and puts it through
the same `safe_rd` guard as `/auth/session`. With no `rd` the browser lands on the login
page, not on the caller's root, which is what `safe_rd` defaults to and is the wrong end for
a logout.

A link that says nothing is the common case, though, and there the only party left who
knows anything is the browser: `Referer` (`REFERER_HEADER`) is read in the `rd`'s place,
through that same guard. `handle_login` reads it the same way, for the visitor who opened the
sign-in page instead of being bounced there off a `401`. One function is the order for both
(`rd_candidate`, used by `logout_target` and `login_rd`): the `?rd=` was written for this
link and means something specific, the `Referer` was written by the browser about a link that
meant nothing in particular, so the link is read first and a *rejected* candidate does not
promote the other one. Neither endpoint trusts a value for having arrived in a header, which
is what makes it safe that a client can send one itself.

`Referer` is second because nobody configured it. It is absent under
`Referrer-Policy: no-referrer`, absent when a privacy tool or a proxy strips it, absent on a
typed URL or a bookmark, and trimmed to a bare origin cross-origin
(`strict-origin-when-cross-origin` is the browsers' default). On a logout it also names a page
the person may no longer be allowed to see, which costs a `401` and one more hop to the login
page. That is the price of a backup that costs nothing to have, and a `?rd=` on the link is
the way to name a landing place on purpose.

### URL patterns

A scope's `urls` are full `<scheme>://<host>/<path>` patterns; the request URL must match
one of them, and all of them must lie inside the application's `base`. **Access is
enumerated, never assumed**: a scope with no `urls` matches nothing, and blanket coverage is
the explicit pattern `*://*/*`, something an operator has to mean in order to write.

Two wildcards, legal in every component:

- **`*`** — zero or more characters, never `/`, **except** as the pattern's final
  byte, where it matches the remainder of the URL including `/`.
- **`&`** — exactly one character, never `/`.

The match is anchored at both ends (`glob_match`). Since a non-final `*` cannot cross
`/`, and `://` holds two of them, no wildcard leaks between scheme, host and path —
which is why one matcher serves all three without special-casing them. `glob_match` is
a bottom-up DP over `(pattern suffix, input suffix)`, O(n·m); a recursive
star-backtracker would go exponential on a pattern with many `*`.

Patterns are validated and normalised once at load (`compile_pattern`): the authority
is lowercased (the path keeps its case), and an entry is rejected if it lacks `://`,
lacks a path, has an empty scheme or host, carries userinfo (`@`), contains `..`, or
holds a control byte. Ports never appear in a candidate URL (nginx's `$host` omits
them), so a pattern must not contain one.

`/auth/validate` reads the original request URL from the `BB_AUTH_ORIGINAL_URL_HEADER`
header (default `X-Original-URL`), strips query/fragment, lowercases the authority,
and checks it against the resolved scope. nginx must set it on the subrequest:

```nginx
location / {
    # Hardcode the host — it is this server block, and a literal cannot be spoofed
    # by a `Host:` header. $uri (not $request_uri): decoded, normalised, query-free.
    set $bb_url https://app.example.com$uri;
    auth_request /internal/auth-gate;
    …
}
location = /internal/auth-gate {
    internal;
    proxy_set_header X-Original-URL $bb_url;   # NOT $uri — see below
    …
}
```

The two-step is mandatory. Inside the `auth_request` subrequest `$uri` is the
*subrequest's* URI — the literal `/internal/auth-gate` — so writing `$uri` in the
gate would scope every request against that one path. `$request_uri` does survive
into the subrequest, which is why it is tempting, but it is wrong on two counts: it
carries the query string, and it is undecoded, so `/app/%2e%2e/admin` would match a
pattern for `/app/*` while nginx serves `/admin`. `$uri` is decoded and normalised,
i.e. the path nginx will actually route. A subrequest shares its parent's variable
array, so a `set` in the gated location — rewrite phase, which runs before the
access phase that fires `auth_request` — is visible in the gate. Put the `set` in
the *location*, never at `server` level: the subrequest re-runs the server rewrite
phase and would overwrite it with its own `$uri`. A gated location that omits the
`set` sends an empty header, which nginx drops entirely, and bb-auth denies.

Using `$scheme://$host$uri` instead of the literal host is acceptable **only** behind
a `default_server` that rejects unknown Hosts; otherwise a spoofed `Host:` picks which
scope is evaluated.

The header is **required**, not optional: since every credential is scoped, a
subrequest without it fails closed (`401`). A URL containing `..` is likewise rejected
outright. One caveat: nginx leaves `%2f` encoded in `$uri`, so the matcher sees three
literal bytes rather than a segment boundary — which also fails closed.

### Credential precedence at `/auth/validate`

`handle_validate` tries credentials in this order, each additionally URL-scoped:

1. **`Authorization: Bearer bbk_…`** — static API key: looked up by hash, its owner
   checked against `denied`, then checked for expiry (`bearer_apikey`), and only then put
   to the scope that answers, as `Subject::Key`.
2. **`Authorization: Bearer <id_token>`** — a Cognito id_token validated exactly as at
   `/auth/session` (§6), then authorized like a cookie (`authorize_login`).
3. **Session cookie** — verified as in §7, then the same `authorize_login`.
4. **No credential at all** — which an `anonymous` scope grants, and nothing else does.

`decide` is one rule, in this order: resolve the URL to one application and one scope (a
URL outside every application is reachable by nobody); an `anonymous` scope grants
immediately, before the veto, because a scope that grants with no credential cannot be
protected by one; then `denied` vetoes, and after it the answering scope's own `excluded`;
then the scope's kind decides, and for a `restricted` one the credential class, the roster,
membership and the key's own restriction follow in that order.

A failed bearer falls through to the cookie check, so a stray `Authorization` header never
blocks an otherwise-valid cookie, and only then is the anonymous case considered, so a
credential that *does* authorize still names its holder downstream. Any authorized
credential → `204`; otherwise `401`.

### Identity propagation (`identity_attrs`)

Whichever credential wins, it resolves to one roster row, or to one identifier that is in no
row at all (on an `authenticated` scope, which is exactly what an onboarding app needs in
order to enroll them). An API key resolves to its *owning user's* row. `respond_authorized`
names that identity on the `204`, in one header per configured attribute, and the gated
nginx location lifts them into the proxied request:

```nginx
auth_request_set $bb_email $upstream_http_x_auth_email;
proxy_set_header X-Auth-Email $bb_email;   # rename to whatever the app reads
proxy_set_header X-Auth-Uuid  "";          # clear what this location does not set
```

**Which** attributes go out is configuration (`gate.identity_attrs`, default `email`);
the header each one derives is code, through the very function the profile claims use, so
`email` is `X-Auth-Email` and `uuid` is `X-Auth-Uuid` and the two can never disagree. Three
consequences:

- **nginx must clear every *possible* identity header, not the configured ones.**
  `proxy_set_header` overrides only the names it lists, so a name the gate could emit but
  this installation has turned off is a name a client can send. The set of possible names is
  finite and code-defined (`IDENTITY_ATTRS`) precisely so that it *can* be cleared, and
  turning an attribute on later then needs no nginx change at all.
- **Multiple values of one attribute are joined with a space** (a user with two emails).
  That is unambiguous by construction, not by convention: every identifier passed
  `header_safe_email`, which requires printable ASCII, and a space is not printable ASCII. A
  comma would not do, because an email may legally contain one in its local part.
- **An attribute with no value omits its header**, rather than sending it empty, because
  nginx reads an unset variable as no header at all. An identity admitted by an
  `authenticated` scope has no `uuid` to send.

All of which is worth nothing unless the app is unreachable except through nginx.

Emails are validated as printable ASCII (`header_safe_email`) at the **two** places one
can enter, which between them cover all three credentials — a CR/LF in an email would
otherwise be a response-splitting gadget:

- **`read_access`, at load**, for every roster identifier (warn-and-skip: dropping one is
  fail-closed). It is the only guard on the API-key path, whose identity never passes
  through a token claim.
- **`validate_id_token`**, for every identifier lifted out of a Cognito claim. An
  `authenticated` scope emits identities that are in no table, so load time cannot see
  them; and since that is the only way an identifier reaches `make_session`, the cookie
  inherits the property through the HMAC rather than needing its own check.

Together they are what lets `respond_authorized` build the header with no per-request
check; its `debug_assert!` pins both halves.

The app must not decode the credential itself. Two of the three carry no claim — the
cookie is an HMAC blob holding the email and the profile claims below, an API key is an
opaque secret — and a valid `id_token` proves identity, not authorization: self-signup is
open, so authorization lives in the access file and only the gate consults it.

### Profile claims (`profile_claims`)

A `204` can carry OIDC profile claims from the token, so an app has a display name
without inventing one from the email's local part. **Which** claims is configuration;
empty by default. With `gate.profile_claims = ["given_name", "family_name"]`:

```nginx
auth_request_set $bb_given  $upstream_http_x_auth_given_name;
auth_request_set $bb_family $upstream_http_x_auth_family_name;
proxy_set_header X-Auth-Given-Name  $bb_given;
proxy_set_header X-Auth-Family-Name $bb_family;
```

- **The set is config; the header name is code.** An operator names a *claim*, never a
  header: `derive_profile_header` maps `_`/`:` to `-`, title-cases each part and prefixes
  `X-Auth-`, so `given_name` → `X-Auth-Given-Name` and `custom:department` →
  `X-Auth-Custom-Department` (nginx `$upstream_http_x_auth_custom_department`). The two
  can therefore never disagree, and since a claim name is restricted to `[A-Za-z0-9_:-]`
  a derived header is always a valid token — which is why `h()` cannot panic on it.
- **The reserved set is every *possible* identity header**, not the enabled ones: turning
  an attribute on tomorrow must not collide with a claim configured yesterday, because that
  discovery would happen at runtime, on a header an application already trusts.
- **Every config error is fatal at startup** (`compile_profile_claims`): a bad character,
  an empty part around a separator, a claim the gate consumes itself (`email`,
  `email_verified`, `token_use`, `identities` — they never reach `Claims::extra`), or two
  entries deriving one header. A silently skipped entry would be a header the app waits
  for forever.
- **Percent-encoded UTF-8** (RFC 3986, `pct_encode`): every byte outside
  `[A-Za-z0-9-._~]` becomes `%XX`, so `Niccolò` → `Niccol%C3%B2` and a space → `%20`.
  Not the form-urlencoded variant: `+` is a literal plus.
- **The encoder is the safety argument, not a validator.** `pct_encode`'s output is
  printable ASCII for *any* input, control bytes included, so unlike an email a claim
  value needs no `header_safe_email` and no per-request check — which matters because a
  name legitimately contains spaces and accents that `header_safe_email` would reject.
  The second `debug_assert!` in `respond_authorized` is what would catch a later change
  emitting a value raw.
- **Absent ⇒ omitted, never empty**, since nginx cannot represent the difference: an
  empty variable drops the header. That covers a token without the claim, a cookie minted
  before the claim was configured, and every API key — the one credential with no token
  to read a claim from.
- **Emission follows the live config, not the credential** (`profile_headers`). A cookie
  outlives an edit to the list: a claim it still carries but the config no longer names
  emits nothing.
- **Additive and opt-in per location.** A gated location that lifts only `$bb_email` sees
  exactly what it saw before; an app must treat every profile header as optional. But the
  empty-variable rule is also the *clear*: an app that trusts these behind a location
  that does not set them would read whatever the client sent.
- **Self-asserted.** Any Cognito user edits their own profile, verified email or not, so
  these are display hints and must never be an authorization input. Nothing in the access
  file mentions them, and `authorize_login` keeps them out of the decision, which is
  what keeps `bb-auth-adm can` answering the gate's question.
- **Never logged.** The log line already carries the email; a profile value is PII it does
  not need. The startup banner lists the configured claim *names*, which are config.
