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
its schema, its parser, its matcher and its grant model are the one thing the programs
must agree on byte for byte, so they live in a library all of them link. Everything else about
the gate is the gate's, and stays in one file.

| Target | What it is |
|--------|------------|
| `src/lib.rs` (`bb_auth_core`) | **The access file.** Schema (`AccessFile`), parser (`compile_access`), URL matcher (`glob_match` / `UrlScope`), the two-level resolution (`Access::resolve`, `base_covers`), the grant model (`decide`, `decide_api_key`), identity and key minting (`mint_uuid`, `mint_api_key`), and how a file is edited and written (`open_access_file`, `AccessWrite`, the document mutations). Plus the settings file, and **the presentation contract** (`THEME_CSS` from `src/assets/theme.css`, `BASE_CSS` from `src/assets/base.css`, `UiTheme`, `stylesheet_link`, `html_escape`, `compile_asset_url`): the palette two programs paint from **and the components they build out of it**, on the same membership rule as everything else here. A thing (a button, a field, a card, a tag, a message) is defined once for all of them; how a page arranges those things is not. Reads no env, opens no socket, holds no HTTP, prints nothing. |
| `src/bin/bb-auth.rs` (`bb-auth`) | **The gate**, still a single file read top to bottom: HTTP, config, the session cookie, id_token validation, the nginx contract, and the four pages it serves out of `src/assets/` (sign-in, social callback, refusal, error). |
| `src/bin/bb-auth-adm.rs` (`bb-auth-adm`) | **The access-file admin CLI.** CRUD over `applications` / `scopes` / `user_groups` / `denied` / `users` / `api_keys`, key minting and rotation, and `can EMAIL URL` — which calls the library's `decide`, so it answers the question the gate will answer. Every edit and every write is a library call (`AccessWrite`), so it cannot save a file the gate would reject; what is left here is flags, warnings and the wording of a verdict. See §12. |
| `src/bin/bb-auth-web.rs` (`bb-auth-web`) | **The access-file admin GUI**: server-rendered (`maud`; no page needs JavaScript, the one inline handler is the account menu's Preferences shortcut with a `<noscript>` submit behind it) over the library, read *and* write; CRUD through `AccessWrite` alone, `POST`-only mutations behind a same-origin check and a `rev` (sha256-of-file) concurrency check. Both surfaces wear one header (`top_bar`), one row at every width: the deployment's logo, its name, the console's **four** tabs, and a pill (given name, else the first address) that opens the **account menu**, whose rows are the caller's addresses, the System settings page, "Go to your account" on the console only, Preferences nested and closed, and Sign out; at 800px and below the tabs ride in that menu too (§13.28). Loopback behind nginx `auth_request`, identity from the `X-Auth-Email` nginx injects plus its own administrator allowlist (`web.admins` in the settings file, read fresh on every request and editable from its own System settings page). The **self-service page** at `BB_AUTH_WEB_ACCOUNT_PATH` (`/account`) is the one part of it a person who is not an administrator reaches: dispatched *ahead of* `web.admins`, since an administrator there is one more person acting on their own account, with four sections about the caller (reach, groups and profile read-only, the API keys section carrying the caller's own mint, rotate and revoke), the `denied` veto answered ahead of them, the `ui` look on the console's own column (§13.26), and a theme and language selector in the account menu, answered by one `302` setting the console's own cookies. The two prefixes are siblings, and `compile_account_path` refuses at startup a page equal to, inside or containing the console's base, which is what makes an empty `BB_AUTH_WEB_BASE_PATH` a fatal startup. See §13. Links the library, none of the gate. |

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
| `compile_login_url` | Validates `gate.login_url` and every application's `login_url`: printable ASCII, absolute `https://`, no userinfo `@`, no backslash. What makes emitting them in `X-Auth-Login-URL`, a `Location:` and a page safe with no per-use check. |
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
| `GET` | `/auth/validate` | nginx only (`auth_request`) | `204` naming the identity in one header per `identity_attrs` entry (default `X-Auth-Email`) if an accepted credential authorizes the request URL; `401` + `X-Auth-Login-URL: <this area's login page>` when nothing identified the caller; `403`, and no login page, when something did and no scope admits them. A `204` also carries one header per `profile_claims` entry the credential knows (percent-encoded; omitted otherwise), and `X-Auth-Native-Username` when this session came from a native Cognito sign-in: the pool username behind it, which the self-service profile edit acts on (§13.25) and which a federated sign-in, an API key and a cookie minted before the header existed do not send. Accepts (in order) an `Authorization: Bearer bbk_…` static API key, an `Authorization: Bearer <id_token>`, or the session cookie, and then no credential at all, which only an `anonymous` scope grants. A request with no credential names nobody; one that carried a valid credential is still named, so the header is bimodal on such a scope and an application there must treat it as "if you know who this is, say so". A **vetoed** identity is never named. See §12. |
| `GET`, `HEAD` | `/auth/login[?rd=…]` | browser | The sign-in page: runs the Cognito `USER_AUTH` flow in the browser and POSTs the resulting id_token to `/auth/session`. Self-contained (palette, layout, script and both languages in the document; only the operator's optional stylesheet and logo are external). `rd` is validated here with the same `rd_url_allowed` `safe_rd` uses and dropped if it fails; with none, the browser's `Referer` answers in its place, through that same check and absolute-only, since this page resolves nothing against nginx. Social buttons appear only when `gate.oauth_domain`, `gate.social_callback_url` and at least one `gate.social_buttons` entry add up to a social sign-in that could work. The registration step, which is where a `UserNotFoundException` lands, opens with a warning that signing up with a code creates a second, separate account, and repeats those buttons under it, so a person who signs in with a provider has the way back in front of them; on a deployment with no buttons neither is in the document (§13.27). |
| `GET`, `HEAD` | `/auth/denied` | browser (through nginx `error_page 403`) | `403` with the refusal page, in the same palette every other page wears. Says that this account cannot open that page without saying whether the page exists, and links to a sign-out rather than a sign-in. `302` to the operator's own page instead when the area's `denied_url`, or `gate.denied_url`, names one; the area is resolved from `BB_AUTH_ORIGINAL_URL_HEADER` when nginx forwards it here, and without it the global page answers. |
| `GET`, `HEAD` | `/auth/callback` | browser | Finishes a social sign-in: exchanges the OAuth code and the PKCE verifier for tokens, offers a profile form when the IdP sent no names, and delivers the id_token exactly as the sign-in page does. `404` when no social client is configured. |
| `POST` | `/auth/session` | browser | Body `application/x-www-form-urlencoded`: `id_token=…&rd=…`. Fully validates the id_token; on success sets the session cookie and `302`s to `rd` (open-redirect guarded). |
| `GET` | `/auth/logout[?rd=…]` | browser | Sets an expired (Max-Age=0) cookie and `302` → `rd` (same `safe_rd` guard), or, with no `rd`, the browser's `Referer` (same guard), and failing both the login page. Cross-site requests (`Sec-Fetch-Site: cross-site`) are ignored (no cookie clear) to block CSRF-forced logout. Reads nothing about the host it was called on, and the expiring cookie carries the same `Domain` as the minted one, so under a shared `gate.cookie_domain` one mounted location logs the browser out of every vhost: see README "One logout endpoint for every vhost". |
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
   - `exp` validated (60 s leeway), `iss == gate.issuer`,
     `aud` ∈ accepted audiences (`gate.client_id` plus every `gate.social_buttons` audience);
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
  have minted it). Each value is capped at 256 bytes. The gate writes one key of its own into
  that same object, `native_username` (§13.25), and the same self-description is what makes that
  a no-logout change too: a binary that never wrote the key verifies a cookie that carries it,
  and this one names no username for a cookie minted before it existed.
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
  the service host (a `Domain` can be set via `gate.cookie_domain` but is
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
| `BB_AUTH_ACCESS_FILE` | yes | — | Path to the JSON access file (`applications`, `user_groups`, `denied`, and the roster of users with their `bbk_` API keys; see §12). Loaded at startup, hot-reloaded on `SIGHUP`. The name is a contract with the operator-owned env file a deploy never rewrites. |
| `BB_AUTH_ORIGINAL_URL_HEADER` | no | `X-Original-URL` | Request header carrying the original request URL (scheme + host + normalised path). Set by nginx on the `auth_request` subrequest (from a `$bb_url` captured in the gated location — **not** from `$uri`, see §12) **and** on `/auth/session` (there a plain `https://app.example.com$uri` is correct). Drives URL scoping, and on `/auth/session` tells bb-auth which host the login is on. Query/fragment are stripped; missing ⇒ fail closed. |
| `BB_AUTH_LISTEN` | no | `127.0.0.1:4181` | Bind address. Loopback only — nginx fronts it. |
| `BB_AUTH_COOKIE_NAME` | no | `bb_session` | The cookie's **name** only. Its domain and its lifetime are settings (§8a). Renaming it orphans every cookie already issued, which is why it is here and the domain is not. |
| `BB_AUTH_SETTINGS_FILE` | no | `settings.json` beside the access file | Path to the settings file (§8a). Re-read on `SIGHUP` like the access file, fail-soft on both. A missing file is a fatal startup. |
| `BB_AUTH_AUDIT_FILE` | no | `/var/log/bb-auth/audit.jsonl` | The authentication audit (§8b): one JSON object per line, appended by the gate and read back by `bb-auth-web`'s Audit tab. **Empty turns it off**, and the events go to the journal instead. Not a setting for the same reason the access file's path is not: a path is where a process opens a file. |
| `BB_AUTH_WORKERS` | no | `4` | Thread pool size (min 1). |

The admin GUI is a separate service with a separate env file
(`deploy/bb-auth-web.env.example`, installed as `etc/bb-auth-web.env`): `BB_AUTH_ACCESS_FILE`
and `BB_AUTH_SETTINGS_FILE`, the same names for the same files, plus `BB_AUTH_WEB_LISTEN`,
`BB_AUTH_WEB_BASE_PATH`, `BB_AUTH_WEB_DEFAULT_LANG`, `BB_AUTH_WEB_LOGOUT_URL` (unset means
the header carries no Sign out control at all, and on `/account` the same value is worn with
its `rd` parameter dropped, so a person who is not an administrator signs out to the sign-in
page rather than to a `403` on the console: §13.17), `BB_AUTH_WEB_ALLOW_NONLOOPBACK` (a
non-loopback listen address is otherwise a fatal startup, because this service's only
credential is a header nginx sets) and `BB_AUTH_WEB_WORKERS` (request threads, default `8`,
1 to 64, anything else a fatal startup naming the variable: §13.13). It holds no secret at all, and its
administrator allowlist is not an env var: it is `web.admins` in the settings file, read
fresh on every request, because this is the one service that can edit it.

### 8a. The settings file

`compile_settings` (in the library, so all three programs agree on it) turns it into
`Settings`. Three sections: `gate` and `web` are one per service, and `ui` is the one both
HTML services read. Each service ignores what is not its own, and all of it goes
through the same parser, so an edit made by one is one the others would accept.

| Setting | Default | Notes |
|---------|---------|-------|
| `gate.profile_claims` | `[]` → none | OIDC claim names to propagate to the app on a `204`, each in a header derived from its own name (`given_name` → `X-Auth-Given-Name`; see §12). Any unusable entry is refused, never skipped. Changing it logs nobody out: a claim removed stops being emitted at once, one added appears at the holder's next sign-in. |
| `gate.identity_attrs` | `["email"]` | Which identity attributes a `204` names (§12). `email` and `uuid` are the only two that exist. **Empty is refused**: a `204` that names nobody breaks every application behind the gate, in silence. |
| `gate.allow_unverified_social` | `false` | Accepts `email_verified=false` tokens **only** for federated/social logins (those carrying an `identities` claim); native Cognito users stay strict. |
| `gate.social_providers` | `[]` → any | `providerName`s (case-insensitive, e.g. `Google`, `SignInWithApple`) the relaxation above applies to. No effect unless it is on. |
| `gate.client_id` | `""` → no login can complete | The Cognito **app client the email flow uses**: what `/auth/login` runs `USER_AUTH` against, and the first accepted audience. Empty is tolerated, because a package creates this file and cannot know the value, and reported loudly at startup. |
| `gate.login_url` | `""` → the gate's own `/auth/login` | Where a `401` sends people, and where a rejected redirect target lands. Absolute https when set; an application's own `login_url` in the access file overrides it for that area. |
| `gate.denied_url` | `""` → the gate's own `/auth/denied` | Where a `403` lands. Absolute https when set, and `/auth/denied` then answers `302` to it; an application's own `denied_url` in the access file overrides it for that area, which is what makes a refusal page per host. The one URL here that can close nothing: it is read after somebody has already been refused. |
| `gate.landing_url` | `""` → the caller's root | Where a sign-in lands when nothing named a place: `/auth/session` arriving with no `rd` (and no `Referer`). Absolute https when set, **and its host must be one `gate.authorized_hosts` covers**, or the file is refused: `safe_rd` refuses a landing page outside them at every login, so such a value is the loop this setting exists to end, with a setting beside it saying it is fixed. A present `rd` still wins, a rejected one still falls back to the sign-in page, and a logout with nothing said still ends at the sign-in page (§8b). Not a guarded change, for the `gate.denied_url` reason: it is read after the cookie is built. An empty value is **never written**, because `GateSettings` refuses unknown keys and an older binary therefore refuses a file that carries the key: deploy, then set; unset before a rollback (§13.19). |
| `gate.oauth_domain` | `""` → no social sign-in | Cognito's hosted UI, as a bare host with no scheme and no path. The authorize and token URLs are derived from it. |
| `gate.social_callback_url` | `""` → no social sign-in | The `redirect_uri`, which Cognito compares **byte for byte** with the one registered on every app client in `social_buttons`. |
| `gate.social_buttons` | `[]` → none | Which social buttons `/auth/login` offers, in the order given, and **the app client each runs through**: `{ "idp": "Google", "audience": "<app client id>" }`. The app client is per button because Cognito federates per app client. Empty offers none, which is the same page a deployment with no `oauth_domain` serves. The admin GUI renders it as a table, a row per way in (the email row first, then `SOCIAL_IDPS`, then any name already in the file), with the tick the only writable column besides the app clients. Not to be confused with `social_providers` above: that one decides whose unverified email is accepted, this one what a visitor is shown. |
| `gate.session_ttl_secs` | `2592000` (30 d) | Applies to cookies minted from then on and to none already in a browser, so changing it logs nobody out. Below 60s is refused (a login loop); above 400 days is warned about (the cap browsers apply to `Max-Age`). |
| `audit.client_ip_header` | `""` → no address recorded | The request header the audit reads the client's address from (`X-Real-IP` in the README's recipe). Name it only once nginx **overwrites** it on every location that reaches the gate; a header nginx does not overwrite is the client's own. The last entry of a list is taken, which makes `X-Forwarded-For` usable. A credential header is refused (§8b). |
| `audit.request_id_header` | `""` → no request id recorded | The request header carrying nginx's `$request_id` (`X-Request-ID` in the recipe), which finds an audit row's line in nginx's access log. Same rule, same refusal. |
| `audit.rotation` | `"4 MiB"` | When the live audit file moves onto `.1`, replacing it: a size (`MiB`, `GiB`) or an age of its oldest event (`weeks`, `months`, `years`). §8b. |
| `audit.retention` | `""` → none | The most the audit keeps across both files: an age (no older event stays) or a size (the pair never exceeds it). At least one of rotation and retention must be a size, or the file is refused. §8b. |
| `web.admins` | `[]` | Who may use `bb-auth-web`, matched against the `X-Auth-Email` nginx injects **address by address**: that header carries every email of the caller's roster row joined by a single space, so listing any one of them is enough. **Never empty**: the binary refuses to serve without one and both editors refuse to write an empty list. The gate ignores this section. |
| `ui.stylesheet_url` | `""` → none | A stylesheet loaded **after** each program's built-in one, so it wins by source order. Absolute `https://`, or a path starting with `/` on this host. Read by both services, which is what makes one file restyle the gate's pages and the whole GUI together. Expected to redefine the custom properties in `THEME_CSS` and nothing else. |
| `ui.logo_url` | `""` → none | Shown on the sign-in page above the name. Same two shapes. |
| `ui.brand_name` | `""` | What the sign-in page calls this deployment; empty falls back to each page's own name. |
| `ui.theme` | `"system"` | `system`, `light` or `dark`: which palette a page starts in. For the gate's pages it is the whole answer (they keep no per-visitor state); in `bb-auth-web` it is the default an administrator's own Settings menu overrides. |

The `ui` four pass the "cannot lock anybody out" test for one structural reason: **both
binaries already carry a complete stylesheet**, so an override is an addition to a working
page and never the page itself. The worst a wrong value there achieves is a page in the
wrong colours, and a stylesheet host that is down costs nothing but its palette.

What is **not** in it is a short list, and after version 3 it is nearly the whole env file:
the listener and the worker count need a rebind; the HMAC key is the secret; the cookie's
**name** orphans every cookie already issued; `BB_AUTH_ACCESS_FILE` is the file this one is
found beside and cannot live inside it; and `BB_AUTH_ORIGINAL_URL_HEADER` *is* the lockout
when it is wrong.

Everything Cognito moved INTO the file, in two steps: the app clients and the sign-in wiring
in version 2, the **pool** (`gate.issuer`) in version 3, along with the cookie's domain and
the hosts a post-login redirect may land on. The argument version 2 rested on — the pool is in
the environment, so the file can only choose among the app clients of an issuer that is
already trusted — is retired by version 3 rather than quietly untrue, and what replaces it is
that this file is trusted as much as the gate: whoever can write it can already write the
access file beside it and the admin list inside it.

Three of the twenty-four do not pass the three-part rule cleanly, which is stated rather than
glossed. `gate.issuer` is not read per request but once, to fetch a JWKS, so a reload
re-fetches and swaps keys and settings **together or neither**. `gate.cookie_domain` cannot
log anybody out but does something worse: every cookie already issued keeps the old `Domain`,
so it stays valid and `/auth/logout` can no longer clear it. And `gate.authorized_hosts` used
to be the boundary that kept `gate.login_url` from being a redirect gadget. What the move buys
is the check that was not expressible while those two lived in different files: **a host the
cookie cannot reach is refused**, because it is a login that lands, sends no cookie, gets a
`401` and bounces back to the sign-in page for ever.

Five of them can stop people getting in (`issuer`, `client_id`, `login_url`, `cookie_domain`,
and *removing* an `authorized_hosts` entry), so both editors ask before writing one and
neither refuses: no cookie is invalidated, so whoever made the edit still holds a session and
can undo it. `guarded_changes` is the single list, in the library, so the two editors cannot
disagree about which fields those are.

Edited with `bb-auth-adm settings …` or from `bb-auth-web`'s Settings tab, through the same
validate-before-write the access file gets (`SettingsWrite`). Checked by hand with
`bb-auth --check-settings <file>`; `scripts/verify.sh` and the gate's `postinst` both run it.
Unknown keys **inside a section** are a hard error, for the reason a misspelled scope field
is one; unknown keys at the top level are preserved, which is where `_comment` lives.

### 8b. Where the post-login redirect may land (`safe_rd`)

There is no canonical service base URL: one gate fronts several hosts, and which one is
in play is decided by the caller. `safe_rd` therefore takes three inputs beyond the `rd`
itself — the **caller origin** (`scheme://host` of the `/auth/session` request, from
`BB_AUTH_ORIGINAL_URL_HEADER`) and **`gate.authorized_hosts`**, the only authority on
where a redirect may land, plus **`gate.landing_url`**, the answer when there is no `rd`
at all.

| `rd` | resolves to |
|---|---|
| absent / empty | `gate.landing_url` when set, else the caller's root, `https://<caller-host>/` |
| `/preferences` (absolute path) | `https://<caller-host>/preferences` |
| `https://sibling.example.com/x` | itself, if the host matches a pattern |
| anything else, or a rejected host | `gate.login_url`, else the gate's own `/auth/login` |

Every candidate — including one resolved against the caller — passes through the same
`rd_url_allowed` gate, so even a spoofed caller origin cannot produce an off-domain
redirect. The gate is https-only and rejects userinfo (`@`), backslashes, `//evil`,
`/\evil` and any control byte (CR/LF ⇒ no response splitting), stripping a `:port`
before matching the host with the same glob a scope's `urls` use. Lookalikes such
as `evilexample.com` and `example.com.evil.com` do not match `*.example.com`, because
the pattern's literal dot must be present — and the apex `example.com` doesn't either,
so list it explicitly.

### 8b. The audit file

The third file more than one program reads, and the only one written by the gate:
`BB_AUTH_AUDIT_FILE`, one JSON object per line, appended under a mutex and rotated onto `.1`
under `audit.rotation` (4 MiB by default). `AuditEvent`, `AuditWriter` and `read_audit` are in the library for the same reason
the access file's parser is: the gate writes those lines and `bb-auth-web` reads them, so a
second answer to what one line means would be a reader showing something the writer never
said. The unit provides the directory (`LogsDirectory=bb-auth`, `bb-auth:bb-auth 0750`), which
is why this is the one thing the gate writes and its own `/opt/bb-auth` prefix stays
`ReadOnlyPaths`.

Five kinds, and they are all about **authentication** rather than traffic: `login_granted`
(with the credential that proved it, which is the only moment the gate knows whether a
federation was involved), `login_refused`, `login_ended`, `access_refused`, and the
`access_granted` that matters, which is an identity in no roster row being let in by an
`authenticated` scope. Not the ordinary allowed request, which is nginx's access log and
would be one row per asset here; not a refusal that carried no credential, which is every
signed-out browser on its way to the login page. The two kinds that fire per request are
deduplicated over five minutes by `first_audited`, on a table of its own so that the journal's
verbosity cannot change what the audit holds, keyed by who, where, why and from which address.

Each row can say where its request came from, in four optional fields that differ in how far
they are to be believed (`AuditClient`, stamped by the gate's `RequestAudit` so no call site
can forget it). `ip` and `rid` are read from the headers `audit.client_ip_header` and
`audit.request_id_header` name, and only when they name one, because the gate never sees a
client itself and a header nginx does not overwrite is the client's word; the address is
parsed (and taken from the last entry of a list), the id is held to letters, digits and `-`,
a charset every credential of ours fails. `ua` is the client's `User-Agent`, cut at 256 bytes
and recorded as the client's word. `sub` is the Cognito account of a token validated on that
request; a session cookie carries none. The schema stays `v: 1`, because it is additive: an
older reader ignores the four fields and a newer one reads an older line with none of them.

**Rotation and retention** (`AuditPolicy`, compiled from `audit.rotation` and
`audit.retention`). There are only ever two files, the live one and `.1`, and a rotation
replaces the old `.1`. `AuditWriter::record` rotates on **size**, before the append that would
cross it, so the live file never holds more than the policy allows; the size is the rotation's
own or half a retention in space, whichever is smaller, which is how a retention in space holds
without ever rewriting a file. `AuditWriter::maintain` does the rest: a rotation on **age**, a
`.1` written under a looser policy cut down to its newest lines, and a retention in **time**
dropping every expired event from both files (a temp file and a rename, streamed, so a reader
that opened the file keeps its bytes). The gate runs it at startup, on every reload and hourly
from a thread of its own, which is what makes a retention in time hold on a deployment that
writes nothing for a month. At least one of the two settings is a size (`AuditPolicy::new`),
so `AuditPolicy::max_bytes` is always the ceiling a flood can reach. `read_audit` walks both
files backwards in blocks (`RevLines`), so a gibibyte of history costs the Audit tab a block
of memory, and the tab applies a retention in time as a floor on every period it offers.

`bb-auth-web` shows the times in UTC, in the host's zone (`/etc/localtime`) or in one the
reader names (an IANA name read from `/usr/share/zoneinfo`, or a fixed offset), through
`tz-rs`, which reads the host's database and bundles none. The choice is a per-browser cookie,
like the language and the theme; `Local` is the host's zone rather than the browser's,
because no request header carries a browser's zone and no page there may need a script.

The `reason` is a **code** and never a sentence — `decision_reason` is the only place one is
spelled, and it is the `Decision` variant's own name — so the wording belongs to whoever
reads: the GUI renders a refusal in the reader's language, reusing the very phrases its access
check already uses for the same verdict.

The gate's journal and this file are exclusive: with an audit configured the request-path
lines go here *instead*, and `Audit::on` reports false the moment a write fails, so a broken
audit hands its events straight back to the journal.

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
| `tz-rs` (`alloc` only) | `bb-auth-web` only: reading the audit's times in a zone, from the host's own `/usr/share/zoneinfo`. No dependencies, no `unsafe`, no bundled database. |

**Release profile** (`Cargo.toml`): `opt-level=3`, LTO, single codegen unit,
`panic="abort"`, stripped: optimized for speed (`opt-level=3`, the user's choice on 2026-11-23).

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
  matches `gate.authorized_hosts` — an absolute path resolves against the caller's
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
so `remove_user_group` refuses while one still names the group. `remove_user` does **not**
sweep a uuid exclusion: it rewrites it to the row's primary email, as it already does for
`denied`, because dropping a veto lifts it and the same person re-registering on Cognito
under that email walks back into the scope they were just shut out of. A row with no email
has no stranger spelling to leave behind, so its entry goes, and a `@group` entry stays a
group reference.

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

An application's `login_url` overrides `gate.login_url` for its whole area
(`login_url_for`); it names the login page on `/auth/validate`'s `401`, the fallback for a
rejected `rd`, and the link on `/auth/session`'s error pages. Its `denied_url` is the same
field one page along (`denied_url_for`): where a `403` in that area lands. Since an area is an
absolute prefix it names a host, so those two are also how one gate fronting several hosts
gives each host its own pages. There is no ambiguity to
resolve: areas do not overlap, so at most one application answers, and it answers
whether or not any of its scopes covers the URL. A `401` inside an application is exactly
when its own login page is wanted.

bb-auth never redirects a gated request: it answers `401` and nginx decides. So the login
page reaches nginx as a **response header**, `X-Auth-Login-URL` (`LOGIN_URL_HEADER`), lifted
by `auth_request_set` into a request variable (which is what stops a later `proxy_pass` from
clobbering `$upstream_http_*`):

```nginx
map $bb_login $bb_login_safe {          # http{} level
    ""      https://login.example.com/; # = gate.login_url
    default $bb_login;
}
location /app1 {
    set $bb_url https://app.example.com$uri;
    auth_request     /internal/auth-gate;
    auth_request_set $bb_login $upstream_http_x_auth_login_url;
    error_page 401 = @bb_signin;
    error_page 403 = @bb_denied;
}
location @bb_signin { return 302 $bb_login_safe?rd=$scheme://$host$request_uri; }
location @bb_denied {
    proxy_set_header X-Original-URL $bb_url;
    rewrite ^ /auth/denied break;    # a named location takes no URI on proxy_pass
    proxy_pass http://127.0.0.1:4181;
}
```

The `403` arm is the other half of the same rule, and it needs no header of the gate's: the
page is a fixed path on the gate, the choice of *which* page lives in the two files
(`denied_url_for`), and `X-Original-URL` is only what lets the area's own page be found. `=`
is what keeps the status honest, since `/auth/denied` answers `403` itself.

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
checked against `gate.authorized_hosts`, and cannot be: `read_access` reads no env, which
is precisely what lets `--check-access` validate a file with no config and no network. Moving
that check to startup would turn an operator's typo into a fatal boot under
`Restart=on-failure` that `--check-access` never saw.

There is deliberately **no per-area logout landing page**. The gate can name a login page on
a `401` because the `401` happens *on* a gated URL, so the application resolves. A logout
happens at `/auth/logout`, which is inside no application's area: nothing resolves, and a
`logout_url` field would be unreachable in practice. The party that knows which area you are
leaving is whoever wrote the logout link, so `handle_logout` reads `?rd=` and puts it through
the same `safe_rd` guard as `/auth/session`. With no `rd` the browser lands on the login
page, not on `safe_rd`'s no-`rd` default (the landing page, or the caller's root when none is
set), which is the wrong end for a logout.

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
credential → `204`.

The refusal is two statuses, and which one it is turns on whether the gate **identified** the
caller rather than on whether it authorized them: a `bbk_` key that resolved to a live row, an
id_token that validated, or a session cookie whose signature held all mean the client is who
they say they are, and a refusal after that is `403`. Everything else is `401` + the login
page. The reason is nginx's answer to each: a `401` becomes a redirect to the login page, and
a browser that already holds a valid cookie signs straight back in, returns to the URL that
refused it and is refused again, for ever, with no error anywhere. Signing in cannot fix a
`403`, so nginx answers that one with a page (`error_page 403 = @bb_denied` → `/auth/denied`)
and no redirect at all.

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
proxy_set_header X-Auth-Native-Username "";  # the gate's own name, cleared the same way
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
- **The gate's own `X-Auth-Native-Username` follows the same rule, and is not an
  `identity_attrs` entry.** It names the Cognito username of the session, for a native sign-in
  only, and the self-service profile edit acts on it (§13.25). The `/account/` location forwards
  it; every other gated location clears it, the console included, because a name a program
  trusts has to be one only the gate wrote.
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
  discovery would happen at runtime, on a header an application already trusts. It reserves the
  gate's own `X-Auth-Native-Username` for the same reason in the other direction: every spelling
  of `native_username` derives it, and a self-asserted claim arriving on the header the profile
  edit acts on would be a pool name an attacker typed.
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

---

## 13. Self-service, as a section of `bb-auth-web` (`/account/`)

**Status: redesigned on 2026-11-23 (afternoon) at the user's decision, replacing the separate
binary the morning's design described, and moved to its own prefix `/account/` that evening;
13.12 records both reversals.** What is
built is the page plan steps 2b-1, 2b-2 and 2b-3 produced, still as its own target,
`src/bin/bb-auth-me.rs` (26 tests): the identity half (both files read fresh on every request,
`X-Auth-Email` split into the list of addresses the gate sends, the `denied` veto ahead of
everything), four read-only sections (reach as application and scope names from
`Access::scopes_reached`, groups, keys without hash or bearer, profile claims percent-decoded),
and the look (the `ui` section, a centred card, a script-free theme and language selector
writing the same `theme` and `lang` cookies `bb-auth-web` writes). That target was never
packaged, so no host carries it, and it is now **to be folded into `bb-auth-web`** (13.10) and
deleted. Nothing of the keys' writes, the profile edit or the deletion exists yet. As each step
lands, its mechanism moves to rustdoc and its rules to `AGENTS.md`, and this section shrinks to
the component view.

What was read to write it: `AGENTS.md` (the invariants, `bb-auth-web`'s trust model), `PLAN.md`,
this document's previous §13, `src/bin/bb-auth-web.rs` (the crate-root trust model, `handle`
and its check order, `route`, `csrf_ok`, `edited_file`, `mutate` and `WRITE_LOCK`,
`negotiate_lang`, `negotiate_theme`, `respond_preference_redirect`, `admin_csp`),
`src/bin/bb-auth-me.rs` (`handle`, `Look`, `Prefs`, `respond_preference_redirect`, the test
module), `src/lib.rs` (`page_csp`, `Access::scopes_reached`), `deploy/bb-auth-web.service`,
`deploy/bb-auth-web.env.example`, `deploy/debian/bb-auth-web/postinst` and
`deploy/debian/bb-auth/postinst` (how `bb-auth.env` and the HMAC key are created), and the
README's nginx recipe. The forged-header finding of 13.3 was run by the coordinator on a local
instance and reported; it was not re-run for this section.

### 13.1 What it is, and what it reaches

A set of routes inside `bb-auth-web`, under `/account/` (13.2), that lets one person act on **their
own** account and on nobody else's. Same process, same unit, same uid, same writer:

| The `/account/` routes can | They cannot |
|---|---|
| Read the access file and the settings file | Write the settings file: no self-service handler calls `SettingsWrite` |
| Write the access file through `AccessWrite` only, and only the caller's own row: add, rotate and remove that row's `bbk_` keys, and remove the row with the sweep `remove_user` does | Touch another row, `denied`, `user_groups` other than through the deletion sweep, or any application or scope |
| Call Cognito's public user-pool API with an access token the person has just obtained by answering an email code (13.7) | Hold any Cognito or AWS credential between requests; call any `Admin*` operation |
| Write one journal line per mutation | Write the audit file (13.6) |
| Be reached by any identity nginx vouches for (13.5) | Read `web.admins`, or let it confer anything: an administrator here is one more person |

**The honest limit, now sharper than in the separate-binary design: the process that serves a
stranger's request is the process that may write both files.** "Only the caller's own row" and
"never the settings file" are properties of the code (the route classification of 13.2 and the
handlers behind it), not of the kernel or of a uid. That was already true of the access file
under the morning's design; what the merge adds is that the settings file and every admin
handler are now one routing bug away from a stranger, which is why 13.2 makes the
classification a closed list with a test over every route.

### 13.2 Where it lives: one listener, two prefixes, two nginx locations

**Decision (the user, 2026-11-23 evening): the admin pages stay under `BB_AUTH_WEB_BASE_PATH`
(`/admin` on rpi-01 and in the example env), and the self-service page lives under its own
prefix, `BB_AUTH_WEB_ACCOUNT_PATH`, default `/account`.** One binary, one listener
(`127.0.0.1:8091`), one proxy secret checked first on both prefixes.

**Why an env var and not the settings file.** Against the three-part rule it fails part 1 in
the way that matters: the value is read per request, but it is one half of a contract whose
other half is an nginx `location`, which changes only with an nginx reload, so making it hot
buys nothing and lets a GUI save move the page away from the location that serves it. No
second program has an opinion about it, and it must be checked against the admin base at
startup, which is only a single check if both come from the same place. So it sits beside
`BB_AUTH_WEB_BASE_PATH`, in `bb-auth-web.env`.

**Validation, at startup, fatal on failure and naming the variable:** the value goes through
`normalize_base_path` (printable ASCII, no `?` or `#`, one leading `/`, trailing `/` stripped);
the result must not be empty (an empty prefix would be the whole host and swallow the admin
pages); and it must not overlap the admin base at a path boundary in either direction, by the
rule `base_covers` applies to areas (equal, `/admin/account` under `/admin`, or `/admin` under
`/account`, are all refused; `/accounts` beside `/account` is not an overlap). An **empty admin
base covers every path**, so it is refused too: the GUI mounted at the root cannot coexist with
a self-service prefix. That is a cost for anybody running the GUI at the root (the README's
default); the packaged env example and rpi-01 both set `/admin`, so no known deployment pays it.

**URL shapes.** The page is `GET /account/`. `/account` with no slash is answered by nginx with
a `301` to `/account/` from an exact `location = /account` (the `return` runs in the rewrite
phase, before the gate, and discloses nothing); nginx's own implicit `301` for a prefix location
ending in `/` exists ([location](https://nginx.org/en/docs/http/ngx_http_core_module.html#location))
but whether it precedes `auth_request` is **not verified**, so the recipe does not rely on it. If
`/account` reaches the binary anyway, it is the page, as `/admin` is the dashboard. The
selector is `GET /account/?theme=…&lang=…` (either or both), answered by one `302` to
`/account/` setting each named cookie (`Path=/`, so a choice carries to the admin pages and
back). Nothing else exists under the prefix today: any other path under it is a `404`, the same
for everybody; the key, profile and deletion routes of 13.6 to 13.9 will be added under it.

Inside the binary the check order of `handle` becomes:

| # | Check | On failure | Applies to |
|---|---|---|---|
| 1 | The proxy secret (13.3) | `403`, built-in look, nothing else read | every request |
| 2 | `X-Auth-Email` present | `401`, as today | every request |
| 3 | The settings file compiles | `500`, as today | every request |
| 4 | **Is the path `<account>` or under `<account>/`?** A prefix test at a path boundary, before `route` | | |
| 4a | yes: the self-service handler, which reads no `web.admins` and runs the table of 13.5 | as 13.5 | the account prefix only |
| 4b | no: `web.admins` empty is `500`, not naming the caller is `403`, then `route`, whose miss is the `404` | as today | everything else |

Step 4 runs **before** the admin check, so an unknown path outside the account prefix (under
the admin base or outside both) still answers a non-administrator with the `403` and never with
a `404` that says which paths exist. The self-service routes are a closed enum of their own,
and the test of 13.11 walks every admin `Route` variant as a non-administrator and requires the
`403`. A `POST` under the prefix will go through the same `csrf_ok`, the same `rev` over the
access file's bytes (`edited_file`) and the same `WRITE_LOCK` as every GUI save.

**nginx: a second location, a copy of the admin one.** `location /account/` carries everything
the README's `location /admin/` carries (the `set $bb_url` with the hardcoded host and `$uri`,
`auth_request`, `X-Auth-Email` lifted and set, the other `IDENTITY_ATTRS` headers cleared,
`Host $host`, `include /opt/bb-auth/etc/bb-auth-web.nginx;`, `error_page 401 = @bb_signin`,
`error_page 403 = @bb_denied`, `proxy_pass http://127.0.0.1:8091;` with no URI part), plus one
difference: it **forwards** each configured profile header (`auth_request_set` from
`$upstream_http_x_auth_<claim>`, then `proxy_set_header`), because the page shows them, where
the admin location keeps clearing them. Beside it, `location = /account { return 301 /account/; }`.
The secret include has to be in both locations, since a location that sets any header of its
own inherits none (13.3).

**The access file.** Applications partition by literal base, so the account prefix is covered
in whichever application already owns that host's area:

- **One application whose base is the host** (rpi-01: `auth`, base `https://auth.badbat75.com`):
  an `authenticated` scope with `https://<host>/account` and `https://<host>/account/*`,
  listed **before** the restricted catch-all, the carve-out first match exists for. A second
  application with base `https://<host>/account` would overlap the host's base and is refused.
- **One application per prefix** (bases `https://<host>/admin` and `https://<host>/account`): the
  account application holds that one `authenticated` scope and its order means nothing. This is
  the README's recipe, because it cannot be broken by reordering scopes.

The bare `/account` pattern costs nothing and keeps a deployment that gates `/account` instead
of redirecting it from refusing a non-administrator there through the restricted catch-all.

Rejected:

- **`<base>/me/` inside the admin base** (this section's previous decision): reversed by the
  user on 2026-11-23 (evening), because administrators' URLs must not move and `/admin/me/` is
  a bad URL to hand somebody who is not an administrator.
- **A separate binary**, the morning's design: reversed by the user (13.12).

### 13.3 The proxy secret

**The finding (reported by the coordinator, run on a local instance):** `bb-auth-web` believes
`X-Auth-Email` from any local process that reaches its loopback port. A request with a forged
header and no cookie got the admin dashboard, `200`. The trust model on its crate root says the
service is "unreachable except through nginx"; on a host with other users or other services,
loopback is reachable by all of them.

**Decision: nginx sends a secret header on every request it proxies to `bb-auth-web`, and
`bb-auth-web` refuses any request without it, as check 1 of 13.2.**

**On every request, not only on mutations (the architect's recommendation; the user said "add
or remove", so this needs the user's yes).** A forged `GET` with the mutation-only version
would still read: every roster row with its emails and uuid, every group, every application and
scope with its URL patterns, the settings (the administrator list, the issuer, the app client,
the cookie domain), and the Audit tab, which holds the address, user agent and account of every
sign-in and refusal on the estate; and under `/account/`, any named person's reach, groups and key
ids. That is a personal-data read open to every local user. Requiring the secret everywhere
costs nothing more: nginx sets it on the one location anyway, and one check before everything
is simpler than a check inside the `POST` branch.

| | |
|---|---|
| Header | `X-BB-Web-Secret`. Not under `X-Auth-`, because that prefix is where the gate derives claim headers (`derive_profile_header`), and a claim named `web_secret` must not be able to collide with it |
| Binary | `BB_AUTH_WEB_PROXY_SECRET`, required: absent, or shorter than 32 characters, or outside `[A-Za-z0-9_-]`, is a fatal startup naming the variable and not the value. Compared by hashing both sides and folding the XOR of the 32 digest bytes (`proxy_secret_matches`), so every byte is read and the comparison's timing reveals nothing usable, and no dependency is added (`sha2` is in the tree) |
| Refusal | `403`, the built-in look, a page saying the request did not come through the proxy. It is the same page for absent and wrong, echoes no header, and is answered before the identity or the settings are read |
| Where it lives (binary) | `/opt/bb-auth/etc/bb-auth-web.env`, which the postinst already creates `root:bb-auth-web 0640` |
| Where it lives (nginx) | `/opt/bb-auth/etc/bb-auth-web.nginx`, `root:root 0600`, one line: `proxy_set_header X-BB-Web-Secret <value>;`, the value unquoted, which is what the `[A-Za-z0-9_-]` charset buys. Written beside the target under `umask 077` (so the temp is never world-readable), then `chown root:root`, `chmod 0600` and renamed onto it, so a reload never reads a half line. `root`-only is enough because the nginx **master** process reads the configuration ("The main purpose of the master process is to read and evaluate configuration", [nginx beginner's guide](https://nginx.org/en/docs/beginners_guide.html)); that it runs as root is the Debian default and is **assumed** here, and step (b)'s `nginx -t` on rpi-01 shows it |
| nginx placement | `include /opt/bb-auth/etc/bb-auth-web.nginx;` **inside the `bb-auth-web` location only.** At `server` level it would reach every upstream of that server, and it would be silently lost anyway in any location that sets a header of its own: "These directives are inherited from the previous configuration level if and only if there are no `proxy_set_header` directives defined on the current level" ([proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)). `proxy_set_header` overwrites whatever the client sent under that name, which is what makes a client unable to supply it |
| Generation | `bb-auth-web`'s postinst, on every configure: if the env file has no `BB_AUTH_WEB_PROXY_SECRET`, append one (`head -c 33 /dev/urandom \| base64 -w0 \| tr '+/' '-_' \| tr -d '='`, 44 characters, measured on this host); then (re)write the nginx file from the env file's value. The env file is the one source; the nginx file is derived from it on every configure, so the two cannot drift across an upgrade |
| Rotation | Edit the value in the env file, reinstall the same package (the postinst rewrites the nginx file and restarts the service), `systemctl reload nginx`. The seconds between the restart and the nginx reload answer `403` |
| Never logged | Not in the startup banner (it prints "proxy secret: set"), not on any page, not in the journal, not in a `--check-*` output. The README tells the operator never to name it in a `log_format` |

What it holds against: every local process that cannot read either file, which is every user
but root and `bb-auth-web`, the gate's own `bb-auth` user included (it is not in group
`bb-auth-web`), and an SSRF in any service running as one of them. What it does not hold
against: root, or code already running as `bb-auth-web`. It does not make a non-loopback bind
safe either: off the host it would cross the network in the clear, so the loopback rule and
`BB_AUTH_WEB_ALLOW_NONLOOPBACK` stay as they are.

The cost: the env file stops being strictly "created once, never edited". The exception is
narrow (a line is appended only when the variable is absent, and an existing value is never
rewritten), and the alternative was a postinst that fails every upgrade until somebody adds a
line by hand. A deployment whose nginx forgets the `include` answers `403` on every page, which
fails closed and says why.

Rejected:

- **A Unix socket with a group only nginx is in.** The stronger answer, and the user deferred it
  ("loopback TCP for now"): `tiny_http` would have to listen on it and nginx's user would join a
  group, which is more change than a header.
- **Mutations only.** The read exposure above.
- **mTLS between nginx and the GUI.** A CA, two keys and rustls server code, for what a shared
  secret on loopback already gives.

### 13.4 The HMAC key out of `bb-auth-web`'s reach

Today `bb-auth.env`, which holds `BB_AUTH_HMAC_KEY`, is `root:bb-auth 0640`, and `bb-auth-web`
is in group `bb-auth` (it has to be, to restore the access file's group). So the GUI can read
the key that signs every session cookie, and with it mint a cookie for anybody. Self-service
makes that the process strangers talk to.

**Decision: `InaccessiblePaths=/opt/bb-auth/etc` in `bb-auth-web.service`**, the directory and
not the file. It is safe because the binary reads nothing under `etc/` at run time: its own env
file is read by the service manager, not by the process, and before the sandbox exists. Read in
the source: "The files are read from the file system of the service manager, before any file
system changes like bind mounts take place" (`EnvironmentFile=`,
[systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html),
and the same sentence in the systemd 259 manual on the development host). Not yet seen on a real
host: step (a)'s check is that run.

The directory and not the file, for two reasons. A per-file mount does not survive a rename onto
that file from outside the namespace (it is lazily detached, Linux 3.18, commit 8ed936b5671b), so
an operator's `sed -i` on `bb-auth.env` would quietly hand the key back until the next restart.
And the directory also hides the GUI's own env file and nginx snippet, which hold the proxy
secret: the process already has the value in its environment and has no reason to be able to
read it a second time. Group `bb-auth` keeps doing what it is there for (the access file, the
settings file, and the audit under `/var/log/bb-auth`).

Cost: one line, and a unit that will not start if `/opt/bb-auth/etc` is missing, which on a
host where the GUI's own env file lives there cannot happen.

### 13.5 Who reaches `/account/`

nginx gates it with its own `location /account/` (13.2), a copy of the admin one: `auth_request`,
`set $bb_url`, the lifted `X-Auth-Email`, the cleared `IDENTITY_ATTRS` headers and the proxy
secret. The one difference is that it forwards the configured **profile** headers, because the
page shows them. On rpi-01 the access file already has an `authenticated` scope over
`/account/*` (`auth/self-service`, for the static deletion page this replaces), so the
`/auth/session` consequence below is already in force there.

**The access file covers it with an `authenticated` scope** (decided, 13.12), so any identity
Cognito vouches for reaches the page, enrolled or not. That grant lists nobody, so its cost is
said out loud. **Since self-signup is open, `authenticated` means anyone who can register.** On
this page that is deliberate and bounded: a stranger sees that bb-auth knows nothing about them,
edits their own Cognito profile and deletes their own Cognito user, and gets no key form,
because a key needs a roster owner. **The side effect is at `/auth/session`**, which mints a
cookie for a valid id_token whose identifier has somewhere to go, and "somewhere" includes *any*
`authenticated` scope existing at all (`Access::any_authenticated_scope`). On a deployment that
had none before, adding this scope is what starts handing every self-signup a session cookie.
That cookie reaches only `authenticated` and `anonymous` scopes, since every `restricted` scope
still names people; but an operator who believed strangers were turned away at the sign-in page
should know they no longer are. It multiplies with `gate.allow_unverified_social`, exactly as the
invariant says. `bb-auth --check-access` and the startup banner already name every
`authenticated` scope, so nothing new is needed to make it visible; the README's recipe says
this paragraph's consequence in one line.

The self-service handler decides from the access file it opens on every request:

| Caller | What it gets |
|---|---|
| No proxy secret | `403` (13.3), before anything below |
| No `X-Auth-Email` | `401`: a broken deployment, not an anonymous visitor |
| `gate.identity_attrs` lacks `email` | `500` naming the setting: there is no identity to act on |
| **Denied** (`vetoes_identifier` on any value) | `403`, nothing else, checked first. The gate refuses a vetoed identity before it gets here; this is the second lock, for a file edited mid-request |
| **Roster user** | The page, keys, profile, deletion |
| **Administrator** | Same as a roster user (or a stranger): `web.admins` is not read. Deletion warns that it does not remove them from `web.admins`, which only an administrator can edit |
| **Authenticated stranger** (no row) | What bb-auth knows (no row; the `authenticated` scopes that do not exclude them, under their applications), the profile, and deleting the **Cognito** user. No keys |

**What the page shows of the access file is applications and scope names, and never a URL**
(decided, 13.12), on any page: the profile, the key form, the key list included. The scopes a
person reaches are `Access::scopes_reached` (built, step 2a): `restricted` ones whose members
include their uuid (directly or through a `@group`) and whose `credentials` admit a login;
every `authenticated` one; never an `anonymous` one, which says nothing about this person. A
scope whose `excluded` names them is left out, as `decide` would refuse it; `denied` removes
everything. Scopes are grouped under their application in file order. It is membership, not a
promise for every URL: a listed scope may be shadowed for some URLs by an earlier one, which the
page does not try to explain without showing URLs.

`X-Auth-Email` carries **every** identifier of the row, space-joined (`identity_headers`), so the
handler splits on spaces; every value must resolve to the same row, or none must, or the request
is a `500` (a header built from two identities is not a person).

### 13.6 API keys (R1)

All through the existing library calls (`add_api_key`, `rotate_api_key`, `remove_api_key`),
keyed by the caller's uuid, never by a form field.

- **Narrow only, by scope** (decided, 13.12). The form offers "everything I reach" (no `scopes`
  field, which the gate reads as "at most what the owner reaches") or any subset of the scopes
  the owner's keys reach (`Access::key_scopes_for`, 13.8), as checkboxes (since 13.16 in the
  keys table's new row, each spelled `app/scope` as the table's Scopes column spells it). It
  submits `application/scope` pairs, each checked against that set: a pair outside it is a `400` and nothing is written, never dropped silently. What is written is the
  submitted pairs, sorted. The restriction is a restriction either way, so this check keeps the
  file honest rather than keeping anybody out.
- **Shown with scope names, never URLs.** Each key's id, expiry, and either "everything you
  reach" or its entries (one `app/scope` per line since 13.16). An entry the owner no longer reaches is shown
  and marked, not hidden.
- **Rotate keeps the restriction byte for byte.** `rotate_api_key` changes only `key_hash` and
  `released`, and the self-service rotate offers no field that could change `scopes`.
- **Reveal once.** `SealedKey::reveal` needs the `Written` receipt; the bearer is rendered once,
  in the `200` answering the `POST` (never behind a redirect or in a URL, with
  `Cache-Control: no-store`), and is in no log line. The page shows the key alone, with a copy
  icon that only a script reveals (13.14, 13.15).
- **`rev`.** A mismatch is a `409` and nothing is written.
- **Abuse bound, as constants** (not settings: no second program has an opinion): at most 10 keys
  per row, counting keys an administrator made; `duration` chosen from 1 year, 6 months,
  3 months, custom days or no expiry, so at least `1d` or `never` (the 365-day ceiling was
  lifted by the user on 2026-11-24, 13.15); `id` from `[a-z0-9-]{1,32}`. An administrator's
  own pages are not bound by these.
- **Revoke asks first.** A `GET` renders a confirmation naming the key, and only its `POST`
  revokes, the console's own shape (13.15).
- **Journal, not the audit file.** The audit has one writer, the gate, and records
  authentication. Mutations go to the journal in the GUI's shape, marked as self-service:
  `[bb-auth-web] <uuid> (self): key add <id>`, `key rotate <id>`, `key remove <id>`,
  `profile update <attribute names>`, `account delete`. Never a bearer, a hash or a value.

### 13.7 Cognito: profile edit and user deletion (R2, R4) without JavaScript

bb-auth holds no Cognito credential, and the gate receives only an `id_token`. Both operations
need one:

- `UpdateUserAttributes` and `DeleteUser` are authorized by **the user's own access token** with
  the scope `aws.cognito.signin.user.admin`, and IAM is not evaluated for them
  ([UpdateUserAttributes](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserAttributes.html),
  [DeleteUser](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUser.html)).
- A token from API sign-in carries exactly that scope
  ([access token](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html)).
- `InitiateAuth` and `RespondToAuthChallenge` are public, IAM is not evaluated for them, and
  `USER_AUTH` with `PREFERRED_CHALLENGE=EMAIL_OTP` returns a `Session` that the `EMAIL_OTP_CODE`
  response turns into `AccessToken`, `IdToken` and `RefreshToken`
  ([InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html),
  [RespondToAuthChallenge](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html)).
  It is the flow `/auth/login` already runs in the browser (`login.html`).

**Decision: the self-service handler runs that same email-code sign-in itself, server-side, as a
re-authentication in front of each Cognito action, and throws the tokens away at the end of the
request that obtained them.** Three requests, no JavaScript, no state on the server:

1. The person submits the edit (or confirms the deletion) and picks which of their own emails to
   prove (a select over the `X-Auth-Email` values). The handler calls `InitiateAuth` with
   `USERNAME` = that email and `ClientId` = `gate.client_id`, at the issuer's origin
   (`cognito_endpoint`, moved to the library: 13.8).
2. It renders a code form carrying, as hidden fields, Cognito's `Session`, the chosen email, the
   action and its values (and the `rev`, for a deletion). `Cache-Control: no-store`. (Changed by §13.29
   for the deletion: no email is chosen; the code goes to the session's own Cognito user, and the
   form carries `Session`, `rev`, `uuid` and `kind`. Changed again by §13.29 W4: a deletion asks for
   no code at all; it is handed to the owner's worker, and only the profile edit runs this flow.)
3. The code `POST` re-checks everything against the live files (identity, veto, the email still
   among the caller's, the attributes still editable), calls `RespondToAuthChallenge`, then the
   action with the `AccessToken`, and drops all three tokens. None is logged, stored, or put in
   a cookie.

The `Session` lasts `AuthSessionValidity`, 3 to 15 minutes per app client
([UserPoolClientType](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UserPoolClientType.html));
the value on the real pool is **unverified**. (Changed by §13.22: 3 minutes on `gate.client_id`,
read from the pool on 2026-11-25.) A late code is `NotAuthorizedException` and the
page starts again. The action is bound to the right Cognito user without reading any token,
because `USERNAME` is one of the caller's own identifiers and the code goes to that inbox.
(Changed by §13.22: the `IdToken` that `RespondToAuthChallenge` returns **is** read, and must
name the chosen email for this audience and issuer before the action runs, so a `Session` carried
in from another flow can never act on the caller's behalf.)
**Assumed:** the pool signs in by email, which `login.html` relies on too; the read-only
`describe-user-pool` under "Waiting for the user" confirms it. (Changed by §13.22: read on 2026-11-25, `UsernameAttributes: [email]`.)

**The outbound call, and the unit's IP filter.** `bb-auth-web.service` carries
`IPAddressDeny=any` and `IPAddressAllow=localhost`, and those cgroup filters apply to outbound
traffic as well, so they block the call to Cognito. **Decision: the profile step removes both
lines**, and not before, so the kernel's loopback lock stays for as long as it costs nothing.
After that, "nothing but nginx reaches it" is held by the binary's bind check
(`BB_AUTH_WEB_ALLOW_NONLOOPBACK`) and by the proxy secret, which together are stronger than the
filter was against a local caller and weaker against a stray non-loopback bind, where the
secret is now the only lock. The other cost is egress: the most privileged process on the host
can open connections anywhere, which a compromise could use. Rejected: allowing only AWS's
address ranges (`IPAddressAllow=` takes static prefixes, and AWS publishes a list that changes,
so it would rot in a unit file); routing the call through the gate, which already has egress
(a new write API on the gate, the one component whose job is to stay small). `ureq` and rustls
are already dependencies of the crate, so no dependency is added.

Rejected mechanisms (unchanged from the morning's design): **admin calls with IAM credentials**
(a long-lived AWS secret with power over every user of the pool, and the AWS SDK for Rust's
`aws-lc-rs`, system roots and async runtime break three invariants,
[SDK for Rust, HTTP](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/http.html));
**keeping the browser's access token** (in the cookie: a `COOKIE_VERSION` bump and a Cognito
bearer on every request; in a server store: breaks stateless sessions; in the page: needs
JavaScript); **the authorization-code flow through the hosted UI** (more moving parts for the
same token).

**Federated (social) users cannot do this**: `InitiateAuth` cannot sign one in. For them the page
says their profile is their provider's, which Cognito re-maps at every sign-in
([attribute mapping](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html)),
and that an administrator must delete their Cognito account (accepted as meeting R4, 13.12).
**Unverified:** that the federated profile would be re-created at their next social sign-in.
(Changed by §13.22: the real social client allows only `ALLOW_REFRESH_TOKEN_AUTH`, and the page
tells a person this before they start and again when `InitiateAuth` answers
`UserNotFoundException`, which is how a social-only email shows on the native client.)

**Editable attributes**: those in `gate.profile_claims`, minus `email`, `phone_number`,
`preferred_username` and anything under `dev:`. Cognito's `WriteAttributes` on the app client is
the second authority ([attribute permissions](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-attribute-permissions-and-scopes)),
and its refusal is reported. **`email` is not editable**: it is the roster's identity key, and
depending on `AttributesRequireVerificationBeforeUpdate` a change either replaces the sign-in name
unverified (a lockout, since `email_verified` is mandatory for native users) or leaves the roster
naming an address the token no longer carries
([verifying changed emails](https://docs.aws.amazon.com/cognito/latest/developerguide/signing-up-users-in-your-app.html#verifying-when-users-change-their-email-or-phone-number)).
It stays an administrator's job, and the page says so. (Changed by §13.22: the editable set is an
**allowlist**, the `oidc:profile` attributes minus `preferred_username`, intersected with
`gate.profile_claims`; `WriteAttributes` is unset on the real native client, which Cognito
documents as every standard and custom attribute writable; and the pool's
`AttributesRequireVerificationBeforeUpdate` is empty, which would make an email change apply
unconfirmed, one more reason it stays read-only.)

### 13.8 What moves into the library

By the membership rule (a thing belongs there iff a file more than one program reads has an
opinion about it):

- **`cognito_endpoint`**, private to the gate today: the gate and `bb-auth-web` must agree on
  where the pool's API is. Becomes a `Settings` method.
- **`Access::key_scopes_for(uuid)`**, beside `scopes_reached` (built): the `restricted` scopes
  whose members include the uuid, whose `credentials` admit a key, and whose `excluded` does not
  name it. Tests drive `decide` on a URL inside each returned scope and require a grant.
- **`remove_user` rewrites a uuid in a scope's `excluded` to the primary email** (built,
  step 6), as it already does for `denied`, instead of dropping it: the same person
  re-registering is the walk-back-in that rewrite exists to prevent, and self-deletion would
  otherwise be a veto lifted by the person it vetoes. One sweep, so `bb-auth-adm` and the
  admin pages change too (decided, 13.12). Built as step 6: the CLI's report names the
  rewrite, "still kept out of APP/SCOPE by email EMAIL" and "still denied by email EMAIL"
  for the veto (`user_rm_report`); the admin pages go through the same call and say nothing
  about exclusions, so they did not change.

Nothing else moves. The presentation contract is already shared, and the merge removes the one
place it was copied: `bb-auth-me`'s private copies of `Lang`, `LangPref`, `negotiate_lang`,
`negotiate_theme`, `pct_decode` and the header and cookie helpers go, in favour of
`bb-auth-web`'s.

### 13.9 Account deletion (R4): order and partial failure

After the confirmation page and the email code of 13.7, in this order: (Changed by §13.29: the
code is asked for the session's own Cognito user, `USERNAME` = `X-Auth-Native-Username`, and its
`IdToken` is bound by `cognito:username`; a roster user with no such header deletes the row only,
on the confirmation page's `POST`; a stranger with none has nothing to delete here.)

1. **The roster row**, through `AccessWrite` with the `rev` from the confirmation form:
   `remove_user` on the caller's uuid (keys, scope and group references, the `excluded` and
   `denied` rewrites of 13.8).
2. **The Cognito user**, `DeleteUser` with the access token from step 3 of 13.7.

If step 2 fails, what is left is a Cognito user with no row, an `authenticated` stranger who
reaches only `authenticated` scopes and holds no key; the other order, on a failed write, would
leave a row with live API keys and every grant waiting for the same person to re-register. If
step 1 fails (`409`, I/O), nothing has changed. If step 2 fails, the page says the row is gone and
the Cognito account is not, and offers the retry, which the person still reaches as a stranger. (Changed by §13.29 §4: the
retry is the stranger's code walk on the same link, and `WRITE_LOCK` is released before step 2.
Changed again by §13.29 W3: step 2 is a request queued at the owner's worker, one per address,
after the row is gone, and the retry is the stranger's walk with no code.)

A `denied` entry is never lifted. A **stranger's** deletion does not touch the access file. The
audit is not edited; the confirmation page says their lines are kept until `audit.retention`
drops them (or, with no retention, until rotation does, said as a size). The final page links to
`/auth/logout`, because their cookie is still valid and now names a stranger.

### 13.10 Moving the page into `bb-auth-web`

**Mostly mechanical, because the hard half is already shared.** The two programs use the same
cookie names (`lang`, `theme`), the same values, the same `Path=/; HttpOnly; SameSite=Lax`, the
same negotiation order (query, cookie, `Accept-Language`, default), the same `THEME_CSS` and
`BASE_CSS`, and the same `ui` section, so a preference already carries between them and keeps
doing so with nothing to migrate. What is not trivial, and is the work of step (c):

- **The `K` table.** `bb-auth-me`'s keys join `bb-auth-web`'s, where names such as
  `NoIdentityTitle` already exist: identical texts are reused, the rest take a `Me` prefix.
- **The look.** The centred card's arrangement moves from `bb-auth-me`'s inline `CSS` into
  `admin.css`, so `admin_csp` keeps hashing one style block. The `/account/` pages also show
  `ui.logo_url` and `ui.brand_name`, so their policy passes the logo to `page_csp`, as
  `bb-auth-me` does today.
- **The selector.** `bb-auth-me` sets both cookies in one `302`; the admin pages answer
  `?lang=&theme=` with two round trips. The account page keeps one `302` carrying one
  `Set-Cookie` per named preference (13.2), built from the same cookie string the admin pages
  use, because its selector is one visible submit and a second hop is a choice that can be
  lost; the admin pages keep theirs.
- **The tests.** The 26 move into `bb-auth-web`'s test module on its existing real-socket
  harness, retargeted at `/account/` with the admin base `/admin`, a settings fixture whose
  `web.admins` names somebody else (which is what proves the page never reads it) and, once 13.3 lands, the proxy secret on
  every request. They keep their names and assertions; what changes is the path and the
  fixture. New tests are in 13.11.
- **Deleted:** `src/bin/bb-auth-me.rs`, its `[[bin]]` in `Cargo.toml`, and its mentions in
  `AGENTS.md`, the README and §2 and §3 of this document. No package, unit, env file or port
  (`8092`) ever shipped, so no host has anything to remove.

**Questions the merge closes**, all of which existed only because there were two writers in two
processes: the shared service account (one service, one uid); the per-file `ReadOnlyPaths=` that
was to keep `bb-auth-me` off `settings.json`, and its unverified nesting (the code is the guard,
as 13.1 says); moving `bb-auth-reload.path` to the gate's package with `Breaks`/`Replaces` (it
stays with `bb-auth-web`, still the only unprivileged editor); the conditional `postrm`
hand-back between two editor packages; and a fourth `.deb` in the build and deploy scripts.

### 13.11 How each decision is shown to hold

| Decision | Test or real run |
|---|---|
| Proxy secret | Unit: no secret is `403` on `GET` and `POST`, an admin route and an `/account/` route alike; a wrong one the same; the right one passes; the value is in no response body; a missing or short secret is a fatal startup whose message names the variable and not the value. Real, on rpi-01: `curl` to `127.0.0.1:8091` with a forged `X-Auth-Email` and no secret is `403` (today's finding, reproduced and closed), the same page through nginx is `200` |
| HMAC key unreadable | Real, on rpi-01: the service starts and listens (its env was loaded), and `sudo cat /proc/$(systemctl show -p MainPID --value bb-auth-web)/root/opt/bb-auth/etc/bb-auth.env` fails, since that path resolves in the service's mount namespace |
| Route classification | Unit, with base `/admin` and account path `/account`: a non-administrator gets `200` on `/account/` and `/account`, a `302` to `/account/` with both cookies on `/account/?theme=dark&lang=it`, and `403` on every admin `Route` variant, on an unknown path under `/admin/` and on one outside both (`/nope`); `/account/nope` is `404` for an administrator and a non-administrator alike; the page answers with a `web.admins` that does not name the caller; `/accounts` is not the page |
| Prefix validation | Unit: `BB_AUTH_WEB_ACCOUNT_PATH` unset is `/account`; `account/` normalises to `/account`; empty, equal to the admin base, under it (`/admin/account`), above it (`/admin` with base `/admin/x`), and any value with an empty admin base are refused naming the variable; `/accounts` beside `/account` is accepted |
| Two locations, the account scope | Unit (`decide` on both layouts of 13.2): a stranger is granted `/account/` and `/account`, refused `/admin/`; an administrator is granted both. Real, on rpi-01: `nginx -t`, `bb-auth-adm can` the same, `curl -I https://auth.badbat75.com/account` is `301` to `/account/`, and in a browser a non-administrator sees their page and is refused `/admin/` |
| Identity from `X-Auth-Email` only | Unit: missing header `401`; two values of one row act on that row; values of two rows `500`; a form field naming another uuid changes nothing |
| The callers of 13.5 | Unit: denied `403` even for a mutation `POST`; a stranger sees no key form and a key `POST` is refused; an administrator with no row is a stranger |
| No URLs on screen | Unit (moved from `bb-auth-me`): no rendered `/account/` page contains a URL pattern or base from the fixture |
| `key_scopes_for` | Library unit: `decide` grants a key on a URL inside every returned scope, and refuses on a scope excluded or not admitting a key |
| Keys: narrowing, bounds, rotate, reveal once, `rev` | Unit: a pair outside the set is `400` with the file bytes unchanged; the file gets exactly the submitted pairs; the eleventh key, `12h` and an empty `duration` refused, `never` and `400d` accepted (13.15); rotate leaves `scopes` bytes identical; the bearer appears in one response only, with `no-store`; a stale `rev` is `409` |
| No page needs JavaScript (13.14) | `no_page_but_the_reveal_carries_a_script` (replacing `the_page_carries_one_handler_and_no_script`): every page but the two reveals carries no script, each reveal exactly one, allowed by its own policy's hash; the `nojs.js` and `account.js` walks run the reveal with scripting off |
| Copy icon, confirmed revoke, duration choice (13.15) | Unit: `the_copy_control_is_an_icon_with_a_name`, `revoking_a_key_asks_first_on_the_account_page`, `the_duration_choice_maps_onto_the_grammar`, `a_self_service_key_may_never_expire`, `the_key_form_offers_five_choices`. E2E: `account.js` and `nojs.js` as listed in 13.15 |
| Cognito re-auth | Unit against a fake endpoint: a wrong code changes nothing; an email not among the caller's and a non-editable attribute are refused before Cognito is called; tokens appear in no response or log. Real pool once, with the user's go-ahead |
| Egress | Real, on rpi-01 after the profile step: the unit has no `IPAddress*` line, a profile edit reaches Cognito, and a non-loopback `BB_AUTH_WEB_LISTEN` without the opt-in still refuses to start |
| Deletion order | Unit with the fake endpoint: `DeleteUser` failing leaves the row gone and says so; the write failing never calls `DeleteUser` |
| `excluded` rewrite | Library unit: after `remove_user`, a scope that excluded the uuid excludes the primary email |
| Worker count (13.13) | Unit, on the parser alone (no env mutation, so tests stay parallel-safe): unset is `8`; `1` and `64` are accepted; `0`, `65`, `-1`, empty, `8` with a leading space, `8x` and `eight` are refused with a message naming `BB_AUTH_WEB_WORKERS`. Startup: the banner prints `workers=N`, so a real run shows the value the process took |
| Write lock scope (13.13) | Unit, kept as a regression guard: two concurrent key `POST`s and two concurrent console saves against one `rev` give one success and one `409`, never two successes. The guard's narrower scope in `account_key_post` changes nothing a test can see while the page fits a socket buffer, and is checked by reading the diff |
| Cognito timeout (13.13) | Unit, step 5, against a fake endpoint that accepts and never answers: the handler answers within the per-call bound plus a margin, with a page saying Cognito did not answer, and the worker serves the next request |

### 13.12 Decisions recorded on 2026-11-23

Morning, as the user answered the proposal's questions, and still in force:

1. **Cognito mechanism**: a server-side `USER_AUTH` / `EMAIL_OTP` re-authentication before each
   profile edit or deletion; no IAM, no AWS SDK (13.7).
2. **Scope over the page**: `authenticated`; strangers see the profile, can delete their Cognito
   user, and get no keys; the `/auth/session` consequence is in 13.5.
3. **`remove_user`** keeps a uuid in a scope's `excluded` as the primary email, in every editor
   (13.8).
4. **Social-only users**: self-deletion removes only their access-file data, and the page says
   an administrator must delete the Cognito account. Accepted as meeting R4.
5. **Visibility**: applications and scope names, never a URL pattern or base; `anonymous` not
   listed, `excluded` removes a scope, `denied` removes everything (13.5).
6. **Key narrowing by scope**: any subset of `key_scopes_for`, submitted as checked
   `application/scope` pairs, never dropped silently; rotate keeps the restriction (13.6).

The morning's "the shared `bb-auth-web` account stays and is not renamed" is moot: there is one
service.

Afternoon, the user's decisions, final:

1. **No separate binary.** Self-service is a section of `bb-auth-web`; the `bb-auth-me`
   target goes, and its page and tests move (13.10).
2. **The self-service page is open to any identity nginx vouches for, never reads `web.admins`, and acts only on
   the caller's own account** (keys, profile, deletion), writing through `AccessWrite`, `rev` and
   the same-origin check like every other GUI write.
3. **A secret header only nginx sets** is required by `bb-auth-web`, which stays on loopback TCP
   (13.3). The user said "requests that add or remove"; **the architect recommends every
   request**, for the read exposure 13.3 lists, and that needs the user's confirmation.
4. **`bb-auth-web` cannot read the HMAC key**: `InaccessiblePaths=/opt/bb-auth/etc` (13.4).

Evening, the user's decision: **the self-service page is `/account/`, not `<base>/me/`**
(`BB_AUTH_WEB_ACCOUNT_PATH`, 13.2), because administrators' URLs must not move and `/admin/me/`
is a bad URL to hand a non-administrator. On rpi-01 it replaces the static deletion page at
`/account/`, so self-service account deletion is missing until plan step 7 (accepted).

**The reversal, plainly.** The morning's rule was that "a non-admin surface must not share a
binary with the admin CRUD". The first afternoon decision reverses it. What that costs:

- **Strangers now talk to the admin process.** Every request from anyone who can register on
  Cognito is parsed by the program that writes the settings file and every row of the access
  file. Before, the worst a self-service bug could reach was the caller's own row; now it is
  one route-classification mistake from the admin handlers (13.2 keeps that a closed list with a
  test over every route, which narrows the risk and does not remove it).
- **Egress on the most privileged process** once the profile step lands (13.7), where the
  separate binary would have carried it alone.
- **One process, one failure domain**: a crash or an overload from self-service traffic takes
  the admin pages with it (`WORKERS = 2` was sized for a handful of administrators; plan step
  4e makes it `BB_AUTH_WEB_WORKERS`, default 8, argued in 13.13).

What it buys: no second package, unit, env file, port, service account or ownership scheme
(13.10's closed questions), the shared presentation and preferences with no copy to drift, and
self-service writes serialized with admin writes by one mutex rather than only by `rev`.

### 13.13 The worker pool and the write lock (plan step 4e)

What was read: `src/bin/bb-auth-web.rs` (`WORKERS`, `WRITE_LOCK`, `mutate`,
`account_key_post`, `main`'s worker loop, `env_or`, the other env parsers), `src/lib.rs`
(`write_atomically`), `src/bin/bb-auth.rs` (`BB_AUTH_WORKERS`, `JWKS_TIMEOUT`), and the crate
sources in `~/.cargo/registry`: `tiny_http-0.12.0/src/lib.rs` and `src/util/task_pool.rs`,
`ureq-3.4.0/src/config.rs`.

**What a worker is, read in the source.** `tiny_http` 0.12 runs its own accept thread, which
hands every connection to an internal pool that keeps 4 threads and grows by one per busy
connection (`TaskPool::spawn`, `MIN_THREADS = 4`); those threads parse requests and push them
onto one queue with no bound (`MessagesQueue`, `lib.rs` around line 284 to 335). Our workers
are only the threads that call `server.recv()` and run a handler. So `WORKERS` bounds how many
**handlers run at once**, not how many connections are open, and a request that finds every
worker busy is not refused: it waits in that queue. Too few workers shows up as latency for
everybody, never as an error, which is exactly the failure 4e exists for.

**Decision: `BB_AUTH_WEB_WORKERS`, an env var in `bb-auth-web.env`, default `8`, accepted from
1 to 64; unset means the default, and any other value (0, 65, negative, empty, padded,
non-numeric) is a fatal startup whose message names the variable.**

- *Env and not the settings file*: it fails part 1 of the three-part rule exactly as the
  gate's `BB_AUTH_WORKERS` does. The threads are spawned once, in `main`, and a value read per
  request would change nothing until a restart, so it belongs where restart-only values live.
- *Fatal and not the gate's `unwrap_or(4)`*: a silent fallback turns `BB_AUTH_WEB_WORKERS=16x`
  into 8 with nothing anywhere saying so, which is the operator's intent lost without a trace.
  Every other value this binary parses from its env is already fatal on a bad value
  (`BB_AUTH_WEB_BASE_PATH`, `BB_AUTH_WEB_DEFAULT_LANG`, `BB_AUTH_WEB_ACCOUNT_PATH`,
  `BB_AUTH_WEB_PROXY_SECRET`), and the boot-loop argument that makes the gate careful does not
  carry over: a GUI that refuses to start locks nobody out of any application, and
  `bb-auth-adm` over SSH is untouched. Empty is refused rather than defaulted because `env_or`
  hands an empty value through as a value, and `BB_AUTH_WEB_ACCOUNT_PATH` already reads an
  empty assignment as somebody meaning to say something. Zero is refused rather than raised to
  one, since a service that binds its port and never answers is the worst of both. The gate's
  own fallback is not changed by this step; the inconsistency is noted, not fixed.
- *Why 8, from the workload and not from any host*: a handler here does one of three things.
  A read (two small files parsed, a page rendered) takes milliseconds and is CPU-light. A
  write holds `WRITE_LOCK` for a read, two parses, a write and two fsyncs, so writes run one
  at a time whatever the worker count, and a second writer only waits. From step 5, a
  Cognito action waits on the network for up to its timeout (below) while using no CPU. None
  of those is CPU-bound, so the core count is the wrong ruler; the right one is how many
  **slow handlers may be in flight while reads still flow**. Eight lets one write, a few
  waiting writers and several Cognito calls run at once and still leave workers for page
  views, at the cost of a few idle threads, which is a stack reservation each and nothing
  measurable in CPU (not measured here). It is the gate's 4 doubled because this service has
  the slow handlers the gate does not, and it is small because nothing in the workload
  parallelises: more workers past the slow-handler count only queue on the lock or on Cognito.
- *Why 64 as the ceiling*: past it the threads have nothing to do in parallel (writes
  serialise, reads are milliseconds), and a deployment that really needs more concurrent
  handlers than that on an admin and self-service page has outgrown a blocking
  thread-per-handler design, which is a design question and not a number. The ceiling is there to turn a
  typo (`800`) into a refusal rather than to forbid anything a real deployment needs.
- *How an operator sizes it*: count the slow handlers at the busiest moment, which is the
  rate of Cognito-calling requests times the bound on one of them (Little's law: 1 profile
  edit a second at 10 s each is 10 in flight), plus one for a write, plus a few for page
  views, and round up. Watch nginx's `$upstream_response_time` on the GUI's locations: page
  views that slow down while nothing is writing mean the workers are all waiting on something,
  and the queue above is where the time went. rpi-01 is one deployment that runs the default.

Rejected: sizing by core count (the handlers wait, they do not compute); keeping 2 (two slow
handlers stop the page for everyone, which is 4e's premise); an async runtime (forbidden by
the dependency invariant, and nothing here needs it).

**`WRITE_LOCK`: what it must cover, and the one place it covers more.** The lock exists for one
race `rev` cannot see: two workers that read the same bytes compute the same fingerprint, and
both are entitled to write. So it must be held from **the read whose bytes `rev` is compared
against, until the rename that replaces them**: no other writer in this process may rename
between this one's check and this one's rename. Everything between is inside by necessity,
not by habit:

- the parses (`open_access_file` on the way in, `AccessWrite::prepare` on the way out) work on
  bytes derived from that read, and validate-before-write is only a guarantee when the bytes
  compiled are the bytes committed, so neither can move out;
- the file's fsync cannot move out, because it must come before the rename (a rename that
  lands ahead of its data is how a crash leaves an empty access file, which `write_atomically`
  says), the rename must be inside, and the temp file's content cannot be written before the
  lock since it depends on what was read under it;
- the directory's fsync after the rename could in principle follow the unlock, but it lives
  inside `write_atomically`, the single door both editors share, and splitting that door to
  save milliseconds per write on a serial path is not worth a second shape of write.

So the console's `mutate` holds exactly what it must (the form is parsed before it is called,
and the guard drops when it returns). **`account_key_post` holds more**: the guard is a local
that lives to the end of the function, so the response (the reveal page carrying the bearer,
or the redirect) is written to the socket while the lock is still held. Today that costs close
to nothing, since nginx buffers upstream responses and the page fits a socket buffer, but it
couples every writer's wait to one response's send for no reason. **Proposed for 4e: end the
guard's scope at the commit**, before anything is rendered or sent. Its body is already read
before the lock, as it should be.

**A Cognito call in a handler (step 5 inherits this).** The default above already counts
Cognito calls as slow handlers, so it needs no extra margin; what keeps a slow Cognito from
pinning all workers **indefinitely** is the timeout, and `ureq` 3.4 has none by default
(`Timeouts::default` sets every field to `None` except `await_100`, `config.rs` around line
893). **Decision: every Cognito call goes through an agent built with
`timeout_global(Some(5 s))`, which `ureq` documents as end to end, DNS to the last body byte;
no retry inside the request; and at most two calls per request** (`RespondToAuthChallenge` then
the action), so one handler waits at most about 10 s. That is well under nginx's default
upstream read timeout of 60 s (as the gate's `JWKS_TIMEOUT` rustdoc records; not re-checked
here), so the handler gives up and frees its worker before nginx gives up on it, the same
ordering the gate's JWKS fetch keeps at 3 s. Five seconds and not the gate's three because these
are API calls that do work (`InitiateAuth` sends an email) rather than a cached document;
**assumed**, not measured against the real pool. A timed-out call is reported to the person as
Cognito not answering, with nothing written. Rejected for now: a separate cap on concurrent
Cognito calls (a semaphore below the worker count, so admin pages always keep a worker). With
the timeout, a Cognito outage costs each attempt at most 10 s of one worker, the callers are
signed-in people, and a scripted one could still hold workers only for as long as they keep
sending; revisit if `$upstream_response_time` ever shows it happening.

### 13.14 The bearer reveal: only the key, and a copy button (plan step 4g)

What was read: `src/bin/bb-auth-web.rs` (`page_minted`, `page_account_minted`, the
`K::Bearer*` texts, `respond_page`, `admin_csp`, `respond_account`, `account_csp`,
`SETTINGS_ONCHANGE`, `no_page_but_the_reveal_carries_a_script`, `handlers_in`),
`src/lib.rs` (`page_csp`, `csp_hash`, `PAGE_SECURITY_HEADERS`), `src/bin/bb-auth.rs`
(`csp_nonce`), `src/assets/base.css` and `admin.css` (`.secret code`), `e2e/tests/nojs.js`
and `e2e/tests/account.js`.

**The user's decision, 2026-11-24.** The page that reveals a freshly minted or rotated bearer,
in the console and on `/account/` alike, shows **only the key** (`bbk_…`), not the
`Authorization: Bearer` line, and carries a **copy button** (an icon since 4h: its markup,
CSS and feedback are revised in 13.15, and what follows about the script, the policy and the
bearer's single place still holds). Copying to the clipboard needs
JavaScript, and the user accepted that: the rule "no page carries a script" becomes "no page
**needs** one". Scripting off, the page is exactly today's minus the header prefix: one click
on the key still selects all of it (`user-select: all`), and no button is shown.

**One rendering, two callers.** A single function, `bearer_reveal(lang, bearer) -> Markup`,
renders the `div.secret` block, and both `page_minted` and `page_account_minted` call it, so
the key, the button and the script cannot drift between the console and `/account/` (the
texts were already shared; now the markup is too). Its markup, in order:

- `strong` with `K::BearerHeading`, `p` with `K::BearerOnce` (unchanged);
- `code id="bearer"` whose text is the bearer and nothing else: no prefix, no whitespace
  around it, because what a click selects and what the button copies is that text;
- `button type="button" id="bearer-copy" hidden data-done=… data-failed=…` labelled
  `K::CopyKey`, the two data attributes carrying `K::CopyDone` and `K::CopyFailed` in the
  page's language. `type="button"` because the block is in no form and a button must never
  be able to submit one; `hidden` because a browser with scripting off must show no button
  that does nothing. The script is the only thing that removes it;
- `p class="hint"` with `K::BearerClickHint`, reworded to "the key" since there is no longer a
  header line to select;
- the `script` element, last, so the two elements it looks up already exist when it runs and
  it needs no load event.

`hidden` is a presentational hint that author CSS overrides: "changing the value of the CSS
`display` property on a hidden element will override the hidden state"
(<https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Global_attributes/hidden>).
Nothing in `base.css` gives `button` a `display` today, but the operator's stylesheet loads
after ours and may. So `admin.css` (the `CSS` both the console and `/account/` emit) gets
`.secret button[hidden]{display:none}`, whose specificity beats a plain `button` rule, so a
scripting-off page stays buttonless under an ordinary token file.

**The script: inline, a compile-time constant, allowed by its hash.** `COPY_SCRIPT: &str`, in
`bb-auth-web.rs`, and only there (the gate has no reveal page). What it does:

1. Look up `#bearer` and `#bearer-copy`; if either is missing, or the page is not a secure
   context, or `navigator.clipboard` is absent, **stop and leave the button hidden**. The page
   is then the scripting-off page, which already works.
2. Otherwise set `hidden = false` and attach a click listener with `addEventListener` (no
   `on…` attribute, so `handlers_in`'s allowlist is unchanged).
3. On click, `navigator.clipboard.writeText(code.textContent)`. Resolved: the button's text
   becomes `data-done`. Rejected (`NotAllowedError`, for example a denied permission): select
   the key's text (`getSelection().selectAllChildren(code)`) and set the button's text to
   `data-failed`, which says the key is selected and to copy it with the keyboard.

Facts relied on, read in a source: `Navigator.clipboard` and `Clipboard.writeText` are
"available only in secure contexts (HTTPS), in some or all supporting browsers", and
`writeText` fails with `NotAllowedError` "if writing to the clipboard is not allowed"
(<https://developer.mozilla.org/en-US/docs/Web/API/Navigator/clipboard>,
<https://developer.mozilla.org/en-US/docs/Web/API/Clipboard/writeText>); "some or all" is why
step 1 checks both `isSecureContext` and the property rather than either. The GUI is served
over HTTPS through nginx, so a real deployment is a secure context; the check is there for a
plain-HTTP setup somebody might build, where the honest behaviour is no button at all. No
`document.execCommand("copy")` fallback: MDN marks it deprecated and "not implemented
consistently or fully by user agents"
(<https://developer.mozilla.org/en-US/docs/Web/API/Document/execCommand>), and the fallback
this page needs already exists, which is the selection.

**The bearer is in exactly one place in the response: the text of `code#bearer`.** The script
is a constant and reads the key from the DOM at click time; the button's attributes carry only
translated texts. So the bearer is in no script, no attribute, no URL and no header, and the
existing reveal-once properties (rendered directly in the `200` answering the `POST`,
`Cache-Control: no-store` from `PAGE_SECURITY_HEADERS`, in no log line) are untouched.

**The policy, for exactly that response.** A hash source allows the inline block whose bytes
hash to it, and only that block: "you can create hashes from your inline scripts", and hashes
"allow scripts and styles by their hash, but not event handlers" without `'unsafe-hashes'`
(<https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src>).

- Console reveal: `script-src 'unsafe-hashes' <hash(SETTINGS_ONCHANGE)> <hash(COPY_SCRIPT)>`.
  The first two are today's, because the console's shell carries the Settings list boxes on
  every page, this one included. `'unsafe-hashes'` then also lets an *attribute* whose body is
  exactly `COPY_SCRIPT` run; that is our own constant, so it grants nothing new.
- `/account/` reveal: `script-src <hash(COPY_SCRIPT)>`, and nothing else. (Changed by plan
  step 13, 2026-11-26: it is `'unsafe-hashes' <hash(SETTINGS_ONCHANGE)> <hash(COPY_SCRIPT)>`
  now, the console's own, because the reveal wears the account menu, which carries the
  Preferences list boxes on this surface too.)
- **Every other response keeps the policy it has**: the console's `'unsafe-hashes'` plus the
  one handler, `/account/`'s `'none'`. (Changed by plan step 13, 2026-11-26: `/account/`'s is
  not `'none'`. Both policies are built by one `page_script_src(reveal)`, so the two surfaces
  allow exactly the same thing to run: the handler's hash, plus the copy script's on a reveal
  and on nothing else. `only_the_reveal_policy_names_the_copy_script` compares the two
  directives and so pins the sharing.)

The widening is a distinct response path rather than a flag every page passes: `admin_csp`
and `account_csp` each take a `reveal: bool`, and the only callers that pass `true` are the
two reveal responses (in the console, an `Outcome` variant for a reveal, so the mint and
rotate arms are the only code that can produce it). A forgotten `true` elsewhere would allow
one known constant on a page that does not carry it, which is harmless; a forgotten one on the
reveal is a button that never appears, which the e2e walk below catches.

**Rejected:**

- *A per-response nonce* (what the gate's sign-in page uses, and the wording of the plan). A
  nonce is for content assembled per render, which is why the gate needs one: its script is
  built out of the configuration. This script is a constant, and this program already argues,
  on `admin_csp`, that a hash is the better source for a constant: nothing to generate per
  response, nothing to thread through two renderers, and the policy and the page derived from
  the same `&str` so they cannot disagree. The property the user asked for (a script allowed
  only on the reveal page, by that page's own policy, with no `'unsafe-inline'`) is the same
  either way, and the browser sees no difference. If the user wants the nonce literally, it is
  a swap of the source expression and of where the value comes from (`csp_nonce` moves to the
  library); nothing else in this design changes.
- *A static `.js` asset with its hash or `'self'`*: a new route, served through nginx's
  `auth_request` like every other path, with its own cache headers, for a dozen lines; and
  `'self'` would allow any script this origin ever serves, which is wider than one hash.
- *Building the button in script* (`createElement`) instead of `hidden`: no CSS can ever show a
  dead button that way, but the label has to reach the script some other way and a server-side
  test can no longer see the button. `hidden` plus the one CSS rule keeps the markup testable.
- *`'unsafe-inline'`*: allows every inline script anybody ever adds.

**How it is shown to hold.** Unit tests in `bb-auth-web.rs`:

- `no_page_but_the_reveal_carries_a_script` replaces `the_page_carries_one_handler_and_no_script`:
  every route of `every_route()` still has no `<script` and only the two Settings handlers; the
  console's mint and rotate `POST` responses and `/account/`'s mint and rotate responses each
  carry **exactly one** `<script>`, whose content's `csp_hash` is in that response's
  `Content-Security-Policy`, and no `on…` attribute beyond the console's two. (Changed by plan
  step 13, 2026-11-26: "the console's two" is now "the shell's two" on **both** surfaces, and the
  assertion is a constant `2` where it used to be `2` for the console and `0` for
  `/account/`.)
- `the_reveal_shows_only_the_key`: on all four reveal responses, the text of `code id="bearer"`
  equals the bearer exactly, the body contains no `Authorization`, the bearer occurs once in the
  body and that occurrence is inside the `code` element, and the button is `type="button"` and
  carries `hidden`.
- `only_the_reveal_policy_names_the_copy_script`: `admin_csp(_, false)` and `account_csp(_, false)`
  do not contain `csp_hash(COPY_SCRIPT)`, and `account_csp(_, false)` still says
  `script-src 'none'`; the `true` variants contain it. A failed mint (the `400` key form) and the
  `409` carry no script. (Changed by plan step 13, 2026-11-26: no policy says `script-src 'none'`
  any more, and the test compares the two surfaces' `script-src` directives for equality, on the
  `false` and the `true` variants alike, so the copy hash stays the only difference a reveal
  makes.)

E2E: `nojs.js` keeps its zero-script list and adds the console reveal twice, with scripting on
(one `script`, the button visible, a click shows `K::CopyDone`, and in Chromium with
`clipboard-read` granted, `navigator.clipboard.readText()` equals the code's text) and with
scripting off (the button not visible, the key selectable). `account.js`, which runs with
scripting off, reads the bearer from `#bearer` instead of the `Bearer bbk_…` regex, asserts no
`Authorization` text, the button hidden, and one `<script` on the reveal response while every
other page in the area still has none.

### 13.15 A copy icon, a confirmed revoke, and a duration chosen from five (plan step 4h)

What was read: `PLAN.md` step 4 (the 4h paragraph), `src/bin/bb-auth-web.rs` (`bearer_reveal`,
`COPY_SCRIPT`, `admin_csp`, `account_csp`, `account_mint_form`, `account_key_forms`,
`account_key_post`, `AccountKeyOp`, `ACCOUNT_KEY_MIN_SECS` / `ACCOUNT_KEY_MAX_SECS`,
`account_key_window_ok`, the account dispatch, `KeyForm`, `page_key_form`, the console's
`Route::KeyAdd` / `KeyEdit` / `KeyRotate` / `KeyRm` handlers, `act_rm`, `page_confirm`, the
Settings guard's `page_settings` confirmation), `src/lib.rs` (`parse_duration`, `key_expiry`,
`format_date`, `civil_from_days`, `only_the_palette_names_a_colour`), `src/assets/base.css`,
`admin.css` and `theme.css`.

**The user's decision, 2026-11-24**, on `/account/` and in the console alike: the copy control
is a small icon; removing a key asks first; the duration is one of **1 year, 6 months,
3 months, custom (in days), no expiry**; and the 365-day self-service bound is lifted, so a
person may mint a key of their own that never expires. The 10-key bound and the id grammar
stay.

#### The copy icon

**Amended by §13.17 (icons):** the control is now the shared `pill ico` component, its name
in hidden text rather than `aria-label`; the glyphs, the status span and the script stand.

Still the one control `COPY_SCRIPT` reveals, still server-rendered `hidden`, still in
`bearer_reveal` and therefore identical on both surfaces. The markup becomes:

- `button type="button" id="bearer-copy" class="copy" hidden="hidden"
  aria-label=K::CopyKey title=K::CopyKey data-done=… data-failed=…`, with **no text**;
- inside it two inline SVGs, `svg class="i-copy"` (two overlapping rounded squares) and
  `svg class="i-done"` (a check mark), each `viewBox="0 0 24 24" aria-hidden="true"
  focusable="false"` and carrying only geometry (`rect`, `path d=…`): no `fill`, `stroke` or
  `style` attribute, so everything about how they look is the stylesheet's;
- after the button, `span id="bearer-copy-status" class="copy-status" role="status"`, empty
  as served.

The accessible name is the `aria-label`, the icon is hidden from the accessibility tree, which
is MDN's own pattern for "a button containing an SVG icon without any text"
(<https://developer.mozilla.org/en-US/docs/Web/Accessibility/ARIA/Reference/Attributes/aria-label>;
`aria-hidden="true"` "removes that element and all of its children from the accessibility
tree", <https://developer.mozilla.org/en-US/docs/Web/Accessibility/ARIA/Reference/Attributes/aria-hidden>).
`title` is the same translated text, so a pointer user who does not know the glyph gets a
tooltip; it adds nothing to the name, since `aria-label` takes precedence.

The feedback is two things at once, because each serves a different reader. The script sets
`data-state="done"` on the button, and the CSS swaps the copy glyph for the check; and it
writes `data-done` (`K::CopyDone`, "Copied") into the status span, which is visible beside the
icon and is announced: `role="status"` has an implicit `aria-live` of `polite` and an implicit
`aria-atomic` of `true`
(<https://developer.mozilla.org/en-US/docs/Web/Accessibility/ARIA/Reference/Roles/status_role>).
Changing the button's own `aria-label` instead was rejected: a name change on a focused control
is not an announcement anybody can rely on, and the status region is the mechanism made for
it. A refusal sets `data-state="failed"`, keeps the copy glyph, selects the key as today and
writes `data-failed` into the status span. The state is not reset on a timer: the word stays
true for as long as the page is open, and a timer is one more thing in a script that should
stay a dozen lines.

`COPY_SCRIPT` changes in exactly those two lines (the attribute and the status span's text
instead of the button's text), still looks its elements up by id, still uses
`addEventListener`, and still stops with the button hidden when either element, a secure
context or `navigator.clipboard` is missing. Its hash changes with its bytes, and the policy is
derived from the same `&str`, so nothing else moves.

**CSS, in `admin.css`.** **Amended by §13.17 (icons):** the geometry is now the shared
`.pill.ico` component in `base.css`, and `admin.css` keeps only what the reveal's own state
needs, the glyph swap (`.secret .i-done`, `.secret [data-state=done] .i-copy`,
`.secret [data-state=done] .i-done`) and `.copy-status`. The rules as 4h decided them, in
words:

- `.secret .copy`: `display:inline-flex`, centred, `min-width:32px; min-height:32px`, a small
  padding, `background:transparent`, `border-color:var(--card-border)`, `color:var(--text)`;
  hover `background:var(--chip)` rather than `base.css`'s filled accent, so the icon stays
  legible on hover.
- `.secret .copy svg`: `width:18px; height:18px; fill:none; stroke:currentColor;
  stroke-width:2`, round caps and joins. `currentColor` is what lets the palette paint it:
  `only_the_palette_names_a_colour` deliberately admits it, since it is not a colour a token
  file could supply.
- `.secret .copy .i-done{display:none}`, `.secret .copy[data-state=done] .i-copy{display:none}`,
  `.secret .copy[data-state=done] .i-done{display:block}`.
- `.copy-status{margin-left:8px}` and the existing `.secret button[hidden]{display:none}`, which
  already covers the new button.
- The focus ring is `base.css`'s global `:focus-visible` (2px `--accent` outline, offset 2px),
  unchanged and not restated.

The geometry goes in CSS and not in SVG attributes because the GUI's `style-src` is a hash of
its stylesheet with no `'unsafe-inline'`, so a `style=` attribute would not apply; presentation
attributes are a different mechanism, but keeping all of it in the stylesheet means there is
nothing to argue. Inline `<svg>` is markup in the document, not a fetched resource, so no
`img-src` is needed (assumed from how CSP fetch directives work; the e2e walk below shows the
glyph painted under the real policy).

**Target size.** WCAG 2.2 2.5.8 (AA): "The size of the target for pointer inputs is at least 24
by 24 CSS pixels", with a spacing exception
(<https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html>). Amended by §13.17:
the shared component's floor is `min-width:24px;min-height:24px`, the criterion's own minimum,
so it passes on size alone, without leaning on the exception, and `nojs.js` measures the
reveal's box in a browser at 1280 and 390 px and requires that floor. The floor is in `px` on
purpose: the criterion is stated in CSS pixels, and a floor in `em` would shrink under a
smaller font size. The glyph itself is in `em`, so it follows the pill's own text size.

#### Revoking asks first

**The console already does.** `remove` on a key is `act_rm`, a link to
`GET /users/<u>/keys/<id>/rm`, which renders `page_confirm` (the key's id, `K::ConfirmKeyRm`, a
`POST` form carrying `rev`) and changes nothing; the `POST` to the same path removes. So the
console needs no change for this requirement, and `/account/` takes the **same shape**:

- the list's revoke control becomes `form method="get" action="<prefix>/keys/remove"` with a
  hidden `id` and the same `button.danger` (`K::AccountKeyRemove`): it still looks and reads as
  today's button, and it navigates rather than mutates (amended by §13.16: the control is
  now the console's own row action, a link `a.pill.rm` reading "×" to
  `<prefix>/keys/remove?id=<id>`, named "Revoke key `<id>`", beside an `a.pill` "rotate"
  to the rotate confirmation, exactly as `act_rm` and `act` are in the console);
- `GET <prefix>/keys/remove?id=<id>` passes the doors every `/account/` request meets (proxy
  secret, identity header, veto `403`, row resolution, a stranger's `403`), looks the id up on
  **the caller's row only**, and renders a confirmation card: heading `K::AccountKeyRemove`,
  the key's id and expiry as the list shows them, `K::AccountKeyRemoveWarn` (new: anything
  using this key stops getting in within seconds, and it cannot be brought back; a new key can
  be made instead), a `POST` form to `<prefix>/keys/remove` carrying `rev` (the fingerprint of
  the file as **this** `GET` read it) and `id`, with `button.danger` `K::AccountKeyRemove`, and
  a link `K::Cancel` back to the page;
- an id not on the caller's row is a `404` that names nothing else, so the step is no oracle
  for other people's keys; no `id` is a `404` too;
- the `POST` is today's `account_key_post` with `AccountKeyOp::Remove`, unchanged: the
  same-origin door, the write lock, the `rev` check, `remove_api_key`, the journal line.

No confirm field on the `POST`, as there is none on the console's: a confirmation is there for
a misclick, while forgery is answered by the same-origin door and a lost update by `rev`, and a
field a forger can add as easily as anybody else protects against neither. A direct `POST` from
a hand-written client keeps working, which is what the console's `POST` already allows.

**Rejected:**

- *The Settings guard's shape* (the first `POST` renders a panel, a second `POST` carrying a
  token commits). That guard exists because the change is a whole form's worth of typed values
  that must not be lost between the two steps; a revoke carries one id, so the confirmation
  can be a plain `GET`, which is also what the console already does for the same object. One
  URL meaning two things depending on a hidden field is harder to read in a log, and a `POST`
  confirmation page answers a reload with the browser's resubmission prompt.
- *Reusing the Settings guard's or the console's `K` strings.* `K::ConfirmKeyRm` speaks of "the
  gate reloads", which is operator vocabulary; the self-service page speaks to the person.
  `K::Cancel` is reused, being one word with one meaning.
- *A shared confirmation renderer.* The two surfaces share the shape (a `GET` that renders, a
  `POST` that does it) and the rule, not the arrangement: the console's page is `form_shell`
  inside its shell, the account's is a card. The thing worth sharing byte for byte, the
  bearer, already is.

#### The duration, chosen from five

**Amended by §13.16 (2026-11-24).** The five choices, their order, the posted values, the
`days` field, the default and `duration_from_form` all stand. What changes is the markup: the
component is one `select name="duration"` with five `option`s instead of five radios, on both
surfaces, because on `/account/` it now lives in one cell of a table row, and one component
rendered two ways would be two components. In `form.edit` the select and the days field sit in
the existing `span.limit` row. The radio markup below is kept as the record of what 4h
decided.

One component, `duration_choice`, rendered by both `account_mint_form` and `page_key_form`:

- `fieldset class="dur"` with `legend class="lbl"` (`K::AccountKeyDurationLabel` on
  `/account/`, `duration` in the console, which labels by the file's field names);
- five `label class="radio"` rows, in the user's order, each `input type="radio"
  name="duration"`: `value="365d"` (`K::DurOneYear`), `value="182d"` (`K::DurSixMonths`),
  `value="91d"` (`K::DurThreeMonths`), `value="custom"` (`K::DurCustom`), `value="never"`
  (`K::DurNever`);
- right after the custom row, **not inside its label**, `input type="text" inputmode="numeric"
  name="days" size="6"` with `aria-label` `K::DurDaysLabel` ("Custom duration, in days"), and
  a hint: `K::DurDaysHint` ("days") on `/account/`, and in the console `<n>d · <n>h`, because
  the console's custom field takes the whole grammar (below). Not inside the label because a
  click on a text field inside a label does not activate the label's radio, so nesting buys
  nothing and makes the label's text the field's too.
- on an add form `365d` is checked, which was the old field's suggestion and is the longest
  bounded choice; `never` is never preselected, since the widest credential must be asked for.

**The field keeps its name, and the radio's values are the stored strings.** `duration` is
the file's own field name and the one every existing test and hand-written client posts; the
four presets are therefore not codes to translate but the exact strings that land in the file,
and `bb-auth-adm`, the gate and existing files see nothing new.

| Choice | Posted | Stored `duration` |
|---|---|---|
| 1 year | `duration=365d` | `365d` |
| 6 months | `duration=182d` | `182d` |
| 3 months | `duration=91d` | `91d` |
| custom, 40 | `duration=custom&days=40` | `40d` (a bare number gets its `d`, so the file reads unambiguously) |
| custom, `30d` / `12h` (console) | `duration=custom&days=12h` | as typed, trimmed |
| no expiry | `duration=never` | `never` |

**182 and 91, not 183 and 90.** Six calendar months are 181 to 184 days and three are 89 to 92,
depending on where they start, so any fixed number is a day or two off some calendar span, and
no choice is wrong by more than that. 182 and 91 are exactly 26 and 13 weeks, so a key minted
on a working day expires on the same weekday, a working day, rather than drifting onto a
weekend when nobody is there to notice the integration that stopped. 365 stays 365 because the
user named it, and it is a fact about the grammar the file already uses.

**The server, one function for both:** `duration_from_form(form) -> Result<String, K>`, in
`bb-auth-web.rs` (only this program renders the choice; the library's grammar is unchanged):

1. `duration` trimmed; **empty or absent is refused** (`K::KeyDurationRequired`). This is the
   trap in the grammar: `parse_duration("")` is `Dur::Never`, so a field that went missing
   would otherwise mint a key that never expires. The form this replaced had exactly that hole
   (an emptied text field filed a non-expiring key); both surfaces now refuse it, which is the
   one break a hand-written client of these forms sees.
2. `days` non-empty while `duration` is not `custom` is refused (`K::KeyDaysWithoutCustom`:
   "you typed a number of days; choose Custom, or clear it"). The field is always visible, so
   a number typed beside the default 1 year is a choice the person thinks they made, and
   filing a year instead would be a silent substitution.
3. `custom`: `days` must parse with `parse_duration` to `Dur::Secs(n)` with `n > 0`, and must
   not be a spelling of never (`0`, `-`, `never`, which have their own radio). An all-digit
   value is stored with a `d`. Otherwise `K::KeyDaysInvalid` ("a whole number of days, at
   least 1").
4. Anything else is passed through as typed, so a hand-written `duration=30d` keeps working.
5. Then each surface's own check, unchanged in kind: the console's `key_expiry(released, d)`
   (`K::BadKeyWindow`); `/account/`'s `account_key_window_ok`, now **`Dur::Never`, or
   `Dur::Secs(s)` with `s >= ACCOUNT_KEY_MIN_SECS`** (one day). `ACCOUNT_KEY_MAX_SECS` is
   removed with its comment, which argued the opposite of the user's decision.

**No upper bound on custom days.** With "no expiry" on offer, a ceiling protects nothing: a
key of 36500 days and a key that never expires are the same credential, and refusing the first
while offering the second would be a rule with no reason. The grammar is the only limit:
`parse_duration` and `key_expiry` use checked arithmetic and answer `None` on overflow, which
step 3 or 5 refuses, and `format_date` of a far year prints a far year rather than failing
(`civil_from_days` is plain `i64` arithmetic, well inside range for any `u64` the grammar
yields; read, not measured). The "hours" a hand-written `/account/` `POST` might send stay
refused by the one-day floor, which keeps a self-service key from being a credential that dies
before anybody has used it.

**The console's free text survives as the custom field.** The console's custom field takes the
whole grammar (`40`, `40d`, `12h`), so nothing an administrator could express before is lost
except the empty-means-never accident; `never` is its own radio. On the edit form the choice is
read back from the stored string: exactly `365d`, `182d` or `91d` checks that preset, a never
spelling (`never`, `0`, `-`) checks no expiry, and anything else (`30d`, `365`, `8760h`) checks
custom with the stored string in the field, so the form shows what the file says rather than
the preset it happens to equal. Saving a key stored as `0` with no expiry checked writes
`never`, which `key_expiry` reads identically.

**`K` changes.** New: `DurOneYear`, `DurSixMonths`, `DurThreeMonths`, `DurCustom`, `DurNever`,
`DurDaysLabel`, `DurDaysHint`, `KeyDurationRequired`, `KeyDaysWithoutCustom`, `KeyDaysInvalid`,
`AccountKeyRemoveWarn`. Removed: `AccountKeyDurationHint` ("between 1 and 365 days"). Reworded:
`AccountKeyBound`, which loses its duration half (the id grammar is all it still has to say;
the duration errors are now their own keys, each naming its own fix). Refusals attach to the
`duration` field (`Refusal::on("duration", …)` in the console), so the fieldset carries the
invalid marking the other fields do.

**Rejected:**

- *A select instead of radios.* Five options fit on screen, a radio group shows them all
  without opening anything, and the custom field reads as belonging to the row before it.
  (Reversed by §13.16: in the table's new row a select and the days field share one line
  through the existing `.limit`, where five radio rows would be the tallest thing in it.)
- *Hiding the days field with `:has()` until custom is checked.* It degrades to visible where
  `:has()` is not supported, but where it is, a number typed and then hidden by a change of
  mind is still submitted, and step 2 would then refuse a value the person cannot see. An
  always-visible field plus step 2 has no invisible state.
- *Radio values as codes (`1y`, `6m`) translated server-side.* A second vocabulary for the same
  four strings, and every existing client posting `duration=30d` would need one more branch.

#### How it is shown to hold

Unit tests in `bb-auth-web.rs`:

- `the_copy_control_is_an_icon_with_a_name` (with `the_reveal_shows_only_the_key` updated): on
  the four reveal responses the button is the shared `pill ico` component (§13.17), is still
  `hidden` and `type="button"`, carries **no** `aria-label`, and its name is one `span.vh`
  inside it with the same words in `title`; it holds two `svg` each `aria-hidden="true"` and
  `focusable="false"` and naming no colour; a `span role="status"` follows it, empty; the words
  the click writes are `data-done` / `data-failed` attributes, never the control's text; no
  `style=` attribute appears in the block; the bearer still occurs once.
- `no_page_but_the_reveal_carries_a_script` unchanged, and still green with the new script's
  hash.
- `the_duration_choice_maps_onto_the_grammar`, on `duration_from_form` alone: the four presets
  come back verbatim; `custom`+`40` is `40d`, `custom`+`12h` is `12h`; empty or absent
  `duration` is `KeyDurationRequired`; `custom` with empty, `0`, `-`, `never`, `abc`, `40x`,
  `-3` and an overflowing number is `KeyDaysInvalid`; `365d`+`days=40` is
  `KeyDaysWithoutCustom`.
- `a_self_service_key_may_never_expire`: `/account/` mints with `never` (stored `never`, and
  `key_expiry` reads it as no expiry) and with `custom`+`366` (stored `366d`, a year and a day,
  read as one); refuses `custom` with `""`, `0`, `-3`, `never` and `abc`, and an empty
  `duration`, each with `400` and the file's bytes unchanged; a rotate of the never-expiring key
  leaves it without expiry. This replaces the case that refused `never` and `366d`.
- `the_key_form_offers_five_choices`: the `/account/` form and the console's add form carry one
  `fieldset` with a `legend`, five `name="duration"` radios with the values in the order above,
  `365d` checked, and a `days` input with an `aria-label`; the console's edit form for keys
  stored as `91d`, `0` and `8760h` checks 3 months, no expiry, and custom with `8760h` filled
  in. (Changed by §13.16: one `select name="duration"` with the five `option`s in that order and
  `365d` `selected`; the edit form marks the stored choice `selected`; on `/account/` the form
  is only on `GET <prefix>/keys/new`, not on the plain page.)
- `revoking_a_key_asks_first_on_the_account_page`: the page's revoke control is a `GET` form
  and no `POST` form to `<prefix>/keys/remove` remains on it; `GET <prefix>/keys/remove?id=laptop`
  is `200`, names `laptop`, carries a `POST` form to the same path with the file's current
  `rev` and the id, and leaves the file's bytes unchanged; an id on another row, an unknown id
  and no id are `404` naming nothing; a stranger is `403`, a denied caller `403`; the `POST`
  from that form removes the key. (Changed by §13.16 in its first clause only: the revoke
  control is a link to `<prefix>/keys/remove?id=laptop` among the row's destructive pills,
  named "Revoke key `laptop`" (as hidden text since §13.17, not an `aria-label`), not a `GET`
  form; the rest stands.)

E2E: `account.js` (scripting off) mints with 6 months and sees the expiry 182 days out, with
custom 40, and with no expiry and sees "never"; revokes through the confirmation, first
cancelling (the key is still listed) and then confirming (it is gone). `nojs.js`, on the
console reveal with scripting on: the icon is visible, its bounding box is at least 24 by 24,
a click shows the check glyph and the status text `K::CopyDone`, and the clipboard read equals
the key; with scripting off the icon is not visible. `shots.js` gains the reveal and the key
form, in both themes, which is the look no assertion can give.

### 13.16 The keys as a table, with a + row (plan step 8a, asked 2026-11-24)

What was read: `PLAN.md` steps 4 and 8, §13.6, §13.14 and §13.15, `src/bin/bb-auth-web.rs`
(`page_account`, `account_mint_form`, `account_key_forms`, `handle_account`,
`account_key_post`, `account_shell`, the console's `shell`, `page_user` and its keys table,
`act`, `act_rm`, `page_confirm`, `form_shell`, `text_field`, `url_list`, `expiry_markup`),
`src/assets/base.css`, `admin.css`, and the operator's token file as deployed on rpi-01 (a
copy, whose header promises custom properties on `:root` and nothing that selects a
component). What was looked at: the current `/account/` with no keys and with two, and the
console's person page, light, dark and at phone width; then mockups built only from the real
`theme.css`, `base.css` and `admin.css` plus the few rules listed under *What is new*, shot at
1280 px light and dark, at 360 and 320 px, each **twice**, with the built-in palette and with
the token file loaded after our CSS as `ui.stylesheet_url` does (throwaway, in
`/tmp/keysdesign/mock2/`: `account-*`, `account-error-*`, `account-full-*`,
`account-confirm-*`, `account-menu-*`, `console-after-*`, `header-console-before-*`; a `-tok`
suffix is the token-file run; network fetches were blocked, so the token file's web font was
not loaded and the typeface is the only token not seen). No page-level horizontal scroll at
360 or 320 px in any of them (measured on `scrollWidth`).

**The requests, 2026-11-24.** A table of key name, scopes and expiry, an × per row that
removes the key, and a + at the end that adds a row and so a key; interfaces simple enough to
read at a glance; and, later the same day, **reuse everything that already exists**: a new
component or rule only where nothing existing fits, each one argued below. This section was
first written with its own icon buttons, chips and table classes; that version is replaced by
this one, and every one of those inventions is gone.

#### The table: the console's own

`section#keys` holds the console's key table markup, the same `table`/`thead`/`tbody` with no
class, so the console's table rules, its row hover and its phone stacking all apply as they
are:

| Column | Header | Cell (all existing functions) |
|---|---|---|
| name | `K::KeyColName` "Name" | `td.mono` with the id, as the console's `id` cell |
| scopes | `K::Scopes` | `url_list(lang, k.scopes, K::KeyScopesAll)`: one `app/scope` per line in `ul.plain.mono`, or "all scopes" muted; the console passes its own operator wording (`KeyScopeInherit`) to the same function |
| expiry | `K::ColExpiry` | `expiry_markup` unchanged: "expires 2027-07-08 (225d)", or the `never expires`, `expires soon` and `expired` tags |
| actions | empty `th`, as the console's | `td.pills` holding `span.pills` with two row actions |

The header row reads "Name / Scopes / Expiry" where the console's reads "id / ... ": the
console labels by the file's field names on purpose, and this page is read by somebody who
has never seen the file. A pair the owner no longer reaches is marked inside `url_list`'s
line with the existing `tag warn` and the words `K::KeyScopeGone` ("no longer reached"), so
nothing is said by colour alone (WCAG 1.4.1,
<https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html>).

**The row actions are the console's row actions.** In the console a row is acted on by
`act` (an `a.pill`) and `act_rm` (an `a.pill.rm`), each a link to a `GET` page that changes
nothing. `/account/` does the same:

- `a.pill` reading `K::Rotate` ("rotate") to `<prefix>/keys/rotate?id=<id>`, with
  `aria-label` "`K::AccountKeyRotate` `<id>`" ("Rotate key laptop");
- `a.pill.rm` reading "×" to `<prefix>/keys/remove?id=<id>`, with `aria-label` and `title`
  "`K::AccountKeyRemove` `<id>`" ("Revoke key laptop"). (Superseded by §13.17's icon
  component: the × becomes `a.pill.rm.ico` with an SVG glyph and the name as hidden text.)

The × is the user's word for the control. As 4h decided it, the control was a text glyph
inside the existing pill, taking the pill's muted colour and its red hover from `base.css` and
its colour and shape from whatever token file is loaded, and needing no SVG and no icon-button
class; §13.17 swapped the glyph for that component's SVG and the visible word for hidden text,
and the colour argument stands untouched, since the component is a pill. The name carries
the id because ten links all called "Revoke key" are ten identical entries in a screen
reader's list of links (WCAG 2.4.6, <https://www.w3.org/WAI/WCAG22/Understanding/headings-and-labels.html>);
"rotate" keeps its visible word, which the longer name contains (WCAG 2.5.3,
<https://www.w3.org/WAI/WCAG22/Understanding/label-in-name.html>). The pill is about 26 px tall
and wider than 24 px, which meets WCAG 2.5.8's 24 by 24
(<https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html>), and the two have the
`.pills` gap between them. A link rather than 4h's `GET` form, because that is what the
console's `act_rm` is; the confirmation page is still the one that mutates.

**Rotate stays, as a text pill beside the ×** (approved by the user). It must stay possible
and confirmed: step 4 is not done until a person rotates a key in a browser, and a rotate is
the one way to replace a leaked secret while keeping the name and the restriction byte for
byte, which removing and re-adding would make the person re-tick from memory.

**The confirmation pages are the console's `page_confirm`.** Its markup is `h1` (what), a
`p.lede` (what that means), a `div.panel.bad` holding the object and a `form.edit` with
`div.actions`: a submit (`button.danger` for a revoke) and a `cancel` pill. Both
`GET <prefix>/keys/remove?id=` (4h) and `GET <prefix>/keys/rotate?id=` render exactly that,
inside `account_shell`. The pair used to take a console `View` for three things (the form's
action, `rev`, the cancel link); `page_confirm_at` and `form_shell_at` take those three values
instead, and `page_confirm` and `form_shell` are the console's one-line calls of them, so one
function renders both surfaces' confirmations. Texts:
`K::AccountKeyRemoveWarn` (4h) and `K::AccountKeyRotateWarn` ("A new secret replaces this one.
Anything still using the old one stops getting in within seconds. The name and the scopes
stay; the expiry starts again from today."), the last clause because `rotate_api_key` stamps a
new `released`. Doors and `404`s as §13.15 states for the revoke. Screenshot:
`account-confirm-*.png`.

**Empty state.** With no keys there is no table, as in the console (`page_user` shows a muted
line instead): `p.muted` with `K::AccountKeysNone` reworded to "No API keys yet.", then
the + below it.

#### The + row

Under the table, the console's add control: `p.primary` holding `a.pill` "+ New key"
(`K::AccountKeyNew`, approved by the user), to `GET <prefix>/keys/new`. The console puts its
`p.primary` above a table; here it is below, because the user asked for the + at the end and
because the row it opens appears there.

`GET <prefix>/keys/new` renders the same page with the `p.primary` gone and **one more
`tbody` row**: a single `td colspan="4"` holding a `form.edit`, which is the console's own
form furniture, posting to `<prefix>/keys`. A `form` may not wrap a table row, but it may sit
inside a cell, so no `form` attribute is needed. Inside it, in order, all existing pieces:

- `text_field` for the name (label `K::KeyColName`, `name="id"`, placeholder `laptop`, hint
  `K::AccountKeyIdHint`), plus `required`, `maxlength="32"`, `pattern="[a-z0-9-]{1,32}"` and
  `autofocus`. `pattern` and `required` are the browser's constraint validation and need no
  script; MDN asks for the format to be stated in visible text, which the hint does
  (<https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/input>). The server
  checks everything again.
- The restriction as the current mint form has it, `span.lbl` and `label.radio` rows
  (`form.edit .radio`): "all scopes" (`K::KeyScopesAll`) checked, "only these:"
  (`K::KeyScopesOnly`), then a checkbox row per `key_scopes_for` pair in `code`. Absent when
  there is nothing to narrow to, as today. Not one list where none ticked means all: the
  widest key by omission is what the handler deliberately refuses.
- The duration: `span.lbl` `K::KeyColExpires` ("Expires") and the existing `span.limit` row
  holding `duration_choice`'s `select name="duration"` ("in 1 year" `365d` selected, "in 6
  months" `182d`, "in 3 months" `91d`, "after a number of days" `custom`, "never" `never`)
  and the `days` input (`aria-label` `K::DurDaysLabel`, placeholder "days").
- `div.actions`: `button` `K::AccountKeyCreate` and the `cancel` pill back to the page, which
  is `form_shell`'s own ending.

No fragment on the + link: `autofocus` puts the person in the name field and scrolls to it,
and MDN states that a fragment in the URL wins over `autofocus`
(<https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Global_attributes/autofocus>).
Its warning that a screen reader "teleports" does not bite: the person just pressed "New
key", and its first field is where that press asked to go.

**Errors (`400`)** are `form_shell`'s: the refusal's sentence in `div.err#ERR_ID` at the top
of the form, the field it is about marked by `text_field`'s `invalid` (red border,
`aria-invalid`, `aria-describedby` pointing at the message), and every value as posted (name,
radio, ticks, option, days). Which field: the id bound and `AccountKeyDup` on `id`; the
duration refusals of §13.15 on `duration`; `AccountKeyUnknownScope` and the new
`KeyScopesWithoutOnly` ("You ticked scopes; choose 'only these', or untick them.") on the
restriction, with no field marked since a radio group has no `invalid` style;
`AccountKeyFull` on none. WCAG 3.3.1 and 3.3.3 ask for the error to be identified in text and
the fix suggested (<https://www.w3.org/WAI/WCAG22/Understanding/error-identification.html>,
<https://www.w3.org/WAI/WCAG22/Understanding/error-suggestion.html>); each message names its
fix. `409`, `403` and `500` keep their own pages. `KeyScopesWithoutOnly` is the twin of
§13.15's `KeyDaysWithoutCustom`: ticks beside "all scopes" are a choice the person thinks they
made, and today the handler drops them and files the widest key. Screenshot:
`account-error-*.png`.

**The 10-key bound.** At ten keys the `p.primary` is replaced by `p.muted`
`K::AccountKeyFullRow` ("An account holds at most 10 keys. Revoke one to add another."); `GET
keys/new` shows the same sentence and no row. Not a disabled control: it is skipped by the
keyboard and says nothing about why. Screenshot: `account-full-*.png`.

**JavaScript: none.** Links, `GET` pages and `POST` forms only.

#### What the console gains, and what stays its own

The parts are now literally shared: `url_list`, `expiry_markup`, `page_confirm`, `form_shell`,
`text_field`, `duration_choice`, `.pill` / `.pill.rm`, `p.primary`, the table. The console
keeps its columns (released and duration matter to an operator), its `edit` action and its
separate add page with fields a person never sees. The console's `remove` pill could read "×"
too; that is left to the user, since it would change every console table at once.

#### Phone width

Nothing new: the existing phone block stacks every table row into a card with `data-label`
headings, and the new row is one full-width cell holding a form, which already stacks.
Screenshot: `account-*-phone.png`, `account-*-p320.png`. WCAG 1.4.10 asks for no
two-dimensional scrolling at 320 CSS px (<https://www.w3.org/WAI/WCAG22/Understanding/reflow.html>),
and stacked cards need no exception.

#### What is new, and what was tried first

- **`td.pills`, replaced in place** (both surfaces): today `td.pills{display:flex;...}`. A flex
  `td` is no longer a table cell, so its bottom border stops short of the row whenever another
  cell wraps to two lines; the mockup showed it on every wrapped row, and the console has the
  same defect waiting for a long cell. The replacement keeps the cell a cell and puts the
  no-wrap where the pills are: `td.pills{text-align:right;white-space:nowrap}` and
  `td.pills .pills{flex-wrap:nowrap}`, with `text-align:left` in the phone block where today's
  rule has `justify-content:flex-start`. The markup gains a `span.pills` inside the cell,
  which is the existing group component. Tried first: leaving the rule (the defect stays) and
  `span.pills` alone in a plain `td` (the pills then wrap onto two lines in a narrow column).
- Nothing else in this section. Dropped from the earlier version: `table.keys`, `tfoot`
  styling, `tr.new`, `.field-error`, `.keys-full`, and the three phone rules, each replaced by
  the existing piece named above. `.icon-btn` is gone as a class, and its glyph and its hidden
  name stayed: the slice shipped them as the shared `.pill.ico` component and `.vh` in
  `base.css`, which is what §13.17 asks for, since the × is an icon whose name a reader speaks
  and no browser shows.

Removed with the markup that needed them: `.selfserve .keyact`, `.selfserve form.edit h2`.

#### `K` changes

New: `KeyColName`, `KeyColExpires`, `KeyScopesAll` ("all scopes", "tutti gli ambiti"),
`KeyScopesOnly`, `KeyScopesWithoutOnly`, `KeyScopeGone`, `AccountKeyNew` ("+ New key",
"+ Nuova chiave"), `AccountKeyFullRow`, `AccountKeyRotateWarn`. Reused: `Scopes`,
`ColExpiry`, `Rotate`, `Cancel`, `AccountKeyRotate`, `AccountKeyRemove`, `AccountKeyCreate`,
`AccountKeyIdHint`. Reworded: `AccountKeysNone` ("No API keys yet."), the five `Dur*` of
§13.15 ("in 1 year" and so on). Removed: `AccountKeyIdLabel`, `AccountKeyDurationLabel`,
`AccountKeyRestrict`, `AccountKeyScopeGroups`, `AccountKeyRestrictAll`,
`AccountKeyRestrictSome`, `AccountKeyAllScopes` (replaced by `KeyScopesAll`). `AccountKeyAdd`
stays as the refusal pages' title.

#### How the table is shown to hold

- `the_keys_are_the_consoles_table`: for a row with keys, `section#keys` has one `table` with
  four `th` (the last empty), one `tbody tr` per key, the id in a `td.mono`, `KeyScopesAll`
  or the pairs, `expiry_markup`'s words; no URL in the section; with no keys, no `table` and
  the `AccountKeysNone` line.
- `each_key_row_acts_like_a_console_row`: per key, a `td.pills` holding an `a.pill` to
  `keys/rotate?id=<id>` with the verb-plus-id `aria-label`, and an `a.pill.rm.ico` (the shared
  icon component, §13.17) to `keys/remove?id=<id>` named by text inside it and a `title`, with
  no `aria-label` so the two names cannot drift; no `form` on the plain page that is not a
  `GET`.
- `the_new_key_row_is_a_page_of_its_own`: the plain page has the `+ New key` link and no input
  named `id`; `GET keys/new` is `200`, has no such link, and has one `td colspan="4"` holding
  a `form.edit` posting to `keys` with `rev`, the `id` input carrying `autofocus`, `required`,
  `pattern`, one `select name="duration"` with the five options, `365d` selected; a
  stranger's page has neither.
- `a_refused_key_keeps_the_row_and_says_where`: `id=My Laptop` answers `400` with the row open,
  the value kept, `div.err` with the message, the input `aria-invalid="true"`; ticks with
  `restrict=all` give `KeyScopesWithoutOnly`; the file's bytes unchanged.
- `the_tenth_key_closes_the_row`, and `rotating_a_key_asks_first_on_the_account_page` (the twin
  of 4h's revoke test, including `scopes` byte for byte after the `POST`).
- `page_confirm_renders_both_surfaces`: the console's key revoke page is byte-identical to
  today's after the refactor.

E2E (`account.js`, scripting off): `+ New key`, a bad id refused by the field with the value
kept, a mint with "in 6 months", Back shows the row, rotate and revoke through their
confirmations (cancelling once first). `shots.js` gains `account`, `account-new`,
`account-error`, `account-rm`.

#### Impact on the 4h tests

- `the_copy_control_is_an_icon_with_a_name`, `the_duration_choice_maps_onto_the_grammar`,
  `a_self_service_key_may_never_expire`: this section left them alone, and the shipped slice
  moved the first with the icon component: the copy control's name is hidden text and it
  carries no `aria-label` (§13.17). The other two post the values §13.15 states.
- `the_key_form_offers_five_choices`: one `select` with five options, `365d` selected, plus
  the `days` input; on `/account/` read from `GET keys/new`.
- `revoking_a_key_asks_first_on_the_account_page`: the control is the row's icon link
  (`pill rm ico`, §13.17), not a `GET` form; the confirmation and the `POST` are unchanged.
- `e2e/tests/account.js`: the mint opens `keys/new` first and uses `selectOption` for the
  duration; the `form[action="/account/keys"]` selector still finds the inputs.

#### Rejected

- *Own icon buttons, chips, a `table.keys` class, an in-row field per column.* All tried in
  the first version of this section and all replaced by existing pieces; the per-column row
  also needed the `form` attribute and squeezed every field at the page's 620 px.
- *A disabled + at ten keys*, *a `details` for "only these"* (its summary cannot change
  without a script), *none ticked meaning all*, *opening the row with a script*.

### 13.17 The account page as a whole, and the one header (plan steps 8b and 8c)

The user asked for the whole page to be better, then for "a header with the user's info, the
classic settings and sign out, not that thing at the end of the page", then for everything to
reuse what exists, then allowed the console's header itself to be revised if it was not good
enough, for both surfaces at once, then required that the operator's theme keep working
(rpi-01: `brand_name` "BadBat75", a logo, `theme` system, and the token file as
`stylesheet_url`). Mockups as in 13.16.

#### The header: the console's, shared

`/account/` gets the console's header, the same markup from one function: `shell`'s
`header.top > div.bar` is factored out as `top_bar(brand, tabs, acct)` and both `shell` and
`account_shell` call it. Every class is existing: `header.top`, `.bar`, `.brand`, `nav`,
`nav.acct`, `details.settings`, `summary.pill`, `.menu`, `form.edit`, `.actions`, `.pill`.

| Slot | Console | `/account/` |
|---|---|---|
| brand | `a.brand` "bb-auth-web" plus version, links home. (Changed by §13.18: `ui.brand_name`, else `bb-auth`, over `K::ConsoleTag` ("Administration" / "Amministrazione"), still a link; the version is the footer's alone. Changed by §13.34 §10: no tag line, the name alone, still a link) | `span.brand.selfserve-brand`: the `ui.logo_url` image (when set) and `ui.brand_name`, where the page shows them today; not a link, since the page is the only one |
| tabs | the five `nav` pills | an empty `nav`, which is what the console's own `403` page already renders |
| identity | **new**: `span.who.muted` in `nav.acct`, the address | the same: the given name and the first address ("Bot · `bot@example.com`"), or the address alone |
| Preferences | `details.settings` "Preferences" (`K::Settings`), Language then Theme, `onchange` applies, `noscript` Apply | the same `details` and `.menu` and order, **no `onchange`**, and the Apply `button` in `div.actions` always present (Changed by plan step 13, 2026-11-26: the same `onchange` and the same `noscript` Apply, both shells emitting one `prefs_form`) |
| Sign out | `a.pill` to `BB_AUTH_WEB_LOGOUT_URL`, absent when unset | the same pill and the same setting, with its `rd` dropped (below) |

**Where they differ, and why.** The account page carries no handler at all (AGENTS.md, the
self-service paragraph) and its policy has no `'unsafe-hashes'`; the console's handler only
saves one click and its `noscript` button already shows the shape that works without it. So
the account's menu is the console's menu as a browser with scripting off sees it, and the
write stays as today: one submit, one `302` that sets the `theme` and `lang` cookies, the same
names the console writes. The form's `action` is the account page. The brand slot shows the
operator's brand because this page is the operator's estate seen by a person, while the
console names the tool to its administrators. (Changed by §13.18: the console's bar names the
deployment the same way, over a line saying what that surface is, so the sentence's second half
no longer holds; the reason for the first half stands. Changed again by §13.34 §10: the line
saying what the surface is went too, so both bars now show the brand alone.) (Changed by plan step 13, 2026-11-26:
the first sentence describes what was built then, not the page as it stands. The user asked for
fewer clicks, so the account menu carries the console's handler, its policy admits that handler
by the same hash (`page_script_src` is one function for both surfaces), and Apply is the
`noscript` fallback here exactly as it is there. The write is unchanged: one `GET`, one `302`,
the same two cookie names, and the page still works with scripting off through that button.)

**The identity, added to the console too.** Today the console says who is signed in only in
its footer, below the fold on a long page; Nielsen's first heuristic (visibility of system
status) puts "who am I acting as" where the session controls are. It goes in `nav.acct`
before Preferences, muted, as text and not a control, and is also the first line of the
Preferences panel (`p.lede`), which is where it remains on a phone. The console's footer drops
its "signed in as" (one home for the fact) and keeps the version. The given name comes from
the forwarded profile claim `given_name` when the deployment configures it, else nothing is
shown but the address. Screenshots, before and after:
`header-console-before-{light,dark,phone}.png` and `header-console-before-menu-*.png`, then
`console-after-*.png` and `console-after-menu-*.png`.

Nothing else in the console header changes: on the comparison its controls are legible, the
menu works without a script, and the one weakness seen (the fifth tab clipped at 360 px, with
only a horizontal scroll to reach it) is the tabs' own and not part of this request; it is
named here for a later look.

**Phone.** The existing phone block applies: one line holding the brand and the two pills.
The identity in the bar gives way there (it would push the bar to a second line) and is read
at the top of the menu; on `/account/` the page body names the person anyway.
Screenshots: `account-menu-tok-phone.png`, `console-after-phone.png`.

**Sign out on `/account/`: the operator's link with its `rd` dropped (decided for 8b).** The
code paths, read before deciding: `Config::logout_url` is `BB_AUTH_WEB_LOGOUT_URL` passed
through `compile_asset_url` once at startup, and `shell` emits it verbatim as the pill's
`href`; the gate's `/auth/logout` lands where `logout_target` says, which is `rd_candidate`
(the `?rd=`, else the `Referer`) through `safe_rd`, and the login page when neither spoke. So
the `rd` an operator writes on that variable is the console's round trip, and on `/account/` it
would bring a person who is not an administrator to a `403`. The account page therefore renders
the **same variable with its `rd` query parameter removed**, derived once at startup beside
`Config::logout_url` (`Config::account_logout_url`, from a pure `logout_without_rd`): every
other parameter, the path and the host are kept as the operator wrote them, a value with no
`rd` is used unchanged, and an unset variable is no pill on either surface. The person signs
out, lands on the sign-in page and stops there, which is the destination the variable's own
documentation already calls honest for somebody who just ended their session; signing in again
from there lands where any sign-in without an `rd` lands (`safe_rd`'s default), which is the
gate's existing behaviour and not something this page adds.

Why this keeps every invariant: the link can only lose a parameter, never gain one, so it names
no landing place the operator did not already write, and the gate's `safe_rd` against
`gate.authorized_hosts` still decides where any logout may land. No setting is added, so the
three-part rule for the settings file is not asked. The `Referer` is **not** what brings the
person back, and the design must not lean on it: every page of this program carries
`Referrer-Policy: no-referrer` (`PAGE_SECURITY_HEADERS`), so a click on `/account/` sends none
and `logout_target` falls through to the login page, which is the intended result rather than a
backup that happens to work.

Rejected: **a second variable** naming the account's round trip (`BB_AUTH_WEB_ACCOUNT_LOGOUT_URL`
or a `web` field in the settings file), which would buy only "after signing in again, land on
`/account/`", a need nobody has stated, for one more value an operator must keep in step with
the first; **rewriting the `rd`** to the account page, which this program cannot do honestly,
since it knows neither its scheme nor its host (the reason the variable exists) and the
operator's `rd` may name a page that is not the console at all; **a relative `rd`** to the
account path, which `safe_rd` resolves against `BB_AUTH_ORIGINAL_URL_HEADER`, a header nginx
does not set on the ungated logout location, so it would fall back to the login page anyway and
silently; **relying on the `Referer`**, absent here by our own policy; **the same link
unchanged**, which is the `403`.

How it is shown to hold: `logout_without_rd_keeps_everything_else` (unit, on the pure
function: `/auth/logout?rd=https%3A%2F%2Fa.x.com%2Fadmin%2F` becomes `/auth/logout`;
`https://a.x.com/auth/logout?x=1&rd=…` becomes `https://a.x.com/auth/logout?x=1`; a parameter
merely starting with `rd`, such as `rdx=1`, is kept; a value with no query is returned as it
is) and `the_account_sign_out_carries_no_rd` (over a socket, with `BB_AUTH_WEB_LOGOUT_URL`
carrying an `rd`: the console's Sign out `href` is the value as written, the account page's is
the value without its `rd`, and with the variable unset neither page has the control).

**One `h1` on the account's confirmation (from the designer's review of 8a).** Today
`account_shell` writes `h1` with the page's title on every page and `page_confirm_at` writes a
second one with the action, so a rotate or a revoke confirmation reads "Your account" then
"Revoke key". It fits the header: once the bar carries the brand and the identity, "whose
account is this" is answered above the page, and the confirmation reads as the console's
already does, where the `h1` is the action and the bar says where you are. So
`page_confirm_at` is split into its card (the `p.lede` and the `.panel.bad` with the form,
`confirm_card`) and its heading, the console keeping both through `page_confirm_at`
unchanged, and `page_account_confirm` returns only the card while its caller passes the action
word (`K::AccountKeyRotate`, `K::AccountKeyRemove`) as the shell's title, so the one `h1` and
the `<title>` both name the action. Every other page under the prefix keeps the shell's one
`h1`. Test: `the_account_confirmation_has_one_h1` (both operations, exactly one `<h1>`, whose
text is the action word, and the `<title>` ends with it).

#### The body

- `h1` `K::AccountTitle`, then one `p.lede`: every address in `code`, and on a second line
  `K::AccountIdLabel` ("Account id") and the uuid (approved by the user). A stranger's
  `p.lede` carries the address and `K::AccountNoRow` instead of the uuid. (Changed by plan
  step 13, 2026-11-26: a caller with no roster row gets the addresses alone. The second line
  names an id, so with no id to name the line and its `br` go, in both languages, and
  `K::AccountNoRow` is deleted with its sentence: the page writes no words standing in for a
  row the file does not have.)
- (Changed by §13.26: the order is now `#profile`, `#keys`, `#groups`, `#reach`, the user's
  decision of 2026-11-25, and the profile sub-line is reworded.) The four sections keep their
  ids and order (`#reach`, `#groups`, `#keys`, `#profile`): each
  a `.panel` with `h2` and one `p.lede.sub` saying what it is for (the class the console's
  sections already use for this): `K::AccountReachSub`, `K::AccountGroupsSub`,
  `K::AccountKeysSub`, `K::AccountProfileSub` (texts as listed below).
- Where you reach: `ul.plain` of `code` `app/scope`, the console's own person-page list.
- Groups: `ul.plain` of `code`. Heading `K::AccountGroups` ("Groups").
- API keys: §13.16.
- Profile: `ul.plain`, `code` claim, then the value, or `span.muted` `K::AccountNotProvided`
  ("not provided") where the deployment configured a claim that was not forwarded. Step 5's
  edit goes here.
- Delete my account (step 7) will be a last `.panel.bad`, after Profile (changed by §13.26:
  after Where you reach, which is now the last section).
- Empty states name what is missing, each a `p.muted`: `K::AccountReachNone` ("Your sign-in
  opens no application yet."), `K::AccountGroupsNone` ("You are in no group."),
  `AccountKeysNone`, `K::AccountProfileNone` ("This deployment shares no profile details.").
- The theme and language form at the foot is gone; it is the header's Preferences.

Sub-line texts: reach "The applications your sign-in opens, and the areas inside each.";
groups "Groups an administrator has put you in."; keys "A key lets a script or a tool sign in
as you. It reaches at most what you reach."; profile "What your sign-in tells these
applications about you." (Italian in the `K` table.)

**The body's markup, exactly (8c-1).** All in `page_account`; every class exists.

- The lede: `p.lede` holding each address as `code`, separated by one space, then `br`, then
  `K::AccountIdLabel` `": "` and the uuid in `code`; for a stranger, after the `br`,
  `K::AccountNoRow` as plain text. (Changed by plan step 13, 2026-11-26: the `br` travels with
  the id, so a caller with no row gets the `code` addresses and nothing after them.) The old
  `p` "signed in as" and the separate uuid `p` go:
  the bar already says "signed in as" (§13.17 header), and the lede says which addresses and
  which account.
- Each section: `section#<id>.panel` > `h2` > `p.lede.sub` > content.
- Where you reach: one `ul.plain`, one `li` per pair holding `code` `app/scope`, in
  `account_reached`'s order (file order). The per-application `p` and nested `ul` go: the
  console's person page lists pairs the same way, and one flat list reads at a glance.
- Groups: `ul.plain`, one `li` > `code` per group. The heading becomes `K::AccountGroups`
  ("Groups"), not the console's `K::Groups` ("User groups"), which names the file section.
- Profile: `ul.plain`, one `li` per claim: `code` claim, `": "`, then the decoded value as
  plain text, or `span.muted` `K::AccountNotProvided`. The value is the person's name or
  department, which is prose, not code.
- Empty: `p.muted` with the section's own `*None` key. `K::AccountNone` ("None.") then has no
  caller and is removed.

Italian for the body's keys (English above): `AccountIdLabel` "Id dell'account";
`AccountGroups` "Gruppi"; `AccountReachSub` "Le applicazioni a cui il tuo accesso apre la
porta, e le aree dentro ciascuna."; `AccountGroupsSub` "I gruppi in cui ti ha messo un
amministratore."; `AccountKeysSub` "Una chiave permette a uno script o a uno strumento di
accedere come te. Arriva al massimo dove arrivi tu."; `AccountProfileSub` "Cosa il tuo accesso
dice di te a queste applicazioni."; `AccountNotProvided` "non fornito"; `AccountReachNone` "Il
tuo accesso non apre ancora nessuna applicazione."; `AccountGroupsNone` "Non sei in nessun
gruppo."; `AccountProfileNone` "Questa installazione non condivide dettagli del profilo.".
`AccountUuid` is removed (replaced by `AccountIdLabel`).

Tests (8c-1): `the_lede_names_the_addresses_and_the_account_id` (a row with two addresses:
one `p.lede` before the first section, both addresses in `code`, `Account id: <uuid>`; a
stranger: the address and `AccountNoRow`, no uuid; no "signed in as" in `main`). (Changed by
plan step 13, 2026-11-26: the stranger's half is now the address, no `<br` anywhere in the
lede, no `code class="uid"`, and neither language's old no-row sentence; the words of that
sentence live in the test as constants, since the key they used to read is deleted.);
`each_section_says_what_it_is_for` (each of the four sections has exactly one `p.lede.sub`
right after its `h2`, with its key's text, in both languages); `empty_sections_name_what_is_missing`
(a stranger with no groups and a deployment with no claims: the three `*None` sentences in
`p.muted`, and `None.` nowhere); `the_sections_are_plain_lists` (reach, groups and profile
each a `ul.plain`, reach items read `app/scope`, a configured but unforwarded claim shows
`span.muted` "not provided"). The existing `account_the_reach_section_…`,
`account_the_groups_section_…`, `account_the_profile_section_…` and
`account_a_stranger_…` tests change to the flat `app/scope` form and the new words.

#### The key form's refusals, the days box and the restriction (8c-2, from the review of 8a)

**One refusal, one fact.** `K::AccountKeyBound` says two things ("a key id is … and a key
lasts at least a day") whichever field was wrong, so a person who typed `My Laptop` reads
about durations. It is split, and removed:

| Key | Field marked | English | Italian |
|---|---|---|---|
| `AccountKeyIdBad` | `id` | A key name is lowercase letters, digits and dashes, up to 32 characters, such as laptop. | Il nome di una chiave è fatto di lettere minuscole, cifre e trattini, fino a 32 caratteri, per esempio laptop. |
| `AccountKeyTooShort` | `duration` | A key must last at least a day; choose a longer duration. | Una chiave deve durare almeno un giorno; scegli una durata più lunga. |
| `KeyScopesChoose` | none | Choose 'all scopes' or 'only these'. | Scegli 'tutti gli ambiti' o 'solo questi'. |

The message says "name" because the field is labelled `K::KeyColName` ("Name") since 8a; the
file's word `id` is not on this page. `KeyScopesChoose` answers the third former use of
`AccountKeyBound` (a `restrict` that is neither `all` nor `some`), which only a hand-written
`POST` sends; a sentence that names the two choices is still the honest answer to it.

**Surfaces.** `/account/` only: the console never used `AccountKeyBound`, and its own id and
duration refusals are the library's words, verbatim, by design (`form_shell_at`). The two
duration refusals `duration_from_form` answers on **both** surfaces are made sentences too,
because they sit beside `KeyDurationRequired`, already one, in the same box:
`KeyDaysWithoutCustom` "You typed a number of days; choose 'after a number of days', or clear
it." / "Hai scritto un numero di giorni; scegli 'dopo un numero di giorni', o cancellalo."
(it named an option "Custom" that no longer exists: the option reads `K::DurCustom`), and
`KeyDaysInvalid` "Write a whole number of days, at least 1." / "Scrivi un numero intero di
giorni, almeno 1.". The account page's other refusals become sentences with a capital and a
period, words unchanged otherwise: `AccountKeyFull` "This account has ten keys, which is the
most this page mints." / "Questo account ha dieci chiavi, il massimo che questa pagina crea.",
`AccountKeyDup` "This account already has a key with that name." / "Questo account ha già una
chiave con quel nome." ("name", for the label's reason), `AccountKeyUnknownScope` "A scope you
picked is not one a key of yours can reach." / "Uno degli ambiti scelti non è uno che una tua
chiave può raggiungere." ("ambiti", the word the form's radios use). WCAG 3.3.1 and 3.3.3:
the error is identified in text and the fix is named
(<https://www.w3.org/WAI/WCAG22/Understanding/error-identification.html>,
<https://www.w3.org/WAI/WCAG22/Understanding/error-suggestion.html>).

**The days box.** Today the box sits beside the select with the hint "days" alone on the line
below it, which reads as a caption of the whole row. `duration_choice` takes the box's
placeholder and an optional hint: `/account/` passes placeholder `K::DurDaysHint` ("days",
"giorni") and no hint, so no `span.hint` is rendered; the console passes no placeholder (no
attribute) and its hint `<n>d · <n>h` unchanged, because its box takes the whole grammar and a
placeholder of "days" would be a lie about `12h`. The box keeps its own name as an
`aria-label`, since a placeholder is not a label (MDN,
<https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/input#placeholder>) and
the wrapping `label` labels only its first labelable descendant, the select
(<https://html.spec.whatwg.org/multipage/forms.html#the-label-element>). `K::DurDaysLabel` is
reworded to "Number of days" / "Numero di giorni" on both surfaces: it echoes the option the
person picked ("after a number of days") and contains the placeholder's word, where "Custom
duration" named nothing on screen (WCAG 2.5.3,
<https://www.w3.org/WAI/WCAG22/Understanding/label-in-name.html>). The placeholder is painted
`--muted` by `base.css`, the colour every hint already uses. Trade-off: a placeholder
disappears once the person types; here that costs nothing, because what was typed is a number
and the select beside it still says "after a number of days".

**The restriction, left out when there is nothing to narrow to.** `account_key_row` already
drops "only these" when `key_scopes_for` is empty, but still shows the "Scopes" label and a
lone checked radio "all scopes": a choice of one. With nothing to narrow to, the whole `div`
(the `span.lbl` and the radio) is not rendered, and the form carries
`input type="hidden" name="restrict" value="all"` in its place, so the handler is unchanged
and still refuses a request that chose nothing. The section's sub-line already says a key
reaches at most what its owner reaches. With pairs to offer, the block is as today.

Tests (8c-2): `a_bad_key_name_is_refused_without_naming_the_duration` (`id=My Laptop`:
`400`, `div.err` is `AccountKeyIdBad` and contains neither "day" nor "giorn", the `id` input
`aria-invalid="true"`, the select not; the file unchanged);
`a_too_short_key_is_refused_without_naming_the_name` (`duration=custom`, `days=12h`:
`AccountKeyTooShort`, the select `aria-invalid="true"`, the `id` input not);
`the_account_refusals_are_sentences` (unit, over the account form's refusal keys and the
three `Key*` duration keys, both languages: first letter uppercase, last character `.`);
`the_days_box_has_a_placeholder_and_its_own_name` (on `GET /account/keys/new`, `en` and `it`:
`input[name=days]` has `placeholder` "days"/"giorni" and `aria-label` "Number of days"/"Numero
di giorni", and the form has no `span.hint` reading "days"; on the console's key add page the
box has no `placeholder` and the hint `<n>d · <n>h` is there);
`a_key_with_nothing_to_narrow_has_no_scope_choice` (a caller whose `key_scopes_for` is empty:
no `input[type=radio][name=restrict]`, no "all scopes" in the form, one hidden `restrict=all`;
posting the form as rendered mints a key with no `scopes`; a caller with pairs still gets both
radios). `a_refused_key_keeps_the_row_and_says_where` changes to the new key, and the test's
list of `K` names drops `AccountKeyBound` and gains the three new ones.

#### The console's 403, and the menu scene (8c-3, from the review of 8b)

**Who lands there.** Any signed-in person who opens `/admin/`, for example from an old bookmark
or a link an administrator shared. Today the page says, in a red panel, that their address is
not an administrator, and offers nothing but the two icons; the bar names nobody, because
`shell_as` takes the identity from `v.admin`, which is `None` here. Screenshot of today:
`e2e/artifacts/visual/light/forbidden.png`.

**The identity in the bar.** `shell_as` is split: `shell_named(v, who: Option<String>, title,
content)` renders the page with the bar's identity as given, and `shell_as` becomes the
one-line call `shell_named(v, v.admin.map(|a| identity_label(given_name, a)), title, content)`,
so every console page is byte for byte as today. The `403` branch calls
`shell_named(&v, Some(identity_label(given, &who)), …)`, `who` being the identity header as
received (first address, given name when configured), so the bar and the menu's first line say
who is signed in, as on every other page (Nielsen 1, visibility of system status). Tabs stay
an empty `nav` and the brand an inert `span`, as today.

**A way forward.** After the red panel, the console's add control: `p.primary` > `a.pill`
`K::NotAdminToAccount` ("Go to your account", "Vai al tuo account") to `Config::account_path`
plus `/`. Nielsen 9 (help users recognise, diagnose and recover from errors): the page now says
what the person can do instead. A pill and not a sentence link because it is the one action on
the page. The panel's sentence is unchanged. Sign out stays the console's full
`BB_AUTH_WEB_LOGOUT_URL`, with its `rd`: on this page it is the way to sign in as somebody
else, an administrator, and come back here.

Test (8c-3): `the_console_403_names_the_caller_and_links_to_their_account` (over a socket,
`you@example.com`, not an administrator: `403`; `nav.acct span.who` and the menu's first
`p.lede` read the address; with `given_name` configured and forwarded, "Name · address"; with
two addresses in the header, the first; one `p.primary a.pill` whose `href` is `/account/` and
whose text is `NotAdminToAccount`, in both languages; the `nav` before `nav.acct` is empty);
`icon_controls_are_named_by_hidden_text` keeps passing on the `403`.

**The menu scene.** `e2e/shots.js` gains `account-menu`, next to `account`: `asPerson`, `goto`
`/account/`, `click('details.settings > summary')`, `asAdmin`; added to the `it` view's `only`
list. It is the one place the account menu's always-present Apply is seen in review. The phone
view runs it with no change, since that view takes every scene. Check: `node e2e/shots.js
account-menu` writes `{light,dark,phone,it}/account-menu.png`, and the image shows the menu
open with the identity line, both list boxes and Apply. (Changed by plan step 13, 2026-11-26:
the Apply is behind `noscript` on this surface as it is in the console, so a scripting view
shows the identity line and the two list boxes and no button, and the scene's own comment says
as much; the `noscript` view is where the button is seen in review, and `nojs.js` is where
pressing it is checked on both surfaces.)

#### Icons instead of words: one component (asked 2026-11-24)

The user: "let's start using some icons instead of buttons (settings and logout, for
example)". Mockups redone in `/tmp/keysdesign/mock2/` (`account-*`, `account-menu-*`,
`console-after-*`, `console-after-menu-*`, light, dark, phone, 320 px, each with and without the
token file); target sizes measured in them: 39 by 39 CSS px in the desktop bar, 30 by 30 on a
phone and in a table row.

**The component is the pill, squared.** `.pill` already is the estate's outline control: its
border, its accent colour, its hover, its `.rm` red hover, its `:focus-visible` ring from
`base.css`. An icon button is that object with a glyph instead of a word, so it is
`class="pill ico"` (and `pill rm ico` for a destructive one) and adds only what a glyph needs.
In **`base.css`**, because both programs emit it and the gate's pages may want one later:

- `.pill.ico{justify-content:center;padding:4px;min-width:24px;min-height:24px}`: the pill's
  own vertical padding on all four sides, so an icon is exactly as tall as a text pill beside
  it and square; the minimums are WCAG 2.5.8's 24 by 24
  (<https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html>).
- `.pill.ico svg{width:1.45em;height:1.45em;fill:none;stroke:currentColor;stroke-width:2;
  stroke-linecap:round;stroke-linejoin:round}`: the glyph is the pill's line height, and
  `currentColor` is what lets the palette, the hover and a token file paint it with no token
  of its own.
- `.vh`, the visually hidden text utility (`position:absolute; width:1px; height:1px;
  overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; border:0`). Looked for first: there
  is none; the phone block hides `thead` with the same declarations inline, which is the one
  other place that needed it.

In **`admin.css`**, one added rule: `.bar .pill.ico{padding:7px}`, with `padding:4px` inside the
phone block, because the bar's own `.bar .pill` sets `7px 15px` and an icon there must be
square at the bar's height. Looked for first: excluding icons from `.bar .pill` with `:not`,
which would also drop the bar's font size and make the glyph smaller than its neighbours.

**The name is text inside the control, hidden visually**, not an `aria-label`: `<svg
aria-hidden="true" focusable="false">` then `<span class="vh">` with the words, plus `title`
with the same words as a pointer tooltip. The reason is the Preferences trigger: it is a
`summary`, which MDN says has no implicit ARIA role and permits none, with browsers differing
in what they expose (<https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/summary>),
so an `aria-label` on it is not a name every reader can rely on, while text content is. One
mechanism for every icon control, rather than `aria-label` on links and text on the one
summary. `aria-hidden` removes the glyph from the accessibility tree
(<https://developer.mozilla.org/en-US/docs/Web/Accessibility/ARIA/Reference/Attributes/aria-hidden>).

**The glyphs are drawn here**, as a few lines of SVG geometry in a 24 by 24 box with no
`fill`, `stroke` or `style` attribute, so no third-party notice has to travel with the
binaries. Five are needed: sliders (Preferences: three lines with three knobs), sign-out (an
open bracket and an arrow leaving it), × (two strokes), copy (two overlapping rounded squares)
and check. A set was considered: Lucide is ISC-licensed, with the icons derived from Feather
under MIT, and both licences require their copyright and permission notice in every copy
(<https://github.com/lucide-icons/lucide/blob/main/LICENSE>); for five shapes this simple, a
notice file is more than the shapes are worth. Nothing is fetched at runtime: each glyph is
inline in the page, which the policy allows with no `img-src` (§13.15).

**Where it is used now:**

- The shared header: Preferences becomes the sliders `summary.pill.ico` (name `K::Settings`)
  opening the same `details` menu, which still needs no script; Sign out becomes the sign-out
  `a.pill.ico` (name `K::SignOut`), still the plain link to the gate's logout. Sliders and not
  a gear: the menu sets two display preferences, and a gear beside a "Settings" tab in the
  console would promise the access settings. The identity text stays beside them, so the bar
  still says who is signed in in words.
- The keys table's revoke: `a.pill.rm.ico` with the × glyph (name "Revoke key `<id>`"),
  replacing the text "×" of §13.16; the user's first request was an × button.
- The 4h copy control becomes this component: `button.pill.ico` with the copy and check
  glyphs, the name in `.vh` (`K::CopyKey`), the status span unchanged. Its own `.secret .copy`
  sizing rules from §13.15 go; the glyph swap on `data-state` stays as the one rule that is
  the reveal's.

**Where words stay**, because an icon would make the person recall what a glyph means instead
of reading it (Nielsen's "recognition rather than recall"); icons without labels are safe only
for actions everybody already knows by their glyph:

- "rotate" on a key: the obvious glyph, a circular arrow, reads as "refresh", which is not
  what it does;
- "edit", "+ New key", "+ add", "← back", "Create key", "cancel", and every submit button: a
  word is shorter to understand than any pencil or plus, and a submit names its consequence;
- the console's tabs, the Preferences menu's contents and every confirmation page;
- a page-level "remove" beside a heading (the console's user, application and scope pages):
  an × there reads as "close this page".

**The console's other row actions:** recommended, as their own slice, that every row-level
`remove` (`act_rm` inside a table row or a list item: users, emails, groups, denied entries,
keys, scopes) become the × `pill rm ico` with the name "Remove `<thing>`", for the same reason
as on `/account/`, and with the same safety net, since each leads to a confirmation page.
`edit` and `rotate` stay words.

**Tests:** `icon_controls_are_named_by_hidden_text`: every `.pill.ico` contains exactly one
`svg aria-hidden="true" focusable="false"` with no `fill`, `stroke` or `style` attribute, one
`span.vh` with the translated name, and a `title` equal to it; the header has the sliders
`summary` and, when configured, the sign-out link; `the_icon_target_is_at_least_24px` in the
e2e walk (bounding boxes in the bar, a table row and the reveal, at desktop and phone width).
`the_copy_control_is_an_icon_with_a_name` changes from an `aria-label` to the `.vh` text, and
`each_key_row_acts_like_a_console_row` expects the × as an icon with "Revoke key `<id>`" as
its text. Shipped with 8a: the first test over the reveal and the account's table, and the
e2e walk in `nojs.js` (a table row and the reveal, at 1280 and 390 px; the bar is measured
only once it carries an icon, which is 8b).

#### The operator's theme

Every rule above is an existing rule or is written in existing custom properties only; no new
token is needed, so the token file needs no change. With the token file loaded, light and
dark, the header, the brand with its logo (painted through `--logo-filter`, which the token
file inverts on dark), the table, the tags, the icon glyphs (`currentColor`), the `div.err` and
the confirmation all take the operator's palette and shape: no rule of ours escaped it (`account-*-tok-*.png`). The token
file's web font was not loaded in the mockups, so the typeface is the one token not seen.

#### What the page adds, and what was tried first

- `@media (max-width:640px){nav.acct .who{display:none}}`: the identity giving way on a phone.
  Tried first: leaving it, which wraps the account bar onto two lines for a fact the menu and
  the page body already carry; and putting the identity only in the menu, which misses the
  user's "user info on the right".
- `.selfserve-brand{margin:0 0 16px}` becomes `margin:0`: an edit of the existing rule, whose
  margin spaced the brand from the heading below it and has no job inside the bar. The rule
  and its `img` and `.name` rules are otherwise reused as they are for the brand slot.
- `.who` is a class name for the one selector above, not a component: the element is the
  existing `.muted` text.
- Removed with their markup: `.selfserve-prefs`, `.selfserve-prefs .fields`,
  `.selfserve-prefs .fields label`, and `body:has(.selfserve)` if the header's own ground makes
  the flat-ground fix unnecessary (to check on the real page).

New `K`: `AccountIdLabel`, `AccountGroups`, `AccountReachSub`, `AccountGroupsSub`,
`AccountKeysSub`, `AccountProfileSub`, `AccountNotProvided`, `AccountReachNone`,
`AccountGroupsNone`, `AccountProfileNone`. `SignedInAs` moves from the console's footer and
the account body to the menu's first line; `AccountUuid` is replaced by `AccountIdLabel`.

**Tests:** `both_surfaces_share_one_header` (the same `header.top` structure on `/admin/` and
`/account/`, the identity in `nav.acct`, Sign out when configured); `the_account_menu_has_no_handler`
(no `onchange` anywhere under the prefix, an Apply button in the menu, the form a `GET` to the
page); `the_console_footer_no_longer_names_the_identity`; `each_section_says_what_it_is_for`;
`empty_sections_name_what_is_missing`. The existing shell tests asserting the footer's "signed
in as" change. (Changed by plan step 13, 2026-11-26: `the_account_menu_has_no_handler` is
deleted with the rule it pinned. What stands in its place asserts the sharing and its bound:
`the_preferences_form_is_scripted_on_both_surfaces`,
`the_account_policy_admits_the_preferences_handler`, and
`account_every_look_and_preference_page_carries_no_script_and_only_the_menu_handler`.)

**Slices.** 8a: §13.16 (the table, the + row, the confirmations through a shared
`page_confirm`, the `td.pills` fix, the duration select on both surfaces). 8c: the body's lede,
sub-lines, lists and empty states, plus the review items (its three parts are at the end of this section). 8b: the shared header on both surfaces, the identity, the
footer change, the removal of the foot form, in three tester and coder passes, each over a few
functions:

- **8b-1, the console's header.** `top_bar` factored out of `shell` (only `shell` calls it
  yet); the identity from a pure `identity_label(given_name, email_header)` (the `given_name`
  claim's forwarded value when the deployment configures that claim, then the **first** address
  of `X-Auth-Email`, which may hold several joined by a space) as `span.who.muted` in
  `nav.acct` and as the menu's first `p.lede`; Preferences as the sliders `summary.pill.ico`
  and Sign out as the sign-out `a.pill.ico`; the footer's "signed in as" removed; in
  `admin.css` the `.bar .pill.ico` padding and the phone rule hiding `nav.acct .who`. Green:
  `the_identity_is_the_given_name_and_the_first_address`,
  `the_console_footer_no_longer_names_the_identity`, `icon_controls_are_named_by_hidden_text`
  extended to a console page (both header icons), and the existing shell tests that asserted
  the footer, updated. The e2e walk's `iconBoxes` already measures the bar once it holds icons.
- **8b-2, the account's header.** `account_shell` calls `top_bar` with the account's brand
  slot, an empty `nav`, the identity, and the menu with no `onchange` and its Apply button
  always present, the form a `GET` to `AccountPrefs::page`; the foot form and its
  `.selfserve-prefs` rules removed, `.selfserve-brand` margin `0`. `AccountPrefs` carries what
  the bar needs (the identity once it is read, and the Sign out `href`), so `account_shell`'s
  callers do not change. The pill still uses `Config::logout_url` here. Green:
  `both_surfaces_share_one_header`, `the_account_menu_has_no_handler`, and
  `icon_controls_are_named_by_hidden_text` extended to the account page. (Changed by plan step
  13, 2026-11-26: the menu here is the console's, `onchange` and all, and that test is gone with
  the rule it pinned, `the_preferences_form_is_scripted_on_both_surfaces` and
  `the_account_policy_admits_the_preferences_handler` standing in.)
- **8b-3, the two decisions above.** `logout_without_rd` and `Config::account_logout_url`, fed
  to the account's pill; `confirm_card` split out of `page_confirm_at` and used by
  `page_account_confirm`, whose caller passes the action word as the title. Green:
  `logout_without_rd_keeps_everything_else`, `the_account_sign_out_carries_no_rd`,
  `the_account_confirmation_has_one_h1`.

**8c, in three tester and coder passes**, each over a few functions:

- **8c-1, the body.** `page_account` and the `K` table only: the lede, the sub-lines, the
  plain lists, the empty states, `AccountGroups` as the heading; `AccountNone` and
  `AccountUuid` removed. Green: `the_lede_names_the_addresses_and_the_account_id`,
  `each_section_says_what_it_is_for`, `empty_sections_name_what_is_missing`,
  `the_sections_are_plain_lists`, and the four existing `account_*` section tests updated.
- **8c-2, the key form.** `account_key_row`, `duration_choice` (placeholder and optional
  hint; both callers), `account_key_post`'s three former `AccountKeyBound` arms, and the `K`
  table (`AccountKeyIdBad`, `AccountKeyTooShort`, `KeyScopesChoose`, the rewordings above).
  Green: `a_bad_key_name_is_refused_without_naming_the_duration`,
  `a_too_short_key_is_refused_without_naming_the_name`, `the_account_refusals_are_sentences`,
  `the_days_box_has_a_placeholder_and_its_own_name`,
  `a_key_with_nothing_to_narrow_has_no_scope_choice`, and
  `a_refused_key_keeps_the_row_and_says_where` updated.
- **8c-3, the console's 403 and the scene.** `shell_named` split out of `shell_as`, the `403`
  branch of the console's handler, `K::NotAdminToAccount`, and the `account-menu` scene in
  `e2e/shots.js`. Green: `the_console_403_names_the_caller_and_links_to_their_account`, and
  the scene rendering in its four views.

### 13.18 The theme, reviewed (plan step 8d)

The user found the theme unsightly (2026-11-24) and set one constraint: **the theme contract
does not change**. Every custom property `THEME_CSS` defines keeps its name and its meaning, none
is removed, and an operator's token file written for today's `theme.css` must still render
correctly after ours. This design meets it **without a new token**: every change is either a new
*value* for an existing token or a rule in `base.css` / `admin.css` that reads existing tokens. So
no migration guide is owed to theme authors; the CHANGELOG still lists the changed defaults and
the values a token file may want to copy (below), because the operator's file pins the old ones.

What was looked at: `theme.css`, `base.css`, `admin.css`, `auth.css`; the `shots.js` walk of
2026-11-25 (light, dark, phone); and a mockup harness that captures the console and `/account/`
pages as served by the e2e server, renders `login.html` with its placeholders filled, and shoots
each with and without the proposed rules, and with and without the operator's `tokens.css`
(rpi-01's copy) loaded after ours. Before and after: `/tmp/d8d/shots/{before,after}/`
(`<page>-{light,dark,phone}[-tok].png`), the delta itself `/tmp/d8d/proposed.css`.

#### What made it unsightly

Measured on the screenshots, in the order a person notices them.

1. **Everything clickable is the same loud blue box.** The five tabs, the two header icons,
   every `+ add`, `Apply`, `edit`, `rotate`, `cancel` and `+ New key` are `.pill`s with a 1px
   accent border and accent text, and in the header they are body-size with 7px by 15px padding.
   A screen of the users page carries a dozen of them, all equally loud, so nothing leads: the
   primary button, the selected tab and a link are the same blue as a filter's Apply. The tabs
   also look like buttons, which they are not (Nielsen 4, consistency: a control should look
   like what it does).
2. **The ground repeats.** `body` paints `var(--bg-grad),var(--bg)` with the default
   `background-repeat`, and `html{height:100%}` makes the positioning area one viewport tall,
   so on any page longer than the window the glow starts again one viewport down: a hard band of
   a second shade across the content. This is the "background shade change on the phone
   dashboard" from 8c's review, and it shows on the desktop users page too; the
   `body:has(.selfserve)` rule only hid it on one page.
3. **Card soup.** Every panel, tile, message and state box has a border **and** a drop shadow
   (`--shadow-md`). Stacked down a page, the shadows add a grey haze between panels and make a
   column of sections read as a pile of floating cards. A shadow says "this floats above the
   page", which only the Preferences menu and the sign-in card actually do.
4. **A flat type scale.** `h1` is 1.25rem against a 15px body, `h2` 1rem, the body size, told
   apart by weight alone; a section heading barely outranks the paragraph under it.
5. **Pale fields read as disabled.** In light, a field is `#f6f7fb` with a `#d8d9e4` border:
   1.4:1 against the card. The days box beside the duration list (8c's review) looks greyed out,
   and the boundary of a text field fails WCAG 2.2 SC 1.4.11, which asks 3:1 of the indicator
   that shows a field is a field
   (<https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html>, figures 31 to 34).
   Dark has the same fault (`#3a3a48` on `#20202a`, 1.44:1).
6. **Misalignment.** The header bar's content starts 16px left of the page's content (the bar
   has no inner padding, `main` has 16px), and on `/account/` the bar is 1000px wide over a 620px
   column, so the brand floats far to the left of everything under it (8b's review).
7. **Small ragged details.** The count tiles wrap five and one at desktop width
   (`minmax(110px,160px)` cannot stretch); every link in a table cell is underlined, so a column
   of emails is a column of blue rules; a panel whose first child carries a top margin opens with
   an empty band (the revoke confirmation, 8c's review) and the same at the bottom of the
   Profile panel.

The sign-in page was checked the same way and has little of this: one card, one primary button,
no pills. It changes in one value only (5, the field), which is the point of saying so: the
console is what was unsightly, and the gate's page is what the console now follows more closely.

#### The changes

**In our built-in `theme.css`, values only** (repaints the gate's four pages, the console and
`/account/`; checked on `login.html` light and dark, the dashboard, users, application and
account pages, each with and without `tokens.css`):

| Token | Arm | Was | Becomes | Why |
|---|---|---|---|---|
| `--input-border` | light | `#d8d9e4` | `#8a8c9e` | 3.32:1 on `--card`, 3.10:1 on `--bg` (SC 1.4.11) |
| `--input-bg` | light | `#f6f7fb` | `#ffffff` | a field level with the card reads as enabled once its border carries it |
| `--input-border` | both dark arms | `#3a3a48` | `#6e6e86` | 3.26:1 on `--card`, 3.49:1 on `--input-bg` |

No other value moves. The accent, the states and every text colour already pass AA and keep
their measured comments. `--bg-grad` keeps its value: the band was a missing `no-repeat`, not
the gradient.

**In `base.css`, the shared components** (both programs):

- `body`'s background becomes `var(--bg-grad) no-repeat,var(--bg)`: the glow is painted once at
  the top and the flat `--bg` it fades into carries the rest of the page. Fixes 2 on every page
  and every token file, the operator's included.
- The surface rule (`.card,.panel,.msg,.flash,.err,.secret`) drops `box-shadow` to `none`. The
  two surfaces that float keep theirs from their own layout, as they already state it:
  `auth.css`'s `.card` (`--shadow-lg`) and `admin.css`'s `.menu` (`--shadow-md`). Both shadow
  tokens therefore stay in use.
- A surface owns its padding: `>:first-child{margin-top:0}` and `>:last-child{margin-bottom:0}`
  on the same six surfaces. Removes the empty band at the top of the confirmation card and at the
  foot of a panel, with no markup change.
- Type: `h1` 1.5rem, line-height 1.25, weight 650, letter-spacing -.01em, margin `0 0 6px`;
  `h2` 1.0625rem, weight 600, margin `28px 0 10px`. The sign-in card's `.brand h1` keeps its own
  size from `auth.css`.
- The secondary pill is neutral: `.pill` text `--text`, border `--input-border` (the same 3:1
  boundary a field has, so a pill still reads as a control on every surface, which is the reason
  the border was `currentColor`); hover adds `--chip` fill, accent border and accent text;
  `.pill.rm` stays `--muted` and turns `--error` on hover; `.pill.on` keeps the accent fill. The
  accent is left to what deserves it: the primary button, the selected tab, links and the focus
  ring.
- A pill in a `nav` is a tab: `nav .pill` has no visible box at rest (border `--card`, the
  header's own fill, so the box keeps its size across states), text `--muted`; hover fills
  `--chip`. That reaches the two header icons too (they sit in `nav.acct`), which is intended:
  icon buttons in a bar need no box, and their glyph in `--muted` is 6:1. SC 1.4.11 does not ask
  for a boundary where the content identifies the control (same Understanding page, "a border or
  other indication of the overall boundary of the hit area is not required"), and the focus ring
  is unchanged. The auth pages have no `nav`, so this rule paints nothing there.
- Links in a table cell or a list item are not underlined at rest, underlined on hover. They
  are not links inside a block of text, which is where colour alone would fail SC 1.4.1
  (<https://www.w3.org/WAI/WCAG22/Techniques/failures/F73>).

**In `admin.css`, the arrangement:**

- `header.top` padding `10px 0`, `.bar` padding `0 16px` (phone: `6px 0` and `0 16px`), so the
  bar's content edge is `main`'s. `body:has(.selfserve) .bar{max-width:620px}` (phone padding
  `0 12px`) puts the account page's brand over its column. `:has` is Baseline 2023
  (<https://developer.mozilla.org/en-US/docs/Web/CSS/:has>); without it the brand stays where it
  is today, which costs alignment and nothing else.
- `.bar .pill` 0.95rem, padding `6px 12px` (`.pill.ico` `6px`): a header that holds tabs, not
  buttons. Phone sizes unchanged.
- `p.primary .pill,.actions .pill` take the button's measure (font-size inherit, line-height
  1.55, padding `9px 16px`), so `cancel` beside `Create key` is the same height.
- `.cards` becomes `repeat(auto-fill,minmax(140px,1fr))`: the six counts sit on one row at
  desktop width and wrap evenly on a phone.

**Not done, and why.** Radii stay (14px and 10px are the brand's, and the operator's file states
them as such). The uppercase table headings stay: they hide two `K` capitalisation slips
(`expiry`, `API_KEYS`) that sentence case would expose, which is a separate wording task. The
dashboard's monospaced file words (`api_keys`, `user_groups`) stay: they teach the file's
vocabulary on purpose, and the question is the user's (below).

**For the operator's `tokens.css`** (rpi-01; not in this repository, recommendations only).
The file redefines `--input-bg` and `--input-border` with today's built-in values, so after this
change it keeps pale fields and faint pills on that deployment. Everything else here reaches it
untouched, since it is rules and not values. To match: in `:root`, `--input-bg: #ffffff;
--input-border: #8a8c9e;` and in both dark arms `--input-border: #6e6e86;`. With Inter loaded, the
`h1` weight 650 is a real weight (the face is variable, 100 to 900). Nothing in it needs
removing; `--danger-*` are untouched.

#### The rest of 8d's list, folded in

- **The two brands agree.** The console's bar says "bb-auth-web" over a version, the account
  page "bb-auth" (or `ui.brand_name`). Both become `ui.brand_name`, default `bb-auth` (the
  account page's `DEFAULT_ACCOUNT_BRAND`), with the logo when `ui.logo_url` is set; the console's
  second line becomes `K::ConsoleTag` ("Administration" / "Amministrazione") instead of the
  version, which stays in the footer, where `version_line` already prints the full build string.
- **The account id on a phone.** The id becomes `code.uid`, and `.uid{white-space:nowrap}` with
  `font-size:.85em` under 640px: 36 characters fit 296px at 320px wide, so it moves whole to its
  own line instead of breaking at a hyphen. The email beside it is not given `nowrap`, since a
  long address must still wrap.
- **The days box.** Its presence is the price of no JavaScript; its look is fixed by the field
  values above (white, 3:1 border, the `days` placeholder in `--muted`).
- **The Name hint while a refusal shows.** `account_key_row` omits the field's hint when that
  field carries the refusal: the refusal already says what is allowed, as a sentence.
- **The scope radios.** A `shots.js` scene `account-new-scopes` opens `/account/keys/new` as
  `bot@example.com`, whose `laptop` key shows `mcp/api` is reachable, so the radios get a look.

#### Tests

Kept green, unchanged: `the_theme_defines_every_token_in_all_four_arms`,
`only_the_palette_names_a_colour`, `the_components_are_shared_and_the_layouts_only_arrange_them`.

New, by part (each a tester and coder pass):

- **8d-1, `theme.css` values and `base.css` surfaces** (lib.rs): `the_token_set_is_the_contract`
  (the set of custom-property names `THEME_CSS` defines equals a fixed list of today's 29, so a
  rename or a removal is red); `fields_have_a_three_to_one_border_in_every_arm` (parses each
  arm's `--input-border`, `--card`, `--input-bg` and computes the WCAG ratio, at least 3.0);
  `the_ground_is_painted_once` (`BASE_CSS`'s body background reads `var(--bg-grad) no-repeat`);
  `only_floating_surfaces_cast_a_shadow` (the surface rule says `box-shadow:none`, `AUTH_CSS`'s
  `.card` names `--shadow-lg`, `admin.css`'s `.menu` `--shadow-md`);
  `a_surface_owns_its_padding` (the first-child and last-child rules exist). Plus a look at
  `/auth/login` in both themes, as the commands table asks.
- **8d-2, the controls and the arrangement** (lib.rs and bb-auth-web):
  `the_secondary_pill_is_neutral` (`.pill{` reads `--text` and `--input-border`, and `.pill.on`
  is the only pill rule naming `--accent` as a fill); `a_pill_in_a_nav_is_a_tab`
  (`nav .pill` exists in `BASE_CSS`, border `--card`); `table_links_underline_on_hover`;
  `the_header_shares_the_content_column` (the `.bar` and `body:has(.selfserve) .bar` rules). In
  `e2e/run.js`: the header brand's left edge equals the `h1`'s at 1280 and 360, on `/admin/` and
  `/account/`; `.actions .pill` and `.actions button` are equally tall (within 1px); the six
  dashboard tiles share one top at 1280.
- **8d-3, the markup items** (bb-auth-web): `both_bars_name_the_deployment` (console and account
  brand text is `ui.brand_name`, else `bb-auth`; the console's second line is `K::ConsoleTag` in
  both languages; the version appears in the footer); `the_account_id_is_one_token` (`code.uid`;
  e2e at 320: no page scroll and the id is one line tall);
  `a_refused_field_shows_the_refusal_not_the_hint`; and the `account-new-scopes` scene rendering
  in its four views.

The slice closes on the user's look at the `shots.js` walk in both themes and both languages,
at desktop and phone width, with and without the operator's token file.

### 13.19 Where a login lands when nothing named a place (`gate.landing_url`, plan step 10, asked and built 2026-11-25)

The user's words: "configure the account page as the default rd, so that after a logout it at
least doesn't loop on the login page".

#### What happens today

Read in the code (`safe_rd`, `logout_target`, `login_rd`, `handle_login`, `handle_session` in
`src/bin/bb-auth.rs`; `logout_without_rd` in `src/bin/bb-auth-web.rs`):

1. Sign out on `/account/` is `BB_AUTH_WEB_LOGOUT_URL` with its `rd` dropped (§13.17), so
   `/auth/logout` gets no `rd`, and no `Referer` either, because every page we serve sends
   `Referrer-Policy: no-referrer`. `logout_target`'s last arm sends the browser to the login
   page, and `login_rd` gives that page an empty `data-rd`.
2. After the sign-in, `/auth/session` gets no `rd` and `safe_rd`'s no-`rd` branch answers the
   **caller's root**. The caller is the host of the `/auth/session` request, which is the host
   serving the sign-in page, so that root is always the auth host's root
   (`https://auth.badbat75.com/` on rpi-01), never the application the person came from.
3. What that root serves on rpi-01 is **not verified**: the vhost could not be read for this
   design (SSH from this machine failed host-key verification). The user reports a loop back
   to the sign-in page, which is consistent with `/` redirecting to `/auth/login`. Whatever it
   serves, it is not a page anybody chose, and the same happens to anybody who opens the
   sign-in page from a bookmark.

So the loop is not a logout problem. A logout already ends at the sign-in page, which is the
right place for a signed-out person to be; what is missing is somewhere for a sign-in to land
when nobody named one.

#### Decision

One new settings-file value, `gate.landing_url`: an absolute `https://` URL, empty by default.
It is used in exactly **one** place, `safe_rd`'s no-`rd` branch (an absent or empty `rd`): set,
the login lands there; empty, it lands on the caller's root exactly as today. Nothing else
changes:

- a present `rd` still wins, so every 401 round trip ("sign in, and be where you were") is
  untouched;
- a **rejected** `rd` still falls back to the login page, as the `safe_rd` invariant says
  (a rejected value is an attack or a misconfiguration, and landing it on a real page would hide
  both);
- `logout_target` is **not** changed: a logout with nothing said still ends at the sign-in page,
  and the sign-in it leads to now lands on `gate.landing_url`. Sending the logout itself to the
  landing page would reach the same end one `401` hop later, and would drop a signed-out person
  on a page instead of the sign-in when the landing page happens to be public.

Because `logout_target` only ever calls `safe_rd` with a non-empty candidate, the change is
visible on `/auth/session` alone, and through it on both ways in: the email sign-in page and the
social callback, which posts `bb_social_rd` (empty when the page had none).

The name is `landing_url` and not `default_rd`: the section's other pages are `login_url` and
`denied_url`, and `rd` is the name of a query parameter, not of a page.

#### The three-part rule, out loud

1. **Read per request**: on every `/auth/session`, under the same settings read that already
   takes `authorized_hosts` and the session lifetime. Passes.
2. **Cannot lock the operator out irreversibly**: it is read **after** the token has been
   verified and the cookie built, and it decides only where a browser that is already signed in
   is sent. The worst a wrong value does is land somebody on a `403`, a `404`, or (pointed at the
   sign-in page itself) today's loop; the cookie is set either way, so the editor still reaches
   the GUI, and `bb-auth-adm` over SSH is there regardless. Passes cleanly, and for that reason
   it is **not** a guarded change (`guarded_changes` stays five), the same argument
   `gate.denied_url` made.
3. **Not a secret**: it is a `Location:` a browser follows. Passes.

The settings invariant's count becomes twenty-four, and the paragraph above is the argument it
asks for.

#### Validation, and why the guard moves into the library

`compile_settings` refuses, with a sentence naming `landing_url`, a value that fails
`compile_page_url("landing_url", …)` (absolute https, printable ASCII, no `@`, no `\`) **or**
whose host `gate.authorized_hosts` does not cover. The second check is the one that matters: a
landing page outside the redirect scope would be refused by `safe_rd` at every login and fall
back to the login page, which is today's loop with a setting standing beside it saying it is
fixed. Silent is the half that costs an afternoon, so the refusal belongs on the way to disk,
where both editors can still say so, exactly as `cookie_domain_covers` already refuses a cookie
domain that misses a host.

That makes `rd_url_allowed` a rule the settings file has an opinion about, and by the library's
own membership rule ("the moment an editor must refuse to *write* a bad value, the rule that
decides one is shared") it **moves into `bb_auth_core`**, unchanged, and the gate imports it.
`safe_rd` stays in the gate: it is HTTP. `safe_rd` still runs the landing URL through
`rd_url_allowed` at use time as it does every candidate, so the invariant "every candidate
passes the same gate" keeps holding with no exception; the load-time check only makes the
refusal visible before it can be silent.

A file that carries a landing URL outside the hosts is refused like any other bad settings file:
fail-soft on SIGHUP (the live values stay), fatal at startup. Removing the `authorized_hosts`
entry the landing URL needs is therefore refused too, with that sentence, which is the right
answer and not a sixth guarded change.

#### Version, and an older binary

**No version bump.** The precedent is `gate.denied_url`, added under version 3 (commit
`131b35f`), and a bump would make every existing file a refusal for an optional key. But
`GateSettings` is `deny_unknown_fields`, so an **older binary refuses a file that carries
`landing_url`**: on a SIGHUP it keeps the live values, at a restart it does not start. Two
consequences, both cheap:

- `landing_url` is serialized with `skip_serializing_if = "String::is_empty"`, unlike its
  neighbours: an editor that never set it never writes the key, so a host that does not use the
  setting can still roll back to `share/previous/` with no step at all.
- On a host that does use it, the order is **deploy all three packages, then set it**, and a
  rollback to an older binary is preceded by `settings set --landing-url ''`. This goes in the
  release notes.

#### The editors

- **`bb-auth-adm`**: `settings set --landing-url URL` (an empty value unsets it, as for the
  other `settings set` URLs), and `settings show` prints it, `(caller's root)` when empty.
- **`bb-auth-web`, Settings tab**: one text field in the gate group, beside `denied_url`, with
  its own `K` label and help line (`GlobalLandingUrl`, `GlobalLandingUrlHelp`). A refusal shows on
  the field and writes nothing, through the same `Refusal::on` path `denied_url` uses. The help
  line is the designer's to word; the field is the one `denied_url` already has, so no new layout.
- **`bb-auth --check-settings`**: prints the landing page, or that a login with no `rd` lands on
  the caller's root.

#### The three logouts, on rpi-01 with `landing_url` = `https://auth.badbat75.com/account/`

| Sign out from | What happens |
| --- | --- |
| `/account/` | `/auth/logout` with no `rd` → the sign-in page with no `rd` → sign in → `/account/`. The loop is gone. |
| the console (`/admin/`) | Unchanged. If `BB_AUTH_WEB_LOGOUT_URL` carries `rd=…/admin/` (the env example's recipe; rpi-01's value is not verified), the round trip returns to `/admin/` through a `401`. If it carries none, the administrator lands on `/account/`, their own page, rather than on the auth host's root. |
| another application | Unchanged when its link names an `rd`, or its own page sends a `Referer` the gate accepts: the browser returns there through a `401`. When it says nothing, the sign-in now lands on `/account/` instead of the auth host's root. |

#### Rejected for the landing page

- **Carry `rd=<account page>` on `/account/`'s Sign out** (no new setting). `bb-auth-web` does
  not know its own absolute URL, which is the reason `BB_AUTH_WEB_LOGOUT_URL` exists, and a
  relative `rd` falls back to the login page because the ungated logout location carries no
  `X-Original-URL` (the env example says so). Deriving it from `Host` would be a canonical base
  URL by the back door; a second env var would be restart-only and a value written in two files.
  And it fixes only that one link: a bookmark to the sign-in page, or another application's
  logout that says nothing, still lands on the auth host's root.
- **Change `logout_target`'s last arm to the landing page as well**: same end state, one more
  hop, and a public landing page would leave a signed-out person off the sign-in page. See above.
- **Change the no-`rd` default to the login page** with no setting: that *is* the loop.
- **A landing URL per application**, as `login_url` and `denied_url` have: `/auth/session` runs
  on the sign-in page's host, which is inside no application's area when it is the gate's own
  page, so a per-area value would have nothing to resolve against. Nobody asked for one.

#### How each part is shown to hold, and the work

**Built** (plan step 10, in commits `c5867c2`, `03398aa`, `90590ec`), in three parts: the
commits name them 10-1 to 10-3, this section names them 19-1 to 19-3.

- **19-1, library** (`src/lib.rs`): `GateSettings::landing_url`, `Settings::landing_url`,
  `rd_url_allowed` moved in. Tests: `a_landing_url_is_absolute_https_on_an_authorized_host`
  (accepts `https://auth.x.com/account/` under `auth.x.com`; refuses `http://`, a relative path,
  `@`, `\`, and a host the patterns do not cover, each message naming `landing_url`);
  `an_unset_landing_url_is_never_written` (a `SettingsFile` with it empty serializes with no
  `landing_url` key, and the file round-trips); `removing_the_host_a_landing_url_needs_is_refused`;
  `the_landing_url_is_not_a_guarded_change`. The existing `rd_url_allowed_*` tests keep passing
  against the moved function.
- **19-2, gate** (`src/bin/bb-auth.rs`): `safe_rd` takes the landing URL. Tests:
  `safe_rd_with_no_rd_lands_on_the_landing_url` (absent and empty `rd` → the landing URL; empty
  landing → the caller's root, as `safe_rd_resolves_relative_against_the_caller` already pins; a
  present `rd` still wins; a rejected `rd` still → the login page, not the landing URL);
  `a_session_with_no_rd_redirects_to_the_landing_url` (router over a real socket, in the style of
  `a_whole_login_lands_where_the_page_that_ran_it_permits`);
  `logout_with_nothing_said_still_ends_at_the_login_page` (router: `landing_url` set, `/auth/logout`
  with no `rd` and no `Referer` → `Location:` is the login page); `check_settings_names_the_landing_page`
  if `--check-settings` output is already under test, else a look at its output.
- **19-3, editors** (`src/bin/bb-auth-adm.rs`, `src/bin/bb-auth-web.rs`):
  `settings_set_landing_url_writes_and_an_empty_value_unsets`,
  `settings_set_landing_url_off_the_authorized_hosts_is_refused`, and in the GUI
  `the_settings_form_saves_the_landing_url` and
  `the_settings_form_refuses_a_landing_url_off_the_authorized_hosts` (the field carries the
  refusal, the file's bytes are unchanged). Markup changes, so `node e2e/run.js` and
  `node e2e/shots.js config` for the designer's look; no new e2e step.

The real run that closes it, after the deploy and the operator's `settings set` (both the user's
to approve): Sign out on `https://auth.badbat75.com/account/`, sign in, land on `/account/`.

When it lands, `docs` updates §8b's first row, the settings invariant's count and list, §8a, and
`deploy/settings.example.json`. (Done 2026-11-25 for the first three; the example file is **not**
updated, so it still has no `landing_url` key and no `_comment` block for one.)

### 13.20 The Preferences menu closes on a click outside it (plan step 9, asked and built 2026-11-25)

The menu is `details.settings` in `top_bar`'s account end, one markup on both surfaces (the
console's `shell_as` and the account page). Today it closes only from its own trigger, so a
person who opened it and clicked back into the page finds it still hanging over the content.

#### Decision: CSS only, the open trigger covers the page

```css
details.settings[open]>summary::before{content:"";position:fixed;inset:0;z-index:9;cursor:default}
details.settings[open]>summary{background:var(--chip);border-color:var(--accent);color:var(--accent)}
```

Both rules go in `admin.css`, beside `details.settings` (it is the header's arrangement, and it
names only tokens). While the menu is open, its trigger grows a transparent box over the whole
viewport. A click anywhere outside the menu lands on that box, which *is* the `summary`, so the
browser does what activating a summary always does: it toggles the `details` shut. `.menu`
keeps `z-index:10`, one above the cover, so everything inside the panel (the list boxes, Apply,
the console's `SETTINGS_ONCHANGE` submit) is hit first and works as it does today. No markup
changes and no script is added, so the account page keeps "no handler at all". (Changed by plan
step 13, 2026-11-26: that half held until then, when the page gained the console's handler; the
cover rule itself is untouched, and the two list boxes it protects are the ones that submit.)

Why not a script, under "JavaScript is used sparingly": markup and CSS do this one well, and a
script would buy only Escape-to-close. Escape is not owed here. The control is a disclosure (a
`summary` revealing a form), not an ARIA menu, and the APG disclosure pattern's keyboard
contract is Enter and Space only (<https://www.w3.org/WAI/ARIA/apg/patterns/disclosure/>).
WCAG 2.2 SC 1.4.13 asks for dismissal of content shown on *hover or focus*, not on activation
(<https://www.w3.org/WAI/WCAG22/Understanding/content-on-hover-or-focus.html>). And the CSS way
works with scripting off, which a script cannot.

What was checked, against the real pages with the two rules injected (Edge, 1280 and 360,
scripting on and off, `/admin/users` and `/account/`; scratch script `/tmp/menu9/proto.js`,
screenshots `/tmp/menu9/*-open.png`): the trigger opens it; a click on a list box inside leaves
it open; a click outside closes it; a click inside the panel's area at 360 (where it covers the
middle of a phone screen) leaves it open; Apply still submits and applies the theme; the hit
test at the centre of a list box is the `SELECT`, not the cover; `scrollWidth` stays 360.

- **Containing block.** A `position:fixed` box is placed against the viewport unless an
  ancestor has `transform`, `perspective`, `filter` or `will-change:transform`
  (<https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Properties/position>). No ancestor
  of the trigger has any of them today (`button:active`'s `transform` is on buttons, not on
  the summary). A future rule that puts one on `header.top`, `.bar`, `nav.acct` or
  `details.settings` shrinks the cover to that box and quietly breaks this; the Rust test below
  is where that is caught.
- **Stacking.** No ancestor sets a `z-index`, so the cover (9) and the panel (10) stack in the
  same context. A future `z-index` on the header must stay below neither.
- **Accessible name.** `content:""` adds no text, so the trigger's name stays its `.vh` words.
  Focus after an outside click is on the trigger, which is where a closed disclosure should
  leave it.
- **Scrolling.** The cover is not a scroller, so a wheel or a touch drag over it scrolls the
  page as before; only a tap is taken.
- **The open state.** The second rule is not decoration: with the cover up, the pointer is
  "on" the trigger everywhere outside the panel, so `.pill:hover` would flash on and off as
  the pointer crossed the panel's edge. Giving the open trigger the hover look for as long as
  it is open makes that steady and shows the state (Nielsen 1, visibility of system status).

**The trade-off, stated.** The click that closes the menu does nothing else: a click on a link
or on Sign out while the menu is open closes the menu, and a second click follows the link.
That is the platform's own "light dismiss" (the Popover API's `popover="auto"` behaves the
same, <https://developer.mozilla.org/en-US/docs/Web/API/Popover_API/Using>), and it is the safe
side of the error: a click meant to dismiss never navigates by accident. A second, minor cost:
the trigger's `title` tooltip ("Preferences") may appear if the pointer rests outside the
panel while it is open, because the cover is the trigger. Not verified in a screenshot (native
tooltips are not captured); to look at in the review.

Leaving the menu by `Tab` still leaves it open, as today. Not asked, and closing on focus loss
needs a script.

#### Rejected for the menu

- **A script for click outside and Escape** (a `document` listener, hashed into `admin_csp`
  and a new account-page CSP). Gives Escape, costs a third script, a policy on a page that has
  none, and nothing with scripting off. Revisit only if the user wants Escape.
- **CSS for click outside plus a script only for Escape.** The same third script for a key
  nothing here requires.
- **`popover` instead of `details`.** Light dismiss and Escape with no script, but the panel
  goes to the top layer centred in the viewport and hanging it off the trigger needs CSS anchor
  positioning; it rewrites a control two surfaces and several tests are built on, for one key.
- **The cover on `details.settings::before`.** A click on it hits the `details`, not the
  `summary`, and nothing closes.

#### Tests, in two parts

- **9-1, the rule** (`src/assets/admin.css`, tests in `src/bin/bb-auth-web.rs`):
  `an_open_menu_closes_on_a_click_outside_it` asserts `CSS` contains
  `details.settings[open]>summary::before{content:"";position:fixed;inset:0;z-index:9` and the
  open-state rule, that `.menu`'s `z-index` is greater than the cover's, and that none of
  `header.top`, `.bar`, `nav.acct`, `details.settings` carries `transform`, `filter`,
  `perspective` or `will-change`. `no_page_but_the_reveal_carries_a_script` stays as it is: it
  is what says no script came with this. (Built: the test parses the rules out of `admin.css`
  and checks each declaration, so it is not the literal string above, and pins the same three
  things.)
- **9-2, the walk** (`e2e/tests/settings.js` for the console, `e2e/tests/account.js` for the
  page, and the same two checks in `nojs.js`'s scripting-off pass): open the menu, click a
  point outside the panel (bottom-left of the viewport), `details.settings` is not `open`;
  open it, click a list box inside, still `open`; pick a theme and submit (onchange in the
  console, Apply on the page, Apply in the console with scripting off), `data-theme` changed.
  The designer then looks at `node e2e/shots.js settings-menu` and `account-menu` for the open
  state, light and dark.

### 13.21 Three nits from the review of 8d, and a scene for the landing refusal (plan step 8)

Three small faults the designer found reviewing 8d (2026-11-25), each fixed by the smallest rule
that removes it, plus one `shots.js` scene from the review of steps 9 and 10. No token is added
and no value in `theme.css` moves, so the 29-token contract (`the_token_set_is_the_contract`)
holds and no operator's token file needs a change.

What was looked at: `base.css`, `admin.css`, `auth.css`, `login.html`; `node e2e/shots.js users
user-detail account scope-edit config app-detail key-edit` (copied to `/tmp/d8f/before/`); and
computed geometry measured in Edge through `boot()` (`/tmp/d8f/measure.js`, `/tmp/d8f/m2.js`).
Each fix was tried on the real pages by injecting `/tmp/d8f/proposed.css` before `</head>` with
the CSP removed (`/tmp/d8f/shoot.js`). Before and after: `/tmp/d8f/shots/{before,after}/<page>-
{light,dark,phone,p320}.png` for `account-new`, `account`, `users`, `user-detail`, `scope-edit` and
`audit`. Side-by-side crops: `/tmp/d8f/shots/crop-{keys-light,keys-dark,keys-phone,users-light,
audit-light}.png`. No page scrolls sideways at 390 or 320, before or after.

#### 1. The row rules stop short of the actions column: `td.pills` is not a table cell

**The cause is not the one 8a removed.** 8a took `display:flex` out of the `td.pills` rule, and
the existing test checks exactly that. But the cell's class is `pills`, and `base.css`'s group
rule `.pills{display:inline-flex}` matches the `td` as well as the `span.pills` inside it. So the
cell still computes `display:inline-flex` (measured: every `td.pills` on `/account/keys/new`,
`/admin/users` and a person page). An inline-flex box in a row is wrapped in an anonymous cell
and sized to its content (CSS 2.2 §17.2.1,
<https://www.w3.org/TR/CSS22/tables.html#anonymous-boxes>), so on `/account/` the row's rule ends
19px short of the table's edge, on `/admin/users` 131px short, the actions sit mid-column
instead of at the right edge (`text-align:right` never applied), and the cell's top is a pixel
lower than its siblings'.

**The fix** (`src/assets/admin.css`, two declarations):

- the existing `td.pills{text-align:right;white-space:nowrap}` gains `display:table-cell`
  (specificity 0,1,1 beats `.pills` at 0,1,0,
  <https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_cascade/Specificity>);
- the existing phone `td.pills{text-align:left;padding-top:6px}` gains `display:block`, because
  the phone block stacks every cell with `td{display:block}` (0,0,1), which the new
  `table-cell` would otherwise outrank.

After: every cell of a row shares one bottom and the last cell ends at the table's right edge
(measured at 1280 on the three pages), the actions sit right-aligned against that edge, and the
phone stack is unchanged.

**Repaints:** every console table with a row action (users, groups, denied, applications,
scopes, a person's keys) and the `/account/` keys table. Nothing on the gate's pages.

**Rejected:** renaming the cell's class (`td.acts`): touches every table's markup and several
Rust tests that read `class="pills"` for one declaration's worth of effect. Scoping `base.css`'s
group to `.pills:not(td)`: puts a table's concern in the shared component file.

#### 2. Three sizes of secondary control in one section

Measured, not just seen. Two heights are designed (§13.18): the **compact** pill, 29.7px, for row
actions and filters, and the **full** pill, 43px, which takes a button's measure beside a button
or as the page's create action (`p.primary`, `.actions`). Two more crept in:

- **On a phone, a text pill and an icon pill in the same row differ.** The phone block's
  `.pill{padding:3px 8px}` shrinks `rotate` to 28px, while `×` (`.pill.ico`, 0,2,0, which
  outranks it) stays 30px. With `cancel` at 43px below, the keys section shows three heights.
- **A filter's field is shorter than its own Apply.** `.listctl input[type=search]` and
  `.listctl select` measure 27px beside a 29.7px Apply, and the users section therefore shows 43
  (`+ add`), 27 (the field) and 29.7 (Apply and the row actions). The audit's four list boxes are
  27px too.

**The fix:**

- `src/assets/admin.css`, phone block: **delete** `.pill{padding:3px 8px}`. A row pill on a phone
  is then the desktop pill, the same height as the icon beside it. It is 6px wider and 2px taller
  than today, which the stacked cards have room for (no sideways scroll at 320) and which only
  helps WCAG 2.5.8's 24px target size
  (<https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html>). `.bar .pill` keeps its
  own phone size.
- `src/assets/admin.css`: `.listctl input[type=search]`, `.listctl select` and
  `.listctl input.tzc` each gain `min-height:calc(1.45em + 10px)`. That is the compact pill's own
  box (line-height 1.45 at the same `--fs-sm`, 4px padding and 1px border on each side), so field
  and button are one height whatever the font. A `min-height` and not a line-height or padding
  change because Edge ignores `line-height` on a `select` (measured: still 27px with
  `line-height:1.45`) and only a fractional padding (5.5px) would hit the height there.

After: 29.72px field, 29.70px Apply, 30px for `rotate` and `×` at every width, 43px for the
full pills. Two heights in every section.

**Repaints:** every list's filter row in the console (users, groups, denied, applications,
audit) and the row actions of every table on a phone, console and `/account/`. Nothing on the
gate's pages.

**Not done:** bringing `cancel` and `+ New key` down to the compact size. They sit beside or in
place of a button, and §13.18 made them its height on purpose (Nielsen 4, a peer reads as a
peer).

#### 3. Radios and checkboxes in the browser's blue

`accent-color` is `auto` on every radio and checkbox, so a ticked one is the engine's own blue
(a mid blue in light, a pale blue in dark), the one colour on the page not from the palette.

**The fix** (`src/assets/base.css`, one rule in the Fields section, after the field rule, since
it says what a control looks like and both programs emit it):

```css
input[type=radio],input[type=checkbox]{accent-color:var(--accent)}
```

`accent-color` tints the checked state and leaves the rest native, and the browser picks the
tick's own colour for contrast against it
(<https://developer.mozilla.org/en-US/docs/Web/CSS/accent-color>; Baseline since 2022). The
section's comment ("a checkbox [draws] its own box, which is the browser's job") stays true:
the box is still the browser's, only its tint is ours. SC 1.4.11 asks 3:1 of the checked
indicator (<https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html>): `--accent`
measures 4.96:1 on the light card and 4.93:1 on the dark one (the figures `theme.css` records),
so both arms pass, and an operator's accent is held to the same 4.5:1 as link text by the
contract already. No new token: `--accent` is the control colour by the file's own definition.

**Repaints:** the scope form (access radios, credential checkboxes), the Settings tab's social
checkboxes, the console's key form and `/account/`'s key form (scope radios and ticks). On the
gate's pages it paints nothing: `login.html`, `callback.html`, `denied.html` and `error.html`
carry no radio or checkbox (checked by grep), so a look at `/auth/login` must show no change.

#### 4. A scene for the landing URL's refusal

`e2e/shots.js`, after `config-refused`:

```js
['config-landing-refused', async (page, ctx) => {
  await page.goto(ctx.base + '/config?groups=open');
  await page.fill('input[name=landing_url]', 'https://evil.example.org/account/');
  await submit(page);
}],
```

and `'config-landing-refused'` added to the `it` view's `only` list. The fixture's
`authorized_hosts` (`example.com`, `*.example.com`) does not cover the host, so the page answers
400 with the field marked `invalid`. A scratch run is at
`/tmp/d8f/shots/config-landing-refused-{en,it}.png`: in both languages the sentence reads
"refusing to write: landing_url: its host is not covered by authorized_hosts, …", which is the
next item. (Changed by §13.31, built 2026-11-26: the page now answers in the reader's language,
opening with the field's visible label; the sentence quoted above is what `bb-auth-adm` prints,
byte for byte as it always did.)

#### Not in this slice: library refusals in the page's words and language

(Built by §13.31, 2026-11-26, so the present tense below is the state at this slice: the page now
maps every refusal code to a sentence in the reader's language that opens with the field's visible
label and marks that field, and `bb-auth-adm` and `bb-auth --check-settings` print the library's
sentence unchanged.)

The Settings tab shows `compile_settings`' error string as it comes from the library, so it names
the file's keys (`landing_url`, `authorized_hosts`) in English on an Italian page, against the
rule that a refusal names the field by its visible label. Fixing it means the library returning
a **code with arguments** for each settings refusal (an enum beside the string, as the audit's
`reason` already is: `decision_reason`) instead of a sentence, `bb-auth-web` mapping each code to
a `K` key in English and Italian that names the visible labels ("Landing page", "Authorized
hosts"), and `bb-auth-adm` keeping today's English sentence through the same enum's `Display`. It
reaches every settings refusal, not just this one, so it is a slice of its own, with a test that
every code has both translations and a Settings-tab test per code that the page shows the label
and not the key. Designed in §13.31, which settles the test differently: one test over every
code for both translations, and one route test per path rather than per code.

#### Tests for the three nits and the scene

Rule-level, in the style of §13.18's (each first red against today's CSS):

- **`the_actions_cell_is_a_table_cell`** (bb-auth-web, beside
  `each_key_row_acts_like_a_console_row`): `the_rule(CSS, "td.pills")` contains
  `display:table-cell`; the `td.pills` rule inside the `@media (max-width:640px)` block contains
  `display:block` (`the_rule` returns the first match, so read the phone block's own text). The
  reason belongs in the doc comment: `.pills` in `BASE_CSS` also matches the cell, which is why
  the old "no `display:flex`" assertion passed while the defect stayed.
- **`a_row_pill_is_one_size_at_every_width`** (bb-auth-web): no rule whose selector is exactly
  `.pill` exists inside the phone block of `CSS`.
- **`a_filter_field_is_its_buttons_height`** (bb-auth-web): each of `.listctl input[type=search]`,
  `.listctl select`, `.listctl input.tzc` contains `min-height:calc(1.45em+10px)` (whitespace
  stripped, as `flat_rules` does), and `BASE_CSS`'s `.pill` still says `line-height:1.45` and
  `padding:4px11px`, since the formula is that box.
- **`ticks_wear_the_accent`** (lib.rs): `rules_named(BASE_CSS, "input[type=radio],input[type=checkbox]")`
  is one rule reading `accent-color:var(--accent)`. `only_the_palette_names_a_colour` and
  `the_token_set_is_the_contract` stay green unchanged.

In the e2e walk (`e2e/run.js`, at 1280 and 390, on `/admin/users` and `/account/` as
`bot@example.com`): in every `tbody tr`, every `td` has the same `getBoundingClientRect().bottom`
and the last `td`'s `right` equals the table's (within 0.5px); `getComputedStyle(td.pills).display`
is `table-cell` at 1280 and `block` at 390; every `.pill` that is not in `p.primary`, `.actions` or
`.bar` is the same height (within 0.5px) at both widths; every `.listctl` field's height equals its
Apply's (within 0.5px). On `/account/keys/new` as `bot@example.com`, `accent-color` of
`input[type=radio]` is not `auto`.

The scene renders in `light`, `dark`, `phone` and `it` (`node e2e/shots.js config-landing`).
The slice closes on the designer's look at `node e2e/shots.js users account audit scope-edit
config-landing` against `/tmp/d8f/shots/before/`, and a look at `/auth/login` in both themes,
which must be unchanged.

### 13.22 The profile edit, in slices (plan step 5, designed 2026-11-25)

Plan step 5 turned into test-first slices, now that the real pool has been read. It settles
what §13.7 left open, and §13.7 carries "(Changed by §13.22 ...)" where these facts change it.

What was read to write it: `PLAN.md` steps 5 and 7 (with the pool facts recorded there),
§13.7, §13.11 to §13.13 and §13.17 of this document, `AGENTS.md` (the invariants and
`bb-auth-web`'s trust model), `src/bin/bb-auth.rs` (`cognito_endpoint`, `origin_of`,
`email_verified_true`, the JWKS agent), `src/assets/login.html` (`cognito`, `startLogin`, the
code step), `src/bin/bb-auth-web.rs` (`handle_account` and its closed path list, `account_claims`,
the Profile panel, the `K` keys `Account*`, `MAX_BODY`, the test harness `cfg_for` and its
`ureq` clients), `src/lib.rs` (`Settings`, `compile_issuer`, `IDENTITY_ATTRS`, `norm_email`, the
test that reads both unit files), `deploy/bb-auth-web.service`, and `ureq-3.4.0/src/config.rs`
and `src/proxy.rs` in the cargo registry.

#### What is known, and how

**Measured** (a real run): the email-code sign-in works against the real pool from the browser,
with `Content-Type: application/x-amz-json-1.1`, `X-Amz-Target:
AWSCognitoIdentityProviderService.<Action>`, the error code in the body's `__type` after its last
`#`, and `RespondToAuthChallenge`'s `USERNAME` taken from `ChallengeParameters.USERNAME`: that is
what `login.html` does on every sign-in on rpi-01. And the sign-up branch of that page works,
which means `InitiateAuth` on `gate.client_id` answers `UserNotFoundException` for an unknown
email, which only happens with `PreventUserExistenceErrors` `LEGACY` (the page's own comment says
it relies on that).

**Read in the pool on 2026-11-25** (PLAN.md step 5, read-only, by the IT-Admin session): email is
the username; `EMAIL_OTP` is a first factor; the native client `gate.client_id` allows
`ALLOW_USER_AUTH`, `AuthSessionValidity` 3 minutes, no secret, `ReadAttributes` and
`WriteAttributes` unset; the social client allows only `ALLOW_REFRESH_TOKEN_AUTH`;
`AttributesRequireVerificationBeforeUpdate` is empty; no custom attributes. The pool and both
clients are OpenTofu-managed in another repository, so **this step changes nothing in the pool**.

**Read in a source:**

- `InitiateAuth` cannot sign in a federated user, and `USER_AUTH` takes `USERNAME` and
  `PREFERRED_CHALLENGE`; an `EMAIL_OTP` answer carries `ChallengeName`, `ChallengeParameters` and
  `Session` ([InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html)).
- `EMAIL_OTP` is answered with `USERNAME` and `EMAIL_OTP_CODE`; a `Session` is 20 to 4096
  characters; the errors include `CodeMismatchException`, `ExpiredCodeException`,
  `NotAuthorizedException`, `TooManyRequestsException`; success is an `AuthenticationResult`
  with `AccessToken`, `IdToken`, `RefreshToken`
  ([RespondToAuthChallenge](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html)).
- `UpdateUserAttributes` is authorized by the access token alone (scope
  `aws.cognito.signin.user.admin`, IAM not evaluated), a blank value deletes the attribute, and
  an attribute the client may not write is `NotAuthorizedException`
  ([UpdateUserAttributes](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserAttributes.html),
  [attribute permissions](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-attribute-permissions-and-scopes)).
- With `WriteAttributes` unset, an app client may write every standard and custom attribute, and
  `DescribeUserPoolClient` returns the two lists only when they are not the default; values are up
  to 2048 characters; the `oidc:profile` set is `name`, `family_name`, `given_name`,
  `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`,
  `birthdate`, `zoneinfo`, `locale`
  ([user attributes](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html)).
  This replaces the plan's "unverified" on the default.
- With `PreventUserExistenceErrors` `ENABLED`, `USER_AUTH` answers an unknown user with a
  simulated challenge instead of `UserNotFoundException`
  ([user existence errors](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html)).
- An ID token carries `iss`, `sub`, `aud` (the app client), `exp`, `token_use` = `id`, and
  `email`/`email_verified` when readable; `identities` marks a federated sign-in
  ([ID token](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-id-token.html)).
- `IPAddressDeny=`/`IPAddressAllow=` filter both ingress and egress, by destination for outgoing
  packets, and `localhost` is 127.0.0.0/8 and ::1/128
  ([systemd.resource-control(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)).
- `ureq` 3.4: no timeout unless set (`Timeouts::default`), `http_status_as_error` true by
  default (a `400` would be an `Err` with no body), a proxy taken from `ALL_PROXY`/`HTTPS_PROXY`
  when set, and `timeout_global` end to end (`config.rs`, `proxy.rs`).

**Assumed, and to be confirmed by the real run of 5d:** that a social-only email gets
`UserNotFoundException` from the native client rather than a challenge (it follows from
`LEGACY` and from `InitiateAuth` not signing federated users in, but no run has shown it); that
the `AccessToken` and `IdToken` of one `AuthenticationResult` name the same user; that one
`UpdateUserAttributes` applies all its attributes or none; that 5 s per call is enough; that
an email code is at most 16 ASCII letters and digits (the documented example is 8 digits).

#### Decisions

**The client is `gate.client_id`**, read per request from the settings file as the page already
reads it. It is the client that has `ALLOW_USER_AUTH`, the one `login.html` signs in with, and
it has no secret, so no `SECRET_HASH` and no secret anywhere in `bb-auth-web`. A social button's
`audience` is never used: the social client cannot run this flow at all. An empty
`gate.client_id` or `gate.issuer` means the edit is **not offered** (no Edit control), because a
form that can only end in an error is a promise the page cannot keep.

**The endpoint is `Settings::cognito_endpoint()`**, moved from the gate's private
`cognito_endpoint` into the library with the origin rule it needs (the gate's `origin_of` keeps
its other use). By the membership rule: both programs derive the API's address from the
settings file's `gate.issuer`, and two derivations are two answers. `email_verified_true` moves
beside it for the same reason one step along: both programs read a Cognito ID token, and must
not disagree on what "verified" means.

**The call is the existing `ureq` with rustls, no new crate.** One function,
`cognito_call(cfg, settings, action, body) -> Result<Value, CognitoError>`, used for all three
actions, with an agent built with `timeout_global(Some(cfg.cognito_timeout))`,
`http_status_as_error(false)` (so a `400`'s `__type` is readable), `max_redirects(0)` (a
redirect from the API is a refusal, never a second host handed a token), the two headers above,
and the body as JSON. `CognitoError` is `NoAnswer` (timeout or transport) or `Refused(code)`,
the code being `__type` after its last `#` and nothing else from the body. `cfg.cognito_timeout`
is the constant `COGNITO_TIMEOUT` = 5 s in production and is no env var (§13.13: assumed, no
retry, at most two calls per request: the start makes one, the code step two).

**The fake endpoint is a `Config` field, not an env var.** `compile_issuer` is https-only, so a
plain-HTTP fake cannot be named through the settings file, and a TLS fake would need a test CA
the bundled roots do not trust. So `Config` gains `cognito_endpoint: Option<String>`, which
`from_env` always leaves `None` (then `Settings::cognito_endpoint()` is used) and which the tests
set to their fake's `http://127.0.0.1:<port>/`; no variable and no file can set it on a host.
`FakeCognito`, in `bb-auth-web`'s test module: a `tiny_http` server on `127.0.0.1:0` in a
thread, recording every request as `(X-Amz-Target, JSON body)` and answering each action from a
per-test script (status, JSON). It mints ID tokens as `base64url(header).base64url(payload).x`
with whatever claims a test chooses, and uses distinctive token strings (`FAKEACCESS...`,
`FAKEID...`, `FAKEREFRESH...`) so a test can search every response for them. A `silent` mode is
a plain `TcpListener` that accepts and holds the socket without a byte. The tests set
`cognito_timeout` to 300 ms so the silent test is fast, and never reach the real pool.

**The identity is bound twice: before Cognito, and after.** (Changed by §13.25: the binding key
is the session's own Cognito username, forwarded by the gate, and no longer the email.)

1. *Before*, on both `POST`s, against the live files: the identity header, the `denied` veto,
   the one-row rule (§13.5), and the chosen email **among the header's own values**
   (`norm_email` on both sides). A chosen email that is not the caller's is a `400` and **no**
   Cognito call is made. Every hidden field the code step carries back (email, values, the
   challenge username, the `Session`) is re-validated there as if new. (Changed by §13.25: no
   chosen email and no challenge username any more; a session with no `X-Auth-Native-Username`
   is refused here with no call.)
2. *After*, between `RespondToAuthChallenge` and `UpdateUserAttributes`, the returned `IdToken`
   must have `token_use` = `id`, `iss` = `gate.issuer`, `aud` = `gate.client_id`, `exp` in the
   future, a truthy `email_verified`, and an `email` equal (`norm_email`) to the chosen email.
   Anything else is a `403`, the `AccessToken` is dropped unused, and the journal says a token
   named another account (without that account's email). This is what makes a `Session`
   obtained for some other address (one the caller also reads mail for) unable to act here,
   whatever Cognito does with a mismatched `USERNAME`. (Changed by §13.25: the email comparison
   is replaced by `cognito:username` equal to the session's; on rpi-01 the email check passed for
   a native twin of a federated session, which is the bug §13.25 fixes.)

   The `sub` is not compared: nginx hands `bb-auth-web` no Cognito `sub` (the identity
   attributes are `email` and the roster's `uuid`), so the email is the only identity the two
   sides share, and it is the pool's username. **The signature is not verified**, on purpose:
   the token arrived in the TLS response to a request this process made to the endpoint
   derived from `gate.issuer`, so a forger would have to be the endpoint, and a party that can
   answer as the endpoint can answer `UpdateUserAttributes` too. Verifying would need the JWKS,
   a third call. The AWS page's "verify before you trust" is about a token a client *hands* an
   application, which is the gate's case and not this one. (Changed by §13.25: the gate now
   forwards the session's Cognito username, so the email is no longer the only shared identity.)

**Editable is an allowlist, intersected with the settings.** An attribute is editable iff it is
in `gate.profile_claims` **and** in the `oidc:profile` list minus `preferred_username`
(`name`, `family_name`, `given_name`, `middle_name`, `nickname`, `profile`, `picture`, `website`,
`gender`, `birthdate`, `zoneinfo`, `locale`). Not `email`, `phone_number`, `address`, `sub`,
`updated_at`, `dev:`, and not `custom:` today: the pool has none, and adding them is a later
decision with its own argument. A list of what is allowed fails closed when somebody configures
a new claim; the denylist of §13.7 failed open. A value is trimmed, at most 2048 characters (the
documented limit), and free of control characters, else a `400` before Cognito. Only the fields
whose value differs from what nginx forwarded on this request are sent; a form with no change
sends **no** code. An emptied field that had a value is sent empty, which deletes the attribute
(as documented), and the form says so beside each field.

**The page and its routes.** Two paths join `handle_account`'s closed list, both under the
account prefix and both `no-store`:

- `GET <prefix>/profile`: the account page with the Profile panel as a `form.edit` (the
  `keys/new` pattern of §13.16): one field per editable claim, prefilled with the forwarded
  value; the configured claims that are not editable and the caller's email(s) shown read-only,
  email with the sentence that an administrator changes it; "Send code to" as a `select` over
  the header's emails, or a hidden field when there is one; a line saying a person who signs in
  only through a social provider has their profile from that provider and cannot change it here.
  (Changed by §13.25: no "Send code to" at all, the code goes to the session's own Cognito user;
  a session that is not a native sign-in gets no form, only the provider sentence.)
  The read-only panel gains an Edit pill to this page when the edit is offered.
- `POST <prefix>/profile`: validate (above), call `InitiateAuth` (`USER_AUTH`,
  `PREFERRED_CHALLENGE=EMAIL_OTP`, `USERNAME` = chosen email, `ClientId` = `gate.client_id`), and
  answer the code page: one code field, a Save button, a Start-again link to `GET
  <prefix>/profile` (changed by §13.23: a "Send a new code" form re-posting the values instead), and hidden fields for the `Session`, `ChallengeParameters.USERNAME`, the
  chosen email and the changed values (changed by §13.25: `USERNAME` is the session's
  `X-Auth-Native-Username`, the hidden fields are the `Session` and the values only). An answer that is not an `EMAIL_OTP` challenge (tokens
  straight away, another challenge) is a refusal: nothing acts without a code.
- `POST <prefix>/profile/code`: re-check (above), `RespondToAuthChallenge`, bind, then
  `UpdateUserAttributes` with the changed values, and drop every token. Success is a `200` page
  (not a redirect: the panel is drawn from the cookie and would show the old values) naming the
  attributes changed and saying the applications see the change from the next sign-in.

| Cognito says | The person sees | Status |
|---|---|---|
| no answer within the bound | the service did not answer, nothing changed (changed by §13.23: on `UpdateUserAttributes` it says the change may have been made) | `504` |
| `UserNotFoundException` (start) | this account does not sign in with an email code, so its profile is its provider's (changed by §13.25: a federated session never reaches Cognito; this now means the session's user was deleted since sign-in) | `400` |
| `CodeMismatchException` | the code form again, "wrong code", with the answer's new `Session` if it carried one, else the same | `400` |
| `ExpiredCodeException`, `NotAuthorizedException` (code step) | the code has expired, start again | `400` |
| `TooManyRequestsException` | too many attempts, try later | `502` |
| `NotAuthorizedException`, `InvalidParameterException` (update) | the change was refused, nothing changed (a value Cognito did not accept for the second) | `502`, `400` |
| anything else | the service refused, nothing changed | `502` |
| a token for another account | nothing changed | `403` |

**Social-only people are told twice and never sent an email that cannot arrive.** Once on the
form, before they start, and again when `InitiateAuth` answers `UserNotFoundException`, which is
how their email shows on the native client while `PreventUserExistenceErrors` stays `LEGACY`
(which `login.html`'s sign-up branch already requires). If the pool ever moved to `ENABLED`,
the same person would get a code form and no email, and the code form's line "No code? An
account that signs in only through a social provider cannot change its profile here" covers that
case too, so the design does not depend on which value the pool holds. A person with both a
native and an unlinked social user under one email edits the native one; the success page names
the email the change was made for. (Changed by §13.25: that last sentence was the rpi-01 bug of
2026-11-25. A federated session is now told before any call, by the gate's
`X-Auth-Native-Username` being absent, and edits nothing, whichever twin exists.)

**Who may edit**: anybody the page already serves, roster row or not, since the Cognito profile
is the person's whatever the access file says and §13.12 (2) opens the page to strangers. The
`denied` veto is answered before any of it, as everywhere on the page.

**What is never logged**: the code, the `Session`, any token, any attribute value, and Cognito's
`message` text (it can carry the username). The journal gets, in the GUI's shape,
`[bb-auth-web] <uuid, else the chosen email> (self): profile update <attribute names>` on success,
`... (self): profile update refused (<code>)` when the update is refused, `... (self): profile
update refused (token named another account)` on a binding failure, and `cognito <Action> did not
answer within 5s` on a timeout. A wrong code is not logged (it is the ordinary mistake).
`stderr` cannot be read over the test socket (§13.15's note), so the guarantee is made by type:
the journal line is built by a function that takes attribute **names** only, and the type that
holds the tokens prints as `Tokens { .. }` under `Debug`.

**The unit loses `IPAddressDeny=any` and `IPAddressAllow=localhost`** in the slice that makes
the first call, with the unit's comment rewritten ("no outbound connection at all" stops being
true). The cost is §13.7's, restated: the kernel's loopback lock on the listener goes, leaving
the binary's bind check and the proxy secret, and the most privileged process on the host gains
egress anywhere. `RestrictAddressFamilies` already allows `AF_INET`/`AF_INET6`;
`InaccessiblePaths=/opt/bb-auth/etc` stays, so egress does not come with the HMAC key. Rejected
again, for §13.7's reasons: an `IPAddressAllow=` of AWS ranges, and relaying through the gate.

**Abuse**: each start sends one email, only to one of the caller's own addresses, and Cognito
throttles (`TooManyRequestsException`). A signed-in person looping the form spends the pool's
authentication quota, which anyone can already do by calling the public `InitiateAuth` with the
client id `login.html` publishes; no new exposure, no limiter added.

#### The `K` keys and the page sections

No new section: the edit lives in the existing `section#profile` panel, as a form on
`<prefix>/profile` and as two card pages after it, all inside `account_shell`. New keys, English
and Italian, wording the designer's (5b): `AccountProfileEdit` (the pill), `AccountProfileEditSub`
(what the code is for), `AccountProfileEmailFixed` (an administrator changes the email),
`AccountProfileClearDeletes` (an emptied field removes the value), `AccountProfileSocialNote`
(a social-only account's profile is its provider's), `AccountProfileSendTo`,
`AccountProfileSendCode`, `AccountProfileCodeTitle`, `AccountProfileCodeBody` (the code went to
`{email}` and lasts a few minutes, never a number the pool may change), `AccountProfileCodeLabel`,
`AccountProfileNoCode` (the line for a code that never arrives), `AccountProfileSave`,
`AccountProfileStartAgain`, `AccountProfileSavedTitle`, `AccountProfileSavedBody` (the change shows
from the next sign-in), `AccountProfileNothingChanged`, `AccountProfileWrongCode`,
`AccountProfileExpired`, `AccountProfileNoEmailSignIn`, `AccountProfileNoAnswer`,
`AccountProfileTooMany`, `AccountProfileRefused`, `AccountProfileBadValue`, `AccountProfileNotYours`.
No logic reads any of them.

#### Slices

Each starts with its tests red. Design first: **5b needs the designer** for the form, the code
page and the outcome pages of 5c (one pass covering both, with Italian texts); 5a and 5c's
logic do not.

**5a. `Settings::cognito_endpoint` and `email_verified_true` in the library.** No behaviour
changes.

- Tests: `the_cognito_endpoint_is_the_issuers_origin` (lib: the pool URL gives
  `https://cognito-idp.<region>.amazonaws.com/`, an empty issuer gives empty);
  `email_verified_is_true_or_the_string_true` (lib, moved from the gate); the gate's test that
  the sign-in page carries `var ENDPOINT = "https://cognito-idp.eu-central-1.amazonaws.com/";`
  stays green unchanged.
- Done when: the gate's private function is gone, both programs call the method, `cargo test`,
  clippy, fmt and `cargo doc --no-deps` clean.

**5b. The form and the start: refusals before Cognito, `InitiateAuth`, the code page, the
unit.** Lands `cognito_call`, `FakeCognito`, the two `Config` fields, the keys above
and the unit change together, because a client nobody calls is a `dead_code` warning and clippy
must stay clean.

- Tests (bb-auth-web unless marked): `the_profile_panel_offers_edit_only_when_wired` (no
  `client_id`, no `issuer`, no editable claim: no pill; all three: a pill to `<prefix>/profile`);
  `the_profile_form_offers_only_editable_claims` (`email`, `phone_number`,
  `preferred_username`, `address` configured: read-only, never an input);
  `the_code_goes_only_to_the_callers_own_emails` (a `select` of the header's values, a hidden
  field for one); `an_email_not_among_the_callers_is_refused_before_cognito`,
  `a_non_editable_attribute_is_refused_before_cognito`,
  `an_overlong_or_control_value_is_refused_before_cognito`, `an_unchanged_form_sends_no_code`,
  `a_denied_caller_cannot_start_a_profile_edit`, `a_cross_site_profile_post_is_refused` (each:
  the status, and the fake recorded **zero** calls);
  `starting_an_edit_asks_cognito_for_an_email_code` (one `InitiateAuth`, the target header, the
  content type, `USER_AUTH`, `gate.client_id`, the chosen email, `EMAIL_OTP`);
  `the_code_page_carries_the_session_and_is_not_stored`;
  `an_email_with_no_code_sign_in_is_told_its_profile_is_its_providers`
  (`UserNotFoundException`); `an_answer_that_is_not_an_email_code_is_refused`;
  `a_cognito_call_follows_no_redirect`; `a_silent_cognito_answers_within_the_bound_and_frees_the_worker`
  (one worker, the silent fake: a `504` within the bound plus 2 s, then `GET <prefix>/` is a
  `200`); the route-classification test of §13.11 extended to the two paths;
  `the_gui_unit_lets_cognito_out` (lib, reading `deploy/bb-auth-web.service`: no `IPAddress`
  line, `InaccessiblePaths=/opt/bb-auth/etc` and `RestrictAddressFamilies` still there); the
  existing `BB_AUTH_WEB_ALLOW_NONLOOPBACK` startup refusal stays.
- Done when: the above, the designer's look at the form and the code page (`node e2e/shots.js
  account`, light, dark, phone, `it`), `node e2e/run.js` including the scripting-off walk (the
  pages carry no script). **5b and 5c ship together**: no deploy between them, since 5b's code
  page posts to 5c's route.

**5c. The code step: answer, bind, update.**

- Tests: `a_wrong_code_changes_nothing` (`CodeMismatchException`: the form again, no
  `UpdateUserAttributes` recorded, the new `Session` reused);
  `an_expired_code_starts_again`; `a_token_for_another_account_is_never_used` (an `IdToken`
  naming another email: `403`, no update recorded);
  `a_token_of_the_wrong_audience_issuer_or_use_is_never_used` (one case each, plus expired and
  unverified); `the_code_step_rechecks_everything` (a hidden email edited to a stranger's, the
  caller added to `denied` between the steps, the claim dropped from `gate.profile_claims`
  between the steps: each refused with zero calls);
  `a_right_code_updates_exactly_the_changed_attributes` (the fake's `AccessToken`, only the
  changed names, the success page names them and says "next sign-in");
  `an_emptied_field_deletes_the_attribute`; `a_refused_update_says_so`;
  `no_token_reaches_any_response` (the three fake token strings in no body and no header of the
  whole flow, and the `Session` not on the success page); `at_most_two_cognito_calls_per_request`;
  `the_profile_journal_line_names_attributes_only`; `tokens_print_as_redacted`.
- Done when: the above, the designer's look at the outcome pages, e2e green.

**5d. Real, with the user's go-ahead.** Deploy (this is where egress opens on rpi-01), then: the
unit has no `IPAddress` line; `curl` to `127.0.0.1:8091` without the secret is still a `403`; a
non-loopback `BB_AUTH_WEB_LISTEN` without the opt-in still refuses to start; in a browser, a
native test account changes `given_name`, signs out and in, and `/account/` shows the new value
(the next token's profile claim); a social-only account is told its profile is its provider's
and receives no email (this confirms the first assumption above); nginx's
`$upstream_response_time` for those requests is recorded against the 5 s bound. Docs: the
trust model in `AGENTS.md` (the GUI now calls Cognito, and what it never logs), the unit's
comments, and this section shrinking to the component view.

- Done when: step 5's "Done when" in `PLAN.md` holds.

### 13.23 The profile edit, as a person sees it (plan step 5, slices 5b and 5c, designed 2026-11-25)

The interface of §13.22: the form, the code page and the outcome pages, in one pass, with every
word in English and Italian. §13.22 decides what is called and what is checked; this section
decides what a person sees and does. Where it changes §13.22 the change is marked there.

What was looked at: §13.16, §13.17, §13.21 and §13.22 of this document; `PLAN.md` step 5;
`page_account`, `account_shell`, `form_shell_at`, `text_field`, `account_key_id_field`,
`confirm_card`, `page_account_minted` and the `K` keys `Account*`, `Back`, `Cancel` in
`src/bin/bb-auth-web.rs`; the component list of `src/assets/base.css` (`.msg.warn`, `.err`,
`.tag.warn`, `.card`, `.pill`, `.hint`, `.lbl`) and `input.f-*` in `src/assets/admin.css`; the
current screenshots `e2e/artifacts/visual/light/account{,-new,-rm}.png`. Mockups: plain HTML over
the real `theme.css`, `base.css` and `admin.css` plus one proposed rule, generated by
`/tmp/d5b/gen.js` and shot by `/tmp/d5b/shot.js` in Edge at 1280 light and dark and 360:
`/tmp/d5b/shots/<page>-{light,dark,phone}.png` for `ro`, `form`, `form-one`, `form-nothing`,
`code`, `code-wrong`, `saved`, `expired`, `social`, `noanswer`, `unsure`. No page scrolls sideways
at 360 (measured, `scrollWidth`).

Measured: only the mockups' layout (no sideways scroll, the shots above). Read in a source: each
WCAG, HTML and MDN fact, cited where used. Assumed: that most screen readers do not announce `s`
(the reason given for writing changes in words, which is right either way), the screen-reader note on
the wrong-code `autofocus`, and every Cognito fact §13.22 lists as assumed.

User decisions this rests on (2026-11-25): a stranger (a Cognito account with no roster row) may
edit their own profile; emptying a field and saving deletes that attribute in Cognito; email stays
read-only.

#### 1. An Edit pill, then the form in place (the `keys/new` pattern)

The read-only Profile panel stays what every visit sees, and gains one `p.primary > a.pill`
(`K::AccountProfileEdit`, "Edit profile") after its list, exactly where "+ New key" sits in the keys
panel. It is `GET <prefix>/profile`: the same account page, with the Profile panel's content
replaced by the form (§13.22), as `keys/new` replaces one table row. The pill appears only when
§13.22 says the edit is offered (issuer, client id, and at least one editable claim), for a
stranger too.

Rejected: **the panel always a form.** Most visits read; a form that is always open puts twelve
"empty it to remove it" hints and a Send button on the page of somebody who came to look, and one
stray Enter in a field would send an email. Editing costs an email, so it starts with an explicit
act (Nielsen 3, user control; error prevention). Rejected: **a page of its own** without the rest of
the account: the keys flow already taught "the page, with one part open", and a second pattern for
the same act would cost recognition (Nielsen 4, consistency).

`autofocus` on the first editable field (no fragment on the pill's URL, the skill's pitfall), so
the browser scrolls to the form and the keyboard starts in it.

#### 2. The form

Inside `section#profile.panel`: the `h2` stays, the sub-line becomes `K::AccountProfileEditSub`, then
one `form.edit` posting to `<prefix>/profile`:

- **One field per editable claim**, in `gate.profile_claims` order, with a **human label** (one `K`
  key per attribute, below), never the claim name: a form labelled `family_name` asks the person to
  translate (WCAG 3.3.2, <https://www.w3.org/WAI/WCAG22/Understanding/labels-or-instructions.html>).
  The read-only panel keeps its `code` claim names; it is the wiring view and is not changed here.
- Each field is `input type="text"`, `maxlength="2048"` (the documented limit), `autocapitalize`
  and `spellcheck` left at the browser's default for names (people's names are prose, unlike a key
  id), and an `autocomplete` token from the HTML autofill list, which WCAG 1.3.5 (AA) asks for on a
  field about the user (<https://www.w3.org/WAI/WCAG22/Understanding/identify-input-purpose.html>,
  tokens: <https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#autofill>):
  `name`, `given-name`, `family-name`, `additional-name` (middle_name), `nickname`, `sex` (gender),
  `bday` (birthdate), `url` (website, profile), `photo` (picture), `language` (locale);
  `zoneinfo` has no token and gets none. `inputmode="url"` on the three URL fields.
- **No `type="date"` and no `type="url"`, on purpose.** The browser sanitises a `date` field's value
  to empty when it is not a valid date string
  (<https://html.spec.whatwg.org/multipage/input.html#date-state-(type=date)>), and Cognito accepts
  `0000-MM-DD`; a prefilled value the browser blanked would then post as an emptied field and
  **delete** the attribute while the person was changing something else. A `url` field refuses to
  submit the whole form when a stored value is not an absolute URL, which would block a change of
  name because of an old website. Both browser features would turn an old value into a trap, so
  every field is text and the server checks. Birthdate carries the hint `K::AccountProfileDateHint`
  ("YYYY-MM-DD").
- **What an emptied field says before saving, without a script.** Under each field that has a value
  now, `span.hint` `K::AccountProfileClearDeletes` ("Empty it to remove it."): the rule is told where
  the act happens. The **code page then lists every change, a removal in words** (section 3), so the
  deletion is confirmed before it is made. That is WCAG 3.3.4's "Confirmed" for a submission that
  deletes user data, AA (<https://www.w3.org/WAI/WCAG22/Understanding/error-prevention-legal-financial-data.html>),
  and it costs no extra step, because the code page exists anyway. No live "will be removed" warning
  on the form: that needs a script, and the code page says it with certainty instead of guessing
  from keystrokes.
- **Configured claims that are not editable** (what an operator configured outside the
  allowlist): a `ul.plain` of `code` claim `": "` value, as the read-only
  panel shows them, after the fields. No hint per line: §13.22's allowlist is the reason, and a
  person needs to know only that these are not fields.
- (Changed by §13.26: there is no choice and no address on the form any more; the code goes to
  the session's own Cognito user, and `AccountProfileEmailFixed` is a `p.muted` after the
  fields.) **Where the code goes.** `K::AccountProfileSendTo` ("Send the code to") as the label of a `select`
  over the identity header's emails, header order, the first selected, when there are two or more.
  With **one** email no choice is shown: a `div` with `span.lbl` "Send the code to", the address in
  `code`, and the hidden `email` input (no `label` element, since there is no control to label). In
  both cases `span.hint` `K::AccountProfileEmailFixed` under it, which is where the email's
  read-onlyness is said: the person reads their address at the moment they need it, and is told once
  why it is not a field. There is no separate read-only email line: it would be the same address a
  second time.
- (Removed by §13.26: the form is offered only to a native sign-in, so the note is never true
  of its reader.) `p.muted` `K::AccountProfileSocialNote`, before the buttons: a person who signs in only through a
  social provider learns it before an email is promised (§13.22, "told twice").
- `div.actions`: `button` `K::AccountProfileSendCode` ("Send code"), `a.pill` `K::Cancel` to the
  account page. The shape of `form_shell_at` without `rev` (this form changes no file).

**Nothing changed.** A submission whose values all equal the forwarded ones sends no code (§13.22)
and answers `200` with the same form and, at its top, `div.msg.warn#err`
`K::AccountProfileNothingChanged`. Not `.err`: the person did nothing wrong, the page only explains
why no email is coming.

**A refusal before Cognito** (a value with a control character, a value over 2048 that a
hand-edited form sent, an email not among the caller's, an attribute not editable): the form again,
`400`, the values as posted, and `div.err#err` naming the field by its **visible label** (the
skill's pitfall): the label, `": "`, then `K::AccountProfileValueBad`; the field `aria-invalid="true"`
`aria-describedby="err"` (WCAG 3.3.1, <https://www.w3.org/WAI/WCAG22/Understanding/error-identification.html>).
The two that only a crafted request reaches are a sentence and no field: `K::AccountProfileNotYourEmail`,
`<label>` or the claim name `": "` `K::AccountProfileCannotEdit`.

#### 3. The code page

Its own page in `account_shell`, the `h1` `K::AccountProfileCodeTitle` ("Enter the code"), as the
confirmations wear their act as the `h1` (§13.17).

- (Changed by §13.26: the address is Cognito's masked `CODE_DELIVERY_DESTINATION`, or the whole
  sentence `AccountProfileCodeSentNoDest` when there is none.) `p.lede`: `K::AccountProfileCodeSent` + `code` email + "." + " " + `K::AccountProfileCodeLasts`
  ("It works for 3 minutes."). **The number is said**: the person must know they are racing a clock
  (Nielsen 1), and "a few minutes" is not something one can plan by. It lives in exactly one key,
  so a change of the pool's `AuthSessionValidity` is a one-line edit of the `K` table (open
  question 1). The limit is Cognito's and is a security limit, which WCAG 2.2.1's essential
  exception covers (<https://www.w3.org/WAI/WCAG22/Understanding/timing-adjustable.html>); what makes
  it humane is that starting again keeps every value (below).
- `div.card`, holding, in this order: the refusal when there is one (`div.err#err`), `p.lbl`
  `K::AccountProfileChanges` ("What will change"), then a `ul.plain.changes`, one `li` per changed
  attribute: label `": "` new value `" "` `span.muted` `"("` `K::AccountProfileWas` `" "` old value
  `")"`; a removal is label `": "` `span.tag.warn` `K::AccountProfileRemoved` and the same `was`
  part; an attribute that had no value has no `was` part. **In words, not strike-through**: `s` is
  not announced by most screen readers and colour alone fails WCAG 1.4.1
  (<https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html>). `.tag.warn` and not `.tag.bad`:
  the removal is what the person asked for, so it is pointed out, not alarmed about.
  Then the `form.edit` posting to `<prefix>/profile/code`: the hidden fields of §13.22, one field
  `K::AccountProfileCodeLabel` ("Code"), and `div.actions` with `button` `K::AccountProfileSave`
  ("Save profile") and `a.pill` `K::Cancel` to the account page.
- The code field: `input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"
  autocapitalize="off" spellcheck="false" required maxlength="32" autofocus`, class `f-code`
  (MDN: <https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/autocomplete>,
  <https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Global_attributes/inputmode>).
  **No `pattern`**: a pasted `123 456` would be blocked by the browser for a space the server can
  simply strip (forgiving input). The server removes whitespace, then checks ASCII letters and digits,
  at most 16 (§13.22's assumption). `type="text"` and not `number`: a code can begin with `0`, and a
  number field shows spinners and accepts `1e3`.
- After the card: one more `form.edit` posting the same hidden values (email and changed values,
  never the `Session`) to `<prefix>/profile`, holding `p.muted` `K::AccountProfileNoCode` and
  `div.actions > button.pill` `K::AccountProfileSendNew` ("Send a new code"). **Resend is starting
  over**, and it says so by being the start's own form: one `InitiateAuth`, a new email, a new page.
  It replaces §13.22's Start-again *link* to `GET <prefix>/profile`, which would drop everything the
  person typed (WCAG 2.2.5 asks this at AAA; it is cheap here). The button is the secondary style,
  so Save stays the one primary action.
- **A wrong code** (`CodeMismatchException`): the same page, `400`, `div.err#err`
  `K::AccountProfileWrongCode` at the top of the card, the field emptied, `aria-invalid="true"
  aria-describedby="err"`, and no `autofocus` (assumed, not tested with a screen reader: focus jumping past the
  error would skip it; the field still names it through `aria-describedby`). The summary stays.

CSS: one rule in `admin.css`, beside `input.f-id`: `input.f-code{max-width:14ch}` (a code is short;
a full-width box reads as "type a sentence"). Tried first: the existing `f-id` measure, which is the
same width but a class named for another field.

#### 4. The outcome pages

One shape for all: `account_shell` with an `h1` that states the result, one `p.lede` saying why and
what to do, and one row of actions. The `h1` is the result, not the cause, so the person learns in
three words whether anything happened (Nielsen 1, 9).

| Case (from §13.22's table) | `h1` | `p.lede` | Actions | Status |
|---|---|---|---|---|
| saved | `AccountProfileSavedTitle` | `AccountProfileSavedLead` + the changed labels, comma-joined + "." + `AccountProfileSavedBody` | `a.pill` "← " `K::Back` | `200` |
| no answer, at `InitiateAuth` or `RespondToAuthChallenge` | `AccountProfileNotSavedTitle` | `AccountProfileNoAnswer` | Send a new code, back | `504` |
| no answer, at `UpdateUserAttributes` | `AccountProfileUnsureTitle` | `AccountProfileNoAnswerUnsure` | back | `504` |
| `UserNotFoundException` (changed by §13.26: lede `AccountProfileNoUser`) | `AccountProfileNotSavedTitle` | `AccountProfileNoEmailSignIn` | back | `400` |
| expired or `NotAuthorizedException` at the code step | `AccountProfileNotSavedTitle` | `AccountProfileExpired` | Send a new code, back | `400` |
| `TooManyRequestsException` | `AccountProfileNotSavedTitle` | `AccountProfileTooMany` | back | `502` |
| update refused / `InvalidParameterException` | `AccountProfileNotSavedTitle` | `AccountProfileRefused` / `AccountProfileBadValue` | back | `502` / `400` |
| a token for another account, or a challenge naming another username (§13.26, reworded there) | `AccountProfileNotSavedTitle` | `AccountProfileNotYours` | back | `403` |
| any other refusal | `AccountProfileNotSavedTitle` | `AccountProfileRefused` | back | `502` |

"Send a new code, back" is one `form.edit` re-posting the values to `<prefix>/profile`, with
`div.actions > button` `K::AccountProfileSendNew` (primary here: it is the way forward) and `a.pill`
"← " `K::Back`. "back" alone is `p.primary > a.pill`, as `page_account_minted` does.

**The timeout at the update is not "nothing changed"** (changed in §13.22's table): a request that
reached Cognito and timed out may have been applied, and telling the person it was not would be a
claim the page cannot make. The other two timeouts happen before anything is written and can say it.

**Saved, and why the account page still shows the old value.** The panel is drawn from the cookie,
so "← back" lands on the old values; `AccountProfileSavedBody` says it before the person sees it
("Your applications, and this page, show it from your next sign-in.") rather than letting the
person think the save failed.

**Not named: Cognito.** The person does not know the word; "the sign-in service" is what they used.
The journal names it (§13.22).

#### 5. The `K` keys, English and Italian

(Changed by §13.26: `AccountProfileSendTo`, `AccountProfileSocialNote`,
`AccountProfileNotYourEmail` and `AccountProfileNoEmailSignIn` go; `AccountProfileNoCode` and
`AccountProfileNotYours` are reworded; three keys are added. The table below is the 5b-5d state.)
New keys (no logic reads any; the sentences around a value are split, as `BearerHintLead`/`Tail`
are, because the table has no placeholders). This replaces §13.22's provisional list: kept
`AccountProfileEdit`, `EditSub`, `EmailFixed`, `ClearDeletes`, `SocialNote`, `SendTo`, `SendCode`,
`CodeTitle`, `CodeLabel`, `NoCode`, `Save`, `SavedTitle`, `SavedBody`, `NothingChanged`, `WrongCode`,
`Expired`, `NoEmailSignIn`, `NoAnswer`, `TooMany`, `Refused`, `BadValue`, `NotYours`; `CodeBody`
split into `CodeSent` and `CodeLasts`; `StartAgain` renamed `SendNew`; added the rest.

| Key | English | Italian |
|---|---|---|
| `AccountProfileEdit` | Edit profile | Modifica il profilo |
| `AccountProfileEditSub` | Change what you need, then confirm with a code we email you. | Cambia ciò che ti serve, poi conferma con un codice che ti mandiamo per email. |
| `AccountProfileClearDeletes` | Empty it to remove it. | Svuotalo per eliminarlo. |
| `AccountProfileDateHint` | YYYY-MM-DD | AAAA-MM-GG |
| `AccountProfileSendTo` | Send the code to | Invia il codice a |
| `AccountProfileEmailFixed` | Your email address is how you sign in, so only an administrator can change it. | Il tuo indirizzo email è il modo in cui accedi, quindi solo un amministratore può cambiarlo. |
| `AccountProfileSocialNote` | If you sign in only with a social account such as Google, your profile comes from that provider and cannot be changed here. | Se accedi solo con un account social come Google, il tuo profilo viene da quel fornitore e non si può cambiare qui. |
| `AccountProfileSendCode` | Send code | Invia il codice |
| `AccountProfileNothingChanged` | Nothing to save: every field is as it was, so no code was sent. | Niente da salvare: ogni campo è com'era, quindi non è stato inviato alcun codice. |
| `AccountProfileValueBad` | too long, or holds characters that cannot be saved. | troppo lungo, o contiene caratteri che non si possono salvare. |
| `AccountProfileNotYourEmail` | The code can only go to one of your own email addresses. | Il codice può andare solo a uno dei tuoi indirizzi email. |
| `AccountProfileCannotEdit` | cannot be changed here. | non si può cambiare qui. |
| `AccountProfileCodeTitle` | Enter the code | Inserisci il codice |
| `AccountProfileCodeSent` | We emailed a code to | Abbiamo inviato un codice a |
| `AccountProfileCodeLasts` | It works for 3 minutes. | Vale per 3 minuti. |
| `AccountProfileChanges` | What will change | Cosa cambierà |
| `AccountProfileWas` | was | prima: |
| `AccountProfileRemoved` | removed | eliminato |
| `AccountProfileCodeLabel` | Code | Codice |
| `AccountProfileSave` | Save profile | Salva il profilo |
| `AccountProfileNoCode` | No email after a minute? Look in your spam folder, or send a new code. If you sign in only with a social account, no code will come: your profile is kept by that provider. | Nessuna email dopo un minuto? Guarda nello spam, o invia un nuovo codice. Se accedi solo con un account social, nessun codice arriverà: il tuo profilo è gestito da quel fornitore. |
| `AccountProfileSendNew` | Send a new code | Invia un nuovo codice |
| `AccountProfileWrongCode` | That code is not right. Use the code in the latest email, and type it again. | Il codice non è corretto. Usa il codice dell'ultima email e scrivilo di nuovo. |
| `AccountProfileSavedTitle` | Profile saved | Profilo salvato |
| `AccountProfileSavedLead` | Changed: | Modificato: |
| `AccountProfileSavedBody` | Your applications, and this page, show it from your next sign-in. | Le tue applicazioni, e questa pagina, lo mostrano dal prossimo accesso. |
| `AccountProfileNotSavedTitle` | Your profile was not changed | Il tuo profilo non è stato modificato |
| `AccountProfileUnsureTitle` | Your profile may not have been saved | Il tuo profilo potrebbe non essere stato salvato |
| `AccountProfileNoAnswer` | The sign-in service did not answer within 5 seconds. Try again in a minute. | Il servizio di accesso non ha risposto entro 5 secondi. Riprova tra un minuto. |
| `AccountProfileNoAnswerUnsure` | The sign-in service accepted the code, then did not answer within 5 seconds, so the change may or may not have been made. Your next sign-in will show which. | Il servizio di accesso ha accettato il codice, poi non ha risposto entro 5 secondi: la modifica potrebbe essere stata fatta oppure no. Il prossimo accesso lo mostrerà. |
| `AccountProfileNoEmailSignIn` | Your account signs in through a social provider such as Google, so your profile comes from there and no code was sent. Change it with that provider, or ask an administrator. | Il tuo account accede tramite un fornitore social come Google, quindi il profilo viene da lì e non è stato inviato alcun codice. Cambialo presso quel fornitore, o chiedi a un amministratore. |
| `AccountProfileExpired` | The code has expired. Send a new one, and type it as soon as it arrives. | Il codice è scaduto. Inviane uno nuovo e scrivilo appena arriva. |
| `AccountProfileTooMany` | Too many attempts. Wait a few minutes, then try again. | Troppi tentativi. Aspetta qualche minuto, poi riprova. |
| `AccountProfileRefused` | The sign-in service refused the change. | Il servizio di accesso ha rifiutato la modifica. |
| `AccountProfileBadValue` | The sign-in service did not accept one of the values. Check the date (YYYY-MM-DD) and the web addresses, then try again. | Il servizio di accesso non ha accettato uno dei valori. Controlla la data (AAAA-MM-GG) e gli indirizzi web, poi riprova. |
| `AccountProfileNotYours` | The code belonged to a different account, so nothing was changed. | Il codice apparteneva a un altro account, quindi non è cambiato nulla. |
| `AttrName` | Full name | Nome completo |
| `AttrGivenName` | Given name | Nome |
| `AttrFamilyName` | Family name | Cognome |
| `AttrMiddleName` | Middle name | Secondo nome |
| `AttrNickname` | Nickname | Soprannome |
| `AttrProfile` | Profile page | Pagina del profilo |
| `AttrPicture` | Picture (web address) | Immagine (indirizzo web) |
| `AttrWebsite` | Website | Sito web |
| `AttrGender` | Gender | Genere |
| `AttrBirthdate` | Date of birth | Data di nascita |
| `AttrZoneinfo` | Time zone | Fuso orario |
| `AttrLocale` | Language and region | Lingua e regione |

48 keys: 36 `AccountProfile*` and 12 `Attr*`. Existing keys reused: `Cancel`, `Back`. Each label key
is used as the field's visible label and as the change summary's and the saved page's name, so
the three never disagree (WCAG 2.5.3 holds by construction: the accessible name is the label).

#### 6. Heuristics and WCAG, and where they trade

- Visibility of status (1): the code page names the address and the clock; every outcome's `h1`
  says whether anything changed. Match with the real world (2): human labels, "sign-in service".
  Control (3): Edit is opt-in, Cancel on both steps, resend keeps the values. Consistency (4): the
  `keys/new` pattern, the confirmation's `h1`, `form.edit`, `.err`. Error prevention (5): the
  change list before the save, no browser field type that could blank a stored value. Recognition
  (6): the code page restates what is about to change. Minimalism (8): one email shows no choice;
  no hint on non-editable lines. Recovery (9): each refusal says what to do next.
- (Resolved by §13.26: the note is gone, because the page can now tell a native sign-in.)
  **Trade 1**: the social note is on the form for everybody, because the page cannot tell a
  social-only person apart (nginx forwards no `identities`). It costs one muted line for the
  majority to spare the minority an email that never comes.
- **Trade 2**: no live "will be removed" warning while typing (no script), traded for a certain one
  on the code page.
- **Trade 3**: saying "3 minutes" in the `K` table duplicates a pool setting (open question 1).
- Scripting off: nothing in this flow carries a script or a handler; every step is a `GET` link or a
  `POST` form. `nojs.js` covers it by walking the flow.

#### 7. Open questions for the user

1. The code page says "3 minutes", which is the pool's `AuthSessionValidity` read on 2026-11-25 and
   lives in one `K` key. Keep the number (the coordinator's brief) or say "a few minutes" (§13.22's
   draft)? This design keeps the number.
2. Human labels for the form only, or also for the read-only Profile panel (which shows claim names
   today)? Using them there too would be one change of `page_account`, not in this step.

#### 8. Tests and scenes

Unit and socket tests (bb-auth-web), in addition to §13.22's:

- `the_profile_panel_offers_edit_only_when_wired` also asserts the pill is `p.primary > a.pill`
  with `K::AccountProfileEdit` and the `href` `<prefix>/profile` (no fragment), for a stranger too.
- `the_profile_form_labels_fields_in_words`: each editable claim's `input` sits in a `label` whose
  `span.lbl` is its `Attr*` text, in both languages; `autocomplete` is the token above
  (`given_name` is `given-name`, `birthdate` is `bday`, `zoneinfo` has none); every field is
  `type="text"` with `maxlength="2048"`; the first field has `autofocus`.
- `an_emptied_field_is_announced_before_saving`: a field with a forwarded value carries
  `K::AccountProfileClearDeletes` as its `span.hint`, an empty one does not; posting the form with
  `family_name` emptied yields a code page whose `ul.changes` has an `li` with `.tag.warn`
  `K::AccountProfileRemoved` and the old value after `K::AccountProfileWas`.
- (Replaced by §13.26's `the_form_names_no_address`.) `one_email_shows_no_choice`: one email renders no `select`, the address in `code` and a hidden
  `email`; two render a `select` named `email` with the first selected; both carry
  `K::AccountProfileEmailFixed`.
- `an_unchanged_form_sends_no_code` also asserts `200`, the form again, `div.msg.warn` with
  `K::AccountProfileNothingChanged`, and no `.err`.
- `a_bad_value_names_the_field_by_its_label`: the `div.err#err` begins with the `Attr*` label, the
  field has `aria-invalid="true"` and `aria-describedby="err"`, the values are kept.
- `the_code_field_is_a_one_time_code`: `inputmode="numeric"`, `autocomplete="one-time-code"`,
  `required`, `type="text"`, no `pattern`, a `label` "Code"; the lede names the chosen email in
  `code` and carries `K::AccountProfileCodeLasts`.
- `a_code_with_spaces_is_accepted` (the fake records `EMAIL_OTP_CODE` without the spaces).
- `a_wrong_code_changes_nothing` also asserts `div.err#err` with `K::AccountProfileWrongCode`
  inside the card, the code field empty with `aria-invalid`, the change list still there.
- `resend_starts_over_with_the_same_values`: the code page's second form posts to `<prefix>/profile`
  with the email and the changed values and **no** `Session`; submitting it records one new
  `InitiateAuth` and renders a fresh code page with the same change list.
- `each_outcome_states_its_result_in_the_h1`: one case per row of section 4's table, the `h1` key,
  the lede key, the status, and which actions are present (a "Send a new code" form exactly on the
  no-answer-before-update and expired rows).
- `a_timeout_at_the_update_does_not_claim_nothing_changed`: the silent fake on
  `UpdateUserAttributes` only: `504`, `K::AccountProfileUnsureTitle`, and
  `K::AccountProfileNotSavedTitle` absent.
- `the_saved_page_says_the_change_shows_next_sign_in`: the changed labels in words and
  `K::AccountProfileSavedBody`.
- `the_profile_flow_carries_no_script`: every page of the flow has no `script` and no `on…=`
  attribute (extends `no_page_but_the_reveal_carries_a_script`).

e2e (`node e2e/run.js`, with the fake endpoint): the walk Edit, change `given_name`, empty
`family_name`, Send code, code page shows both changes, a wrong code, the right code, the saved
page; then Cancel from the form returns to `/account/` with the read-only panel; the same walk
with scripting off in `nojs.js`. Keyboard only: Tab from the pill's page lands in the first field;
Enter in the code field submits Save, not Send a new code (Save's form is first in source order and
contains the field).

`shots.js` scenes (changed by §13.26: `-edit-one` goes, `-social` becomes `-gone`, `-provider`
and `-notyours` are added) (light, dark, phone, and `it` for all, since every one is prose):
`account-profile` (the read-only panel with the pill, a fixture with `given_name` and
`family_name` configured and forwarded), `account-profile-edit` (two emails, the `select`),
`account-profile-edit-one` (one email), `account-profile-nothing`, `account-profile-code`,
`account-profile-code-wrong`, `account-profile-saved`, `account-profile-expired`,
`account-profile-social`, `account-profile-noanswer`, `account-profile-unsure`. The designer's
review of 5b and 5c looks at these eleven.

### 13.24 A fake Cognito for the browser suites, and why no package can carry it (plan step 5, designed 2026-11-25)

`node e2e/run.js` and `node e2e/shots.js` start the real `bb-auth-web` (`e2e/lib/server.js`),
and `Config::cognito_endpoint` (§13.22) is set by nothing but the Rust tests, so the profile walks
of §13.23 and its eleven `account-profile*` scenes have no pool to talk to. This section gives the
harness one, and keeps the §13.22 property that a deployed binary cannot be pointed at one.

What was read to write it: §13.22 and §13.23, `e2e/README.md`, `e2e/lib/server.js` (`buildBin`,
`startServer`, `SETTINGS_FIXTURE`), `e2e/run.js`, `e2e/shots.js`, `src/bin/bb-auth-web.rs`
(`Config::cognito_endpoint`, `from_env`, `cognito_endpoint_of`, `cognito_post`, `cognito_call`,
`cognito_answer`, `cognito_update`, `id_token_email`, `COGNITO_TIMEOUT`, the test `FakeCognito`),
`Cargo.toml` (no `[features]` table today; the deb assets are `target/release/*`),
`scripts/build.sh` and `scripts/package.sh` (the `--no-build` check of `dist/`).

**Measured**: the stripped aarch64 release `dist/bb-auth-web` of 2026-11-25 contains the
literal `BB_AUTH_WEB_PROXY_SECRET` (`grep -ac` finds 3), so an env var name read by the code
survives `strip` and LTO and a byte search of the artifact can see it. **Read in a source**:
`compile_error!` in a `#[cfg]`'d item stops the build (the Rust reference, "Conditional compilation" and `std::compile_error`); the `release`
profile has `debug-assertions = false` by default (the Cargo book, "Profiles"), and this
`[profile.release]` does not override it. **Assumed**: nothing else.

#### The decision: a cargo feature, locked to debug builds, and a fake in the Node harness

1. **A cargo feature, `e2e-fake-cognito`**, empty and not in `default`. Only with it does
   `from_env` read **`BB_AUTH_WEB_E2E_COGNITO_ENDPOINT`** into `Config::cognito_endpoint`. The
   value must start with `http://127.0.0.1:`; anything else is a fatal startup naming the
   variable. When it is set the binary says so on stderr at startup, in a line containing
   `E2E BUILD: Cognito calls go to <url>`, so nobody mistakes the process for a real one.
2. **The read is one function with two bodies**, so the default build has a body to test:
   `fn e2e_cognito_endpoint(lookup: impl Fn(&str) -> Option<String>) -> Result<Option<String>, String>`.
   Without the feature it is `Ok(None)` whatever `lookup` answers, and the variable's name does
   not appear in the source that is compiled. With it, it is the rule in point 1. `from_env`
   calls it with `|k| std::env::var(k).ok()` in place of today's `cognito_endpoint: None`.
3. **The fake is the harness's own**, `e2e/lib/cognito.js`, an `http` server on
   `127.0.0.1:0` in the Node process that drives the browser, so a scene scripts it directly
   the way the Rust tests script `FakeCognito`. `lib/server.js` starts it before the binary,
   builds with the feature into its own target directory, and passes the variable.

#### The guard: three locks, each on a different thing

- **The source**: `#[cfg(all(feature = "e2e-fake-cognito", not(debug_assertions)))]
  compile_error!("e2e-fake-cognito is for the e2e harness's debug build only");` in
  `bb-auth-web.rs`. A release build with the feature does not compile, so the switch and a
  `.deb` (always `--release`, `build.sh`) cannot meet whatever flags somebody passes.
- **The artifact**: `scripts/package.sh` refuses to package when any of
  `dist/{bb-auth,bb-auth-adm,bb-auth-web}` contains the bytes `BB_AUTH_WEB_E2E_COGNITO_ENDPOINT`
  (`grep -aq`), beside its existing check of `dist/`, so it runs with and without `--no-build`.
  This is the check on what ships rather than on what the source says, and it is what catches a
  future edit that reads the variable outside the `cfg` or drops the `compile_error!`. Every
  `.deb` comes out of `package.sh`, and `deploy.ps1` always goes through it.
- **The build directory**: the harness builds with `--target-dir target/e2e`, so
  `target/debug/bb-auth-web`, the binary a developer would copy by hand, never carries the
  feature, and `cargo test` and the harness stop rebuilding over each other.

How each is shown to hold:

- `the_e2e_endpoint_is_not_read_without_the_feature` (default `cargo test`, so `package.sh`
  runs it before every release): `e2e_cognito_endpoint` with a `lookup` that answers
  `http://127.0.0.1:9/` for every name is `Ok(None)`.
- Under `cargo test --bin bb-auth-web --features e2e-fake-cognito` (`#[cfg(feature)]` tests,
  run by whoever changes the harness): the loopback URL is `Ok(Some(..))`, unset is `Ok(None)`,
  and `https://cognito-idp.eu-central-1.amazonaws.com/`, `http://10.0.0.1:80/` and
  `http://127.0.0.1.evil.com/` are each `Err` naming the variable.
- The artifact check is shown to see something by its positive control, run once by the coder
  and recorded in the commit: `grep -ac BB_AUTH_WEB_E2E_COGNITO_ENDPOINT
  target/e2e/debug/bb-auth-web` is non-zero, and on a `package.sh` build's `dist/bb-auth-web` it
  is 0. The `compile_error!` is shown once by `cargo build --release --features
  e2e-fake-cognito --bin bb-auth-web` failing with its message (also in the commit, not a test:
  a test cannot assert a build failure without a second cargo run).
- `lib/server.js` refuses to go on unless it saw the `E2E BUILD` line, so a walk that silently
  reached no fake (every page a `502` "refused", which looks like a scene) fails the run.

#### The interface the tester and the coder need

Rust: feature `e2e-fake-cognito` (`[features] e2e-fake-cognito = []`), env var
`BB_AUTH_WEB_E2E_COGNITO_ENDPOINT`, function `e2e_cognito_endpoint` as above, the stderr line
above, and the `compile_error!` above. Nothing else changes in `cognito_post`: it already posts
to the endpoint as given.

Harness: `buildBin` runs `cargo build --bin bb-auth-web --features e2e-fake-cognito
--target-dir target/e2e` and returns `target/e2e/debug/bb-auth-web[.exe]`. `e2e/lib/cognito.js`
exports `startFakeCognito()` resolving to `{ url, script(list), calls, close() }`:

- It answers `POST /` only. It records each request as `{ target, body }`, where `target` is the
  part of `X-Amz-Target` after `AWSCognitoIdentityProviderService.`, and it requires
  `Content-Type: application/x-amz-json-1.1` (anything else is a `400`, so a regression in the
  envelope fails a walk).
- `script([[target, reply], ...])` queues replies; a request takes the first queued reply for
  its target, else the default. A reply is `{ status, body }` (sent as JSON with
  `Content-Type: application/x-amz-json-1.1`) or `'silent'`, which reads the request and never
  answers until `close()`, so `cognito_post` times out at `COGNITO_TIMEOUT` (5 s).
- Defaults, the happy path:
  - `InitiateAuth`: `200 {"ChallengeName":"EMAIL_OTP","Session":"fake-session-1","ChallengeParameters":{"USERNAME":<AuthParameters.USERNAME>}}`.
  - `RespondToAuthChallenge`: `200 {"AuthenticationResult":{"IdToken":<jwt>,"AccessToken":"fake-access","RefreshToken":"fake-refresh"}}`,
    where `<jwt>` is three base64url parts, the signature any bytes (`id_token_email` decodes,
    it does not verify), with payload `token_use:"id"`, `iss` = `SETTINGS_FIXTURE`'s
    `gate.issuer`, `aud` = its `gate.client_id`, `exp` = now + 3600, `email_verified: true`,
    `email` = `ChallengeResponses.USERNAME`.
  - `UpdateUserAttributes`: `200 {}`.
- The scenes' scripts: `code-wrong` is `RespondToAuthChallenge` `400
  {"__type":"CodeMismatchException","Session":"fake-session-2"}`; `expired` is
  `RespondToAuthChallenge` `400 {"__type":"ExpiredCodeException"}`; `social` is `InitiateAuth`
  `400 {"__type":"UserNotFoundException"}`; `noanswer` is `InitiateAuth` `'silent'`; `unsure` is
  `UpdateUserAttributes` `'silent'`.

#### What was rejected for the fake

- **An env var read in every build**: it is exactly what §13.22 refused, a value a deployment
  can point at a host of its choosing.
- **An env var behind `debug_assertions` alone**: no opt-in, so every `cargo build` binary on a
  developer's disk honours it, and one `debug-assertions = true` in `[profile.release]` would
  ship it silently. It is kept as the second lock (the `compile_error!`), not as the only one.
- **A key in the settings file, or a TLS fake named through `gate.issuer`**: `compile_issuer` is
  https-only and the bundled Mozilla roots trust no local CA, and a settings key would be
  editable from the GUI, which is worse than an env var.
- **A fake written in Rust as a second binary**: a new `src/bin/` file is a binary `build.sh`
  copies and compiles for the target, and a scene would script it across a process boundary.
  The Node fake lives where the scenes are.
- **Magic inputs instead of a script** (code `000000` means wrong): it would work for the code,
  but `social` and the two silences depend on the account, not on what is typed, and a queue
  is what the Rust `FakeCognito` already does, so the two suites read alike.
- **A shorter timeout for the e2e build** (a second variable): `noanswer` and `unsure` cost 5 s
  each per view, under a minute over the shots' four views, which is not worth a second switch.

#### What the fake costs

About 15 lines of Rust behind the feature, one `grep` in `package.sh`, about 80 lines of Node.
The harness's first build compiles the crate once more into `target/e2e`. No new dependency.

### 13.25 The profile edit acts on the session's own Cognito user (plan step 5, designed 2026-11-25)

A bug found on rpi-01 on 2026-11-25 (`v1.99.9-gcf9109b`), and its fix. It changes §13.22, which
carries "(Changed by §13.25 ...)" where it does.

What was read to write it: `AGENTS.md` ("What a 204 hands nginx", the profile-claims and
identity invariants, the cookie wire-format invariant, the audit's `sub` sentence), §13.2,
§13.22 to §13.24, `src/bin/bb-auth.rs` (`UserIdentity`, `Claims`, `validate_id_token`,
`make_session`, `verify_session`, `decode_claims_segment`, `authorized_response`), `src/lib.rs`
(`RESERVED_CLAIMS`, `IDENTITY_ATTRS`, `claim_name_ok`, `derive_profile_header`,
`compile_profile_claims`, `LOGIN_URL_HEADER`, `IDENTITY_HEADER`, `default_session_ttl`),
`src/bin/bb-auth-web.rs` (`account_profile_post`, `id_token_email`, the start and code calls and
their tests), the README's `location /admin/` recipe, and `PLAN.md` step 5.

#### What happened, and how it is known

**Measured on rpi-01** (the user's run, and the IT-Admin session's read-only `list-users`): a
person signed in through `MicrosoftPersonal`, opened `/account/profile`, received the email code,
entered it and read "Profile saved", and nothing they see changed. The pool holds two users with
that email: a **native** one (a UUID username, `CONFIRMED`, no `identities`), modified at 13:06 CET
by that edit, and a **federated** one (`MicrosoftPersonal_...`, `EXTERNAL_PROVIDER`, primary
identity `MicrosoftPersonal`, not linked to the native one), untouched since June. With a Google
account that has no native twin the page answered `UserNotFoundException` and showed the
social-only page, as designed.

So `InitiateAuth` with `USERNAME` = the email resolved to the native user, every check of
§13.22 (2) passed (same email, this client, this issuer), and `UpdateUserAttributes` changed the
native user. The code proved control of the **mailbox**, and the native user is the account that
mailbox signs into, so nobody gained anything they could not already do on the sign-in page: the
bug is that the edit acted on a Cognito user **other than the session's**, and said it had saved
the session's profile. §13.22 accepted that case in a sentence ("edits the native one"); it was
the wrong call, because the person cannot tell which twin they are.

**Read in a source:**

- An ID token carries `cognito:username` ("the username of your user in your user pool"), and a
  federated user's carries `identities`, with a username of the form `<ProviderName>_<id>`;
  `identities` also describes a federated profile **linked** to a local one
  ([ID token](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-id-token.html)).
- With email as a username attribute, the email is unique among the pool's own users, `SignUp`
  sets `username` to a UUID equal to `sub`, a username is unique in the pool and cannot change,
  and the email may be used **in place of** the username in every API but `ListUsers`, so the
  username itself is always accepted
  ([user attributes](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html)).
- `USER_AUTH` takes `USERNAME`; the documented `EMAIL_OTP` answer carries
  `ChallengeParameters` `CODE_DELIVERY_DELIVERY_MEDIUM` and `CODE_DELIVERY_DESTINATION` (a masked
  address such as `t***@e***`); `InitiateAuth` cannot sign a federated user in
  ([InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html)).
- "When a user signs in through an IdP, Amazon Cognito updates the mapped attributes with the
  latest information from the IdP" (only when the value changed)
  ([attribute mapping](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html)).
- nginx passes no header whose `proxy_set_header` value is empty, and a location that sets any
  `proxy_set_header` of its own inherits none from the server level
  ([proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)).

**Assumed, to be confirmed by the real run (5h):** that `InitiateAuth` with `USERNAME` = the UUID
username behaves exactly as with the email (it follows from the second source, no run has shown
it); that its `ChallengeParameters.USERNAME` is that same username; that every native user in this
pool has a printable-ASCII username (the source says UUID for `SignUp`; an `AdminCreateUser` user
was not checked); that the pool's case-insensitivity does not make the token's `cognito:username`
differ in case from the one the session carries (both come from Cognito for the same user).

#### Decision: the session's own user

**The gate tells `bb-auth-web` which Cognito user a session is, and only for a native sign-in.**
One new response header on an authorized `204`, `X-Auth-Native-Username`, carrying the token's
`cognito:username`, present **iff** the credential is an id_token (bearer, or the cookie it minted)
whose `identities` claim is empty or absent. A federated sign-in, an API key, an anonymous grant,
and a cookie minted before this change send none. `bb-auth-web` then:

1. offers the edit only when the header is present (the Edit pill and the form). Without it,
   `GET <prefix>/profile` shows the read-only panel and one sentence (the designer's wording):
   the profile of an account that signs in through a provider comes from that provider, and a
   session started before this release has to sign in again to edit. Both `POST`s refuse it
   with no Cognito call: a `400` naming the same sentence.
2. asks for the code with `USERNAME` = that header's value. The code goes to that user's own
   email, whichever of the roster's emails `X-Auth-Email` lists, so the "Send code to" choice and
   the posted `email` field disappear, and a posted `email` is a non-editable name like any other
   (refused before Cognito). The code page names `ChallengeParameters.CODE_DELIVERY_DESTINATION`
   (escaped), or says "your email address" when the answer carries none. A
   `ChallengeParameters.USERNAME` that is present and differs from the header is a refusal
   (`403`, nothing further sent): the pool answered for somebody else.
3. answers the code with `USERNAME` = the header's value **as it arrives on the code step**
   (no hidden username field to re-validate), and binds the returned `IdToken` by
   `cognito:username` equal to that value, with the other checks of §13.22 (2) kept
   (`token_use`, `iss`, `aud`, `exp`, `email_verified`). The email comparison goes: the username
   is the stronger key, unique and immutable, and the email equality is exactly what let the
   native twin through. A mismatch is the existing `403` "a token for another account", the
   `AccessToken` dropped unused.

**A federated session's profile is its provider's, so it is refused, not re-proved.** The
IT-Admin session suggested two ways to let it edit: redo the provider sign-in, or an
administrator call on the session's own username after a proof bound to that session. Both are
rejected. The source above says a federated user's mapped attributes are rewritten from the
provider at every sign-in that changes them, so an edit would last until the provider next
disagreed, and the success page would be a promise the pool breaks. The first needs an OAuth leg
in `bb-auth-web` (a second redirect flow, `state`, PKCE) for that; the second needs IAM
credentials (`AdminUpdateUserAttributes` evaluates IAM) in the process that writes both files,
which §13.7 refused. An attribute the provider does not map would survive, but no such attribute
is editable today and the social client cannot run any flow that yields the federated user's
access token. Refusing costs nothing and is what R2 can honestly offer such a person.

**Where the value rides in the cookie: inside the claims segment, under a gate-owned key, and
this is not a `COOKIE_VERSION` bump.** The invariant says to bump when the serialization or the
signed-message bytes change. They do not: the cookie is still `bb1.<kid>.<exp>.<email>.<claims>.<sig>`,
and the claims segment is still "a JSON object of strings whose every key passes `claim_name_ok`
and every value `claim_value_ok`", which is the grammar `decode_claims_segment` checks. A native
session's object gains one entry, `"native_username": "<cognito:username>"`. Both directions are
safe, and the tests pin both:

- **an old cookie under the new binary** verifies, carries no `native_username`, and its holder
  is refused the edit (fail closed, below);
- **a new cookie under an older binary** (a rollback) verifies too, because the key and value
  pass the old grammar, and the old `profile_headers` emits only configured claims, which this
  key cannot be (next point). Nobody is logged out either way.

The key cannot collide with a profile claim: `compile_profile_claims` already refuses any claim
whose derived header collides with a reserved one, and `X-Auth-Native-Username` joins
`LOGIN_URL_HEADER` in that reserved set, so `native_username`, `native:username` and
`native-username` are all refused as claims (`derive_profile_header` maps all three to it). An
older binary could have stored that key only if an operator had configured such a claim **and**
Cognito had issued such a token claim; Cognito issues none (custom attributes are `custom:`), so
no cookie in the wild carries it. `verify_session` splits the key out of the map into
`UserIdentity.native_username` before anything reads `claims`, so the profile path never sees
it. The value is read in `validate_id_token` from `Claims::extra`, the way `sub` already is, and
**not** as a typed field: a typed field would hide `cognito:username` from `flatten` and would
force it into `RESERVED_CLAIMS`, refusing a settings file that configures it as a profile claim
today. It is kept only when it passes `claim_value_ok` and is printable ASCII with no space;
otherwise the header is omitted and the edit is not offered (fail closed).

This deliberately does **not** sign `cred` or `sub` into the cookie: the audit's account stays
"from a validated token and from nothing else". The reason `UserIdentity`'s comments and
`AGENTS.md` give for that ("would be a `COOKIE_VERSION` bump") is not true of a key in the claims
object, and the docs step should say the real reason (the audit records what the login proved,
once) rather than leave a wrong one standing.

**Old cookies fail closed: no edit until a fresh sign-in.** Treating an absent header as native
would keep the bug alive for every federated cookie minted before the deploy, for up to
`gate.session_ttl_secs` (default 30 days). Refusing costs a native person one sign-out and
sign-in, which the sentence above tells them, on a page they open rarely.

**What kind of header it is: a reserved one, code-defined, not an identity attribute and not a
profile claim.** It is not an `IDENTITY_ATTRS` member: those are chosen by the operator in
`gate.identity_attrs`, derived from the roster, and multi-valued, while this one is a fact of the
credential, single-valued, and something `bb-auth-web`'s correctness depends on, so an operator
switch that could turn it off would silently turn the edit off with it. It is not a profile claim:
those are self-asserted decoration nothing may key on, while this value is set by Cognito, cannot
be edited by the user, and is carried under the cookie's HMAC. It is the third header the gate's
contract names in code, beside `X-Auth-Login-URL` and `X-Auth-Email`: the string is a library
constant, `NATIVE_USERNAME_HEADER`, because the gate emits it, `bb-auth-web` reads it, and
`compile_profile_claims` reserves it, three uses and one spelling.

**nginx's duty, and why it is mandatory on `/account/`.** `bb-auth-web` believes the header only
because nginx overwrites it, exactly as for `X-Auth-Email`. If `/account/` did not overwrite it, a
client could name another user's username: the code would go to **that** user's mailbox (a
nuisance email, never a takeover, since the code step needs that code), and a native person's
header would never arrive (no edit). So `location /account/` gains

```nginx
auth_request_set $bb_native $upstream_http_x_auth_native_username;
proxy_set_header X-Auth-Native-Username $bb_native;   # empty for federated: not passed
```

and every other gated location of the recipe clears it (`proxy_set_header
X-Auth-Native-Username "";`) beside `X-Auth-Uuid`, by the rule that every name the gate can
emit is cleared where it is not set. On rpi-01 only `/account/` is required for this fix; the
admin location and the applications read no such header. Order on rpi-01: **nginx first, then
the packages**. The nginx line is harmless under today's binaries (an empty variable passes
nothing and overrides whatever a client sent), while the packages before the line would leave a
window in which `/account/` believes a client-supplied header. rpi-01's auth vhost gates at
server level (`snippets/bb-auth.conf`): read `sudo nginx -T` before placing the lines.

**What this costs.** One header, one cookie key, one reserved name, about forty lines over
three files; no new dependency, no new call, no new setting. One Cognito round trip fewer of
uncertainty on the page (no address choice). A native person with a pre-deploy cookie signs in
once more before editing. A native user **linked** to a provider (none today, measured) would
carry `identities` on every token and be refused too; if linking is ever set up, this decision
is revisited, not patched.

**Rejected:**

- **Bind by `sub` alone** (option b without a sign-in kind): it stops the wrong write but only
  after the code was sent to the twin's mailbox, and the federated person still types a code to
  be refused. The username does both jobs: it is the `USERNAME` to ask with and the key to bind
  by, and for this pool's native users it equals `sub` (source above).
- **Forward the sign-in kind and keep the email as `USERNAME`**: a roster row may list several
  emails, each possibly another native user, so the "Send code to" choice could still reach a
  user other than the session's. The username removes the choice.
- **A three-call start** (`USER_AUTH` with no preferred challenge, compare
  `ChallengeParameters.USERNAME` before choosing `EMAIL_OTP`): it would detect the twin without a
  gate change, but adds a Cognito call, depends on a username comparison against a value the page
  does not have (the federated session's own username), and still needs the gate to know it.
- **Configure `cognito:username` as a profile claim** (no gate change at all): profile claims are
  decoration nothing may key on, an operator editing the list would silently change the edit,
  and it says nothing about federation.
- **An identity attribute `native_username`** in `IDENTITY_ATTRS`: an operator switch on a value
  the edit depends on, and a roster-shaped mechanism for a credential fact.
- **A new positional cookie segment**: a format change, a `bb1` to `bb2` bump, everybody logged out,
  for a value the self-describing segment already holds.
- **Treat a missing header as native**: the bug for up to 30 days of old federated cookies.

#### How each part is shown to hold

Gate (`bb-auth.rs`), red first:

- `a_native_token_names_its_username_on_the_204` (bearer id_token with no `identities` and a
  `cognito:username`: the header carries it);
- `a_federated_token_names_no_native_username` (`identities` present: no header, login still
  `204`);
- `the_cookie_carries_the_native_username_and_gives_it_back` (`/auth/session` then
  `/auth/validate` with the cookie: the header);
- `a_cookie_without_it_still_verifies_and_names_none` (a `bb1` cookie whose claims segment lacks
  the key, signed with the test key: `204`, no header): this is the "no bump" test;
- `the_new_claims_segment_passes_the_old_grammar` (every key of a native session's segment passes
  `claim_name_ok`, every value `claim_value_ok`, so a rollback binary verifies it);
- `the_native_username_is_never_a_profile_header` (a session with profile claims configured
  emits no `X-Auth-Native-...` profile header);
- `an_unsafe_username_is_omitted_not_emitted` (a username with a space or non-ASCII: no header);
- `an_api_key_names_no_native_username`.

Library: `the_native_username_header_is_reserved` (`native_username`, `native:username`,
`native-username` refused by `compile_profile_claims`, naming the header); the constant's
spelling pinned where `IDENTITY_HEADER`'s is.

`bb-auth-web`, red first, with `FakeCognito`:

- `a_session_with_no_native_username_gets_no_form_and_no_code` (`GET` shows the sentence and no
  form; both `POST`s `400`; zero calls): the federated and the old-cookie case;
- `the_code_is_asked_for_the_sessions_own_username` (`USERNAME` = the header, no `email` posted);
- `a_posted_email_field_is_refused_before_cognito`;
- `the_rpi01_twin_is_never_written` (the regression test: header username `U1`, the fake's
  `IdToken` has the **same email** and `cognito:username` `U2`: `403`, no `UpdateUserAttributes`
  recorded);
- `a_challenge_for_another_username_is_refused` (`ChallengeParameters.USERNAME` `U2`: `403`, one
  call only);
- `the_code_step_uses_the_header_not_a_form_field` (a header changed between the steps: the
  code step answers with the new value and the bind fails, `403`, no update);
- `the_code_page_names_cognitos_masked_destination` (escaped; absent: the generic sentence);
- the tests that asserted `USERNAME` = the chosen email and the "Send code to" `select` are
  rewritten, not kept beside.

e2e: the harness sends `X-Auth-Native-Username` for the native walks; one walk and one scene
(`provider`) without it. The designer reviews the sentence and the code page's lede (§13.23's
"Where the code goes" and the code page lede are superseded by this section).

Real (5h): `sudo nginx -T | grep -n X-Auth-Native-Username` shows both lines in `/account/`; the
`MicrosoftPersonal` session (after a fresh sign-in) sees the provider sentence and receives **no**
email; a native account edits `given_name`, signs out and in, and sees it; the native twin's
`UserLastModifiedDate` does not move on the federated attempt (read-only `admin-get-user` by the
IT-Admin session).

#### Slices of the fix

- **5f. The gate names a native session's Cognito user.** Library constant and reservation,
  `validate_id_token`, the cookie key, the `204` header; the gate tests above. Nothing reads the
  header yet, so it ships safely alone, and no cookie is invalidated.
- **5g. `bb-auth-web` acts only on that user.** Steps 1 to 3 of the decision, the `K` changes
  (the designer's sentence; `AccountProfileSendTo` goes), the web tests and the e2e walk. Without
  5f deployed it offers no edit at all (fail closed), so the order between them is free, but
  they ship together.
- **5h. Real, with the user's go-ahead**: the nginx lines on rpi-01 first, then the packages,
  then the checks above. Then 5e (the real edit) resumes on this design.

#### For the user

- the nginx change on rpi-01 and the deploy, in that order (each a real-effect change);
- whether the native twin modified at 13:06 should get its old values back (only the IT-Admin
  session can read what they were, from the pool, and only the user can say to restore them);
- whether the duplicate native user should stay, be linked to the federated one, or be deleted:
  a pool change through the OpenTofu repository or an administrator action, outside this step.

### 13.26 The account page after §13.25: section order, the page width, the native-only edit, and what it still does its own way (plan step 5, slice 5g, designed 2026-11-25)

The interface of §13.25's fix, plus three user decisions of 2026-11-25: the sections in a new
order, the account page at the console's width, and "factor out most of the front-end code and
parameters shared by the admin console and the account page; don't reinvent the wheel". It
changes §13.17 and §13.23, which carry "(Changed by §13.26 ...)" where they do.

What was looked at: §13.17, §13.23, §13.25; `PLAN.md` step 5; in `src/bin/bb-auth-web.rs`
`page_account`, `account_shell`, `shell_named`, `top_bar`, `prefs_trigger`, `sign_out_pill`,
`act`, `act_rm`, `back`, `text_field`, `account_key_id_field`, `account_key_line`,
`profile_form`, `page_profile_code`, `page_user` and the `K` keys `Account*`, `SignOut`, `Back`;
`src/assets/admin.css` (`main`, `p.lede.sub`, `form.edit`, the `.selfserve` block, the phone
block) and `base.css` (`p.lede`, inputs); `e2e/shots.js` (the account and profile scenes,
`profileScene`), `e2e/tests/{account,profile,nojs}.js`, `e2e/lib/cognito.js`
(`PROFILE_HEADERS`); `the_header_shares_the_content_column` in `src/lib.rs` and
`account_lede_zone` in the web tests.

Measured: a mockup over the real `theme.css`, `base.css` and `admin.css` (`/tmp/d5g/m.js`, Edge)
with the account column on the console's `main` rules: no sideways scroll at 320, 360 or 1280;
at 320 the uuid ends at x=292 of the 304 the 16px padding leaves, so it still fits whole; at 1280
a sub-line runs 934px wide (about 140 characters), which is the reason for the measure below.
Read in a source: each WCAG fact, cited where used. Assumed: that screen readers read the
asterisks of a masked address as symbols or skip them, which leaves the domain readable either
way.

#### 1. The section order: Profile, API keys, Groups, Where you reach

`page_account` renders `section#profile`, `section#keys`, `section#groups`, `section#reach`, in
that order, on every path that draws the page (`/account/`, `/account/profile`,
`/account/keys/new`, and a refused mint or profile post). The ids do not change, so no link and
no selector changes. The lede (addresses and account id) stays above all four. Delete my account
(step 7) goes after Where you reach, last.

The reason the order is right and not only asked for: the two sections a person acts in come
first and the two read-only lists last (the common case first, Nielsen 8), and `/account/profile`
now opens with the form at the top instead of three panels down.

Wording that changes because of the order: only the profile sub-line. "What your sign-in tells
**these** applications about you" pointed back at the list above it, which is now below it, so it
becomes `AccountProfileSub` "What your sign-in tells your applications about you." / "Cosa il tuo
accesso dice di te alle tue applicazioni." (the saved page already says "Your applications"). The
keys sub-line ("It reaches at most what you reach.") names no position and stays; no heading
changes.

#### 2. The account page at the console's width

The account column is the console's `main`, not a narrower copy of it: the `.selfserve` width
rules are **deleted** rather than set to 1000px, because `main{max-width:1000px;margin:0
auto;padding:18px 16px 40px}` and `.bar{max-width:1000px}` already say it, and a second rule
naming the same number is the drift this decision is about.

Delete from `admin.css`:

```css
.selfserve{max-width:620px;margin:0 auto;padding:28px 16px 48px}
body:has(.selfserve) .bar{max-width:620px}
.selfserve .panel h2{margin-top:0}
/* in @media (max-width:640px) */
  .selfserve{padding:16px 12px 32px}
  body:has(.selfserve) .bar{padding:0 12px}
```

Add, after `main{...}`:

```css
/* Prose keeps a reading measure on a 1000px column: a lede or a muted sentence 140 characters
   wide is hard to track back to the next line. 75ch stays under WCAG 1.4.8's 80 characters. */
main p.lede,main p.muted{max-width:75ch}
```

and extend the existing 40ch list so a profile field is not 930px wide for a given name:

```css
input.f-email,input.f-name,input.f-login_url,input.f-aud,input.f-profile{max-width:40ch}
```

Markup: each account `h2` gains `class="tight"` (the console's class for a heading that opens a
panel, replacing the deleted `.selfserve .panel h2`); each profile `input` gains `class="f-profile"`
(tried first: `f-name`, which is the right width but a class named for another field, the same
reasoning as `f-code` in §13.23). `main class="selfserve"` keeps its class only for the flat
ground until slice F of section 6.

The measure is WCAG 1.4.8 (AAA, not required at AA, applied because it costs one rule):
<https://www.w3.org/WAI/WCAG22/Understanding/visual-presentation.html>. It applies to the
console's ledes too, which is the point of one rule for both surfaces; no console lede carries
anything wider than prose (the access check's verdict is a `.panel`, not a `p.lede`).

On a phone: the column's side padding goes from 12px to the console's 16px, and nothing else
changes (the uuid still fits at 320, measured above). The table cards, the bar and the menu are
the console's already.

#### 3. The Profile panel when the edit is not offered to this session

When the deployment wires the edit (issuer, client id, at least one editable claim) and the
request carries **no** `X-Auth-Native-Username`, the read-only panel shows its claims as today
and, where the "Edit profile" pill would be, one `p.muted` `K::AccountProfileNotNative`. No pill,
no disabled control (a disabled control says nothing and the keyboard skips it). A deployment
that does not wire the edit says nothing about editing, as today.

The page cannot tell a federated session from a native one whose cookie predates 5f: both arrive
with no header (§13.25). So the sentence is one key with two conditional sentences, each naming
how the person signs in, and the second gives the one action that helps (sign out and in, the
same verb as the bar's `K::SignOut`, "Esci" in Italian). Its first sentence keeps the wording of
the existing social note and outcome page ("comes from that provider", "cannot be changed here").

`GET <prefix>/profile` with no header: `200`, the same page as `/account/` (no form, the
sentence). Either `POST` with no header: `400`, the same page, no Cognito call. Not `.err`: the
person did nothing wrong.

Rejected: **two sentences shown by case** (`account-profile-signin-again` as its own state). It
needs the gate to mark a federated session as well, which §13.25 does not; if the architect adds
such a marker, the key splits into its two sentences and nothing else changes.

#### 4. The form and the code page without the address choice

- The form loses the "Send the code to" block (the `select`, the `div.fixed`, the hidden `email`)
  and `AccountProfileSocialNote`. `AccountProfileEmailFixed` stays, moved to a `p.muted` after
  the fields (and after the non-editable list), before the actions: the email is still not a
  field and the reason is still worth one line. A posted `email` is refused as a non-editable
  name, "email: cannot be changed here." (`AccountProfileCannotEdit`), before Cognito.
- The code page lede: `AccountProfileCodeSent` + `code` the masked destination +
  `"." " "` + `AccountProfileCodeLasts`, e.g. "We emailed a code to `e***@o***.com`. It works for
  3 minutes." The destination is shown only when it is 1 to 254 printable ASCII characters with
  no space (escaped as every value is); otherwise the lede is the whole sentence
  `AccountProfileCodeSentNoDest` + `" "` + `AccountProfileCodeLasts`. A masked address is still
  the address (Nielsen 1): it is enough to recognise which mailbox to open.
- `AccountProfileNoCode` drops its social sentence, which is now never true of its reader.
- The resend form posts the changed values only (no `email`).
- `UserNotFoundException` now means the session's own user is gone from the pool (the request
  names it by username): the outcome row's lede becomes `AccountProfileNoUser`, status `400`.
- A `ChallengeParameters.USERNAME` for another user and a returned token for another username
  are one outcome: `AccountProfileNotSavedTitle`, `AccountProfileNotYours` reworded so it is true
  of both, back, `403`.

#### 5. The `K` keys

Removed: `AccountProfileSendTo`, `AccountProfileSocialNote`, `AccountProfileNotYourEmail`,
`AccountProfileNoEmailSignIn`. Kept as is: `AccountProfileEmailFixed` (moved), `CannotEdit`,
`CodeSent`, `CodeLasts`.

| Key | English | Italian |
|---|---|---|
| `AccountProfileSub` (changed) | What your sign-in tells your applications about you. | Cosa il tuo accesso dice di te alle tue applicazioni. |
| `AccountProfileNotNative` (new) | If you sign in with a social account such as Google, your profile comes from that provider and cannot be changed here. If you sign in with your email address, sign out and sign in again to edit it. | Se accedi con un account social come Google, il tuo profilo viene da quel fornitore e non si può cambiare qui. Se accedi con il tuo indirizzo email, esci e accedi di nuovo per modificarlo. |
| `AccountProfileCodeSentNoDest` (new) | We emailed a code to the address you sign in with. | Abbiamo inviato un codice all'indirizzo con cui accedi. |
| `AccountProfileNoCode` (changed) | No email after a minute? Look in your spam folder, or send a new code. | Nessuna email dopo un minuto? Guarda nello spam, o invia un nuovo codice. |
| `AccountProfileNoUser` (new) | The sign-in service no longer has the account you signed in with, so no code was sent. Sign out and sign in again. | Il servizio di accesso non ha più l'account con cui hai effettuato l'accesso, quindi non è stato inviato alcun codice. Esci e accedi di nuovo. |
| `AccountProfileNotYours` (changed) | The sign-in service answered for a different account, so nothing was changed. | Il servizio di accesso ha risposto per un altro account, quindi non è cambiato nulla. |

#### 6. What the account page still does its own way, and the slices that end it

With one width, the two surfaces differ only where a reason says so. Already shared and left
alone: `top_bar`, `prefs_trigger`, `sign_out_pill`, `form_shell_at`, `confirm_card`,
`bearer_reveal`, `expiry_markup`, `url_list_marked`, the duration field, `table` with
`data-label`, `p.lede`, `p.primary > a.pill`, `.actions`, `.err`/`.msg.warn`. The slices, each
small enough for one red-green pass, in order (W comes with 5g):

- **W (5g). Width and section order.** Sections 1 and 2 above: the CSS deleted and added, `h2.tight`,
  `f-profile`, the order.
- **P. Pill links without a `View`.** New `pill_link(href, label)`, `pill_link_rm(href, label)`
  and `back_link(lang, href)` (the `"\u{2190} "` + `K::Back` pill); `act`, `act_rm` and `back`
  become one-line wrappers over them; `account_key_line`'s written-out `a.pill` / `a.pill.rm`,
  `page_account_minted`'s and the profile outcome pages' back pills call them. Nothing visible
  changes; the reason is that "how a pill looks" is said once (the comment on `back` already
  claims that, and the account page breaks it).
- **M. One Preferences menu.** New `prefs_menu(lang, lang_pref, theme, who: Option<&str>,
  action, hidden: &[(k, v)], scripted: bool)`, called by `shell_named` (`scripted: true`:
  `onchange` and the `noscript` Apply) and `account_shell` (`scripted: false`: no handler, Apply
  always shown, `who` omitted when the page has its own lede). Deletes the second copy of the
  two `select`s and their option lists in `account_shell`. The `scripted` flag is the one real
  difference (the account page carries no script, §13.17). (Changed by §13.28 §7, which shipped
  it as `prefs_form`, the `who` and the logout slot moving to `account_menu`. Changed by plan
  step 13, 2026-11-26: the flag is deleted, and both shells call one `prefs_form(lang,
  lang_pref, theme, action, hidden)` with the same arguments, because the user asked for the
  theme to apply on selection on this page too. There is no second shape of the form left.)
- **D. One document skeleton.** New `page_document(lang, theme_attr, title, stylesheet,
  body)`: `DOCTYPE`, `html lang data-theme`, the `head` with the three raw styles and
  `stylesheet_link`; both shells pass their own title string ("bb-auth-web · ..." versus
  "(brand) · ...") and body. Deletes the duplicated head in `account_shell`.
- **T. One text field.** `text_field` takes a `FieldOpts { autofocus, required, maxlength,
  pattern, autocomplete, inputmode, class, prose }` with `Default`; `prose: true` leaves
  `autocapitalize` and `spellcheck` at the browser's default (the review nit for names in
  `PLAN.md`). `account_key_id_field` becomes a call with `pattern`, `maxlength`, `autofocus`,
  `required` and the hint rule; `profile_form`'s hand-written `input` becomes a call with
  `class: "f-profile"`, `autocomplete`, `maxlength`, `prose: true`. Deletes the two hand copies of
  the label + input + hint + `aria-invalid` + `aria-describedby` markup.
- **F. The flat ground.** Delete `body:has(.selfserve){background:var(--bg)}` and the class on
  `main`: its reason was "one narrow column", which is gone, and the console's ground is the
  estate's. Review `account` and `account-profile` shots for the band §13.18 saw; if it is there,
  it is there on the console's long pages too, and the fix belongs to both (the skill's
  `no-repeat` pitfall). Open question 2.

Kept different, with the reason:

- **The sections.** The console writes `h2` then `div.panel`, with "None." for empty; the account
  page writes `section.panel > h2 + p.lede.sub` with a sentence per empty state. The console is
  the file's wiring view named by file sections; the account page is prose for a person who does
  not know the file (§13.17). One helper would force sub-lines onto twenty console sections, which
  nobody asked for.
- **The brand slot.** The console's is a link home with `K::ConsoleTag`; the account's is an
  inert `span` with the operator's logo, because it is the only page its visitor came for
  (§13.17). Whether the console should show the logo too is open question 1.
- **`account_csp`.** The account page shows the logo, so its `img-src` is not the console's
  `'none'`. (Changed by §13.28 §6: `admin_csp` passes the logo to `page_csp` too, so that
  difference went. Changed by plan step 13, 2026-11-26: `script-src` is shared as well, through
  `page_script_src`, so the two policies are one function's output for one `reveal`; what is
  left of this bullet is that the logo reaches the two policies by separate arguments,
  `admin_csp_logo`'s own and `AccountLook::logo`.)
- **The keys' mint row.** No owner field and no `released` (the owner is the caller): that is a
  rule, not a style.

#### 7. Tests and scenes

Unit and socket tests (`bb-auth-web`):

- `the_sections_come_in_the_users_order`: on `/account/`, `/account/profile` and
  `/account/keys/new`, the byte offsets of `id="profile"`, `id="keys"`, `id="groups"`,
  `id="reach"` increase; `account_lede_zone` ends at the **first** `<section`, not at
  `id="reach"` (it would otherwise swallow three sections).
- `each_section_says_what_it_is_for` asserts the new `AccountProfileSub` in both languages.
- `a_session_with_no_native_username_gets_no_form_and_no_code` (§13.25) also asserts: no
  `a[href=<prefix>/profile]`, one `p.muted` with `AccountProfileNotNative` inside `#profile`, `200`
  on `GET` and `400` on both `POST`s with the same sentence; and the sentence absent where the
  deployment does not wire the edit.
- `the_form_names_no_address` (replaces `one_email_shows_no_choice`): no `select`, no
  `name="email"`, no `AccountProfileSendTo`/`SocialNote` text; `AccountProfileEmailFixed` in a
  `p.muted` after the fields; the resend form carries no `email`.
- `the_code_page_names_cognitos_masked_destination`: `e***@o***.com` in `code`; `<b>` escaped;
  absent, empty, over 254 or with a space: `AccountProfileCodeSentNoDest` and no `code` in the lede.
- `each_outcome_states_its_result_in_the_h1`: the `UserNotFound` row reads `AccountProfileNoUser`,
  and a challenge for another username reads `AccountProfileNotYours` with `403`.
- Removed keys are not rendered anywhere (`AccountProfileNoEmailSignIn`, `NotYourEmail`).

`src/lib.rs` `the_header_shares_the_content_column`: the two lines asserting
`body:has(.selfserve).bar` `max-width:620px` and `padding:012px` go; it asserts instead that no
rule is named `.selfserve`, `body:has(.selfserve).bar` or `.selfserve.panelh2`, that `main p.lede`
carries `max-width:75ch`, and that the 40ch list includes `input.f-profile`.

e2e:

- `account.js`: `$$eval('main section', s => s.map(x => x.id))` equals
  `['profile','keys','groups','reach']`; at 1280 the account `main`'s left edge and width equal the
  console's (`getBoundingClientRect`).
- `nojs.js`: the brand-versus-`h1` checks stay (they now hold at 16px on a phone too); the
  comment naming "the account's 620px column" is updated; the 320px no-scroll check stays.
- `profile.js`: the native walks send `X-Auth-Native-Username`; one walk without it sees the
  sentence, no pill, and records zero Cognito calls.
- `e2e/lib/cognito.js`: `PROFILE_HEADERS` gains `X-Auth-Native-Username` (a fixed UUID); the
  fake's `EMAIL_OTP` answer carries `ChallengeParameters` `USERNAME` equal to it and
  `CODE_DELIVERY_DESTINATION` `y***@e***.com`, and its `IdToken` carries the same
  `cognito:username`.
- No selector in `shots.js` depends on section order; the `account*` screenshots change
  (full-page) and are reviewed, not asserted.

`shots.js` scenes: `account-profile-edit` (one identity, the native header) replaces both
`-edit` and `-edit-one`; `account-profile-social` is renamed `account-profile-gone`;
new `account-profile-provider` (`/account/` with the profile settings and no native header) and
`account-profile-notyours` (the fake's challenge names another username). No
`account-profile-signin-again`: it would be the same pixels as `-provider` (section 3).

#### 8. Open questions for the user

1. Should the console's brand show the operator's logo too, as the account page's does? Today
   only the account page does, and it is the one visible difference left in the bar.
2. Slice F drops the account page's flat ground, which §13.18 chose for a narrow column. Drop it
   (one ground for the estate), or keep it on the account page alone?

### 13.27 The sign-in page warns before a duplicate account (plan step 6, R5, designed 2026-11-25)

The problem, measured on rpi-01 on 2026-11-25: a person who normally signs in with Google or
Microsoft types the same address into the email-code form. Cognito has no native user with it,
answers `UserNotFoundException`, and `/auth/login` moves to its registration step, where
"Create account" makes a native user beside the federated one. The user chose to say so on the
page, with no Cognito change and no new setting.

What was looked at: `src/assets/login.html` (the three steps, the inline script's `I18N` tables,
`applyLang`, the `UserNotFoundException` branch of the email step's submit handler, the
`[data-idp]` binding loop), `src/assets/auth.css` and `src/assets/base.css` (`.hint`, `.panel`,
`.warn`, `.divider`, `.social`, `button.social-btn`), and in `src/bin/bb-auth.rs` `social_block`,
`login_page`, `render_page` and the page tests (`every_button_carries_its_own_app_client`,
`with_no_social_wiring_the_page_has_no_social_markup_at_all`). Mockup: `/tmp/d6/gen.js` fills
the real template with the three real stylesheets and the registration step active, shot in
Edge as `/tmp/d6/reg-{en,it}-{light,dark}-{1280,360}.png` and `reg-{en,it}-light-320.png`; no
sideways scroll at 320, 360 or 1280 (`scrollWidth` equals the viewport).

#### 1. Where, and how the page knows

On the **registration step only**, between its intro sentence and the name fields, and only on a
deployment that has social buttons. The page does not decide that at run time: the gate does,
the same way it already decides the social section of the email step. `social_block` returns
nothing when `gate.social_buttons` is empty, and a new sibling of it does the same for the
registration step, so on a deployment with no buttons the notice is simply not in the document.
That is the precedent `social_block`'s rustdoc names ("one way for the section to be absent"),
and it is what lets a unit test on the rendered HTML show the absence.

The step reads, top to bottom:

1. the existing intro (`#register-intro`, "No account yet for {email}. Finish signing up.");
2. the notice, a `warn` panel;
3. the deployment's social buttons again, the same buttons the email step shows;
4. the existing divider with "or";
5. the name and phone fields and "Create account", unchanged;
6. "Use a different email", unchanged.

The buttons are repeated **on this step** because the email step's buttons are hidden here
(`.step{display:none}`), and a notice that says "use your provider" while the only way to do so
is two clicks back is recall over recognition (heuristic 6). Repeating them costs no script: the
page binds every `[data-idp]` it finds, and a step that is `display:none` is out of the
accessibility tree, so a screen reader meets one set at a time.

#### 2. The words

| Key | English | Italian |
| --- | --- | --- |
| `dup_note` | Do you usually sign in with one of the buttons below? Use it instead: signing up with a code creates a second, separate account. | Di solito accedi con uno dei pulsanti qui sotto? Usa quello: registrarti con un codice crea un secondo account, separato. |

Why these words. It is a question, not a statement about the person, so a genuinely new visitor
reads it as not about them and moves on, and the twin recognises themself in it. It names **no
provider**: the buttons directly below name them, from the gate's own labels, so the sentence can
never mention one the deployment lacks and needs no `{name}` argument (the `K`-style rule that a
sentence around a value is two keys does not arise). It says what to do ("use it instead") and
the one consequence that matters ("a second, separate account") without the words "duplicate",
"error" or "wrong". "Below" is literally true on every width, because the buttons follow the
panel in the same column.

#### 3. The markup

No new class and no CSS change. The notice is `<p class="panel warn" id="dup-note"
data-i18n="dup_note">` with the English sentence as its text, so it reads correctly before the
script runs and `applyLang` replaces it as it does every other `data-i18n` element. `.panel` and
`.warn` are `BASE_CSS`'s surface and state (the tint, the 4px bar in `--warn`), already used by
the console; the colour lives in `theme.css` only. The buttons are the existing `div.social`
holding the existing `button.social-btn` markup, and the divider is the existing `div.divider`
with `<span data-i18n="or">`. `auth.css` does not restyle `.panel`, so its `margin:0 0 16px`
spaces it from the buttons. `.msg.warn` was tried and rejected: `auth.css` hides `.msg` until
`.show`, and `#msg` is the page's `role="alert"` live region, which a static note is not.

The panel carries no ARIA role and no live region: it is part of the step, not an event. Since
the script moves focus to `#given_name` when the step opens, a screen-reader user would land
after the notice and never hear it, so `#given_name` carries
`aria-describedby="register-intro dup-note"` in the static template. On a deployment with no
buttons `dup-note` does not exist, and an IDREF that matches no element is ignored when the
description is computed (WAI-ARIA 1.2, `aria-describedby`:
<https://www.w3.org/TR/wai-aria-1.2/#aria-describedby>; Accessible Name and Description
Computation 1.2, step 2B: <https://www.w3.org/TR/accname-1.2/#computation-steps>), so the one
template serves both. This also gives the intro sentence, which had the same problem, to that
user for the first time.

WCAG 2.2 AA: the state is carried by the words, not by the tint (1.4.1 Use of Color,
<https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html>); the panel's text is `--text`
on `--warn-bg`, the pair the console already uses; the reading order equals the visual order
(1.3.2 Meaningful Sequence, <https://www.w3.org/WAI/WCAG22/Understanding/meaningful-sequence.html>).

#### 4. Registration stays open

The notice asks; it does not block. The fields and "Create account" are where they were, under
"or", with no checkbox and no confirmation: a separate account is a legitimate wish, signing up
is not destructive, and a confirmation on a non-destructive action is one people learn to click
through. The trade is heuristic 5 (error prevention) against heuristic 7 (efficiency for the
person who meant it), settled toward the lighter touch the user chose.

#### 5. What changes, file by file

- `src/assets/login.html`: a new placeholder `__BB_SOCIAL_REGISTER__` on its own line directly
  after `<p class="hint" id="register-intro"></p>`; `aria-describedby="register-intro dup-note"`
  on `#given_name`; and one entry per dictionary in the inline script's `I18N`, `dup_note`, with
  the two sentences above. That is data in the existing script, not logic: no new function, no
  new listener, no new script element, and the nonce CSP is unchanged.
- `src/bin/bb-auth.rs`: factor the per-button loop out of `social_block` (its output stays byte
  for byte the same), and add its sibling for the registration step, which returns the empty
  string for an empty list and otherwise the panel, `<div class="social">` with the same buttons,
  then the divider, in that order. `login_page` adds `("__BB_SOCIAL_REGISTER__", ...)` beside
  `__BB_SOCIAL_BUTTONS__`. The rustdoc of both says why the buttons appear twice.
- No change to `auth.css`, `base.css`, `theme.css`, any setting, or Cognito.

This differs from the plan's wording in two places, which the coordinator should know: the gate
(`bb-auth.rs`) changes, because a static template cannot be absent on one deployment and present
on another, and the inline script gains two strings, because that is where the page's words
live.

#### 6. Tests for the notice

Gate unit tests (`src/bin/bb-auth.rs`, on `login_page`'s output):

- With buttons (`settings_with_buttons(&[("Google", ..), ("Okta", ..)])`): the page contains
  `id="dup-note"` with `data-i18n="dup_note"`; its position is after `id="register-form"` and
  before `id="given_name"`; `data-idp="Google"` occurs **twice**, the second occurrence inside the
  registration step (after `id="register-form"`, before `id="code-form"`), followed by
  `class="divider"` before `id="given_name"`.
- In both languages: the script carries the exact English and Italian `dup_note` strings
  (`dup_note: "Do you usually sign in ..."` and `dup_note: "Di solito accedi ..."`), and the
  panel's own text is the English one.
- Without buttons (`social_settings("", &[])`, and a domain with an empty list): no
  `id="dup-note"`, no `data-i18n="dup_note"` attribute, `data-idp=` absent, and no `__BB_` left
  anywhere on the page. Assert on the element, not the string: the `I18N` table carries the
  sentence on every deployment.
- `#given_name` carries `aria-describedby="register-intro dup-note"` on both.
- The email step is unchanged: the first `class="divider"` still precedes the first
  `data-idp=` inside `id="email-form"`, and the existing ordering test still holds.

No e2e walk covers `/auth/login` (the browser suites drive `bb-auth-web`). The designer reviews
the rendered page in a browser with the registration step active, light and dark, at 1280 and
360, in both languages, before the slice closes, as the plan's "Done when" says.

#### 7. Alternatives rejected

- **The notice alone, pointing back to the email step**: the action is two clicks away and the
  person has to remember which button; the buttons beside the sentence are the instruction.
- **Naming the providers in the sentence**: needs names derived from the buttons and a `{name}`
  list in two word orders; the buttons below already say them, in the gate's labels.
- **A static notice hidden by CSS `:has()` when there is no `.social`**: the sentence would be
  in every document, and a unit test could not show its absence.
- **Moving the social section out of the steps and showing the notice with a sibling selector**:
  restructures the email step for a second purpose, and puts the notice under the form, after
  the person has typed their names.
- **The notice on the email step, before anyone types**: it would speak to everybody who signs
  in, almost all of whom are not the case, and teach people to ignore the card.
- **A checkbox or a confirmation before "Create account"**: friction on a legitimate,
  non-destructive choice (section 4).

#### 8. Open questions for the user on the notice

1. The intro just above the notice says "No account yet for {email}", which is not true for the
   person this notice is for (they have a provider account). Leave it, since the notice sits
   right under it, or soften it for every deployment to "No account signs in with a code for
   {email} yet"?
2. The email step's own hint promises "No account yet? We'll create one on the fly." Leave it?

#### 9. User enumeration: accepted, with a pool migration kept for later (2026-11-26)

The user asked whether the sign-in page lets anybody learn which addresses have an account. It
does, and the notice above adds nothing to it: the notice is static, rendered for every visitor on
a deployment with social buttons. What reveals existence is the email step itself. A known native
address gets a code, and an unknown one moves to registration, because the page follows Cognito's
`UserNotFoundException`. That needs the app client's `PreventUserExistenceErrors` at `LEGACY`
(inferred from the page working, **not read** on the pool). Only native users show this way; a
federated-only address looks unknown, which is the duplicate problem this section exists for.

Turning the protection on alone does not close it here. With it `ENABLED`, `USER_AUTH` answers an
unknown user with a challenge, so the page could no longer route to registration; and `SignUp`
"always returns `UsernameExistsException` when a username is already taken", while this pool's
username *is* the email (`UsernameAttributes: [email]`). The documented way out is the email as a
verification-based **alias**, which is fixed when a pool is created.

Three options were weighed with the user:

1. **Accept the risk.** One address at a time, existence of a native account only, no WAF today.
   **Chosen on 2026-11-26**, because the user wants sign-in and sign-up as fast as possible.
2. Rate-limit in front of Cognito (AWS WAF on the pool, or Cognito's threat protection), keeping
   today's flow. Cost not checked.
3. **A new pool with the email as an alias and the protection on, kept in view for the future.**
   Returning users would see no change. A new user would choose "Create account" before typing,
   one click more. A new user who picks "Sign in" would wait for a code that probably never comes,
   which is the slow case; the page could soften it with a sentence after a minute. Somebody who
   already has an account and picks "Create account" gets a code, then `AliasExistsException` at
   `ConfirmSignUp`, then a second code to sign in. And it is a migration: import the users,
   re-link the providers, new app clients, a `gate.issuer` change (a guarded change), and
   everybody's first sign-in on the new pool. bb-auth's own cookies survive it. Two things to
   verify on a test pool before deciding: whether the challenge for an unknown user claims to send
   a code, and whether sign-up's automatic sign-in works the same with an alias.

Source: <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html>.

### 13.28 One account menu in the shared header, on one row, with the logo (plan step 8, slices H and L, designed 2026-11-25)

The user's requests of 2026-11-25, in the order they came:

1. Slim the header. The bar shows only the person's name or only the email, and a click on it
   opens one panel holding the page menu, the settings (expanding) and Sign out. On desktop the
   console's tabs stay in the bar as the primary navigation; at narrow widths they move into the
   panel (accepted compromise). `/account/` has no tabs.
2. The panel also holds "Delete account and all its data", the entry to step 7.
3. On the live console the header wraps, with the user, settings and logout on a second row. The
   header must be on **one row, always, at every width**.
4. Slice L folds in: `ui.logo_url` in the console's bar too, which widens the console's
   `img-src`.
5. The console's Settings tab moves into the panel too. The bar keeps four tabs: Dashboard,
   Applications, Users, Audit. (Changed by plan step 15, 2026-11-26: System settings is a fifth
   tab again, last, and the narrow-width tabs go into a navigation menu of their own, never into
   this panel: §13.34.)

This replaces the header's identity span, the sliders trigger and the Sign out icon of §13.17
and the Preferences menu of §13.20 (whose light-dismiss cover is kept). It absorbs slice M of
§13.26 §6 and slice L of `PLAN.md` step 8. The user offered a collapsible side menu of icons as
another way out ("vedi tu"); §11 says why it is not taken.

What was looked at: §13.17, §13.20, §13.26 §6, `PLAN.md` steps 7 and 8; in
`src/bin/bb-auth-web.rs` `identity_label`, `top_bar`, `prefs_trigger`, `sign_out_pill`,
`shell_as`, `shell_named`, `account_shell`, `AccountPrefs` (`who`, `page_lede`), `Look`,
`AccountLook`, `account_csp`, `admin_csp`, `SETTINGS_ONCHANGE`, `K::Config` (the tab, the
Settings page's `h1` and its title), and the two places the given name is read (the console's
dispatcher and `handle_account`, both `settings.profile_claims` → the `given_name` claim's header
→ `pct_decode`); `page_csp` in `src/lib.rs` (its `img-src`); `src/assets/admin.css` (the header
block, `details.settings`, `.menu`, `.selfserve-brand img`, the phone block at
`@media (max-width:640px)`, the only `@media` in the file) and `base.css` (`.pill`, `.pill.rm`,
`.pill.on`, `nav .pill`, `.vh`). Rendered today: `node e2e/shots.js settings-menu` and
`account-menu`, copied to `/tmp/d8h/before/{light,dark,phone,it,noscript}/`. At 360 the
console's bar is two lines, the tabs strip scrolls sideways with the fifth tab clipped, and the
open menu covers the strip.

#### 0. Measurements (slice H)

All on the **real console** from the current tree (`/admin/users` booted with `e2e/lib/server.js`,
Edge), with the H changes injected into the live DOM and CSS (`/tmp/d8h/wrap/m.js`, `v.js`,
`v4.js`); "fits" means every displayed child of `.bar` shares one vertical centre and
`scrollWidth` equals the viewport. The name pill is capped at 16rem (256px); "long name" is
"Bartholomew-Alexander Montgomery", "long brand" is "BadBat75 Estate Services", the logo a
120x35 image drawn at 28px high.

Narrowest viewport at which the bar is one row, wrapping allowed as today:

| Bar | EN | IT |
|---|---|---|
| today (default brand, five tabs, address, sliders, sign-out) | 821 | 856 |
| today, long brand | 927 | 948 |
| H, five tabs, name pill "Ada" | 666 | 700 |
| H, five tabs, long name | 847 | 882 |
| H, five tabs, long brand and long name | 954 | 975 |

So H alone does not stop the wrap above 640px, and the bar's content column is at most 968px
(`.bar` is 1000px with 16px padding), so the five-tab worst case cannot fit at any width.

Natural width of each part with **four** tabs (the Settings tab moved): tabs 349px EN, 340px IT;
brand 85 (EN) or 99 (IT) without a logo, 191 to 224 with one or with the long brand (capped at
14rem); name pill 74 for "Ada", 256 when long. With the bar's 16px padding and two 20px gaps, the
widest case that keeps the brand whole and leaves the name at least 128px is **773px** (EN, long
brand, logo, long name); every other combination needs between 580 and 764.

With the rules of §4 (no wrapping by construction, the tabs at 800px and below in the panel)
every combination was walked from 320 to 1400 in 4px steps: **one row and no sideways scroll at
every width**, in both languages, with and without the logo, the long brand and the long name.
With the tabs moving only at the existing 640px the bar also stays one row, but between 641 and
about 770 the brand text is cut to one letter and a short name to "A…" (screenshot of the IT
worst case at 1280, 761, 760, 641, 360 and 320: `/tmp/d8h/wrap/strip.png`), so 640 is rejected.

Static mockup of the panel (not of the four-tab bar) over the real CSS plus a delta
(`/tmp/d8h/proposed.css`, pages `/tmp/d8h/{console,account}-{light,dark}.html`,
`/tmp/d8h/shot.js`): `/tmp/d8h/{console,account}-{light,dark}-{1280,360}.png`; the panel spans
x=84 to 344 at 360 and 864 to 1124 at 1280. Found while measuring: the phone rule
`nav.acct .who{display:none}` hides the new trigger outright, so it must go.

#### 1. The label

The trigger shows **one** string: the given name when nginx forwards it, else the first address.
No "·", no second fact: the panel says the rest.

- **Console**: the dispatcher already computes `given` (the `given_name` claim's header named by
  `settings.profile_claims`, percent-decoded) before any page is built, and the email header is
  `v.admin` (or, on the `403`, the raw header `shell_named` receives today).
- **`/account/`**: `handle_account` computes the same `given` from the same settings, and the
  email header is `raw` (the `X-Auth-Email` value).
- A deployment that does not configure `given_name`, or a person whose token has none, shows the
  address. An empty or whitespace name counts as none (as `identity_label` does today).

`identity_label` is replaced by `Who { label: String, emails: Vec<String>, name: Option<String> }`
built by one `who(given, email_header)`: `label` is the name else the first address, `emails`
every address of the header split on ASCII whitespace, in order. Both shells take `Option<Who>`
where they take `Option<String>` today; the `403` builds one the same way.

**Truncation.** `span.who-name` inside the trigger: `overflow:hidden; text-overflow:ellipsis;
white-space:nowrap; min-width:0`; the trigger `max-width:16rem` (256px) above 640px and `11rem`
(176px) at or below it, and `min-width:0` so it is the bar's first give when room is short.
`text-overflow` needs exactly those companions
(<https://developer.mozilla.org/en-US/docs/Web/CSS/text-overflow>). Nothing is lost: the full
text stays in the DOM (a reader hears all of it), the trigger's `title` carries the full label,
and the panel's first block prints every address whole, wrapping with `overflow-wrap:anywhere`.
That is what keeps the cut acceptable under WCAG 1.4.10 Reflow, which asks that content stay
available without two-dimensional scrolling, not that every string be shown in full in place
(<https://www.w3.org/WAI/WCAG22/Understanding/reflow.html>).

#### 2. The panel's content and order

Top to bottom, in groups divided by a rule (`div.sep`), each block present only where it applies:

1. **Who** (`p.who-full`): the name in `strong` when there is one, then every address on its own
   line, muted and small. It heads the panel because the panel was opened by clicking that name,
   and this is the one place a person with several addresses or accounts checks which identity
   they are acting as. **The uuid is not here**: it is a machine id, the account page's lede
   already shows it as "Account id" (one home for one fact), and on the console nobody asked for
   it.
2. **The console's places**, console administrators only (`div.menu-places`): at 800px and below
   the four tabs (`div.menu-tabs`, full-width rows, the current one `.pill.on` with
   `aria-current="page"`), then, at every width, **System settings** as an `a.pill` row to the
   Settings page (`Route::Config`, URL unchanged), with a gear glyph and `aria-current="page"` and
   `.on` on any Settings page. It sits with the tabs because it is a page of the console, as they
   are; the rule below it is what tells it apart from the person's own preferences. (Changed by
   plan step 15, 2026-11-26: neither the tabs nor System settings are in this panel any more; the
   console's places are "Go to your account" alone, §13.34 §3.)
3. **Preferences**, as a **nested `details.prefs`**: a full-width row `summary.pill` with the
   sliders glyph, the word `K::Settings` ("Preferences") and a caret that turns when open; inside
   it the existing form (Language, then Theme, the two `select`s), closed by default.
4. **Sign out**: `a.pill` row with the existing out glyph **and** the visible word `K::SignOut`.
   In a panel there is room for the word, so the icon stops being the only label.
5. **Delete account and all its data** (§5 below), last, `/account/` only, **added by step 7**.

**The wording "System settings".** Two rows a rule apart would still both say "settings" if the
console's page kept its tab word, and "Preferences" next to "Settings" is exactly the pair people
confuse. The page's own content is four sections (the gate, the audit, the administrators, the
look), so "Gate settings" names one of four; "System settings" names the whole file and reads as
the opposite of "my preferences". The glyphs follow the reason §13.17 gave for choosing the
sliders: the gear now goes on the system's configuration and the sliders stay on the display
preferences. **One name per place**: `K::Config`'s text changes to "System settings" /
"Impostazioni di sistema", so the panel row, the page's `h1` and its `<title>` agree (Nielsen 4);
the Settings tab was the key's only other use, and it is gone.

**Why a nested group and not inline radios.** The user's own word was "the settings
(expanding)". The common case is opening the panel to check who you are or to sign out, and
preferences are set once; a closed group keeps the panel short (progressive disclosure,
Nielsen 8). It also reuses the existing two `select`s, their option lists, the console's
`onchange` and its tests unchanged, where six radios would need new fieldset markup, a new test
set and the handler attribute moved onto six inputs. The trade-off: one more click to reach a
preference (Nielsen 7, efficiency), accepted because it is rare.

`p.who-full` is **not** a `p.lede`, so the panel adds no lede to a page and the one-lede rule of
§13.23 holds by construction: `AccountPrefs::page_lede` and the branch on it are deleted. A closed
`details`' content is not rendered, so it is not read before the page's own lede either
(<https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/details>).

#### 3. Mechanics

- **The control.** The outer element stays `details.settings` (the class names "the bar's
  menu"; the §13.20 cover rule, its Rust test and every e2e selector target it, and renaming
  buys a word). Its `summary` becomes `summary.pill.who`: `span.who-name` (the label), a hidden
  `span.vh` ", " + `K::AccountMenu`, and the caret `svg.i-caret` (`aria-hidden`). The accessible
  name is "Ada, account menu", which contains the visible "Ada" as WCAG 2.5.3 Label in Name asks
  (<https://www.w3.org/WAI/WCAG22/Understanding/label-in-name.html>). Not `role="menu"`: the
  panel holds a form and links, and the APG menu-button pattern would promise arrow-key
  navigation and `menuitem` children that a form cannot be
  (<https://www.w3.org/WAI/ARIA/apg/patterns/menu-button/>); a disclosure is the honest pattern
  (<https://www.w3.org/WAI/ARIA/apg/patterns/disclosure/>), and `details` exposes its
  expanded state to assistive technology natively.
- **Closing.** The §13.20 cover stays as is: `details.settings[open]>summary::before` covers the
  viewport while open, so a click outside closes. Its selector is a child combinator, so the
  nested `details.prefs` gets no cover of its own and toggles only from its own row. Submitting
  the form, or following a row's link, loads a page, which closes both. Escape does not close, as
  in §13.20.
- **Keyboard.** Tab reaches the trigger (after the tabs on desktop); Enter or Space opens it;
  focus stays on the trigger; the next Tab enters the panel in DOM order (the tab rows when
  shown, System settings, the Preferences row and its fields when open, Sign out, Delete). Tab
  past the last item leaves the panel open, as today. Both `summary` rows show the existing focus
  ring.
- **Scripting off.** Everything is HTML: both disclosures open, the links navigate, and the
  Preferences form submits with its button. The console keeps its one handler as it is
  (`onchange=SETTINGS_ONCHANGE` on both `select`s, `noscript` Apply); `/account/` has no handler
  and its Apply is always shown in `div.actions`. (Changed by plan step 13, 2026-11-26: that
  handler is on both surfaces, so the button is the `noscript` fallback on each, and "scripting
  off" means that button here exactly as it does in the console.) The form is the same `GET` to
  the page and the same `302` that sets `theme` and `lang`.
- **Size.** The panel gets `max-height:calc(100dvh - 80px); overflow-y:auto`, so a short phone in
  landscape can still reach the last row (`dvh`:
  <https://developer.mozilla.org/en-US/docs/Web/CSS/length#dynamic_viewport_units>), and
  `max-width:calc(100vw - 32px)`. Rows are `.bar .pill`, so at least 30px tall at phone width,
  above WCAG 2.5.8's 24px (<https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html>).
- **Look of the rows.** The panel sits inside `nav.acct`, so `nav .pill` already gives every row
  the quiet tab look (muted text, chip on hover) and `.pill.on` the current page's fill: no new
  colour, and the rows read as the same objects as the bar's tabs.

#### 4. One row at every width, and one breakpoint for the tabs

**One row by construction, not by arithmetic.** `.bar{flex-wrap:nowrap}` (replacing `wrap`), so
the bar cannot make a second row whatever an operator's font, brand or a person's name does. What
gives instead, in this order: the name pill shrinks with its ellipsis (`min-width:0`), then the
brand's text with its ellipsis (`.brand{min-width:0; max-width:14rem}`, the text in a `span.t`
with `overflow:hidden; text-overflow:ellipsis; white-space:nowrap`). The tabs never shrink
(`flex:none` on the tab `nav`'s content, `min-width:max-content`), because a cut tab is a
navigation item nobody can read, and the logo never shrinks (`flex:none`). The `.bar` keeps its
20px gap; `.bar{gap:6px 8px}` in the phone block stays.

**The tabs move into the panel at `max-width:800px`.** One new `@media (max-width:800px)` block in
`admin.css`, holding only the header: the bar's tab `nav` gets `display:none` and
`div.menu-tabs` `display:flex; flex-direction:column`; above it `div.menu-tabs{display:none}`.
800 because the measured worst case with four tabs needs 773px (§0) and the margin absorbs an
operator's slightly wider font; the existing 640 is not enough (§0: brand text cut to a letter up
to about 770). It means a tablet in portrait (768) gets the tabs in the panel, which is the
compromise the user accepted for narrow widths. Today's sideways-scrolling tab strip in the phone
block goes (`nav:not(.acct){order:3;…overflow-x:auto…}`), and with it the clipped fifth tab §13.17
named. (Changed by plan step 15, 2026-11-26: the breakpoint is 941px, measured for five tabs, and
below it the tabs go into `details.navmenu`, not into this panel: §13.34 §2.)

**The phone block (640) keeps two header rules of its own**: delete `nav.acct .who{display:none}`
and its comment (the name **is** the trigger now) and cap the trigger at `11rem`; and with a logo,
hide the brand's text visually (`.brand:has(img) .t` gets the `.vh` declarations), leaving the
logo alone, since below 640 a logo plus two lines of text plus a name does not fit a 320px
screen. The text stays in the accessibility tree, which is why the image keeps `alt=""`. Without
a logo the text stays and truncates.

**The tab links are emitted twice, from one loop.** Moving one element between the bar and the
inside of a closed `details` cannot be done in CSS: a closed `details` does not render its
content, and positioning the bar's `nav` over the panel would put it before the trigger in the
tab order and fight the cover's stacking. So one helper, `tab_links(v) -> Markup` (the `@for`
`shell_named` has today, minus Settings, plus `aria-current="page"` on the current one), is called
in the bar's `nav` and in `div.menu-tabs`. Acceptable because the source has one copy; at any
width exactly one copy is displayed and `display:none` removes the other from the accessibility
tree, so no reader hears the links twice; and the cost is four anchors per page.
`aria-current="page"` is the attribute for "the current item in a set of links"
(<https://www.w3.org/TR/wai-aria-1.2/#aria-current>), and it is added in the bar's copy as well,
which today says "current" only by colour (WCAG 1.3.1). `div` and not `nav` for the panel copy:
it is already inside `nav.acct`.

On a Settings page no bar tab is current, so no tab is highlighted while the bar shows the tabs;
the `h1` "System settings" says where the person is, and the panel's Settings row is marked. The
trigger is not marked, because a marked trigger would look open. (Changed by plan step 15,
2026-11-26: on a Settings page the bar's fifth tab is current, §13.34 §1.)

#### 5. Delete account and all its data

- **Placement.** The last row, after Sign out, behind its own rule. Last because Tab order then
  never crosses it on the way to Sign out, and the destructive, rare action sits farthest from
  the first rows a person reaches; the rule plus the row gap (12px between the two targets) keeps
  a slip off Sign out from landing on it.
- **Style.** `a.pill.rm`, the console's remove component: muted text, the error colour on hover
  and focus, no new colour. The words say what it does; there is no icon. (Changed by §13.30 §1:
  the row carries a trash glyph, because every row of the panel as H built it has one and a row
  without it starts its word a glyph's width left of the words above; and the error colour is on
  hover only, as `base.css` has it, while focus shows the estate's one accent ring.)
- **A link, never a form.** A plain `GET` to `{account}/delete` (`Config::account_path` +
  `delete`), which renders step 7's confirmation page and changes nothing; only that page's
  `POST` deletes. A prefetch or a misclick costs nothing. This is the confirmation-before-
  deletion WCAG 3.3.4 asks for on data deletion
  (<https://www.w3.org/WAI/WCAG22/Understanding/error-prevention-legal-financial-data.html>).
- **On the console.** Recommended: **not** in the console's menu. On the console every page is
  about other people's accounts and the users page has its own "remove"; "Delete account" in a
  panel opened over `/admin/users/bob` reads as deleting bob, and the cost of that misreading is
  high. An administrator is a person with an account, and reaches its deletion from `/account/`.
  Whether the console's panel should then carry a "Your account" row to `/account/` (reusing
  `K::NotAdminToAccount`, "Go to your account") is open question 2.
- **Before step 7.** Recommended: **not built in H**. Step 7 adds the row, its route, its `K`
  key and its tests together. Hidden markup would be a dead link a stylesheet could reveal, and
  an unused `K` key is dead code; H only reserves the place (last, after a rule) and this
  wording.

| Key | English | Italian |
|---|---|---|
| `AccountDelete` (step 7) | Delete account and all its data | Elimina l'account e tutti i suoi dati |

#### 6. The logo in the console's bar (slice L), and the one CSP change

- **Markup.** The console's brand becomes `a.brand` > `img` (when `ui.logo_url` is set, `alt=""`)
  and `span.t` (the brand name, then `span.v` with `K::ConsoleTag`); the `403`'s `span.brand` the
  same. `/account/`'s `span.brand.selfserve-brand` keeps its markup and gains the `span.t`
  wrapper around its name, so both surfaces have one shape. `alt=""` because the name beside it
  says what the picture is; where the text is visually hidden (§4) it is still read.
- **Size.** One rule for both surfaces replaces `.selfserve-brand img`: `.brand img{height:30px;
  width:auto; max-width:96px; flex:none; filter:var(--logo-filter)}`, the height the account page
  already uses, which sits inside the 36px pill row; `max-width` keeps a wide wordmark from
  eating the tabs' room (the measurements used a 96px-wide image). `.brand` becomes
  `display:flex; align-items:center; gap:10px`: the logo left, the two text lines right of it,
  vertically centred.
- **Data.** `Look` gains `logo: Option<&str>` from `settings.logo_url`, read where `Look` is
  built today, exactly as `AccountLook::logo` is.
- **CSP, console only.** `admin_csp` passes `look.logo` to `page_csp` where it passes `None`
  today, so `img-src` goes from `data:` to `<the logo's source> data:` when a logo is set, and is
  unchanged when it is not. That is the account page's `img-src` exactly, from the same
  `csp_asset_source`. Nothing else in either policy changes. The rustdoc on `admin_csp` that says
  `img-src` is `'none'` is already stale (`page_csp` always emits `data:`) and is rewritten with
  this change.

#### 7. What slice M becomes

M (one `prefs_menu` for both shells) is done inside H, one level up: one `account_menu` built by
both shells, so no menu markup is written twice.

- `prefs_form(lang, lang_pref, theme, action, hidden: &[(String, String)], scripted: bool) ->
  Markup`: the `form.edit` with the two `select`s; `scripted` adds the `onchange` and wraps
  Apply in `noscript`, else Apply is plain in `div.actions`. Deletes the second copy in
  `account_shell`. (Changed by plan step 13, 2026-11-26: the `scripted` argument is deleted, and
  one shape ships for both surfaces, the two `select`s carrying
  `onchange=SETTINGS_ONCHANGE` and Apply inside `noscript`.)
- `account_menu(lang, who: Option<&Who>, places: Option<Markup>, prefs: Markup, logout:
  Option<&str>) -> Markup`: the `details.settings` with the trigger and the panel in §2's order.
  Step 7 adds a `delete: Option<&str>` argument. `shell_named` passes `Some(div.menu-tabs from
  tab_links(v) + the System settings row)` when `v.admin` is set, `Config::logout_url`,
  `scripted: true`; `account_shell` passes `None`, `Config::account_logout_url`,
  `scripted: false`. (Changed by plan step 13, 2026-11-26: those two are the `prefs_form` flag's
  call sites, and the flag is gone from both; `account_menu`'s own signature is untouched.)
- `brand_block(name, tag: Option<&str>, logo: Option<&str>, href: Option<&str>) -> Markup` for
  the brand slot of both shells (link or `span`, the logo, `span.t`), so slice L is not written
  twice either.
- `prefs_trigger` and `sign_out_pill` are replaced by the two rows (the glyphs move with them);
  `identity_label` by `who`; `span.who` in `nav.acct` and `AccountPrefs::page_lede` go.
  `nav.acct` keeps only `account_menu`.

#### 8. `K` keys (H)

| Key | English | Italian | Use |
|---|---|---|---|
| `AccountMenu` | account menu | menu dell'account | hidden suffix of the trigger's name |
| `Config` (text changed) | System settings | Impostazioni di sistema | the panel row, the Settings page's `h1` and title |

Reused unchanged: `K::Settings` (the Preferences row), `K::SignOut` (now also visible text),
`K::SettingLanguage`, `K::SettingTheme`, `K::Apply`, the four tab keys, `K::ConsoleTag`.

#### 9. Tests and scenes (slice H)

Unit and socket tests in `src/bin/bb-auth-web.rs`:

- `who_is_the_name_else_the_first_address`: `who(Some("Ada"), "a@x b@x")` has label `Ada` and
  both emails; `who(None, …)` and `who(Some("  "), …)` have label `a@x`; no `·` anywhere.
- `the_trigger_is_the_label`: on the console and on `/account/`, with and without the
  `given_name` header configured and forwarded, `details.settings > summary` text starts with the
  label, carries `span.vh` with `K::AccountMenu` in both languages, a `title` equal to the full
  label, and no `span.who` is left in `nav.acct`.
- `the_bar_has_four_tabs`: the bar's `nav` holds exactly Dashboard, Applications, Users, Audit;
  no bar link to `Route::Config`. (Changed by plan step 15, 2026-11-26: renamed and inverted,
  §13.34 §7.)
- `the_panel_is_in_order`: inside `.menu`, in this order: one `p.who-full` listing every address;
  on the console `div.menu-tabs` (the four tab links, same hrefs and order as the bar's) then one
  `a` to the Settings route reading `K::Config`; one `details.prefs` holding the one `form`; one
  Sign out `a.pill` whose text is `K::SignOut` (only when the logout URL is set). No `p.lede` in
  `.menu` on any page, including the profile code page. `/account/` and the console's `403`
  have no `div.menu-tabs` and no Settings row.
- `aria_current_names_the_page`: on `/admin/users` exactly one `aria-current="page"` in the bar
  (Users) and one in `div.menu-tabs`; on `/admin/config` none in the bar or `div.menu-tabs` and
  one on the Settings row, which is `.on`; the Settings page's `h1` and title read `K::Config`'s
  new text in both languages.
- The preference handlers: the console's two `select`s carry `onchange="this.form.submit()"` and
  Apply is inside `noscript`; the account's carry no `on…` attribute and Apply is in
  `div.actions`. `no_page_but_the_reveal_carries_a_script` unchanged. (Changed by plan step 13,
  2026-11-26: the account's two carry the same handler and the same `noscript` Apply, and that
  test now asserts exactly two handler attributes on every page of **both** surfaces, each one
  the shell's; `nojs.js` allows the same two, and runs the self-service page with scripting on
  to show a pick submits.)
- `the_console_shows_the_logo_and_permits_it`: with `ui.logo_url` set, the console's `a.brand`
  holds `img[alt=""]` with that `src` before `span.t`, and `admin_csp`'s `img-src` is that
  source followed by `data:`; without it, no `img` and `img-src data:` exactly as today. The
  account page's policy is byte for byte what it was. (Changed by plan step 13, 2026-11-26: what
  that test compares across the two surfaces is `img-src`, and it still passes; the account
  page's whole policy is not what it was, since its `script-src` gained the handler's hash, so
  the sentence's "byte for byte" is the logo's half only.)
- CSS, parsed as `an_open_menu_closes_on_a_click_outside_it` does: `.bar` has
  `flex-wrap:nowrap`; outside the media blocks `.menu-tabs{display:none}`, the trigger's
  `max-width:16rem` and `min-width:0`, `.who-name` and `.brand .t` with
  `text-overflow:ellipsis`, `overflow:hidden`, `white-space:nowrap`, `.brand img` with `height`,
  `max-width` and `flex:none`; a `@media (max-width:800px)` block with the tab `nav`
  `display:none` and `.menu-tabs` `display:flex`; the 640 block with the `11rem` cap,
  `.brand:has(img) .t` hidden, and **no** `nav.acct .who` rule and no `overflow-x` on the tab
  `nav`; the cover test extended so `details.prefs` has no `::before` cover.
- Existing tests to rewrite: those on `span.who` and the menu's `p.lede` (the `who_span` and
  `account_lede_zone` assertions), the icon trigger, the Sign out pill and the five tabs.

e2e:

- A new one-row check in `e2e/tests/settings.js` and `account.js`: for widths 320, 360, 640,
  641, 800, 801, 1024 and 1280, every displayed child of `.bar` has the same vertical centre and
  `scrollWidth` equals the width, with the fixture's settings plus a long `ui.brand_name` and a
  `data:` `ui.logo_url` (the CSP permits `data:`, so no network).
- `settings.js`: open `details.settings > summary`, open `details.prefs > summary`, pick a theme,
  `data-theme` changes (the handler); click bottom-left, the menu is closed; the System settings
  row reaches `/admin/config`. At 360x760 and at 800: the bar's tab `nav` is not visible, the
  panel shows four tab links with `aria-current` on the current one, clicking "Applications"
  navigates.
- `account.js`: the trigger reads the email (fixture without `given_name`) and the name when
  `PROFILE_HEADERS` forward one; open, open Preferences, Apply changes `data-theme`; the Sign out
  `href` has no `rd`; no `div.menu-tabs` and no Settings row.
- `nojs.js`: the same open, nested open and Apply on both surfaces with scripting off, and at 360
  a tab and the System settings row reached from the panel navigate.
- `e2e/shots.js`: `settings-menu` and `account-menu` now open the account menu (closed
  Preferences); add `settings-menu-prefs` and `account-menu-prefs` (Preferences open),
  `config-menu` (the panel open on `/config`, Settings row current), `forbidden-menu` (the
  `403`'s panel: who and Sign out only) and `header-logo` (a long brand and a `data:` logo, the
  bar closed). The designer reviews all of them light, dark, phone and `it` before the slice
  closes.

For the coder: `src/bin/bb-auth-web.rs` (`who`, `tab_links`, `prefs_form`, `account_menu`,
`brand_block`, `shell_named`, `account_shell`, `AccountPrefs`, `Look`, `admin_csp`, the
dispatcher's and `handle_account`'s label building, the `K` table); `src/assets/admin.css` (the
`.bar` nowrap, `.brand` as a flex row with `span.t`, `.brand img` replacing `.selfserve-brand
img`, the trigger, `.who-name`, `.menu` as a flex column with `max-height`, `.menu .pill`
full-width rows and their glyph size, `.menu .sep`, `p.who-full`, `details.prefs` marker removal
and caret turn, `.menu-tabs`, the new 800 block and the 640 block's changes). The deltas in
`/tmp/d8h/proposed.css` and `/tmp/d8h/wrap/v4.js` are starting points, not rules to copy.

#### 10. Alternatives rejected (slice H)

- **Tabs always in the panel, on desktop too**: the user's first idea; hides the primary
  navigation behind a click on every page (recognition over recall). The user accepted the
  compromise.
- **The tabs moving at the existing 640px**: §0, the brand cut to a letter up to about 770.
- **A wrapping bar with the tabs moving only when they would wrap**: CSS cannot ask "would this
  wrap"; a fixed breakpoint plus `nowrap` is the only one-row guarantee without a script.
- **Inline radios for the preferences**: §2.
- **"Gate settings"**: names one of the page's four sections (§2).
- **`popover` or `role="menu"`**: §13.20's reasons, plus a form inside a menu role.
- **The sliders icon as a second trigger beside the name**: two controls where the user asked
  for one.
- **The uuid in the panel**: §2.
- **Moving the bar's `nav` into the panel with CSS only**: §4.
- **Delete above Sign out, or in red at rest**: Tab would cross it on the way to Sign out; red at
  rest would be the loudest row of a panel opened mostly to sign out, and the console's removes
  are quiet until hovered.

#### 11. Why not a collapsible side menu of icons (slice H)

The user offered it as an option. Not taken: after H the bar holds a brand, four tabs and one
pill, which §0 shows fits on one row down to 800px and, with the tabs in the panel, down to 320;
a rail would add a second layout for every page, an icon for each of four tabs that people must
learn (recognition over recall: an icon rail is the opposite of a labelled tab), a collapsed and
an expanded state that need either a script or a second disclosure, and it would take a column
from every table on a phone. The problem it would solve is solved.

#### 12. Open questions for the user (slice H)

1. Delete on the console's panel: recommended no (§5). Agree?
2. If not there, should the console's panel carry "Go to your account" (a link to `/account/`)?
   Recommended yes, one row above Sign out; it is a new item nobody has asked for yet.
3. "System settings" / "Impostazioni di sistema" as the page's new name everywhere (§2)?

### 13.29 Delete my account (plan step 7, designed 2026-11-26; redone the same day on the owner's worker)

R4 as the user changed it on 2026-11-26 (option a): bb-auth-web removes the roster row itself and
hands every Cognito deletion to the owner's existing deletion worker (`bb-account-delete`, in the
itadmin repository), so bb-auth-web holds no AWS credential and makes no Cognito call for a
deletion. A social-only person's Cognito account is now deleted too. Sections W1 to W12 are the
design; the overnight design for a direct `DeleteUser` is kept after them, under "The direct
DeleteUser design", each part marked where it is superseded or still holds. IT-Admin was reachable
only through the coordinator, so every change on the itadmin side is a **proposal for the owner**
(W8), never a step of this plan.

What was read for the redo: `AGENTS.md` (the invariants, the self-service paragraph, "Actions with
real effects"), `PLAN.md` R4 and step 7 as changed on 2026-11-26, §13.3, §13.7, §13.9, §13.13,
§13.29 and §13.30 as written overnight; `deploy/bb-auth-web.service` (no `IPAddressDeny`,
`RestrictAddressFamilies` with `AF_INET`, one `ReadWritePaths`); in `src/bin/bb-auth-web.rs`
`Config` (`cognito_timeout`, `account_logout_url`), `handle_account`, `account_uuid_of`,
`native_user`, `cognito_post` (its `timeout_global`), `WRITE_LOCK`, `csrf_ok`, `audit()`, the
tests' `FakeCognito`; in `src/bin/bb-auth.rs` `authorized_response` (the identity headers are
derived per request from the live file); ureq 3.4.0's `src/config.rs` in the cargo registry.

#### W1. The worker's contract, as read (worker)

**Read, not by this role:** the coordinator and IT-Admin read itadmin's
`infra/rpi-01/bb-delete-request/` and rpi-01's installed copies on 2026-11-26, read-only. The intake
is `bb-delete-request.py` v2.0.0, the worker `bb-account-delete.py` v1.0.0, rpi-01's copies are
byte-identical to the repository's, and no environment override is set there. This role has not
read the itadmin source; the facts below are theirs, as relayed.

- **Intake.** A `DynamicUser` service listening on `127.0.0.1:8480`, spool in
  `/var/lib/private/bb-delete-request` (0750). Two hard-coded paths: `GET /account/whoami` answers
  `{email, protected}` for the `X-Auth-Email` it is sent; `POST /account/delete` takes a
  form-urlencoded body of at most 4096 bytes with `confirm_email`. Checks in this order: no header
  `401`; `confirm_email` differs from the header `400` (`confirm_mismatch`); the address is in
  `BBDR_PROTECTED` (default the operator's address) `403` (`protected`); the spool file is at its
  2 MiB cap `503` (`unavailable`); else it appends `{"ts","email","remote_addr"}` to
  `selfdelete.jsonl` (0640, fsync) and answers `202 {"ok":true,"status":"accepted"}`.
  `remote_addr` is `X-Real-IP`; the worker needs only `email`. It reads the **whole** header,
  lowercased and stripped, as one address. It checks no secret: any local process that reaches the
  port is believed.
- **Worker.** `root`, oneshot, started by a path unit on `selfdelete.jsonl`, with
  `AWS_SHARED_CREDENTIALS_FILE=/etc/bb-privacy.aws` and `ReadWritePaths=/opt/bb-auth/var/lib`. Per
  record: an address in `BBAD_PROTECTED` (its own list, default the operator's address) is refused
  and an SNS mail sent; else `list-users` with the filter `email = "..."`, an exact re-check, and
  `admin-delete-user` for every match, federated twins included; then `bb-auth-adm user show EMAIL`,
  and on failure it logs "not in the roster" and goes on, else `user rm EMAIL` and
  `systemctl reload bb-auth`. It records `done.jsonl` in its own 0700 `StateDirectory`, keeps a
  cursor, and takes at most `MAX_PER_RUN=10` records: **above ten pending, the whole run is
  refused**. There is no timer: a run happens only when the spool changes. A failed run keeps the
  cursor and sends an SNS "FAILED" mail. `BBAD_DRY_RUN` exists.
- **The race IT-Admin named.** The worker runs `user show` before `user rm`; a row removed between
  the two makes `rm` fail, the run counts as failed (cursor kept, SNS "FAILED", no retry until the
  next spool change), and the Cognito deletion has already happened. A row already gone when
  `show` runs is the tolerated "not in the roster" path.
- **State on rpi-01.** The path has never run: `selfdelete.jsonl` does not exist and the worker's
  `StateDirectory` was never created. nginx no longer routes `/account/delete` to the intake
  (bb-auth-web took `/account/` on 2026-11-24), so nothing reaches it today, except a local process.
- **IT-Admin's notes.** The email-code sign-in fires the pool's `post_authentication` Lambda, which
  mails the administrator a "login". A deleted person's session cookie keeps its `authenticated`
  grants until it expires or they sign out (the stateless-session invariant says the same).

**Read in a source by this role:** ureq 3.4.0 follows redirects by default (`max_redirects: 10`
in `Config::default`, `src/config.rs`), so the intake client must set it to 0, or a `3xx` would
carry an identity header to wherever it pointed.

**Assumed, to be shown by 7g:** that a record whose address no Cognito user has is zero
`admin-delete-user` calls and not an error (the contract says "for each match"); that the worker
removes the row through the same `remove_user` the CLI uses (it calls `bb-auth-adm user rm`, which
does); how long a record takes from the `202` to the deletion (no number is promised anywhere until
7g measures one).

#### W1a. The next versions, prepared and not deployed (worker)

**Relayed by IT-Admin on 2026-11-26, not read by this repository's roles.** The owner had IT-Admin
prepare W8 §1, §2, §3 and §5 in itadmin as intake 2.1.0 and worker 1.1.0. They were tested there
with stubs and are not on rpi-01 until the owner says so. W8 §4 (a mail to the person) was left
out by the owner. What bb-auth-web may rely on once 2.1.0 is installed, on both `GET
/account/whoami` and `POST /account/delete`, checked in this order:

- `X-BB-Delete-Secret` wrong, **or sent while the intake has none configured**: `403
  {"error":"forbidden"}`. A missing header is accepted while `BBDR_REQUIRE_SECRET=0` (the
  transition), and is a `403` once that is `1`. So the secret is set on both sides or on
  neither, and bb-auth-web treats this `403` as "not accepted", like every non-`202`.
- `X-Auth-Email` empty: `401`. It contains whitespace: `400 multiple_identities` (W8 §5). W3's
  one-address-per-request already never sends one.
- The protected list unreadable or empty: `503 unavailable` (fail closed).
- Then, unchanged: `confirm_email` mismatch `400`, a protected address `403 protected`, success
  `202` / whoami `200 {"ok","email","protected"}`.

The secret is read through `LoadCredential` from `/etc/bb-delete-request/delete-secret`
(`^[A-Za-z0-9_-]{32,}$`, compared with `hmac.compare_digest`). The owner's recipe generates it with
`secrets.token_urlsafe(32)`, which gives 43 characters and passes W2's rule, and the same bytes go
to `BB_AUTH_WEB_DELETE_SECRET`, written by the operator (7g). The protected list becomes one file,
`/etc/bb-delete-request/protected`, read on every request and every run. Worker 1.1.0 processes at
most 10 distinct addresses per run and leaves the rest queued, with a timer (5 min after boot,
then every 15 min). On a failure it stops at that line and the timer retries it, which also
retires W1's "no retry without a new record". W3's order (the row removed before the first `POST`)
is unchanged by any of this.

#### W2. Decision: bb-auth-web calls the intake on loopback, and its unit does not change (worker)

bb-auth-web calls the intake's two paths itself, over plain HTTP on loopback, with the identity it
already holds for this request: `GET {intake}/account/whoami` and
`POST {intake}/account/delete`, each with `X-Auth-Email: <one address>` and the proposed
`X-BB-Delete-Secret` (W8 §1). The intake is the only interface the worker has, and using it keeps
every check the owner wrote (protected list, spool cap, confirmation) in force.

- **Configuration, in `bb-auth-web.env`, restart-only:** `BB_AUTH_WEB_DELETE_INTAKE`, the intake's
  **origin** (`http://127.0.0.1:8480`), because the intake hard-codes its paths. Validated at
  startup by a new `compile_delete_intake`: `http`, a loopback IP literal (`127.0.0.0/8` or
  `[::1]`), a port, and nothing else (no path, no query, no userinfo, no name); anything else is a
  fatal startup naming the variable. Loopback only because the request carries an identity in clear
  to a service whose one check is that header: to any other host it is an identity sent unencrypted
  to something that deletes accounts on it. **Unset turns the feature off**: no menu row, and
  `{account}/delete` is the `404` every unknown path gets, which is how `BB_AUTH_WEB_LOGOUT_URL`
  unset already behaves. An env variable and not a setting because it is the GUI's own, read once,
  and decides where an identity is sent: the settings file is editable from the console, and a
  field there would let a console session point every future deletion at another port.
- **`BB_AUTH_WEB_DELETE_SECRET`**, **optional** (the user's answer to question 3, 2026-11-26), with
  `compile_proxy_secret`'s rules (32 or more of `[A-Za-z0-9_-]`, never printed; a malformed value is
  still fatal), sent on both calls when set. Today's intake ignores the header, so bb-auth ships its
  half once and the owner can start enforcing it with no bb-auth release. With the intake set and no
  secret the GUI starts, and its startup banner says once, in the journal, that the intake trusts any
  local caller until a secret is set on both sides; the gap is the intake's and closing it is W8 §1,
  at the owner's word. Not generated by the postinst, unlike the proxy secret: the same value must
  reach a file the owner's unit reads, so the operator generates it once (the proxy secret's command)
  and writes it to both. (Changed by the coordinator, 2026-11-26: the architect had it required.)
- **The client:** a ureq agent with `timeout_global` 5 s (a new `Config::intake_timeout`, which
  tests shorten as they do `cognito_timeout`), `http_status_as_error(false)`, `max_redirects(0)`.
  A `202` with `"ok":true` is the only acceptance; `whoami` is read only from a `200` whose `email`
  equals the address sent and whose `protected` is a boolean. Anything else, including a body that
  does not parse, is "not accepted", never a guess.
- **No `X-Real-IP`.** The worker needs only `email`, and bb-auth-web has no client address it can
  vouch for: one copied from a request header would put a client-chosen address into the owner's
  record, which is what the audit's "believes a header only when an operator has named it" refuses.
- **The unit is unchanged.** It has no `IPAddressDeny` (removed for Cognito, §13.22), allows
  `AF_INET`, and needs no new path: the call is an outbound loopback connection. **The spool is not
  given to it**: the spool belongs to a `DynamicUser`, whose uid is allocated at each start, so
  there is no stable owner or group to share; and writing it directly would skip the protected
  list, the cap and the confirmation, which are the owner's checks and the only ones the worker's
  input passes.

#### W3. Decision: one request per address, and the row goes before the first request (worker)

**Which addresses.** `X-Auth-Email` holds every email of the caller's row, joined by a space, and
the intake reads the whole header as one address. Sent as is, a two-address row would queue the
address `"a@x b@y"`, which no Cognito user has and no row names: a deletion that does nothing and
says it was accepted. So bb-auth-web splits the header exactly as `handle_account` already does
(`split_ascii_whitespace`, `norm_email`) and sends **one `whoami` and one `POST` per address**, in
the header's order, each with that one address as `X-Auth-Email` and as `confirm_email`. Every
address goes because the row says all of them are this person, and R4 says every Cognito user with
their address. More than ten addresses is refused before anything is sent (a constant
`DELETE_MAX_ADDRESSES = 10`, named after the worker's `MAX_PER_RUN`), since that many records would
make every run of the worker refuse until somebody intervenes.

**The order of one deletion**, each refusal ending the request with nothing changed after it:

1. what every `/account` `POST` checks: the proxy secret, the same-origin door (`csrf_ok`, strict),
   the identity, the `denied` veto (`handle_account`, before anything else);
2. the posted `uuid` equals the live row's (both empty for a stranger), and for a roster user the
   posted `rev` equals the live file's sha256 (a pre-check without the lock, so a stale page sends
   nothing);
3. the typed address (W4) equals one of the caller's addresses, and there are at most ten;
4. `whoami` for every address: any `protected: true` is the protected page (W5); any other answer
   than a usable `200`, or none in 5 s, is "not deleted" (`502`, `504`). Nothing has changed yet;
5. for a roster user: `WRITE_LOCK`, `rev` again under the lock, `open_access_file`,
   `remove_user(doc, uuid)`, `AccessWrite::prepare(..)?.commit(..)`, the lock released at the
   commit (§13.13: never held across a network call). A `409` or an I/O error ends the request
   with nothing changed and **nothing posted**;
6. `POST` for every address, stopping at the first that is not a `202`;
7. the journal lines (W7) and the outcome page (W6).

**Why the row goes first, and not after a `202`.** IT-Admin's race (W1): the worker runs `user show`
then `user rm`, and a row that disappears between the two fails the run, keeps the cursor and stops
every later deletion until the spool changes again. A row removed **before** the record exists is
the tolerated path: `show` finds nothing, the worker logs "not in the roster" and goes on, which
the contract states. Removing it after the `202` races the worker by construction, however short
our write is. The other reasons are §13.9's, unchanged: whatever the queue then does, no live key
is left waiting, and R4 says the row, keys and references go at once (the keys stop at the gate's
next reload, which `bb-auth-reload.path` sends after our write).

**What a failure after the row costs.** If the first `POST` is refused (`503` full, or anything
else) or unanswered, the row is gone and the sign-in accounts may not be queued. That is §13.9's
partial state, and it is chosen over its opposite for the same reason. The page says so and offers
"Try again", which is the same link: the person is now a stranger, and the stranger's walk (no
file write) posts again. A second record for an address already deleted is harmless (W1: no user
matches, no row). The cost to state: with the row gone, the gate sends only the address the session
signed in with, so a retry reaches that address alone, and the other addresses of a multi-address
row are left to an administrator; the partial page says so in one clause.

#### W4. Decision: one confirmation for everyone, the typed address, and no email code (worker)

**The email code goes, for every caller.** It existed to obtain the `AccessToken` `DeleteUser` asks
for; nothing needs that token now. Kept only for native sessions, it would guard half of the
callers of an operation whose effect is the same for all of them (every Cognito user with the
address, twins included), and the unguarded half would set the real bar. It also fires the
`post_authentication` Lambda, mailing the administrator a "login" for every deletion attempt, and
it is most of the old design's moving parts (the `Session`, the twin binding of §13.25, two Cognito
calls and fifteen outcomes). `native_user` is not read by the deletion at all, and the four
variants of the overnight design become two: a **roster** caller (the row and the sign-in accounts)
and a **stranger** (the sign-in accounts only).

**The proof is the session plus a typed address.** The confirmation page carries one text field,
the person's email address, which must equal one of the caller's addresses after `norm_email`; a
mismatch is a `400` with nothing sent. One press now deletes every sign-in account with that
address, at every provider, irreversibly, so the page asks for something a slip cannot produce;
and it is the intake's own `confirm_email` contract, so what goes in is the person's confirmation
and not a value bb-auth-web made up (for a multi-address row bb-auth-web supplies the others, which
the page lists). This overturns §13.29 §8's rejection of a typed word for B: that deletion removed
a row an administrator could re-add, this one cannot be undone by anybody.

**The cost, stated:** a signed-in browser left unattended can delete the account; the code would
have stopped that, for native sessions only. Typing the address does not stop it, since the bar
shows the address. Open question 1.

#### W5. Decision: the protected list is asked first, through `whoami`, and relayed (worker)

bb-auth-web cannot read either protected list, and does not need to: the intake's `whoami` answers
`protected` for one address, so step 4 of W3 asks it for every address **before** the row is
touched. A protected caller changes nothing anywhere. The page (`403`) says the account cannot be
deleted from this page, that nothing was deleted, and to ask an administrator; it never names a
list or the address that matched. A `403` from the `POST` itself (the list changed between the two
calls) is the same page when nothing was posted yet, and the partial page otherwise.

The two lists (`BBDR_PROTECTED`, `BBAD_PROTECTED`) both default to the operator's address today. If
they ever differ, the worker refuses a record the intake accepted, after our row is gone, and mails
the owner; the person's page has already said "queued". W8 §3 proposes one list.

#### W6. Decision: what the page can honestly say (worker)

No page can read the outcome: the only per-request result is the worker's private `done.jsonl` and
an SNS mail to the owner. So the page reports what bb-auth-web did and what the intake accepted,
never that a sign-in account **is** deleted. A `202` means queued.

| Where it stops | Status | What is true | What the page offers |
|---|---|---|---|
| refusals in W3 steps 1 to 3 (door, veto, `uuid`, `rev`, typed address, too many addresses) | 400 / 403 / 409 | nothing changed | start again, or back |
| `whoami`: protected | 403 | nothing changed | back |
| `whoami`: no answer, or not usable | 504 / 502 | nothing changed | try again, back |
| the write (step 5) | 409 / 500 | nothing changed, nothing posted | start again |
| every `POST` `202` (roster) | 200 | the row is gone; the sign-in accounts are queued | sign out |
| every `POST` `202` (stranger) | 200 | the sign-in accounts are queued; the file is untouched | sign out |
| the first `POST` refused (`503` or other), roster | 502 | the row is gone; nothing is queued | try again, sign out |
| the first `POST` unanswered, roster | 504 | the row is gone; maybe queued, and a retry is harmless | try again, sign out |
| the first `POST` refused or unanswered, stranger | 502 / 504 | nothing changed, or maybe queued | try again, back |
| a later `POST` refused or unanswered | 502 / 504 | the row is gone (roster); some addresses queued | try again, sign out |

The words of every row, its `h1` and its actions are §13.30 §4 and §5 (one refinement there: a
first-`POST` `403` for a roster user is the partial page, since the row is already gone).

- **The done page** says the API keys and every access an administrator gave by name are gone now
  (roster), that the sign-in accounts with the address, whichever way the person signs in, are
  queued and will be deleted by a separate process, that no message says when, and that if they
  can still sign in later they should tell an administrator. It promises no duration until 7g
  measures one.
- **The cookie.** bb-auth cannot end it (stateless sessions), and it keeps any `authenticated`
  grant until it expires, even after the Cognito user is gone. The done page's one action is Sign
  out (`Config::account_logout_url`, as the menu's), with the sentence that says why; where that
  URL is unset, the "close your browser" sentence instead, as §13.30 §4 already decided.
- **How the person learns the result:** by not being able to sign in. A status page was rejected
  (W9). W8 §4 proposes that the worker tell the person.

#### W7. The veto, strangers, administrators and the journal (worker)

- **The `denied` veto** is answered first, on the `GET` and every `POST` (`handle_account`,
  unchanged), so a vetoed identity never reaches the intake. `remove_user` rewrites a `denied` or
  `excluded` entry naming the uuid to the row's primary email, which is also what the worker's
  `user rm` would do, so the veto survives the deletion either way.
- **A stranger** reaches the same page with the row lines left out, and the access file is never
  opened for writing. The social-only stranger, who had nothing to delete overnight (variant D), now
  queues their sign-in accounts like anybody else (R4 as changed).
- **`web.admins`** is not read and not touched, as §13.29 §6 decided (it still holds).
- **The journal**, through the existing `audit()` helper, one line per effect:
  `{email} (self): user rm {uuid}` after the commit, and
  `{email} (self): delete-request {n} queued` or `... refused {status}` / `... no answer` after the
  `POST`s. No audit-file event, for §13.29 §5's reason (it still holds). The secret is never in a
  line.
- **`gate.allow_unverified_social` multiplies with this.** The worker deletes by address. With that
  setting on, a federated identity whose address nobody verified gets that address in
  `X-Auth-Email`, and could queue the deletion of every Cognito user with it, a verified native one
  included. bb-auth-web cannot tell. The example file ships it `false`; 7g reads the live value
  first, and if it is on, open question 4 decides before deletion is turned on.

#### W8. Proposals for the itadmin owner (worker)

Each is the owner's to accept; bb-auth does not depend on any of them to work, only to be safe
against a local caller.

1. **The intake believes any local caller, today.** Any process on rpi-01 can `POST` an address to
   `127.0.0.1:8480/account/delete` and queue the irreversible deletion of every Cognito user with
   it (the protected address excepted). This exists now, before step 7, since nginx no longer routes
   the path and nothing legitimate calls it. Proposal: the intake requires `X-BB-Delete-Secret` on
   both paths, compared in constant time, its value read through `LoadCredential=` (which works
   with `DynamicUser`) from a root-only file, the same value as `BB_AUTH_WEB_DELETE_SECRET`. Until
   the owner decides, stopping the intake costs nothing, since nothing uses it. A Unix socket with
   a fixed group was the alternative; it changes the intake's listener and its unit more.
2. **A backlog of more than ten stops every deletion.** With no timer and the whole run refused
   above `MAX_PER_RUN`, eleven pending records (a flood through the gap above, or retries) stop the
   worker until somebody acts. Proposal: process the first ten and leave the cursor on the rest, a
   timer to retry a failed run, and pending records deduplicated by address.
3. **One protected list.** The intake and the worker each have one; proposal: one file both read.
4. **Tell the person.** Optional: on completion the worker emails the address it deleted, which is
   the only way the person learns the result.
5. **One address per header.** The intake takes `"a@x b@y"` as one address. bb-auth-web never sends
   that (W3), but the intake could refuse a header with a space (`400`), so no caller can queue a
   deletion that does nothing.

#### W9. Alternatives rejected (worker)

- **Write the spool from bb-auth-web**: a `DynamicUser`'s directory has no stable owner to share, a
  new hole in the unit, and it skips the owner's three checks.
- **Remove the row after the `202`**: the worker's `show`/`rm` race (W1, W3).
- **Keep the email code for native sessions**: W4.
- **Send the joined header**: a no-op deletion reported as accepted (W3).
- **Route `/account/delete` from nginx straight to the intake** (as before 2026-11-24): no `rev`, no
  row first, the joined header, and bb-auth-web owns `/account/`.
- **A status page reading `done.jsonl`**: that file is the worker's, 0700, and a readable status
  is a new interface between two repositories for a page a person visits once.
- **`AdminDeleteUser` in bb-auth-web**: an AWS credential in the process that writes both files;
  the user chose (a) instead.
- **Pass `X-Real-IP`**: W2.

#### W10. Slices (worker)

They replace 7a to 7h. Each is one red-green pass; tests in `src/bin/bb-auth-web.rs` unless named.
A `FakeIntake` (7c) is a `tiny_http` server on `127.0.0.1:0` in the test module, shaped as
`FakeCognito`: it records each request's method, path, `X-Auth-Email`, `X-BB-Delete-Secret` and
`confirm_email`, answers from a script per path, can stay silent past the timeout, and can be given
the access file's path to record whether a uuid was still in it when each `POST` arrived.

- **7a. Configuration and the menu row.** `compile_delete_intake`, both variables in `from_env`,
  `Config::{delete_intake, delete_secret, intake_timeout}`, the example env file's comment; and
  `account_menu`'s delete row (§13.30 §1, unchanged) shown only when the intake is set, so the
  fields have a production reader in the same slice. Tests:
  `delete_intake_accepts_a_loopback_http_origin`,
  `delete_intake_refuses_a_non_loopback_host_a_name_https_a_path_or_userinfo`,
  `delete_intake_without_a_secret_starts_and_sends_no_secret_header`,
  `a_malformed_delete_secret_is_fatal_and_names_the_variable`,
  `the_account_menu_ends_with_delete_after_sign_out`, `the_console_menu_has_no_delete_row`,
  `no_delete_row_when_the_intake_is_unset`.
- **7b. The confirmation page.** The route, `page_account_delete` in its two variants, hidden `rev`
  and `uuid`, the typed-address field, the audit sentence (`limit_text` taking a `Lang`). Tests:
  `delete_page_for_a_roster_user_lists_what_goes_and_asks_for_the_address`,
  `delete_page_for_a_stranger_lists_only_the_sign_in_accounts`,
  `delete_page_says_how_long_the_audit_keeps_lines`, `delete_page_refuses_a_denied_identity`,
  `delete_page_never_names_the_veto`, `delete_page_changes_nothing_and_calls_nothing`,
  `delete_page_is_a_404_when_the_intake_is_unset`.
- **7c. The stranger's deletion.** `account_delete_post` without the write: steps 1 to 4 and 6 of
  W3, `intake_whoami`, `intake_delete`, the journal line, the done page; and `FakeIntake`. Tests:
  `a_strangers_deletion_posts_each_address_and_leaves_the_file_unchanged`,
  `each_request_carries_one_address_and_the_secret_never_the_joined_header`,
  `a_typed_address_that_is_not_the_callers_sends_nothing`,
  `a_protected_address_is_refused_before_anything_is_posted`,
  `whoami_with_no_answer_changes_nothing_within_the_bound`, `a_redirect_from_the_intake_is_not_followed`,
  `more_addresses_than_one_worker_run_takes_are_refused`, `a_cross_site_delete_is_refused`,
  `a_stranger_who_gained_a_row_between_steps_is_refused`,
  `the_done_page_says_queued_and_links_to_sign_out`.
- **7d. The roster row, first.** Step 5 of W3 in the same handler. Tests:
  `a_roster_deletion_removes_the_row_before_the_first_post` (the fake reports the uuid absent at
  the `POST`), `keys_scope_and_group_references_go_and_exclusions_become_the_email`,
  `a_stale_rev_is_a_409_and_posts_nothing`, `a_protected_roster_user_keeps_the_row`,
  `a_failed_write_posts_nothing` (`cfg(unix)`, the directory read-only; run under WSL).
- **7e. The partial outcomes.** Tests: `a_refused_post_after_the_row_says_partly_and_offers_the_retry`
  (`503`), `an_unanswered_post_says_maybe_and_the_retry_is_harmless`,
  `the_retry_reaches_the_stranger_path_and_posts_again`,
  `a_second_address_refused_says_some_are_queued`, `each_delete_outcome_states_its_result_in_the_h1`
  (one case per row of W6), `no_secret_reaches_a_response_or_a_log`.
- **7f. The browser suite.** `e2e/lib/intake.js` (the same fake in Node), the e2e server started
  with `BB_AUTH_WEB_DELETE_INTAKE` pointing at it, `e2e/tests/delete.js` (the menu row, the roster
  walk to the done page with the row gone, the stranger walk, protected, the `503` then Try again),
  the `nojs.js` pass, and the scenes of §13.30 §7 as amended there.
- **7g. The real run, each step with the user's go-ahead**, the first use the path has ever had:
  1. read-only: the live `gate.allow_unverified_social` (`sudo bb-auth-adm -s
     /opt/bb-auth/var/lib/settings.json settings show`) and the intake listening
     (`sudo ss -ltnp 'sport = :8480'`);
  2. the owner sets `BBAD_DRY_RUN=1` on the worker, as its README says (the owner's command);
  3. the operator adds both variables to `/opt/bb-auth/etc/bb-auth-web.env` and deploys;
  4. a test account that signs in by email code (with a federated twin if one can be made), with a
     row, a key, a scope reference and an `excluded` entry elsewhere, deletes itself in a browser.
     Expected: the row gone and an exclusion now the email (`bb-auth-adm show`), the key a `401` at
     once, one `selfdelete.jsonl` record per address, the worker's journal naming the users it
     would delete and "not in the roster", no Cognito change (IT-Admin's read-only
     `admin-get-user` still finds it), no SNS "FAILED";
  5. the owner removes the dry run; the test account, now a stranger, deletes again from the page.
     Expected: `admin-get-user` reports no user for every match, an email-code sign-in fails, and
     the time from the `202` to the deletion is measured and written into W6.

#### W11. How each decision is shown to hold (worker)

The loopback-only client: 7a's refusals and 7c's redirect test. One address per request: 7c's
request record. Row first: 7d's "uuid absent at the `POST`", and in 7g the absence of a "FAILED"
run. Protected first: 7c and 7d's protected tests (nothing posted, row kept). No code: no Cognito
action in any 7c to 7e test (`FakeCognito` not started). The honest outcome: 7e's per-row h1 test.
The worker's tolerance of a missing row and the zero-match record: only 7g.

#### W12. Questions for the user (worker)

**Answered by the user on 2026-11-26:** 1, the email code is dropped for everyone; 2, every address
of the row is queued; 3, the secret is optional for now and the intake is not stopped (W2 as
changed); 4, if 7g finds `gate.allow_unverified_social` on, it is turned off, with the user's
go-ahead, before deletion is turned on. 5 and 6 stay open.

1. **No email code (W4).** Recommended: drop it for everyone, the typed address as the confirmation.
   Or keep it in front of native sessions only, at the cost W4 states?
2. **Every address of the row (W3).** Accept that a multi-address row queues every address, or
   send only the one the person types?
3. **The delete secret (W2, W8 §1).** Require it in bb-auth-web now, before the owner enforces it?
   And should the operator stop the intake until then?
4. **`gate.allow_unverified_social` (W7)**, if 7g finds it on: turn it off, or not ship deletion?
5. **`web.admins`** (§13.29 §6, unchanged): accept that a deleted administrator stays listed.
6. **7g:** which test account, and the go-ahead for each step, the dry run first.

#### The direct DeleteUser design (Superseded by §13.29 W1 to W12, 2026-11-26)

The overnight design, kept as the record of why the code step, the twin binding and the four
variants existed. Each part below says where it still holds.

R4, rebuilt on what §13.25 changed. §13.7 and §13.9 were written before the deletion could act on
the session's own Cognito user, and both carry "(Changed by §13.29 ...)" where they are now wrong.
Every decision below was taken by the architect overnight on the user's delegation, and each says
why, so the user can overturn any of them in the morning.

What was read to write it: `AGENTS.md` (the invariants, above all "What lives where", the audit's
four, the veto, `excluded` and API-key ones, and the self-service paragraph that says `web.admins`
is never read there), `PLAN.md` step 5 (the real pool, read 2026-11-25) and step 7, §13.7, §13.9,
§13.13, §13.22 to §13.25, §13.28 §5 and §7; `src/bin/bb-auth-web.rs`: `handle_account`,
`account_uuid_of`, `account_own`, `native_user`, `cognito_post`, `cognito_call`,
`cognito_answer`, `cognito_update`, `id_token_username`, `account_profile_post`,
`account_profile_code_post`, `account_key_post` (its `WRITE_LOCK`, `rev` and journal line),
`page_account_confirm`, `confirm_card`, `page_profile_code`, `account_menu`, the console's
`audit()` journal helper and `limit_text`, and the tests' `FakeCognito`, `email_otp`,
`signed_in`, `PROFILE_HEADERS`; `src/lib.rs`: `remove_user`, `user_refs`, `AccessWrite`,
`AuditPolicy`; `e2e/lib/cognito.js`.

##### 1. Cognito facts this rests on (Superseded by §13.29 W1: a deletion makes no Cognito call)

**Read in a source (AWS API reference and developer guide, read 2026-11-26):**

- `DeleteUser` "deletes the profile of the currently signed-in user", which "can no longer be used
  to sign in and can't be restored". It is authorized by the user's own access token, which "must
  include the scope `aws.cognito.signin.user.admin`"; IAM is not evaluated. The request is
  `{"AccessToken": ...}`; success is HTTP 200 with an empty body; the documented errors include
  `NotAuthorizedException`, `UserNotFoundException`, `TooManyRequestsException`,
  `InternalErrorException` (500) and `ForbiddenException` (a WAF web ACL)
  ([DeleteUser](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUser.html)).
- "A token from Amazon Cognito API sign-in only contains the scope
  `aws.cognito.signin.user.admin`" (the `scope` claim of
  [the access token](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html)).
  So the `AccessToken` the email-code sign-in of §13.22 already obtains is the token `DeleteUser`
  asks for, with no OAuth scope to configure on the app client.
- `InitiateAuth` with `USER_AUTH` takes `USERNAME` (required) and `PREFERRED_CHALLENGE`; its
  `EMAIL_OTP` answer carries `ChallengeParameters` `CODE_DELIVERY_DELIVERY_MEDIUM` and
  `CODE_DELIVERY_DESTINATION` and a `Session` of 20 to 4096 characters; "You can't sign in a user
  with a federated IdP with `InitiateAuth`"; IAM is not evaluated
  ([InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html)).
- `RespondToAuthChallenge` answers `EMAIL_OTP` with `EMAIL_OTP_CODE` and `USERNAME`, returns an
  `AuthenticationResult` with `AccessToken`, `IdToken` and `RefreshToken`, and lists
  `CodeMismatchException`, `ExpiredCodeException` and `NotAuthorizedException`; IAM is not
  evaluated
  ([RespondToAuthChallenge](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html)).

**Measured (PLAN.md step 5, the IT-Admin session's read-only reads of 2026-11-25):** the native
client `gate.client_id` allows `ALLOW_USER_AUTH`, `AuthSessionValidity` 3 minutes, no secret; the
social client allows only `ALLOW_REFRESH_TOKEN_AUTH`; `DeletionProtection` is inactive (that
setting protects the **pool**, not a user, and does not bear on `DeleteUser`).

**Unverified, to be settled by the real run (7h):** that no pre-token-generation Lambda or WAF web
ACL on the real pool strips the scope or refuses `DeleteUser` (none is in the reads above, but
nobody looked for one with this question); that the documentation names no app-client setting
that gates `DeleteUser` and none was found, which is an absence, not a statement; that a
`UserNotFoundException` from `DeleteUser` is what a second call for an already deleted user
returns (the error is documented, the circumstance is not).

##### 2. Decision: the four callers (Superseded by §13.29 W4: two callers, roster and stranger, and no code)

Who the caller is decides what is deleted, and it is decided **per request from the live
request and the live file**, never from a form field: the row is `account_uuid_of` over
`X-Auth-Email` (as every `/account` request already computes it), and "native" is
`native_user(&req)` (§13.25's header). The `denied` veto is answered first, by `handle_account`,
on the `GET` and on every `POST` alike, before any of this, so a vetoed identity never sees the
page and is never lifted (R4, §13.9).

| Caller | Row | Header | What is deleted | Proof asked |
|---|---|---|---|---|
| A. roster, native | yes | yes | the row (`remove_user`), then the Cognito user (`DeleteUser`) | the email code |
| B. roster, social-only (or a cookie from before §13.25) | yes | no | the row only | the confirmation page's `POST` |
| C. stranger, native | no | yes | the Cognito user only; the access file is not written | the email code |
| D. stranger, social-only | no | no | nothing | none: no form |

What each page says (the wording is the designer's; these are the facts each page must carry;
changed by §13.30 §2: the places are not listed, the record's line says "every access an
administrator gave you by name" instead, because for B an `authenticated` scope stays reachable
through the provider sign-in that remains):

- **A.** What goes: the API keys (their count), the groups and the places the page already lists
  (`account_own`), and the sign-in account. That the audit keeps their lines until
  `audit.retention` drops them, or until the files' size bound does when there is no retention
  (the facts `limit_text` and `size_text` already phrase on the Audit tab). That a Google or
  Microsoft sign-in under the same address is a **separate** account this page cannot delete
  (R5's fact: the pool holds unlinked native and federated users with one email). One button,
  which asks for the code.
- **B.** The same list, minus the sign-in account, and why: this session signed in through a
  provider (or before the current release), nothing here can prove it is them to the sign-in
  service, and an administrator must delete that account. Also, because bb-auth-web cannot tell a
  federated session from an old native cookie (§13.25 "Old cookies fail closed"): a person who
  signs in with an email code should sign out and in again first, so their sign-in account goes
  too. One button, which deletes the row.
- **C.** That bb-auth holds no record of them, so only the sign-in account goes, and the audit
  sentence. One button, which asks for the code.
- **D.** That there is nothing here to delete: bb-auth keeps no record of them, and their sign-in
  account is held through their provider and only an administrator can delete it. No form, a
  `200`, and the way back to the page.

**Why B deletes on one `POST` with no re-authentication.** R4 accepted the access-file half for a
social-only person on 2026-11-23, and nothing can re-authenticate them (§13.7: `InitiateAuth`
cannot sign a federated user in, and the social client runs no flow this process can drive). The
row-only deletion is the same authority the page already grants on one confirmed `POST`: revoking
every key one by one is already possible that way (§13.15), and the scope and group references go
with the row by construction. It writes nothing Cognito holds, and an administrator can re-add a
row; the keys alone are unrecoverable, and they are exactly what a person deleting their account
wants gone. Rejected: refusing B outright (R4 says otherwise); sending B a code by email
(`USERNAME` would have to be an address, which is the §13.25 bug: it reaches a native twin, or
nobody).

**Why the kind is carried and compared.** Every form carries a hidden `kind` (`code` for A and C,
`row` for B), and every `POST` refuses a `kind` that differs from the kind this request computes,
with no write and no call (a `409`-class "the page changed, start again"). Without it, a person who
clicked "Send code" under a native session and whose next request arrived without the header
(another tab signed in through a provider) would have their row deleted without the code they were
promised. The field chooses nothing: it is compared, never obeyed.

**Why D has no form, and the social-only Cognito user is never deleted here.** Nothing proves to the
pool that the caller holds that account, and the only call that could delete it without the user's
own token (`AdminDeleteUser`) evaluates IAM, which §13.7 refused for this process. R4's accepted
answer is the sentence.

##### 3. Decision: the binding (Superseded by §13.29 W2 and W3)

Routes, all under the account prefix, beside the key routes:

- `GET {account}/delete`: the confirmation page of §2. Changes nothing, calls nothing. Carries, as
  hidden fields, `rev` (the file's sha256 as rendered, as every form does), `uuid` (the caller's
  row, empty for a stranger) and `kind`.
- `POST {account}/delete`: for B, the deletion; for A and C, the start: `cognito_call(cfg,
  settings, native)`, unchanged from §13.25, so `USERNAME` is the header's value, a
  `ChallengeParameters.USERNAME` that names anybody else is the existing `403`, and the code page
  names `CODE_DELIVERY_DESTINATION`. The code page carries `Session`, `rev`, `uuid` and `kind`.
- `POST {account}/delete/code`: the code step, A and C only.

The code step, in order, every refusal writing nothing and calling nothing after it:

1. the same-origin door (`csrf_ok`, the console's strict policy);
2. what `handle_account` re-checks for every request against the live files: the proxy secret, the
   identity, the veto, the row resolution;
3. the header is present (else the profile's "not native" refusal, no call; changed by §13.30 §4:
   the status stays `400` but the words are the deletion's "your sign-in changed" page, since the
   profile's sentence talks about editing a profile), and the posted `kind`
   equals the computed one;
4. the posted `uuid` equals the live row's uuid (both empty for a stranger). A stranger who gained
   a row between the steps, a row whose uuid changed, and a row removed by an administrator are all
   refused here: the person confirmed a deletion of something else;
5. for A only, the posted `rev` equals the live file's sha256 (a cheap pre-check, without the lock,
   so a stale form never spends a code);
6. `cognito_answer(cfg, settings, session, native, code)`, `USERNAME` = the header's value **on
   this request**, never a field (§13.25 step 3);
7. `id_token_username(IdToken, settings) == native`, or the existing `403` "a token for another
   account", the `AccessToken` dropped unused. This is the regression the rpi-01 twin taught
   (`the_rpi01_twin_is_never_written`), and it guards a call that cannot be undone;
8. for A: `WRITE_LOCK`, `rev` again against the bytes under the lock, `open_access_file`,
   `remove_user(doc, uuid)`, `AccessWrite::prepare(..)?.commit(..)`, the lock released at the
   commit as §13.13 requires (never held across a Cognito call). A `409` or an I/O error here ends
   the request: nothing in the file changed, and `DeleteUser` is **not** called;
9. `cognito_delete(cfg, settings, access_token)`, a new function shaped as `cognito_update`
   (`DeleteUser`, the same `cognito_post`, the same 5 s bound, no retry), and the tokens dropped at
   the end of the request: none reaches a page, a header, a log line or a file.

At most two Cognito calls in the code request (`RespondToAuthChallenge`, `DeleteUser`), which is
§13.13's bound. The `rev` is not checked for C, because C writes no file and a stranger's form
should not fail on an unrelated edit; step 4 is what pins C to "still a stranger".

##### 4. Decision: partial failure, and the retry (Changed by §13.29 W3 and W6: the row still goes first and the retry is still the stranger's walk, but the second half is a queued request)

The order is §13.9's and its reason stands: the row first, because a failed `DeleteUser` then
leaves a Cognito user with no row (a stranger who reaches only `authenticated` scopes and holds no
key), while the other order on a failed write leaves a row with live keys waiting for the same
person to re-register.

| Where it stops | Status | What is true | What the page offers |
|---|---|---|---|
| any refusal in steps 1 to 7 | 400 / 403 / 409 | nothing changed | start again (`{account}/delete`) |
| the write (step 8) | 409 / 500 | nothing changed, no `DeleteUser` | start again |
| `DeleteUser` refused | 502 | the row is gone, the sign-in account is not | the retry |
| `DeleteUser` no answer | 504 | the row is gone, the sign-in account may or may not be | the retry |
| `DeleteUser` ok, or `UserNotFoundException` | 200 | both gone | sign out |

**The retry is the C path, reached by the same link.** After the row went, the same session is a
stranger with the header still present (the cookie still carries `native_username`), so
`GET {account}/delete` now renders C's page, and C's code walk deletes the Cognito user. No new
route, no stored state. A retry after a deletion that did happen (the `504` case) gets
`UserNotFoundException` from `InitiateAuth`, and C's start answers with a deletion-specific
sentence ("there is no sign-in account left to delete for this session; sign out") instead of the
profile's. `UserNotFoundException` from `DeleteUser` itself counts as done: the goal is that the
user does not exist.

**The final page** links to `Config::account_logout_url`, the same link the menu's Sign out
carries, because the cookie is stateless and stays valid until it expires (the "Sessions are
stateless" invariant forbids a revocation list): for A and B it now names a stranger, for C a
Cognito user that no longer exists. Where that URL is unset the menu has no Sign out either, and
the page says to close the browser instead of linking nowhere.

##### 5. Decision: what is recorded, and where (still holds; the Cognito line becomes the delete-request line of §13.29 W7)

**No audit-file event.** The audit file is the gate's, and records authentication (sign-ins,
sign-outs, refusals); `bb-auth-web` writes none, and no edit of the access file by either editor
is in it today. A self-deletion is an edit of the access file plus a Cognito call, not an
authentication, so it has no place there. **One journal line per effect**, through the console's
existing `audit()` helper, as `account_key_post` already logs a self-service key write:
`{email} (self): user rm {uuid}` after the commit, and `{email} (self): cognito delete-user
{ok|refused|no answer}` after the call, never the Cognito username (`native_user`'s doc: it is a
personal identifier read only by the request that carries it). This is not a breach of "an event
has exactly one home": that invariant divides the gate's request-path events between its audit
file and the journal, and a GUI mutation line has only ever had the journal as its home. Nothing is
recorded twice.

The audit file is **not edited** (R4): the confirmation page says how long their lines last.

##### 6. What `remove_user` does (built in step 6) (still holds)

One call, `remove_user(doc, uuid)` in `src/lib.rs`, the same one `bb-auth-adm user rm` and the
console use:

- the row goes, and with it every key it owned (keys live on the row, `UserSpec::api_keys`), so
  every `bbk_` bearer of theirs stops at the gate's next reload (`bb-auth-reload.path`);
- every scope's `users` list loses the uuid, and every `user_groups` entry loses it;
- every scope's `excluded` entry naming the uuid is **rewritten** to the row's primary email, once,
  in place (not swept: dropping a veto lifts it, and the same person re-registering would walk back
  in);
- every `denied` entry naming the uuid is rewritten to that email the same way, so the veto
  survives the person who is vetoed (and such a person never reaches this far: §2);
- a row with no email has no stranger spelling, so its exclusions are dropped as before.

The swept list `user_refs` returns is not shown on the done page: the page already listed what
goes before the person confirmed, and the console's removal says nothing about exclusions either.

**`web.admins` is not touched and not mentioned.** The self-service page never reads it (AGENTS.md:
an administrator here is one more person acting on their own account), so it cannot say "you are an
administrator", and writing the settings file from here would also risk the refused empty list.
An administrator who deletes their account stays named there by email until another administrator
removes them. Question 2 below.

##### 7. The pool and OpenTofu (Superseded by §13.29 W2: no self-service `DeleteUser`; the worker deletes with the owner's credential)

**Nothing in the app client needs to change, as far as the sources say**: the access token from the
API sign-in carries the one scope `DeleteUser` requires, the native client already allows
`ALLOW_USER_AUTH`, and `DeleteUser` is not an OAuth flow. **This is a question for the user and the
IT-Admin session, not an assumption to build on**: whether anything in itadmin's
`infra/tofu/stacks/aws/production/cognito.tf` (a Lambda trigger, a WAF association, a client
setting this design does not know) would stop or should accompany a self-service `DeleteUser`, and
whether the estate wants self-deletion of Cognito users at all (it is irreversible by the source
above). No change is proposed to that repository.

##### 8. Alternatives rejected (Changed by §13.29 W9; the typed confirmation is taken up in W4)

- **The email as `USERNAME`** (§13.7 as written): the §13.25 bug, on an irreversible call.
- **Delete the Cognito user first**: §13.9's reason, a failed write would leave live keys behind.
- **Hold `WRITE_LOCK` across `DeleteUser`**: §13.13, a slow Cognito would block every writer.
- **A server-side record of a half-done deletion to resume from**: state for a case the C path
  already covers with none.
- **`AdminDeleteUser` for social-only users**: IAM credentials in the process that writes both
  files (§13.7).
- **An audit-file event written by `bb-auth-web`**: a second writer of a file whose single writer
  is part of its guarantee ("an audit an administrator can edit is not an audit"), and not an
  authentication.
- **A typed confirmation word for B**: the confirmation page is the WCAG 3.3.4 step (§13.28 §5),
  and the key revoke already rests on the same.
- **The menu row hidden for D**: the page explains better than an absent row, and showing the row
  to everyone keeps the menu one shape.

##### 9. Slices (Superseded by §13.29 W10)

Each is one red-green pass over a few functions; tests in `src/bin/bb-auth-web.rs` with
`FakeCognito` unless named otherwise, and "no call" means `fake.actions()` is empty.

- **7a. The confirmation page.** `handle_account`'s route list gains `{account}/delete`; a
  `DeleteKind` (`Code`, `Row`, `Nothing`) computed from `native_user` and the uuid;
  `page_account_delete` (four variants, the hidden `rev`/`uuid`/`kind`, the audit sentence, which
  needs `limit_text` to take a `Lang` instead of a console `View`). Tests:
  `delete_page_for_a_native_roster_user_lists_what_goes_and_asks_for_a_code`,
  `delete_page_for_a_social_roster_user_deletes_the_row_and_names_the_administrator`,
  `delete_page_for_a_native_stranger_says_the_file_is_untouched`,
  `delete_page_for_a_social_stranger_has_no_form`,
  `delete_page_says_how_long_the_audit_keeps_lines` (a retention, and none),
  `delete_page_refuses_a_denied_identity`, `delete_page_changes_nothing_and_calls_nothing`.
- **7b. The menu row (§13.28 §5).** `account_menu` gains `delete: Option<&str>`;
  `account_shell` passes `{account}/delete`, the console passes `None`; `K::AccountDelete`.
  Tests: `the_account_menu_ends_with_delete_after_sign_out` (last row, behind the rule, an `a.pill.rm`,
  a `GET` link), `the_console_menu_has_no_delete_row`, and the Italian string.
- **7c. B: the row-only deletion.** `account_delete_post` for `kind=row`: door, kind, uuid,
  `WRITE_LOCK`, `rev`, `remove_user`, `AccessWrite`, the journal line, the done page. Tests:
  `a_social_roster_deletion_removes_the_row_and_calls_no_cognito` (keys, scope and group
  references gone, an exclusion and a `denied` entry now the email, no call),
  `a_stale_rev_is_a_409_and_writes_nothing`, `a_cross_site_delete_is_refused`,
  `a_kind_that_no_longer_matches_is_refused`, `a_changed_uuid_is_refused`,
  `the_done_page_links_to_sign_out`.
- **7d. A and C: the start.** `account_delete_post` for `kind=code`: `cognito_call` on the header,
  `page_delete_code` (the masked destination, the code field, the hidden fields). Tests:
  `the_delete_code_is_asked_for_the_sessions_own_username`,
  `a_delete_challenge_for_another_username_is_refused`,
  `kind_code_with_no_header_is_refused_with_no_call`, `the_delete_start_writes_nothing`,
  `a_stranger_with_a_header_is_offered_the_code`,
  `a_retry_after_the_user_is_gone_says_there_is_nothing_left` (`InitiateAuth`
  `UserNotFoundException`).
- **7e. A: the code step.** `account_delete_code_post` (steps 1 to 9 of §3) and `cognito_delete`.
  Tests: `the_whole_deletion_drops_the_row_then_deletes_the_user` (actions
  `[RespondToAuthChallenge, DeleteUser]`, the `AccessToken` the fake issued, the row gone),
  `the_delete_twin_is_never_deleted` (same email, other `cognito:username`: `403`, file unchanged,
  no `DeleteUser`), `a_wrong_delete_code_writes_nothing`, `a_stale_rev_spends_no_code` (no call),
  `a_failed_write_never_calls_delete_user` (`cfg(unix)`, the file's directory read-only: actions
  `[RespondToAuthChallenge]` only, row still there; run under WSL),
  `a_failed_delete_user_leaves_the_row_gone_and_offers_the_retry` (`502`),
  `delete_user_with_no_answer_says_unsure_and_offers_the_retry` (status 0, `504`, within the bound),
  `no_token_reaches_the_delete_response`, `a_header_changed_between_steps_deletes_nothing`.
- **7f. C: the stranger's code step.** The same handler with no row: no `rev`, no write. Tests:
  `a_strangers_deletion_leaves_the_files_bytes_unchanged`,
  `a_stranger_who_gained_a_row_between_steps_is_refused`,
  `the_retry_reaches_the_stranger_path_and_finishes` (a `502` at 7e, then the C walk on the same
  headers deletes the user), `delete_user_not_found_counts_as_done`.
- **7g. The browser suite.** `e2e/lib/cognito.js`'s `defaultReply` answers `DeleteUser` with
  `200 {}` (today it is `UnknownOperationException`); a walk per kind in a new
  `e2e/tests/delete.js` (A to the done page, B with zero Cognito calls, the `502` then the retry,
  D with no form), the `nojs.js` pass over them, and scenes (changed by §13.30 §7: the full list
  is there) `account-delete`, `-row`, `-stranger`,
  `-nothing`, `-code`, `-done`, `-partial` in `shots.js` for the designer's review.
- **7h. Real, with the user's go-ahead**: a test account on rpi-01 that signs in by email code,
  with a row, a key and a scope reference; deleted in a browser; then `bb-auth-adm show` no longer
  names it except as an email in any `excluded`/`denied` entry, its key gets a `401`, and its
  sign-in by email code fails (the IT-Admin session can confirm with a read-only `admin-get-user`).

##### 10. How each decision is shown to hold (Superseded by §13.29 W11)

The binding: 7d's username test, 7e's twin test, `the_code_step_uses_the_header_not_a_form_field`
carried over as `a_header_changed_between_steps_deletes_nothing`. The order: 7e's actions list and
the `cfg(unix)` write failure. The kinds: 7a's four pages, 7c's zero calls, 7f's unchanged bytes.
The veto: 7a's refusal (and `handle_account`'s existing test). The partial failure: 7e's `502` and
`504` and 7f's retry. No tokens out: 7e. The pool facts: only 7h.

##### 11. Questions for the user and the IT-Admin session (Superseded by §13.29 W8 and W12; question 2 is W12 question 5)

1. **itadmin's OpenTofu** (§7): anything in `cognito.tf` that would stop a self-service
   `DeleteUser`, or that should change with it? Is irreversible self-deletion of Cognito users
   wanted on this pool?
2. **`web.admins`** (§6): an administrator who deletes their account stays in the list by email.
   Accept that (recommended: the self-service page must not read the list), or should the console
   flag admins with no row?
3. **B's single `POST`** (§2): accept that a social-only person's row is deleted on a confirmed
   `POST` with no re-authentication, as their keys already can be?
4. **The real run (7h)**: which test account, and the go-ahead for an irreversible deletion on the
   real pool.

### 13.30 Delete my account, as a person sees it (plan step 7, slices 7a to 7g, designed 2026-11-26; reworded the same day for the owner's worker)

The interface of §13.29: the menu row, the confirmation page in its two variants and every
outcome, with every word in English and Italian. §13.29 decides what is called, checked and
written; this section decides what a person sees and does. Where it changes §13.29 or §13.28 §5
the change is marked there. Decided on the user's delegation; each decision says why.

What was looked at, overnight: §13.9, §13.23, §13.26 §3 to §5, §13.28 §2, §3 and §5, §13.29
whole; `account_menu`, `account_shell`, `confirm_card`, `form_shell_at`, `page_account_confirm`,
`page_profile_code`, `page_profile_saved`, `page_profile_outcome`, `limit_text`, `size_text`,
the account page's `409` and the `K` keys `Account*`, `AccountProfile*`, `Conflict*`, `Unit*`,
`SignOut`, `Cancel`, `Back` in `src/bin/bb-auth-web.rs`; `.pill.rm`, `button.danger`, `.panel.bad`,
`.menu .pill`, `.menu svg`, `ul.plain` in `src/assets/{base,admin}.css`; the built menu,
`node e2e/shots.js account-menu` (light, dark, phone, it). For the rewording on 2026-11-26:
§13.29 W1 to W12, `PLAN.md` step 7, `text_field_with` and `FieldOpts`, `form_shell_at`'s
`div.err`, `fill`, and `input.f-email`'s width rule in `admin.css`.

Mockups: `/tmp/d7w/mock.js` writes each page below into a `main` over the real `theme.css`,
`base.css` and `admin.css`, inlined, with no header bar (the e2e server's Edge would not launch that
day, so the overnight shell could not be reused); shots in
`/tmp/d7w/<page>-{light,dark}-{1280,360}.png` and `-light-320.png` for `delete` (roster, two
addresses), `delete-stranger`, `delete-typed-wrong`, `delete-protected`, `delete-queued`,
`delete-partial`, `delete-unsure`, `delete-some`, `delete-changed`. The menu row's shots are the
overnight ones, `/tmp/d7/menu-{light,dark}-{1280,360}.png`, `menu-light-320.png`,
`menu-focus-{light,dark}-1280.png` (the row did not change).

Measured: no page of either set of mockups scrolls sideways at 1280, 360 or 320 (`scrollWidth`;
Edge overnight, Chromium's headless shell for the rewording); the menu's Sign out and Delete rows are 36px tall at 1280 and 30px at 360 and 320, above WCAG 2.5.8's
24px, and their glyphs share one left edge. Read in a source: each WCAG fact, cited where used.
Assumed: nothing about the worker; its facts are §13.29 W1's, as relayed there.

(Changed by §13.29 W4 and W6, 2026-11-26, and reworded here the same day. **Still holds from the
overnight design:** §1, the menu row, whole; the page's shape, `confirm_card`, the `h1`, no
`autofocus`, the audit sentence, the record, keys and groups lines, the places and the uuid not
listed, the veto never named; §4's principles. **Gone:** the four variants (now two, roster and
stranger), §3's code page, every string that said a sign-in account **is** deleted, and every
string that said a provider account survives.)

**No new CSS.** Every element below is an existing component: `a.pill.rm`, `div.sep`, `p.lede`,
`div.panel.bad` with `form.edit` (through `confirm_card`), `div.err`, `p.lbl`, `ul.plain`,
`p.muted`, the one text field (`text_field_with`, its `span.hint`, its `.invalid` pair) sized by
the existing `input.f-email` rule, `button.danger`, `p.primary > a.pill`. The one new piece of
markup is a trash glyph's three paths in the menu row, sized and stroked by the existing
`.menu svg` rule.

#### 1. The menu row (§13.28 §5, as built in H) (delete design)

- **Where.** The last child of `div.menu` on `/account/` only, and only when
  `BB_AUTH_WEB_DELETE_INTAKE` is set (§13.29 W2): `div.sep`, then
  `a.pill.rm href="{account}/delete"`. After Sign out's own rule, so the panel reads: who, then
  Preferences, rule, Sign out, rule, Delete. Where `account_logout_url` is unset there is no Sign
  out, and the row follows Preferences behind its own `div.sep`. The console's panel has no row
  (§13.28 §5, unchanged).
- **Look, both themes.** `nav .pill` gives it the quiet muted text of the rows above;
  `.pill.rm:hover` (specificity 0,3,0 beats `nav .pill:hover`'s 0,2,1) turns text and border
  `--error` on hover; keyboard focus shows the estate's one accent ring (`:focus-visible`), as on
  every row. Seen in `/tmp/d7/menu-light-1280.png` and `menu-dark-360.png`.
- **A glyph, changed from §13.28 §5.** H built every row with a glyph and a `.5em` margin, so the
  words form a column; a row without one starts its word about 22px left of "Sign out". The glyph
  is a trash can (`M3 6h18`, `M8 6V4h8v2`, `M6 6l1 14h10l1-14`), `aria-hidden`, beside the visible
  word `K::AccountDelete`, which is the accessible name. Not the keys table's `×`: at the bottom of
  a panel an `×` reads as "close this panel".
- **The words stay "Delete account and all its data"** (§13.28's key). Since the worker design
  they are true for every caller: a roster user loses the record and every sign-in account, a
  stranger every sign-in account, which is all bb-auth and the pool hold for them.

#### 2. The confirmation page, two variants (delete design)

`GET {account}/delete`, `account_shell` with the `h1` `K::AccountDeleteTitle` ("Delete your
account"), so the heading echoes the row that was clicked (Nielsen 4). Both variants are
`confirm_card`: the `p.lede` `K::AccountDeleteLead` (its `why`), then `div.panel.bad` holding the
facts (its `what`) and the `form.edit` posting to `{account}/delete` with hidden `rev` and `uuid`
(both empty for a stranger), the typed-address field, the `button.danger`
`K::AccountDeleteConfirm` and the `K::Cancel` pill back to the account page. **No `autofocus`**,
not even on the field: Enter must not be one keystroke from a deletion, and an empty `required`
field stops a stray Enter in the browser anyway. The page changes nothing and calls nothing,
not even `whoami` (§13.29 W3 asks it on the `POST`).

The facts inside the panel, in this order, each present only where it applies:

1. `p.lbl` `K::AccountDeleteGoes` ("What is deleted"), then one `ul.plain`:
   - `K::AccountDeleteRecord` (roster);
   - `K::AccountDeleteKeysLead` + `" "` + each key's id in `code`, joined by `", "` (roster, only
     with one key or more);
   - `K::AccountDeleteGroupsLead` + `" "` + each group's name in `code`, joined by `", "` (roster,
     only with one group or more);
   - `K::AccountDeleteSignInOne` (one address) or `K::AccountDeleteSignInMany` (two or more) +
     `" "` + each address in `code`, joined by `", "`, in the header's order (both variants, last,
     because it is the one item that does not go at once).
2. `p.muted` `K::AccountDeleteLater`: the sign-in accounts are queued, not deleted on the press.
   A sentence after the list rather than a second `p.lbl` ("Deleted later"), for the reason the
   overnight mockup found: `ul.plain` has no margin, and a second label sits against the last item.
3. Stranger only: **nothing**. (Changed by the user, 2026-11-26: the page's existing
   `K::AccountNoRow` sentence is not written here, and no line stands in its place. Plan step 13,
   the same day, took that sentence out of the account page as well and deleted the key, so the
   sentence this bullet declined to write exists nowhere now.) A person who
   came to delete is being told what goes, and a line about what is not there is not a fact about
   the deletion, so the stranger's list is the sign-in accounts and the page stops there.
4. `p.muted`, the audit: with a retention, `K::AccountDeleteAuditKept` + `" "` +
   `limit_text(lang, retention)` + `K::AccountDeleteAuditTail` ("... is kept for 6 months, then
   dropped."); with none, `K::AccountDeleteAuditSize` + `" "` + `size_text(max_bytes)` + `"."`
   ("... keeps at most 8 MiB."). `limit_text` takes a `Lang` (§13.29 W10 7b) so the unit is
   Italian on an Italian page.
5. Inside the form, before the actions: the field, `text_field_with(K::AccountDeleteTypeLabel,
   "confirm_email", value, "", hints, invalid, FieldOpts { required: true, inputmode:
   Some("email"), class: Some("f-email"), .. })`, with the hint
   `K::AccountDeleteTypeHintMany` only when the row has two addresses or more. Empty on a `GET`,
   and no `autocomplete` (the trade below).

**The addresses are listed** because they are what the press acts on (every one of them is queued,
§13.29 W3 and W12 answer 2), and because the field asks for one of them: the person reads the
address they are asked to type (recognition over recall, Nielsen 6). Typing a shown value is no
proof of anything, and §13.29 W4 does not ask it to be one: it guards against a slip, not an
attacker.

**No `autocomplete`, and the trade.** WCAG 1.3.5 asks that a field collecting information
about the user name its purpose, and the person's own email is one of the listed purposes
(<https://www.w3.org/WAI/WCAG22/Understanding/identify-input-purpose.html>); the same token lets a
browser offer the address, which keeps a person who cannot type easily from typing it. That
weakens the slip guard by one deliberate pick from a list, which is still not a slip. WCAG 3.3.7
would not require it (re-entry "required to ensure the security of the content" is an exception,
<https://www.w3.org/WAI/WCAG22/Understanding/redundant-entry.html>), so this is a choice for 1.3.5
and for the person, not an obligation. (Changed by the user, 2026-11-26: the field carries **no**
`autocomplete`, and the browser offers nothing.) The design asked for the token so the field stayed
usable; the answer is that this confirmation is the person's own act, and a value picked from a
browser's list is not that act. The cost is named: someone who cannot type their own address
cannot confirm, and Cancel is the way back. A `text` field with `inputmode="email"` and not
`type="email"`: the browser's own refusal would be in the browser's language and wording, and the
server already normalises (`norm_email`) and answers in the page's.

**The typed address refused** (`400`, §13.29 W3 step 3): the same page, with `div.err#form-error`
`K::AccountDeleteTypedWrong` at the top of the form (`form_shell_at`'s place for it), the field
**keeping what was typed** with `.invalid`, `aria-invalid="true"` and
`aria-describedby="form-error"`, so a typo is seen and fixed rather than retyped (forgiving input,
WCAG 3.3.1 and 3.3.3). No `autofocus` on this one either.

**More than ten addresses** (§13.29 W3 `DELETE_MAX_ADDRESSES`): the `GET` renders the `h1`, the
`p.lede` `K::AccountDeleteTooMany` and `p.primary` with `back_link`, and no panel and no form,
`200`; a `POST` that gets that far anyway is the outcome row of §4. Prevention before the message
(Nielsen 5): a form whose every submission would be refused is not offered.

**The places are not listed.** "Every access an administrator gave you by name" covers what the
record grants, and the sign-in line takes every `authenticated` place with it once the worker has
run; "Where you reach" under "What is deleted" would add names without adding a fact. The uuid is
not shown either: a person does not know it, and the record line says what it means.

**The veto is never named.** A vetoed identity never reaches the page (§13.29 W7); `remove_user`
keeps `denied` and `excluded` entries as the email, and the page says nothing about them, to
anyone.

| Variant | `p.lede` | Facts | Field | Button |
|---|---|---|---|---|
| roster | `AccountDeleteLead` | Record, keys, groups, SignInOne/Many; Later; audit | `TypeLabel`, `TypeHintMany` with two addresses or more | `AccountDeleteConfirm`, `danger` |
| stranger | `AccountDeleteLead` | SignInOne; Later; audit | `TypeLabel` | `AccountDeleteConfirm`, `danger` |
| more than ten addresses | `AccountDeleteTooMany` | none, no panel, no form | none | `p.primary` back link |

**One red press, and it deletes.** There is one step now, so the brief's "danger" falls on the
press that acts, and the panel is `.panel.bad` so the subject reads as destructive before it.

**The irreversibility statement is the lede's first sentence**, "This cannot be undone", the same
words as the key revoke's warning (`AccountKeyRemoveWarn`), followed by what stands between the
person and the deletion (the typed address and the button by name). The page is the review and the
typed address the confirmation of WCAG 3.3.4's "Confirmed" for a submission that deletes user data
(<https://www.w3.org/WAI/WCAG22/Understanding/error-prevention-legal-financial-data.html>).

#### 3. The code page (delete design) (Superseded by §13.29 W4, 2026-11-26: no code for anyone)

Removed. The `AccountProfile*` code keys stay in the profile's flow and are not used here.

#### 4. Every outcome (delete design)

One shape, the profile's (§13.23 §4): `account_shell`, an `h1` that states the result, one
`p.lede`, one row of actions. "Sign out" is `pill_link(account_logout_url, K::SignOut)`; where
that URL is unset there is no pill and the lede's last sentence is `K::AccountDeletedClose`
instead of `K::AccountDeletedSignOut` (written "SignOut/Close" below). "Try again" and "Start
again" are `pill_link({account}/delete, K::AccountDeleteRetry)` and `pill_link({account}/delete,
K::AccountDeleteStartAgain)`: both render the confirmation page, which after a roster write is the
stranger's variant (§13.29 W3). "Back" is `back_link` to the account page. "+" joins sentences
with one space. "Multi" means the row had two addresses or more.

| Case (§13.29 W6) | Status | `h1` | `p.lede` | Actions |
|---|---|---|---|---|
| cross-site `POST`, `denied` veto | 403 | the existing door's and veto's answers, unchanged | | |
| `uuid` or `rev` differs (before the lock or under it) | 409 | `AccountDeleteChangedTitle` | `AccountDeleteChanged` | Start again, back |
| typed address not the caller's, or empty | 400 | the confirmation page, §2 | `TypedWrong` in the form | Delete, cancel |
| more than ten addresses | 400 | `AccountDeleteNotDoneTitle` | `AccountDeleteTooMany` | back |
| `whoami`: protected (any address); or the first `POST` `403` for a stranger | 403 | `AccountDeleteNotDoneTitle` | `AccountDeleteProtected` | back |
| `whoami`: no answer, or not usable | 504 / 502 | `AccountDeleteNotDoneTitle` | `AccountDeleteNoCheck` | Try again, back |
| the write fails (I/O) | 500 | `AccountDeleteNotDoneTitle` | `AccountDeleteWriteFailed` | Start again, back |
| every `POST` `202`, roster | 200 | `AccountDeleteQueuedTitle` | `NowGone` + `Queued` + SignOut/Close | Sign out |
| every `POST` `202`, stranger | 200 | `AccountDeleteQueuedTitle` | `Queued` + SignOut/Close | Sign out |
| first `POST` refused (`503`, `403` or other), roster | 502 | `AccountDeletePartialTitle` | `NowGone` + `NotQueued` (+ `RetryOneAddress` if multi) | Try again, Sign out |
| first `POST` unanswered, roster | 504 | `AccountDeleteUnsureTitle` | `NowGone` + `MaybeQueued` (+ `RetryOneAddress` if multi) | Try again, Sign out |
| first `POST` refused (not `403`), stranger | 502 | `AccountDeleteNotDoneTitle` | `NotQueued` | Try again, back |
| first `POST` unanswered, stranger | 504 | `AccountDeleteUnsureTitle` | `MaybeQueued` | Try again, back |
| a later `POST` refused or unanswered (roster, multi only) | 502 / 504 | `AccountDeletePartialTitle` | `NowGone` + `Some` + `RetryOneAddress`; then `p.muted` `UnconfirmedLead` + the addresses from the one that failed on, in `code` | Try again, Sign out |

Short names in the table are `AccountDelete…` keys of §5. A stranger has one address (no row, so
the gate sends only the session's), which is why the "later `POST`" row is a roster's.

(Changed by §13.32 §1 and §13.33 §3, built 2026-11-26: the two `200` rows of "every `POST` `202`"
are that page **only where `BB_AUTH_WEB_LOGOUT_URL` is unset**. Where it is set, both rows are one
answer and no page: a `303` to that logout with `rd=/auth/login?notice=account-deleted`, the gate
clears the cookie, and the person lands on the sign-in page's notice, which carries what those two
ledes said. `K::AccountDeletedSignOut` is gone with the pill that rendered it, and
`K::AccountDeletedClose` is reworded ("This browser stays signed in until the session ends."),
because the cookie carries `Max-Age` and outlives a closed browser. Every partial row is
unchanged, pills included.)

**A `403` from the first `POST` is not one page** (a refinement of §13.29 W5). For a stranger
nothing has changed, so the protected page is true. For a roster user the row is already gone, and
"nothing was deleted" would be false, so it is the partial page: the keys are gone, the sign-in
accounts were not queued. The protected list is never named on either.

Why these shapes:

- **The done page says "being deleted", never "deleted".** A `202` is a queued request (§13.29
  W6), so the `h1` is in the progressive, the lede says what is gone now (keys and named access,
  for a roster user) apart from what is queued, names no duration (none is measured before 7g),
  does not promise the deletion service will act, and says what to do if sign-in still works
  later. That last clause is the only way the person can notice a worker that refused or failed
  (§13.29 W5, W8 §2): the owner hears of it by mail, the person by still getting in.
- **The done pages offer only Sign out.** It is the one thing left to do: the cookie still names
  them (stateless sessions) and keeps any `authenticated` grant until it expires, and "back"
  would land on an account page saying bb-auth has no row, which reads as a fault (Nielsen 8).
- **The partial pages say first what did happen.** `NowGone` before the rest, so the person knows
  the keys are safe and the remaining step is one try away (Nielsen 9). The unanswered page cannot
  claim either way, so it says "may or may not" and that a retry is safe (a second record for an
  address is harmless, §13.29 W3); it no longer promises the retry will tell, since nothing can.
- **A multi-address row's retry reaches one address** (§13.29 W3), so every partial page for one
  says so and sends the rest to an administrator, and the "some" page lists the addresses not
  confirmed: what the person would otherwise have to remember is on the page for the
  administrator they ask (recognition over recall). Not "not queued": an unanswered request may
  have been queued.
- **The `409` page is the deletion's own, not the console's `ConflictBody`.** That text names
  `bb-auth-adm` over SSH and "the access file", an operator's words. One page serves the stale
  `rev` and the changed `uuid` (§13.29 W3 steps 2 and 5), because for the person each is "my
  account changed", and splitting them would tell an attacker which check fired.
- **The service is named "the deletion service"**, everywhere it appears, and the sign-in
  accounts are "sign-in accounts": no Cognito, no worker, no intake, no queue file, no status code.
- **No blame anywhere.** Every refusal names what happened and the next step; nothing says
  "invalid", "wrong" or "you failed". The typed-address refusal says the address "is not one of
  this account's", which is a fact about the address.

#### 5. The `K` keys (delete design)

Reworded on 2026-11-26: **18 added, 1 changed (`AccountDeleteChanged`), 17 removed**, 19 kept
from the overnight table, 38 in all. Reused unchanged from elsewhere: `Cancel`, `Back`, `SignOut`,
`AccountNoRow` (the last deleted by plan step 13, 2026-11-26, with the account page's no-row
sentence; the deletion never wrote it, so the removal costs this design nothing), and the `Unit*`
words through `limit_text`. No `AccountProfile*` key is used by
the deletion any more.

| Key | English | Italian |
|---|---|---|
| `AccountDelete` (§13.28) | Delete account and all its data | Elimina l'account e tutti i suoi dati |
| `AccountDeleteTitle` | Delete your account | Elimina il tuo account |
| `AccountDeleteLead` (new) | This cannot be undone. To confirm, type your email address below and press Delete my account. | Non si può annullare. Per confermare, scrivi qui sotto il tuo indirizzo email e premi Elimina il mio account. |
| `AccountDeleteGoes` | What is deleted | Cosa viene eliminato |
| `AccountDeleteRecord` | Your bb-auth record, and every access an administrator gave you by name. | I tuoi dati in bb-auth, e ogni accesso che un amministratore ti ha dato per nome. |
| `AccountDeleteKeysLead` | Your API keys, which stop working within seconds: | Le tue chiavi API, che smettono di funzionare in pochi secondi: |
| `AccountDeleteGroupsLead` | Your place in these groups: | Il tuo posto in questi gruppi: |
| `AccountDeleteSignInOne` (new) | Every sign-in account with this email address, whether you sign in with an emailed code or with a provider such as Google: | Ogni account di accesso con questo indirizzo email, sia che tu acceda con un codice via email sia con un fornitore come Google: |
| `AccountDeleteSignInMany` (new) | Every sign-in account with any of these email addresses, whether you sign in with an emailed code or with a provider such as Google: | Ogni account di accesso con uno di questi indirizzi email, sia che tu acceda con un codice via email sia con un fornitore come Google: |
| `AccountDeleteLater` (new) | The sign-in accounts are not deleted at once: they are queued for a separate deletion service. | Gli account di accesso non vengono eliminati subito: vengono messi in coda per un servizio di eliminazione separato. |
| `AccountDeleteAuditKept` | The record of your sign-ins and refusals is kept for | Il registro dei tuoi accessi e dei rifiuti è conservato per |
| `AccountDeleteAuditTail` | , then dropped. | , poi viene eliminato. |
| `AccountDeleteAuditSize` | The record of your sign-ins and refusals is kept until newer entries replace it; this deployment keeps at most | Il registro dei tuoi accessi e dei rifiuti resta finché voci più recenti non lo sostituiscono; questa installazione ne conserva al massimo |
| `AccountDeleteTypeLabel` (new) | Type your email address to confirm | Scrivi il tuo indirizzo email per confermare |
| `AccountDeleteTypeHintMany` (new) | Any one of the addresses above. | Uno qualsiasi degli indirizzi qui sopra. |
| `AccountDeleteTypedWrong` (new) | The email address typed is not one of this account's, so nothing was deleted. Type it as it is shown above. | L'indirizzo email scritto non è uno di quelli di questo account, quindi non è stato eliminato nulla. Scrivilo come appare qui sopra. |
| `AccountDeleteConfirm` | Delete my account | Elimina il mio account |
| `AccountDeleteTooMany` (new) | This account has more email addresses than this page can delete at once, so it cannot be deleted here, and nothing was deleted. If you want it deleted, ask an administrator. | Questo account ha più indirizzi email di quanti questa pagina ne possa eliminare in una volta, quindi non può essere eliminato qui, e non è stato eliminato nulla. Se vuoi eliminarlo, chiedi a un amministratore. |
| `AccountDeleteProtected` (new) | This account cannot be deleted from this page, and nothing was deleted. If you want it deleted, ask an administrator. | Questo account non può essere eliminato da questa pagina, e non è stato eliminato nulla. Se vuoi eliminarlo, chiedi a un amministratore. |
| `AccountDeleteNoCheck` (new) | The deletion service did not answer as expected, so nothing was deleted and you can still sign in. Try again in a minute; if it fails again, tell an administrator. | Il servizio di eliminazione non ha risposto come previsto, quindi non è stato eliminato nulla e puoi ancora accedere. Riprova tra un minuto; se non funziona di nuovo, avvisa un amministratore. |
| `AccountDeleteNotDoneTitle` | Your account was not deleted | Il tuo account non è stato eliminato |
| `AccountDeleteChangedTitle` | Your account changed | Il tuo account è cambiato |
| `AccountDeleteChanged` (changed: "or your sign-in" dropped, there is no `kind` or header check) | Your account changed after you opened this page, so nothing was deleted. Start again to see what would be deleted now. | Il tuo account è cambiato dopo che hai aperto questa pagina, quindi non è stato eliminato nulla. Ricomincia per vedere cosa verrebbe eliminato adesso. |
| `AccountDeleteStartAgain` | Start again | Ricomincia |
| `AccountDeleteWriteFailed` | bb-auth could not save the change, so nothing was deleted and you can still sign in. Try again in a minute; if it fails again, tell an administrator. | bb-auth non è riuscito a salvare la modifica, quindi non è stato eliminato nulla e puoi ancora accedere. Riprova tra un minuto; se non funziona di nuovo, avvisa un amministratore. |
| `AccountDeleteQueuedTitle` (new) | Your account is being deleted | Il tuo account è in fase di eliminazione |
| `AccountDeleteNowGone` (new) | Your API keys and every access an administrator gave you by name are gone. | Le tue chiavi API e ogni accesso che un amministratore ti ha dato per nome non ci sono più. |
| `AccountDeleteQueued` (new) | Your sign-in accounts are queued for deletion. This page cannot tell when that happens; if you can still sign in later, tell an administrator. | I tuoi account di accesso sono in coda per l'eliminazione. Questa pagina non può dire quando avverrà; se più avanti riesci ancora ad accedere, avvisa un amministratore. |
| `AccountDeletedSignOut` | This browser stays signed in until you sign out, so sign out now. | Questo browser resta connesso finché non esci, quindi esci adesso. |
| `AccountDeletedClose` | This browser stays signed in until the session ends: close your browser to end it. | Questo browser resta connesso finché la sessione non termina: chiudi il browser per terminarla. |
| `AccountDeletePartialTitle` | Your account is only partly deleted | Il tuo account è stato eliminato solo in parte |
| `AccountDeleteNotQueued` (new) | Your sign-in accounts could not be queued for deletion, so they still exist. Try again later; if it fails again, tell an administrator. | Non è stato possibile mettere in coda l'eliminazione dei tuoi account di accesso, che quindi esistono ancora. Riprova più tardi; se non funziona di nuovo, avvisa un amministratore. |
| `AccountDeleteRetry` | Try again | Riprova |
| `AccountDeleteUnsureTitle` | Your account may not be fully deleted | Il tuo account potrebbe non essere stato eliminato del tutto |
| `AccountDeleteMaybeQueued` (new) | The deletion service did not answer, so your sign-in accounts may or may not be queued for deletion. Trying again is safe, even if they were. | Il servizio di eliminazione non ha risposto, quindi i tuoi account di accesso potrebbero essere in coda per l'eliminazione oppure no. Riprovare non crea problemi, anche se lo erano già. |
| `AccountDeleteSome` (new) | The sign-in accounts of some of your addresses are queued for deletion; the others may not be. | Gli account di accesso di alcuni dei tuoi indirizzi sono in coda per l'eliminazione; gli altri potrebbero non esserlo. |
| `AccountDeleteUnconfirmedLead` (new) | Addresses not confirmed as queued: | Indirizzi di cui non è confermata la messa in coda: |
| `AccountDeleteRetryOneAddress` (new) | Trying again covers only the address you signed in with; for the others, tell an administrator. | Riprovare riguarda solo l'indirizzo con cui hai effettuato l'accesso; per gli altri, avvisa un amministratore. |

The Italian "dati in bb-auth" for "bb-auth record" is chosen over *riga* (the console's word for a
roster row) because a person has no roster; "account di accesso" is "sign-in account" and
"servizio di eliminazione" is "deletion service" on every page of the flow, so each thing keeps one
fixed name in both languages. "Fornitore" for a sign-in provider is the plain word; Google is named
as an example only, as the overnight keys did, since the deployment's providers vary.

**Removed (Superseded by §13.29 W4 and W6, 2026-11-26), 17 keys:** `AccountDeleteLeadCode`,
`AccountDeleteCodeUntil` (no code); `AccountDeleteLeadRow` (said everything goes on the press;
replaced by `AccountDeleteLead`); `AccountDeleteSignIn` (one account, at once; replaced by
`AccountDeleteSignInOne`/`Many` and `AccountDeleteLater`); `AccountDeleteSocialTwin`,
`AccountDeleteRowWhy`, `AccountDeleteNothing`, `AccountRowDeletedTitle`, `AccountRowDeletedBody`
(a provider account with the address is deleted too, and every stranger has something to delete);
`AccountDeletedTitle`, `AccountDeletedBody` (untrue when shown; replaced by
`AccountDeleteQueuedTitle`, `AccountDeleteNowGone`, `AccountDeleteQueued`);
`AccountDeletePartial`, `AccountDeleteRefused`, `AccountDeleteUnsure`,
`AccountDeleteUnsureStranger` (spoke of the sign-in service refusing a deletion; replaced by
`AccountDeleteNotQueued`, `AccountDeleteMaybeQueued`, `AccountDeleteSome`,
`AccountDeleteRetryOneAddress`); `AccountDeleteGoneTitle`, `AccountDeleteGone` (no page can know
an account is gone).

#### 6. Heuristics and WCAG, and where they trade (delete design)

- Visibility (1): every outcome's `h1` says whether, and how much, was deleted, and the done page
  says what is gone and what is only queued. Match (2): "sign-in account", "bb-auth record",
  "deletion service"; no Cognito, no worker, no veto, no protected list. Control (3): Cancel on the
  confirmation, no `autofocus`. Consistency (4): the profile's outcome shape, the key revoke's
  "This cannot be undone". Error prevention (5): the typed address, the empty `required` field,
  no form when every submission would be refused. Recognition (6): the addresses listed beside
  the field that asks for one; the unconfirmed addresses listed on the "some" page. Minimalism
  (8): one step, done pages carry one action; the places and the uuid are not listed. Recovery
  (9): partial and unsure pages lead with what happened and offer the retry, and the typed
  refusal keeps the typed value.
- WCAG 3.3.4 (AA): the page is the review and the typed address the confirmation; 3.3.1 and
  3.3.3: the refusal is text, tied to the field by `aria-describedby`, and says how to fix it;
  1.3.5: **not met on the typed field**, by the user's decision of 2026-11-26 (no `autocomplete`,
  §2); 3.3.2: the field has a visible label; 1.4.1: the danger button
  says what it does in words; 2.5.3: every button's accessible name is its visible text; 2.5.8:
  the menu rows measure 30px at phone width.
- **Trade 1:** the typed field carries no `autocomplete`, so 1.3.5 is not met and a person who
  cannot type their own address cannot confirm here (the user's decision, 2026-11-26, §2). What it
  buys is that the confirmation is typed by the person rather than picked from a browser's list.
- **Trade 2:** the done page cannot say when, or even whether, the worker acts (§13.29 W6); it
  is honest at the cost of an ending with no certainty, and "tell an administrator" is the
  recovery for the case it cannot see.
- Scripting off: every step is a `GET` link or a `POST` form; nothing in the flow carries a script
  or a handler, and the menu row is a link inside the existing `details`.

#### 7. Tests and scenes (delete design)

Unit and socket tests in `src/bin/bb-auth-web.rs`, by slice of §13.29 W10. Where a name is
W10's, the assertions below are added to it; the others are new. Every assertion on text compares
with `t(lang, K::…)`, never with a literal.

- 7a `the_account_menu_ends_with_delete_after_sign_out`: the last child of `div.menu` is
  `a.pill.rm` with `href` `{account}/delete`, its previous sibling `div.sep`, containing one
  `svg[aria-hidden=true]` and the text `AccountDelete`; with no logout URL the row is still last,
  after Preferences and its own `div.sep`. `the_console_menu_has_no_delete_row` and
  `no_delete_row_when_the_intake_is_unset` as W10.
- 7b `delete_page_for_a_roster_user_lists_what_goes_and_asks_for_the_address`: `h1`
  `AccountDeleteTitle`; `p.lede` `AccountDeleteLead`; inside `div.panel.bad` a `p.lbl`
  `AccountDeleteGoes` and one `ul.plain` whose `li`s are, in order, Record, the keys line with each
  id in `code`, the groups line, and last `AccountDeleteSignInMany` with each address in `code` in
  the header's order (a fixture row with two addresses); `p.muted` `AccountDeleteLater` then the
  audit; one `form.edit` posting to `{account}/delete` with hidden `rev` and `uuid`, one `input`
  `name="confirm_email"` with `value=""`, `required`, no `autocomplete` (the user's decision,
  2026-11-26), `inputmode="email"`, class `f-email`, under the label
  `AccountDeleteTypeLabel` with the hint
  `AccountDeleteTypeHintMany`; its button is `AccountDeleteConfirm` with `class="danger"`; a
  `K::Cancel` pill to the page; no `autofocus` attribute anywhere; no `AccountNoRow`.
- 7b `delete_page_with_one_address_uses_the_singular_and_no_hint`: `AccountDeleteSignInOne`, no
  `span.hint` in the form.
- 7b `delete_page_for_a_stranger_lists_only_the_sign_in_accounts`: the `li`s are SignInOne only;
  `AccountDeleteLater`; no `AccountNoRow` (the user's decision, 2026-11-26: where the caller has no
  roster row the page writes nothing in its place); empty `uuid`; the same field and button.
- 7b `delete_page_omits_empty_key_and_group_lines`: a row with no keys and no groups lists Record
  and SignIn only.
- 7b `delete_page_with_more_addresses_than_a_run_takes_has_no_form`: eleven addresses give `200`,
  `AccountDeleteTooMany`, no `form`, a `back_link`.
- 7b `delete_page_says_how_long_the_audit_keeps_lines`: retention `6 months` gives `AuditKept`
  "6 months" `AuditTail`; Italian gives "6 mesi"; no retention gives `AuditSize` and
  `size_text(max_bytes)`.
- 7b `delete_page_never_names_the_veto`: a row named in an `excluded` entry: the page text has no
  `excluded`, `denied`, "veto" or `AccountVeto*` text. `delete_page_refuses_a_denied_identity`,
  `delete_page_changes_nothing_and_calls_nothing` (no `FakeIntake` request, file bytes equal) and
  `delete_page_is_a_404_when_the_intake_is_unset` as W10.
- 7b `delete_page_is_in_italian`: both variants with `lang=it` carry the Italian of every key in
  their row of §2's table (the 2.5.3 pitfall: button text and accessible name agree in `it`).
- 7c `a_typed_address_that_is_not_the_callers_sends_nothing` also asserts `400`, the confirmation
  page again, `div.err#form-error` with `AccountDeleteTypedWrong` inside the `form`, the field
  keeping the typed value with class `invalid`, `aria-invalid="true"`,
  `aria-describedby="form-error"`, and no `autofocus`. The same with an empty `confirm_email`.
- 7c `a_protected_address_is_refused_before_anything_is_posted` also asserts `403`,
  `AccountDeleteNotDoneTitle`, `AccountDeleteProtected`, one back link, and that neither
  "protected" nor the address appears in the text.
- 7c `the_done_page_says_queued_and_links_to_sign_out`: stranger: `200`, `h1`
  `AccountDeleteQueuedTitle`, lede `AccountDeleteQueued` then `AccountDeletedSignOut`, no
  `AccountDeleteNowGone`, one pill whose `href` is `account_logout_url`, no back link; with no
  logout URL, `AccountDeletedClose` and no pill.
- 7d `a_roster_deletion_removes_the_row_before_the_first_post` also asserts the roster done page:
  lede `AccountDeleteNowGone`, `AccountDeleteQueued`, `AccountDeletedSignOut`, in that order.
- 7d `a_stale_rev_is_a_409_and_posts_nothing` also asserts `AccountDeleteChangedTitle`,
  `AccountDeleteChanged`, a Start again pill to `{account}/delete`, and that `ConflictBody` (the
  console's text) is absent; the same on `a_stranger_who_gained_a_row_between_steps_is_refused`.
- 7e `each_delete_outcome_states_its_result_in_the_h1`: one case per row of §4's table: status,
  `h1` key, lede keys in order, and exactly the actions named (Sign out, Try again or Start again
  to `{account}/delete`, back); for the multi rows, `AccountDeleteRetryOneAddress` present, and
  absent for a one-address row.
- 7e `a_roster_first_post_403_is_the_partial_page_not_the_protected_one`: the row gone, `502`,
  `AccountDeletePartialTitle`, `AccountDeleteNotQueued`, no `AccountDeleteProtected`.
- 7e `a_second_address_refused_says_some_are_queued` also asserts `p.muted`
  `AccountDeleteUnconfirmedLead` listing in `code` the refused address and every one after it, and
  not the first.
- `the_delete_flow_carries_no_script`: every page of §2 and §4 has no `script` and no `on…=`
  (extends `no_page_but_the_reveal_carries_a_script`).

e2e (7f, `e2e/tests/delete.js`): the menu row, the roster page, a wrong typed address (the value
kept, the message read), the right one, the done page and Sign out's `href`; Cancel returns to
`/account/`; the stranger walk; protected; the `503` then Try again landing on the stranger's
page; keyboard only: from the menu trigger, Tab reaches Delete last, Enter opens the confirmation,
nothing is focused on load, Tab order is the field, Delete my account, cancel; all of it again in
`nojs.js`; `scrollWidth == clientWidth` at 320 on every page.

`shots.js` scenes (light, dark, phone, `it`; all prose), as §13.29 W10 names them plus one:
`account-menu-delete` (the panel open with the row), `account-delete` (roster, two addresses, two
keys and a group, so the plural line and the hint show), `account-delete-stranger` (one address),
`account-delete-typed-wrong`, `account-delete-protected`, `account-delete-queued` (roster),
`account-delete-partial` (roster, two addresses, the first `POST` `503`), `account-delete-unsure`,
`account-delete-some` (added here: the one page with a second list), `account-delete-changed`.
Ten; the designer's review of 7b to 7f looks at these. The fixture needs a caller whose row has
two addresses, a key and a group (`you@example.com` has none of them, the skill's pitfall).

#### 8. Open questions for the user (delete design)

Overnight question 1 (the menu row's words) is settled: they are now true for every caller (§1).
Question 2 (one red press) is settled: there is one press. Question 3 stood as the two below, and
the user answered both on 2026-11-26:

1. The places reached are **not** listed among what is deleted (§2): accepted as designed.
2. The typed address carries **no** `autocomplete` (§2, §6): the confirmation stays the person's
   own act, and WCAG 1.3.5 is not met on this one field.

### 13.31 Settings refusals as codes, in the page's words (plan step 8, later item)

Designed 2026-11-26, while the user was asleep and had delegated the decisions; each decision
below carries its reason so it can be overturned in the morning without re-deriving it.

What was read: `compile_settings` and everything it calls in `src/lib.rs` (`compile_page_url`,
`compile_login_url`, `compile_issuer`, `compile_asset_url`, `compile_cookie_domain`,
`compile_host_pattern`, `compile_oauth_domain`, `compile_app_client_id`,
`compile_profile_claims`, `compile_identity_attrs`, `compile_social_buttons`,
`compile_audit_header`, `compile_audit_policy`, `AuditLimit::parse`, `AuditPolicy::new`,
`compile_brand_name`, `UiTheme::parse`), `SettingsWrite::prepare`, `read_settings`,
`open_settings_file`; in `src/bin/bb-auth-web.rs` `Refusal`, `ConfigForm::apply`, the
`Route::Config` arm of `mutate`, `page_config`, `page_file_error`, `unit_label` and the `K`
labels of the Settings tab; in `src/bin/bb-auth-adm.rs` `cmd_settings_set`'s validators and
`save_settings`. Nothing here was run against a real system; every string quoted is read from
the source at commit `8358b7c`.

#### 1. The problem, measured in the source

`compile_settings` returns `Result<Settings, String>`, and the sentence names the file's keys.
The GUI reaches it on two paths, and both are English on an Italian page:

- **Through `prepare`.** `mutate` shows `SettingsWrite::prepare`'s `String` as the refusal, and
  attributes it to a field by sniffing the text (`e.contains("landing_url")`), which is exactly
  what `Refusal`'s own rustdoc says never to do ("never guessed from the message text").
  `profile_claims`, `identity_attrs` and the `landing_url` cross-check reach the page only this
  way.
- **Through `apply`'s pre-checks.** `ConfigForm::apply` calls eleven of the library's validators
  itself, to attribute each refusal to its input, and shows their English sentences verbatim
  (`Refusal::on("issuer", &e)`). It also writes two English sentences of its own inline, with
  `format!` (the stray host, the shared audit header), against the Displayed text rule.

The CLI (`bb-auth-adm settings set`, `settings init`) and the gate (`--check-settings`, startup,
SIGHUP) print the same sentences and must keep printing them byte for byte.

#### 2. Inventory: every refusal `compile_settings` can produce

One row per distinct sentence. "Prefix" is what `compile_settings` adds in front of a leaf's
own sentence (today's `map_err(|e| format!("…: {e}"))`); `{x}` marks an argument. The `raw`
argument is always **the text the sentence quotes today**, which is sometimes trimmed and
sometimes not (`issuer`, `cookie_domain` and a host pattern quote the value as given; a page
URL, an asset URL and the OAuth domain quote it trimmed); `compile_settings` stores whichever
the old sentence printed, so the bytes cannot move. Codes are `snake_case` of the variant, or
`url_<fault>` / `audit_header_<fault>` for the nested ones.

| # | Variant (args) | Today's string (source literal; the S0 golden test copies each exactly) | GUI |
| --- | --- | --- | --- |
| 1 | `Version { found: u32 }` | `"version": 1 was written before the app clients moved into this file (expected 3). Set gate.client_id, …` / `"version": 2 was written before the pool, …` / `"version": {v} is not this format (expected 3)` (three sentences, one variant: Display branches on `found`) | file only |
| 2 | `ClaimCharset { claim }` | prefix `profile_claims`: `claim '{claim}' must be non-empty and contain only [A-Za-z0-9_:-]` | claims |
| 3 | `ClaimEmptyPart { claim }` | prefix `profile_claims`: `claim '{claim}' has an empty part around a '_', ':' or '-'` | claims |
| 4 | `ClaimConsumed { claim }` | prefix `profile_claims`: `claim '{claim}' is consumed by the gate itself and cannot be propagated` | claims |
| 5 | `ClaimHeaderReserved { claim, header }` | prefix `profile_claims`: `claim '{claim}' derives '{header}', which is reserved` | claims |
| 6 | `ClaimsCollide { first, second, header }` | prefix `profile_claims`: `claims '{first}' and '{second}' both derive '{header}'` | claims |
| 7 | `AttrUnknown { attr }` | prefix `identity_attrs`: `unknown identity attribute '{attr}' (known: uuid, email)` (the list is `IDENTITY_ATTRS` joined) | identity |
| 8 | `AttrTwice { attr }` | prefix `identity_attrs`: `identity attribute '{attr}' is listed twice` | identity |
| 9 | `AttrNone` | prefix `identity_attrs`: `at least one identity attribute is required (known: uuid, email); a 204 that names nobody breaks every application behind this gate, in silence` | identity |
| 10 | `TtlBelowFloor { ttl }` | `session_ttl_secs: {ttl} is below the 60s floor; a session that expires as it is handed over is a login loop, not a short login` | ttl |
| 11 | `TtlAboveCeiling { ttl }` | `session_ttl_secs: {ttl} is past the 3153600000s ceiling; a lifetime that does not fit the arithmetic mints a cookie that is already expired` | ttl |
| 12 | `AppClientId { button: Option<String>, id }` | `client_id: '{id}' is not an app client id, which is letters, digits, '.', '_' and '-'`; with a button: `social_buttons '{button}': audience: '{id}' is not an app client id, …` | client_id / `aud-{button}` |
| 13 | `Url { key, raw, fault: UrlFault::NotPrintable }` | `{key} '{raw}': must be printable ASCII (no spaces, no control bytes)` | by key |
| 14 | `Url { …, UrlFault::NotHttps }` | `{key} '{raw}': must be an absolute https:// URL` | by key |
| 15 | `Url { …, UrlFault::EmptyHost }` | `{key} '{raw}': empty host` | by key |
| 16 | `Url { …, UrlFault::Userinfo }` | `{key} '{raw}': userinfo '@' is not allowed in the host` | by key |
| 17 | `Url { …, UrlFault::Backslash }` | `{key} '{raw}': backslash is not allowed` | by key |
| 18 | `Url { …, UrlFault::UserinfoOrBackslash }` | `issuer '{raw}': userinfo '@' and backslashes are not allowed` | issuer |
| 19 | `Url { …, UrlFault::QueryOrFragment }` | `issuer '{raw}': must be the bare issuer URL: no query, no fragment` | issuer |
| 20 | `Url { …, UrlFault::Quote }` | `{key} '{raw}': must not contain a quote or an angle bracket` | by key |
| 21 | `Url { …, UrlFault::NotHttpsOrRooted }` | `{key} '{raw}': must be an absolute https:// URL or a root-relative path starting with '/'` | by key |
| 22 | `CallbackNotHttps` | `social_callback_url: must be the absolute https:// URL registered on the app client, because Cognito compares it byte for byte` | callback |
| 23 | `CookieDomainNotBare { raw }` | `cookie_domain '{raw}': is not a bare domain: letters, digits, '.' and '-', an optional leading dot, and no scheme, port or path` | cookie_domain |
| 24 | `CookieDomainSingleLabel { raw }` | `cookie_domain '{raw}': is a single label, which a browser stores for nothing: name the registrable domain the services share, such as '.example.com'` | cookie_domain |
| 25 | `HostControlByte { raw }` | prefix `authorized_hosts`: `host pattern '{raw}': contains a control byte` | hosts |
| 26 | `HostNotBare { raw }` | prefix `authorized_hosts`: `host pattern '{raw}': must be a bare host — no scheme, port or path` (the dash is today's data, kept) | hosts |
| 27 | `HostAtOrDotDot { raw }` | prefix `authorized_hosts`: `host pattern '{raw}': must not contain '@' or '..'` | hosts |
| 28 | `HostsOutsideCookieDomain { hosts: Vec<String>, cookie_domain }` | `authorized_hosts: {hosts joined ", "} outside cookie_domain '{cookie_domain}', so a login would redirect there and the browser would send no session cookie: a 401, a bounce back to the sign-in page, and a loop` | hosts |
| 29 | `LandingOffHosts` | `landing_url: its host is not covered by authorized_hosts, so every sign-in with no rd would fall back to the sign-in page` | landing_url |
| 30 | `OauthDomainNotBare { raw }` | `oauth_domain: '{raw}' is not a bare host, which is letters, digits, '.' and '-' with no scheme and no path` | domain |
| 31 | `ButtonBareName { name }` | `social_buttons: '{name}' is a bare provider name, which was the shape before each button carried its own app client. Write it as { "idp": "{name}", "audience": "<app client id>" }` | file only |
| 32 | `ButtonNoIdp` | `social_buttons: an entry names no identity_provider` | file only |
| 33 | `ButtonIdpCharset { idp }` | `social_buttons '{idp}': a Cognito identity_provider name is letters, digits, '.', '_' and '-'` | file only |
| 34 | `ButtonTwice { idp }` | `social_buttons: '{idp}' is listed twice` | file only |
| 35 | `ButtonNoAudience { idp }` | `social_buttons '{idp}': names no app client, so no button could be drawn for it. Cognito federates per app client, so this is the one that offers {idp}` | `aud-{idp}` |
| 36 | `SocialHalfConfigured { buttons: usize }` | `social_buttons: {buttons} button(s) configured, but oauth_domain or social_callback_url is empty, so there is nowhere to send a visitor and nowhere for them to come back to` | domain |
| 37 | `AuditHeader { key, name, fault: HeaderFault::NotAName }` | `{key}: '{name}' is not a header name, which is letters, digits and '-' (nginx drops a request header with an underscore in its name)` | by key |
| 38 | `AuditHeader { …, HeaderFault::Credential }` | `{key}: '{name}' carries a credential, and the audit never writes one down` | by key |
| 39 | `AuditHeadersSame { name }` | `audit.client_ip_header and audit.request_id_header both name '{name}'; one header cannot carry an address and a request id at once` | request_id_header |
| 40 | `AuditLimitNotAmount { key, raw }` | prefix `{key}`: `'{raw}' is not an amount and a unit: write it as, say, '4 MiB', '1 GiB', '26 weeks', '6 months' or '1 year'` | by key |
| 41 | `AuditLimitZero { key, raw }` | prefix `{key}`: `'{raw}': an amount of nothing is not a limit` | by key |
| 42 | `AuditLimitTooMuch { key, raw, unit: AuditUnit }` | prefix `{key}`: `'{raw}': at most {unit.max_amount()} {unit.code()}, which is already more than any disk or any audit needs` | by key |
| 43 | `AuditUnbounded { rotation: String, retention: Option<String> }` | prefix `audit`: `rotation '{rotation}' with retention '{r}'` (or `with no retention`) `bounds how old the audit gets and not how big: a flood of refusals would grow the live file without limit. Rotate on a size (MiB, GiB) or give the retention one` | audit_retention |
| 44 | `BrandControl { name }` | `brand_name '{name}': contains a control character` | brand |
| 45 | `BrandTooLong { chars: usize }` | `brand_name: {chars} characters is longer than the 64 allowed` | brand |
| 46 | `ThemeUnknown { raw }` | `theme: '{raw}' is not one of system, light, dark` | theme |

**46 codes, in 37 variants of `SettingsRefusal`**: `Url` carries 9 faults and `AuditHeader` 2.
`key` is a `SettingKey` (below). `web.admins` has no row because it refuses nothing: a malformed
entry is a warning and a skip, and so are the two TTL and `social_providers` warnings, which are
not refusals and stay `eprintln!`. Two strings in the leaves are not rows because
`compile_settings` can never produce them: `compile_page_url`'s `empty` and
`compile_host_pattern`'s `empty` (a blank value is skipped before either is called). They stay
in the `String` wrappers, outside the enum, so the enum holds only what is reachable and the
golden test can reach every code.

`SettingsWrite::prepare` adds two more failures that are not settings refusals,
`cannot serialize: {e}` and `serialized to invalid JSON: {e}` (serde on our own structs, never
seen), and prefixes a refusal with `refusing to write:` and a space.

#### 3. Decision: the enum, where it lives, and its `Display`

**`SettingsRefusal` lives in `src/lib.rs`, beside `compile_settings`.** Reason: the membership
rule. What a settings file is refused for is an opinion about a file three programs read, and
two of them (the CLI and the gate) print the same sentence for it; it is the same argument that
put `decision_reason` in the library for the audit. The English sentence stays in the library
too, as `Display`, because it is already there and is the one both the CLI and the gate print:
moving it into each binary would make two copies of one sentence. The **translation** does not
go in the library, because the library has no language and the `K` table is the one home of
displayed text.

Its shape, flat except where a leaf is shared with a caller that names the setting differently:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsRefusal { /* the 37 variants of §2 */ }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingKey {
    LoginUrl, DeniedUrl, LandingUrl, Issuer, SocialCallbackUrl, StylesheetUrl, LogoUrl,
    ClientIpHeader, RequestIdHeader, AuditRotation, AuditRetention,
}
// SettingKey::name(): "login_url", …, "audit.client_ip_header", "audit.rotation": the name
// today's sentences use, which is a gate key bare and an audit key with its section.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlFault { NotPrintable, NotHttps, EmptyHost, Userinfo, Backslash,
                    UserinfoOrBackslash, QueryOrFragment, Quote, NotHttpsOrRooted }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderFault { NotAName, Credential }

pub enum PrepareError { Serialize(String), Reparse(String), Refused(SettingsRefusal) }
impl From<PrepareError> for String { fn from(e: PrepareError) -> String { e.to_string() } }
```

- **Why nested for `Url` and `AuditHeader` only.** Those leaves take a `field`/`what` argument
  and the CLI calls them with its own flag names (`compile_asset_url("--stylesheet", …)`,
  `compile_audit_header("--client-ip-header", …)`), so the tail of the sentence (`UrlFault`'s and
  `HeaderFault`'s `Display`) must exist without the setting's name, once, for both the wrapper and
  the enum. Everywhere else a flat variant is one arm in each match, which is what a small model
  can extend without a map of types.
- **`Display` reproduces today's bytes through two private methods.** `prefix(&self) ->
  Option<&'static str>` is what `compile_settings` used to add (`profile_claims`,
  `identity_attrs`, `authorized_hosts` for the three host faults, `login_url` for
  `Url { key: LoginUrl, .. }`, which is how today's doubled `login_url: login_url '…': …` is
  kept, the audit limit's `key.name()`, and `audit` for `AuditUnbounded`); `sentence(&self) ->
  String` is the rest. `Display` writes `{prefix}: {sentence}` or `{sentence}`.
- **The `String` leaves keep their signatures, as thin wrappers.** Each keeps
  `pub fn … -> Result<_, String>` and becomes a private typed core plus a `map_err`:
  `compile_profile_claims`, `compile_identity_attrs`, `compile_host_pattern`,
  `compile_cookie_domain`, `compile_oauth_domain`, `compile_brand_name`, `AuditLimit::parse`
  and `AuditPolicy::new` return `r.sentence()`; `compile_page_url`, `compile_issuer` and
  `compile_asset_url` format `{field} '{raw}': {fault}`; `compile_app_client_id` and
  `compile_audit_header` format `{what}: '{x}' {tail}` with the tail a `const` (app client) or
  `HeaderFault`'s `Display`. Reason: the access file's parser (`compile_access` calls
  `compile_login_url` and `compile_page_url`), the CLI's flag-named pre-checks (which `.replace`
  inside these strings) and the gate's tests all call them, and none of that is in scope. The one
  exception is `compile_social_buttons`, whose only caller is `compile_settings`: it returns
  `SettingsRefusal` directly.
- **How it travels.** `compile_settings -> Result<Settings, SettingsRefusal>`.
  `SettingsWrite::prepare -> Result<SettingsWrite, PrepareError>`, whose `Display` is
  `cannot serialize: {e}` / `serialized to invalid JSON: {e}` / `refusing to write: {r}`.
  `read_settings` and `open_settings_file` keep `Result<_, String>`: they already `format!`
  the error with the path, which works on `Display` unchanged, and they also carry I/O and serde
  errors that are no refusal. The CLI's `SettingsWrite::prepare(doc)?` in a function returning
  `Result<_, String>` keeps compiling through `From<PrepareError> for String`, so
  `bb-auth-adm` changes not one line. The gate's tests call `compile_settings(..).unwrap()`,
  which needs only `Debug`.
- **`code(&self) -> &'static str`, an exhaustive match, and `SETTINGS_REFUSAL_CODES: [&str;
  46]`.** The codes exist for the tests (§6) and as the refusal's stable name, as `Decision`'s
  are; no production code branches on them. `#[doc(hidden)] pub fn
  settings_refusal_samples() -> Vec<SettingsRefusal>` builds one of each code with neutral
  arguments, so the GUI's test can iterate them across the crate boundary (a `cfg(test)` item is
  invisible to another crate). It is the one item here that exists only for tests, and it is
  `doc(hidden)` to say so.

#### 4. Decision: the GUI maps each code to a `K` key naming the visible label

One function in `bb-auth-web.rs`, an **exhaustive match with no `_` arm**, so a new variant
does not compile until somebody decides what the page says about it:

```rust
fn settings_refusal(lang: Lang, r: &SettingsRefusal) -> Refusal
```

- **The message** is a `K` template with positional placeholders `{0}`, `{1}`, … filled by one
  new helper, `fn fill(template: &str, args: &[&str]) -> String`, single-pass (a substituted
  argument is never rescanned, the reason `render_page` gives for its own substitution). `{0}` is
  always the visible label of the field, `t(lang, label)`, which is what "names the visible field
  label" means mechanically. The value an operator typed is quoted only where the field cannot
  show which part is wrong: an entry of a list (a claim, an attribute, a host) or a header name.
  A single-value field is marked `invalid` and already shows its value.
- **The field** is decided in the same arm and goes in `Refusal::field` (its `name=`), which is
  what marks the input `invalid`, points `aria-describedby` at the message and opens its group.
  `SettingKey` maps to its `name=` and its label in one helper, `setting_field(key) ->
  (&'static str, K)`: `LoginUrl` `("login_url", GlobalLoginUrl)`, `DeniedUrl` `("denied_url",
  GlobalDeniedUrl)`, `LandingUrl` `("landing_url", GlobalLandingUrl)`, `Issuer` `("issuer",
  Issuer)`, `SocialCallbackUrl` `("callback", SocialCallback)`, `StylesheetUrl` `("stylesheet",
  StylesheetUrl)`, `LogoUrl` `("logo", LogoUrl)`, `ClientIpHeader` `("client_ip_header",
  ClientIpHeader)`, `RequestIdHeader` `("request_id_header", RequestIdHeader)`, `AuditRotation`
  `("audit_rotation", AuditRotation)`, `AuditRetention` `("audit_retention", AuditRetention)`.
  The other variants name their field in their arm: the "GUI" column of §2. The two cross-checks
  go where today's code already sends them: a stray host to `hosts`, the landing page to
  `landing_url`, the half-configured social sign-in to `domain`, the shared header to
  `request_id_header`, the unbounded pair to `audit_retention`.
- **`unit_label` takes `Lang` instead of `&View`** (its body reads only `v.t`), so
  `AuditLimitTooMuch` can name the unit in the list box's own words.

The keys (English, then Italian). New keys are prefixed `SetRef`; three existing keys are reused
because they already say the same thing. The field each refusal marks is the "GUI" column of §2.

(Changed by the designer, 2026-11-26.) The architect's draft was reviewed against the `K`
labels as both languages spell them today; 23 of its 38 rows changed in one language or both,
12 stand as drafted, and the three reused keys are untouched. What changed, and why:

- **Every message says what is allowed, not only what is wrong** (Nielsen's ninth heuristic,
  "help users recognize, diagnose, and recover from errors", and WCAG 2.2 SC 3.3.3 Error
  Suggestion, <https://www.w3.org/WAI/WCAG22/Understanding/error-suggestion.html>). So
  `claim_empty_part` names the three shapes it refuses and where a separator may sit,
  `claims_collide` says to keep one, `landing_off_hosts` is worded as the rule its own help text
  states, `audit_limit_zero` says "more than 0" instead of an aphorism, and a control byte in a
  host says where it usually comes from and to type the entry again.
- **`url_not_printable` was wrong for one input.** The library refuses anything outside printable
  ASCII, so an accented letter was refused under a message naming only spaces and control
  characters. It now names all three.
- **The session lifetime quotes no value.** It is a single-value field, which §4's own rule says
  already shows its value, so `ttl_below_floor` takes `{0}` label and `{1}` floor, and
  `ttl_above_ceiling` `{0}` label and `{1}` ceiling (the draft's `ttl` argument is dropped). The
  draft's "60 seconds is under the minimum of 60" also put a number with no unit in the sentence.
- **`hosts_outside_cookie_domain` no longer agrees in number with a list.** `{1}` is one host or
  several joined by ", ", so "{1} is not covered" was wrong for two; the sentence now has the
  cookie domain as its subject. Same arguments, new order of use.
- **Italian reads as Italian.** Plural agreement ("{1} secondi sono", "{1} caratteri, e ne sono
  ammessi"), no doubled verb ("non può correggere; correggilo"), "host puro" as the OAuth
  domain's help text already says, "registra" for what the audit writes, and the landing page's
  wording taken from its own help text ("deve stare su uno degli host autorizzati, altrimenti
  ogni accesso ricade sulla pagina di accesso").
- **Lists are introduced the way `DefaultThemeBad` already does it**: "is not one of: {2}" /
  "non è uno tra: {2}". `{2}` of `attr_unknown` and `{1}` of `attr_none` are `IDENTITY_ATTRS`
  joined with ", " (`uuid, email`): the words a person types in that field, not wire keys.
- **A label is quoted with its capital where it falls mid-sentence** ("not covered by the Cookie
  domain", "uno degli Host autorizzati"): it is the label as the page prints it, which is what
  makes it findable, and lowercasing it in code would break "User pool (issuer)".

| Code(s) | `K` key | `{…}` | English | Italian |
| --- | --- | --- | --- | --- |
| `claim_charset` | `SetRefClaimCharset` | label, claim | `{0}: '{1}' may contain only letters, digits, '_', ':' and '-'.` | `{0}: '{1}' può contenere solo lettere, cifre, '_', ':' e '-'.` |
| `claim_empty_part` | `SetRefClaimEmptyPart` | label, claim | `{0}: '{1}' starts or ends with '_', ':' or '-', or has two of them in a row; each one must sit between letters or digits.` | `{0}: '{1}' inizia o finisce con '_', ':' o '-', oppure ne ha due di fila; ognuno deve stare tra lettere o cifre.` |
| `claim_consumed` | `SetRefClaimConsumed` | label, claim | `{0}: '{1}' is a claim the gate reads for itself, so it cannot be passed to the application.` | `{0}: '{1}' è un claim che il gate legge per sé, quindi non può essere passato all'applicazione.` |
| `claim_header_reserved` | `SetRefClaimHeaderReserved` | label, claim, header | `{0}: '{1}' would become the header {2}, which the gate keeps for itself.` | `{0}: '{1}' diventerebbe l'header {2}, che il gate riserva a sé.` |
| `claims_collide` | `SetRefClaimsCollide` | label, first, second, header | `{0}: '{1}' and '{2}' would both become the header {3}; keep only one of them.` | `{0}: '{1}' e '{2}' diventerebbero entrambi l'header {3}; tienine solo uno.` |
| `attr_unknown` | `SetRefAttrUnknown` | label, attr, known | `{0}: '{1}' is not one of: {2}.` | `{0}: '{1}' non è uno tra: {2}.` |
| `attr_twice` | `SetRefAttrTwice` | label, attr | `{0}: '{1}' is listed twice.` | `{0}: '{1}' compare due volte.` |
| `attr_none` | `SetRefAttrNone` | label, known | `{0}: at least one is needed ({1}); without one, the applications behind the gate cannot tell who signed in.` | `{0}: ne serve almeno uno ({1}); senza, le applicazioni dietro il gate non sanno chi è entrato.` |
| `ttl_below_floor` | `SetRefTtlBelowFloor` | label, floor | `{0}: must be at least {1} seconds; a session that expires as it is handed over sends everybody back to the sign-in page.` | `{0}: servono almeno {1} secondi; una sessione che scade mentre viene consegnata rimanda tutti alla pagina di accesso.` |
| `ttl_above_ceiling` | `SetRefTtlAboveCeiling` | label, ceiling | `{0}: must be at most {1} seconds.` | `{0}: può essere al massimo di {1} secondi.` |
| `app_client_id` | `SetRefAppClientId` | way in, id | `App client for {0}: '{1}' may contain only letters, digits, '.', '_' and '-'.` | `App client per {0}: '{1}' può contenere solo lettere, cifre, '.', '_' e '-'.` |
| `url_not_printable` | `SetRefUrlNotPrintable` | label | `{0}: may contain only plain ASCII characters, with no spaces, accented letters or control characters.` | `{0}: può contenere solo caratteri ASCII semplici, senza spazi, lettere accentate o caratteri di controllo.` |
| `url_not_https` | `SetRefUrlNotHttps` | label | `{0}: must be an absolute address starting with https://.` | `{0}: deve essere un indirizzo assoluto che inizia con https://.` |
| `url_empty_host` | `SetRefUrlEmptyHost` | label | `{0}: the address names no host after https://.` | `{0}: l'indirizzo non indica alcun host dopo https://.` |
| `url_userinfo` | `SetRefUrlUserinfo` | label | `{0}: a user name and '@' before the host are not allowed.` | `{0}: un nome utente con '@' prima dell'host non è ammesso.` |
| `url_backslash` | `SetRefUrlBackslash` | label | `{0}: a backslash (\) is not allowed.` | `{0}: la barra rovesciata (\) non è ammessa.` |
| `url_userinfo_or_backslash` | `SetRefUrlUserinfoOrBackslash` | label | `{0}: neither a user name with '@' nor a backslash (\) is allowed.` | `{0}: non sono ammessi né un nome utente con '@' né la barra rovesciata (\).` |
| `url_query_or_fragment` | `SetRefUrlQueryOrFragment` | label | `{0}: must be the issuer address alone, with no '?' query and no '#' fragment.` | `{0}: deve essere solo l'indirizzo dell'issuer, senza query '?' né frammento '#'.` |
| `url_quote` | `SetRefUrlQuote` | label | `{0}: quotes and angle brackets are not allowed.` | `{0}: virgolette e parentesi angolari non sono ammesse.` |
| `url_not_https_or_rooted` | `SetRefUrlNotHttpsOrRooted` | label | `{0}: must be an absolute https:// address or a path starting with '/'.` | `{0}: deve essere un indirizzo https:// assoluto o un percorso che inizia con '/'.` |
| `callback_not_https` | `SetRefCallbackNotHttps` | label | `{0}: must be the absolute https:// address registered on the app clients, because Cognito compares it byte for byte.` | `{0}: deve essere l'indirizzo https:// assoluto registrato sugli app client, perché Cognito lo confronta byte per byte.` |
| `cookie_domain_not_bare` | `SetRefCookieDomainNotBare` | label | `{0}: must be a bare domain such as .example.com: letters, digits, '.' and '-', with no scheme, port or path.` | `{0}: deve essere un dominio puro come .example.com: lettere, cifre, '.' e '-', senza schema, porta o percorso.` |
| `cookie_domain_single_label` | `SetRefCookieDomainSingleLabel` | label | `{0}: no browser keeps a cookie for a one-word domain; name the domain the services share, such as .example.com.` | `{0}: nessun browser conserva un cookie per un dominio di una sola parola; indica il dominio che i servizi hanno in comune, come .example.com.` |
| `host_control_byte` | `SetRefHostControlByte` | label, host | `{0}: '{1}' contains a control character, often left by a paste; type it again.` | `{0}: '{1}' contiene un carattere di controllo, spesso lasciato da un copia e incolla; riscrivilo.` |
| `host_not_bare` | `SetRefHostNotBare` | label, host | `{0}: '{1}' must be a bare host such as app.example.com, with no scheme, port or path.` | `{0}: '{1}' deve essere un host puro come app.example.com, senza schema, porta o percorso.` |
| `host_at_or_dot_dot` | `SetRefHostAtOrDotDot` | label, host | `{0}: '{1}' must not contain '@' or '..'.` | `{0}: '{1}' non deve contenere '@' o '..'.` |
| `hosts_outside_cookie_domain` | `SetRefHostsOutsideCookieDomain` | label, hosts, cookie label, domain | `{0}: the {2} '{3}' does not reach {1}, so a sign-in that lands there carries no session cookie and loops back to the sign-in page.` | `{0}: il {2} '{3}' non raggiunge {1}, quindi un accesso che arriva lì non porta il cookie di sessione e torna in ciclo alla pagina di accesso.` |
| `landing_off_hosts` | `SetRefLandingOffHosts` | label, hosts label | `{0}: must be on one of the {1}, or every sign-in that names no page falls back to the sign-in page.` | `{0}: deve stare su uno degli {1}, altrimenti ogni accesso che non indica una pagina ricade sulla pagina di accesso.` |
| `oauth_domain_not_bare` | `SetRefOauthDomainNotBare` | label | `{0}: must be a bare host: letters, digits, '.' and '-', with no scheme and no path.` | `{0}: deve essere un host puro: lettere, cifre, '.' e '-', senza schema né percorso.` |
| `button_no_audience` | `AudienceNeeded` (exists) | none | as today | as today |
| `social_half_configured` | `SocialWiringNeeded` (exists) | none | as today | as today |
| `audit_header_not_a_name` | `SetRefHeaderNotAName` | label, name | `{0}: '{1}' is not a header name: letters, digits and '-' only (nginx drops a header with an underscore in its name).` | `{0}: '{1}' non è un nome di header: solo lettere, cifre e '-' (nginx scarta un header con un trattino basso nel nome).` |
| `audit_header_credential` | `SetRefHeaderCredential` | label, name | `{0}: '{1}' carries a credential, and the audit never writes one down.` | `{0}: '{1}' contiene una credenziale, e l'audit non registra mai credenziali.` |
| `audit_headers_same` | `SetRefHeadersSame` | label, name, other label | `{0}: '{1}' is already the {2}; one header cannot carry both an address and a request id.` | `{0}: '{1}' è già l'{2}; un solo header non può portare sia un indirizzo sia un id di richiesta.` |
| `audit_limit_not_amount` | `SetRefLimitNotAmount` | label | `{0}: the amount must be a whole number.` | `{0}: la quantità deve essere un numero intero.` |
| `audit_limit_zero` | `SetRefLimitZero` | label | `{0}: the amount must be more than 0.` | `{0}: la quantità deve essere maggiore di 0.` |
| `audit_limit_too_much` | `SetRefLimitTooMuch` | label, max, unit label | `{0}: the most allowed is {1} {2}.` | `{0}: il massimo ammesso è {1} {2}.` |
| `audit_unbounded` | `SetRefAuditUnbounded` | rotation label, retention label | `{0} and {1}: at least one of the two must be a size (MiB, GiB), or a flood of refusals would grow the audit without limit.` | `{0} e {1}: almeno una delle due deve essere una dimensione (MiB, GiB), altrimenti un'ondata di rifiuti farebbe crescere l'audit senza limite.` |
| `brand_control` | `SetRefBrandControl` | label | `{0}: control characters are not allowed.` | `{0}: i caratteri di controllo non sono ammessi.` |
| `brand_too_long` | `SetRefBrandTooLong` | label, chars, max | `{0}: {1} characters, and at most {2} are allowed.` | `{0}: {1} caratteri, e ne sono ammessi al massimo {2}.` |
| `theme_unknown` | `DefaultThemeBad` (exists) | none | as today | as today |
| `version`, `button_bare_name`, `button_no_idp`, `button_idp_charset`, `button_twice` | `SetRefFileOnly` | the English sentence | `The settings file is refused for a reason this page cannot fix: correct it with bb-auth-adm over SSH. The gate says: {0}` | `Il file delle impostazioni viene rifiutato per un motivo che questa pagina non può risolvere: correggilo con bb-auth-adm via SSH. Il gate dice: {0}` |

`{1}` of `audit_limit_too_much` is `unit.max_amount()` as plain digits and `{2}` is
`unit_label(lang, unit, max)`, which is always the plural because no maximum is 1. `{1}` of
`ttl_below_floor` is `MIN_SESSION_TTL`, of `ttl_above_ceiling` `MAX_SESSION_TTL`, and `{2}` of
`brand_too_long` `MAX_BRAND_NAME`, each as plain digits.

**One register the page does not share yet** (designer, 2026-11-26). The reused keys and the
form's own pre-checks (`SessionTtlBad`, `IssuerNeeded`, `AuthorizedHostsNeeded`,
`DefaultThemeBad`, `AdminsNeverEmpty`) are lowercase fragments with no label and no full stop
("must be a whole number of seconds"), shown in the `div.err` above the form. The new keys name
the field first and end with a full stop, because the message sits above the form and not beside
the field, and WCAG 2.2 SC 3.3.1 Error Identification asks that the item in error be identified
in text (<https://www.w3.org/WAI/WCAG22/Understanding/error-identification.html>), which the
fragments do only through the red outline and `aria-describedby`. That trades consistency
(Nielsen's fourth heuristic) for identification until the old keys are brought in line, which is
a separate change to the `K` table and not part of S8; it is proposed to the coordinator as
follow-up work, not done here. (Designed as S10 in §10.)

`app_client_id`'s `{0}` is `t(lang, K::SignInEmail)` for `client_id` and the provider's name
for a button: the "Ways in" table labels its rows that way, and the cell is the field.

#### 5. Decision: refusals the GUI's own form can never produce

Five codes cannot come from this form, and each for a reason the form's construction gives:
`version` (the form edits a document that already opened, and never touches `version`);
`button_bare_name` (`ConfigForm::read` writes only `Wired` buttons; a bare name on disk is
rendered as a row with an empty app client, which `button_no_audience` answers first);
`button_no_idp` (`idps` is split on whitespace, so no entry is empty); `button_idp_charset` and
`button_twice` (the providers come from the page's own hidden `idps`, so only a forged request
carries a bad or repeated one).

**They are mapped, not skipped, to `SetRefFileOnly`, which wraps the library's English sentence
verbatim and attributes nothing.** Reason: the exhaustive match still forces a decision for
each, so a new variant cannot hide behind a wildcard; and the honest reader of those five is an
operator at a shell, which is the precedent `page_file_error` already sets (a file the gate
refuses is shown in the gate's own words, because the operator will meet those exact words in
`--check-settings` and the journal). Translating sentences nobody can reach through the page
would be 10 strings of maintenance for no reader. `open_settings_file`'s error in the `POST`
(a file broken on disk between the `GET` and the `POST`) stays as it is for the same reason.

The `apply` pre-checks the GUI keeps are only the ones that are **not** the library's: `ttl` not
a number, `admins` empty or without the caller, an empty `client_id` / `issuer` /
`authorized_hosts` / button audience (the GUI is stricter than the gate on purpose), and a
`ui_theme` the list box cannot send. Those already have `K` keys. Every other check in `apply`
duplicates `compile_settings` and is removed (slice S9), so there is exactly one path from a
library refusal to the page, and the two inline English `format!`s go with them. Where `apply`
used a validator's `Ok` value to normalise what it writes (`issuer` without its trailing slash,
`cookie_domain` lowercased, `client_id` and the two headers trimmed, the rotation and retention
spelled), it keeps the call and takes `.unwrap_or` the trimmed input on `Err`, so for every
value the library accepts the file is written byte for byte as before, and a value it refuses
reaches `prepare` and is refused there, in the page's words, on its field.

#### 6. How each decision is shown to hold

- **CLI and gate bytes unchanged.** Slice S0 lands, before any code moves, three golden tests
  in `src/lib.rs` written from today's source literals:
  `settings_refusals_read_as_they_always_have` (one bad `SettingsFile` per code, built by
  mutating a valid one, asserting `format!("{}", compile_settings(&f).err().unwrap())` equals the
  literal; `format!("{}", …)` compiles against both `String` and the enum, so the test is not
  edited when the type changes), `settings_leaf_refusals_read_as_they_always_have` (each `String`
  wrapper, with the CLI's own names: `compile_app_client_id("--client-id", …)`,
  `compile_audit_header("--client-ip-header", …)`, `compile_asset_url("--stylesheet", …)`,
  `compile_page_url("denied_url", …)`, and each fault of each other leaf, including the two
  `empty`s) and `a_refused_write_reads_as_it_always_has` (`SettingsWrite::prepare` on a bad
  document starts with `refusing to write:`, a space, and continues with the first test's literal). They are
  green on the day they land, by design: their red is shown by changing one byte of one library
  sentence locally, watching the test fail, and reverting. Every later slice keeps them green
  unedited; that is the byte-identity guarantee for `bb-auth-adm` (which prints the `String`
  that `From<PrepareError>` makes, `e.to_string()`) and for `--check-settings` (which prints
  `read_settings`' `{path}: {e}`). `prepare_error_becomes_the_same_string` pins the `From`.
- **Every code has a sentence, a sample and a golden.** `every_refusal_has_a_code_a_sample_and_a_sentence`
  (lib): the codes of `settings_refusal_samples()` are exactly `SETTINGS_REFUSAL_CODES`, each
  once, and every sample's `Display` is non-empty; the golden test asserts the set of codes its
  files produced equals `SETTINGS_REFUSAL_CODES`. A new variant fails to compile in `code()`, then
  fails this test until it is listed, sampled and given a golden.
- **Every code has a `K` mapping in both languages.** Compile time: `settings_refusal` has no
  `_` arm. Run time, `every_settings_refusal_reads_in_both_languages` (bb-auth-web): for each
  sample and each of `Lang::En`, `Lang::It`, the message is non-empty and holds no `{digit}`;
  for the five file-only codes (a `const FILE_ONLY: [&str; 5]` in the test) the message contains
  `r.to_string()` and `field` is `None`; for every other code `field` is `Some`, the message does
  **not** contain `r.to_string()`, does not contain any wire key that has a `_` or a `.` in it
  (`profile_claims`, `identity_attrs`, `session_ttl_secs`, `client_id`, `login_url`,
  `denied_url`, `landing_url`, `cookie_domain`, `authorized_hosts`, `oauth_domain`,
  `social_callback_url`, `social_buttons`, `client_ip_header`, `request_id_header`,
  `audit.rotation`, `audit.retention`, `stylesheet_url`, `logo_url`, `brand_name`; the samples'
  arguments avoid them, and `issuer` is not in the list because the label "User pool (issuer)"
  carries it), and the English and Italian messages differ. `fill_is_single_pass`: an argument
  holding `{1}` is not expanded.
- **The wiring, once per path rather than once per code.** `settings_refusal` is a pure
  function, so the test above covers every code; the route needs one test per path into it:
  `an_italian_settings_refusal_names_the_labels` (landing page off the hosts, through `prepare`,
  with the `lang=it` cookie: the `div.err` text contains "Pagina di arrivo" and "Host
  autorizzati" and neither `landing_url` nor `authorized_hosts`, and `f-landing_url invalid`
  stays), `a_claim_refusal_is_marked_on_its_field` (a bad claim, through `prepare`: `claims`
  marked, which is not attributed today), and in S9
  `the_settings_form_says_a_stray_host_in_italian` and
  `the_settings_form_says_a_shared_audit_header_in_italian` (today `apply`'s inline English).
  Assert on the `div.err` text, not the whole body: the body contains `name="landing_url"`, which
  is why §13.21's `body.contains("landing_url")` passes whatever the message says.
- **What a person sees.** `node e2e/shots.js config-landing-refused`: the designer reads the
  Italian shot and the English one, which today show the wire sentence (§13.21).
  Reviewed after S8 (designer, 2026-11-26): the four views show the message in the reader's
  language, opening with the field's label, and the landing page's input is the one marked
  (`invalid`, `aria-invalid="true"`, `aria-describedby="form-error"`); a folded group opens
  itself on the refusal (checked without `?groups=open`, which the scene passes). That meets
  SC 3.3.1 by the text alone, and the message is first in `main` after a full page load, so it
  needs no live region or focus move. Claims (`claim_consumed`, `claims_collide`) and the
  session lifetime read the same way in both languages. The stray host still shows `apply`'s
  English `format!` until S9, so the several-host sentence of `hosts_outside_cookie_domain` is
  reachable only then; its sample reads "Authorized hosts: the Cookie domain '.example.com'
  does not reach a.other.org, b.other.org, c.third.net, so …", which holds for a list.

#### 7. Slices

Each is one red-green pass touching a few functions, in this order, and none leaves a `pub`
function without a caller (clippy's `dead_code` does not fire on a library `pub` item, but a
GUI helper with no caller does, which is why S8 is one slice).

| Slice | What changes | Red test(s) first |
| --- | --- | --- |
| S0 | Tests only: §6's three goldens. | Green by design; red shown by a one-byte local edit. |
| S1 | `SettingsRefusal` with `Version`, `TtlBelowFloor`, `TtlAboveCeiling`, `HostsOutsideCookieDomain`, `LandingOffHosts`, `CallbackNotHttps`, `SocialHalfConfigured`, `AuditHeadersSame`, `ThemeUnknown`, plus a **temporary** `Other(String)` holding the prefixed sentence of every leaf not yet converted; `Display`, `code()` (`Other` is `"other"`); `PrepareError` and its `From`; `compile_settings`, `prepare` change type; the GUI's `prepare` call takes `.to_string()` before its existing sniff (unchanged behaviour). | `compile_settings_names_its_refusal` (`matches!(…, SettingsRefusal::LandingOffHosts)`, and one TTL case), `prepare_error_becomes_the_same_string`. |
| S2 | `ClaimCharset`, `ClaimEmptyPart`, `ClaimConsumed`, `ClaimHeaderReserved`, `ClaimsCollide`, `AttrUnknown`, `AttrTwice`, `AttrNone`; the private `prefix()`/`sentence()` pair; `compile_profile_claims` and `compile_identity_attrs` become wrappers. | `claim_and_attribute_refusals_are_codes`. |
| S3 | `SettingKey`, `UrlFault`, `Url`; private cores behind `compile_page_url`, `compile_issuer`, `compile_asset_url`. | `url_refusals_name_the_setting_and_the_fault` (login, landing, issuer, callback, logo). |
| S4 | `AppClientId`, `CookieDomainNotBare`, `CookieDomainSingleLabel`, `HostControlByte`, `HostNotBare`, `HostAtOrDotDot`, `OauthDomainNotBare`; wrappers for the four leaves. | `domain_host_and_client_refusals_are_codes`. |
| S5 | `ButtonBareName`, `ButtonNoIdp`, `ButtonIdpCharset`, `ButtonTwice`, `ButtonNoAudience` (`AppClientId { button: Some }` already exists); `compile_social_buttons` returns `SettingsRefusal`. | `social_button_refusals_are_codes`. |
| S6 | `HeaderFault`, `AuditHeader`, `AuditLimitNotAmount`, `AuditLimitZero`, `AuditLimitTooMuch`, `AuditUnbounded`; wrappers `compile_audit_header`, `AuditLimit::parse`, `AuditPolicy::new` (`compile_audit_policy` stays `String` for the CLI's `.replace("audit:", …)`). | `audit_refusals_are_codes`. |
| S7 | `BrandControl`, `BrandTooLong`; delete `Other`; `SETTINGS_REFUSAL_CODES`, `settings_refusal_samples()`. | `every_refusal_has_a_code_a_sample_and_a_sentence`; the golden test's codes-reached assertion. |
| S8 | GUI: `fill`, the `SetRef*` keys (§4), `setting_field`, `unit_label(Lang, …)`, `settings_refusal` (exhaustive), and the `prepare` call mapped through it with the `e.contains("landing_url")` sniff deleted. Update the existing test that asserts the English sentence, if any. | `every_settings_refusal_reads_in_both_languages`, `fill_is_single_pass`, `an_italian_settings_refusal_names_the_labels`, `a_claim_refusal_is_marked_on_its_field`. |
| S9 | GUI: `ConfigForm::apply` drops the checks that duplicate the library (and its two inline English `format!`s), keeping only its own stricter ones and the `.unwrap_or` normalisation (§5). Every existing attribution test (`f-hosts invalid`, `f-aud-… invalid`, …) stays green unedited. | `the_settings_form_says_a_stray_host_in_italian`, `the_settings_form_says_a_shared_audit_header_in_italian`. |

Checks per slice, per the table in AGENTS.md: S0 to S7 touch the library, so `cargo test`,
`cargo clippy --all-targets`, `cargo fmt --check` and `cargo doc --no-deps` (new intra-doc links
to `SettingsRefusal`); S8 and S9 add the `K` keys, so also `node e2e/run.js` and the
`config-landing-refused` scene, reviewed by the designer.

#### 8. Alternatives rejected (settings refusals)

- **Keep sniffing the English in the GUI** (extend `e.contains("landing_url")` to every
  sentence): it is the practice `Refusal`'s rustdoc forbids, and a reworded library sentence
  would silently move or drop the attribution.
- **Codes only in the library, the English moved into the CLI and the gate:** two binaries print
  these sentences, so that is two copies of each, which is the drift the library exists to end.
- **The library returns translated text, or `K` keys:** the library has no language, and the
  Displayed text rule gives the `K` table as the one home of what the GUI shows.
- **`thiserror` / `strum` for `Display` and iteration:** a dependency to save two hand-written
  matches, against the rule that keeps the tree small and checked after every bump; the
  exhaustive matches are the coverage guarantee anyway.
- **Change every leaf to return the typed error:** the access file's parser and the CLI's
  flag-named pre-checks call those leaves and edit their strings, so the change would reach the
  access file's error path, which nobody asked to change.
- **Translate the five file-only codes too:** ten strings no reader of the page can reach; the
  English is what the operator meets at the shell.
- **One route test per code:** the mapping is pure; one route test per path proves the wiring.
- **A fully flat enum** (each URL fault times seven settings): forty-odd arms that repeat one
  tail; and a fully nested one (a fault type per setting) is more types than a small model can
  hold. Nested only where a leaf is shared with a caller that names the setting itself.

#### 9. Open questions for the user (settings refusals)

None blocks the slices. Two are worth a look in the morning: the wording in §4, which the
designer reviewed and rewrote on 2026-11-26 (see the list above its table; the TTL keys now take
the floor or ceiling and not the value, and the older fragment-style keys are reworded in §10); and whether the
CLI should one day name its flags in these refusals the way it already does in its pre-checks
is left alone here, because the user asked for its bytes to stay as they are.

#### 10. S10: the page's own refusals

Designed by the designer on 2026-11-26, after S9 (`0e3db28`). What was read: `ConfigForm::apply`,
the `Route::Config` arm of `mutate` (the confirmation of guarded changes included),
`settings_refusal`, `settings_group_of`, `social_choices`, `page_config`, `Route::title`, the
`GET /config` branch of the request handler, the file-error branch that reads `web.admins`, and
every `K` entry named below, in both languages, at `0e3db28`. Nothing was rendered for this
section: it changes words, and §4's register was already reviewed on screen after S8.

**What the page can refuse on its own.** Nine messages, all raised by `ConfigForm::apply` except
the last, which the library raises and `settings_refusal` maps onto the page's own key. The
confirmation of guarded changes raises no refusal: a token that does not match re-shows the
confirmation, which is a step and not an error. The rest of the `POST`'s failures are not field
refusals and stay as they are: a stale `rev` is the shared `page_conflict` (a `409` on every
page), and a settings file broken on disk or a failed write is shown in the gate's English, for
the reason §5 gives.

| Field (`name=`) | Raised by | Key today | Key after S10 | Shared with |
| --- | --- | --- | --- | --- |
| `ttl` | `apply` | `SessionTtlBad` | `SessionTtlBad` | nothing |
| `admins` (empty) | `apply` | `AdminsNeverEmpty` | **`SetRefAdminsNone`** (new) | `AdminsNeverEmpty` is also the 500 page for a settings file with no administrators |
| `admins` (yourself) | `apply` | `AdminsKeepYourself` | **`SetRefAdminsSelf`** (new) | `AdminsKeepYourself` is also the Administrators help text, in brackets |
| `client_id` | `apply` | `ClientIdNeeded` | `ClientIdNeeded` | nothing |
| `aud-<idp>` | `apply` and `settings_refusal` (`button_no_audience`) | `AudienceNeeded` | `AudienceNeeded` | nothing outside this page |
| `issuer` | `apply` | `IssuerNeeded` | `IssuerNeeded` | nothing |
| `hosts` | `apply` | `AuthorizedHostsNeeded` | `AuthorizedHostsNeeded` | nothing |
| `ui_theme` | `apply` and `settings_refusal` (`theme_unknown`) | `DefaultThemeBad` | `DefaultThemeBad` | nothing outside this page |
| `domain` | `settings_refusal` (`social_half_configured`) | `SocialWiringNeeded` | `SocialWiringNeeded` | nothing outside this page |

No key here is used by the access-file pages or by `/account`. **Two are shared inside this
binary and are split, not reworded**, because their other use reads correctly as it is and
would read wrongly with a label in front: `AdminsNeverEmpty` follows a file path on the
file-error page (`settings.json: at least one administrator is required: …`), which is the
register of a shell message, and `AdminsKeepYourself` sits in brackets after the
Administrators help text, where "Administrators:" would repeat the label printed just above it.
Both keep their key and their words; `apply` moves to the two new keys. The seven others are
reworded in place, and every call site of them (the eight `apply` refusals and the three
`settings_refusal` arms) goes through `fill`.

**The words.** The register is §4's: the visible label first, then a colon, then what is
allowed, ending with a full stop; `{0}` is `t(lang, label)` so a renamed label carries. The two
app client rows have no label of their own, so they start the way `SetRefAppClientId` already
does, with "App client for" and the row's heading (`t(lang, K::SignInEmail)`, or
`social_idp_label(idp)` for a provider). "Sign-in" replaces "login", which the page does not say
anywhere else.

| `K` key | `{…}` | English | Italian |
| --- | --- | --- | --- |
| `SessionTtlBad` | `SessionTtl` | `{0}: must be a whole number of seconds, such as 2592000 for 30 days.` | `{0}: deve essere un numero intero di secondi, come 2592000 per 30 giorni.` |
| `SetRefAdminsNone` | `Admins` | `{0}: at least one is needed; an empty list must never come to mean 'everyone'.` | `{0}: ne serve almeno uno; una lista vuota non deve mai finire per significare 'chiunque'.` |
| `SetRefAdminsSelf` | `Admins` | `{0}: your own address must stay on the list; to remove yourself, use bb-auth-adm over SSH.` | `{0}: il tuo indirizzo deve restare nella lista; per rimuovere te stesso usa bb-auth-adm via SSH.` |
| `ClientIdNeeded` | `SignInEmail` | `App client for {0}: cannot be empty; without one, no sign-in can complete. It is the Cognito app client the sign-in page signs people in against.` | `App client per {0}: non può essere vuoto; senza, nessun accesso può concludersi. È l'app client Cognito con cui la pagina di accesso fa entrare le persone.` |
| `AudienceNeeded` | provider label | `App client for {0}: this provider needs its own, because Cognito federates per app client; name the one that offers this provider.` | `App client per {0}: questo provider ha bisogno del proprio, perché Cognito federa per app client; indica quello che offre questo provider.` |
| `IssuerNeeded` | `Issuer` | `{0}: cannot be empty; without one, no token can be validated and no sign-in can complete.` | `{0}: non può essere vuoto; senza, nessun token può essere validato e nessun accesso può concludersi.` |
| `AuthorizedHostsNeeded` | `AuthorizedHosts` | `{0}: at least one is needed; without one, every redirect after sign-in is refused and everybody lands back on the sign-in page.` | `{0}: ne serve almeno uno; senza, ogni redirect dopo l'accesso viene rifiutato e tutti tornano alla pagina di accesso.` |
| `DefaultThemeBad` | `DefaultTheme` | `{0}: choose one of the options in the list; this request carried a value the list does not offer.` | `{0}: scegli una delle opzioni dell'elenco; questa richiesta portava un valore che l'elenco non offre.` |
| `SocialWiringNeeded` | `OauthDomain`, `SocialCallback` | `{0} and {1}: a social button needs both; without them there is nowhere to send a visitor and nowhere for them to come back to.` | `{0} e {1}: un pulsante social ha bisogno di entrambi; senza, non c'è dove mandare chi entra né dove farlo tornare.` |

`DefaultThemeBad` no longer lists `light, dark, system`: those are the file's codes, and the list
box shows "Light", "Dark" and the system option in the reader's language, so the codes were wire
words on the page. Only a request this form did not build can carry another value, which is what
the sentence now says. `SocialWiringNeeded` names both labels because the library does not say
which of the two is empty; it still marks `domain`, as today.

**Two attribution faults found on the way, fixed in the same slice.** `apply` refuses the theme
on `"theme"`, but the list box is `name="ui_theme"` and `settings_refusal` already says
`"ui_theme"`: `apply` moves to `"ui_theme"`. And `settings_group_of` lists `"theme"`, so a theme
refusal on `"ui_theme"` opens the sign-in group instead of the one holding the list box: the arm
names `"ui_theme"`. Both can only be reached by a forged request; they are fixed because the
walk below would otherwise have to encode the wrong group.

**Accents written as apostrophes.** The rule a test can check is stated under the tests. Against
all 457 `K` entries at `0e3db28` it finds 22 occurrences in five keys, all genuine, and nothing
else. `AudienceNeeded` has none. `ClientIdNeeded` and `SocialWiringNeeded` are fixed by their
rewording above; the three help texts change only where listed.

| Key | Old | New |
| --- | --- | --- |
| `GlobalLoginUrlHelp` | `che e' quello` | `che è quello` |
| `GlobalLoginUrlHelp` | `Una applicazione puo' sovrascriverla` | `Una applicazione può sovrascriverla` |
| `GlobalDeniedUrlHelp` | `qui non e' ammesso` | `qui non è ammesso` |
| `GlobalDeniedUrlHelp` | `Non puo' chiudere` | `Non può chiudere` |
| `GlobalDeniedUrlHelp` | `chi e' gia' stato respinto` (two) | `chi è già stato respinto` |
| `GlobalDeniedUrlHelp` | `Una applicazione puo' sovrascriverla` | `Una applicazione può sovrascriverla` |
| `GlobalDeniedUrlHelp` | `ed e' cosi' che` (two) | `ed è così che` |
| `GlobalDeniedUrlHelp` | `un solo gate da' a ogni host` | `un solo gate dà a ogni host` |
| `ClientIdNeeded` | `puo' concludersi. E' l'app client` (two) | as in the table of words above |
| `SocialWiringNeeded` | `non c'e' dove … ne' dove` (two) | as in the table of words above |
| `SocialWaysHelp` | `Email e codice e' sempre offerto ed e' l'app client` (two) | `Email e codice è sempre offerto ed è l'app client` |
| `SocialWaysHelp` | `solo se e' spuntato` | `solo se è spuntato` |
| `SocialWaysHelp` | `perche' Cognito federa` | `perché Cognito federa` |
| `SocialWaysHelp` | `per cui e' stato emesso` | `per cui è stato emesso` |
| `SocialWaysHelp` | `da qui non si puo' raggiungerne un altro` | removed with its sentence, see below |
| `SocialWaysHelp` | `Microsoft e' l'account personale` | `Microsoft è l'account personale` |
| `SocialWaysHelp` | `un tenant Entra ID e' un provider separato` | `un tenant Entra ID è un provider separato` |

**One sentence of `SocialWaysHelp` is no longer true, in both languages**, and it is in the
string being edited, so it is corrected here rather than left for later: "The pool they belong
to stays in the env file, so nothing here can reach another one." / "Il pool a cui appartengono
resta nel file env, quindi da qui non si può raggiungerne un altro." The pool has been
`gate.issuer` in the settings file since version 3, edited by the User pool (issuer) field at the
top of this same group. It becomes "They all belong to the User pool (issuer) above." /
"Appartengono tutti allo User pool (issuer) qui sopra."

**The refused page's title.** Every response to `/config` carries the title the `GET` carries,
`t(lang, K::Config)`: "System settings" / "Impostazioni di sistema", for a refusal (`400`), a
confirmation (`200`), a stale `rev` (`409`) and a broken file (`500`) alike. Today the `POST`
takes `Route::title`, which answers the untranslated "settings". That rule (a page is titled with
the file section an operator types) fits the access-file pages and not this one: the settings
file is a whole file in four sections, "settings" is a key in neither file, and the `GET`, the
`h1` and the account menu's row all already say "System settings". A browser tab or a screen
reader's page title that changes language and wording after a save is a page that seems to have
moved (WCAG 2.2 SC 2.4.2 Page Titled,
<https://www.w3.org/WAI/WCAG22/Understanding/page-titled.html>; Nielsen's fourth heuristic,
consistency).

#### 10a. Tests for S10 (the tester's names)

- **`every_config_refusal_starts_with_its_label`** (bb-auth-web, over the real router like the
  S9 tests). For each row of the first table, `POST /config` with a form built by
  `settings_fields` that triggers it, once with the `lang=en` cookie and once with `lang=it`:
  `ttl=abc`; `admins` blank; `admins=someone@else.com`; `client_id` blank; `issuer` blank; `hosts`
  blank; `idp-Google=on` with `aud-Google` blank; `ui_theme=purple`; and `idp-Google=on` with an
  app client and `domain` blank. Each answers `400`; the `div.err` text (not the whole body, which
  carries the help texts) starts with the expected label as the page prints it in that language
  (`Session lifetime` / `Durata della sessione`, `Administrators` / `Amministratori`, `App client
  for Email and code` / `App client per Email e codice`, `App client for Google` / `App client
  per Google`, `User pool (issuer)`, `Authorized hosts` / `Host autorizzati`, `Default
  appearance` / `Aspetto predefinito`, `Hosted UI domain and Callback URL` / `Dominio della
  hosted UI e URL di callback`) followed by `:`, ends with `.`, holds no `{` followed by a digit,
  and differs between the two languages; the field named in the first column is the one marked
  `invalid` with `aria-describedby="form-error"` (except `ui_theme`, whose list box is not marked:
  its group `g-look` is asserted `open` instead, on plain `/config` without `?groups=open`). The
  two admins rows assert the new keys' text and that the help text still reads "you cannot
  remove yourself here" / "non puoi rimuovere te stesso da qui".
- **`every_settings_refusal_reads_in_both_languages`** gains one assertion: for every code that
  is not file-only, the message starts with the label of the field its `Refusal` marks, using the
  same field-to-label map as the walk above (extended to the library's fields), so the three
  library arms that reuse the page's keys are held to the same rule.
- **`italian_k_strings_write_accents_as_letters`** (bb-auth-web, unit). It walks the Italian of
  every `K` entry. `K` has no list of its variants and none is added for a test: the test reads
  its own file with `include_str!("bb-auth-web.rs")`, takes the body of `fn t(lang: Lang, key:
  K)`, and from each `m(lang, "…", "…")` the third argument, unescaped as Rust does (a `\` at a
  line end drops the newline and the next line's leading spaces; `\"`, `\\` and `\u{…}` become
  their characters). The rule, exactly: an apostrophe `'` (U+0027) is a fault when the character
  before it is one of `a e i o u A E I O U` and the character after it is not a letter (a space,
  punctuation, or the end of the string), **unless it closes a quotation**, where a quotation is
  opened by a `'` at the start of the string or right after a space or `(`, and closed by the next
  `'` that is followed by a non-letter. The failure names the key and the text around the fault.
  Red on today's table with exactly the 22 occurrences listed above.
- **`the_accent_rule_flags_only_apostrophe_accents`** (unit, over the rule's function alone):
  it flags `puo' x`, `c'e' x`, `ne' dove`, `È bene. E' l`, `da' a`, `perche'.`, `gia'`; it does not
  flag `l'Header`, `un'email`, `dell'URL`, `'chiunque'`, `'solo questi',`, `'@nome'`,
  `('tutti gli ambiti')`, or the typographic `un’email`. This is what keeps the walk from being
  satisfied by a rule that flags nothing.
- **`a_refused_settings_save_keeps_the_page_title`** (bb-auth-web, over the router): the `<title>`
  of a `400` (`ttl=abc`), of a confirmation `200` (an `issuer` change) and of a `409` (a stale
  `rev`) on `/config` equals the `GET`'s, in English and in Italian: `System settings` /
  `Impostazioni di sistema`.
- **Existing tests whose assertion is the old wording**: the admins test around line 15052 asserts
  `"at least one administrator"` on the refused page and moves to the new `SetRefAdminsNone` text
  in its `div.err`; the one at 15042 (`"cannot remove yourself"`) passes on the help text alone
  and should assert the `div.err` instead. No other test spells these keys' English.
- **What a person sees**: the designer reviews an Italian refusal of the page's own (`ttl=abc`)
  from a scratch probe on plain `/config` (the `config-*` scenes force every group open), plus
  the help texts of the sign-in group in Italian, before the slice closes. No new `shots.js`
  scene: `config-landing-refused` already shows the register on screen.

### 13.32 Deleting the account signs the person out (plan step 14, designed 2026-11-26)

Asked by the user on 2026-11-26, after the first real self-service deletion on rpi-01: the
roster row and the key went (the key answered `401`), the owner's worker deleted the Cognito
user, and the done page then said "This browser stays signed in until you sign out, so sign out
now." Confirming the deletion should sign the person out by itself. A second finding from the
same run: the session cookie is stateless and lives `gate.session_ttl_secs` (30 days there), so
any `authenticated` scope keeps admitting the deleted identity, in every browser that holds such
a cookie, until it expires.

**What was read.** `account_delete_post` and `page_account_delete_outcome`
(`src/bin/bb-auth-web.rs`), `logout_without_rd` and `Config::account_logout_url`; the gate's
`handle_logout`, `logout_target`, `safe_rd`, `rd_candidate`, `build_cookie`, `make_session` /
`verify_session`, `handle_login` / `login_rd` / `login_page` and `src/assets/login.html`; the
README's logout recipe (`location = /auth/logout`, `X-Original-URL` needed only for a relative
`rd`); `e2e/lib/server.js` (`BB_AUTH_WEB_LOGOUT_URL: '/auth/logout'`) and the `account-delete-*`
scenes; §13.29 W3 and W6, §13.30 §4. rpi-01's nginx and settings were **not** read (no SSH host
key in this session): what they must hold is listed under 14d as a read for the coordinator.

#### 1. Decision for this browser: the success answer is a `303` through the gate's logout

On the one outcome where every address was queued (§13.29 W6, the `200` rows of §13.30 §4), and
only where `BB_AUTH_WEB_LOGOUT_URL` is set, the `POST` answers

```text
303 See Other
Location: <account_logout_url> ? or & rd=%2Fauth%2Flogin%3Fnotice%3Daccount-deleted
```

and renders no page. The browser follows with a `GET` (RFC 9110 §15.4.4, not re-read this
session; the console's preference write already relies on a redirect after a submit), the gate's
`/auth/logout` clears the cookie with the same `(name, Domain, Path)` it was minted with
(`build_cookie`), records the sign-out in the audit as every logout does, and sends the browser to
its own sign-in page with a notice that says what was queued. The person never sees a page that
asks them to sign out, because by the time a page is drawn they are signed out.

- **Why the gate clears it, not bb-auth-web.** The gate is the only program that knows the
  cookie's name and the only one that builds the clearing `Set-Cookie`; a second builder is the
  drift `build_cookie`'s rustdoc warns about (a clear whose `Domain` or `Path` differs from the
  mint's "silently succeeds at nothing").
- **Why `rd` names the gate's own page, always, and not `gate.login_url`.** Only the gate's page
  understands the notice, and it is a page every deployment already routes ungated (AGENTS.md:
  "nginx must leave all three page locations ungated"). An operator's own sign-in page would land
  the person signed out with nothing said.
- **Why relative.** bb-auth-web knows neither its scheme nor its host (`logout_without_rd`'s
  rustdoc). The logout's `safe_rd` resolves a relative `rd` against `X-Original-URL` on the logout
  location, which the README's recipe sets. Without it the gate falls back to the login page
  (`logout_target`): the person is still signed out and only the notice is lost, which is
  fail-soft and is what 14d checks on rpi-01.
- **Why only on full success.** Every partial outcome (§13.30 §4: the first `POST` refused or
  unanswered, some queued) offers "Try again", and the retry is the stranger's walk over the
  header's addresses, which needs the session. Those pages keep their "Sign out" pill and their
  words. With no logout URL configured the done page stays what it is (`K::AccountDeletedClose`,
  no pill): there is nowhere to send the browser.
- **The notice is a closed set of one.** `/auth/login?notice=account-deleted` shows one fixed
  paragraph from `login.html`; any other value, or none, shows nothing, and no byte of the query
  reaches the page. That keeps AGENTS.md's "request data reaches a page in exactly one place,
  `data-rd`" true in substance (a code selects a fixed element, nothing is reflected), and the
  sentence there gains that clause (docs, 14c). The page itself is unchanged otherwise: the form
  is there, since a person whose Cognito user is not yet deleted can still sign in, and the notice
  says so.
- **What both programs must agree on**, by the library's membership rule: the path
  `/auth/login` and the code `account-deleted`. Two `pub const`s in `bb_auth_core`
  (`GATE_LOGIN_PATH`, `LOGIN_NOTICE_ACCOUNT_DELETED`); the gate's `OWN_LOGIN_PATH` becomes the
  library's, and bb-auth-web builds the `rd` from both.

Alternatives rejected:

| Option | What it costs | Why not |
|---|---|---|
| (b) bb-auth-web clears the cookie itself | the cookie's name in a second env file, and a second builder of the clearing `Set-Cookie` | two copies of `BB_AUTH_COOKIE_NAME` drift with nothing to catch it; a clear that differs in `Domain`/`Path` does nothing and says nothing; bb-auth-web is "just another app bb-auth fronts", and no app touches the gate's cookie |
| (c) the done page with `<meta http-equiv="refresh">` to the logout | no code in the gate | with a delay it fails WCAG 2.2.1, 2.2.4 and 3.2.5 (F41: the page changes under a person reading it); with no delay nobody reads the page, so it is (a) with an extra hop; and it is still a page asking a browser to do what an HTTP answer can |
| a script on the done page | one more inline script | W12 ("JavaScript is used sparingly"), and it does what (c) does |
| a hidden `img`/`iframe` loading `/auth/logout` | a CSP widening | a sign-out nobody can see happen, relying on a subresource's `Set-Cookie`; obscure for no gain over (a) |
| `rd` to a bb-auth-web page after the logout | an ungated route in bb-auth-web | every bb-auth-web request needs `X-Auth-Email` ("a missing header is a 401"); a signed-out person has none, and opening a route without it changes the trust model for one sentence |
| `rd` to `gate.landing_url` | nothing | on rpi-01 it is `/account/`, which is gated: a signed-out browser lands on the sign-in page with no notice |

#### 2. Decision for other browsers: accept the gap, and say so

Recommended: **accept it, state it in AGENTS.md and on the notice**, and build nothing, because
while self-signup is open the stale cookie grants nothing a stranger cannot get in a minute.

The argument, from what the gate decides with a cookie after the row is gone:

- `restricted` scopes admit nobody: the cookie's email resolves to no roster row, so it is a
  member of nothing (`ScopeRecord::members` are references to rows, and `remove_user` swept them).
- `excluded` entries naming the row were rewritten to its primary email, and `denied` matches a
  bare email, so every veto still applies to the stale cookie.
- The API keys went with the row (`401` measured on rpi-01).
- What is left is `anonymous` and `authenticated` scopes. `authenticated` admits any identity
  Cognito vouches for, and with self-signup open (AGENTS.md; `AllowAdminCreateUserOnly` false
  means "users can register themselves", Cognito API reference, AdminCreateUserConfigType) the
  deleted person can register the same email again at once and walk into exactly the same
  scopes. The stale cookie is therefore no wider than the front door.
- An id_token bearer works until its own `exp`, which is the pool's ID-token validity (not read
  here); the same argument covers it.

The premise is the one thing to watch: **if the pool becomes admin-create-only**, or an
`authenticated` scope starts to mean "people we once knew", the gap becomes real and the
tombstone below is the design to build.

Alternatives weighed:

| Option | What it costs | Verdict |
|---|---|---|
| a revocation the gate checks per request (session ids in a store) | a server-side store, its writer, its backup; breaks "Sessions are stateless" (any worker validates any cookie, a restart logs nobody out) | rejected: an invariant traded for a gap no wider than self-signup |
| the email into `denied` | nothing to build | rejected: `denied` is permanent and blocks a re-registration with that email for ever, and is never lifted by design (§13.29) |
| **a tombstone**: a time-bounded section of the access file, `{email, at}`, written by `remove_user`'s self-service caller; the gate refuses a cookie for that email minted before `at` (an `iat` key added to the cookie's claims object, which is no `COOKIE_VERSION` bump, §13.25), and a cookie with no `iat` for that email; editors drop entries older than `at + session_ttl` | a schema change (version 2 of the access file or a tolerated top-level key, read by three programs), an `iat` in every cookie, a check on the validate path, pruning in both editors, and its tests | stateless (it is the access file, re-read per request like `denied`), so no invariant breaks; **the design to build if the premise above fails**, not now |
| a shorter `gate.session_ttl_secs` on rpi-01 | more sign-ins for everybody; no code | narrows the gap, closes nothing; an operator's choice, not a fix |
| accept, and say so | one AGENTS.md paragraph, one sentence on the notice | **recommended** |

#### 3. What changes for the designer

The designer's answers (the notice's words, its place and markup, the rows that replace the
done page) are §13.33; where they differ from the bullets below, §13.33 holds.

- **The success page of §13.30 §4 is gone** where a logout URL is set: the two `200` rows
  (roster, stranger) become "`303` to the logout, then the sign-in page with the notice". Their
  words move to the notice, in `login.html` (English in the element, Italian in the page's
  `i18n` dictionary under one key, e.g. `notice_account_deleted`), not in `K`.
- **One sentence for both rows.** The notice cannot tell a roster caller from a stranger (one
  code, nothing reflected), so it says what is true for both: the sign-in accounts are queued
  for deletion, this browser is signed out, and if signing in still works later, tell an
  administrator. `K::AccountDeleteNowGone` (keys and named access gone) is not on it; the
  confirmation page already said what goes. If the designer wants the roster half back, a second
  code is cheap and is the only change; say so before 14a.
- **The gap's sentence**: other browsers where the person signed in stay signed in until they
  sign out there or the session ends. Whether it carries the session length is the designer's
  call (the gate knows `session_ttl`; a number means formatting days in two languages).
- `K::AccountDeletedSignOut` goes (nothing renders it); `K::AccountDeletedClose` stays for the
  no-logout-URL page. The partial pages' wording is unchanged.
- The notice is a status message on a page whose job is a form: `role="status"`, above the form,
  the components `BASE_CSS` already has for a message. It is hidden with the `hidden` attribute,
  so `AUTH_CSS` needs a `[hidden]{display:none}` rule (the operator's stylesheet loads later and
  can override `hidden` with a `display` rule).

#### 4. Slices and tests

**14a. The gate's notice** (`src/lib.rs`, `src/bin/bb-auth.rs`, `src/assets/login.html`,
`src/assets/auth.css`). Red first:

- `the_sign_in_page_shows_the_deletion_notice_only_for_its_code` (gate, over `login_page`): with
  `notice=account-deleted` the notice element has no `hidden`; with no `notice`, `notice=other`,
  `notice=` and `notice=<script>x</script>` it carries `hidden`, and in every case the page bytes
  contain no part of the query beyond the fixed element.
- `the_deletion_notice_speaks_both_languages` (gate): the element's `data-i18n` key is in both
  arms of the page's dictionary, and the English text in the element equals the `en` arm.
- `the_login_path_is_the_librarys` (gate): `global_login` of an empty `gate.login_url` equals
  `bb_auth_core::GATE_LOGIN_PATH` (pins the move of `OWN_LOGIN_PATH`).
- `a_logout_with_the_deletion_rd_clears_and_lands_on_the_notice` (gate, router over a socket):
  `GET /auth/logout?rd=%2Fauth%2Flogin%3Fnotice%3Daccount-deleted` with `X-Original-URL` on an
  authorized host and `Sec-Fetch-Site: same-origin` answers `302` to
  `https://<host>/auth/login?notice=account-deleted` and a `Set-Cookie` with `Max-Age=0`, the
  configured `Domain` and `Path=/`; without `X-Original-URL` it still clears and lands on the
  login page (the fail-soft half).
- Checks: `cargo test`, clippy, fmt, and a look at `/auth/login?notice=account-deleted` in a
  browser, both languages (AGENTS.md: `src/assets/*.html` and `auth.css`).

**14b. The `303`** (`src/bin/bb-auth-web.rs`). Red first:

- `a_complete_deletion_answers_with_the_gates_logout` (web, router, fake intake): roster and
  stranger, both languages: status `303`, `Location` equals
  `/auth/logout?rd=%2Fauth%2Flogin%3Fnotice%3Daccount-deleted`, built from the two library
  constants; the roster's row is gone from the file and the journal still carries `user rm` and
  `N queued`.
- `the_deletion_rd_is_added_to_the_operators_query` (web, unit over the builder): an operator URL
  `https://auth.x.com/auth/logout?x=1&rd=/admin#f` gives
  `https://auth.x.com/auth/logout?x=1&rd=%2Fauth%2Flogin%3Fnotice%3Daccount-deleted#f` (the
  console's `rd` dropped by `logout_without_rd`, ours added once).
- `with_no_logout_url_the_done_page_stays` (web): `account_logout_url = None`, every `POST` `202`:
  `200`, the queued title, `Queued` + `AccountDeletedClose`, no pill. This replaces
  `the_done_page_says_queued_and_links_to_sign_out`, whose logout-set half becomes the first test.
- `a_partial_deletion_does_not_sign_out` (web): first `POST` `503` after the row went: `502`, no
  `Location`, pills "Try again" and "Sign out" (the existing 7e table test's partial rows already
  pin the words; this pins the absence of the redirect).
- The 7e `h1` table test's two done rows move to the `303` assertion; `DELETE_SIGN_OUT_*` and
  `K::AccountDeletedSignOut` go.
- Checks: `cargo test`, clippy, fmt, `node e2e/run.js`.

**14c. Browser suite and docs.** `e2e/run.js` (delete area): the queued walk ends on a request
to `/auth/logout?rd=…` (the suite runs bb-auth-web alone, so assert the navigation's URL, not the
gate's page). `e2e/shots.js`: `account-delete-queued` is retired for the logout-set view, or kept
by starting that scene with no logout URL (the `Close` page), the designer's choice; the notice
itself is reviewed by hand on `/auth/login`. Docs: AGENTS.md's self-service paragraph (the
deletion answers with the gate's logout), the `data-rd` sentence (the closed-set notice), and a
paragraph under "Sessions are stateless" stating the accepted gap and its premise; §13.30 §4's two
`200` rows marked changed by this section.

**14d. On rpi-01**, each with the user's go-ahead. Reads first, for the coordinator to hand over:
`sudo nginx -T | grep -n -A8 'auth/logout'` (does the logout location set `X-Original-URL`?),
`sudo grep LOGOUT_URL /opt/bb-auth/etc/bb-auth-web.env`, `sudo bb-auth-adm settings show`
(`gate.login_url`, `gate.cookie_domain`, `gate.session_ttl_secs`), and the pool's
`AllowAdminCreateUserOnly` through the OpenTofu repository named in step 5 (the premise of §2).
Then a new test account deleted in a browser: it lands on the sign-in page with the notice, and
the browser's next request to an `authenticated` scope goes to the sign-in page.

#### 5. The user's answers (2026-11-26)

The user chose the recommended answers ("applica solo il raccomandato"):

1. **The stale cookies in other browsers: the gap is accepted**, stated in AGENTS.md and on the
   notice, and valid while self-signup is open. The tombstone of §2 stays a design for the day that
   premise fails.
2. **`gate.session_ttl_secs` on rpi-01 stays at 30 days.**

The success answer through the gate's logout (§1) is the recommended one too. The line in rpi-01's
nginx that makes the notice show (`X-Original-URL` on `location = /auth/logout`) is part of 14d,
with the user's go-ahead.

### 13.33 The deletion notice on the sign-in page (plan step 14, designed 2026-11-26)

The designer's half of §13.32 §3. **What was looked at:** `src/assets/login.html` (its `.brand`,
the `#msg` box with `role="alert"`, the `autofocus` email field, `applyLang`, which sets each
`[data-i18n]` element's `textContent`), `src/assets/auth.css` (`.msg{display:none}` and
`.msg.show{display:block}`), `src/assets/base.css` (`.msg.ok`, the bordered box with the `--ok`
left rule), the `K::AccountDelete*` keys in `src/bin/bb-auth-web.rs`, `build_cookie` in
`src/bin/bb-auth.rs` (the cookie carries `Max-Age`, so it is persistent), and a mockup:
`/tmp/d14/gen.js` fills `login.html` with the three real stylesheets plus the one rule below and
shoots it (`/tmp/d14/notice-{en,it}-{light,dark}-{1280,360}.png`, and light at 320; no sideways
scroll at any width).

#### 1. The words (deletion notice)

One paragraph, the same for a roster user and a stranger, since one code reflects nothing about
who arrived:

- **English** (the text in the element): "Your account is being deleted: this browser is signed
  out, and your sign-in accounts are queued for deletion. Signing in again later creates a new
  account; if you use an email code and are not asked to sign up first, tell an administrator.
  Other browsers where you signed in stay signed in until
  you sign out there or the session ends."
- **Italian** (`i18n.it.notice_account_deleted`): "Il tuo account è in fase di eliminazione:
  questo browser è disconnesso e i tuoi account di accesso sono in coda per l'eliminazione. Se
  accedi di nuovo più avanti viene creato un nuovo account; se usi un codice via email e non ti
  viene chiesto prima di registrarti, avvisa un amministratore. Gli altri
  browser in cui avevi effettuato l'accesso restano connessi finché non esci da lì o la sessione
  non termina."

Why these words:

- **Queued, never deleted**, for the Cognito half (the user's rule, §13.29 W6). "Is being deleted"
  is the done page's own title (`K::AccountDeleteQueuedTitle`), so the person reads the same
  claim they would have read there, and the rest is `K::AccountDeleteQueued` without "This page
  cannot tell when", which a sign-in page has no reason to say.
- **"without signing up again"** is new and needed here: this page creates an account on the fly
  for an email it does not know, so after a deletion typing the same email *should* succeed, as a
  registration. Only the old account signing straight in means the deletion service did not act,
  and that is the case the administrator must hear of.
- **"if you use an email code"** narrows that check to the one kind of account it fits (slice
  14e, 2026-11-26). A Google or Microsoft sign-in recreates the Cognito user at once, which is no
  fault, and the page cannot say which kind was deleted (one fixed code, no request data), so the
  first clause is true for both ("creates a new account") and only the second, conditional on the
  email code, asks for an administrator. "Asked to sign up" names what the person sees, the
  page's own `register_intro` step, rather than what Cognito did.
- **The gap's sentence** is the last one, because it is the least likely to matter (§13.32 §2,
  accepted by the user on 2026-11-26). It names what the person can do about it (sign out there)
  and carries **no session length**: the number is per deployment, would be a substitution into a
  page whose notice is otherwise fixed bytes, and needs day plurals in two languages; "the session
  ends" is true everywhere. Rejected for the same reason: a second code for the roster half
  (`K::AccountDeleteNowGone`). The confirmation page already listed what goes, and a second code is
  a second sentence to keep true for no new decision.
- **Not "close your browser".** The cookie has `Max-Age` (`build_cookie`), so it outlives a closed
  browser. `K::AccountDeletedClose` says the opposite today and is false; its replacement is in §3.

#### 2. Where it sits, and its markup (deletion notice)

```html
<p id="notice" class="msg ok show" role="status" data-i18n="notice_account_deleted"__BB_NOTICE_HIDDEN__>…English…</p>
```

- **Between `.brand` and `#msg`**, so the card reads brand, what just happened, then the form. Not
  inside `#msg`: the script empties that box on every step, and its `role="alert"` would make an
  arrival read as an error.
- **`.msg.ok`** from `BASE_CSS`: the box the page already has for a message, in its success arm.
  Not `.warn`: nothing went wrong, and the one thing to act on is conditional. `show` is static,
  because `auth.css` hides a bare `.msg`.
- **`hidden` unless the code matches**: `__BB_NOTICE_HIDDEN__` is a space and `hidden`, or empty. `AUTH_CSS`
  gains one rule, placed **after** `.msg.show`: `.msg[hidden]{display:none}`. A bare
  `[hidden]{display:none}` (§13.32 §3) is not enough: `.msg.show` (two classes) outranks one
  attribute selector, so the notice would show for every visitor. The two have equal specificity
  (0,2,0) and the later wins.
- **Reaching a screen reader.** The email field has `autofocus`, so focus lands below the notice
  and a screen-reader user starts past it; and a live region's content present at load is not
  announced, only later changes (MDN, ARIA live regions:
  <https://developer.mozilla.org/en-US/docs/Web/Accessibility/ARIA/Guides/Live_regions>, not
  re-read this session). So when the code matches the email input also gets
  `aria-describedby="notice"` (`__BB_NOTICE_DESCRIBEDBY__`, a space and `aria-describedby="notice"`, or empty),
  read when the field takes focus
  (<https://developer.mozilla.org/en-US/docs/Web/Accessibility/ARIA/Reference/Attributes/aria-describedby>).
  It must not be there unconditionally: a `hidden` element referenced by `aria-describedby` is
  still read (Accessible Name and Description Computation 1.2, step 2A,
  <https://www.w3.org/TR/accname-1.2/>). `role="status"` stays, harmless, as §13.32 §3 asked.
  Both placeholders are fixed strings chosen by `notice == "account-deleted"`, so no byte of the
  query reaches the page. Trade-off: the field's description is long for one visit; the
  alternative, dropping `autofocus` when the notice shows, costs every sighted person a click.

#### 3. What replaces the two `200` rows of §13.30 §4 (deletion notice)

| Case | Logout URL set | Logout URL unset |
|---|---|---|
| every `POST` `202`, roster | `303` to `/auth/logout?rd=…notice=account-deleted`; the person lands on §2 | `200`, `AccountDeleteQueuedTitle`, `NowGone` + `Queued` + `AccountDeletedClose`, no pill |
| every `POST` `202`, stranger | the same `303` | `200`, `AccountDeleteQueuedTitle`, `Queued` + `AccountDeletedClose`, no pill |

`K::AccountDeletedSignOut` goes. `K::AccountDeletedClose` is reworded, because the cookie
outlives a closed browser: "This browser stays signed in until the session ends." / "Questo
browser resta connesso finché la sessione non termina." Every partial row is unchanged, pills
included.

#### 4. Tests and scenes (deletion notice)

- §13.32 14a's `the_sign_in_page_shows_the_deletion_notice_only_for_its_code` also asserts the
  email input carries `aria-describedby="notice"` with the code and no `aria-describedby` without
  it, and that the notice precedes `id="msg"` in the bytes.
- `the_deletion_notice_speaks_both_languages`: the English and Italian strings above, verbatim.
- `the_auth_css_hides_a_hidden_message` (gate, over `AUTH_CSS`): `.msg[hidden]{display:none}`
  appears after `.msg.show{display:block}`.
- `with_no_logout_url_the_done_page_stays` asserts the reworded `AccountDeletedClose` and that
  neither language contains "close" / "chiudi".
- `e2e/shots.js`: retire `account-delete-queued` (its page no longer exists in the shots' view,
  which sets a logout URL); the notice is reviewed by hand on `/auth/login?notice=account-deleted`
  in both languages, light and dark, and at 360.

### 13.34 Two menus in the bar: navigation and account (plan step 15, designed 2026-11-26)

The user's words of 2026-11-26: System settings belongs in the tab list beside Dashboard,
Applications, Users and Audit, where it was before §13.28; in the account menu it makes little
sense. Then, the same day, option B: **split the two jobs the account menu does.** The account
menu holds only the person's own things and is the same on both surfaces; the console's
navigation is all in the tab list, and at narrow widths it moves into a navigation menu of its
own, never into the account menu. And: the account menu is a different size on `/account/` and
on the console, against W13. Later the same day the user chose the tab's label: "Impostazioni"
in Italian, so "Settings" in English, replacing the "Sistema" / "System" first proposed here;
the breakpoint was remeasured for it (§0).

Kept from §13.28: one row at every width, `details` and no script, one header function for both
surfaces (`top_bar`), `/account/` with no navigation at all.

What was looked at: `PLAN.md` step 15; §13.28 (§0 measurements, §2 panel, §4 breakpoint, §9
tests); `shell_named`, `account_menu`, `top_bar`, `Route::tab`, `K::Config`,
`K::NotAdminToAccount` in `src/bin/bb-auth-web.rs`; the header and menu block and the 800 and
640 media blocks of `src/assets/admin.css`; `e2e/tests/settings.js`, `nojs.js`, `account.js` and
`e2e/shots.js` (`settings-menu`, `config-menu`, `account-menu`). `git show 3c6137c^` gives the
five-tab bar before §13.28: Config was the **last** tab, "Settings" / "Impostazioni".

#### 0. Measurements (two menus)

Measured on the real console (`e2e/lib/server.js`, Edge) with the proposed tab and rules
injected into the live page (`/tmp/d15/probe.js`, `/tmp/d15/ham.js`, `/tmp/d15/size.js`),
walking 320 to 1400 in 4px steps. "Fits" is §13.28 §0's test (one vertical centre, no sideways
scroll); "brand whole" adds that the brand's text is as wide as at 1400 and the name pill keeps
at least 128px.

Width of the tab strip: four tabs 349 EN / 340 IT (as §13.28 §0); plus "System settings" /
"Impostazioni di sistema" 486 / 528; plus "Settings" / "Impostazioni" 434 / 455; plus "System" /
"Sistema" 430 / 425.

First run, in 4px steps. Narrowest width with the brand whole, worst of {default brand, long
brand with logo} × {"Ada", "Bartholomew-Alexander Montgomery"}:

| Fifth tab | EN | IT |
|---|---|---|
| none (today) | 820 | 824 |
| "System" / "Sistema" | 900 | 908 |
| "Settings" / "Impostazioni" | 904 | 940 |
| "System settings" / "Impostazioni di sistema" | 956 | 992 |

With "Impostazioni di sistema" and a long name the brand is cut even at 1400, since `.bar` is
capped at 1000px: the full label leaves no room at any width. With "Sistema" and a 940px
breakpoint, every combination fits from 320 to 1400 with no fault, in both languages, light and
dark, the ☰ trigger included below 940.

**Remeasured for the chosen label, "Settings" / "Impostazioni"** (`/tmp/d15b/edge.js`: the same
real console, the same callers and the same test, walking 1100 down to 641 in **1px** steps, in
light and in dark, with the strip forced visible). Widest width at which the test still fails:

| Brand | Name | EN | IT |
|---|---|---|---|
| default, no logo | "Ada" | 722 | 759 |
| default, no logo | "Bartholomew-Alexander Montgomery" | 905 | **941** |
| "BadBat75 Estate Services" + logo | "Ada" | 798 | 821 |
| "BadBat75 Estate Services" + logo | "Bartholomew-Alexander Montgomery" | 875 | 892 |

Light and dark give the same figures. The strip is 436px in English and 459px in Italian. The
worst case is Italian, default brand, long name: whole from **942px**, so the breakpoint is
`max-width:941px`, with no margin, as the user asked for the smallest width that holds. (The
long brand is not the worst case because `.bar` is capped at 1000px, so that brand is already
cut at 1400 and "whole" means as wide as there.) One row and no sideways scroll alone never
fail above 641: the brand and the name truncate first, which is why the test is the brand whole
and the name pill at least 128px. With the ☰ rules and the 941 breakpoint injected
(`/tmp/d15b/ham.js`), every combination is one row with no sideways scroll from 320 to 1400, in
both languages, light and dark.

The account menu's size, same caller, same viewport: console `.menu` 230px wide at 1280 and 360;
`/account/` 286px at 1280 and 257px at 360. Same element, same classes, same ancestors
(`div.menu < details.settings < nav.acct < div.bar < header.top`).

Mockups (proposed rules injected into the real console; the panel rows there show the full pill
border because the mockup's ☰ sits outside a `nav`, which §2 corrects):
`/tmp/d15b/ham-{en,it}-light-{1280-none,942-none,941-navmenu,941-acct,360-navmenu,360-acct,320-navmenu,320-acct}.png`
and `/tmp/d15b/ham-{en,it}-dark-{1280-none,360-navmenu,360-acct}.png` (the chosen label; the
first run's "Sistema" shots are under `/tmp/d15/`).

(Superseded by §10, plan step 17: without the console's tag line the breakpoint is
`max-width:883px`, measured the same way.)

#### 1. The tab list: five tabs, Settings last, labelled "Settings" / "Impostazioni"

- **Order**: Dashboard, Applications, Users, Audit, **Settings**. Last, where it was before
  §13.28, and for the reason AGENTS.md already gives: the first four are about who reaches what,
  and the system's configuration is the one place that is not.
- **Label**: a new key `K::ConfigTab`, "Settings" / "Impostazioni", the user's choice of
  2026-11-26 (it was the tab's label before §13.28). `K::Config` ("System settings" /
  "Impostazioni di sistema") stays the page's `h1` and title. The tab drops "system" / "di
  sistema" because the bar needs it: the full Italian label leaves the brand cut at every width
  (§0). A noun like the other four tabs, and the `h1` it opens spells it out (Nielsen 4,
  consistency: the tab's word is in the heading). It costs 34px in Italian over "Sistema", which
  moves the breakpoint from 908 measured to 941 (§0). What "Settings" says less than "System"
  (whose settings) is said by the heading and by the account menu calling the person's own
  choices "Preferences", a different word.
- **Current**: `Route::tab` already returns `Route::Config` for the Settings page, so the strip
  marks Settings `.pill.on` with `aria-current="page"` there, which §13.28 §4 could not do.
- **One loop**: the five come from the one `tabs` array in `shell_named`, emitted in the strip
  and in the navigation menu (§2) by the existing `tab_links` markup.

#### 2. Narrow widths: a navigation menu of its own

- **Breakpoint** (now 883px, §10): `@media (max-width:941px)` replaces `(max-width:800px)`: 942px is the narrowest
  width at which the measured worst case with "Impostazioni" keeps the brand whole (§0). No
  margin, by the user's choice of the smallest width that holds, so an operator's stylesheet with
  a wider font can cut the brand just above 941 (it truncates; the bar stays one row with no
  sideways scroll). A 960px window (half of a 1920 screen) keeps the tabs in the bar.
- **Markup**: a new first child of `.bar`, before the brand, on the console only (`v.admin`
  set): `nav class="navm"` holding `details class="settings navmenu" name="bar-menu"`, whose
  `summary class="pill ico"` holds the menu glyph (three lines, `svg aria-hidden="true"`), a
  `span.vh` with `K::NavMenu` and `title` equal to that text, and whose `div.menu` holds
  `div.menu-tabs` with the five tab links. A `nav` because it is navigation, which also gives
  the rows the quiet tab look of `nav .pill` exactly as in the account panel. The bar's strip
  gets a class, `nav class="tabs"`, so the breakpoint rule names it instead of
  `nav:not(.acct)`, which would now also hide `nav.navm`.
- **Order in the bar**: ☰, brand, (strip), account menu. Left because a navigation trigger at
  the start of a bar is the convention; first in the source too, so focus order follows what is
  seen (WCAG 2.4.3, <https://www.w3.org/WAI/WCAG22/Understanding/focus-order.html>).
- **CSS**: top level `nav.navm{display:none}`; in the 941 block `nav.tabs{display:none}` and
  `nav.navm{display:flex}`. `details.navmenu .menu{left:0;right:auto}` so the panel opens under
  its trigger. `.menu-tabs` is always `display:flex;flex-direction:column` (its `display:none`
  rule and its line in the media block go: it now lives only in `nav.navm`, which the media rule
  shows or hides whole). The `details.settings` class carries the open look and the §13.20 cover
  to the new trigger with no new rule.
- **Label and name**: icon only. `K::NavMenu` "Navigation menu" / "Menu di navigazione" in
  `span.vh` (a `summary` has no ARIA role, so hidden text and not `aria-label`,
  <https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/summary>). Visible text
  ("Menu") was weighed: three lines are the most widely recognised navigation glyph and the bar
  at 320 has no 45px to spare beside a logo and a name. Trade-off against Nielsen 6 (recognition
  over recall), which the glyph's convention and the `title` tooltip mitigate. Target at least
  30px tall at phone width (the phone block's `.bar .pill`), above WCAG 2.5.8's 24px
  (<https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html>).
- **One open at a time**: both outer `details` (`navmenu` and the account one) carry
  `name="bar-menu"`, which makes them an exclusive group: opening one closes the other, with no
  script (<https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/details#name>).
  Measured in Edge: with both opened, only the second stays open. A pointer cannot reach the
  other trigger anyway while the cover is up; `name` covers the keyboard (Tab to the other
  trigger, Enter). A browser without `name` support shows both panels, one under each end of
  the bar, which is harmless. The nested `details.prefs` gets **no** `name`, or opening
  Preferences would close the account menu it sits in.

#### 3. The account menu: only the person's own things, one object on both surfaces

Rows, in order: `p.who-full` (name and every address); on the console only, `div.menu-places`
with one row, "Go to your account" (`K::NotAdminToAccount`), then a rule; `details.prefs`
(Preferences); a rule and Sign out (when a logout URL is set); on `/account/` only, a rule and
"Delete account and all its data" (when the intake is set). **Moved out**: the four tab rows
(`div.menu-tabs`) and the System settings row, both to §1 and §2. Nothing else changes: same
`account_menu` function, same arguments, and `shell_named`'s `places` shrinks to the one link.
The console's `403` keeps no places, no ☰ and no tabs.

**Why the panel was two sizes**: `.menu` is absolutely positioned with `min-width:230px` and no
`width`, so it is shrink-to-fit and takes the width of its widest row. On `/account/` that row
is "Delete account and all its data" (286px at 1280, 257 at 360, where the phone font is
smaller); on the console every row fits in 230. Not a class, not a container, not CSS only one
surface gets: the content. **Fix**: `.menu{width:20rem;max-width:calc(100vw - 32px)}`, and the
`min-width` goes. 20rem holds the longest row on either surface in both languages, a long
address still wraps inside it (`overflow-wrap:anywhere`), and the cap keeps it on a 320 screen.
The navigation panel is the same `.menu` object and takes the same width.

#### 4. `/account/`

Unchanged apart from §3's width: no `nav.navm`, an empty strip, the same account menu.
`top_bar` gains one argument, `navm: Option<Markup>`, emitted first; `account_shell` passes
`None`. One header function for both surfaces, as W13 asks.

#### 5. `K` keys (two menus)

| Key | English | Italian | Use |
|---|---|---|---|
| `ConfigTab` (new) | Settings | Impostazioni | the fifth tab, in the strip and in the navigation menu |
| `NavMenu` (new) | Navigation menu | Menu di navigazione | the ☰ trigger's hidden name and `title` |

`K::Config` keeps its text and is now the Settings page's `h1` and title only.

#### 6. AGENTS.md sentences that change (bb-auth-web paragraph)

- "**four tabs** (Dashboard, Applications, Users, Audit) and one pill" becomes five tabs, Settings
  last, plus a navigation menu at 941px and below.
- "its rows are the caller's name and every address, then the places (System settings, and "Go
  to your account" on the console only)" loses "System settings".
- "At 800px and below the tabs ride in it too, which is the compromise the user accepted on
  2026-11-25: one tap away, never a second row." becomes: at 941px and below the tabs ride in a
  navigation menu of their own, opened by a ☰ at the start of the bar, never in the account
  menu (the user's option B, 2026-11-26); the two are one exclusive `details` group.
- "System settings is not a tab at all, for the reason it read as the odd one out while it was
  one: … so it is a row of the account menu …" is replaced by the reason it is last among the
  tabs (§1).
- The self-service paragraph's "the console's one account menu with **no places** in it (this
  page has no tabs to move and offers no console page)" stays true; "no tabs to move" can go.

#### 7. Tests and scenes (two menus)

Unit and socket tests in `src/bin/bb-auth-web.rs`:

- `the_bar_has_four_tabs` becomes `the_bar_has_five_tabs`: `nav.tabs` holds Dashboard,
  Applications, Users, Audit, Settings in that order, the last one's `href` the Settings route,
  text `K::ConfigTab` in both languages.
- `the_navigation_menu_holds_the_tabs` (new): on the console `nav.navm` comes before the brand
  in the bytes and holds one `details.settings.navmenu[name="bar-menu"]`; its summary is
  `.pill.ico` with an `svg[aria-hidden=true]`, a `span.vh` reading `K::NavMenu` and a `title`
  equal to it, in both languages; its `.menu` holds `div.menu-tabs` with the same five links,
  hrefs and order as `nav.tabs`. `/account/` and the console's `403` contain no `navmenu`.
- `the_panel_is_in_order` rewritten for §3: the account menu's `details` carries
  `name="bar-menu"`, `details.prefs` carries no `name`; on the console `div.menu-places` holds
  exactly one `a`, to the account path; no `menu-tabs` and no link to the Settings route inside
  the account menu on any page.
- `the_account_menu_is_one_object` (new): the account menu's `details`, `summary` and `.menu`
  have the same `class` and `name` on the console and on `/account/`, and the sequence of
  classed elements inside `.menu` is the same once `div.menu-places` (console) and the delete
  row (account) are removed.
- `aria_current_names_the_page`: on `/admin/config` one `aria-current="page"` in `nav.tabs`
  (Settings) and one in the navigation menu, none inside the account menu; on `/admin/users` the
  same on Users.
- `the_bar_stays_one_row_at_every_width` (the CSS test): the block is `@media(max-width:941px)`
  with `nav.tabs{display:none}` and `nav.navm{display:flex}`; top level `nav.navm{display:none}`,
  `.menu` with `width:20rem` and `max-width:calc(100vw - 32px)` and **no** `min-width`,
  `details.navmenu .menu` with `left:0` and `right:auto`; no `max-width:800px` block and no
  `.menu-tabs{display:none}` anywhere.
- `K` test: `ConfigTab` reads "Settings" / "Impostazioni" and `NavMenu` the strings of §5;
  `Config` unchanged ("System settings" / "Impostazioni di sistema").
- `no_page_but_the_reveal_carries_a_script` unchanged: no script is added.

e2e:

- `settings.js`: the one-row widths become 320, 360, 640, 641, 941, 942, 1024, 1280. At 360 and
  941: `nav.tabs` hidden, the ☰ visible; at 942 `nav.tabs` visible with all five tabs and the ☰
  hidden. Open the ☰: five links with `aria-current` on the current one; "Applications"
  navigates; Settings reaches `/admin/config`. At 942, with a long given name
  (`X-Auth-Given-Name` plus `profile_claims:['given_name']`) in Italian, `.bar` is one row and
  `scrollWidth` does not exceed the viewport. With the ☰ open, focus the
  account trigger and press Enter: the account menu is open and the navigation menu is closed.
  The account menu holds no `.menu-tabs` and no `/config` link (replace the selector on the
  System settings row, line 82, with the strip's and the ☰'s).
- `settings.js` and `account.js`, **the menu is one size** (new): same caller
  (`admin@example.com`), at 1280 and 360, open the account menu on `/admin/users` and on
  `/account/`; the two `.menu` boxes have equal widths (within 0.5px), equal to
  `min(320, viewport − 32)`, and the same `className` on `details`, `summary` and `.menu`.
- `nojs.js`: at 360 with scripting off, open the ☰, a tab and Settings navigate; the account
  panel carries no tabs (replace the checks at lines 502 to 509).
- `account.js`: no `nav.navm`, no `.menu-tabs` (line 186 stays).
- `e2e/shots.js`: `config-menu` becomes the ☰ open on `/config` at phone width (Settings
  current); new `nav-menu` (the ☰ open on `/admin/users`); `settings-menu` and `account-menu`
  stay (account menu open) and now show the same panel width; `header-logo` now shows five
  tabs at 1280, the last "Settings" / "Impostazioni". The designer reviews light, dark, phone
  and `it`, and by hand the console at 942 and 941 in `it` with the long name.

For the coder: `src/bin/bb-auth-web.rs` (`shell_named`'s `tabs` and `places`, a `nav.navm`
built there, `top_bar`'s new first argument and both call sites, `name="bar-menu"` in
`account_menu`, the two `K` keys); `src/assets/admin.css` (`nav.tabs`, `nav.navm`,
`details.navmenu .menu`, `.menu` width, the 941 block replacing 800).

#### 8. Alternatives rejected (two menus)

- **"System settings" / "Impostazioni di sistema" as the tab**: the brand is cut at every width
  in Italian with a long name, and the breakpoint would sit at about 1000, sending a half-screen
  window to the ☰ (§0).
- **"System" / "Sistema" as the tab**: first proposed here and 33px narrower in Italian (908
  rather than 941); the user chose "Impostazioni" / "Settings".
- **A margin above the measured 942**: the user asked for the smallest width that holds.
- **System settings in the bar, the tabs still in the account menu below the breakpoint**: what
  the user turned down for option B.
- **One trigger for both menus**: two jobs in one panel is the problem being solved.
- **The ☰ on the right beside the name**: two triggers side by side read as one control, and the
  left is where people look for navigation.
- **The current page's name on the ☰ ("☰ Users")**: tells where one is, but costs up to 150px in
  Italian at 320; the page's `h1` already says it.
- **Letting each panel size to its content and only matching the account one**: the two would
  still be two sizes the day a row changes; a fixed width makes the sameness structural.

#### 9. Open questions for the user (two menus)

1. Answered 2026-11-26: the tab reads "Settings" / "Impostazioni", the page it opens "System
   settings" / "Impostazioni di sistema", and the breakpoint is the measured 941px with no
   margin (§0, §2).

#### 10. Step 17: the brand without the tag, and why it stays a link (designed 2026-11-26; the link overruled in §11)

The user, at desktop width on rpi-01: beside "BadBat75" and its logo the bar shows the grey tag
"Amministrazione" cut to "Amministrazio…", then the tabs; remove it. And: why is the brand a
link at all?

What was looked at: `PLAN.md` step 17; `shell_named`, `brand_block`, `K::ConsoleTag` and the
`403` branch of the dispatcher in `src/bin/bb-auth-web.rs`; `.brand`, `.brand .v`, `nav.acct`,
`.bar .who` and the 941 and 640 blocks of `src/assets/admin.css`; `brandStaysWhole` and the
942/941 walk in `e2e/tests/settings.js`; §0's probe `/tmp/d15b/edge.js`.

**Recommendation: the tag goes from every bar.** What it said ("this is the administration
surface") is said four other ways on the console: the five tabs, which no other page of the
estate has; the page's `h1`; the `<title>` (`bb-auth-web · …`); and the account menu's "Go to
your account" row, which names the other surface as somewhere else. On the console's `403` (no
tabs) the notice's own heading is "Not an administrator" / "Non sei un amministratore", so the
tag would repeat the sentence right under it; it does not earn its place there either. On a
1280px screen it was cut, and a cut label is the one form of a label that costs room and says
less (Nielsen 8, aesthetic and minimalist design). `/account/` already shows the brand alone,
so the two bars become the same shape, which is what §13.18 wanted from the tag in the first
place (W13). Trade-off: a person who arrives at the console's `403` from a bookmark reads "which
surface" from the notice rather than from the bar; that notice is the page's first content.

**`K::ConsoleTag` goes.** Its only uses are `shell_named` (the one call of `brand_block` with
`Some(tag)`) and the test `both_bars_name_the_deployment`. With the account call already passing
`None`, `brand_block` loses its `tag` parameter and `span.v`, and `admin.css` loses `.brand .v`
and `.brand:has(img) .v` (§13.34 §0's `flex-shrink:100` and the 2026-11-26 phone rule).

**The brand stays a link on the console, and stays a `span` on `/account/` and on the `403`.**
"Website logos should link to the homepage. This recommendation is a long-standing web
convention", and the same article says to offer both the logo and an explicit Home link, not one
instead of the other (Nielsen Norman Group, "Homepage Links Remain a Necessity",
<https://www.nngroup.com/articles/homepage-links/>). So the Dashboard tab beside it is the
explicit link the article asks for, not a reason to drop the implicit one. Below the breakpoint
the Dashboard tab is inside the ☰, so the brand is the console's one-tap way home on a phone.
Taking it away would break an expectation people bring from every other site (Nielsen 4,
consistency and standards) to remove a redundancy that costs nothing. The two `span`s stay for
the reasons §13.17 and §13.18 gave: `/account/` is the only page of its surface, so a link would
lead to the page already open, and the `403` names a console the caller may not open, so a link
home would lead to the same refusal. (The article says nothing about the logo on the home page
itself; on `/admin/` the brand is a link to the page it is on, which is what the convention does
and is harmless.) Open question 2 below, since the user asked.

**One CSS change besides the deletions, and why it is needed.** Removing the tag alone makes the
breakpoint worse, not better: walked with the same test as §0, the worst case rises from 941 to
974 (Italian, "BadBat75 Estate Services" with no logo, long given name). The tag was the bar's
hidden give: with `flex-shrink:100` it absorbed the shortfall inside the brand, so the name stayed
whole while the name pill had room to spare. Without it, the brand and the name pill shrink in
proportion and the name is cut the moment the row is short. The fix is to say out loud the order
`admin.css` already promises in its `.brand` comment ("the name pill shrinks first, and the
brand's words shrink next"): `nav.acct{flex-shrink:100}`, **only above the breakpoint**, inside
`@media (min-width:884px)`. Below it the ☰ regime keeps today's proportional split: put
everywhere, that rule let a long brand with no logo squeeze the name pill to 52px at 320 (just
the glyph and one letter), while the split keeps it at 121px. The name pill never goes under
128px above the breakpoint, because that is the test the breakpoint is measured by.

##### 10a. Measurements (step 17)

The real console after step 15 (`e2e/lib/server.js`, Edge), the tag removed from the live page
and the rules injected, five real tabs. `/tmp/d17/edge.js` and `/tmp/d17/edge2.js`: strip forced
visible, 1100 down to 641 in 1px steps, light and dark, the §0 test (one row, no sideways
scroll, the brand's name as wide as at 1400, the name pill at least `min(128px, its natural
width)`). Widest width at which the test still fails, for "Ada" / "Bartholomew-Alexander
Montgomery":

| Brand | Today (tag) EN | Today IT | No tag EN | No tag IT | No tag + `nav.acct` first EN | IT |
|---|---|---|---|---|---|---|
| `bb-auth`, no logo | 721 / 712 | 757 / 742 | <641 / 812 | 653 / 835 | <641 / 693 | 654 / 716 |
| `bb-auth` + logo | 798 / 850 | 821 / 864 | 737 / 923 | 760 / 946 | 737 / 798 | 760 / 821 |
| "BadBat75 Estate Services", no logo | 798 / 884 | 821 / 898 | 765 / 951 | 788 / 974 | 765 / 826 | 788 / 849 |
| "BadBat75 Estate Services" + logo | 798 / 876 | 821 / 893 | 798 / 922 | 821 / 945 | 798 / 860 | 821 / **883** |

Light and dark give the same figures. (The "today" column shows that step 15's `flex-shrink:100`
had already brought the real worst case down to 898; §0's 941 was measured before it.) With the
tag gone the long brand is whole at 1400 (191px of 191), where the tag used to cut it by a pixel,
so "whole" is a stricter test than before, and it still holds from 884. **The breakpoint becomes
`max-width:883px`**, no margin, as the user chose for §2. A 900px window now keeps the tabs.

`/tmp/d17/ham.js` with that breakpoint and the scoped rule, 1400 down to 320 in 1px steps, the
four brands, both languages, light and dark, both names: one row and no sideways scroll at every
width, no fault. The brand's name is whole at 320, 360 and 390 for `bb-auth` with or without a
logo and for the long brand with a logo (its words are hidden at 640 and below, as today); the
24-character brand with no logo is cut there, as it is today, since 288px cannot hold it beside
a ☰ and a name. Smallest name pill: 121px (long brand, long name, 320), 133px above the
breakpoint (at 884, Italian, long brand with logo, long name).

Screenshots: `/tmp/d17/bar-{plain,logo,long,longlogo}-{en,it}-light-{Ada,Bar}-{1280,884,883,390,320}.png`
and `/tmp/d17/bar-plain-{en,it}-dark-{Ada,Bar}-{1280,884,883,390,320}.png` (the bar's top 70px).

##### 10b. Changes (step 17)

- `src/bin/bb-auth-web.rs`: `K::ConsoleTag` and its row go; `brand_block` loses `tag` and
  `span.v`; `shell_named`'s comment about the two lines goes.
- `src/assets/admin.css`: `.brand .v` and `.brand:has(img) .v` go, with their comments;
  `@media (max-width:941px)` becomes `(max-width:883px)`; new
  `@media (min-width:884px){nav.acct{flex-shrink:100}}`, its comment saying it is the give the
  tag used to be. The comments naming 941/942 say 883/884.
- AGENTS.md: the bb-auth-web paragraph's "at 941px and below" (as §6 rewrote it) says 883px, and
  the bar is "the operator's logo, the brand, five tabs and one pill" with no tag.

##### 10c. Tests and shots (step 17)

Unit and socket tests in `src/bin/bb-auth-web.rs`:

- `both_bars_name_the_deployment`: drop the two `K::ConsoleTag` asserts and the "second line is
  the tag" check; instead, in both languages, the console's `a.brand` contains no `span.v` and its
  visible text is exactly the brand name (`bb-auth`, then `BadBat75`), and its `href` is the
  dashboard route. The account's `span.brand` is unchanged.
- `the_forbidden_bar_names_only_the_deployment` (new): a non-administrator's `403` on `/admin/`
  has one `span.brand` in the header, no `a.brand`, no `span.v`, visible text exactly the brand
  name, in both languages.
- `the_tag_line_hides_with_the_words_and_the_panel_rows_need_no_gap` becomes
  `the_words_hide_with_a_logo_and_the_panel_rows_need_no_gap`: the `.brand:has(img) .t` checks
  (clip pattern, no `display` or `visibility`) and the `.menu-tabs` gap check stay; and no rule in
  `admin.css`, at any width, has a selector naming `.brand .v`.
- `the_bar_stays_one_row_at_every_width`: the block is `@media(max-width:883px)` with
  `nav.tabs{display:none}` and `nav.navm{display:flex}`; a `@media(min-width:884px)` block holds
  `nav.acct` with `flex-shrink:100`; the top-level `nav.acct` keeps `flex:0 1 auto` and
  `min-width:0`; no `max-width:941px` block remains.
- A `K` test, or a compile failure, is enough for the key: `K::ConsoleTag` no longer exists.

e2e:

- `settings.js`: the one-row widths 941 and 942 become 883 and 884 (and keep 320, 360, 640, 641,
  1024, 1280); at 883 the ☰ shows and `nav.tabs` is hidden, at 884 the reverse. At 884 in Italian
  with the long brand, the logo and the long given name, the brand's `.t` has `scrollWidth` equal
  to its width at 1280, the name pill is at least 128px, and the bar is one row with no sideways
  scroll. `brandStaysWhole` drops the `.brand .v` sentence from its comment; its checks stay.
- `e2e/shots.js`: retake `header-logo`, `forbidden`, `config-menu`, `nav-menu`, `settings-menu`
  and `account-menu` (one run, all filters; the designer reviews light, dark, phone and `it`),
  and by hand the console at 884 and 883 in `it` with the long brand, logo and long name.

#### 11. The user's answers (step 17, 2026-11-26)

1. The breakpoint is 883px, the measured smallest width, with no margin, as in §2. Accepted (the
   user raised no objection to it).
2. **The console's brand becomes a `span`, as on `/account/` and on the `403`: the user's
   decision, against §10's recommendation.** The user's reason: it leads to the page the
   Dashboard tab already names, so it adds no destination. That overrides §10's paragraph "The
   brand stays a link on the console": `brand_block` emits a `span.brand` on every surface, with
   no `href`, and `both_bars_name_the_deployment` pins a `span` (no `a.brand`) on the console too.
   The cost the designer named stands and is accepted: on a phone, home is the ☰ then Dashboard.

#### 12. Step 19: how wide the brand may grow, and the broken logo (designed 2026-11-27)

The designer's finding while reviewing step 17 (`PLAN.md` step 19): `.brand{max-width:14rem}`
leaves the name 118px beside a logo at every width, so "BadBat75 Operations Console" reads
"BadBat75 Op…" at 1280px with 180px of empty bar beside it; and a logo that answers `404` leaves
the phone bar with no brand at all.

What was looked at: `.brand`, `.brand .t`, `.brand img`, `nav.acct`, the 883, 884 and 640 blocks
and `.selfserve-brand` in `src/assets/admin.css`; `top_bar` and `brand_block` in
`src/bin/bb-auth-web.rs`; `brandStaysWhole` and `barAtTheWorstWidth` in `e2e/tests/settings.js`,
`barStaysOneRow` in `e2e/lib/harness.js`, the `header-logo` scene of `e2e/shots.js`.

##### 12a. What the measurements found (step 19)

`/tmp/d19/probe.js` (boots the e2e server, rules injected, `CAND=<name>`): the console (`/users`)
and `/account/`, 1400 down to 320 (1px steps from 900 to 600 and below 400, 4px or 6px
elsewhere), EN and IT, "Ada" and "Bartholomew-Alexander Montgomery", eight brands: `bb-auth`,
"BadBat75 Estate Services" (24 characters), "BadBat75 Operations Console" (27) and a 47-character
one, each with no logo and with a working 120x36 SVG logo. Light and dark give the same numbers.
Results: `/tmp/d19/{today,F,F2}.txt`; the final rules' walk is printed by `CAND=G`.

1. **Today, the cap is the only thing that cuts a 24 or 27-character brand with a logo above the
   breakpoint.** At 1280 in English with "Ada" the bar has 202px free and the name is cut at
   118px of 224 (`opslogo`); the cut lasts from 1400 down to 884 at every width.
2. **It also breaks "one row" on `/account/`, which nobody had measured.**
   `.selfserve-brand{flex-wrap:wrap}` wraps the name under the logo as soon as the cap is reached:
   with "BadBat75 Estate Services" and a logo the account bar is 58px tall instead of 36 at every
   width from 1400 to 641 (`/tmp/d19/today-acct-longlogo-1280.png`). The wrap's comment says it
   is there for "the name and the id", and the id has not been in the brand slot since §13.28.
3. **A broken logo is a 0x30 box in Chromium** (`/tmp/d19/broken.js`): `img alt=""` that fails
   to load renders nothing, so above 640 the name stands alone (harmless) and at 640 and below
   the clip rule `.brand:has(img) .t` still hides the words, because the `img` element is still
   there: an empty brand on the console, on `/account/` and on the `403`.
4. **The e2e walks measure a broken logo, not a logo.** `barAtTheWorstWidth` and `account.js`
   set `logo_url:'/img/logo.png'`, which the test server answers with `404`, and the comment says
   "a broken image is sized by its CSS box"; measured, that box is 0px wide, so the "worst case"
   those walks assert is 106px easier than the one §10a measured with a real image.

##### 12b. The design: the brand takes the room the bar has, up to a budget the rest keeps (step 19)

The order the bar gives way in stays §13.28 §4's: the name pill first, then the brand's words,
never a tab or the logo. What changes is **how wide the brand may be when nothing is short**.
A fixed `14rem` was a guess at "the longest brand worth reading"; the room the bar actually has
is a fact about the bar, so the cap is written as the bar's width minus what everything else in
the row needs. A percentage `max-width` on a flex item resolves against the flex container's
content box, here `.bar`'s
(<https://developer.mozilla.org/en-US/docs/Web/CSS/max-width>), and `max()` and `calc()` mix
`rem` and `%` (<https://developer.mozilla.org/en-US/docs/Web/CSS/max>).

There are three budgets, one per shape of the row:

| Bar | What else is in the row | Brand `max-width` |
|---|---|---|
| `/account/` and the `403` (no tabs), every width | the empty tab `nav` (two 20px gaps) and a name pill of at least 128px | `max(14rem, 100% - 10.5rem)` |
| console, 883px and below (☰) | the ☰ (30px), two gaps, a name pill of at least 128px | `max(14rem, 100% - 12.5rem)` |
| console, 884px and up (tabs in the bar) | the five Italian tabs (455px), two gaps, a name pill of at least 133px | `calc(100% - 39.25rem)` |

`39.25rem` is not a new measurement but today's own geometry at the breakpoint: at 884 the bar's
content box is 852px, and `852 - 628 = 224px = 14rem`, the brand box §10a measured the
breakpoint with. So **the 883/884 breakpoint stays, by construction**: at 884 every number is
today's, and above it every pixel the bar gains goes to the brand until the brand is whole, while
the tabs and the name pill keep exactly what they had at 884 (the pill never under 133px in
Italian with the long name; more in English, whose tabs are narrower). `max(14rem, …)` keeps
today's cap wherever the arithmetic would give less, which is the phone widths, so a phone keeps
today's proportional split and its numbers (long brand, long name, 320: brand 131px, pill 121px,
unchanged). The console's two rules are selected with `.bar:has(nav.tabs a)`, the tab links
existing in the markup whether or not the strip is displayed (`:has()` matches the tree, not the
rendering, <https://developer.mozilla.org/en-US/docs/Web/CSS/:has>); the stylesheet already
depends on `:has()` for `.brand:has(img)`.

Above the breakpoint the brand does not shrink at all (`flex-shrink:0`): the budget already
reserves the pill's floor, so the brand never needs to give there, and letting it share the
shortfall in proportion cost it 1px, which is an ellipsis on a name with room (measured: "BadBat75
Operations Consol…" at 1280 with the long given name). That makes `nav.acct{flex-shrink:100}`
redundant, since the strip cannot shrink (`min-width:max-content`) and the ☰ is not displayed, so
the account end is the only item left that can; it goes, and `.brand{flex-shrink:0}` takes its
place in the 884 block as the sentence "the account end gives way first".

What a person sees with the final rules (`CAND=G`, light and dark, EN and IT):

- "BadBat75 Operations Console" with a logo is whole on the console from about 990px up with "Ada" (the cap reaches its 330px box at a 958px bar), and
  at 1024 and 1280 with the long given name too (which is then cut to "Bartholome…", 143px in
  Italian: the pill gives first, as promised, where today the brand gave at 118px while the pill
  kept 249px). Below that, down to 884, it is cut exactly as today.
- "BadBat75 Estate Services" with a logo: whole on the console from about 958px up, whole on `/account/`
  at every width above 640, and the account bar is one row again.
- The 47-character brand: whole on `/account/` above the ☰ widths; on the console capped at 340px
  (1024px and up), because the budget assumes the Italian tabs and the long name. That brand is
  the one case still cut with room to spare (86px in English with "Ada").
- One row and no sideways scroll at every width from 1400 to 320, on both surfaces, both
  languages, both themes, with and without a logo; the pill's smallest width above the
  breakpoint is 133px, as today.

Screenshots: `/tmp/d19/stack-desktop.png` (today against the design: console at 1280 with "Ada" and
with the long name, 1024 dark, 884; `/account/` at 1280 and 700 dark) and the single bars
`/tmp/d19/s-<case>-{today,G,G2}-{light,dark}-<width>.png`.

##### 12c. The broken logo: on a phone the words stay and the mark goes (step 19)

**Recommendation (open question 1): at 640px and below, hide the logo and show the words**, which
truncate with their ellipsis like any brand with no logo; above 640 nothing changes. The words
come from the settings file and are rendered by this program, so they are always there; the mark
comes from another host, and the invariant for the pages this estate serves is that they are
complete without a second host answering (`ui.logo_url` "is equally optional"). A brand that
exists on a phone only if another host is up is that rule broken in the bar. The clip rule
`.brand:has(img) .t` goes, and with it the only case in which the words were visually hidden, so
the `img` keeps `alt=""` on every width and a reader hears the name once, from the words
(decorative image beside its own text, <https://www.w3.org/WAI/tutorials/images/decorative/>).
Measured (`CAND=F2`): the live "BadBat75" reads whole at 360 and 320 with or without a working
logo (`/tmp/d19/stack-phone.png`); a broken logo now shows "BadBat75" on the console and on
`/account/` where today it showed nothing.

The cost, said plainly: rpi-01's phone bar changes from the red mark to the word "BadBat75", and a
long brand with a logo is now cut on a phone where the mark used to stand whole ("BadBat75
Operations Console" at 320: cut at 196px of 224 beside "Ada", whose pill falls from 58px to 50px;
the 47-character brand drops the "Ada" pill to 34px, which is what a 47-character brand with no
logo already does today). Both pills stay above WCAG 2.5.8's 24px
(<https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html>).

Rejected for the broken logo:

- **`alt` carrying the name, the words hidden from readers, the alt text shown when the image
  fails.** HTML renders a failed image as its alt text
  (<https://html.spec.whatwg.org/multipage/rendering.html#images-3>), but Chromium draws its
  broken-image icon beside it: measured 18x30 at desktop and 88x30 with the icon on a phone
  (`/tmp/d19/broken-stack.png`, rows three to five). A visible broken icon is worse than nothing.
- **`img::after` with the name.** Paints only on a failed image in Chromium and Firefox, which is
  behaviour no specification promises, and not in Safari, which is most phones.
- **`object` with the name as fallback content.** Needs an `object-src` in the policy for an
  operator's host, and an SVG in an `object` is a document that runs its own scripts.
- **`onerror="this.remove()"` on the `img`.** Works (the `:has(img)` rule stops matching and the
  words come back), keeps the mark on a phone, and costs a third script: one more hash in every
  page's `script-src`, and `no_page_but_the_reveal_carries_a_script` widened. With scripting off
  the brand is still empty. This is the alternative if the user wants the mark kept on phones
  (open question 1, option b).
- **Words always shown beside the mark on a phone** (`CAND=A4`). The console's `bb-auth` beside a
  logo is cut to 14px ("b…") at 320 with the long name, and `/account/` wraps from 379 down.

##### 12d. Changes (step 19)

`src/assets/admin.css`:

- `.brand`: `max-width:14rem` becomes `max-width:max(14rem,100% - 10.5rem)`; its comment says the
  cap is the bar's width less the room the rest of the row keeps, not a length of a brand.
- New, after `.brand`: `.bar:has(nav.tabs a) .brand{max-width:max(14rem,100% - 12.5rem)}`, with
  a comment naming the ☰ and the pill's floor.
- `@media (min-width:884px)`: `nav.acct{flex-shrink:100}` goes; the block holds
  `.brand{flex-shrink:0}` and `.bar:has(nav.tabs a) .brand{max-width:calc(100% - 39.25rem)}`, its
  comment saying 39.25rem is the bar at 884 less the 14rem the breakpoint was measured with.
- `.selfserve-brand{flex-wrap:wrap;margin:0}` becomes `.selfserve-brand{margin:0}`, its comment
  losing the sentence about the name and the id wrapping under the mark.
- `@media (max-width:640px)`: `.brand:has(img) .t{…}` and its comment go; new
  `.brand img{display:none}` with a comment saying the words are the part that is always there
  (only if the user takes open question 1's recommendation).
- The header comment that says the bar gives "the name pill, then the brand's text" is unchanged.

`src/bin/bb-auth-web.rs`: no markup change. `brand_block`'s doc comment loses "(§4), since a reader
is then the only one reading the name", because the words are never visually hidden any more.

##### 12e. Tests and shots (step 19)

Rust, in `src/bin/bb-auth-web.rs` (the selectors as `css_scoped` normalises them):

- `the_bar_gives_room_by_shrinking_the_ellipsis_pieces`: the top-level `.brand` has
  `max-width` `max(14rem,100% - 10.5rem)` (not `14rem`) and `min-width:0`; a top-level
  `.bar:has(nav.tabs a) .brand` has `max-width` `max(14rem,100% - 12.5rem)`; the phone block's
  `.brand:has(img) .t` assertions are replaced by `.brand img` with `display:none` in
  `@media(max-width:640px)`.
- `the_bar_stays_one_row_at_every_width`: the `@media(min-width:884px)` block holds `.brand` with
  `flex-shrink:0` and `.bar:has(nav.tabs a) .brand` with `max-width` `calc(100% - 39.25rem)`; no
  rule in it names `nav.acct`; the 883 block is unchanged.
- `the_words_hide_with_a_logo_and_the_panel_rows_need_no_gap` becomes
  `the_mark_gives_way_on_a_phone_and_the_panel_rows_need_no_gap`: no rule at any width has a
  selector naming `.brand:has(img) .t`, and no rule naming `.brand .t` sets `position`,
  `clip-path` or `display`; the `.brand .v` and `.menu-tabs` checks stay.
- New, `the_brand_slot_never_wraps`: no rule whose selector names `.brand` or `.selfserve-brand`
  sets `flex-wrap` to `wrap`.
- `both_bars_name_the_deployment` stays as it is; it already pins `alt=""` and the words.

e2e, `e2e/lib/harness.js`:

- New `routeLogo(context)`: `context.route('**/img/logo.svg', …)` answering a 120x36 SVG, so a
  walk measures a 96px mark; the comment of `barStaysOneRow` that says a broken image is sized by
  its CSS box is corrected (it is 0px wide). `barAtTheWorstWidth` and the `account.js` walk use
  `/img/logo.svg` with `routeLogo`, so the worst case they assert is the one measured.
- `barStaysOneRow` also asserts the bar's height is at most 40px at each width (the account
  bar's wrap was one row by the centres test only because its children are centred).

e2e, `e2e/tests/settings.js`:

- New `brandHasRoom(t, ctx, look)`: "BadBat75 Operations Console" with the routed logo; at 1280
  and 1024, EN and IT, given name "Ada" and the long one: `header .brand .t` has `scrollWidth` no
  greater than `clientWidth` (whole), the bar is one row at most 40px tall with no sideways scroll,
  and the name pill is at least 128px. Then `/account/` at 1280 and 700 with "BadBat75 Estate
  Services" and the logo: whole name, bar at most 40px.
- `barAtTheWorstWidth` keeps 884 and 883; its 1280 reference is now always whole (no cap made it).
- New `brokenLogoKeepsTheName(t, ctx, look)`: `logo_url:'/img/logo.png'` (the test server's
  `404`), brand "BadBat75", at 360 and 320, EN: on the console, on `/account/` and on the
  non-administrator's `403`, `header .brand .t` has `position` not `absolute`, a `clientWidth`
  above 0, text "BadBat75", and the bar is one row. With the routed logo at 360,
  `header .brand img` computes `display:none` and the words are whole.

`e2e/shots.js`: `header-logo` routes a working logo (today it shows the broken one), and a new
`header-logo-broken` keeps `/img/logo.png`. Retake in one run `header-logo`,
`header-logo-broken`, `forbidden`, `account-menu`, `account`, `nav-menu`, `config-menu` and
`settings-menu`; the designer reviews light, dark, phone and `it`, and by hand the console at
1280, 1024, 884 and 883 in `it` with "BadBat75 Operations Console", the logo and both names.

##### 12f. Alternatives rejected (step 19)

- **A larger fixed cap (`24rem`).** A number again: still cuts a brand at 1280 with room, and at
  884 a brand wider than 14rem would push the pill under the 128px the breakpoint is measured by,
  so the breakpoint would rise.
- **No cap at all.** With the pill as the first give and no floor, a long brand squeezes the name
  pill to its glyph above the breakpoint. CSS has no "at least 128px, or less if the content is
  less" for the pill: `min()` takes no `max-content`.
- **A brand that grows into free space (`flex:1 1 0` and `max-width:max-content`).** With a basis
  of 0 the brand is the first thing to give, the order reversed.
- **`100vw` in the budget.** On a browser with classic scrollbars `100vw` counts the scrollbar and
  the bar does not have it; `%` is the bar's own width. (The 884 media query does count the
  scrollbar, as before; headless walks hide scrollbars, so that 15 to 17px is not measured here.
  Unverified.)
- **A budget per language.** The English tabs are about 40px narrower, so an English brand could
  have 40px more; a second set of rules keyed on `lang` for 40px is not worth its upkeep.

##### 12g. Questions for the user (step 19), answered by the coordinator

(On 2026-11-27 the user first asked for a placeholder, designed in §13.37, then withdrew it the
same day: a logo that does not load is a configuration fault, so option (c) stands.)

The user asked on 2026-11-27 for the plan to be carried to its end, with the decisions taken on
the recommendations and reviewed afterwards. So both are taken as recommended, (a) for the first
and acceptance for the second, and stand until the user reviews them.

1. **The phone bar with a logo.** (a) *Recommended:* at 640px and below show the brand's words and
   not the mark, so a logo that does not load can never leave the bar without a name; rpi-01's
   phone bar then reads "BadBat75" instead of the red mark. (b) Keep the mark on phones and add a
   one-line `onerror` script that removes a broken image, so the words come back (empty brand with
   scripting off). (c) Keep today's bar and accept an empty brand on a phone when the logo fails.
2. **A brand longer than about 28 characters with a logo (40 without) is still cut on the console
   at 1280**, because the budget assumes the Italian tabs and the longest given name. Recommended:
   accept; `/account/` and the `403`, which have no tabs, show it whole.

**The user reviewed the first answer on 2026-11-27 and turned it round: at 640px and below the bar
keeps the mark and hides the words**, as it did before step 19 (the words stay in the markup,
visually hidden, so a screen reader still reads the name). That overrules §12c and the phone rule
of §12d, and it takes back the "words on a phone" checks of §12e. Between the two options left the
coordinator chose (c), no script: a logo that does not load leaves the phone's brand empty. Only a
wrong `ui.logo_url` causes that, the operator sees it on the first page, and the bar's other
controls still work. The alternative, (b), would add an inline `onerror` script, and the
"JavaScript is used sparingly" rule in AGENTS.md wants each script decided on purpose; an empty brand
on a misconfigured phone is not worth one. The second answer stands.

### 13.35 Each dashboard warning names its kind (plan step 20, designed 2026-11-27)

The user read "`@delete-test` referenced by nothing" on rpi-01's dashboard and could not tell
what `@delete-test` was. Each of the five warnings `page_dashboard` pushes is an identifier in
`code` followed by a `K` predicate, and nothing says whether the identifier is a scope, a person
or a group. Read for this design: `page_dashboard`, the five `K` predicates, `groups_section`
(the other use of `K::ReferencedByNothing`), `Route::path`, the console's own singular words for
each kind (`K::MsgScopeAdded`, `K::MsgUserAdded`, `K::MsgGroupAdded`, `K::NoSuch*`), and the
`li a` rules in `base.css`. No shot was taken for the design: the change is words and one link
per line, and the review shot comes after the code.

#### 1. Words (warning kinds)

Each line becomes **kind, identifier, predicate**. The kind is one new `K` key, capitalised
because it now opens the list item, and its words are the ones the console already uses for that
object in its add/save/remove messages, so the dashboard says what the tabs and forms say:

| New key | English | Italian |
| --- | --- | --- |
| `K::KindScope` | Scope | Scope |
| `K::KindUser` | User | Utente |
| `K::KindGroup` | User group | Gruppo di utenti |

The five lines, as rendered (identifier in `code`, the predicate key unchanged):

| # | English | Italian |
| --- | --- | --- |
| 1 | Scope `mpa/old` unreachable: an earlier scope of this application already covers every url it has | Scope `mpa/old` irraggiungibile: uno scope precedente di questa applicazione copre già ogni url che ha |
| 2 | Scope `mpa/admin` restricted and lists nobody: it admits no one | Scope `mpa/admin` ristretto e non elenca nessuno: non ammette nessuno |
| 3 | User `bob@x.com` reaches nothing: no scope lists them | Utente `bob@x.com` non raggiunge nulla: nessuno scope lo elenca |
| 4 | User `bob@x.com` is in users and in denied — denied wins, on every credential | Utente `bob@x.com` è in users e in denied — vince denied, su ogni credenziale |
| 5 | User group `@delete-test` referenced by nothing | Gruppo di utenti `@delete-test` referenziato da nulla |

Italian "scope" stays the console's singular (it is "scope" in every message and in the
predicates themselves; "Ambiti" is only the plural heading), and the predicates already agree
with a masculine subject, so no predicate key changes. The em-dash in line 4 is existing text and
is left alone. "Application" gets no key: no warning is about an application, and a scope's
identifier `app/scope` already names its application, which is how the file and both editors
name a scope.

**`K::ReferencedByNothing` at its other use does not change.** In `groups_section` it is the
muted line under a group's own panel, inside the "User groups" section, where the heading already
says what the object is; prefixing the kind there would repeat the heading on every panel.

#### 2. Links (warning kinds)

The identifier becomes a link where the object has a page of its own, exactly as the key table
above it already links its owner (`a href=… { … }` in a `td`):

- lines 1 and 2: `a href=(v.href(&Route::App(app)))` around the `code`. The application page,
  not the scope's edit form, because a shadowed scope is explained only by the earlier scopes
  listed above it, and that page shows them in file order (the empty restricted scope is already
  tagged there too).
- lines 3 and 4: `a href=(v.href(&Route::User(uuid)))` around the `code`, the uuid trimmed and
  lowercased as the key table does.
- line 5: **no link**. A group has no page of its own; its only `GET` is the edit form, which
  cannot fix "nothing references it" (the fix is on a scope, or the group's removal), and a link
  to the whole Users page would land somewhere that does not show the group in view.

Markup per line: `li { (kind) " " a href=… { code { … } } " " (predicate) }`, and for line 5
`li { (kind) " " code { "@" (name) } " " (predicate) }`.

Heuristics: the kind word is match with the real world and consistency (Nielsen 2, 4), and the
link is recognition rather than recall (6): the operator no longer has to find the object by hand.
WCAG 2.4.4 Link Purpose (In Context) is met because the link's list item gives its context
(<https://www.w3.org/WAI/WCAG22/Understanding/link-purpose-in-context.html>). The trade: `li a`
in `base.css` drops the underline until hover, so the link is told apart by colour and by the
monospace face; that is the console's existing list-link style (technique G183 asks for 3:1
against the text plus a cue on hover or focus,
<https://www.w3.org/WAI/WCAG22/Techniques/general/G183>), and it is kept for consistency rather
than restyled in this step.

#### 3. Tests and scene (warning kinds)

Rust, in `src/bin/bb-auth-web.rs`, on the rendered dashboard (a fixture that raises all five,
inline if `dash` does not):

- `each_dashboard_warning_names_its_kind_first`: every `li` of the warnings list starts with
  "Scope ", "User " or "User group "; and the group line is exactly
  `<li>User group <code>@unused</code> referenced by nothing</li>`.
- `dashboard_warning_kinds_are_translated`: with `lang=it`, "Scope ", "Utente " and
  "Gruppo di utenti " open the same lines.
- `a_dashboard_warning_links_to_the_page_of_what_it_names`: the scope lines hold
  `<a href="…/apps/mpa"><code>mpa/…</code></a>`, the user lines `<a href="…/users/<uuid>">`
  around the `code`, and the group line holds no `<a`.
- `the_group_panel_still_says_referenced_by_nothing_alone`: the users page's group panel reads
  "referenced by nothing" with no "User group" before it.

Extend, not replace, `dashboard_counts_expiries_and_warnings`. Scene to retake for the review:
`node e2e/shots.js dashboard` (light, dark, phone and `it`); the fixture's dashboard shows at
least lines 3 and 5.

#### 4. Questions for the user (warning kinds), answered by the coordinator

Taken as recommended (no group page in this step), as the user asked on 2026-11-27 for the plan
to be carried to its end with the decisions reviewed afterwards.

1. Should a user group get a page (or an anchor on the Users page) so line 5 can link too?
   Recommended: no, not for this step; the group is one search away in the Users page's filter.

   Changed by §13.36 (plan step 22, the user's choice of 2026-11-27): a group now has a page,
   `/groups/{name}`, and line 5 links to it.

### 13.36 The users page in three sub-pages, a page per group, and lists that say how many (plan step 22, designed 2026-11-27)

The user, on 2026-11-27: with many people and groups the users page, which stacks
`user_groups`, the roster and `denied` on one long page, is unmanageable. They chose all four
points of plan step 22. Read for this design: `page_users`, `groups_section`, `page_denied`,
`denied_list`, `l_keeps_user`, `Listing`, `list_controls_with`, `Route` (`path`, `tab`,
`parent`, `title`, `route`), the group arms of `mutate`, `user_group_refs` and `group_ref` in
the library, `page_dashboard`'s counts and warnings, the `nav`, `.pill.on`, `td.pills` and
`.listctl` rules in `base.css` and `admin.css`, and `shots.js users` (light, dark, phone, `it`).
Mockups over the real console shell and the real CSS: `/tmp/d22/mock.js` (boots the e2e server,
swaps `<main>`, shoots EN light/dark at 1280 and 390, EN and IT light at 320; 56 shots in
`/tmp/d22/*.png`, the measures printed per shot).

**What this reverses, and why.** The users page put groups and the veto on the roster's page
because "a group only means anything in terms of the roster", and "a list that is usually three
lines long does not earn a tab". The second premise is what failed: with many groups, each
group's panel listing every member, the roster begins a screen or more below the top, and the
`denied` list several screens further. The first premise still holds, and this design keeps it
by keeping all three **under the one Users tab** and linking them both ways (§3), instead of
moving groups or `denied` into the bar: the bar keeps its five tabs and its 883/884 breakpoint
(§13.34), and "every tab is a noun" still holds, since a sub-page is a section of that noun.

#### 1. Three sub-pages, under the one tab (users page)

**Routes. The three already exist, so none moves.** People is `/users` (the default: the bar's
Users tab still goes there), Groups is `/groups`, Denied is `/denied`. `/groups` resolves to
`Route::Users` today and `/denied` is `page_denied`, so every bookmark, PRG redirect and form
URL already points at the page it will now show; the group forms stay at `/groups/+add`,
`/groups/{name}/edit` and `/groups/{name}/rm`. The plan's `/users/groups` was rejected for that
reason: it would move two working URLs to make three look alike, and `/users/{x}` is the person
route, which would have to give up two names to literal arms.

- `Route::Groups` (new): `/groups`, `route()` maps `["groups"]` to it instead of `Route::Users`.
- `Route::Denied` (exists): unchanged path.
- `tab()`: `Groups`, `Group(_)` (§2) and `Denied` light the Users tab, as `Denied` and the group
  forms already do.
- `title()`: `Groups` and `Group(_)` are `user_groups`, `Denied` stays `denied`, People stays
  `users`.

**One shape for all three pages**, top to bottom:

1. `h1` "Users" / "Utenti" (`K::Users`), the tab's word, identical on the three, so the page
   says which tab it is under. The `h1`'s lede (`K::UsersIntro`) moves down to People's section,
   because it describes the roster only and would be wrong on the other two.
2. The **sub-tabs**: `nav class="sub" aria-label=(K::UsersSections)`, three `a.pill` links in
   this order, each the section's short word and its **whole** count (never the filtered one, so
   the number does not change while the person types):
   - `People (4)` / `Persone (4)`, `K::People`, `doc.users.len()`, href `/users`
   - `Groups (2)` / `Gruppi (2)`, `K::GroupsTab`, `doc.user_groups.len()`, href `/groups`,
     `id="user_groups"`
   - `Denied (1)` / `Bloccati (1)`, `K::Denied` (exists), `doc.denied.len()`, href `/denied`,
     `id="denied"`

   The current one is `class="pill on"` and `aria-current="page"`, the others plain `pill`:
   exactly the bar's tab markup, so a sub-tab looks and behaves like the tab above it, one size
   down (`nav .pill`, `.pill.on` in `base.css`; Nielsen 4). Each label is one text node
   (`(label) " (" (n) ")"`): a `span` inside a flex `.pill` loses the space before it, which the
   mockup hit on the group chip below. `GroupsTab` is not `K::Groups` ("User groups" / "Gruppi
   di utenti") for the bar's reason (`K::ConfigTab` versus `K::Config`): the row must fit a
   phone, and the section's `h2` spells the name out.
3. The section: `h2 { section_heading(label, file key) }`, `p.lede.sub`, `+ add`, the list's
   controls and the list, as each section is rendered today. People's `h2` becomes `People
   users` (`K::People`), so the sub-tab's word and the heading it lands on are the same word
   (today it repeats the `h1`'s "Users"); Groups' is `User groups user_groups`; Denied's is
   `Denied denied`, and `page_denied`'s own `h1` goes, since the shared `h1` is now "Users".

`page_users` becomes three page functions over one helper that renders items 1 and 2 (the coder
names it; `users_subnav(v, doc)` is a suggestion). `groups_section` and `denied_list` are no
longer rendered on `/users`, and the comment that says they are must go.

**The CSS, one rule in `admin.css`, measured.** The bar's `nav:not(.acct){flex-wrap:nowrap;
min-width:max-content}` matches any `nav`, so it reaches this one too, and at 320px with
four-digit counts the row is wider than the column: 7px of sideways scroll in English and 17px
in Italian (`CAND='.listctl .pager{flex-wrap:wrap}' ONLY=people-many node /tmp/d22/mock.js`).
So:

```css
main nav.sub{flex-wrap:wrap;min-width:0;margin:0 0 18px}
```

With it, no shot from 320 to 1280 scrolls sideways (both languages, both themes); the row is
one line (30px) everywhere except 320 with four-digit counts, where it takes two (63px), which
is the honest cost of a count that long. Nothing else is new: the unselected sub-tab keeps the
bar's `--card` border, which on the page's `--bg` reads as a faint box (seen in both themes),
and that is the affordance a tab row inside the page needs.

**Old links.**

- `/users#user_groups`, `/users#denied`: a fragment never reaches the server, so no redirect can
  serve it. The Groups and Denied sub-tabs carry `id="user_groups"` and `id="denied"`, so such a
  link scrolls to, and starts keyboard navigation at, the link to the page it meant
  (<https://html.spec.whatwg.org/multipage/browsing-the-web.html#scroll-to-the-fragment-identifier>).
  No element carried those ids before, so this is two attributes, no behaviour.
- `/groups`: now the Groups page (it was `/users`).
- `/denied`: the Denied page, with the shared `h1` and sub-tabs.
- The dashboard's count row: `user_groups` links to `Route::Groups` (it links to `/users` now);
  `users` and `denied` keep their targets.

**PRG and cancel**, so a form lands where its object is shown:

| Action | `303` to, today | `303` to, after | `parent()` (cancel, `409` back), after |
| --- | --- | --- | --- |
| group add | `/users` | `/groups/{name}` | `/groups` |
| group edit | `/users` | `/groups/{name}` | `/groups/{name}` |
| group remove | `/users` | `/groups` | `/groups/{name}` |
| denied add, remove | `/denied` | unchanged | unchanged (`/denied`) |
| user add, remove | unchanged | unchanged | unchanged |

The `?msg=` notice already renders on any page, so the moved targets need nothing more.

#### 2. A page per group (users page)

`Route::Group(String)` at `/groups/{name}`, matched after `["groups", ACTION_ADD]`. A group
name is `[A-Za-z0-9_-]` (`compile_access`), so no name can spell `+add`. An unknown name is
`404` through `page_missing(v, K::NoSuchGroup, name, &Route::Groups)`, as the edit form's is.

Top to bottom (mockups `group-*.png`, `group-none-*.png`):

1. `h1 { code { "@" (name) } " " span.muted.mono { "user_groups" } }`, then `p.lede` with
   `back(v, &Route::Groups)`, then `p.pills` with `act(GroupEdit)` and `act_rm(GroupRm)`: the
   person page's head, with the existing forms. The edit and the removal are the **existing**
   `page_group_form` and the `GroupRm` confirmation, unchanged; only where they return changes
   (§1). The removal still refuses while a scope references the group, and its refusal still
   names the referrers.
2. `h2 { section_heading(K::Scopes, "scopes") }`, then a panel: every scope that names the
   group, in file order, each `li { a href=(Route::App(app)) { code { app "/" scope } } }`, and a
   scope that **excludes** it also carries `tag("bad", "excluded")` after the link. The words
   are the file's (`EXCLUDED_REF`, which `user_group_refs` already prints), and they are words
   beside the link, not a colour (WCAG 1.4.1). Scopes come before members because they are why
   the group matters, and because the dashboard's "referenced by nothing" lands here (§13.35
   line 5): its answer is the first thing under the head. Empty: the panel says
   `K::ReferencedByNothing` in `span.muted`, the same words as the warning that linked here.
   The list must agree with `user_group_refs` entry for entry; the coder decides whether that is
   a structured variant of it in the library or a parse of its strings, but not a third walk of
   `group_ref` with its own rule.
3. `h2 { (K::Members) }`, then `p.primary` with one pill, "show them in People" / "mostrali in
   Persone" (`K::GroupInRoster`), to `/users?ug={name}` (§3), then the members as
   `groups_section` lists them today (a link with the person's label where a roster row resolves
   the uuid, the uuid in `code.bad` with `tag("bad", K::UnknownMember)` where none does), behind
   their own `Listing` with prefix `m` (filter over label and uuid, pager), so a group of a
   thousand people is a page and not a scroll. Empty group: `list_panel`'s `K::None`.

**Warning link** (§13.35 §2, line 5): `li { (kind) " " a href=(Route::Group(name)) { code {
"@" (name) } } " " (predicate) }`, the same shape as the other four lines.

**The Groups list** stops stacking a panel per group, which is what made it long: it becomes a
table, one row per group, columns `name` (the file's word, as the applications table heads its
first column), `K::Members`, `K::Scopes`, and the row's actions:

- `name`: `a href=(Route::Group(n)) { code { "@" (n) } }`
- members: the count
- scopes: the same links and `excluded` tags as the group page, separated by a space; with none,
  `span.muted` `K::ReferencedByNothing` (the muted line `the_group_panel_still_says_referenced_by_nothing_alone`
  pins moves into this cell, still without the "User group" kind before it)
- actions: `td class="pills" { span class="pills" { edit remove } }`. The inner `span` is not
  decoration: `td.pills` is a table cell with no gap, and two pills straight in it touch, which
  the mockup shows (`groups-en-light-1280.png`); `.pills` has the `gap:6px`.

The filter keeps today's reach (`@name` and each member's label), so "which group is bob in?"
still finds the row, now also answered by the roster's own column (§3).

#### 3. The two lists link (users page)

**The roster's groups column.** Between `emails` and `api_keys`, header and `data-label`
`K::ColGroups` ("groups" / "gruppi", lowercase like the `emails` column beside it). The cell
lists every group whose members hold the row's uuid, in the file's order, each
`a href=(Route::Group(n)) { code { "@" (n) } }`, one space apart; none is `span.muted` `K::None`.
The membership map is built once per request (uuid to group names), not per row. A group link
goes to the **group's page**, not to the filter: every other `@name` and `app/scope` in the
console is a link to its object's page, and a link that filtered here would be the one that
behaved differently (Nielsen 4). The filter is one click from that page.

**The roster filtered by group: `ug={name}`**, read beside `uq`/`up` and namespaced with the
roster's `u` like them.

- Exact name, never a substring, so `@staff` does not also show `@staff-old`.
- **AND** with the text filter: `/users?ug=admins&uq=bot` shows the members of `@admins`
  whose label, uuid or key id contains `bot`.
- Setting it, from the group page's pill, carries no `up`, so the result starts on page 1, the
  rule `list_controls` already applies to a new text filter. The text filter's form keeps
  `ug` through `preserved_query`'s hidden inputs and its `×` keeps it too (`listing_href`
  drops only `uq` and `up`), so typing narrows the group rather than leaving it.
- While it is set, the roster's control row opens with a chip, `a.pill`, text
  "group: @admins ×" / "gruppo: @admins ×" (`K::GroupFilter` filled with the name, one text
  node), `title=(K::GroupFilterClear)` "show every group" / "mostra tutti i gruppi", whose
  href is this URL without `ug` and `up`. It is rendered inside the same form through
  `list_controls_with`'s `extra`, with `"ug"` in `owned` and a hidden `ug` input beside it, so
  one Apply submits both and `ug` is not sent twice.
- A name that is no group (a stale bookmark after a removal) is a filter that matches nobody:
  the chip names it, the panel says `K::NoMatch`, the `×` clears it. No `404`: the page exists,
  the filter is what is wrong.
- No group `select` in the control row: with many groups a list box of all of them is the
  scrolling this step is removing, and the group page and the roster's column are two ways in
  that need no new control. A `select` was the alternative rejected.

#### 4. Lists that say how many (users page)

**The filter's reach is already uuid and key id**: `l_keeps_user` searches every email, the uuid
and each key's id. What is missing is that nobody can know it (Nielsen 6 and 10): the box says
"filter". So the roster's box, only, says what it searches: placeholder **and** `aria-label`
`K::FilterPeople`, "email, uuid or key id" / "email, uuid o id chiave". The name and the
visible hint are the same string, which keeps WCAG 2.5.3 Label in Name trivially true
(<https://www.w3.org/WAI/WCAG22/Understanding/label-in-name.html>); the field is `type=search`,
so it is announced as a search field without the word "filter". This needs a placeholder
argument on `list_controls_with` (the other lists keep `K::Filter`); no behaviour changes, and
a test pins the reach that was never pinned.

**The pager's count**, in the shared `list_controls_with`, so every list says it the same way:

- `K::PagerRows` "rows {0}–{1} of {2}" / "righe {0}–{1} di {2}", filled with the first row's
  1-based number, the last's, and the matched count.
- `K::PagerRowsFiltered` "rows {0}–{1} of {2} (filtered from {3})" / "righe {0}–{1} di {2}
  (filtrate da {3})", the same plus the list's whole length, used while any filter is set (the
  text, or on the roster `ug`).
- Shown when the list has a matching row **and** either there is more than one page or a filter
  is set; on one unfiltered page every row is in view, and on the users sub-pages the sub-tab
  already says the total. With no matching row there is no count: the panel's `K::NoMatch`
  already says it.
- It **replaces** both "page 2/5" (`K::Page`, then unused, removed) and the bare "matched/total"
  span shown while filtering, so one sentence says what two fragments said.
- `{0}–{1}` uses an en dash: data, a range, not prose punctuation.
- **Order, measured.** Inside `span.pager` the text comes first, then ← previous, then next →,
  and `.listctl .pager` gets `flex-wrap:wrap`. With the text between the two buttons, at 320px
  the Italian filtered sentence was squeezed into a column one word wide between them
  (`people-many-it-light-320.png`, first run); text first, it is one line and the two buttons
  sit under it, with no sideways scroll. At 1280 it reads "rows 101–125 of 1180 (filtered from
  1234) ← previous next →" on the line under the filter.

```css
.listctl .pager{flex-wrap:wrap}
```

#### 5. Phone, themes, scripting off (users page)

- **Phone**: measured at 390 and 320, no sideways scroll on any of the seven mockups in either
  language; the roster's stacked cards gain a `gruppi` / `groups` label like the other cells;
  the sub-tab row is one line at both widths with real counts and two lines at 320 only with
  four-digit counts.
- **Themes**: nothing names a colour; the sub-tabs are the bar's tab tokens and the chip is a
  `.pill`. Shot in both.
- **Scripting off**: nothing here has or needs a script. The sub-tabs are links, the filters
  `GET` forms, the chip and the pager links; `nojs.js` proves it on the three pages.
- **Keyboard and reader**: the sub-tab `nav` is the page's fourth navigation landmark, so it is
  named (`K::UsersSections`, "Users sections" / "Sezioni di Utenti"), as the APG asks of more
  than one landmark of a kind (<https://www.w3.org/WAI/ARIA/apg/practices/landmark-regions/>).
  Tab order: bar, `h1` has no stop, the three sub-tabs, then `+ add`.
- **A trade, stated**: on `/groups` the bar's Users tab and the Groups sub-tab both carry
  `aria-current="page"`. ARIA allows one current element per set
  (<https://www.w3.org/TR/wai-aria-1.2/#aria-current>), and these are two sets, each named; the
  bar already marks Users current on a person's page whose URL is not `/users`. Changing the
  bar's tab to `aria-current="true"` on a sub-page would be more exact and would touch the shared
  header on every page, so it is left as it is.

#### 6. Words (users page)

| New key | English | Italian |
| --- | --- | --- |
| `K::People` | People | Persone |
| `K::GroupsTab` | Groups | Gruppi |
| `K::UsersSections` | Users sections | Sezioni di Utenti |
| `K::ColGroups` | groups | gruppi |
| `K::GroupInRoster` | show them in People | mostrali in Persone |
| `K::GroupFilter` | group: {0} | gruppo: {0} |
| `K::GroupFilterClear` | show every group | mostra tutti i gruppi |
| `K::FilterPeople` | email, uuid or key id | email, uuid o id chiave |
| `K::PagerRows` | rows {0}–{1} of {2} | righe {0}–{1} di {2} |
| `K::PagerRowsFiltered` | rows {0}–{1} of {2} (filtered from {3}) | righe {0}–{1} di {2} (filtrate da {3}) |

`K::Page` is removed. "Bloccati" stays the Denied word, as the console already says it.

#### 7. What was removed, and the alternatives rejected (users page)

Removed: the stacked page; the per-group panels with their full member lists (now a count, and
the list on the group's page); `page_denied`'s own `h1`; "page n/m" and "matched/total". Rejected:
`/users/groups` and `/users/denied` (two URLs moved for symmetry, §1); Groups and Denied as bar
tabs (a sixth and seventh tab breaks the 883 breakpoint and the noun rule's reading of the bar);
a group `select` on the roster (§3); a `?ug=` link in the roster's column instead of the group
page (§3); a filter that matches `@name` as a substring of the roster's text, which needs no new
parameter but cannot tell `@staff` from `@staff-old` and is invisible until somebody guesses it.

#### 8. Tests and scenes (users page)

Rust, in `src/bin/bb-auth-web.rs`:

- `route_maps_the_three_sub_pages_and_a_group`: `/groups` is `Route::Groups`, `/groups/admins`
  is `Route::Group("admins")`, `/groups/+add` still `GroupAdd`, `/denied` still `Denied`; each
  `path()` round-trips; `tab()` of `Groups`, `Group(_)`, `Denied` is `Users`; `title()` of
  `Groups` and `Group(_)` is `user_groups`. Replace the `route("/groups", "")` assertion that
  expects `Route::Users`, and add both new routes to the exhaustive route lists near the test of
  every route.
- `each_users_sub_page_carries_the_three_sub_tabs_with_counts`: on `/users`, `/groups` and
  `/denied`, `main nav.sub[aria-label]` holds three links in the order People, Groups, Denied,
  texts `People (4)`, `Groups (2)`, `Denied (1)` for the fixture, exactly one `aria-current="page"`
  inside it, on the link for that page, and `id="user_groups"` and `id="denied"` on the second and
  third.
- `the_users_sub_page_shows_only_its_own_list`: `/users` has no `user_groups` and no `denied`
  section, `/groups` no roster, `/denied` neither.
- `group_writes_land_on_the_group_or_the_list`: the `Location:` of add (`/groups/{name}?msg=`),
  edit (same), remove (`/groups?msg=`), and `parent()` of each group route per §1's table.
- `a_group_page_lists_scopes_then_members`: `@admins` shows `app1/admin` linked to `/apps/app1`
  before the members, each member linked to their person page; a scope that excludes the group
  carries the `excluded` tag; the scopes listed equal `user_group_refs`; an unknown member shows
  `UnknownMember`; `GET /groups/nope` is `404`.
- `a_group_nothing_references_says_so_on_its_page`: `@staff`'s scopes panel is
  `referenced by nothing`.
- `the_groups_list_is_a_table_of_counts`: one `tr` per group, the members count, the scope links,
  `referenced by nothing` alone in `@staff`'s cell (replaces
  `the_group_panel_still_says_referenced_by_nothing_alone`), and `span.pills` holding edit and
  remove.
- `a_dashboard_warning_links_to_the_page_of_what_it_names`: extend, the group line now holds
  `<a href="…/groups/unused"><code>@unused</code></a>`.
- `the_roster_shows_each_persons_groups`: `you@` row's groups cell links `@admins` to
  `/groups/admins`; `bot@` row reads `none`; with `lang=it` the header is `gruppi`.
- `the_roster_filters_by_group_exactly_and_with_the_text`: `ug=admins` keeps `you@` and
  `suspended@` only; `ug=staf` keeps nobody (`NoMatch`) and still shows the chip; `ug=admins&uq=you`
  keeps `you@` only; the chip's href drops `ug` and `up` and keeps the rest; the filter form holds
  exactly one `ug` input.
- `the_roster_filter_reaches_the_uuid_and_a_key_id`: `uq=` a fragment of `bot@`'s uuid, and
  `uq=laptop` (its key id), each keep `bot@` alone; the box's placeholder and `aria-label` are
  `FilterPeople` in both languages.
- `the_pager_says_which_rows_of_how_many`: a fixture of 60 people: page 1 reads
  `rows 1–25 of 60`, `up=3` reads `rows 51–60 of 60`; a filter matching 30 reads
  `rows 1–25 of 30 (filtered from 60)`; one unfiltered page shows no count; a filter that matches
  nothing shows no count; `it` reads `righe 1–25 di 60`; the text precedes the two pager controls;
  no `page 1/3` text anywhere.

e2e (`node e2e/run.js`): in `crud.js`, after group add/edit/remove, assert the landing URL per
§1's table. In `nojs.js`: the existing roster-filter check (line ~649) loses "the groups section
beside it" and instead asserts that the sub-tabs navigate with scripting off (`/users` to
`/groups` to `/denied`, each `aria-current` right), that `/groups/admins`' "show them in People"
lands on the filtered roster, and that the text filter submitted there keeps `ug`; add `/groups`,
`/groups/admins` and `/denied` to the list of pages checked for no script (line ~109). In
`settings.js`, `barStaysOneRow` on `/groups`.

`shots.js`: retake `users`, `groups` and `denied` (all now sub-pages; `groups` already exists at
`/groups`) and `dashboard`; add `group-detail` (`/groups/admins`), `users-by-group`
(`/users?ug=admins`) and `users-paged` (a fixture or a scene that writes enough rows for three
pages, at `?up=2`), and add `groups`, `group-detail` and `users-by-group` to the `it` view's
list. The review also needs a dark 390 shot of `/users`, which the `phone` view does not take.

#### 9. Questions for the user (users page), answered by the coordinator

All three taken as recommended, as the user asked on 2026-11-27 for the work to be carried
through with the decisions reviewed afterwards.
The user confirmed all three later that day.

1. The default sub-page is People. Should it rather be the last one the person opened (a cookie)?
   Recommended: no. A cookie makes the same URL show different pages, and the bar's Users tab
   would stop being predictable; People is the list most visits are for.
2. Each sub-tab's count is the whole list, never the filtered result. Recommended as designed:
   the filtered count is in the pager line, and a tab whose number changes as you type reads as
   the data changing.
3. A group link in the roster opens the group's page, not the filtered roster. Recommended as
   designed (§3); the alternative makes it one click shorter to see the members as a table.

### 13.37 A placeholder where a broken logo left the phone's brand empty (plan step 23, designed 2026-11-27)

**Not built: the user withdrew step 23 on 2026-11-27.** A logo that does not load is a
configuration fault to fix where the URL is set, not a state worth designing for, so §13.34 §12g
option (c) stands and a broken logo still leaves the phone's brand empty. The design below is kept
as the record of what was considered.

The user, on 2026-11-27, reversing the coordinator's choice of §13.34 §12g option (c): at 640px
and below the bar hides the brand's words and keeps the mark (`ui.logo_url`), so a mark that does
not load left the phone's brand empty; it must show a placeholder. The same day the user said the
10px gap before the words when a mark fails **above** 640px is fine as it is ("if it does not load
there is a problem"), so this design changes nothing above 640px. Read for this design:
`brand_block`, `top_bar`, the `.brand` rules and the 640px block of `admin.css`, `page_csp` and
the GUI's `img-src`, `brandWordsHidden` and `thePhoneHidesTheWordsAndTheConsoleKeepsThem` in
`e2e/tests/settings.js`, and `the_words_hide_with_a_logo_and_the_panel_rows_need_no_gap`.

**Measured** on the real server (`/tmp/d23/real.js`: boots the e2e server, writes
`ui.brand_name` "BadBat75" with the `404` mark `/img/logo.png` and then a working one through
`routeLogo`, injects the markup and CSS below into `/users` as an administrator, `/account/` and
the non-administrator's `403`; 320, 360, 390, 640, 641 and 1280; EN and IT; light and dark;
scripting on and off), and in Chromium and Firefox over the real stylesheets (`/tmp/d23/m.js`).
Contact sheet of the four 320px bars, broken and working: `/tmp/d23/sheet-320.png`.

#### 1. What it shows (placeholder)

The brand's **initial** in a 30x30 tile where the mark would be: the first character of
`ui.brand_name`, upper-cased ("BadBat75" gives "B"), bold, `--text` on `--accent-weak`, the
`--r-ctl` corner. It is the mark's height, so the bar keeps its 30px phone height, and it is a
tile with no border, so it reads as an avatar and not as a control (the brand is a `span`, not a
link, §13.34 §11). It is the deployment's own letter rather than a generic picture because the
words it stands in for are the deployment's name, and a person who sees "B" on the phone and
"BadBat75" on the laptop recognises the same place (Nielsen 6). Contrast, computed from the
palette: `--text` on `--accent-weak` over `--card` is 14.7:1 (light) and 10.7:1 (dark); `--accent` on the
same tile was 4.06:1 (light) and 3.98:1 (dark), under WCAG 1.4.3's 4.5:1
(<https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html>), which is why the letter is
`--text`.

#### 2. How it appears with no script (placeholder)

A broken `img` with `alt=""` lays out **0px wide** (measured: Chromium and Firefox, both themes,
every width), and a loaded one is its own width (96px for the suite's mark). The placeholder
uses that and nothing else, so it needs no script and no new CSP source:

```html
<span class="brand">
  <span class="mk"><img src="…" alt=""><span class="ph" aria-hidden="true">B</span></span>
  <span class="t">BadBat75</span>
</span>
```

```css
.brand .mk{display:flex;flex:none}
.brand .ph{display:none}
@media (max-width:640px){
  .brand .mk{overflow:hidden;min-width:30px}
  .brand .ph{display:flex;align-items:center;justify-content:center;flex:none;width:30px;
    height:30px;margin-right:-30px;border-radius:var(--r-ctl);background:var(--accent-weak);
    color:var(--text);font-weight:700}
}
```

The tile sits right after the image and its `-30px` right margin makes it add nothing to the
`.mk` box, so `.mk` is as wide as the image and at least 30px. A loaded mark (W of 30px or more)
puts the tile at x = W, wholly past the box's edge, and `overflow:hidden` clips it. A broken mark
is 0px, so the tile sits at 0 inside a 30px box and shows. `brand_block` writes `span.mk` and
`span.ph` only when a logo is set; with no logo the words show as they do today.

Measured with it: on all three surfaces at 320 to 640, both languages, both themes, scripting on
and off, the broken mark shows the whole 30px tile and the working mark shows none of it; the
bar stays one row, 30px tall; no page scrolls sideways; the mark-to-pill gap at 320 is 55px on
the console and 108px on `/account/`. Above 640px the image, the words, the name pill and the
bar's height are identical to today's at 641 and 1280 on all three surfaces (96 measurements
compared, no difference), which is the user's "leave it" for that width.

**The one cost**: a mark narrower than it is tall (under 30px wide at 30px high) leaves a slice
of the tile showing beside it (a 17px-wide mark showed 13px of it). No CSS can tell a loaded
image from a broken one (there is no `:broken` pseudo-class), so the box can only be sized by
the image; a portrait mark in a bar slot is rare and is the operator's to fix.

**Safari is unmeasured**: the installed WebKit does not match this Playwright build, so the
0px broken image is measured in Chromium and Firefox only. Unverified for WebKit.

#### 3. Both surfaces, and the gate (placeholder)

`brand_block` is the one brand of both shells (§13.28 §6), so the console, its `403` for a
non-administrator, and `/account/` all get the tile from one change. The gate's own pages
(`/auth/login`, `/auth/denied`, the error page) wear no bar: their mark sits above a card that
also carries the brand's name in its `h1` or footer, and they have no phone rule that hides
words, so a broken mark there costs a picture and never the name. They are untouched.

#### 4. What a screen reader hears (placeholder)

Unchanged: "BadBat75", once, from the clipped words. The tile is `aria-hidden="true"`, so the
letter is never read as a second name, and the image keeps `alt=""`. Measured with Playwright's
accessibility snapshot of `header` at 320, broken and working: `text: BadBat75` and no "B".
`aria-hidden` on a non-focusable decoration is the documented use
(<https://www.w3.org/TR/wai-aria-1.2/#aria-hidden>).

#### 5. Alternatives rejected (placeholder)

- **An `onerror` script** that removes a broken image so the words return (§13.34 §12g (b)).
  Works, but adds an inline handler to every page of both programs under AGENTS.md's "used
  sparingly" rule, does nothing with scripting off, and brings back the words a 320px bar has no
  room for.
- **Visible alt text** (`alt="BadBat75"`, styled). A broken image would show its alt, but a
  loaded one would then name the deployment twice to a reader beside the words, and above 640px
  a broken one would print the name twice on screen.
- **`<object data=… >fallback</object>`**: the fallback is exactly the behaviour wanted, but
  both programs' policies are `default-src 'none'` with no `object-src`, and an SVG in an
  `object` is a document that can run script, which is a hole for a logo.
- **The tile stacked under the image** (one grid cell, the image painted over it): a transparent
  mark shows the letter through it, unless the image gets the bar's background, which breaks the
  moment an operator's stylesheet gives the header another ground.
- **A CSS background on `.brand`**: the letter would have to be the brand's, which means a
  per-deployment `data:` image in a `style` attribute, which the hash-only CSP refuses.

#### 6. Tests (placeholder)

Rust (`src/bin/bb-auth-web.rs`):

- `the_words_hide_with_a_logo_and_the_panel_rows_need_no_gap`: keep the clip-pattern checks; add
  that `brand_block(name, Some(src), "")` holds `span class="mk"` with the `img` then
  `span class="ph" aria-hidden="true"` whose text is the name's first character upper-cased
  (`"badBat"` gives `B`), that `brand_block(name, None, "")` holds neither `mk` nor `ph`, and
  that the 640px block's `.brand .ph` rule has `margin-right:-30px`, `width:30px`,
  `height:30px` and `.brand .mk` has `overflow:hidden` and `min-width:30px`, while the
  top-level `.brand .ph` is `display:none`. The "And only on a phone" loop is unchanged.
- `only_the_palette_names_a_colour` already covers the tile's two tokens.

e2e (`e2e/tests/settings.js`, `thePhoneHidesTheWordsAndTheConsoleKeepsThem`):

- With the `404` mark, at 360 and 320 on the console, `/account/` and the `403`: `header .brand
  .ph` is visible, its box is 30x30 and lies wholly inside `header .brand .mk`'s box, its text is
  "B", the words stay the clipped strip (`brandWordsHidden`), and the bar is one row, at most
  40px. At 1280 and 884, the tile computes `display:none` and the words are whole (today's
  checks).
- With the routed mark at 360: the tile's visible width inside `.mk` is 0 and the mark keeps its
  96px.
- The accessible name of `header .brand` is "BadBat75" (no "B"): `aria-hidden` on `.ph`.
- `nojs.js` needs nothing new: the walk above has no script in it.

`e2e/shots.js`: retake `header-logo-broken` (phone and `it`; its phone shot now shows the tile)
and `header-logo`; `e2e/README.md`'s `phone` row, which says the broken mark leaves the brand
empty, changes with it (docs agent).

#### 7. Question for the user (placeholder)

1. The tile shows the brand's **initial**. The alternative is one generic picture (a neutral
   image glyph) for every deployment. Recommended: the initial, because it is the deployment's
   own and carries over to the words a wider screen shows; the glyph says only "something is
   missing", which the person cannot fix.
