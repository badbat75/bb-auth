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
| `src/bin/bb-auth-web.rs` (`bb-auth-web`) | **The access-file admin GUI**: server-rendered (`maud`; no page needs JavaScript, the one inline handler is a Settings-menu shortcut with a `<noscript>` submit behind it) over the library, read *and* write — CRUD through `AccessWrite` alone, `POST`-only mutations behind a same-origin check and a `rev` (sha256-of-file) concurrency check. Loopback behind nginx `auth_request`, identity from the `X-Auth-Email` nginx injects plus its own administrator allowlist (`web.admins` in the settings file, read fresh on every request and editable from its own Settings tab). The **self-service page** at `BB_AUTH_WEB_ACCOUNT_PATH` (`/account`) is the one part of it a person who is not an administrator reaches: dispatched *ahead of* `web.admins`, since an administrator there is one more person acting on their own account, with four sections about the caller (reach, groups and profile read-only, the API keys section carrying the caller's own mint, rotate and revoke), the `denied` veto answered ahead of them, the `ui` look in a centred card, and a theme and language selector answered by one `302` setting the console's own cookies. The two prefixes are siblings, and `compile_account_path` refuses at startup a page equal to, inside or containing the console's base, which is what makes an empty `BB_AUTH_WEB_BASE_PATH` a fatal startup. See §13. Links the library, none of the gate. |

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
| `GET` | `/auth/validate` | nginx only (`auth_request`) | `204` naming the identity in one header per `identity_attrs` entry (default `X-Auth-Email`) if an accepted credential authorizes the request URL; `401` + `X-Auth-Login-URL: <this area's login page>` when nothing identified the caller; `403`, and no login page, when something did and no scope admits them. A `204` also carries one header per `profile_claims` entry the credential knows (percent-encoded; omitted otherwise). Accepts (in order) an `Authorization: Bearer bbk_…` static API key, an `Authorization: Bearer <id_token>`, or the session cookie, and then no credential at all, which only an `anonymous` scope grants. A request with no credential names nobody; one that carried a valid credential is still named, so the header is bimodal on such a scope and an application there must treat it as "if you know who this is, say so". A **vetoed** identity is never named. See §12. |
| `GET`, `HEAD` | `/auth/login[?rd=…]` | browser | The sign-in page: runs the Cognito `USER_AUTH` flow in the browser and POSTs the resulting id_token to `/auth/session`. Self-contained (palette, layout, script and both languages in the document; only the operator's optional stylesheet and logo are external). `rd` is validated here with the same `rd_url_allowed` `safe_rd` uses and dropped if it fails; with none, the browser's `Referer` answers in its place, through that same check and absolute-only, since this page resolves nothing against nginx. Social buttons appear only when `gate.oauth_domain`, `gate.social_callback_url` and at least one `gate.social_buttons` entry add up to a social sign-in that could work. |
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
   action and its values (and the `rev`, for a deletion). `Cache-Control: no-store`.
3. The code `POST` re-checks everything against the live files (identity, veto, the email still
   among the caller's, the attributes still editable), calls `RespondToAuthChallenge`, then the
   action with the `AccessToken`, and drops all three tokens. None is logged, stored, or put in
   a cookie.

The `Session` lasts `AuthSessionValidity`, 3 to 15 minutes per app client
([UserPoolClientType](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UserPoolClientType.html));
the value on the real pool is **unverified**. A late code is `NotAuthorizedException` and the
page starts again. The action is bound to the right Cognito user without reading any token,
because `USERNAME` is one of the caller's own identifiers and the code goes to that inbox.
**Assumed:** the pool signs in by email, which `login.html` relies on too; the read-only
`describe-user-pool` under "Waiting for the user" confirms it.

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

**Editable attributes**: those in `gate.profile_claims`, minus `email`, `phone_number`,
`preferred_username` and anything under `dev:`. Cognito's `WriteAttributes` on the app client is
the second authority ([attribute permissions](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-attribute-permissions-and-scopes)),
and its refusal is reported. **`email` is not editable**: it is the roster's identity key, and
depending on `AttributesRequireVerificationBeforeUpdate` a change either replaces the sign-in name
unverified (a lockout, since `email_verified` is mandatory for native users) or leaves the roster
naming an address the token no longer carries
([verifying changed emails](https://docs.aws.amazon.com/cognito/latest/developerguide/signing-up-users-in-your-app.html#verifying-when-users-change-their-email-or-phone-number)).
It stays an administrator's job, and the page says so.

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

After the confirmation page and the email code of 13.7, in this order:

1. **The roster row**, through `AccessWrite` with the `rev` from the confirmation form:
   `remove_user` on the caller's uuid (keys, scope and group references, the `excluded` and
   `denied` rewrites of 13.8).
2. **The Cognito user**, `DeleteUser` with the access token from step 3 of 13.7.

If step 2 fails, what is left is a Cognito user with no row, an `authenticated` stranger who
reaches only `authenticated` scopes and holds no key; the other order, on a failed write, would
leave a row with live API keys and every grant waiting for the same person to re-register. If
step 1 fails (`409`, I/O), nothing has changed. If step 2 fails, the page says the row is gone and
the Cognito account is not, and offers the retry, which the person still reaches as a stranger.

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
- `/account/` reveal: `script-src <hash(COPY_SCRIPT)>`, and nothing else.
- **Every other response keeps the policy it has**: the console's `'unsafe-hashes'` plus the
  one handler, `/account/`'s `'none'`.

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
  `Content-Security-Policy`, and no `on…` attribute beyond the console's two.
- `the_reveal_shows_only_the_key`: on all four reveal responses, the text of `code id="bearer"`
  equals the bearer exactly, the body contains no `Authorization`, the bearer occurs once in the
  body and that occurrence is inside the `code` element, and the button is `type="button"` and
  carries `hidden`.
- `only_the_reveal_policy_names_the_copy_script`: `admin_csp(_, false)` and `account_csp(_, false)`
  do not contain `csp_hash(COPY_SCRIPT)`, and `account_csp(_, false)` still says
  `script-src 'none'`; the `true` variants contain it. A failed mint (the `400` key form) and the
  `409` carry no script.

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
| brand | `a.brand` "bb-auth-web" plus version, links home. (Changed by §13.18: `ui.brand_name`, else `bb-auth`, over `K::ConsoleTag` ("Administration" / "Amministrazione"), still a link; the version is the footer's alone) | `span.brand.selfserve-brand`: the `ui.logo_url` image (when set) and `ui.brand_name`, where the page shows them today; not a link, since the page is the only one |
| tabs | the five `nav` pills | an empty `nav`, which is what the console's own `403` page already renders |
| identity | **new**: `span.who.muted` in `nav.acct`, the address | the same: the given name and the first address ("Bot · `bot@example.com`"), or the address alone |
| Preferences | `details.settings` "Preferences" (`K::Settings`), Language then Theme, `onchange` applies, `noscript` Apply | the same `details` and `.menu` and order, **no `onchange`**, and the Apply `button` in `div.actions` always present |
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
no longer holds; the reason for the first half stands.)

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
  `p.lede` carries the address and `K::AccountNoRow` instead of the uuid.
- The four sections keep their ids and order (`#reach`, `#groups`, `#keys`, `#profile`): each
  a `.panel` with `h2` and one `p.lede.sub` saying what it is for (the class the console's
  sections already use for this): `K::AccountReachSub`, `K::AccountGroupsSub`,
  `K::AccountKeysSub`, `K::AccountProfileSub` (texts as listed below).
- Where you reach: `ul.plain` of `code` `app/scope`, the console's own person-page list.
- Groups: `ul.plain` of `code`. Heading `K::AccountGroups` ("Groups").
- API keys: §13.16.
- Profile: `ul.plain`, `code` claim, then the value, or `span.muted` `K::AccountNotProvided`
  ("not provided") where the deployment configured a claim that was not forwarded. Step 5's
  edit goes here.
- Delete my account (step 7) will be a last `.panel.bad`, after Profile.
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
  `K::AccountNoRow` as plain text. The old `p` "signed in as" and the separate uuid `p` go:
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
stranger: the address and `AccountNoRow`, no uuid; no "signed in as" in `main`);
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
open with the identity line, both list boxes and Apply.

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
in as" change.

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
  `icon_controls_are_named_by_hidden_text` extended to the account page.
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
changes and no script is added, so the account page keeps "no handler at all".

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
