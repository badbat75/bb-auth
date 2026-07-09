# bb-auth — Authentication Flow

End-to-end sequence by which a user gets from a cold browser to an authenticated
session on a service behind the bb-auth gate. Hostnames below are placeholders:
`app.example.com` is the protected service and `login.example.com` is the login
page. Three phases: **access check** (nginx → bb-auth gate), **login** (browser ↔
login page ↔ Cognito ↔ bb-auth), and **per-request validation** thereafter.

For the service's internal structure and config, see
[`ARCHITECTURE.md`](./ARCHITECTURE.md).

---

## Actors

| Actor | Where |
|-------|-------|
| **Browser** | The user's UA. Holds the session cookie after login. |
| **nginx** | Edge on the service host, `:443`. TLS terminator + `auth_request` enforcer. |
| **bb-auth** | `127.0.0.1:4181`, loopback only. Validates Cognito id_tokens and issues/verifies the session cookie. |
| **Login page** | `https://login.example.com/`. Email-first UI; runs the Cognito `USER_AUTH` flow in the browser and `POST`s the resulting id_token to bb-auth. |
| **AWS Cognito** | A user pool + public app client. Issues RS256-signed id_tokens. |

---

## Phase 1 — First visit (no cookie) → redirect to login

```text
 browser ──GET https://app.example.com/────────────────────▶ nginx :443
 nginx: auth_request → /internal/auth-gate
        └─ proxy to bb-auth GET /auth/validate
                 (no Cookie, or invalid cookie)
                 └─ 401
        error_page 401 = @bb_signin
 nginx ──302 https://login.example.com/?rd=https://app.example.com/──▶ browser
```

Key points:

- nginx carries the original destination as `?rd=<scheme://host$request_uri>`.
- The login page receives `rd` and will replay it back to bb-auth at the end.
- The user has **not** talked to Cognito yet.

---

## Phase 2 — Login on the login page (browser ↔ Cognito)

This phase happens entirely outside bb-auth; bb-auth only sees its result. The
page talks to Cognito directly on the **public** client using the `USER_AUTH`
flow.

### 2a — Returning user (email exists)

```text
 browser ─▶ login.example.com
 page → Cognito InitiateAuth  (USER_AUTH, preferred auth = EMAIL_OTP)
 Cognito ──emails OTP──▶ user
 page → Cognito RespondToAuthChallenge(EMAIL_OTP)
 Cognito ──id_token (+ access/refresh)──▶ page
```

### 2b — New user (email not found) — the frictionless path

This is the whole reason bb-auth exists: registration that **auto-logs-in without
a second OTP**.

```text
 page → Cognito SignUp(email)
 Cognito ──emails signup code──▶ user          (code is delivered but NOT required to proceed)
 page → Cognito ConfirmSignUp(code)            (page completes confirmation programmatically
                                               when the code arrives, OR the flow is wired so the
                                               same OTP confirms + authenticates)
 page → Cognito InitiateAuth(session)          (reuses the session from SignUp)
 Cognito ──id_token──▶ page
```

In both 2a and 2b the page ends up holding a valid **id_token** for a
`token_use=id`, `email_verified=true`, RS256-signed JWT whose `aud` is the public
client id.

---

## Phase 3 — Exchange id_token for session cookie (browser → bb-auth)

The page performs a **top-level form POST** (so the session cookie lands on
`app.example.com`, not on the login-page host):

```text
 browser ──POST https://app.example.com/auth/session──────────────────────▶ bb-auth
            body: application/x-www-form-urlencoded
                  id_token=<JWT>&rd=https://app.example.com/...
```

Inside bb-auth (`handle_session`):

1. Read up to 64 KiB of body; parse `id_token` and `rd`.
2. **`validate_id_token`:**
   - header `alg == RS256`; read `kid`.
   - look up `kid` in the JWKS cache (refresh once per 60 s on a miss).
   - verify signature + `exp` (60 s leeway) + `iss` + `aud == client_id`;
     require `exp`/`aud`/`iss` present.
   - require `token_use == "id"` and `email_verified` truthy. Exception: if
     `BB_AUTH_ALLOW_UNVERIFIED_SOCIAL` is on, an `email_verified=false` token is
     accepted when it carries a federated `identities` entry (a social login),
     optionally narrowed to `BB_AUTH_SOCIAL_PROVIDERS`. Native users stay strict.
   - extract and lowercase the `email` claim, and require it to be printable ASCII
     (`header_safe_email`) — it will be handed to the app in `X-Auth-Email`, and on a
     `public_auth` site no table has vetted it.
3. **Access-table check:** `email` must not be in `denied`, and must be either present in
   the roster (`by_email`) or able to go somewhere — i.e. some site grants `public_auth`.
   The cookie is identity, not authorization: it grants nothing on its own, and every
   request it accompanies is re-authorized. This `403` is a courtesy, so someone who is
   not enrolled hears it at the login page instead of bouncing off a `401` later.
4. **Build the cookie** (see `ARCHITECTURE.md` §7):
   `bb2.<keyid>.<exp>.<b64url(email)>.<b64url(HMAC_SHA256(prefix))>`, signed with
   the active key, `exp = now + TTL`.
5. **`safe_rd(rd)`:** the redirect target must resolve to an `https://` URL whose host
   matches `BB_AUTH_AUTHORIZED_HOSTS`. An absolute path (no `//`, no `/\`) resolves
   against the caller's own host, which nginx supplies via `X-Original-URL` on this
   very request; with no `rd` at all the browser lands on that host's root. Any
   control byte (incl. CR/LF) is rejected. Anything else falls back to the login page.
   This blocks open-redirect abuse and response splitting.
6. Respond `302` to `rd` with `Set-Cookie: <cookie>=…; HttpOnly; Secure;
   SameSite=Lax; Max-Age=2592000`.

Outcomes the user can see:

| Result | Status | Page shown |
|--------|--------|------------|
| Missing/empty `id_token` | `400` | “Missing token.” |
| Token invalid/expired/claims wrong | `401` | “The access token is invalid or has expired.” |
| Token valid but the email is `denied`, or is unknown with no `public_auth` site to reach | `403` | “This email address is not allowed to sign in.” |
| Success | `302 → rd` | (cookie set, back to the app) |

---

## Phase 4 — Authenticated request (cookie present)

Every subsequent request to `app.example.com` re-enters the nginx gate. The gated
location captures the original request URL (`set $bb_url https://app.example.com$uri;`)
and the gate forwards it as `X-Original-URL $bb_url` — `$uri` inside the subrequest
would be `/internal/auth-gate`. For programmatic clients it also forwards the
`Authorization` header:

```text
 browser ──GET https://app.example.com/?...  Cookie: <cookie>=bb2...──▶ nginx
 nginx: auth_request → /internal/auth-gate → bb-auth GET /auth/validate
        (X-Original-URL: https://app.example.com/...
         [+ Authorization: Bearer … for API clients])
 bb-auth (handle_validate), first credential that authorizes wins:
   a. Authorization: Bearer bbk_…  → static API key: sha256(bearer) in by_key_hash,
      owner not denied, unexpired, request URL in the key's scope. No site applies.
   b. Authorization: Bearer <id_token>  → validated as in Phase 3, then authorize()
   c. session cookie → verify_session: split up to 5 parts; version==bb2 → key by id
      (bb1 legacy → try every accepted key); HMAC verify_slice (constant-time);
      exp>now; then the lowercased email it carries → authorize()
   authorize(email, url): denied? → 401.  Else a site covering `url` with
      public_auth → granted, roster not consulted.  Else roster: email in by_email
      and url in that user's scope.
   └─ 204 + X-Auth-Email: <the authorized user> if any of a/b/c authorizes, else 401
 nginx: auth_request_set $bb_email $upstream_http_x_auth_email
 nginx ──proxy to upstream app (X-Auth-Email: …)──▶ browser (the app's response)
```

A few things are worth emphasizing:

- **The access table is re-checked on every request**, not just at login. Removing
  a user (or one of their API keys), or adding them to `denied`, and reloading/restarting
  bb-auth revokes access immediately, even for a still-unexpired, correctly-signed cookie
  or API key. On a `public_auth` site the roster is never consulted, so there `denied` is
  the only lever — removing the row changes nothing.
- **Bearer credentials fall through to the cookie**, so a stray `Authorization`
  header never blocks a valid cookie. Static `bbk_` API keys (see
  [`ARCHITECTURE.md`](./ARCHITECTURE.md) §12) let non-browser clients (e.g. MCP)
  authenticate without the cookie flow; every credential is also confined to its
  `authorized_urls` patterns, and a restricted scope with `X-Original-URL` missing is
  denied (`401`).
- **A `public_auth` site grants on identity alone.** Anyone Cognito vouches for reaches
  it, enrolled or not — and since self-signup is open, that means anyone who can register.
  It is how an onboarding area gets an `X-Auth-Email` for someone it is about to enroll.
  An unknown `bbk_` key is not rescued by it: Cognito vouches for no key of ours.
- **The gate names the user; the app trusts nginx for it.** A `204` carries the
  authorized email in `X-Auth-Email`, the gated location lifts it with
  `auth_request_set` and passes it upstream. An API key resolves to its *owning
  user's* email. The app must not decode the credential itself: the cookie is not a
  JWT and an API key carries no token, and a valid `id_token` proves identity, never
  authorization. This holds only while the app is unreachable except through nginx.
- **Verification is stateless.** No server-side lookup is needed; any of the
  worker threads can validate any cookie, and a restart changes nothing about
  existing cookies (they are time-bound, not session-store-bound).
- The cookie is `HttpOnly` + `Secure` + `SameSite=Lax`, so it is not readable by
  JS and is sent on top-level navigations/GETs to the service host.

---

## Phase 5 — Logout

```text
 browser ──GET https://app.example.com/auth/logout[?rd=/app1/goodbye]──▶ bb-auth (handle_logout)
 bb-auth: if Sec-Fetch-Site is not "cross-site":
            Set-Cookie: <cookie>=; Max-Age=0; ...   (expire)
          302 → safe_rd(rd), or the login page when there is no rd
```

Same-origin / same-site / direct navigations (a normal logout link click) clear
the cookie. A cross-site navigation (`Sec-Fetch-Site: cross-site`, i.e. a CSRF
logout) is ignored — the attacker cannot force the victim to log out. If the
header is absent (legacy browsers) the cookie is still cleared.

Where the browser lands is the logout link's choice, guarded by the same `safe_rd` used
on `/auth/session`. There is no per-site landing page: `/auth/logout` is covered by no
site's `urls`, so the gate cannot tell which area is being left — unlike a `401`, which
happens on a gated URL and therefore can name that site's `login_url` in
`X-Auth-Login-URL`. A relative `rd` needs `X-Original-URL` on this location too;
without it the redirect falls back to the login page.

This clears the bb-auth session cookie only. It does **not** revoke the Cognito
refresh token the login page may still hold; the browser will need to re-enter
Phase 2 on next access. (Cognito global sign-out is intentionally out of scope —
the gate only manages its own cookie.)

---

## Full sequence (happy path, new user)

```text
 browser        nginx         bb-auth       login page    Cognito
   │              │              │              │             │
   │─GET /───────▶│              │              │             │
   │              │─validate────▶│              │             │
   │              │◀──401────────│              │             │
   │◀──302 login/?rd=…───────────│              │             │
   │─GET login/?rd=…───────────────────────────▶│             │
   │              │              │              │─SignUp──────▶│
   │              │              │              │◀──(session)──│
   │              │              │              │─Confirm──────▶│
   │              │              │              │─InitiateAuth▶│
   │              │              │              │◀──id_token───│
   │─POST /auth/session id_token=…&rd=…────────▶│             │
   │              │              │─JWKS (cache) │             │
   │              │              │  verify sig+claims          │
   │              │              │  email ∈ users table        │
   │              │              │  build HMAC cookie          │
   │◀─────────────302 rd  Set-Cookie <cookie>─────────────────│
   │─GET / Cookie: <cookie>─────▶│              │             │
   │              │─validate────▶│              │             │
   │              │◀──204────────│              │             │
   │              │  X-Auth-Email│              │             │
   │◀── app response ────────────│              │             │
```

---

## Trust boundaries

- **Browser ↔ nginx:** public TLS. The cookie travels only here, on HTTPS.
- **nginx ↔ bb-auth:** loopback HTTP, same host, not exposed. nginx strips the
  request body before calling `/auth/validate` (`proxy_pass_request_body off`).
- **bb-auth ↔ Cognito:** outbound HTTPS **only** — bb-auth fetches the public
  JWKS and never sends anything to Cognito. It holds no client secret.
- **Browser ↔ Cognito:** direct, from the login page on the public client; bb-auth
  is not in this path at all.

The credential crossing a trust boundary is the **id_token** (browser → bb-auth
via the `POST`). Its integrity does not rely on the transport: bb-auth verifies
the RS256 signature against Cognito's published JWKS before trusting anything in
it.
