# bb-auth

Minimal **auth gate**. It accepts an AWS **Cognito `id_token`** that a browser
already obtained and turns it into an HMAC-signed session cookie that a reverse
proxy (nginx `auth_request`) enforces on every request. It is
**service-agnostic** — it fronts any web service and is wired per-deployment
through `BB_AUTH_*` env vars.

## Why

Authorization-code OIDC proxies (e.g. oauth2-proxy) drive the login themselves:
they redirect the browser to the IdP's hosted login and exchange the returned
code. They **cannot accept a token the browser already obtained** — which is what
a "frictionless" browser-driven flow produces. bb-auth is built for that model: a
login page runs the Cognito `USER_AUTH` flow in the browser (which enables
sign-up and auto-login with no second OTP) and ends up holding an `id_token`.
bb-auth takes
that token, validates it, and issues the session cookie.

## Flow

```text
browser ── hits the protected service ──▶ nginx auth_request → GET /auth/validate
   │                                          └─ 401 (no/!valid cookie)
   ▼
nginx error_page 401 → 302  <login-page>/?rd=<original>
   │  (login page; talks to Cognito directly on the public client)
   │   • email exists  → InitiateAuth USER_AUTH / EMAIL_OTP → id_token
   │   • not found     → SignUp → ConfirmSignUp → InitiateAuth(Session) → id_token  (auto-login)
   ▼  top-level form POST  id_token=…&rd=…
<service>/auth/session  (bb-auth)
   • validate id_token (RS256 via JWKS, iss/aud/exp, token_use=id, email_verified)
   • email on allowlist?  → Set-Cookie (HMAC, ~30d) ; 302 → rd
   ▼
<service>  → nginx auth_request → /auth/validate → 204 → upstream app
```

## Endpoints

| Method | Path             | Who        | Purpose                                            |
|--------|------------------|------------|----------------------------------------------------|
| GET    | `/auth/validate` | nginx only | `auth_request`: 204 + `X-Auth-Email` if the session cookie, an `Authorization: Bearer <id_token>`, or a static `Authorization: Bearer bbk_…` API key authorizes the request (in a user's URL scope, or on a `public_auth` site), else 401 + `X-Auth-Login-URL` |
| POST   | `/auth/session`  | browser    | validate posted `id_token`, set cookie, 302 → `rd` |
| GET    | `/auth/logout`   | browser    | clear cookie, 302 → `rd` (guarded) or the login page |
| GET    | `/auth/healthz`  | local      | liveness                                           |

## Programmatic access (Bearer)

The cookie flow is for browsers. A programmatic client (e.g. an MCP client) sends
its credential on every request as a bearer, which `/auth/validate` checks **before**
the cookie. Two kinds are accepted; either way nothing is stored server-side and no
cookie is issued (a stateless per-request credential), and a failed bearer falls
through to the cookie check. The reverse proxy must forward the `Authorization`
header on the `auth_request` subrequest (`proxy_set_header Authorization
$http_authorization;`).

**1. Cognito `id_token`** — for a client that already holds one (a scripted
`USER_AUTH`/`USER_PASSWORD_AUTH` call, a device flow, a cached token):

```text
Authorization: Bearer <cognito_id_token>
```

Validated with the **same** checks as `/auth/session` (RS256 via JWKS, iss/aud/exp,
`token_use=id`, `email_verified`), then the email must be granted the URL — by the
access file's roster, or by a `public_auth` site.
No flag needed: a valid id_token for an allowlisted email is exactly the credential
`/auth/session` already trusts to mint a 30-day cookie. Mint/refresh one with
[`tools/bb-token.py`](tools/bb-token.py) (dependency-free Python 3 stdlib; runs the
passwordless email-OTP login against Cognito's public API, caches + auto-refreshes):

```bash
python tools/bb-token.py login --email you@example.com      # once (emails you a code)
curl -H "$(python tools/bb-token.py header)" https://mcp.badbat75.com/mcp/foo/
```

**2. Static API key (`bbk_…`)** — a long-lived key that needs no Cognito round-trip:

```text
Authorization: Bearer bbk_<secret>
```

bb-auth looks it up by `sha256(bearer)` in the access file (only the hash is stored,
never the raw key), checks its owner is not `denied`, checks it is not past its
`duration`, and enforces its URL scope. A `public_auth` site does **not** rescue an
unknown key — that grant is for identities Cognito vouches for, and an unknown key is
nobody. Mint one with [`tools/bb-apikey.py`](tools/bb-apikey.py) — it prints the raw
bearer **once** and a JSON entry to paste into the owning user's `api_keys`:

```bash
python tools/bb-apikey.py bob@badbat75.com --id laptop --duration 365d \
    --urls 'https://mcp.badbat75.com/mcp,https://mcp.badbat75.com/mcp/*'
# → Authorization: Bearer bbk_…  (give to the client)   +   { "id": "laptop", "key_hash": … }
```

## Passing the identity to the app

All three credentials resolve to one thing: an email. A `204` from `/auth/validate`
carries it in **`X-Auth-Email`**, which nginx lifts out of the subrequest and injects
into the request it proxies — that is how the app behind the gate learns who is
calling. An API key resolves to its **owning user's** email: a key acts as its user.
On a [`public_auth` site](#sites-and-public_auth) the email may name someone with no
entry anywhere — an *authenticated* identity that the app is expected to enroll.

```nginx
auth_request_set $bb_email $upstream_http_x_auth_email;
proxy_set_header X-Auth-Email $bb_email;   # rename to whatever the app reads
```

`auth_request_set` belongs in the **gated location**, not in the gate's own location.
The header name bb-auth emits is fixed; nginx renames it on the way through, so an app
expecting `X-Forwarded-User` or `Remote-User` needs no change on this side.

Two things make the header trustworthy, and both are required:

- **nginx sets or clears it on every gated location.** `proxy_set_header` overwrites
  whatever the client sent and nginx drops the header when the variable is empty — but
  only for the names it lists. Explicitly clear any *other* name the app also trusts.
- **The app is unreachable except through nginx** (loopback, unix socket, firewall).
  An app reachable directly believes any header anybody sends it.

The app should **not** try to read the identity itself. Usually there is nothing to
read: the session cookie is not a JWT (it carries only the email, HMAC-signed) and an
API key has no token at all, so decoding a claim would work for exactly one of the
three credentials. It would not be safe either — Cognito self-signup is open, so a
valid `id_token` proves *identity*, never *authorization*. What decides authorization
is the access file, and only the gate reads it.

## URL scoping

Each user, and each key, carries `authorized_urls` — a list of full
`<scheme>://<host>/<path>` patterns it is allowed to reach. **Access is enumerated,
never assumed:** a user with no `authorized_urls` (or an empty list) reaches nothing.
Blanket access is spelled out, as `["*://*/*"]`. A key with no `authorized_urls`
inherits its user's scope.

Two wildcards, valid in **every** component — scheme, host and path:

| | |
|---|---|
| `*` | any run of characters, but never `/` — **except** as the pattern's final character, where it swallows the rest of the URL, slashes included |
| `&` | exactly one character, never `/` |

The match is anchored at both ends. Because a non-final `*` cannot cross `/`, and
`://` contains two of them, no wildcard ever leaks from one component into the next.

```text
https://app.example.com/path1/*           →  /path1/ , /path1/a , /path1/a/b/c.png     (not /path1)
https://app.example.com/path1/*/          →  /path1/a/ , /path1/ab/                    (not /path1/a/b/)
https://app.example.com/path1/*/images/*  →  /path1/a/images/x.png , …/images/sub/y.png
https://app.example.com/v&/*              →  /v1/x , /v9/x                             (not /v10/x)
*://app.example.com/mcp/*                 →  either scheme
https://*.example.com/mcp/*               →  any subdomain (`*` crosses dots, so also a.b.example.com)
*://*/*                                   →  everything: the only way to grant it
```

Put the `/` before the `*`: `…/mcp/*` covers the subtree, whereas `…/mcp*` would also
match `/mcp-admin`. And `…/mcp/*` does **not** match a bare `/mcp` — list both if the
client hits the parent too. The host and scheme match case-insensitively; the path
does not. Ports never appear (nginx's `$host` omits them), so don't write one.

Scoping needs the original request URL, so nginx must pass it on the subrequest —
see [the nginx wiring](#putting-a-service-behind-the-gate). Since every credential is
scoped, that header is **required**: a request without it is denied, as is any URL
containing `..` (fail-closed on both counts).

## Access file

The access gate is a single JSON file (`BB_AUTH_USERS_FILE`, installed as
`/opt/bb-auth/var/lib/users.json`; see [`deploy/users.example.json`](deploy/users.example.json)).
Three sibling sections answer three different questions:

```json
{ "sites": [
    { "name": "signup", "urls": ["https://app.badbat75.com/welcome",
                                 "https://app.badbat75.com/welcome/*"],
      "public_auth": true }
  ],
  "denied": ["spammer@badbat75.com"],
  "users": [
    { "email": "you@badbat75.com", "authorized_urls": ["*://*/*"] },
    { "email": "bot@badbat75.com",
      "authorized_urls": ["https://mcp.badbat75.com/mcp", "https://mcp.badbat75.com/mcp/*"],
      "api_keys": [
        { "id": "laptop", "key_hash": "<sha256 hex of the bbk_ bearer>",
          "released": "2026-07-08", "duration": "365d",
          "authorized_urls": ["https://mcp.badbat75.com/mcp/*"] }
      ] }
] }
```

A request is authorized when its credential resolves to an identity and one of exactly
**two grant sources** covers the request URL: the user's `authorized_urls`, or a
`public_auth` site. Both are re-checked on every `/validate`. The one thing that takes
access away is `denied`.

### `users` — the roster

- **`email`** (required) — matched case-insensitively; its presence is the allowlist.
- **`authorized_urls`** — allowed URL patterns (see [URL scoping](#url-scoping)). Omitted or `[]` grants nothing; `["*://*/*"]` grants everything.
- **`api_keys[]`** — static `bbk_` keys for that user (see [Programmatic access](#programmatic-access-bearer)):
  - **`key_hash`** — `sha256` of the bearer; the raw key is never stored (mint via `tools/bb-apikey.py`).
  - **`duration`** — `<n>d` / `<n>h` / `0` / `never`, counted from **`released`** (`YYYY-MM-DD`).
  - **`id`** — human label for logs/revocation. **`authorized_urls`** — omit to inherit the user's scope.
  - Unknown fields (e.g. `notes`) are ignored, so annotate freely.

### Sites and `public_auth`

A site describes a **URL area**, never a person: no field of it may name a user. That
line is what keeps `sites` from becoming a second, conflicting way to say what
`authorized_urls` already says — and it is why a user removed from the roster cannot
walk back in through a site.

- **`urls`** — the same `<scheme>://<host>/<path>` patterns as `authorized_urls`. A malformed one is fatal.
- **`public_auth`** — grant this area to **any** identity Cognito vouches for, enrolled in `users` or not. This is the point: it is how someone who has just registered reaches an onboarding area, with the app receiving their `X-Auth-Email` and enrolling them. `false` (the default) grants nothing and is indistinguishable from having no site at all — the field exists to carry future properties.
- **`login_url`** — an absolute `https://` login page for this area, overriding `BB_AUTH_LOGIN_URL` (see [Per-site login page](#per-site-login-page)). Validated at load: printable ASCII, https, no userinfo `@`, no backslash — it ends up in a header and a redirect.
- **`name`** — a label for the logs (`granted via site 'signup' (public_auth): …`), which is your only visibility into who is walking in un-enrolled.
- Unknown fields are a **hard error** here, unlike everywhere else. The day `public_auth` gains a companion restriction, a typo in that companion must not be silently dropped, leaving `public_auth: true` standing alone — that would fail *open*.

**First match wins**, in file order: the first site whose `urls` cover the request
answers for it — for `public_auth` *and* for `login_url` — even if it grants nothing. Put
specific sites before broad ones. A URL with no site is not denied — it is simply not
open, and the roster decides as before.

> Cognito self-signup is open, so `public_auth` means *anyone who can register*. It is
> the right grant for an onboarding page and the wrong one for everything else. An
> `id_token` behind it still proves a verified email (unless
> `BB_AUTH_ALLOW_UNVERIFIED_SOCIAL` is on, which widens this further).

### `denied` — the veto

Lowercased emails refused on **every** credential and **both** grant sources, checked
before anything else. It is not the same as deleting the user's row:

- On a `public_auth` site the roster is never consulted, so for an un-enrolled identity this is the **only** denial that exists.
- For an enrolled one it is a *suspension*, not a deletion: their scope and their API keys survive the lockout, so re-enabling is a one-line edit. (A user's `authorized_urls: []` locks them out of the roster grant — but **not** out of a `public_auth` site. That is what `denied` is for.)

Like everything else it applies from the next request; a cookie or `id_token` already
in flight is stateless and cannot be recalled mid-request.

### Per-site login page

bb-auth never redirects a gated request: it answers `401` and **nginx** decides where to
send the browser. So the way a site names its own login page is a response header the
gate sets on that `401`, which nginx lifts with `auth_request_set` — exactly as it
already does for `X-Auth-Email`:

```nginx
# http{} level. An empty $bb_login means the gate named no login page — a stale
# binary, or a location with no auth_request_set. Falling back to the global URL
# here is what keeps @bb_signin from emitting a *relative* `Location: ?rd=…`,
# which redirects the browser to the gated path it just came from: a loop.
map $bb_login $bb_login_safe {
    ""      https://login.example.com/;   # = BB_AUTH_LOGIN_URL
    default $bb_login;
}

location /app1 {
    set $bb_url https://app.example.com$uri;
    auth_request     /internal/auth-gate;
    auth_request_set $bb_login $upstream_http_x_auth_login_url;
    error_page 401 = @bb_signin;
    ...
}
location @bb_signin { return 302 $bb_login_safe?rd=$scheme://$host$request_uri; }
```

The header carries the site's `login_url`, or `BB_AUTH_LOGIN_URL` when it declares none.
`auth_request_set` copies it into a request variable, which is what stops a later
`proxy_pass` from clobbering `$upstream_http_*`; it reads the subrequest's headers even
though the subrequest answered `401`, which is the whole reason this works. Without the
`auth_request_set` line nothing breaks — the `map` yields the global URL, exactly as a
hardcoded `@bb_signin` did before.

The gate can name the login page here because a `401` happens **on** a gated URL, so the
site resolves. Logout gets no such luck.

### Logging out

`GET /auth/logout` clears the bb-auth cookie and `302`s away. It clears *only* that
cookie: any Cognito session the login page holds is out of scope, and a cross-site
navigation is ignored (CSRF-forced logout).

There is deliberately **no per-site logout landing page**. A logout happens at
`/auth/logout`, which no site's `urls` cover, so the gate cannot tell which area you are
leaving — there is nothing to resolve against. The one party that knows is whoever wrote
the logout link, so they say it:

```html
<a href="/auth/logout?rd=/app1/goodbye">Sign out</a>
```

`rd` goes through the same [`safe_rd`](#where-the-post-login-redirect-may-land) guard as on `/auth/session`,
so it opens no new redirect surface. With no `rd`, the browser lands on the login page. A
relative `rd` needs `X-Original-URL` on that location too; if nginx omits it, the redirect
falls back to the login page — fail-soft.

### Validating and reloading

Check a file before shipping it — a bad pattern or an unknown site field is a fatal
startup error, and the deploy script runs this same check before it restarts anything:

```bash
bb-auth --check-users deploy/users.json     # exit 0 + a summary, or exit 1 + the error
```

It is the real access gate, re-checked on **every** `/validate`, hot-reloaded on
SIGHUP (`systemctl reload bb-auth`) — remove a user or a single key + reload to
de-authorize even a still-valid cookie. A reload that fails to parse keeps the live
table (never nuked). Keys are indexed by their hash, so a lookup is a single map hit
(and trivially a single indexed query if you ever move this to a database).

> **Upgrading from 1.x.** `enabled_paths` is gone and its presence is rejected
> outright: silently ignoring it would leave a user unscoped, which under the old
> semantics failed *open*. Rewrite each entry as a full URL pattern — and note that a
> 1.x user with **no** scope meant "all paths", so those users now need an explicit
> `["*://*/*"]` or they will reach nothing. Update nginx to send `X-Original-URL` too;
> the deploy script aborts before restarting rather than boot-loop the service.
>
> **Upgrading from 2.1.** Nothing to do: a file with no `sites` and no `denied`
> behaves exactly as before.

## Session cookie

`<cookie> = bb2.<keyid>.<exp>.<b64url(email)>.<b64url(HMAC_SHA256(...))>` — HttpOnly,
Secure, SameSite=Lax, host-only on the service host, ~30 days. The key id is
stamped in so the signing key can roll over with zero downtime (see "Key
rotation" below). Stateless: no server-side session store — any worker can
validate any cookie and a restart logs nobody out. Cookies signed under the
previous single-key scheme are still honoured:

```text
bb2.<keyid>.<exp>.<b64url(email)>.<b64url(HMAC_SHA256("bb2.<keyid>.<exp>.<b64url(email)>", key[keyid]))>   # active
bb1.<exp>.<b64url(email)>.<b64url(HMAC_SHA256("bb1.<exp>.<b64url(email)>"))>                                 # legacy (verify-only)
```

The access file is re-checked on every `/validate`, so de-authorizing someone is
just an edit (remove the user or a single API key, or add them to `denied`) +
`systemctl reload bb-auth` (SIGHUP). A restart works too.

## Build (cross-compile)

```bash
bash scripts/build.sh        # run on Linux (or WSL)
# → dist/bb-auth   (the build prints the max GLIBC symbol required, so you can
#                   match it to your target host's glibc)
```

`scripts/build.sh` cross-compiles to `aarch64-unknown-linux-gnu` by default; edit
it for a different target. Deps are pure-Rust or `ring`-based (`tiny_http`,
`ureq`+rustls, `jsonwebtoken`, `hmac`/`sha2`) — no system OpenSSL, so the cross
build needs only the matching GNU toolchain. Built blocking/threaded (no async
runtime) to keep the binary and resident memory small.

## Deploy

On the target, bb-auth is laid out as:

```text
/opt/bb-auth/bin/bb-auth          # binary (root-owned, read-only to the service)
/opt/bb-auth/etc/bb-auth.env      # config + HMAC key (0640, service-user readable)
/opt/bb-auth/var/lib/users.json   # access list (0640, service-user readable)
/etc/systemd/system/bb-auth.service
```

`scripts/deploy.sh` is the **on-host installer** (run as root, on the target):
it installs the binary/unit + staged `bb-auth.env` (generating the HMAC key on
first install, then preserving it forever), restarts the service, and runs a
**post-deploy verification** — service active, `GET /auth/healthz == ok`,
`GET /auth/validate` (no cookie) `== 401`, HMAC key present, users.json
integrity, clean journal startup — exiting non-zero if any check fails. Staging a
`users.json` is **optional**: if absent, the live one is preserved, so a
binary-only redeploy can never lock anyone out. Before it restarts anything it
validates the users file that is about to go live with the real parser
(`bb-auth --check-users`) and aborts if it is rejected, leaving the previous
binary serving.

`scripts/deploy.ps1` (**run from Windows**) orchestrates the whole thing for a
`user@host`:

```powershell
./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -Build          # build in WSL + redeploy (users.json + HMAC key kept)
./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -UsersFile .\deploy\users.json   # first install / replace access file
```

It verifies SSH + passwordless sudo + aarch64, stages the artifacts, runs
`deploy.sh` as root, pings healthz, and cleans up. By default it ships no
users.json and never regenerates the HMAC key, so redeploys are zero-downtime.

## Run

bb-auth is a single binary configured entirely from the environment. It expects
to run **as a non-privileged service, on loopback, behind a TLS-terminating
reverse proxy** that performs the `auth_request`. It needs two files: the env
file (holds the HMAC secret) and the users file (JSON access list). The included
`deploy/bb-auth.service` runs it as a dedicated system user with aggressive
systemd hardening; `scripts/deploy.sh` is an example installer (creates the
user, installs the binary/unit + staged `bb-auth.env`, generates the HMAC key
once and preserves it across redeploys). See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §"Running it".

## Config

All via env — see [`deploy/bb-auth.env.example`](deploy/bb-auth.env.example) for
every variable. The only secret is `BB_AUTH_HMAC_KEY` (`openssl rand -base64 48`);
keep it out of version control and off shared storage.

## Putting a service behind the gate

The binary is service-agnostic. To front a service at `app.example.com`:

1. **nginx** on the service host: add the `auth_request` wiring.

   ```nginx
   # Reject requests for a Host we don't serve, so $host is always a real
   # server_name. Without this, a spoofed Host: could widen a URL scope.
   server { listen 443 ssl default_server; ssl_reject_handshake on; }

   # Optional: let a site pick its own login page (see "Per-site login page").
   # The default arm is what a location without auth_request_set, or an older
   # bb-auth, falls back to — never leave $bb_login to reach `return 302` raw.
   map $bb_login $bb_login_safe {
       ""      https://login.example.com/;
       default $bb_login;
   }

   server {
       listen 443 ssl;
       server_name app.example.com;

       # The gate. `internal` = unreachable from outside; only auth_request hits it.
       location = /internal/auth-gate {
           internal;
           proxy_pass              http://127.0.0.1:4181/auth/validate;
           proxy_pass_request_body off;
           proxy_set_header        Content-Length "";
           # The URL being guarded, captured by the gated location below. Do NOT
           # write $uri here: inside an auth_request subrequest $uri is the
           # subrequest's own URI, i.e. the literal /internal/auth-gate.
           proxy_set_header        X-Original-URL $bb_url;
           # Programmatic clients authenticate with a bearer on every request.
           proxy_set_header        Authorization $http_authorization;
       }

       location / {
           # Every gated location must set this before auth_request runs (rewrite
           # phase precedes access phase); the subrequest inherits the variable.
           # Hardcode the host: it is this server block, and a literal cannot be
           # spoofed. $uri, never $request_uri: $uri is decoded and normalised, so
           # /a/%2e%2e/b has already collapsed to the /b nginx will really serve,
           # and the query string is gone. Forget the `set` and bb-auth sends no
           # header, so the request is denied — the failure is closed, and loud.
           set $bb_url https://app.example.com$uri;
           auth_request /internal/auth-gate;

           # Who the gate just authenticated. auth_request_set reads the subrequest's
           # response header; proxy_set_header then overwrites whatever the client
           # sent, and nginx omits the header entirely if the variable is empty.
           auth_request_set $bb_email $upstream_http_x_auth_email;
           proxy_set_header X-Auth-Email     $bb_email;
           proxy_set_header X-Forwarded-User "";   # clear names we do NOT set
           proxy_set_header Remote-User      "";

           # Which login page this area uses. auth_request_set reads the 401's
           # headers too, so the gate can name it per site.
           auth_request_set $bb_login $upstream_http_x_auth_login_url;

           error_page 401 = @bb_signin;
           proxy_pass http://127.0.0.1:8080;   # the upstream app
       }

       location @bb_signin {
           return 302 $bb_login_safe?rd=$scheme://$host$request_uri;
       }

       location = /auth/session {
           # Same header here: it tells bb-auth which host the login is happening
           # on, so a relative `rd` resolves against the caller. This is a plain
           # proxy_pass, not a subrequest, so $uri is the real one.
           proxy_set_header X-Original-URL https://app.example.com$uri;
           proxy_pass http://127.0.0.1:4181/auth/session;
       }
       location = /auth/logout  {
           # Only needed so a relative `?rd=` on the logout link resolves against
           # this host; without it the logout falls back to the login page.
           proxy_set_header X-Original-URL https://app.example.com$uri;
           proxy_pass http://127.0.0.1:4181/auth/logout;
       }
   }
   ```

   `X-Original-URL` is what [URL scoping](#url-scoping) matches against. It is
   required — every credential is scoped, so a subrequest without it is denied.
   The `set $bb_url …` / `$bb_url` split is not stylistic: an `auth_request`
   subrequest gets its own `$uri` (`/internal/auth-gate`) but shares the parent's
   variables, so the real URL has to be captured in the gated location and read
   back in the gate.

   `X-Auth-Email` is how the **app** learns who is calling — see
   [Passing the identity to the app](#passing-the-identity-to-the-app). Rename it
   there to whatever your app reads, and clear every other name it might trust:
   `proxy_set_header` only overrides the names it lists, so an unlisted one travels
   straight through from the client.
2. **Cross-service SSO vs per-service login** — pure configuration:
   - *SSO (one login across a domain):* set `BB_AUTH_COOKIE_DOMAIN=.example.com`
     so the session cookie is shared, and list every sibling in
     `BB_AUTH_AUTHORIZED_HOSTS=example.com,*.example.com` so the `rd`
     open-redirect guard accepts them.
   - *Per-service login:* run a separate bb-auth instance per service, with a
     host-only cookie and `BB_AUTH_AUTHORIZED_HOSTS=app.example.com`.
3. **Login page**: it must POST the `id_token` to the *right* service's
   `/auth/session`. For multiple services, derive the target from the validated
   `rd` instead of a fixed base.

Step 3 is the only per-service behaviour change; the SSO scope in step 2 is now
just configuration (`BB_AUTH_COOKIE_DOMAIN` + `BB_AUTH_AUTHORIZED_HOSTS`).

### Where the post-login redirect may land

There is no canonical "service base URL" — one gate fronts several hosts, and which
one is in play is decided by the caller. So `BB_AUTH_AUTHORIZED_HOSTS` is the sole
authority on where `?rd=…` may send a freshly-logged-in browser:

- a relative `rd` (`/preferences`) resolves against the **caller's** host, taken from
  `X-Original-URL` on `/auth/session`;
- an absolute `rd` must be `https://` on a host matching one of the patterns;
- with no `rd` at all, the browser lands on the caller's root;
- anything rejected — an off-host URL, a control byte, `//evil`, `/\evil`, userinfo
  (`https://app.example.com@evil.com/`), a lookalike (`evilexample.com`) — falls back
  to `BB_AUTH_LOGIN_URL`.

Every candidate, including one resolved against the caller, goes through the same host
gate, so even a misconfigured proxy cannot turn this into an open redirect. Note that
`*.example.com` does **not** match the bare apex `example.com`: list it if you want it.

## Security notes

- A Cognito-signed `id_token` is unforgeable; possession of one for an
  allowlisted, verified email is the credential.
- Static `bbk_` API keys are stored only as a SHA-256 hash; a valid, unexpired key
  authorizes its user per request within its path scope. Revoke by removing the key
  (or the user) from the users file + reload. Keys bypass Cognito, so treat the raw
  bearer like a password and prefer scoping it to the paths it needs.
- `rd` is open-redirect-guarded to `BB_AUTH_AUTHORIZED_HOSTS`.
- Login-CSRF (an attacker POSTing *their* token to log a victim into the
  attacker's account) is possible in theory but low-impact for a read gate;
  accepted. Revisit with a state/nonce if the gate ever fronts something sensitive.

### Key rotation

The cookie is HMAC-signed under `BB_AUTH_HMAC_KEY`, addressed by
`BB_AUTH_HMAC_KEY_ID`. Rotation is **zero-downtime** because the key id is
stamped into every `bb2` cookie and multiple keys can be accepted for
verification at once. 3-step runbook (k1 → k2):

1. Generate the new key and publish it as verify-only, then reload:

   ```bash
   NEW=$(openssl rand -base64 48)
   # in the env file: BB_AUTH_HMAC_ACCEPTED_KEYS=k2:$NEW   (k1 stays the active key)
   systemctl reload bb-auth
   ```

2. Flip the active key + id and reload. New cookies are signed with k2; existing
   cookies (signed with k1) still verify because k1 is still in the accepted set:

   ```bash
   # in the env file: BB_AUTH_HMAC_KEY=$NEW  and  BB_AUTH_HMAC_KEY_ID=k2
   systemctl reload bb-auth
   ```

3. After ~30 d (one TTL), every surviving cookie is k2-signed. Drop k1 from
   `BB_AUTH_HMAC_ACCEPTED_KEYS` and reload.

Nobody is logged out at any step. The old `bb1` (single-key) cookies are also
still accepted — they verify against any key in the set — so the original
migration from `bb1` to `bb2` invalidated nobody.
