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
| GET    | `/auth/validate` | nginx only | `auth_request`: 204 naming the identity in one header per configured attribute (default `X-Auth-Email`, plus one per configured profile claim when known) if the session cookie, an `Authorization: Bearer <id_token>`, or a static `Authorization: Bearer bbk_…` API key is admitted by the scope that owns the URL, else 401 + `X-Auth-Login-URL`. An `anonymous` scope answers 204 with no credential, and names nobody. |
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
scope that owns the request URL.
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
`duration`, and then the scope that owns the URL decides. An `authenticated` scope does **not** rescue an
unknown key — that grant is for identities Cognito vouches for, and an unknown key is
nobody. Mint one with `bb-auth-adm`, which writes the entry into the file itself and
prints the raw bearer **once**, on stdout, after the file is safely saved:

```bash
bb-auth-adm -f users.json key add bob@badbat75.com --id laptop --duration 365d \
    --scope mcp/api
# → stdout: bbk_…                   (the bearer — give it to the client, it is not recoverable)
# → the file now holds only its sha256
bb-auth-adm -f users.json key rotate bob@badbat75.com laptop   # a leak? new secret, same grant
```

See [Editing it — `bb-auth-adm`](#editing-it--bb-auth-adm) for the rest of the tool.

## Passing the identity to the app

All three credentials resolve to one thing: an email. A `204` from `/auth/validate`
carries it in **`X-Auth-Email`**, which nginx lifts out of the subrequest and injects
into the request it proxies — that is how the app behind the gate learns who is
calling. An API key resolves to its **owning user's** email: a key acts as its user.
On an [`authenticated` scope](#scopes--who-reaches-what-and-how) the email may name someone with no
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
read: the session cookie is not a JWT (it carries the email and the profile claims
below, HMAC-signed) and an API key has no token at all, so decoding a claim would work
for exactly one of the three credentials. It would not be safe either — Cognito
self-signup is open, so a valid `id_token` proves *identity*, never *authorization*.
What decides authorization is the access file, and only the gate reads it.

### Profile claims (optional)

So an app need not guess a display name out of the email's local part, a `204` can also
carry OIDC profile claims from the token. **Which** claims is configuration:

```bash
BB_AUTH_PROFILE_CLAIMS=given_name,family_name
```

Empty by default — set it and the gate emits, on every `204` where the credential
carried them:

```text
X-Auth-Given-Name:  Niccol%C3%B2
X-Auth-Family-Name: de%27%20Medici
```

```nginx
auth_request_set $bb_given  $upstream_http_x_auth_given_name;
auth_request_set $bb_family $upstream_http_x_auth_family_name;
proxy_set_header X-Auth-Given-Name  $bb_given;
proxy_set_header X-Auth-Family-Name $bb_family;
```

- **The header name is derived from the claim name**, never configured separately: `_`
  and `:` become `-`, each part is title-cased, and the whole is prefixed `X-Auth-`. So
  `given_name` → `X-Auth-Given-Name`, `nickname` → `X-Auth-Nickname`,
  `custom:department` → `X-Auth-Custom-Department` (nginx variable
  `$upstream_http_x_auth_custom_department`). A claim name may contain only
  `[A-Za-z0-9_:-]`; anything else, a claim the gate consumes itself (`email`,
  `email_verified`, `token_use`, `identities`), or two entries deriving the same header
  is a **fatal startup error**, not a skipped entry.
- **Percent-encoded UTF-8** (RFC 3986), because HTTP header values are not UTF-8: every
  byte outside `[A-Za-z0-9-._~]` is `%XX`, so a space is `%20` and `Niccolò` is
  `Niccol%C3%B2`. Decode with any standard URI-decoder — note this is *not* the
  form-urlencoded variant, so a `+` is a literal plus, never a space.
- **Absent ⇒ the header is omitted entirely**, never sent empty. That happens when the
  token carries no such claim and on **every API key** (a key has no token to read one
  from). nginx passes that through: an unset variable drops the header too.
- **Additive.** Adding the four lines above is per gated location; leave them out and
  nothing changes. An app must treat every profile header as optional.
- **Read at startup, so changing the list needs `systemctl restart`** — not `reload`,
  which only re-reads the access file. It is *not* a cookie-format change: an existing
  cookie keeps working, a claim removed from the list stops being emitted even from
  cookies that still carry it, and one added appears at each user's next sign-in.
- **A value is capped at 256 bytes** and dropped, not truncated, beyond that. Keep the
  list short: the claims ride in the session cookie, and a browser silently drops a
  cookie over ~4 KB. The gate warns at startup if the configured set could get close.
- **These claims are self-asserted.** Any Cognito user edits their own profile, so treat
  them as display hints and never as an authorization input. The identity is the email.

## URL patterns

A scope carries `urls` — a list of full `<scheme>://<host>/<path>` patterns it answers
for. **Access is enumerated, never assumed:** a scope with no `urls` matches nothing, a
`restricted` scope that lists nobody admits nobody, and a URL no application covers is
reachable by nobody at all. Blanket coverage is spelled out, as `["*://*/*"]`.

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

Matching needs the original request URL, so nginx must pass it on the subrequest —
see [the nginx wiring](#putting-a-service-behind-the-gate). That header is **required**:
a request without it resolves to no application and is denied, as is any URL containing
`..` (fail-closed on both counts).

## Access file

The access gate is a single JSON file (`BB_AUTH_USERS_FILE`, installed as
`/opt/bb-auth/var/lib/users.json`; see [`deploy/users.example.json`](deploy/users.example.json)).
Since 3.0 it is **application-centric**: a grant is written once, on the side of the
place. Four sibling sections answer four different questions:

```json
{ "version": 3,
  "applications": [
    { "name": "app1",
      "base": ["https://app.badbat75.com/app1"],
      "login_url": "https://signup.badbat75.com/",
      "scopes": [
        { "name": "healthz", "urls": ["https://app.badbat75.com/app1/healthz"],
          "access": "anonymous" },
        { "name": "admin", "urls": ["https://app.badbat75.com/app1/admin/*"],
          "access": "restricted", "groups": ["@admins"], "credentials": ["login"] },
        { "name": "everything", "urls": ["https://app.badbat75.com/app1",
                                         "https://app.badbat75.com/app1/*"],
          "access": "authenticated", "excluded": ["nuisance@badbat75.com"] } ] } ],
  "user_groups": { "admins": ["8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b"] },
  "denied": ["spammer@badbat75.com"],
  "users": [
    { "uuid": "8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b",
      "emails": ["you@badbat75.com"],
      "api_keys": [
        { "id": "laptop", "key_hash": "<sha256 hex of the bbk_ bearer>",
          "released": "2026-07-08", "duration": "365d",
          "scopes": ["app1/admin"] } ] } ] }
```

A request is authorized when the URL resolves to a scope and **that scope admits the
credential**. All of it is re-checked on every `/validate`. Two things take access away:
`denied`, everywhere, and a scope's own `excluded`, in that one place.

Coming from an older file, one with no `"version"` in it? The format changed, and the
gate refuses the old one by name. Convert it with `bb-auth-adm migrate`, which replays
every (identity, URL) pair the old file granted and refuses to write if any answer
changed. Read [Upgrading to 3.0](#upgrading-to-30) before you install anything.

### `applications` — the places

An application owns a **literal** URL area and a list of named scopes.

- **`name`** — `[A-Za-z0-9_-]+`, unique in the file, and the left half of `application/scope`.
- **`base`** — one or more literal URL prefixes, **no wildcards**. Every pattern of every scope must lie inside one of them, and **no two applications may overlap**, anywhere in the file. Together those make applications a partition of the URL space: at most one can answer for a URL, so their order carries no meaning.
- **`login_url`** — an absolute `https://` login page for this whole area, overriding `BB_AUTH_LOGIN_URL` (see [Per-application login page](#per-application-login-page)). Validated at load: printable ASCII, https, no userinfo `@`, no backslash, because it ends up in a header and a redirect.
- **`scopes`** — see below. Order is meaning.

The area is compared at a **path boundary**, which is why `https://x.com/app` covers
`https://x.com/app/deep` but not `https://x.com/application`. The same trap as a `*`
written with no `/` before it.

> **A URL no application covers is reachable by nobody.** A gated location outside every
> area is a `401` for everyone, including you. `bb-auth --check-users FILE` prints each
> application's area so you can compare it with what nginx actually gates.

### `scopes` — who reaches what, and how

**First match wins**, in file order: the first scope whose `urls` cover the request
answers for it, even if it grants nothing. That is what makes a **carve-out**
expressible, as `healthz` and `admin` are above: put the narrow, stricter scope
*before* the broad one. Reversed, `everything` would answer for all three and the other
two would never be reached. `bb-auth-adm scope mv` reorders them, and
`bb-auth-adm check` warns when one is shadowed.

- **`name`** — `[A-Za-z0-9_-]+`, unique inside its application.
- **`urls`** — the patterns this scope answers for (see [URL patterns](#url-patterns)). A malformed one is fatal, and so is one outside the application's `base`.
- **`access`** — **required, no default**, one of three words:
  - `anonymous` — no credential at all. The `204` names nobody. Note `denied` does not reach here: the scope grants with nothing, so a vetoed client would simply send nothing.
  - `authenticated` — any identity Cognito vouches for, enrolled or not. It is how someone who has just registered reaches an onboarding area, with the app receiving their `X-Auth-Email` and enrolling them. An unknown `bbk_` key is not rescued by it: Cognito vouches for no key of ours.
  - `restricted` — the people in `users` and `groups`, and nobody else.
- **`users`** / **`groups`** — uuids and `"@name"` group references. Legal **only** under `restricted`.
- **`credentials`** — `["login"]` and/or `["api_key"]`; absent means both. Legal only under `restricted`. This is a property of the *place*: "this area is reached by a browser login" is a statement about the application, and expressing it here is what let a key stop carrying URLs of its own.
- **`excluded`** — the scope's own veto, checked **before** its grant. See [`excluded`](#excluded--the-scopes-own-veto) below.
- Unknown fields are a **hard error** in an application or a scope, unlike in the sections that describe people. The day `access` gains a companion restriction, a typo in that companion must not be silently dropped, leaving the field it was meant to narrow standing alone — that would fail *open*.

> Cognito self-signup is open, so `authenticated` means *anyone who can register*, and
> `anonymous` means everyone. Both are the right grant for an onboarding or health-check
> area and the wrong one for everything else. `--check-users` and the startup banner
> print every scope of either kind by name, because they are the two an operator most
> often did not mean to leave open.

#### `excluded` — the scope's own veto

`denied` shuts somebody out everywhere. `excluded` shuts them out of **this scope**, and
it is checked *before* the scope grants, which is what makes it able to do two things
nothing else can:

- keep one member of a `@group` out of one place, without unpicking the group;
- keep one identity out of an `authenticated` scope, which lists nobody and so has nobody
  to remove.

It takes the same spellings the file-level veto does, plus groups: a **uuid**, a
**`"@name"`** group, or a bare **email** for an identity the roster has never heard of. An
email that does resolve is folded onto its uuid when the file loads, so excluding one
address of a user cannot leave another standing.

Two rules worth knowing before you reach for it. `denied` is reported **ahead** of it, so
somebody vetoed file-wide is logged as vetoed rather than as merely excluded from wherever
they knocked. And it is a **fatal error on `anonymous`**, for the same reason the file-level
veto does not reach that kind: the scope grants with no credential at all, so an excluded
client would simply send none, and a field that reads like a defence while defending
nothing is worse than no field at all.

```bash
bb-auth-adm -f users.json scope set app1 admin --add-exclude bob@x.com
bb-auth-adm -f users.json scope set app1 everything --add-exclude nuisance@x.com
bb-auth-adm -f users.json scope set app1 admin --rm-exclude bob@x.com
bb-auth-adm -f users.json can bob@x.com https://app.x.com/app1/admin/panel
# → DENIED — app1/admin excludes this identity, ahead of its own grant
```

### `user_groups` — one name for a set of people

A group is **abbreviation, never a grant**: defining one authorizes nobody until a scope
names it in `groups`.

- **name** — `[A-Za-z0-9_-]+`, matched exactly (case-sensitive).
- Members are uuids. Groups are **flat**: a group may not reference another group.
- An **unknown** `@name` is fatal, like a malformed pattern: a silently dropped entry would change who reaches what. Every group is validated even when nothing references it.
- A member that names no roster row only warns, and grants nothing.
- `bb-auth-adm group add|set|list|rm` edits them; `rm` refuses while a scope still references the group.

### `users` — the roster

A user is an identity plus the identifiers that resolve to it. It carries **no URL**:
what a user reaches is written in the scopes that list them.

- **`uuid`** (required) — canonical lowercase 8-4-4-4-12. What every reference in the file names. `bb-auth-adm user add EMAIL` mints it for you, and both editors take an email wherever they take a uuid, so you never have to type one.
- **`emails`** — the identifiers Cognito can vouch for; any of them resolves to this row. Changing how someone signs in is therefore one edit here, not a sweep over every scope that lists them. Two rows may not share an identifier, and may not share a uuid.
- **`api_keys[]`** — static `bbk_` keys for that user (see [Programmatic access](#programmatic-access-bearer)):
  - **`key_hash`** — `sha256` of the bearer; the raw key is never stored (mint via `bb-auth-adm key add`).
  - **`duration`** — `<n>d` / `<n>h` / `0` / `never`, counted from **`released`** (`YYYY-MM-DD`).
  - **`id`** — human label for logs and revocation.
  - **`scopes`** — a list of `"application/scope"` names, and a **restriction, never a grant**: it can only subtract from what the owner already reaches. Omit it and the key reaches everything its owner does through scopes that admit `api_key`.
  - Unknown fields (e.g. `notes`) are ignored, so annotate freely.

### `denied` — the veto

Refused on **every** credential, ahead of every grant, checked before anything else. Two
kinds of entry, and both matter:

- a **uuid**, which vetoes the user and every email they hold. An email that resolves to a roster row is folded onto its uuid when the file loads, so denying one address cannot leave another standing.
- a bare **email**, which vetoes an identity the file has never heard of. On an `authenticated` scope the roster is never consulted, so for an un-enrolled identity this is the **only** denial that exists.

For an enrolled user it is a *suspension*, not a deletion: their group memberships and
their API keys survive the lockout, so re-enabling is a one-line edit. An entry that is
neither a uuid nor an email is a fatal load error, because a veto that vetoes nobody
while reading as if it did is the one failure this section cannot afford.

Like everything else it applies from the next request; a cookie or `id_token` already
in flight is stateless and cannot be recalled mid-request. And it does not reach an
`anonymous` scope, which asks for no credential at all.

### Per-application login page

bb-auth never redirects a gated request: it answers `401` and **nginx** decides where to
send the browser. So the way an application names its own login page is a response header the
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

The header carries the application's `login_url`, or `BB_AUTH_LOGIN_URL` when it declares none.
`auth_request_set` copies it into a request variable, which is what stops a later
`proxy_pass` from clobbering `$upstream_http_*`; it reads the subrequest's headers even
though the subrequest answered `401`, which is the whole reason this works. Without the
`auth_request_set` line nothing breaks — the `map` yields the global URL, exactly as a
hardcoded `@bb_signin` did before.

The gate can name the login page here because a `401` happens **on** a gated URL, so the
application resolves, and it answers even when none of its scopes covers the URL. Logout gets no such luck.

### Logging out

`GET /auth/logout` clears the bb-auth cookie and `302`s away. It clears *only* that
cookie: any Cognito session the login page holds is out of scope, and a cross-site
navigation is ignored (CSRF-forced logout).

There is deliberately **no per-area logout landing page**. A logout happens at
`/auth/logout`, which is inside no application's area, so the gate cannot tell which area you are
leaving — there is nothing to resolve against. The one party that knows is whoever wrote
the logout link, so they say it:

```html
<a href="/auth/logout?rd=/app1/goodbye">Sign out</a>
```

`rd` goes through the same [`safe_rd`](#where-the-post-login-redirect-may-land) guard as on `/auth/session`,
so it opens no new redirect surface. With no `rd`, the browser lands on the login page. A
relative `rd` needs `X-Original-URL` on that location too; if nginx omits it, the redirect
falls back to the login page — fail-soft.

### Editing it — `bb-auth-adm`

The file is JSON and you can edit it by hand; `bb-auth-adm` is the way not to. It does
CRUD over every section, and it links the gate's own parser, so **it cannot save a file
the gate would refuse** — which matters, because a refused file is a fatal startup, and
under `Restart=on-failure` that is a boot loop.

```bash
bb-auth-adm -f users.json show                 # the file as the gate resolves it
bb-auth-adm -f users.json app add app1 --base 'https://app.x.com/app1'
bb-auth-adm -f users.json user add bob@x.com   # mints the uuid; a user carries no URL
bb-auth-adm -f users.json group add admins --member bob@x.com
bb-auth-adm -f users.json scope add app1 reports --url 'https://app.x.com/app1/reports/*'     --access restricted --group @admins
bb-auth-adm -f users.json scope set app1 reports --add-exclude carol@x.com
bb-auth-adm -f users.json key add bob@x.com --id laptop --duration 365d --scope app1/reports
bb-auth-adm -f users.json deny add spammer@x.com
bb-auth-adm -f users.json check                # the gate's parser, then lint
```

It talks back. Adding a user says they reach nothing until a scope lists them; adding an
`authenticated` scope says what that means; removing a user reminds you that such a scope
does not consult the roster, so deleting them is not a lockout: `deny` is, or that scope's
own `excluded`. `check` also finds what parses fine and still doesn't mean what it says: a
duplicate email, an expired key, a scope listed after a broader one that already answers
for its URLs so it never speaks, a group nothing references. And it refuses to remove a
group while a scope still names it — in `groups` or in `excluded`.

And it answers the question you actually have, with the gate's own decision function —
exit 0 iff the request would pass:

```bash
bb-auth-adm -f users.json can bob@x.com https://app.x.com/app1/reports/q3
# AUTHORIZED — app1/reports admits this credential for https://app.x.com/app1/reports/q3
bb-auth-adm -f users.json can carol@x.com https://app.x.com/app1/reports/q3
# DENIED — app1/reports excludes this identity, ahead of its own grant
bb-auth-adm -f users.json can bob@x.com https://app.x.com/app1/admin --key laptop
# DENIED — this key restricted itself to other scopes, not app1/admin
```

Edit the **live** file (`sudo bb-auth-adm -f /opt/bb-auth/var/lib/users.json …`, the tool
is deployed alongside the gate): it is the copy that is current, and the write preserves
its `root:bb-auth 0640` ownership. Then reload — see below.

### Editing it in a browser — `bb-auth-web`

The same file in a browser: a server-rendered admin GUI that needs no JavaScript. Four tabs.
**Users** holds the three sections about people, in the order they nest: the user groups and
who references each one, then the roster, then the `denied` veto. **Applications** lists each
one with its area, its scope count and which credential classes get in anywhere inside it,
and each application's page shows its scopes **numbered in file order** (the number is the
meaning — first match wins) with their members, their credentials and their `excluded`.
Every key's expiry is on its owner's page, and the **can** tab is a tester answered by the
gate's own decision function.

Every list carries a **filter box and a pager**, both of which are just query parameters — so
they work with scripting off, survive a language change, and can be bookmarked. Scopes are
the one list without them, deliberately: their order is their meaning and the ↑/↓ buttons
move them within the file, so a filtered view would show positions that are not the file's.

It **edits** the file too — the same CRUD as `bb-auth-adm`, made through the same library
code, so it cannot save a file the gate would reject. Three rules make that safe with no
script and no server-side session: a `GET` never mutates; every `POST` must be
same-origin (`Sec-Fetch-Site`, else `Origin`'s host against `Host`'s — hosts, not schemes,
since this speaks plain HTTP behind nginx); and every form carries a hidden `rev`, the
sha256 of the file's exact bytes when the form was rendered. If the file moved in between —
a `bb-auth-adm` over SSH, another tab — the `POST` answers `409` and writes nothing, instead
of quietly discarding someone's edit. A successful mutation redirects (so a reload cannot
repeat it), except minting a key, which shows the `bbk_` bearer once, on the spot, after the
file carrying its hash is on disk. Destructive actions go through a confirmation page. An
edit is live at the next `systemctl reload bb-auth` — which, once this is deployed, is
sent for you (see "Making an edit live" below).

It is *just another app bb-auth fronts*: it binds loopback, and nginx gates its URL with
`auth_request` like any other, injecting the authorized email as `X-Auth-Email` (the
contract in "Passing the identity to the app"). It validates no token and holds no
secret — which is exactly why it must never be reachable except through nginx. A request
with no identity header answers `401` and says so, rather than serving anyone.

| Var | Required | Default | Meaning |
|-----|----------|---------|---------|
| `BB_AUTH_USERS_FILE` | yes | — | the access file to render (the gate's own variable name) |
| `BB_AUTH_WEB_ADMINS` | yes | — | comma-separated emails allowed in. **Empty is fatal**, never "everyone" |
| `BB_AUTH_WEB_LISTEN` | no | `127.0.0.1:8091` | bind address. Keep it on loopback |
| `BB_AUTH_WEB_BASE_PATH` | no | *(empty)* | the URL prefix nginx mounts it at, e.g. `/admin` |
| `BB_AUTH_WEB_DEFAULT_LANG` | no | `en` | `en` or `it`; a `?lang=` choice is remembered in a cookie |

`BB_AUTH_WEB_ADMINS` is deliberate defense in depth, not a second copy of the roster: a
`authenticated` scope covering the GUI's URL would otherwise hand the admin surface to any
Cognito account, and self-signup is open.

The file is read fresh on **every request** — no cache, no reload signal, and no
server-side session. An edit made over SSH with `bb-auth-adm` a second ago is on the next
page load, and a file the gate would refuse renders as the parser's own error message
instead of taking the GUI down. The `rev` field is what makes that safe for writing as
well: what a form needs to know about the file travels in the form.

#### Deploying it

Optional, exactly like `bb-auth-adm`: it is its own package, `bb-auth-web`, carrying its
unit, its env template and the reload watcher, and depending on the exact same version of
`bb-auth`. `deploy.ps1 -Packages bb-auth` leaves it out, and a host that never installs it
is untouched by all of this, down to the ownership of the access file.

```text
/opt/bb-auth/bin/bb-auth-web        # binary (root-owned, executed by bb-auth-web)
/opt/bb-auth/etc/bb-auth-web.env    # its config — operator-owned, installed once
/etc/systemd/system/bb-auth-web.service
/etc/systemd/system/bb-auth-reload.{path,service}
```

The unit mirrors the gate's hardening (`NoNewPrivileges`, `ProtectSystem=strict`,
`PrivateTmp`, empty `CapabilityBoundingSet`, `SystemCallFilter=@system-service`, …) with
the two differences the job forces: it runs as its own user `bb-auth-web`, and it *writes*,
so `ReadWritePaths=/opt/bb-auth/var/lib` punches one hole in the read-only tree. The hole
is the **directory**, not the file, because the replacement is a temp file renamed into
place — that is what makes it atomic, and renaming needs the directory.

Its env is operator-owned like the gate's: installed once, then never edited by a redeploy,
and *validated* before anything restarts (`BB_AUTH_WEB_ADMINS` non-empty, and
`BB_AUTH_USERS_FILE` naming the file the gate actually loads). A missing required var is a
fatal startup and under `Restart=on-failure` a boot loop, so the deploy aborts first. The
practical consequence: **the first deploy that carries the GUI stops at that check**, having
installed `/opt/bb-auth/etc/bb-auth-web.env` from the template. Fill in
`BB_AUTH_WEB_ADMINS` on the host and re-run. (Keep a filled-in `deploy/bb-auth-web.env`
locally — gitignored — and it is staged instead, and the first deploy goes straight
through.)

#### Who owns the access file

Installing the GUI hands the access file over, once and idempotently:

| | before | with `bb-auth-web` installed |
|---|---|---|
| `var/lib/` | `root:root 0755` | `bb-auth-web:bb-auth 0750` |
| `users.json` | `root:bb-auth 0640` | `bb-auth-web:bb-auth 0640` |

The gate reads it through the `bb-auth` group exactly as before — **its unit does not
change**. The GUI needs to own it because the writer restores the replaced file's mode and
owner before renaming, and an unprivileged process may only `chown` to the uid it already
owns and to a group it is a member of (hence `SupplementaryGroups=bb-auth` in the unit);
own it, and the same write is legal. And `sudo bb-auth-adm` keeps working with no change at
all — root may write anything, and because the writer *preserves the owner it finds*, its
rewrites leave the file `bb-auth-web:bb-auth` too. The two editors go on sharing one file,
which is what the `rev` check was built for.

A deploy that does **not** carry the GUI performs no migration: nothing would need the new
owner, so `root:bb-auth` stays exactly as it is.

#### Making an edit live

`bb-auth-reload.path` watches `users.json` and runs `systemctl reload bb-auth` whenever it
is replaced — by the GUI or by a `sudo bb-auth-adm` over SSH. It is installed with the GUI
because it is what makes a GUI edit live: `bb-auth-web` runs unprivileged, is not the gate,
and could not signal it. It uses `PathChanged=`, which catches the `rename(2)` both editors
end with (and a hand-edit's close-write); `PathModified=` would only add mid-write triggers,
i.e. reloading the gate on half a file.

So a CLI operator no longer *has* to reload by hand — and if they do, it is one extra
reload of the same file, which costs nothing: a reload re-reads the file, and one that fails
to parse keeps the live table. The habit is still worth keeping, since the watcher is only
there when the GUI is.

nginx wiring: see [The admin GUI behind the gate](#the-admin-gui-behind-the-gate).

### Validating and reloading

Check a file before shipping it — a bad pattern or an unknown scope field is a fatal
startup error, and the deploy script runs this same check before it restarts anything:

```bash
bb-auth --check-users deploy/users.json     # exit 0 + a summary, or exit 1 + the error
```

It is the real access gate, re-checked on **every** `/validate`, hot-reloaded on
SIGHUP (`systemctl reload bb-auth`) — remove a user or a single key + reload to
de-authorize even a still-valid cookie. **An edit is not live until the reload.** A reload
that fails to parse keeps the live table (never nuked). Keys are indexed by their hash, so
a lookup is a single map hit (and trivially a single indexed query if you ever move this
to a database).

> **Upgrading from 1.x.** `enabled_paths` is gone and its presence is rejected
> outright: silently ignoring it would leave a user unscoped, which under the old
> semantics failed *open*. Rewrite each entry as a full URL pattern — and note that a
> 1.x user with **no** scope meant "all paths", so those users now need an explicit
> `["*://*/*"]` or they will reach nothing. Update nginx to send `X-Original-URL` too;
> the deploy script aborts before restarting rather than boot-loop the service.
>
> **Upgrading from 2.1.** Nothing to do: a file with no `sites` and no `denied`
> behaves exactly as before.
>
> **Upgrading to 2.4.** The access file is unchanged, but the cookie format moved to
> `bb3` and older cookies are no longer accepted, so **every signed-in user is logged
> out once** and signs in again (their Cognito session usually makes that a click).
> Nothing to prepare; just don't deploy it in the middle of something. The two new name
> headers are opt-in per nginx location — see
> [Profile claims](#profile-claims-optional).
>
> **Upgrading to 2.5.** The access file is again unchanged, and again the cookie format
> moved — to `bb4`, so **every signed-in user is logged out once**. Two things to know
> before deploying. First, the name headers are no longer emitted by default: which OIDC
> claims propagate is now `BB_AUTH_PROFILE_CLAIMS`, empty unless set, so a 2.4
> deployment that wants its two headers back must add
> `BB_AUTH_PROFILE_CLAIMS=given_name,family_name` to the env file (which the deploy never
> edits) — the headers are byte-identical, nginx needs no change. Second, that variable
> is read at startup, so later edits to it need a `restart`, not a `reload`. See
> [Profile claims](#profile-claims-optional).
>
> **Upgrading to 2.6.** Nobody is logged out: the cookie is unchanged, and so is every
> access file that does not use the new `url_groups` section. The one ordering rule is
> **deploy the binary before an access file that uses `@groups`** — a 2.5 gate does not
> know what `"@mcp"` is, fails the load outright and keeps its previous table (fail-closed;
> there is no partial grant to worry about). `bb-auth --check-users` on the old binary
> tells you the same thing before a restart does.
>
> **Upgrading to 3.0.** **Nobody is logged out**: the cookie is still `bb4`, the HMAC key
> is preserved as always, the access file is unchanged, and so is every env var the gate
> reads — its unit is byte-identical too. The major number is about the *deploy*, which
> grows a second service: `bb-auth-web`, with its own system user, its own unit and env,
> and the `bb-auth-reload.path` watcher — and, when it is installed, the access file
> changes owner to `bb-auth-web:bb-auth`.
>
> All of that is **opt-in by staging**. A `dist/` without `bb-auth-web` deploys exactly as
> it did on 2.6: no new user, no new units, no migration, `users.json` still `root:bb-auth`.
> If you do ship it, know two things. The first deploy **stops at the env preflight** —
> `/opt/bb-auth/etc/bb-auth-web.env` has just been installed from the template with an
> empty `BB_AUTH_WEB_ADMINS`, which is fatal by design; fill it in on the host and re-run.
> Nothing was restarted, exactly as with any other rejected config. And the GUI is reachable
> only through nginx, so it needs a gated location
> ([The admin GUI behind the gate](#the-admin-gui-behind-the-gate)) plus a grant covering
> the admin area for each admin. `sudo bb-auth-adm` needs no change and keeps working on
> the same file; rolling back is dropping the old `dist/` back on, though the file stays
> `bb-auth-web`-owned until someone chowns it back.

### Upgrading to 3.0

**Nobody is logged out**: the cookie is still `bb4` and the HMAC key is preserved, as
always. What changes is the **access file**, which becomes application-centric, and the
gate refuses the old format outright rather than misreading it.

That refusal is the whole reason there is a procedure. A 3.0 gate reading an older file
exits fatally, which under `Restart=on-failure` is a boot loop; the older gate reading a
3.0 file would see an empty table, which is a silent, total lockout. Neither is survivable
on its own, but the reload being **fail-soft** makes one order work:

```bash
# 1. put the new bb-auth-adm on the host (or convert a copy of the file on a workstation)
scp dist/bb-auth-adm user@host:/tmp/

# 2. convert. The still-running old gate cannot read the result, so the reload that the
#    path unit fires FAILS and keeps the table already in memory: the service goes on
#    serving, unchanged.
sudo /tmp/bb-auth-adm migrate -f /opt/bb-auth/var/lib/users.json -o /tmp/users.v3.json
sudo install -o bb-auth-web -g bb-auth -m 0640 /tmp/users.v3.json /opt/bb-auth/var/lib/users.json

# 3. now install. The restart is the first moment the new file is read, by the binary
#    that understands it.
./scripts/deploy.ps1 user@host
```

Do not reverse steps 2 and 3, and do not restart the gate between them.

`migrate` is not a best-effort translation: it replays every (identity, URL) pair the old
file speaks about through both rule sets and **refuses to write if any answer changed**.
What it cannot place, it reports. What it produces is safe to install, but it is not
necessarily tidy: it invents an application per URL area it found, and renaming those is a
separate, unhurried edit once the service is up.

Two things to check afterwards, because they are the ones the old format had no answer for:

- **Every gated URL must fall inside some application's `base`.** A URL no application
  covers is now reachable by nobody. `bb-auth --check-users FILE` prints the areas; compare
  them with the locations nginx actually gates.
- **nginx should clear `X-Auth-Uuid`** on every gated location, even though it is off by
  default. `proxy_set_header` overrides only the names it lists, so a header the gate could
  emit and nginx does not clear is one a client can send. Doing it now means enabling the
  attribute later needs no nginx change at all.

## Session cookie

HttpOnly, Secure, SameSite=Lax, host-only on the service host, ~30 days. The key id is
stamped in so the signing key can roll over with zero downtime (see "Key
rotation" below). Stateless: no server-side session store — any worker can
validate any cookie and a restart logs nobody out.

```text
bb4.<keyid>.<exp>.<b64url(email)>.<b64url(claims_json)>.<b64url(sig)>
sig = HMAC_SHA256("bb4.<keyid>.<exp>.<b64url(email)>.<b64url(claims_json)>", key[keyid])
```

Six fields always. `claims_json` is a JSON object of the profile claims the token
asserted — `{"family_name":"Byron","given_name":"Ada"}` — with **no claims written as the
empty segment**, never as `{}`. Values are stored as raw UTF-8 and percent-encoded only
when emitted as a header.

The blob names its own claims rather than relying on position, which is what makes
`BB_AUTH_PROFILE_CLAIMS` safe to edit: a cookie lives up to a month, and positional
segments would let a change to that list reinterpret a live cookie's values under
someone else's claim name. Editing the list is therefore *not* a format change — no one
is logged out by it.

`bb4` is the **only** format accepted — there is no verify-only arm for the older `bb1`,
`bb2` and `bb3`. A format bump therefore costs every user one trip through the login
page, which is a re-authentication (the browser still holds its Cognito session), not a
re-enrolment. That was judged cheaper than carrying every format bb-auth ever had, but
it means **the 2.5 upgrade logs everyone out once** — don't deploy it mid-something.
Key *rotation* is the separate mechanism that must never do that, and doesn't.

The access file is re-checked on every `/validate`, so de-authorizing someone is
just an edit (remove the user or a single API key, or add them to `denied`) +
`systemctl reload bb-auth` (SIGHUP). A restart works too.

## Build (cross-compile)

```bash
bash scripts/build.sh        # run on Linux (or WSL)
# → dist/{bb-auth, bb-auth-adm, bb-auth-web}
#   (the build prints the max GLIBC symbol required for the gate, so you can
#    match it to your target host's glibc)
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
/opt/bb-auth/share/*.example      # the templates the first install copies from
/opt/bb-auth/var/lib/users.json   # access list (0640, readable by the bb-auth group)
/usr/lib/systemd/system/bb-auth.service

# separate packages, both optional: see "Editing it" and "Editing it in a browser"
/opt/bb-auth/bin/bb-auth-adm      # the admin CLI
/opt/bb-auth/bin/bb-auth-web      # the admin GUI, run by its own bb-auth-web user
/opt/bb-auth/etc/bb-auth-web.env  # the GUI's config (operator-owned, no secret)
/usr/lib/systemd/system/bb-auth-web.service
/usr/lib/systemd/system/bb-auth-reload.{path,service}   # users.json changed -> reload the gate
```

The units live where a **package** must put them. `/etc/systemd/system` is the admin's
directory and a copy there *overrides* them, which is what an install from before the
packages left behind; `deploy.sh` moves any it finds aside.

Installing the GUI is what moves `users.json` to `bb-auth-web:bb-auth` (the gate keeps
reading it through the group, unit unchanged); a deploy without it changes no ownership at
all. See [Who owns the access file](#who-owns-the-access-file).

**The install is a `.deb`.** Three of them, one per binary, built by
`scripts/package.sh` (cargo-deb; the metadata is `[package.metadata.deb]` in
`Cargo.toml`, the maintainer scripts are real files under `deploy/debian/`):

```powershell
bash scripts/package.sh                    # arm64; --arch amd64, --no-build, --only
# → dist/{bb-auth,bb-auth-adm,bb-auth-web}_<version>-1_<arch>.deb
```

Everything the install does lives in those packages: the service users, the units, the
env file, the HMAC key, an empty access file, and the order they must happen in. What
they deliberately do **not** carry is any state, so `dpkg` cannot clobber
`etc/bb-auth.env` (the HMAC key: every live session cookie depends on it) or
`var/lib/users.json` (the only copy that is current). It cannot clobber a file it does
not ship, and that is a stronger guarantee than a `conffile` prompt, which one
`--force-confnew` would lose. Both are created on the **first** install only, and the
`postinst` runs the same preflight before anything restarts: the required env vars, and
`bb-auth --check-users` on the access file about to go live. A failure there exits
non-zero with the running process still serving, because a fatal startup under
`Restart=on-failure` is a boot loop.

A first install therefore ends *without* starting the gate: it says what to fill in.

`scripts/deploy.sh` is the **on-host installer** (run as root, on the target) and does
only what a package may not: `dpkg -i` in one transaction (not `apt install`, which
declines to reinstall an equal version, so a rebuilt `3.0.0-1` would silently not
deploy); moves aside any unit an older install left in `/etc/systemd/system`; installs a
staged `users.json` after `--check-users` has vouched for it, with the owner and mode
the live file already had; and runs `scripts/verify.sh`.

`scripts/verify.sh` is the **post-deploy verification**, and it is standalone: packages
configured, no unit shadowed, service active, `GET /auth/healthz == ok`,
`GET /auth/validate` (no cookie) `== 401`, HMAC key present, the access file parsing,
clean journal startup, and with the GUI its own liveness plus the ownership the write
path needs. It exits non-zero if any check fails, and changes nothing, so it is also the
way to ask a host how it is doing:

```powershell
ssh user@host 'sudo bash -s' < ./scripts/verify.sh
```

`scripts/deploy.ps1` (**run from Windows**) orchestrates the whole thing for a
`user@host`:

```powershell
./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local          # package in WSL + redeploy (users.json + HMAC key kept)
./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -Packages bb-auth   # gate only
./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -UsersFile .\deploy\users.json   # also replace the access file
```

It builds the packages (`package.sh`, which builds through `build.sh`, so `dist/` stays
current for everything else), verifies SSH + passwordless sudo + the target's
architecture, ships the `.deb` files with `deploy.sh` and `verify.sh`, runs `deploy.sh`
as root, and cleans up. By default it ships no `users.json` and never regenerates the
HMAC key, so redeploys are zero-downtime. `-Packages` is how the two admin tools stay
optional: they are separate packages that `Depends: bb-auth (= <version>)`, and a
gate-only host installs the gate alone.

## Run

bb-auth is a single binary configured entirely from the environment. It expects
to run **as a non-privileged service, on loopback, behind a TLS-terminating
reverse proxy** that performs the `auth_request`. It needs two files: the env
file (holds the HMAC secret) and the users file (JSON access list). The included
`deploy/bb-auth.service` runs it as a dedicated system user with aggressive
systemd hardening, and the `bb-auth` package installs exactly that: it creates the
user, puts the binary and the unit in place, writes `bb-auth.env` from the shipped
template with a freshly generated HMAC key on the **first** install, and preserves that
key and the access file through every later upgrade. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §"Running it".

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

   # Optional: let an application pick its own login page (see "Per-application login page").
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

           # Optional: profile claims, for a display name. These two are what
           # BB_AUTH_PROFILE_CLAIMS=given_name,family_name emits; omit both pairs
           # if the app has no use for them.
           auth_request_set $bb_given  $upstream_http_x_auth_given_name;
           auth_request_set $bb_family $upstream_http_x_auth_family_name;
           proxy_set_header X-Auth-Given-Name  $bb_given;
           proxy_set_header X-Auth-Family-Name $bb_family;

           # Which login page this area uses. auth_request_set reads the 401's
           # headers too, so the gate can name it per application.
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

   `X-Original-URL` is what [URL patterns](#url-patterns) matches against. It is
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

### The admin GUI behind the gate

[`bb-auth-web`](#editing-it-in-a-browser--bb-auth-web) is fronted the same way as anything
else — there is no special case for it, and that is the point. Mount it on whichever vhost
you keep for auth (here `auth.badbat75.com`, an existing server block), at the prefix its
`BB_AUTH_WEB_BASE_PATH` names:

```nginx
server {
    listen 443 ssl;
    server_name auth.badbat75.com;

    # The gate. Identical to every other vhost's — one bb-auth serves them all.
    location = /internal/auth-gate {
        internal;
        proxy_pass              http://127.0.0.1:4181/auth/validate;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
        proxy_set_header        X-Original-URL $bb_url;
        proxy_set_header        Authorization $http_authorization;
    }

    location /admin/ {
        # Mandatory, and it must live HERE, not at server level: the auth_request
        # subrequest re-runs the server rewrite phase and would clobber it, and inside
        # the subrequest $uri is /internal/auth-gate. Hardcode the host; use $uri.
        set $bb_url https://auth.badbat75.com$uri;
        auth_request /internal/auth-gate;

        # Who the gate authenticated. bb-auth-web reads THIS and nothing else, so the
        # proxy_set_header is not decoration: it overwrites whatever the client sent,
        # and without it anyone could name themselves an admin.
        auth_request_set $bb_email $upstream_http_x_auth_email;
        proxy_set_header X-Auth-Email     $bb_email;
        proxy_set_header X-Forwarded-User "";
        proxy_set_header Remote-User      "";
        # The GUI has no use for a display name; clear them rather than relay the
        # client's. (Only needed if BB_AUTH_PROFILE_CLAIMS names them at all.)
        proxy_set_header X-Auth-Given-Name  "";
        proxy_set_header X-Auth-Family-Name "";
        # If this server block gets its proxy headers from a server-level
        # `include proxy_params;`, re-include it here: a location-level
        # proxy_set_header discards every inherited one.

        auth_request_set $bb_login $upstream_http_x_auth_login_url;
        error_page 401 = @bb_signin;

        # NO URI part. The request path passes through unchanged, so /admin/users
        # arrives as /admin/users — which is why BB_AUTH_WEB_BASE_PATH=/admin.
        # Writing `proxy_pass http://127.0.0.1:8091/;` would strip the prefix and every
        # link the GUI emits would 404.
        proxy_pass http://127.0.0.1:8091;
    }

    location @bb_signin {
        return 302 $bb_login_safe?rd=$scheme://$host$request_uri;
    }
}
```

Three operator notes, and the first is the one that matters:

- **The admin area must be a scope that lists each admin.** The gate is the lock;
  `BB_AUTH_WEB_ADMINS` is the backstop behind it. Enrol each admin:

  ```bash
  sudo /opt/bb-auth/bin/bb-auth-adm -f /opt/bb-auth/var/lib/users.json \
      user set you@badbat75.com \
      --add-url 'https://auth.badbat75.com/admin,https://auth.badbat75.com/admin/*'
  ```

  A blanket `*://*.badbat75.com/*` scope already covers it — check with
  `bb-auth-adm can you@badbat75.com https://auth.badbat75.com/admin/` before assuming
  either way.
- **Never cover the admin area with an `anonymous` or `authenticated` scope.** Those grant without listing anybody,
  to anyone who can register, and Cognito self-signup is open — it would put every account
  in front of the admin surface with only `BB_AUTH_WEB_ADMINS` left standing. Two locks or
  one is the whole difference.
- **Every gated location must set or clear `X-Auth-Email`**, here as everywhere — see
  [Passing the identity to the app](#passing-the-identity-to-the-app). `proxy_set_header`
  only overrides the names it lists, so an unlisted one travels straight through from the
  client.

The vhost's host must also match `BB_AUTH_AUTHORIZED_HOSTS`, or the `401 → login → back
here` round trip lands on the login page instead (`*.badbat75.com` covers
`auth.badbat75.com`).

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
stamped into every cookie and multiple keys can be accepted for
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

Nobody is logged out at any step — that is the point of rotating by id rather than by
swapping the secret. A **cookie-format** bump is the other axis and behaves the
opposite way: only [the current format](#session-cookie) is accepted, so it does log
everyone out once. Don't conflate the two.
