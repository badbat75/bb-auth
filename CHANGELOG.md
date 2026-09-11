# Changelog

What changed between releases, and above all what an **upgrade does to people who are
signed in**. That last question is why this file exists at all: the session cookie is a
versioned wire format and exactly one version is ever accepted, so a change to it logs
every user out, and the invariant that says so nominates release notes as the place it must
be announced. There were none.

Versions are the crate's (`Cargo.toml`); packages add a Debian revision
(`1.99.1-1`), which is bumped by `--revision` when the same code is repackaged.

## Standing facts

* **Cookie format**: `bb1`. Unchanged since 1.0.0. While this line does not change, an
  upgrade logs nobody out.
* **Access file format**: `"version": 1`. A file declaring anything else is refused, with
  an explanation, rather than compiled into a different set of grants.
* **Settings file format**: `"version": 3`. Versions 1 and 2 are each refused with a
  sentence naming the fields to move in, rather than a type error three levels down.
* **Rollback**: safe by construction while the cookie format is unchanged, because sessions
  are stateless and no state is packaged. See "Rollback" in [README.md](README.md).

## Unreleased

**Due out as 1.99.6, and the numbers before it are behind us.** 1.99.5 was spent by a deploy
on 2026-09-11 from `g15ae13e`, which carried everything in the section named after it except
the Settings page opening folded. 1.99.4 was spent by a deploy
on 2026-09-10 from `gfd77f1f`, which carried the audit and nothing of what the section below
calls new after it. 1.99.2 was spent by a
deploy: a build carrying it went to a host on 2026-08-20 from `g3b40e77`, which had the
`form-action` fix below and nothing of the `403` work. 1.99.3 is left behind one step along,
and without the same claim being made about it, because the claim is not the point: the
refusal page's sign-out link changed after that number was written, so the bytes under it are
not the bytes under this one, whether or not any host ever ran them. Reusing either would put
two different sets of bytes behind one version string, which is the failure the commit in the
version string exists to catch rather than to cause.

**A release candidate for 2.0.0**, and the version number says so: the
configuration surface moved far enough in one window that calling it 1.2.0 would have
undersold what an upgrade has to do. The findings of an architecture and process review,
addressed; the gate's whole Cognito wiring and the estate it serves moved out of the
environment and into the settings file; and a confirmation step in front of the five settings
that can stop people getting in.

**A version gets a section of its own here only once it is tagged and released, and a
release candidate is neither.** 1.99.6 is a version number, not a release: it is built,
deployed and run, and it is **not tagged**, because a tag is what says "this is a thing you
can install and go back to" and a candidate is not that. So this section stays under this
heading through however many 1.99.x there are, and becomes `## 2.0.0` on the day 2.0.0 is
tagged. That rule is also what took 1.1.0 out of this file: it was built, deployed and never
released, with no tag and no artefact anybody could have installed from, and the single host
that ran it was running a working tree. It had a section here as though it had shipped, which
is a version number somebody could have gone looking for. What it contained is the first
section below, because this is the release that actually ships it.

The practical consequence is worth knowing before you need it: **an untagged build's handle is
its commit**, which every binary bakes in and `--version` prints. That string changed shape in
this release for exactly this reason: it used to be the crate version followed by
`git describe`, and describe anchors on the last **tag**, so an untagged candidate read
`bb-auth 1.99.1 (v1.0.0-18-g0a8d129)` — the true version, then a string opening with a version
one minor number and eighteen commits out of date. It now reads `bb-auth v1.99.1-g0a8d129`:
cargo's version, which cannot be wrong, and the commit, which is what a rollback checks out
when there is no tag to check out.

**Nothing here changes the cookie format or the access-file format, so no upgrade in this
release logs anybody out.** The settings file goes from version 1 to version 3, which needs an
edit before the binaries land: see "Upgrading" below.

### New: the audit, and an Audit tab to read it

The gate now records what it has answered, and `bb-auth-web` grew a fifth tab that reads it
back: newest first, filtered by person, by credential (social, Cognito account, API key,
session) and by period, paged like every other list here and needing no JavaScript for any of
it. Refresh is a link to the same address, because the page reads the file on every request.

**It is on by default at `/var/log/bb-auth/audit.jsonl`, and there is one thing to know before
upgrading: the events move.** With an audit file, a sign-in, a sign-out and a refusal go to
that file *instead* of into the journal, because the same event in two places is one somebody
has to reconcile by eye. `journalctl -u bb-auth` keeps everything else it ever had (startup,
configuration, reloads, failures), `journalctl` at `BB_AUTH_LOG_LEVEL=debug` prints the
request lines regardless, and `BB_AUTH_AUDIT_FILE=` (empty) turns the file off and puts the
journal back exactly as it was. If the file cannot be written the events fall back into the
journal on their own, with one line saying so.

What it records is **authentication, not traffic**: sign-ins, sign-outs, refusals, and the one
grant worth a line, which is somebody Cognito vouches for walking into an `authenticated`
scope while being in no `users` entry. Not the ordinary allowed request: the gate answers an
`auth_request` for every asset of every page, so that is nginx's log and always was, and it
has the URL, the status and the byte count of every request. Refusals that carry no
credential at all are not recorded either, being what every signed-out browser gets on its way
to the login page. A refusal repeated inside five minutes is recorded once.

The file is JSON, one object per line, with a schema version on every one, and it rotates
itself at 4 MB onto `.1`, so the pair cannot exceed 8 MB whatever happens. Nothing about it
can cost a login: a write that fails is one journal line and the request proceeds.

Two deployment notes. The gate's unit gains `LogsDirectory=bb-auth`, so **the unit file has to
land and `systemctl daemon-reload` has to run** before the gate can write anything (the
package does both); until then the audit fails soft and the events stay in the journal. And
`bb-auth-web` reads that directory through the `bb-auth` group it already belongs to for the
access file, so a GUI host needs no new privilege. One credential is recorded less precisely
than it might be: a session cookie says who you are and not how you proved it, so a refusal
carrying one reads "Session" rather than "Google". Stamping the provider into the cookie is a
cookie-format bump, and a cookie-format bump logs everybody out. The sign-in event carries the
exact answer, which is where the question is really being asked.

### Carried by 1.99.5: where a request came from, how long it is kept, and in which time zone

Every audit row can now say where its request came from: the client's **address**, nginx's
own **id for the request** (which finds that request's line in nginx's access log, where
everything the audit leaves out is), the client's **user agent** (cut at 256 bytes), and, on a
sign-in, the Cognito **account** behind the token (`sub`), which is what tells this month's
owner of an address from last month's once an account has been deleted and registered again.
The Audit tab shows them in a Client column and under the name, and its filter box finds a
row by any of them, so an address pasted from a firewall's log or an id from nginx's lands on
the row. The credential moved under the event to make room, and reads as one fact with it:
"Signed in, Social Google".

**The address and the request id are off until you say which headers to believe**, and that
is the one thing to know before switching them on. The gate listens on loopback, so an
address is only as true as the nginx in front of it, and a header nginx does not overwrite is
whatever the client sent. Two new settings name the headers, `audit.client_ip_header` and
`audit.request_id_header` (`bb-auth-adm settings set --client-ip-header X-Real-IP
--request-id-header X-Request-ID`, or a new group on the Settings tab), and the README's
nginx recipe sets `X-Real-IP $remote_addr` and `X-Request-ID $request_id` on the three
locations that reach the gate, plus a `log_format` carrying `$request_id`. A list such as
`X-Forwarded-For` is read from its last entry, the one nginx added; neither setting may name
`Authorization`, `Cookie` or `Proxy-Authorization`. The user agent needs no setting, being
the client's word about itself and recorded as nothing more.

They live in a **new `audit` section** of the settings file, with the two below, and that
has one convenient consequence: an older gate keeps an unknown top-level key rather than
refusing the file, so the section can be written before the binaries that read it land.

A refusal repeated inside five minutes is still recorded once, but the window is now per
address as well: the same key refused from a second machine is a second row, and usually the
interesting one.

**How long the audit is kept is now a setting**, two in fact, each an amount and a unit of
time (`weeks`, `months`, `years`) or of space (`MiB`, `GiB`). `audit.rotation` is when the
live file moves onto `.1` (at a size, or when its oldest event reaches an age), still keeping
only the last one; `audit.retention` is the most kept across the two files (no event older
than an age, or the pair never over a size). The defaults, `4 MiB` and none, are exactly what
the audit did before. **At least one of the two has to be a size**, or a flood of refusals could
fill the disk, and a file with both in time is refused with a sentence saying so. A retention in
time is applied hourly, at startup and on every reload, so a quiet deployment still forgets an
address on the day it said it would, and the Audit tab shows nothing past it even in the hour
between. For personal data such as addresses this is the setting that answers "for how long".
The audit's files are also read backwards in blocks now, so a rotation set to a gibibyte costs
the Audit tab no more memory than one set to four mebibytes.

The Settings tab's groups **fold**: each heading opens and closes its group (a `details`, so no
script), and "Expand all" / "Collapse all" at the top are remembered per browser like the
language and the theme, so a page somebody opened stays open after a save. **Since 1.99.6 the
page opens folded**, reading as its five headings; 1.99.5 opened it expanded. A group holding a
refused field opens whatever the preference says.

The Audit tab reads its times in UTC (as before, and still the default), in the **host's**
zone, or in one you name (`Europe/Rome`, `+05:30`), chosen beside the filters and remembered
per browser like the language and the theme. "Local" is the host's zone and not the
browser's: no request header carries a browser's zone, and no page here may need a script to
ask. The zones come from the host's own database through one new dependency, `tz-rs`, which
has none of its own and bundles no zone data; a host without `tzdata` offers UTC and says so
above the table.

Nothing here changes the cookie, the access file or the settings file's version: the new
section is additive, and so are the four audit fields, whose schema stays `v: 1` (an older
reader ignores them, a newer one reads an older line without them).

### Fixed in 1.99.2: `form-action` blocked every Chromium login

**If you are running a 1.99.1 build, upgrade.** Between 1.99.1 and this build, the
`Content-Security-Policy` the gate's pages carry named `form-action 'self'` as a constant,
and that blocks the last hop of every login in a deployment whose sign-in page and landing
host are different hosts, on any Chromium browser. Firefox and Safari are unaffected, which
is what made it look like something else.

The shape it takes is the worst one available. Both gate pages hand the id_token over with a
real top-level form `POST` to `/auth/session`, which is same-origin and passes; the response
is a `302` onto wherever the visitor was going; and Chromium applies `form-action` to the
**redirect target** of a form submission, not only to the URL the form names. So the session
is minted, the cookie is set, the journal records `session granted`, and the browser silently
cancels the navigation: the person is signed in and is looking at a spinner that will never
finish, with nothing on screen and nothing in the log to say why.

`form-action` is now derived from `gate.cookie_domain`, like everything else in that policy:
`'self' https://<domain> https://*.<domain>`. Nothing to configure, and no new setting. The
cookie domain is the source rather than `gate.authorized_hosts` because the settings file
already refuses a file whose authorized hosts that domain does not cover, so it is a superset
of every host a login can legitimately reach, and because a host pattern may be a glob that no
CSP source expression can express. Where no cookie domain is set the directive stays `'self'`,
which is correct: a host-only cookie has no second host to survive to. The admin GUI keeps
`'self'` and always did, since it only ever redirects to itself. This is not a change to where
a login may land: `safe_rd` and `gate.authorized_hosts` decide that, exactly as before.

### Carried by 1.99.3: the `403` and the page it lands on

1.99.3 is the number the rest of this section was first built under, and it is written down
because a candidate's handle is its commit while the number is the only thing a host reports
about itself. It carries everything from "A refused request that is signed in gets a `403`,
and a page" onwards, and three things too small to have a section of their own:

* **Shell scripts are checked out with LF** (`.gitattributes`). A `deploy.sh` that reaches a
  Debian host with CRLF line endings dies on `bash: $'\r': command not found` at its first
  line, so the rule is not tidiness: it is the difference between a release leaving this
  machine and not.
* **`scripts/package.sh` works the commit out before handing over to WSL**, for the reason
  `deploy.ps1` already did one script along: the build runs where the checkout is a `/mnt/c`
  mount and `git` may not exist, so asking there answered `unknown`.
* A clippy 1.98 fix (`?` in place of a match that only ever returned `None`), and the
  refusal page's nginx recipe corrected to `rewrite ^ /auth/denied break`, since a named
  location takes no URI on `proxy_pass` and the shorter form fails `nginx -t`.

### Fixed in 1.99.4: the refusal page signed out into a 404

The `Sign out` link on `/auth/denied` was `href="/auth/logout"`, root-relative, and that is
wrong everywhere the page is actually read. nginx answers a `403` with it through
`error_page 403 = @bb_denied`, which **proxies rather than redirects**, so the browser is
still on the gated vhost: the click resolved against a host that mounts a service and not the
gate, and landed in that vhost's catch-all. A `404` for whoever the service knows, and the
refusal page again for whoever it does not, which is the loop the `403` exists to end,
arriving one click later.

The link is now absolute on the origin of that area's login page, and carries that page as
its `?rd=`. The origin is the login page's because it is the host a deployment has already
said the gate answers on, and it is resolved per area, so one gate fronting several hosts
signs each host's people out where they signed in. The `?rd=` is there because a sign-out
offered on this page means "use another account" and has somewhere specific to land; without
one the browser's `Referer` answers instead, naming the page that has just refused them,
which costs a `401` and one more hop.

Nothing to configure, and one thing to know: this is the rule "One logout endpoint for every
vhost" in README already stated, applied to the gate's own page, which was the last thing in
the repository breaking it. **A gated vhost therefore needs no `/auth/logout` location of its
own.** Where `gate.login_url` is empty the link stays relative, which is correct: the gate's
own sign-in page is only reachable when the gate is mounted on the vhost being read from, and
then the endpoint beside it is too.

### The gate serves its own sign-in page

* `/auth/login` and `/auth/callback` are the gate's now, complete on their own: no font, no
  CDN, no second host, because the situation those pages exist for is somebody not being able
  to get in. `gate.login_url` may still point at a page of your own.
* **The look is shared**: the palette (`theme.css`) and the components built out of it
  (`base.css`) live in the library and both programs emit the same bytes, so one
  `ui.stylesheet_url` restyles the sign-in page and the admin interface together.
* The admin GUI's access check moved out of a tab of its own and into the application page and
  the person page, which is where the question is actually asked. There is no `/can` route.
* Logging out is one endpoint for every vhost, and a link that says nothing falls back to
  `Referer`.
* **nginx must leave `/auth/login` and `/auth/callback` ungated**, exactly as it leaves
  `/auth/session` and `/auth/logout`: a sign-in page behind `auth_request` answers a signed-out
  visitor with itself, forever.

### A refused request that is signed in gets a `403`, and a page

* **`/auth/validate` now answers `403` when it identified the caller and no scope admits
  them**, and keeps `401` for a caller it could not identify. That ends a redirect loop that
  had no error anywhere in it: nginx turns a `401` into the login page, and somebody who is
  already signed in signs straight back in, returns to the URL that refused them, and is
  refused again. The line is drawn where each credential is *verified*, so a live `bbk_` key,
  a valid id_token and an unexpired session cookie all reach the new status; an expired
  cookie, a forged one and no credential at all keep the old one. The `403` deliberately
  carries no `X-Auth-Login-URL`: there is nothing to redirect to.
* **nginx needs one more line per gated location**, and without it a `403` is whatever your
  server block does with an unhandled one:

  ```nginx
  error_page 401 = @bb_signin;
  error_page 403 = @bb_denied;          # new
  location @bb_denied {
      proxy_set_header X-Original-URL $bb_url;
      rewrite ^ /auth/denied break;    # a named location takes no URI on proxy_pass
      proxy_pass http://127.0.0.1:4181;
  }
  ```

* **All four of the gate's pages are now files** under `src/assets/`: `login.html`,
  `callback.html`, and the two that used to be built in a `format!` in the middle of the
  gate, `denied.html` and `error.html` (the page a failed `/auth/session` lands on). Same
  `__BB_*__` substitution, same shared `<style>`, so a page is edited, diffed and reviewed as
  HTML.
* **The gate serves the page**, at `/auth/denied`, in the palette the `ui` section gives every
  other page. It answers `403` itself, so `error_page 403 = @bb_denied` keeps the status
  honest, and it says that this account cannot open that page **without** saying whether the
  page exists: a URL outside every application is refused exactly like one whose scope
  excludes you. Its one link is a sign-out, since signing in as the same person lands right
  back on it, and it is absolute on the origin of that area's login page (see "Fixed in
  1.99.4" above). Leave the page's location ungated, like the other two pages.
* **Two ways to use your own page instead**: `gate.denied_url` in the settings file for the
  whole deployment, and `denied_url` on an application in the access file for one area.
  Because an area is an absolute prefix, that second one is **per host**: one gate fronting
  several hosts gives each host its own refusal page, written where every other property of
  an area is. `/auth/denied` then answers `302` to it, which is why the nginx snippet above
  forwards `X-Original-URL`: without it the area cannot be resolved and the global page
  answers, which still says no.

### Security

* `POST /auth/session` now refuses a request the browser reports as `cross-site`, or one
  that says nothing about where it came from. Minting a session cookie for somebody else's
  form is login CSRF, and `SameSite=Lax` does not cover it: that attribute governs when a
  cookie is *sent*, never who may cause one to be *set*. A sign-in page an operator serves
  themselves on a sibling host still works (`same-site` passes); one on another site does
  not.
* Every page either program serves now carries a `Content-Security-Policy`
  (`default-src 'none'` plus exactly what that page uses), plus `Referrer-Policy`,
  `X-Content-Type-Options` and `X-Frame-Options`. The gate's pages use a per-response
  nonce; the admin GUI uses content hashes, since everything it emits is a constant. One
  practical consequence: an operator's `ui.stylesheet_url` and `ui.logo_url` are now named
  in the policy, so a third host cannot be introduced by a page that has one of them.
  `font-src` follows the stylesheet and only the stylesheet, so a token file may bring its
  own `@font-face` from the host it came from (or a `data:` face), and no other host may
  serve a typeface to these pages.
* **The admin GUI's own stylesheet was being refused by its own policy on every build made
  on Windows**, which is every build this project ships: an HTML parser collapses CRLF before
  the CSP check runs, so a browser hashes the LF form of an inline block, while `csp_hash`
  hashed the bytes `include_str!` embedded, and this repository's working tree is CRLF
  (`core.autocrlf=true`, and the cross-compile builds from that same tree). The result was an
  admin interface rendered as unstyled markup, with nothing in any log and nothing in a test:
  the test that checks the pairing compared the function against itself. `csp_hash` now
  normalises newlines, and the test pins a literal hash rather than a round trip. The gate's
  own pages were never affected, because they use a per-response nonce.
* The admin GUI refuses to start on a non-loopback address unless
  `BB_AUTH_WEB_ALLOW_NONLOOPBACK=1` says it was meant. Its only credential is a header
  nginx injects, so a bind to `0.0.0.0` was an unauthenticated remote writer of the access
  list.
* The admin GUI's refusals wear the deployment's look once the settings can be read: a
  `403` for somebody who is authenticated but not on `web.admins` used to render in the
  built-in palette, which on a themed installation looks like a page of another service.
  The two pages that answer *before* the settings are read keep the built-in look, because
  the file that would describe another one is exactly what is missing or broken.
* An `anonymous` scope no longer names a **vetoed** identity in `X-Auth-Email`. The veto
  cannot close an area that is open with no credential at all, but it now stops the gate
  introducing that person to the application behind it.
* An unknown field on an `api_keys` entry is reported at load. A misspelled `scopes` widens
  a key to everything its owner reaches and a misspelled `duration` makes it immortal, both
  silently.
* `remove_user` rewrites a `denied` entry for the removed uuid as that person's primary
  email instead of leaving it dangling: deleting a suspended user used to lift their
  suspension, and with an `authenticated` scope anywhere in the file they could simply
  re-register.

### The settings file, now at `"version": 3`

* **`gate.denied_url`**, the nineteenth setting: where a `403` lands, empty meaning the gate's
  own `/auth/denied`. It is a new optional field rather than a format change, so a version-3
  file that does not mention it is read exactly as before. It passes the three-part rule more
  cleanly than anything else in the file, because it is read *after* somebody has been
  refused: the worst a wrong value achieves is a broken link shown to a person who was never
  getting in, which is why it is not a sixth change that asks before it answers. An
  application's own `denied_url` in the access file overrides it for that area.
* **The user pool, the cookie's domain and the authorized hosts moved in too**, and three more
  environment variables are no longer read: `BB_AUTH_COGNITO_ISSUER`, `BB_AUTH_COOKIE_DOMAIN`
  and `BB_AUTH_AUTHORIZED_HOSTS`, replaced by `gate.issuer`, `gate.cookie_domain` and
  `gate.authorized_hosts` (a list, not a comma-separated string). `bb-auth.env` is down to
  seven values: the listener, the worker count, the HMAC key and its two rotation companions,
  the cookie's **name**, and the path of the access file.

  **What this costs is worth stating, because it retires an argument rather than adding one.**
  Version 2 was safe to hand to a browser-editable file because the *pool* stayed in the
  environment, so the file could only choose among the app clients of an issuer that was
  already trusted. With `gate.issuer` in the file that sentence is no longer true, and the
  honest replacement is that this file is trusted as much as the gate itself: whoever can write
  it can already write the access file beside it and the admin list inside it.

  Two of the three do not pass the settings file's own three-part rule cleanly.
  **`gate.issuer` is not read per request** but once, to fetch a JWKS, so a `SIGHUP` that sees
  a new pool fetches its keys first and swaps the keys and the settings together or swaps
  neither: a gate holding half of that pair would check one pool's tokens against the other's
  keys. And **`gate.cookie_domain` cannot log anybody out, which is worse than if it could**:
  a browser matches a clearing `Set-Cookie` on `(name, Domain, Path)`, so every cookie already
  issued under the old domain stays valid for its full lifetime *and* `/auth/logout` can no
  longer clear it. Putting the old value back makes those cookies clearable again.

  **What the move buys** is a check that was not expressible while the two lived in different
  files: `gate.cookie_domain` must reach every host in `gate.authorized_hosts`, or the file is
  refused. A host the cookie cannot reach is a login that succeeds, redirects, sends no cookie,
  gets a `401` and lands back on the sign-in page it came from, for ever, with nothing anywhere
  saying why.

* **Five settings now take two steps to change**, in both editors: `gate.issuer`,
  `gate.client_id`, `gate.login_url`, `gate.cookie_domain`, and *removing* an entry from
  `gate.authorized_hosts`. `bb-auth-adm` prints what each change costs and writes nothing
  without `--yes`; `bb-auth-web` renders a panel naming the old and the new value and holds the
  save until a second `POST` carries the token that page rendered. Asking rather than refusing,
  because none of them invalidates a cookie: whoever makes the edit still holds a session and
  can undo it, and `bb-auth-adm` over SSH is the way back if not.

  It is five and not fifteen on purpose, and it fires on what is **taken away**: filling in a
  value that was empty is a deployment being finished, not a risk, and *adding* an authorized
  host cannot stop a login. A confirmation that fires on every save is a button people learn to
  click without reading, which is worse than no confirmation because it is also an alibi.

* **`bb-auth-web` refuses to write an empty `issuer`, `client_id` or `authorized_hosts`**,
  while the gate tolerates all three and says so loudly at startup. That is the same rule at
  two distances rather than a contradiction: a package creates this file and cannot know any of
  those values, so refusing to start would be a boot loop on every first install, but a *form*
  should not be able to express a deployment nobody can get into. A fresh install is therefore
  wired with `bb-auth-adm` over SSH, and has to be: `bb-auth-web` is itself behind the gate.

* **Fixed: a page returned by a `POST` carried an empty `rev`**, so submitting it again was a
  `409` about a file nobody else had touched. Fix the field a refusal named, press Save, and
  the answer was a conflict. It never mattered before because every refusal page was reached by
  reloading; the confirmation step above is *designed* to be submitted again, which is how the
  browser suite found it.

* **Every Cognito app client this gate is part of is now in the settings file**, and six
  environment variables are no longer read: `BB_AUTH_CLIENT_ID`, `BB_AUTH_AUDIENCES`,
  `BB_AUTH_LOGIN_URL`, `BB_AUTH_OAUTH_DOMAIN`, `BB_AUTH_SOCIAL_CALLBACK_URL` and
  `BB_AUTH_SOCIAL_IDPS`. What replaces them is `gate.client_id` (the email flow's app
  client), `gate.login_url` (where people sign in, empty meaning the gate's own
  `/auth/login`), `gate.oauth_domain`, `gate.social_callback_url`, and a `gate.social_buttons`
  list whose entries are now `{ "idp": …, "audience": … }`.

  **The audiences are derived from those and no longer configured.** An id_token carries the
  app client it was minted for in `aud`, so naming an app client in this file is what makes
  its tokens acceptable; `BB_AUTH_AUDIENCES` existed only to repeat that by hand. Two lists
  that had to agree with a third are now one, and the startup warning that used to say they
  did not is gone with them. The safety argument at the time was that the **pool** stayed in
  the environment, so this file could only choose among the app clients of one issuer; the
  version-3 entry above is where that argument was retired and replaced.

  **Each social button carries its own app client**, because Cognito federates per app
  client: which providers a client offers is a property of that client, so two providers may
  live on two of them and a single value could not express it. The sign-in page puts the
  clicked button's client id in `sessionStorage` beside the PKCE verifier, and the callback
  exchanges its code with that one.

  **Upgrading is a two-step, in this order.** Write the new settings file first: the running
  gate refuses it (unknown fields, and a version it does not know), keeps the values it already
  has, and says so in the journal, so nothing goes down. Then deploy. Doing it the other way
  round leaves the new binaries with a file they refuse, and a settings file the gate cannot
  read is fatal at startup, which under `Restart=on-failure` is a boot loop.
  `bb-auth --check-settings <file>` validates the new shape before either step, and
  `--check-env` names every retired variable still sitting in `bb-auth.env`. Coming from
  version 1, both moves happen in the same edit; coming from version 2, only the three fields
  the entry above names have to be added.
* ~~**`gate.social_client_id`**~~, introduced and removed on the same day, along with
  `BB_AUTH_SOCIAL_CLIENT_ID`.
  The Cognito app client a social sign-in runs through moved from the env file to the
  settings file, because all three programs have an opinion about it and an env var is
  readable only by the process that was started with it: the admin GUI could only have shown
  it by being handed a second copy, and a value written in two files drifts. It is the
  twelfth setting and the one member of the `BB_AUTH_SOCIAL_*` group to cross that line, so
  it was argued against the three-part rule rather than moved: read per request, unable to
  lock anybody out (a wrong value costs the social buttons, never the email path), and no
  secret, since the sign-in page has always emitted it into its own script. It cannot widen
  what the gate accepts either: the audiences stay in `BB_AUTH_AUDIENCES`, and no button is
  drawn through an app client that is not already one of them, which is what the env var's
  fatal startup check became. Fail-soft on purpose, because a hot file may never be fatal:
  with no app client, or an unusable one, the social section is simply not drawn and the gate
  says which of the two it was at startup and after every reload.
  **Upgrading a deployment with social sign-in requires moving the value**:
  `bb-auth-adm settings set --social-client-id <id>`, then delete the variable from
  `bb-auth.env`. The gate warns while it is still there.
* **`gate.social_buttons`**: which social sign-in buttons the page offers, by Cognito
  `identity_provider` name, in the order they appear, changed with no restart and from the
  admin GUI, where it is a checkbox per provider (`Google`, and `Microsoft` meaning the
  personal account rather than an Entra ID tenant) instead of a list of names to type: a name
  Cognito will not match is a button that never appears with nothing to say why. A provider
  configured from `bb-auth-adm` that this build does not know gets a checkbox of its own, so
  the page can never drop what it cannot name. **Empty offers none**, so a provider is shown
  because somebody enabled it and not because the deployment happens to federate it. It is
  the eleventh setting and was
  checked against the three-part rule before it was added: read per request, unable to lock
  anybody out (the email path is untouched), not a secret. `BB_AUTH_SOCIAL_IDPS` keeps its
  own job, which is a different one: it says what the app client federates, and a button
  needs both. **Upgrading a deployment that had social buttons requires setting this**, or
  the sign-in page will offer none.
* The Settings page is now four boxes grouped by what a setting decides (access policy;
  what the application receives; the sign-in page; administration and look) rather than one
  form with three headings named after the file's own sections. The file is unchanged: each
  box still names the key it writes.
* The ways in are a **table** on that page, a row per way: what a visitor reads, the
  `identity_provider` Cognito matches byte for byte, and the app client the sign-in runs
  through. The email row is in it and has no tick, because the email path is not something a
  deployment turns off and its app client is the same kind of value as every other row's.
  A stacked list of checkboxes ran those three facts together, and the first two differ
  exactly where it matters: `Microsoft` is the word on the button and `MicrosoftPersonal` is
  the name Amazon knows.

### The built-in palette

* **The dark arm's accent moved for contrast, and `--on-accent` moved with it**:
  `--accent` `#5b78ff` to `#6a85ff`, `--accent-hover` to the old `#5b78ff`, `--accent-weak`
  to match, and `--on-accent` `#ffffff` to `#16161b`. Against the dark `--card`, the old blue
  measured 4.28:1 as link text, under the 4.5:1 WCAG AA asks of body text. It could not be
  fixed alone: the same token fills buttons, white on it was already 3.77:1, and lightening
  the blue makes that worse. Text on the card wants a relative luminance of at least .243,
  white on the fill wants at most .183, and no single colour is both, so the pair had to move
  together. The new values measure 4.93:1 and 5.51:1. The light arm is unchanged and already
  passed at 4.96:1 in both roles.
* **Visible consequence**: on a dark theme, text on a filled accent surface is now dark rather
  than white. That affects `button`, `button:hover` and `.pill.on`, which is every primary
  action on the sign-in page and every selected pill in the admin GUI. It is the rule this
  palette already applied to filled STATE surfaces (`--on-state`), and the accent was the last
  token exempt from it.
* **A deployment with its own `ui.stylesheet_url` sees nothing change** if that file already
  redefines these four tokens, which a complete token file does. One that redefines `--accent`
  but not `--on-accent` should check the pairing: it will now inherit a dark `--on-accent`
  under whatever blue it chose.
* No cookie, access-file or settings-file format is touched, so nobody is logged out. The
  admin GUI's `style-src` hash is computed from the emitted bytes at build time and needs no
  manual update.

### The admin interface

* **The access check answers where it was asked.** Both check forms submit to `#check`, which
  the section's heading carries, so the verdict arrives in front of the person who asked for
  it instead of at the top of a fresh document several screens above it. A `GET` form keeps
  the fragment of its `action` and replaces only the query, so this costs one attribute and
  no script.

### Availability

* A `recv()` error is now fatal. `tiny_http` reports at most one accept error per listener
  and then stops accepting, so the previous `continue` left a live process with no listener:
  no exit code, no restart, and every gated request failing.
* An unknown `kid` no longer serialises every worker behind one JWKS fetch. The refresh
  lock is taken with `try_lock`, the fetch timeout is 3s, and a failure is cached for 10s.
* The gate warns at startup when an application's `login_url` is outside
  `gate.authorized_hosts`, and when it is listening on a non-loopback address.
* `session_ttl_secs` has a ceiling as well as a floor, and the cookie's expiry is computed
  with a saturating add.

### Release and operations

* **`bb-auth --self-test`** performs the offline RS256 verification a login performs, with
  no env, no config and no network. `scripts/verify.sh` runs it: every check it had was
  green on the build whose JWT verifier was a `panic!`.
* **`bb-auth --version`** (and the GUI's footer, and both startup banners) reports the
  commit the binary was built from, with a `-dirty` marker: `scripts/build.sh` and
  `scripts/package.sh` export it as `BB_AUTH_BUILD` and the binaries read it at compile
  time. A `.deb` version reads the same for a tagged release and for a working tree somebody
  built by hand. `deploy.ps1` works the string out on the Windows side and passes it in,
  because the build runs inside a WSL distribution where the checkout is a `/mnt/c` mount and
  `git` may not exist: asking there answered `unknown` for every release built the supported
  way, and left the dirty-tree refusal unable to fire.
* **`scripts/package.sh` runs the test suite** before it builds, and refuses an uncommitted
  tree unless `--allow-dirty`. `--skip-tests` exists for repackaging bytes already tested.
* Builds are `--locked`, and `scripts/build.sh` no longer copies the resolved `Cargo.lock`
  back over the tracked one: a dependency bump is a deliberate commit again.
* `cargo-deb` is installed at a fixed version. The toolchain and the cross-linker
  configuration stay where they were, on the release machine (`rustup default`, its own
  `~/.cargo/config.toml`); `scripts/README.md` lists what that machine needs.
* `bb-auth --check-env <file>` answers "is every required variable set?", and the gate's
  postinst asks the binary instead of keeping its own list of six names in shell.
* A staged access file is validated **before** `dpkg -i`, not after: a rejected file now
  costs nothing instead of a red deploy on a host that has already been mutated.
* A failed restart in either postinst is now a failed install. It used to be `|| true`.
* `scripts/deploy.sh` records what it is replacing under `share/previous/`, and README has
  a Rollback section.
* Purging either package now treats `settings.json` exactly as it treats `access.json`.

### Documentation

* The nginx blocks in README now clear **every** identity header, `X-Auth-Uuid` included.
  They stated the rule and shipped the counter-example twice.
* README no longer claims `scripts/deploy.sh` moves a shadowing systemd unit aside. It does
  not, deliberately, and says so.
* AGENTS.md said "ten" settings in one section and "six" in another, and the code comment
  agreed with the wrong one.

## 1.0.0 (2026-08-17)

The first release. The version sequence before it (2.6.0, 3.0.0, 3.1.0) belongs to a
history this release deliberately does not remember: every tag and release was deleted, the
migration tooling was removed, and the two formats were reset to `bb1` and `"version": 1`.

The tag `v1.0.0` points at `7d7cc8c`, six commits after the release commit, and that is
deliberate: `7d7cc8c` is the fix for a build whose JWT verifier was a `panic!`
(`jsonwebtoken`'s crypto is a feature, and selecting none of them compiles). The commits
between the two are not a release anybody should install; `f3a4e48`, `7f3d4a3` and `7650b92`
in particular carry that defect.
