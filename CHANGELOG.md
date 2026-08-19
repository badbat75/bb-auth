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

## 1.99.1 (2026-08-19)

**A release candidate for 2.0.0**, and the version number says so: the configuration surface
moved far enough in one window that calling it 1.2.0 would have undersold what an upgrade has
to do. The findings of an architecture and process review, addressed; the gate's whole Cognito
wiring and the estate it serves moved out of the environment and into the settings file; and a
confirmation step in front of the five settings that can stop people getting in.

**Nothing here changes the cookie format or the access-file format, so no upgrade in this
release logs anybody out.** The settings file goes from version 1 to version 3, which needs an
edit before the binaries land: see "Upgrading" below.

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

### Availability

* A `recv()` error is now fatal. `tiny_http` reports at most one accept error per listener
  and then stops accepting, so the previous `continue` left a live process with no listener:
  no exit code, no restart, and every gated request failing.
* An unknown `kid` no longer serialises every worker behind one JWKS fetch. The refresh
  lock is taken with `try_lock`, the fetch timeout is 3s, and a failure is cached for 10s.
* The gate warns at startup when an application's `login_url` is outside
  `BB_AUTH_AUTHORIZED_HOSTS`, and when it is listening on a non-loopback address.
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

## 1.1.0 (2026-08-18)

The gate serves its own sign-in page. `/auth/login` and `/auth/callback` are the gate's
now, complete on their own: no font, no CDN, no second host, because the situation those
pages exist for is somebody not being able to get in. `BB_AUTH_LOGIN_URL` may still point
at a page of your own.

The look is shared: the palette (`theme.css`) and the components built out of it
(`base.css`) live in the library and both programs emit the same bytes, so one
`ui.stylesheet_url` restyles the sign-in page and the admin interface together.

The admin GUI's access check moved out of a tab of its own and into the application page
and the person page, which is where the question is actually asked. There is no `/can`
route.

Logging out is one endpoint for every vhost, and a link that says nothing falls back to
`Referer`.

**Upgrade**: cookie format unchanged, so nobody is logged out. nginx must leave
`/auth/login` and `/auth/callback` **ungated**.

## 1.0.0 (2026-08-17)

The first release. The version sequence before it (2.6.0, 3.0.0, 3.1.0) belongs to a
history this release deliberately does not remember: every tag and release was deleted, the
migration tooling was removed, and the two formats were reset to `bb1` and `"version": 1`.

The tag `v1.0.0` points at `7d7cc8c`, six commits after the release commit, and that is
deliberate: `7d7cc8c` is the fix for a build whose JWT verifier was a `panic!`
(`jsonwebtoken`'s crypto is a feature, and selecting none of them compiles). The commits
between the two are not a release anybody should install; `f3a4e48`, `7f3d4a3` and `7650b92`
in particular carry that defect.
