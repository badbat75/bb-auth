# Changelog

What changed between releases, and above all what an **upgrade does to people who are
signed in**. That last question is why this file exists at all: the session cookie is a
versioned wire format and exactly one version is ever accepted, so a change to it logs
every user out, and the invariant that says so nominates release notes as the place it must
be announced. There were none.

Versions are the crate's (`Cargo.toml`); packages add a Debian revision
(`1.1.0-1`), which is bumped by `--revision` when the same code is repackaged.

## Standing facts

* **Cookie format**: `bb1`. Unchanged since 1.0.0. While this line does not change, an
  upgrade logs nobody out.
* **Access file format**: `"version": 1`. A file declaring anything else is refused, with
  an explanation, rather than compiled into a different set of grants.
* **Settings file format**: `"version": 1`.
* **Rollback**: safe by construction while the cookie format is unchanged, because sessions
  are stateless and no state is packaged. See "Rollback" in [README.md](README.md).

## Unreleased

The findings of an architecture and process review, addressed. Nothing here changes the
cookie format, the access-file format or the settings-file format, so no upgrade in this
section logs anybody out.

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
