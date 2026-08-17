# bb-auth scripts

Five scripts, three machines. The split is not cosmetic: each one runs somewhere the
others cannot, and the boundaries are where the interesting failures live.

| Script | Runs on | Normally called by | Does |
| --- | --- | --- | --- |
| `build.sh` | Linux or WSL | `package.sh` | cross-compiles the three binaries into `dist/` |
| `package.sh` | Linux or WSL | `deploy.ps1`, or you | builds the three `.deb` (cargo-deb) |
| `deploy.ps1` | Windows, **pwsh 7** | you | orchestrates a deploy over SSH |
| `deploy.sh` | the target host, as root | `deploy.ps1`, or you | `dpkg -i` and the three things a package may not do |
| `verify.sh` | the target host, as root | `deploy.sh`, or you | read-only post-deploy checks |

**The install itself is not here.** It lives in the packages: `[package.metadata.deb]` in
[`../Cargo.toml`](../Cargo.toml) and the maintainer scripts under
[`../deploy/debian/`](../deploy/debian). The service users, the units, the env file, the
HMAC key, the empty access file and the order they must happen in are all `postinst`'s
business. Everything in this directory is scaffolding around that.

## The normal path

```text
./scripts/deploy.ps1 user@host
├── package.sh --arch arm64                (in WSL)
│   └── build.sh                           (cross-compile -> dist/)
├── probe the host BEFORE copying          (sudo, architecture, package manager)
├── scp *.deb + deploy.sh + verify.sh
└── deploy.sh, as root on the host
    ├── dpkg -i, one transaction
    ├── move aside units from a pre-package install
    ├── install access.json                 (only with -AccessFile)
    └── verify.sh
```

## `build.sh`

```bash
bash scripts/build.sh                 # BB_AUTH_TARGET=aarch64-unknown-linux-gnu by default
```

Owns the cross-compile and nothing else. It expects the toolchain (linker, sysroot,
`CC`/`AR`) in `~/.cargo/config.toml`, builds in `$HOME/.cache/bb-auth-build` rather than in
the checkout (on WSL that is a DrvFs mount: slow, and its file modes are not the ones a
build wants), harvests the stripped binaries into `dist/`, and prints the highest GLIBC
symbol version the gate references. `BB_AUTH_TARGET` and `BB_AUTH_OBJDUMP` override the
target and the objdump used for that report.

You rarely run this directly; `package.sh` does. Run it when you want the raw binaries and
no `.deb`, or just that GLIBC number.

## `package.sh`

```bash
bash scripts/package.sh                    # arm64, the Pi
bash scripts/package.sh --arch amd64
bash scripts/package.sh --no-build         # package the binaries already in dist/
bash scripts/package.sh --only gate,web    # skip a package
bash scripts/package.sh --revision 2       # 3.0.0-2 instead of 3.0.0-1
```

Produces `dist/{bb-auth,bb-auth-adm,bb-auth-web}_<version>-<rev>_<arch>.deb`. Started from
a Windows shell it re-execs itself inside WSL on the same checkout, so the same command
works from either side. It installs `cargo-deb` if it is missing.

What it adds on top of a bare `cargo deb`:

- It builds **through `build.sh`**, so the bytes in the package are the bytes
  `deploy.ps1` would otherwise ship, and `dist/` stays current for everything else.
  cargo-deb then runs with `--no-build --no-strip`.
- It stages the crate under `$HOME`, never in the repo, and normalizes the maintainer
  scripts to LF there. A Windows checkout with `core.autocrlf=true` delivers CRLF, and
  `#!/bin/sh\r` is a shebang no kernel will honour: the package would install and every
  maintainer script would fail.
- It **refuses a binary that is not for the requested architecture**, reading `e_machine`
  out of the ELF header. That is the one mistake `--no-build` makes easy.
- It re-checks the `libc6 (>= X)` floor declared in `Cargo.toml` against the symbols the
  binary actually references. That dependency is stated by hand, because `dpkg-shlibdeps`
  cannot inspect a cross-compiled binary, so a toolchain bump would otherwise raise it in
  silence and apt on the target would refuse a package that used to install.
- It rewrites the `bb-auth (= <version>)` pin the two admin packages carry, from the
  version and revision actually in play, so `--revision 2` cannot produce a `bb-auth-web`
  that depends on a `bb-auth` nothing built.

## `deploy.ps1`

```powershell
./scripts/deploy.ps1 user@host                                   # build + deploy all three
./scripts/deploy.ps1 user@host -Packages bb-auth                 # gate only
./scripts/deploy.ps1 user@host -AccessFile .\deploy\access.json     # also replace the access file
./scripts/deploy.ps1 user@host -NoBuild                          # repackage the current dist/
```

**pwsh 7, not Windows PowerShell 5.1.** Other switches: `-Arch` (arm64, amd64, armhf),
`-KeepLegacyUnits`, `-WslDistro`.

It probes the target **before copying anything**, because neither of the two things it
asks can be discovered halfway through a transfer:

| Target | Result |
| --- | --- |
| `.deb` host, matching architecture | proceeds |
| RPM host (Fedora, RHEL, Rocky, openSUSE) | refused: RPM packaging is **not supported yet** |
| neither `dpkg` nor `rpm` | refused, naming the distribution it found |
| architecture mismatch | refused, suggesting the right `-Arch` |

Then it ships the `.deb` files together with `deploy.sh` and `verify.sh` and runs the
former as root. The host-side logic is staged as files on purpose: a script quoted through
PowerShell into `ssh` into a remote shell is exactly where a live auth gate does not want
its logic to live.

## `deploy.sh`

```bash
sudo bash deploy.sh <staging_dir>     # DEST=/opt/bb-auth, BB_AUTH_KEEP_LEGACY_UNITS=1
```

Installs nothing itself. It does the four things a package cannot:

1. **`dpkg -i`, in one transaction**, so the strict `bb-auth (= <version>)` dependency of
   the two admin packages is satisfied by the gate in the same run. Not `apt install`:
   apt declines to reinstall a version equal to the one already there, so a rebuilt
   `3.0.0-1` would silently not deploy.
2. **Moves aside units left in `/etc/systemd/system`** by an install from before the
   packages. That is the admin's directory and it *overrides* `/usr/lib/systemd/system`,
   where a package must put its units, so left in place they win forever. Moved, not
   deleted, and the enablement symlinks are `reenable`d onto the packaged files.
3. **Installs a staged `access.json`**, after the gate's own parser has vouched for it,
   with the owner and mode the live file already had. The packages create that file once,
   empty, and never touch it again, which is what makes a redeploy safe, so replacing it
   is necessarily a separate and explicit act.
4. Runs `verify.sh`.

A **first** install ends without starting the gate: its env file is still a template, and
the script says which three steps are left instead of failing the verification.

## `verify.sh`

```bash
ssh user@host 'sudo bash -s' < ./scripts/verify.sh
```

Read-only, standalone, exits non-zero if any check fails. Packages configured, no unit
shadowed, gate active, `GET /auth/healthz == ok`, `GET /auth/validate` without a cookie
`== 401`, HMAC key present, the access file parsing under the gate's own parser, a clean
`listening on` in the journal since the unit came up, and with the GUI installed its own
liveness plus the ownership its write path needs.

It changes nothing, which is what makes it usable as a health check on a host nobody is
deploying to. Keep it that way.

## What must not break

- **No state in the packages.** `etc/*.env` (the HMAC key: every live session cookie
  depends on it), `var/lib/access.json` and `var/lib/settings.json` are created by
  `postinst` only when absent and
  are in no package, so `dpkg` cannot clobber them. They are deliberately not
  `conf-files`: a prompt that one `--force-confnew` would lose is not the same guarantee.
- **One build path.** `package.sh` goes through `build.sh` so the `.deb` contains exactly
  the bytes in `dist/`, which is what makes those bytes independently checkable.
- **Validate before restart.** The `postinst` preflight, `--check-settings` on the settings
  file it creates, and `--check-access` on any staged
  access file, run before anything is restarted. A fatal startup under
  `Restart=on-failure` is a boot loop.
- **Host-side logic stays in these files**, not in strings assembled by the orchestrator.

The rules behind all of this are in [`../CLAUDE.md`](../CLAUDE.md); the deploy narrative,
including the layout on the target, is in [`../README.md`](../README.md) under "Deploy".
