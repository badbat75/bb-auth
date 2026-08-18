#!/usr/bin/env bash
# Build the bb-auth .deb packages for a target architecture, with cargo-deb.
#
# Runs natively on Linux or WSL. Started from a Windows shell (Git Bash, MSYS) it
# re-execs itself inside WSL on the same checkout, so `bash scripts/package.sh` does
# the right thing from either side.
#
#   bash scripts/package.sh                    # arm64, the Pi: build + package
#   bash scripts/package.sh --arch amd64
#   bash scripts/package.sh --no-build         # package the binaries already in dist/
#   bash scripts/package.sh --only gate,web    # skip a package
#   bash scripts/package.sh --revision 2       # 1.1.0-2 instead of 1.1.0-1
#   bash scripts/package.sh --skip-tests       # repackage without re-running the suite
#   bash scripts/package.sh --allow-dirty      # package an uncommitted working tree
#
# Output, in dist/:
#   bb-auth_<ver>-<rev>_<arch>.deb       the gate, its unit, the env template
#   bb-auth-adm_<ver>-<rev>_<arch>.deb   the admin CLI            (Depends: bb-auth)
#   bb-auth-web_<ver>-<rev>_<arch>.deb   the admin GUI, its units (Depends: bb-auth)
#
# The three packages, what they carry, what they must never carry, and why the systemd
# handling is hand-written rather than generated: [package.metadata.deb] in Cargo.toml,
# which is where cargo-deb reads all of it from. The maintainer scripts are real files
# under deploy/debian/, one directory per package.
#
# WHAT THIS SCRIPT ADDS ON TOP OF `cargo deb`:
#
#   * It RUNS THE TESTS FIRST, on the host, natively. The suite is seconds long and it is
#     the only thing standing between a release and the crypto-provider failure that took
#     the gate down once already: `rsa_signature_verification_works` is what catches a
#     build whose JWT verifier is a `panic!`, `cargo tree` cannot see it, and until now the
#     whole defence was a human remembering a table in AGENTS.md. --skip-tests is for
#     repackaging bytes that were already tested, and says so out loud.
#   * It refuses to package an UNCOMMITTED tree unless told to. A .deb version says
#     1.1.0-1 whether it was built from a tag, a dirty checkout or a hand-patched
#     experiment; --allow-dirty makes that a decision, and either way the build string
#     baked into every binary (`bb-auth --version`) carries the commit and a -dirty
#     marker.
#
#   * It builds through scripts/build.sh, so the bytes in the package are the same
#     bytes scripts/deploy.ps1 would ship, from the same cross toolchain, and dist/ is
#     left current for both paths. cargo-deb then runs with --no-build.
#   * It stages the crate under $HOME, never in the repo. On WSL the checkout is a
#     DrvFs mount: builds there are slow, and the maintainer scripts can arrive with
#     CRLF line endings from a Windows checkout, which makes `#!/bin/sh` a shebang no
#     kernel will honour. The staged copy is normalized to LF and made executable.
#   * It refuses to package a binary that is not for the requested architecture, which
#     is the one mistake --no-build makes easy to make.
#   * It re-checks the declared `libc6 (>= X)` against the symbols the binary actually
#     references, because that dependency is stated by hand (dpkg-shlibdeps cannot
#     inspect a cross-compiled binary) and a toolchain bump would otherwise raise it
#     silently: apt on the target would refuse a package that used to install.
#   * It rewrites the `bb-auth (= <version>)` dependency of the two admin packages from
#     the crate version and the revision in play, so the pin cannot drift.
#
# Target and the objdump used for the two checks are overridable, as in build.sh:
#   BB_AUTH_TARGET   (derived from --arch when unset)
#   BB_AUTH_OBJDUMP  (derived from the target when unset)
#   BB_AUTH_PKG_DIR  (staging dir, default ~/.cache/bb-auth-pkg)
set -euo pipefail

# --- 0. Windows shell: hand over to WSL --------------------------------------
# Everything below wants a Linux userland (the cross toolchain, POSIX modes, cargo-deb
# invoking cargo). Rather than fail with something cryptic, re-run the same file there
# on the same checkout. `wslpath -a` maps C:/... to /mnt/c/....
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    command -v wsl.exe >/dev/null 2>&1 || {
      echo "[pkg] FATAL: run this under Linux or WSL (wsl.exe not found)." >&2; exit 1; }
    WIN_CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd; })"
    QARGS=""
    for a in "$@"; do QARGS="$QARGS $(printf '%q' "$a")"; done
    echo "[pkg] Windows shell detected, re-running inside WSL ..."
    exec wsl.exe -e bash -lc \
      "cd \"\$(wslpath -a '$WIN_CRATE_DIR')\" && exec bash scripts/package.sh$QARGS"
    ;;
esac

# Make cargo/rustup available even when invoked non-login (`wsl.exe -e bash script.sh`).
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="${BB_AUTH_PKG_DIR:-$HOME/.cache/bb-auth-pkg}"
OUT_DIR="$CRATE_DIR/dist"
REVISION=1
DO_BUILD=1
DO_TEST=1
ALLOW_DIRTY=0
ONLY=""
ARCH=""
TARGET="${BB_AUTH_TARGET:-}"

# --- 1. arguments ------------------------------------------------------------
usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --arch)     ARCH="${2:?--arch needs a value}"; shift 2 ;;
    --target)   TARGET="${2:?--target needs a value}"; shift 2 ;;
    --revision) REVISION="${2:?--revision needs a value}"; shift 2 ;;
    --only)     ONLY="${2:?--only needs a value}"; shift 2 ;;
    --output)   OUT_DIR="${2:?--output needs a value}"; shift 2 ;;
    --no-build) DO_BUILD=0; shift ;;
    --skip-tests) DO_TEST=0; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    -h|--help)  usage 0 ;;
    *)          echo "[pkg] FATAL: unknown argument '$1'" >&2; usage 1 ;;
  esac
done

# The two names for one machine. Debian names the architecture, Rust names the triple,
# and either one may be given: whichever is missing is derived from the other. A triple
# that is not in the table is a fatal unknown rather than a guess, because the wrong
# `Architecture:` field produces a package apt installs and the kernel cannot exec.
case "${ARCH}|${TARGET}" in
  \|)                   ARCH=arm64 ;;                       # the default: the Pi
esac
if [ -z "$TARGET" ]; then
  case "$ARCH" in
    arm64) TARGET=aarch64-unknown-linux-gnu ;;
    amd64) TARGET=x86_64-unknown-linux-gnu ;;
    armhf) TARGET=armv7-unknown-linux-gnueabihf ;;
    *) echo "[pkg] FATAL: unknown --arch '$ARCH' (arm64, amd64, armhf)" >&2; exit 1 ;;
  esac
fi
if [ -z "$ARCH" ]; then
  case "$TARGET" in
    aarch64-*) ARCH=arm64 ;;
    x86_64-*)  ARCH=amd64 ;;
    armv7-*)   ARCH=armhf ;;
    *) echo "[pkg] FATAL: cannot derive a Debian architecture from '$TARGET'." >&2
       echo "[pkg]        Pass --arch as well." >&2; exit 1 ;;
  esac
fi

# ELF e_machine, one byte at offset 18 (little-endian). Cheaper than `file`, which the
# Fedora WSL image does not ship, and it answers the only question that matters here.
case "$ARCH" in
  arm64) WANT_MACHINE=183 ;;
  amd64) WANT_MACHINE=62 ;;
  armhf) WANT_MACHINE=40 ;;
esac

OBJDUMP="${BB_AUTH_OBJDUMP:-}"
if [ -z "$OBJDUMP" ]; then
  case "$ARCH" in
    arm64) OBJDUMP=aarch64-linux-gnu-objdump ;;
    amd64) OBJDUMP=objdump ;;
    armhf) OBJDUMP=arm-linux-gnueabihf-objdump ;;
  esac
fi

VERSION="$(grep -m1 -E '^version[[:space:]]*=' "$CRATE_DIR/Cargo.toml" | cut -d'"' -f2)"
[ -n "$VERSION" ] || { echo "[pkg] FATAL: no version in Cargo.toml" >&2; exit 1; }
DEB_VERSION="$VERSION-$REVISION"

echo "[pkg] crate    : $CRATE_DIR"
echo "[pkg] version  : $DEB_VERSION"
echo "[pkg] target   : $TARGET  (Architecture: $ARCH)"
echo "[pkg] staging  : $PKG_DIR"
echo "[pkg] output   : $OUT_DIR"

# --- 2. provenance -----------------------------------------------------------
# What these bytes are, in a form that survives into the binary (`bb-auth --version`) and
# into this log. A .deb version cannot answer it: 1.1.0-1 is what a tagged release, a dirty
# checkout and a hand-patched experiment all report.
BB_AUTH_BUILD="$(cd "$CRATE_DIR" && git describe --always --dirty --tags 2>/dev/null || echo unknown)"
export BB_AUTH_BUILD
echo "[pkg] build    : $BB_AUTH_BUILD"
case "$BB_AUTH_BUILD" in
  *-dirty)
    if [ "$ALLOW_DIRTY" = 1 ]; then
      echo "[pkg] WARNING: packaging an uncommitted working tree (--allow-dirty)."
    else
      echo "[pkg] FATAL: the working tree has uncommitted changes, so this package could" >&2
      echo "[pkg]        not be rebuilt from any commit and nothing on the host would say" >&2
      echo "[pkg]        so. Commit them, or pass --allow-dirty to mean it." >&2
      exit 1
    fi
    ;;
esac

# --- 2b. the tests -----------------------------------------------------------
# Host-native and target-independent: what they cover is the feature selection and the
# logic, neither of which changes with the architecture. See the header for why this is
# not optional by default.
if [ "$DO_TEST" = 1 ]; then
  echo "[pkg] tests    : cargo test --locked (host)"
  ( cd "$CRATE_DIR" && cargo test --locked --quiet ) || {
    echo "[pkg] FATAL: the test suite failed; nothing was packaged." >&2
    exit 1; }
else
  echo "[pkg] WARNING: --skip-tests: packaging without running the suite."
fi

# --- 3. cargo-deb ------------------------------------------------------------
# Pinned, because an unpinned `cargo install` is a different packaging tool on every
# machine and on every day: the one thing a release pipeline must not have.
CARGO_DEB_VERSION="${BB_AUTH_CARGO_DEB_VERSION:-3.1.0}"
if ! cargo deb --version >/dev/null 2>&1; then
  echo "[pkg] cargo-deb is not installed; installing $CARGO_DEB_VERSION."
  cargo install cargo-deb --version "$CARGO_DEB_VERSION" --locked
fi

# --- 4. the binaries ---------------------------------------------------------
# One build path for the whole repo: build.sh owns the cross toolchain and harvests
# into dist/, and this packages exactly what it left there. --no-build skips it, which
# is what makes re-packaging an existing dist/ instant.
if [ "$DO_BUILD" = 1 ]; then
  BB_AUTH_TARGET="$TARGET" BB_AUTH_OBJDUMP="$OBJDUMP" bash "$CRATE_DIR/scripts/build.sh"
else
  echo "[pkg] --no-build: packaging the binaries already in dist/"
fi

for b in bb-auth bb-auth-adm bb-auth-web; do
  [ -f "$OUT_DIR/$b" ] || {
    echo "[pkg] FATAL: $OUT_DIR/$b is missing. Drop --no-build, or run scripts/build.sh." >&2
    exit 1; }
  got="$(od -An -tu1 -j18 -N1 "$OUT_DIR/$b" | tr -d ' \n')"
  [ "$got" = "$WANT_MACHINE" ] || {
    echo "[pkg] FATAL: $OUT_DIR/$b is not a $ARCH binary (ELF machine $got, expected $WANT_MACHINE)." >&2
    echo "[pkg]        dist/ holds a build for another target. Re-run without --no-build." >&2
    exit 1; }
done
echo "[pkg] binaries : dist/{bb-auth,bb-auth-adm,bb-auth-web} are $ARCH"

# The libc6 floor is declared by hand in Cargo.toml because dpkg-shlibdeps cannot read
# a cross-compiled binary. That makes it something to verify, not something to trust:
# a toolchain that starts referencing a newer symbol would otherwise ship a package apt
# refuses to install on a host where the previous one installed fine.
DECLARED_GLIBC="$(grep -m1 -oE 'libc6 \(>= [0-9.]+\)' "$CRATE_DIR/Cargo.toml" \
  | sed -E 's/.*>=[[:space:]]*([0-9.]+).*/\1/' || true)"
if command -v "$OBJDUMP" >/dev/null 2>&1; then
  ACTUAL_GLIBC="$("$OBJDUMP" -T "$OUT_DIR/bb-auth" 2>/dev/null \
    | grep -oE 'GLIBC_[0-9.]+' | sed 's/GLIBC_//' | sort -V | tail -1 || true)"
  if [ -n "$ACTUAL_GLIBC" ] && [ -n "$DECLARED_GLIBC" ]; then
    highest="$(printf '%s\n%s\n' "$DECLARED_GLIBC" "$ACTUAL_GLIBC" | sort -V | tail -1)"
    if [ "$highest" != "$DECLARED_GLIBC" ]; then
      echo "[pkg] FATAL: the binary needs GLIBC $ACTUAL_GLIBC but Cargo.toml declares" >&2
      echo "[pkg]        libc6 (>= $DECLARED_GLIBC). Raise it there (both variants) and" >&2
      echo "[pkg]        check the target host still satisfies it: ldd --version." >&2
      exit 1
    fi
    echo "[pkg] glibc    : needs $ACTUAL_GLIBC, declared libc6 (>= $DECLARED_GLIBC)"
  fi
else
  echo "[pkg] WARNING: $OBJDUMP not found, cannot verify libc6 (>= $DECLARED_GLIBC)." >&2
fi

# --- 5. staging --------------------------------------------------------------
# Never in the repo. On WSL that is a DrvFs mount, where cargo is slow and file modes
# and line endings are not the ones a package needs.
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/src" "$PKG_DIR/deploy" "$PKG_DIR/target/$TARGET/release"
cp "$CRATE_DIR/Cargo.toml" "$PKG_DIR/Cargo.toml"
[ -f "$CRATE_DIR/Cargo.lock" ] && cp "$CRATE_DIR/Cargo.lock" "$PKG_DIR/Cargo.lock"
cp -r "$CRATE_DIR/src/." "$PKG_DIR/src/"
cp -r "$CRATE_DIR/deploy/." "$PKG_DIR/deploy/"

# The deploy directory holds the live config next to the templates, and only the
# templates are assets. Whitelist rather than blacklist: everything that is not an
# *.example*, a unit, or the debian/ tree is deleted from the copy. The previous version
# named the three files it knew about and missed deploy/settings.json, which .gitignore
# itself anticipates, and the next file somebody drops in there would have been missed
# too. The HMAC key and the real roster must not be able to reach a .deb by way of an edit
# somewhere else, and that has to hold for files nobody has thought of yet.
find "$PKG_DIR/deploy" -maxdepth 1 -type f \
  ! -name '*.example*' ! -name '*.service' ! -name '*.path' -print -delete

# A Windows checkout with core.autocrlf=true delivers CRLF, and `#!/bin/sh\r` is a
# shebang the kernel will not honour: the package installs and every maintainer script
# fails. Normalize, then set the mode cargo-deb would set anyway, so the staged tree is
# also directly runnable for debugging.
for f in "$PKG_DIR"/deploy/debian/*/*; do
  [ -f "$f" ] || continue
  sed -i 's/\r$//' "$f"
  chmod 0755 "$f"
done

# The pin the two admin packages carry on the gate. Written out here, from the version
# and revision actually in play, so `--revision 2` cannot produce a bb-auth-web that
# depends on a bb-auth nothing built.
sed -i -E "s/bb-auth \(= [^)]*\)/bb-auth (= $DEB_VERSION)/g" "$PKG_DIR/Cargo.toml"

for b in bb-auth bb-auth-adm bb-auth-web; do
  cp "$OUT_DIR/$b" "$PKG_DIR/target/$TARGET/release/$b"
done

mkdir -p "$OUT_DIR"

# --- 5. the packages ---------------------------------------------------------
# --no-strip because the release profile already stripped these, and re-stripping would
# need a cross strip that may not be installed. --output names the file, so the name
# never depends on how cargo-deb derives one.
build_variant() { # $1 = variant name, $2 = package name
  local variant="$1" name="$2" deb
  deb="$OUT_DIR/${name}_${DEB_VERSION}_${ARCH}.deb"
  case ",$ONLY," in
    ,,) ;;
    *",$variant,"*) ;;
    *) echo "[pkg] skip     : $name (--only $ONLY)"; return 0 ;;
  esac
  echo "[pkg] building : $name"
  ( cd "$PKG_DIR" && cargo deb \
      --variant "$variant" \
      --target "$TARGET" \
      --deb-revision "$REVISION" \
      --no-build --no-strip \
      --output "$deb" )
  BUILT="$BUILT $deb"
}

BUILT=""
build_variant gate bb-auth
build_variant adm  bb-auth-adm
build_variant web  bb-auth-web

# --- 6. what came out --------------------------------------------------------
echo "[pkg] --- result ---"
for deb in $BUILT; do
  echo "  $(stat -c '%9s bytes  %n' "$deb")"
  if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb -f "$deb" Package Version Architecture Depends Installed-Size | sed 's/^/    /'
    dpkg-deb -c "$deb" | sed 's/^/    /'
  else
    # No dpkg on this host (a Fedora WSL, say). The ar members still prove the shape,
    # and the contents were listed by cargo-deb above.
    ar t "$deb" | sed 's/^/    member: /'
  fi
done

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "[pkg] note: dpkg-deb is not installed here, so the listing above is shallow."
  echo "[pkg]       Full check on any Debian host, or in a container:"
  echo "[pkg]         podman run --rm -v \"$OUT_DIR:/pkg:z\" debian:bookworm \\"
  echo "[pkg]           bash -c 'apt-get install -y /pkg/*.deb && systemctl cat bb-auth'"
fi

cat <<EOF
[pkg] SUCCESS
[pkg] Install on the target (the gate first, the two admin tools are optional):
[pkg]   scp $OUT_DIR/*_${DEB_VERSION}_${ARCH}.deb user@host:/tmp/
[pkg]   ssh user@host 'sudo apt-get install -y /tmp/bb-auth_${DEB_VERSION}_${ARCH}.deb'
[pkg] A first install does not start the gate: it writes an HMAC key and an empty
[pkg] access file, and says what to fill in. A reinstall preserves both and restarts.
EOF
