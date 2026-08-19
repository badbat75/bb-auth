#!/usr/bin/env bash
# Cross-compile bb-auth to a Linux target. Run on Linux (or WSL).
#
#   bash scripts/build.sh
#
# Normally you do not run this: scripts/package.sh runs it, then packages exactly the
# binaries it left in dist/. Run it directly when you want the raw binaries and no .deb,
# or just the GLIBC report it prints at the end.
#
# Target and the objdump used for the GLIBC report are overridable:
#   BB_AUTH_TARGET=aarch64-unknown-linux-gnu  (default)
#   BB_AUTH_OBJDUMP=aarch64-linux-gnu-objdump (default)
#
# The cross toolchain (linker, --sysroot for both the link and C-compile steps,
# CC/CXX/AR) is expected to be configured in ~/.cargo/config.toml, so this script
# just builds and harvests the stripped binary into <crate>/dist/. It builds in a
# local cache dir (not a slow/synced filesystem) for speed.
#
# WHAT THE BUILD IS ALLOWED TO CHANGE: nothing in the repository. It used to copy the
# resolved Cargo.lock back over the tracked one, so a release build could quietly bump
# every semver-compatible dependency and leave that resolution committed as a side effect
# of building. The dependency invariant (pure Rust, no OpenSSL, no aws-lc) is checked
# against the lockfile, so a bump has to be a deliberate `cargo update` commit, not
# something a build does on the way past.
set -euo pipefail

# Make cargo/rustup available even when invoked non-login (e.g. `bash build.sh`).
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

TARGET="${BB_AUTH_TARGET:-aarch64-unknown-linux-gnu}"
OBJDUMP="${BB_AUTH_OBJDUMP:-aarch64-linux-gnu-objdump}"
CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BB_AUTH_BUILD_DIR:-$HOME/.cache/bb-auth-build}"

# What these bytes were built from, read HERE because the compile happens in a copy of the
# crate with no .git of its own. `bb_auth_core::BUILD` reads this variable at compile time
# and `--version` prints it; with git unavailable it degrades to "unknown" rather than
# failing the build.
# The COMMIT, and deliberately not `git describe`: describe anchors on the last TAG, and a
# release candidate is never tagged, so it would open with the version of a tag several
# releases back. The version half of the identity is cargo's own, and `version_id()` joins
# the two, so no shell script here can be wrong about a number it does not read.
if [ -z "${BB_AUTH_BUILD:-}" ]; then
  BB_AUTH_BUILD="$(cd "$CRATE_DIR" && git rev-parse --short=7 HEAD 2>/dev/null)" || BB_AUTH_BUILD=""
  if [ -n "$BB_AUTH_BUILD" ]; then
    (cd "$CRATE_DIR" && git diff-index --quiet HEAD -- 2>/dev/null) ||
      BB_AUTH_BUILD="$BB_AUTH_BUILD-dirty"
    BB_AUTH_BUILD="g$BB_AUTH_BUILD"
  else
    BB_AUTH_BUILD="unknown"
  fi
fi
export BB_AUTH_BUILD

echo "[build] crate  : $CRATE_DIR"
echo "[build] target : $TARGET"
echo "[build] work   : $BUILD_DIR"
echo "[build] build  : $BB_AUTH_BUILD"

# The source tree is REPLACED, not merged into. `cargo` discovers binaries from src/bin/,
# so a file deleted in the repository would go on being compiled here forever, and the
# packages would ship a fourth binary nobody could find in the source. target/ is kept:
# that is the whole reason this directory exists.
rm -rf "$BUILD_DIR/src"
mkdir -p "$BUILD_DIR/src"
cp "$CRATE_DIR/Cargo.toml" "$BUILD_DIR/Cargo.toml"
cp -r "$CRATE_DIR/src/." "$BUILD_DIR/src/"
[ -f "$CRATE_DIR/Cargo.lock" ] && cp "$CRATE_DIR/Cargo.lock" "$BUILD_DIR/Cargo.lock" || true

rustup target add "$TARGET" >/dev/null 2>&1 || true

# --locked: build the dependency versions that were reviewed, and fail rather than resolve
# new ones. A release must not be the first place a bumped dependency is compiled.
( cd "$BUILD_DIR" && cargo build --locked --release --target "$TARGET" )

mkdir -p "$CRATE_DIR/dist"
# Three binaries out of one crate: the gate, the access-file admin CLI, and the admin GUI.
# The two admin tools are built alongside the gate because the file they edit lives on the
# host. They are OPTIONAL to a deploy, and that is expressed by each being its own
# package (`deploy.ps1 -Packages`), not by what happens to be sitting in dist/.
for b in bb-auth bb-auth-adm bb-auth-web; do
  cp "$BUILD_DIR/target/$TARGET/release/$b" "$CRATE_DIR/dist/$b"
done

echo "[build] OK -> $CRATE_DIR/dist/{bb-auth,bb-auth-adm,bb-auth-web}"
file "$CRATE_DIR/dist/bb-auth" || true
printf '[build] max GLIBC required: '
"$OBJDUMP" -T "$CRATE_DIR/dist/bb-auth" 2>/dev/null \
  | grep -oE 'GLIBC_[0-9.]+' | sort -V | tail -1 || echo "n/a"
