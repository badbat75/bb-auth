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
set -euo pipefail

# Make cargo/rustup available even when invoked non-login (e.g. `bash build.sh`).
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

TARGET="${BB_AUTH_TARGET:-aarch64-unknown-linux-gnu}"
OBJDUMP="${BB_AUTH_OBJDUMP:-aarch64-linux-gnu-objdump}"
CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BB_AUTH_BUILD_DIR:-$HOME/.cache/bb-auth-build}"

echo "[build] crate  : $CRATE_DIR"
echo "[build] target : $TARGET"
echo "[build] work   : $BUILD_DIR"

mkdir -p "$BUILD_DIR/src"
cp "$CRATE_DIR/Cargo.toml" "$BUILD_DIR/Cargo.toml"
cp -r "$CRATE_DIR/src/." "$BUILD_DIR/src/"
[ -f "$CRATE_DIR/Cargo.lock" ] && cp "$CRATE_DIR/Cargo.lock" "$BUILD_DIR/Cargo.lock" || true

rustup target add "$TARGET" >/dev/null 2>&1 || true

( cd "$BUILD_DIR" && cargo build --release --target "$TARGET" )

mkdir -p "$CRATE_DIR/dist"
# Three binaries out of one crate: the gate, the access-file admin CLI, and the admin GUI.
# The two admin tools are built alongside the gate because the file they edit lives on the
# host. They are still OPTIONAL to a deploy, but that is now expressed by each being its
# own package (`deploy.ps1 -Packages`), not by what happens to be sitting in dist/.
for b in bb-auth bb-auth-adm bb-auth-web; do
  cp "$BUILD_DIR/target/$TARGET/release/$b" "$CRATE_DIR/dist/$b"
done
[ -f "$BUILD_DIR/Cargo.lock" ] && cp "$BUILD_DIR/Cargo.lock" "$CRATE_DIR/Cargo.lock" || true

echo "[build] OK -> $CRATE_DIR/dist/{bb-auth,bb-auth-adm,bb-auth-web}"
file "$CRATE_DIR/dist/bb-auth" || true
printf '[build] max GLIBC required: '
"$OBJDUMP" -T "$CRATE_DIR/dist/bb-auth" 2>/dev/null \
  | grep -oE 'GLIBC_[0-9.]+' | sort -V | tail -1 || echo "n/a"
