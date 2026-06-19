#!/usr/bin/env bash
# Cross-compile bb-auth to a Linux target. Run on Linux (or WSL).
#
#   bash scripts/build.sh
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

BIN="$BUILD_DIR/target/$TARGET/release/bb-auth"
mkdir -p "$CRATE_DIR/dist"
cp "$BIN" "$CRATE_DIR/dist/bb-auth"
[ -f "$BUILD_DIR/Cargo.lock" ] && cp "$BUILD_DIR/Cargo.lock" "$CRATE_DIR/Cargo.lock" || true

echo "[build] OK -> $CRATE_DIR/dist/bb-auth"
file "$CRATE_DIR/dist/bb-auth" || true
printf '[build] max GLIBC required: '
"$OBJDUMP" -T "$CRATE_DIR/dist/bb-auth" 2>/dev/null \
  | grep -oE 'GLIBC_[0-9.]+' | sort -V | tail -1 || echo "n/a"
