#!/usr/bin/env bash
# Install the bb-auth .deb packages on the target host. Runs ON the host, as root (via
# sudo). Idempotent, self-verifying.
#
#   sudo bash deploy.sh <staging_dir>
#
# <staging_dir> is what scripts/deploy.ps1 leaves behind: one or more .deb files,
# verify.sh, and optionally access.json. Nothing else is read from it, and nothing is
# read from the network.
#
# THIS SCRIPT INSTALLS NOTHING ITSELF. The binaries, the units, the service users, the
# env file, the HMAC key, the access file, and the order they must happen in are all the
# packages' business: see [package.metadata.deb] in Cargo.toml and
# deploy/debian/*/postinst. What is left here is the things a package may not do:
#
#   1. Validate a staged access.json BEFORE anything is installed. It used to happen
#      after dpkg -i, which fails closed (the live file is untouched) but only after the
#      host has already been mutated and the services restarted: a red deploy over a file
#      that could have been rejected while the host was still exactly as it was. The
#      check needs a bb-auth binary, and the staged one is right there in the directory.
#   2. dpkg -i, in ONE transaction, so the strict `bb-auth (= <version>)` dependency of
#      the two admin packages is satisfied by the gate in the same run. `dpkg -i` and
#      not `apt install`, deliberately: apt declines to reinstall a version equal to the
#      one already installed, so a rebuilt 1.1.0-1 would silently not deploy.
#   3. Keep the packages it is replacing, so there is something to roll back TO. dpkg has
#      no archive of its own past the apt cache, and this repository ships no other copy;
#      see "Rollback" in README.md for what to do with them.
#   4. Install a staged access.json over the live one. The packages create that file
#      once, empty, and never touch it again, which is what makes a redeploy safe; so
#      REPLACING it is necessarily a separate, explicit act. It is validated with the
#      freshly-installed binary before anything is overwritten, and written back with
#      the owner and mode the live file already had.
#
# What is preserved across every run, and why it is preserved by construction rather
# than by care: neither etc/bb-auth.env (the HMAC key, so every session cookie keeps
# verifying) nor var/lib/access.json is part of any package, and dpkg cannot clobber a
# file it does not ship.
#
# Install dir is overridable:  DEST=/opt/bb-auth (default).
set -euo pipefail

SRC_DIR="${1:?usage: sudo bash deploy.sh <staging_dir>}"
DEST="${DEST:-/opt/bb-auth}"
LIVE_ACCESS="$DEST/var/lib/access.json"
TS="$(date +%Y%m%d-%H%M%S)"

[ "$(id -u)" = "0" ] || { echo "[deploy] FATAL: run as root (sudo bash deploy.sh ...)"; exit 1; }

# deploy.ps1 asks this before it copies anything, but this script is also runnable by
# hand on a host nobody probed. An RPM machine is a real target family and simply is
# not supported yet: cargo-deb produces .deb only, so name that instead of letting the
# operator read "dpkg: command not found" and wonder what is missing.
if ! command -v dpkg >/dev/null 2>&1; then
  if command -v rpm >/dev/null 2>&1; then
    echo "[deploy] FATAL: this host is RPM-based, and RPM packaging is NOT SUPPORTED yet."
    echo "[deploy]        bb-auth ships .deb packages only (scripts/package.sh, cargo-deb)."
  else
    echo "[deploy] FATAL: no dpkg on this host, and no rpm either. Only Debian-family"
    echo "[deploy]        hosts are supported."
  fi
  exit 1
fi

shopt -s nullglob
DEBS=("$SRC_DIR"/*.deb)
shopt -u nullglob
[ "${#DEBS[@]}" -gt 0 ] || { echo "[deploy] FATAL: no .deb file in $SRC_DIR"; exit 1; }

echo "[deploy] host    : $(uname -m), $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
echo "[deploy] packages: ${#DEBS[@]}"
for d in "${DEBS[@]}"; do echo "           $(basename "$d")"; done

# --- 1. the staged access file, before anything is installed -------------------
# The gate's own parser, run from the .deb that is about to be installed rather than from
# the one already on the host: it is the parser that will read the file, and it is the one
# whose refusal matters. A rejected file stops the deploy with the host untouched.
if [ -f "$SRC_DIR/access.json" ]; then
  echo "[deploy] --- checking the staged access.json ---"
  STAGED_GATE=""
  for d in "${DEBS[@]}"; do
    case "$(basename "$d")" in bb-auth_*) STAGED_GATE="$d" ;; esac
  done
  CHECKER=""
  if [ -n "$STAGED_GATE" ] && command -v dpkg-deb >/dev/null 2>&1; then
    TMP_EXTRACT="$(mktemp -d)"
    if dpkg-deb -x "$STAGED_GATE" "$TMP_EXTRACT" 2>/dev/null; then
      [ -x "$TMP_EXTRACT$DEST/bin/bb-auth" ] && CHECKER="$TMP_EXTRACT$DEST/bin/bb-auth" || true
    fi
  fi
  # Nothing staged to check with (a --Packages run without the gate): the installed
  # binary is the next best parser, and an install that has none has no gate to break.
  if [ -z "$CHECKER" ] && [ -x "$DEST/bin/bb-auth" ]; then CHECKER="$DEST/bin/bb-auth"; fi
  if [ -n "$CHECKER" ]; then
    if ! "$CHECKER" --check-access "$SRC_DIR/access.json"; then
      echo "[deploy] FATAL: the staged access.json is not a valid bb-auth access file."
      echo "[deploy]        NOTHING was installed and the live file was not touched."
      rm -rf "${TMP_EXTRACT:-/nonexistent}"
      exit 1
    fi
  else
    echo "[deploy] WARNING: no bb-auth binary to validate the staged access.json with yet;"
    echo "[deploy]          it will be checked after the install instead."
  fi
  rm -rf "${TMP_EXTRACT:-/nonexistent}"
fi

# --- 2. keep what is being replaced --------------------------------------------
# A rollback needs the previous .deb files, and nothing else on this host keeps them: dpkg
# stores no archive and apt's cache holds only what apt downloaded. Copy them aside before
# they are overwritten, once per deploy, into a directory the packages do not own.
PREV_DIR="$DEST/share/previous"
mkdir -p "$PREV_DIR"
{
  echo "# what was installed before the deploy of $TS"
  for pkg in bb-auth bb-auth-adm bb-auth-web; do
    ver="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
    [ -n "$ver" ] || continue
    echo "$pkg $ver"
    # The .deb that installed it, if apt still has it. Best effort by design: the rollback
    # story is "install the previous version", and when the file is gone the answer is to
    # rebuild it from its tag, which is why the version is recorded either way.
    found="$(ls /var/cache/apt/archives/"${pkg}"_*.deb 2>/dev/null | head -1 || true)"
    [ -n "$found" ] && cp -f "$found" "$PREV_DIR/" 2>/dev/null || true
  done
} > "$PREV_DIR/versions.txt"
echo "[deploy] what is being replaced is recorded in $PREV_DIR/versions.txt"

# --- 3. install ---------------------------------------------------------------
# A postinst that fails its preflight exits non-zero and dpkg reports it here. That is
# the deploy failing with the gate still serving on the inode it holds, which is the
# whole point of doing the validation before the restart rather than after it.
echo "[deploy] --- dpkg -i ---"
if ! DEBIAN_FRONTEND=noninteractive dpkg -i "${DEBS[@]}"; then
  echo "[deploy] FATAL: dpkg -i failed (see the maintainer-script output above)."
  echo "[deploy]        If it named an unmet dependency: apt-get -f install -y"
  echo "[deploy]        Nothing was rolled back, but no service was restarted either."
  exit 1
fi

# --- 4. the access file, only if one was staged --------------------------------
# Absent, the live file is left exactly as it is, so a binary-only redeploy can never
# lock anyone out. Staged, it REPLACES the live one, after the gate's own parser has
# vouched for it: a rejected file is a fatal startup, and under Restart=on-failure that
# is a boot loop.
if [ -f "$SRC_DIR/access.json" ]; then
  echo "[deploy] --- access file ---"
  # Checked again, with the binary that is now installed: the pre-install run used the
  # staged package's copy, and this is the parser that will actually read the file.
  if ! "$DEST/bin/bb-auth" --check-access "$SRC_DIR/access.json"; then
    echo "[deploy] FATAL: the staged access.json is not a valid bb-auth access file (see above)."
    echo "[deploy]        The live file was NOT touched."
    exit 1
  fi
  # Whatever the live file is, the replacement must stay: bb-auth-web:bb-auth 0640 once
  # the GUI is installed, root:bb-auth 0640 without it. Getting this wrong locks either
  # the gate out of its own access list or the GUI out of writing it.
  if [ -e "$LIVE_ACCESS" ]; then
    OWNER="$(stat -c '%U:%G' "$LIVE_ACCESS")"
    MODE="$(stat -c '%a' "$LIVE_ACCESS")"
    cp -a "$LIVE_ACCESS" "$LIVE_ACCESS.bak.$TS"
  else
    OWNER="root:bb-auth"
    MODE=640
  fi
  install -o "${OWNER%%:*}" -g "${OWNER##*:}" -m "$MODE" "$SRC_DIR/access.json" "$LIVE_ACCESS"
  echo "[deploy] installed access.json as $OWNER $MODE (previous kept as $(basename "$LIVE_ACCESS").bak.$TS)"
  # bb-auth-reload.path already turns the replacement into a reload when the GUI is
  # installed. Doing it here as well costs one extra reload and covers a gate-only host.
  # Guarded, because a first install leaves the gate stopped on purpose and `reload` on
  # an inactive unit fails.
  if systemctl is-active --quiet bb-auth; then
    systemctl reload bb-auth
  else
    echo "[deploy] bb-auth is not running yet, so there is nothing to reload"
  fi
else
  echo "[deploy] no access.json staged, keeping the live $LIVE_ACCESS"
fi

# --- 5. verify -----------------------------------------------------------------
# A first install leaves the gate installed and NOT enabled, because its env file is
# still the template: the postinst enables and starts only once its preflight passes.
# Verifying then would fail on "bb-auth active", which would be a red deploy for a host
# that is in exactly the state it should be in. So ask whether there is anything to
# verify first, and say plainly what is left to do when there is not.
if ! systemctl is-enabled bb-auth >/dev/null 2>&1; then
  echo "[deploy] bb-auth is installed but not enabled: this is a FIRST install."
  echo "[deploy]   1. fill in $DEST/etc/bb-auth.env (the HMAC key is already there)"
  echo "[deploy]   2. systemctl enable --now bb-auth"
  echo "[deploy]   3. sudo bash verify.sh"
  echo "[deploy] Skipping the post-deploy checks; there is nothing running to check."
elif [ -f "$SRC_DIR/verify.sh" ]; then
  echo "[deploy] --- verify ---"
  bash "$SRC_DIR/verify.sh"
else
  echo "[deploy] WARNING: no verify.sh staged, skipping the post-deploy checks"
fi

echo "[deploy] SUCCESS"
exit 0
