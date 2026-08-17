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
# THIS SCRIPT NO LONGER INSTALLS ANYTHING ITSELF. Everything that used to be here (the
# binaries, the units, the service users, the env file, the HMAC key, the access file,
# and the order they must happen in) now lives in the packages: see
# [package.metadata.deb] in Cargo.toml and deploy/debian/*/postinst. What is left here
# is the three things a package may not do:
#
#   1. dpkg -i, in ONE transaction, so the strict `bb-auth (= <version>)` dependency of
#      the two admin packages is satisfied by the gate in the same run. `dpkg -i` and
#      not `apt install`, deliberately: apt declines to reinstall a version equal to the
#      one already installed, so a rebuilt 3.0.0-1 would silently not deploy.
#   2. Move aside the units an older version of this script wrote to
#      /etc/systemd/system. That is the ADMIN's directory and it OVERRIDES the packaged
#      units in /usr/lib/systemd/system, so left in place they win forever and the unit
#      just installed is never read. A package must not touch that directory; a deploy
#      must. Moved, not deleted: systemd ignores the renamed file and the original is
#      one `mv` away.
#   3. Install a staged access.json over the live one. The packages create that file
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
# Keep the legacy units:       BB_AUTH_KEEP_LEGACY_UNITS=1
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

# --- 1. install ---------------------------------------------------------------
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

# --- 2. units from an older deploy.sh -----------------------------------------
if [ "${BB_AUTH_KEEP_LEGACY_UNITS:-0}" != "1" ]; then
  # Each entry is "unit:was-active:was-enabled", captured BEFORE the move because the
  # move is what makes both unreadable. `enabled` here means literally that word:
  # bb-auth-reload.service is `static` (it has no [Install] section, the .path unit
  # starts it), and reenabling a static unit is an error, not a no-op.
  MOVED=""
  for u in bb-auth.service bb-auth-web.service bb-auth-reload.path bb-auth-reload.service; do
    if [ -e "/etc/systemd/system/$u" ] && [ -e "/usr/lib/systemd/system/$u" ]; then
      ACT=no; systemctl is-active --quiet "$u" && ACT=yes
      ENA="$(systemctl is-enabled "$u" 2>/dev/null || true)"
      mv "/etc/systemd/system/$u" "/etc/systemd/system/$u.deploy-sh-legacy-$TS"
      echo "[deploy] moved aside /etc/systemd/system/$u (it overrode the packaged unit)"
      MOVED="$MOVED $u:$ACT:$ENA"
    fi
  done
  if [ -n "$MOVED" ]; then
    systemctl daemon-reload
    for entry in $MOVED; do
      u="${entry%%:*}"; rest="${entry#*:}"; ACT="${rest%%:*}"; ENA="${rest##*:}"
      # The enablement symlink in multi-user.target.wants pointed at the file just
      # moved, so it now dangles. systemd would still pull the unit in by NAME, but
      # `systemctl is-enabled` reports it broken, and this script and verify.sh both ask
      # that question. `reenable` rewrites the link onto the packaged unit.
      if [ "$ENA" = "enabled" ]; then
        systemctl reenable "$u" >/dev/null 2>&1 || echo "[deploy] WARNING: could not reenable $u"
      fi
      # Restart only what was already running. On a first install the gate is
      # deliberately not started (its env is still a template), and starting it here
      # would turn an unconfigured host into the Restart=on-failure loop the postinst
      # went out of its way to avoid.
      if [ "$ACT" = "yes" ]; then
        systemctl restart "$u"
        echo "[deploy] restarted $u on the packaged unit"
      fi
    done
  fi
fi

# --- 3. the access file, only if one was staged --------------------------------
# Absent, the live file is left exactly as it is, so a binary-only redeploy can never
# lock anyone out. Staged, it REPLACES the live one, after the gate's own parser has
# vouched for it: a rejected file is a fatal startup, and under Restart=on-failure that
# is a boot loop.
if [ -f "$SRC_DIR/access.json" ]; then
  echo "[deploy] --- access file ---"
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

# --- 4. verify -----------------------------------------------------------------
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
