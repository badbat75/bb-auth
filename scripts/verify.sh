#!/usr/bin/env bash
# Post-deploy verification for bb-auth. Runs ON the host, as root (via sudo).
#
#   sudo bash verify.sh
#
# It asks the questions scripts/deploy.sh used to ask itself at the end of an install,
# and it asks them of whatever is on the host right now: the .deb path (scripts/deploy.ps1)
# and a hand-run `apt install` land in the same place, so this is the one check both
# share. It reads nothing but the host, changes nothing, and exits non-zero if any
# check fails, so a CI or an orchestrator caller can detect it.
#
# `set -e` is deliberately absent: every check must run even after one fails, or the
# first failure hides the rest.
set -uo pipefail

DEST="${DEST:-/opt/bb-auth}"
ENV_FILE="$DEST/etc/bb-auth.env"
WEB_ENV_FILE="$DEST/etc/bb-auth-web.env"
ACCESS_FILE="$DEST/var/lib/access.json"
VAR_DIR="$DEST/var/lib"
SVC_USER=bb-auth
WEB_USER=bb-auth-web

FAIL=0
chk() { # chk NAME EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then
    echo "  PASS  $1"
  else
    echo "  FAIL  $1: expected '$2', got '${3:-<empty>}'"
    FAIL=1
  fi
}
note() { echo "  info  $*"; }
bad()  { echo "  FAIL  $*"; FAIL=1; }

envval() { # $1 = var, $2 = env file
  grep -E "^[[:space:]]*$1=" "${2:-$ENV_FILE}" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]' || true
}

# journalctl --since wants "YYYY-MM-DD HH:MM:SS"; systemd prints a weekday in front of
# it. Dropping the first field is the whole conversion, and an empty answer (a unit that
# never came up) simply means "no window", which the caller reports as a failure anyway.
unit_active_since() { systemctl show -p ActiveEnterTimestamp --value "$1" 2>/dev/null | cut -d' ' -f2,3; }

echo "[verify] --- packages ---"
if command -v dpkg-query >/dev/null 2>&1; then
  for p in bb-auth bb-auth-adm bb-auth-web; do
    v="$(dpkg-query -W -f='${Version} ${db:Status-Status}' "$p" 2>/dev/null || true)"
    case "$v" in
      "")            note "$p: not installed" ;;
      *" installed") note "$p ${v% installed}" ;;
      *)             bad  "$p is ${v#* } (dpkg did not finish configuring it)" ;;
    esac
  done
else
  note "no dpkg on this host (installed by scripts/deploy.sh, not by package)"
fi

# The units a package ships live in /usr/lib/systemd/system. A copy under
# /etc/systemd/system is the ADMIN's and overrides it, which is exactly what an older
# scripts/deploy.sh install leaves behind: the packaged unit is then never read, and the
# next change to it would silently not apply.
echo "[verify] --- units ---"
SHADOWED=0
for u in bb-auth.service bb-auth-web.service bb-auth-reload.path bb-auth-reload.service; do
  if [ -e "/etc/systemd/system/$u" ] && [ -e "/usr/lib/systemd/system/$u" ]; then
    bad "/etc/systemd/system/$u shadows the packaged unit (move it aside)"
    SHADOWED=1
  fi
done
[ "$SHADOWED" = 0 ] && echo "  PASS  no legacy unit shadows a packaged one"

echo "[verify] --- the gate ---"
chk "bb-auth active" "active" "$(systemctl is-active bb-auth 2>/dev/null || true)"

LISTEN="$(envval BB_AUTH_LISTEN)"
LISTEN="${LISTEN:-127.0.0.1:4181}"
chk "GET /auth/healthz == ok" "ok" \
    "$(curl -fsS --max-time 3 "http://$LISTEN/auth/healthz" 2>/dev/null || true)"
chk "GET /auth/validate (no cookie) == 401" "401" \
    "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$LISTEN/auth/validate" || true)"

HKV="$(envval BB_AUTH_HMAC_KEY)"
if [ -n "$HKV" ] && [ "${#HKV}" -ge 32 ]; then
  echo "  PASS  HMAC key present (>=32 bytes)"
else
  bad "HMAC key missing or too short in $ENV_FILE"
fi

# The env must name the file the gate actually reads, or a validated file is not the
# one being served.
ENV_ACCESS="$(envval BB_AUTH_ACCESS_FILE)"
chk "BB_AUTH_ACCESS_FILE names the installed access file" "$ACCESS_FILE" "$ENV_ACCESS"

if [ -e "$ACCESS_FILE" ]; then
  if OUT="$("$DEST/bin/bb-auth" --check-access "$ACCESS_FILE" 2>&1)"; then
    note "$OUT"
  else
    bad "access file rejected by the gate's own parser:"
    echo "$OUT" | sed 's/^/        /'
  fi
else
  bad "$ACCESS_FILE does not exist"
fi

SINCE="$(unit_active_since bb-auth)"
if [ -n "$SINCE" ] && journalctl -u bb-auth --since "$SINCE" --no-pager 2>/dev/null | grep -q 'listening on'; then
  echo "  PASS  journal: clean startup (listening line since the unit came up)"
else
  bad "journal: no 'listening on' line since bb-auth last started"
fi

# --- the GUI, only if it is installed ---------------------------------------
if [ -x "$DEST/bin/bb-auth-web" ]; then
  echo "[verify] --- the admin GUI ---"
  chk "bb-auth-web active" "active" "$(systemctl is-active bb-auth-web 2>/dev/null || true)"
  chk "bb-auth-reload.path active" "active" \
      "$(systemctl is-active bb-auth-reload.path 2>/dev/null || true)"

  WEB_LISTEN="$(envval BB_AUTH_WEB_LISTEN "$WEB_ENV_FILE")"
  WEB_LISTEN="${WEB_LISTEN:-127.0.0.1:8091}"
  # A 401 IS the ready signal: identity comes from the X-Auth-Email nginx injects and
  # curl sends none, so a served 401 means bound, configured and failing closed.
  chk "GET bb-auth-web / (no identity header) == 401" "401" \
      "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$WEB_LISTEN/" || true)"

  if [ -z "$(envval BB_AUTH_WEB_ADMINS "$WEB_ENV_FILE")" ]; then
    bad "$WEB_ENV_FILE sets no BB_AUTH_WEB_ADMINS (empty must never mean 'everyone')"
  else
    echo "  PASS  BB_AUTH_WEB_ADMINS is set"
  fi
  chk "the GUI edits the file the gate reads" "$ACCESS_FILE" \
      "$(envval BB_AUTH_ACCESS_FILE "$WEB_ENV_FILE")"

  # The whole write path in two lines: own the file, share the gate's group, 0640; and
  # write permission on the DIRECTORY, because the replacement is a rename into place.
  chk "access.json ownership" "$WEB_USER:$SVC_USER 640" \
      "$(stat -c '%U:%G %a' "$ACCESS_FILE" 2>/dev/null || true)"
  chk "var/lib ownership" "$WEB_USER:$SVC_USER 750" \
      "$(stat -c '%U:%G %a' "$VAR_DIR" 2>/dev/null || true)"

  SINCE="$(unit_active_since bb-auth-web)"
  if [ -n "$SINCE" ] && journalctl -u bb-auth-web --since "$SINCE" --no-pager 2>/dev/null | grep -q 'listening on'; then
    echo "  PASS  journal: bb-auth-web clean startup"
  else
    bad "journal: no 'listening on' line since bb-auth-web last started"
  fi
else
  echo "[verify] --- the admin GUI is not installed (fine: it is optional) ---"
  # Without the GUI the access file stays root-owned, which is what a gate-only host
  # looks like. Assert that rather than skipping, so a half-finished purge is visible.
  chk "access.json ownership" "root:$SVC_USER 640" \
      "$(stat -c '%U:%G %a' "$ACCESS_FILE" 2>/dev/null || true)"
fi

echo "[verify] --- status ---"
systemctl --no-pager --full status bb-auth 2>/dev/null | sed -n '1,8p'

if [ "$FAIL" = 1 ]; then
  echo "[verify] FAILED: one or more checks did not pass"
  exit 1
fi
echo "[verify] OK"
exit 0
