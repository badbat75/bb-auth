#!/usr/bin/env bash
# Deploy bb-auth on the target host. Runs ON the host, as root (via sudo). Idempotent.
#
#   sudo bash deploy.sh <staging_dir>
#
# <staging_dir> must contain: bb-auth (the target binary), bb-auth.service,
# bb-auth.env (deployment config — see deploy/bb-auth.env.example). It MAY also
# contain users.json (the JSON access file — see deploy/users.example.json); see below.
#
# bb-auth.env: on first install the staged file is installed and, if its
# BB_AUTH_HMAC_KEY is empty, a fresh >=32-byte key is generated in place. On
# later runs the existing /opt/bb-auth/bb-auth.env is PRESERVED — the HMAC key
# stays stable, so existing session cookies keep verifying (nobody is logged out).
#
# users.json: if staged, it REPLACES the live one (validated first; the old is
# backed up). If ABSENT, the existing /opt/bb-auth/users.json is left untouched,
# so a binary-only redeploy can never lock users out. If there is no users.json
# yet but a legacy /opt/bb-auth/allowed_emails exists, it is auto-migrated to
# users.json (one {"email": ...} per line). If none of these exist, the script aborts.
#
# After install the service is restarted and a set of post-deploy checks runs
# (service active, GET /auth/healthz == ok, GET /auth/validate (no cookie) ==
# 401, HMAC key present, allowlist integrity, clean journal startup). The script
# exits non-zero if any check fails, so a CI/orchestrator caller can detect it.
#
# Install dir is overridable:  DEST=/opt/bb-auth (default).
set -euo pipefail

SRC_DIR="${1:?usage: sudo bash deploy.sh <staging_dir>}"
DEST="${DEST:-/opt/bb-auth}"
SVC_USER=bb-auth

for f in bb-auth bb-auth.service bb-auth.env; do
  [ -f "$SRC_DIR/$f" ] || { echo "[deploy] FATAL: missing $SRC_DIR/$f"; exit 1; }
done

# --- system user/group (no login, no home) ---
getent group "$SVC_USER" >/dev/null || groupadd --system "$SVC_USER"
getent passwd "$SVC_USER" >/dev/null || useradd --system --gid "$SVC_USER" \
  --no-create-home --home-dir "$DEST" --shell /usr/sbin/nologin "$SVC_USER"

mkdir -p "$DEST"

# --- pre-install snapshot (drives the post-deploy verification) ---
OLD_BIN_SHA="$(sha256sum "$DEST/bb-auth" 2>/dev/null | cut -d' ' -f1 || true)"
OLD_USERS_MD5="$(md5sum "$DEST/users.json" 2>/dev/null | cut -d' ' -f1 || true)"
STAGED_USERS_MD5="$(md5sum "$SRC_DIR/users.json" 2>/dev/null | cut -d' ' -f1 || true)"

# --- binary (root-owned, read-only to the service) ---
install -o root -g root -m 0755 "$SRC_DIR/bb-auth" "$DEST/bb-auth"

# --- users file (staged replaces; absent = preserve; legacy = migrate) ---
USERS_DEST="$DEST/users.json"

validate_users_json() { # $1 = path; 0 = valid (or uncheckable), 1 = invalid JSON
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$1" <<'PY' || return 1
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert isinstance(d.get("users"), list), "top-level 'users' must be an array"
PY
  elif command -v jq >/dev/null 2>&1; then
    jq -e '.users | type == "array"' "$1" >/dev/null 2>&1 || return 1
  fi
  return 0
}

if [ -n "$STAGED_USERS_MD5" ]; then
  validate_users_json "$SRC_DIR/users.json" \
    || { echo "[deploy] FATAL: staged users.json is not valid JSON"; exit 1; }
  [ -n "$OLD_USERS_MD5" ] && cp -a "$USERS_DEST" "$USERS_DEST.bak.$(date +%Y%m%d-%H%M%S)"
  install -o root -g "$SVC_USER" -m 0640 "$SRC_DIR/users.json" "$USERS_DEST"
  echo "[deploy] installed users.json from staging"
elif [ -n "$OLD_USERS_MD5" ]; then
  echo "[deploy] no users.json staged — keeping existing $USERS_DEST"
elif [ -f "$DEST/allowed_emails" ]; then
  command -v python3 >/dev/null 2>&1 \
    || { echo "[deploy] FATAL: python3 needed to migrate allowed_emails -> users.json (or stage a users.json)"; exit 1; }
  echo "[deploy] migrating legacy allowed_emails -> users.json"
  python3 - "$DEST/allowed_emails" "$USERS_DEST" <<'PY'
import json, sys
emails = []
for line in open(sys.argv[1], encoding="utf-8"):
    s = line.strip()
    if s and not s.startswith("#"):
        emails.append(s.lower())
json.dump({"users": [{"email": e} for e in emails]},
          open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
  cp -a "$DEST/allowed_emails" "$DEST/allowed_emails.migrated.$(date +%Y%m%d-%H%M%S)"
  chown "root:$SVC_USER" "$USERS_DEST"
  chmod 0640 "$USERS_DEST"
  echo "[deploy] migrated $(grep -cvE '^[[:space:]]*(#|$)' "$DEST/allowed_emails" 2>/dev/null || echo '?') email(s) to $USERS_DEST"
else
  echo "[deploy] FATAL: no users file (none staged, none at $USERS_DEST, no legacy allowed_emails)"
  exit 1
fi

# --- env (install staged config; generate HMAC key once, keep it stable) ---
ENV_DEST="$DEST/bb-auth.env"
if [ -f "$ENV_DEST" ]; then
  echo "[deploy] keeping existing $ENV_DEST (HMAC key preserved)"
else
  STAGED_ENV="$SRC_DIR/bb-auth.env"
  umask 027
  if grep -qE '^[[:space:]]*BB_AUTH_HMAC_KEY=[^[:space:]]' "$STAGED_ENV"; then
    install -o root -g "$SVC_USER" -m 0640 "$STAGED_ENV" "$ENV_DEST"
    echo "[deploy] installed $ENV_DEST (HMAC key from staged config)"
  else
    HMAC="$(head -c 48 /dev/urandom | base64 -w0)"
    { echo "BB_AUTH_HMAC_KEY=$HMAC"
      grep -vE '^[[:space:]]*BB_AUTH_HMAC_KEY=' "$STAGED_ENV"
    } > "$ENV_DEST"
    chown "root:$SVC_USER" "$ENV_DEST"
    chmod 0640 "$ENV_DEST"
    echo "[deploy] installed $ENV_DEST (generated fresh HMAC key)"
  fi
fi

# Migration: pre-1.2 deploys set BB_AUTH_ALLOWLIST_FILE and have no BB_AUTH_USERS_FILE,
# but the preserved env above is never rewritten — so the new binary (which REQUIRES
# BB_AUTH_USERS_FILE) would fatal on start. Add it in place if missing, pointing at the
# migrated users.json. Idempotent; leaves the HMAC key and everything else untouched.
if ! grep -qE '^[[:space:]]*BB_AUTH_USERS_FILE=' "$ENV_DEST"; then
  printf '\n# added by deploy.sh (v1.2 migration): JSON users file replaces BB_AUTH_ALLOWLIST_FILE\nBB_AUTH_USERS_FILE=%s\n' "$USERS_DEST" >> "$ENV_DEST"
  echo "[deploy] added BB_AUTH_USERS_FILE=$USERS_DEST to $ENV_DEST"
fi

chown root:root "$DEST"
chmod 0755 "$DEST"

# --- systemd unit ---
install -o root -g root -m 0644 "$SRC_DIR/bb-auth.service" /etc/systemd/system/bb-auth.service
systemctl daemon-reload
systemctl enable bb-auth >/dev/null 2>&1 || true

# --- restart + wait for readiness (active AND healthz) ---
RESTART_TS="$(date '+%Y-%m-%d %H:%M:%S')"
systemctl restart bb-auth

LISTEN="$(grep -E '^[[:space:]]*BB_AUTH_LISTEN=' "$ENV_DEST" | tail -1 | cut -d= -f2-)"
LISTEN="${LISTEN:-127.0.0.1:4181}"

echo "[deploy] waiting for readiness on $LISTEN ..."
READY=0
for _ in $(seq 1 15); do
  if [ "$(systemctl is-active bb-auth)" = "active" ] \
     && curl -fsS --max-time 2 "http://$LISTEN/auth/healthz" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done

# --- verification ---
echo "[deploy] --- verify ---"
FAIL=0
chk() { # chk NAME EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then
    echo "  PASS  $1"
  else
    echo "  FAIL  $1: expected '$2', got '${3:-<empty>}'"
    FAIL=1
  fi
}

ACT="$(systemctl is-active bb-auth || true)"
chk "service active" "active" "$ACT"
if [ "$READY" != "1" ]; then
  echo "  FAIL  readiness: not active+healthz within 15s"
  FAIL=1
fi

HZ="$(curl -fsS --max-time 3 "http://$LISTEN/auth/healthz" 2>/dev/null || true)"
chk "GET /auth/healthz == ok" "ok" "$HZ"

VC="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$LISTEN/auth/validate" || true)"
chk "GET /auth/validate (no cookie) == 401" "401" "$VC"

HKV="$(grep -E '^BB_AUTH_HMAC_KEY=' "$ENV_DEST" | head -1 | cut -d= -f2- || true)"
if [ -n "$HKV" ] && [ "${#HKV}" -ge 32 ]; then
  echo "  PASS  HMAC key present (>=32 bytes)"
else
  echo "  FAIL  HMAC key missing or too short"
  FAIL=1
fi

NEW_USERS_MD5="$(md5sum "$USERS_DEST" 2>/dev/null | cut -d' ' -f1 || true)"
if [ -z "$NEW_USERS_MD5" ]; then
  echo "  FAIL  users.json: none present after install"
  FAIL=1
elif [ -n "$STAGED_USERS_MD5" ]; then
  chk "users.json installed==staged" "$STAGED_USERS_MD5" "$NEW_USERS_MD5"
elif [ -n "$OLD_USERS_MD5" ]; then
  chk "users.json preserved (unchanged)" "$OLD_USERS_MD5" "$NEW_USERS_MD5"
else
  echo "  info  users.json created (migrated / first install)"
fi
if [ -n "$NEW_USERS_MD5" ] && command -v python3 >/dev/null 2>&1; then
  UCOUNT="$(python3 - "$USERS_DEST" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
u = d.get("users", [])
k = sum(len(x.get("api_keys", [])) for x in u)
print(f"{len(u)} users, {k} api keys")
PY
)"
  echo "  info  users.json: ${UCOUNT:-unparseable}"
fi

if journalctl -u bb-auth --since "$RESTART_TS" --no-pager 2>/dev/null | grep -q 'listening on'; then
  echo "  PASS  journal: clean startup (listening line present)"
else
  echo "  FAIL  journal: no 'listening on' line since restart"
  FAIL=1
fi

NEW_BIN_SHA="$(sha256sum "$DEST/bb-auth" 2>/dev/null | cut -d' ' -f1 || true)"
BINSZ="$(stat -c%s "$DEST/bb-auth" 2>/dev/null || echo '?')"
if [ -n "$OLD_BIN_SHA" ] && [ "$OLD_BIN_SHA" = "$NEW_BIN_SHA" ]; then
  echo "  info  binary unchanged (same sha256)"
else
  echo "  info  binary updated ($BINSZ bytes)"
fi

echo "[deploy] --- status ---"
systemctl --no-pager --full status bb-auth | sed -n '1,12p' || true

if [ "$FAIL" = "1" ]; then
  echo "[deploy] FAILED — one or more verification checks did not pass"
  exit 1
fi
echo "[deploy] SUCCESS — bb-auth deployed and verified"
exit 0
