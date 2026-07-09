#!/usr/bin/env bash
# Deploy bb-auth on the target host. Runs ON the host, as root (via sudo). Idempotent.
#
#   sudo bash deploy.sh <staging_dir>
#
# <staging_dir> must contain: bb-auth (the target binary), bb-auth.service,
# bb-auth.env (deployment config — see deploy/bb-auth.env.example). It MAY also
# contain users.json (the JSON access file — see deploy/users.example.json); see below.
#
# Layout under DEST (default /opt/bb-auth):
#   bin/bb-auth          the binary
#   etc/bb-auth.env      config + HMAC key (0640, service-user readable)
#   var/lib/users.json   the access list (0640, service-user readable)
#
# bb-auth.env: on first install the staged file is installed and, if its
# BB_AUTH_HMAC_KEY is empty, a fresh >=32-byte key is generated in place. On
# later runs the existing etc/bb-auth.env is PRESERVED — the HMAC key stays
# stable, so existing session cookies keep verifying (nobody is logged out). A
# pre-2.0 flat DEST/bb-auth.env is relocated into etc/ first, key and all.
#
# users.json: if staged, it REPLACES the live one (the old is backed up). If
# ABSENT, the existing var/lib/users.json is left untouched, so a binary-only
# redeploy can never lock users out. If neither exists, the script aborts —
# 2.0 has no legacy auto-migration (the pre-2.0 `enabled_paths` format is
# rejected outright, so an access file must be migrated by hand and staged).
#
# The users file that is about to go live is validated with the REAL parser
# (`bb-auth --check-users`) BEFORE the unit is installed and the service is
# restarted. A rejected file is a fatal startup error, and with Restart=on-failure
# that would be a boot loop; instead we abort with the old binary still serving.
#
# After install the service is restarted and a set of post-deploy checks runs
# (service active, GET /auth/healthz == ok, GET /auth/validate (no cookie) ==
# 401, HMAC key present, users file integrity, clean journal startup). The script
# exits non-zero if any check fails, so a CI/orchestrator caller can detect it.
#
# Install dir is overridable:  DEST=/opt/bb-auth (default).
set -euo pipefail

SRC_DIR="${1:?usage: sudo bash deploy.sh <staging_dir>}"
DEST="${DEST:-/opt/bb-auth}"
SVC_USER=bb-auth

BIN_DIR="$DEST/bin"
ETC_DIR="$DEST/etc"
VAR_DIR="$DEST/var/lib"
BIN_DEST="$BIN_DIR/bb-auth"
ENV_DEST="$ETC_DIR/bb-auth.env"
USERS_DEST="$VAR_DIR/users.json"
TS="$(date +%Y%m%d-%H%M%S)"

for f in bb-auth bb-auth.service bb-auth.env; do
  [ -f "$SRC_DIR/$f" ] || { echo "[deploy] FATAL: missing $SRC_DIR/$f"; exit 1; }
done

# --- system user/group (no login, no home) ---
getent group "$SVC_USER" >/dev/null || groupadd --system "$SVC_USER"
getent passwd "$SVC_USER" >/dev/null || useradd --system --gid "$SVC_USER" \
  --no-create-home --home-dir "$DEST" --shell /usr/sbin/nologin "$SVC_USER"

mkdir -p "$BIN_DIR" "$ETC_DIR" "$VAR_DIR"

# --- relocate a pre-2.0 flat layout ------------------------------------------
# The env file carries the HMAC key. If it is not found at ENV_DEST the "generate
# a fresh key" branch below would fire and log out every user, so move it first.
# Guarded, not a bare `mv`: a re-run (source gone) must not fail under `set -e`,
# and a half-completed previous run (both present) must never clobber the tree copy.
relocate() { # $1 = flat path, $2 = tree path, $3 = label
  [ -f "$1" ] || return 0
  if [ -f "$2" ]; then
    mv "$1" "$1.flatdup.$TS"
    echo "[deploy] $3: both flat and tree copies existed; kept $2, moved the flat one to $1.flatdup.$TS"
  else
    mv "$1" "$2"
    echo "[deploy] relocated $3: $1 -> $2"
  fi
}
relocate "$DEST/bb-auth.env" "$ENV_DEST" "env (HMAC key preserved)"

# --- pre-install snapshot (drives the post-deploy verification) ---------------
# Taken from the TREE paths, after the relocation above, so every check below
# compares like with like.
OLD_BIN_SHA="$(sha256sum "$BIN_DEST" 2>/dev/null | cut -d' ' -f1 || true)"
OLD_USERS_MD5="$(md5sum "$USERS_DEST" 2>/dev/null | cut -d' ' -f1 || true)"
STAGED_USERS_MD5="$(md5sum "$SRC_DIR/users.json" 2>/dev/null | cut -d' ' -f1 || true)"

# --- binary ------------------------------------------------------------------
# Non-destructive: the unit may still point at the old flat binary, and the running
# process holds its own inode either way. Nothing restarts until the checks pass.
install -o root -g root -m 0755 "$SRC_DIR/bb-auth" "$BIN_DEST"

# --- users file: validate BEFORE it can brick the service ---------------------
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

# Which file will the service actually read after this deploy?
if [ -n "$STAGED_USERS_MD5" ]; then
  USERS_SRC="$SRC_DIR/users.json"
elif [ -n "$OLD_USERS_MD5" ]; then
  USERS_SRC="$USERS_DEST"
else
  echo "[deploy] FATAL: no users file (none staged, none at $USERS_DEST)."
  if [ -f "$DEST/users.json" ] || [ -f "$DEST/allowed_emails" ]; then
    echo "[deploy]        A pre-2.0 access file exists at $DEST. bb-auth 2.0 replaced the"
    echo "[deploy]        'enabled_paths' path prefixes with 'authorized_urls' full-URL"
    echo "[deploy]        patterns; migrate it by hand and stage it (deploy.ps1 -UsersFile)."
  fi
  exit 1
fi

validate_users_json "$USERS_SRC" \
  || { echo "[deploy] FATAL: $USERS_SRC is not valid JSON"; exit 1; }

# The authoritative gate: the real parser. Catches a residual `enabled_paths` and
# any malformed authorized_urls pattern — both fatal at startup. The light JSON
# check above would happily pass either.
if ! "$BIN_DEST" --check-users "$USERS_SRC"; then
  echo "[deploy] FATAL: $USERS_SRC is not a valid bb-auth 2.0 users file (see above)."
  echo "[deploy]        Nothing was restarted; the service is still running the previous binary."
  echo "[deploy]        Fix the file, stage it (deploy.ps1 -UsersFile), and re-run."
  exit 1
fi

if [ -n "$STAGED_USERS_MD5" ]; then
  [ -n "$OLD_USERS_MD5" ] && cp -a "$USERS_DEST" "$USERS_DEST.bak.$TS"
  install -o root -g "$SVC_USER" -m 0640 "$SRC_DIR/users.json" "$USERS_DEST"
  echo "[deploy] installed users.json from staging"
else
  echo "[deploy] no users.json staged — keeping existing $USERS_DEST"
fi

# --- env (install staged config; generate HMAC key once, keep it stable) ------
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

# A preserved env still points BB_AUTH_USERS_FILE at the pre-2.0 flat path, so
# rewrite it in place (appending would leave the stale line winning or losing by
# accident). Idempotent; the HMAC key and everything else are untouched.
if grep -qE '^[[:space:]]*BB_AUTH_USERS_FILE=' "$ENV_DEST"; then
  if ! grep -qE "^[[:space:]]*BB_AUTH_USERS_FILE=$USERS_DEST\$" "$ENV_DEST"; then
    sed -i "s#^[[:space:]]*BB_AUTH_USERS_FILE=.*#BB_AUTH_USERS_FILE=$USERS_DEST#" "$ENV_DEST"
    echo "[deploy] repointed BB_AUTH_USERS_FILE -> $USERS_DEST in $ENV_DEST"
  fi
else
  printf '\nBB_AUTH_USERS_FILE=%s\n' "$USERS_DEST" >> "$ENV_DEST"
  echo "[deploy] added BB_AUTH_USERS_FILE=$USERS_DEST to $ENV_DEST"
fi

# 2.0 dropped BB_AUTH_SEARCH_URL (there is no single service base — one gate fronts
# several hosts) and replaced BB_AUTH_RD_BASE_DOMAIN with an explicit list,
# BB_AUTH_AUTHORIZED_HOSTS. The latter is REQUIRED, so a preserved 1.x env would make
# the new binary exit fatally on start — and with Restart=on-failure, loop. Derive it
# from the old settings, which map onto it exactly.
# Trailing `|| true`: under `set -o pipefail` a non-matching grep would make the whole
# pipeline exit 1, and `VAR="$(envval X)"` would inherit that and trip `set -e` — the
# script would die silently on a variable that is simply absent.
envval() {
  grep -E "^[[:space:]]*$1=" "$ENV_DEST" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]' || true
}
if ! grep -qE '^[[:space:]]*BB_AUTH_AUTHORIZED_HOSTS=[^[:space:]]' "$ENV_DEST"; then
  OLD_BASE="$(envval BB_AUTH_RD_BASE_DOMAIN | sed 's/^\.//')"
  # scheme, then anything from the first '/', '?' or '#', then a :port. Note the ','
  # delimiter: a '#' delimiter would end the expression inside the [/?#] class.
  OLD_SEARCH="$(envval BB_AUTH_SEARCH_URL | sed -e 's,^[a-zA-Z][a-zA-Z0-9+.-]*://,,' -e 's,[/?#].*$,,' -e 's,:[0-9]*$,,')"
  if [ -n "$OLD_BASE" ]; then
    # Old rule: host == base OR host ends with ".base". Exactly these two patterns.
    HOSTS="$OLD_BASE,*.$OLD_BASE"
  elif [ -n "$OLD_SEARCH" ]; then
    # No SSO base was set, so only the canonical service host was ever allowed.
    HOSTS="$OLD_SEARCH"
  else
    echo "[deploy] FATAL: $ENV_DEST has no BB_AUTH_AUTHORIZED_HOSTS (required since 2.0)"
    echo "[deploy]        and nothing to derive it from. Add e.g.:"
    echo "[deploy]          BB_AUTH_AUTHORIZED_HOSTS=example.com,*.example.com"
    echo "[deploy]        Nothing was restarted; the service is still running the previous binary."
    exit 1
  fi
  printf '\n# added by deploy.sh (2.0 migration): replaces BB_AUTH_RD_BASE_DOMAIN / BB_AUTH_SEARCH_URL\nBB_AUTH_AUTHORIZED_HOSTS=%s\n' "$HOSTS" >> "$ENV_DEST"
  echo "[deploy] added BB_AUTH_AUTHORIZED_HOSTS=$HOSTS to $ENV_DEST"
fi

# Dead variables: don't rewrite them (a header NAME may legitimately differ), but say
# so loudly. The X-Original-URL change is the one that silently breaks scoped access.
for dead in BB_AUTH_SEARCH_URL BB_AUTH_RD_BASE_DOMAIN; do
  if grep -qE "^[[:space:]]*$dead=" "$ENV_DEST"; then
    echo "[deploy] WARNING: $ENV_DEST still sets $dead — ignored by 2.0, safe to delete."
  fi
done
if grep -qE '^[[:space:]]*BB_AUTH_ORIGINAL_URI_HEADER=' "$ENV_DEST"; then
  echo "[deploy] WARNING: $ENV_DEST still sets BB_AUTH_ORIGINAL_URI_HEADER — that variable"
  echo "[deploy]          is ignored by bb-auth 2.0. Every credential is now URL-scoped and"
  echo "[deploy]          needs the full request URL via BB_AUTH_ORIGINAL_URL_HEADER"
  echo "[deploy]          (default X-Original-URL). nginx must set it on the auth-gate"
  echo "[deploy]          location AND on /auth/session:"
  echo "[deploy]            proxy_set_header X-Original-URL https://<server_name>\$uri;"
  echo "[deploy]          Until nginx sends it, every request fails closed (401)."
fi

chown root:root "$DEST" "$BIN_DIR" "$ETC_DIR" "$DEST/var" "$VAR_DIR"
chmod 0755 "$DEST" "$BIN_DIR" "$ETC_DIR" "$DEST/var" "$VAR_DIR"

# --- systemd unit ------------------------------------------------------------
# restart, not reload: ExecStart and EnvironmentFile both moved.
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
fi
if [ -n "$NEW_USERS_MD5" ]; then
  echo "  info  $("$BIN_DEST" --check-users "$USERS_DEST" 2>&1 || echo 'users.json unparseable')"
fi

if journalctl -u bb-auth --since "$RESTART_TS" --no-pager 2>/dev/null | grep -q 'listening on'; then
  echo "  PASS  journal: clean startup (listening line present)"
else
  echo "  FAIL  journal: no 'listening on' line since restart"
  FAIL=1
fi

NEW_BIN_SHA="$(sha256sum "$BIN_DEST" 2>/dev/null | cut -d' ' -f1 || true)"
BINSZ="$(stat -c%s "$BIN_DEST" 2>/dev/null || echo '?')"
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

# --- retire the pre-2.0 flat layout (only once everything verified) ----------
rm -f "$DEST/bb-auth"
# Rename rather than delete: it still holds the key hashes, and an inert name makes
# it obvious that editing it no longer does anything.
if [ -f "$DEST/users.json" ]; then
  mv "$DEST/users.json" "$DEST/users.json.pre2.0.$TS"
  echo "[deploy] retired the pre-2.0 $DEST/users.json (now .pre2.0.$TS; the live file is $USERS_DEST)"
fi

echo "[deploy] SUCCESS — bb-auth deployed and verified"
exit 0
