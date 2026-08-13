#!/usr/bin/env bash
# Deploy bb-auth on the target host. Runs ON the host, as root (via sudo). Idempotent.
#
#   sudo bash deploy.sh <staging_dir>
#
# <staging_dir> must contain: bb-auth (the target binary), bb-auth.service,
# bb-auth.env (deployment config — see deploy/bb-auth.env.example). It MAY also
# contain users.json (the JSON access file — see deploy/users.example.json),
# bb-auth-adm (the access-file admin CLI) and bb-auth-web (the admin GUI, which
# additionally needs bb-auth-web.service, bb-auth-web.env, bb-auth-reload.path and
# bb-auth-reload.service staged with it); see below.
#
# Layout under DEST (default /opt/bb-auth):
#   bin/bb-auth            the binary
#   bin/bb-auth-adm        the access-file admin CLI (optional; installed if staged)
#   bin/bb-auth-web        the access-file admin GUI (optional; installed if staged)
#   etc/bb-auth.env        config + HMAC key (0640, service-user readable)
#   etc/bb-auth-web.env    the GUI's config (0640; only when the GUI is installed)
#   var/lib/users.json     the access list (0640, readable by the gate's group)
# plus /etc/systemd/system/{bb-auth.service, and with the GUI bb-auth-web.service,
# bb-auth-reload.path, bb-auth-reload.service}.
#
# bb-auth-adm edits var/lib/users.json in place — `sudo bb-auth-adm user add …`, then
# `systemctl reload bb-auth`. It is why the live file is the one worth editing: it is the
# only copy that is current. It validates with the gate's own parser before writing, and
# preserves the file's mode and ownership, which a plain redirect would not.
#
# bb-auth-web edits the same file, from a browser, through the same library code. It is
# the reason the access file changes hands: once the GUI is installed the file becomes
# bb-auth-web:bb-auth 0640 and its directory bb-auth-web:bb-auth 0750, because a
# temp+rename replacement needs write permission on the DIRECTORY and the writer must be
# able to chown the temp file back. The gate keeps read access through the bb-auth group
# and its unit does not change; `sudo bb-auth-adm` keeps working untouched, because the
# writer preserves whatever owner it finds. This migration happens ONLY when bb-auth-web
# is staged — a deploy without it leaves root:bb-auth exactly as it was.
#
# bb-auth-reload.path is installed with the GUI: it watches var/lib/users.json and runs
# `systemctl reload bb-auth` whenever it is replaced, so an edit from EITHER editor goes
# live without anyone needing the privilege to signal the service. A CLI operator who
# also reloads by hand just causes a second, harmless reload.
#
# bb-auth.env: on first install the staged file is installed and, if its
# BB_AUTH_HMAC_KEY is empty, a fresh >=32-byte key is generated in place. On
# later runs the existing etc/bb-auth.env is PRESERVED and never edited — the
# HMAC key stays stable, so existing session cookies keep verifying (nobody is
# logged out). The env file is operator-owned: this script validates it and
# aborts on a problem, it does not rewrite it.
#
# bb-auth-web.env: the same contract with no secret to generate — installed once if
# absent, then preserved, and validated (BB_AUTH_WEB_ADMINS non-empty, BB_AUTH_USERS_FILE
# naming the file this deploy installs) before anything is restarted. Landing the tracked
# template therefore ABORTS the first GUI deploy at the preflight, by design: an empty
# admin list is fatal in the binary too. Fill it in on the host and re-run.
#
# users.json: if staged, it REPLACES the live one (the old is backed up). If
# ABSENT, the existing var/lib/users.json is left untouched, so a binary-only
# redeploy can never lock users out. If neither exists, the script aborts.
#
# The users file that is about to go live is validated with the REAL parser
# (`bb-auth --check-users`) BEFORE the unit is installed and the service is
# restarted. A rejected file is a fatal startup error, and with Restart=on-failure
# that would be a boot loop; instead we abort with the old binary still serving.
#
# After install the service is restarted and a set of post-deploy checks runs
# (service active, GET /auth/healthz == ok, GET /auth/validate (no cookie) ==
# 401, HMAC key present, users file integrity, clean journal startup). With the
# GUI staged it also checks bb-auth-web is active and answers 401 to a request
# carrying no identity header, that the watcher is running, and that the access
# file and its directory carry the ownership the write path needs. The script
# exits non-zero if any check fails, so a CI/orchestrator caller can detect it.
#
# Install dir is overridable:  DEST=/opt/bb-auth (default).
set -euo pipefail

SRC_DIR="${1:?usage: sudo bash deploy.sh <staging_dir>}"
DEST="${DEST:-/opt/bb-auth}"
SVC_USER=bb-auth
WEB_USER=bb-auth-web

BIN_DIR="$DEST/bin"
ETC_DIR="$DEST/etc"
VAR_DIR="$DEST/var/lib"
BIN_DEST="$BIN_DIR/bb-auth"
ENV_DEST="$ETC_DIR/bb-auth.env"
WEB_BIN_DEST="$BIN_DIR/bb-auth-web"
WEB_ENV_DEST="$ETC_DIR/bb-auth-web.env"
USERS_DEST="$VAR_DIR/users.json"
TS="$(date +%Y%m%d-%H%M%S)"

for f in bb-auth bb-auth.service bb-auth.env; do
  [ -f "$SRC_DIR/$f" ] || { echo "[deploy] FATAL: missing $SRC_DIR/$f"; exit 1; }
done

# Does this deploy carry the admin GUI? Everything about it below hangs off this one
# answer, and when it is 0 nothing in this script behaves differently from before it
# existed — the gate never calls it, and an older dist/ must still deploy. Staging the
# binary without its unit and its env would install a service that cannot start, so that
# is a fatal staging error rather than a silent skip.
if [ -f "$SRC_DIR/bb-auth-web" ]; then
  WEB_STAGED=1
  for f in bb-auth-web.service bb-auth-web.env bb-auth-reload.path bb-auth-reload.service; do
    [ -f "$SRC_DIR/$f" ] \
      || { echo "[deploy] FATAL: bb-auth-web is staged but $SRC_DIR/$f is missing"; exit 1; }
  done
else
  WEB_STAGED=0
fi

# --- system user/group (no login, no home) ---
getent group "$SVC_USER" >/dev/null || groupadd --system "$SVC_USER"
getent passwd "$SVC_USER" >/dev/null || useradd --system --gid "$SVC_USER" \
  --no-create-home --home-dir "$DEST" --shell /usr/sbin/nologin "$SVC_USER"

# The GUI gets its own identity: it is the only thing here that WRITES the access file,
# and the gate must not inherit that. It joins the gate's group too — the file stays
# readable to the gate through it, and the writer's chown of its temp file back to
# <web-user>:<gate-group> is only permitted for a group the writer is in. The unit says
# SupplementaryGroups=bb-auth for the same reason; this keeps `id bb-auth-web` honest.
if [ "$WEB_STAGED" = "1" ]; then
  getent group "$WEB_USER" >/dev/null || groupadd --system "$WEB_USER"
  getent passwd "$WEB_USER" >/dev/null || useradd --system --gid "$WEB_USER" \
    --groups "$SVC_USER" --no-create-home --home-dir "$DEST" \
    --shell /usr/sbin/nologin "$WEB_USER"
  # Asserted separately, because --groups only applies at creation and this user may
  # predate the line above. (A `case`, not a pipe into `grep -q`: an early-exiting
  # reader under `set -o pipefail` would make this run every time.)
  case " $(id -nG "$WEB_USER") " in
    *" $SVC_USER "*) ;;
    *) usermod -aG "$SVC_USER" "$WEB_USER" ;;
  esac
fi

mkdir -p "$BIN_DIR" "$ETC_DIR" "$VAR_DIR"

# --- pre-install snapshot (drives the post-deploy verification) ---------------
OLD_BIN_SHA="$(sha256sum "$BIN_DEST" 2>/dev/null | cut -d' ' -f1 || true)"
OLD_USERS_MD5="$(md5sum "$USERS_DEST" 2>/dev/null | cut -d' ' -f1 || true)"
STAGED_USERS_MD5="$(md5sum "$SRC_DIR/users.json" 2>/dev/null | cut -d' ' -f1 || true)"

# --- binary ------------------------------------------------------------------
# Non-destructive: the unit may still point at the old flat binary, and the running
# process holds its own inode either way. Nothing restarts until the checks pass.
install -o root -g root -m 0755 "$SRC_DIR/bb-auth" "$BIN_DEST"

# The admin CLI, if this deploy carries one. Optional by design — the gate never calls it,
# so an older dist/ (or a build that skipped it) must still deploy. root-only (0755, but
# users.json is 0640 root:bb-auth, so editing it needs sudo anyway).
if [ -f "$SRC_DIR/bb-auth-adm" ]; then
  install -o root -g root -m 0755 "$SRC_DIR/bb-auth-adm" "$BIN_DIR/bb-auth-adm"
  echo "[deploy] installed bb-auth-adm -> $BIN_DIR/bb-auth-adm"
fi

# The admin GUI, same deal: optional, root-owned, executed by its own service user. It is
# not restarted here — first the users file and the env have to be vouched for.
if [ "$WEB_STAGED" = "1" ]; then
  install -o root -g root -m 0755 "$SRC_DIR/bb-auth-web" "$WEB_BIN_DEST"
  echo "[deploy] installed bb-auth-web -> $WEB_BIN_DEST"
fi

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
  echo "[deploy]        Stage one with deploy.ps1 -UsersFile."
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

# --- the GUI's env: same contract, no secret to generate ----------------------
# Installed once from what was staged (deploy/bb-auth-web.env if there is one, else the
# tracked template), then preserved and never edited. There is nothing to generate here:
# bb-auth-web holds no secret. Group-readable to its own user, like the gate's.
if [ "$WEB_STAGED" = "1" ]; then
  if [ -f "$WEB_ENV_DEST" ]; then
    echo "[deploy] keeping existing $WEB_ENV_DEST (operator-owned)"
  else
    umask 027
    install -o root -g "$WEB_USER" -m 0640 "$SRC_DIR/bb-auth-web.env" "$WEB_ENV_DEST"
    echo "[deploy] installed $WEB_ENV_DEST (from staging)"
    echo "[deploy] NOTE: if it came from the template, BB_AUTH_WEB_ADMINS is empty and the"
    echo "[deploy]       preflight below will abort — fill it in on the host and re-run."
  fi
fi

# --- env preflight: validate, never rewrite -----------------------------------
# The env file is operator-owned — installed once, then preserved untouched. So
# everything the service needs must already be in it. A missing required var is a
# fatal startup error, and with Restart=on-failure that becomes a boot loop; catch
# it here, while the old binary is still serving. Same contract as --check-users:
# validate the thing about to go live, abort before the restart, fix nothing silently.
#
# Trailing `|| true`: under `set -o pipefail` a non-matching grep would make the whole
# pipeline exit 1, and `VAR="$(envval X)"` would inherit that and trip `set -e` — the
# script would die silently on a variable that is simply absent.
envval() { # $1 = var name; $2 = env file (default: the gate's); value, empty if unset
  grep -E "^[[:space:]]*$1=" "${2:-$ENV_DEST}" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]' || true
}

ENV_FAIL=0
for req in BB_AUTH_HMAC_KEY BB_AUTH_COGNITO_ISSUER BB_AUTH_CLIENT_ID \
           BB_AUTH_AUTHORIZED_HOSTS BB_AUTH_LOGIN_URL BB_AUTH_USERS_FILE; do
  if [ -z "$(envval "$req")" ]; then
    echo "[deploy] FATAL: $ENV_DEST does not set $req (required)"
    ENV_FAIL=1
  fi
done

# The users file just validated must be the one the service will actually read,
# otherwise --check-users vouched for a file nothing loads.
ENV_USERS_FILE="$(envval BB_AUTH_USERS_FILE)"
if [ -n "$ENV_USERS_FILE" ] && [ "$ENV_USERS_FILE" != "$USERS_DEST" ]; then
  echo "[deploy] FATAL: BB_AUTH_USERS_FILE=$ENV_USERS_FILE but this deploy installs $USERS_DEST."
  echo "[deploy]        --check-users validated a file the service would not read."
  ENV_FAIL=1
fi

# The GUI's env, same rules and the same reason: it is operator-owned, it is read once at
# startup, a missing required var is a fatal exit, and Restart=on-failure turns that into
# a boot loop. Two things have to hold.
if [ "$WEB_STAGED" = "1" ]; then
  if [ -z "$(envval BB_AUTH_WEB_ADMINS "$WEB_ENV_DEST")" ]; then
    echo "[deploy] FATAL: $WEB_ENV_DEST does not set BB_AUTH_WEB_ADMINS (required)"
    echo "[deploy]        Empty is fatal in the binary too — it must never mean 'everyone'."
    echo "[deploy]        List the admin emails there, then re-run this deploy."
    ENV_FAIL=1
  fi
  # The GUI must edit the file the gate reads. Otherwise it writes a copy nothing serves,
  # and every edit silently does nothing — the exact failure --check-users guards against
  # on the gate's side, arriving from the other end.
  WEB_USERS_FILE="$(envval BB_AUTH_USERS_FILE "$WEB_ENV_DEST")"
  if [ -z "$WEB_USERS_FILE" ]; then
    echo "[deploy] FATAL: $WEB_ENV_DEST does not set BB_AUTH_USERS_FILE (required)"
    ENV_FAIL=1
  elif [ "$WEB_USERS_FILE" != "$USERS_DEST" ]; then
    echo "[deploy] FATAL: $WEB_ENV_DEST sets BB_AUTH_USERS_FILE=$WEB_USERS_FILE but this"
    echo "[deploy]        deploy installs $USERS_DEST — the GUI would edit a file the gate"
    echo "[deploy]        does not read."
    ENV_FAIL=1
  fi
fi

if [ "$ENV_FAIL" = "1" ]; then
  echo "[deploy]        Nothing was restarted; the service is still running the previous binary."
  echo "[deploy]        Edit $ENV_DEST on the host and re-run."
  exit 1
fi

chown root:root "$DEST" "$BIN_DIR" "$ETC_DIR" "$DEST/var" "$VAR_DIR"
chmod 0755 "$DEST" "$BIN_DIR" "$ETC_DIR" "$DEST/var" "$VAR_DIR"

# --- the access file changes hands when the GUI is installed ------------------
# Deliberately after the line above, which it overrides for var/lib alone. ONLY when
# bb-auth-web is staged: nothing else needs the new owner, so a deploy without the GUI
# leaves root:bb-auth exactly as it has always been. Idempotent — it re-asserts the same
# ownership every time.
#
# Why the directory and not just the file: the library's writer replaces the access file
# by writing a temp file BESIDE it and renaming that onto it, which is what makes the
# replacement atomic. Renaming and creating both need write permission on the directory.
# 0750 keeps the gate able to traverse and read through the bb-auth group, and keeps
# everyone else out.
#
# Why the file must be OWNED by the GUI: before renaming, the writer chowns the temp file
# back to the mode and owner it found, so `sudo bb-auth-adm` and the GUI leave the file
# identical. An unprivileged process may only chown to the uid it already owns and to a
# group it belongs to — so bb-auth-web has to be the owner and a member of bb-auth (the
# unit's SupplementaryGroups=), or every save aborts with EPERM and writes nothing.
if [ "$WEB_STAGED" = "1" ]; then
  chown "$WEB_USER:$SVC_USER" "$VAR_DIR"
  chmod 0750 "$VAR_DIR"
  chown "$WEB_USER:$SVC_USER" "$USERS_DEST"
  chmod 0640 "$USERS_DEST"
  # The writer's one-step-back copy. It is replaced with an open(O_TRUNC), not recreated,
  # so its owner survives whoever writes next — which means creating it here, once, owned
  # by the GUI, is what keeps a root-run `bb-auth-adm` from leaving behind a root-owned
  # .bak that the GUI's next save could not open for writing.
  [ -e "$USERS_DEST.bak" ] || cp -p "$USERS_DEST" "$USERS_DEST.bak"
  chown "$WEB_USER:$SVC_USER" "$USERS_DEST.bak"
  chmod 0640 "$USERS_DEST.bak"
  echo "[deploy] $USERS_DEST is now $WEB_USER:$SVC_USER 0640 (gate reads via the $SVC_USER group)"
fi

# --- systemd units -----------------------------------------------------------
# restart, not reload: ExecStart and EnvironmentFile both moved.
install -o root -g root -m 0644 "$SRC_DIR/bb-auth.service" /etc/systemd/system/bb-auth.service
# The GUI's unit, plus the watcher that turns any rewrite of the access file into a
# `systemctl reload bb-auth`. The watcher ships with the GUI because it is what makes a
# GUI edit live; a CLI operator reloading by hand as well just reloads twice.
if [ "$WEB_STAGED" = "1" ]; then
  install -o root -g root -m 0644 "$SRC_DIR/bb-auth-web.service" \
    /etc/systemd/system/bb-auth-web.service
  install -o root -g root -m 0644 "$SRC_DIR/bb-auth-reload.path" \
    /etc/systemd/system/bb-auth-reload.path
  install -o root -g root -m 0644 "$SRC_DIR/bb-auth-reload.service" \
    /etc/systemd/system/bb-auth-reload.service
fi
systemctl daemon-reload
systemctl enable bb-auth >/dev/null 2>&1 || true
if [ "$WEB_STAGED" = "1" ]; then
  systemctl enable bb-auth-web bb-auth-reload.path >/dev/null 2>&1 || true
fi

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

# --- the GUI: restart, then the watcher --------------------------------------
# After the gate, and after its readiness: the watcher must not be armed while the gate
# is restarting, or the users.json this deploy just installed could trigger a reload into
# a service that is not up yet.
WEB_READY=0
WEB_LISTEN=""
WEB_RESTART_TS=""
if [ "$WEB_STAGED" = "1" ]; then
  WEB_RESTART_TS="$(date '+%Y-%m-%d %H:%M:%S')"
  systemctl restart bb-auth-web
  WEB_LISTEN="$(envval BB_AUTH_WEB_LISTEN "$WEB_ENV_DEST")"
  WEB_LISTEN="${WEB_LISTEN:-127.0.0.1:8091}"
  echo "[deploy] waiting for bb-auth-web on $WEB_LISTEN ..."
  for _ in $(seq 1 15); do
    # A 401 IS the ready signal: identity comes from the X-Auth-Email nginx injects, and
    # curl sends none, so a served 401 means bound, configured and failing closed. Any
    # other answer to a header-less request would be the bug worth catching.
    if [ "$(systemctl is-active bb-auth-web)" = "active" ] \
       && [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://$WEB_LISTEN/" || true)" = "401" ]; then
      WEB_READY=1
      break
    fi
    sleep 1
  done
  systemctl restart bb-auth-reload.path
fi

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

if [ "$WEB_STAGED" = "1" ]; then
  ACTW="$(systemctl is-active bb-auth-web || true)"
  chk "bb-auth-web active" "active" "$ACTW"
  if [ "$WEB_READY" != "1" ]; then
    echo "  FAIL  bb-auth-web readiness: not active+401 within 15s"
    FAIL=1
  fi
  WC="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$WEB_LISTEN/" || true)"
  chk "GET bb-auth-web / (no identity header) == 401" "401" "$WC"
  chk "bb-auth-reload.path active" "active" "$(systemctl is-active bb-auth-reload.path || true)"
  # The whole write path in one line: own the file, share the gate's group, 0640.
  chk "users.json ownership" "$WEB_USER:$SVC_USER 640" \
      "$(stat -c '%U:%G %a' "$USERS_DEST" 2>/dev/null || true)"
  chk "var/lib ownership" "$WEB_USER:$SVC_USER 750" \
      "$(stat -c '%U:%G %a' "$VAR_DIR" 2>/dev/null || true)"
  if journalctl -u bb-auth-web --since "$WEB_RESTART_TS" --no-pager 2>/dev/null \
     | grep -q 'listening on'; then
    echo "  PASS  journal: bb-auth-web clean startup (listening line present)"
  else
    echo "  FAIL  journal: bb-auth-web has no 'listening on' line since restart"
    FAIL=1
  fi
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
if [ "$WEB_STAGED" = "1" ]; then
  systemctl --no-pager --full status bb-auth-web | sed -n '1,12p' || true
fi

if [ "$FAIL" = "1" ]; then
  echo "[deploy] FAILED — one or more verification checks did not pass"
  exit 1
fi

if [ "$WEB_STAGED" = "1" ]; then
  echo "[deploy] SUCCESS — bb-auth + bb-auth-web deployed and verified"
  echo "[deploy] the GUI answers only through nginx: gate its location with auth_request"
  echo "[deploy] and inject X-Auth-Email (README, \"The admin GUI behind the gate\")."
else
  echo "[deploy] SUCCESS — bb-auth deployed and verified"
fi
exit 0
