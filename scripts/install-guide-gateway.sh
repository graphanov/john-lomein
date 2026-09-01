#!/usr/bin/env bash
# Install/restart the per-instance public Discord guide gateway.
# Owner-gated: exits without starting anything unless instance manifest enables
# both discord and guide_gateway and a profile-local Discord token is present.
set -Eeuo pipefail
if [ $# -ne 1 ]; then
  echo "usage: install-guide-gateway.sh /path/to/instance" >&2
  exit 2
fi
HERE="$(cd "$(dirname "$0")/.." && pwd)"
READ_ENV="$HERE/scripts/read-instance-env.py"
SERVICE_REGISTRY="$HERE/scripts/john_lomein_service_registry.py"
if [ ! -f "$READ_ENV" ] && [ -n "${HERMES_HOME:-}" ] && [ -f "$HERMES_HOME/scripts/read-instance-env.py" ]; then
  READ_ENV="$HERMES_HOME/scripts/read-instance-env.py"
fi
if [ ! -f "$SERVICE_REGISTRY" ] && [ -n "${HERMES_HOME:-}" ] && [ -f "$HERMES_HOME/scripts/john_lomein_service_registry.py" ]; then
  SERVICE_REGISTRY="$HERMES_HOME/scripts/john_lomein_service_registry.py"
fi
if command -v uv >/dev/null 2>&1 && [ -f "$HERE/pyproject.toml" ]; then
  PRODUCT_PYTHON=(uv run --frozen --project "$HERE" python)
else
  RUNTIME_PYTHON="${HERMES_PYTHON:-}"
  if [ ! -x "$RUNTIME_PYTHON" ]; then
    HERMES_BIN="$(command -v hermes || true)"
    [ -n "$HERMES_BIN" ] && RUNTIME_PYTHON="$(dirname "$HERMES_BIN")/python3"
  fi
  [ -x "$RUNTIME_PYTHON" ] || RUNTIME_PYTHON="$HOME/.hermes/hermes-agent/venv/bin/python"
  [ -x "$RUNTIME_PYTHON" ] || RUNTIME_PYTHON="$(command -v python3)"
  PRODUCT_PYTHON=("$RUNTIME_PYTHON")
fi
if [ -z "${JOHN_LOMEIN_SERVICE_LOCK_FD:-}" ]; then
  exec "${PRODUCT_PYTHON[@]}" "$SERVICE_REGISTRY" run-locked -- bash "$0" "$1"
fi
"${PRODUCT_PYTHON[@]}" "$SERVICE_REGISTRY" assert-locked
eval "$("${PRODUCT_PYTHON[@]}" "$READ_ENV" "$1")"
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"
UID_NUM="$(id -u)"
AGENTS_DIR="$HOME/Library/LaunchAgents"
LABEL="ai.hermes.gateway-john-lomein-${BOT_SLUG}-guide"
PLIST="$AGENTS_DIR/${LABEL}.plist"
remove_gateway() {
  "${PRODUCT_PYTHON[@]}" "$SERVICE_REGISTRY" stop \
    --manifest "$JL_INSTANCE_MANIFEST" \
    --runtime-home "$BOT_HERMES_HOME" \
    --service "guide=$LABEL" >/dev/null
}
# Stop the old public process before validating or applying the new
# configuration. Any failed preflight therefore leaves the gateway closed.
remove_gateway
INSTALL_COMMITTED=0
rollback_gateway() {
  local status=$?
  local cleanup_status=0
  trap - ERR INT TERM
  if [ "$INSTALL_COMMITTED" != "1" ]; then
    set +e
    remove_gateway >/dev/null
    cleanup_status=$?
    set -e
  fi
  if [ "$cleanup_status" -ne 0 ]; then
    echo "Guide gateway rollback incomplete: service removal could not be verified" >&2
    exit 70
  fi
  if [ "$status" -eq 0 ]; then
    status=1
  fi
  exit "$status"
}
trap rollback_gateway ERR INT TERM
PAUSE_FILE="$BOT_HERMES_HOME/state/honcho/INGESTION_PAUSED.json"
TOMBSTONE_DIR="$BOT_HERMES_HOME/private/honcho-deletion-tombstones"
TOMBSTONES_PRESENT=0
shopt -s nullglob dotglob
for tombstone in "$TOMBSTONE_DIR"/*; do
  if [ -e "$tombstone" ]; then TOMBSTONES_PRESENT=1; break; fi
done
if [ -e "$PAUSE_FILE" ] || [ "$TOMBSTONES_PRESENT" = "1" ] || \
  [ "${BOT_MISSION_COMPLETE:-0}" != "1" ] || \
  [ "${BOT_DISCORD_ENABLED:-0}" != "1" ] || \
  [ "${BOT_GUIDE_GATEWAY_ENABLED:-0}" != "1" ]
then
  INSTALL_COMMITTED=1
  trap - ERR INT TERM
  if [ -e "$PAUSE_FILE" ]; then
    echo "guide gateway blocked by Honcho ingestion pause for instance=$BOT_SLUG; stale launchagent removed"
  elif [ "${BOT_MISSION_COMPLETE:-0}" != "1" ]; then
    echo "guide gateway blocked by incomplete owner mission for instance=$BOT_SLUG; stale launchagent removed"
  else
    echo "guide gateway owner-gated for instance=$BOT_SLUG; stale launchagent removed"
  fi
  exit 0
fi
GUIDE_ENV="$BOT_HERMES_HOME/profiles/$BOT_GUIDE_PROFILE/.env"
if ! "${PRODUCT_PYTHON[@]}" - "$GUIDE_ENV" <<'PY'
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_file() or path.is_symlink():
    raise SystemExit(1)
for raw in path.read_text(encoding="utf-8", errors="strict").splitlines():
    if not raw.startswith("DISCORD_BOT_TOKEN="):
        continue
    value = raw.split("=", 1)[1].strip()
    try:
        parts = shlex.split(value)
    except ValueError:
        raise SystemExit(1)
    if parts and parts[0].strip():
        raise SystemExit(0)
raise SystemExit(1)
PY
then
  echo "missing DISCORD_BOT_TOKEN in guide profile env; refusing to start public guide gateway" >&2
  exit 2
fi
if [ -z "${BOT_ALLOWED_CHANNELS:-}" ]; then
  echo "missing allowed Discord channels; refusing to start public guide gateway" >&2
  exit 2
fi
export HERMES_HOME="$BOT_HERMES_HOME"
export JOHN_LOMEIN_INSTANCE_HERMES_HOME="$BOT_HERMES_HOME"
export JOHN_LOMEIN_HERMES_HOME="$BOT_HERMES_HOME"
export HERMES_MANAGED_DIR="$BOT_HERMES_MANAGED_ROOT/$BOT_GUIDE_PROFILE"
"${PRODUCT_PYTHON[@]}" \
  "$BOT_HERMES_HOME/scripts/apply-guide-discord-config.py" \
  "$JL_INSTANCE_DIR" >/dev/null
"${PRODUCT_PYTHON[@]}" "$BOT_HERMES_HOME/scripts/john-lomein-trust-assertion.py" init-verifier >/dev/null
HERMES_BIN="$(command -v hermes || true)"
HERMES_PYTHON=""
if [ -n "$HERMES_BIN" ]; then
  HERMES_PYTHON="$(dirname "$HERMES_BIN")/python3"
fi
[ -x "$HERMES_PYTHON" ] || HERMES_PYTHON="$HOME/.hermes/hermes-agent/venv/bin/python"
[ -x "$HERMES_PYTHON" ] || HERMES_PYTHON="$(command -v python3)"
HERMES_VENV="$(cd "$(dirname "$HERMES_PYTHON")/.." 2>/dev/null && pwd || printf '')"
REAL_USER_HOME="${HERMES_REAL_HOME:-$HOME}"
AUTH_AUTHORITY_HOME="${JOHN_LOMEIN_AUTH_AUTHORITY_HOME:-$REAL_USER_HOME/.hermes}"
HERMES_GATEWAY_LOCK_DIR="$("${PRODUCT_PYTHON[@]}" - \
  "$BOT_HERMES_HOME" \
  "$REAL_USER_HOME" <<'PY'
import sys
from pathlib import Path

runtime, real_home = sys.argv[1:]
sys.path.insert(0, str(Path(runtime) / "scripts"))
from john_lomein_gateway_lock_contract import prepare_gateway_lock_root

print(prepare_gateway_lock_root(Path(real_home)))
PY
)"
export HERMES_GATEWAY_LOCK_DIR HERMES_REAL_HOME="$REAL_USER_HOME"
export JOHN_LOMEIN_AUTH_AUTHORITY_HOME="$AUTH_AUTHORITY_HOME"
if [ "${BOT_MODEL_PROVIDER:-}" = "openai-codex" ] || [ "${BOT_FALLBACK_PROVIDER:-}" = "openai-codex" ]; then
  "$HERMES_PYTHON" "$BOT_HERMES_HOME/scripts/john_lomein_auth_projection.py" sync \
    --runtime-home "$BOT_HERMES_HOME" \
    --authority-home "$AUTH_AUTHORITY_HOME" \
    --provider openai-codex \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_MAINTAINER_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_FORGE_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_GUIDE_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_OVERWATCH_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_LEARNING_STEWARD_PROFILE" \
    --quiet
fi
# Refuse to register a restart loop around a gateway that cannot enter the
# required boundary. This is a real descendant/read/write canary, not an
# environment-only check.
"${PRODUCT_PYTHON[@]}" - \
  "$BOT_HERMES_HOME" \
  "${BOT_MODEL_MEMORY_ISOLATION:-required}" \
  "$BOT_STEWARD_PRIVATE_ROOT" \
  "$BOT_STEWARD_PROJECTION_ROOT" \
  "$BOT_LOCAL" \
  "$HERMES_PYTHON" <<'PY'
import os
import sys
from pathlib import Path

home, mode, private, projection, checkout, runtime_python = sys.argv[1:]
sys.path.insert(0, str(Path(home) / "scripts"))
from john_lomein_model_isolation import run_isolation_canary

env = dict(os.environ)
env.update(
    {
        "BOT_HERMES_HOME": home,
        "HERMES_HOME": home,
        "BOT_LOCAL": checkout,
        "BOT_MODEL_MEMORY_ISOLATION": mode,
        "BOT_STEWARD_PRIVATE_ROOT": private,
        "BOT_STEWARD_PROJECTION_ROOT": projection,
        "BOT_MODEL_PROVIDER": os.environ.get("BOT_MODEL_PROVIDER", ""),
        "BOT_FALLBACK_PROVIDER": os.environ.get("BOT_FALLBACK_PROVIDER", ""),
        "HERMES_REAL_HOME": os.environ.get("HERMES_REAL_HOME", ""),
        "JOHN_LOMEIN_AUTH_AUTHORITY_HOME": os.environ.get(
            "JOHN_LOMEIN_AUTH_AUTHORITY_HOME",
            "",
        ),
    }
)
ok, detail = run_isolation_canary(env, python=runtime_python)
if not ok:
    print(f"guide gateway model-isolation preflight failed: {detail}", file=sys.stderr)
    raise SystemExit(78)
PY
mkdir -p "$AGENTS_DIR" "$BOT_HERMES_HOME/profiles/$BOT_GUIDE_PROFILE/logs"
"${PRODUCT_PYTHON[@]}" - "$PLIST" "$LABEL" "$HERMES_PYTHON" "$BOT_GUIDE_PROFILE" "$BOT_HERMES_HOME" "$HERMES_MANAGED_DIR" "$HERMES_VENV" "$REAL_USER_HOME" "$AUTH_AUTHORITY_HOME" "$HERMES_GATEWAY_LOCK_DIR" "$BOT_REPO" "${BOT_OWNER_APPROVERS:-}" "${BOT_TRUST_PUBLIC_KEY_SHA256:-}" "${BOT_DISCORD_OWNER_USER_IDS:-}" "${BOT_DISCORD_TRUSTED_COLLABORATOR_USER_IDS:-}" "${BOT_MODEL_MEMORY_ISOLATION:-required}" "${BOT_MODEL_PROVIDER:-}" "${BOT_FALLBACK_PROVIDER:-}" <<'PY'
import os, plistlib, sys, tempfile
plist,label,py,profile,H,managed_dir,venv,real_home,auth_authority_home,gateway_lock_dir,repo,owner_approvers,trust_public_key_sha256,owner_ids,collaborator_ids,isolation,model_provider,fallback_provider=sys.argv[1:]
obj={
  'Label': label,
  'ProgramArguments': [py, f'{H}/scripts/john_lomein_model_isolation.py', '--profile', profile, '--', py, '-I', '-m', 'hermes_cli.main', '--profile', profile, 'gateway', 'run', '--replace'],
  'WorkingDirectory': f'{H}/profiles/{profile}',
  'EnvironmentVariables': {
    'HERMES_HOME': H,
    'HERMES_HONCHO_HOST': f'hermes_{profile}',
    'HERMES_MANAGED_DIR': managed_dir,
    'JOHN_LOMEIN_INSTANCE_HERMES_HOME': H,
    'JOHN_LOMEIN_HERMES_HOME': H,
    'BOT_HERMES_HOME': H,
    'BOT_MODEL_MEMORY_ISOLATION': isolation,
    'BOT_STEWARD_PRIVATE_ROOT': f'{H}/private/learning-steward',
    'BOT_STEWARD_PROJECTION_ROOT': f'{H}/state/learning',
    'HERMES_REAL_HOME': real_home,
    'JOHN_LOMEIN_AUTH_AUTHORITY_HOME': auth_authority_home,
    'HERMES_GATEWAY_LOCK_DIR': gateway_lock_dir,
    # John schedules its own bounded cron/worker lanes. The Hermes Kanban
    # dispatcher is unused and would otherwise write a shared DB at the sealed
    # runtime root from inside this model sandbox.
    'HERMES_KANBAN_DISPATCH_IN_GATEWAY': '0',
    'BOT_MODEL_PROVIDER': model_provider,
    'BOT_FALLBACK_PROVIDER': fallback_provider,
    'VIRTUAL_ENV': venv,
    'GH_PROMPT_DISABLED': '1',
    'GH_NO_UPDATE_NOTIFIER': '1',
    'GH_NO_EXTENSION_UPDATE_NOTIFIER': '1',
    'BOT_REPO': repo,
    'BOT_OWNER_APPROVERS': owner_approvers,
    'BOT_TRUST_PUBLIC_KEY_SHA256': trust_public_key_sha256,
    'BOT_DISCORD_OWNER_USER_IDS': owner_ids,
    'BOT_DISCORD_TRUSTED_COLLABORATOR_USER_IDS': collaborator_ids,
    'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin',
  },
  'LimitLoadToSessionType': ['Aqua','Background'],
  'RunAtLoad': True,
  'KeepAlive': True,
  'StandardOutPath': f'{H}/profiles/{profile}/logs/gateway.log',
  'StandardErrorPath': f'{H}/profiles/{profile}/logs/gateway.error.log',
}
parent=os.path.dirname(plist)
fd,temporary=tempfile.mkstemp(prefix='.guide-gateway-',dir=parent)
try:
  os.fchmod(fd,0o600)
  with os.fdopen(fd,'wb') as f:
    plistlib.dump(obj,f)
    f.flush(); os.fsync(f.fileno())
  os.replace(temporary,plist)
  directory=os.open(parent,os.O_RDONLY)
  try: os.fsync(directory)
  finally: os.close(directory)
finally:
  if os.path.exists(temporary): os.unlink(temporary)
PY
plutil -lint "$PLIST" >/dev/null
GATEWAY_ERROR_LOG="$BOT_HERMES_HOME/profiles/$BOT_GUIDE_PROFILE/logs/gateway.error.log"
if [ -f "$GATEWAY_ERROR_LOG" ]; then
  GATEWAY_ERROR_OFFSET="$(wc -c <"$GATEWAY_ERROR_LOG" | tr -d ' ')"
else
  GATEWAY_ERROR_OFFSET=0
fi
launchctl bootout "gui/${UID_NUM}" "$PLIST" >/dev/null 2>&1 || launchctl bootout "gui/${UID_NUM}/${LABEL}" >/dev/null 2>&1 || true
# A previous uninstall/failed install can leave the label disabled in launchd.
# Enabling only after bootstrap is too late: disabled labels can fail bootstrap
# with macOS error 5 (Input/output error).
launchctl enable "gui/${UID_NUM}/${LABEL}" >/dev/null 2>&1 || true
launchctl bootstrap "gui/${UID_NUM}" "$PLIST"
launchctl enable "gui/${UID_NUM}/${LABEL}" >/dev/null 2>&1 || true
launchctl kickstart -k "gui/${UID_NUM}/${LABEL}" >/dev/null 2>&1 || true
"${PRODUCT_PYTHON[@]}" - \
  "$UID_NUM" \
  "$LABEL" \
  "$BOT_HERMES_HOME/profiles/$BOT_GUIDE_PROFILE" \
  "$GATEWAY_ERROR_LOG" \
  "$GATEWAY_ERROR_OFFSET" <<'PY'
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

uid, label, profile_raw, error_raw, offset_raw = sys.argv[1:]
profile = Path(profile_raw)
error_log = Path(error_raw)
offset = int(offset_raw)
deadline = time.monotonic() + 45
stable_since = None
last_reason = "launchd_not_running"


def safe_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


while time.monotonic() < deadline:
    proc = subprocess.run(
        ["launchctl", "print", f"gui/{uid}/{label}"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    output = proc.stdout if proc.returncode == 0 else ""
    pid_match = re.search(r"(?m)^\s*pid = ([1-9][0-9]*)\s*$", output)
    running = bool(
        proc.returncode == 0
        and re.search(r"(?m)^\s*state = running\s*$", output)
        and pid_match
    )
    pid = int(pid_match.group(1)) if pid_match else 0
    lock = safe_json(profile / "gateway.lock")
    state = safe_json(profile / "gateway_state.json")
    pid_agrees = (
        pid > 0
        and lock.get("pid") == pid
        and state.get("pid") == pid
        and state.get("gateway_state") == "running"
    )
    new_errors = ""
    if error_log.is_file() and not error_log.is_symlink():
        try:
            with error_log.open("rb") as handle:
                handle.seek(offset)
                new_errors = handle.read(512 * 1024).decode(
                    "utf-8",
                    errors="replace",
                )
        except OSError:
            new_errors = ""
    forbidden_error = (
        "PermissionError" in new_errors
        or "Operation not permitted" in new_errors
        or "known_plugin_toolsets" in new_errors
    )
    if forbidden_error:
        last_reason = "gateway_sandbox_or_config_error"
        stable_since = None
    elif running and pid_agrees:
        if stable_since is None:
            stable_since = time.monotonic()
        # Hermes starts background watchers after a five-second delay. Require
        # a longer window so a live PID cannot be accepted just before a
        # sandbox/path failure appears on that first watcher tick.
        if time.monotonic() - stable_since >= 7:
            raise SystemExit(0)
        last_reason = "gateway_stability_window"
    else:
        stable_since = None
        last_reason = (
            "gateway_runtime_identity_unproven"
            if running
            else "launchd_not_running"
        )
    time.sleep(0.25)

print(
    f"Guide gateway failed closed before registry commit: {last_reason}",
    file=sys.stderr,
)
raise SystemExit(78)
PY
# Hermes 0.18.2 creates a new scoped token-lock entry with os.open's default
# 0777 mode.  The enclosing contract root is already 0700, so the entry is
# never exposed while the gateway starts; once the live identity is stable,
# normalize every safe entry to 0600 and prove the contract before recording
# the service.  Preparation changes modes only, never lock contents.
"${PRODUCT_PYTHON[@]}" - \
  "$BOT_HERMES_HOME" \
  "$REAL_USER_HOME" \
  "$HERMES_GATEWAY_LOCK_DIR" <<'PY'
import sys
from pathlib import Path

runtime, real_home, expected_root = sys.argv[1:]
sys.path.insert(0, str(Path(runtime) / "scripts"))
from john_lomein_gateway_lock_contract import (
    prepare_gateway_lock_root,
    validate_gateway_lock_root,
)

prepared = prepare_gateway_lock_root(Path(real_home))
validated = validate_gateway_lock_root(Path(real_home))
if prepared != Path(expected_root) or validated != prepared:
    raise SystemExit("gateway_lock_contract_path_mismatch")
PY
"${PRODUCT_PYTHON[@]}" "$SERVICE_REGISTRY" record \
  --manifest "$JL_INSTANCE_MANIFEST" \
  --runtime-home "$BOT_HERMES_HOME" \
  --service "guide=$LABEL" >/dev/null
INSTALL_COMMITTED=1
trap - ERR INT TERM
echo "guide gateway installed: $LABEL runtime=$BOT_HERMES_HOME profile=$BOT_GUIDE_PROFILE allowed=$BOT_ALLOWED_CHANNELS"
launchctl print "gui/${UID_NUM}/${LABEL}" 2>/dev/null | sed -n '1,45p' || true
