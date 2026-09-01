#!/usr/bin/env bash
# Install/restart per-instance john-lomein scheduler + optional keep-awake LaunchAgents.
# Scheduler runs the maintainer profile gateway for this instance HERMES_HOME so
# instance-local crons fire without using the owner's default Hermes runtime.
set -Eeuo pipefail
if [ $# -ne 1 ]; then
  echo "usage: install-runtime-supervisor.sh /path/to/instance" >&2
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
export HERMES_HOME="$BOT_HERMES_HOME"
export JOHN_LOMEIN_INSTANCE_HERMES_HOME="$BOT_HERMES_HOME"
export JOHN_LOMEIN_HERMES_HOME="$BOT_HERMES_HOME"
export HERMES_MANAGED_DIR="$BOT_HERMES_MANAGED_ROOT/$BOT_MAINTAINER_PROFILE"
export HERMES_REAL_HOME="${HERMES_REAL_HOME:-$HOME}"
export JOHN_LOMEIN_AUTH_AUTHORITY_HOME="${JOHN_LOMEIN_AUTH_AUTHORITY_HOME:-$HERMES_REAL_HOME/.hermes}"
unset MNEMOSYNE_DATA_DIR
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"

UID_NUM="$(id -u)"
HERMES_BIN="$(command -v hermes || true)"
HERMES_PYTHON=""
if [ -n "$HERMES_BIN" ]; then
  HERMES_PYTHON="$(dirname "$HERMES_BIN")/python3"
fi
[ -x "$HERMES_PYTHON" ] || HERMES_PYTHON="$HOME/.hermes/hermes-agent/venv/bin/python"
[ -x "$HERMES_PYTHON" ] || HERMES_PYTHON="$(command -v python3)"
HERMES_VENV="$(cd "$(dirname "$HERMES_PYTHON")/.." 2>/dev/null && pwd || printf '')"
AGENTS_DIR="$HOME/Library/LaunchAgents"
mkdir -p "$AGENTS_DIR" "$BOT_HERMES_HOME/logs" "$BOT_HERMES_HOME/profiles/$BOT_MAINTAINER_PROFILE/logs"
SCHED_LABEL="ai.hermes.john-lomein-${BOT_SLUG}-scheduler"
SCHED_PLIST="$AGENTS_DIR/${SCHED_LABEL}.plist"
KEEP_LABEL="ai.hermes.john-lomein-${BOT_SLUG}-keepawake"
KEEP_PLIST="$AGENTS_DIR/${KEEP_LABEL}.plist"
SERVICE_ARGS=(
  --manifest "$JL_INSTANCE_MANIFEST"
  --runtime-home "$BOT_HERMES_HOME"
  --service "scheduler=$SCHED_LABEL"
  --service "keepawake=$KEEP_LABEL"
)

"${PRODUCT_PYTHON[@]}" "$SERVICE_REGISTRY" stop "${SERVICE_ARGS[@]}" >/dev/null

INSTALL_COMMITTED=0
rollback_install() {
  local status=$?
  local cleanup_status=0
  trap - ERR INT TERM
  if [ "$INSTALL_COMMITTED" != "1" ]; then
    set +e
    "${PRODUCT_PYTHON[@]}" "$SERVICE_REGISTRY" stop "${SERVICE_ARGS[@]}" >/dev/null
    cleanup_status=$?
    set -e
  fi
  if [ "$cleanup_status" -ne 0 ]; then
    echo "supervisor rollback incomplete: service removal could not be verified" >&2
    exit 70
  fi
  if [ "$status" -eq 0 ]; then
    status=1
  fi
  exit "$status"
}
trap rollback_install ERR INT TERM

write_plist() {
  local label="$1" plist="$2" profile="$3" stdout_path="$4" stderr_path="$5"
  local managed_dir="$BOT_HERMES_MANAGED_ROOT/$profile"
  "${PRODUCT_PYTHON[@]}" - "$plist" "$label" "$HERMES_PYTHON" "$profile" "$BOT_HERMES_HOME" "$managed_dir" "$HERMES_VENV" "$stdout_path" "$stderr_path" "$HERMES_REAL_HOME" "$JOHN_LOMEIN_AUTH_AUTHORITY_HOME" "$BOT_HERMES_HOME/profiles/$profile/home/.config/gh" "${BOT_MODEL_PROVIDER:-}" "${BOT_FALLBACK_PROVIDER:-}" <<'PY'
import plistlib, sys
plist,label,py,profile,H,managed_dir,venv,out,err,real_home,auth_authority_home,gh_config,model_provider,fallback_provider=sys.argv[1:]
obj={
  'Label': label,
  'ProgramArguments': [py, '-m', 'hermes_cli.main', '--profile', profile, 'gateway', 'run', '--replace'],
  'WorkingDirectory': f'{H}/profiles/{profile}',
  'EnvironmentVariables': {
    'HERMES_HOME': H,
    'HERMES_MANAGED_DIR': managed_dir,
    'JOHN_LOMEIN_INSTANCE_HERMES_HOME': H,
    'JOHN_LOMEIN_HERMES_HOME': H,
    'HERMES_REAL_HOME': real_home,
    'JOHN_LOMEIN_AUTH_AUTHORITY_HOME': auth_authority_home,
    # John owns scheduling through its exact instance crons and worker
    # supervisor; the generic Hermes Kanban dispatcher is deliberately idle.
    'HERMES_KANBAN_DISPATCH_IN_GATEWAY': '0',
    'BOT_MODEL_PROVIDER': model_provider,
    'BOT_FALLBACK_PROVIDER': fallback_provider,
    'VIRTUAL_ENV': venv,
    'GH_CONFIG_DIR': gh_config,
    'GH_PROMPT_DISABLED': '1',
    'GH_NO_UPDATE_NOTIFIER': '1',
    'GH_NO_EXTENSION_UPDATE_NOTIFIER': '1',
    'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin',
  },
  'LimitLoadToSessionType': ['Aqua','Background'],
  'RunAtLoad': True,
  'KeepAlive': True,
  'StandardOutPath': out,
  'StandardErrorPath': err,
}
with open(plist,'wb') as f: plistlib.dump(obj,f)
PY
  plutil -lint "$plist" >/dev/null
}

bootstrap_label() {
  local label="$1" plist="$2"
  # A previous uninstall/failed install can leave the label disabled in launchd.
  # Enabling only after bootstrap is too late: disabled labels can fail bootstrap
  # with macOS error 5 (Input/output error).
  launchctl enable "gui/${UID_NUM}/${label}" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/${UID_NUM}" "$plist"
  launchctl enable "gui/${UID_NUM}/${label}" >/dev/null 2>&1 || true
  launchctl kickstart -k "gui/${UID_NUM}/${label}" >/dev/null 2>&1 || true
}

SCHED_REQUIRED=0
if [ "${BOT_MISSION_COMPLETE:-0}" = "1" ] && \
  { [ "${BOT_ACTIVATION:-owner_gated}" = "active" ] || [ "${BOT_MUTATION_ENABLED:-0}" = "1" ]; }
then
  SCHED_REQUIRED=1
fi
if [ "$SCHED_REQUIRED" = "1" ]; then
  write_plist "$SCHED_LABEL" "$SCHED_PLIST" "$BOT_MAINTAINER_PROFILE" "$BOT_HERMES_HOME/logs/scheduler.launchd.log" "$BOT_HERMES_HOME/logs/scheduler.launchd.error.log"
  bootstrap_label "$SCHED_LABEL" "$SCHED_PLIST"
  echo "scheduler installed: $SCHED_LABEL runtime=$BOT_HERMES_HOME profile=$BOT_MAINTAINER_PROFILE"
else
  if [ "${BOT_MISSION_COMPLETE:-0}" != "1" ]; then
    echo "scheduler blocked by incomplete owner mission for instance=$BOT_SLUG; stale launchagent removed"
  else
    echo "scheduler owner-gated for instance=$BOT_SLUG; stale launchagent removed"
  fi
fi

if [ "${BOT_KEEP_AWAKE_ON_AC:-0}" = "1" ]; then
  "${PRODUCT_PYTHON[@]}" - "$KEEP_PLIST" "$KEEP_LABEL" "$BOT_HERMES_HOME" <<'PY'
import plistlib, sys
plist,label,H=sys.argv[1:]
obj={
  'Label': label,
  'ProgramArguments': [f'{H}/scripts/john-lomein-keepawake.sh'],
  'WorkingDirectory': H,
  'EnvironmentVariables': {
    'HERMES_HOME': H,
    'HERMES_MANAGED_DIR': f'{H}/managed-policy/john-lomein-maintainer',
    'JOHN_LOMEIN_INSTANCE_HERMES_HOME': H,
    'JOHN_LOMEIN_HERMES_HOME': H,
    'GH_CONFIG_DIR': f'{H}/profiles/john-lomein-maintainer/home/.config/gh',
    'GH_PROMPT_DISABLED': '1',
    'GH_NO_UPDATE_NOTIFIER': '1',
    'GH_NO_EXTENSION_UPDATE_NOTIFIER': '1',
    'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin',
  },
  'LimitLoadToSessionType': ['Aqua','Background'],
  'RunAtLoad': True,
  'KeepAlive': True,
  'StandardOutPath': f'{H}/logs/keepawake.launchd.log',
  'StandardErrorPath': f'{H}/logs/keepawake.launchd.error.log',
}
with open(plist,'wb') as f: plistlib.dump(obj,f)
PY
  plutil -lint "$KEEP_PLIST" >/dev/null
  bootstrap_label "$KEEP_LABEL" "$KEEP_PLIST"
  echo "keepawake installed: $KEEP_LABEL runtime=$BOT_HERMES_HOME"
else
  echo "keepawake not requested for instance=$BOT_SLUG; stale launchagent removed"
fi

RECORD_ARGS=(
  --manifest "$JL_INSTANCE_MANIFEST"
  --runtime-home "$BOT_HERMES_HOME"
)
if [ "$SCHED_REQUIRED" = "1" ]; then
  RECORD_ARGS+=(--service "scheduler=$SCHED_LABEL")
fi
if [ "${BOT_KEEP_AWAKE_ON_AC:-0}" = "1" ]; then
  RECORD_ARGS+=(--service "keepawake=$KEEP_LABEL")
fi
if [ "${#RECORD_ARGS[@]}" -gt 4 ]; then
  "${PRODUCT_PYTHON[@]}" "$SERVICE_REGISTRY" record "${RECORD_ARGS[@]}" >/dev/null
fi
INSTALL_COMMITTED=1
trap - ERR INT TERM

if [ "$SCHED_REQUIRED" = "1" ]; then
  launchctl print "gui/${UID_NUM}/${SCHED_LABEL}" 2>/dev/null | sed -n '1,45p' || true
fi
