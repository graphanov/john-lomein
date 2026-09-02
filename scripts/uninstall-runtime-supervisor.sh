#!/usr/bin/env bash
# Stop/remove per-instance john-lomein LaunchAgents. Does not delete runtime data.
set -euo pipefail
if [ $# -ne 1 ]; then
  echo "usage: uninstall-runtime-supervisor.sh /path/to/instance" >&2
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
SCHED_LABEL="ai.hermes.john-lomein-${BOT_SLUG}-scheduler"
KEEP_LABEL="ai.hermes.john-lomein-${BOT_SLUG}-keepawake"
GUIDE_LABEL="ai.hermes.gateway-john-lomein-${BOT_SLUG}-guide"
PUBLIC_HONCHO_LABEL="ai.john-lomein.${BOT_SLUG}.public-honcho"
"${PRODUCT_PYTHON[@]}" "$SERVICE_REGISTRY" stop \
  --manifest "$JL_INSTANCE_MANIFEST" \
  --runtime-home "$BOT_HERMES_HOME" \
  --service "scheduler=$SCHED_LABEL" \
  --service "keepawake=$KEEP_LABEL" \
  --service "guide=$GUIDE_LABEL" \
  --service "public_honcho=$PUBLIC_HONCHO_LABEL" >/dev/null
echo "verified absent and removed launchagent if present: $SCHED_LABEL"
echo "verified absent and removed launchagent if present: $KEEP_LABEL"
echo "verified absent and removed launchagent if present: $GUIDE_LABEL"
echo "verified absent and removed launchagent if present: $PUBLIC_HONCHO_LABEL"
