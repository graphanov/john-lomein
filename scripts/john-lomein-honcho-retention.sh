#!/usr/bin/env bash
# No-agent scheduler entry point. The Python command owns quiescence and recovery.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$SCRIPT_DIR/john-lomein-instance.env"
[ -f "$ENV_FILE" ] || exit 2
. "$ENV_FILE"
[ "${BOT_GUIDE_GATEWAY_ENABLED:-0}" = "1" ] || exit 0
PY="${HERMES_PYTHON:-python3}"
exec "$PY" "$BOT_HERMES_HOME/scripts/john_lomein_honcho_pilot.py" retention-scheduled-run \
  --manifest "$BOT_INSTANCE_MANIFEST"
