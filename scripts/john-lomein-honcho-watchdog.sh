#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$SCRIPT_DIR/john-lomein-instance.env"
[ -f "$ENV_FILE" ] || exit 2
. "$ENV_FILE"
[ "${BOT_HONCHO_WATCHDOG_ENABLED:-0}" = "1" ] || exit 0
PY="${HERMES_PYTHON:-python3}"
exec "$PY" "$BOT_HERMES_HOME/scripts/john-lomein-honcho-watchdog.py" \
  --database "$BOT_HONCHO_DATABASE" --base-url "$BOT_HONCHO_BASE_URL" \
  --workspace "$BOT_HONCHO_WORKSPACE" --runtime-home "$BOT_HERMES_HOME" \
  --manifest "$BOT_INSTANCE_ROOT/instance.yaml" --guide-profile "$BOT_GUIDE_PROFILE" \
  --guide-label "ai.hermes.gateway-john-lomein-$BOT_SLUG-guide" \
  --supervisor-label "$BOT_HONCHO_SUPERVISOR_LABEL" \
  --server-root "$BOT_HONCHO_SERVER_ROOT" --expected-memory-model "$BOT_HONCHO_EXPECTED_MEMORY_MODEL" \
  --snapshot "$BOT_HERMES_HOME/state/honcho/watchdog-latest.json"
