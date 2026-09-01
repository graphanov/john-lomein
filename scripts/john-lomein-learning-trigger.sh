#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$SCRIPT_DIR/john-lomein-instance.env"
[ -f "$ENV_FILE" ] || exit 0
. "$ENV_FILE"
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"
[ "${BOT_LEARNING_ENABLED:-1}" = "1" ] || exit 0

PY="${HERMES_PYTHON:-}"
if [ -z "$PY" ] || [ ! -x "$PY" ]; then
  HERMES_BIN="$(command -v hermes || true)"
  if [ -n "$HERMES_BIN" ]; then
    PY="$(dirname "$HERMES_BIN")/python3"
  fi
fi
[ -x "$PY" ] || PY="$HOME/.hermes/hermes-agent/venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
export HERMES_PYTHON="$PY"
if [ -x "$PY" ]; then
  VIRTUAL_ENV="$(cd "$(dirname "$PY")/.." 2>/dev/null && pwd || printf '')"
  PATH="$(dirname "$PY"):$PATH"
  export VIRTUAL_ENV PATH
fi

if [ "${BOT_MODEL_MEMORY_ISOLATION:-}" != "required" ]; then
  echo "learning steward refused: required model-memory isolation is not deployed" >&2
  exit 78
fi
expected_private="$BOT_HERMES_HOME/private/learning-steward"
[ "${BOT_STEWARD_PRIVATE_ROOT:-}" = "$expected_private" ] || {
  echo "learning steward refused: non-canonical private root" >&2
  exit 78
}
export MNEMOSYNE_DATA_DIR="$BOT_STEWARD_PRIVATE_ROOT/mnemosyne/data"
set +e
out="$("$PY" "$BOT_HERMES_HOME/scripts/john-lomein-learning-steward.py" reconcile --mode scheduled --json 2>&1)"
status=$?
set -e

# Healthy scheduled learning ticks stay silent. Cron/no-agent will deliver this
# output only on failure so memory-learning breakage is visible but not noisy.
if [ "$status" -ne 0 ]; then
  printf '%s\n' "$out"
fi
exit "$status"
