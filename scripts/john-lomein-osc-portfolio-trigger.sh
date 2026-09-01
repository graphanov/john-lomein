#!/usr/bin/env bash
set -euo pipefail

# Do not honor caller-supplied instance-env selector here: this cron can
# create public GitHub issues/branches/PRs, so it must source only the deployed
# env next to this deployed trigger script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$SCRIPT_DIR/john-lomein-instance.env"
[ -f "$ENV_FILE" ] || exit 0
. "$ENV_FILE"
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"
PY="${HERMES_PYTHON:-$(command -v python3)}"

# `.osc` portfolio steward is opt-in and mutating: it can open public
# issues and draft PRs with .osc backlog-plan files. Stay silent unless the
# instance explicitly enables it and mutation is enabled.
[ "${BOT_OSC_PORTFOLIO_ENABLED:-0}" = "1" ] || exit 0
[ "${BOT_MUTATION_ENABLED:-0}" = "1" ] || exit 0
[ "${BOT_MISSION_COMPLETE:-0}" = "1" ] || exit 0

"$PY" "$BOT_HERMES_HOME/scripts/john-lomein-worker.py" spawn portfolio \
  --quiet --fingerprint "portfolio:$(date -u +%Y%m%dT%H)"
exit 0
