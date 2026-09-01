#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$SCRIPT_DIR/john-lomein-instance.env"
[ -f "$ENV_FILE" ] || exit 0
. "$ENV_FILE"
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"
PY="${HERMES_PYTHON:-$(command -v python3)}"
# Silent while owner-gated; manual Forge runs synchronously through the worker.
[ "${BOT_MUTATION_ENABLED:-0}" = "1" ] || exit 0
[ "${BOT_MISSION_COMPLETE:-0}" = "1" ] || exit 0

# Reconcile configured labels and mark unlabeled issues for triage before the
# queue-health spawn decision. This helper never grants readiness; only the
# authenticated external intake-broker route may enqueue public suggestions.
"$PY" "$BOT_HERMES_HOME/scripts/john-lomein-issue-triage.py" --json >/dev/null 2>&1 || true

# Do not launch the forge lane just because ready labels exist. The forge shares
# the managed checkout with the maintainer lane and cannot create useful PRs
# while the PR queue is full or blocked. Heavy candidate/coverage checks still
# live inside the orchestrator; this cron gate prevents pointless wake/sleep
# loops when maintainer must drain existing PRs first.
health="$("$PY" "$BOT_HERMES_HOME/scripts/john-lomein-queue-health.py" --json 2>/dev/null || true)"
need="$(HEALTH_JSON="$health" MAX_TOTAL="${BOT_MAX_OPEN_TOTAL_PRS:-4}" "$PY" - <<'PY'
import json, os
try:
    data = json.loads(os.environ.get('HEALTH_JSON') or '{}')
except Exception:
    data = {}
max_total = int(os.environ.get('MAX_TOTAL') or 4)
open_prs = int(data.get('open_prs') or 0)
ready = bool(data.get('retry_due_issues') or data.get('ready_issues'))
action_board = data.get('action_board') or {}
blocked_pr_queue = bool(action_board.get('automation_blocker') or data.get('failures'))
capacity_available = open_prs < max_total
print('1' if ready and capacity_available and not blocked_pr_queue else '0')
PY
)"
if [ "$need" != "1" ]; then
  exit 0
fi
fingerprint="$(HEALTH_JSON="$health" "$PY" - <<'PY'
import hashlib, json, os
try:
    health = json.loads(os.environ.get("HEALTH_JSON") or "{}")
except Exception:
    health = {}
raw = json.dumps(health, sort_keys=True, separators=(",", ":")).encode()
print(hashlib.sha256(raw).hexdigest())
PY
)"
# Detach real forge work. Capacity/no-duplicate checks happen inside the orchestrator.
"$PY" "$BOT_HERMES_HOME/scripts/john-lomein-worker.py" spawn forge \
  --quiet --fingerprint "forge:$fingerprint"
exit 0
