#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$SCRIPT_DIR/john-lomein-instance.env"
[ -f "$ENV_FILE" ] || exit 0
. "$ENV_FILE"
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"
PY="${HERMES_PYTHON:-$(command -v python3)}"
# Owner-gated installs stay silent on scheduled ticks. Manual diagnostic uses john-lomein-diagnostic-tick.sh.
if [ "${BOT_MUTATION_ENABLED:-0}" != "1" ]; then
  exit 0
fi
if [ "${BOT_MISSION_COMPLETE:-0}" != "1" ]; then
  exit 0
fi
# Maintainer is for PR maintenance only. Issues are handled by the forge lane,
# and clean PRs are handled by the release-bundler owner gate. Do not spawn a
# heavyweight maintainer worker merely because open issues or already-clean PRs
# exist; that caused duplicate @codex review comments on the same reviewed head.
health="$("$PY" "$BOT_HERMES_HOME/scripts/john-lomein-queue-health.py" --json 2>/dev/null || true)"
checkout_dirty=0
if [ -n "${BOT_LOCAL:-}" ] && [ -d "$BOT_LOCAL/.git" ] && git -C "$BOT_LOCAL" status --porcelain 2>/dev/null | grep -q .; then
  checkout_dirty=1
fi
need="$(HEALTH_JSON="$health" CHECKOUT_DIRTY="$checkout_dirty" "$PY" - <<'PY'
import json, os
try:
    data = json.loads(os.environ.get('HEALTH_JSON') or '{}')
except Exception:
    data = {}
dirty = os.environ.get('CHECKOUT_DIRTY') == '1'
# Run the maintainer only when a PR/workspace needs maintainer action: draft
# promotion, failing/pending/blocked PRs, unresolved threads, missing latest-head
# Codex, or an abandoned dirty managed checkout from a previous partial worker.
# Do not run for clean_candidates (owner-gated bundle) or codex_pending_prs
# (a request is already in flight), and never run solely because ready issues exist.
needed = bool(data.get('drafts') or data.get('blockers') or data.get('failures') or data.get('codex_awaiting_prs') or dirty)
print('1' if needed else '0')
PY
)"
if [ "$need" != "1" ]; then
  exit 0
fi
fingerprint="$(HEALTH_JSON="$health" CHECKOUT_DIRTY="$checkout_dirty" "$PY" - <<'PY'
import hashlib, json, os
try:
    health = json.loads(os.environ.get("HEALTH_JSON") or "{}")
except Exception:
    health = {}
payload = {
    "health": health,
    "checkout_dirty": os.environ.get("CHECKOUT_DIRTY") == "1",
}
raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
print(hashlib.sha256(raw).hexdigest())
PY
)"
# Cron/no-agent scripts are capped by the scheduler. Detach the real worker so a
# legitimate long PR repair does not show up as a cron timeout or get killed.
"$PY" "$BOT_HERMES_HOME/scripts/john-lomein-worker.py" spawn maintainer \
  --quiet --fingerprint "maintainer:$fingerprint"
exit 0
