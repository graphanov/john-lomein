#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$SCRIPT_DIR/john-lomein-instance.env"
[ -f "$ENV_FILE" ] || exit 0
. "$ENV_FILE"
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"
if [ "${BOT_MODEL_PROVIDER:-}" = "openai-codex" ] || [ "${BOT_FALLBACK_PROVIDER:-}" = "openai-codex" ]; then
  "$HERMES_PYTHON" "$BOT_HERMES_HOME/scripts/john_lomein_auth_projection.py" scrub \
    --runtime-home "$BOT_HERMES_HOME" \
    --provider openai-codex \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_MAINTAINER_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_FORGE_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_GUIDE_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_OVERWATCH_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_LEARNING_STEWARD_PROFILE" \
    --quiet
fi
mkdir -p "$BOT_HERMES_HOME/state/watchdogs"
fp_file="$BOT_HERMES_HOME/state/watchdogs/${BOT_SLUG}.fingerprint"
json="$( (gh pr list --repo "$BOT_REPO" --state open --json number,title,headRefName,updatedAt 2>/dev/null; gh issue list --repo "$BOT_REPO" --state open --json number,title,labels,updatedAt 2>/dev/null) | shasum -a 256 | awk '{print $1}' )"
old="$(cat "$fp_file" 2>/dev/null || true)"
if [ "$json" != "$old" ]; then
  printf '%s' "$json" > "$fp_file"
  prs="$(gh pr list --repo "$BOT_REPO" --state open --json number --jq 'length' 2>/dev/null || echo '?')"
  issues="$(gh issue list --repo "$BOT_REPO" --state open --json number --jq 'length' 2>/dev/null || echo '?')"
  msg="WATCHDOG_STATE_CHANGE instance=$BOT_SLUG repo=$BOT_REPO open_prs=$prs open_issues=$issues mutation_enabled=$BOT_MUTATION_ENABLED"
  printf '%s' "$msg" |
    "$BOT_HERMES_HOME/scripts/john-lomein-overwatch-post.sh" "WATCHDOG" >/dev/null || true
  echo "$msg"
fi
