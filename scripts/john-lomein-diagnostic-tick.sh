#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$SCRIPT_DIR/john-lomein-instance.env"
[ -f "$ENV_FILE" ] || { echo "missing env file: $ENV_FILE" >&2; exit 1; }
. "$ENV_FILE"
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"
cd "$BOT_LOCAL"
branch="$(git branch --show-current 2>/dev/null || true)"
status="$(git status --short --branch 2>/dev/null | head -1 || true)"
remote_oid="$(git ls-remote --heads origin "refs/heads/${BOT_DEFAULT_BRANCH}" 2>/dev/null | awk 'NR == 1 { print $1 }' || true)"
tracking_oid="$(git rev-parse "refs/remotes/origin/${BOT_DEFAULT_BRANCH}" 2>/dev/null || true)"
if [[ "$remote_oid" =~ ^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$ ]] && \
  [ "$remote_oid" = "$tracking_oid" ]
then
  tracking_fresh=1
  fresh="$(git rev-list --left-right --count "HEAD...refs/remotes/origin/${BOT_DEFAULT_BRANCH}" 2>/dev/null || echo '? ?')"
else
  tracking_fresh=0
  fresh="? ?"
fi
prs="$(gh pr list --repo "$BOT_REPO" --state open --json number --jq 'length' 2>/dev/null || echo '?')"
issues="$(gh issue list --repo "$BOT_REPO" --state open --json number --jq 'length' 2>/dev/null || echo '?')"
echo "john-lomein diagnostic: instance=$BOT_SLUG repo=$BOT_REPO branch=$branch status=[$status] tracking_fresh=$tracking_fresh ahead_behind=[$fresh] open_prs=$prs open_issues=$issues mutation_enabled=$BOT_MUTATION_ENABLED"
