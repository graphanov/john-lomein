#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$SCRIPT_DIR/john-lomein-instance.env"
[ -f "$ENV_FILE" ] || exit 0
. "$ENV_FILE"
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"
PY="${HERMES_PYTHON:-$(command -v python3)}"

set +e
out="$("$PY" "$BOT_HERMES_HOME/scripts/john-lomein-overwatch-scan.py" 2>&1)"
status=$?
set -e

# Healthy ticks stay silent. Warnings/failures are pushed to the visible bot
# notification channel via the guide profile, but only when the alert fingerprint
# changes so a stuck PR does not spam Discord every cron interval.
if [ "$status" -ne 0 ] || [[ "$out" != *"details=ok"* ]]; then
  mkdir -p "$BOT_HERMES_HOME/state/watchdogs"
  fp_file="$BOT_HERMES_HOME/state/watchdogs/${BOT_SLUG}.overwatch-alert"
  fp="$(printf '%s\n%s' "$status" "$out" | shasum -a 256 | awk '{print $1}')"
  old="$(cat "$fp_file" 2>/dev/null || true)"
  if [ "$fp" != "$old" ]; then
    printf '%s' "$fp" > "$fp_file"
    printf '%s' "$out" |
      "$BOT_HERMES_HOME/scripts/john-lomein-overwatch-post.sh" "OVERWATCH" >/dev/null || true
    printf '%s\n' "$out"
  fi
fi
exit 0
