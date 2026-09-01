#!/usr/bin/env bash
set -euo pipefail

label="${1:-OVERWATCH}"
if [ "$#" -ge 2 ]; then
  body="${2:-}"
else
  body="$(cat)"
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$SCRIPT_DIR/john-lomein-instance.env"
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
[ -n "${BOT_HERMES_HOME:-}" ] && [ -f "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh" ] && . "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"

PUBLIC_PYTHON="/usr/bin/python3"
if [ ! -x "$PUBLIC_PYTHON" ]; then
  PUBLIC_PYTHON="$(PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" command -v python3 || true)"
fi
if [ -z "$PUBLIC_PYTHON" ] || [ ! -x "$PUBLIC_PYTHON" ]; then
  body="[notification redaction unavailable]"
elif ! body="$(
  printf '%s' "$body" |
    "$PUBLIC_PYTHON" "$SCRIPT_DIR/john_lomein_public_safety.py" sanitize --max-chars 1650
)"; then
  body="[notification redaction failed]"
fi

message="[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ${BOT_DISPLAY_NAME:-john-lomein} ${label}: ${body}"

# Keep Discord notifications inside the normal 2k character limit. This is a
# signal channel, not a raw log sink.
if [ ${#message} -gt 1800 ]; then
  message="${message:0:1760}… [truncated]"
fi

target="${BOT_NOTIFICATION_TARGET:-}"
if [ -z "$target" ] && [ -n "${BOT_NOTIFICATIONS_CHANNEL:-}" ]; then
  target="discord:${BOT_NOTIFICATIONS_CHANNEL}"
fi

if [ "${JOHN_LOMEIN_NOTIFY_DRY_RUN:-0}" = "1" ]; then
  echo "dry-run notify ${target:-stdout}: $label"
  exit 0
fi

resolve_hermes_cmd() {
  local hermes_bin="${HERMES_BIN:-}"
  if [ -z "$hermes_bin" ]; then
    hermes_bin="$(command -v hermes || true)"
  fi
  if [ -n "$hermes_bin" ] && [ -x "$hermes_bin" ]; then
    printf '%s\n' "$hermes_bin"
    return 0
  fi
  local real_home="${HERMES_REAL_HOME:-${BOT_REAL_HOME:-}}"
  if [ -z "$real_home" ] && [[ "${BOT_HERMES_HOME:-}" == */.john-lomein/instances/*/hermes ]]; then
    real_home="${BOT_HERMES_HOME%%/.john-lomein/instances/*/hermes}"
  fi
  [ -n "$real_home" ] || real_home="${HOME:-}"
  for py in "${HERMES_PYTHON:-}" "$real_home/.hermes/hermes-agent/venv/bin/python3" "$real_home/.hermes/hermes-agent/venv/bin/python" "$(command -v python3 || true)"; do
    [ -n "$py" ] || continue
    if [ -x "$py" ] && "$py" -c 'import hermes_cli.main' >/dev/null 2>&1; then
      printf '%s\n' "$py -m hermes_cli.main"
      return 0
    fi
  done
  return 1
}

if [ "${BOT_DISCORD_ENABLED:-0}" = "1" ] && [ -n "$target" ] && [ -n "${BOT_HERMES_HOME:-}" ]; then
  cmd="$(resolve_hermes_cmd || true)"
  if [ -n "$cmd" ]; then
    # shellcheck disable=SC2086 # cmd intentionally may be: python -m hermes_cli.main
    if HERMES_HOME="$BOT_HERMES_HOME" \
       HERMES_MANAGED_DIR="${BOT_HERMES_MANAGED_ROOT:-$BOT_HERMES_HOME/managed-policy}/${BOT_GUIDE_PROFILE:-john-lomein-guide}" \
       JOHN_LOMEIN_INSTANCE_HERMES_HOME="$BOT_HERMES_HOME" \
       PATH="${PATH:-}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
       $cmd --profile "${BOT_GUIDE_PROFILE:-john-lomein-guide}" send --to "$target" --quiet "$message"; then
      echo "notified $target: $label"
      exit 0
    fi
  fi
fi

echo "$message"
