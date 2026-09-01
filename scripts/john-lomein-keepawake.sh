#!/usr/bin/env bash
# Generic john-lomein instance keep-awake loop.
# Holds a macOS power assertion while on AC power so Hermes gateways/schedulers
# can keep running while the machine is idle. Display sleep is still allowed.
set -u

SLEEP_ON_AC="${JOHN_LOMEIN_KEEPAWAKE_AC_POLL:-60}"
SLEEP_ON_BATTERY="${JOHN_LOMEIN_KEEPAWAKE_BATTERY_POLL:-60}"
RUNTIME_HOME="${JOHN_LOMEIN_INSTANCE_HERMES_HOME:-${JOHN_LOMEIN_HERMES_HOME:-${HERMES_HOME:-$HOME/.john-lomein/instance/hermes}}}"
LOG_DIR="$RUNTIME_HOME/logs"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/john-lomein-keepawake.log"
last_state=""
caffeinate_pid=""

log_state() {
  local state="$1"
  if [ "$state" != "$last_state" ]; then
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$state" >> "$LOG"
    last_state="$state"
  fi
}

is_ac_power() {
  /usr/bin/pmset -g batt 2>/dev/null | /usr/bin/head -1 | /usr/bin/grep -q "AC Power"
}

caffeinate_alive() {
  [ -n "${caffeinate_pid:-}" ] && /bin/kill -0 "$caffeinate_pid" 2>/dev/null
}

start_caffeinate() {
  if caffeinate_alive; then
    return 0
  fi
  /usr/bin/caffeinate -s -i 2>>"$LOG" &
  caffeinate_pid="$!"
  log_state "AC power detected; holding PreventSystemSleep/PreventUserIdleSystemSleep assertion pid=$caffeinate_pid"
}

stop_caffeinate() {
  if caffeinate_alive; then
    /bin/kill "$caffeinate_pid" 2>/dev/null || true
    wait "$caffeinate_pid" 2>/dev/null || true
  fi
  caffeinate_pid=""
}

cleanup() { stop_caffeinate; }
trap cleanup EXIT INT TERM

while true; do
  if is_ac_power; then
    start_caffeinate
    /bin/sleep "$SLEEP_ON_AC"
  else
    stop_caffeinate
    log_state "battery power detected; not preventing idle sleep"
    /bin/sleep "$SLEEP_ON_BATTERY"
  fi
done
