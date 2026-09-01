#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  printf '%s\n' 'macOS clean-machine check must run on Darwin' >&2
  exit 2
fi

for command in git make uv python3; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'missing prerequisite: %s\n' "$command" >&2
    exit 2
  }
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CLEANUP_WITH_SUDO=0
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  command -v /usr/bin/sudo >/dev/null 2>&1
  TEMP_ROOT="$(/usr/bin/sudo /usr/bin/mktemp -d /private/var/lib/jlcm.XXXXXX)"
  /usr/bin/sudo /usr/sbin/chown "$(id -u):$(id -g)" "$TEMP_ROOT"
  CLEANUP_WITH_SUDO=1
else
  SAFE_TMPDIR="${TMPDIR:-$(getconf DARWIN_USER_TEMP_DIR)}"
  SAFE_TMPDIR="$(cd "$SAFE_TMPDIR" && pwd -P)"
  TEMP_ROOT="$(mktemp -d "$SAFE_TMPDIR/jlcm.XXXXXX")"
  chgrp "$(id -g)" "$TEMP_ROOT"
fi
/bin/chmod -N "$TEMP_ROOT"
chmod 700 "$TEMP_ROOT"
cleanup() {
  if [[ "$CLEANUP_WITH_SUDO" -eq 1 ]]; then
    /usr/bin/sudo /bin/rm -rf -- "$TEMP_ROOT"
  else
    rm -rf "$TEMP_ROOT"
  fi
}
trap cleanup EXIT INT TERM

mkdir -p "$TEMP_ROOT/home" "$TEMP_ROOT/cache" "$TEMP_ROOT/tmp" "$TEMP_ROOT/venv"

CLEAN_PATH="$PATH"
env -i \
  HOME="$TEMP_ROOT/home" \
  PATH="$CLEAN_PATH" \
  TMPDIR="$TEMP_ROOT/tmp" \
  LANG="${LANG:-en_US.UTF-8}" \
  LC_ALL="${LC_ALL:-en_US.UTF-8}" \
  CI=true \
  UV_CACHE_DIR="$TEMP_ROOT/cache" \
  UV_NO_SYSTEM_CONFIG=1 \
  UV_PYTHON=3.11 \
  UV_PROJECT_ENVIRONMENT="$TEMP_ROOT/venv" \
  PYTHONHASHSEED=0 \
  make -C "$ROOT" verify

printf '%s\n' 'macOS clean-machine verification passed'
