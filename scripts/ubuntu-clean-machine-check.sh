#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  printf '%s\n' 'Ubuntu clean-machine check must run on Linux' >&2
  exit 2
fi

for command in git make uv /usr/bin/sudo /usr/bin/mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'missing prerequisite: %s\n' "$command" >&2
    exit 2
  }
done

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SECURE_ROOT="$(/usr/bin/sudo /usr/bin/mktemp -d /var/lib/john-lomein-ci.XXXXXX)"
case "$SECURE_ROOT" in
  /var/lib/john-lomein-ci.*) ;;
  *)
    printf '%s\n' 'secure CI root is outside the fixed /var/lib namespace' >&2
    exit 2
    ;;
esac
cleanup() {
  /usr/bin/sudo /bin/rm -rf -- "$SECURE_ROOT"
}
trap cleanup EXIT INT TERM

/usr/bin/sudo /usr/bin/chown "$(id -u):$(id -g)" "$SECURE_ROOT"
chmod 700 "$SECURE_ROOT"
git clone --quiet --no-local --no-hardlinks "$SOURCE_ROOT" "$SECURE_ROOT/source"
mkdir -m 700 "$SECURE_ROOT/home" "$SECURE_ROOT/tmp" "$SECURE_ROOT/cache"

CLEAN_PATH="$PATH"
env -i \
  HOME="$SECURE_ROOT/home" \
  PATH="$CLEAN_PATH" \
  TMPDIR="$SECURE_ROOT/tmp" \
  LANG="${LANG:-C.UTF-8}" \
  LC_ALL="${LC_ALL:-C.UTF-8}" \
  CI=true \
  UV_CACHE_DIR="$SECURE_ROOT/cache" \
  UV_NO_SYSTEM_CONFIG=1 \
  UV_PYTHON=3.11 \
  UV_PROJECT_ENVIRONMENT="$SECURE_ROOT/venv" \
  PYTHONHASHSEED=0 \
  make -C "$SECURE_ROOT/source" verify

printf '%s\n' 'Ubuntu clean-machine verification passed'
