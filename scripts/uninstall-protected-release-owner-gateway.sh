#!/bin/bash
# Remove one owner-gateway invocation boundary while preserving credentials,
# audit records, request evidence, configs, and per-instance root-owned code.
set -Eeuo pipefail

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
umask 077

usage() {
  echo "usage: uninstall-protected-release-owner-gateway.sh --slug SLUG" >&2
  exit 2
}

die() {
  echo "protected release owner gateway uninstall refused: $*" >&2
  exit 2
}

SLUG=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --slug)
      [ "$#" -ge 2 ] && [ -n "$2" ] || usage
      [ -z "$SLUG" ] || die "--slug was provided more than once"
      SLUG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ -n "$SLUG" ] || usage

[ "$(/usr/bin/id -u)" -eq 0 ] || die "root is required"
[ "$(/usr/bin/uname -s)" = "Darwin" ] ||
  die "this uninstaller currently supports macOS only"
[[ "$SLUG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] ||
  die "slug contains unsafe characters"

encode_sudoers_slug() {
  local input="$1"
  local encoded=''
  local character
  local index
  for ((index = 0; index < ${#input}; index++)); do
    character="${input:index:1}"
    case "$character" in
      [A-Za-z0-9]) encoded+="$character" ;;
      .) encoded+='_d' ;;
      _) encoded+='_u' ;;
      -) encoded+='_h' ;;
      *) die "slug could not be encoded for sudoers" ;;
    esac
  done
  printf '%s' "$encoded"
}
SUDOERS_SAFE_SLUG="$(encode_sudoers_slug "$SLUG")"

reject_acl() {
  local path="$1"
  local label="$2"
  local permissions
  permissions="$(/bin/ls -lde "$path" | /usr/bin/awk 'NR == 1 { print $1 }')" ||
    die "$label ACL could not be inspected"
  case "$permissions" in
    *+*) die "$label has an access-control list" ;;
  esac
}

SCRIPT_SOURCE="${BASH_SOURCE[0]}"
case "$SCRIPT_SOURCE" in
  /*) ;;
  *) SCRIPT_SOURCE="$PWD/$SCRIPT_SOURCE" ;;
esac
SCRIPT_DIRECTORY="$(
  cd -P "$(/usr/bin/dirname "$SCRIPT_SOURCE")" && pwd -P
)"
SCRIPT_PATH="$SCRIPT_DIRECTORY/$(/usr/bin/basename "$SCRIPT_SOURCE")"
[ -f "$SCRIPT_PATH" ] && [ ! -L "$SCRIPT_PATH" ] ||
  die "uninstaller must be a regular non-symlink file"
[ "$(/usr/bin/stat -f '%u' "$SCRIPT_PATH")" -eq 0 ] ||
  die "uninstaller must be staged as a root-owned operator asset"
SCRIPT_MODE="$(/usr/bin/stat -f '%Lp' "$SCRIPT_PATH")"
case "$SCRIPT_MODE" in
  ''|*[!0-7]*) die "uninstaller mode is invalid" ;;
esac
[ $(((8#$SCRIPT_MODE) & 0022)) -eq 0 ] ||
  die "uninstaller must not be group/other writable"
reject_acl "$SCRIPT_PATH" "uninstaller"

SUDOERS_PATH="/private/etc/sudoers.d/john-lomein-release-owner-$SUDOERS_SAFE_SLUG"
WRAPPER_PATH="/usr/local/libexec/john-lomein-release-owner-gateway-instances/$SLUG/mint"
PUBLIC_CONFIG_PATH="/private/etc/john-lomein-release-owner-gateway-public/$SLUG.json"
CONFIG_ROOT='/private/etc/john-lomein-release-owner-gateway.d'
STATE_DIR="/private/var/db/john-lomein-release-owner-gateway/state/$SLUG"
REQUEST_DIR="/private/var/db/john-lomein-release-owner-gateway/requests/$SLUG"
CODE_ROOT="/usr/local/libexec/john-lomein-release-owner-gateway-instances/$SLUG/code"

remove_root_file() {
  local path="$1"
  local label="$2"
  [ ! -L "$path" ] || die "$label is an unsafe symlink"
  [ -e "$path" ] || return 0
  [ -f "$path" ] || die "$label is not a regular file"
  [ "$(/usr/bin/stat -f '%u' "$path")" -eq 0 ] ||
    die "$label is not root owned"
  mode="$(/usr/bin/stat -f '%Lp' "$path")"
  case "$mode" in
    ''|*[!0-7]*) die "$label mode is invalid" ;;
  esac
  [ $(((8#$mode) & 0022)) -eq 0 ] ||
    die "$label is group/other writable"
  reject_acl "$path" "$label"
  /bin/rm -f "$path"
}

remove_root_file "$SUDOERS_PATH" "owner gateway sudoers policy"
remove_root_file "$WRAPPER_PATH" "owner gateway signer wrapper"
remove_root_file "$PUBLIC_CONFIG_PATH" "owner gateway public invocation config"

echo "protected release owner gateway invocation removed: $SLUG"
echo "preserved root-owned signer configs and credentials: $CONFIG_ROOT"
echo "preserved signer audit state: $STATE_DIR"
echo "preserved request evidence: $REQUEST_DIR"
echo "preserved per-instance root-owned gateway code: $CODE_ROOT"
