#!/bin/bash
# Stop/remove one protected broker LaunchDaemon without deleting durable state.
set -Eeuo pipefail

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
umask 077

usage() {
  echo "usage: uninstall-protected-broker.sh --slug SLUG" >&2
  exit 2
}

die() {
  echo "protected broker uninstall refused: $*" >&2
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
    *)
      die "unknown argument: $1"
      ;;
  esac
done
[ -n "$SLUG" ] || usage

[ "$(/usr/bin/id -u)" -eq 0 ] || die "root is required"
[ "$(/usr/bin/uname -s)" = "Darwin" ] ||
  die "this uninstaller currently supports macOS LaunchDaemons only"
[[ "$SLUG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] ||
  die "slug contains unsafe characters"

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
case "$SCRIPT_MODE" in ''|*[!0-7]*) die "uninstaller mode is invalid" ;; esac
[ $(((8#$SCRIPT_MODE) & 0022)) -eq 0 ] ||
  die "uninstaller must not be group/other writable"
reject_acl "$SCRIPT_PATH" "uninstaller"

LABEL="com.john-lomein.protected-broker.$SLUG"
PLIST_PATH="/Library/LaunchDaemons/$LABEL.plist"
DATA_ROOT='/private/var/db/john-lomein-broker'
RUN_DIR="$DATA_ROOT/run/$SLUG"
SOCKET_PATH="$RUN_DIR/broker.sock"
SOCKET_LOCK_PATH="$SOCKET_PATH.lock"
STATE_DIR="$DATA_ROOT/state/$SLUG"
CONFIG_PATH="/private/etc/john-lomein-broker.d/$SLUG.json"
PUBLIC_DIR='/private/etc/john-lomein-broker-public'
CLIENT_CONFIG_PATH="$PUBLIC_DIR/$SLUG.json"
PUBLIC_KEY_PATH="$PUBLIC_DIR/$SLUG.receipt-ed25519.pub.pem"
CODE_ROOT='/usr/local/libexec/john-lomein-protected-broker'

/bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
if [ -f "$PLIST_PATH" ]; then
  /bin/launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
fi
if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
  die "LaunchDaemon could not be verified stopped"
fi
/bin/launchctl disable "system/$LABEL"

if [ -L "$PLIST_PATH" ]; then
  die "LaunchDaemon plist is an unsafe symlink"
fi
if [ -e "$PLIST_PATH" ]; then
  [ -f "$PLIST_PATH" ] || die "LaunchDaemon plist is not a regular file"
  [ "$(/usr/bin/stat -f '%u' "$PLIST_PATH")" -eq 0 ] ||
    die "LaunchDaemon plist is not root owned"
  PLIST_MODE="$(/usr/bin/stat -f '%Lp' "$PLIST_PATH")"
  case "$PLIST_MODE" in ''|*[!0-7]*) die "LaunchDaemon mode is invalid" ;; esac
  [ $(((8#$PLIST_MODE) & 0022)) -eq 0 ] ||
    die "LaunchDaemon plist is group/other writable"
  reject_acl "$PLIST_PATH" "LaunchDaemon plist"
  /bin/rm -f "$PLIST_PATH"
fi

remove_transient() {
  local path="$1"
  local expected_kind="$2"
  local label="$3"
  [ ! -L "$path" ] || die "$label is an unsafe symlink"
  [ -e "$path" ] || return 0
  case "$expected_kind" in
    socket) [ -S "$path" ] || die "$label is not a socket" ;;
    file) [ -f "$path" ] || die "$label is not a regular file" ;;
    *) die "internal transient kind error" ;;
  esac
  reject_acl "$path" "$label"
  /bin/rm -f "$path"
}

remove_transient "$SOCKET_PATH" socket "broker socket"
remove_transient "$SOCKET_LOCK_PATH" file "broker socket lock"

echo "protected broker LaunchDaemon removed and verified absent: $LABEL"
echo "preserved durable state and private keys: $STATE_DIR"
echo "preserved installed broker config: $CONFIG_PATH"
echo "preserved public client config: $CLIENT_CONFIG_PATH"
echo "preserved public receipt key: $PUBLIC_KEY_PATH"
echo "preserved root-owned broker code: $CODE_ROOT"
