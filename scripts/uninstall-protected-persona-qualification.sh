#!/bin/bash
# Remove one protected persona-qualification invocation surface.
#
# Durable identities, keys, configs, signed archives, public proof, activation
# history, and content-addressed bundles are deliberately preserved.
set -Eeuo pipefail

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
umask 077

usage() {
  echo \
    "usage: uninstall-protected-persona-qualification.sh --slug SLUG" \
    >&2
  exit 2
}

die() {
  echo "protected persona qualification uninstall refused: $*" >&2
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
[[ "$SLUG" =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]] ||
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

validate_root_directory_chain() {
  local path="$1"
  local label="$2"
  local current="$path"
  local mode
  while true; do
    [ -d "$current" ] && [ ! -L "$current" ] ||
      die "$label has an unsafe ancestor"
    [ "$(/usr/bin/stat -f '%u' "$current")" -eq 0 ] ||
      die "$label has a non-root-owned ancestor"
    mode="$(/usr/bin/stat -f '%Lp' "$current")"
    case "$mode" in ''|*[!0-7]*) die "$label ancestor mode is invalid" ;; esac
    [ $(((8#$mode) & 0022)) -eq 0 ] ||
      die "$label has a group/other-writable ancestor"
    reject_acl "$current" "$label"
    [ "$current" = "/" ] && break
    current="$(/usr/bin/dirname "$current")"
  done
}

validate_root_file() {
  local path="$1"
  local label="$2"
  local mode
  [ -f "$path" ] && [ ! -L "$path" ] ||
    die "$label is not a regular non-symlink file"
  [ "$(/usr/bin/stat -f '%u' "$path")" -eq 0 ] ||
    die "$label is not root owned"
  [ "$(/usr/bin/stat -f '%l' "$path")" -eq 1 ] ||
    die "$label is hard linked"
  mode="$(/usr/bin/stat -f '%Lp' "$path")"
  case "$mode" in ''|*[!0-7]*) die "$label mode is invalid" ;; esac
  [ $(((8#$mode) & 0022)) -eq 0 ] ||
    die "$label is group/other writable"
  reject_acl "$path" "$label"
  validate_root_directory_chain "$(/usr/bin/dirname "$path")" "$label"
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
validate_root_file "$SCRIPT_PATH" "uninstaller"

GLOBAL_INSTALL_LOCK='/private/var/run/john-lomein-persona-qualification.install.lock'
validate_root_directory_chain /private/var/run "uninstaller lock root"
exec 9>"$GLOBAL_INSTALL_LOCK"
validate_root_file "$GLOBAL_INSTALL_LOCK" "uninstaller lock"
/usr/bin/lockf -t 0 9 ||
  die "another persona qualification install or uninstall is running"

INSTANCE_ID="$(
  /usr/bin/printf '%s' "$SLUG" |
    /usr/bin/shasum -a 256 |
    /usr/bin/awk '{ print substr($1, 1, 12) }'
)"
[[ "$INSTANCE_ID" =~ ^[0-9a-f]{12}$ ]] ||
  die "derived instance identity is invalid"
SIGNER_USER="_jlqs_$INSTANCE_ID"
CAPTURE_USER="_jlqc_$INSTANCE_ID"
VERIFIER_USER="_jlqv_$INSTANCE_ID"
EXPORT_GROUP="_jlqe_$INSTANCE_ID"

LABEL="com.john-lomein.persona-qualification.$SLUG"
PLIST_PATH="/Library/LaunchDaemons/$LABEL.plist"
INSTANCE_CODE_DIR="/usr/local/libexec/john-lomein-persona-qualification-instances/$SLUG"
ATTEST_WRAPPER_PATH="$INSTANCE_CODE_DIR/attest"
TRUST_WRAPPER_PATH="$INSTANCE_CODE_DIR/trust"
DOCTOR_WRAPPER_PATH="$INSTANCE_CODE_DIR/doctor"
PUBLIC_TRUST_COMMAND="/usr/local/bin/john-lomein-persona-trust-$SLUG"
PUBLIC_DOCTOR_COMMAND="/usr/local/bin/john-lomein-persona-qualification-doctor-$SLUG"

CONFIG_ROOT='/private/etc/john-lomein-persona-qualification.d'
INSTANCE_CONFIG_DIR="$CONFIG_ROOT/$SLUG"
PUBLIC_ROOT='/private/etc/john-lomein-persona-qualification-public'
INSTANCE_PUBLIC_DIR="$PUBLIC_ROOT/$SLUG"
DATA_ROOT='/private/var/db/john-lomein-persona-qualification'
INSTANCE_DATA_DIR="$DATA_ROOT/$SLUG"
BUNDLES_ROOT='/usr/local/libexec/john-lomein-persona-qualification/bundles'

if [ -e "$PLIST_PATH" ] || [ -L "$PLIST_PATH" ]; then
  validate_root_file "$PLIST_PATH" "qualification LaunchDaemon plist"
fi
/bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
if [ -f "$PLIST_PATH" ] && [ ! -L "$PLIST_PATH" ]; then
  /bin/launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
fi
if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
  die "qualification LaunchDaemon could not be verified stopped"
fi
/bin/launchctl disable "system/$LABEL"

remove_root_file() {
  local path="$1"
  local label="$2"
  [ ! -L "$path" ] || die "$label is an unsafe symlink"
  [ -e "$path" ] || return 0
  validate_root_file "$path" "$label"
  /bin/rm -f "$path"
}

remove_root_file "$PLIST_PATH" "qualification LaunchDaemon plist"
remove_root_file "$ATTEST_WRAPPER_PATH" "qualification attestor wrapper"
remove_root_file "$TRUST_WRAPPER_PATH" "qualification trust wrapper"
remove_root_file "$DOCTOR_WRAPPER_PATH" "qualification Doctor wrapper"
remove_root_file "$PUBLIC_TRUST_COMMAND" "qualification public trust command"
remove_root_file "$PUBLIC_DOCTOR_COMMAND" \
  "qualification public Doctor command"

echo "protected persona qualification invocation removed: $SLUG"
echo "preserved service identities: $SIGNER_USER $CAPTURE_USER $VERIFIER_USER"
echo "preserved evidence export group: $EXPORT_GROUP"
echo "preserved configs, keys, manifests, and activation history: $INSTANCE_CONFIG_DIR"
echo "preserved signed archive and raw-state namespace: $INSTANCE_DATA_DIR"
echo "preserved public key, pin, policy, and trust projection: $INSTANCE_PUBLIC_DIR"
echo "preserved content-addressed role bundles: $BUNDLES_ROOT"
