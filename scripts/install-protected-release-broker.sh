#!/bin/bash
# Install one isolated macOS LaunchDaemon for the protected release broker.
#
# SECURITY MODEL
# This operator-only installer must itself run from a root-owned source
# snapshot. The release broker has a dedicated OS identity, GitHub App,
# socket, database, keys, and LaunchDaemon; it deliberately shares none of
# those authority-bearing assets with the routine protected-action broker.
set -Eeuo pipefail

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
PYTHONDONTWRITEBYTECODE=1
export PYTHONDONTWRITEBYTECODE
umask 077

usage() {
  cat >&2 <<'EOF'
usage:
  install-protected-release-broker.sh \
    --slug SLUG \
    --config /absolute/root-owned/release-broker.json \
    --github-app-private-key /absolute/secure/github-app.pem \
    --owner-assertion-public-key /absolute/secure/owner-ed25519.pub.pem \
    --receipt-private-key /absolute/secure/receipt-ed25519.pem \
    --receipt-public-key /absolute/secure/receipt-ed25519.pub.pem \
    --python /absolute/root-owned/python3 \
    --broker-user EXISTING_USER \
    --requester-user EXISTING_USER \
    --submit-group EXISTING_GROUP

The installer, release-broker source, supplied Python runtime, and their
ancestor chains must be root controlled. cryptography 49.0.0 must already be
installed in the supplied isolated Python runtime.

The installed code root is shared by all protected-release-broker instances.
This installer refuses to replace it while another release broker is loaded.
EOF
  exit 2
}

die() {
  echo "protected release broker install refused: $*" >&2
  exit 2
}

require_value() {
  [ "$#" -ge 2 ] || usage
  [ -n "$2" ] || die "$1 requires a non-empty value"
}

SLUG=''
CONFIG_SOURCE=''
GITHUB_KEY_SOURCE=''
OWNER_PUBLIC_SOURCE=''
RECEIPT_PRIVATE_SOURCE=''
RECEIPT_PUBLIC_SOURCE=''
PYTHON=''
BROKER_USER=''
REQUESTER_USER=''
SUBMIT_GROUP=''

while [ "$#" -gt 0 ]; do
  case "$1" in
    --slug)
      require_value "$@"
      [ -z "$SLUG" ] || die "--slug was provided more than once"
      SLUG="$2"
      shift 2
      ;;
    --config)
      require_value "$@"
      [ -z "$CONFIG_SOURCE" ] || die "--config was provided more than once"
      CONFIG_SOURCE="$2"
      shift 2
      ;;
    --github-app-private-key)
      require_value "$@"
      [ -z "$GITHUB_KEY_SOURCE" ] ||
        die "--github-app-private-key was provided more than once"
      GITHUB_KEY_SOURCE="$2"
      shift 2
      ;;
    --owner-assertion-public-key)
      require_value "$@"
      [ -z "$OWNER_PUBLIC_SOURCE" ] ||
        die "--owner-assertion-public-key was provided more than once"
      OWNER_PUBLIC_SOURCE="$2"
      shift 2
      ;;
    --receipt-private-key)
      require_value "$@"
      [ -z "$RECEIPT_PRIVATE_SOURCE" ] ||
        die "--receipt-private-key was provided more than once"
      RECEIPT_PRIVATE_SOURCE="$2"
      shift 2
      ;;
    --receipt-public-key)
      require_value "$@"
      [ -z "$RECEIPT_PUBLIC_SOURCE" ] ||
        die "--receipt-public-key was provided more than once"
      RECEIPT_PUBLIC_SOURCE="$2"
      shift 2
      ;;
    --python)
      require_value "$@"
      [ -z "$PYTHON" ] || die "--python was provided more than once"
      PYTHON="$2"
      shift 2
      ;;
    --broker-user)
      require_value "$@"
      [ -z "$BROKER_USER" ] ||
        die "--broker-user was provided more than once"
      BROKER_USER="$2"
      shift 2
      ;;
    --requester-user)
      require_value "$@"
      [ -z "$REQUESTER_USER" ] ||
        die "--requester-user was provided more than once"
      REQUESTER_USER="$2"
      shift 2
      ;;
    --submit-group)
      require_value "$@"
      [ -z "$SUBMIT_GROUP" ] ||
        die "--submit-group was provided more than once"
      SUBMIT_GROUP="$2"
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

for required in \
  SLUG CONFIG_SOURCE GITHUB_KEY_SOURCE OWNER_PUBLIC_SOURCE \
  RECEIPT_PRIVATE_SOURCE RECEIPT_PUBLIC_SOURCE PYTHON BROKER_USER \
  REQUESTER_USER SUBMIT_GROUP
do
  eval "required_value=\${$required}"
  [ -n "$required_value" ] || usage
done

[ "$(/usr/bin/id -u)" -eq 0 ] ||
  die "root is required; run only from a root-controlled source snapshot"
[ "$(/usr/bin/uname -s)" = "Darwin" ] ||
  die "this installer currently supports macOS LaunchDaemons only"

[[ "$SLUG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] ||
  die "slug contains unsafe characters"
[[ "$BROKER_USER" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,63}$ ]] ||
  die "broker user name contains unsafe characters"
[[ "$REQUESTER_USER" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,63}$ ]] ||
  die "requester user name contains unsafe characters"
[[ "$SUBMIT_GROUP" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,63}$ ]] ||
  die "submit group name contains unsafe characters"

BROKER_UID="$(/usr/bin/id -u "$BROKER_USER" 2>/dev/null)" ||
  die "broker user does not exist: $BROKER_USER"
REQUESTER_UID="$(/usr/bin/id -u "$REQUESTER_USER" 2>/dev/null)" ||
  die "requester user does not exist: $REQUESTER_USER"
BROKER_PRIMARY_GID="$(/usr/bin/id -g "$BROKER_USER" 2>/dev/null)" ||
  die "broker primary group is unavailable"
BROKER_PRIMARY_GROUP="$(/usr/bin/id -gn "$BROKER_USER" 2>/dev/null)" ||
  die "broker primary group is unavailable"
SUBMIT_GID="$(
  /usr/bin/dscl . -read "/Groups/$SUBMIT_GROUP" PrimaryGroupID 2>/dev/null |
    /usr/bin/awk 'NR == 1 { print $2 }'
)"

for resolved_id in \
  "$BROKER_UID" "$REQUESTER_UID" "$BROKER_PRIMARY_GID" "$SUBMIT_GID"
do
  case "$resolved_id" in
    ''|*[!0-9]*) die "resolved UID/GID values are invalid" ;;
  esac
done
[ "$BROKER_UID" -gt 0 ] || die "broker user must not be root"
[ "$REQUESTER_UID" -gt 0 ] || die "requester user must not be root"
[ "$BROKER_PRIMARY_GID" -gt 0 ] ||
  die "broker primary group must not be the root group"
[ "$SUBMIT_GID" -gt 0 ] || die "submit group must not be the root group"
[ "$BROKER_UID" -ne "$REQUESTER_UID" ] ||
  die "broker and requester must be different OS identities"
[ "$BROKER_PRIMARY_GID" -ne "$SUBMIT_GID" ] ||
  die "broker private-key group and submit group must differ"
[[ "$BROKER_PRIMARY_GROUP" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,63}$ ]] ||
  die "broker primary group name is unsafe"

user_has_gid() {
  local user="$1"
  local wanted="$2"
  local candidate
  for candidate in $(/usr/bin/id -G "$user"); do
    [ "$candidate" = "$wanted" ] && return 0
  done
  return 1
}

user_has_gid "$BROKER_USER" "$SUBMIT_GID" ||
  die "broker user must belong to submit group $SUBMIT_GROUP"
user_has_gid "$REQUESTER_USER" "$SUBMIT_GID" ||
  die "requester user must belong to submit group $SUBMIT_GROUP"
if user_has_gid "$REQUESTER_USER" "$BROKER_PRIMARY_GID"; then
  die "requester user must not belong to the broker private-key group"
fi
DIRECTORY_USERS="$(/usr/bin/dscl . -list /Users)" ||
  die "local user directory could not be enumerated"
while IFS= read -r candidate_user; do
  [ -n "$candidate_user" ] || continue
  [ "$candidate_user" = "$BROKER_USER" ] && continue
  candidate_uid="$(/usr/bin/id -u "$candidate_user" 2>/dev/null)" ||
    continue
  [ "$candidate_uid" -eq 0 ] && continue
  if user_has_gid "$candidate_user" "$BROKER_PRIMARY_GID"; then
    die \
      "broker private-key group must be dedicated to the broker OS identity"
  fi
done <<<"$DIRECTORY_USERS"
unset DIRECTORY_USERS

contains_control_character() {
  case "$1" in
    *$'\n'*|*$'\r'*|*$'\t'*) return 0 ;;
  esac
  return 1
}

validate_lexical_absolute_path() {
  local path="$1"
  local label="$2"
  case "$path" in
    /*) ;;
    *) die "$label must be an absolute path" ;;
  esac
  contains_control_character "$path" &&
    die "$label contains a control character"
  [ "$path" = "/" ] || [ "${path%/}" = "$path" ] ||
    die "$label must not end with a slash"
  case "$path" in
    *//*|*/./*|*/../*|*/.|*/..)
      die "$label must be lexically normalized"
      ;;
  esac
}

uid_is_allowed() {
  local actual="$1"
  local allowed_csv="$2"
  case ",$allowed_csv," in
    *",$actual,"*) return 0 ;;
  esac
  return 1
}

mode_value() {
  local mode="$1"
  case "$mode" in
    ''|*[!0-7]*) die "could not parse filesystem permissions" ;;
  esac
  echo $((8#$mode))
}

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

validate_existing_path() {
  local path="$1"
  local allowed_uids="$2"
  local final_kind="$3"
  local label="$4"
  local current="$path"
  local uid mode numeric

  validate_lexical_absolute_path "$path" "$label"
  [ ! -L "$path" ] || die "$label must not be a symlink"
  [ -e "$path" ] || die "$label does not exist"
  case "$final_kind" in
    file) [ -f "$path" ] || die "$label must be a regular file" ;;
    executable)
      if [ ! -f "$path" ] || [ ! -x "$path" ]; then
        die "$label must be an executable regular file"
      fi
      ;;
    directory) [ -d "$path" ] || die "$label must be a directory" ;;
    any) ;;
    *) die "internal path-kind error for $label" ;;
  esac

  while :; do
    [ ! -L "$current" ] || die "$label has a symlink in its path"
    [ -e "$current" ] || die "$label has a missing path component"
    uid="$(/usr/bin/stat -f '%u' "$current")" ||
      die "$label ownership could not be inspected"
    uid_is_allowed "$uid" "$allowed_uids" ||
      die "$label has an untrusted owner in its path"
    mode="$(/usr/bin/stat -f '%Lp' "$current")" ||
      die "$label permissions could not be inspected"
    numeric="$(mode_value "$mode")"
    [ $((numeric & 0022)) -eq 0 ] ||
      die "$label has a group/other-writable path component"
    reject_acl "$current" "$label"
    [ "$current" = "/" ] && break
    current="$(/usr/bin/dirname "$current")"
  done
}

validate_runtime_path() {
  local path="$1"
  local label="$2"
  local parent
  [ -n "$path" ] || return 0
  validate_lexical_absolute_path "$path" "$label"
  if [ -e "$path" ] || [ -L "$path" ]; then
    validate_existing_path "$path" 0 any "$label"
    if [ -d "$path" ]; then
      while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        validate_existing_path "$candidate" 0 any "$label runtime tree"
      done < <(/usr/bin/find -x "$path" -print)
    fi
    return 0
  fi
  parent="$path"
  while [ ! -e "$parent" ] && [ "$parent" != "/" ]; do
    parent="$(/usr/bin/dirname "$parent")"
  done
  validate_existing_path "$parent" 0 directory "$label nearest parent"
}

validate_root_owned_tree() {
  local root="$1"
  local label="$2"
  local candidate
  validate_existing_path "$root" 0 directory "$label"
  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    validate_existing_path "$candidate" 0 any "$label"
  done < <(/usr/bin/find -x "$root" -print)
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
PRODUCT_ROOT="$(cd -P "$SCRIPT_DIRECTORY/.." && pwd -P)"
SOURCE_BROKER_DIR="$PRODUCT_ROOT/release_broker"

validate_existing_path "$SCRIPT_PATH" 0 file "installer script"
validate_root_owned_tree "$SOURCE_BROKER_DIR" "release broker source"
validate_existing_path "$PYTHON" 0 executable "release broker Python interpreter"
validate_existing_path "$CONFIG_SOURCE" 0 file "release broker config source"
validate_existing_path \
  "$GITHUB_KEY_SOURCE" 0 file "GitHub App key source"
validate_existing_path \
  "$OWNER_PUBLIC_SOURCE" 0 file \
  "owner assertion public-key source"
validate_existing_path \
  "$RECEIPT_PRIVATE_SOURCE" 0 file \
  "receipt private-key source"
validate_existing_path \
  "$RECEIPT_PUBLIC_SOURCE" 0 file \
  "receipt public-key source"

for private_source in "$GITHUB_KEY_SOURCE" "$RECEIPT_PRIVATE_SOURCE"; do
  private_mode="$(/usr/bin/stat -f '%Lp' "$private_source")"
  private_numeric="$(mode_value "$private_mode")"
  [ $((private_numeric & 0077)) -eq 0 ] ||
    die "private key sources must not grant group or other permissions"
done

CONFIG_DIR='/private/etc/john-lomein-release-broker.d'
PUBLIC_DIR='/private/etc/john-lomein-release-broker-public'
DATA_ROOT='/private/var/db/john-lomein-release-broker'
RUN_ROOT="$DATA_ROOT/run"
RUN_DIR="$RUN_ROOT/$SLUG"
STATE_ROOT="$DATA_ROOT/state"
STATE_DIR="$STATE_ROOT/$SLUG"
SECRETS_DIR="$CONFIG_DIR/$SLUG.secrets"
TMP_RUNTIME_DIR="$STATE_DIR/tmp"
SOCKET_PATH="$RUN_DIR/release-broker.sock"
SOCKET_LOCK_PATH="$SOCKET_PATH.lock"
DATABASE_PATH="$STATE_DIR/release-broker.sqlite"
GITHUB_KEY_PATH="$SECRETS_DIR/github-app.pem"
OWNER_PUBLIC_PATH="$SECRETS_DIR/owner-assertion-ed25519.pub.pem"
RECEIPT_PRIVATE_PATH="$SECRETS_DIR/receipt-ed25519.pem"
RECEIPT_PUBLIC_PATH="$PUBLIC_DIR/$SLUG.receipt-ed25519.pub.pem"
CONFIG_PATH="$CONFIG_DIR/$SLUG.json"
CLIENT_CONFIG_PATH="$PUBLIC_DIR/$SLUG.json"
CODE_PARENT='/usr/local/libexec'
CODE_ROOT='/usr/local/libexec/john-lomein-protected-release-broker'
ENTRYPOINT="$CODE_ROOT/release_broker/run_release_broker.py"
LABEL="com.john-lomein.protected-release-broker.$SLUG"
PLIST_PATH="/Library/LaunchDaemons/$LABEL.plist"

TEMP_DIR="$(
  /usr/bin/mktemp -d /private/tmp/john-lomein-release-broker-install.XXXXXX
)"
/bin/chmod 0700 "$TEMP_DIR"
ROLLBACK_DIR="$TEMP_DIR/rollback"
/usr/bin/install -d -o root -g wheel -m 0700 "$ROLLBACK_DIR"
TRANSACTION_STARTED=0
TRANSACTION_COMMITTED=0
PREVIOUS_LOADED=0
FILES_MUTATED=0
CODE_INSTALLED=0
CODE_BACKUP=''
STATE_SNAPSHOTTED=0
RUN_DIR_QUARANTINED=0
STATE_DIR_QUARANTINED=0

restore_managed_file() {
  local backup="$1"
  local destination="$2"
  local staged
  if [ -f "$backup" ]; then
    if [ -d "$destination" ] && [ ! -L "$destination" ]; then
      return 1
    fi
    staged="$(/usr/bin/mktemp "$destination.rollback.XXXXXX")" || return 1
    /bin/cp -p "$backup" "$staged" || {
      /bin/rm -f "$staged"
      return 1
    }
    /bin/mv -f "$staged" "$destination" || {
      /bin/rm -f "$staged"
      return 1
    }
    return 0
  fi
  if [ -e "$destination" ] || [ -L "$destination" ]; then
    [ ! -d "$destination" ] || return 1
    /bin/rm -f "$destination" || return 1
  fi
}

cleanup() {
  local status=$?
  local cleanup_status=0
  local state_restore_safe=0
  trap - EXIT
  if \
    [ "$status" -ne 0 ] &&
    [ "$TRANSACTION_STARTED" -eq 1 ] &&
    [ "$TRANSACTION_COMMITTED" -eq 0 ]
  then
    /bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
    if \
      [ ! -L "$STATE_DIR" ] &&
      [ -d "$STATE_DIR" ] &&
      /usr/sbin/chown root:wheel "$STATE_DIR" &&
      /bin/chmod 0700 "$STATE_DIR"
    then
      STATE_DIR_QUARANTINED=1
      state_restore_safe=1
    else
      cleanup_status=1
    fi
    if [ "$FILES_MUTATED" -eq 1 ]; then
      restore_managed_file \
        "$ROLLBACK_DIR/github-app.pem" "$GITHUB_KEY_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/owner-public.pem" "$OWNER_PUBLIC_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/receipt-private.pem" "$RECEIPT_PRIVATE_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/receipt-public.pem" "$RECEIPT_PUBLIC_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/release-broker-config.json" "$CONFIG_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/client-config.json" "$CLIENT_CONFIG_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/launchdaemon.plist" "$PLIST_PATH" ||
        cleanup_status=1
    fi
    if [ "$STATE_SNAPSHOTTED" -eq 1 ]; then
      if [ "$state_restore_safe" -eq 1 ]; then
        restore_managed_file \
          "$ROLLBACK_DIR/release-broker.sqlite" "$DATABASE_PATH" ||
          cleanup_status=1
        restore_managed_file \
          "$ROLLBACK_DIR/release-broker.sqlite-wal" "$DATABASE_PATH-wal" ||
          cleanup_status=1
        restore_managed_file \
          "$ROLLBACK_DIR/release-broker.sqlite-shm" "$DATABASE_PATH-shm" ||
          cleanup_status=1
        restore_managed_file \
          "$ROLLBACK_DIR/release-broker.sqlite-journal" \
          "$DATABASE_PATH-journal" || cleanup_status=1
      else
        cleanup_status=1
      fi
    fi
    if [ -n "$CODE_BACKUP" ] && [ -d "$CODE_BACKUP" ]; then
      if [ -e "$CODE_ROOT" ] || [ -L "$CODE_ROOT" ]; then
        if \
          [ ! -L "$CODE_ROOT" ] &&
          [ -d "$CODE_ROOT" ] &&
          [ "$(/usr/bin/stat -f '%u' "$CODE_ROOT" 2>/dev/null || echo -1)" -eq 0 ]
        then
          /bin/rm -rf "$CODE_ROOT" || cleanup_status=1
        else
          cleanup_status=1
        fi
      fi
      if [ ! -e "$CODE_ROOT" ] && [ ! -L "$CODE_ROOT" ]; then
        /bin/mv "$CODE_BACKUP" "$CODE_ROOT" || cleanup_status=1
      else
        cleanup_status=1
      fi
    elif [ "$CODE_INSTALLED" -eq 1 ]; then
      if \
        [ ! -L "$CODE_ROOT" ] &&
        [ -d "$CODE_ROOT" ] &&
        [ "$(/usr/bin/stat -f '%u' "$CODE_ROOT" 2>/dev/null || echo -1)" -eq 0 ]
      then
        /bin/rm -rf "$CODE_ROOT" || cleanup_status=1
      else
        cleanup_status=1
      fi
    fi
    if [ "$RUN_DIR_QUARANTINED" -eq 1 ]; then
      /usr/sbin/chown "$BROKER_USER:$SUBMIT_GROUP" "$RUN_DIR" ||
        cleanup_status=1
      /bin/chmod 0750 "$RUN_DIR" || cleanup_status=1
      RUN_DIR_QUARANTINED=0
    fi
    if [ "$STATE_DIR_QUARANTINED" -eq 1 ]; then
      /usr/sbin/chown "$BROKER_USER:$BROKER_PRIMARY_GROUP" "$STATE_DIR" ||
        cleanup_status=1
      /bin/chmod 0700 "$STATE_DIR" || cleanup_status=1
      STATE_DIR_QUARANTINED=0
    fi
    if [ "$PREVIOUS_LOADED" -eq 1 ]; then
      if [ -f "$PLIST_PATH" ] && [ ! -L "$PLIST_PATH" ]; then
        /bin/launchctl enable "system/$LABEL" >/dev/null 2>&1 ||
          cleanup_status=1
        /bin/launchctl bootstrap system "$PLIST_PATH" >/dev/null 2>&1 ||
          cleanup_status=1
        /bin/launchctl kickstart -k "system/$LABEL" >/dev/null 2>&1 ||
          cleanup_status=1
        /bin/launchctl print "system/$LABEL" >/dev/null 2>&1 ||
          cleanup_status=1
      else
        cleanup_status=1
      fi
    fi
  fi
  if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ]; then
    /bin/rm -rf "$TEMP_DIR"
  fi
  if [ "$cleanup_status" -ne 0 ]; then
    echo \
      "protected release broker install rollback was incomplete; service remains fail-closed" \
      >&2
    exit 70
  fi
  exit "$status"
}
trap cleanup EXIT

while IFS= read -r environment_name; do
  case "$environment_name" in
    DYLD_*|LD_LIBRARY_PATH|PYTHONHOME|PYTHONPATH|PYTHONUSERBASE)
      unset "$environment_name"
      ;;
  esac
done < <(compgen -v)

PYTHON_REPORT="$TEMP_DIR/python-paths.tsv"
"$PYTHON" -I -B -S -c '
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or newer is required")
paths = [
    ("executable", sys.executable),
    ("base_executable", getattr(sys, "_base_executable", "")),
    ("prefix", sys.prefix),
    ("base_prefix", sys.base_prefix),
    ("exec_prefix", sys.exec_prefix),
    ("base_exec_prefix", sys.base_exec_prefix),
]
paths.extend(("sys_path", value) for value in sys.path if value)
for kind, value in paths:
    if value and ("\n" in value or "\r" in value or "\t" in value):
        raise SystemExit("Python runtime path contains a control character")
    if value:
        print(f"{kind}\t{value}")
' >"$PYTHON_REPORT"

seen_executable=0
while IFS=$'\t' read -r path_kind runtime_path; do
  if [ -z "$path_kind" ] || [ -z "$runtime_path" ]; then
    die "Python runtime path report is malformed"
  fi
  if [ "$path_kind" = "executable" ]; then
    [ "$runtime_path" = "$PYTHON" ] ||
      die "Python sys.executable does not equal the supplied interpreter path"
    seen_executable=1
  fi
  validate_runtime_path "$runtime_path" "Python $path_kind"
done <"$PYTHON_REPORT"
[ "$seen_executable" -eq 1 ] ||
  die "Python runtime did not report sys.executable"

SYSCONFIG_REPORT="$TEMP_DIR/python-sysconfig-paths.tsv"
"$PYTHON" -I -B -S -c '
import sysconfig
for kind, value in sorted(sysconfig.get_paths().items()):
    if value and ("\n" in value or "\r" in value or "\t" in value):
        raise SystemExit("Python sysconfig path contains a control character")
    if value:
        print(f"{kind}\t{value}")
' >"$SYSCONFIG_REPORT"

while IFS=$'\t' read -r path_kind runtime_path; do
  if [ -z "$path_kind" ] || [ -z "$runtime_path" ]; then
    die "Python sysconfig path report is malformed"
  fi
  validate_runtime_path "$runtime_path" "Python sysconfig $path_kind"
done <"$SYSCONFIG_REPORT"

CRYPTOGRAPHY_REPORT="$TEMP_DIR/cryptography-paths.tsv"
"$PYTHON" -I -B -c '
import importlib.metadata
import pathlib
import sys
import cryptography
from cryptography.hazmat.bindings import _rust
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

if cryptography.__version__ != "49.0.0":
    raise SystemExit(
        "the protected release broker requires locked cryptography 49.0.0"
    )
native = getattr(_rust, "__file__", "")
if not native or not pathlib.Path(native).is_file():
    raise SystemExit("cryptography native binding is unavailable")
if not native.endswith((".so", ".dylib")):
    raise SystemExit("cryptography native binding has an unexpected type")

reported = {
    ("executable", sys.executable),
    ("prefix", sys.prefix),
    ("base_prefix", sys.base_prefix),
    ("cryptography_package", str(pathlib.Path(cryptography.__file__).parent)),
    ("cryptography_native_binding", native),
    (
        "cryptography_distribution",
        str(pathlib.Path(importlib.metadata.distribution("cryptography").locate_file(""))),
    ),
}
reported.update(("sys_path", value) for value in sys.path if value)
for name, module in sorted(sys.modules.items()):
    value = getattr(module, "__file__", "")
    if name == "cryptography" or name.startswith("cryptography."):
        if value:
            reported.add(("cryptography_module", value))
for kind, value in sorted(reported):
    if "\n" in value or "\r" in value or "\t" in value:
        raise SystemExit("cryptography path contains a control character")
    print(f"{kind}\t{value}")
' >"$CRYPTOGRAPHY_REPORT"

seen_crypto_package=0
seen_crypto_native=0
while IFS=$'\t' read -r path_kind runtime_path; do
  if [ -z "$path_kind" ] || [ -z "$runtime_path" ]; then
    die "cryptography path report is malformed"
  fi
  [ "$path_kind" != "cryptography_package" ] || seen_crypto_package=1
  [ "$path_kind" != "cryptography_native_binding" ] || seen_crypto_native=1
  validate_runtime_path "$runtime_path" "$path_kind"
done <"$CRYPTOGRAPHY_REPORT"
if [ "$seen_crypto_package" -ne 1 ] || [ "$seen_crypto_native" -ne 1 ]; then
  die "cryptography package/native binding trust could not be established"
fi

snapshot_input() {
  local source="$1"
  local destination="$2"
  local allowed_uids="$3"
  local privacy="$4"
  local marker="$5"
  "$PYTHON" -I -B -S - "$source" "$destination" "$allowed_uids" \
    "$privacy" "$marker" <<'PY'
import os
import stat
import sys

source, destination, raw_uids, privacy, marker = sys.argv[1:]
allowed = {int(value) for value in raw_uids.split(",")}
flags = os.O_RDONLY
if hasattr(os, "O_CLOEXEC"):
    flags |= os.O_CLOEXEC
if not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("O_NOFOLLOW is required")
flags |= os.O_NOFOLLOW
source_fd = os.open(source, flags)
try:
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("input must be a singly linked regular file")
    if before.st_uid not in allowed or before.st_mode & 0o022:
        raise SystemExit("input ownership or write permissions are unsafe")
    if privacy == "private" and before.st_mode & 0o077:
        raise SystemExit("private input grants group or other permissions")
    if before.st_size > 131072:
        raise SystemExit("input exceeds the installation size limit")
    chunks = []
    total = 0
    while True:
        chunk = os.read(source_fd, min(65536, 131073 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > 131072:
            raise SystemExit("input exceeds the installation size limit")
    after = os.fstat(source_fd)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise SystemExit("input changed while being snapshotted")
    payload = b"".join(chunks)
    if marker and marker.encode("ascii") not in payload:
        raise SystemExit("key input is not the expected PEM form")
    output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        output_flags |= os.O_CLOEXEC
    output_fd = os.open(destination, output_flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(output_fd, view)
            if written <= 0:
                raise SystemExit("input snapshot write made no progress")
            view = view[written:]
        os.fsync(output_fd)
    finally:
        os.close(output_fd)
finally:
    os.close(source_fd)
PY
}

CONFIG_SNAPSHOT="$TEMP_DIR/release-broker-config.json"
GITHUB_KEY_SNAPSHOT="$TEMP_DIR/github-app.pem"
OWNER_PUBLIC_SNAPSHOT="$TEMP_DIR/owner-public.pem"
RECEIPT_PRIVATE_SNAPSHOT="$TEMP_DIR/receipt-private.pem"
RECEIPT_PUBLIC_SNAPSHOT="$TEMP_DIR/receipt-public.pem"
snapshot_input "$CONFIG_SOURCE" "$CONFIG_SNAPSHOT" 0 public ''
snapshot_input \
  "$GITHUB_KEY_SOURCE" "$GITHUB_KEY_SNAPSHOT" 0 \
  private 'PRIVATE KEY'
snapshot_input \
  "$OWNER_PUBLIC_SOURCE" "$OWNER_PUBLIC_SNAPSHOT" 0 \
  public 'PUBLIC KEY'
snapshot_input \
  "$RECEIPT_PRIVATE_SOURCE" "$RECEIPT_PRIVATE_SNAPSHOT" \
  0 private 'PRIVATE KEY'
snapshot_input \
  "$RECEIPT_PUBLIC_SOURCE" "$RECEIPT_PUBLIC_SNAPSHOT" \
  0 public 'PUBLIC KEY'

ENABLED="$(
  "$PYTHON" -I -B - "$PRODUCT_ROOT" "$CONFIG_SNAPSHOT" \
    "$GITHUB_KEY_SNAPSHOT" "$OWNER_PUBLIC_SNAPSHOT" \
    "$RECEIPT_PRIVATE_SNAPSHOT" "$RECEIPT_PUBLIC_SNAPSHOT" \
    "$SLUG" "$BROKER_UID" "$BROKER_PRIMARY_GID" "$REQUESTER_UID" \
    "$SUBMIT_GID" \
    "$SOCKET_PATH" "$DATABASE_PATH" "$GITHUB_KEY_PATH" \
    "$OWNER_PUBLIC_PATH" "$RECEIPT_PRIVATE_PATH" "$RECEIPT_PUBLIC_PATH" <<'PY'
import hashlib
import pathlib
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

(
    product_root,
    config_path,
    github_path,
    owner_public_path,
    receipt_private_path,
    receipt_public_path,
    slug,
    broker_uid,
    broker_private_gid,
    requester_uid,
    submit_gid,
    socket_path,
    database_path,
    expected_github_path,
    expected_owner_public_path,
    expected_receipt_private_path,
    expected_receipt_public_path,
) = sys.argv[1:]
sys.path.insert(0, product_root)
from release_broker.john_lomein_release_broker_protocol import (
    MAX_CONFIG_BYTES,
    parse_json_bytes,
    normalize_config,
)

raw = pathlib.Path(config_path).read_bytes()
config = normalize_config(
    parse_json_bytes(
        raw,
        field="release broker config",
        maximum_bytes=MAX_CONFIG_BYTES,
    )
)
checks = (
    (
        config["schema_version"]
        == "john-lomein.protected-release-broker-config.v1",
        "schema",
    ),
    (config["instance"]["slug"] == slug, "instance slug"),
    (config["broker_uid"] == int(broker_uid), "broker UID"),
    (
        config["broker_private_gid"] == int(broker_private_gid),
        "broker private GID",
    ),
    (
        config["transport"]["requester_uid"] == int(requester_uid),
        "requester UID",
    ),
    (
        config["transport"]["submit_gid"] == int(submit_gid),
        "submit GID",
    ),
    (str(config["transport"]["socket_path"]) == socket_path, "socket path"),
    (str(config["state"]["database_path"]) == database_path, "database path"),
    (
        str(config["github_app"]["private_key_path"])
        == expected_github_path,
        "GitHub private-key path",
    ),
    (
        str(config["owner_assertion"]["public_key_path"])
        == expected_owner_public_path,
        "owner assertion public-key path",
    ),
    (
        str(config["receipt_signing"]["private_key_path"])
        == expected_receipt_private_path,
        "receipt private-key path",
    ),
    (
        str(config["receipt_signing"]["public_key_path"])
        == expected_receipt_public_path,
        "receipt public-key path",
    ),
    (
        config["instance"]["policy"]["max_prs_per_bundle"] == 1,
        "one-PR policy",
    ),
    (
        config["instance"]["policy"]["merge_method"] == "squash",
        "squash policy",
    ),
    (
        config["instance"]["policy"]["publish"] is False,
        "publish policy",
    ),
    (
        config["instance"]["policy"]["delete_branch"] is False,
        "delete-branch policy",
    ),
)
for passed, label in checks:
    if not passed:
        raise SystemExit(
            f"release broker config {label} does not match installer binding"
        )

github_private = serialization.load_pem_private_key(
    pathlib.Path(github_path).read_bytes(), password=None
)
if not isinstance(github_private, rsa.RSAPrivateKey):
    raise SystemExit("GitHub App key must be an RSA private key")
if github_private.key_size < 2048:
    raise SystemExit("GitHub App RSA key must be at least 2048 bits")

owner_public_bytes = pathlib.Path(owner_public_path).read_bytes()
owner_public = serialization.load_pem_public_key(owner_public_bytes)
if not isinstance(owner_public, ed25519.Ed25519PublicKey):
    raise SystemExit("owner assertion public key must be Ed25519")
owner_fingerprint = "sha256:" + hashlib.sha256(
    owner_public_bytes
).hexdigest()
if (
    config["owner_assertion"]["public_key_sha256"]
    != owner_fingerprint
):
    raise SystemExit(
        "owner assertion public-key fingerprint does not match config"
    )

receipt_private = serialization.load_pem_private_key(
    pathlib.Path(receipt_private_path).read_bytes(), password=None
)
receipt_public_bytes = pathlib.Path(receipt_public_path).read_bytes()
receipt_public = serialization.load_pem_public_key(receipt_public_bytes)
if not isinstance(receipt_private, ed25519.Ed25519PrivateKey):
    raise SystemExit("receipt private key must be Ed25519")
if not isinstance(receipt_public, ed25519.Ed25519PublicKey):
    raise SystemExit("receipt public key must be Ed25519")
expected_public = receipt_private.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
actual_public = receipt_public.public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
if expected_public != actual_public:
    raise SystemExit("receipt private and public keys do not match")
receipt_fingerprint = "sha256:" + hashlib.sha256(
    receipt_public_bytes
).hexdigest()
if (
    config["receipt_signing"]["public_key_sha256"]
    != receipt_fingerprint
):
    raise SystemExit(
        "receipt public-key fingerprint does not match config"
    )
print("1" if config["enabled"] else "0")
PY
)"
[ "$ENABLED" = 0 ] || [ "$ENABLED" = 1 ] ||
  die "release broker config preflight returned invalid enablement"

ensure_secure_parent() {
  local path="$1"
  local label="$2"
  local parent
  if [ -e "$path" ] || [ -L "$path" ]; then
    validate_existing_path "$path" 0 directory "$label"
    return
  fi
  parent="$(/usr/bin/dirname "$path")"
  validate_existing_path "$parent" 0 directory "$label parent"
  /usr/bin/install -d -o root -g wheel -m 0755 "$path"
  validate_existing_path "$path" 0 directory "$label"
}

ensure_managed_directory() {
  local path="$1"
  local owner="$2"
  local group="$3"
  local mode="$4"
  local owner_uid="$5"
  local label="$6"
  local allowed_uids="$owner_uid"
  if [ "$owner_uid" -ne 0 ]; then
    allowed_uids="0,$owner_uid"
  fi
  if [ -e "$path" ] || [ -L "$path" ]; then
    validate_existing_path "$path" "$allowed_uids" directory "$label"
    [ "$(/usr/bin/stat -f '%u' "$path")" -eq "$owner_uid" ] ||
      die "$label final directory has the wrong owner"
  else
    /usr/bin/install -d -o "$owner" -g "$group" -m "$mode" "$path"
  fi
  /bin/chmod -N "$path" 2>/dev/null || true
  /usr/sbin/chown "$owner:$group" "$path"
  /bin/chmod "$mode" "$path"
  validate_existing_path "$path" "$allowed_uids" directory "$label"
  [ "$(/usr/bin/stat -f '%u' "$path")" -eq "$owner_uid" ] ||
    die "$label final directory has the wrong owner"
}

validate_existing_path /usr 0 directory "/usr"
ensure_secure_parent /usr/local "/usr/local"
ensure_secure_parent "$CODE_PARENT" "release broker code parent"
validate_existing_path /private/etc 0 directory "/private/etc"
validate_existing_path /private/var/db 0 directory "/private/var/db"
validate_existing_path /Library/LaunchDaemons 0 directory "LaunchDaemons"

ensure_managed_directory "$CONFIG_DIR" root wheel 0755 0 \
  "release broker config directory"
ensure_managed_directory "$PUBLIC_DIR" root wheel 0755 0 \
  "release broker public directory"
ensure_managed_directory \
  "$SECRETS_DIR" root "$BROKER_PRIMARY_GROUP" 0750 0 \
  "release broker secrets directory"
ensure_managed_directory "$DATA_ROOT" root wheel 0755 0 \
  "release broker data root"
ensure_managed_directory "$RUN_ROOT" root wheel 0755 0 \
  "release broker run root"
ensure_managed_directory "$STATE_ROOT" root wheel 0755 0 \
  "release broker state root"
ensure_managed_directory \
  "$RUN_DIR" "$BROKER_USER" "$SUBMIT_GROUP" 0750 "$BROKER_UID" \
  "instance release broker run directory"
ensure_managed_directory \
  "$STATE_DIR" "$BROKER_USER" "$BROKER_PRIMARY_GROUP" 0700 "$BROKER_UID" \
  "instance release broker state directory"
ensure_managed_directory \
  "$TMP_RUNTIME_DIR" "$BROKER_USER" "$BROKER_PRIMARY_GROUP" 0700 \
  "$BROKER_UID" "instance release broker temporary directory"

backup_optional_file() {
  local source="$1"
  local backup="$2"
  local allowed_uids="$3"
  local label="$4"
  local maximum_bytes="${5:-1048576}"
  if [ -L "$source" ]; then
    die "$label is an unsafe symlink"
  fi
  if [ -e "$source" ]; then
    validate_existing_path "$source" "$allowed_uids" file "$label"
    "$PYTHON" -I -B -S - "$source" "$backup" "$allowed_uids" \
      "$maximum_bytes" <<'PY'
import os
import stat
import sys

source, backup, raw_uids, raw_maximum = sys.argv[1:]
allowed_uids = {int(value) for value in raw_uids.split(",")}
maximum = int(raw_maximum)
source_flags = os.O_RDONLY
if hasattr(os, "O_CLOEXEC"):
    source_flags |= os.O_CLOEXEC
if not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("O_NOFOLLOW is required for rollback snapshots")
source_flags |= os.O_NOFOLLOW
source_fd = os.open(source, source_flags)
backup_created = False
try:
    before = os.fstat(source_fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid not in allowed_uids
        or before.st_mode & 0o022
    ):
        raise SystemExit("rollback source metadata is unsafe")
    if before.st_size > maximum:
        raise SystemExit("rollback source exceeds its size limit")
    backup_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        backup_flags |= os.O_CLOEXEC
    backup_fd = os.open(backup, backup_flags, 0o600)
    backup_created = True
    try:
        copied = 0
        while True:
            chunk = os.read(
                source_fd,
                min(1024 * 1024, maximum + 1 - copied),
            )
            if not chunk:
                break
            copied += len(chunk)
            if copied > maximum:
                raise SystemExit("rollback source exceeds its size limit")
            view = memoryview(chunk)
            while view:
                written = os.write(backup_fd, view)
                if written <= 0:
                    raise SystemExit(
                        "rollback snapshot write made no progress"
                    )
                view = view[written:]
        after = os.fstat(source_fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise SystemExit("rollback source changed during snapshot")
        os.fchown(backup_fd, before.st_uid, before.st_gid)
        os.fchmod(backup_fd, stat.S_IMODE(before.st_mode))
        os.fsync(backup_fd)
    finally:
        os.close(backup_fd)
except BaseException:
    if backup_created:
        try:
            os.unlink(backup)
        except FileNotFoundError:
            pass
    raise
finally:
    os.close(source_fd)
PY
  fi
}

backup_optional_file \
  "$GITHUB_KEY_PATH" "$ROLLBACK_DIR/github-app.pem" 0 \
  "existing installed release GitHub App key"
backup_optional_file \
  "$OWNER_PUBLIC_PATH" "$ROLLBACK_DIR/owner-public.pem" 0 \
  "existing installed owner assertion public key"
backup_optional_file \
  "$RECEIPT_PRIVATE_PATH" "$ROLLBACK_DIR/receipt-private.pem" 0 \
  "existing installed release receipt private key"
backup_optional_file \
  "$RECEIPT_PUBLIC_PATH" "$ROLLBACK_DIR/receipt-public.pem" 0 \
  "existing installed release receipt public key"
backup_optional_file \
  "$CONFIG_PATH" "$ROLLBACK_DIR/release-broker-config.json" 0 \
  "existing installed release broker config"
backup_optional_file \
  "$CLIENT_CONFIG_PATH" "$ROLLBACK_DIR/client-config.json" 0 \
  "existing installed release broker client config"
backup_optional_file \
  "$PLIST_PATH" "$ROLLBACK_DIR/launchdaemon.plist" 0 \
  "existing installed release broker LaunchDaemon"

if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
  PREVIOUS_LOADED=1
  [ -f "$ROLLBACK_DIR/launchdaemon.plist" ] ||
    die "loaded release broker has no safe LaunchDaemon plist to restore"
fi

shopt -s nullglob
OTHER_BROKER_PLISTS=(
  /Library/LaunchDaemons/com.john-lomein.protected-release-broker.*.plist
)
shopt -u nullglob
for other_plist in "${OTHER_BROKER_PLISTS[@]}"; do
  other_label="$(/usr/bin/basename "$other_plist" .plist)"
  [ "$other_label" = "$LABEL" ] && continue
  if /bin/launchctl print "system/$other_label" >/dev/null 2>&1; then
    die \
      "shared release broker code cannot be upgraded while another instance is loaded: $other_label"
  fi
done

TRANSACTION_STARTED=1

stop_existing_service() {
  /bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
  if [ -f "$PLIST_PATH" ]; then
    /bin/launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
  fi
  if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
    die "existing release broker LaunchDaemon could not be verified stopped"
  fi
}
stop_existing_service

/usr/sbin/chown root:wheel "$STATE_DIR"
/bin/chmod 0700 "$STATE_DIR"
STATE_DIR_QUARANTINED=1

backup_optional_file \
  "$DATABASE_PATH" "$ROLLBACK_DIR/release-broker.sqlite" \
  "0,$BROKER_UID" "existing release broker database" 8589934592
backup_optional_file \
  "$DATABASE_PATH-wal" "$ROLLBACK_DIR/release-broker.sqlite-wal" \
  "0,$BROKER_UID" "existing release broker database WAL" 8589934592
backup_optional_file \
  "$DATABASE_PATH-shm" "$ROLLBACK_DIR/release-broker.sqlite-shm" \
  "0,$BROKER_UID" "existing release broker database shared-memory file" \
  8589934592
backup_optional_file \
  "$DATABASE_PATH-journal" "$ROLLBACK_DIR/release-broker.sqlite-journal" \
  "0,$BROKER_UID" "existing release broker database journal" 8589934592
STATE_SNAPSHOTTED=1

remove_stale_runtime_object() {
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
  [ "$(/usr/bin/stat -f '%u' "$path")" -eq "$BROKER_UID" ] ||
    die "$label has the wrong owner"
  reject_acl "$path" "$label"
  /bin/rm -f "$path"
}
remove_stale_runtime_object \
  "$SOCKET_PATH" socket "stale release broker socket"
remove_stale_runtime_object \
  "$SOCKET_LOCK_PATH" file "stale release broker socket lock"

REQUIRED_MODULES=(
  __init__.py
  john_lomein_release_broker_protocol.py
  john_lomein_release_broker_actions.py
  john_lomein_release_broker_github_app.py
  john_lomein_release_broker_github_live.py
  john_lomein_release_broker_store.py
  john_lomein_release_broker_receipts.py
  john_lomein_release_broker_service.py
  john_lomein_release_broker_daemon.py
  run_release_broker.py
)
for module_name in "${REQUIRED_MODULES[@]}"; do
  source_file="$SOURCE_BROKER_DIR/$module_name"
  if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
    die "required release broker module is missing or unsafe: $module_name"
  fi
done

CODE_STAGE="$(
  /usr/bin/mktemp -d \
    "$CODE_PARENT/.john-lomein-protected-release-broker.stage.XXXXXX"
)"
/usr/sbin/chown root:wheel "$CODE_STAGE"
/bin/chmod 0755 "$CODE_STAGE"
/usr/bin/install -d -o root -g wheel -m 0755 "$CODE_STAGE/release_broker"
for module_name in "${REQUIRED_MODULES[@]}"; do
  /usr/bin/install -o root -g wheel -m 0444 \
    "$SOURCE_BROKER_DIR/$module_name" \
    "$CODE_STAGE/release_broker/$module_name"
done
[ -f "$CODE_STAGE/release_broker/run_release_broker.py" ] ||
  die "release broker entrypoint is missing"
validate_root_owned_tree "$CODE_STAGE" "staged release broker code"

if [ -e "$CODE_ROOT" ] || [ -L "$CODE_ROOT" ]; then
  validate_root_owned_tree "$CODE_ROOT" "existing installed release broker code"
  CODE_BACKUP="$(
    /usr/bin/mktemp -d \
      "$CODE_PARENT/.john-lomein-protected-release-broker.backup.XXXXXX"
  )"
  /bin/rmdir "$CODE_BACKUP"
  /bin/mv "$CODE_ROOT" "$CODE_BACKUP"
else
  CODE_BACKUP=''
fi
/bin/mv "$CODE_STAGE" "$CODE_ROOT"
CODE_STAGE=''
CODE_INSTALLED=1
validate_root_owned_tree "$CODE_ROOT" "installed release broker code"

assert_replaceable_file() {
  local path="$1"
  local label="$2"
  [ ! -L "$path" ] || die "$label is an unsafe symlink"
  if [ -e "$path" ]; then
    [ -f "$path" ] || die "$label is not a regular file"
  fi
}

install_file_atomically() {
  local source="$1"
  local destination="$2"
  local owner="$3"
  local group="$4"
  local mode="$5"
  local label="$6"
  local staged
  assert_replaceable_file "$destination" "$label"
  staged="$(/usr/bin/mktemp "$destination.new.XXXXXX")"
  /usr/bin/install -o "$owner" -g "$group" -m "$mode" "$source" "$staged"
  /bin/chmod -N "$staged" 2>/dev/null || true
  /bin/mv -f "$staged" "$destination"
}

FILES_MUTATED=1
install_file_atomically \
  "$GITHUB_KEY_SNAPSHOT" "$GITHUB_KEY_PATH" root \
  "$BROKER_PRIMARY_GROUP" 0640 "installed release GitHub App private key"
install_file_atomically \
  "$OWNER_PUBLIC_SNAPSHOT" "$OWNER_PUBLIC_PATH" root \
  "$BROKER_PRIMARY_GROUP" 0440 \
  "installed owner assertion public key"
install_file_atomically \
  "$RECEIPT_PRIVATE_SNAPSHOT" "$RECEIPT_PRIVATE_PATH" root \
  "$BROKER_PRIMARY_GROUP" 0640 \
  "installed release receipt private key"
install_file_atomically \
  "$RECEIPT_PUBLIC_SNAPSHOT" "$RECEIPT_PUBLIC_PATH" root wheel 0444 \
  "installed release receipt public key"
install_file_atomically \
  "$CONFIG_SNAPSHOT" "$CONFIG_PATH" root "$BROKER_PRIMARY_GROUP" 0640 \
  "installed release broker config"

assert_installed_file_metadata() {
  local path="$1"
  local expected_uid="$2"
  local expected_gid="$3"
  local expected_mode="$4"
  local label="$5"
  if [ ! -f "$path" ] || [ -L "$path" ]; then
    die "$label is not a regular non-symlink file"
  fi
  [ "$(/usr/bin/stat -f '%u' "$path")" -eq "$expected_uid" ] ||
    die "$label owner is incorrect"
  [ "$(/usr/bin/stat -f '%g' "$path")" -eq "$expected_gid" ] ||
    die "$label group is incorrect"
  [ "$(/usr/bin/stat -f '%Lp' "$path")" = "$expected_mode" ] ||
    die "$label mode is incorrect"
  [ "$(/usr/bin/stat -f '%l' "$path")" -eq 1 ] ||
    die "$label must be singly linked"
  reject_acl "$path" "$label"
}

assert_installed_file_metadata \
  "$GITHUB_KEY_PATH" 0 "$BROKER_PRIMARY_GID" 640 \
  "installed release GitHub App private key"
assert_installed_file_metadata \
  "$RECEIPT_PRIVATE_PATH" 0 "$BROKER_PRIMARY_GID" 640 \
  "installed release receipt private key"

"$PYTHON" -I -B - "$CODE_ROOT" "$CONFIG_PATH" <<'PY'
import pathlib
import sys

code_root, config_path = sys.argv[1:]
sys.path.insert(0, code_root)
from release_broker.john_lomein_release_broker_protocol import load_config
from release_broker import john_lomein_release_broker_actions
from release_broker import john_lomein_release_broker_daemon
from release_broker import john_lomein_release_broker_github_app
from release_broker import john_lomein_release_broker_github_live
from release_broker import john_lomein_release_broker_receipts
from release_broker import john_lomein_release_broker_service
from release_broker import john_lomein_release_broker_store

load_config(
    pathlib.Path(config_path),
    expected_owner_uids={0},
    parent_owner_uids={0},
    trusted_path_root=pathlib.Path(
        "/private/etc/john-lomein-release-broker.d"
    ),
)
expected_permissions = {
    "checks": "read",
    "contents": "write",
    "issues": "read",
    "metadata": "read",
    "pull_requests": "read",
    "statuses": "read",
}
if (
    john_lomein_release_broker_github_app.API_VERSION != "2026-03-10"
    or john_lomein_release_broker_github_app.REQUIRED_PERMISSIONS
    != expected_permissions
):
    raise SystemExit(
        "installed release GitHub App authority contract is unexpected"
    )
PY

"$PYTHON" -I -B "$ENTRYPOINT" --help >/dev/null

CLIENT_CONFIG_SNAPSHOT="$TEMP_DIR/client-config.json"
"$PYTHON" -I -B - "$CODE_ROOT" "$CONFIG_PATH" \
  "$CLIENT_CONFIG_SNAPSHOT" <<'PY'
import json
import pathlib
import sys

code_root, config_path, destination = sys.argv[1:]
sys.path.insert(0, code_root)
from release_broker.john_lomein_release_broker_protocol import (
    config_digest,
    load_config,
)
from release_broker.john_lomein_release_broker_receipts import (
    MAX_RECEIPT_BYTES,
)

config = load_config(
    pathlib.Path(config_path),
    expected_owner_uids={0},
    parent_owner_uids={0},
    trusted_path_root=pathlib.Path(
        "/private/etc/john-lomein-release-broker.d"
    ),
)
transport = config["transport"]
github = config["github_app"]
receipt = config["receipt_signing"]
instance = config["instance"]
repository = instance["repository"]
client = {
    "schema_version": (
        "john-lomein.protected-release-broker-client-config.v1"
    ),
    "broker_id": config["broker_id"],
    "broker_uid": config["broker_uid"],
    "requester_uid": transport["requester_uid"],
    "submit_gid": transport["submit_gid"],
    "broker_config_sha256": config_digest(config),
    "socket_path": str(transport["socket_path"]),
    "receipt_public_key_path": str(receipt["public_key_path"]),
    "receipt_public_key_sha256": receipt["public_key_sha256"],
    "receipt_key_id": receipt["key_id"],
    "connect_timeout_seconds": 5,
    "request_timeout_seconds": transport["request_timeout_seconds"],
    "max_response_bytes": MAX_RECEIPT_BYTES + 64 * 1024,
    "instance_slug": instance["slug"],
    "repository": {
        "id": repository["id"],
        "full_name": repository["full_name"],
        "default_branch": repository["default_branch"],
    },
    "github_app": {
        "app_id": github["app_id"],
        "app_slug": github["app_slug"],
        "installation_id": github["installation_id"],
    },
}
pathlib.Path(destination).write_text(
    json.dumps(
        client,
        allow_nan=False,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY
install_file_atomically \
  "$CLIENT_CONFIG_SNAPSHOT" "$CLIENT_CONFIG_PATH" root wheel 0444 \
  "installed release broker client config"

PLIST_SNAPSHOT="$TEMP_DIR/$LABEL.plist"
"$PYTHON" -I -B - "$PLIST_SNAPSHOT" "$LABEL" "$PYTHON" "$ENTRYPOINT" \
  "$CONFIG_PATH" "$CODE_ROOT" "$BROKER_USER" "$BROKER_PRIMARY_GROUP" \
  "$STATE_DIR" "$TMP_RUNTIME_DIR" <<'PY'
import plistlib
import sys

(
    destination,
    label,
    python,
    entrypoint,
    config,
    code_root,
    broker_user,
    broker_group,
    state_dir,
    tmp_dir,
) = sys.argv[1:]
environment = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "HOME": state_dir,
    "TMPDIR": tmp_dir,
    "PYTHONHOME": "",
    "PYTHONPATH": "",
    "PYTHONUSERBASE": "",
    "PYTHONDONTWRITEBYTECODE": "1",
    "LD_LIBRARY_PATH": "",
    "DYLD_LIBRARY_PATH": "",
    "DYLD_FRAMEWORK_PATH": "",
    "DYLD_FALLBACK_LIBRARY_PATH": "",
    "DYLD_FALLBACK_FRAMEWORK_PATH": "",
    "DYLD_INSERT_LIBRARIES": "",
    "GH_TOKEN": "",
    "GITHUB_TOKEN": "",
    "CURL_CA_BUNDLE": "",
    "GIT_SSL_CAINFO": "",
    "NODE_EXTRA_CA_CERTS": "",
    "REQUESTS_CA_BUNDLE": "",
    "SSL_CERT_DIR": "",
    "SSL_CERT_FILE": "",
    "SSLKEYLOGFILE": "",
    "HTTP_PROXY": "",
    "HTTPS_PROXY": "",
    "ALL_PROXY": "",
    "NO_PROXY": "",
    "http_proxy": "",
    "https_proxy": "",
    "all_proxy": "",
    "no_proxy": "",
}
payload = {
    "Label": label,
    "ProgramArguments": [
        python,
        "-I",
        "-B",
        entrypoint,
        "--config",
        config,
    ],
    "WorkingDirectory": code_root,
    "UserName": broker_user,
    "GroupName": broker_group,
    "EnvironmentVariables": environment,
    "RunAtLoad": True,
    "KeepAlive": {"SuccessfulExit": False},
    "ProcessType": "Background",
    "ThrottleInterval": 10,
    "Umask": 0o077,
    "StandardOutPath": f"{state_dir}/release-broker.stdout.log",
    "StandardErrorPath": f"{state_dir}/release-broker.stderr.log",
}
with open(destination, "wb") as target:
    plistlib.dump(payload, target, fmt=plistlib.FMT_XML, sort_keys=True)
PY
/usr/bin/plutil -lint "$PLIST_SNAPSHOT" >/dev/null
install_file_atomically \
  "$PLIST_SNAPSHOT" "$PLIST_PATH" root wheel 0644 \
  "installed release broker LaunchDaemon"
/usr/bin/plutil -lint "$PLIST_PATH" >/dev/null

prepare_transaction_commit() {
  if [ -n "$CODE_BACKUP" ] && [ -d "$CODE_BACKUP" ]; then
    validate_root_owned_tree "$CODE_BACKUP" "release broker code backup"
  fi
}

discard_transaction_backup() {
  if [ -n "$CODE_BACKUP" ] && [ -d "$CODE_BACKUP" ]; then
    /bin/rm -rf "$CODE_BACKUP" || {
      echo \
        "warning: obsolete release broker code backup remains at $CODE_BACKUP" \
        >&2
    }
  fi
}

if [ "$ENABLED" -eq 0 ]; then
  /bin/launchctl disable "system/$LABEL"
  if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
    die "disabled release broker unexpectedly remained loaded"
  fi
  /usr/sbin/chown "$BROKER_USER:$BROKER_PRIMARY_GROUP" "$STATE_DIR"
  /bin/chmod 0700 "$STATE_DIR"
  STATE_DIR_QUARANTINED=0
  prepare_transaction_commit
  TRANSACTION_COMMITTED=1
  discard_transaction_backup
  echo "protected release broker installed but disabled by config: $LABEL"
  echo "client config: $CLIENT_CONFIG_PATH"
  exit 0
fi

/usr/sbin/chown "$BROKER_USER:$BROKER_PRIMARY_GROUP" "$STATE_DIR"
/bin/chmod 0700 "$STATE_DIR"
STATE_DIR_QUARANTINED=0
/usr/sbin/chown "$BROKER_USER:$SUBMIT_GROUP" "$RUN_DIR"
/bin/chmod 0700 "$RUN_DIR"
RUN_DIR_QUARANTINED=1
/bin/launchctl enable "system/$LABEL"
/bin/launchctl bootstrap system "$PLIST_PATH"
/bin/launchctl kickstart -k "system/$LABEL"

attempt=0
while [ "$attempt" -lt 50 ]; do
  if [ -S "$SOCKET_PATH" ]; then
    break
  fi
  /bin/launchctl print "system/$LABEL" >/dev/null 2>&1 ||
    die "enabled release broker left launchd before opening its socket"
  /bin/sleep 0.2
  attempt=$((attempt + 1))
done
[ -S "$SOCKET_PATH" ] ||
  die "enabled release broker did not open its socket"
[ ! -L "$SOCKET_PATH" ] || die "release broker socket is a symlink"
[ "$(/usr/bin/stat -f '%u' "$SOCKET_PATH")" -eq "$BROKER_UID" ] ||
  die "release broker socket owner is incorrect"
[ "$(/usr/bin/stat -f '%g' "$SOCKET_PATH")" -eq "$SUBMIT_GID" ] ||
  die "release broker socket group is incorrect"
[ "$(/usr/bin/stat -f '%Lp' "$SOCKET_PATH")" = 660 ] ||
  die "release broker socket mode is not 0660"
reject_acl "$SOCKET_PATH" "release broker socket"
/bin/launchctl print "system/$LABEL" >/dev/null 2>&1 ||
  die "enabled release broker is not loaded"

prepare_transaction_commit
/bin/chmod 0750 "$RUN_DIR"
RUN_DIR_QUARANTINED=0
TRANSACTION_COMMITTED=1
discard_transaction_backup
echo "protected release broker installed and running: $LABEL"
echo "socket: $SOCKET_PATH"
echo "client config: $CLIENT_CONFIG_PATH"
