#!/bin/bash
# Install one macOS release-owner gateway boundary without starting a daemon.
#
# The gateway is an on-demand, credential-bearing signer. A model-controlled
# runtime can only invoke a root-owned fixed-argument wrapper through sudo.
# The signer independently retrieves the named Discord message before minting
# an assertion. No sudo authorization is installed while either strict config
# is disabled.
set -Eeuo pipefail

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
PYTHONDONTWRITEBYTECODE=1
export PYTHONDONTWRITEBYTECODE
umask 077

usage() {
  cat >&2 <<'EOF'
usage:
  install-protected-release-owner-gateway.sh \
    --slug SLUG \
    --signer-config /absolute/root-owned/signer.json \
    --discord-source-config /absolute/root-owned/discord-source.json \
    --signing-private-key /absolute/secure/owner-ed25519.pem \
    --signing-public-key /absolute/secure/owner-ed25519.pub.pem \
    --discord-bot-token /absolute/secure/discord-bot.token \
    --python /absolute/root-owned/python3 \
    --signer-user EXISTING_USER \
    --requester-user EXISTING_USER \
    --submit-group EXISTING_GROUP

The installer, source snapshot, supplied Python runtime, configs, keys, and
token must be root controlled. cryptography 50.0.1 must already be installed
in the isolated Python runtime. The signer and requester must be separate OS
identities. The signer primary group is private; a separate submit group is
the only shared filesystem relationship.
EOF
  exit 2
}

die() {
  echo "protected release owner gateway install refused: $*" >&2
  exit 2
}

require_value() {
  [ "$#" -ge 2 ] || usage
  [ -n "$2" ] || die "$1 requires a non-empty value"
}

SLUG=''
SIGNER_CONFIG_SOURCE=''
SOURCE_CONFIG_SOURCE=''
PRIVATE_KEY_SOURCE=''
PUBLIC_KEY_SOURCE=''
BOT_TOKEN_SOURCE=''
PYTHON=''
SIGNER_USER=''
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
    --signer-config)
      require_value "$@"
      [ -z "$SIGNER_CONFIG_SOURCE" ] ||
        die "--signer-config was provided more than once"
      SIGNER_CONFIG_SOURCE="$2"
      shift 2
      ;;
    --discord-source-config)
      require_value "$@"
      [ -z "$SOURCE_CONFIG_SOURCE" ] ||
        die "--discord-source-config was provided more than once"
      SOURCE_CONFIG_SOURCE="$2"
      shift 2
      ;;
    --signing-private-key)
      require_value "$@"
      [ -z "$PRIVATE_KEY_SOURCE" ] ||
        die "--signing-private-key was provided more than once"
      PRIVATE_KEY_SOURCE="$2"
      shift 2
      ;;
    --signing-public-key)
      require_value "$@"
      [ -z "$PUBLIC_KEY_SOURCE" ] ||
        die "--signing-public-key was provided more than once"
      PUBLIC_KEY_SOURCE="$2"
      shift 2
      ;;
    --discord-bot-token)
      require_value "$@"
      [ -z "$BOT_TOKEN_SOURCE" ] ||
        die "--discord-bot-token was provided more than once"
      BOT_TOKEN_SOURCE="$2"
      shift 2
      ;;
    --python)
      require_value "$@"
      [ -z "$PYTHON" ] || die "--python was provided more than once"
      PYTHON="$2"
      shift 2
      ;;
    --signer-user)
      require_value "$@"
      [ -z "$SIGNER_USER" ] ||
        die "--signer-user was provided more than once"
      SIGNER_USER="$2"
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
  SLUG SIGNER_CONFIG_SOURCE SOURCE_CONFIG_SOURCE PRIVATE_KEY_SOURCE \
  PUBLIC_KEY_SOURCE BOT_TOKEN_SOURCE PYTHON SIGNER_USER REQUESTER_USER \
  SUBMIT_GROUP
do
  eval "required_value=\${$required}"
  [ -n "$required_value" ] || usage
done

[ "$(/usr/bin/id -u)" -eq 0 ] ||
  die "root is required; run only from a root-controlled source snapshot"
[ "$(/usr/bin/uname -s)" = "Darwin" ] ||
  die "this installer currently supports macOS only"

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

for identity in "$SIGNER_USER" "$REQUESTER_USER" "$SUBMIT_GROUP"; do
  [[ "$identity" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,63}$ ]] ||
    die "OS identity name contains unsafe characters"
done

SIGNER_UID="$(/usr/bin/id -u "$SIGNER_USER" 2>/dev/null)" ||
  die "signer user does not exist: $SIGNER_USER"
REQUESTER_UID="$(/usr/bin/id -u "$REQUESTER_USER" 2>/dev/null)" ||
  die "requester user does not exist: $REQUESTER_USER"
SIGNER_GID="$(/usr/bin/id -g "$SIGNER_USER" 2>/dev/null)" ||
  die "signer primary group is unavailable"
SIGNER_GROUP="$(/usr/bin/id -gn "$SIGNER_USER" 2>/dev/null)" ||
  die "signer primary group is unavailable"
SUBMIT_GID="$(
  /usr/bin/dscl . -read "/Groups/$SUBMIT_GROUP" PrimaryGroupID 2>/dev/null |
    /usr/bin/awk 'NR == 1 { print $2 }'
)"
for resolved_id in \
  "$SIGNER_UID" "$REQUESTER_UID" "$SIGNER_GID" "$SUBMIT_GID"
do
  case "$resolved_id" in
    ''|*[!0-9]*) die "resolved UID/GID values are invalid" ;;
  esac
done
if [ "$SIGNER_UID" -le 0 ] || [ "$REQUESTER_UID" -le 0 ]; then
  die "signer and requester users must not be root"
fi
if [ "$SIGNER_GID" -le 0 ] || [ "$SUBMIT_GID" -le 0 ]; then
  die "signer and submit groups must not be the root group"
fi
[ "$SIGNER_UID" -ne "$REQUESTER_UID" ] ||
  die "signer and requester must be different OS identities"
[ "$SIGNER_GID" -ne "$SUBMIT_GID" ] ||
  die "signer private group and submit group must differ"
[[ "$SIGNER_GROUP" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,63}$ ]] ||
  die "signer primary group name is unsafe"

user_has_gid() {
  local user="$1"
  local wanted="$2"
  local candidate
  for candidate in $(/usr/bin/id -G "$user"); do
    [ "$candidate" = "$wanted" ] && return 0
  done
  return 1
}

user_has_gid "$SIGNER_USER" "$SUBMIT_GID" ||
  die "signer user must belong to submit group $SUBMIT_GROUP"
user_has_gid "$REQUESTER_USER" "$SUBMIT_GID" ||
  die "requester user must belong to submit group $SUBMIT_GROUP"
if user_has_gid "$REQUESTER_USER" "$SIGNER_GID"; then
  die "requester user must not belong to the signer private group"
fi
DIRECTORY_USERS="$(/usr/bin/dscl . -list /Users)" ||
  die "local user directory could not be enumerated"
while IFS= read -r candidate_user; do
  [ -n "$candidate_user" ] || continue
  candidate_uid="$(/usr/bin/id -u "$candidate_user" 2>/dev/null)" || continue
  [ "$candidate_uid" -eq 0 ] && continue
  if \
    [ "$candidate_user" != "$SIGNER_USER" ] &&
    user_has_gid "$candidate_user" "$SIGNER_GID"
  then
    die "signer private group must be dedicated to the signer OS identity"
  fi
  if \
    [ "$candidate_user" != "$SIGNER_USER" ] &&
    [ "$candidate_user" != "$REQUESTER_USER" ] &&
    user_has_gid "$candidate_user" "$SUBMIT_GID"
  then
    die "submit group must be dedicated to signer and requester identities"
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
    *//*|*/./*|*/../*|*/.|*/..) die "$label must be normalized" ;;
  esac
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

uid_allowed() {
  case ",$2," in
    *",$1,"*) return 0 ;;
  esac
  return 1
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
    *) die "internal path-kind error" ;;
  esac
  while :; do
    [ ! -L "$current" ] || die "$label has a symlink in its path"
    uid="$(/usr/bin/stat -f '%u' "$current")" ||
      die "$label ownership could not be inspected"
    uid_allowed "$uid" "$allowed_uids" ||
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
  local parent="$path"
  validate_lexical_absolute_path "$path" "$label"
  if [ -e "$path" ] || [ -L "$path" ]; then
    validate_existing_path "$path" 0 any "$label"
    return
  fi
  while [ ! -e "$parent" ] && [ "$parent" != "/" ]; do
    parent="$(/usr/bin/dirname "$parent")"
  done
  validate_existing_path "$parent" 0 directory "$label nearest parent"
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
SOURCE_OWNER_DIR="$PRODUCT_ROOT/owner_gateway"
SOURCE_RELEASE_DIR="$PRODUCT_ROOT/release_broker"
SOURCE_ENTRYPOINT="$PRODUCT_ROOT/scripts/john-lomein-release-owner-sign.py"

validate_existing_path "$SCRIPT_PATH" 0 file "installer script"
validate_existing_path \
  "$SOURCE_OWNER_DIR" 0 directory "owner gateway source directory"
for source_file in \
  "$SOURCE_OWNER_DIR/__init__.py" \
  "$SOURCE_OWNER_DIR/john_lomein_release_owner_signer.py" \
  "$SOURCE_OWNER_DIR/john_lomein_discord_release_source.py"
do
  validate_existing_path "$source_file" 0 file "owner gateway source"
done
validate_existing_path \
  "$SOURCE_RELEASE_DIR" 0 directory "release protocol source directory"
for source_file in \
  "$SOURCE_RELEASE_DIR/__init__.py" \
  "$SOURCE_RELEASE_DIR/john_lomein_release_broker_protocol.py" \
  "$SOURCE_RELEASE_DIR/john_lomein_release_broker_github_app.py" \
  "$SOURCE_RELEASE_DIR/john_lomein_release_broker_github_live.py"
do
  validate_existing_path "$source_file" 0 file "release protocol dependency source"
done
validate_existing_path "$SOURCE_ENTRYPOINT" 0 file "owner signer entrypoint"
validate_existing_path "$PYTHON" 0 executable "owner gateway Python"
validate_existing_path "$SIGNER_CONFIG_SOURCE" 0 file "signer config source"
validate_existing_path \
  "$SOURCE_CONFIG_SOURCE" 0 file "Discord source config source"
validate_existing_path "$PRIVATE_KEY_SOURCE" 0 file "signing private-key source"
validate_existing_path "$PUBLIC_KEY_SOURCE" 0 file "signing public-key source"
validate_existing_path "$BOT_TOKEN_SOURCE" 0 file "Discord bot-token source"

for private_source in "$PRIVATE_KEY_SOURCE" "$BOT_TOKEN_SOURCE"; do
  private_mode="$(/usr/bin/stat -f '%Lp' "$private_source")"
  private_numeric="$(mode_value "$private_mode")"
  [ $((private_numeric & 0077)) -eq 0 ] ||
    die "private key and token sources must be root-only"
done

CONFIG_ROOT='/private/etc/john-lomein-release-owner-gateway.d'
PUBLIC_ROOT='/private/etc/john-lomein-release-owner-gateway-public'
DATA_ROOT='/private/var/db/john-lomein-release-owner-gateway'
STATE_ROOT="$DATA_ROOT/state"
STATE_DIR="$STATE_ROOT/$SLUG"
TMP_DIR="$STATE_DIR/tmp"
REQUEST_ROOT="$DATA_ROOT/requests"
REQUEST_DIR="$REQUEST_ROOT/$SLUG"
SECRETS_DIR="$CONFIG_ROOT/$SLUG.secrets"
SIGNER_CONFIG_PATH="$CONFIG_ROOT/$SLUG.signer.json"
SOURCE_CONFIG_PATH="$CONFIG_ROOT/$SLUG.discord-source.json"
PRIVATE_KEY_PATH="$SECRETS_DIR/owner-assertion-ed25519.pem"
PUBLIC_KEY_PATH="$SECRETS_DIR/owner-assertion-ed25519.pub.pem"
BOT_TOKEN_PATH="$SECRETS_DIR/discord-observer-bot.token"
WRAPPER_PARENT='/usr/local/libexec/john-lomein-release-owner-gateway-instances'
WRAPPER_DIR="$WRAPPER_PARENT/$SLUG"
CODE_ROOT="$WRAPPER_DIR/code"
ENTRYPOINT="$CODE_ROOT/scripts/john-lomein-release-owner-sign.py"
WRAPPER_PATH="$WRAPPER_DIR/mint"
PUBLIC_CONFIG_PATH="$PUBLIC_ROOT/$SLUG.json"
SUDOERS_DIR='/private/etc/sudoers.d'
SUDOERS_PATH="$SUDOERS_DIR/john-lomein-release-owner-$SUDOERS_SAFE_SLUG"

TEMP_DIR="$(
  /usr/bin/mktemp -d /private/tmp/john-lomein-owner-gateway-install.XXXXXX
)"
/bin/chmod 0700 "$TEMP_DIR"
ROLLBACK_DIR="$TEMP_DIR/rollback"
/usr/bin/install -d -o root -g wheel -m 0700 "$ROLLBACK_DIR"
TRANSACTION_STARTED=0
TRANSACTION_COMMITTED=0
FILES_MUTATED=0
CODE_INSTALLED=0
CODE_BACKUP=''

restore_managed_file() {
  local backup="$1"
  local destination="$2"
  local staged
  if [ -f "$backup" ]; then
    [ ! -d "$destination" ] || return 1
    staged="$(/usr/bin/mktemp "$destination.rollback.XXXXXX")" || return 1
    /bin/cp -p "$backup" "$staged" || return 1
    /bin/mv -f "$staged" "$destination" || return 1
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
  trap - EXIT
  if \
    [ "$status" -ne 0 ] &&
    [ "$TRANSACTION_STARTED" -eq 1 ] &&
    [ "$TRANSACTION_COMMITTED" -eq 0 ]
  then
    if [ "$FILES_MUTATED" -eq 1 ]; then
      restore_managed_file \
        "$ROLLBACK_DIR/signer-config.json" "$SIGNER_CONFIG_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/source-config.json" "$SOURCE_CONFIG_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/private-key.pem" "$PRIVATE_KEY_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/public-key.pem" "$PUBLIC_KEY_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/bot-token" "$BOT_TOKEN_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/mint-wrapper" "$WRAPPER_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/public-config.json" "$PUBLIC_CONFIG_PATH" ||
        cleanup_status=1
      restore_managed_file \
        "$ROLLBACK_DIR/sudoers" "$SUDOERS_PATH" ||
        cleanup_status=1
    fi
    if [ -n "$CODE_BACKUP" ] && [ -d "$CODE_BACKUP" ]; then
      if [ -d "$CODE_ROOT" ] && [ ! -L "$CODE_ROOT" ]; then
        /bin/rm -rf "$CODE_ROOT" || cleanup_status=1
      else
        cleanup_status=1
      fi
      if [ ! -e "$CODE_ROOT" ] && [ ! -L "$CODE_ROOT" ]; then
        /bin/mv "$CODE_BACKUP" "$CODE_ROOT" || cleanup_status=1
      else
        cleanup_status=1
      fi
    elif [ "$CODE_INSTALLED" -eq 1 ]; then
      if [ -d "$CODE_ROOT" ] && [ ! -L "$CODE_ROOT" ]; then
        /bin/rm -rf "$CODE_ROOT" || cleanup_status=1
      else
        cleanup_status=1
      fi
    fi
    if [ -f "$SUDOERS_PATH" ]; then
      /usr/sbin/visudo -cf "$SUDOERS_PATH" >/dev/null 2>&1 ||
        cleanup_status=1
    fi
  fi
  [ ! -d "${TEMP_DIR:-}" ] || /bin/rm -rf "$TEMP_DIR"
  if [ "$cleanup_status" -ne 0 ]; then
    echo \
      "protected release owner gateway rollback was incomplete; invocation remains fail-closed" \
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
paths = {
    ("executable", sys.executable),
    ("base_executable", getattr(sys, "_base_executable", "")),
    ("prefix", sys.prefix),
    ("base_prefix", sys.base_prefix),
    ("exec_prefix", sys.exec_prefix),
    ("base_exec_prefix", sys.base_exec_prefix),
}
paths.update(("sys_path", value) for value in sys.path if value)
for kind, value in sorted(paths):
    if value and any(character in value for character in "\n\r\t"):
        raise SystemExit("Python runtime path contains a control character")
    if value:
        print(f"{kind}\t{value}")
' >"$PYTHON_REPORT"
while IFS=$'\t' read -r path_kind runtime_path; do
  if [ -z "$path_kind" ] || [ -z "$runtime_path" ]; then
    die "Python runtime path report is malformed"
  fi
  [ "$path_kind" != "executable" ] || [ "$runtime_path" = "$PYTHON" ] ||
    die "Python sys.executable differs from the supplied interpreter"
  validate_runtime_path "$runtime_path" "Python $path_kind"
done <"$PYTHON_REPORT"

CRYPTOGRAPHY_REPORT="$TEMP_DIR/cryptography-paths.tsv"
"$PYTHON" -I -B -c '
import importlib.metadata
import pathlib
import sys
import sysconfig
import cryptography
from cryptography.hazmat.bindings import _rust
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

if cryptography.__version__ != "50.0.1":
    raise SystemExit(
        "the release owner gateway requires locked cryptography 50.0.1"
    )
native = getattr(_rust, "__file__", "")
if not native or not pathlib.Path(native).is_file():
    raise SystemExit("cryptography native binding is unavailable")
reported = {
    ("cryptography_package", str(pathlib.Path(cryptography.__file__).parent)),
    ("cryptography_native_binding", native),
    (
        "cryptography_distribution",
        str(pathlib.Path(importlib.metadata.distribution("cryptography").locate_file(""))),
    ),
}
reported.update(("sysconfig", value) for value in sysconfig.get_paths().values())
reported.update(("sys_path", value) for value in sys.path if value)
for kind, value in sorted(reported):
    if value:
        print(f"{kind}\t{value}")
' >"$CRYPTOGRAPHY_REPORT"
while IFS=$'\t' read -r path_kind runtime_path; do
  if [ -z "$path_kind" ] || [ -z "$runtime_path" ]; then
    die "cryptography path report is malformed"
  fi
  validate_runtime_path "$runtime_path" "$path_kind"
done <"$CRYPTOGRAPHY_REPORT"

snapshot_input() {
  local source="$1"
  local destination="$2"
  local maximum="$3"
  local privacy="$4"
  local marker="$5"
  "$PYTHON" -I -B -S - \
    "$source" "$destination" "$maximum" "$privacy" "$marker" <<'PY'
import os
import stat
import sys

source, destination, raw_maximum, privacy, marker = sys.argv[1:]
maximum = int(raw_maximum)
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
if not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("O_NOFOLLOW is required")
flags |= os.O_NOFOLLOW
source_fd = os.open(source, flags)
try:
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("input must be a singly linked regular file")
    if before.st_uid != 0 or before.st_mode & 0o022:
        raise SystemExit("input ownership or write permissions are unsafe")
    if privacy == "private" and before.st_mode & 0o077:
        raise SystemExit("private input grants group or other permissions")
    if before.st_size < 1 or before.st_size > maximum:
        raise SystemExit("input exceeds the installation size limit")
    payload = bytearray()
    while len(payload) <= maximum:
        chunk = os.read(source_fd, min(65536, maximum + 1 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
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
    if not payload or len(payload) > maximum:
        raise SystemExit("input exceeds the installation size limit")
    if marker and marker.encode("ascii") not in payload:
        raise SystemExit("key input is not the expected PEM form")
    output_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
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

SIGNER_CONFIG_SNAPSHOT="$TEMP_DIR/signer-config.json"
SOURCE_CONFIG_SNAPSHOT="$TEMP_DIR/source-config.json"
PRIVATE_KEY_SNAPSHOT="$TEMP_DIR/private-key.pem"
PUBLIC_KEY_SNAPSHOT="$TEMP_DIR/public-key.pem"
BOT_TOKEN_SNAPSHOT="$TEMP_DIR/bot-token"
snapshot_input \
  "$SIGNER_CONFIG_SOURCE" "$SIGNER_CONFIG_SNAPSHOT" 262144 public ''
snapshot_input \
  "$SOURCE_CONFIG_SOURCE" "$SOURCE_CONFIG_SNAPSHOT" 131072 public ''
snapshot_input \
  "$PRIVATE_KEY_SOURCE" "$PRIVATE_KEY_SNAPSHOT" 65536 private 'PRIVATE KEY'
snapshot_input \
  "$PUBLIC_KEY_SOURCE" "$PUBLIC_KEY_SNAPSHOT" 65536 public 'PUBLIC KEY'
snapshot_input "$BOT_TOKEN_SOURCE" "$BOT_TOKEN_SNAPSHOT" 512 private ''

ENABLED="$(
  "$PYTHON" -I -B - "$PRODUCT_ROOT" \
    "$SIGNER_CONFIG_SNAPSHOT" "$SOURCE_CONFIG_SNAPSHOT" \
    "$PRIVATE_KEY_SNAPSHOT" "$PUBLIC_KEY_SNAPSHOT" "$BOT_TOKEN_SNAPSHOT" \
    "$SLUG" "$SIGNER_UID" "$SIGNER_GID" "$REQUESTER_UID" \
    "$SIGNER_CONFIG_PATH" "$SOURCE_CONFIG_PATH" "$PRIVATE_KEY_PATH" \
    "$PUBLIC_KEY_PATH" "$BOT_TOKEN_PATH" "$STATE_DIR" <<'PY'
import hashlib
import pathlib
import sys

(
    product_root,
    signer_config_path,
    source_config_path,
    private_key_path,
    public_key_path,
    token_path,
    slug,
    signer_uid,
    signer_gid,
    requester_uid,
    expected_signer_config_path,
    expected_source_config_path,
    expected_private_key_path,
    expected_public_key_path,
    expected_token_path,
    expected_state_path,
) = sys.argv[1:]
sys.path.insert(0, product_root)
from owner_gateway import john_lomein_discord_release_source as source
from owner_gateway import john_lomein_release_owner_signer as signer
from release_broker import john_lomein_release_broker_protocol as protocol

signer_config = signer.normalize_signer_config(
    protocol.parse_json_bytes(
        pathlib.Path(signer_config_path).read_bytes(),
        field="release owner signer config",
        maximum_bytes=signer.MAX_CONFIG_BYTES,
    )
)
source_config = source.normalize_source_config(
    protocol.parse_json_bytes(
        pathlib.Path(source_config_path).read_bytes(),
        field="Discord release source config",
        maximum_bytes=source.MAX_SOURCE_CONFIG_BYTES,
    ),
    signer_config,
)
checks = (
    (signer_config["instance"]["slug"] == slug, "instance slug"),
    (signer_config["signer_uid"] == int(signer_uid), "signer UID"),
    (signer_config["signer_gid"] == int(signer_gid), "signer GID"),
    (signer_config["runtime_uid"] == int(requester_uid), "runtime UID"),
    (
        signer_config["private_key_path"] == expected_private_key_path,
        "private-key path",
    ),
    (
        signer_config["public_key_path"] == expected_public_key_path,
        "public-key path",
    ),
    (
        signer_config["state_directory"] == expected_state_path,
        "state directory",
    ),
    (
        source_config["bot_token_path"] == expected_token_path,
        "Discord token path",
    ),
    (
        source_config["signer_config_sha256"]
        == protocol.sha256_json(signer_config),
        "signer config digest",
    ),
    (
        signer_config["enabled"] is source_config["enabled"],
        "coordinated enablement",
    ),
)
for passed, label in checks:
    if not passed:
        raise SystemExit(
            f"release owner gateway config {label} does not match installer binding"
        )

private_bytes = pathlib.Path(private_key_path).read_bytes()
public_bytes = pathlib.Path(public_key_path).read_bytes()
signer._load_key_pair(
    private_bytes,
    public_bytes,
    expected_public_key_sha256=signer_config["public_key_sha256"],
)
if (
    "sha256:" + hashlib.sha256(public_bytes).hexdigest()
    != signer_config["public_key_sha256"]
):
    raise SystemExit("signer public-key fingerprint does not match config")
token = pathlib.Path(token_path).read_bytes()
if token.endswith(b"\n"):
    token = token[:-1]
if b"\n" in token or b"\r" in token:
    raise SystemExit("Discord observer bot token is invalid")
try:
    token_text = token.decode("ascii", errors="strict")
except UnicodeError as exc:
    raise SystemExit("Discord observer bot token is invalid") from exc
if not source.BOT_TOKEN_RE.fullmatch(token_text):
    raise SystemExit("Discord observer bot token is invalid")
print("1" if signer_config["enabled"] else "0")
PY
)"
[ "$ENABLED" = 0 ] || [ "$ENABLED" = 1 ] ||
  die "owner gateway config preflight returned invalid enablement"

ensure_root_directory() {
  local path="$1"
  local mode="$2"
  local label="$3"
  local parent
  if [ -e "$path" ] || [ -L "$path" ]; then
    validate_existing_path "$path" 0 directory "$label"
    [ "$((8#$(/usr/bin/stat -f '%Lp' "$path")))" -eq "$((8#$mode))" ] ||
      die "$label mode does not match"
    return
  fi
  parent="$(/usr/bin/dirname "$path")"
  validate_existing_path "$parent" 0 directory "$label parent"
  /usr/bin/install -d -o root -g wheel -m "$mode" "$path"
  validate_existing_path "$path" 0 directory "$label"
}

ensure_exact_directory() {
  local path="$1"
  local owner="$2"
  local group="$3"
  local mode="$4"
  local owner_uid="$5"
  local group_gid="$6"
  local label="$7"
  local parent
  if [ -e "$path" ] || [ -L "$path" ]; then
    if [ -L "$path" ] || [ ! -d "$path" ]; then
      die "$label is not a safe directory"
    fi
  else
    parent="$(/usr/bin/dirname "$path")"
    if [ ! -d "$parent" ] || [ -L "$parent" ]; then
      die "$label parent is unsafe"
    fi
    /usr/bin/install -d -o "$owner" -g "$group" -m "$mode" "$path"
  fi
  [ "$(/usr/bin/stat -f '%u' "$path")" -eq "$owner_uid" ] ||
    die "$label owner does not match"
  [ "$(/usr/bin/stat -f '%g' "$path")" -eq "$group_gid" ] ||
    die "$label group does not match"
  [ "$((8#$(/usr/bin/stat -f '%Lp' "$path")))" -eq "$((8#$mode))" ] ||
    die "$label mode does not match"
  reject_acl "$path" "$label"
}

ensure_root_directory "$CONFIG_ROOT" 0755 "gateway config root"
ensure_root_directory "$PUBLIC_ROOT" 0755 "gateway public config root"
ensure_root_directory "$DATA_ROOT" 0755 "gateway data root"
ensure_root_directory "$STATE_ROOT" 0755 "gateway state root"
ensure_root_directory "$REQUEST_ROOT" 0755 "gateway request root"
ensure_root_directory "$WRAPPER_PARENT" 0755 "gateway wrapper root"
validate_existing_path "$SUDOERS_DIR" 0 directory "sudoers include directory"

ensure_exact_directory \
  "$SECRETS_DIR" root "$SIGNER_GROUP" 0750 0 "$SIGNER_GID" \
  "gateway secrets directory"
ensure_exact_directory \
  "$STATE_DIR" "$SIGNER_USER" "$SIGNER_GROUP" 0700 \
  "$SIGNER_UID" "$SIGNER_GID" "gateway state directory"
ensure_exact_directory \
  "$TMP_DIR" "$SIGNER_USER" "$SIGNER_GROUP" 0700 \
  "$SIGNER_UID" "$SIGNER_GID" "gateway temporary directory"
ensure_exact_directory \
  "$REQUEST_DIR" root "$SUBMIT_GROUP" 2770 0 "$SUBMIT_GID" \
  "gateway request spool"
ensure_exact_directory \
  "$WRAPPER_DIR" root wheel 0755 0 0 "gateway instance wrapper directory"

backup_optional_file() {
  local source="$1"
  local backup="$2"
  "$PYTHON" -I -B -S - "$source" "$backup" <<'PY'
import os
import stat
import sys

source, backup = sys.argv[1:]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
if not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("O_NOFOLLOW is required")
flags |= os.O_NOFOLLOW
try:
    source_fd = os.open(source, flags)
except FileNotFoundError:
    raise SystemExit(0)
try:
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("rollback source is not a singly linked regular file")
    payload = bytearray()
    while len(payload) <= 4 * 1024 * 1024:
        chunk = os.read(source_fd, 65536)
        if not chunk:
            break
        payload.extend(chunk)
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
    backup_fd = os.open(
        backup,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(backup_fd, view)
            if written <= 0:
                raise SystemExit("rollback snapshot made no progress")
            view = view[written:]
        os.fchown(backup_fd, before.st_uid, before.st_gid)
        os.fchmod(backup_fd, stat.S_IMODE(before.st_mode))
        os.fsync(backup_fd)
    finally:
        os.close(backup_fd)
finally:
    os.close(source_fd)
PY
}

for pair in \
  "$SIGNER_CONFIG_PATH:$ROLLBACK_DIR/signer-config.json" \
  "$SOURCE_CONFIG_PATH:$ROLLBACK_DIR/source-config.json" \
  "$PRIVATE_KEY_PATH:$ROLLBACK_DIR/private-key.pem" \
  "$PUBLIC_KEY_PATH:$ROLLBACK_DIR/public-key.pem" \
  "$BOT_TOKEN_PATH:$ROLLBACK_DIR/bot-token" \
  "$WRAPPER_PATH:$ROLLBACK_DIR/mint-wrapper" \
  "$PUBLIC_CONFIG_PATH:$ROLLBACK_DIR/public-config.json" \
  "$SUDOERS_PATH:$ROLLBACK_DIR/sudoers"
do
  backup_optional_file "${pair%%:*}" "${pair#*:}"
done

CODE_STAGE="$TEMP_DIR/code"
/usr/bin/install -d -o root -g wheel -m 0755 \
  "$CODE_STAGE/owner_gateway" "$CODE_STAGE/release_broker" \
  "$CODE_STAGE/scripts"
for source_file in \
  "$SOURCE_OWNER_DIR/__init__.py" \
  "$SOURCE_OWNER_DIR/john_lomein_release_owner_signer.py" \
  "$SOURCE_OWNER_DIR/john_lomein_discord_release_source.py"
do
  /usr/bin/install -o root -g wheel -m 0444 \
    "$source_file" "$CODE_STAGE/owner_gateway/"
done
for source_file in \
  "$SOURCE_RELEASE_DIR/__init__.py" \
  "$SOURCE_RELEASE_DIR/john_lomein_release_broker_protocol.py" \
  "$SOURCE_RELEASE_DIR/john_lomein_release_broker_github_app.py" \
  "$SOURCE_RELEASE_DIR/john_lomein_release_broker_github_live.py"
do
  /usr/bin/install -o root -g wheel -m 0444 \
    "$source_file" "$CODE_STAGE/release_broker/"
done
/usr/bin/install -o root -g wheel -m 0555 \
  "$SOURCE_ENTRYPOINT" "$CODE_STAGE/scripts/john-lomein-release-owner-sign.py"

WRAPPER_SNAPSHOT="$TEMP_DIR/mint-wrapper"
"$PYTHON" -I -B -S - \
  "$WRAPPER_SNAPSHOT" "$SIGNER_UID" "$SIGNER_GID" "$REQUEST_DIR" \
  "$PYTHON" "$ENTRYPOINT" "$SIGNER_CONFIG_PATH" "$SOURCE_CONFIG_PATH" \
  "$TMP_DIR" <<'PY'
import pathlib
import shlex
import sys

(
    destination,
    signer_uid,
    signer_gid,
    request_dir,
    python,
    entrypoint,
    signer_config,
    source_config,
    tmp_dir,
) = sys.argv[1:]
q = shlex.quote
body = f"""#!/bin/bash
set -Eeuo pipefail
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
umask 077

die() {{
  echo "release owner gateway invocation refused: $*" >&2
  exit 2
}}

[ "$(/usr/bin/id -u)" -eq {signer_uid} ] ||
  die "process UID is not the configured signer"
[ "$(/usr/bin/id -g)" -eq {signer_gid} ] ||
  die "process GID is not the configured signer group"
if [ "$#" -eq 1 ] && [ "$1" = "--status" ]; then
  exec /usr/bin/env -i \\
    HOME=/private/var/empty \\
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \\
    PYTHONDONTWRITEBYTECODE=1 \\
    TMPDIR={q(tmp_dir)} \\
    {q(python)} -I -B {q(entrypoint)} self-check \\
      --config {q(signer_config)} \\
      --discord-source-config {q(source_config)}
fi
[ "$#" -eq 6 ] || die "expected --bundle, --channel-id, and --message-id"
[ "$1" = "--bundle" ] && [ "$3" = "--channel-id" ] &&
  [ "$5" = "--message-id" ] ||
  die "arguments must use the fixed documented order"
BUNDLE="$2"
CHANNEL_ID="$4"
MESSAGE_ID="$6"
REQUEST_SPOOL={q(request_dir)}
case "$BUNDLE" in
  "$REQUEST_SPOOL"/*.json) ;;
  *) die "bundle must be an absolute JSON path in the instance request spool" ;;
esac
BUNDLE_NAME="${{BUNDLE#"$REQUEST_SPOOL"/}}"
case "$BUNDLE_NAME" in
  */*) die "bundle must be a direct child of the instance request spool" ;;
esac
case "$BUNDLE" in
  *//*|*/./*|*/../*|*/.|*/..|*$'\\n'*|*$'\\r'*|*$'\\t'*)
    die "bundle path is not normalized"
    ;;
esac
[[ "$CHANNEL_ID" =~ ^[0-9]{{17,20}}$ ]] ||
  die "channel ID is not a Discord snowflake"
[[ "$MESSAGE_ID" =~ ^[0-9]{{17,20}}$ ]] ||
  die "message ID is not a Discord snowflake"

exec /usr/bin/env -i \\
  HOME=/private/var/empty \\
  PATH=/usr/bin:/bin:/usr/sbin:/sbin \\
  PYTHONDONTWRITEBYTECODE=1 \\
  TMPDIR={q(tmp_dir)} \\
  {q(python)} -I -B {q(entrypoint)} mint \\
    --config {q(signer_config)} \\
    --discord-source-config {q(source_config)} \\
    --bundle "$BUNDLE" \\
    --channel-id "$CHANNEL_ID" \\
    --message-id "$MESSAGE_ID"
"""
pathlib.Path(destination).write_text(body, encoding="utf-8")
PY
/bin/chmod 0555 "$WRAPPER_SNAPSHOT"
/bin/bash -n "$WRAPPER_SNAPSHOT" ||
  die "generated signer wrapper has invalid shell syntax"

PUBLIC_CONFIG_SNAPSHOT="$TEMP_DIR/public-config.json"
"$PYTHON" -I -B - "$PUBLIC_CONFIG_SNAPSHOT" "$SLUG" \
  "$SIGNER_CONFIG_SNAPSHOT" "$REQUESTER_UID" "$SIGNER_USER" \
  "$SIGNER_GROUP" "$REQUEST_DIR" "$WRAPPER_PATH" <<'PY'
import json
import pathlib
import sys

(
    destination,
    slug,
    signer_config_path,
    requester_uid,
    signer_user,
    signer_group,
    request_dir,
    wrapper_path,
) = sys.argv[1:]
config = json.loads(pathlib.Path(signer_config_path).read_text(encoding="utf-8"))
public = {
    "schema_version": "john-lomein.release-owner-gateway-invocation.v2",
    "instance_slug": slug,
    "repository_full_name": config["instance"]["repository"]["full_name"],
    "approval_channel_ids": config["discord"]["approval_channel_ids"],
    "requester_uid": int(requester_uid),
    "signer_user": signer_user,
    "signer_primary_group": signer_group,
    "request_spool_dir": request_dir,
    "wrapper_path": wrapper_path,
}
pathlib.Path(destination).write_text(
    json.dumps(public, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

SUDOERS_SNAPSHOT="$TEMP_DIR/sudoers"
SUDOERS_ALIAS="$(
  /bin/echo "JLROG_$SUDOERS_SAFE_SLUG" |
    /usr/bin/tr '[:lower:].-' '[:upper:]__'
)"
{
  echo "# Managed by John Lomein; do not edit."
  echo "Cmnd_Alias $SUDOERS_ALIAS = $WRAPPER_PATH *"
  echo "Defaults!$SUDOERS_ALIAS env_reset, !setenv, umask=0077"
  echo \
    "$REQUESTER_USER ALL=($SIGNER_USER:$SIGNER_GROUP) NOPASSWD: $SUDOERS_ALIAS"
} >"$SUDOERS_SNAPSHOT"
/bin/chmod 0440 "$SUDOERS_SNAPSHOT"
/usr/sbin/visudo -cf "$SUDOERS_SNAPSHOT" >/dev/null ||
  die "generated sudoers policy is invalid"

install_managed_file() {
  local source="$1"
  local destination="$2"
  local owner="$3"
  local group="$4"
  local mode="$5"
  local staged
  [ ! -L "$destination" ] || die "managed destination is a symlink"
  [ ! -d "$destination" ] || die "managed destination is a directory"
  staged="$(/usr/bin/mktemp "$destination.install.XXXXXX")"
  /usr/bin/install -o "$owner" -g "$group" -m "$mode" "$source" "$staged"
  /bin/mv -f "$staged" "$destination"
}

TRANSACTION_STARTED=1
FILES_MUTATED=1
if [ -e "$CODE_ROOT" ] || [ -L "$CODE_ROOT" ]; then
  if [ ! -d "$CODE_ROOT" ] || [ -L "$CODE_ROOT" ]; then
    die "installed owner gateway code root is unsafe"
  fi
  CODE_BACKUP="$TEMP_DIR/code.backup"
  /bin/mv "$CODE_ROOT" "$CODE_BACKUP"
fi
/bin/mv "$CODE_STAGE" "$CODE_ROOT"
CODE_INSTALLED=1

install_managed_file \
  "$SIGNER_CONFIG_SNAPSHOT" "$SIGNER_CONFIG_PATH" root "$SIGNER_GROUP" 0440
install_managed_file \
  "$SOURCE_CONFIG_SNAPSHOT" "$SOURCE_CONFIG_PATH" root "$SIGNER_GROUP" 0440
install_managed_file \
  "$PRIVATE_KEY_SNAPSHOT" "$PRIVATE_KEY_PATH" root "$SIGNER_GROUP" 0640
install_managed_file \
  "$PUBLIC_KEY_SNAPSHOT" "$PUBLIC_KEY_PATH" root "$SIGNER_GROUP" 0440
install_managed_file \
  "$BOT_TOKEN_SNAPSHOT" "$BOT_TOKEN_PATH" root "$SIGNER_GROUP" 0640
install_managed_file \
  "$WRAPPER_SNAPSHOT" "$WRAPPER_PATH" root wheel 0555
install_managed_file \
  "$PUBLIC_CONFIG_SNAPSHOT" "$PUBLIC_CONFIG_PATH" root wheel 0444

if [ "$ENABLED" -eq 0 ]; then
  /bin/rm -f "$SUDOERS_PATH"
else
  install_managed_file \
    "$SUDOERS_SNAPSHOT" "$SUDOERS_PATH" root wheel 0440
  /usr/sbin/visudo -cf "$SUDOERS_PATH" >/dev/null ||
    die "installed sudoers policy is invalid"
  /usr/sbin/visudo -c >/dev/null ||
    die "system sudoers policy is invalid after gateway installation"
  /usr/bin/sudo -n -l \
    -U "$REQUESTER_USER" \
    -u "$SIGNER_USER" \
    -g "$SIGNER_GROUP" \
    -- "$WRAPPER_PATH" --status \
    >/dev/null ||
    die "installed sudoers policy is not effective for the requester"
  /usr/bin/sudo -n \
    -u "$SIGNER_USER" \
    -g "$SIGNER_GROUP" \
    -- "$WRAPPER_PATH" --status \
    >/dev/null ||
    die "installed release owner gateway self-check failed"
fi

"$PYTHON" -I -B "$ENTRYPOINT" --help >/dev/null
TRANSACTION_COMMITTED=1
if [ -n "$CODE_BACKUP" ] && [ -d "$CODE_BACKUP" ]; then
  /bin/rm -rf "$CODE_BACKUP"
  CODE_BACKUP=''
fi

if [ "$ENABLED" -eq 0 ]; then
  echo "protected release owner gateway installed disabled: $SLUG"
  echo "runtime sudo authorization was not installed"
else
  echo "protected release owner gateway installed and invocation authorized: $SLUG"
fi
echo "public invocation config: $PUBLIC_CONFIG_PATH"
echo "request spool: $REQUEST_DIR"
echo "fixed signer wrapper: $WRAPPER_PATH"
