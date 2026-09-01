#!/bin/bash
# Install the inert macOS scaffold for protected persona qualification.
#
# SECURITY MODEL
# This installer creates the durable identities, immutable source bundles,
# fixed control files, public pins, and disabled launch surface needed by a
# future protected qualification transaction.  It does not activate capture,
# verification, signing, or publication.  It never writes a canary receipt,
# enables a launchd job, or bootstraps a LaunchDaemon.
#
# Run only from a reviewed root-owned product snapshot. Runtime transaction-
# journal orchestration, installed-launcher binding, native dependency
# closure, and privileged canaries remain intentional hard stops.
set -Eeuo pipefail

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
PYTHONDONTWRITEBYTECODE=1
export PYTHONDONTWRITEBYTECODE
umask 077

usage() {
  cat >&2 <<'EOF'
usage:
  install-protected-persona-qualification.sh \
    --slug SLUG \
    --config /absolute/root-owned/install-config.json \
    --attestor-private-key /absolute/secure/attestor-ed25519.pem \
    --attestor-public-key /absolute/secure/attestor-ed25519.pub.pem \
    --python /absolute/root-owned/python3 \
    --evidence-user EXISTING_RUNTIME_USER

This command installs a disabled scaffold only. The config must contain
"enabled": false. It derives three non-login service users and four groups
from sha256(SLUG), installs separate content-addressed role bundles, writes a
root-owned sparse selection, transaction-journal namespace and control, and
public verifier pin, then installs a disabled LaunchDaemon plist. The journal
is not connected to runtime orchestration. This installer never bootstraps or
enables that job and never emits an activation receipt.

The installer, product source, Python runtime, config, and keys must be staged
under root-controlled, non-symlinked ancestor chains. cryptography 49.0.0 and
PyYAML >=6.0.2,<7 must be importable by the supplied Python for installation
preflight. Their successful import is not a native-closure qualification.
EOF
  exit 2
}

die() {
  echo "protected persona qualification install refused: $*" >&2
  exit 2
}

require_value() {
  [ "$#" -ge 2 ] || usage
  [ -n "$2" ] || die "$1 requires a non-empty value"
}

SLUG=''
CONFIG_SOURCE=''
PRIVATE_KEY_SOURCE=''
PUBLIC_KEY_SOURCE=''
PYTHON=''
EVIDENCE_USER=''

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
    --attestor-private-key)
      require_value "$@"
      [ -z "$PRIVATE_KEY_SOURCE" ] ||
        die "--attestor-private-key was provided more than once"
      PRIVATE_KEY_SOURCE="$2"
      shift 2
      ;;
    --attestor-public-key)
      require_value "$@"
      [ -z "$PUBLIC_KEY_SOURCE" ] ||
        die "--attestor-public-key was provided more than once"
      PUBLIC_KEY_SOURCE="$2"
      shift 2
      ;;
    --python)
      require_value "$@"
      [ -z "$PYTHON" ] || die "--python was provided more than once"
      PYTHON="$2"
      shift 2
      ;;
    --evidence-user)
      require_value "$@"
      [ -z "$EVIDENCE_USER" ] ||
        die "--evidence-user was provided more than once"
      EVIDENCE_USER="$2"
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
  SLUG CONFIG_SOURCE PRIVATE_KEY_SOURCE PUBLIC_KEY_SOURCE PYTHON EVIDENCE_USER
do
  eval "required_value=\${$required}"
  [ -n "$required_value" ] || usage
done

[ "$(/usr/bin/id -u)" -eq 0 ] ||
  die "root is required; run only from a root-controlled source snapshot"
[ "$(/usr/bin/uname -s)" = "Darwin" ] ||
  die "this installer currently supports macOS LaunchDaemons only"
[[ "$SLUG" =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]] ||
  die "slug contains unsafe characters"
[[ "$EVIDENCE_USER" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,63}$ ]] ||
  die "evidence user name contains unsafe characters"

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

reject_xattrs() {
  local path="$1"
  local label="$2"
  local attributes attribute
  attributes="$(/usr/bin/xattr "$path" 2>/dev/null)" ||
    die "$label extended attributes could not be inspected"
  while IFS= read -r attribute; do
    [ -n "$attribute" ] || continue
    case "$attribute" in
      com.apple.provenance|com.apple.rootless) ;;
      *) die "$label has unsupported extended attributes" ;;
    esac
  done <<<"$attributes"
}

uid_allowed() {
  local actual="$1"
  local allowed="$2"
  local candidate
  IFS=',' read -r -a candidates <<<"$allowed"
  for candidate in "${candidates[@]}"; do
    [ "$actual" = "$candidate" ] && return 0
  done
  return 1
}

validate_existing_path() {
  local path="$1"
  local allowed_uids="$2"
  local expected_kind="$3"
  local label="$4"
  local current="$path"
  local owner mode kind

  validate_lexical_absolute_path "$path" "$label"
  while true; do
    [ ! -L "$current" ] || die "$label has a symlink path component"
    [ -e "$current" ] || die "$label is missing: $current"
    owner="$(/usr/bin/stat -f '%u' "$current")" ||
      die "$label owner could not be inspected"
    uid_allowed "$owner" "$allowed_uids" ||
      die "$label has an untrusted owner in its ancestor chain"
    mode="$(/usr/bin/stat -f '%Lp' "$current")" ||
      die "$label mode could not be inspected"
    case "$mode" in ''|*[!0-7]*) die "$label mode is invalid" ;; esac
    [ $(((8#$mode) & 0022)) -eq 0 ] ||
      die "$label has a group/other-writable path component"
    reject_acl "$current" "$label"
    [ "$current" = "/" ] && break
    current="$(/usr/bin/dirname "$current")"
  done

  case "$expected_kind" in
    file)
      [ -f "$path" ] && [ ! -L "$path" ] ||
        die "$label must be a regular non-symlink file"
      [ "$(/usr/bin/stat -f '%l' "$path")" -eq 1 ] ||
        die "$label must be a singly linked regular file"
      ;;
    directory)
      [ -d "$path" ] && [ ! -L "$path" ] ||
        die "$label must be a non-symlink directory"
      ;;
    executable)
      [ -f "$path" ] && [ ! -L "$path" ] && [ -x "$path" ] ||
        die "$label must be a regular executable"
      ;;
    *) die "internal path-kind error" ;;
  esac
}

validate_private_input() {
  local path="$1"
  local label="$2"
  validate_existing_path "$path" 0 file "$label"
  local mode
  mode="$(/usr/bin/stat -f '%Lp' "$path")"
  [ $(((8#$mode) & 0077)) -eq 0 ] ||
    die "$label grants group or other permissions"
}

validate_private_file_owner() {
  local path="$1"
  local expected_uid="$2"
  local label="$3"
  local current mode
  validate_existing_path "$path" "0,$expected_uid" file "$label"
  [ "$(/usr/bin/stat -f '%u' "$path")" = "$expected_uid" ] ||
    die "$label has the wrong owner"
  mode="$(/usr/bin/stat -f '%Lp' "$path")" ||
    die "$label mode could not be inspected"
  [ $(((8#$mode) & 0077)) -eq 0 ] ||
    die "$label must not grant group or other permissions"
  current="$path"
  while true; do
    reject_xattrs "$current" "$label"
    [ "$current" = "/" ] && break
    current="$(/usr/bin/dirname "$current")"
  done
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

validate_existing_path "$SCRIPT_PATH" 0 file "installer script"
validate_existing_path "$PRODUCT_ROOT" 0 directory "product source"
validate_existing_path "$CONFIG_SOURCE" 0 file "install config source"
validate_private_input "$PRIVATE_KEY_SOURCE" "attestor private-key source"
validate_existing_path "$PUBLIC_KEY_SOURCE" 0 file "attestor public-key source"
validate_existing_path "$PYTHON" 0 executable "Python runtime"

GLOBAL_INSTALL_LOCK='/private/var/run/john-lomein-persona-qualification.install.lock'
validate_existing_path /private/var/run 0 directory "installer lock root"
exec 9>"$GLOBAL_INSTALL_LOCK"
validate_existing_path "$GLOBAL_INSTALL_LOCK" 0 file "installer lock"
/usr/bin/lockf -t 0 9 ||
  die "another persona qualification install or uninstall is running"

SOURCE_FILES=(
  "$PRODUCT_ROOT/qualification_attestor/__init__.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_adoption_binding.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_adoption_reconciliation.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_adoption_result.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_attestor.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_capture_adoption.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_capture_child.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_capture_helper.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_capture_plan.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_capture_protocol.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_capture_selection.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_capture_staging.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_capture_staging_receipts.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_lifecycle_receipts.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_native_bundle.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_native_host_evidence.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_opaque_capture.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_orchestrator.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_public_verifier.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_recovered_adoption_evidence.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_sandbox.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_source_revalidation_binding.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_transaction_journal.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_trust_projection.py"
  "$PRODUCT_ROOT/qualification_attestor/john_lomein_persona_qualification_wheel_provenance.py"
  "$PRODUCT_ROOT/qualification_attestor/schemas/persona-qualification-native-bundle-manifest.v3.schema.json"
  "$PRODUCT_ROOT/qualification_verifier/__init__.py"
  "$PRODUCT_ROOT/qualification_verifier/john_lomein_persona_qualification_verifier.py"
  "$PRODUCT_ROOT/scripts/john-lomein-persona-eval.py"
  "$PRODUCT_ROOT/scripts/john-lomein-persona-qualification.py"
  "$PRODUCT_ROOT/scripts/john-lomein-persona-trust.py"
  "$PRODUCT_ROOT/scripts/john_lomein_autonomy.py"
  "$PRODUCT_ROOT/scripts/john_lomein_factory_receipts.py"
  "$PRODUCT_ROOT/scripts/john_lomein_manifest_contract.py"
  "$PRODUCT_ROOT/scripts/john_lomein_profile_contract.py"
  "$PRODUCT_ROOT/persona/JOHN_LOMEIN.md"
  "$PRODUCT_ROOT/evals/persona/scenarios.json"
  "$PRODUCT_ROOT/evals/persona/rubric.json"
)
for profile in \
  john-lomein-maintainer john-lomein-forge john-lomein-guide \
  john-lomein-overwatch john-lomein-learning-steward
do
  SOURCE_FILES+=("$PRODUCT_ROOT/profiles/$profile/SOUL.md")
done
for schema in "$PRODUCT_ROOT"/evals/persona/schemas/*.json; do
  SOURCE_FILES+=("$schema")
done
for source_file in "${SOURCE_FILES[@]}"; do
  validate_existing_path "$source_file" 0 file "qualification source"
done

EVIDENCE_UID="$(/usr/bin/id -u "$EVIDENCE_USER" 2>/dev/null)" ||
  die "evidence user does not exist: $EVIDENCE_USER"
case "$EVIDENCE_UID" in
  ''|*[!0-9]*) die "evidence UID is invalid" ;;
esac
[ "$EVIDENCE_UID" -gt 0 ] || die "evidence user must not be root"

TEMP_DIR="$(
  /usr/bin/mktemp -d /private/tmp/john-lomein-qualification-install.XXXXXX
)"
/bin/chmod 0700 "$TEMP_DIR"
ROLLBACK_DIR="$TEMP_DIR/rollback"
/usr/bin/install -d -o root -g wheel -m 0700 "$ROLLBACK_DIR"
GENERATED_DIR="$TEMP_DIR/generated"
BUNDLE_STAGE_ROOT="$TEMP_DIR/bundles"
/usr/bin/install -d -o root -g wheel -m 0700 \
  "$GENERATED_DIR" "$BUNDLE_STAGE_ROOT"

TRANSACTION_STARTED=0
TRANSACTION_COMMITTED=0
CREATED_USERS=()
CREATED_GROUPS=()
ADDED_EXPORT_MEMBERS=()
MANAGED_FILES=()
CREATED_BUNDLES=()
CREATED_DIRECTORIES=()
CREATED_STATE_FILES=()

restore_managed_file() {
  local backup="$1"
  local destination="$2"
  local staged
  if [ -f "$backup" ]; then
    staged="$(/usr/bin/mktemp "$destination.rollback.XXXXXX")" || return 1
    /bin/cp -p "$backup" "$staged" || return 1
    /usr/sbin/chown root:wheel "$staged" || return 1
    /bin/mv -f "$staged" "$destination" || return 1
  elif [ -f "$backup.absent" ]; then
    [ ! -L "$destination" ] || return 1
    [ ! -e "$destination" ] || [ -f "$destination" ] || return 1
    /bin/rm -f "$destination" || return 1
  fi
}

cleanup() {
  local status="$?"
  local cleanup_status=0
  local index pair backup destination member user group bundle directory state_file
  trap - EXIT
  if [ "$TRANSACTION_STARTED" -eq 1 ] &&
     [ "$TRANSACTION_COMMITTED" -eq 0 ]; then
    for ((index=${#MANAGED_FILES[@]}-1; index>=0; index--)); do
      pair="${MANAGED_FILES[$index]}"
      backup="${pair%%|*}"
      destination="${pair#*|}"
      restore_managed_file "$backup" "$destination" || cleanup_status=1
    done
    for ((index=${#CREATED_BUNDLES[@]}-1; index>=0; index--)); do
      bundle="${CREATED_BUNDLES[$index]}"
      case "$bundle" in
        "$BUNDLES_ROOT/$INSTANCE_ID/"*) ;;
        *) cleanup_status=1; continue ;;
      esac
      if [ -e "$bundle" ] || [ -L "$bundle" ]; then
        [ -d "$bundle" ] && [ ! -L "$bundle" ] &&
          [ "$(/usr/bin/stat -f '%Su' "$bundle" 2>/dev/null)" = root ] ||
          {
            cleanup_status=1
            continue
          }
        /bin/rm -rf "$bundle" || cleanup_status=1
      fi
    done
    for ((index=${#CREATED_STATE_FILES[@]}-1; index>=0; index--)); do
      state_file="${CREATED_STATE_FILES[$index]}"
      [ "$state_file" = "$TRANSACTION_JOURNAL_LOCK_PATH" ] ||
        {
          cleanup_status=1
          continue
        }
      if [ -e "$state_file" ] || [ -L "$state_file" ]; then
        [ -f "$state_file" ] && [ ! -L "$state_file" ] &&
          [ "$(/usr/bin/stat -f '%Su' "$state_file" 2>/dev/null)" = root ] &&
          [ "$(/usr/bin/stat -f '%Sg' "$state_file" 2>/dev/null)" = wheel ] &&
          [ "$(/usr/bin/stat -f '%Lp' "$state_file" 2>/dev/null)" = 600 ] &&
          [ "$(/usr/bin/stat -f '%l' "$state_file" 2>/dev/null)" -eq 1 ] &&
          [ "$(/usr/bin/stat -f '%z' "$state_file" 2>/dev/null)" -eq 0 ] ||
          {
            cleanup_status=1
            continue
          }
        /bin/rm -f "$state_file" || cleanup_status=1
      fi
    done
    for ((index=${#CREATED_DIRECTORIES[@]}-1; index>=0; index--)); do
      directory="${CREATED_DIRECTORIES[$index]}"
      if [ -e "$directory" ] || [ -L "$directory" ]; then
        [ -d "$directory" ] && [ ! -L "$directory" ] ||
          {
            cleanup_status=1
            continue
          }
        /bin/rmdir "$directory" || cleanup_status=1
      fi
    done
    # Preserve the identities if any filesystem rollback failed. Deleting a
    # group while an owned directory or bundle remains would strand an opaque
    # numeric owner and make the next installation unsafe.
    if [ "$cleanup_status" -eq 0 ]; then
      for ((index=${#ADDED_EXPORT_MEMBERS[@]}-1; index>=0; index--)); do
        member="${ADDED_EXPORT_MEMBERS[$index]}"
        /usr/sbin/dseditgroup -o edit -d "$member" -t user \
          "$EXPORT_GROUP" >/dev/null 2>&1 || cleanup_status=1
      done
    fi
    if [ "$cleanup_status" -eq 0 ]; then
      for ((index=${#CREATED_USERS[@]}-1; index>=0; index--)); do
        user="${CREATED_USERS[$index]}"
        /usr/bin/dscl . -delete "/Users/$user" >/dev/null 2>&1 ||
          cleanup_status=1
      done
    fi
    if [ "$cleanup_status" -eq 0 ]; then
      for ((index=${#CREATED_GROUPS[@]}-1; index>=0; index--)); do
        group="${CREATED_GROUPS[$index]}"
        /usr/bin/dscl . -delete "/Groups/$group" >/dev/null 2>&1 ||
          cleanup_status=1
      done
    fi
  fi
  /bin/rm -rf "$TEMP_DIR"
  if [ "$cleanup_status" -ne 0 ]; then
    echo \
      "protected persona qualification rollback was incomplete; installation remains disabled" \
      >&2
    exit 1
  fi
  exit "$status"
}
trap cleanup EXIT

snapshot_input() {
  local source="$1"
  local destination="$2"
  local maximum="$3"
  "$PYTHON" -I -B -S - "$source" "$destination" "$maximum" <<'PY'
import os
import stat
import sys

source, destination, raw_maximum = sys.argv[1:]
maximum = int(raw_maximum)
flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
descriptor = os.open(source, flags)
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 1 <= before.st_size <= maximum
    ):
        raise SystemExit("snapshot input is not a bounded singly linked file")
    chunks = []
    observed = 0
    while observed <= maximum:
        chunk = os.read(descriptor, min(65536, maximum + 1 - observed))
        if not chunk:
            break
        chunks.append(chunk)
        observed += len(chunk)
    after = os.fstat(descriptor)
    named = os.lstat(source)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if observed != before.st_size or identity(before) != identity(after) or identity(after) != identity(named):
        raise SystemExit("snapshot input changed while being read")
finally:
    os.close(descriptor)
out = os.open(
    destination,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
    0o600,
)
try:
    payload = b"".join(chunks)
    while payload:
        written = os.write(out, payload)
        if written <= 0:
            raise SystemExit("snapshot write made no progress")
        payload = payload[written:]
    os.fsync(out)
finally:
    os.close(out)
PY
}

CONFIG_SNAPSHOT="$TEMP_DIR/install-config.json"
PRIVATE_KEY_SNAPSHOT="$TEMP_DIR/attestor-private.pem"
PUBLIC_KEY_SNAPSHOT="$TEMP_DIR/attestor-public.pem"
snapshot_input "$CONFIG_SOURCE" "$CONFIG_SNAPSHOT" 262144
snapshot_input "$PRIVATE_KEY_SOURCE" "$PRIVATE_KEY_SNAPSHOT" 65536
snapshot_input "$PUBLIC_KEY_SOURCE" "$PUBLIC_KEY_SNAPSHOT" 65536

# BEGIN PERSONA_QUALIFICATION_INSTALL_GENERATOR
GENERATOR_REPORT="$TEMP_DIR/preflight.tsv"
"$PYTHON" -I -B - "$CONFIG_SNAPSHOT" "$PRIVATE_KEY_SNAPSHOT" \
  "$PUBLIC_KEY_SNAPSHOT" "$SLUG" "$PYTHON" "$PRODUCT_ROOT" \
  >"$GENERATOR_REPORT" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

import cryptography
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CONFIG_FIELDS = {
    "schema_version", "enabled", "instance_slug", "instance_manifest_path",
    "runtime_root", "checkout_source_path", "checkout_identity_path",
    "runtime_source_path", "evidence_home_path", "qualification_public_root",
    "qualification_private_root", "attestor_key_id",
    "verifier_timeout_seconds", "capture_limits", "capture_lifecycle",
}
LIMIT_FIELDS = {
    "max_files", "max_directories", "max_bytes", "max_file_bytes", "max_depth",
}
LIFECYCLE_FIELDS = {
    "retention", "max_capture_slots", "max_orphan_age_seconds",
}
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,127}$")


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit("install config contains a duplicate JSON field")
        result[key] = value
    return result


def absolute(value, field):
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value != str(Path(value))
        or "." in Path(value).parts
        or ".." in Path(value).parts
        or any(ord(character) < 32 for character in value)
    ):
        raise SystemExit(f"{field} must be a normalized absolute path")
    return Path(value)


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode()


(
    config_path,
    private_path,
    public_path,
    slug,
    python_path,
    product_root,
) = sys.argv[1:]
sys.path.insert(0, product_root)
from qualification_attestor.john_lomein_persona_qualification_capture_selection import (  # noqa: E402
    CAPTURE_SELECTION_SCHEMA,
    ROLE_PROFILES,
    CaptureSelectionError,
    normalize_capture_selection,
)
raw = Path(config_path).read_bytes()
config = json.loads(
    raw.decode("utf-8"),
    object_pairs_hook=reject_duplicates,
    parse_constant=lambda value: (_ for _ in ()).throw(
        SystemExit("install config contains a non-finite number")
    ),
)
if not isinstance(config, dict) or set(config) != CONFIG_FIELDS:
    raise SystemExit("install config fields are invalid")
if config["schema_version"] != "john-lomein.persona-qualification-install-config.v1":
    raise SystemExit("install config schema is unsupported")
if config["enabled"] is not False:
    raise SystemExit("enabled must remain false in the scaffold installer")
if config["instance_slug"] != slug or not SLUG_RE.fullmatch(slug):
    raise SystemExit("install config slug does not match --slug")
if not isinstance(config["attestor_key_id"], str) or not TOKEN_RE.fullmatch(config["attestor_key_id"]):
    raise SystemExit("attestor key id is invalid")
if (
    type(config["verifier_timeout_seconds"]) is not int
    or not 1 <= config["verifier_timeout_seconds"] <= 3600
):
    raise SystemExit("verifier timeout is invalid")
if not isinstance(config["capture_limits"], dict) or set(config["capture_limits"]) != LIMIT_FIELDS:
    raise SystemExit("capture limits are invalid")
limit_caps = {
    "max_files": 4096,
    "max_directories": 4096,
    "max_bytes": 134217728,
    "max_file_bytes": 16777216,
    "max_depth": 64,
}
for field, maximum in limit_caps.items():
    value = config["capture_limits"][field]
    if type(value) is not int or not 1 <= value <= maximum:
        raise SystemExit(f"capture limit {field} is invalid")
if config["capture_limits"]["max_file_bytes"] > config["capture_limits"]["max_bytes"]:
    raise SystemExit("capture file limit exceeds total limit")
if not isinstance(config["capture_lifecycle"], dict) or set(config["capture_lifecycle"]) != LIFECYCLE_FIELDS:
    raise SystemExit("capture lifecycle is invalid")
if config["capture_lifecycle"]["retention"] != "ephemeral":
    raise SystemExit("capture retention must be ephemeral")
if (
    type(config["capture_lifecycle"]["max_capture_slots"]) is not int
    or not 1 <= config["capture_lifecycle"]["max_capture_slots"] <= 8
    or type(config["capture_lifecycle"]["max_orphan_age_seconds"]) is not int
    or not 1 <= config["capture_lifecycle"]["max_orphan_age_seconds"] <= 3600
):
    raise SystemExit("capture lifecycle bounds are invalid")

paths = {
    field: absolute(config[field], field)
    for field in (
        "instance_manifest_path", "runtime_root", "checkout_source_path",
        "checkout_identity_path", "runtime_source_path", "evidence_home_path",
        "qualification_public_root", "qualification_private_root",
    )
}
if paths["qualification_public_root"] != paths["runtime_root"] / "state" / "persona-qualification":
    raise SystemExit("qualification public root must use the deployed runtime layout")
selection = {
    "schema_version": CAPTURE_SELECTION_SCHEMA,
    "instance_slug": slug,
    # The real numeric identities are generated after this no-mutation
    # preflight. Their values do not affect the selector's path topology.
    "evidence_uid": 1,
    "verifier_gid": 1,
    "source_roots": {
        "instance_manifest": str(paths["instance_manifest_path"]),
        "runtime": str(paths["runtime_root"]),
        "qualification_public": str(paths["qualification_public_root"]),
        "qualification_private": str(paths["qualification_private_root"]),
    },
    "path_identities": {
        "evidence_home": str(paths["evidence_home_path"]),
        "checkout_source": str(paths["checkout_source_path"]),
        "runtime_source": str(paths["runtime_source_path"]),
        "checkout": str(paths["checkout_identity_path"]),
        "runtime": str(paths["runtime_root"]),
    },
    "role_profiles": dict(ROLE_PROFILES),
    "limits": config["capture_limits"],
    "lifecycle": config["capture_lifecycle"],
}
try:
    normalize_capture_selection(selection)
except CaptureSelectionError as exc:
    raise SystemExit(f"capture selection rejected: {exc.code}") from exc

if cryptography.__version__ != "49.0.0":
    raise SystemExit("cryptography 49.0.0 is required for key preflight")
yaml_version = tuple(int(item) for item in yaml.__version__.split(".")[:3])
if not ((6, 0, 2) <= yaml_version < (7, 0, 0)):
    raise SystemExit("PyYAML >=6.0.2,<7 is required")
private = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
public_raw = Path(public_path).read_bytes()
public = serialization.load_pem_public_key(public_raw)
if not isinstance(private, Ed25519PrivateKey) or not isinstance(public, Ed25519PublicKey):
    raise SystemExit("attestor keypair must be Ed25519")
derived = private.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
supplied = public.public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
if derived != supplied:
    raise SystemExit("attestor private and public keys do not match")

expected = (
    json.dumps(config, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
    + "\n"
).encode()
if raw != expected:
    raise SystemExit("install config must use canonical retained JSON encoding")

report = {
    "public_key_sha256": hashlib.sha256(public_raw).hexdigest(),
    "yaml_root": str(Path(yaml.__file__).resolve().parent),
}
for field, value in paths.items():
    report[field] = str(value)
for field, value in sorted(report.items()):
    if "\t" in value or "\n" in value:
        raise SystemExit("preflight report value is unsafe")
    print(f"{field}\t{value}")
# END PERSONA_QUALIFICATION_INSTALL_GENERATOR
PY

PUBLIC_KEY_SHA256=''
YAML_ROOT=''
INSTANCE_MANIFEST_PATH=''
RUNTIME_ROOT=''
CHECKOUT_SOURCE_PATH=''
CHECKOUT_IDENTITY_PATH=''
RUNTIME_SOURCE_PATH=''
EVIDENCE_HOME_PATH=''
QUALIFICATION_PUBLIC_ROOT=''
QUALIFICATION_PRIVATE_ROOT=''
while IFS=$'\t' read -r key value; do
  case "$key" in
    public_key_sha256) PUBLIC_KEY_SHA256="$value" ;;
    yaml_root) YAML_ROOT="$value" ;;
    instance_manifest_path) INSTANCE_MANIFEST_PATH="$value" ;;
    runtime_root) RUNTIME_ROOT="$value" ;;
    checkout_source_path) CHECKOUT_SOURCE_PATH="$value" ;;
    checkout_identity_path) CHECKOUT_IDENTITY_PATH="$value" ;;
    runtime_source_path) RUNTIME_SOURCE_PATH="$value" ;;
    evidence_home_path) EVIDENCE_HOME_PATH="$value" ;;
    qualification_public_root) QUALIFICATION_PUBLIC_ROOT="$value" ;;
    qualification_private_root) QUALIFICATION_PRIVATE_ROOT="$value" ;;
    *) die "preflight returned an unknown field" ;;
  esac
done <"$GENERATOR_REPORT"
[ -n "$PUBLIC_KEY_SHA256" ] && [ -n "$YAML_ROOT" ] &&
  [ -n "$INSTANCE_MANIFEST_PATH" ] && [ -n "$RUNTIME_ROOT" ] &&
  [ -n "$CHECKOUT_SOURCE_PATH" ] && [ -n "$CHECKOUT_IDENTITY_PATH" ] &&
  [ -n "$RUNTIME_SOURCE_PATH" ] && [ -n "$EVIDENCE_HOME_PATH" ] &&
  [ -n "$QUALIFICATION_PUBLIC_ROOT" ] &&
  [ -n "$QUALIFICATION_PRIVATE_ROOT" ] ||
  die "preflight report is incomplete"
validate_existing_path "$YAML_ROOT" 0 directory "PyYAML package"
while IFS= read -r -d '' yaml_file; do
  validate_existing_path "$yaml_file" 0 file "PyYAML package file"
done < <(/usr/bin/find -x "$YAML_ROOT" -type f -name '*.py' -print0)

validate_private_file_owner \
  "$INSTANCE_MANIFEST_PATH" "$EVIDENCE_UID" "instance manifest"
validate_existing_path "$RUNTIME_ROOT" "0,$EVIDENCE_UID" directory \
  "deployed runtime root"
validate_existing_path "$CHECKOUT_SOURCE_PATH" "0,$EVIDENCE_UID" directory \
  "checkout source identity"
validate_existing_path "$RUNTIME_SOURCE_PATH" "0,$EVIDENCE_UID" directory \
  "runtime source identity"
validate_existing_path "$EVIDENCE_HOME_PATH" "0,$EVIDENCE_UID" directory \
  "evidence home identity"
validate_existing_path "$QUALIFICATION_PUBLIC_ROOT" "0,$EVIDENCE_UID" \
  directory "qualification public root"
validate_existing_path "$QUALIFICATION_PRIVATE_ROOT" "0,$EVIDENCE_UID" \
  directory "qualification private root"
INSTANCE_MANIFEST_SNAPSHOT="$TEMP_DIR/instance.yaml"
snapshot_input "$INSTANCE_MANIFEST_PATH" "$INSTANCE_MANIFEST_SNAPSHOT" 2097152
INSTANCE_MANIFEST_SHA256="$(
  /usr/bin/shasum -a 256 "$INSTANCE_MANIFEST_SNAPSHOT" |
    /usr/bin/awk '{ print $1 }'
)"
[[ "$INSTANCE_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
  die "instance manifest digest is invalid"

INSTANCE_ID="$(
  "$PYTHON" -I -B -S - "$SLUG" <<'PY'
import hashlib
import sys
print(hashlib.sha256(sys.argv[1].encode("ascii")).hexdigest()[:12])
PY
)"
[[ "$INSTANCE_ID" =~ ^[0-9a-f]{12}$ ]] ||
  die "derived instance identity is invalid"
SIGNER_USER="_jlqs_$INSTANCE_ID"
CAPTURE_USER="_jlqc_$INSTANCE_ID"
VERIFIER_USER="_jlqv_$INSTANCE_ID"
SIGNER_GROUP="$SIGNER_USER"
CAPTURE_GROUP="$CAPTURE_USER"
VERIFIER_GROUP="$VERIFIER_USER"
EXPORT_GROUP="_jlqe_$INSTANCE_ID"

CONFIG_ROOT='/private/etc/john-lomein-persona-qualification.d'
INSTANCE_CONFIG_DIR="$CONFIG_ROOT/$SLUG"
KEYS_DIR="$INSTANCE_CONFIG_DIR/keys"
PUBLIC_ROOT='/private/etc/john-lomein-persona-qualification-public'
INSTANCE_PUBLIC_DIR="$PUBLIC_ROOT/$SLUG"
DATA_ROOT='/private/var/db/john-lomein-persona-qualification'
INSTANCE_DATA_DIR="$DATA_ROOT/$SLUG"
STATE_DIR="$INSTANCE_DATA_DIR/state"
TRANSACTION_JOURNAL_DIR="$STATE_DIR/transactions"
TRANSACTION_JOURNAL_COMPLETED_DIR="$TRANSACTION_JOURNAL_DIR/.completed"
TRANSACTION_JOURNAL_LOCK_PATH="$TRANSACTION_JOURNAL_DIR/.lock"
STAGING_DIR="$INSTANCE_DATA_DIR/staging"
CAPTURE_DIR="$INSTANCE_DATA_DIR/captures"
SCRATCH_DIR="$INSTANCE_DATA_DIR/verifier-scratch"
EXPORT_DIR="$INSTANCE_DATA_DIR/evidence-export"
CODE_ROOT='/usr/local/libexec/john-lomein-persona-qualification'
BUNDLES_ROOT="$CODE_ROOT/bundles"
INSTANCES_ROOT='/usr/local/libexec/john-lomein-persona-qualification-instances'
INSTANCE_CODE_DIR="$INSTANCES_ROOT/$SLUG"

ATTESTOR_CONFIG_PATH="$INSTANCE_CONFIG_DIR/attestor.json"
INSTALLED_BINDING_PATH="$INSTANCE_CONFIG_DIR/persona-qualification-verifier.$SLUG.json"
SELECTION_PATH="$INSTANCE_CONFIG_DIR/capture-selection.json"
INSTALL_RECORD_PATH="$INSTANCE_CONFIG_DIR/install-record.json"
NATIVE_CLOSURE_PATH="$INSTANCE_CONFIG_DIR/native-closure.json"
TRANSACTION_JOURNAL_CONTROL_PATH="$INSTANCE_CONFIG_DIR/transaction-journal.json"
PRIVATE_KEY_PATH="$KEYS_DIR/attestor-ed25519.pem"
CONFIG_PUBLIC_KEY_PATH="$KEYS_DIR/attestor-ed25519.pub.pem"
VERIFIER_MANIFEST_PATH="$INSTANCE_CONFIG_DIR/verifier-bundle-manifest.json"
CAPTURE_MANIFEST_PATH="$INSTANCE_CONFIG_DIR/capture-bundle-manifest.json"
COORDINATOR_MANIFEST_PATH="$INSTANCE_CONFIG_DIR/coordinator-bundle-manifest.json"
PUBLIC_VERIFIER_MANIFEST_PATH="$INSTANCE_CONFIG_DIR/public-verifier-bundle-manifest.json"

PUBLIC_KEY_PATH="$INSTANCE_PUBLIC_DIR/attestor-ed25519.pub.pem"
PUBLIC_PIN_PATH="$INSTANCE_PUBLIC_DIR/public-verifier.json"
PUBLIC_STATUS_PATH="$INSTANCE_PUBLIC_DIR/install-status.json"
PUBLIC_OPERATOR_POLICY_PATH="$INSTANCE_PUBLIC_DIR/operator-policy.json"
PUBLIC_PROJECTION_PATH="$INSTANCE_PUBLIC_DIR/trust-projection.json"

ATTEST_WRAPPER_PATH="$INSTANCE_CODE_DIR/attest"
TRUST_WRAPPER_PATH="$INSTANCE_CODE_DIR/trust"
DOCTOR_WRAPPER_PATH="$INSTANCE_CODE_DIR/doctor"
PUBLIC_TRUST_COMMAND="/usr/local/bin/john-lomein-persona-trust-$SLUG"
PUBLIC_DOCTOR_COMMAND="/usr/local/bin/john-lomein-persona-qualification-doctor-$SLUG"
LABEL="com.john-lomein.persona-qualification.$SLUG"
PLIST_PATH="/Library/LaunchDaemons/$LABEL.plist"

UPGRADE_EXISTING=0
for durable_path in \
  "$INSTANCE_CONFIG_DIR" "$INSTANCE_PUBLIC_DIR" "$INSTANCE_DATA_DIR" \
  "$INSTANCE_CODE_DIR" "$BUNDLES_ROOT/$INSTANCE_ID" \
  "$ATTEST_WRAPPER_PATH" "$TRUST_WRAPPER_PATH" "$DOCTOR_WRAPPER_PATH" \
  "$PUBLIC_TRUST_COMMAND" "$PUBLIC_DOCTOR_COMMAND" "$PLIST_PATH"
do
  if [ -e "$durable_path" ] || [ -L "$durable_path" ]; then
    UPGRADE_EXISTING=1
    break
  fi
done

if [ "$UPGRADE_EXISTING" -eq 1 ]; then
  for required_upgrade_file in \
    "$ATTESTOR_CONFIG_PATH" "$INSTALL_RECORD_PATH" "$PRIVATE_KEY_PATH" \
    "$CONFIG_PUBLIC_KEY_PATH" "$PUBLIC_KEY_PATH"
  do
    [ -f "$required_upgrade_file" ] && [ ! -L "$required_upgrade_file" ] ||
      die "durable instance state exists without a complete trust identity"
  done
  validate_private_file_owner \
    "$ATTESTOR_CONFIG_PATH" 0 "existing attestor config"
  validate_private_file_owner \
    "$INSTALL_RECORD_PATH" 0 "existing install record"
  validate_private_file_owner \
    "$PRIVATE_KEY_PATH" 0 "existing attestor private key"
  validate_existing_path \
    "$CONFIG_PUBLIC_KEY_PATH" 0 file "existing config public key"
  validate_existing_path \
    "$PUBLIC_KEY_PATH" 0 file "existing public verifier key"
  /usr/bin/cmp -s "$PRIVATE_KEY_PATH" "$PRIVATE_KEY_SNAPSHOT" ||
    die "installed attestor private key differs; key rotation is unsupported"
  /usr/bin/cmp -s "$CONFIG_PUBLIC_KEY_PATH" "$PUBLIC_KEY_SNAPSHOT" ||
    die "installed config public key differs; key rotation is unsupported"
  /usr/bin/cmp -s "$PUBLIC_KEY_PATH" "$PUBLIC_KEY_SNAPSHOT" ||
    die "installed public verifier key differs; key rotation is unsupported"

  "$PYTHON" -I -B - \
    "$PRODUCT_ROOT" "$CONFIG_SNAPSHOT" "$ATTESTOR_CONFIG_PATH" \
    "$INSTALL_RECORD_PATH" "$SLUG" "$EVIDENCE_USER" "$EVIDENCE_UID" \
    "$SIGNER_USER" "$CAPTURE_USER" "$VERIFIER_USER" "$EXPORT_GROUP" \
    "$PRIVATE_KEY_PATH" "$CONFIG_PUBLIC_KEY_PATH" \
    "$QUALIFICATION_PUBLIC_ROOT" "$QUALIFICATION_PRIVATE_ROOT" \
    "$STATE_DIR/head.json" "$PUBLIC_KEY_SHA256" <<'PY'
import json
import sys
from pathlib import Path

(
    product_root,
    install_config_path,
    existing_config_path,
    install_record_path,
    slug,
    evidence_user,
    evidence_uid_raw,
    signer_user,
    capture_user,
    verifier_user,
    export_group,
    private_key_path,
    public_key_path,
    qualification_public_root,
    qualification_private_root,
    head_path,
    public_key_sha256,
) = sys.argv[1:]
sys.path.insert(0, product_root)
from qualification_attestor.john_lomein_persona_qualification_attestor import (  # noqa: E402
    QualificationAttestorError,
    normalize_config,
)


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit("existing trust state contains duplicate JSON fields")
        value[key] = item
    return value


def load(path):
    return json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda value: (_ for _ in ()).throw(
            SystemExit("existing trust state contains a non-finite number")
        ),
    )


install_config = load(install_config_path)
existing_config = load(existing_config_path)
expected_config = {
    "schema_version": 1,
    "instance_slug": slug,
    "qualification_public_root": qualification_public_root,
    "qualification_private_root": qualification_private_root,
    "expected_evidence_uid": int(evidence_uid_raw),
    "attestor_key_id": install_config["attestor_key_id"],
    "private_key_path": private_key_path,
    "public_key_path": public_key_path,
    "public_key_sha256": public_key_sha256,
    "head_path": head_path,
}
try:
    if normalize_config(existing_config) != normalize_config(expected_config):
        raise SystemExit(
            "existing attestor trust identity differs; explicit migration required"
        )
except QualificationAttestorError as exc:
    raise SystemExit(
        f"existing attestor trust identity is invalid: {exc.code}"
    ) from exc

record = load(install_record_path)
if (
    not isinstance(record, dict)
    or record.get("schema_version")
    != "john-lomein.persona-qualification-install-record.v1"
    or record.get("instance_slug") != slug
    or not isinstance(record.get("identities"), dict)
):
    raise SystemExit("existing install record is invalid")
identities = record["identities"]
expected_static = {
    "instance_id": __import__("hashlib").sha256(
        slug.encode("ascii")
    ).hexdigest()[:12],
    "evidence": {"user": evidence_user, "uid": int(evidence_uid_raw)},
}
for key, expected in expected_static.items():
    if identities.get(key) != expected:
        raise SystemExit(
            "existing install trust identity differs; explicit migration required"
        )
for role, expected_name, name_field in (
    ("signer", signer_user, "user"),
    ("capture", capture_user, "user"),
    ("verifier", verifier_user, "user"),
    ("export", export_group, "group"),
):
    value = identities.get(role)
    if not isinstance(value, dict) or value.get(name_field) != expected_name:
        raise SystemExit(
            "existing install trust identity differs; explicit migration required"
        )
PY
fi

next_directory_id() {
  local namespace="$1"
  local key="$2"
  local candidate used
  used="$(
    /usr/bin/dscl . -list "$namespace" "$key" 2>/dev/null |
      /usr/bin/awk '{ print $2 }'
  )"
  for ((candidate=499; candidate>=350; candidate--)); do
    if ! /usr/bin/grep -qx "$candidate" <<<"$used"; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

assert_unique_directory_id() {
  local namespace="$1"
  local key="$2"
  local expected_name="$3"
  local expected_id="$4"
  local matches
  matches="$(
    /usr/bin/dscl . -list "$namespace" "$key" 2>/dev/null |
      /usr/bin/awk -v wanted="$expected_id" '$2 == wanted { print $1 }'
  )"
  [ "$matches" = "$expected_name" ] ||
    die "$namespace numeric identity is not unique to $expected_name"
}

ds_value() {
  local record="$1"
  local key="$2"
  /usr/bin/dscl . -read "$record" "$key" 2>/dev/null |
    /usr/bin/awk 'NR == 1 { sub(/^[^:]*:[[:space:]]*/, ""); print; exit }'
}

ds_optional_value() {
  local record="$1"
  local key="$2"
  if /usr/bin/dscl . -read "$record" "$key" >/dev/null 2>&1; then
    ds_value "$record" "$key"
  fi
}

ensure_group() {
  local group="$1"
  local gid real_name nested
  local expected_real_name="John Lomein persona qualification $group"
  if /usr/bin/dscl . -read "/Groups/$group" >/dev/null 2>&1; then
    gid="$(ds_value "/Groups/$group" PrimaryGroupID)"
  else
    [ "$UPGRADE_EXISTING" -eq 0 ] ||
      die "upgrade trust identity group is missing"
    gid="$(next_directory_id /Groups PrimaryGroupID)" ||
      die "no free macOS service group ID is available in 350..499"
    /usr/bin/dscl . -create "/Groups/$group"
    CREATED_GROUPS+=("$group")
    /usr/bin/dscl . -create "/Groups/$group" PrimaryGroupID "$gid"
    /usr/bin/dscl . -create "/Groups/$group" RealName \
      "$expected_real_name"
  fi
  case "$gid" in ''|*[!0-9]*) die "group $group has an invalid GID" ;; esac
  [ "$gid" -gt 0 ] || die "group $group must not use root GID"
  assert_unique_directory_id /Groups PrimaryGroupID "$group" "$gid"
  real_name="$(ds_value "/Groups/$group" RealName)"
  nested="$(ds_optional_value "/Groups/$group" NestedGroups)"
  [ "$real_name" = "$expected_real_name" ] && [ -z "$nested" ] ||
    die "group $group has unsafe existing attributes"
  ENSURED_GROUP_GID="$gid"
}

ensure_user() {
  local user="$1"
  local primary_gid="$2"
  local description="$3"
  local uid observed_gid shell home hidden real_name authentication
  if /usr/bin/dscl . -read "/Users/$user" >/dev/null 2>&1; then
    uid="$(ds_value "/Users/$user" UniqueID)"
  else
    [ "$UPGRADE_EXISTING" -eq 0 ] ||
      die "upgrade trust identity user is missing"
    uid="$(next_directory_id /Users UniqueID)" ||
      die "no free macOS service user ID is available in 350..499"
    /usr/bin/dscl . -create "/Users/$user"
    CREATED_USERS+=("$user")
    /usr/bin/dscl . -create "/Users/$user" UniqueID "$uid"
    /usr/bin/dscl . -create "/Users/$user" PrimaryGroupID "$primary_gid"
    /usr/bin/dscl . -create "/Users/$user" RealName "$description"
    /usr/bin/dscl . -create "/Users/$user" NFSHomeDirectory /var/empty
    /usr/bin/dscl . -create "/Users/$user" UserShell /usr/bin/false
    /usr/bin/dscl . -create "/Users/$user" Password '*'
    /usr/bin/dscl . -create "/Users/$user" IsHidden 1
  fi
  observed_gid="$(ds_value "/Users/$user" PrimaryGroupID)"
  shell="$(ds_value "/Users/$user" UserShell)"
  home="$(ds_value "/Users/$user" NFSHomeDirectory)"
  hidden="$(ds_value "/Users/$user" IsHidden)"
  real_name="$(ds_value "/Users/$user" RealName)"
  authentication="$(
    ds_optional_value "/Users/$user" AuthenticationAuthority
  )"
  case "$uid" in ''|*[!0-9]*) die "user $user has an invalid UID" ;; esac
  [ "$uid" -gt 0 ] || die "service user $user must not be root"
  assert_unique_directory_id /Users UniqueID "$user" "$uid"
  [ "$observed_gid" = "$primary_gid" ] ||
    die "service user $user has the wrong primary group"
  [ "$shell" = "/usr/bin/false" ] && [ "$home" = "/var/empty" ] &&
    [ "$hidden" = "1" ] && [ "$real_name" = "$description" ] &&
    [ -z "$authentication" ] ||
    die "service user $user is not a hidden non-login identity"
  ENSURED_USER_UID="$uid"
}

# Identity provisioning is part of the rollback transaction. Set this before
# the first directory-service mutation, not after the membership audit.
TRANSACTION_STARTED=1
ENSURED_GROUP_GID=''
ENSURED_USER_UID=''
ensure_group "$SIGNER_GROUP"
SIGNER_GID="$ENSURED_GROUP_GID"
ensure_group "$CAPTURE_GROUP"
CAPTURE_GID="$ENSURED_GROUP_GID"
ensure_group "$VERIFIER_GROUP"
VERIFIER_GID="$ENSURED_GROUP_GID"
ensure_group "$EXPORT_GROUP"
EXPORT_GID="$ENSURED_GROUP_GID"
ensure_user "$SIGNER_USER" "$SIGNER_GID" \
  "John Lomein qualification signer $SLUG"
SIGNER_UID="$ENSURED_USER_UID"
ensure_user "$CAPTURE_USER" "$CAPTURE_GID" \
  "John Lomein qualification capture $SLUG"
CAPTURE_UID="$ENSURED_USER_UID"
ensure_user "$VERIFIER_USER" "$VERIFIER_GID" \
  "John Lomein qualification verifier $SLUG"
VERIFIER_UID="$ENSURED_USER_UID"

for resolved in \
  "$SIGNER_UID" "$CAPTURE_UID" "$VERIFIER_UID" \
  "$SIGNER_GID" "$CAPTURE_GID" "$VERIFIER_GID" "$EXPORT_GID"
do
  case "$resolved" in ''|*[!0-9]*) die "resolved service identity is invalid" ;; esac
done
[ "$EVIDENCE_UID" -ne "$SIGNER_UID" ] &&
  [ "$EVIDENCE_UID" -ne "$CAPTURE_UID" ] &&
  [ "$EVIDENCE_UID" -ne "$VERIFIER_UID" ] &&
  [ "$SIGNER_UID" -ne "$CAPTURE_UID" ] &&
  [ "$SIGNER_UID" -ne "$VERIFIER_UID" ] &&
  [ "$CAPTURE_UID" -ne "$VERIFIER_UID" ] ||
  die "qualification service users and evidence user must be distinct"

if [ "$UPGRADE_EXISTING" -eq 1 ]; then
  "$PYTHON" -I -B -S - "$INSTALL_RECORD_PATH" \
    "$SIGNER_UID" "$SIGNER_GID" "$CAPTURE_UID" "$CAPTURE_GID" \
    "$VERIFIER_UID" "$VERIFIER_GID" "$EXPORT_GID" <<'PY'
import json
import sys
from pathlib import Path

record_path, *raw_ids = sys.argv[1:]
record = json.loads(Path(record_path).read_text(encoding="utf-8"))
identities = record.get("identities") if isinstance(record, dict) else None
if not isinstance(identities, dict):
    raise SystemExit("existing install record identities are invalid")
expected = {
    "signer": {"uid": int(raw_ids[0]), "gid": int(raw_ids[1])},
    "capture": {"uid": int(raw_ids[2]), "gid": int(raw_ids[3])},
    "verifier": {"uid": int(raw_ids[4]), "gid": int(raw_ids[5])},
    "export": {"gid": int(raw_ids[6])},
}
for role, fields in expected.items():
    value = identities.get(role)
    if not isinstance(value, dict) or any(
        value.get(field) != expected_value
        for field, expected_value in fields.items()
    ):
        raise SystemExit(
            "existing numeric trust identity differs; explicit migration required"
        )
PY
fi

user_has_gid() {
  local user="$1"
  local wanted="$2"
  local candidate
  for candidate in $(/usr/bin/id -G "$user"); do
    [ "$candidate" = "$wanted" ] && return 0
  done
  return 1
}

ensure_export_member() {
  local user="$1"
  if ! user_has_gid "$user" "$EXPORT_GID"; then
    /usr/sbin/dseditgroup -o edit -a "$user" -t user "$EXPORT_GROUP"
    ADDED_EXPORT_MEMBERS+=("$user")
  fi
}
ensure_export_member "$EVIDENCE_USER"
ensure_export_member "$CAPTURE_USER"

DIRECTORY_USERS="$(/usr/bin/dscl . -list /Users)" ||
  die "local user directory could not be enumerated"
while IFS= read -r candidate_user; do
  [ -n "$candidate_user" ] || continue
  candidate_uid="$(/usr/bin/id -u "$candidate_user" 2>/dev/null)" || continue
  [ "$candidate_uid" -eq 0 ] && continue
  for binding in \
    "$SIGNER_GID:$SIGNER_USER:signer" \
    "$CAPTURE_GID:$CAPTURE_USER:capture" \
    "$VERIFIER_GID:$VERIFIER_USER:verifier"
  do
    gid="${binding%%:*}"
    remainder="${binding#*:}"
    owner_user="${remainder%%:*}"
    label="${remainder#*:}"
    if user_has_gid "$candidate_user" "$gid" &&
       [ "$candidate_user" != "$owner_user" ]; then
      die "$label private group is not dedicated to its service identity"
    fi
  done
  if user_has_gid "$candidate_user" "$EXPORT_GID" &&
     [ "$candidate_user" != "$EVIDENCE_USER" ] &&
     [ "$candidate_user" != "$CAPTURE_USER" ]; then
    die "evidence export group contains an unrelated user"
  fi
done <<<"$DIRECTORY_USERS"
unset DIRECTORY_USERS

stage_role_file() {
  local role="$1"
  local source="$2"
  local relative="$3"
  local default_mode=0440
  local directory_mode=0550
  if [ "$role" = public-verifier ]; then
    default_mode=0444
    directory_mode=0555
  fi
  local mode="${4:-$default_mode}"
  local destination="$BUNDLE_STAGE_ROOT/$role/$relative"
  /usr/bin/install -d -o root -g wheel -m "$directory_mode" \
    "$(/usr/bin/dirname "$destination")"
  /usr/bin/install -o root -g wheel -m "$mode" "$source" "$destination"
  /bin/chmod -N "$destination" 2>/dev/null || true
}

for role in capture verifier coordinator public-verifier; do
  role_directory_mode=0550
  role_python_mode=0550
  if [ "$role" = public-verifier ]; then
    role_directory_mode=0555
    role_python_mode=0555
  fi
  /usr/bin/install -d -o root -g wheel -m "$role_directory_mode" \
    "$BUNDLE_STAGE_ROOT/$role"
  stage_role_file "$role" "$PYTHON" python "$role_python_mode"
done

# The capture role is deliberately standard-library-only.
for name in \
  __init__.py \
  john_lomein_persona_qualification_capture_child.py \
  john_lomein_persona_qualification_capture_plan.py \
  john_lomein_persona_qualification_capture_protocol.py \
  john_lomein_persona_qualification_opaque_capture.py
do
  stage_role_file capture \
    "$PRODUCT_ROOT/qualification_attestor/$name" \
    "qualification_attestor/$name"
done

# The coordinator role contains authority-ordering code, but its fixed wrapper
# remains inert until journal orchestration, installed-launcher binding,
# native closure, and canaries are complete.
for name in \
  __init__.py \
  john_lomein_persona_qualification_adoption_binding.py \
  john_lomein_persona_qualification_adoption_reconciliation.py \
  john_lomein_persona_qualification_adoption_recovery.py \
  john_lomein_persona_qualification_adoption_result.py \
  john_lomein_persona_qualification_attestor.py \
  john_lomein_persona_qualification_capture_adoption.py \
  john_lomein_persona_qualification_capture_child.py \
  john_lomein_persona_qualification_capture_helper.py \
  john_lomein_persona_qualification_capture_plan.py \
  john_lomein_persona_qualification_capture_protocol.py \
  john_lomein_persona_qualification_capture_selection.py \
  john_lomein_persona_qualification_capture_staging.py \
  john_lomein_persona_qualification_capture_staging_receipts.py \
  john_lomein_persona_qualification_lifecycle_receipts.py \
  john_lomein_persona_qualification_native_bundle.py \
  john_lomein_persona_qualification_native_host_evidence.py \
  john_lomein_persona_qualification_opaque_capture.py \
  john_lomein_persona_qualification_orchestrator.py \
  john_lomein_persona_qualification_recovered_adoption_evidence.py \
  john_lomein_persona_qualification_sandbox.py \
  john_lomein_persona_qualification_source_revalidation_binding.py \
  john_lomein_persona_qualification_transaction_journal.py \
  john_lomein_persona_qualification_trust_projection.py \
  john_lomein_persona_qualification_wheel_provenance.py
do
  stage_role_file coordinator \
    "$PRODUCT_ROOT/qualification_attestor/$name" \
    "qualification_attestor/$name"
done
stage_role_file coordinator \
  "$PRODUCT_ROOT/qualification_attestor/schemas/persona-qualification-native-bundle-manifest.v3.schema.json" \
  "qualification_attestor/schemas/persona-qualification-native-bundle-manifest.v3.schema.json"

# Public verification is a separate immutable role. It is installed and
# pinned, but its wrapper remains disabled until its native closure is proven.
for name in \
  __init__.py \
  john_lomein_persona_qualification_adoption_binding.py \
  john_lomein_persona_qualification_adoption_reconciliation.py \
  john_lomein_persona_qualification_adoption_result.py \
  john_lomein_persona_qualification_attestor.py \
  john_lomein_persona_qualification_public_verifier.py \
  john_lomein_persona_qualification_recovered_adoption_evidence.py \
  john_lomein_persona_qualification_source_revalidation_binding.py \
  john_lomein_persona_qualification_trust_projection.py
do
  stage_role_file public-verifier \
    "$PRODUCT_ROOT/qualification_attestor/$name" \
    "qualification_attestor/$name"
done
stage_role_file public-verifier \
  "$PRODUCT_ROOT/scripts/john-lomein-persona-trust.py" \
  scripts/john-lomein-persona-trust.py

# The verifier bundle includes only replay/evaluator assets and a pure-Python
# PyYAML copy. It contains no model adapter, credential, checkout, or key.
for name in \
  __init__.py \
  john_lomein_persona_qualification_adoption_binding.py \
  john_lomein_persona_qualification_adoption_reconciliation.py \
  john_lomein_persona_qualification_adoption_result.py \
  john_lomein_persona_qualification_capture_plan.py \
  john_lomein_persona_qualification_capture_selection.py \
  john_lomein_persona_qualification_opaque_capture.py \
  john_lomein_persona_qualification_recovered_adoption_evidence.py
do
  stage_role_file verifier \
    "$PRODUCT_ROOT/qualification_attestor/$name" \
    "qualification_attestor/$name"
done
for name in __init__.py john_lomein_persona_qualification_verifier.py; do
  stage_role_file verifier \
    "$PRODUCT_ROOT/qualification_verifier/$name" \
    "qualification_verifier/$name"
done
for name in \
  john-lomein-persona-eval.py \
  john-lomein-persona-qualification.py \
  john_lomein_autonomy.py \
  john_lomein_factory_receipts.py \
  john_lomein_manifest_contract.py \
  john_lomein_profile_contract.py
do
  stage_role_file verifier "$PRODUCT_ROOT/scripts/$name" "scripts/$name"
done
stage_role_file verifier "$PRODUCT_ROOT/persona/JOHN_LOMEIN.md" \
  persona/JOHN_LOMEIN.md
stage_role_file verifier "$PRODUCT_ROOT/evals/persona/scenarios.json" \
  evals/persona/scenarios.json
stage_role_file verifier "$PRODUCT_ROOT/evals/persona/rubric.json" \
  evals/persona/rubric.json
for profile in \
  john-lomein-maintainer john-lomein-forge john-lomein-guide \
  john-lomein-overwatch john-lomein-learning-steward
do
  stage_role_file verifier "$PRODUCT_ROOT/profiles/$profile/SOUL.md" \
    "profiles/$profile/SOUL.md"
done
for schema in "$PRODUCT_ROOT"/evals/persona/schemas/*.json; do
  stage_role_file verifier "$schema" \
    "evals/persona/schemas/$(/usr/bin/basename "$schema")"
done
while IFS= read -r -d '' yaml_file; do
  yaml_relative="${yaml_file#"$YAML_ROOT"/}"
  stage_role_file verifier "$yaml_file" "vendor/yaml/$yaml_relative"
done < <(/usr/bin/find -x "$YAML_ROOT" -type f -name '*.py' -print0)

FINAL_REPORT="$TEMP_DIR/final.tsv"
"$PYTHON" -I -B -S - \
  "$CONFIG_SNAPSHOT" "$BUNDLE_STAGE_ROOT" "$GENERATED_DIR" \
  "$SLUG" "$EVIDENCE_USER" "$EVIDENCE_UID" \
  "$SIGNER_USER" "$SIGNER_UID" "$SIGNER_GID" \
  "$CAPTURE_USER" "$CAPTURE_UID" "$CAPTURE_GID" \
  "$VERIFIER_USER" "$VERIFIER_UID" "$VERIFIER_GID" \
  "$EXPORT_GROUP" "$EXPORT_GID" \
  "$INSTANCE_ID" "$PUBLIC_KEY_SHA256" "$INSTANCE_MANIFEST_SHA256" \
  "$PYTHON" "$INSTANCE_MANIFEST_PATH" "$RUNTIME_ROOT" \
  "$CHECKOUT_SOURCE_PATH" "$CHECKOUT_IDENTITY_PATH" \
  "$RUNTIME_SOURCE_PATH" "$EVIDENCE_HOME_PATH" \
  "$QUALIFICATION_PUBLIC_ROOT" "$QUALIFICATION_PRIVATE_ROOT" \
  "$CONFIG_ROOT" "$INSTANCE_CONFIG_DIR" "$KEYS_DIR" \
  "$INSTANCE_PUBLIC_DIR" "$STATE_DIR" "$STAGING_DIR" "$CAPTURE_DIR" \
  "$SCRATCH_DIR" "$EXPORT_DIR" "$BUNDLES_ROOT" "$INSTANCE_CODE_DIR" \
  "$ATTESTOR_CONFIG_PATH" "$INSTALLED_BINDING_PATH" "$SELECTION_PATH" \
  "$INSTALL_RECORD_PATH" "$NATIVE_CLOSURE_PATH" "$PRIVATE_KEY_PATH" \
  "$CONFIG_PUBLIC_KEY_PATH" "$VERIFIER_MANIFEST_PATH" \
  "$CAPTURE_MANIFEST_PATH" "$COORDINATOR_MANIFEST_PATH" \
  "$PUBLIC_VERIFIER_MANIFEST_PATH" "$PUBLIC_KEY_PATH" \
  "$PUBLIC_PIN_PATH" "$PUBLIC_STATUS_PATH" \
  "$PUBLIC_OPERATOR_POLICY_PATH" "$PUBLIC_PROJECTION_PATH" \
  "$ATTEST_WRAPPER_PATH" "$TRUST_WRAPPER_PATH" "$DOCTOR_WRAPPER_PATH" \
  "$PUBLIC_TRUST_COMMAND" "$PUBLIC_DOCTOR_COMMAND" "$LABEL" "$PLIST_PATH" \
  >"$FINAL_REPORT" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import stat
import sys
import ast
from pathlib import Path


def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def write_json(path, value):
    Path(path).write_bytes(canonical(value) + b"\n")


def inventory(root, role):
    root = Path(root)
    directory_mode = 0o555 if role == "public-verifier" else 0o550
    data_mode = 0o444 if role == "public-verifier" else 0o440
    executable_mode = 0o555 if role == "public-verifier" else 0o550
    directories = []
    files = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit(f"{role} bundle contains a symlink")
        if stat.S_ISDIR(info.st_mode):
            if stat.S_IMODE(info.st_mode) != directory_mode:
                raise SystemExit(f"{role} bundle directory mode is invalid")
            directories.append({"path": relative, "mode": directory_mode})
        elif stat.S_ISREG(info.st_mode):
            mode = stat.S_IMODE(info.st_mode)
            if (
                mode not in {data_mode, executable_mode}
                or info.st_nlink != 1
                or info.st_size < 1
            ):
                raise SystemExit(f"{role} bundle file metadata is invalid")
            raw = path.read_bytes()
            files.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                    "mode": mode,
                }
            )
        else:
            raise SystemExit(f"{role} bundle contains an unsupported entry")
    if not files:
        raise SystemExit(f"{role} bundle is empty")
    body = {
        "schema_version": "john-lomein.persona-qualification-role-bundle.v1",
        "role": role,
        "root_mode": directory_mode,
        "directories": directories,
        "files": files,
    }
    return body, hashlib.sha256(canonical(body)).hexdigest()


args = iter(sys.argv[1:])
config_path = next(args)
bundle_stage = Path(next(args))
generated = Path(next(args))
slug = next(args)
evidence_user, evidence_uid = next(args), int(next(args))
signer_user, signer_uid, signer_gid = next(args), int(next(args)), int(next(args))
capture_user, capture_uid, capture_gid = next(args), int(next(args)), int(next(args))
verifier_user, verifier_uid, verifier_gid = next(args), int(next(args)), int(next(args))
export_group, export_gid = next(args), int(next(args))
instance_id, public_key_sha, instance_manifest_sha = next(args), next(args), next(args)
python_source = next(args)
instance_manifest, runtime_root = next(args), next(args)
checkout_source, checkout_identity = next(args), next(args)
runtime_source, evidence_home = next(args), next(args)
qualification_public, qualification_private = next(args), next(args)
config_root, instance_config, keys_dir = next(args), next(args), next(args)
instance_public, state_dir, staging_dir, capture_dir = (
    next(args), next(args), next(args), next(args)
)
scratch_dir, export_dir = next(args), next(args)
bundles_root, instance_code = next(args), next(args)
attestor_config_path, installed_binding_path, selection_path = next(args), next(args), next(args)
install_record_path, native_closure_path, private_key_path = next(args), next(args), next(args)
config_public_key_path, verifier_manifest_path = next(args), next(args)
capture_manifest_path, coordinator_manifest_path = next(args), next(args)
public_verifier_manifest_path, public_key_path = next(args), next(args)
public_pin_path, public_status_path = next(args), next(args)
public_operator_policy_path, public_projection_path = next(args), next(args)
attest_wrapper, trust_wrapper, doctor_wrapper = next(args), next(args), next(args)
public_trust_command, public_doctor_command = next(args), next(args)
label, plist_path = next(args), next(args)
try:
    next(args)
except StopIteration:
    pass
else:
    raise SystemExit("internal generator argument count mismatch")

config = json.loads(Path(config_path).read_text(encoding="utf-8"))
roles = {}
for role in ("capture", "verifier", "coordinator", "public-verifier"):
    body, digest = inventory(bundle_stage / role, role)
    final_root = Path(bundles_root) / instance_id / role / digest
    role_manifest = {
        **body,
        "bundle_sha256": digest,
        "bundle_root": str(final_root),
        "native_dependency_closure": "not-qualified",
        "activation": False,
    }
    roles[role] = {
        "digest": digest,
        "root": str(final_root),
        "body": body,
        "manifest": role_manifest,
    }
    print(f"bundle\t{role}\t{digest}\t{bundle_stage / role}\t{final_root}")

verifier_root = Path(roles["verifier"]["root"])
verifier_manifest = {
    "schema_version": 2,
    "verifier_version": "john-lomein.persona.operator-verifier.v4",
    "bundle_root": str(verifier_root),
    "entrypoint_path": str(
        verifier_root
        / "qualification_verifier"
        / "john_lomein_persona_qualification_verifier.py"
    ),
    "root_mode": 0o550,
    "directories": roles["verifier"]["body"]["directories"],
    "files": roles["verifier"]["body"]["files"],
}
verifier_manifest_raw = canonical(verifier_manifest) + b"\n"
verifier_manifest_sha = hashlib.sha256(verifier_manifest_raw).hexdigest()
python_raw = (bundle_stage / "verifier" / "python").read_bytes()
verifier_python_sha = hashlib.sha256(python_raw).hexdigest()

journal_relative_path = (
    "qualification_attestor/"
    "john_lomein_persona_qualification_transaction_journal.py"
)
journal_stage_path = bundle_stage / "coordinator" / journal_relative_path
journal_raw = journal_stage_path.read_bytes()
journal_module_sha = hashlib.sha256(journal_raw).hexdigest()
journal_tree = ast.parse(
    journal_raw.decode("utf-8", "strict"),
    filename=str(journal_stage_path),
)
journal_constants = {}
for node in journal_tree.body:
    if (
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id
        in {
            "JOURNAL_RECORD_SCHEMA",
            "STORE_MODE",
            "LOCK_FILE_MODE",
            "COMPLETED_DIRECTORY_MODE",
            "PRODUCTION_ACTIVATION",
        }
    ):
        journal_constants[node.targets[0].id] = ast.literal_eval(node.value)
if journal_constants != {
    "JOURNAL_RECORD_SCHEMA": (
        "john-lomein.persona-qualification-transaction-journal.v5"
    ),
    "STORE_MODE": 0o700,
    "LOCK_FILE_MODE": 0o600,
    "COMPLETED_DIRECTORY_MODE": 0o700,
    "PRODUCTION_ACTIVATION": False,
}:
    raise SystemExit("transaction journal constants are unsupported")

selection = {
    "schema_version": "john-lomein.persona-qualification-capture-selection.v1",
    "instance_slug": slug,
    "evidence_uid": evidence_uid,
    "verifier_gid": verifier_gid,
    "source_roots": {
        "instance_manifest": instance_manifest,
        "runtime": runtime_root,
        "qualification_public": qualification_public,
        "qualification_private": qualification_private,
    },
    "path_identities": {
        "evidence_home": evidence_home,
        "checkout_source": checkout_source,
        "runtime_source": runtime_source,
        "checkout": checkout_identity,
        "runtime": runtime_root,
    },
    "role_profiles": {
        "maintainer": "john-lomein-maintainer",
        "forge": "john-lomein-forge",
        "guide": "john-lomein-guide",
        "overwatch": "john-lomein-overwatch",
        "learning_steward": "john-lomein-learning-steward",
    },
    "limits": config["capture_limits"],
    "lifecycle": config["capture_lifecycle"],
}
selection_sha = hashlib.sha256(canonical(selection)).hexdigest()

attestor = {
    "schema_version": 1,
    "instance_slug": slug,
    "qualification_public_root": qualification_public,
    "qualification_private_root": qualification_private,
    "expected_evidence_uid": evidence_uid,
    "attestor_key_id": config["attestor_key_id"],
    "private_key_path": private_key_path,
    "public_key_path": config_public_key_path,
    "public_key_sha256": public_key_sha,
    "head_path": str(Path(state_dir) / "head.json"),
}
# The verifier binding remains schema v3 and intentionally contains no
# journal authority. The root coordinator receives a separate immutable
# control whose digest is bound into the install record below.
journal_store_path = Path(state_dir) / "transactions"
journal_control = {
    "schema_version": (
        "john-lomein.persona-qualification-transaction-journal-control.v1"
    ),
    "instance_slug": slug,
    "journal_record_schema": journal_constants["JOURNAL_RECORD_SCHEMA"],
    "coordinator_bundle_sha256": roles["coordinator"]["digest"],
    "journal_module_path": str(
        Path(roles["coordinator"]["root"]) / journal_relative_path
    ),
    "journal_module_sha256": journal_module_sha,
    "filesystem_anchor_path": str(Path(state_dir).parent),
    "store_path": str(journal_store_path),
    "completed_directory_path": str(journal_store_path / ".completed"),
    "lock_file_path": str(journal_store_path / ".lock"),
    "store_mode": journal_constants["STORE_MODE"],
    "completed_directory_mode": journal_constants[
        "COMPLETED_DIRECTORY_MODE"
    ],
    "lock_file_mode": journal_constants["LOCK_FILE_MODE"],
    "runtime_orchestration_enabled": False,
    "production_activation": False,
}
journal_control_raw = canonical(journal_control) + b"\n"
journal_control_sha = hashlib.sha256(journal_control_raw).hexdigest()
binding = {
    "schema_version": 3,
    "instance_manifest_path": instance_manifest,
    "instance_manifest_sha256": instance_manifest_sha,
    "capture_uid": capture_uid,
    "capture_export_gid": export_gid,
    "verifier_uid": verifier_uid,
    "verifier_gid": verifier_gid,
    "verifier_python_path": str(verifier_root / "python"),
    "verifier_python_sha256": verifier_python_sha,
    "verifier_bundle_root": str(verifier_root),
    "verifier_manifest_path": verifier_manifest_path,
    "verifier_manifest_sha256": verifier_manifest_sha,
    "verifier_entrypoint_path": verifier_manifest["entrypoint_path"],
    "verifier_version": verifier_manifest["verifier_version"],
    "verifier_timeout_seconds": config["verifier_timeout_seconds"],
    "capture_parent_path": capture_dir,
    "evidence_home_path": evidence_home,
    "runtime_identity_path": runtime_root,
    "checkout_identity_path": checkout_identity,
}
execution_policy = {
    "schema_version": "john-lomein.persona-qualification-verification-execution-policy.v5",
    "argv": ["pinned-python", "-I", "-S", "-B", "pinned-entrypoint"],
    "request_transport": "bounded-root-stdin",
    "environment": ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR", "TZ"],
    "python_hash_randomization": "isolated-runtime-default",
    "bundle_inventory": "complete-declared-root-owned-files",
    "native_dependency_closure": "not-claimed-by-repository-primitive",
    "activation_state": "disabled-pending-protected-installer-canary",
    "working_directory": "root-owned-bundle",
    "close_inherited_fds": True,
    "separate_verifier_uid": True,
    "supplementary_groups_cleared": True,
    "real_effective_saved_ids_equal": True,
    "linux_capability_bounding_set_empty": True,
    "linux_no_new_privs": True,
    "same_uid_debugging_denied": True,
    "network_credentials_present": False,
    "signing_key_opened_after_child": True,
    "sealed_capture_revalidated_after_child": True,
    "live_sources_revalidated_before_child_relinquish": True,
    "post_verifier_live_source_revalidation": True,
    "post_verifier_live_source_revalidation_receipt_schema": (
        "john-lomein.persona-qualification-post-verifier-live-source-"
        "revalidation-receipt.v1"
    ),
    "post_verifier_live_source_revalidation_order": [
        "verifier_process_reaped",
        "verifier_output_canonicalized_and_adoption_bound",
        "live_sources_revalidated_against_adopted_manifest",
        "private_key_opened",
    ],
    "capture_adoption_receipt_required": True,
    "capture_creator_identity_bound": True,
    "adopted_snapshot_owner_uid": 0,
    "adoption_tree_reobserved_by_verifier": True,
    "child_stdout_max_bytes": 1000000,
    "child_stderr_max_bytes": 1000000,
    "address_space_max_bytes": 2147483648,
    "file_size_max_bytes": 1000000,
    "open_files_max": 64,
    "processes_max": 16,
}
operator_policy = {
    "schema_version": "john-lomein.persona-qualification-operator-policy.v3",
    "instance_slug": slug,
    "expected_evidence_uid": evidence_uid,
    "expected_capture_uid": capture_uid,
    "expected_capture_export_gid": export_gid,
    "expected_adopted_uid": 0,
    "capture_adoption_binding_schema": "john-lomein.persona-qualification-capture-adoption-binding.v1",
    "capture_adoption_required": True,
    "instance_manifest_sha256": instance_manifest_sha,
    "verifier_uid": verifier_uid,
    "verifier_gid": verifier_gid,
    "verifier_python_sha256": verifier_python_sha,
    "verifier_bundle_sha256": verifier_manifest_sha,
    "verifier_version": verifier_manifest["verifier_version"],
    "verifier_timeout_seconds": config["verifier_timeout_seconds"],
    "verification_execution_policy_sha256": hashlib.sha256(
        canonical(execution_policy)
    ).hexdigest(),
    "capture_selection_sha256": selection_sha,
    "claim_strength": "operator_verified_local_conformance",
    "public_reputation_eligible": False,
}
blockers = [
    "capture_handoff_v2_not_bound_to_installed_launcher",
    "capture_staging_parent_session_lifecycle_missing",
    "lifecycle_root_supervisor_not_implemented",
    "lifecycle_supervisor_installed_bundle_service_missing",
    "lifecycle_supervisor_server_peer_auth_missing",
    "lifecycle_capability_process_boundary_missing",
    "lifecycle_recovered_clearance_consume_authority_missing",
    "lifecycle_remote_error_commit_proof_missing",
    "lifecycle_terminal_retirement_authority_missing",
    "lifecycle_privileged_provider_adapter_missing",
    "lifecycle_privileged_canary_missing",
    "capture_adoption_crash_recovery_missing",
    "adoption_reconciliation_producer_missing",
    "recovered_adoption_installed_journal_mint_integration_missing",
    "recovered_adoption_downstream_binding_missing",
    "outer_ack_clearance_capability_missing",
    "transaction_journal_runtime_orchestration_missing",
    "transaction_journal_installed_operation_lease_integration_missing",
    "native_dependency_closure_not_qualified",
    "privileged_capture_handoff_canary_missing",
    "privileged_verifier_canary_missing",
]
identities = {
    "instance_id": instance_id,
    "evidence": {"user": evidence_user, "uid": evidence_uid},
    "signer": {"user": signer_user, "uid": signer_uid, "gid": signer_gid},
    "capture": {"user": capture_user, "uid": capture_uid, "gid": capture_gid},
    "verifier": {"user": verifier_user, "uid": verifier_uid, "gid": verifier_gid},
    "export": {"group": export_group, "gid": export_gid},
}
install_record = {
    "schema_version": "john-lomein.persona-qualification-install-record.v1",
    "status": "disabled",
    "production_activation": False,
    "instance_slug": slug,
    "identities": identities,
    "bundles": {
        role: {
            "bundle_root": roles[role]["root"],
            "bundle_sha256": roles[role]["digest"],
            "native_dependency_closure": "not-qualified",
        }
        for role in sorted(roles)
    },
    "controls": {
        "attestor_config_path": attestor_config_path,
        "installed_binding_path": installed_binding_path,
        "capture_selection_path": selection_path,
        "transaction_journal_control_path": str(
            Path(instance_config) / "transaction-journal.json"
        ),
        "transaction_journal_control_sha256": journal_control_sha,
        "transaction_journal_store_path": str(journal_store_path),
        "transaction_journal_filesystem_anchor_path": str(
            Path(state_dir).parent
        ),
        "public_pin_path": public_pin_path,
        "public_projection_path": public_projection_path,
        "launchdaemon_plist_path": plist_path,
    },
    "activation_blockers": blockers,
    "activation_receipts": [],
    "public_reputation_eligible": False,
}
native_closure = {
    "schema_version": "john-lomein.persona-qualification-native-closure.v1",
    "status": "not-qualified",
    "python_source_path": python_source,
    "role_bundle_sha256": {
        role: roles[role]["digest"] for role in sorted(roles)
    },
    "resolved_native_artifacts": [],
    "activation": False,
    "reason": "installer_scaffold_does_not_claim_native_dependency_closure",
}
pin = {
    "schema_version": "john-lomein.persona-qualification-public-verifier-config.v1",
    "projection_path": public_projection_path,
    "instance_slug": slug,
    "attestor_key_id": config["attestor_key_id"],
    "public_key_sha256": public_key_sha,
}
public_status = {
    "schema_version": "john-lomein.persona-qualification-install-status.v1",
    "status": "disabled",
    "instance_slug": slug,
    "production_activation": False,
    "activation_blockers": blockers,
    "public_key_sha256": public_key_sha,
    "operator_policy_sha256": hashlib.sha256(canonical(operator_policy)).hexdigest(),
    "public_reputation_eligible": False,
}

generated.mkdir(parents=True, exist_ok=True)
write_json(generated / "attestor.json", attestor)
write_json(generated / "installed-binding.json", binding)
write_json(generated / "capture-selection.json", selection)
write_json(generated / "install-record.json", install_record)
write_json(generated / "native-closure.json", native_closure)
(generated / "transaction-journal.json").write_bytes(journal_control_raw)
write_json(generated / "public-pin.json", pin)
write_json(generated / "public-status.json", public_status)
write_json(generated / "operator-policy.json", operator_policy)
(generated / "verifier-manifest.json").write_bytes(verifier_manifest_raw)
write_json(generated / "capture-manifest.json", roles["capture"]["manifest"])
write_json(generated / "coordinator-manifest.json", roles["coordinator"]["manifest"])
write_json(generated / "public-verifier-manifest.json", roles["public-verifier"]["manifest"])

invalid = canonical(
    {
        "reason": "protected_persona_qualification_not_activated",
        "status": "invalid",
    }
).decode("ascii")
trust_invalid = canonical(
    {
        "reason": "public_verifier_native_closure_not_qualified",
        "status": "invalid",
    }
).decode("ascii")
doctor = canonical(
    {
        "activation_blockers": blockers,
        "instance_slug": slug,
        "production_activation": False,
        "schema_version": "john-lomein.persona-qualification-doctor.v1",
        "status": "disabled",
    }
).decode("ascii")
wrapper_header = "#!/bin/bash\nset -Eeuo pipefail\nPATH='/usr/bin:/bin:/usr/sbin:/sbin'\nexport PATH\n"
(generated / "attest").write_text(
    wrapper_header
    + "if [ \"$#\" -ne 0 ]; then echo '{\"reason\":\"command_arguments_unsupported\",\"status\":\"invalid\"}' >&2; exit 2; fi\n"
    + "if [ \"$(/usr/bin/id -u)\" -ne 0 ]; then echo '{\"reason\":\"root_required\",\"status\":\"invalid\"}' >&2; exit 2; fi\n"
    + f"echo '{invalid}' >&2\nexit 2\n",
    encoding="utf-8",
)
(generated / "trust").write_text(
    wrapper_header
    + "if [ \"$#\" -ne 0 ]; then echo '{\"reason\":\"command_arguments_unsupported\",\"status\":\"invalid\"}' >&2; exit 2; fi\n"
    + f"echo '{trust_invalid}' >&2\nexit 2\n",
    encoding="utf-8",
)
(generated / "doctor").write_text(
    wrapper_header
    + "if [ \"$#\" -ne 0 ]; then echo '{\"reason\":\"command_arguments_unsupported\",\"status\":\"invalid\"}' >&2; exit 2; fi\n"
    + f"echo '{doctor}'\nexit 1\n",
    encoding="utf-8",
)
(generated / "public-trust-command").write_text(
    wrapper_header
    + "if [ \"$#\" -ne 0 ]; then echo '{\"reason\":\"command_arguments_unsupported\",\"status\":\"invalid\"}' >&2; exit 2; fi\n"
    + f"exec '{trust_wrapper}'\n",
    encoding="utf-8",
)
(generated / "public-doctor-command").write_text(
    wrapper_header
    + "if [ \"$#\" -ne 0 ]; then echo '{\"reason\":\"command_arguments_unsupported\",\"status\":\"invalid\"}' >&2; exit 2; fi\n"
    + f"exec '{doctor_wrapper}'\n",
    encoding="utf-8",
)
plist = {
    "Label": label,
    "ProgramArguments": [attest_wrapper],
    "Disabled": True,
    "RunAtLoad": False,
    "KeepAlive": False,
    "ProcessType": "Background",
    "UserName": "root",
    "GroupName": "wheel",
    "Umask": 0o077,
    "StandardOutPath": "/dev/null",
    "StandardErrorPath": "/dev/null",
}
(generated / "launchdaemon.plist").write_bytes(
    plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=True)
)
PY

BUNDLE_LINES=()
while IFS=$'\t' read -r kind role digest stage final; do
  [ "$kind" = "bundle" ] || die "final generator returned an unknown record"
  [[ "$role" =~ ^(capture|verifier|coordinator|public-verifier)$ ]] ||
    die "final generator returned an invalid role"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] ||
    die "final generator returned an invalid bundle digest"
  BUNDLE_LINES+=("$role|$digest|$stage|$final")
done <"$FINAL_REPORT"
[ "${#BUNDLE_LINES[@]}" -eq 4 ] ||
  die "final generator did not return four role bundles"

ensure_root_directory() {
  local path="$1"
  local owner="$2"
  local group="$3"
  local mode="$4"
  local label="$5"
  if [ -e "$path" ] || [ -L "$path" ]; then
    [ -d "$path" ] && [ ! -L "$path" ] ||
      die "$label is not a non-symlink directory"
    [ "$(/usr/bin/stat -f '%Su' "$path")" = "$owner" ] ||
      die "$label has the wrong owner"
    [ "$(/usr/bin/stat -f '%Sg' "$path")" = "$group" ] ||
      die "$label has the wrong group"
    [ "$(/usr/bin/stat -f '%Lp' "$path")" = "$mode" ] ||
      die "$label has the wrong mode"
    reject_acl "$path" "$label"
  else
    CREATED_DIRECTORIES+=("$path")
    /usr/bin/install -d -o "$owner" -g "$group" -m "$mode" "$path"
    /bin/chmod -N "$path" 2>/dev/null || true
  fi
}

ensure_transaction_journal_lock_file() {
  local result
  result="$(
    "$PYTHON" -I -B -S - \
      "$INSTANCE_DATA_DIR" "$STATE_DIR" "$TRANSACTION_JOURNAL_DIR" \
      "$TRANSACTION_JOURNAL_COMPLETED_DIR" \
      "$TRANSACTION_JOURNAL_LOCK_PATH" 0 0 <<'PY'
from __future__ import annotations

import errno
import fcntl
import os
import stat
import sys
from pathlib import Path


(
    anchor_raw,
    state_raw,
    store_raw,
    completed_raw,
    lock_raw,
    expected_uid_raw,
    expected_gid_raw,
) = sys.argv[1:]
anchor = Path(anchor_raw)
state = Path(state_raw)
store = Path(store_raw)
completed = Path(completed_raw)
lock = Path(lock_raw)
expected_uid = int(expected_uid_raw)
expected_gid = int(expected_gid_raw)
paths = (anchor, state, store, completed, lock)
raw_paths = (
    anchor_raw,
    state_raw,
    store_raw,
    completed_raw,
    lock_raw,
)
if any(
    not path.is_absolute()
    or raw != str(path)
    or "." in path.parts
    or ".." in path.parts
    or any(ord(character) < 32 for character in raw)
    for raw, path in zip(raw_paths, paths, strict=True)
):
    raise SystemExit("transaction journal path is not normalized")
if (
    state != anchor / "state"
    or store != state / "transactions"
    or completed != store / ".completed"
    or lock != store / ".lock"
):
    raise SystemExit("transaction journal layout escaped its fixed namespace")
if not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("transaction journal nofollow support is unavailable")
directory_flags = (
    os.O_RDONLY
    | os.O_NOFOLLOW
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
file_flags = os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
descriptors = []


def same_object(named, opened):
    return (
        named.st_dev,
        named.st_ino,
        stat.S_IFMT(named.st_mode),
    ) == (
        opened.st_dev,
        opened.st_ino,
        stat.S_IFMT(opened.st_mode),
    )


def validate_directory(descriptor, mode, label):
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_uid
        or info.st_gid != expected_gid
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise SystemExit(f"{label} metadata is unsafe")
    return info


def validate_named(parent_fd, name, descriptor, directory, label):
    named = os.stat(
        name,
        dir_fd=parent_fd,
        follow_symlinks=False,
    )
    opened = os.fstat(descriptor)
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_kind(named.st_mode) or not same_object(named, opened):
        raise SystemExit(f"{label} name-to-descriptor binding changed")


try:
    anchor_fd = os.open(anchor, directory_flags)
    descriptors.append(anchor_fd)
    state_fd = os.open("state", directory_flags, dir_fd=anchor_fd)
    descriptors.append(state_fd)
    store_fd = os.open("transactions", directory_flags, dir_fd=state_fd)
    descriptors.append(store_fd)
    completed_fd = os.open(
        ".completed",
        directory_flags,
        dir_fd=store_fd,
    )
    descriptors.append(completed_fd)
    anchor_info = validate_directory(anchor_fd, 0o711, "journal anchor")
    state_info = validate_directory(state_fd, 0o700, "journal state root")
    store_info = validate_directory(store_fd, 0o700, "journal store")
    completed_info = validate_directory(
        completed_fd,
        0o700,
        "journal completed archive",
    )
    named_anchor = os.lstat(anchor)
    if not same_object(named_anchor, anchor_info):
        raise SystemExit("journal anchor name-to-descriptor binding changed")
    validate_named(
        anchor_fd,
        "state",
        state_fd,
        True,
        "journal state root",
    )
    validate_named(
        state_fd,
        "transactions",
        store_fd,
        True,
        "journal store",
    )
    validate_named(
        store_fd,
        ".completed",
        completed_fd,
        True,
        "journal completed archive",
    )
    created = False
    try:
        lock_fd = os.open(
            ".lock",
            file_flags | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=store_fd,
        )
        created = True
        os.fchown(lock_fd, expected_uid, expected_gid)
        os.fchmod(lock_fd, 0o600)
    except FileExistsError:
        lock_fd = os.open(".lock", file_flags, dir_fd=store_fd)
    descriptors.append(lock_fd)
    lock_info = os.fstat(lock_fd)
    if (
        not stat.S_ISREG(lock_info.st_mode)
        or lock_info.st_uid != expected_uid
        or lock_info.st_gid != expected_gid
        or stat.S_IMODE(lock_info.st_mode) != 0o600
        or lock_info.st_nlink != 1
        or lock_info.st_size != 0
    ):
        raise SystemExit("journal lock metadata is unsafe")
    validate_named(
        store_fd,
        ".lock",
        lock_fd,
        False,
        "journal lock",
    )
    devices = {
        value.st_dev
        for value in (
            anchor_info,
            state_info,
            store_info,
            completed_info,
            lock_info,
        )
    }
    if len(devices) != 1:
        raise SystemExit("transaction journal crosses filesystem devices")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN}:
            raise SystemExit(
                "transaction journal lock is already held"
            ) from exc
        raise
    for descriptor in (
        lock_fd,
        completed_fd,
        store_fd,
        state_fd,
        anchor_fd,
    ):
        os.fsync(descriptor)
    print("created" if created else "existing")
finally:
    for descriptor in reversed(descriptors):
        os.close(descriptor)
PY
  )" || die "transaction journal layout provisioning failed"
  case "$result" in
    created) CREATED_STATE_FILES+=("$TRANSACTION_JOURNAL_LOCK_PATH") ;;
    existing) ;;
    *) die "transaction journal layout provisioner returned invalid output" ;;
  esac
  for path in \
    "$INSTANCE_DATA_DIR" "$STATE_DIR" "$TRANSACTION_JOURNAL_DIR" \
    "$TRANSACTION_JOURNAL_COMPLETED_DIR" "$TRANSACTION_JOURNAL_LOCK_PATH"
  do
    reject_acl "$path" "transaction journal installed path"
    reject_xattrs "$path" "transaction journal installed path"
  done
}

ensure_root_directory /usr/local root wheel 0755 "/usr/local"
ensure_root_directory /usr/local/libexec root wheel 0755 "/usr/local/libexec"
ensure_root_directory "$CODE_ROOT" root wheel 0755 "qualification code root"
ensure_root_directory "$BUNDLES_ROOT" root wheel 0755 "bundle root"
ensure_root_directory "$BUNDLES_ROOT/$INSTANCE_ID" root wheel 0755 \
  "instance bundle root"
for role in capture verifier coordinator public-verifier; do
  ensure_root_directory "$BUNDLES_ROOT/$INSTANCE_ID/$role" root wheel 0755 \
    "$role bundle parent"
done
ensure_root_directory "$INSTANCES_ROOT" root wheel 0755 \
  "qualification instances root"
ensure_root_directory "$INSTANCE_CODE_DIR" root wheel 0755 \
  "instance invocation root"

ensure_root_directory /private/etc root wheel 0755 "/private/etc"
ensure_root_directory "$CONFIG_ROOT" root wheel 0700 \
  "qualification config root"
ensure_root_directory "$INSTANCE_CONFIG_DIR" root wheel 0700 \
  "instance config root"
ensure_root_directory "$KEYS_DIR" root wheel 0700 "instance key root"
ensure_root_directory "$PUBLIC_ROOT" root wheel 0755 \
  "qualification public root"
ensure_root_directory "$INSTANCE_PUBLIC_DIR" root wheel 0755 \
  "instance public root"

ensure_root_directory /private/var/db root wheel 0755 "/private/var/db"
ensure_root_directory "$DATA_ROOT" root wheel 0711 \
  "qualification data root"
ensure_root_directory "$INSTANCE_DATA_DIR" root wheel 0711 \
  "instance qualification data root"
ensure_root_directory "$STATE_DIR" root wheel 0700 \
  "attestation state root"
ensure_root_directory "$TRANSACTION_JOURNAL_DIR" root wheel 0700 \
  "transaction journal store"
ensure_root_directory "$TRANSACTION_JOURNAL_COMPLETED_DIR" root wheel 0700 \
  "transaction journal completed archive"
ensure_transaction_journal_lock_file
ensure_root_directory "$STAGING_DIR" root wheel 0711 \
  "capture staging root"
ensure_root_directory "$CAPTURE_DIR" root "$VERIFIER_GROUP" 0710 \
  "adopted capture root"
ensure_root_directory "$SCRATCH_DIR" "$VERIFIER_USER" "$VERIFIER_GROUP" 0700 \
  "verifier scratch root"
ensure_root_directory "$EXPORT_DIR" "$EVIDENCE_USER" "$EXPORT_GROUP" 0750 \
  "evidence export root"
ensure_root_directory /usr/local/bin root wheel 0755 "/usr/local/bin"

backup_optional_file() {
  local source="$1"
  local backup="$2"
  if [ ! -e "$source" ] && [ ! -L "$source" ]; then
    /usr/bin/touch "$backup.absent"
    /bin/chmod 0600 "$backup.absent"
    return 0
  fi
  [ ! -L "$source" ] && [ -f "$source" ] ||
    die "existing managed path is not a regular non-symlink file: $source"
  "$PYTHON" -I -B -S - "$source" "$backup" <<'PY'
import os
import stat
import sys

source, backup = sys.argv[1:]
source_fd = os.open(
    source,
    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
)
try:
    before = os.fstat(source_fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or before.st_size > 64 * 1024 * 1024
    ):
        raise SystemExit("rollback source metadata is unsafe")
    chunks = []
    observed = 0
    while observed <= 64 * 1024 * 1024:
        chunk = os.read(source_fd, min(65536, 64 * 1024 * 1024 + 1 - observed))
        if not chunk:
            break
        chunks.append(chunk)
        observed += len(chunk)
    after = os.fstat(source_fd)
    named = os.lstat(source)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if observed != before.st_size or identity(before) != identity(after) or identity(after) != identity(named):
        raise SystemExit("rollback source changed during snapshot")
finally:
    os.close(source_fd)
backup_fd = os.open(
    backup,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
    0o600,
)
try:
    payload = b"".join(chunks)
    while payload:
        written = os.write(backup_fd, payload)
        if written <= 0:
            raise SystemExit("rollback snapshot made no progress")
        payload = payload[written:]
    os.fchmod(backup_fd, stat.S_IMODE(before.st_mode))
    os.fsync(backup_fd)
finally:
    os.close(backup_fd)
PY
}

register_managed_file() {
  local destination="$1"
  local backup_name="$2"
  local backup="$ROLLBACK_DIR/$backup_name"
  backup_optional_file "$destination" "$backup"
  MANAGED_FILES+=("$backup|$destination")
}

register_managed_file "$ATTESTOR_CONFIG_PATH" attestor.json
register_managed_file "$INSTALLED_BINDING_PATH" installed-binding.json
register_managed_file "$SELECTION_PATH" capture-selection.json
register_managed_file "$INSTALL_RECORD_PATH" install-record.json
register_managed_file "$NATIVE_CLOSURE_PATH" native-closure.json
register_managed_file \
  "$TRANSACTION_JOURNAL_CONTROL_PATH" transaction-journal.json
register_managed_file "$PRIVATE_KEY_PATH" private-key.pem
register_managed_file "$CONFIG_PUBLIC_KEY_PATH" config-public-key.pem
register_managed_file "$VERIFIER_MANIFEST_PATH" verifier-manifest.json
register_managed_file "$CAPTURE_MANIFEST_PATH" capture-manifest.json
register_managed_file "$COORDINATOR_MANIFEST_PATH" coordinator-manifest.json
register_managed_file "$PUBLIC_VERIFIER_MANIFEST_PATH" public-verifier-manifest.json
register_managed_file "$PUBLIC_KEY_PATH" public-key.pem
register_managed_file "$PUBLIC_PIN_PATH" public-pin.json
register_managed_file "$PUBLIC_STATUS_PATH" public-status.json
register_managed_file "$PUBLIC_OPERATOR_POLICY_PATH" operator-policy.json
register_managed_file "$ATTEST_WRAPPER_PATH" attest-wrapper
register_managed_file "$TRUST_WRAPPER_PATH" trust-wrapper
register_managed_file "$DOCTOR_WRAPPER_PATH" doctor-wrapper
register_managed_file "$PUBLIC_TRUST_COMMAND" public-trust-command
register_managed_file "$PUBLIC_DOCTOR_COMMAND" public-doctor-command
register_managed_file "$PLIST_PATH" launchdaemon.plist

# Key replacement is not a casual upgrade. Once installed, v1 requires exact
# byte continuity; rotation needs a separate archive migration design.
if [ -f "$PRIVATE_KEY_PATH" ] &&
   ! /usr/bin/cmp -s "$PRIVATE_KEY_PATH" "$PRIVATE_KEY_SNAPSHOT"; then
  die "installed attestor private key differs; key rotation is unsupported"
fi
if [ -f "$PUBLIC_KEY_PATH" ] &&
   ! /usr/bin/cmp -s "$PUBLIC_KEY_PATH" "$PUBLIC_KEY_SNAPSHOT"; then
  die "installed attestor public key differs; key rotation is unsupported"
fi

install_bundle() {
  local role="$1"
  local stage="$2"
  local final="$3"
  local group mode candidate directory_mode data_mode executable_mode
  case "$role" in
    capture) group="$CAPTURE_GROUP" ;;
    verifier) group="$VERIFIER_GROUP" ;;
    coordinator|public-verifier) group=wheel ;;
    *) die "internal bundle role is invalid" ;;
  esac
  directory_mode=0550
  data_mode=0440
  executable_mode=0550
  if [ "$role" = public-verifier ]; then
    directory_mode=0555
    data_mode=0444
    executable_mode=0555
  fi
  if [ -e "$final" ] || [ -L "$final" ]; then
    [ -d "$final" ] && [ ! -L "$final" ] ||
      die "$role content-addressed bundle path is unsafe"
    /usr/bin/diff -qr "$stage" "$final" >/dev/null ||
      die "$role content-addressed bundle has conflicting bytes"
    while IFS= read -r -d '' candidate; do
      [ ! -L "$candidate" ] ||
        die "$role installed bundle contains a symlink"
      [ "$(/usr/bin/stat -f '%Su' "$candidate")" = root ] ||
        die "$role installed bundle has the wrong owner"
      [ "$(/usr/bin/stat -f '%Sg' "$candidate")" = "$group" ] ||
        die "$role installed bundle has the wrong group"
      if [ -d "$candidate" ]; then
        mode="$directory_mode"
      elif [ -f "$candidate" ]; then
        [ "$(/usr/bin/stat -f '%l' "$candidate")" -eq 1 ] ||
          die "$role installed bundle contains a hard-linked file"
        if [ "$(/usr/bin/basename "$candidate")" = python ]; then
          mode="$executable_mode"
        else
          mode="$data_mode"
        fi
      else
        die "$role installed bundle contains an unsupported entry"
      fi
      [ "$(/usr/bin/stat -f '%Lp' "$candidate")" = "$mode" ] ||
        die "$role installed bundle has the wrong mode"
      reject_acl "$candidate" "$role installed bundle"
      reject_xattrs "$candidate" "$role installed bundle"
    done < <(/usr/bin/find -x "$final" -print0)
    return 0
  fi
  local parent staged
  parent="$(/usr/bin/dirname "$final")"
  staged="$(/usr/bin/mktemp -d "$parent/.${role}.stage.XXXXXX")"
  CREATED_BUNDLES+=("$staged")
  /usr/bin/ditto --noqtn --noextattr --noacl "$stage/" "$staged/"
  /usr/sbin/chown -R "root:$group" "$staged"
  while IFS= read -r -d '' candidate; do
    if [ -d "$candidate" ]; then
      /bin/chmod "$directory_mode" "$candidate"
    elif [ "$(/usr/bin/basename "$candidate")" = python ]; then
      /bin/chmod "$executable_mode" "$candidate"
    else
      /bin/chmod "$data_mode" "$candidate"
    fi
    /bin/chmod -N "$candidate" 2>/dev/null || true
  done < <(/usr/bin/find -x "$staged" -print0)
  CREATED_BUNDLES+=("$final")
  /bin/mv "$staged" "$final"
}

for bundle_line in "${BUNDLE_LINES[@]}"; do
  role="${bundle_line%%|*}"
  remainder="${bundle_line#*|}"
  digest="${remainder%%|*}"
  remainder="${remainder#*|}"
  stage="${remainder%%|*}"
  final="${remainder#*|}"
  [ "$final" = "$BUNDLES_ROOT/$INSTANCE_ID/$role/$digest" ] ||
    die "generated bundle path escaped its role namespace"
  install_bundle "$role" "$stage" "$final"
done

install_managed_file() {
  local source="$1"
  local destination="$2"
  local owner="$3"
  local group="$4"
  local mode="$5"
  local staged
  [ ! -L "$destination" ] ||
    die "managed destination is an unsafe symlink: $destination"
  [ ! -e "$destination" ] || [ -f "$destination" ] ||
    die "managed destination is not a regular file: $destination"
  staged="$(/usr/bin/mktemp "$destination.install.XXXXXX")"
  /usr/bin/install -o "$owner" -g "$group" -m "$mode" "$source" "$staged"
  /bin/chmod -N "$staged" 2>/dev/null || true
  /bin/mv -f "$staged" "$destination"
}

install_managed_file "$GENERATED_DIR/attestor.json" \
  "$ATTESTOR_CONFIG_PATH" root wheel 0600
install_managed_file "$GENERATED_DIR/installed-binding.json" \
  "$INSTALLED_BINDING_PATH" root wheel 0600
install_managed_file "$GENERATED_DIR/capture-selection.json" \
  "$SELECTION_PATH" root wheel 0600
install_managed_file "$GENERATED_DIR/install-record.json" \
  "$INSTALL_RECORD_PATH" root wheel 0600
install_managed_file "$GENERATED_DIR/native-closure.json" \
  "$NATIVE_CLOSURE_PATH" root wheel 0600
install_managed_file "$GENERATED_DIR/transaction-journal.json" \
  "$TRANSACTION_JOURNAL_CONTROL_PATH" root wheel 0600
install_managed_file "$PRIVATE_KEY_SNAPSHOT" \
  "$PRIVATE_KEY_PATH" root wheel 0600
install_managed_file "$PUBLIC_KEY_SNAPSHOT" \
  "$CONFIG_PUBLIC_KEY_PATH" root wheel 0600
install_managed_file "$GENERATED_DIR/verifier-manifest.json" \
  "$VERIFIER_MANIFEST_PATH" root wheel 0600
install_managed_file "$GENERATED_DIR/capture-manifest.json" \
  "$CAPTURE_MANIFEST_PATH" root wheel 0600
install_managed_file "$GENERATED_DIR/coordinator-manifest.json" \
  "$COORDINATOR_MANIFEST_PATH" root wheel 0600
install_managed_file "$GENERATED_DIR/public-verifier-manifest.json" \
  "$PUBLIC_VERIFIER_MANIFEST_PATH" root wheel 0600
install_managed_file "$PUBLIC_KEY_SNAPSHOT" \
  "$PUBLIC_KEY_PATH" root wheel 0444
install_managed_file "$GENERATED_DIR/public-pin.json" \
  "$PUBLIC_PIN_PATH" root wheel 0444
install_managed_file "$GENERATED_DIR/public-status.json" \
  "$PUBLIC_STATUS_PATH" root wheel 0444
install_managed_file "$GENERATED_DIR/operator-policy.json" \
  "$PUBLIC_OPERATOR_POLICY_PATH" root wheel 0444
install_managed_file "$GENERATED_DIR/attest" \
  "$ATTEST_WRAPPER_PATH" root wheel 0555
install_managed_file "$GENERATED_DIR/trust" \
  "$TRUST_WRAPPER_PATH" root wheel 0555
install_managed_file "$GENERATED_DIR/doctor" \
  "$DOCTOR_WRAPPER_PATH" root wheel 0555
install_managed_file "$GENERATED_DIR/public-trust-command" \
  "$PUBLIC_TRUST_COMMAND" root wheel 0555
install_managed_file "$GENERATED_DIR/public-doctor-command" \
  "$PUBLIC_DOCTOR_COMMAND" root wheel 0555

if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
  die "existing qualification LaunchDaemon is loaded; disable it before scaffold upgrade"
fi
/bin/launchctl disable "system/$LABEL"
install_managed_file "$GENERATED_DIR/launchdaemon.plist" \
  "$PLIST_PATH" root wheel 0644
/usr/bin/plutil -lint "$PLIST_PATH" >/dev/null
/bin/launchctl disable "system/$LABEL"
if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
  die "disabled qualification LaunchDaemon unexpectedly became loaded"
fi

# The activation-receipt namespace must remain absent. A future installer
# revision may create it only after independently executing every canary.
[ ! -e "$INSTANCE_CONFIG_DIR/activation" ] &&
  [ ! -L "$INSTANCE_CONFIG_DIR/activation" ] ||
  die "unexpected activation namespace exists; scaffold cannot bless it"

TRANSACTION_COMMITTED=1
echo "protected persona qualification scaffold installed disabled: $SLUG"
echo "derived identities: signer=$SIGNER_USER capture=$CAPTURE_USER verifier=$VERIFIER_USER export=$EXPORT_GROUP"
echo "public status: $PUBLIC_STATUS_PATH"
echo "public pin: $PUBLIC_PIN_PATH"
echo "LaunchDaemon installed disabled and not bootstrapped: $LABEL"
echo "activation remains blocked by runtime journal orchestration, installed capture wiring, native closure, and privileged canaries"
