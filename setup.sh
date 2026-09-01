#!/usr/bin/env bash
set -Eeuo pipefail
PRODUCT_ROOT="$(cd "$(dirname "$0")" && pwd)"

usage() {
  cat >&2 <<'EOF'
usage:
  ./setup.sh /path/to/existing-instance
  ./setup.sh --init /path/to/new-instance --repo owner/repo \
    --mission "Public-safe mission candidate" --test-cmd "project test command"
EOF
}

if [ $# -lt 1 ]; then
  usage
  exit 2
fi
if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required for locked john-lomein product commands: https://docs.astral.sh/uv/" >&2
  exit 2
fi

if [ "$1" = "--init" ]; then
  shift
  if [ $# -lt 1 ]; then
    usage
    exit 2
  fi
  exec uv run --frozen --project "$PRODUCT_ROOT" python \
    "$PRODUCT_ROOT/scripts/john-lomein-init.py" "$@" --install
fi

if [ $# -ne 1 ]; then
  usage
  exit 2
fi
INSTANCE="$1"
SERVICE_REGISTRY="$PRODUCT_ROOT/scripts/john_lomein_service_registry.py"

if [ -z "${JOHN_LOMEIN_SERVICE_LOCK_FD:-}" ]; then
  exec uv run --frozen --project "$PRODUCT_ROOT" python \
    "$SERVICE_REGISTRY" run-locked -- bash "$0" "$INSTANCE"
fi
uv run --frozen --offline --project "$PRODUCT_ROOT" python \
  "$SERVICE_REGISTRY" assert-locked

# Bind the complete locked transaction to one stable, owner-private manifest
# snapshot. The original manifest path remains the service-registry identity,
# while every configuration consumer reads these exact staged bytes.
cleanup_setup_manifest() {
  local original_status=$?
  local cleanup_status=0
  trap - EXIT
  set +e
  if [ -n "${JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT:-}" ] && \
    { [ -e "$JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT" ] || \
      [ -L "$JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT" ]; }
  then
    rm -f -- "$JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT"
    cleanup_status=$?
  fi
  if [ "$cleanup_status" -ne 0 ]; then
    echo "setup manifest cleanup failed; inspect the owner-private staged file" >&2
    if [ "$original_status" -eq 0 ]; then
      original_status=70
    fi
  fi
  exit "$original_status"
}
trap cleanup_setup_manifest EXIT
if SETUP_MANIFEST_BINDING="$(
  uv run --frozen --offline --project "$PRODUCT_ROOT" python \
    "$PRODUCT_ROOT/scripts/john-lomein-stage-manifest.py" \
    stage "$INSTANCE"
)"
then
  eval "$SETUP_MANIFEST_BINDING"
  unset SETUP_MANIFEST_BINDING
else
  SETUP_MANIFEST_STATUS=$?
  echo "setup preflight failed: instance manifest could not be staged safely" >&2
  exit "$SETUP_MANIFEST_STATUS"
fi
export JOHN_LOMEIN_SETUP_MANIFEST_SOURCE
export JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT
export JOHN_LOMEIN_SETUP_MANIFEST_SHA256

verify_setup_manifest() {
  uv run --frozen --project "$PRODUCT_ROOT" python \
    "$PRODUCT_ROOT/scripts/read-instance-env.py" "$INSTANCE" >/dev/null
  uv run --frozen --offline --project "$PRODUCT_ROOT" python \
    "$PRODUCT_ROOT/scripts/john-lomein-stage-manifest.py" verify \
    "$JOHN_LOMEIN_SETUP_MANIFEST_SOURCE" \
    "$JOHN_LOMEIN_SETUP_MANIFEST_SHA256"
}

# Validate the staged desired manifest before disturbing a live runtime.
if uv run --frozen --offline --project "$PRODUCT_ROOT" python \
  "$PRODUCT_ROOT/scripts/john-lomein-orient.py" \
  "$JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT" --json >/dev/null
then
  ORIENTATION_PREFLIGHT_STATUS=0
else
  ORIENTATION_PREFLIGHT_STATUS=$?
fi
if [ "$ORIENTATION_PREFLIGHT_STATUS" -ge 2 ]; then
  echo "setup preflight failed: instance orientation is broken" >&2
  exit "$ORIENTATION_PREFLIGHT_STATUS"
fi
verify_setup_manifest

SERVICES_RECONCILED=0
rollback_services() {
  local status=$?
  local cleanup_status=0
  trap - ERR INT TERM
  if [ "$SERVICES_RECONCILED" = "1" ]; then
    set +e
    make uninstall-supervisor INSTANCE="$INSTANCE" >/dev/null
    cleanup_status=$?
    set -e
  fi
  if [ "$cleanup_status" -ne 0 ]; then
    echo "setup rollback incomplete: one or more product-managed services could not be verified absent" >&2
    exit 70
  fi
  if [ "$status" -eq 0 ]; then
    status=1
  fi
  echo "setup failed; no newly configured product-managed service was left running" >&2
  exit "$status"
}
trap rollback_services ERR INT TERM

# The uninstaller consults the stable per-manifest service registry, so it also
# removes labels from the instance's previous slug before deployment mutates
# runtime state.
make uninstall-supervisor INSTANCE="$INSTANCE"
SERVICES_RECONCILED=1
make deploy INSTANCE="$INSTANCE"
verify_setup_manifest
make smoke-all INSTANCE="$INSTANCE"
make install-supervisor INSTANCE="$INSTANCE"
make install-guide-gateway INSTANCE="$INSTANCE"
verify_setup_manifest

# Invoke Doctor directly so its tri-state exit contract survives intact:
# 0=clean, 1=healthy with warnings, 2=failed. GNU make converts any non-zero
# recipe result to its own exit code 2, which would turn warnings into a false
# setup failure and roll back otherwise healthy services. Keep the command in
# an if condition so Bash's ERR trap also waits for this explicit decision.
if uv run --frozen --project "$PRODUCT_ROOT" python \
  "$PRODUCT_ROOT/scripts/doctor-instance.py" \
  "$JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT"
then
  DOCTOR_STATUS=0
else
  DOCTOR_STATUS=$?
fi
if [ "$DOCTOR_STATUS" -ge 2 ]; then
  false
fi
verify_setup_manifest

if uv run --frozen --project "$PRODUCT_ROOT" python \
  "$PRODUCT_ROOT/scripts/john-lomein-orient.py" \
  "$JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT"
then
  ORIENTATION_STATUS=0
else
  ORIENTATION_STATUS=$?
fi
if [ "$ORIENTATION_STATUS" -ge 2 ]; then
  false
fi
verify_setup_manifest

SERVICES_RECONCILED=0
trap - ERR INT TERM
if [ "$DOCTOR_STATUS" -eq 1 ]; then
  echo "setup completed with doctor warnings; protected actions remain fail-closed where prerequisites are absent" >&2
fi
if [ "$ORIENTATION_STATUS" -eq 1 ]; then
  echo "setup completed with an orientation action; configured authority remains unproven until the named local gap is repaired" >&2
fi
