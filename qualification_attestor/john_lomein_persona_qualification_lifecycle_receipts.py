#!/usr/bin/env python3
"""Pure, path-free lifecycle receipts for protected capture supervision.

This module is deliberately standard-library only.  It describes evidence
minted by a separately measured root supervisor; it does not launch, inspect,
signal, or reap a process.  A canonical digest is only a cross-binding and is
never treated as lifecycle authority by itself.

Production proof minting remains disabled.  The private test seam exists so
the one-shot capability contract can be exercised without blessing a runtime
route.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any


PRODUCTION_ACTIVATION = False

ACTIVATION_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-activation.v1"
)
SCOPE_STARTED_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-scope-started.v1"
)
CLEARANCE_INTENT_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-clearance-intent.v1"
)
SCOPE_EMPTY_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-scope-empty.v1"
)
CLEARANCE_BUNDLE_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-clearance-bundle.v1"
)

ACTIVATION_STATUS = "privileged_canary_passed"
SCOPE_STARTED_STATUS = "scope_started"
CLEARANCE_INTENT_STATUS = "scope_clearance_requested"
SCOPE_EMPTY_STATUS = "scope_empty"
CLEARANCE_BUNDLE_STATUS = "scope_clearance_complete"

LIFECYCLE_BACKEND = "root_supervisor"
SYSTEMS = frozenset({"Linux", "Darwin"})
PROVIDERS_BY_SYSTEM = {
    "Linux": frozenset(
        {
            "linux_cgroup_v2",
            "systemd_transient_scope",
            "direct_waitid_deny_fork",
        }
    ),
    "Darwin": frozenset(
        {
            "darwin_launchd_job",
            "direct_waitid_deny_fork",
        }
    ),
}
BOOT_MEASUREMENT_BY_SYSTEM = {
    "Linux": "linux_boot_id",
    "Darwin": "darwin_boot_session_uuid",
}
NORMAL_CLEARANCE_BASIS_BY_PROVIDER = {
    "linux_cgroup_v2": "linux_cgroup_kill_populated_zero",
    "systemd_transient_scope": "systemd_control_group_empty",
    "darwin_launchd_job": "launchd_job_absent_fork_denied",
    "direct_waitid_deny_fork": (
        "direct_waitid_pinned_single_process"
    ),
}
NO_EFFECT_CLEARANCE_BASIS = "supervisor_ledger_no_effect"
REBOOT_CLEARANCE_BASIS = "host_boot_epoch_changed"
CLEARANCE_BASES = frozenset(
    {
        *NORMAL_CLEARANCE_BASIS_BY_PROVIDER.values(),
        NO_EFFECT_CLEARANCE_BASIS,
        REBOOT_CLEARANCE_BASIS,
    }
)
COMPLETION_DISPOSITIONS = frozenset(
    {
        "never_started",
        "never_started_after_reboot",
        "clean_exit",
        "abnormal_exit",
        "forced_termination",
        "exit_unobserved_after_restart",
        "host_reboot",
    }
)
EFFECT_ORIGIN_STATES = frozenset(
    {"child_launch_intent", "child_running", "capture_ready"}
)
CLEARANCE_MODES = frozenset(
    {
        "wait_clean_then_terminate_on_deadline",
        "terminate_and_clear",
    }
)
PROOF_PURPOSES = frozenset({"staging_cleanup", "capture_adoption"})

ACTIVATION_ASSERTIONS = frozenset(
    {
        "fork_denied",
        "host_boot_epoch_observed",
        "lifecycle_ledger_crash_safe",
        "numeric_process_ids_not_authority",
        "scope_before_untrusted_exec",
        "scope_empty_provider_observed",
        "stderr_supervisor_owned",
        "supervisor_ipc_authenticated",
        "supervisor_root_owned",
        "wrapper_scope_contained",
    }
)

ACTIVATION_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "system",
        "lifecycle_backend",
        "lifecycle_provider",
        "supervisor_policy_sha256",
        "supervisor_bundle_sha256",
        "helper_activation_policy_sha256",
        "lifecycle_canary_sha256",
        "host_boot_measurement",
        "host_boot_id_sha256",
        "assertions",
        "production_activation",
    }
)
SCOPE_STARTED_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "capture_session_id",
        "lifecycle_backend",
        "lifecycle_provider",
        "lifecycle_scope_id",
        "scope_incarnation_id",
        "supervisor_epoch_id",
        "host_boot_id_sha256",
        "staging_transaction_intent_sha256",
        "staging_exposure_receipt_sha256",
        "child_launch_intent_record_sha256",
        "handoff_policy_sha256",
        "helper_activation_policy_sha256",
        "capture_uid",
        "export_gid",
        "lifecycle_activation_receipt_sha256",
    }
)
CLEARANCE_INTENT_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "capture_session_id",
        "lifecycle_backend",
        "lifecycle_provider",
        "lifecycle_scope_id",
        "scope_incarnation_id",
        "lifecycle_activation_receipt_sha256",
        "child_launch_intent_record_sha256",
        "effect_origin_state",
        "effect_origin_record_sha256",
        "scope_started_receipt_sha256",
        "clearance_mode",
        "outer_clearance_intent_record_sha256",
    }
)
SCOPE_EMPTY_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "capture_session_id",
        "lifecycle_backend",
        "lifecycle_provider",
        "lifecycle_scope_id",
        "scope_incarnation_id",
        "lifecycle_activation_receipt_sha256",
        "child_launch_intent_record_sha256",
        "effect_origin_state",
        "effect_origin_record_sha256",
        "scope_started_receipt_sha256",
        "clearance_intent_receipt_sha256",
        "outer_clearance_intent_record_sha256",
        "clearance_mode",
        "start_supervisor_epoch_id",
        "clearance_supervisor_epoch_id",
        "start_host_boot_id_sha256",
        "clearance_host_boot_id_sha256",
        "clearance_basis",
        "completion_disposition",
        "stderr_bytes",
        "stderr_sha256",
        "adoption_eligible",
    }
)
CLEARANCE_BUNDLE_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "activation_receipt",
        "activation_receipt_sha256",
        "scope_started_receipt",
        "scope_started_receipt_sha256",
        "clearance_intent_receipt",
        "clearance_intent_receipt_sha256",
        "scope_empty_receipt",
        "scope_empty_receipt_sha256",
    }
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SESSION_ID_RE = SHA256_RE
TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
ZERO_SHA256 = "0" * 64
SCOPE_ID_RE = re.compile(
    r"^jlq-root_supervisor-([0-9a-f]{64})$"
)
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_IDENTITY = (1 << 31) - 1
MAX_STDERR_BYTES = 128 * 1024
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
FORBIDDEN_FIELD_PARTS = frozenset({"pid", "pgid", "path", "key"})


class LifecycleReceiptError(ValueError):
    """Stable public-safe lifecycle contract rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> LifecycleReceiptError:
    return LifecycleReceiptError(code)


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error("lifecycle_receipt_encoding_invalid") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_forbidden_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise _error("lifecycle_receipt_field_name_invalid")
            parts = frozenset(raw_key.lower().split("_"))
            if parts & FORBIDDEN_FIELD_PARTS:
                raise _error("lifecycle_receipt_forbidden_field")
            _reject_forbidden_fields(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_forbidden_fields(child)


def _strict_mapping(
    value: Any,
    fields: frozenset[str],
    *,
    code: str,
) -> dict[str, Any]:
    _reject_forbidden_fields(value)
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _error(code)
    return {field: value[field] for field in fields}


def _digest(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not SHA256_RE.fullmatch(value)
        or value == ZERO_SHA256
    ):
        raise _error(f"{field}_invalid")
    return value


def _nullable_digest(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _digest(value, field=field)


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int = 0,
    maximum: int = MAX_SAFE_INTEGER,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise _error(f"{field}_invalid")
    return value


def _session_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not SESSION_ID_RE.fullmatch(value)
        or value == ZERO_SHA256
    ):
        raise _error("lifecycle_receipt_capture_session_id_invalid")
    return value


def _scope_id(value: Any, *, session_id: str) -> str:
    if (
        not isinstance(value, str)
        or not SCOPE_ID_RE.fullmatch(value)
        or value != f"jlq-{LIFECYCLE_BACKEND}-{session_id}"
    ):
        raise _error("lifecycle_receipt_scope_id_invalid")
    return value


def _token(
    value: Any,
    *,
    field: str,
    permitted: frozenset[str],
) -> str:
    if (
        not isinstance(value, str)
        or not TOKEN_RE.fullmatch(value)
        or value not in permitted
    ):
        raise _error(f"{field}_invalid")
    return value


def _exact(value: Any, expected: str, *, field: str) -> str:
    if value != expected:
        raise _error(f"{field}_invalid")
    return expected


def _nullable_epoch(value: Any, *, field: str) -> str | None:
    return _nullable_digest(value, field=field)


def _provider(value: Any) -> str:
    permitted = frozenset(
        provider
        for providers in PROVIDERS_BY_SYSTEM.values()
        for provider in providers
    )
    return _token(
        value,
        field="lifecycle_receipt_provider",
        permitted=permitted,
    )


def _common_scope(
    selected: Mapping[str, Any],
) -> tuple[str, str, str, str]:
    session_id = _session_id(selected["capture_session_id"])
    backend = _exact(
        selected["lifecycle_backend"],
        LIFECYCLE_BACKEND,
        field="lifecycle_receipt_backend",
    )
    provider = _provider(selected["lifecycle_provider"])
    scope_id = _scope_id(
        selected["lifecycle_scope_id"],
        session_id=session_id,
    )
    return session_id, backend, provider, scope_id


def normalize_activation_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize the path-free privileged lifecycle canary receipt."""

    selected = _strict_mapping(
        value,
        ACTIVATION_RECEIPT_FIELDS,
        code="lifecycle_activation_receipt_fields_invalid",
    )
    system = selected["system"]
    if system not in SYSTEMS:
        raise _error("lifecycle_activation_system_invalid")
    provider = _provider(selected["lifecycle_provider"])
    if provider not in PROVIDERS_BY_SYSTEM[system]:
        raise _error("lifecycle_activation_provider_system_mismatch")
    expected_boot_measurement = BOOT_MEASUREMENT_BY_SYSTEM[system]
    if selected["host_boot_measurement"] != expected_boot_measurement:
        raise _error(
            "lifecycle_activation_boot_measurement_mismatch"
        )
    assertions = _strict_mapping(
        selected["assertions"],
        ACTIVATION_ASSERTIONS,
        code="lifecycle_activation_assertions_invalid",
    )
    if any(assertions[name] is not True for name in ACTIVATION_ASSERTIONS):
        raise _error("lifecycle_activation_assertion_not_proven")
    if selected["production_activation"] is not False:
        raise _error("lifecycle_activation_must_remain_disabled")
    return {
        "schema_version": _exact(
            selected["schema_version"],
            ACTIVATION_RECEIPT_SCHEMA,
            field="lifecycle_activation_schema",
        ),
        "status": _exact(
            selected["status"],
            ACTIVATION_STATUS,
            field="lifecycle_activation_status",
        ),
        "system": system,
        "lifecycle_backend": _exact(
            selected["lifecycle_backend"],
            LIFECYCLE_BACKEND,
            field="lifecycle_activation_backend",
        ),
        "lifecycle_provider": provider,
        "supervisor_policy_sha256": _digest(
            selected["supervisor_policy_sha256"],
            field="lifecycle_activation_supervisor_policy_sha256",
        ),
        "supervisor_bundle_sha256": _digest(
            selected["supervisor_bundle_sha256"],
            field="lifecycle_activation_supervisor_bundle_sha256",
        ),
        "helper_activation_policy_sha256": _digest(
            selected["helper_activation_policy_sha256"],
            field="lifecycle_activation_helper_policy_sha256",
        ),
        "lifecycle_canary_sha256": _digest(
            selected["lifecycle_canary_sha256"],
            field="lifecycle_activation_canary_sha256",
        ),
        "host_boot_measurement": expected_boot_measurement,
        "host_boot_id_sha256": _digest(
            selected["host_boot_id_sha256"],
            field="lifecycle_activation_host_boot_id_sha256",
        ),
        "assertions": {
            name: True for name in sorted(ACTIVATION_ASSERTIONS)
        },
        "production_activation": False,
    }


def activation_receipt_sha256(value: Mapping[str, Any]) -> str:
    return _sha256(_canonical_json(normalize_activation_receipt(value)))


def normalize_scope_started_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize a supervisor-minted, contained-before-exec start receipt."""

    selected = _strict_mapping(
        value,
        SCOPE_STARTED_RECEIPT_FIELDS,
        code="lifecycle_scope_started_receipt_fields_invalid",
    )
    session_id, backend, provider, scope_id = _common_scope(selected)
    return {
        "schema_version": _exact(
            selected["schema_version"],
            SCOPE_STARTED_RECEIPT_SCHEMA,
            field="lifecycle_scope_started_schema",
        ),
        "status": _exact(
            selected["status"],
            SCOPE_STARTED_STATUS,
            field="lifecycle_scope_started_status",
        ),
        "capture_session_id": session_id,
        "lifecycle_backend": backend,
        "lifecycle_provider": provider,
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": _digest(
            selected["scope_incarnation_id"],
            field="lifecycle_scope_incarnation_id",
        ),
        "supervisor_epoch_id": _digest(
            selected["supervisor_epoch_id"],
            field="lifecycle_supervisor_epoch_id",
        ),
        "host_boot_id_sha256": _digest(
            selected["host_boot_id_sha256"],
            field="lifecycle_host_boot_id_sha256",
        ),
        "staging_transaction_intent_sha256": _digest(
            selected["staging_transaction_intent_sha256"],
            field="lifecycle_staging_transaction_intent_sha256",
        ),
        "staging_exposure_receipt_sha256": _digest(
            selected["staging_exposure_receipt_sha256"],
            field="lifecycle_staging_exposure_receipt_sha256",
        ),
        "child_launch_intent_record_sha256": _digest(
            selected["child_launch_intent_record_sha256"],
            field="lifecycle_child_launch_intent_record_sha256",
        ),
        "handoff_policy_sha256": _digest(
            selected["handoff_policy_sha256"],
            field="lifecycle_handoff_policy_sha256",
        ),
        "helper_activation_policy_sha256": _digest(
            selected["helper_activation_policy_sha256"],
            field="lifecycle_helper_activation_policy_sha256",
        ),
        "capture_uid": _integer(
            selected["capture_uid"],
            field="lifecycle_capture_uid",
            minimum=1,
            maximum=MAX_IDENTITY,
        ),
        "export_gid": _integer(
            selected["export_gid"],
            field="lifecycle_export_gid",
            minimum=1,
            maximum=MAX_IDENTITY,
        ),
        "lifecycle_activation_receipt_sha256": _digest(
            selected["lifecycle_activation_receipt_sha256"],
            field="lifecycle_activation_receipt_sha256",
        ),
    }


def scope_started_receipt_sha256(value: Mapping[str, Any]) -> str:
    return _sha256(
        _canonical_json(normalize_scope_started_receipt(value))
    )


def normalize_clearance_intent_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize the durable outer intent that precedes scope clearing."""

    selected = _strict_mapping(
        value,
        CLEARANCE_INTENT_RECEIPT_FIELDS,
        code="lifecycle_clearance_intent_receipt_fields_invalid",
    )
    session_id, backend, provider, scope_id = _common_scope(selected)
    origin = _token(
        selected["effect_origin_state"],
        field="lifecycle_effect_origin_state",
        permitted=EFFECT_ORIGIN_STATES,
    )
    start_digest = _nullable_digest(
        selected["scope_started_receipt_sha256"],
        field="lifecycle_scope_started_receipt_sha256",
    )
    if origin == "child_launch_intent" and start_digest is not None:
        raise _error(
            "lifecycle_clearance_recovered_start_must_be_deferred"
        )
    if origin != "child_launch_intent" and start_digest is None:
        raise _error("lifecycle_clearance_intent_start_missing")
    mode = _token(
        selected["clearance_mode"],
        field="lifecycle_clearance_mode",
        permitted=CLEARANCE_MODES,
    )
    if (
        origin in {"child_launch_intent", "child_running"}
        and mode != "terminate_and_clear"
    ):
        raise _error("lifecycle_clearance_mode_origin_mismatch")
    launch_digest = _digest(
        selected["child_launch_intent_record_sha256"],
        field="lifecycle_child_launch_intent_record_sha256",
    )
    origin_digest = _digest(
        selected["effect_origin_record_sha256"],
        field="lifecycle_effect_origin_record_sha256",
    )
    if (
        origin == "child_launch_intent"
        and not hmac.compare_digest(origin_digest, launch_digest)
    ):
        raise _error("lifecycle_clearance_origin_record_mismatch")
    return {
        "schema_version": _exact(
            selected["schema_version"],
            CLEARANCE_INTENT_RECEIPT_SCHEMA,
            field="lifecycle_clearance_intent_schema",
        ),
        "status": _exact(
            selected["status"],
            CLEARANCE_INTENT_STATUS,
            field="lifecycle_clearance_intent_status",
        ),
        "capture_session_id": session_id,
        "lifecycle_backend": backend,
        "lifecycle_provider": provider,
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": _digest(
            selected["scope_incarnation_id"],
            field="lifecycle_scope_incarnation_id",
        ),
        "lifecycle_activation_receipt_sha256": _digest(
            selected["lifecycle_activation_receipt_sha256"],
            field="lifecycle_activation_receipt_sha256",
        ),
        "child_launch_intent_record_sha256": launch_digest,
        "effect_origin_state": origin,
        "effect_origin_record_sha256": origin_digest,
        "scope_started_receipt_sha256": start_digest,
        "clearance_mode": mode,
        "outer_clearance_intent_record_sha256": _digest(
            selected["outer_clearance_intent_record_sha256"],
            field=(
                "lifecycle_outer_clearance_intent_record_sha256"
            ),
        ),
    }


def clearance_intent_receipt_sha256(value: Mapping[str, Any]) -> str:
    return _sha256(
        _canonical_json(normalize_clearance_intent_receipt(value))
    )


def normalize_scope_empty_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize a provider-observed execution-scope clearance receipt."""

    selected = _strict_mapping(
        value,
        SCOPE_EMPTY_RECEIPT_FIELDS,
        code="lifecycle_scope_empty_receipt_fields_invalid",
    )
    session_id, backend, provider, scope_id = _common_scope(selected)
    origin = _token(
        selected["effect_origin_state"],
        field="lifecycle_effect_origin_state",
        permitted=EFFECT_ORIGIN_STATES,
    )
    clearance_mode = _token(
        selected["clearance_mode"],
        field="lifecycle_clearance_mode",
        permitted=CLEARANCE_MODES,
    )
    if (
        origin in {"child_launch_intent", "child_running"}
        and clearance_mode != "terminate_and_clear"
    ):
        raise _error("lifecycle_clearance_mode_origin_mismatch")
    launch_digest = _digest(
        selected["child_launch_intent_record_sha256"],
        field="lifecycle_child_launch_intent_record_sha256",
    )
    origin_digest = _digest(
        selected["effect_origin_record_sha256"],
        field="lifecycle_effect_origin_record_sha256",
    )
    if (
        origin == "child_launch_intent"
        and not hmac.compare_digest(origin_digest, launch_digest)
    ):
        raise _error("lifecycle_scope_empty_origin_record_mismatch")
    start_digest = _nullable_digest(
        selected["scope_started_receipt_sha256"],
        field="lifecycle_scope_started_receipt_sha256",
    )
    start_epoch = _nullable_epoch(
        selected["start_supervisor_epoch_id"],
        field="lifecycle_start_supervisor_epoch_id",
    )
    start_boot = _nullable_digest(
        selected["start_host_boot_id_sha256"],
        field="lifecycle_start_host_boot_id_sha256",
    )
    clearance_epoch = _digest(
        selected["clearance_supervisor_epoch_id"],
        field="lifecycle_clearance_supervisor_epoch_id",
    )
    clearance_boot = _digest(
        selected["clearance_host_boot_id_sha256"],
        field="lifecycle_clearance_host_boot_id_sha256",
    )
    basis = _token(
        selected["clearance_basis"],
        field="lifecycle_clearance_basis",
        permitted=CLEARANCE_BASES,
    )
    disposition = _token(
        selected["completion_disposition"],
        field="lifecycle_completion_disposition",
        permitted=COMPLETION_DISPOSITIONS,
    )
    stderr_bytes_value = selected["stderr_bytes"]
    stderr_digest_value = selected["stderr_sha256"]
    if disposition in {
        "clean_exit",
        "abnormal_exit",
        "forced_termination",
    }:
        stderr_bytes = _integer(
            stderr_bytes_value,
            field="lifecycle_stderr_bytes",
            maximum=MAX_STDERR_BYTES,
        )
        stderr_digest = _digest(
            stderr_digest_value,
            field="lifecycle_stderr_sha256",
        )
    else:
        if stderr_bytes_value is not None or stderr_digest_value is not None:
            raise _error("lifecycle_stderr_not_applicable_invalid")
        stderr_bytes = None
        stderr_digest = None

    normal_basis = NORMAL_CLEARANCE_BASIS_BY_PROVIDER[provider]
    if disposition in {
        "never_started",
        "never_started_after_reboot",
    }:
        expected_basis = (
            NO_EFFECT_CLEARANCE_BASIS
            if disposition == "never_started"
            else REBOOT_CLEARANCE_BASIS
        )
        if (
            basis != expected_basis
            or origin != "child_launch_intent"
            or start_digest is not None
            or start_epoch is not None
            or start_boot is not None
        ):
            raise _error("lifecycle_never_started_structure_invalid")
    elif disposition == "host_reboot":
        if (
            basis != REBOOT_CLEARANCE_BASIS
            or start_digest is None
            or start_epoch is None
            or start_boot is None
            or hmac.compare_digest(start_boot, clearance_boot)
            or hmac.compare_digest(start_epoch, clearance_epoch)
        ):
            raise _error("lifecycle_reboot_structure_invalid")
    else:
        if (
            basis != normal_basis
            or start_digest is None
            or start_epoch is None
            or start_boot is None
            or not hmac.compare_digest(start_boot, clearance_boot)
        ):
            raise _error("lifecycle_normal_clearance_structure_invalid")
        if (
            provider == "direct_waitid_deny_fork"
            and not hmac.compare_digest(start_epoch, clearance_epoch)
        ):
            raise _error("lifecycle_direct_wait_epoch_changed")
        if (
            disposition in {"clean_exit", "abnormal_exit"}
            and not hmac.compare_digest(start_epoch, clearance_epoch)
        ):
            raise _error("lifecycle_exit_observer_epoch_changed")
        if disposition == "exit_unobserved_after_restart" and (
            provider == "direct_waitid_deny_fork"
            or hmac.compare_digest(start_epoch, clearance_epoch)
        ):
            raise _error(
                "lifecycle_unobserved_exit_structure_invalid"
            )

    if disposition == "clean_exit" and (
        stderr_bytes != 0
        or not hmac.compare_digest(
            stderr_digest or "", EMPTY_SHA256
        )
    ):
        raise _error("lifecycle_clean_exit_stderr_not_empty")
    if disposition in {"abnormal_exit", "forced_termination"} and (
        (stderr_bytes == 0 and stderr_digest != EMPTY_SHA256)
        or (stderr_bytes > 0 and stderr_digest == EMPTY_SHA256)
    ):
        raise _error("lifecycle_stderr_length_digest_incoherent")
    expected_adoption_eligible = (
        disposition == "clean_exit"
        and origin == "capture_ready"
        and clearance_mode
        == "wait_clean_then_terminate_on_deadline"
        and stderr_bytes == 0
        and stderr_digest == EMPTY_SHA256
    )
    if selected["adoption_eligible"] is not expected_adoption_eligible:
        raise _error("lifecycle_adoption_eligibility_invalid")

    return {
        "schema_version": _exact(
            selected["schema_version"],
            SCOPE_EMPTY_RECEIPT_SCHEMA,
            field="lifecycle_scope_empty_schema",
        ),
        "status": _exact(
            selected["status"],
            SCOPE_EMPTY_STATUS,
            field="lifecycle_scope_empty_status",
        ),
        "capture_session_id": session_id,
        "lifecycle_backend": backend,
        "lifecycle_provider": provider,
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": _digest(
            selected["scope_incarnation_id"],
            field="lifecycle_scope_incarnation_id",
        ),
        "lifecycle_activation_receipt_sha256": _digest(
            selected["lifecycle_activation_receipt_sha256"],
            field="lifecycle_activation_receipt_sha256",
        ),
        "child_launch_intent_record_sha256": launch_digest,
        "effect_origin_state": origin,
        "effect_origin_record_sha256": origin_digest,
        "scope_started_receipt_sha256": start_digest,
        "clearance_intent_receipt_sha256": _digest(
            selected["clearance_intent_receipt_sha256"],
            field="lifecycle_clearance_intent_receipt_sha256",
        ),
        "outer_clearance_intent_record_sha256": _digest(
            selected["outer_clearance_intent_record_sha256"],
            field=(
                "lifecycle_outer_clearance_intent_record_sha256"
            ),
        ),
        "clearance_mode": clearance_mode,
        "start_supervisor_epoch_id": start_epoch,
        "clearance_supervisor_epoch_id": clearance_epoch,
        "start_host_boot_id_sha256": start_boot,
        "clearance_host_boot_id_sha256": clearance_boot,
        "clearance_basis": basis,
        "completion_disposition": disposition,
        "stderr_bytes": stderr_bytes,
        "stderr_sha256": stderr_digest,
        "adoption_eligible": expected_adoption_eligible,
    }


def scope_empty_receipt_sha256(value: Mapping[str, Any]) -> str:
    return _sha256(_canonical_json(normalize_scope_empty_receipt(value)))


def normalize_clearance_bundle(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize and cross-bind one complete supervisor clearance bundle."""

    selected = _strict_mapping(
        value,
        CLEARANCE_BUNDLE_FIELDS,
        code="lifecycle_clearance_bundle_fields_invalid",
    )
    activation = normalize_activation_receipt(
        selected["activation_receipt"]
    )
    activation_digest = activation_receipt_sha256(activation)
    if not hmac.compare_digest(
        _digest(
            selected["activation_receipt_sha256"],
            field="lifecycle_bundle_activation_receipt_sha256",
        ),
        activation_digest,
    ):
        raise _error("lifecycle_bundle_activation_digest_mismatch")

    raw_started = selected["scope_started_receipt"]
    raw_started_digest = selected["scope_started_receipt_sha256"]
    if raw_started is None:
        if raw_started_digest is not None:
            raise _error("lifecycle_bundle_start_pair_invalid")
        started = None
        started_digest = None
    else:
        started = normalize_scope_started_receipt(raw_started)
        started_digest = scope_started_receipt_sha256(started)
        if not hmac.compare_digest(
            _digest(
                raw_started_digest,
                field="lifecycle_bundle_start_receipt_sha256",
            ),
            started_digest,
        ):
            raise _error("lifecycle_bundle_start_digest_mismatch")

    intent = normalize_clearance_intent_receipt(
        selected["clearance_intent_receipt"]
    )
    intent_digest = clearance_intent_receipt_sha256(intent)
    if not hmac.compare_digest(
        _digest(
            selected["clearance_intent_receipt_sha256"],
            field="lifecycle_bundle_intent_receipt_sha256",
        ),
        intent_digest,
    ):
        raise _error("lifecycle_bundle_intent_digest_mismatch")

    empty = normalize_scope_empty_receipt(
        selected["scope_empty_receipt"]
    )
    empty_digest = scope_empty_receipt_sha256(empty)
    if not hmac.compare_digest(
        _digest(
            selected["scope_empty_receipt_sha256"],
            field="lifecycle_bundle_empty_receipt_sha256",
        ),
        empty_digest,
    ):
        raise _error("lifecycle_bundle_empty_digest_mismatch")

    activation_ref = activation_digest
    if (
        intent["lifecycle_activation_receipt_sha256"]
        != activation_ref
        or empty["lifecycle_activation_receipt_sha256"]
        != activation_ref
        or (
            started is not None
            and started["lifecycle_activation_receipt_sha256"]
            != activation_ref
        )
    ):
        raise _error("lifecycle_bundle_activation_binding_changed")

    stable_fields = (
        "capture_session_id",
        "lifecycle_backend",
        "lifecycle_provider",
        "lifecycle_scope_id",
        "scope_incarnation_id",
        "child_launch_intent_record_sha256",
    )
    reference = intent
    for receipt in (empty, *((started,) if started is not None else ())):
        if any(receipt[field] != reference[field] for field in stable_fields):
            raise _error("lifecycle_bundle_scope_binding_changed")
    if (
        activation["lifecycle_backend"]
        != intent["lifecycle_backend"]
        or activation["lifecycle_provider"]
        != intent["lifecycle_provider"]
    ):
        raise _error("lifecycle_bundle_provider_binding_changed")

    if (
        empty["effect_origin_state"] != intent["effect_origin_state"]
        or empty["effect_origin_record_sha256"]
        != intent["effect_origin_record_sha256"]
        or empty["clearance_mode"] != intent["clearance_mode"]
        or empty["outer_clearance_intent_record_sha256"]
        != intent["outer_clearance_intent_record_sha256"]
        or empty["clearance_intent_receipt_sha256"]
        != intent_digest
    ):
        raise _error("lifecycle_bundle_clearance_binding_changed")

    intent_start_digest = intent["scope_started_receipt_sha256"]
    if empty["scope_started_receipt_sha256"] != started_digest:
        raise _error("lifecycle_bundle_start_binding_changed")
    if started is None:
        if intent_start_digest is not None:
            raise _error("lifecycle_bundle_start_binding_changed")
        if empty["completion_disposition"] not in {
            "never_started",
            "never_started_after_reboot",
        }:
            raise _error("lifecycle_bundle_start_receipt_missing")
        activation_boot = activation["host_boot_id_sha256"]
        clearance_boot = empty["clearance_host_boot_id_sha256"]
        if (
            empty["completion_disposition"] == "never_started"
            and activation_boot != clearance_boot
        ) or (
            empty["completion_disposition"]
            == "never_started_after_reboot"
            and activation_boot == clearance_boot
        ):
            raise _error(
                "lifecycle_bundle_activation_boot_binding_changed"
            )
    else:
        if (
            intent_start_digest != started_digest
            and not (
                intent["effect_origin_state"]
                == "child_launch_intent"
                and intent_start_digest is None
            )
        ):
            raise _error("lifecycle_bundle_start_binding_changed")
        if empty["completion_disposition"] == "never_started":
            raise _error("lifecycle_bundle_start_receipt_unexpected")
        if (
            empty["start_supervisor_epoch_id"]
            != started["supervisor_epoch_id"]
            or empty["start_host_boot_id_sha256"]
            != started["host_boot_id_sha256"]
        ):
            raise _error("lifecycle_bundle_start_observation_changed")
        if (
            activation["host_boot_id_sha256"]
            != started["host_boot_id_sha256"]
        ):
            raise _error(
                "lifecycle_bundle_activation_boot_binding_changed"
            )
        if (
            started["helper_activation_policy_sha256"]
            != activation["helper_activation_policy_sha256"]
        ):
            raise _error("lifecycle_bundle_helper_policy_changed")

    return {
        "schema_version": _exact(
            selected["schema_version"],
            CLEARANCE_BUNDLE_SCHEMA,
            field="lifecycle_clearance_bundle_schema",
        ),
        "status": _exact(
            selected["status"],
            CLEARANCE_BUNDLE_STATUS,
            field="lifecycle_clearance_bundle_status",
        ),
        "activation_receipt": activation,
        "activation_receipt_sha256": activation_digest,
        "scope_started_receipt": started,
        "scope_started_receipt_sha256": started_digest,
        "clearance_intent_receipt": intent,
        "clearance_intent_receipt_sha256": intent_digest,
        "scope_empty_receipt": empty,
        "scope_empty_receipt_sha256": empty_digest,
    }


def clearance_bundle_sha256(value: Mapping[str, Any]) -> str:
    return _sha256(_canonical_json(normalize_clearance_bundle(value)))


_SCOPE_CLEARANCE_PROOF_TOKEN = object()


class ScopeClearanceProof:
    """One-shot, nonserializable capability backed by a validated bundle."""

    __slots__ = (
        "__session_id",
        "__scope_empty_receipt_sha256",
        "__completion_disposition",
        "__adoption_eligible",
        "__consumed",
    )

    def __init__(
        self,
        *,
        _token: object,
        bundle: Mapping[str, Any],
    ) -> None:
        if _token is not _SCOPE_CLEARANCE_PROOF_TOKEN:
            raise TypeError("ScopeClearanceProof cannot be constructed directly")
        normalized = normalize_clearance_bundle(bundle)
        empty = normalized["scope_empty_receipt"]
        self.__session_id = empty["capture_session_id"]
        self.__scope_empty_receipt_sha256 = normalized[
            "scope_empty_receipt_sha256"
        ]
        self.__completion_disposition = empty[
            "completion_disposition"
        ]
        self.__adoption_eligible = empty["adoption_eligible"]
        self.__consumed = False

    @property
    def active(self) -> bool:
        return not self.__consumed

    @property
    def capture_session_id(self) -> str:
        return self.__session_id

    @property
    def scope_empty_receipt_sha256(self) -> str:
        return self.__scope_empty_receipt_sha256

    @property
    def completion_disposition(self) -> str:
        return self.__completion_disposition

    @property
    def adoption_eligible(self) -> bool:
        return self.__adoption_eligible

    def consume(
        self,
        *,
        capture_session_id: str,
        purpose: str,
    ) -> tuple[str, str]:
        """Consume once and return the exact session/clearance binding."""

        if self.__consumed:
            raise _error("lifecycle_scope_clearance_proof_consumed")
        session_id = _session_id(capture_session_id)
        selected_purpose = _token(
            purpose,
            field="lifecycle_scope_clearance_proof_purpose",
            permitted=PROOF_PURPOSES,
        )
        if session_id != self.__session_id:
            raise _error("lifecycle_scope_clearance_proof_session_mismatch")
        if (
            selected_purpose == "capture_adoption"
            and not self.__adoption_eligible
        ):
            raise _error(
                "lifecycle_scope_clearance_proof_adoption_forbidden"
            )
        self.__consumed = True
        return self.__session_id, self.__scope_empty_receipt_sha256

    def __copy__(self) -> Any:
        raise TypeError("ScopeClearanceProof is not copyable")

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError("ScopeClearanceProof is not copyable")

    def __reduce__(self) -> Any:
        raise TypeError("ScopeClearanceProof is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("ScopeClearanceProof is not serializable")


def _mint_scope_clearance_proof(
    bundle: Mapping[str, Any],
) -> ScopeClearanceProof:
    return ScopeClearanceProof(
        _token=_SCOPE_CLEARANCE_PROOF_TOKEN,
        bundle=bundle,
    )


def mint_scope_clearance_proof(
    bundle: Mapping[str, Any],
) -> ScopeClearanceProof:
    """Production mint gate; intentionally disabled."""

    if not PRODUCTION_ACTIVATION:
        raise _error("lifecycle_scope_clearance_production_disabled")
    return _mint_scope_clearance_proof(bundle)


def _mint_scope_clearance_proof_for_test(
    bundle: Mapping[str, Any],
) -> ScopeClearanceProof:
    """Mechanical test seam; never an activation or runtime authority."""

    return _mint_scope_clearance_proof(bundle)


__all__ = [
    "ACTIVATION_ASSERTIONS",
    "ACTIVATION_RECEIPT_SCHEMA",
    "ACTIVATION_STATUS",
    "CLEARANCE_BUNDLE_SCHEMA",
    "CLEARANCE_BUNDLE_STATUS",
    "CLEARANCE_INTENT_RECEIPT_SCHEMA",
    "CLEARANCE_INTENT_STATUS",
    "EMPTY_SHA256",
    "LIFECYCLE_BACKEND",
    "LifecycleReceiptError",
    "PRODUCTION_ACTIVATION",
    "SCOPE_EMPTY_RECEIPT_SCHEMA",
    "SCOPE_EMPTY_STATUS",
    "SCOPE_STARTED_RECEIPT_SCHEMA",
    "SCOPE_STARTED_STATUS",
    "ScopeClearanceProof",
    "ZERO_SHA256",
    "activation_receipt_sha256",
    "clearance_bundle_sha256",
    "clearance_intent_receipt_sha256",
    "mint_scope_clearance_proof",
    "normalize_activation_receipt",
    "normalize_clearance_bundle",
    "normalize_clearance_intent_receipt",
    "normalize_scope_empty_receipt",
    "normalize_scope_started_receipt",
    "scope_empty_receipt_sha256",
    "scope_started_receipt_sha256",
]
