"""Pure evidence contract for crash-time capture-adoption reconciliation.

The module owns no filesystem descriptor, lock, path, process, signer, or
publication authority.  It validates the path-free receipt produced only
after a future root reconciler has inspected both the staging and final
parents under one bound lock epoch.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any


PRODUCTION_ACTIVATION = False

ADOPTION_RECONCILIATION_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-adoption-reconciliation.v1"
)
ADOPTION_RECONCILIATION_STATUS = "dual_parent_reconciled"

RECONCILIATION_RESULTS = frozenset(
    {
        "recovered_adoption",
        "staging_absent",
        "staging_quarantined",
        "operator_attention",
    }
)
FINAL_OBSERVATIONS = frozenset(
    {"exact_present", "absent", "identity_mismatch", "unreadable"}
)
STAGING_OBSERVATIONS = frozenset(
    {
        "absent",
        "exact_quarantine",
        "identity_mismatch",
        "unreadable",
    }
)
STAGING_TERMINAL_DISPOSITIONS = frozenset(
    {"absent", "quarantined"}
)

ADOPTION_RECONCILIATION_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "result",
        "capture_session_id",
        "adoption_intent_record_sha256",
        "adoption_policy_sha256",
        "lifecycle_scope_empty_receipt_sha256",
        "staging_transaction_intent_sha256",
        "staging_terminal_receipt_sha256",
        "staging_tombstone_sha256",
        "staging_terminal_disposition",
        "staging_leaf_identity_sha256",
        "staging_inspection_lock_epoch_sha256",
        "shared_root_identity_sha256",
        "recovery_namespace_identity_sha256",
        "quarantine_namespace_identity_sha256",
        "transactions_namespace_identity_sha256",
        "final_parent_identity_sha256",
        "final_parent_filesystem_device",
        "dual_parent_lock_epoch_sha256",
        "final_name",
        "expected_object_identity_sha256",
        "expected_verifier_gid",
        "adoption_limits",
        "final_observation",
        "final_object_identity_sha256",
        "final_object_stat_sha256",
        "final_content_inventory_sha256",
        "final_file_count",
        "final_directory_count",
        "final_total_bytes",
        "final_largest_file_bytes",
        "final_maximum_depth",
        "final_object_owner_uid",
        "final_object_group_gid",
        "final_object_mode",
        "final_object_nlink",
        "staging_observation",
        "staging_observed_leaf_identity_sha256",
        "staging_terminal_quarantine_name",
        "staging_terminal_quarantine_reason_code",
        "staging_terminal_quarantined_stat_sha256",
        "staging_observed_quarantined_stat_sha256",
        "final_parent_fsynced",
        "staging_parents_fsynced",
        "observations_rechecked_under_lock",
    }
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FINAL_NAME_RE = re.compile(r"^opaque-capture-[0-9a-f]{32}$")
TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
ZERO_SHA256 = "0" * 64
MAX_IDENTITY = (1 << 31) - 1
ADOPTED_DIRECTORY_MODE = 0o550
MAX_CAPTURE_FILES = 4_096
MAX_CAPTURE_DIRECTORIES = 4_096
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_CAPTURE_FILE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_DEPTH = 64
ADOPTION_LIMIT_FIELDS = frozenset(
    {
        "max_files",
        "max_directories",
        "max_bytes",
        "max_file_bytes",
        "max_depth",
    }
)


class AdoptionReconciliationError(ValueError):
    """Stable public-safe rejection from the pure receipt boundary."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> AdoptionReconciliationError:
    return AdoptionReconciliationError(code)


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error("adoption_reconciliation_json_invalid") from exc


def _strict_mapping(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != ADOPTION_RECONCILIATION_RECEIPT_FIELDS
    ):
        raise _error("adoption_reconciliation_receipt_fields_invalid")
    return {
        field: value[field]
        for field in ADOPTION_RECONCILIATION_RECEIPT_FIELDS
    }


def _digest(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not SHA256_RE.fullmatch(value)
        or value == ZERO_SHA256
    ):
        raise _error(f"adoption_reconciliation_{field}_invalid")
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
    maximum: int = MAX_IDENTITY,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise _error(f"adoption_reconciliation_{field}_invalid")
    return value


def _nullable_integer(
    value: Any,
    *,
    field: str,
    minimum: int = 0,
    maximum: int = MAX_IDENTITY,
) -> int | None:
    if value is None:
        return None
    return _integer(
        value,
        field=field,
        minimum=minimum,
        maximum=maximum,
    )


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
        raise _error(f"adoption_reconciliation_{field}_invalid")
    return value


def _nullable_reason(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise _error(f"adoption_reconciliation_{field}_invalid")
    return value


def _adoption_limits(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != ADOPTION_LIMIT_FIELDS:
        raise _error("adoption_reconciliation_adoption_limits_invalid")
    limits = {
        "max_files": _integer(
            value["max_files"],
            field="adoption_limits_max_files",
            minimum=1,
            maximum=MAX_CAPTURE_FILES,
        ),
        "max_directories": _integer(
            value["max_directories"],
            field="adoption_limits_max_directories",
            minimum=1,
            maximum=MAX_CAPTURE_DIRECTORIES,
        ),
        "max_bytes": _integer(
            value["max_bytes"],
            field="adoption_limits_max_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_BYTES,
        ),
        "max_file_bytes": _integer(
            value["max_file_bytes"],
            field="adoption_limits_max_file_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_FILE_BYTES,
        ),
        "max_depth": _integer(
            value["max_depth"],
            field="adoption_limits_max_depth",
            minimum=1,
            maximum=MAX_CAPTURE_DEPTH,
        ),
    }
    if limits["max_file_bytes"] > limits["max_bytes"]:
        raise _error(
            "adoption_reconciliation_adoption_file_limit_exceeds_total"
        )
    return limits


def _expected_result(
    *,
    final_observation: str,
    staging_observation: str,
    staging_terminal_disposition: str,
) -> str:
    if (
        final_observation == "exact_present"
        and staging_observation == "absent"
        and staging_terminal_disposition == "absent"
    ):
        return "recovered_adoption"
    if (
        final_observation == "absent"
        and staging_observation == "absent"
        and staging_terminal_disposition == "absent"
    ):
        return "staging_absent"
    if (
        final_observation == "absent"
        and staging_observation == "exact_quarantine"
        and staging_terminal_disposition == "quarantined"
    ):
        return "staging_quarantined"
    return "operator_attention"


def normalize_adoption_reconciliation_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize one exact dual-parent reconciliation observation."""

    selected = _strict_mapping(value)
    if (
        selected["schema_version"]
        != ADOPTION_RECONCILIATION_RECEIPT_SCHEMA
    ):
        raise _error("adoption_reconciliation_schema_invalid")
    if selected["status"] != ADOPTION_RECONCILIATION_STATUS:
        raise _error("adoption_reconciliation_status_invalid")

    session_id = _digest(
        selected["capture_session_id"],
        field="capture_session_id",
    )
    final_name = selected["final_name"]
    if (
        not isinstance(final_name, str)
        or not FINAL_NAME_RE.fullmatch(final_name)
    ):
        raise _error("adoption_reconciliation_final_name_invalid")

    final_observation = _token(
        selected["final_observation"],
        field="final_observation",
        permitted=FINAL_OBSERVATIONS,
    )
    staging_observation = _token(
        selected["staging_observation"],
        field="staging_observation",
        permitted=STAGING_OBSERVATIONS,
    )
    terminal_disposition = _token(
        selected["staging_terminal_disposition"],
        field="staging_terminal_disposition",
        permitted=STAGING_TERMINAL_DISPOSITIONS,
    )
    expected_identity = _digest(
        selected["expected_object_identity_sha256"],
        field="expected_object_identity_sha256",
    )
    expected_verifier_gid = _integer(
        selected["expected_verifier_gid"],
        field="expected_verifier_gid",
        minimum=1,
    )
    adoption_limits = _adoption_limits(selected["adoption_limits"])
    final_parent_filesystem_device = _integer(
        selected["final_parent_filesystem_device"],
        field="final_parent_filesystem_device",
        maximum=(1 << 63) - 1,
    )
    final_identity = _nullable_digest(
        selected["final_object_identity_sha256"],
        field="final_object_identity_sha256",
    )
    final_stat = _nullable_digest(
        selected["final_object_stat_sha256"],
        field="final_object_stat_sha256",
    )
    final_inventory = _nullable_digest(
        selected["final_content_inventory_sha256"],
        field="final_content_inventory_sha256",
    )
    final_file_count = _nullable_integer(
        selected["final_file_count"],
        field="final_file_count",
        maximum=MAX_CAPTURE_FILES,
    )
    final_directory_count = _nullable_integer(
        selected["final_directory_count"],
        field="final_directory_count",
        minimum=1,
        maximum=MAX_CAPTURE_DIRECTORIES,
    )
    final_total_bytes = _nullable_integer(
        selected["final_total_bytes"],
        field="final_total_bytes",
        maximum=MAX_CAPTURE_BYTES,
    )
    final_largest_file_bytes = _nullable_integer(
        selected["final_largest_file_bytes"],
        field="final_largest_file_bytes",
        maximum=MAX_CAPTURE_FILE_BYTES,
    )
    final_maximum_depth = _nullable_integer(
        selected["final_maximum_depth"],
        field="final_maximum_depth",
        maximum=MAX_CAPTURE_DEPTH,
    )
    final_owner = _nullable_integer(
        selected["final_object_owner_uid"],
        field="final_object_owner_uid",
    )
    final_group = _nullable_integer(
        selected["final_object_group_gid"],
        field="final_object_group_gid",
    )
    final_mode = _nullable_integer(
        selected["final_object_mode"],
        field="final_object_mode",
        maximum=0o7777,
    )
    final_nlink = _nullable_integer(
        selected["final_object_nlink"],
        field="final_object_nlink",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    final_stat_metadata = (
        final_identity,
        final_stat,
        final_owner,
        final_group,
        final_mode,
        final_nlink,
    )
    final_inventory_metadata = (
        final_inventory,
        final_file_count,
        final_directory_count,
        final_total_bytes,
        final_largest_file_bytes,
        final_maximum_depth,
    )
    if final_observation == "exact_present":
        if (
            final_identity != expected_identity
            or any(item is None for item in final_stat_metadata)
            or any(item is None for item in final_inventory_metadata)
            or final_owner != 0
            or final_group != expected_verifier_gid
            or final_mode != ADOPTED_DIRECTORY_MODE
        ):
            raise _error(
                "adoption_reconciliation_exact_final_object_invalid"
            )
        assert final_file_count is not None
        assert final_directory_count is not None
        assert final_total_bytes is not None
        assert final_largest_file_bytes is not None
        assert final_maximum_depth is not None
        if (
            final_file_count > adoption_limits["max_files"]
            or final_directory_count
            > adoption_limits["max_directories"]
            or final_total_bytes > adoption_limits["max_bytes"]
            or final_largest_file_bytes
            > adoption_limits["max_file_bytes"]
            or final_largest_file_bytes > final_total_bytes
            or final_maximum_depth > adoption_limits["max_depth"]
            or final_maximum_depth >= final_directory_count
            or (
                final_total_bytes > 0
                and final_largest_file_bytes == 0
            )
            or (
                final_file_count == 0
                and (
                    final_total_bytes != 0
                    or final_largest_file_bytes != 0
                )
            )
        ):
            raise _error(
                "adoption_reconciliation_final_inventory_limits_invalid"
            )
    elif final_observation == "identity_mismatch":
        if (
            final_identity is None
            or final_identity == expected_identity
            or final_stat is None
            or final_owner is None
            or final_group is None
            or final_mode is None
            or final_nlink is None
            or any(
                item is not None for item in final_inventory_metadata
            )
        ):
            raise _error(
                "adoption_reconciliation_final_mismatch_invalid"
            )
    elif any(
        item is not None
        for item in final_stat_metadata + final_inventory_metadata
    ):
        raise _error(
            "adoption_reconciliation_final_metadata_unexpected"
        )

    staging_leaf_identity = _digest(
        selected["staging_leaf_identity_sha256"],
        field="staging_leaf_identity_sha256",
    )
    observed_staging_identity = _nullable_digest(
        selected["staging_observed_leaf_identity_sha256"],
        field="staging_observed_leaf_identity_sha256",
    )
    terminal_quarantine_name = selected[
        "staging_terminal_quarantine_name"
    ]
    terminal_quarantine_reason = _nullable_reason(
        selected["staging_terminal_quarantine_reason_code"],
        field="staging_terminal_quarantine_reason_code",
    )
    terminal_quarantined_stat = _nullable_digest(
        selected["staging_terminal_quarantined_stat_sha256"],
        field="staging_terminal_quarantined_stat_sha256",
    )
    observed_quarantined_stat = _nullable_digest(
        selected["staging_observed_quarantined_stat_sha256"],
        field="staging_observed_quarantined_stat_sha256",
    )
    expected_quarantine_name = f"session-{session_id}"
    if terminal_disposition == "quarantined":
        if (
            terminal_quarantine_name != expected_quarantine_name
            or terminal_quarantine_reason is None
            or terminal_quarantined_stat is None
        ):
            raise _error(
                "adoption_reconciliation_terminal_quarantine_invalid"
            )
    elif (
        terminal_quarantine_name is not None
        or terminal_quarantine_reason is not None
        or terminal_quarantined_stat is not None
    ):
        raise _error(
            "adoption_reconciliation_terminal_quarantine_unexpected"
        )
    if staging_observation == "exact_quarantine":
        if (
            terminal_disposition != "quarantined"
            or observed_staging_identity != staging_leaf_identity
            or observed_quarantined_stat != terminal_quarantined_stat
        ):
            raise _error(
                "adoption_reconciliation_staging_identity_invalid"
            )
    elif staging_observation == "identity_mismatch":
        if (
            observed_staging_identity is None
            or observed_staging_identity == staging_leaf_identity
            or observed_quarantined_stat is None
        ):
            raise _error(
                "adoption_reconciliation_staging_mismatch_invalid"
            )
    elif (
        observed_staging_identity is not None
        or observed_quarantined_stat is not None
    ):
        raise _error(
            "adoption_reconciliation_staging_identity_unexpected"
        )

    result = _token(
        selected["result"],
        field="result",
        permitted=RECONCILIATION_RESULTS,
    )
    expected_result = _expected_result(
        final_observation=final_observation,
        staging_observation=staging_observation,
        staging_terminal_disposition=terminal_disposition,
    )
    if result != expected_result:
        raise _error("adoption_reconciliation_result_mismatch")

    for field in (
        "final_parent_fsynced",
        "staging_parents_fsynced",
        "observations_rechecked_under_lock",
    ):
        if selected[field] is not True:
            raise _error(f"adoption_reconciliation_{field}_invalid")

    normalized = {
        "schema_version": ADOPTION_RECONCILIATION_RECEIPT_SCHEMA,
        "status": ADOPTION_RECONCILIATION_STATUS,
        "result": expected_result,
        "capture_session_id": session_id,
        "final_name": final_name,
        "expected_verifier_gid": expected_verifier_gid,
        "adoption_limits": adoption_limits,
        "final_parent_filesystem_device": (
            final_parent_filesystem_device
        ),
        "staging_terminal_disposition": terminal_disposition,
        "final_observation": final_observation,
        "final_object_identity_sha256": final_identity,
        "final_object_stat_sha256": final_stat,
        "final_content_inventory_sha256": final_inventory,
        "final_file_count": final_file_count,
        "final_directory_count": final_directory_count,
        "final_total_bytes": final_total_bytes,
        "final_largest_file_bytes": final_largest_file_bytes,
        "final_maximum_depth": final_maximum_depth,
        "final_object_owner_uid": final_owner,
        "final_object_group_gid": final_group,
        "final_object_mode": final_mode,
        "final_object_nlink": final_nlink,
        "staging_observation": staging_observation,
        "staging_observed_leaf_identity_sha256": (
            observed_staging_identity
        ),
        "staging_terminal_quarantine_name": (
            terminal_quarantine_name
        ),
        "staging_terminal_quarantine_reason_code": (
            terminal_quarantine_reason
        ),
        "staging_terminal_quarantined_stat_sha256": (
            terminal_quarantined_stat
        ),
        "staging_observed_quarantined_stat_sha256": (
            observed_quarantined_stat
        ),
        "final_parent_fsynced": True,
        "staging_parents_fsynced": True,
        "observations_rechecked_under_lock": True,
    }
    for field in (
        "adoption_intent_record_sha256",
        "adoption_policy_sha256",
        "lifecycle_scope_empty_receipt_sha256",
        "staging_transaction_intent_sha256",
        "staging_terminal_receipt_sha256",
        "staging_tombstone_sha256",
        "staging_leaf_identity_sha256",
        "staging_inspection_lock_epoch_sha256",
        "shared_root_identity_sha256",
        "recovery_namespace_identity_sha256",
        "quarantine_namespace_identity_sha256",
        "transactions_namespace_identity_sha256",
        "final_parent_identity_sha256",
        "dual_parent_lock_epoch_sha256",
        "expected_object_identity_sha256",
    ):
        normalized[field] = _digest(selected[field], field=field)
    return normalized


def adoption_reconciliation_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        _canonical_json(
            normalize_adoption_reconciliation_receipt(value)
        )
    ).hexdigest()


__all__ = [
    "ADOPTION_RECONCILIATION_RECEIPT_FIELDS",
    "ADOPTION_RECONCILIATION_RECEIPT_SCHEMA",
    "ADOPTION_RECONCILIATION_STATUS",
    "ADOPTION_LIMIT_FIELDS",
    "ADOPTED_DIRECTORY_MODE",
    "AdoptionReconciliationError",
    "FINAL_OBSERVATIONS",
    "PRODUCTION_ACTIVATION",
    "RECONCILIATION_RESULTS",
    "STAGING_OBSERVATIONS",
    "STAGING_TERMINAL_DISPOSITIONS",
    "ZERO_SHA256",
    "adoption_reconciliation_receipt_sha256",
    "normalize_adoption_reconciliation_receipt",
]
