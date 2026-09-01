#!/usr/bin/env python3
"""Pure contract for post-verifier live-source revalidation evidence.

The privileged capture coordinator performs the filesystem work.  This
standard-library-only module defines the small, path-free receipt that binds
that work to the adopted capture, the exact verifier output, and the signed
attestation.  It intentionally contains no filesystem, signing, or verifier
launch authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any


SOURCE_REVALIDATION_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-post-verifier-"
    "live-source-revalidation-receipt.v1"
)
SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA = (
    "john-lomein.persona-qualification-post-verifier-"
    "live-source-revalidation-receipt.v2"
)
SOURCE_REVALIDATION_STATUS = "revalidated"
SOURCE_REVALIDATION_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "capture_adoption_receipt_sha256",
        "capture_object_identity_sha256",
        "capture_plan_sha256",
        "capture_manifest_sha256",
        "verifier_output_sha256",
        "revalidator_uid",
        "revalidated_at_unix",
    }
)
SOURCE_REVALIDATION_RECEIPT_V2_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "capture_adoption_provenance",
        "capture_adoption_provenance_sha256",
        "capture_object_identity_sha256",
        "capture_plan_sha256",
        "capture_manifest_sha256",
        "verifier_output_sha256",
        "revalidator_uid",
        "revalidated_at_unix",
    }
)
SOURCE_REVALIDATION_EVIDENCE_FIELDS = frozenset(
    {
        "post_verifier_live_source_revalidation_receipt",
        "post_verifier_live_source_revalidation_receipt_sha256",
    }
)

# Keep this root/helper-facing contract import-isolated.  These are wire
# identifiers, not execution dependencies on the normal-adoption or recovery
# implementations.  Importing their tagged-union module here would pull both
# privileged adoption stacks into the capture-helper runtime role.
_CAPTURE_ADOPTION_PROVENANCE_SCHEMA = (
    "john-lomein.persona-qualification-capture-adoption-provenance.v1"
)
_NORMAL_ADOPTION_KIND = "normal_adoption"
_RECOVERED_ADOPTION_KIND = "recovered_adoption"
_NORMAL_ADOPTION_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-capture-adoption.v2"
)
_RECOVERED_ADOPTION_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-recovered-adoption-evidence.v1"
)
_TRANSACTION_JOURNAL_SCHEMA = (
    "john-lomein.persona-qualification-transaction-journal.v5"
)
_CAPTURE_ADOPTION_PROVENANCE_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "evidence_schema",
        "evidence_sha256",
        "details",
    }
)
_NORMAL_ADOPTION_PROVENANCE_DETAIL_FIELDS = frozenset(
    {"adopted_at_unix"}
)
_RECOVERED_ADOPTION_PROVENANCE_DETAIL_FIELDS = frozenset(
    {
        "transaction_journal_schema",
        "adoption_reconciliation_record_sha256",
        "adoption_reconciliation_receipt_sha256",
    }
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_SAFE_INTEGER = (1 << 53) - 1


class SourceRevalidationBindingError(ValueError):
    """Stable, public-safe receipt or evidence-binding rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> SourceRevalidationBindingError:
    return SourceRevalidationBindingError(code)


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _error("source_revalidation_receipt_json_invalid") from exc


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error("source_revalidation_receipt_not_object")
    if any(not isinstance(key, str) for key in value):
        raise _error("source_revalidation_receipt_fields_invalid")
    return value


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise _error(f"source_revalidation_receipt_{field}_invalid")
    return value


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int = 0,
    maximum: int = MAX_SAFE_INTEGER,
) -> int:
    if (
        type(value) is not int
        or value < minimum
        or value > maximum
    ):
        raise _error(f"source_revalidation_receipt_{field}_invalid")
    return value


def normalize_source_revalidation_receipt(value: Any) -> dict[str, Any]:
    """Return the exact canonical root revalidation receipt."""

    receipt = _mapping(value)
    if set(receipt) != SOURCE_REVALIDATION_RECEIPT_FIELDS:
        raise _error("source_revalidation_receipt_fields_invalid")
    if receipt.get("schema_version") != SOURCE_REVALIDATION_RECEIPT_SCHEMA:
        raise _error("source_revalidation_receipt_schema_unsupported")
    if receipt.get("status") != SOURCE_REVALIDATION_STATUS:
        raise _error("source_revalidation_receipt_status_invalid")
    revalidator_uid = _integer(
        receipt.get("revalidator_uid"),
        field="revalidator_uid",
    )
    if revalidator_uid != 0:
        raise _error("source_revalidation_receipt_revalidator_uid_invalid")
    return {
        "schema_version": SOURCE_REVALIDATION_RECEIPT_SCHEMA,
        "status": SOURCE_REVALIDATION_STATUS,
        "capture_adoption_receipt_sha256": _digest(
            receipt.get("capture_adoption_receipt_sha256"),
            field="capture_adoption_receipt_sha256",
        ),
        "capture_object_identity_sha256": _digest(
            receipt.get("capture_object_identity_sha256"),
            field="capture_object_identity_sha256",
        ),
        "capture_plan_sha256": _digest(
            receipt.get("capture_plan_sha256"),
            field="capture_plan_sha256",
        ),
        "capture_manifest_sha256": _digest(
            receipt.get("capture_manifest_sha256"),
            field="capture_manifest_sha256",
        ),
        "verifier_output_sha256": _digest(
            receipt.get("verifier_output_sha256"),
            field="verifier_output_sha256",
        ),
        "revalidator_uid": 0,
        "revalidated_at_unix": _integer(
            receipt.get("revalidated_at_unix"),
            field="revalidated_at_unix",
            minimum=1,
        ),
    }


def source_revalidation_receipt_sha256(value: Any) -> str:
    """Digest one normalized receipt using the shared canonical encoding."""

    return hashlib.sha256(
        canonical_json(normalize_source_revalidation_receipt(value))
    ).hexdigest()


def bind_source_revalidation_receipt(
    value: Any,
    *,
    expected_receipt_sha256: str,
    expected_capture_adoption_receipt_sha256: str,
    expected_capture_object_identity_sha256: str,
    expected_capture_plan_sha256: str,
    expected_capture_manifest_sha256: str,
    expected_verifier_output_sha256: str,
    verified_at_unix: int,
    expires_at_unix: int,
) -> dict[str, Any]:
    """Bind a root receipt to exact verifier evidence for signing."""

    receipt = normalize_source_revalidation_receipt(value)
    receipt_digest = _digest(
        expected_receipt_sha256,
        field="expected_receipt_sha256",
    )
    if not hmac.compare_digest(
        source_revalidation_receipt_sha256(receipt),
        receipt_digest,
    ):
        raise _error("source_revalidation_receipt_digest_mismatch")
    expected = {
        "capture_adoption_receipt_sha256": _digest(
            expected_capture_adoption_receipt_sha256,
            field="expected_capture_adoption_receipt_sha256",
        ),
        "capture_object_identity_sha256": _digest(
            expected_capture_object_identity_sha256,
            field="expected_capture_object_identity_sha256",
        ),
        "capture_plan_sha256": _digest(
            expected_capture_plan_sha256,
            field="expected_capture_plan_sha256",
        ),
        "capture_manifest_sha256": _digest(
            expected_capture_manifest_sha256,
            field="expected_capture_manifest_sha256",
        ),
        "verifier_output_sha256": _digest(
            expected_verifier_output_sha256,
            field="expected_verifier_output_sha256",
        ),
    }
    for field, expected_value in expected.items():
        if not hmac.compare_digest(receipt[field], expected_value):
            raise _error(
                f"source_revalidation_receipt_{field}_mismatch"
            )
    verified_at = _integer(
        verified_at_unix,
        field="verified_at_unix",
        minimum=1,
    )
    expires_at = _integer(
        expires_at_unix,
        field="expires_at_unix",
        minimum=1,
    )
    if not (
        verified_at
        <= receipt["revalidated_at_unix"]
        < expires_at
    ):
        raise _error("source_revalidation_receipt_time_invalid")
    return {
        "post_verifier_live_source_revalidation_receipt": receipt,
        "post_verifier_live_source_revalidation_receipt_sha256": (
            receipt_digest
        ),
    }


def _v2_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error("source_revalidation_receipt_v2_not_object")
    if any(not isinstance(key, str) for key in value):
        raise _error("source_revalidation_receipt_v2_fields_invalid")
    return value


def _v2_digest(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not SHA256_RE.fullmatch(value)
        or value == "0" * 64
    ):
        raise _error(
            f"source_revalidation_receipt_v2_{field}_invalid"
        )
    return value


def _v2_integer(
    value: Any,
    *,
    field: str,
    minimum: int = 0,
    maximum: int = MAX_SAFE_INTEGER,
) -> int:
    if (
        type(value) is not int
        or value < minimum
        or value > maximum
    ):
        raise _error(
            f"source_revalidation_receipt_v2_{field}_invalid"
        )
    return value


def _v2_adoption_provenance(value: Any) -> tuple[dict[str, Any], str]:
    try:
        selected = _v2_mapping(value)
        if set(selected) != _CAPTURE_ADOPTION_PROVENANCE_FIELDS:
            raise _error(
                "source_revalidation_receipt_v2_"
                "capture_adoption_provenance_fields_invalid"
            )
        if (
            selected["schema_version"]
            != _CAPTURE_ADOPTION_PROVENANCE_SCHEMA
        ):
            raise _error(
                "source_revalidation_receipt_v2_"
                "capture_adoption_provenance_schema_invalid"
            )
        kind = selected["kind"]
        if kind not in {
            _NORMAL_ADOPTION_KIND,
            _RECOVERED_ADOPTION_KIND,
        }:
            raise _error(
                "source_revalidation_receipt_v2_"
                "capture_adoption_provenance_kind_invalid"
            )
        evidence_sha256 = _v2_digest(
            selected["evidence_sha256"],
            field=(
                "capture_adoption_provenance_evidence_sha256"
            ),
        )
        details = _v2_mapping(selected["details"])
        if kind == _NORMAL_ADOPTION_KIND:
            if (
                selected["evidence_schema"]
                != _NORMAL_ADOPTION_EVIDENCE_SCHEMA
                or set(details)
                != _NORMAL_ADOPTION_PROVENANCE_DETAIL_FIELDS
            ):
                raise _error(
                    "source_revalidation_receipt_v2_"
                    "capture_adoption_provenance_kind_mismatch"
                )
            evidence_schema = _NORMAL_ADOPTION_EVIDENCE_SCHEMA
            normalized_details = {
                "adopted_at_unix": _v2_integer(
                    details["adopted_at_unix"],
                    field=(
                        "capture_adoption_provenance_"
                        "adopted_at_unix"
                    ),
                    minimum=1,
                )
            }
        else:
            if (
                selected["evidence_schema"]
                != _RECOVERED_ADOPTION_EVIDENCE_SCHEMA
                or set(details)
                != _RECOVERED_ADOPTION_PROVENANCE_DETAIL_FIELDS
                or details["transaction_journal_schema"]
                != _TRANSACTION_JOURNAL_SCHEMA
            ):
                raise _error(
                    "source_revalidation_receipt_v2_"
                    "capture_adoption_provenance_kind_mismatch"
                )
            evidence_schema = _RECOVERED_ADOPTION_EVIDENCE_SCHEMA
            normalized_details = {
                "transaction_journal_schema": (
                    _TRANSACTION_JOURNAL_SCHEMA
                ),
                "adoption_reconciliation_record_sha256": (
                    _v2_digest(
                        details[
                            "adoption_reconciliation_record_sha256"
                        ],
                        field=(
                            "capture_adoption_provenance_"
                            "reconciliation_record_sha256"
                        ),
                    )
                ),
                "adoption_reconciliation_receipt_sha256": (
                    _v2_digest(
                        details[
                            "adoption_reconciliation_receipt_sha256"
                        ],
                        field=(
                            "capture_adoption_provenance_"
                            "reconciliation_receipt_sha256"
                        ),
                    )
                ),
            }
        provenance = {
            "schema_version": _CAPTURE_ADOPTION_PROVENANCE_SCHEMA,
            "kind": kind,
            "evidence_schema": evidence_schema,
            "evidence_sha256": evidence_sha256,
            "details": normalized_details,
        }
        provenance_sha256 = hashlib.sha256(
            canonical_json(provenance)
        ).hexdigest()
    except SourceRevalidationBindingError as exc:
        raise _error(
            "source_revalidation_receipt_v2_"
            "capture_adoption_provenance_invalid"
        ) from exc
    return provenance, provenance_sha256


def normalize_source_revalidation_receipt_v2(
    value: Any,
) -> dict[str, Any]:
    """Normalize a tagged-adoption post-verifier revalidation receipt."""

    receipt = _v2_mapping(value)
    if set(receipt) != SOURCE_REVALIDATION_RECEIPT_V2_FIELDS:
        raise _error("source_revalidation_receipt_v2_fields_invalid")
    if (
        receipt.get("schema_version")
        != SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA
    ):
        raise _error(
            "source_revalidation_receipt_v2_schema_unsupported"
        )
    if receipt.get("status") != SOURCE_REVALIDATION_STATUS:
        raise _error(
            "source_revalidation_receipt_v2_status_invalid"
        )

    provenance, observed_provenance_sha256 = (
        _v2_adoption_provenance(
            receipt.get("capture_adoption_provenance")
        )
    )
    claimed_provenance_sha256 = _v2_digest(
        receipt.get("capture_adoption_provenance_sha256"),
        field="capture_adoption_provenance_sha256",
    )
    if not hmac.compare_digest(
        claimed_provenance_sha256,
        observed_provenance_sha256,
    ):
        raise _error(
            "source_revalidation_receipt_v2_"
            "capture_adoption_provenance_digest_mismatch"
        )

    revalidator_uid = _v2_integer(
        receipt.get("revalidator_uid"),
        field="revalidator_uid",
        maximum=(1 << 31) - 1,
    )
    if revalidator_uid != 0:
        raise _error(
            "source_revalidation_receipt_v2_"
            "revalidator_uid_invalid"
        )
    return {
        "schema_version": SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA,
        "status": SOURCE_REVALIDATION_STATUS,
        "capture_adoption_provenance": provenance,
        "capture_adoption_provenance_sha256": (
            observed_provenance_sha256
        ),
        "capture_object_identity_sha256": _v2_digest(
            receipt.get("capture_object_identity_sha256"),
            field="capture_object_identity_sha256",
        ),
        "capture_plan_sha256": _v2_digest(
            receipt.get("capture_plan_sha256"),
            field="capture_plan_sha256",
        ),
        "capture_manifest_sha256": _v2_digest(
            receipt.get("capture_manifest_sha256"),
            field="capture_manifest_sha256",
        ),
        "verifier_output_sha256": _v2_digest(
            receipt.get("verifier_output_sha256"),
            field="verifier_output_sha256",
        ),
        "revalidator_uid": 0,
        "revalidated_at_unix": _v2_integer(
            receipt.get("revalidated_at_unix"),
            field="revalidated_at_unix",
            minimum=1,
        ),
    }


def source_revalidation_receipt_v2_sha256(value: Any) -> str:
    """Digest one canonical tagged-adoption revalidation receipt."""

    return hashlib.sha256(
        canonical_json(normalize_source_revalidation_receipt_v2(value))
    ).hexdigest()


def bind_source_revalidation_receipt_v2(
    value: Any,
    *,
    expected_receipt_sha256: str,
    expected_capture_adoption_provenance: Mapping[str, Any],
    expected_capture_adoption_provenance_sha256: str,
    expected_capture_object_identity_sha256: str,
    expected_capture_plan_sha256: str,
    expected_capture_manifest_sha256: str,
    expected_verifier_output_sha256: str,
    verified_at_unix: int,
    expires_at_unix: int,
) -> dict[str, Any]:
    """Bind v2 to one exact normal-or-recovered adoption provenance."""

    receipt = normalize_source_revalidation_receipt_v2(value)
    receipt_digest = _v2_digest(
        expected_receipt_sha256,
        field="expected_receipt_sha256",
    )
    if not hmac.compare_digest(
        source_revalidation_receipt_v2_sha256(receipt),
        receipt_digest,
    ):
        raise _error(
            "source_revalidation_receipt_v2_digest_mismatch"
        )

    expected_provenance, observed_expected_provenance_sha256 = (
        _v2_adoption_provenance(
            expected_capture_adoption_provenance
        )
    )
    claimed_expected_provenance_sha256 = _v2_digest(
        expected_capture_adoption_provenance_sha256,
        field="expected_capture_adoption_provenance_sha256",
    )
    if not hmac.compare_digest(
        claimed_expected_provenance_sha256,
        observed_expected_provenance_sha256,
    ):
        raise _error(
            "source_revalidation_receipt_v2_expected_"
            "capture_adoption_provenance_digest_mismatch"
        )
    if not hmac.compare_digest(
        canonical_json(receipt["capture_adoption_provenance"]),
        canonical_json(expected_provenance),
    ):
        raise _error(
            "source_revalidation_receipt_v2_"
            "capture_adoption_provenance_mismatch"
        )
    if not hmac.compare_digest(
        receipt["capture_adoption_provenance_sha256"],
        claimed_expected_provenance_sha256,
    ):
        raise _error(
            "source_revalidation_receipt_v2_"
            "capture_adoption_provenance_sha256_mismatch"
        )

    expected = {
        "capture_object_identity_sha256": _v2_digest(
            expected_capture_object_identity_sha256,
            field="expected_capture_object_identity_sha256",
        ),
        "capture_plan_sha256": _v2_digest(
            expected_capture_plan_sha256,
            field="expected_capture_plan_sha256",
        ),
        "capture_manifest_sha256": _v2_digest(
            expected_capture_manifest_sha256,
            field="expected_capture_manifest_sha256",
        ),
        "verifier_output_sha256": _v2_digest(
            expected_verifier_output_sha256,
            field="expected_verifier_output_sha256",
        ),
    }
    for field, expected_value in expected.items():
        if not hmac.compare_digest(receipt[field], expected_value):
            raise _error(
                f"source_revalidation_receipt_v2_{field}_mismatch"
            )

    verified_at = _v2_integer(
        verified_at_unix,
        field="verified_at_unix",
        minimum=1,
    )
    expires_at = _v2_integer(
        expires_at_unix,
        field="expires_at_unix",
        minimum=1,
    )
    if not (
        verified_at
        <= receipt["revalidated_at_unix"]
        < expires_at
    ):
        raise _error(
            "source_revalidation_receipt_v2_time_invalid"
        )
    return {
        "post_verifier_live_source_revalidation_receipt": receipt,
        "post_verifier_live_source_revalidation_receipt_sha256": (
            receipt_digest
        ),
    }


__all__ = [
    "SOURCE_REVALIDATION_EVIDENCE_FIELDS",
    "SOURCE_REVALIDATION_RECEIPT_FIELDS",
    "SOURCE_REVALIDATION_RECEIPT_SCHEMA",
    "SOURCE_REVALIDATION_RECEIPT_V2_FIELDS",
    "SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA",
    "SOURCE_REVALIDATION_STATUS",
    "SourceRevalidationBindingError",
    "bind_source_revalidation_receipt",
    "bind_source_revalidation_receipt_v2",
    "canonical_json",
    "normalize_source_revalidation_receipt",
    "normalize_source_revalidation_receipt_v2",
    "source_revalidation_receipt_sha256",
    "source_revalidation_receipt_v2_sha256",
]
