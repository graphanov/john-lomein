"""Pure tagged-union contract for capture-adoption results.

The live adoption path and the crash-recovery path make deliberately
different claims.  A normal adoption receipt can bind facts observed by the
live operation, such as its adoption time.  Recovered-adoption evidence can
bind only facts reconstructed from a validated transaction-journal history
and an exact dual-parent reconciliation.

This module prevents those result kinds from being confused downstream.  It
owns no path, descriptor, process, journal, signer, publication, or activation
authority.  The full result carries one exact evidence object; the compact
provenance projection preserves the result kind and evidence identity without
copying the full evidence object into every later receipt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_adoption_binding
    as adoption_binding,
)
from qualification_attestor import (
    john_lomein_persona_qualification_recovered_adoption_evidence
    as recovered_adoption,
)


PRODUCTION_ACTIVATION = False

CAPTURE_ADOPTION_RESULT_SCHEMA = (
    "john-lomein.persona-qualification-capture-adoption-result.v1"
)
CAPTURE_ADOPTION_PROVENANCE_SCHEMA = (
    "john-lomein.persona-qualification-capture-adoption-provenance.v1"
)

NORMAL_ADOPTION_KIND = "normal_adoption"
RECOVERED_ADOPTION_KIND = "recovered_adoption"
CAPTURE_ADOPTION_KINDS = frozenset(
    {NORMAL_ADOPTION_KIND, RECOVERED_ADOPTION_KIND}
)

CAPTURE_ADOPTION_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "evidence",
        "evidence_sha256",
    }
)
CAPTURE_ADOPTION_PROVENANCE_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "evidence_schema",
        "evidence_sha256",
        "details",
    }
)
NORMAL_ADOPTION_PROVENANCE_DETAIL_FIELDS = frozenset(
    {"adopted_at_unix"}
)
RECOVERED_ADOPTION_PROVENANCE_DETAIL_FIELDS = frozenset(
    {
        "transaction_journal_schema",
        "adoption_reconciliation_record_sha256",
        "adoption_reconciliation_receipt_sha256",
    }
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ZERO_SHA256 = "0" * 64
MAX_SAFE_INTEGER = (1 << 53) - 1


class CaptureAdoptionResultError(ValueError):
    """Stable public-safe rejection of an adoption result or provenance."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> CaptureAdoptionResultError:
    return CaptureAdoptionResultError(code)


def canonical_json(value: Any) -> bytes:
    """Return the one canonical encoding used by both union digests."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _error("capture_adoption_result_json_invalid") from exc


def _strict_mapping(
    value: Any,
    expected: frozenset[str],
    *,
    code: str,
) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != expected
        or any(not isinstance(field, str) for field in value)
    ):
        raise _error(code)
    return value


def _digest(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not SHA256_RE.fullmatch(value)
        or value == ZERO_SHA256
    ):
        raise _error(f"capture_adoption_{field}_invalid")
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
        raise _error(f"capture_adoption_{field}_invalid")
    return value


def _kind(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or value not in CAPTURE_ADOPTION_KINDS
    ):
        raise _error(f"capture_adoption_{field}_invalid")
    return value


def _normal_evidence(value: Any) -> tuple[dict[str, Any], str]:
    if (
        not isinstance(value, Mapping)
        or value.get("schema_version")
        != adoption_binding.ADOPTION_RECEIPT_SCHEMA
        or value.get("status") != adoption_binding.ADOPTION_STATUS
    ):
        raise _error("capture_adoption_result_kind_evidence_mismatch")
    try:
        evidence = adoption_binding.normalize_adoption_receipt(value)
        digest = adoption_binding.adoption_receipt_sha256(evidence)
    except adoption_binding.CaptureAdoptionBindingError as exc:
        raise _error(
            "capture_adoption_result_normal_evidence_invalid"
        ) from exc
    return evidence, digest


def _recovered_evidence(value: Any) -> tuple[dict[str, Any], str]:
    if (
        not isinstance(value, Mapping)
        or value.get("schema_version")
        != recovered_adoption.RECOVERED_ADOPTION_EVIDENCE_SCHEMA
        or value.get("status")
        != recovered_adoption.RECOVERED_ADOPTION_STATUS
    ):
        raise _error("capture_adoption_result_kind_evidence_mismatch")
    try:
        evidence = (
            recovered_adoption.normalize_recovered_adoption_evidence(
                value
            )
        )
        digest = (
            recovered_adoption.recovered_adoption_evidence_sha256(
                evidence
            )
        )
    except recovered_adoption.RecoveredAdoptionEvidenceError as exc:
        raise _error(
            "capture_adoption_result_recovered_evidence_invalid"
        ) from exc
    return evidence, digest


def normalize_capture_adoption_result(value: Any) -> dict[str, Any]:
    """Normalize one full, exact normal-or-recovered adoption result."""

    selected = _strict_mapping(
        value,
        CAPTURE_ADOPTION_RESULT_FIELDS,
        code="capture_adoption_result_fields_invalid",
    )
    if selected["schema_version"] != CAPTURE_ADOPTION_RESULT_SCHEMA:
        raise _error("capture_adoption_result_schema_invalid")
    kind = _kind(selected["kind"], field="result_kind")
    if kind == NORMAL_ADOPTION_KIND:
        evidence, observed_digest = _normal_evidence(
            selected["evidence"]
        )
    else:
        evidence, observed_digest = _recovered_evidence(
            selected["evidence"]
        )
    claimed_digest = _digest(
        selected["evidence_sha256"],
        field="result_evidence_sha256",
    )
    if not hmac.compare_digest(claimed_digest, observed_digest):
        raise _error("capture_adoption_result_evidence_digest_mismatch")
    return {
        "schema_version": CAPTURE_ADOPTION_RESULT_SCHEMA,
        "kind": kind,
        "evidence": evidence,
        "evidence_sha256": observed_digest,
    }


def build_capture_adoption_result(
    kind: str,
    evidence: Any,
) -> dict[str, Any]:
    """Build one canonical union shape without granting any authority."""

    normalized_kind = _kind(kind, field="result_kind")
    if normalized_kind == NORMAL_ADOPTION_KIND:
        normalized_evidence, evidence_sha256 = _normal_evidence(
            evidence
        )
    else:
        normalized_evidence, evidence_sha256 = _recovered_evidence(
            evidence
        )
    return normalize_capture_adoption_result(
        {
            "schema_version": CAPTURE_ADOPTION_RESULT_SCHEMA,
            "kind": normalized_kind,
            "evidence": normalized_evidence,
            "evidence_sha256": evidence_sha256,
        }
    )


def capture_adoption_result_sha256(value: Any) -> str:
    """Digest one canonical full adoption result."""

    return hashlib.sha256(
        canonical_json(normalize_capture_adoption_result(value))
    ).hexdigest()


def normalize_capture_adoption_provenance(value: Any) -> dict[str, Any]:
    """Normalize the compact result-kind projection used downstream."""

    selected = _strict_mapping(
        value,
        CAPTURE_ADOPTION_PROVENANCE_FIELDS,
        code="capture_adoption_provenance_fields_invalid",
    )
    if (
        selected["schema_version"]
        != CAPTURE_ADOPTION_PROVENANCE_SCHEMA
    ):
        raise _error("capture_adoption_provenance_schema_invalid")
    kind = _kind(selected["kind"], field="provenance_kind")
    evidence_sha256 = _digest(
        selected["evidence_sha256"],
        field="provenance_evidence_sha256",
    )
    if kind == NORMAL_ADOPTION_KIND:
        if (
            selected["evidence_schema"]
            != adoption_binding.ADOPTION_RECEIPT_SCHEMA
        ):
            raise _error(
                "capture_adoption_provenance_kind_schema_mismatch"
            )
        details = _strict_mapping(
            selected["details"],
            NORMAL_ADOPTION_PROVENANCE_DETAIL_FIELDS,
            code="capture_adoption_provenance_details_invalid",
        )
        normalized_details = {
            "adopted_at_unix": _integer(
                details["adopted_at_unix"],
                field="provenance_adopted_at_unix",
                minimum=1,
            )
        }
        evidence_schema = adoption_binding.ADOPTION_RECEIPT_SCHEMA
    else:
        if (
            selected["evidence_schema"]
            != recovered_adoption.RECOVERED_ADOPTION_EVIDENCE_SCHEMA
        ):
            raise _error(
                "capture_adoption_provenance_kind_schema_mismatch"
            )
        details = _strict_mapping(
            selected["details"],
            RECOVERED_ADOPTION_PROVENANCE_DETAIL_FIELDS,
            code="capture_adoption_provenance_details_invalid",
        )
        if (
            details["transaction_journal_schema"]
            != recovered_adoption.TRANSACTION_JOURNAL_SCHEMA
        ):
            raise _error(
                "capture_adoption_provenance_journal_schema_invalid"
            )
        normalized_details = {
            "transaction_journal_schema": (
                recovered_adoption.TRANSACTION_JOURNAL_SCHEMA
            ),
            "adoption_reconciliation_record_sha256": _digest(
                details["adoption_reconciliation_record_sha256"],
                field=(
                    "provenance_"
                    "adoption_reconciliation_record_sha256"
                ),
            ),
            "adoption_reconciliation_receipt_sha256": _digest(
                details["adoption_reconciliation_receipt_sha256"],
                field=(
                    "provenance_"
                    "adoption_reconciliation_receipt_sha256"
                ),
            ),
        }
        evidence_schema = (
            recovered_adoption.RECOVERED_ADOPTION_EVIDENCE_SCHEMA
        )
    return {
        "schema_version": CAPTURE_ADOPTION_PROVENANCE_SCHEMA,
        "kind": kind,
        "evidence_schema": evidence_schema,
        "evidence_sha256": evidence_sha256,
        "details": normalized_details,
    }


def project_capture_adoption_provenance(value: Any) -> dict[str, Any]:
    """Derive compact provenance from a fully validated result."""

    result = normalize_capture_adoption_result(value)
    evidence = result["evidence"]
    if result["kind"] == NORMAL_ADOPTION_KIND:
        details = {
            "adopted_at_unix": evidence["adopted_at_unix"],
        }
        evidence_schema = adoption_binding.ADOPTION_RECEIPT_SCHEMA
    else:
        details = {
            "transaction_journal_schema": evidence[
                "transaction_journal_schema"
            ],
            "adoption_reconciliation_record_sha256": evidence[
                "adoption_reconciliation_record_sha256"
            ],
            "adoption_reconciliation_receipt_sha256": evidence[
                "adoption_reconciliation_receipt_sha256"
            ],
        }
        evidence_schema = (
            recovered_adoption.RECOVERED_ADOPTION_EVIDENCE_SCHEMA
        )
    return normalize_capture_adoption_provenance(
        {
            "schema_version": CAPTURE_ADOPTION_PROVENANCE_SCHEMA,
            "kind": result["kind"],
            "evidence_schema": evidence_schema,
            "evidence_sha256": result["evidence_sha256"],
            "details": details,
        }
    )


def capture_adoption_provenance_sha256(value: Any) -> str:
    """Digest one canonical compact adoption provenance projection."""

    return hashlib.sha256(
        canonical_json(normalize_capture_adoption_provenance(value))
    ).hexdigest()


__all__ = [
    "CAPTURE_ADOPTION_KINDS",
    "CAPTURE_ADOPTION_PROVENANCE_FIELDS",
    "CAPTURE_ADOPTION_PROVENANCE_SCHEMA",
    "CAPTURE_ADOPTION_RESULT_FIELDS",
    "CAPTURE_ADOPTION_RESULT_SCHEMA",
    "CaptureAdoptionResultError",
    "NORMAL_ADOPTION_KIND",
    "NORMAL_ADOPTION_PROVENANCE_DETAIL_FIELDS",
    "PRODUCTION_ACTIVATION",
    "RECOVERED_ADOPTION_KIND",
    "RECOVERED_ADOPTION_PROVENANCE_DETAIL_FIELDS",
    "ZERO_SHA256",
    "build_capture_adoption_result",
    "canonical_json",
    "capture_adoption_provenance_sha256",
    "capture_adoption_result_sha256",
    "normalize_capture_adoption_provenance",
    "normalize_capture_adoption_result",
    "project_capture_adoption_provenance",
]
