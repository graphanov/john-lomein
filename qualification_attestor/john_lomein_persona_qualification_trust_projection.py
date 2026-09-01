#!/usr/bin/env python3
"""Self-contained, privacy-safe public projection of local conformance.

The projection is one canonical JSON object so an installer can publish it
with one atomic replacement.  It embeds the public key, operator policy,
sanitized head, and signed envelope, but never the private archive path or raw
qualification evidence.  Verification requires an out-of-band pinned public
key fingerprint; a self-signed object is not its own identity anchor.
"""

from __future__ import annotations

import hmac
import fcntl
import os
import secrets
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from qualification_attestor import (
    john_lomein_persona_qualification_attestor as core,
)
from qualification_attestor import (
    john_lomein_persona_qualification_adoption_binding as adoption_binding,
)
from qualification_attestor import (
    john_lomein_persona_qualification_adoption_result as adoption_result,
)


PROJECTION_SCHEMA = "john-lomein.persona-qualification-trust-projection.v1"
PUBLIC_HEAD_SCHEMA = "john-lomein.persona-qualification-public-head.v1"
CLAIM_LIMITS_SCHEMA = "john-lomein.persona-qualification-claim-limits.v1"
MAX_PUBLIC_KEY_BYTES = 64 * 1024
MAX_PROJECTION_BYTES = 2 * 1024 * 1024
MAX_INTERRUPTED_PROJECTION_FILES = 16

PROJECTION_FIELDS = {
    "schema_version",
    "generated_at_unix",
    "claim_strength",
    "public_reputation_eligible",
    "claim_limits",
    "public_key_pem",
    "operator_policy",
    "head",
    "attestation",
}
PUBLIC_HEAD_FIELDS = {
    "schema_version",
    "state",
    "instance_slug",
    "chain_sequence",
    "previous_attestation_sha256",
    "run_id",
    "summary_sha256",
    "binding_sha256",
    "qualified_at_unix",
    "verified_at_unix",
    "expires_at_unix",
    "attestation_sha256",
}
OPERATOR_POLICY_V3_FIELDS = {
    "schema_version",
    "instance_slug",
    "expected_evidence_uid",
    "expected_capture_uid",
    "expected_capture_export_gid",
    "expected_adopted_uid",
    "capture_adoption_binding_schema",
    "capture_adoption_required",
    "instance_manifest_sha256",
    "verifier_uid",
    "verifier_gid",
    "verifier_python_sha256",
    "verifier_bundle_sha256",
    "verifier_version",
    "verifier_timeout_seconds",
    "verification_execution_policy_sha256",
    "capture_selection_sha256",
    "claim_strength",
    "public_reputation_eligible",
}
OPERATOR_POLICY_FIELDS = OPERATOR_POLICY_V3_FIELDS
OPERATOR_POLICY_V4_FIELDS = (
    (
        OPERATOR_POLICY_V3_FIELDS
        - {
            "capture_adoption_binding_schema",
        }
    )
    | {
        "capture_adoption_result_schema",
        "capture_adoption_provenance_schema",
        "capture_adoption_permitted_kinds",
        "verifier_request_schema",
        "verifier_output_schema",
        "verification_execution_policy_schema",
    }
)
CLAIM_LIMITS = {
    "schema_version": CLAIM_LIMITS_SCHEMA,
    "evidence_scope": "operator-local-persona-conformance",
    "operator_root_trusted": True,
    "independent_third_party": False,
    "complete_archive_included": False,
    "whole_store_rollback_detected": False,
    "public_reputation_eligible": False,
}


class TrustProjectionError(ValueError):
    """A stable public projection rejection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _error(code: str) -> TrustProjectionError:
    return TrustProjectionError(code)


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(f"{field}_not_object")
    return value


def _strict_fields(
    value: Mapping[str, Any],
    *,
    field: str,
    expected: set[str],
) -> None:
    if set(value) != expected or any(not isinstance(key, str) for key in value):
        raise _error(f"{field}_fields_invalid")


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int = 0,
) -> int:
    if type(value) is not int or value < minimum:
        raise _error(f"{field}_invalid")
    return value


def _normalize_operator_policy_v3(
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Preserve the historical normal-adoption policy contract exactly."""

    _strict_fields(
        policy,
        field="operator_policy",
        expected=OPERATOR_POLICY_V3_FIELDS,
    )
    slug = core._slug(
        policy.get("instance_slug"),
        field="operator_policy_instance_slug",
    )
    evidence_uid = core._integer(
        policy.get("expected_evidence_uid"),
        field="operator_policy_expected_evidence_uid",
        minimum=1,
    )
    verifier_uid = core._integer(
        policy.get("verifier_uid"),
        field="operator_policy_verifier_uid",
        minimum=1,
    )
    if verifier_uid == evidence_uid:
        raise _error("operator_policy_verifier_identity_not_separate")
    capture_uid = core._integer(
        policy.get("expected_capture_uid"),
        field="operator_policy_expected_capture_uid",
        minimum=1,
    )
    capture_export_gid = core._integer(
        policy.get("expected_capture_export_gid"),
        field="operator_policy_expected_capture_export_gid",
        minimum=1,
    )
    adopted_uid = core._integer(
        policy.get("expected_adopted_uid"),
        field="operator_policy_expected_adopted_uid",
    )
    verifier_gid = core._integer(
        policy.get("verifier_gid"),
        field="operator_policy_verifier_gid",
        minimum=1,
    )
    if (
        capture_uid in {evidence_uid, verifier_uid}
        or capture_export_gid == verifier_gid
        or adopted_uid != 0
    ):
        raise _error("operator_policy_capture_identity_invalid")
    if (
        policy.get("capture_adoption_binding_schema")
        != adoption_binding.ADOPTION_BINDING_SCHEMA
        or policy.get("capture_adoption_required") is not True
    ):
        raise _error("operator_policy_capture_adoption_invalid")
    timeout = core._integer(
        policy.get("verifier_timeout_seconds"),
        field="operator_policy_timeout",
        minimum=1,
    )
    if timeout > core.MAX_VERIFIER_TIMEOUT_SECONDS:
        raise _error("operator_policy_timeout_invalid")
    if policy.get("claim_strength") != core.CLAIM_STRENGTH:
        raise _error("operator_policy_claim_strength_invalid")
    if policy.get("public_reputation_eligible") is not False:
        raise _error("operator_policy_reputation_claim_invalid")
    return {
        "schema_version": core.OPERATOR_POLICY_SCHEMA,
        "instance_slug": slug,
        "expected_evidence_uid": evidence_uid,
        "expected_capture_uid": capture_uid,
        "expected_capture_export_gid": capture_export_gid,
        "expected_adopted_uid": 0,
        "capture_adoption_binding_schema": (
            adoption_binding.ADOPTION_BINDING_SCHEMA
        ),
        "capture_adoption_required": True,
        "instance_manifest_sha256": core._digest(
            policy.get("instance_manifest_sha256"),
            field="operator_policy_instance_manifest_sha256",
        ),
        "verifier_uid": verifier_uid,
        "verifier_gid": verifier_gid,
        "verifier_python_sha256": core._digest(
            policy.get("verifier_python_sha256"),
            field="operator_policy_verifier_python_sha256",
        ),
        "verifier_bundle_sha256": core._digest(
            policy.get("verifier_bundle_sha256"),
            field="operator_policy_verifier_bundle_sha256",
        ),
        "verifier_version": core._token(
            policy.get("verifier_version"),
            field="operator_policy_verifier_version",
        ),
        "verifier_timeout_seconds": timeout,
        "verification_execution_policy_sha256": core._digest(
            policy.get("verification_execution_policy_sha256"),
            field="operator_policy_execution_policy_sha256",
        ),
        "capture_selection_sha256": core._digest(
            policy.get("capture_selection_sha256"),
            field="operator_policy_capture_selection_sha256",
        ),
        "claim_strength": core.CLAIM_STRENGTH,
        "public_reputation_eligible": False,
    }


def normalize_operator_policy(value: Any) -> dict[str, Any]:
    policy = _mapping(value, field="operator_policy")
    schema = policy.get("schema_version")
    if schema == core.OPERATOR_POLICY_SCHEMA:
        return _normalize_operator_policy_v3(policy)
    if schema != core.FUTURE_OPERATOR_POLICY_SCHEMA:
        raise _error("operator_policy_schema_unsupported")
    _strict_fields(
        policy,
        field="operator_policy",
        expected=OPERATOR_POLICY_V4_FIELDS,
    )
    slug = core._slug(
        policy.get("instance_slug"),
        field="operator_policy_instance_slug",
    )
    evidence_uid = core._integer(
        policy.get("expected_evidence_uid"),
        field="operator_policy_expected_evidence_uid",
        minimum=1,
    )
    verifier_uid = core._integer(
        policy.get("verifier_uid"),
        field="operator_policy_verifier_uid",
        minimum=1,
    )
    if verifier_uid == evidence_uid:
        raise _error("operator_policy_verifier_identity_not_separate")
    capture_uid = core._integer(
        policy.get("expected_capture_uid"),
        field="operator_policy_expected_capture_uid",
        minimum=1,
    )
    capture_export_gid = core._integer(
        policy.get("expected_capture_export_gid"),
        field="operator_policy_expected_capture_export_gid",
        minimum=1,
    )
    adopted_uid = core._integer(
        policy.get("expected_adopted_uid"),
        field="operator_policy_expected_adopted_uid",
    )
    verifier_gid = core._integer(
        policy.get("verifier_gid"),
        field="operator_policy_verifier_gid",
        minimum=1,
    )
    if (
        capture_uid in {evidence_uid, verifier_uid}
        or capture_export_gid == verifier_gid
        or adopted_uid != 0
    ):
        raise _error("operator_policy_capture_identity_invalid")
    timeout = core._integer(
        policy.get("verifier_timeout_seconds"),
        field="operator_policy_timeout",
        minimum=1,
    )
    if timeout > core.MAX_VERIFIER_TIMEOUT_SECONDS:
        raise _error("operator_policy_timeout_invalid")
    if policy.get("claim_strength") != core.CLAIM_STRENGTH:
        raise _error("operator_policy_claim_strength_invalid")
    if policy.get("public_reputation_eligible") is not False:
        raise _error("operator_policy_reputation_claim_invalid")
    verifier_version = core._token(
        policy.get("verifier_version"),
        field="operator_policy_verifier_version",
    )
    execution_policy_sha256 = core._digest(
        policy.get("verification_execution_policy_sha256"),
        field="operator_policy_execution_policy_sha256",
    )
    common = {
        "instance_slug": slug,
        "expected_evidence_uid": evidence_uid,
        "expected_capture_uid": capture_uid,
        "expected_capture_export_gid": capture_export_gid,
        "expected_adopted_uid": 0,
        "instance_manifest_sha256": core._digest(
            policy.get("instance_manifest_sha256"),
            field="operator_policy_instance_manifest_sha256",
        ),
        "verifier_uid": verifier_uid,
        "verifier_gid": verifier_gid,
        "verifier_python_sha256": core._digest(
            policy.get("verifier_python_sha256"),
            field="operator_policy_verifier_python_sha256",
        ),
        "verifier_bundle_sha256": core._digest(
            policy.get("verifier_bundle_sha256"),
            field="operator_policy_verifier_bundle_sha256",
        ),
        "verifier_version": verifier_version,
        "verifier_timeout_seconds": timeout,
        "verification_execution_policy_sha256": (
            execution_policy_sha256
        ),
        "capture_selection_sha256": core._digest(
            policy.get("capture_selection_sha256"),
            field="operator_policy_capture_selection_sha256",
        ),
        "claim_strength": core.CLAIM_STRENGTH,
        "public_reputation_eligible": False,
    }
    if (
        policy.get("capture_adoption_result_schema")
        != adoption_result.CAPTURE_ADOPTION_RESULT_SCHEMA
        or policy.get("capture_adoption_provenance_schema")
        != adoption_result.CAPTURE_ADOPTION_PROVENANCE_SCHEMA
        or policy.get("capture_adoption_permitted_kinds")
        != core.FUTURE_CAPTURE_ADOPTION_PERMITTED_KINDS
        or policy.get("capture_adoption_required") is not True
    ):
        raise _error("operator_policy_v4_capture_adoption_invalid")
    if (
        policy.get("verifier_request_schema")
        != core.VERIFIER_REQUEST_V5_SCHEMA
        or policy.get("verifier_output_schema")
        != core.VERIFIER_OUTPUT_V4_SCHEMA
        or verifier_version != core.VERIFIER_V5_VERSION
    ):
        raise _error("operator_policy_v4_verifier_contract_invalid")
    if (
        policy.get("verification_execution_policy_schema")
        != core.VERIFICATION_EXECUTION_POLICY_V6_SCHEMA
        or not hmac.compare_digest(
            execution_policy_sha256,
            core.sha256_json(core.VERIFICATION_EXECUTION_POLICY_V6),
        )
    ):
        raise _error(
            "operator_policy_v4_execution_policy_invalid"
        )
    return {
        "schema_version": core.FUTURE_OPERATOR_POLICY_SCHEMA,
        "instance_slug": common["instance_slug"],
        "expected_evidence_uid": common["expected_evidence_uid"],
        "expected_capture_uid": common["expected_capture_uid"],
        "expected_capture_export_gid": common[
            "expected_capture_export_gid"
        ],
        "expected_adopted_uid": 0,
        "capture_adoption_result_schema": (
            adoption_result.CAPTURE_ADOPTION_RESULT_SCHEMA
        ),
        "capture_adoption_provenance_schema": (
            adoption_result.CAPTURE_ADOPTION_PROVENANCE_SCHEMA
        ),
        "capture_adoption_permitted_kinds": list(
            core.FUTURE_CAPTURE_ADOPTION_PERMITTED_KINDS
        ),
        "capture_adoption_required": True,
        "instance_manifest_sha256": common[
            "instance_manifest_sha256"
        ],
        "verifier_uid": common["verifier_uid"],
        "verifier_gid": common["verifier_gid"],
        "verifier_python_sha256": common[
            "verifier_python_sha256"
        ],
        "verifier_bundle_sha256": common[
            "verifier_bundle_sha256"
        ],
        "verifier_version": core.VERIFIER_V5_VERSION,
        "verifier_request_schema": core.VERIFIER_REQUEST_V5_SCHEMA,
        "verifier_output_schema": core.VERIFIER_OUTPUT_V4_SCHEMA,
        "verifier_timeout_seconds": common[
            "verifier_timeout_seconds"
        ],
        "verification_execution_policy_schema": (
            core.VERIFICATION_EXECUTION_POLICY_V6_SCHEMA
        ),
        "verification_execution_policy_sha256": (
            execution_policy_sha256
        ),
        "capture_selection_sha256": common[
            "capture_selection_sha256"
        ],
        "claim_strength": core.CLAIM_STRENGTH,
        "public_reputation_eligible": False,
    }


def _public_head_from_verified(
    head: Any,
    envelope: Any,
) -> dict[str, Any]:
    normalized_head, normalized_envelope = (
        core._assert_head_attestation_binding(head, envelope)
    )
    payload = normalized_envelope["payload"]
    qualification = payload["qualification"]
    return {
        "schema_version": PUBLIC_HEAD_SCHEMA,
        "state": "verified",
        "instance_slug": normalized_head["instance_slug"],
        "chain_sequence": normalized_head["chain_sequence"],
        "previous_attestation_sha256": normalized_head[
            "previous_attestation_sha256"
        ],
        "run_id": normalized_head["run_id"],
        "summary_sha256": normalized_head["summary_sha256"],
        "binding_sha256": normalized_head["binding_sha256"],
        "qualified_at_unix": qualification["qualified_at_unix"],
        "verified_at_unix": core.effective_verified_at_unix(payload),
        "expires_at_unix": normalized_head["expires_at_unix"],
        "attestation_sha256": normalized_head["attestation_sha256"],
    }


def normalize_public_head(value: Any) -> dict[str, Any]:
    head = _mapping(value, field="public_head")
    _strict_fields(
        head,
        field="public_head",
        expected=PUBLIC_HEAD_FIELDS,
    )
    if head.get("schema_version") != PUBLIC_HEAD_SCHEMA:
        raise _error("public_head_schema_unsupported")
    if head.get("state") != "verified":
        raise _error("public_head_not_verified")
    sequence = core._integer(
        head.get("chain_sequence"),
        field="public_head_chain_sequence",
        minimum=1,
    )
    previous = head.get("previous_attestation_sha256")
    if sequence == 1:
        if previous is not None:
            raise _error("public_head_genesis_previous_invalid")
        normalized_previous = None
    else:
        normalized_previous = core._digest(
            previous,
            field="public_head_previous_attestation_sha256",
        )
    qualified = _integer(
        head.get("qualified_at_unix"),
        field="public_head_qualified_at_unix",
    )
    verified = _integer(
        head.get("verified_at_unix"),
        field="public_head_verified_at_unix",
    )
    expires = _integer(
        head.get("expires_at_unix"),
        field="public_head_expires_at_unix",
    )
    if not qualified <= verified < expires:
        raise _error("public_head_timing_invalid")
    run_id = head.get("run_id")
    if not isinstance(run_id, str) or not core.RUN_ID_RE.fullmatch(run_id):
        raise _error("public_head_run_id_invalid")
    return {
        "schema_version": PUBLIC_HEAD_SCHEMA,
        "state": "verified",
        "instance_slug": core._slug(
            head.get("instance_slug"),
            field="public_head_instance_slug",
        ),
        "chain_sequence": sequence,
        "previous_attestation_sha256": normalized_previous,
        "run_id": run_id,
        "summary_sha256": core._digest(
            head.get("summary_sha256"),
            field="public_head_summary_sha256",
        ),
        "binding_sha256": core._digest(
            head.get("binding_sha256"),
            field="public_head_binding_sha256",
        ),
        "qualified_at_unix": qualified,
        "verified_at_unix": verified,
        "expires_at_unix": expires,
        "attestation_sha256": core._digest(
            head.get("attestation_sha256"),
            field="public_head_attestation_sha256",
        ),
    }


def _normalize_public_key(value: Any) -> tuple[str, bytes]:
    if not isinstance(value, str):
        raise _error("projection_public_key_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeError as exc:
        raise _error("projection_public_key_invalid") from exc
    if (
        not encoded
        or len(encoded) > MAX_PUBLIC_KEY_BYTES
        or not encoded.endswith(b"\n")
    ):
        raise _error("projection_public_key_invalid")
    try:
        key = core._load_public_key(encoded)
    except core.QualificationAttestorError as exc:
        raise _error("projection_public_key_invalid") from exc
    canonical = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not hmac.compare_digest(encoded, canonical):
        raise _error("projection_public_key_invalid")
    return canonical.decode("ascii"), canonical


def normalize_projection(value: Any) -> dict[str, Any]:
    projection = _mapping(value, field="trust_projection")
    _strict_fields(
        projection,
        field="trust_projection",
        expected=PROJECTION_FIELDS,
    )
    if projection.get("schema_version") != PROJECTION_SCHEMA:
        raise _error("trust_projection_schema_unsupported")
    if projection.get("claim_strength") != core.CLAIM_STRENGTH:
        raise _error("trust_projection_claim_strength_invalid")
    if projection.get("public_reputation_eligible") is not False:
        raise _error("trust_projection_reputation_claim_invalid")
    if projection.get("claim_limits") != CLAIM_LIMITS:
        raise _error("trust_projection_claim_limits_invalid")
    public_key_text, _ = _normalize_public_key(
        projection.get("public_key_pem")
    )
    return {
        "schema_version": PROJECTION_SCHEMA,
        "generated_at_unix": _integer(
            projection.get("generated_at_unix"),
            field="trust_projection_generated_at_unix",
        ),
        "claim_strength": core.CLAIM_STRENGTH,
        "public_reputation_eligible": False,
        "claim_limits": dict(CLAIM_LIMITS),
        "public_key_pem": public_key_text,
        "operator_policy": normalize_operator_policy(
            projection.get("operator_policy")
        ),
        "head": normalize_public_head(projection.get("head")),
        "attestation": core.normalize_envelope(
            projection.get("attestation")
        ),
    }


def _assert_policy_binding(
    policy: dict[str, Any],
    envelope: dict[str, Any],
) -> None:
    payload = envelope["payload"]
    verification = payload["verification"]
    policy_schema = policy["schema_version"]
    payload_schema = payload["schema_version"]
    if policy_schema == core.OPERATOR_POLICY_SCHEMA:
        if (
            payload_schema
            not in {
                core.HISTORICAL_PAYLOAD_SCHEMA_VERSION,
                core.PAYLOAD_SCHEMA_VERSION,
            }
            or "capture_adoption_provenance" in verification
        ):
            raise _error(
                "operator_policy_payload_schema_incompatible"
            )
    elif policy_schema == core.FUTURE_OPERATOR_POLICY_SCHEMA:
        if payload_schema != core.FUTURE_PAYLOAD_SCHEMA_VERSION:
            raise _error(
                "operator_policy_payload_schema_incompatible"
            )
        provenance = verification.get(
            "capture_adoption_provenance"
        )
        if (
            not isinstance(provenance, Mapping)
            or provenance.get("schema_version")
            != policy["capture_adoption_provenance_schema"]
            or provenance.get("kind")
            not in policy["capture_adoption_permitted_kinds"]
            or policy["capture_adoption_result_schema"]
            != adoption_result.CAPTURE_ADOPTION_RESULT_SCHEMA
        ):
            raise _error(
                "operator_policy_adoption_semantics_incompatible"
            )
        if (
            verification.get("verifier_version")
            != core.VERIFIER_V5_VERSION
            or policy["verifier_version"]
            != core.VERIFIER_V5_VERSION
            or policy["verifier_request_schema"]
            != core.VERIFIER_REQUEST_V5_SCHEMA
            or policy["verifier_output_schema"]
            != core.VERIFIER_OUTPUT_V4_SCHEMA
        ):
            raise _error(
                "operator_policy_verifier_contract_incompatible"
            )
        if (
            policy["verification_execution_policy_schema"]
            != core.VERIFICATION_EXECUTION_POLICY_V6_SCHEMA
            or not hmac.compare_digest(
                policy["verification_execution_policy_sha256"],
                core.sha256_json(
                    core.VERIFICATION_EXECUTION_POLICY_V6
                ),
            )
        ):
            raise _error(
                "operator_policy_execution_policy_incompatible"
            )
    else:  # The normalizer makes this unreachable for public callers.
        raise _error("operator_policy_schema_unsupported")
    expected = {
        "instance_slug": payload["instance"]["slug"],
        "expected_evidence_uid": verification["expected_evidence_uid"],
        "expected_capture_uid": verification["capture_creator_uid"],
        "expected_capture_export_gid": verification[
            "capture_export_gid"
        ],
        "expected_adopted_uid": verification["capture_adopted_uid"],
        "verifier_uid": verification["verifier_uid"],
        "verifier_bundle_sha256": verification[
            "verifier_bundle_sha256"
        ],
        "verifier_version": verification["verifier_version"],
        "claim_strength": verification["claim_strength"],
        "public_reputation_eligible": False,
    }
    for field, expected_value in expected.items():
        if policy[field] != expected_value:
            raise _error("operator_policy_attestation_binding_mismatch")
    if not hmac.compare_digest(
        core.sha256_json(policy),
        verification["operator_policy_sha256"],
    ):
        raise _error("operator_policy_digest_mismatch")


def build_projection(
    config: Any,
    operator_policy: Any,
    head: Any,
    envelope: Any,
    *,
    public_key_bytes: bytes,
    generated_at_unix: int,
) -> dict[str, Any]:
    """Build one public object only after verifying the private chain head."""

    normalized_config = core.normalize_config(config)
    generated = _integer(
        generated_at_unix,
        field="trust_projection_generated_at_unix",
    )
    if len(public_key_bytes) > MAX_PUBLIC_KEY_BYTES:
        raise _error("projection_public_key_invalid")
    try:
        public_key_text = public_key_bytes.decode("ascii")
    except UnicodeError as exc:
        raise _error("projection_public_key_invalid") from exc
    normalized_envelope = core.verify_published_attestation_head(
        normalized_config,
        head,
        envelope,
        public_key_bytes=public_key_bytes,
        now_unix=generated,
    )[1]
    policy = normalize_operator_policy(operator_policy)
    _assert_policy_binding(policy, normalized_envelope)
    public_head = _public_head_from_verified(head, normalized_envelope)
    effective_verified_at = core.effective_verified_at_unix(
        normalized_envelope["payload"]
    )
    if not effective_verified_at <= generated < public_head[
        "expires_at_unix"
    ]:
        raise _error("trust_projection_generation_time_invalid")
    return normalize_projection(
        {
            "schema_version": PROJECTION_SCHEMA,
            "generated_at_unix": generated,
            "claim_strength": core.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
            "claim_limits": dict(CLAIM_LIMITS),
            "public_key_pem": public_key_text,
            "operator_policy": policy,
            "head": public_head,
            "attestation": normalized_envelope,
        }
    )


def verify_projection(
    value: Any,
    *,
    expected_instance_slug: str,
    expected_key_id: str,
    expected_public_key_sha256: str,
    now_unix: int,
) -> dict[str, Any]:
    """Verify one projection against an independently pinned identity."""

    projection = normalize_projection(value)
    _, public_key_bytes = _normalize_public_key(
        projection["public_key_pem"]
    )
    expected_fingerprint = core._digest(
        expected_public_key_sha256,
        field="expected_public_key_sha256",
    )
    if not hmac.compare_digest(
        core.public_key_fingerprint(public_key_bytes),
        expected_fingerprint,
    ):
        raise _error("trust_projection_public_key_not_pinned")
    slug = core._slug(
        expected_instance_slug,
        field="expected_instance_slug",
    )
    key_id = core._token(
        expected_key_id,
        field="expected_key_id",
    )
    policy = projection["operator_policy"]
    if policy["instance_slug"] != slug:
        raise _error("trust_projection_instance_not_pinned")
    envelope = projection["attestation"]
    try:
        verified = core.verify_attestation_envelope(
            envelope,
            public_key_bytes=public_key_bytes,
            expected_key_id=key_id,
            expected_public_key_sha256=expected_fingerprint,
            expected_instance_slug=slug,
            now_unix=now_unix,
        )
        core._assert_payload_schema_activated(verified["payload"])
    except core.QualificationAttestorError as exc:
        raise _error(exc.code) from exc
    _assert_policy_binding(policy, verified)
    effective_verified_at = core.effective_verified_at_unix(
        verified["payload"]
    )
    try:
        derived_head = _public_head_from_verified(
            {
                "schema_version": core.HEAD_SCHEMA_VERSION,
                "state": "verified",
                "instance_slug": projection["head"]["instance_slug"],
                "chain_sequence": projection["head"]["chain_sequence"],
                "previous_attestation_sha256": projection["head"][
                    "previous_attestation_sha256"
                ],
                "run_id": projection["head"]["run_id"],
                "summary_sha256": projection["head"]["summary_sha256"],
                "binding_sha256": projection["head"]["binding_sha256"],
                "expires_at_unix": projection["head"]["expires_at_unix"],
                # Used only by the core in-memory head normalizer. It is never
                # returned or serialized in the public projection.
                "attestation_path": (
                    "/public-projection/internal-attestations/"
                    + core._expected_attestation_path(
                        {
                            "head_path": "/public-projection/head.json",
                        },
                        verified,
                    ).rsplit("/", 1)[-1]
                ),
                "attestation_sha256": projection["head"][
                    "attestation_sha256"
                ],
                "updated_at_unix": effective_verified_at,
            },
            verified,
        )
    except core.QualificationAttestorError as exc:
        raise _error(exc.code) from exc
    if derived_head != projection["head"]:
        raise _error("trust_projection_head_binding_mismatch")
    generated = projection["generated_at_unix"]
    now = _integer(now_unix, field="trust_projection_verification_clock")
    if (
        generated < effective_verified_at
        or generated > now
        or now >= projection["head"]["expires_at_unix"]
    ):
        raise _error("trust_projection_timing_invalid")
    return projection


def _projection_identity(
    projection: Mapping[str, Any],
) -> tuple[str, str, str]:
    envelope = projection["attestation"]
    return (
        projection["head"]["instance_slug"],
        envelope["payload"]["attestor"]["key_id"],
        core.sha256_bytes(projection["public_key_pem"].encode("ascii")),
    )


def _read_public_projection_at(
    directory_fd: int,
    name: str,
    *,
    directory_path: Path,
    expected_owner_uid: int,
) -> dict[str, Any]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise _error("public_projection_unreadable") from exc
    try:
        before = os.fstat(descriptor)
        try:
            core._reject_acl_or_xattrs(
                directory_path / name,
                field="public_projection",
            )
        except core.QualificationAttestorError as exc:
            raise _error(exc.code) from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_owner_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_size < 1
            or before.st_size > MAX_PROJECTION_BYTES
        ):
            raise _error("public_projection_file_unsafe")
        raw = bytearray()
        while len(raw) <= MAX_PROJECTION_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    64 * 1024,
                    MAX_PROJECTION_BYTES + 1 - len(raw),
                ),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            len(raw) != before.st_size
            or core._file_snapshot(before) != core._file_snapshot(after)
            or core._file_snapshot(after) != core._file_snapshot(named)
        ):
            raise _error("public_projection_changed_during_read")
    finally:
        os.close(descriptor)
    try:
        parsed = core.parse_json_bytes(
            bytes(raw),
            field="public_projection",
            maximum_bytes=MAX_PROJECTION_BYTES,
        )
    except core.QualificationAttestorError as exc:
        raise _error(exc.code) from exc
    normalized = normalize_projection(parsed)
    if bytes(raw) != core.canonical_json(normalized) + b"\n":
        raise _error("public_projection_not_canonical")
    return normalized


def _validate_public_parent(
    path: Path,
    *,
    expected_owner_uid: int,
) -> int:
    if (
        not path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
    ):
        raise _error("public_projection_path_invalid")
    current = path
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise _error("public_projection_parent_unreadable") from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, expected_owner_uid}
            or info.st_mode & 0o022
        ):
            raise _error("public_projection_parent_unsafe")
        try:
            core._reject_acl_or_xattrs(
                current,
                field="public_projection_parent",
            )
        except core.QualificationAttestorError as exc:
            raise _error(exc.code) from exc
        if current == path and stat.S_IMODE(info.st_mode) != 0o755:
            raise _error("public_projection_parent_mode_invalid")
        if current.parent == current:
            break
        current = current.parent
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise _error("public_projection_parent_unreadable") from exc


def read_public_projection(
    path: Path,
    *,
    publication_owner_uid: int | None = None,
) -> dict[str, Any]:
    """Read one canonical projection through the same path policy as publish."""

    owner_uid = (
        os.geteuid()
        if publication_owner_uid is None
        else _integer(
            publication_owner_uid,
            field="public_projection_owner_uid",
        )
    )
    projection_path = Path(path)
    name = projection_path.name
    if (
        not projection_path.is_absolute()
        or "." in projection_path.parts
        or ".." in projection_path.parts
        or not name
        or name.startswith(".")
        or "/" in name
        or "\x00" in name
    ):
        raise _error("public_projection_path_invalid")
    parent_fd = _validate_public_parent(
        projection_path.parent,
        expected_owner_uid=owner_uid,
    )
    try:
        return _read_public_projection_at(
            parent_fd,
            name,
            directory_path=projection_path.parent,
            expected_owner_uid=owner_uid,
        )
    except FileNotFoundError as exc:
        raise _error("public_projection_missing") from exc
    finally:
        os.close(parent_fd)


def _repair_projection_temps(
    directory_fd: int,
    *,
    target_name: str,
    expected_owner_uid: int,
) -> None:
    prefix = f".{target_name}."
    try:
        entries = os.listdir(directory_fd)
    except OSError as exc:
        raise _error("public_projection_inventory_unreadable") from exc
    temporary = [
        name
        for name in entries
        if name.startswith(prefix) and name.endswith(".tmp")
    ]
    if len(temporary) > MAX_INTERRUPTED_PROJECTION_FILES:
        raise _error("public_projection_temp_count_invalid")
    for name in temporary:
        token = name[len(prefix) : -len(".tmp")]
        if len(token) != 32 or any(
            character not in "0123456789abcdef" for character in token
        ):
            raise _error("public_projection_temp_unsafe")
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in {0o600, 0o444}
        ):
            raise _error("public_projection_temp_unsafe")
        os.unlink(name, dir_fd=directory_fd)
    if temporary:
        os.fsync(directory_fd)


def publish_projection(
    value: Any,
    path: Path,
    *,
    expected_instance_slug: str,
    expected_key_id: str,
    expected_public_key_sha256: str,
    now_unix: int,
    publication_owner_uid: int | None = None,
) -> tuple[dict[str, Any], str]:
    """Publish only a currently valid projection under one monotonic lock."""

    projection = normalize_projection(value)
    current_time = _integer(
        now_unix,
        field="public_projection_now_unix",
    )
    owner_uid = (
        os.geteuid()
        if publication_owner_uid is None
        else _integer(
            publication_owner_uid,
            field="public_projection_owner_uid",
        )
    )
    projection_path = Path(path)
    parent_fd = _validate_public_parent(
        projection_path.parent,
        expected_owner_uid=owner_uid,
    )
    name = projection_path.name
    if (
        not name
        or name.startswith(".")
        or "/" in name
        or "\x00" in name
    ):
        os.close(parent_fd)
        raise _error("public_projection_path_invalid")
    lock_name = f".{name}.lock"
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        lock_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = -1
    try:
        lock_fd = os.open(
            lock_name,
            lock_flags,
            0o600,
            dir_fd=parent_fd,
        )
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != owner_uid
            or lock_info.st_nlink != 1
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise _error("public_projection_lock_unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _repair_projection_temps(
            parent_fd,
            target_name=name,
            expected_owner_uid=owner_uid,
        )

        slug = core._slug(
            expected_instance_slug,
            field="expected_instance_slug",
        )
        key_id = core._token(
            expected_key_id,
            field="expected_key_id",
        )
        fingerprint = core._digest(
            expected_public_key_sha256,
            field="expected_public_key_sha256",
        )
        verify_projection(
            projection,
            expected_instance_slug=slug,
            expected_key_id=key_id,
            expected_public_key_sha256=fingerprint,
            now_unix=current_time,
        )
        try:
            existing = _read_public_projection_at(
                parent_fd,
                name,
                directory_path=projection_path.parent,
                expected_owner_uid=owner_uid,
            )
        except FileNotFoundError:
            existing = None

        if existing is not None:
            existing_slug, existing_key_id, existing_fingerprint = (
                _projection_identity(existing)
            )
            if (
                existing_slug != slug
                or existing_key_id != key_id
                or not hmac.compare_digest(
                    existing_fingerprint,
                    fingerprint,
                )
            ):
                raise _error("public_projection_identity_changed")
            verify_projection(
                existing,
                expected_instance_slug=slug,
                expected_key_id=key_id,
                expected_public_key_sha256=fingerprint,
                now_unix=max(
                    existing["generated_at_unix"],
                    existing["head"]["verified_at_unix"],
                ),
            )
            previous_sequence = existing["head"]["chain_sequence"]
            next_sequence = projection["head"]["chain_sequence"]
            if (
                next_sequence == previous_sequence
                and hmac.compare_digest(
                    projection["head"]["attestation_sha256"],
                    existing["head"]["attestation_sha256"],
                )
            ):
                return existing, "idempotent"
            if next_sequence <= previous_sequence:
                raise _error("public_projection_rollback_rejected")
            if next_sequence != previous_sequence + 1:
                raise _error("public_projection_sequence_gap")
            if not hmac.compare_digest(
                projection["head"]["previous_attestation_sha256"],
                existing["head"]["attestation_sha256"],
            ):
                raise _error("public_projection_chain_broken")
            if (
                projection["head"]["qualified_at_unix"]
                <= existing["head"]["qualified_at_unix"]
                or projection["head"]["verified_at_unix"]
                <= existing["head"]["verified_at_unix"]
            ):
                raise _error("public_projection_time_rollback")

        encoded = core.canonical_json(projection) + b"\n"
        if len(encoded) > MAX_PROJECTION_BYTES:
            raise _error("public_projection_too_large")
        temp_name = f".{name}.{secrets.token_hex(16)}.tmp"
        descriptor = -1
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                temp_name,
                flags,
                0o600,
                dir_fd=parent_fd,
            )
            if os.fstat(descriptor).st_uid != owner_uid:
                raise _error("public_projection_owner_mismatch")
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise _error("public_projection_write_failed")
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o444)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temp_name,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        published = _read_public_projection_at(
            parent_fd,
            name,
            directory_path=projection_path.parent,
            expected_owner_uid=owner_uid,
        )
        if not hmac.compare_digest(
            core.canonical_json(published),
            core.canonical_json(projection),
        ):
            raise _error("public_projection_publish_mismatch")
        return published, "published"
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(parent_fd)
