#!/usr/bin/env python3
"""Crash-safe protected persona-qualification transaction coordinator.

This module contains the authority-ordering logic that joins an already
confined opaque-capture helper, the kernel-confined verifier, the single-flight
attestation signer, and the privacy-safe public trust projection.

It intentionally does not launch directly from the mutable repository.
Production activation still requires an installer-generated control binding,
dedicated identities, immutable runtime bundles, and privileged sandbox
canaries.  The public entrypoint therefore remains fail-closed while the
transaction primitive is independently testable.
"""

from __future__ import annotations

import copy
import hmac
import json
import os
import re
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

# ``-I`` intentionally removes the script directory from ``sys.path``.  The
# installed coordinator is a measured, relocated role bundle, so restore only
# that bundle root before resolving its sibling qualification modules.
BUNDLE_ROOT = Path(__file__).resolve().parents[1]
if str(BUNDLE_ROOT) not in sys.path:
    sys.path.insert(0, str(BUNDLE_ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_attestor as core,
)
from qualification_attestor import (
    john_lomein_persona_qualification_adoption_binding as adoption_binding,
)
from qualification_attestor import (
    john_lomein_persona_qualification_adoption_recovery
    as adoption_recovery,
)
from qualification_attestor import (
    john_lomein_persona_qualification_capture_adoption
    as capture_adoption,
)
from qualification_attestor import (
    john_lomein_persona_qualification_capture_plan
    as capture_plan_contract,
)
from qualification_attestor import (
    john_lomein_persona_qualification_capture_selection as capture_selection_contract,
)
from qualification_attestor import (
    john_lomein_persona_qualification_opaque_capture
    as opaque_capture,
)
from qualification_attestor import (
    john_lomein_persona_qualification_source_revalidation_binding as source_revalidation_binding,
)
from qualification_attestor import (
    john_lomein_persona_qualification_sandbox as verifier_sandbox,
)
from qualification_attestor import (
    john_lomein_persona_qualification_trust_projection as trust_projection,
)
from qualification_attestor import (
    john_lomein_persona_qualification_transaction_journal
    as transaction_journal,
)


PRODUCTION_ACTIVATION = False
RECOVERED_VERIFIER_V5_PRODUCTION_ACTIVATION = False
VERIFIER_REQUEST_SCHEMA = (
    "john-lomein.persona.operator-verifier-request.v4"
)
TRANSACTION_RESULT_SCHEMA = (
    "john-lomein.persona-qualification-protected-transaction.v3"
)
COMMITTED_CLEANUP_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-committed-cleanup-receipt.v1"
)
CLEANUP_RECONCILIATION_RESULT_SCHEMA = (
    "john-lomein.persona-qualification-cleanup-reconciliation.v1"
)
PENDING_PUBLICATION_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-pending-publication-receipt.v1"
)
PENDING_PUBLICATION_RESULT_SCHEMA = (
    "john-lomein.persona-qualification-pending-publication.v1"
)
PUBLICATION_RECONCILIATION_RESULT_SCHEMA = (
    "john-lomein.persona-qualification-publication-reconciliation.v1"
)
AMBIGUOUS_PUBLICATION_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-ambiguous-publication-receipt.v1"
)
AMBIGUOUS_PUBLICATION_RESULT_SCHEMA = (
    "john-lomein.persona-qualification-ambiguous-publication.v1"
)
BINDING_NAME_PREFIX = "persona-qualification-verifier"
OPAQUE_CAPTURE_NAME_RE = re.compile(
    r"^opaque-capture-[0-9a-f]{32}$"
)
MAX_VERIFIER_STDOUT_BYTES = 1_000_000
MAX_VERIFIER_STDERR_BYTES = 1_000_000

_PREPARED_RECOVERED_TRANSACTION_TOKEN = object()

COMMITTED_CLEANUP_RECEIPT_FIELDS = {
    "schema_version",
    "status",
    "cleanup_operation",
    "cleanup_error_code",
    "instance_slug",
    "run_id",
    "chain_sequence",
    "attestation_sha256",
    "trust_projection_sha256",
    "capture_session_id",
    "capture_adoption_receipt_sha256",
}
COMMITTED_CLEANUP_OPERATIONS = {
    "complete_publication",
    "complete_signing_and_publication",
}
PENDING_PUBLICATION_STATES = {
    "attestation_head_pending",
    "trust_projection_pending",
}
PENDING_PUBLICATION_RECEIPT_FIELDS = {
    "schema_version",
    "status",
    "publication_state",
    "reconciliation_error_code",
    "instance_slug",
    "verified_run_id",
    "requested_evidence_sha256",
    "committed_evidence_sha256",
    "requested_attestation_sha256",
    "authoritative_run_id",
    "authoritative_chain_sequence",
    "authoritative_attestation_sha256",
    "capture_session_id",
    "capture_adoption_receipt_sha256",
    "capture_cleanup_status",
    "capture_cleanup_error_code",
    "control_sha256",
    "operator_policy_sha256",
    "config_sha256",
    "public_key_sha256",
    "public_projection_path_sha256",
}
AMBIGUOUS_PUBLICATION_RECEIPT_FIELDS = {
    "schema_version",
    "status",
    "publication_state",
    "failure_error_code",
    "reconciliation_error_code",
    "instance_slug",
    "verified_run_id",
    "requested_evidence_sha256",
    "capture_session_id",
    "capture_adoption_receipt_sha256",
    "control_sha256",
    "operator_policy_sha256",
    "config_sha256",
    "public_key_sha256",
    "public_projection_path_sha256",
    "recovery_handoff_status",
    "recovery_handoff_error_code",
    "capture_recovery_handoff_sha256",
}

DERIVED_BINDING_FIELDS = {
    "verifier_bundle_sha256",
    "verification_policy_sha256",
    "operator_policy",
    "operator_policy_sha256",
}


def _error(code: str) -> core.QualificationAttestorError:
    return core.QualificationAttestorError(code)


def _path(value: Any, *, field: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise _error(f"{field}_invalid")
    raw = os.fspath(value)
    if not isinstance(raw, str):
        raise _error(f"{field}_invalid")
    try:
        normalized = Path(core._absolute_path(raw, field=field))
    except core.QualificationAttestorError:
        raise
    if str(normalized) != raw:
        raise _error(f"{field}_invalid")
    return normalized


def installed_binding_path(
    config_path: Path,
    instance_slug: str,
) -> Path:
    path = _path(config_path, field="attestor_config_path")
    slug = core._slug(instance_slug)
    return path.parent / f"{BINDING_NAME_PREFIX}.{slug}.json"


def read_root_owned_installed_binding(
    config_path: Path,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Read the strict installer-generated verifier binding."""

    normalized_config = core.normalize_config(config)
    path = installed_binding_path(
        config_path,
        normalized_config["instance_slug"],
    )
    raw = core._read_trusted_file(
        path,
        field="installed_verifier_binding",
        expected_owner_uid=0,
        maximum_bytes=core.MAX_JSON_BYTES,
        private=True,
    )
    parsed = core.parse_json_bytes(
        raw,
        field="installed_verifier_binding",
    )
    return core.normalize_installed_verifier_binding(
        parsed,
        config=normalized_config,
    )


class ProtectedCaptureSession(Protocol):
    """The coordinator-visible half of a key-denied capture helper."""

    @property
    def capture_root(self) -> Path: ...

    @property
    def capture_manifest_sha256(self) -> str: ...

    @property
    def capture_plan_sha256(self) -> str: ...

    @property
    def adoption_receipt(self) -> Mapping[str, Any]: ...

    @property
    def adoption_receipt_sha256(self) -> str: ...

    @property
    def capture_session_id(self) -> str: ...

    @property
    def capture_request_sha256(self) -> str: ...

    @property
    def capture_boundary_policy_sha256(self) -> str: ...

    @property
    def helper_activation_policy_sha256(self) -> str: ...

    def begin_verification(self) -> Any: ...

    def complete_verification(
        self,
        verifier_output_sha256: str,
    ) -> Any: ...

    def complete_signing(
        self,
        attestation_envelope_sha256: str,
    ) -> Any: ...

    def complete_publication(
        self,
        trust_projection_sha256: str,
    ) -> Any: ...

    def abort(self, reason_code: str) -> Any: ...

    def defer_publication_ambiguity(
        self,
        requested_evidence_sha256: str,
    ) -> Mapping[str, Any]: ...

    @property
    def recovery_handoff_receipt_sha256(self) -> str: ...

    def close(self) -> Any: ...


class CommittedCleanupSession(Protocol):
    """Narrow authority accepted after durable publication."""

    @property
    def capture_session_id(self) -> str: ...

    @property
    def adoption_receipt_sha256(self) -> str: ...

    def complete_publication(
        self,
        trust_projection_sha256: str,
    ) -> Any: ...

    def complete_signing(
        self,
        attestation_envelope_sha256: str,
    ) -> Any: ...


@dataclass(frozen=True)
class PreparedQualificationTransaction:
    """Fully normalized authority inputs for one helper-held capture."""

    config: dict[str, Any]
    binding: dict[str, Any]
    operator_policy: dict[str, Any]
    capture_selection: dict[str, Any]
    capture_selection_sha256: str
    capture_plan_sha256: str
    sandbox_policy: verifier_sandbox.QualificationSandboxPolicy
    public_key_bytes: bytes
    public_projection_path: Path
    control_sha256: str


class PreparedRecoveredQualificationTransaction:
    """PID-bound in-memory authority for the dormant recovered v5 route.

    The full capture plan is deliberately retained only in this process.  Its
    canonical digest is already part of the ordinary prepared controls and is
    later cross-bound by the recovered result and journal.  The route therefore
    never accepts a plan, source path, or snapshot path at effect time.
    """

    __slots__ = (
        "__prepared_json",
        "__public_key_bytes",
        "__sandbox_policy",
        "__capture_plan_json",
        "__owner_pid",
    )

    def __init__(
        self,
        *,
        _token: object,
        prepared: PreparedQualificationTransaction,
        capture_plan: Mapping[str, Any],
    ) -> None:
        if _token is not _PREPARED_RECOVERED_TRANSACTION_TOKEN:
            raise TypeError(
                "PreparedRecoveredQualificationTransaction cannot be "
                "constructed directly"
            )
        self.__prepared_json = json.dumps(
            {
                "config": prepared.config,
                "binding": prepared.binding,
                "operator_policy": prepared.operator_policy,
                "capture_selection": prepared.capture_selection,
                "capture_selection_sha256": (
                    prepared.capture_selection_sha256
                ),
                "capture_plan_sha256": prepared.capture_plan_sha256,
                "public_projection_path": str(
                    prepared.public_projection_path
                ),
                "control_sha256": prepared.control_sha256,
            },
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self.__public_key_bytes = bytes(prepared.public_key_bytes)
        self.__sandbox_policy = copy.deepcopy(
            prepared.sandbox_policy
        )
        self.__capture_plan_json = json.dumps(
            capture_plan,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self.__owner_pid = os.getpid()

    def _contents(
        self,
    ) -> tuple[PreparedQualificationTransaction, dict[str, Any]]:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "recovered_transaction_preparation_creator_process_mismatch"
            )
        try:
            raw_prepared = json.loads(
                self.__prepared_json.decode("ascii")
            )
            raw_plan = json.loads(
                self.__capture_plan_json.decode("ascii")
            )
            normalized_plan = (
                capture_plan_contract.normalize_capture_plan(raw_plan)
            )
            prepared = PreparedQualificationTransaction(
                config=raw_prepared["config"],
                binding=raw_prepared["binding"],
                operator_policy=raw_prepared["operator_policy"],
                capture_selection=raw_prepared[
                    "capture_selection"
                ],
                capture_selection_sha256=raw_prepared[
                    "capture_selection_sha256"
                ],
                capture_plan_sha256=raw_prepared[
                    "capture_plan_sha256"
                ],
                sandbox_policy=copy.deepcopy(
                    self.__sandbox_policy
                ),
                public_key_bytes=bytes(self.__public_key_bytes),
                public_projection_path=Path(
                    raw_prepared["public_projection_path"]
                ),
                control_sha256=raw_prepared["control_sha256"],
            )
        except (
            AttributeError,
            capture_plan_contract.CapturePlanError,
            KeyError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise _error(
                "recovered_transaction_preparation_invalid"
            ) from exc
        if (
            capture_plan_contract.capture_plan_sha256(
                normalized_plan
            )
            != prepared.capture_plan_sha256
        ):
            raise _error(
                "recovered_transaction_preparation_plan_changed"
            )
        return prepared, normalized_plan

    def __copy__(self) -> Any:
        raise TypeError(
            "PreparedRecoveredQualificationTransaction is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "PreparedRecoveredQualificationTransaction is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "PreparedRecoveredQualificationTransaction is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "PreparedRecoveredQualificationTransaction is not serializable"
        )


def _base_binding(
    binding: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(binding, Mapping):
        raise _error("verified_binding_not_object")
    expected = (
        set(core.INSTALLED_VERIFIER_BINDING_FIELDS)
        | DERIVED_BINDING_FIELDS
    )
    if set(binding) != expected:
        raise _error("verified_binding_fields_invalid")
    return core.normalize_installed_verifier_binding(
        {
            field: binding[field]
            for field in core.INSTALLED_VERIFIER_BINDING_FIELDS
        },
        config=config,
    )


def _validate_policy_binding(
    *,
    config: Mapping[str, Any],
    binding: Mapping[str, Any],
    policy: Mapping[str, Any],
    capture_selection_sha256: str,
) -> None:
    expected = {
        "instance_slug": config["instance_slug"],
        "expected_evidence_uid": config["expected_evidence_uid"],
        "expected_capture_uid": binding["capture_uid"],
        "expected_capture_export_gid": binding["capture_export_gid"],
        "expected_adopted_uid": 0,
        "capture_adoption_binding_schema": (
            adoption_binding.ADOPTION_BINDING_SCHEMA
        ),
        "capture_adoption_required": True,
        "instance_manifest_sha256": binding[
            "instance_manifest_sha256"
        ],
        "verifier_uid": binding["verifier_uid"],
        "verifier_gid": binding["verifier_gid"],
        "verifier_python_sha256": binding["verifier_python_sha256"],
        "verifier_bundle_sha256": binding["verifier_bundle_sha256"],
        "verifier_version": binding["verifier_version"],
        "verifier_timeout_seconds": binding[
            "verifier_timeout_seconds"
        ],
        "verification_execution_policy_sha256": core.sha256_json(
            core.VERIFICATION_EXECUTION_POLICY
        ),
        "capture_selection_sha256": capture_selection_sha256,
        "claim_strength": core.CLAIM_STRENGTH,
        "public_reputation_eligible": False,
    }
    for field, expected_value in expected.items():
        if policy[field] != expected_value:
            raise _error("operator_policy_binding_mismatch")


def _paths_overlap(left: Path, right: Path) -> bool:
    left_text = os.path.normcase(str(left).rstrip(os.sep))
    right_text = os.path.normcase(str(right).rstrip(os.sep))
    return (
        left_text == right_text
        or left_text.startswith(right_text + os.sep)
        or right_text.startswith(left_text + os.sep)
    )


def prepare_transaction(
    *,
    config: Mapping[str, Any],
    verified_binding: Mapping[str, Any],
    capture_selection: Mapping[str, Any],
    capture_plan_sha256: str,
    sandbox_policy: verifier_sandbox.QualificationSandboxPolicy,
    public_key_bytes: bytes,
    public_projection_path: Path,
) -> PreparedQualificationTransaction:
    """Normalize all static controls before the helper may expose a capture."""

    normalized_config = core.normalize_config(config)
    base_binding = _base_binding(
        verified_binding,
        config=normalized_config,
    )
    bundle_sha256 = core._digest(
        verified_binding.get("verifier_bundle_sha256"),
        field="verified_binding_bundle_sha256",
    )
    verification_policy_sha256 = core._digest(
        verified_binding.get("verification_policy_sha256"),
        field="verified_binding_policy_sha256",
    )
    operator_policy = trust_projection.normalize_operator_policy(
        verified_binding.get("operator_policy")
    )
    operator_policy_sha256 = core._digest(
        verified_binding.get("operator_policy_sha256"),
        field="verified_binding_operator_policy_sha256",
    )
    if not hmac.compare_digest(
        core.sha256_json(operator_policy),
        operator_policy_sha256,
    ):
        raise _error("operator_policy_digest_mismatch")
    normalized_binding = {
        **base_binding,
        "verifier_bundle_sha256": bundle_sha256,
        "verification_policy_sha256": verification_policy_sha256,
        "operator_policy": operator_policy,
        "operator_policy_sha256": operator_policy_sha256,
    }
    try:
        normalized_selection = (
            capture_selection_contract.normalize_capture_selection(
                capture_selection
            )
        )
        selection_sha256 = (
            capture_selection_contract.capture_selection_sha256(
                normalized_selection
            )
        )
    except capture_selection_contract.CaptureSelectionError as exc:
        raise _error(exc.code) from exc
    expected_selection_roots = {
        "instance_manifest": normalized_binding[
            "instance_manifest_path"
        ],
        "qualification_private": normalized_config[
            "qualification_private_root"
        ],
        "qualification_public": normalized_config[
            "qualification_public_root"
        ],
        "runtime": normalized_binding["runtime_identity_path"],
    }
    expected_selection_identities = {
        "evidence_home": normalized_binding["evidence_home_path"],
        "checkout": normalized_binding["checkout_identity_path"],
        "runtime": normalized_binding["runtime_identity_path"],
    }
    if (
        normalized_selection["instance_slug"]
        != normalized_config["instance_slug"]
        or normalized_selection["evidence_uid"]
        != normalized_config["expected_evidence_uid"]
        or normalized_selection["verifier_gid"]
        != normalized_binding["verifier_gid"]
        or normalized_selection["source_roots"]
        != expected_selection_roots
        or any(
            normalized_selection["path_identities"][field] != expected
            for field, expected in expected_selection_identities.items()
        )
    ):
        raise _error("capture_selection_binding_mismatch")
    _validate_policy_binding(
        config=normalized_config,
        binding=normalized_binding,
        policy=operator_policy,
        capture_selection_sha256=selection_sha256,
    )

    plan_digest = core._digest(
        capture_plan_sha256,
        field="capture_plan_sha256",
    )
    if not isinstance(
        sandbox_policy,
        verifier_sandbox.QualificationSandboxPolicy,
    ):
        raise _error("verifier_sandbox_policy_invalid")
    policy_expected = {
        "bundle_root": Path(normalized_binding["verifier_bundle_root"]),
        "bundle_sha256": normalized_binding["verifier_bundle_sha256"],
        "capture_parent": Path(
            normalized_binding["capture_parent_path"]
        ),
        "python_path": Path(normalized_binding["verifier_python_path"]),
        "entrypoint_path": Path(
            normalized_binding["verifier_entrypoint_path"]
        ),
        "verifier_uid": normalized_binding["verifier_uid"],
        "verifier_gid": normalized_binding["verifier_gid"],
        "timeout_seconds": normalized_binding[
            "verifier_timeout_seconds"
        ],
    }
    for field, expected_value in policy_expected.items():
        if getattr(sandbox_policy, field) != expected_value:
            raise _error(f"verifier_sandbox_{field}_mismatch")

    fingerprint = core.public_key_fingerprint(public_key_bytes)
    if not hmac.compare_digest(
        fingerprint,
        normalized_config["public_key_sha256"],
    ):
        raise _error("configured_public_key_fingerprint_mismatch")
    projection_path = _path(
        public_projection_path,
        field="public_projection_path",
    )
    if (
        not projection_path.name
        or projection_path.name.startswith(".")
    ):
        raise _error("public_projection_path_invalid")
    protected_paths = (
        Path(normalized_config["qualification_public_root"]),
        Path(normalized_config["qualification_private_root"]),
        Path(normalized_config["private_key_path"]),
        Path(normalized_config["public_key_path"]),
        Path(normalized_config["head_path"]),
        Path(normalized_binding["capture_parent_path"]),
        Path(normalized_binding["verifier_bundle_root"]),
        sandbox_policy.scratch_root,
        sandbox_policy.activation_receipt_path,
    )
    if any(
        _paths_overlap(projection_path, protected)
        for protected in protected_paths
    ):
        raise _error("public_projection_path_overlaps_control")

    control_record = {
        "schema_version": (
            "john-lomein.persona-qualification-controls.v1"
        ),
        "config": normalized_config,
        "installed_binding": {
            field: normalized_binding[field]
            for field in sorted(
                set(normalized_binding) - {"operator_policy"}
            )
        },
        "operator_policy": operator_policy,
        "capture_selection": normalized_selection,
        "capture_selection_sha256": selection_sha256,
        "capture_plan_sha256": plan_digest,
        "sandbox_activation_policy": (
            sandbox_policy.activation_record()
        ),
        "public_key_sha256": fingerprint,
        "public_projection_path": str(projection_path),
    }
    return PreparedQualificationTransaction(
        config=normalized_config,
        binding=normalized_binding,
        operator_policy=operator_policy,
        capture_selection=normalized_selection,
        capture_selection_sha256=selection_sha256,
        capture_plan_sha256=plan_digest,
        sandbox_policy=sandbox_policy,
        public_key_bytes=bytes(public_key_bytes),
        public_projection_path=projection_path,
        control_sha256=core.sha256_json(control_record),
    )


def _recovered_capture_plan_run_id(
    capture_plan: Mapping[str, Any],
    capture_selection: Mapping[str, Any],
) -> str:
    private_root = Path(
        capture_selection["source_roots"]["qualification_private"]
    )
    candidates = [
        source
        for source in capture_plan["sources"]
        if source["source_class"] == "qualification_private_run"
    ]
    if len(candidates) != 1:
        raise _error(
            "recovered_transaction_capture_plan_private_run_invalid"
        )
    candidate = candidates[0]
    source_path = Path(candidate["source_path"])
    run_id = source_path.name
    if (
        source_path.parent != private_root
        or candidate["kind"] != "tree"
        or candidate["destination_path"] != f"private/{run_id}"
    ):
        raise _error(
            "recovered_transaction_capture_plan_source_roots_mismatch"
        )
    return run_id


def _recompute_recovered_prepared_transaction(
    prepared: PreparedQualificationTransaction,
) -> PreparedQualificationTransaction:
    """Replay the public constructor from an isolated caller snapshot."""

    try:
        snapshot = json.loads(
            json.dumps(
                {
                    "config": prepared.config,
                    "binding": prepared.binding,
                    "operator_policy": prepared.operator_policy,
                    "capture_selection": prepared.capture_selection,
                    "capture_selection_sha256": (
                        prepared.capture_selection_sha256
                    ),
                    "capture_plan_sha256": (
                        prepared.capture_plan_sha256
                    ),
                    "control_sha256": prepared.control_sha256,
                },
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        sandbox_policy = copy.deepcopy(prepared.sandbox_policy)
        public_key_bytes = bytes(prepared.public_key_bytes)
        public_projection_path = Path(
            str(prepared.public_projection_path)
        )
    except (
        AttributeError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise _error(
            "recovered_transaction_prepared_snapshot_invalid"
        ) from exc
    claimed = PreparedQualificationTransaction(
        config=snapshot["config"],
        binding=snapshot["binding"],
        operator_policy=snapshot["operator_policy"],
        capture_selection=snapshot["capture_selection"],
        capture_selection_sha256=snapshot[
            "capture_selection_sha256"
        ],
        capture_plan_sha256=snapshot["capture_plan_sha256"],
        sandbox_policy=sandbox_policy,
        public_key_bytes=public_key_bytes,
        public_projection_path=public_projection_path,
        control_sha256=snapshot["control_sha256"],
    )
    recomputed = prepare_transaction(
        config=claimed.config,
        verified_binding=claimed.binding,
        capture_selection=claimed.capture_selection,
        capture_plan_sha256=claimed.capture_plan_sha256,
        sandbox_policy=claimed.sandbox_policy,
        public_key_bytes=claimed.public_key_bytes,
        public_projection_path=claimed.public_projection_path,
    )
    if (
        recomputed != claimed
        or not hmac.compare_digest(
            recomputed.control_sha256, claimed.control_sha256
        )
    ):
        raise _error(
            "recovered_transaction_prepared_recomputation_mismatch"
        )
    return recomputed


def prepare_recovered_transaction(
    prepared: PreparedQualificationTransaction,
    *,
    capture_plan: Mapping[str, Any],
) -> PreparedRecoveredQualificationTransaction:
    """Seal a digest- and selector-bound plan for the dormant v5 route."""

    if type(prepared) is not PreparedQualificationTransaction:
        raise _error("prepared_transaction_invalid")
    recomputed = _recompute_recovered_prepared_transaction(prepared)
    try:
        normalized_plan = capture_plan_contract.normalize_capture_plan(
            capture_plan
        )
        plan_sha256 = capture_plan_contract.capture_plan_sha256(
            normalized_plan
        )
    except capture_plan_contract.CapturePlanError as exc:
        raise _error(exc.code) from exc
    selection = recomputed.capture_selection
    if (
        normalized_plan["instance_slug"]
        != recomputed.config["instance_slug"]
        or normalized_plan["evidence_uid"]
        != recomputed.config["expected_evidence_uid"]
        or normalized_plan["verifier_gid"]
        != recomputed.binding["verifier_gid"]
        or normalized_plan["limits"] != selection["limits"]
        or normalized_plan["lifecycle"] != selection["lifecycle"]
    ):
        raise _error(
            "recovered_transaction_capture_plan_identity_mismatch"
        )
    run_id = _recovered_capture_plan_run_id(
        normalized_plan, selection
    )
    try:
        expected_plan, selection_plan_sha256 = (
            capture_selection_contract.validate_concrete_capture_plan(
                selection,
                normalized_plan,
                run_id,
            )
        )
    except capture_selection_contract.CaptureSelectionError as exc:
        raise _error(exc.code) from exc
    if (
        expected_plan != normalized_plan
        or not hmac.compare_digest(
            plan_sha256, selection_plan_sha256
        )
        or not hmac.compare_digest(
            plan_sha256, recomputed.capture_plan_sha256
        )
    ):
        raise _error(
            "recovered_transaction_capture_plan_digest_mismatch"
        )
    return PreparedRecoveredQualificationTransaction(
        _token=_PREPARED_RECOVERED_TRANSACTION_TOKEN,
        prepared=recomputed,
        capture_plan=normalized_plan,
    )


def _validate_session(
    prepared: PreparedQualificationTransaction,
    session: ProtectedCaptureSession,
) -> tuple[Path, str, dict[str, Any], str]:
    try:
        capture_root = _path(
            session.capture_root,
            field="capture_helper_root",
        )
        manifest_sha256 = core._digest(
            session.capture_manifest_sha256,
            field="capture_helper_manifest_sha256",
        )
        plan_sha256 = core._digest(
            session.capture_plan_sha256,
            field="capture_helper_plan_sha256",
        )
        adoption_receipt = adoption_binding.normalize_adoption_receipt(
            session.adoption_receipt
        )
        adoption_receipt_sha256 = core._digest(
            session.adoption_receipt_sha256,
            field="capture_helper_adoption_receipt_sha256",
        )
        capture_session_id = session.capture_session_id
        capture_request_sha256 = core._digest(
            session.capture_request_sha256,
            field="capture_helper_request_sha256",
        )
        capture_boundary_policy_sha256 = core._digest(
            session.capture_boundary_policy_sha256,
            field="capture_helper_boundary_policy_sha256",
        )
        helper_activation_policy_sha256 = core._digest(
            session.helper_activation_policy_sha256,
            field="capture_helper_activation_policy_sha256",
        )
    except AttributeError as exc:
        raise _error("capture_helper_session_invalid") from exc
    except adoption_binding.CaptureAdoptionBindingError as exc:
        raise _error(exc.code) from exc
    capture_parent = Path(
        prepared.binding["capture_parent_path"]
    )
    if (
        capture_root.parent != capture_parent
        or not OPAQUE_CAPTURE_NAME_RE.fullmatch(capture_root.name)
    ):
        raise _error("capture_helper_root_binding_mismatch")
    if not hmac.compare_digest(
        plan_sha256,
        prepared.capture_plan_sha256,
    ):
        raise _error("capture_helper_plan_digest_mismatch")
    try:
        observed_receipt_sha256 = (
            adoption_binding.adoption_receipt_sha256(
                adoption_receipt
            )
        )
    except adoption_binding.CaptureAdoptionBindingError as exc:
        raise _error(exc.code) from exc
    if not hmac.compare_digest(
        adoption_receipt_sha256,
        observed_receipt_sha256,
    ):
        raise _error("capture_helper_adoption_receipt_digest_mismatch")
    receipt_expected = {
        "capture_uid": prepared.binding["capture_uid"],
        "capture_gid": prepared.binding["capture_export_gid"],
        "adopted_uid": 0,
        "verifier_uid": prepared.binding["verifier_uid"],
        "verifier_gid": prepared.binding["verifier_gid"],
        "capture_selection_sha256": (
            prepared.capture_selection_sha256
        ),
        "capture_plan_sha256": prepared.capture_plan_sha256,
        "capture_manifest_sha256": manifest_sha256,
        "final_name": capture_root.name,
        "session_id": capture_session_id,
        "request_sha256": capture_request_sha256,
        "capture_boundary_policy_sha256": (
            capture_boundary_policy_sha256
        ),
        "helper_activation_policy_sha256": (
            helper_activation_policy_sha256
        ),
    }
    for field, expected_value in receipt_expected.items():
        if adoption_receipt[field] != expected_value:
            raise _error(
                f"capture_helper_adoption_receipt_{field}_mismatch"
            )
    sandbox_policy = prepared.sandbox_policy
    if (
        sandbox_policy.capture_root != capture_root
        or sandbox_policy.capture_parent != capture_parent
    ):
        raise _error("capture_helper_sandbox_binding_mismatch")
    return (
        capture_root,
        manifest_sha256,
        adoption_receipt,
        adoption_receipt_sha256,
    )


def build_verifier_request(
    prepared: PreparedQualificationTransaction,
    session: ProtectedCaptureSession,
    *,
    verified_at_unix: int,
) -> dict[str, Any]:
    """Build the only path-bearing request accepted by verifier v4."""

    (
        capture_root,
        manifest_sha256,
        adoption_receipt,
        adoption_receipt_sha256,
    ) = _validate_session(
        prepared,
        session,
    )
    verified_at = core._integer(
        verified_at_unix,
        field="qualification_transaction_verified_at_unix",
        minimum=1,
    )
    binding = prepared.binding
    config = prepared.config
    return {
        "schema_version": VERIFIER_REQUEST_SCHEMA,
        "snapshot_root": str(capture_root),
        "capture_manifest_sha256": manifest_sha256,
        "capture_plan_sha256": prepared.capture_plan_sha256,
        "capture_selection": prepared.capture_selection,
        "capture_selection_sha256": (
            prepared.capture_selection_sha256
        ),
        "capture_adoption_receipt": adoption_receipt,
        "capture_adoption_receipt_sha256": (
            adoption_receipt_sha256
        ),
        "capture_session_id": adoption_receipt["session_id"],
        "capture_request_sha256": adoption_receipt["request_sha256"],
        "capture_boundary_policy_sha256": adoption_receipt[
            "capture_boundary_policy_sha256"
        ],
        "capture_helper_activation_policy_sha256": adoption_receipt[
            "helper_activation_policy_sha256"
        ],
        "capture_uid": binding["capture_uid"],
        "capture_export_gid": binding["capture_export_gid"],
        "adopted_uid": 0,
        "instance_manifest_path": binding["instance_manifest_path"],
        "instance_manifest_sha256": binding[
            "instance_manifest_sha256"
        ],
        "qualification_private_root": config[
            "qualification_private_root"
        ],
        "qualification_public_root": config[
            "qualification_public_root"
        ],
        "evidence_home_path": binding["evidence_home_path"],
        "checkout_identity_path": binding["checkout_identity_path"],
        "runtime_identity_path": binding["runtime_identity_path"],
        "instance_slug": config["instance_slug"],
        "evidence_uid": config["expected_evidence_uid"],
        "verifier_uid": binding["verifier_uid"],
        "verifier_gid": binding["verifier_gid"],
        "verifier_bundle_sha256": binding[
            "verifier_bundle_sha256"
        ],
        "verification_policy_sha256": binding[
            "verification_policy_sha256"
        ],
        "operator_policy_sha256": binding[
            "operator_policy_sha256"
        ],
        "verified_at_unix": verified_at,
    }


def _parse_verifier_result(
    result: Any,
) -> tuple[dict[str, Any], str]:
    try:
        stdout = result.stdout
        stderr = result.stderr
        returncode = result.returncode
    except AttributeError as exc:
        raise _error("verifier_sandbox_result_invalid") from exc
    if (
        not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or type(returncode) is not int
    ):
        raise _error("verifier_sandbox_result_invalid")
    if len(stdout) > MAX_VERIFIER_STDOUT_BYTES:
        raise _error("verifier_stdout_too_large")
    if len(stderr) > MAX_VERIFIER_STDERR_BYTES:
        raise _error("verifier_stderr_too_large")
    if returncode != 0:
        raise _error("verifier_child_rejected")
    if stderr:
        raise _error("verifier_child_stderr_not_empty")
    wrapper = core._mapping(
        core.parse_json_bytes(
            stdout,
            field="verifier_output",
            maximum_bytes=MAX_VERIFIER_STDOUT_BYTES,
        ),
        field="verifier_output",
    )
    core._strict_fields(
        wrapper,
        field="verifier_output",
        expected={"schema_version", "status", "evidence"},
    )
    if (
        wrapper.get("schema_version") != core.VERIFIER_OUTPUT_SCHEMA
        or wrapper.get("status") != "verified"
    ):
        raise _error("verifier_output_status_invalid")
    if stdout != core.canonical_json(wrapper) + b"\n":
        raise _error("verifier_output_noncanonical")
    evidence = core._mapping(
        wrapper.get("evidence"),
        field="verifier_evidence",
    )
    return evidence, core.sha256_bytes(stdout)


def _assert_evidence_binding(
    prepared: PreparedQualificationTransaction,
    session: ProtectedCaptureSession,
    evidence: Any,
    *,
    verified_at_unix: int,
) -> dict[str, Any]:
    normalized = core.normalize_verifier_evidence(
        evidence,
        expected_evidence_uid=prepared.config[
            "expected_evidence_uid"
        ],
    )
    try:
        adoption_receipt = adoption_binding.normalize_adoption_receipt(
            session.adoption_receipt
        )
        adoption_receipt_sha256 = (
            adoption_binding.adoption_receipt_sha256(
                adoption_receipt
            )
        )
    except adoption_binding.CaptureAdoptionBindingError as exc:
        raise _error(exc.code) from exc
    expected = {
        "status": "qualified",
        "verifier_version": prepared.binding["verifier_version"],
        "verifier_uid": prepared.binding["verifier_uid"],
        "verifier_bundle_sha256": prepared.binding[
            "verifier_bundle_sha256"
        ],
        "verification_policy_sha256": prepared.binding[
            "verification_policy_sha256"
        ],
        "capture_manifest_sha256": core._digest(
            session.capture_manifest_sha256,
            field="capture_helper_manifest_sha256",
        ),
        "capture_plan_sha256": prepared.capture_plan_sha256,
        "operator_policy_sha256": prepared.binding[
            "operator_policy_sha256"
        ],
        "claim_strength": core.CLAIM_STRENGTH,
        "public_reputation_eligible": False,
        "verified_at_unix": verified_at_unix,
        "observed_evidence_uid": prepared.config[
            "expected_evidence_uid"
        ],
        "capture_creator_uid": prepared.binding["capture_uid"],
        "capture_export_gid": prepared.binding["capture_export_gid"],
        "capture_adopted_uid": 0,
        "capture_adoption_receipt_sha256": (
            adoption_receipt_sha256
        ),
        "capture_adoption_policy_sha256": adoption_receipt[
            "capture_adoption_policy_sha256"
        ],
        "capture_object_identity_sha256": adoption_receipt[
            "object_identity_sha256"
        ],
        "capture_content_inventory_sha256": adoption_receipt[
            "content_inventory_sha256"
        ],
        "capture_adopted_at_unix": adoption_receipt[
            "adopted_at_unix"
        ],
        "capture_request_sha256": adoption_receipt[
            "request_sha256"
        ],
        "capture_boundary_policy_sha256": adoption_receipt[
            "capture_boundary_policy_sha256"
        ],
        "capture_helper_activation_policy_sha256": adoption_receipt[
            "helper_activation_policy_sha256"
        ],
    }
    for field, expected_value in expected.items():
        if normalized[field] != expected_value:
            raise _error(f"verifier_output_{field}_mismatch")
    return normalized


def _bind_source_revalidation_receipt(
    prepared: PreparedQualificationTransaction,
    verifier_evidence: Mapping[str, Any],
    receipt_value: Any,
    *,
    verifier_output_sha256: str,
) -> dict[str, Any]:
    """Join root-only post-verifier evidence to canonical verifier output."""

    output_sha256 = core._digest(
        verifier_output_sha256,
        field="verifier_output_sha256",
    )
    try:
        receipt = (
            source_revalidation_binding.normalize_source_revalidation_receipt(
                receipt_value
            )
        )
        receipt_sha256 = (
            source_revalidation_binding.source_revalidation_receipt_sha256(
                receipt
            )
        )
        bound_receipt = (
            source_revalidation_binding.bind_source_revalidation_receipt(
                receipt,
                expected_receipt_sha256=receipt_sha256,
                expected_capture_adoption_receipt_sha256=(
                    verifier_evidence[
                        "capture_adoption_receipt_sha256"
                    ]
                ),
                expected_capture_object_identity_sha256=(
                    verifier_evidence[
                        "capture_object_identity_sha256"
                    ]
                ),
                expected_capture_plan_sha256=verifier_evidence[
                    "capture_plan_sha256"
                ],
                expected_capture_manifest_sha256=verifier_evidence[
                    "capture_manifest_sha256"
                ],
                expected_verifier_output_sha256=output_sha256,
                verified_at_unix=verifier_evidence[
                    "verified_at_unix"
                ],
                expires_at_unix=verifier_evidence[
                    "expires_at_unix"
                ],
            )
        )
    except source_revalidation_binding.SourceRevalidationBindingError as exc:
        raise _error(exc.code) from exc
    return core.normalize_verified_evidence(
        {
            **dict(verifier_evidence),
            **bound_receipt,
        },
        expected_evidence_uid=prepared.config[
            "expected_evidence_uid"
        ],
    )


def _control_revalidation(
    prepared: PreparedQualificationTransaction,
    revalidate_controls: Callable[[], str],
) -> None:
    if not callable(revalidate_controls):
        raise _error("control_revalidator_invalid")
    observed = core._digest(
        revalidate_controls(),
        field="revalidated_controls_sha256",
    )
    if not hmac.compare_digest(
        observed,
        prepared.control_sha256,
    ):
        raise _error("qualification_controls_changed_during_run")


def _clock_value(clock: Callable[[], int], *, field: str) -> int:
    if not callable(clock):
        raise _error("qualification_clock_invalid")
    return core._integer(clock(), field=field, minimum=1)


def _recovered_snapshot_root(
    prepared: PreparedQualificationTransaction,
    lease: adoption_recovery.RecoveredAdoptedCaptureLeaseV2,
) -> Path:
    final_name = lease.final_name
    if not OPAQUE_CAPTURE_NAME_RE.fullmatch(final_name):
        raise _error("recovered_transaction_final_name_invalid")
    capture_parent = Path(prepared.binding["capture_parent_path"])
    snapshot_root = capture_parent / final_name
    if (
        snapshot_root.parent != capture_parent
        or prepared.sandbox_policy.capture_root != snapshot_root
        or prepared.sandbox_policy.capture_parent != capture_parent
    ):
        raise _error(
            "recovered_transaction_snapshot_binding_mismatch"
        )
    return snapshot_root


def _assert_recovered_ack_binding(
    prepared: PreparedQualificationTransaction,
    lease: adoption_recovery.RecoveredAdoptedCaptureLeaseV2,
    session: transaction_journal.TransactionJournalSession,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        normalized = (
            adoption_recovery
            .normalize_recovered_adoption_lease_binding_v2(binding)
        )
    except adoption_recovery.RecoveredAdoptionRecoveryError as exc:
        raise _error(exc.code) from exc
    head = session.latest_record
    if (
        session.state != "staging_tombstone_acked"
        or head.state != "staging_tombstone_acked"
        or not hmac.compare_digest(
            head.to_dict()["control_sha256"],
            prepared.control_sha256,
        )
        or "recovered_adoption_continuation" not in head.details
        or normalized["transaction_journal_head_state"]
        != "staging_tombstone_acked"
        or normalized["transaction_journal_head_revision"]
        != head.revision
        or not hmac.compare_digest(
            normalized["transaction_journal_head_record_sha256"],
            head.record_sha256,
        )
        or not hmac.compare_digest(
            normalized["staging_tombstone_acked_record_sha256"],
            head.record_sha256,
        )
        or not hmac.compare_digest(
            normalized["capture_session_id"],
            session.session_id,
        )
        or not hmac.compare_digest(
            lease.capture_session_id,
            session.session_id,
        )
    ):
        raise _error(
            "recovered_transaction_enriched_ack_binding_mismatch"
        )
    result = lease.capture_adoption_result
    recovered = result["evidence"]
    expected = {
        "instance_slug": prepared.config["instance_slug"],
        "capture_uid": prepared.binding["capture_uid"],
        "capture_export_gid": prepared.binding[
            "capture_export_gid"
        ],
        "verifier_gid": prepared.binding["verifier_gid"],
        "capture_selection_sha256": (
            prepared.capture_selection_sha256
        ),
        "capture_plan_sha256": prepared.capture_plan_sha256,
    }
    for field, expected_value in expected.items():
        if recovered[field] != expected_value:
            raise _error(
                f"recovered_transaction_result_{field}_mismatch"
            )
    if (
        recovered["final_name"] != lease.final_name
        or recovered["final_object_owner_uid"] != 0
        or recovered["final_object_group_gid"]
        != prepared.binding["verifier_gid"]
        or recovered["adoption_limits"]
        != prepared.capture_selection["limits"]
    ):
        raise _error(
            "recovered_transaction_result_object_binding_mismatch"
        )
    return normalized


def _build_recovered_verifier_request_v5(
    prepared: PreparedQualificationTransaction,
    lease: adoption_recovery.RecoveredAdoptedCaptureLeaseV2,
    snapshot_root: Path,
    *,
    expected_run_id: str,
    verified_at_unix: int,
) -> dict[str, Any]:
    result = lease.capture_adoption_result
    recovered = result["evidence"]
    return {
        "schema_version": transaction_journal.VERIFIER_REQUEST_V5_SCHEMA,
        "snapshot_root": str(snapshot_root),
        "capture_manifest_sha256": recovered[
            "capture_manifest_sha256"
        ],
        "capture_plan_sha256": prepared.capture_plan_sha256,
        "capture_selection": prepared.capture_selection,
        "capture_selection_sha256": (
            prepared.capture_selection_sha256
        ),
        "capture_adoption_result": result,
        "capture_adoption_result_sha256": (
            lease.capture_adoption_result_sha256
        ),
        "capture_adoption_policy_sha256": recovered[
            "capture_adoption_policy_sha256"
        ],
        "adoption_verifier_limits": recovered["adoption_limits"],
        "capture_session_id": lease.capture_session_id,
        "capture_request_sha256": recovered[
            "capture_request_sha256"
        ],
        "capture_boundary_policy_sha256": recovered[
            "capture_boundary_policy_sha256"
        ],
        "capture_helper_activation_policy_sha256": recovered[
            "helper_activation_policy_sha256"
        ],
        "expected_run_id": expected_run_id,
        "capture_uid": prepared.binding["capture_uid"],
        "capture_export_gid": prepared.binding["capture_export_gid"],
        "adopted_uid": 0,
        "instance_manifest_path": prepared.binding[
            "instance_manifest_path"
        ],
        "instance_manifest_sha256": prepared.binding[
            "instance_manifest_sha256"
        ],
        "qualification_private_root": prepared.config[
            "qualification_private_root"
        ],
        "qualification_public_root": prepared.config[
            "qualification_public_root"
        ],
        "evidence_home_path": prepared.binding[
            "evidence_home_path"
        ],
        "checkout_identity_path": prepared.binding[
            "checkout_identity_path"
        ],
        "runtime_identity_path": prepared.binding[
            "runtime_identity_path"
        ],
        "instance_slug": prepared.config["instance_slug"],
        "evidence_uid": prepared.config["expected_evidence_uid"],
        "verifier_uid": prepared.binding["verifier_uid"],
        "verifier_gid": prepared.binding["verifier_gid"],
        "verifier_bundle_sha256": prepared.binding[
            "verifier_bundle_sha256"
        ],
        "verification_policy_sha256": prepared.binding[
            "verification_policy_sha256"
        ],
        "operator_policy_sha256": prepared.binding[
            "operator_policy_sha256"
        ],
        "verified_at_unix": verified_at_unix,
    }


def _parse_recovered_verifier_v5_result(
    result: Any,
    *,
    expected_evidence_uid: int,
) -> tuple[dict[str, Any], str]:
    try:
        stdout = result.stdout
        stderr = result.stderr
        returncode = result.returncode
    except AttributeError as exc:
        raise _error("recovered_verifier_v5_result_invalid") from exc
    if (
        not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or type(returncode) is not int
    ):
        raise _error("recovered_verifier_v5_result_invalid")
    if (
        len(stdout)
        > transaction_journal.MAX_RECOVERED_VERIFIER_OUTPUT_BYTES
        + 1
    ):
        raise _error("recovered_verifier_v5_stdout_too_large")
    if len(stderr) > MAX_VERIFIER_STDERR_BYTES:
        raise _error("recovered_verifier_v5_stderr_too_large")
    if returncode != 0:
        raise _error("recovered_verifier_v5_child_rejected")
    if stderr:
        raise _error("recovered_verifier_v5_stderr_not_empty")
    parsed = core._mapping(
        core.parse_json_bytes(
            stdout,
            field="recovered_verifier_v5_output",
            maximum_bytes=(
                transaction_journal
                .MAX_RECOVERED_VERIFIER_OUTPUT_BYTES
                + 1
            ),
        ),
        field="recovered_verifier_v5_output",
    )
    try:
        normalized = transaction_journal.normalize_verifier_output_v4(
            parsed,
            expected_evidence_uid=expected_evidence_uid,
        )
        output_sha256 = (
            transaction_journal.verifier_output_v4_sha256(
                normalized,
                expected_evidence_uid=expected_evidence_uid,
            )
        )
    except transaction_journal.TransactionJournalError as exc:
        raise _error(exc.code) from exc
    if stdout != core.canonical_json(normalized) + b"\n":
        raise _error("recovered_verifier_v5_output_noncanonical")
    return normalized, output_sha256


def _assert_recovered_verifier_output_binding(
    prepared: PreparedQualificationTransaction,
    lease: adoption_recovery.RecoveredAdoptedCaptureLeaseV2,
    request: Mapping[str, Any],
    output: Mapping[str, Any],
) -> dict[str, Any]:
    evidence = dict(output["evidence"])
    recovered = lease.capture_adoption_result["evidence"]
    provenance = lease.capture_adoption_provenance
    expected = {
        "run_id": request["expected_run_id"],
        "verifier_version": transaction_journal.VERIFIER_V5_VERSION,
        "verifier_uid": request["verifier_uid"],
        "verifier_bundle_sha256": request[
            "verifier_bundle_sha256"
        ],
        "verification_policy_sha256": request[
            "verification_policy_sha256"
        ],
        "capture_manifest_sha256": request[
            "capture_manifest_sha256"
        ],
        "capture_plan_sha256": request["capture_plan_sha256"],
        "operator_policy_sha256": request[
            "operator_policy_sha256"
        ],
        "verified_at_unix": request["verified_at_unix"],
        "observed_evidence_uid": request["evidence_uid"],
        "capture_creator_uid": request["capture_uid"],
        "capture_export_gid": request["capture_export_gid"],
        "capture_adopted_uid": 0,
        "capture_adoption_policy_sha256": recovered[
            "capture_adoption_policy_sha256"
        ],
        "capture_object_identity_sha256": recovered[
            "capture_object_identity_sha256"
        ],
        "capture_content_inventory_sha256": recovered[
            "reconciled_content_inventory_sha256"
        ],
        "capture_request_sha256": recovered[
            "capture_request_sha256"
        ],
        "capture_boundary_policy_sha256": recovered[
            "capture_boundary_policy_sha256"
        ],
        "capture_helper_activation_policy_sha256": recovered[
            "helper_activation_policy_sha256"
        ],
        "capture_adoption_provenance": provenance,
        "capture_adoption_provenance_sha256": (
            lease.capture_adoption_provenance_sha256
        ),
    }
    for field, expected_value in expected.items():
        if evidence[field] != expected_value:
            raise _error(
                f"recovered_verifier_v5_output_{field}_mismatch"
            )
    if (
        evidence["claim_strength"]
        != transaction_journal.VERIFIER_CLAIM_STRENGTH
        or evidence["public_reputation_eligible"] is not False
        or evidence["observed_evidence_uid"]
        != prepared.config["expected_evidence_uid"]
    ):
        raise _error("recovered_verifier_v5_output_claim_invalid")
    return evidence


def _revalidate_recovered_live_sources(
    prepared: PreparedQualificationTransaction,
    capture_plan: Mapping[str, Any],
    lease: adoption_recovery.RecoveredAdoptedCaptureLeaseV2,
    snapshot_root: Path,
) -> None:
    recovered = lease.capture_adoption_result["evidence"]
    try:
        opaque_capture.revalidate_live_opaque_sources(
            snapshot_root,
            plan=capture_plan,
            expected_plan_sha256=prepared.capture_plan_sha256,
            expected_capture_uid=0,
            expected_verifier_gid=prepared.binding["verifier_gid"],
            expected_manifest_sha256=recovered[
                "capture_manifest_sha256"
            ],
            expected_manifest_capture_uid=prepared.binding[
                "capture_uid"
            ],
            expected_snapshot_gid=prepared.binding["verifier_gid"],
            expected_directory_mode=(
                capture_adoption.ADOPTED_DIRECTORY_MODE
            ),
            expected_file_mode=capture_adoption.ADOPTED_FILE_MODE,
            source_gid=prepared.binding["capture_export_gid"],
            source_directory_mode=(
                opaque_capture.EXPORT_SOURCE_DIRECTORY_MODE
            ),
            source_file_mode=opaque_capture.EXPORT_SOURCE_FILE_MODE,
        )
    except opaque_capture.OpaqueCaptureError as exc:
        raise _error(exc.code) from exc


def _build_recovered_source_revalidation_receipt_v2(
    lease: adoption_recovery.RecoveredAdoptedCaptureLeaseV2,
    verifier_evidence: Mapping[str, Any],
    *,
    verifier_output_sha256: str,
    revalidated_at_unix: int,
) -> dict[str, Any]:
    receipt = {
        "schema_version": (
            source_revalidation_binding
            .SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA
        ),
        "status": (
            source_revalidation_binding.SOURCE_REVALIDATION_STATUS
        ),
        "capture_adoption_provenance": (
            lease.capture_adoption_provenance
        ),
        "capture_adoption_provenance_sha256": (
            lease.capture_adoption_provenance_sha256
        ),
        "capture_object_identity_sha256": verifier_evidence[
            "capture_object_identity_sha256"
        ],
        "capture_plan_sha256": verifier_evidence[
            "capture_plan_sha256"
        ],
        "capture_manifest_sha256": verifier_evidence[
            "capture_manifest_sha256"
        ],
        "verifier_output_sha256": verifier_output_sha256,
        "revalidator_uid": 0,
        "revalidated_at_unix": revalidated_at_unix,
    }
    try:
        return (
            source_revalidation_binding
            .normalize_source_revalidation_receipt_v2(receipt)
        )
    except (
        source_revalidation_binding.SourceRevalidationBindingError
    ) as exc:
        raise _error(exc.code) from exc


def _cancel_recovered_verifier_operation(
    session: transaction_journal.TransactionJournalSession,
    operation: (
        transaction_journal.RecoveredVerifierSourceEvidenceOperation
    ),
) -> BaseException | None:
    try:
        operation.cancel()
    except BaseException as exc:
        try:
            session._cancel_recovered_verifier_operation(operation)
        except BaseException:
            pass
        return exc
    return None


def _assert_clearance_prepared_binding(
    prepared: PreparedQualificationTransaction,
    session: transaction_journal.TransactionJournalSession,
    clearance: transaction_journal.RecoveredVerifiedEvidenceV6Clearance,
    *,
    expected_run_id: str,
) -> dict[str, Any]:
    if (
        clearance.head_state
        != "live_revalidation_receipt_complete"
        or session.state != "live_revalidation_receipt_complete"
        or session.latest_record.to_dict()["instance_slug"]
        != prepared.config["instance_slug"]
        or not hmac.compare_digest(
            session.latest_record.to_dict()["control_sha256"],
            prepared.control_sha256,
        )
    ):
        raise _error(
            "recovered_verifier_v5_clearance_head_invalid"
        )
    raw_evidence = clearance.verified_evidence_v6
    normalized = core.normalize_verified_evidence_v6(
        raw_evidence,
        expected_evidence_uid=prepared.config[
            "expected_evidence_uid"
        ],
    )
    expected = {
        "run_id": expected_run_id,
        "verifier_version": transaction_journal.VERIFIER_V5_VERSION,
        "verifier_uid": prepared.binding["verifier_uid"],
        "verifier_bundle_sha256": prepared.binding[
            "verifier_bundle_sha256"
        ],
        "verification_policy_sha256": prepared.binding[
            "verification_policy_sha256"
        ],
        "capture_plan_sha256": prepared.capture_plan_sha256,
        "operator_policy_sha256": prepared.binding[
            "operator_policy_sha256"
        ],
        "observed_evidence_uid": prepared.config[
            "expected_evidence_uid"
        ],
        "capture_creator_uid": prepared.binding["capture_uid"],
        "capture_export_gid": prepared.binding["capture_export_gid"],
        "capture_adopted_uid": 0,
    }
    for field, expected_value in expected.items():
        if normalized[field] != expected_value:
            raise _error(
                f"recovered_verifier_v5_clearance_{field}_mismatch"
            )
    observed_sha256 = (
        transaction_journal.recovered_verified_evidence_v6_sha256(
            raw_evidence,
            expected_evidence_uid=prepared.config[
                "expected_evidence_uid"
            ],
            expected_verifier_output_sha256=(
                clearance.recovered_verifier_source_evidence[
                    "verifier_output_v4_sha256"
                ]
            ),
        )
    )
    if not hmac.compare_digest(
        observed_sha256, clearance.verified_evidence_v6_sha256
    ):
        raise _error(
            "recovered_verifier_v5_clearance_digest_mismatch"
        )
    return normalized


def _resume_recovered_verifier_to_complete(
    prepared: PreparedQualificationTransaction,
    session: transaction_journal.TransactionJournalSession,
    *,
    expected_run_id: str,
) -> dict[str, Any]:
    allowed = {
        "verifier_output_bound",
        "live_revalidation_started",
        "live_revalidation_receipt_complete",
    }
    clearance = session.recover_recovered_verified_evidence_v6()
    if clearance.head_state not in allowed:
        raise _error(
            "recovered_verifier_v5_resume_head_invalid"
        )
    for _unused in range(2):
        if clearance.head_state == "live_revalidation_receipt_complete":
            break
        clearance = (
            session.advance_recovered_verifier_source_evidence()
        )
    clearance = session.recover_recovered_verified_evidence_v6()
    return _assert_clearance_prepared_binding(
        prepared,
        session,
        clearance,
        expected_run_id=expected_run_id,
    )


def resume_recovered_adoption_verifier_v5(
    prepared_recovered: PreparedRecoveredQualificationTransaction,
    journal_session: transaction_journal.TransactionJournalSession,
) -> dict[str, Any]:
    """Resume only already-durable recovered v6 evidence projections."""

    if type(prepared_recovered) is not (
        PreparedRecoveredQualificationTransaction
    ):
        raise _error("recovered_transaction_preparation_required")
    if type(journal_session) is not (
        transaction_journal.TransactionJournalSession
    ):
        raise _error("recovered_transaction_journal_session_required")
    prepared, capture_plan = prepared_recovered._contents()
    expected_run_id = _recovered_capture_plan_run_id(
        capture_plan, prepared.capture_selection
    )
    try:
        return _resume_recovered_verifier_to_complete(
            prepared,
            journal_session,
            expected_run_id=expected_run_id,
        )
    except transaction_journal.TransactionJournalError as exc:
        raise _error(exc.code) from exc


def run_recovered_adoption_verifier_v5(
    prepared_recovered: PreparedRecoveredQualificationTransaction,
    lease: adoption_recovery.RecoveredAdoptedCaptureLeaseV2,
    journal_session: transaction_journal.TransactionJournalSession,
    *,
    verifier_v5_launcher: Callable[[Mapping[str, Any]], Any] | None = None,
    revalidate_controls: Callable[[], str],
    clock: Callable[[], int] = lambda: int(time.time()),
) -> dict[str, Any]:
    """Run the dormant recovered verifier-v5 path without signing.

    The installed executable still speaks request-v4/output-v3, so this route
    has no default launcher and production activation remains false.  A crash
    before the path-free journal commit may safely repeat read-only work; a
    crash after it must use ``resume_recovered_adoption_verifier_v5`` and can
    never relaunch the verifier or reopen a source path.
    """

    if type(prepared_recovered) is not (
        PreparedRecoveredQualificationTransaction
    ):
        raise _error("recovered_transaction_preparation_required")
    if type(lease) is not (
        adoption_recovery.RecoveredAdoptedCaptureLeaseV2
    ):
        raise _error("recovered_transaction_lease_v2_required")
    if type(journal_session) is not (
        transaction_journal.TransactionJournalSession
    ):
        raise _error("recovered_transaction_journal_session_required")
    if verifier_v5_launcher is None:
        raise _error("recovered_verifier_v5_not_installed")
    if not callable(verifier_v5_launcher):
        raise _error("recovered_verifier_v5_launcher_invalid")
    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("recovered_verifier_v5_requires_root")

    prepared, capture_plan = prepared_recovered._contents()
    expected_run_id = _recovered_capture_plan_run_id(
        capture_plan, prepared.capture_selection
    )
    operation: (
        transaction_journal.RecoveredVerifierSourceEvidenceOperation
        | None
    ) = None
    committed = False
    try:
        operation = (
            journal_session.begin_recovered_verifier_source_evidence()
        )
        pre_binding = lease.pre_verifier_revalidate()
        _assert_recovered_ack_binding(
            prepared, lease, journal_session, pre_binding
        )
        snapshot_root = _recovered_snapshot_root(prepared, lease)
        _control_revalidation(prepared, revalidate_controls)
        verified_at = _clock_value(
            clock,
            field="recovered_verifier_v5_verification_clock",
        )
        if verified_at < journal_session.latest_record.recorded_at_unix:
            raise _error(
                "recovered_verifier_v5_clock_precedes_ack"
            )
        request = _build_recovered_verifier_request_v5(
            prepared,
            lease,
            snapshot_root,
            expected_run_id=expected_run_id,
            verified_at_unix=verified_at,
        )
        try:
            request = (
                transaction_journal
                ._normalize_verifier_request_v5_for_recovered_evidence(
                    request
                )
            )
        except transaction_journal.TransactionJournalError as exc:
            raise _error(exc.code) from exc
        request_canonical = core.canonical_json(request)
        launcher_request = json.loads(
            request_canonical.decode("ascii")
        )
        try:
            verifier_result = verifier_v5_launcher(launcher_request)
        except verifier_sandbox.QualificationSandboxError as exc:
            raise _error(exc.code) from exc
        try:
            launcher_request_after = core.canonical_json(
                launcher_request
            )
        except core.QualificationAttestorError as exc:
            raise _error(
                "recovered_verifier_v5_launcher_mutated_request"
            ) from exc
        if not hmac.compare_digest(
            request_canonical, launcher_request_after
        ):
            raise _error(
                "recovered_verifier_v5_launcher_mutated_request"
            )
        output, verifier_output_sha256 = (
            _parse_recovered_verifier_v5_result(
                verifier_result,
                expected_evidence_uid=prepared.config[
                    "expected_evidence_uid"
                ],
            )
        )
        verifier_evidence = (
            _assert_recovered_verifier_output_binding(
                prepared, lease, request, output
            )
        )
        _revalidate_recovered_live_sources(
            prepared,
            capture_plan,
            lease,
            snapshot_root,
        )
        post_binding = lease.post_verifier_revalidate()
        if post_binding != pre_binding:
            raise _error(
                "recovered_transaction_lease_binding_changed"
            )
        revalidated_at = _clock_value(
            clock,
            field="recovered_verifier_v5_revalidation_clock",
        )
        if revalidated_at < verified_at:
            raise _error("qualification_clock_rollback")
        receipt = _build_recovered_source_revalidation_receipt_v2(
            lease,
            verifier_evidence,
            verifier_output_sha256=verifier_output_sha256,
            revalidated_at_unix=revalidated_at,
        )
        _control_revalidation(prepared, revalidate_controls)
        material = operation.mint_material(
            verifier_request_v5=request,
            verifier_output_v4=output,
            source_revalidation_receipt_v2=receipt,
            pre_verifier_recovered_adoption_lease_binding=(
                pre_binding
            ),
            post_verifier_recovered_adoption_lease_binding=(
                post_binding
            ),
        )
        operation.commit(material)
        committed = True
        operation = None
        return _resume_recovered_verifier_to_complete(
            prepared,
            journal_session,
            expected_run_id=expected_run_id,
        )
    except BaseException as failure:
        cancellation_error: BaseException | None = None
        if (
            not committed
            and operation is not None
            and operation.state == "open"
        ):
            cancellation_error = _cancel_recovered_verifier_operation(
                journal_session, operation
            )
        if not isinstance(failure, Exception):
            raise
        if cancellation_error is not None:
            if not isinstance(cancellation_error, Exception):
                raise cancellation_error
            raise _error(
                "recovered_verifier_v5_reservation_cleanup_failed"
            ) from failure
        if isinstance(
            failure,
            (
                adoption_recovery.RecoveredAdoptionRecoveryError,
                transaction_journal.TransactionJournalError,
            ),
        ):
            raise _error(failure.code) from failure
        raise


def _session_failure_code(exc: BaseException) -> str:
    value = getattr(exc, "code", None)
    if (
        isinstance(value, str)
        and core.REASON_RE.fullmatch(value)
    ):
        return value
    return "qualification_transaction_failed"


def _cleanup_failure_code(exc: BaseException) -> str:
    value = getattr(exc, "code", None)
    if (
        isinstance(value, str)
        and core.REASON_RE.fullmatch(value)
    ):
        return value
    return "committed_cleanup_failed"


def _projection_path_sha256(path: Path) -> str:
    return core.sha256_bytes(str(path).encode("utf-8"))


def normalize_pending_publication_receipt(
    value: Any,
) -> dict[str, Any]:
    """Normalize keyless authority to finish trust publication."""

    if (
        not isinstance(value, Mapping)
        or set(value) != PENDING_PUBLICATION_RECEIPT_FIELDS
    ):
        raise _error("pending_publication_receipt_fields_invalid")
    if value.get("schema_version") != PENDING_PUBLICATION_RECEIPT_SCHEMA:
        raise _error("pending_publication_receipt_schema_unsupported")
    if value.get("status") != "publication_reconciliation_required":
        raise _error("pending_publication_receipt_status_invalid")
    publication_state = value.get("publication_state")
    if publication_state not in PENDING_PUBLICATION_STATES:
        raise _error("pending_publication_receipt_state_invalid")
    error_code = value.get("reconciliation_error_code")
    if (
        not isinstance(error_code, str)
        or not core.REASON_RE.fullmatch(error_code)
    ):
        raise _error("pending_publication_receipt_error_code_invalid")
    cleanup_status = value.get("capture_cleanup_status")
    if cleanup_status not in {"complete", "pending"}:
        raise _error("pending_publication_receipt_cleanup_status_invalid")
    cleanup_error_code = value.get("capture_cleanup_error_code")
    if (
        not isinstance(cleanup_error_code, str)
        or not core.REASON_RE.fullmatch(cleanup_error_code)
        or (
            cleanup_status == "complete"
            and cleanup_error_code != "none"
        )
        or (
            cleanup_status == "pending"
            and cleanup_error_code == "none"
        )
    ):
        raise _error(
            "pending_publication_receipt_cleanup_error_code_invalid"
        )
    verified_run_id = value.get("verified_run_id")
    authoritative_run_id = value.get("authoritative_run_id")
    if (
        not isinstance(verified_run_id, str)
        or not core.RUN_ID_RE.fullmatch(verified_run_id)
        or not isinstance(authoritative_run_id, str)
        or not core.RUN_ID_RE.fullmatch(authoritative_run_id)
    ):
        raise _error("pending_publication_receipt_run_id_invalid")
    digest_fields = (
        "requested_evidence_sha256",
        "committed_evidence_sha256",
        "requested_attestation_sha256",
        "authoritative_attestation_sha256",
        "capture_session_id",
        "capture_adoption_receipt_sha256",
        "control_sha256",
        "operator_policy_sha256",
        "config_sha256",
        "public_key_sha256",
        "public_projection_path_sha256",
    )
    normalized = {
        "schema_version": PENDING_PUBLICATION_RECEIPT_SCHEMA,
        "status": "publication_reconciliation_required",
        "publication_state": publication_state,
        "reconciliation_error_code": error_code,
        "capture_cleanup_status": cleanup_status,
        "capture_cleanup_error_code": cleanup_error_code,
        "instance_slug": core._slug(
            value.get("instance_slug"),
            field="pending_publication_receipt_instance_slug",
        ),
        "verified_run_id": verified_run_id,
        "authoritative_run_id": authoritative_run_id,
        "authoritative_chain_sequence": core._integer(
            value.get("authoritative_chain_sequence"),
            field=(
                "pending_publication_receipt_"
                "authoritative_chain_sequence"
            ),
            minimum=1,
        ),
    }
    for field in digest_fields:
        normalized[field] = core._digest(
            value.get(field),
            field=f"pending_publication_receipt_{field}",
        )
    return normalized


def _pending_publication_receipt(
    prepared: PreparedQualificationTransaction,
    *,
    evidence: Mapping[str, Any],
    committed_evidence_sha256: str,
    requested_attestation_sha256: str,
    authoritative_head: Mapping[str, Any],
    capture_session_id: str,
    capture_adoption_receipt_sha256: str,
    capture_cleanup_status: str,
    capture_cleanup_error_code: str,
    publication_state: str,
    failure: BaseException,
) -> dict[str, Any]:
    if authoritative_head.get("state") != "verified":
        raise _error("pending_publication_authoritative_head_invalid")
    return normalize_pending_publication_receipt(
        {
            "schema_version": PENDING_PUBLICATION_RECEIPT_SCHEMA,
            "status": "publication_reconciliation_required",
            "publication_state": publication_state,
            "reconciliation_error_code": _session_failure_code(failure),
            "instance_slug": prepared.config["instance_slug"],
            "verified_run_id": evidence["run_id"],
            "requested_evidence_sha256": core.sha256_json(evidence),
            "committed_evidence_sha256": committed_evidence_sha256,
            "requested_attestation_sha256": (
                requested_attestation_sha256
            ),
            "authoritative_run_id": authoritative_head["run_id"],
            "authoritative_chain_sequence": authoritative_head[
                "chain_sequence"
            ],
            "authoritative_attestation_sha256": authoritative_head[
                "attestation_sha256"
            ],
            "capture_session_id": capture_session_id,
            "capture_adoption_receipt_sha256": (
                capture_adoption_receipt_sha256
            ),
            "capture_cleanup_status": capture_cleanup_status,
            "capture_cleanup_error_code": capture_cleanup_error_code,
            "control_sha256": prepared.control_sha256,
            "operator_policy_sha256": prepared.binding[
                "operator_policy_sha256"
            ],
            "config_sha256": core.sha256_json(prepared.config),
            "public_key_sha256": prepared.config[
                "public_key_sha256"
            ],
            "public_projection_path_sha256": _projection_path_sha256(
                prepared.public_projection_path
            ),
        }
    )


def _pending_publication_result(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    normalized = normalize_pending_publication_receipt(receipt)
    return {
        "schema_version": PENDING_PUBLICATION_RESULT_SCHEMA,
        "status": "publication_reconciliation_required",
        "commit_state": "attestation_committed",
        "publication_state": normalized["publication_state"],
        "cleanup_status": normalized["capture_cleanup_status"],
        "instance_slug": normalized["instance_slug"],
        "verified_run_id": normalized["verified_run_id"],
        "requested_attestation_sha256": normalized[
            "requested_attestation_sha256"
        ],
        "authoritative_run_id": normalized[
            "authoritative_run_id"
        ],
        "authoritative_chain_sequence": normalized[
            "authoritative_chain_sequence"
        ],
        "authoritative_attestation_sha256": normalized[
            "authoritative_attestation_sha256"
        ],
        "capture_session_id": normalized["capture_session_id"],
        "capture_adoption_receipt_sha256": normalized[
            "capture_adoption_receipt_sha256"
        ],
        "public_reputation_eligible": False,
        "publication_receipt": normalized,
        "publication_receipt_sha256": core.sha256_json(normalized),
    }


def normalize_ambiguous_publication_receipt(
    value: Any,
) -> dict[str, Any]:
    """Normalize fail-closed authority for an indeterminate sign attempt."""

    if (
        not isinstance(value, Mapping)
        or set(value) != AMBIGUOUS_PUBLICATION_RECEIPT_FIELDS
    ):
        raise _error("ambiguous_publication_receipt_fields_invalid")
    if (
        value.get("schema_version")
        != AMBIGUOUS_PUBLICATION_RECEIPT_SCHEMA
    ):
        raise _error("ambiguous_publication_receipt_schema_unsupported")
    if value.get("status") != "operator_attention":
        raise _error("ambiguous_publication_receipt_status_invalid")
    if value.get("publication_state") != "attestation_state_ambiguous":
        raise _error("ambiguous_publication_receipt_state_invalid")
    run_id = value.get("verified_run_id")
    if (
        not isinstance(run_id, str)
        or not core.RUN_ID_RE.fullmatch(run_id)
    ):
        raise _error("ambiguous_publication_receipt_run_id_invalid")
    for field in ("failure_error_code", "reconciliation_error_code"):
        error_code = value.get(field)
        if (
            not isinstance(error_code, str)
            or not core.REASON_RE.fullmatch(error_code)
        ):
            raise _error(
                f"ambiguous_publication_receipt_{field}_invalid"
            )
    handoff_status = value.get("recovery_handoff_status")
    if handoff_status not in {"deferred", "failed"}:
        raise _error(
            "ambiguous_publication_receipt_handoff_status_invalid"
        )
    handoff_error_code = value.get("recovery_handoff_error_code")
    if (
        not isinstance(handoff_error_code, str)
        or not core.REASON_RE.fullmatch(handoff_error_code)
        or (
            handoff_status == "deferred"
            and handoff_error_code != "none"
        )
        or (
            handoff_status == "failed"
            and handoff_error_code == "none"
        )
    ):
        raise _error(
            "ambiguous_publication_receipt_handoff_error_invalid"
        )
    raw_handoff_sha256 = value.get(
        "capture_recovery_handoff_sha256"
    )
    if handoff_status == "deferred":
        handoff_sha256: str | None = core._digest(
            raw_handoff_sha256,
            field=(
                "ambiguous_publication_receipt_"
                "capture_recovery_handoff_sha256"
            ),
        )
    elif raw_handoff_sha256 is not None:
        raise _error(
            "ambiguous_publication_receipt_handoff_digest_invalid"
        )
    else:
        handoff_sha256 = None
    normalized = {
        "schema_version": AMBIGUOUS_PUBLICATION_RECEIPT_SCHEMA,
        "status": "operator_attention",
        "publication_state": "attestation_state_ambiguous",
        "failure_error_code": value["failure_error_code"],
        "reconciliation_error_code": value[
            "reconciliation_error_code"
        ],
        "recovery_handoff_status": handoff_status,
        "recovery_handoff_error_code": handoff_error_code,
        "capture_recovery_handoff_sha256": handoff_sha256,
        "instance_slug": core._slug(
            value.get("instance_slug"),
            field="ambiguous_publication_receipt_instance_slug",
        ),
        "verified_run_id": run_id,
    }
    for field in (
        "requested_evidence_sha256",
        "capture_session_id",
        "capture_adoption_receipt_sha256",
        "control_sha256",
        "operator_policy_sha256",
        "config_sha256",
        "public_key_sha256",
        "public_projection_path_sha256",
    ):
        normalized[field] = core._digest(
            value.get(field),
            field=f"ambiguous_publication_receipt_{field}",
        )
    return normalized


def _ambiguous_publication_result(
    prepared: PreparedQualificationTransaction,
    *,
    session: ProtectedCaptureSession,
    evidence: Mapping[str, Any],
    capture_session_id: str,
    capture_adoption_receipt_sha256: str,
    failure: BaseException,
    reconciliation_failure: BaseException,
) -> dict[str, Any]:
    handoff_status = "failed"
    handoff_error_code = "capture_recovery_handoff_failed"
    handoff_sha256: str | None = None
    try:
        handoff_receipt = session.defer_publication_ambiguity(
            core.sha256_json(evidence)
        )
        if not isinstance(handoff_receipt, Mapping):
            raise _error("capture_recovery_handoff_receipt_invalid")
        observed_handoff_sha256 = core._digest(
            session.recovery_handoff_receipt_sha256,
            field="capture_recovery_handoff_sha256",
        )
        if core.sha256_json(handoff_receipt) != observed_handoff_sha256:
            raise _error("capture_recovery_handoff_digest_mismatch")
        handoff_status = "deferred"
        handoff_error_code = "none"
        handoff_sha256 = observed_handoff_sha256
    except BaseException as handoff_failure:
        handoff_error_code = _cleanup_failure_code(handoff_failure)
    receipt = normalize_ambiguous_publication_receipt(
        {
            "schema_version": AMBIGUOUS_PUBLICATION_RECEIPT_SCHEMA,
            "status": "operator_attention",
            "publication_state": "attestation_state_ambiguous",
            "failure_error_code": _session_failure_code(failure),
            "reconciliation_error_code": _session_failure_code(
                reconciliation_failure
            ),
            "recovery_handoff_status": handoff_status,
            "recovery_handoff_error_code": handoff_error_code,
            "capture_recovery_handoff_sha256": handoff_sha256,
            "instance_slug": prepared.config["instance_slug"],
            "verified_run_id": evidence["run_id"],
            "requested_evidence_sha256": core.sha256_json(evidence),
            "capture_session_id": capture_session_id,
            "capture_adoption_receipt_sha256": (
                capture_adoption_receipt_sha256
            ),
            "control_sha256": prepared.control_sha256,
            "operator_policy_sha256": prepared.binding[
                "operator_policy_sha256"
            ],
            "config_sha256": core.sha256_json(prepared.config),
            "public_key_sha256": prepared.config[
                "public_key_sha256"
            ],
            "public_projection_path_sha256": _projection_path_sha256(
                prepared.public_projection_path
            ),
        }
    )
    return {
        "schema_version": AMBIGUOUS_PUBLICATION_RESULT_SCHEMA,
        "status": "operator_attention",
        "commit_state": "publication_ambiguous",
        "publication_state": "attestation_state_ambiguous",
        "cleanup_status": "deferred",
        "recovery_handoff_status": receipt[
            "recovery_handoff_status"
        ],
        "instance_slug": receipt["instance_slug"],
        "verified_run_id": receipt["verified_run_id"],
        "capture_session_id": receipt["capture_session_id"],
        "capture_adoption_receipt_sha256": receipt[
            "capture_adoption_receipt_sha256"
        ],
        "public_reputation_eligible": False,
        "ambiguity_receipt": receipt,
        "ambiguity_receipt_sha256": core.sha256_json(receipt),
    }


def _matching_archive_entry(
    tip: Mapping[str, Any],
    *,
    verified_run_id: str,
    committed_evidence_sha256: str,
    requested_attestation_sha256: str | None = None,
) -> dict[str, Any] | None:
    raw_index = tip.get("archive_index")
    if not isinstance(raw_index, list):
        raise _error("attestation_archive_index_invalid")
    matches: list[dict[str, Any]] = []
    for raw_entry in raw_index:
        if not isinstance(raw_entry, Mapping):
            raise _error("attestation_archive_index_invalid")
        if (
            raw_entry.get("run_id", "").casefold()
            != verified_run_id.casefold()
        ):
            continue
        if raw_entry.get("verified_evidence_sha256") != (
            committed_evidence_sha256
        ):
            raise _error("same_run_different_attestation_rejected")
        entry = {
            "run_id": raw_entry["run_id"],
            "chain_sequence": core._integer(
                raw_entry.get("chain_sequence"),
                field="attestation_archive_index_chain_sequence",
                minimum=1,
            ),
            "attestation_sha256": core._digest(
                raw_entry.get("attestation_sha256"),
                field="attestation_archive_index_attestation_sha256",
            ),
            "verified_evidence_sha256": core._digest(
                raw_entry.get("verified_evidence_sha256"),
                field=(
                    "attestation_archive_index_"
                    "verified_evidence_sha256"
                ),
            ),
        }
        if (
            requested_attestation_sha256 is not None
            and entry["attestation_sha256"]
            != requested_attestation_sha256
        ):
            raise _error(
                "pending_publication_requested_attestation_changed"
            )
        matches.append(entry)
    if len(matches) > 1:
        raise _error("attestation_archive_run_reused")
    return None if not matches else matches[0]


class _PrivateKeyRequiredForRecovery(RuntimeError):
    pass


def _reconcile_sign_attempt_without_key(
    prepared: PreparedQualificationTransaction,
    evidence: Mapping[str, Any],
    *,
    updated_at_unix: int,
    publication_owner_uid: int,
) -> tuple[dict[str, Any], str, dict[str, Any]] | None:
    """Repair or locate an already signed attempt without key authority."""

    def reject_private_key_access() -> bytes:
        raise _PrivateKeyRequiredForRecovery

    try:
        return core.sign_and_publish_attestation(
            prepared.config,
            evidence,
            public_key_bytes=prepared.public_key_bytes,
            private_key_loader=reject_private_key_access,
            updated_at_unix=updated_at_unix,
            publication_owner_uid=publication_owner_uid,
            allow_equivalent_recapture=True,
        )
    except _PrivateKeyRequiredForRecovery:
        return None


def normalize_committed_cleanup_receipt(
    value: Any,
) -> dict[str, Any]:
    """Normalize the serializable authority for cleanup-only reconciliation."""

    if (
        not isinstance(value, Mapping)
        or set(value) != COMMITTED_CLEANUP_RECEIPT_FIELDS
    ):
        raise _error("committed_cleanup_receipt_fields_invalid")
    if value.get("schema_version") != COMMITTED_CLEANUP_RECEIPT_SCHEMA:
        raise _error("committed_cleanup_receipt_schema_unsupported")
    if value.get("status") != "committed_cleanup_pending":
        raise _error("committed_cleanup_receipt_status_invalid")
    operation = value.get("cleanup_operation")
    if operation not in COMMITTED_CLEANUP_OPERATIONS:
        raise _error("committed_cleanup_receipt_operation_invalid")
    error_code = value.get("cleanup_error_code")
    if (
        not isinstance(error_code, str)
        or not core.REASON_RE.fullmatch(error_code)
    ):
        raise _error("committed_cleanup_receipt_error_code_invalid")
    run_id = value.get("run_id")
    if (
        not isinstance(run_id, str)
        or not core.RUN_ID_RE.fullmatch(run_id)
    ):
        raise _error("committed_cleanup_receipt_run_id_invalid")
    return {
        "schema_version": COMMITTED_CLEANUP_RECEIPT_SCHEMA,
        "status": "committed_cleanup_pending",
        "cleanup_operation": operation,
        "cleanup_error_code": error_code,
        "instance_slug": core._slug(
            value.get("instance_slug"),
            field="committed_cleanup_receipt_instance_slug",
        ),
        "run_id": run_id,
        "chain_sequence": core._integer(
            value.get("chain_sequence"),
            field="committed_cleanup_receipt_chain_sequence",
            minimum=1,
        ),
        "attestation_sha256": core._digest(
            value.get("attestation_sha256"),
            field="committed_cleanup_receipt_attestation_sha256",
        ),
        "trust_projection_sha256": core._digest(
            value.get("trust_projection_sha256"),
            field="committed_cleanup_receipt_trust_projection_sha256",
        ),
        "capture_session_id": core._digest(
            value.get("capture_session_id"),
            field="committed_cleanup_receipt_capture_session_id",
        ),
        "capture_adoption_receipt_sha256": core._digest(
            value.get("capture_adoption_receipt_sha256"),
            field=(
                "committed_cleanup_receipt_"
                "capture_adoption_receipt_sha256"
            ),
        ),
    }


def _committed_cleanup_receipt(
    committed_result: Mapping[str, Any],
    *,
    capture_session_id: str,
    operation: str,
    failure: BaseException,
) -> dict[str, Any]:
    return normalize_committed_cleanup_receipt(
        {
            "schema_version": COMMITTED_CLEANUP_RECEIPT_SCHEMA,
            "status": "committed_cleanup_pending",
            "cleanup_operation": operation,
            "cleanup_error_code": _cleanup_failure_code(failure),
            "instance_slug": committed_result["instance_slug"],
            "run_id": committed_result["run_id"],
            "chain_sequence": committed_result["chain_sequence"],
            "attestation_sha256": committed_result[
                "attestation_sha256"
            ],
            "trust_projection_sha256": committed_result[
                "trust_projection_sha256"
            ],
            "capture_session_id": capture_session_id,
            "capture_adoption_receipt_sha256": committed_result[
                "capture_adoption_receipt_sha256"
            ],
        }
    )


def _pending_cleanup_result(
    committed_result: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    normalized_receipt = normalize_committed_cleanup_receipt(receipt)
    return {
        **dict(committed_result),
        "status": "committed_cleanup_pending",
        "commit_state": "committed",
        "cleanup_status": "pending",
        "cleanup_receipt": normalized_receipt,
        "cleanup_receipt_sha256": core.sha256_json(
            normalized_receipt
        ),
    }


def _cleanup_reconciliation_result(
    receipt: Mapping[str, Any],
    *,
    status: str,
    failure: BaseException | None = None,
) -> dict[str, Any]:
    normalized = normalize_committed_cleanup_receipt(receipt)
    if status not in {
        "committed_cleanup_complete",
        "committed_cleanup_pending",
    }:
        raise _error("cleanup_reconciliation_status_invalid")
    result = {
        "schema_version": CLEANUP_RECONCILIATION_RESULT_SCHEMA,
        "status": status,
        "commit_state": "committed",
        "cleanup_status": (
            "complete"
            if status == "committed_cleanup_complete"
            else "pending"
        ),
        "instance_slug": normalized["instance_slug"],
        "run_id": normalized["run_id"],
        "chain_sequence": normalized["chain_sequence"],
        "attestation_sha256": normalized["attestation_sha256"],
        "trust_projection_sha256": normalized[
            "trust_projection_sha256"
        ],
        "capture_session_id": normalized["capture_session_id"],
        "capture_adoption_receipt_sha256": normalized[
            "capture_adoption_receipt_sha256"
        ],
        "cleanup_receipt": normalized,
        "cleanup_receipt_sha256": core.sha256_json(normalized),
    }
    if failure is not None:
        result["cleanup_error_code"] = _cleanup_failure_code(failure)
    return result


def reconcile_committed_cleanup(
    receipt: Mapping[str, Any],
    session: CommittedCleanupSession,
) -> dict[str, Any]:
    """Retry only capture cleanup for an already committed publication.

    This entrypoint deliberately accepts no prepared transaction, private-key
    loader, verifier launcher, clock, or publication path.  A retry therefore
    cannot reopen signing authority, advance the chain, or republish trust
    state.  The receipt is serializable across a coordinator restart.  The
    current descriptor-held adoption lease still requires a separate safe
    recovery primitive before a process restart can reconstruct this narrow
    cleanup authority; this function does not pretend to provide one.
    """

    normalized = normalize_committed_cleanup_receipt(receipt)
    try:
        session_id = core._digest(
            session.capture_session_id,
            field="cleanup_session_id",
        )
        adoption_receipt_sha256 = core._digest(
            session.adoption_receipt_sha256,
            field="cleanup_session_adoption_receipt_sha256",
        )
    except AttributeError as exc:
        raise _error("cleanup_session_invalid") from exc
    if not hmac.compare_digest(
        session_id,
        normalized["capture_session_id"],
    ):
        raise _error("cleanup_session_id_mismatch")
    if not hmac.compare_digest(
        adoption_receipt_sha256,
        normalized["capture_adoption_receipt_sha256"],
    ):
        raise _error("cleanup_session_adoption_receipt_mismatch")

    try:
        if (
            normalized["cleanup_operation"]
            == "complete_signing_and_publication"
        ):
            session.complete_signing(
                normalized["attestation_sha256"]
            )
        session.complete_publication(
            normalized["trust_projection_sha256"]
        )
    except BaseException as exc:
        updated = dict(normalized)
        updated["cleanup_error_code"] = _cleanup_failure_code(exc)
        return _cleanup_reconciliation_result(
            updated,
            status="committed_cleanup_pending",
            failure=exc,
        )
    return _cleanup_reconciliation_result(
        normalized,
        status="committed_cleanup_complete",
    )


def _assert_pending_publication_prepared_binding(
    prepared: PreparedQualificationTransaction,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    normalized = normalize_pending_publication_receipt(receipt)
    expected = {
        "instance_slug": prepared.config["instance_slug"],
        "control_sha256": prepared.control_sha256,
        "operator_policy_sha256": prepared.binding[
            "operator_policy_sha256"
        ],
        "config_sha256": core.sha256_json(prepared.config),
        "public_key_sha256": prepared.config["public_key_sha256"],
        "public_projection_path_sha256": _projection_path_sha256(
            prepared.public_projection_path
        ),
    }
    for field, expected_value in expected.items():
        if normalized[field] != expected_value:
            raise _error(f"pending_publication_{field}_mismatch")
    return normalized


def _refresh_pending_publication_receipt(
    receipt: Mapping[str, Any],
    *,
    authoritative_head: Mapping[str, Any] | None,
    publication_state: str,
    failure: BaseException,
) -> dict[str, Any]:
    updated = dict(normalize_pending_publication_receipt(receipt))
    updated["publication_state"] = publication_state
    updated["reconciliation_error_code"] = _session_failure_code(
        failure
    )
    if authoritative_head is not None:
        if authoritative_head.get("state") != "verified":
            raise _error(
                "pending_publication_authoritative_head_invalid"
            )
        updated["authoritative_run_id"] = authoritative_head["run_id"]
        updated["authoritative_chain_sequence"] = authoritative_head[
            "chain_sequence"
        ]
        updated["authoritative_attestation_sha256"] = (
            authoritative_head["attestation_sha256"]
        )
    return normalize_pending_publication_receipt(updated)


def _publish_projection_with_exact_readback(
    prepared: PreparedQualificationTransaction,
    projection: Mapping[str, Any],
    *,
    now_unix: int,
    publication_owner_uid: int,
) -> tuple[dict[str, Any], str]:
    try:
        return trust_projection.publish_projection(
            projection,
            prepared.public_projection_path,
            expected_instance_slug=prepared.config["instance_slug"],
            expected_key_id=prepared.config["attestor_key_id"],
            expected_public_key_sha256=prepared.config[
                "public_key_sha256"
            ],
            now_unix=now_unix,
            publication_owner_uid=publication_owner_uid,
        )
    except BaseException as publication_failure:
        try:
            observed = trust_projection.read_public_projection(
                prepared.public_projection_path,
                publication_owner_uid=publication_owner_uid,
            )
            trust_projection.verify_projection(
                observed,
                expected_instance_slug=prepared.config[
                    "instance_slug"
                ],
                expected_key_id=prepared.config["attestor_key_id"],
                expected_public_key_sha256=prepared.config[
                    "public_key_sha256"
                ],
                now_unix=now_unix,
            )
            if core.sha256_json(observed) != core.sha256_json(projection):
                raise _error("public_projection_readback_mismatch")
        except BaseException:
            raise publication_failure
        return observed, "published_readback"


def _publication_cleanup_result(
    receipt: Mapping[str, Any],
    *,
    authoritative_head: Mapping[str, Any],
    projection: Mapping[str, Any],
    projection_status: str,
    session: ProtectedCaptureSession | None,
) -> dict[str, Any]:
    normalized = normalize_pending_publication_receipt(receipt)
    projection_sha256 = core.sha256_json(projection)
    committed = {
        "schema_version": PUBLICATION_RECONCILIATION_RESULT_SCHEMA,
        "status": "verified",
        "commit_state": "committed",
        "publication_state": "committed",
        "cleanup_status": "complete",
        "attestation_publication": "previously_committed",
        "trust_publication": projection_status,
        "instance_slug": authoritative_head["instance_slug"],
        "run_id": authoritative_head["run_id"],
        "verified_run_id": normalized["verified_run_id"],
        "chain_sequence": authoritative_head["chain_sequence"],
        "attestation_sha256": authoritative_head[
            "attestation_sha256"
        ],
        "requested_attestation_sha256": normalized[
            "requested_attestation_sha256"
        ],
        "trust_projection_sha256": projection_sha256,
        "capture_adoption_receipt_sha256": normalized[
            "capture_adoption_receipt_sha256"
        ],
        "capture_session_id": normalized["capture_session_id"],
        "public_reputation_eligible": False,
    }
    if normalized["capture_cleanup_status"] == "complete":
        return committed
    if session is None:
        failure = _error("capture_session_recovery_required")
        cleanup_receipt = _committed_cleanup_receipt(
            committed,
            capture_session_id=normalized["capture_session_id"],
            operation="complete_signing_and_publication",
            failure=failure,
        )
        return _pending_cleanup_result(committed, cleanup_receipt)
    try:
        session_id = core._digest(
            session.capture_session_id,
            field="publication_reconciliation_session_id",
        )
        adoption_receipt_sha256 = core._digest(
            session.adoption_receipt_sha256,
            field=(
                "publication_reconciliation_"
                "adoption_receipt_sha256"
            ),
        )
    except AttributeError as exc:
        raise _error("publication_reconciliation_session_invalid") from exc
    if session_id != normalized["capture_session_id"]:
        raise _error("publication_reconciliation_session_id_mismatch")
    if adoption_receipt_sha256 != normalized[
        "capture_adoption_receipt_sha256"
    ]:
        raise _error(
            "publication_reconciliation_adoption_receipt_mismatch"
        )
    try:
        session.complete_signing(
            normalized["requested_attestation_sha256"]
        )
        session.complete_publication(projection_sha256)
    except BaseException as exc:
        cleanup_receipt = _committed_cleanup_receipt(
            committed,
            capture_session_id=session_id,
            operation="complete_signing_and_publication",
            failure=exc,
        )
        return _pending_cleanup_result(committed, cleanup_receipt)
    return committed


def reconcile_pending_publication(
    prepared: PreparedQualificationTransaction,
    receipt: Mapping[str, Any],
    *,
    session: ProtectedCaptureSession | None = None,
    clock: Callable[[], int] = lambda: int(time.time()),
    publication_owner_uid: int | None = None,
) -> dict[str, Any]:
    """Finish a proven signed publication without a key or verifier.

    The mutating authority here is deliberately limited to bounded signed-head
    repair, public projection publication, and optional capture cleanup.  No
    private-key loader, verifier launcher, or evidence producer is accepted.
    """

    if not isinstance(prepared, PreparedQualificationTransaction):
        raise _error("prepared_transaction_invalid")
    normalized = _assert_pending_publication_prepared_binding(
        prepared,
        receipt,
    )
    owner_uid = (
        os.geteuid()
        if publication_owner_uid is None
        else core._integer(
            publication_owner_uid,
            field="publication_owner_uid",
        )
    )
    authoritative_head: dict[str, Any] | None = None
    try:
        # This is the explicit recovery operation.  Unlike the read-only
        # inspector, it may remove bounded interrupted temp links and repair a
        # stale/missing head, but it has no signing authority.
        tip = core.read_attestation_chain_tip(
            prepared.config,
            public_key_bytes=prepared.public_key_bytes,
            publication_owner_uid=owner_uid,
        )
        inspection = core.inspect_attestation_chain_tip(
            prepared.config,
            public_key_bytes=prepared.public_key_bytes,
            publication_owner_uid=owner_uid,
        )
        requested = _matching_archive_entry(
            inspection,
            verified_run_id=normalized["verified_run_id"],
            committed_evidence_sha256=normalized[
                "committed_evidence_sha256"
            ],
            requested_attestation_sha256=normalized[
                "requested_attestation_sha256"
            ],
        )
        if requested is None:
            raise _error("pending_publication_attestation_missing")
        if inspection["head_needs_repair"]:
            raise _error("pending_publication_head_repair_incomplete")
        authoritative_head = tip["current_head"]
        authoritative_envelope = tip["current_envelope"]
        if (
            authoritative_envelope is None
            or authoritative_head["state"] != "verified"
            or core.sha256_json(authoritative_envelope)
            != authoritative_head["attestation_sha256"]
        ):
            raise _error("authoritative_attestation_missing")

        projection_time = _clock_value(
            clock,
            field="qualification_projection_reconciliation_clock",
        )
        projection = trust_projection.build_projection(
            prepared.config,
            prepared.operator_policy,
            authoritative_head,
            authoritative_envelope,
            public_key_bytes=prepared.public_key_bytes,
            generated_at_unix=projection_time,
        )
        published_projection, projection_status = (
            _publish_projection_with_exact_readback(
                prepared,
                projection,
                now_unix=projection_time,
                publication_owner_uid=owner_uid,
            )
        )
    except BaseException as exc:
        refreshed = _refresh_pending_publication_receipt(
            normalized,
            authoritative_head=authoritative_head,
            publication_state=(
                "attestation_head_pending"
                if authoritative_head is None
                else "trust_projection_pending"
            ),
            failure=exc,
        )
        return _pending_publication_result(refreshed)

    return _publication_cleanup_result(
        normalized,
        authoritative_head=authoritative_head,
        projection=published_projection,
        projection_status=projection_status,
        session=session,
    )


def run_prepared_transaction(
    prepared: PreparedQualificationTransaction,
    session: ProtectedCaptureSession,
    *,
    private_key_loader: Callable[[], bytes],
    revalidate_controls: Callable[[], str],
    verifier_launcher: Callable[
        [
            verifier_sandbox.QualificationSandboxPolicy,
            Mapping[str, Any],
        ],
        Any,
    ] = verifier_sandbox.launch_protected_verifier,
    clock: Callable[[], int] = lambda: int(time.time()),
    publication_owner_uid: int | None = None,
) -> dict[str, Any]:
    """Execute one capture-held transaction with the private key opened last."""

    if not isinstance(prepared, PreparedQualificationTransaction):
        raise _error("prepared_transaction_invalid")
    if not callable(private_key_loader):
        raise _error("private_key_loader_invalid")
    if not callable(verifier_launcher):
        raise _error("verifier_launcher_invalid")
    owner_uid = (
        os.geteuid()
        if publication_owner_uid is None
        else core._integer(
            publication_owner_uid,
            field="publication_owner_uid",
        )
    )
    signing_invoked = False
    signing_updated_at: int | None = None
    evidence: dict[str, Any] | None = None
    signed_publication: (
        tuple[dict[str, Any], str, dict[str, Any]] | None
    ) = None
    capture_session_id: str | None = None
    capture_adoption_receipt_sha256: str | None = None
    capture_cleanup_complete = False
    try:
        (
            _capture_root,
            _capture_manifest_sha256,
            initial_adoption_receipt,
            _initial_adoption_receipt_sha256,
        ) = _validate_session(prepared, session)
        capture_session_id = initial_adoption_receipt["session_id"]
        capture_adoption_receipt_sha256 = (
            adoption_binding.adoption_receipt_sha256(
                initial_adoption_receipt
            )
        )
        _control_revalidation(prepared, revalidate_controls)
        verified_at = _clock_value(
            clock,
            field="qualification_verification_clock",
        )
        request = build_verifier_request(
            prepared,
            session,
            verified_at_unix=verified_at,
        )
        session.begin_verification()
        try:
            verifier_result = verifier_launcher(
                prepared.sandbox_policy,
                request,
            )
        except verifier_sandbox.QualificationSandboxError as exc:
            raise _error(exc.code) from exc
        raw_evidence, verifier_output_sha256 = (
            _parse_verifier_result(verifier_result)
        )
        verifier_evidence = _assert_evidence_binding(
            prepared,
            session,
            raw_evidence,
            verified_at_unix=verified_at,
        )

        # Only the root-side session still holds the exact adopted object and
        # the authority needed to reread the live E:export sources.  It returns
        # a path-free receipt only after the live pass and retained-object
        # checks succeed.  The raw verifier cannot manufacture this claim.
        source_revalidation_receipt = session.complete_verification(
            verifier_output_sha256
        )
        evidence = _bind_source_revalidation_receipt(
            prepared,
            verifier_evidence,
            source_revalidation_receipt,
            verifier_output_sha256=verifier_output_sha256,
        )
        _control_revalidation(prepared, revalidate_controls)

        updated_at = _clock_value(
            clock,
            field="qualification_signing_clock",
        )
        revalidated_at = evidence[
            "post_verifier_live_source_revalidation_receipt"
        ]["revalidated_at_unix"]
        if updated_at < revalidated_at:
            raise _error("qualification_clock_rollback")
        signing_invoked = True
        signing_updated_at = updated_at
        signed_publication = core.sign_and_publish_attestation(
            prepared.config,
            evidence,
            public_key_bytes=prepared.public_key_bytes,
            private_key_loader=private_key_loader,
            updated_at_unix=updated_at,
            publication_owner_uid=owner_uid,
            allow_equivalent_recapture=True,
        )
        head, attestation_status, requested_envelope = signed_publication

        # Re-read under the attestation lock.  A concurrent newer publication
        # is authoritative; an archived replay must never project its older
        # envelope as the current head.
        tip = core.read_attestation_chain_tip(
            prepared.config,
            public_key_bytes=prepared.public_key_bytes,
            publication_owner_uid=owner_uid,
        )
        authoritative_head = tip["current_head"]
        authoritative_envelope = tip["current_envelope"]
        if (
            authoritative_envelope is None
            or authoritative_head["state"] != "verified"
            or authoritative_head["chain_sequence"]
            < head["chain_sequence"]
        ):
            raise _error("authoritative_attestation_missing")
        session.complete_signing(
            core.sha256_json(requested_envelope)
        )
        capture_cleanup_complete = True

        projection_time = _clock_value(
            clock,
            field="qualification_projection_clock",
        )
        if projection_time < updated_at:
            raise _error("qualification_clock_rollback")
        projection = trust_projection.build_projection(
            prepared.config,
            prepared.operator_policy,
            authoritative_head,
            authoritative_envelope,
            public_key_bytes=prepared.public_key_bytes,
            generated_at_unix=projection_time,
        )
        published_projection, projection_status = (
            _publish_projection_with_exact_readback(
                prepared,
                projection,
                now_unix=projection_time,
                publication_owner_uid=owner_uid,
            )
        )
        projection_sha256 = core.sha256_json(published_projection)
        current_head = published_projection["head"]
        committed_result = {
            "schema_version": TRANSACTION_RESULT_SCHEMA,
            "status": "verified",
            "commit_state": "committed",
            "cleanup_status": "pending",
            "attestation_publication": attestation_status,
            "trust_publication": projection_status,
            "instance_slug": current_head["instance_slug"],
            "run_id": current_head["run_id"],
            "verified_run_id": evidence["run_id"],
            "chain_sequence": current_head["chain_sequence"],
            "attestation_sha256": current_head[
                "attestation_sha256"
            ],
            "requested_attestation_sha256": core.sha256_json(
                requested_envelope
            ),
            "capture_manifest_sha256": authoritative_envelope[
                "payload"
            ]["verification"]["capture_manifest_sha256"],
            "observed_capture_manifest_sha256": evidence[
                "capture_manifest_sha256"
            ],
            "capture_plan_sha256": evidence[
                "capture_plan_sha256"
            ],
            "capture_adoption_receipt_sha256": evidence[
                "capture_adoption_receipt_sha256"
            ],
            "capture_creator_uid": evidence["capture_creator_uid"],
            "trust_projection_sha256": projection_sha256,
            "expires_at_unix": current_head["expires_at_unix"],
            "claim_strength": core.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
        }
    except BaseException as exc:
        if (
            signing_invoked
            and evidence is not None
            and signing_updated_at is not None
            and capture_session_id is not None
            and capture_adoption_receipt_sha256 is not None
        ):
            recovered_publication = signed_publication
            if recovered_publication is None:
                try:
                    recovered_publication = (
                        _reconcile_sign_attempt_without_key(
                            prepared,
                            evidence,
                            updated_at_unix=signing_updated_at,
                            publication_owner_uid=owner_uid,
                        )
                    )
                except BaseException as reconciliation_failure:
                    return _ambiguous_publication_result(
                        prepared,
                        session=session,
                        evidence=evidence,
                        capture_session_id=capture_session_id,
                        capture_adoption_receipt_sha256=(
                            capture_adoption_receipt_sha256
                        ),
                        failure=exc,
                        reconciliation_failure=reconciliation_failure,
                    )
            if recovered_publication is not None:
                (
                    authoritative_head,
                    _recovered_status,
                    requested_envelope,
                ) = recovered_publication
                committed_evidence = core._verified_evidence_from_payload(
                    requested_envelope["payload"],
                    expected_evidence_uid=prepared.config[
                        "expected_evidence_uid"
                    ],
                )
                if (
                    core.sha256_json(committed_evidence)
                    != core.sha256_json(evidence)
                    and not core.equivalent_verified_evidence_recapture(
                        committed_evidence,
                        evidence,
                        expected_evidence_uid=prepared.config[
                            "expected_evidence_uid"
                        ],
                    )
                ):
                    return _ambiguous_publication_result(
                        prepared,
                        session=session,
                        evidence=evidence,
                        capture_session_id=capture_session_id,
                        capture_adoption_receipt_sha256=(
                            capture_adoption_receipt_sha256
                        ),
                        failure=exc,
                        reconciliation_failure=_error(
                            "recovered_attestation_evidence_mismatch"
                        ),
                    )
                cleanup_error_code = "none"
                if not capture_cleanup_complete:
                    try:
                        session.complete_signing(
                            core.sha256_json(requested_envelope)
                        )
                        capture_cleanup_complete = True
                    except BaseException as cleanup_failure:
                        cleanup_error_code = _cleanup_failure_code(
                            cleanup_failure
                        )
                receipt = _pending_publication_receipt(
                    prepared,
                    evidence=evidence,
                    committed_evidence_sha256=core.sha256_json(
                        committed_evidence
                    ),
                    requested_attestation_sha256=core.sha256_json(
                        requested_envelope
                    ),
                    authoritative_head=authoritative_head,
                    capture_session_id=capture_session_id,
                    capture_adoption_receipt_sha256=(
                        capture_adoption_receipt_sha256
                    ),
                    capture_cleanup_status=(
                        "complete"
                        if capture_cleanup_complete
                        else "pending"
                    ),
                    capture_cleanup_error_code=cleanup_error_code,
                    publication_state="trust_projection_pending",
                    failure=exc,
                )
                return _pending_publication_result(receipt)
        reason = _session_failure_code(exc)
        try:
            session.abort(reason)
        except BaseException:
            abort_failure = _error("capture_helper_abort_failed")
            try:
                session.close()
            except BaseException:
                raise _error("capture_helper_cleanup_failed") from (
                    abort_failure
                )
            raise abort_failure from exc
        try:
            session.close()
        except BaseException:
            raise _error("capture_helper_cleanup_failed") from exc
        raise

    # This is the irreversible boundary: both the signed chain head and the
    # public projection are durable.  From here onward every failure is a
    # cleanup outcome for an already committed transaction.  Abort is no
    # longer a truthful or permitted state transition.
    try:
        session.complete_publication(projection_sha256)
    except BaseException as exc:
        receipt = _committed_cleanup_receipt(
            committed_result,
            capture_session_id=capture_session_id,
            operation="complete_publication",
            failure=exc,
        )
        return _pending_cleanup_result(committed_result, receipt)
    return {
        **committed_result,
        "cleanup_status": "complete",
    }


def attest_configured(
    config_path: Path = core.DEFAULT_CONFIG_PATH,
) -> dict[str, Any]:
    """Reject use until the protected installer has activated every canary."""

    del config_path
    raise _error("protected_attestor_not_installed")
