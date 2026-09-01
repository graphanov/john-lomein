from __future__ import annotations

import copy
import json
import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_attestor as core,
)
from qualification_attestor import (
    john_lomein_persona_qualification_adoption_binding as adoption_binding,
)
from qualification_attestor import (
    john_lomein_persona_qualification_orchestrator as orchestrator,
)
from qualification_attestor import (
    john_lomein_persona_qualification_capture_selection as capture_selection,
)
from qualification_attestor import (
    john_lomein_persona_qualification_source_revalidation_binding as source_revalidation_binding,
)
from qualification_attestor import (
    john_lomein_persona_qualification_sandbox as sandbox,
)
from qualification_attestor import (
    john_lomein_persona_qualification_trust_projection as trust_projection,
)


class _Clock:
    def __init__(self, *values: int) -> None:
        self._values = iter(values)

    def __call__(self) -> int:
        return next(self._values)


class _CaptureSession:
    def __init__(
        self,
        capture_root: Path,
        *,
        manifest_sha256: str,
        selection_sha256: str,
        events: list[str],
        revalidated_at_unix: int = 115,
        receipt_overrides: dict[str, object] | None = None,
    ) -> None:
        self._capture_root = capture_root
        self._manifest_sha256 = manifest_sha256
        self._selection_sha256 = selection_sha256
        self._events = events
        self._revalidated_at_unix = revalidated_at_unix
        self._receipt_overrides = dict(receipt_overrides or {})
        self._session_id = "f" * 64
        self._request_sha256 = "e" * 64
        self._boundary_policy_sha256 = "d" * 64
        self._helper_policy_sha256 = "c" * 64
        self._recovery_handoff_receipt: dict[str, object] | None = None
        self._adoption_receipt = {
            "schema_version": adoption_binding.ADOPTION_RECEIPT_SCHEMA,
            "status": adoption_binding.ADOPTION_STATUS,
            "session_id": self._session_id,
            "capture_adoption_policy_sha256": "b" * 64,
            "capture_selection_sha256": selection_sha256,
            "capture_plan_sha256": "7" * 64,
            "capture_manifest_sha256": manifest_sha256,
            "capture_boundary_policy_sha256": (
                self._boundary_policy_sha256
            ),
            "helper_activation_policy_sha256": (
                self._helper_policy_sha256
            ),
            "request_sha256": self._request_sha256,
            "capture_uid": 504,
            "capture_gid": 505,
            "adopted_uid": 0,
            "verifier_uid": 502,
            "verifier_gid": 503,
            "final_name": capture_root.name,
            "object_identity_sha256": "a" * 64,
            "provisional_stat_sha256": "9" * 64,
            "adopted_stat_sha256": "8" * 64,
            "content_inventory_sha256": "6" * 64,
            "file_count": 10,
            "directory_count": 5,
            "total_bytes": 1_024,
            "child_pid": 12_345,
            "child_exit_status": 0,
            "child_stderr_sha256": adoption_binding.EMPTY_SHA256,
            "process_group_reaped": True,
            "staging_namespace_revoked": True,
            "same_filesystem": True,
            "rename_noreplace": True,
            "rename_primitive": "renameatx_np_excl",
            "adopted_at_unix": 90,
        }

    @property
    def capture_root(self) -> Path:
        return self._capture_root

    @property
    def capture_manifest_sha256(self) -> str:
        return self._manifest_sha256

    @property
    def capture_plan_sha256(self) -> str:
        return "7" * 64

    @property
    def adoption_receipt(self) -> dict[str, object]:
        return copy.deepcopy(self._adoption_receipt)

    @property
    def adoption_receipt_sha256(self) -> str:
        return adoption_binding.adoption_receipt_sha256(
            self._adoption_receipt
        )

    @property
    def capture_session_id(self) -> str:
        return self._session_id

    @property
    def capture_request_sha256(self) -> str:
        return self._request_sha256

    @property
    def capture_boundary_policy_sha256(self) -> str:
        return self._boundary_policy_sha256

    @property
    def helper_activation_policy_sha256(self) -> str:
        return self._helper_policy_sha256

    def begin_verification(self) -> None:
        self._events.append("begin_verification")

    def complete_verification(
        self,
        verifier_output_sha256: str,
    ) -> dict[str, object]:
        self._events.append(
            f"complete_verification:{verifier_output_sha256}"
        )
        receipt: dict[str, object] = {
            "schema_version": (
                source_revalidation_binding.
                SOURCE_REVALIDATION_RECEIPT_SCHEMA
            ),
            "status": source_revalidation_binding.SOURCE_REVALIDATION_STATUS,
            "capture_adoption_receipt_sha256": (
                self.adoption_receipt_sha256
            ),
            "capture_object_identity_sha256": "a" * 64,
            "capture_plan_sha256": self.capture_plan_sha256,
            "capture_manifest_sha256": self.capture_manifest_sha256,
            "verifier_output_sha256": verifier_output_sha256,
            "revalidator_uid": 0,
            "revalidated_at_unix": self._revalidated_at_unix,
        }
        receipt.update(self._receipt_overrides)
        return receipt

    def complete_signing(self, attestation_envelope_sha256: str) -> None:
        self._events.append(
            f"complete_signing:{attestation_envelope_sha256}"
        )

    def complete_publication(self, trust_projection_sha256: str) -> None:
        self._events.append(
            f"complete_publication:{trust_projection_sha256}"
        )

    def abort(self, reason_code: str) -> None:
        self._events.append(f"abort:{reason_code}")

    def defer_publication_ambiguity(
        self,
        requested_evidence_sha256: str,
    ) -> dict[str, object]:
        self._events.append(
            f"defer_publication_ambiguity:{requested_evidence_sha256}"
        )
        self._recovery_handoff_receipt = {
            "schema_version": "test.capture-recovery-handoff.v1",
            "session_id": self._session_id,
            "adoption_receipt_sha256": self.adoption_receipt_sha256,
            "requested_evidence_sha256": requested_evidence_sha256,
        }
        return copy.deepcopy(self._recovery_handoff_receipt)

    @property
    def recovery_handoff_receipt_sha256(self) -> str:
        if self._recovery_handoff_receipt is None:
            raise core.QualificationAttestorError(
                "capture_recovery_handoff_missing"
            )
        return core.sha256_json(self._recovery_handoff_receipt)

    def close(self) -> None:
        self._events.append("close")


class _FaultingCleanupCaptureSession(_CaptureSession):
    def __init__(
        self,
        capture_root: Path,
        *,
        manifest_sha256: str,
        selection_sha256: str,
        events: list[str],
        publication_cleanup_failures: int = 0,
    ) -> None:
        super().__init__(
            capture_root,
            manifest_sha256=manifest_sha256,
            selection_sha256=selection_sha256,
            events=events,
        )
        self._publication_cleanup_failures = (
            publication_cleanup_failures
        )

    def complete_publication(
        self,
        trust_projection_sha256: str,
    ) -> None:
        super().complete_publication(trust_projection_sha256)
        if self._publication_cleanup_failures:
            self._publication_cleanup_failures -= 1
            raise core.QualificationAttestorError(
                "capture_adoption_cleanup_remove_failed"
            )


class _FaultingSigningCaptureSession(_CaptureSession):
    def __init__(
        self,
        capture_root: Path,
        *,
        manifest_sha256: str,
        selection_sha256: str,
        events: list[str],
        fail_on_calls: set[int],
    ) -> None:
        super().__init__(
            capture_root,
            manifest_sha256=manifest_sha256,
            selection_sha256=selection_sha256,
            events=events,
        )
        self._signing_calls = 0
        self._fail_on_calls = set(fail_on_calls)

    def complete_signing(self, attestation_envelope_sha256: str) -> None:
        super().complete_signing(attestation_envelope_sha256)
        self._signing_calls += 1
        if self._signing_calls in self._fail_on_calls:
            raise core.QualificationAttestorError(
                "capture_signing_ack_failed"
            )


class ProtectedQualificationTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.trust = self.root / "trust"
        self.trust.mkdir(mode=0o755)
        self.capture_parent = self.root / "captures"
        self.capture_parent.mkdir(mode=0o710)
        self.private_key = Ed25519PrivateKey.generate()
        self.private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.config = {
            "schema_version": 1,
            "instance_slug": "qualification-test",
            "qualification_public_root": str(
                self.root
                / "runtime"
                / "state"
                / "persona-qualification"
            ),
            "qualification_private_root": str(
                self.root / "evidence-private"
            ),
            "expected_evidence_uid": 501,
            "attestor_key_id": "qualification-key",
            "private_key_path": str(self.root / "keys" / "private.pem"),
            "public_key_path": str(self.root / "keys" / "public.pem"),
            "public_key_sha256": core.public_key_fingerprint(
                self.public_bytes
            ),
            "head_path": str(self.state / "head.json"),
        }
        self.bundle = self.root / "install" / "bundle"
        self.base_binding = {
            "schema_version": core.INSTALLED_BINDING_SCHEMA_VERSION,
            "instance_manifest_path": str(
                self.root / "instance" / "instance.yaml"
            ),
            "instance_manifest_sha256": "1" * 64,
            "capture_uid": 504,
            "capture_export_gid": 505,
            "verifier_uid": 502,
            "verifier_gid": 503,
            "verifier_python_path": str(self.bundle / "python"),
            "verifier_python_sha256": "2" * 64,
            "verifier_bundle_root": str(self.bundle),
            "verifier_manifest_path": str(
                self.root / "install" / "verifier-manifest.json"
            ),
            "verifier_manifest_sha256": "3" * 64,
            "verifier_entrypoint_path": str(
                self.bundle / "qualification-verifier.py"
            ),
            "verifier_version": (
                "john-lomein.persona.operator-verifier.v4"
            ),
            "verifier_timeout_seconds": 300,
            "capture_parent_path": str(self.capture_parent),
            "evidence_home_path": str(self.root / "evidence-home"),
            "runtime_identity_path": str(self.root / "runtime"),
            "checkout_identity_path": str(self.root / "checkout"),
        }
        self.capture_selection = {
            "schema_version": capture_selection.CAPTURE_SELECTION_SCHEMA,
            "instance_slug": "qualification-test",
            "evidence_uid": 501,
            "verifier_gid": 503,
            "source_roots": {
                "instance_manifest": self.base_binding[
                    "instance_manifest_path"
                ],
                "runtime": self.base_binding["runtime_identity_path"],
                "qualification_public": self.config[
                    "qualification_public_root"
                ],
                "qualification_private": self.config[
                    "qualification_private_root"
                ],
            },
            "path_identities": {
                "evidence_home": self.base_binding["evidence_home_path"],
                "checkout_source": self.base_binding[
                    "checkout_identity_path"
                ],
                "runtime_source": self.base_binding[
                    "runtime_identity_path"
                ],
                "checkout": self.base_binding[
                    "checkout_identity_path"
                ],
                "runtime": self.base_binding["runtime_identity_path"],
            },
            "role_profiles": dict(capture_selection.ROLE_PROFILES),
            "limits": {
                "max_files": 1_024,
                "max_directories": 1_024,
                "max_bytes": 64 * 1024 * 1024,
                "max_file_bytes": 8 * 1024 * 1024,
                "max_depth": 32,
            },
            "lifecycle": {
                "retention": "ephemeral",
                "max_capture_slots": 4,
                "max_orphan_age_seconds": 900,
            },
        }
        self.capture_selection_sha256 = (
            capture_selection.capture_selection_sha256(
                self.capture_selection
            )
        )
        self.operator_policy = {
            "schema_version": core.OPERATOR_POLICY_SCHEMA,
            "instance_slug": "qualification-test",
            "expected_evidence_uid": 501,
            "expected_capture_uid": 504,
            "expected_capture_export_gid": 505,
            "expected_adopted_uid": 0,
            "capture_adoption_binding_schema": (
                adoption_binding.ADOPTION_BINDING_SCHEMA
            ),
            "capture_adoption_required": True,
            "instance_manifest_sha256": "1" * 64,
            "verifier_uid": 502,
            "verifier_gid": 503,
            "verifier_python_sha256": "2" * 64,
            "verifier_bundle_sha256": "3" * 64,
            "verifier_version": (
                "john-lomein.persona.operator-verifier.v4"
            ),
            "verifier_timeout_seconds": 300,
            "verification_execution_policy_sha256": core.sha256_json(
                core.VERIFICATION_EXECUTION_POLICY
            ),
            "capture_selection_sha256": (
                self.capture_selection_sha256
            ),
            "claim_strength": core.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
        }
        self.binding = {
            **self.base_binding,
            "verifier_bundle_sha256": "3" * 64,
            "verification_policy_sha256": "4" * 64,
            "operator_policy": self.operator_policy,
            "operator_policy_sha256": core.sha256_json(
                self.operator_policy
            ),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def policy(
        self,
        capture_root: Path,
    ) -> sandbox.QualificationSandboxPolicy:
        return sandbox.QualificationSandboxPolicy(
            system=platform.system(),
            kernel_release=platform.release(),
            backend_path=Path("/usr/bin/false"),
            backend_sha256="5" * 64,
            bundle_root=self.bundle,
            bundle_sha256="3" * 64,
            capture_parent=self.capture_parent,
            capture_root=capture_root,
            python_path=self.bundle / "python",
            entrypoint_path=self.bundle / "qualification-verifier.py",
            scratch_root=self.root / "scratch",
            activation_receipt_path=(
                self.root / "install" / "activation-receipt.json"
            ),
            verifier_uid=502,
            verifier_gid=503,
            timeout_seconds=300,
        )

    def prepared(
        self,
        capture_root: Path,
    ) -> orchestrator.PreparedQualificationTransaction:
        return orchestrator.prepare_transaction(
            config=self.config,
            verified_binding=self.binding,
            capture_selection=self.capture_selection,
            capture_plan_sha256="7" * 64,
            sandbox_policy=self.policy(capture_root),
            public_key_bytes=self.public_bytes,
            public_projection_path=self.trust / "qualification.json",
        )

    def launcher(
        self,
        events: list[str],
        *,
        run_id: str = "run-001",
    ):
        def launch(
            policy: sandbox.QualificationSandboxPolicy,
            request: dict[str, object],
        ) -> sandbox.SandboxRunResult:
            del policy
            events.append("launch_verifier")
            evidence = {
                "run_id": run_id,
                "summary_sha256": "8" * 64,
                "binding_sha256": "9" * 64,
                "status": "qualified",
                "qualified_at_unix": 100,
                "expires_at_unix": 1_000,
                "verifier_version": self.binding["verifier_version"],
                "verifier_uid": self.binding["verifier_uid"],
                "verifier_bundle_sha256": self.binding[
                    "verifier_bundle_sha256"
                ],
                "verification_policy_sha256": self.binding[
                    "verification_policy_sha256"
                ],
                "capture_manifest_sha256": request[
                    "capture_manifest_sha256"
                ],
                "capture_plan_sha256": request[
                    "capture_plan_sha256"
                ],
                "operator_policy_sha256": self.binding[
                    "operator_policy_sha256"
                ],
                "claim_strength": core.CLAIM_STRENGTH,
                "public_reputation_eligible": False,
                "verified_at_unix": request["verified_at_unix"],
                "observed_evidence_uid": 501,
                "capture_creator_uid": request["capture_uid"],
                "capture_export_gid": request["capture_export_gid"],
                "capture_adopted_uid": request["adopted_uid"],
                "capture_adoption_receipt_sha256": request[
                    "capture_adoption_receipt_sha256"
                ],
                "capture_adoption_policy_sha256": request[
                    "capture_adoption_receipt"
                ]["capture_adoption_policy_sha256"],
                "capture_object_identity_sha256": request[
                    "capture_adoption_receipt"
                ]["object_identity_sha256"],
                "capture_content_inventory_sha256": request[
                    "capture_adoption_receipt"
                ]["content_inventory_sha256"],
                "capture_adopted_at_unix": request[
                    "capture_adoption_receipt"
                ]["adopted_at_unix"],
                "capture_request_sha256": request[
                    "capture_request_sha256"
                ],
                "capture_boundary_policy_sha256": request[
                    "capture_boundary_policy_sha256"
                ],
                "capture_helper_activation_policy_sha256": request[
                    "capture_helper_activation_policy_sha256"
                ],
            }
            wrapper = {
                "schema_version": core.VERIFIER_OUTPUT_SCHEMA,
                "status": "verified",
                "evidence": evidence,
            }
            return sandbox.SandboxRunResult(
                stdout=core.canonical_json(wrapper) + b"\n",
                stderr=b"",
                returncode=0,
                elapsed_seconds=0.1,
            )

        return launch

    def test_atomic_order_opens_key_after_helper_and_control_checks(
        self,
    ) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "a" * 32)
        )
        prepared = self.prepared(capture_root)
        session = _CaptureSession(
            capture_root,
            manifest_sha256="a" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=events,
        )

        def revalidate() -> str:
            events.append("revalidate_controls")
            return prepared.control_sha256

        def key_loader() -> bytes:
            events.append("open_private_key")
            return self.private_bytes

        result = orchestrator.run_prepared_transaction(
            prepared,
            session,
            private_key_loader=key_loader,
            revalidate_controls=revalidate,
            verifier_launcher=self.launcher(events),
            clock=_Clock(110, 120, 130),
            publication_owner_uid=os.geteuid(),
        )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["attestation_publication"], "published")
        self.assertEqual(result["trust_publication"], "published")
        self.assertEqual(
            result["capture_manifest_sha256"],
            "a" * 64,
        )
        self.assertEqual(
            result["observed_capture_manifest_sha256"],
            "a" * 64,
        )
        envelope = json.loads(
            Path(self.config["head_path"]).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            envelope["schema_version"],
            core.HEAD_SCHEMA_VERSION,
        )
        archive_paths = list(
            (self.state / "attestations").glob("*.json")
        )
        self.assertEqual(len(archive_paths), 1)
        archive_path = archive_paths[0]
        signed = json.loads(archive_path.read_text(encoding="utf-8"))
        self.assertEqual(
            signed["payload"]["schema_version"],
            core.PAYLOAD_SCHEMA_VERSION,
        )
        receipt = signed["payload"]["verification"][
            "post_verifier_live_source_revalidation_receipt"
        ]
        self.assertEqual(receipt["revalidated_at_unix"], 115)
        self.assertEqual(
            receipt["verifier_output_sha256"],
            next(
                value.split(":", 1)[1]
                for value in events
                if value.startswith("complete_verification:")
            ),
        )
        key_index = events.index("open_private_key")
        complete_index = next(
            index
            for index, value in enumerate(events)
            if value.startswith("complete_verification:")
        )
        self.assertLess(complete_index, key_index)
        self.assertEqual(events.count("revalidate_controls"), 2)
        self.assertLess(
            max(
                index
                for index, value in enumerate(events)
                if value == "revalidate_controls"
            ),
            key_index,
        )
        self.assertTrue(events[-1].startswith("complete_publication:"))

    def test_cleanup_failure_after_projection_is_committed_pending(
        self,
    ) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "e" * 32)
        )
        prepared = self.prepared(capture_root)
        session = _FaultingCleanupCaptureSession(
            capture_root,
            manifest_sha256="e" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=events,
            publication_cleanup_failures=1,
        )
        private_key_reads = 0

        def key_loader() -> bytes:
            nonlocal private_key_reads
            private_key_reads += 1
            events.append("open_private_key")
            return self.private_bytes

        result = orchestrator.run_prepared_transaction(
            prepared,
            session,
            private_key_loader=key_loader,
            revalidate_controls=lambda: prepared.control_sha256,
            verifier_launcher=self.launcher(events),
            clock=_Clock(110, 120, 130),
            publication_owner_uid=os.geteuid(),
        )
        self.assertEqual(
            result["status"],
            "committed_cleanup_pending",
        )
        self.assertEqual(result["commit_state"], "committed")
        self.assertEqual(result["cleanup_status"], "pending")
        receipt = result["cleanup_receipt"]
        self.assertEqual(
            receipt["schema_version"],
            orchestrator.COMMITTED_CLEANUP_RECEIPT_SCHEMA,
        )
        self.assertEqual(
            receipt["cleanup_operation"],
            "complete_publication",
        )
        self.assertEqual(
            receipt["cleanup_error_code"],
            "capture_adoption_cleanup_remove_failed",
        )
        self.assertEqual(
            result["cleanup_receipt_sha256"],
            core.sha256_json(receipt),
        )
        self.assertEqual(private_key_reads, 1)
        self.assertTrue(Path(self.config["head_path"]).is_file())
        projection_path = self.trust / "qualification.json"
        self.assertTrue(projection_path.is_file())
        head_before = Path(self.config["head_path"]).read_bytes()
        projection_before = projection_path.read_bytes()
        self.assertFalse(
            any(value.startswith("abort:") for value in events)
        )
        self.assertNotIn("close", events)

        events_before_reconciliation = list(events)
        serialized_receipt = json.loads(json.dumps(receipt))
        reconciliation = orchestrator.reconcile_committed_cleanup(
            serialized_receipt,
            session,
        )
        self.assertEqual(
            reconciliation["status"],
            "committed_cleanup_complete",
        )
        self.assertEqual(
            reconciliation["cleanup_status"],
            "complete",
        )
        self.assertEqual(private_key_reads, 1)
        self.assertEqual(
            events[len(events_before_reconciliation) :],
            [
                "complete_publication:"
                + result["trust_projection_sha256"]
            ],
        )
        self.assertEqual(
            Path(self.config["head_path"]).read_bytes(),
            head_before,
        )
        self.assertEqual(
            projection_path.read_bytes(),
            projection_before,
        )
        self.assertEqual(
            json.loads(head_before)["chain_sequence"],
            result["chain_sequence"],
        )
        self.assertFalse(
            any(value.startswith("abort:") for value in events)
        )

    def test_source_revalidation_receipt_binds_exact_verifier_output(
        self,
    ) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "1" * 32)
        )
        prepared = self.prepared(capture_root)
        private_key_reads = 0

        def key_loader() -> bytes:
            nonlocal private_key_reads
            private_key_reads += 1
            return self.private_bytes

        with self.assertRaises(
            core.QualificationAttestorError
        ) as caught:
            orchestrator.run_prepared_transaction(
                prepared,
                _CaptureSession(
                    capture_root,
                    manifest_sha256="1" * 64,
                    selection_sha256=self.capture_selection_sha256,
                    events=events,
                    receipt_overrides={
                        "verifier_output_sha256": "0" * 64,
                    },
                ),
                private_key_loader=key_loader,
                revalidate_controls=lambda: prepared.control_sha256,
                verifier_launcher=self.launcher(events),
                clock=_Clock(110, 120),
                publication_owner_uid=os.geteuid(),
            )
        self.assertEqual(
            caught.exception.code,
            (
                "source_revalidation_receipt_"
                "verifier_output_sha256_mismatch"
            ),
        )
        self.assertEqual(private_key_reads, 0)
        self.assertIn(
            (
                "abort:source_revalidation_receipt_"
                "verifier_output_sha256_mismatch"
            ),
            events,
        )

    def test_signing_clock_cannot_precede_revalidation_completion(
        self,
    ) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "2" * 32)
        )
        prepared = self.prepared(capture_root)
        private_key_reads = 0

        def key_loader() -> bytes:
            nonlocal private_key_reads
            private_key_reads += 1
            return self.private_bytes

        with self.assertRaises(
            core.QualificationAttestorError
        ) as caught:
            orchestrator.run_prepared_transaction(
                prepared,
                _CaptureSession(
                    capture_root,
                    manifest_sha256="2" * 64,
                    selection_sha256=self.capture_selection_sha256,
                    events=events,
                    revalidated_at_unix=125,
                ),
                private_key_loader=key_loader,
                revalidate_controls=lambda: prepared.control_sha256,
                verifier_launcher=self.launcher(events),
                clock=_Clock(110, 120),
                publication_owner_uid=os.geteuid(),
            )
        self.assertEqual(
            caught.exception.code,
            "qualification_clock_rollback",
        )
        self.assertEqual(private_key_reads, 0)
        self.assertIn("abort:qualification_clock_rollback", events)

    def test_cleanup_reconciliation_retries_cleanup_only(
        self,
    ) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "f" * 32)
        )
        prepared = self.prepared(capture_root)
        session = _FaultingCleanupCaptureSession(
            capture_root,
            manifest_sha256="f" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=events,
            publication_cleanup_failures=2,
        )
        result = orchestrator.run_prepared_transaction(
            prepared,
            session,
            private_key_loader=lambda: self.private_bytes,
            revalidate_controls=lambda: prepared.control_sha256,
            verifier_launcher=self.launcher(events),
            clock=_Clock(110, 120, 130),
            publication_owner_uid=os.geteuid(),
        )
        before_retry = list(events)
        first_retry = orchestrator.reconcile_committed_cleanup(
            result["cleanup_receipt"],
            session,
        )
        self.assertEqual(
            first_retry["status"],
            "committed_cleanup_pending",
        )
        self.assertEqual(
            events[len(before_retry) :],
            [
                "complete_publication:"
                + result["trust_projection_sha256"]
            ],
        )
        second_retry = orchestrator.reconcile_committed_cleanup(
            first_retry["cleanup_receipt"],
            session,
        )
        self.assertEqual(
            second_retry["status"],
            "committed_cleanup_complete",
        )
        self.assertEqual(events.count("launch_verifier"), 1)
        self.assertEqual(
            sum(
                value.startswith("complete_signing:")
                for value in events
            ),
            1,
        )
        self.assertEqual(
            sum(
                value.startswith("complete_publication:")
                for value in events
            ),
            3,
        )
        self.assertFalse(
            any(value.startswith("abort:") for value in events)
        )

    def test_cleanup_receipt_is_bound_before_cleanup_retry(self) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "0" * 32)
        )
        prepared = self.prepared(capture_root)
        session = _FaultingCleanupCaptureSession(
            capture_root,
            manifest_sha256="0" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=events,
            publication_cleanup_failures=1,
        )
        result = orchestrator.run_prepared_transaction(
            prepared,
            session,
            private_key_loader=lambda: self.private_bytes,
            revalidate_controls=lambda: prepared.control_sha256,
            verifier_launcher=self.launcher(events),
            clock=_Clock(110, 120, 130),
            publication_owner_uid=os.geteuid(),
        )
        tampered = copy.deepcopy(result["cleanup_receipt"])
        tampered["capture_session_id"] = "1" * 64
        before = list(events)
        with self.assertRaises(
            core.QualificationAttestorError
        ) as caught:
            orchestrator.reconcile_committed_cleanup(
                tampered,
                session,
            )
        self.assertEqual(
            caught.exception.code,
            "cleanup_session_id_mismatch",
        )
        self.assertEqual(events, before)
        self.assertFalse(
            any(value.startswith("abort:") for value in events)
        )

    def test_request_v4_binds_adoption_sparse_selection_and_identities(
        self,
    ) -> None:
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "d" * 32)
        )
        prepared = self.prepared(capture_root)
        session = _CaptureSession(
            capture_root,
            manifest_sha256="a" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=[],
        )
        request = orchestrator.build_verifier_request(
            prepared,
            session,
            verified_at_unix=200,
        )
        self.assertEqual(
            request["schema_version"],
            "john-lomein.persona.operator-verifier-request.v4",
        )
        self.assertEqual(
            request["capture_selection"],
            self.capture_selection,
        )
        self.assertEqual(
            request["capture_selection_sha256"],
            self.capture_selection_sha256,
        )
        self.assertEqual(
            request["checkout_identity_path"],
            self.base_binding["checkout_identity_path"],
        )
        self.assertEqual(
            request["runtime_identity_path"],
            self.base_binding["runtime_identity_path"],
        )

        drifted = copy.deepcopy(self.capture_selection)
        drifted["path_identities"]["checkout"] = str(
            self.root / "other-checkout"
        )
        with self.assertRaisesRegex(
            core.QualificationAttestorError,
            "capture_selection_binding_mismatch",
        ):
            orchestrator.prepare_transaction(
                config=self.config,
                verified_binding=self.binding,
                capture_selection=drifted,
                capture_plan_sha256="7" * 64,
                sandbox_policy=self.policy(capture_root),
                public_key_bytes=self.public_bytes,
                public_projection_path=(
                    self.trust / "qualification.json"
                ),
            )

    def test_control_drift_aborts_before_private_key(self) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "b" * 32)
        )
        prepared = self.prepared(capture_root)
        session = _CaptureSession(
            capture_root,
            manifest_sha256="b" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=events,
        )
        calls = 0

        def revalidate() -> str:
            nonlocal calls
            calls += 1
            return (
                prepared.control_sha256
                if calls == 1
                else "0" * 64
            )

        with self.assertRaises(
            core.QualificationAttestorError
        ) as caught:
            orchestrator.run_prepared_transaction(
                prepared,
                session,
                private_key_loader=lambda: (_ for _ in ()).throw(
                    AssertionError("private key opened after control drift")
                ),
                revalidate_controls=revalidate,
                verifier_launcher=self.launcher(events),
                clock=_Clock(110),
                publication_owner_uid=os.geteuid(),
            )
        self.assertEqual(
            caught.exception.code,
            "qualification_controls_changed_during_run",
        )
        self.assertIn(
            "abort:qualification_controls_changed_during_run",
            events,
        )
        self.assertEqual(events[-1], "close")
        self.assertFalse(Path(self.config["head_path"]).exists())

    def test_initial_session_mismatch_aborts_before_private_key(
        self,
    ) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "b" * 32)
        )
        prepared = self.prepared(capture_root)
        session = _CaptureSession(
            capture_root,
            manifest_sha256="b" * 64,
            selection_sha256="0" * 64,
            events=events,
        )
        private_key_reads = 0

        def key_loader() -> bytes:
            nonlocal private_key_reads
            private_key_reads += 1
            return self.private_bytes

        with self.assertRaises(
            core.QualificationAttestorError
        ) as caught:
            orchestrator.run_prepared_transaction(
                prepared,
                session,
                private_key_loader=key_loader,
                revalidate_controls=lambda: prepared.control_sha256,
                verifier_launcher=self.launcher(events),
                clock=_Clock(110),
                publication_owner_uid=os.geteuid(),
            )
        self.assertEqual(
            caught.exception.code,
            (
                "capture_helper_adoption_receipt_"
                "capture_selection_sha256_mismatch"
            ),
        )
        self.assertEqual(private_key_reads, 0)
        self.assertEqual(
            events,
            [
                (
                    "abort:capture_helper_adoption_receipt_"
                    "capture_selection_sha256_mismatch"
                ),
                "close",
            ],
        )
        self.assertFalse(Path(self.config["head_path"]).exists())

    def test_projection_failure_reconciles_keylessly_without_recapture(
        self,
    ) -> None:
        first_events: list[str] = []
        first_root = (
            self.capture_parent
            / ("opaque-capture-" + "c" * 32)
        )
        first = self.prepared(first_root)
        self.trust.chmod(0o700)
        private_key_reads = 0

        def first_loader() -> bytes:
            nonlocal private_key_reads
            private_key_reads += 1
            return self.private_bytes

        first_session = _CaptureSession(
            first_root,
            manifest_sha256="c" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=first_events,
        )
        pending = orchestrator.run_prepared_transaction(
            first,
            first_session,
            private_key_loader=first_loader,
            revalidate_controls=lambda: first.control_sha256,
            verifier_launcher=self.launcher(first_events),
            clock=_Clock(110, 120, 130),
            publication_owner_uid=os.geteuid(),
        )
        self.assertEqual(
            pending["status"],
            "publication_reconciliation_required",
        )
        self.assertEqual(
            pending["commit_state"],
            "attestation_committed",
        )
        self.assertEqual(
            pending["publication_state"],
            "trust_projection_pending",
        )
        self.assertEqual(pending["cleanup_status"], "complete")
        self.assertEqual(private_key_reads, 1)
        self.assertTrue(Path(self.config["head_path"]).exists())
        self.assertTrue(
            any(value.startswith("complete_signing:") for value in first_events)
        )
        self.assertFalse(
            any(value.startswith("abort:") for value in first_events)
        )

        self.trust.chmod(0o755)
        before_reconciliation = list(first_events)
        result = orchestrator.reconcile_pending_publication(
            first,
            pending["publication_receipt"],
            session=first_session,
            clock=_Clock(140),
            publication_owner_uid=os.geteuid(),
        )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["commit_state"], "committed")
        self.assertEqual(result["cleanup_status"], "complete")
        self.assertEqual(private_key_reads, 1)
        self.assertEqual(first_events.count("launch_verifier"), 1)
        self.assertEqual(
            first_events[len(before_reconciliation) :],
            [],
        )
        projection = json.loads(
            (self.trust / "qualification.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            projection["head"]["attestation_sha256"],
            result["attestation_sha256"],
        )

    def test_archive_written_head_failure_repairs_without_key(self) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "4" * 32)
        )
        prepared = self.prepared(capture_root)
        session = _CaptureSession(
            capture_root,
            manifest_sha256="4" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=events,
        )
        private_key_reads = 0

        def key_loader() -> bytes:
            nonlocal private_key_reads
            private_key_reads += 1
            return self.private_bytes

        original_replace = core._replace_json_at
        replacement_calls = 0

        def fail_first_head_replace(*args, **kwargs):
            nonlocal replacement_calls
            replacement_calls += 1
            if replacement_calls == 1:
                raise RuntimeError("simulated head write loss")
            return original_replace(*args, **kwargs)

        with mock.patch.object(
            core,
            "_replace_json_at",
            side_effect=fail_first_head_replace,
        ):
            pending = orchestrator.run_prepared_transaction(
                prepared,
                session,
                private_key_loader=key_loader,
                revalidate_controls=lambda: prepared.control_sha256,
                verifier_launcher=self.launcher(events),
                clock=_Clock(110, 120),
                publication_owner_uid=os.geteuid(),
            )
        self.assertEqual(
            pending["status"],
            "publication_reconciliation_required",
        )
        self.assertEqual(private_key_reads, 1)
        self.assertEqual(replacement_calls, 2)
        self.assertTrue(Path(self.config["head_path"]).is_file())
        self.assertFalse(
            any(value.startswith("abort:") for value in events)
        )

        result = orchestrator.reconcile_pending_publication(
            prepared,
            pending["publication_receipt"],
            session=session,
            clock=_Clock(130),
            publication_owner_uid=os.geteuid(),
        )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(private_key_reads, 1)
        self.assertEqual(events.count("launch_verifier"), 1)

    def test_persistent_sign_repair_failure_defers_exact_authority(
        self,
    ) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "9" * 32)
        )
        prepared = self.prepared(capture_root)
        session = _CaptureSession(
            capture_root,
            manifest_sha256="9" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=events,
        )
        with mock.patch.object(
            core,
            "_replace_json_at",
            side_effect=RuntimeError("persistent head write loss"),
        ):
            result = orchestrator.run_prepared_transaction(
                prepared,
                session,
                private_key_loader=lambda: self.private_bytes,
                revalidate_controls=lambda: prepared.control_sha256,
                verifier_launcher=self.launcher(events),
                clock=_Clock(110, 120),
                publication_owner_uid=os.geteuid(),
            )
        self.assertEqual(result["status"], "operator_attention")
        self.assertEqual(
            result["commit_state"],
            "publication_ambiguous",
        )
        self.assertEqual(
            result["recovery_handoff_status"],
            "deferred",
        )
        receipt = result["ambiguity_receipt"]
        self.assertEqual(
            receipt["capture_recovery_handoff_sha256"],
            session.recovery_handoff_receipt_sha256,
        )
        self.assertTrue(
            any(
                value.startswith("defer_publication_ambiguity:")
                for value in events
            )
        )
        self.assertFalse(
            any(value.startswith("abort:") for value in events)
        )

    def test_interrupted_archive_link_repairs_without_key(self) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "5" * 32)
        )
        prepared = self.prepared(capture_root)
        session = _CaptureSession(
            capture_root,
            manifest_sha256="5" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=events,
        )
        private_key_reads = 0

        def key_loader() -> bytes:
            nonlocal private_key_reads
            private_key_reads += 1
            return self.private_bytes

        original_unlink = os.unlink
        unlink_calls = 0

        def fail_two_temp_unlinks(*args, **kwargs):
            nonlocal unlink_calls
            unlink_calls += 1
            if unlink_calls <= 2:
                raise OSError("simulated link-before-unlink loss")
            return original_unlink(*args, **kwargs)

        with mock.patch.object(
            core.os,
            "unlink",
            side_effect=fail_two_temp_unlinks,
        ):
            pending = orchestrator.run_prepared_transaction(
                prepared,
                session,
                private_key_loader=key_loader,
                revalidate_controls=lambda: prepared.control_sha256,
                verifier_launcher=self.launcher(events),
                clock=_Clock(110, 120),
                publication_owner_uid=os.geteuid(),
            )
        self.assertEqual(
            pending["status"],
            "publication_reconciliation_required",
        )
        self.assertGreaterEqual(unlink_calls, 3)
        self.assertEqual(private_key_reads, 1)
        self.assertTrue(Path(self.config["head_path"]).is_file())
        self.assertFalse(
            any(value.startswith("abort:") for value in events)
        )

    def test_projection_durable_readback_skips_pending_state(self) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "6" * 32)
        )
        prepared = self.prepared(capture_root)
        original_publish = trust_projection.publish_projection

        def publish_then_lose_ack(*args, **kwargs):
            original_publish(*args, **kwargs)
            raise RuntimeError("simulated projection ACK loss")

        with mock.patch.object(
            trust_projection,
            "publish_projection",
            side_effect=publish_then_lose_ack,
        ):
            result = orchestrator.run_prepared_transaction(
                prepared,
                _CaptureSession(
                    capture_root,
                    manifest_sha256="6" * 64,
                    selection_sha256=self.capture_selection_sha256,
                    events=events,
                ),
                private_key_loader=lambda: self.private_bytes,
                revalidate_controls=lambda: prepared.control_sha256,
                verifier_launcher=self.launcher(events),
                clock=_Clock(110, 120, 130),
                publication_owner_uid=os.geteuid(),
            )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["commit_state"], "committed")
        self.assertEqual(
            result["trust_publication"],
            "published_readback",
        )
        self.assertFalse(
            any(value.startswith("abort:") for value in events)
        )

    def test_signing_ack_failure_retries_before_cleanup_only(self) -> None:
        events: list[str] = []
        capture_root = (
            self.capture_parent
            / ("opaque-capture-" + "a" * 32)
        )
        prepared = self.prepared(capture_root)
        self.trust.chmod(0o700)
        session = _FaultingSigningCaptureSession(
            capture_root,
            manifest_sha256="a" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=events,
            fail_on_calls={1, 2, 3},
        )
        private_key_reads = 0

        def key_loader() -> bytes:
            nonlocal private_key_reads
            private_key_reads += 1
            return self.private_bytes

        pending = orchestrator.run_prepared_transaction(
            prepared,
            session,
            private_key_loader=key_loader,
            revalidate_controls=lambda: prepared.control_sha256,
            verifier_launcher=self.launcher(events),
            clock=_Clock(110, 120, 130),
            publication_owner_uid=os.geteuid(),
        )
        self.assertEqual(
            pending["status"],
            "publication_reconciliation_required",
        )
        self.assertEqual(pending["cleanup_status"], "pending")
        self.trust.chmod(0o755)
        cleanup_pending = orchestrator.reconcile_pending_publication(
            prepared,
            pending["publication_receipt"],
            session=session,
            clock=_Clock(140),
            publication_owner_uid=os.geteuid(),
        )
        self.assertEqual(
            cleanup_pending["status"],
            "committed_cleanup_pending",
        )
        self.assertEqual(
            cleanup_pending["cleanup_receipt"]["cleanup_operation"],
            "complete_signing_and_publication",
        )
        before_cleanup = list(events)
        completed = orchestrator.reconcile_committed_cleanup(
            cleanup_pending["cleanup_receipt"],
            session,
        )
        self.assertEqual(
            completed["status"],
            "committed_cleanup_complete",
        )
        self.assertEqual(
            events[len(before_cleanup) :],
            [
                "complete_signing:"
                + cleanup_pending["attestation_sha256"],
                "complete_publication:"
                + cleanup_pending["trust_projection_sha256"],
            ],
        )
        self.assertEqual(private_key_reads, 1)
        self.assertEqual(events.count("launch_verifier"), 1)

    def test_equivalent_recapture_receipt_binds_committed_evidence(
        self,
    ) -> None:
        self.trust.chmod(0o700)
        first_events: list[str] = []
        first_root = (
            self.capture_parent
            / ("opaque-capture-" + "7" * 32)
        )
        first = self.prepared(first_root)
        private_key_reads = 0

        def first_loader() -> bytes:
            nonlocal private_key_reads
            private_key_reads += 1
            return self.private_bytes

        first_pending = orchestrator.run_prepared_transaction(
            first,
            _CaptureSession(
                first_root,
                manifest_sha256="7" * 64,
                selection_sha256=self.capture_selection_sha256,
                events=first_events,
            ),
            private_key_loader=first_loader,
            revalidate_controls=lambda: first.control_sha256,
            verifier_launcher=self.launcher(first_events),
            clock=_Clock(110, 120, 130),
            publication_owner_uid=os.geteuid(),
        )
        self.assertEqual(
            first_pending["status"],
            "publication_reconciliation_required",
        )
        self.assertEqual(private_key_reads, 1)

        second_events: list[str] = []
        second_root = (
            self.capture_parent
            / ("opaque-capture-" + "8" * 32)
        )
        second = self.prepared(second_root)
        second_session = _CaptureSession(
            second_root,
            manifest_sha256="8" * 64,
            selection_sha256=self.capture_selection_sha256,
            events=second_events,
            revalidated_at_unix=145,
        )
        second_pending = orchestrator.run_prepared_transaction(
            second,
            second_session,
            private_key_loader=lambda: (_ for _ in ()).throw(
                AssertionError("private key reopened for recapture")
            ),
            revalidate_controls=lambda: second.control_sha256,
            verifier_launcher=self.launcher(second_events),
            clock=_Clock(140, 150, 160),
            publication_owner_uid=os.geteuid(),
        )
        receipt = second_pending["publication_receipt"]
        self.assertNotEqual(
            receipt["requested_evidence_sha256"],
            receipt["committed_evidence_sha256"],
        )
        self.assertEqual(private_key_reads, 1)

        self.trust.chmod(0o755)
        completed = orchestrator.reconcile_pending_publication(
            second,
            receipt,
            session=second_session,
            clock=_Clock(170),
            publication_owner_uid=os.geteuid(),
        )
        self.assertEqual(completed["status"], "verified")
        self.assertEqual(private_key_reads, 1)
        self.assertEqual(second_events.count("launch_verifier"), 1)

    def test_public_entrypoint_remains_fail_closed(self) -> None:
        with self.assertRaises(
            core.QualificationAttestorError
        ) as caught:
            orchestrator.attest_configured()
        self.assertEqual(
            caught.exception.code,
            "protected_attestor_not_installed",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
