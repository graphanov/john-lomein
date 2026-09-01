from __future__ import annotations

import copy
import hashlib
import os
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_persona_qualification_verifier as verifier_fixtures  # noqa: E402
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_binding as adoption_binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_adoption as adoption,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_plan as capture_plan,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_selection as capture_selection,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_opaque_capture as opaque_capture,
)
from qualification_verifier import (  # noqa: E402
    john_lomein_persona_qualification_verifier as verifier,
)


class AdoptedOpaqueVerifierIntegrationTests(unittest.TestCase):
    """Cross the real capture, adoption, binding, and verifier boundaries."""

    SESSION_ID = "6" * 64
    REQUEST_SHA256 = "7" * 64
    BOUNDARY_POLICY_SHA256 = "8" * 64
    HELPER_POLICY_SHA256 = "9" * 64

    def setUp(self) -> None:
        self.fixture = (
            verifier_fixtures.OpaquePersonaQualificationVerifierTests(
                "test_real_opaque_capture_is_reconstructed_verified_and_bound"
            )
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def assert_code(self, code: str, callable_, **arguments) -> None:
        with self.assertRaises(
            verifier.QualificationVerifierError
        ) as caught:
            callable_(**arguments)
        self.assertEqual(caught.exception.code, code)

    def _export_fixture_sources(self) -> None:
        """Model the E:export 0750/0640 source surface."""

        uid = os.geteuid()
        gid = os.getegid()
        for directory, directories, files in os.walk(
            self.fixture.evidence_home,
            topdown=True,
            followlinks=False,
        ):
            root = Path(directory)
            os.chown(root, uid, gid)
            root.chmod(opaque_capture.EXPORT_SOURCE_DIRECTORY_MODE)
            for name in directories:
                path = root / name
                os.chown(path, uid, gid)
                path.chmod(
                    opaque_capture.EXPORT_SOURCE_DIRECTORY_MODE
                )
            for name in files:
                path = root / name
                os.chown(path, uid, gid)
                path.chmod(opaque_capture.EXPORT_SOURCE_FILE_MODE)

    @staticmethod
    def _bind_distinct_manifest_creator(
        lease: opaque_capture.OpaqueCaptureLease,
        *,
        capture_uid: int,
    ) -> tuple[dict[str, object], str]:
        """Bind the semantic C identity in an unprivileged mechanical run.

        The capture engine still creates and seals every byte itself.  This
        small fixture step changes only the self-described creator UID because
        an unprivileged test process cannot chown a staging tree to a second
        system account.  The real adoption primitive subsequently transforms
        the exact same retained inode and its receipt binds this creator UID.
        """

        manifest = lease.manifest
        manifest["capture_uid"] = capture_uid
        raw = opaque_capture._manifest_bytes(manifest)
        manifest_path = (
            lease.snapshot_root / opaque_capture.OPAQUE_CAPTURE_MANIFEST
        )
        manifest_path.chmod(0o600)
        flags = os.O_WRONLY | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(manifest_path, flags)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise AssertionError("manifest fixture write stalled")
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(
                descriptor,
                opaque_capture.PROVISIONAL_FILE_MODE,
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(lease._fileno_for_test())

        digest = hashlib.sha256(
            opaque_capture._canonical_json(manifest)
        ).hexdigest()
        lease._manifest_bytes_value = raw
        lease._capture_manifest_sha256 = digest
        return manifest, digest

    @staticmethod
    def _reap_child(
        *,
        session_id: str,
        capture_uid: int,
    ) -> adoption.ChildDeathProof:
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_fd)
                os.setsid()
                os.write(write_fd, b"1")
            finally:
                os._exit(0)
        os.close(write_fd)
        try:
            if os.read(read_fd, 1) != b"1":
                raise AssertionError("capture child did not become ready")
        finally:
            os.close(read_fd)
        return adoption.reap_capture_child(
            session_id=session_id,
            capture_uid=capture_uid,
            pid=pid,
            timeout_seconds=2,
        )

    @staticmethod
    def _adopt(
        *,
        policy: adoption.CaptureAdoptionPolicy,
        proof: adoption.ChildDeathProof,
        staging: Path,
        final: Path,
    ) -> adoption.AdoptedCaptureLease:
        staging_fd = os.open(staging, os.O_RDONLY)
        final_fd = os.open(final, os.O_RDONLY)
        try:
            with mock.patch.object(
                adoption.time,
                "time",
                return_value=100,
            ):
                return adoption._adopt_staged_capture_for_test(
                    policy,
                    proof,
                    staging_parent_fd=staging_fd,
                    final_parent_fd=final_fd,
                )
        finally:
            os.close(staging_fd)
            os.close(final_fd)

    def test_real_v2_capture_adoption_is_verified_and_tamper_bound(
        self,
    ) -> None:
        selection = self.fixture.selection()
        plan = capture_selection.compile_current_run_capture_plan(
            selection
        )
        plan_sha256 = capture_plan.capture_plan_sha256(plan)
        selection_sha256 = (
            capture_selection.capture_selection_sha256(selection)
        )
        self._export_fixture_sources()

        staging = self.fixture.root / "capture-v2-staging"
        final = self.fixture.root / "capture-v2-adopted"
        staging.mkdir(mode=adoption.STAGING_PARENT_MODE)
        final.mkdir(mode=adoption.FINAL_PARENT_MODE)
        staging.chmod(adoption.STAGING_PARENT_MODE)
        final.chmod(adoption.FINAL_PARENT_MODE)

        adopted_uid = os.geteuid()
        physical_gid = os.getegid()
        creator_uid = self.fixture.evidence_uid + 20_000
        export_gid = self.fixture.verifier_gid + 20_000
        self.assertNotEqual(creator_uid, adopted_uid)
        self.assertNotEqual(creator_uid, self.fixture.verifier_uid)
        self.assertNotEqual(export_gid, self.fixture.verifier_gid)

        provisional = opaque_capture._capture_opaque_snapshot_from_plan(
            plan=plan,
            plan_sha256=plan_sha256,
            destination_parent=staging,
            capture_uid=adopted_uid,
            capture_gid=physical_gid,
            destination_parent_mode=adoption.STAGING_PARENT_MODE,
            sealed_directory_mode=(
                opaque_capture.PROVISIONAL_DIRECTORY_MODE
            ),
            sealed_file_mode=opaque_capture.PROVISIONAL_FILE_MODE,
            source_gid=physical_gid,
            source_directory_mode=(
                opaque_capture.EXPORT_SOURCE_DIRECTORY_MODE
            ),
            source_file_mode=opaque_capture.EXPORT_SOURCE_FILE_MODE,
        )
        self.addCleanup(provisional.cleanup)
        manifest, manifest_sha256 = (
            self._bind_distinct_manifest_creator(
                provisional,
                capture_uid=creator_uid,
            )
        )

        mechanically_verified = (
            opaque_capture.verify_sealed_opaque_capture(
                provisional.snapshot_root,
                plan=plan,
                expected_plan_sha256=plan_sha256,
                expected_capture_uid=adopted_uid,
                expected_manifest_capture_uid=creator_uid,
                expected_verifier_gid=self.fixture.verifier_gid,
                expected_snapshot_gid=physical_gid,
                expected_manifest_sha256=manifest_sha256,
                expected_directory_mode=(
                    opaque_capture.PROVISIONAL_DIRECTORY_MODE
                ),
                expected_file_mode=(
                    opaque_capture.PROVISIONAL_FILE_MODE
                ),
                expected_source_directory_mode=(
                    opaque_capture.EXPORT_SOURCE_DIRECTORY_MODE
                ),
                expected_source_file_mode=(
                    opaque_capture.EXPORT_SOURCE_FILE_MODE
                ),
            )
        )
        self.assertEqual(mechanically_verified, manifest)
        self.assertEqual(manifest["capture_uid"], creator_uid)
        self.assertEqual(
            {
                entry["source_mode"]
                for entry in manifest["source_directories"]
            },
            {opaque_capture.EXPORT_SOURCE_DIRECTORY_MODE},
        )
        self.assertEqual(
            {entry["source_mode"] for entry in manifest["files"]},
            {opaque_capture.EXPORT_SOURCE_FILE_MODE},
        )

        object_sha256 = (
            provisional._object_identity_sha256_for_adoption()
        )
        verification_arguments, _runner = (
            self.fixture._verification_arguments(provisional)
        )
        verification_arguments.pop("snapshot_owner_uid")
        policy = adoption.CaptureAdoptionPolicy(
            session_id=self.SESSION_ID,
            staging_parent=staging,
            final_parent=final,
            provisional_name=provisional.snapshot_root.name,
            final_name=provisional.snapshot_root.name,
            expected_object_sha256=object_sha256,
            capture_uid=creator_uid,
            capture_gid=export_gid,
            verifier_uid=self.fixture.verifier_uid,
            verifier_gid=self.fixture.verifier_gid,
            capture_selection_sha256=selection_sha256,
            capture_plan_sha256=plan_sha256,
            capture_manifest_sha256=manifest_sha256,
            capture_boundary_policy_sha256=(
                self.BOUNDARY_POLICY_SHA256
            ),
            helper_activation_policy_sha256=(
                self.HELPER_POLICY_SHA256
            ),
            request_sha256=self.REQUEST_SHA256,
            max_files=plan["limits"]["max_files"],
            max_directories=plan["limits"]["max_directories"],
            max_bytes=plan["limits"]["max_bytes"],
            max_file_bytes=plan["limits"]["max_file_bytes"],
            max_depth=plan["limits"]["max_depth"],
        )

        provisional._relinquish_for_adoption()
        proof = self._reap_child(
            session_id=self.SESSION_ID,
            capture_uid=creator_uid,
        )
        adopted = self._adopt(
            policy=policy,
            proof=proof,
            staging=staging,
            final=final,
        )
        self.addCleanup(adopted.cleanup)
        receipt = adopted.receipt
        receipt_sha256 = (
            adoption_binding.adoption_receipt_sha256(receipt)
        )
        self.assertEqual(receipt_sha256, adopted.receipt_sha256)
        self.assertEqual(receipt["capture_uid"], creator_uid)
        self.assertEqual(receipt["adopted_uid"], adopted_uid)
        self.assertNotEqual(
            receipt["capture_uid"],
            receipt["adopted_uid"],
        )

        for directory, _directories, files in os.walk(
            adopted.capture_root
        ):
            root_info = os.lstat(directory)
            self.assertEqual(root_info.st_uid, adopted_uid)
            self.assertEqual(root_info.st_gid, self.fixture.verifier_gid)
            self.assertEqual(
                stat.S_IMODE(root_info.st_mode),
                adoption.ADOPTED_DIRECTORY_MODE,
            )
            for name in files:
                file_info = os.lstat(Path(directory) / name)
                self.assertEqual(file_info.st_uid, adopted_uid)
                self.assertEqual(
                    file_info.st_gid,
                    self.fixture.verifier_gid,
                )
                self.assertEqual(
                    stat.S_IMODE(file_info.st_mode),
                    adoption.ADOPTED_FILE_MODE,
                )

        verification_arguments["snapshot_root"] = adopted.capture_root
        binding_arguments = {
            "capture_adoption_receipt": receipt,
            "expected_capture_adoption_receipt_sha256": (
                receipt_sha256
            ),
            "expected_capture_uid": creator_uid,
            "expected_capture_export_gid": export_gid,
            "expected_adopted_uid": adopted_uid,
            "expected_capture_session_id": self.SESSION_ID,
            "expected_capture_request_sha256": self.REQUEST_SHA256,
            "expected_capture_boundary_policy_sha256": (
                self.BOUNDARY_POLICY_SHA256
            ),
            "expected_capture_helper_activation_policy_sha256": (
                self.HELPER_POLICY_SHA256
            ),
            **verification_arguments,
        }

        def verify_binding(arguments):
            return adoption_binding.verify_adoption_binding(
                arguments["capture_adoption_receipt"],
                expected_receipt_sha256=arguments[
                    "expected_capture_adoption_receipt_sha256"
                ],
                snapshot_root=arguments["snapshot_root"],
                expected_capture_uid=arguments[
                    "expected_capture_uid"
                ],
                expected_export_gid=arguments[
                    "expected_capture_export_gid"
                ],
                expected_adopted_uid=arguments[
                    "expected_adopted_uid"
                ],
                expected_verifier_uid=arguments[
                    "expected_verifier_uid"
                ],
                expected_verifier_gid=arguments[
                    "expected_verifier_gid"
                ],
                expected_capture_selection_sha256=arguments[
                    "expected_capture_selection_sha256"
                ],
                expected_capture_plan_sha256=arguments[
                    "expected_capture_plan_sha256"
                ],
                expected_capture_manifest_sha256=arguments[
                    "expected_capture_manifest_sha256"
                ],
                expected_request_sha256=arguments[
                    "expected_capture_request_sha256"
                ],
                expected_capture_boundary_policy_sha256=arguments[
                    "expected_capture_boundary_policy_sha256"
                ],
                expected_helper_activation_policy_sha256=arguments[
                    "expected_capture_helper_activation_policy_sha256"
                ],
                expected_session_id=arguments[
                    "expected_capture_session_id"
                ],
                verified_at_unix=arguments["verified_at_unix"],
            )

        evidence = verify_binding(binding_arguments)
        if adopted_uid == 0:
            evidence = (
                verifier.verify_adopted_opaque_snapshot_evidence(
                    **binding_arguments
                )
            )
            self.assertEqual(evidence["run_id"], self.fixture.RUN_ID)
        else:
            self.assert_code(
                "adopted_opaque_snapshot_owner_not_root",
                verifier.verify_adopted_opaque_snapshot_evidence,
                **binding_arguments,
            )
        expected_adoption_evidence = {
            "capture_creator_uid": creator_uid,
            "capture_export_gid": export_gid,
            "capture_adopted_uid": adopted_uid,
            "capture_adoption_receipt_sha256": receipt_sha256,
            "capture_adoption_policy_sha256": receipt[
                "capture_adoption_policy_sha256"
            ],
            "capture_object_identity_sha256": receipt[
                "object_identity_sha256"
            ],
            "capture_content_inventory_sha256": receipt[
                "content_inventory_sha256"
            ],
            "capture_adopted_at_unix": receipt[
                "adopted_at_unix"
            ],
            "capture_request_sha256": self.REQUEST_SHA256,
            "capture_boundary_policy_sha256": (
                self.BOUNDARY_POLICY_SHA256
            ),
            "capture_helper_activation_policy_sha256": (
                self.HELPER_POLICY_SHA256
            ),
        }
        self.assertEqual(
            {
                field: evidence[field]
                for field in adoption_binding.ADOPTION_EVIDENCE_FIELDS
            },
            expected_adoption_evidence,
        )
        creator_tamper = {
            **binding_arguments,
            "expected_capture_uid": creator_uid + 1,
        }
        with self.assertRaises(
            adoption_binding.CaptureAdoptionBindingError
        ) as creator_error:
            verify_binding(creator_tamper)
        self.assertEqual(
            creator_error.exception.code,
            "capture_adoption_receipt_capture_uid_mismatch",
        )

        tampered_receipt = copy.deepcopy(receipt)
        tampered_receipt["content_inventory_sha256"] = "a" * 64
        if (
            tampered_receipt["content_inventory_sha256"]
            == receipt["content_inventory_sha256"]
        ):
            tampered_receipt["content_inventory_sha256"] = "b" * 64
        receipt_tamper = {
            **binding_arguments,
            "capture_adoption_receipt": tampered_receipt,
            "expected_capture_adoption_receipt_sha256": (
                adoption_binding.adoption_receipt_sha256(
                    tampered_receipt
                )
            ),
        }
        with self.assertRaises(
            adoption_binding.CaptureAdoptionBindingError
        ) as receipt_error:
            verify_binding(receipt_tamper)
        self.assertEqual(
            receipt_error.exception.code,
            "capture_adoption_inventory_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
