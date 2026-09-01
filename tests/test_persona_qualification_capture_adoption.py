from __future__ import annotations

import errno
import gc
import os
import pickle
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_adoption as adoption,
)


class PersonaQualificationCaptureAdoptionTests(unittest.TestCase):
    maxDiff = None

    session_id = "1" * 64
    capture_name = (
        "opaque-capture-0123456789abcdef0123456789abcdef"
    )

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(adoption.CaptureAdoptionError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def _chmod_writable(self, root: Path) -> None:
        if not root.exists():
            return
        for directory, directories, files in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            path = Path(directory)
            try:
                path.chmod(0o700)
            except OSError:
                pass
            for name in directories:
                child = path / name
                if not child.is_symlink():
                    try:
                        child.chmod(0o700)
                    except OSError:
                        pass
            for name in files:
                child = path / name
                if not child.is_symlink():
                    try:
                        child.chmod(0o600)
                    except OSError:
                        pass

    def _fixture(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        staging = root / "staging-session"
        final = root / "captures"
        staging.mkdir(mode=adoption.STAGING_PARENT_MODE)
        final.mkdir(mode=adoption.FINAL_PARENT_MODE)
        staging.chmod(adoption.STAGING_PARENT_MODE)
        final.chmod(adoption.FINAL_PARENT_MODE)
        capture = staging / self.capture_name
        capture.mkdir(mode=0o700)
        nested = capture / "runtime" / "state"
        nested.mkdir(parents=True, mode=0o700)
        (capture / "instance.yaml").write_bytes(b"instance\n")
        (nested / "status.json").write_bytes(b'{"status":"qualified"}\n')
        for directory, directories, files in os.walk(
            capture,
            topdown=False,
        ):
            path = Path(directory)
            for name in files:
                (path / name).chmod(adoption.PROVISIONAL_FILE_MODE)
            for name in directories:
                (path / name).chmod(
                    adoption.PROVISIONAL_DIRECTORY_MODE
                )
            path.chmod(adoption.PROVISIONAL_DIRECTORY_MODE)
        self.addCleanup(self._chmod_writable, root)
        return temporary, staging, final, capture

    def _object_digest(self, capture: Path) -> str:
        descriptor = os.open(capture, os.O_RDONLY)
        try:
            return adoption.capture_object_identity_sha256(descriptor)
        finally:
            os.close(descriptor)

    def _policy(
        self,
        staging: Path,
        final: Path,
        capture: Path,
        **changes,
    ) -> adoption.CaptureAdoptionPolicy:
        values = {
            "session_id": self.session_id,
            "staging_parent": staging,
            "final_parent": final,
            "provisional_name": self.capture_name,
            "final_name": self.capture_name,
            "expected_object_sha256": self._object_digest(capture),
            "capture_uid": 501,
            "capture_gid": 601,
            "verifier_uid": 502,
            "verifier_gid": 602,
            "capture_selection_sha256": "2" * 64,
            "capture_plan_sha256": "3" * 64,
            "capture_manifest_sha256": "4" * 64,
            "capture_boundary_policy_sha256": "5" * 64,
            "helper_activation_policy_sha256": "6" * 64,
            "request_sha256": "7" * 64,
            "max_files": 32,
            "max_directories": 32,
            "max_bytes": 1024 * 1024,
            "max_file_bytes": 256 * 1024,
            "max_depth": 16,
        }
        values.update(changes)
        return adoption.CaptureAdoptionPolicy(**values)

    def _proof(
        self,
        *,
        session_id: str | None = None,
        capture_uid: int = 501,
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
            self.assertEqual(os.read(read_fd, 1), b"1")
        finally:
            os.close(read_fd)
        return adoption.reap_capture_child(
            session_id=session_id or self.session_id,
            capture_uid=capture_uid,
            pid=pid,
            timeout_seconds=2,
        )

    def _open_parents(
        self,
        staging: Path,
        final: Path,
    ) -> tuple[int, int]:
        return os.open(staging, os.O_RDONLY), os.open(final, os.O_RDONLY)

    def _adopt(
        self,
        policy: adoption.CaptureAdoptionPolicy,
        proof: adoption.ChildDeathProof,
        staging: Path,
        final: Path,
        *,
        provisional_authority=None,
        fault_hook=None,
    ) -> adoption.AdoptedCaptureLease:
        staging_fd, final_fd = self._open_parents(staging, final)
        try:
            return adoption._adopt_staged_capture_for_test(
                policy,
                proof,
                provisional_authority=provisional_authority,
                staging_parent_fd=staging_fd,
                final_parent_fd=final_fd,
                fault_hook=fault_hook,
            )
        finally:
            os.close(staging_fd)
            os.close(final_fd)

    def test_policy_is_strict_and_production_stays_disabled(self) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(staging, final, capture)
        normalized = adoption.normalize_adoption_policy(policy)
        self.assertEqual(normalized, policy)
        record = policy.activation_record()
        self.assertEqual(
            record["ownership_contract"],
            "capture-export-to-root-verifier-same-inode",
        )
        self.assertEqual(
            record["rename_contract"],
            "same-filesystem-exclusive-no-replace-no-copy",
        )
        self.assertEqual(
            record["provisional_authority_contract"],
            "ready-retained-fd-one-shot-no-name-reopen",
        )
        self.assertEqual(
            record["staging_lifecycle_contract"],
            "root-session-leaf-reap-revoke-clean-or-quarantine",
        )
        self.assertEqual(
            record["adopted_modes"],
            {"parent": 0o710, "directory": 0o550, "file": 0o440},
        )
        self.assertIs(adoption.PRODUCTION_ACTIVATION, False)
        self.assert_code(
            "capture_adoption_production_disabled",
            adoption.adopt_staged_capture,
            policy,
            object(),
            staging_parent_fd=-1,
            final_parent_fd=-1,
        )

        self.assert_code(
            "capture_adoption_uid_separation_missing",
            adoption.normalize_adoption_policy,
            self._policy(
                staging,
                final,
                capture,
                verifier_uid=501,
            ),
        )
        self.assert_code(
            "capture_adoption_group_separation_missing",
            adoption.normalize_adoption_policy,
            self._policy(
                staging,
                final,
                capture,
                verifier_gid=601,
            ),
        )
        self.assert_code(
            "capture_adoption_parents_overlap",
            adoption.normalize_adoption_policy,
            self._policy(
                staging,
                final,
                capture,
                final_parent=staging / "nested",
            ),
        )

    def test_child_death_proof_is_opaque_one_shot_and_session_bound(
        self,
    ) -> None:
        with self.assertRaises(TypeError):
            adoption.ChildDeathProof(
                _token=object(),
                session_id=self.session_id,
                capture_uid=501,
                pid=123,
                status=0,
                process_group_reaped=True,
            )
        proof = self._proof()
        with self.assertRaises(TypeError):
            pickle.dumps(proof)
        self.assertEqual(
            proof._consume(
                session_id=self.session_id,
                capture_uid=501,
            )[1],
            0,
        )
        self.assert_code(
            "capture_adoption_child_proof_consumed",
            proof._consume,
            session_id=self.session_id,
            capture_uid=501,
        )

        wrong = self._proof()
        self.assert_code(
            "capture_adoption_child_proof_mismatch",
            wrong._consume,
            session_id="f" * 64,
            capture_uid=501,
        )

    def test_ready_authority_is_cloexec_and_closes_on_failure(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(staging, final, capture)
        staging_fd = os.open(staging, os.O_RDONLY)
        opened: list[tuple[int, int]] = []
        real_open = os.open

        def recording_open(path, flags, *args, **kwargs):
            descriptor = real_open(path, flags, *args, **kwargs)
            opened.append((descriptor, flags))
            return descriptor

        try:
            with mock.patch.object(
                adoption.os,
                "open",
                side_effect=recording_open,
            ):
                authority = adoption.retain_provisional_capture(
                    staging_parent_fd=staging_fd,
                    session_id=self.session_id,
                    capture_uid=501,
                    provisional_name=self.capture_name,
                    expected_object_sha256=(
                        policy.expected_object_sha256
                    ),
                )
            descriptor = authority._fileno_for_test()
            self.assertFalse(os.get_inheritable(descriptor))
            self.assertEqual(len(opened), 1)
            flags = opened[0][1]
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_DIRECTORY)
            self.assertTrue(flags & os.O_CLOEXEC)
            with self.assertRaises(TypeError):
                pickle.dumps(authority)
            authority.close()
            with self.assertRaises(OSError):
                os.fstat(descriptor)

            opened.clear()
            with mock.patch.object(
                adoption.os,
                "open",
                side_effect=recording_open,
            ):
                self.assert_code(
                    "capture_adoption_object_identity_mismatch",
                    adoption.retain_provisional_capture,
                    staging_parent_fd=staging_fd,
                    session_id=self.session_id,
                    capture_uid=501,
                    provisional_name=self.capture_name,
                    expected_object_sha256="f" * 64,
                )
            rejected_descriptor = opened[0][0]
            with self.assertRaises(OSError):
                os.fstat(rejected_descriptor)
        finally:
            os.close(staging_fd)

    def test_retained_authority_transfers_once_into_adoption(self) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(staging, final, capture)
        staging_fd = os.open(staging, os.O_RDONLY)
        try:
            authority = adoption.retain_provisional_capture(
                staging_parent_fd=staging_fd,
                session_id=self.session_id,
                capture_uid=501,
                provisional_name=self.capture_name,
                expected_object_sha256=policy.expected_object_sha256,
            )
            retained = os.fstat(authority._fileno_for_test())
        finally:
            os.close(staging_fd)
        lease = self._adopt(
            policy,
            self._proof(),
            staging,
            final,
            provisional_authority=authority,
        )
        self.addCleanup(lease.cleanup)
        self.assertTrue(authority.consumed)
        self.assertFalse(authority.active)
        self.assert_code(
            "capture_adoption_provisional_authority_consumed",
            authority._consume,
            policy,
        )
        adopted = os.stat(final / self.capture_name)
        self.assertEqual(
            (adopted.st_dev, adopted.st_ino),
            (retained.st_dev, retained.st_ino),
        )

    def test_name_replacement_cannot_rebind_retained_authority(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(staging, final, capture)
        staging_fd = os.open(staging, os.O_RDONLY)
        try:
            authority = adoption.retain_provisional_capture(
                staging_parent_fd=staging_fd,
                session_id=self.session_id,
                capture_uid=501,
                provisional_name=self.capture_name,
                expected_object_sha256=policy.expected_object_sha256,
            )
            retained_descriptor = authority._fileno_for_test()
        finally:
            os.close(staging_fd)

        detached = staging / "detached-original"
        capture.rename(detached)
        replacement = staging / self.capture_name
        replacement.mkdir(mode=adoption.PROVISIONAL_DIRECTORY_MODE)
        replacement.chmod(adoption.PROVISIONAL_DIRECTORY_MODE)

        with mock.patch.object(
            adoption,
            "_open_bound_directory",
            wraps=adoption._open_bound_directory,
        ) as reopened:
            self.assert_code(
                "capture_adoption_provisional_name_rebound",
                self._adopt,
                policy,
                self._proof(),
                staging,
                final,
                provisional_authority=authority,
            )
        reopened.assert_not_called()
        self.assertTrue(authority.consumed)
        with self.assertRaises(OSError):
            os.fstat(retained_descriptor)
        self.assertTrue(detached.exists())
        self.assertTrue(replacement.exists())
        self.assertFalse((final / self.capture_name).exists())

    def test_adoption_keeps_exact_inode_and_returns_cleanup_lease(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        original = capture.stat()
        policy = self._policy(staging, final, capture)
        lease = self._adopt(
            policy,
            self._proof(),
            staging,
            final,
        )
        self.addCleanup(lease.cleanup)

        adopted = final / self.capture_name
        self.assertFalse(capture.exists())
        self.assertTrue(adopted.is_dir())
        observed = adopted.stat()
        self.assertEqual(
            (observed.st_dev, observed.st_ino),
            (original.st_dev, original.st_ino),
        )
        self.assertEqual(
            stat.S_IMODE(observed.st_mode),
            adoption.ADOPTED_DIRECTORY_MODE,
        )
        for directory, _directories, files in os.walk(adopted):
            path = Path(directory)
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                adoption.ADOPTED_DIRECTORY_MODE,
            )
            for name in files:
                self.assertEqual(
                    stat.S_IMODE((path / name).stat().st_mode),
                    adoption.ADOPTED_FILE_MODE,
                )
        receipt = lease.receipt
        self.assertEqual(receipt["status"], "adopted")
        self.assertEqual(receipt["capture_uid"], 501)
        self.assertEqual(receipt["capture_gid"], 601)
        self.assertEqual(receipt["adopted_uid"], os.geteuid())
        self.assertEqual(receipt["verifier_uid"], 502)
        self.assertEqual(receipt["verifier_gid"], 602)
        self.assertTrue(receipt["process_group_reaped"])
        self.assertTrue(receipt["staging_namespace_revoked"])
        self.assertTrue(receipt["rename_noreplace"])
        self.assertEqual(
            receipt["object_identity_sha256"],
            policy.expected_object_sha256,
        )
        self.assertRegex(lease.receipt_sha256, r"^[0-9a-f]{64}$")
        with self.assertRaises(TypeError):
            pickle.dumps(lease)

        lease.cleanup()
        self.assertFalse(adopted.exists())
        self.assertFalse(lease.active)
        lease.cleanup()

    def test_revalidation_binding_pins_retained_descriptor_and_name(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(staging, final, capture)
        lease = self._adopt(
            policy,
            self._proof(),
            staging,
            final,
        )
        self.addCleanup(lease.cleanup)

        binding = lease._assert_post_verifier_revalidation_binding()
        self.assertEqual(
            binding,
            {
                "snapshot_root": final / self.capture_name,
                "capture_adoption_receipt_sha256": (
                    lease.receipt_sha256
                ),
                "capture_object_identity_sha256": (
                    policy.expected_object_sha256
                ),
                "capture_plan_sha256": policy.capture_plan_sha256,
                "capture_manifest_sha256": (
                    policy.capture_manifest_sha256
                ),
            },
        )

        os.set_inheritable(lease._root_fd, True)
        try:
            self.assert_code(
                "capture_adoption_revalidation_"
                "descriptor_inheritable",
                lease._assert_post_verifier_revalidation_binding,
            )
        finally:
            os.set_inheritable(lease._root_fd, False)

        adopted = final / self.capture_name
        detached = final / "detached-adopted-capture"
        adopted.rename(detached)
        adopted.mkdir(mode=adoption.ADOPTED_DIRECTORY_MODE)
        adopted.chmod(adoption.ADOPTED_DIRECTORY_MODE)
        try:
            self.assert_code(
                "capture_adoption_revalidation_name_rebound",
                lease._assert_post_verifier_revalidation_binding,
            )
        finally:
            adopted.rmdir()
            detached.rename(adopted)

        self.assert_code(
            "capture_adoption_revalidation_receipt_mismatch",
            lease._assert_post_verifier_revalidation_binding,
        )

    def test_recovery_handoff_is_path_free_durable_and_never_gc_cleans(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(staging, final, capture)
        lease = self._adopt(
            policy,
            self._proof(),
            staging,
            final,
        )
        adopted = final / self.capture_name
        root_fd = lease._root_fd
        parent_fd = lease._parent_fd
        adoption_receipt_sha256 = lease.receipt_sha256

        with (
            mock.patch.object(adoption.os, "getuid", return_value=0),
            mock.patch.object(adoption.os, "geteuid", return_value=0),
            mock.patch.object(
                adoption.time,
                "time",
                return_value=1_900_000_000,
            ),
        ):
            with lease as bound:
                receipt = bound.defer_to_recovery(
                    expected_object_sha256=(
                        policy.expected_object_sha256
                    ),
                    expected_adoption_receipt_sha256=(
                        adoption_receipt_sha256
                    ),
                    requested_evidence_sha256="8" * 64,
                )

        self.assertEqual(
            receipt,
            adoption.normalize_recovery_handoff_receipt(receipt),
        )
        self.assertEqual(
            set(receipt),
            adoption.RECOVERY_HANDOFF_RECEIPT_FIELDS,
        )
        self.assertEqual(
            receipt["schema_version"],
            adoption.RECOVERY_HANDOFF_RECEIPT_SCHEMA,
        )
        self.assertEqual(
            receipt["status"],
            adoption.RECOVERY_HANDOFF_STATUS,
        )
        self.assertEqual(receipt["capture_session_id"], self.session_id)
        self.assertEqual(
            receipt["capture_adoption_receipt_sha256"],
            adoption_receipt_sha256,
        )
        self.assertEqual(
            receipt["capture_object_identity_sha256"],
            policy.expected_object_sha256,
        )
        self.assertEqual(
            receipt["capture_request_sha256"],
            policy.request_sha256,
        )
        self.assertEqual(receipt["requested_evidence_sha256"], "8" * 64)
        self.assertEqual(receipt["final_name"], self.capture_name)
        self.assertNotIn("/", receipt["final_name"])
        self.assertEqual(receipt["deferred_by_uid"], 0)
        self.assertEqual(receipt["deferred_at_unix"], 1_900_000_000)
        self.assertRegex(
            receipt["deferred_object_stat_sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertRegex(
            receipt["recovery_parent_identity_sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertRegex(
            adoption.recovery_handoff_receipt_sha256(receipt),
            r"^[0-9a-f]{64}$",
        )
        self.assertTrue(lease.detached)
        self.assertFalse(lease.active)
        self.assertFalse(lease.cleanup_pending)
        self.assertTrue(adopted.is_dir())
        self.assertEqual(lease.recovery_handoff_receipt, receipt)
        self.assertEqual(
            lease.recovery_handoff_receipt_sha256,
            adoption.recovery_handoff_receipt_sha256(receipt),
        )
        with self.assertRaises(OSError):
            os.fstat(root_fd)
        with self.assertRaises(OSError):
            os.fstat(parent_fd)

        # Exact retries are pure receipt reads.  A different ambiguity digest
        # can never retarget the detached authority.
        self.assertEqual(
            lease.defer_to_recovery(
                expected_object_sha256=policy.expected_object_sha256,
                expected_adoption_receipt_sha256=(
                    adoption_receipt_sha256
                ),
                requested_evidence_sha256="8" * 64,
            ),
            receipt,
        )
        self.assert_code(
            "capture_adoption_recovery_handoff_evidence_mismatch",
            lease.defer_to_recovery,
            expected_object_sha256=policy.expected_object_sha256,
            expected_adoption_receipt_sha256=(
                adoption_receipt_sha256
            ),
            requested_evidence_sha256="9" * 64,
        )
        lease.cleanup()
        lease.__del__()
        self.assertTrue(adopted.is_dir())
        del bound
        del lease
        gc.collect()
        self.assertTrue(adopted.is_dir())

    def test_recovery_handoff_rejects_wrong_binding_and_rebound_name(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(staging, final, capture)
        lease = self._adopt(
            policy,
            self._proof(),
            staging,
            final,
        )
        self.addCleanup(lease.cleanup)
        receipt_sha256 = lease.receipt_sha256
        with (
            mock.patch.object(adoption.os, "getuid", return_value=0),
            mock.patch.object(adoption.os, "geteuid", return_value=0),
        ):
            self.assert_code(
                "capture_adoption_recovery_handoff_binding_mismatch",
                lease.defer_to_recovery,
                expected_object_sha256=policy.expected_object_sha256,
                expected_adoption_receipt_sha256="f" * 64,
                requested_evidence_sha256="8" * 64,
            )

            adopted = final / self.capture_name
            detached = final / "detached-adopted-capture"
            adopted.rename(detached)
            adopted.mkdir(mode=adoption.ADOPTED_DIRECTORY_MODE)
            adopted.chmod(adoption.ADOPTED_DIRECTORY_MODE)
            try:
                self.assert_code(
                    "capture_adoption_revalidation_name_rebound",
                    lease.defer_to_recovery,
                    expected_object_sha256=(
                        policy.expected_object_sha256
                    ),
                    expected_adoption_receipt_sha256=receipt_sha256,
                    requested_evidence_sha256="8" * 64,
                )
            finally:
                adopted.rmdir()
                detached.rename(adopted)
        self.assertFalse(lease.detached)
        self.assertTrue(lease.active)

    def test_recovery_handoff_receipt_normalizer_rejects_extra_fields(
        self,
    ) -> None:
        value = {
            "schema_version": adoption.RECOVERY_HANDOFF_RECEIPT_SCHEMA,
            "status": adoption.RECOVERY_HANDOFF_STATUS,
            "capture_session_id": self.session_id,
            "capture_adoption_receipt_sha256": "1" * 64,
            "capture_object_identity_sha256": "2" * 64,
            "capture_plan_sha256": "3" * 64,
            "capture_manifest_sha256": "4" * 64,
            "capture_request_sha256": "5" * 64,
            "requested_evidence_sha256": "6" * 64,
            "final_name": self.capture_name,
            "deferred_object_stat_sha256": "7" * 64,
            "recovery_parent_identity_sha256": "8" * 64,
            "deferred_by_uid": 0,
            "deferred_at_unix": 1_900_000_000,
        }
        self.assertEqual(
            adoption.normalize_recovery_handoff_receipt(value),
            value,
        )
        value["capture_root"] = "/forbidden/path"
        self.assert_code(
            "capture_adoption_recovery_handoff_receipt_fields_invalid",
            adoption.normalize_recovery_handoff_receipt,
            value,
        )

    def test_cleanup_retains_authority_after_remove_failure_and_retries(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(staging, final, capture)
        lease = self._adopt(
            policy,
            self._proof(),
            staging,
            final,
        )
        self.addCleanup(lease.cleanup)
        adopted = final / self.capture_name
        root_fd = lease._root_fd
        parent_fd = lease._parent_fd
        real_rmdir = os.rmdir
        injected = False

        def fail_root_remove_once(
            name,
            *,
            dir_fd=None,
        ) -> None:
            nonlocal injected
            if (
                not injected
                and name == self.capture_name
                and dir_fd == parent_fd
            ):
                injected = True
                raise OSError(errno.EIO, "injected root remove failure")
            real_rmdir(name, dir_fd=dir_fd)

        with mock.patch.object(
            adoption.os,
            "rmdir",
            side_effect=fail_root_remove_once,
        ):
            self.assert_code(
                "capture_adoption_cleanup_remove_failed",
                lease.cleanup,
            )

        self.assertTrue(injected)
        self.assertTrue(lease.active)
        self.assertTrue(lease.cleanup_pending)
        os.fstat(root_fd)
        os.fstat(parent_fd)
        self.assertTrue(adopted.is_dir())

        lease.cleanup()
        self.assertFalse(adopted.exists())
        self.assertFalse(lease.active)
        self.assertFalse(lease.cleanup_pending)

    def test_cleanup_retries_only_parent_fsync_after_unlink(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(staging, final, capture)
        lease = self._adopt(
            policy,
            self._proof(),
            staging,
            final,
        )
        self.addCleanup(lease.cleanup)
        adopted = final / self.capture_name
        root_fd = lease._root_fd
        parent_fd = lease._parent_fd
        real_fsync = os.fsync
        injected = False

        def fail_parent_fsync_once(descriptor: int) -> None:
            nonlocal injected
            if not injected and descriptor == parent_fd:
                injected = True
                raise OSError(errno.EIO, "injected parent fsync failure")
            real_fsync(descriptor)

        with mock.patch.object(
            adoption.os,
            "fsync",
            side_effect=fail_parent_fsync_once,
        ):
            self.assert_code(
                "capture_adoption_cleanup_parent_fsync_failed",
                lease.cleanup,
            )

        self.assertTrue(injected)
        self.assertFalse(adopted.exists())
        self.assertTrue(lease.active)
        self.assertTrue(lease.cleanup_pending)
        os.fstat(root_fd)
        os.fstat(parent_fd)

        with mock.patch.object(
            adoption,
            "_unlink_bound_tree",
            wraps=adoption._unlink_bound_tree,
        ) as unlink:
            lease.cleanup()
        unlink.assert_not_called()
        self.assertFalse(lease.active)
        self.assertFalse(lease.cleanup_pending)

    def test_exclusive_rename_never_overwrites_existing_destination(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        destination = final / self.capture_name
        destination.mkdir(mode=0o700)
        marker = destination / "do-not-replace"
        marker.write_text("sentinel", encoding="utf-8")
        policy = self._policy(staging, final, capture)
        self.assert_code(
            "capture_adoption_destination_exists",
            self._adopt,
            policy,
            self._proof(),
            staging,
            final,
        )
        self.assertEqual(marker.read_text(encoding="utf-8"), "sentinel")
        self.assertFalse(capture.exists())

    def test_wrong_inode_and_extra_staging_entry_fail_before_adoption(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(
            staging,
            final,
            capture,
            expected_object_sha256="f" * 64,
        )
        self.assert_code(
            "capture_adoption_object_identity_mismatch",
            self._adopt,
            policy,
            self._proof(),
            staging,
            final,
        )
        # READY-time identity rejection occurs before namespace revocation or
        # cleanup authority is accepted, so the staged object remains for the
        # separate recovery path.
        self.assertTrue(capture.exists())

        temporary2, staging2, final2, capture2 = self._fixture()
        self.addCleanup(temporary2.cleanup)
        (staging2 / "unexpected").write_text("x", encoding="utf-8")
        policy2 = self._policy(staging2, final2, capture2)
        self.assert_code(
            "capture_adoption_staging_inventory_invalid",
            self._adopt,
            policy2,
            self._proof(),
            staging2,
            final2,
        )
        self.assertFalse((final2 / self.capture_name).exists())

    def test_unsafe_entry_types_and_hardlinks_are_quarantined(self) -> None:
        for kind in ("symlink", "fifo", "hardlink"):
            with self.subTest(kind=kind):
                temporary, staging, final, capture = self._fixture()
                self.addCleanup(temporary.cleanup)
                unsafe = capture / "unsafe"
                capture.chmod(0o700)
                if kind == "symlink":
                    unsafe.symlink_to(capture / "instance.yaml")
                elif kind == "fifo":
                    os.mkfifo(unsafe, 0o400)
                else:
                    os.link(capture / "instance.yaml", unsafe)
                capture.chmod(adoption.PROVISIONAL_DIRECTORY_MODE)
                policy = self._policy(staging, final, capture)
                self.assert_code(
                    "capture_adoption_failure_cleanup_failed",
                    self._adopt,
                    policy,
                    self._proof(),
                    staging,
                    final,
                )
                self.assertFalse(
                    (final / self.capture_name).exists()
                )
                self.assertTrue(capture.exists())

    def test_failure_during_mixed_chown_or_after_rename_cleans_exact_tree(
        self,
    ) -> None:
        for point_prefix in (
            "after_entry_adopted:",
            "after_rename",
        ):
            with self.subTest(point=point_prefix):
                temporary, staging, final, capture = self._fixture()
                self.addCleanup(temporary.cleanup)
                policy = self._policy(staging, final, capture)

                def fault(point: str) -> None:
                    if point.startswith(point_prefix):
                        raise RuntimeError("injected adoption crash")

                with self.assertRaisesRegex(
                    RuntimeError,
                    "injected adoption crash",
                ):
                    self._adopt(
                        policy,
                        self._proof(),
                        staging,
                        final,
                        fault_hook=fault,
                    )
                self.assertFalse(capture.exists())
                self.assertFalse(
                    (final / self.capture_name).exists()
                )

    def test_cross_device_or_unsupported_rename_has_no_copy_fallback(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        policy = self._policy(staging, final, capture)
        with mock.patch.object(
            adoption,
            "_exclusive_rename",
            side_effect=adoption.CaptureAdoptionError(
                "capture_adoption_cross_device_forbidden"
            ),
        ) as rename:
            self.assert_code(
                "capture_adoption_cross_device_forbidden",
                self._adopt,
                policy,
                self._proof(),
                staging,
                final,
            )
        rename.assert_called_once()
        self.assertFalse(capture.exists())
        self.assertFalse((final / self.capture_name).exists())

    def test_descriptor_relative_recovery_removes_mixed_mode_tree(
        self,
    ) -> None:
        temporary, staging, final, capture = self._fixture()
        self.addCleanup(temporary.cleanup)
        nested = capture / "runtime"
        file_path = nested / "state" / "status.json"
        nested.chmod(adoption.ADOPTED_DIRECTORY_MODE)
        file_path.chmod(adoption.ADOPTED_FILE_MODE)
        policy = self._policy(staging, final, capture)
        staging_fd = os.open(staging, os.O_RDONLY)
        try:
            adoption._recover_staged_capture_for_test(
                policy,
                self._proof(),
                staging_parent_fd=staging_fd,
            )
        finally:
            os.close(staging_fd)
        self.assertFalse(capture.exists())

    def test_child_must_be_a_reaped_session_leader(self) -> None:
        pid = os.fork()
        if pid == 0:
            try:
                time.sleep(2)
            finally:
                os._exit(0)
        try:
            self.assert_code(
                "capture_adoption_child_not_session_leader",
                adoption.reap_capture_child,
                session_id=self.session_id,
                capture_uid=501,
                pid=pid,
                timeout_seconds=1,
            )
        finally:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass

    def test_reaper_pins_pid_through_group_kill_then_final_wait(
        self,
    ) -> None:
        pid = 4242
        events: list[str] = []
        observations = iter(
            (
                None,
                SimpleNamespace(
                    si_pid=pid,
                    si_code=os.CLD_EXITED,
                    si_status=0,
                ),
            )
        )
        state = {"reaped": False}

        def getpgid(observed_pid: int) -> int:
            self.assertEqual(observed_pid, pid)
            events.append("getpgid")
            return pid

        def waitid(idtype: int, observed_pid: int, flags: int):
            self.assertEqual(idtype, os.P_PID)
            self.assertEqual(observed_pid, pid)
            self.assertTrue(flags & os.WNOWAIT)
            self.assertFalse(state["reaped"])
            value = next(observations)
            events.append("waitid-exit" if value else "waitid-empty")
            return value

        def killpg(process_group_id: int, sig: int) -> None:
            # Once waitpid runs this numeric group is considered reused by
            # the seam.  Any later signal would target an unrelated process.
            self.assertFalse(state["reaped"], "killpg after PID reuse")
            self.assertEqual(process_group_id, pid)
            self.assertEqual(sig, signal.SIGKILL)
            events.append("killpg")

        def waitpid(observed_pid: int, options: int) -> tuple[int, int]:
            self.assertEqual((observed_pid, options), (pid, 0))
            events.append("waitpid")
            state["reaped"] = True
            return pid, 0

        proof = adoption._reap_capture_child_with_syscalls(
            session_id=self.session_id,
            capture_uid=501,
            child_pid=pid,
            timeout=2,
            monotonic=lambda: 0.0,
            syscalls=adoption._ReapSyscalls(
                getpgid=getpgid,
                waitid=waitid,
                killpg=killpg,
                waitpid=waitpid,
                waitstatus_to_exitcode=lambda status: status,
                sleep=lambda _seconds: events.append("sleep"),
            ),
        )
        self.assertEqual(
            events,
            [
                "getpgid",
                "waitid-empty",
                "sleep",
                "waitid-exit",
                "killpg",
                "waitpid",
            ],
        )
        self.assertEqual(
            proof._consume(
                session_id=self.session_id,
                capture_uid=501,
            ),
            (pid, 0),
        )

    def test_failed_exit_is_reaped_once_without_post_reap_group_kill(
        self,
    ) -> None:
        pid = 4343
        events: list[str] = []
        state = {"reaped": False}

        def killpg(process_group_id: int, sig: int) -> None:
            self.assertFalse(state["reaped"], "killpg after PID reuse")
            self.assertEqual((process_group_id, sig), (pid, signal.SIGKILL))
            events.append("killpg")

        def waitpid(observed_pid: int, options: int) -> tuple[int, int]:
            self.assertEqual((observed_pid, options), (pid, 0))
            events.append("waitpid")
            state["reaped"] = True
            return pid, 7

        with self.assertRaises(adoption.CaptureAdoptionError) as caught:
            adoption._reap_capture_child_with_syscalls(
                session_id=self.session_id,
                capture_uid=501,
                child_pid=pid,
                timeout=2,
                monotonic=lambda: 0.0,
                syscalls=adoption._ReapSyscalls(
                    getpgid=lambda _pid: pid,
                    waitid=lambda *_args: SimpleNamespace(
                        si_pid=pid,
                        si_code=os.CLD_EXITED,
                        si_status=7,
                    ),
                    killpg=killpg,
                    waitpid=waitpid,
                    waitstatus_to_exitcode=lambda status: status,
                    sleep=lambda _seconds: None,
                ),
            )
        self.assertEqual(
            caught.exception.code,
            "capture_adoption_child_exit_failed",
        )
        self.assertTrue(caught.exception.child_reaped)
        self.assertEqual(events, ["killpg", "waitpid"])


if __name__ == "__main__":
    unittest.main()
