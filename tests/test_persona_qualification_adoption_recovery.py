from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import pickle
import stat
import sys
import unittest
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_persona_qualification_transaction_journal as journal_fixtures  # noqa: E402
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_reconciliation
    as adoption_reconciliation,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_recovery as recovery,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_result as adoption_result,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_recovered_adoption_evidence
    as recovered_evidence,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_transaction_journal as journal,
)


class PersonaQualificationAdoptionRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.journal_fixture = (
            journal_fixtures.PersonaQualificationTransactionJournalTests(
                "runTest"
            )
        )
        self.journal_fixture.setUp()
        self.addCleanup(self.journal_fixture.doCleanups)

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(
            recovery.RecoveredAdoptionRecoveryError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    @staticmethod
    def canonical_json(value) -> bytes:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

    @classmethod
    def object_identity_sha256(cls, info: os.stat_result) -> str:
        return hashlib.sha256(
            cls.canonical_json(
                [
                    int(info.st_dev),
                    int(info.st_ino),
                    int(stat.S_IFMT(info.st_mode)),
                ]
            )
        ).hexdigest()

    @classmethod
    def full_stat_sha256(cls, info: os.stat_result) -> str:
        return hashlib.sha256(
            cls.canonical_json(
                [
                    int(info.st_dev),
                    int(info.st_ino),
                    int(info.st_mode),
                    int(info.st_uid),
                    int(info.st_gid),
                    int(info.st_nlink),
                    int(info.st_size),
                    int(
                        getattr(
                            info,
                            "st_mtime_ns",
                            int(info.st_mtime * 1_000_000_000),
                        )
                    ),
                    int(
                        getattr(
                            info,
                            "st_ctime_ns",
                            int(info.st_ctime * 1_000_000_000),
                        )
                    ),
                ]
            )
        ).hexdigest()

    def make_fixture(self) -> SimpleNamespace:
        owner_uid = os.geteuid()
        verifier_gid = os.getegid()
        if verifier_gid == 0:
            if owner_uid != 0:
                self.skipTest(
                    "unprivileged process has no positive effective group"
                )
            verifier_gid = 1
        export_gid = 60_001 if verifier_gid != 60_001 else 60_002
        final_name = "opaque-capture-" + "a" * 32
        final_parent = self.journal_fixture.root / "final-captures"
        capture_root = final_parent / final_name
        nested = capture_root / "nested"
        final_parent.mkdir()
        capture_root.mkdir()
        nested.mkdir()
        root_bytes = b"john-lomein\n"
        nested_bytes = b"recovered-object\n"
        root_file = capture_root / "identity.txt"
        nested_file = nested / "result.bin"
        root_file.write_bytes(root_bytes)
        nested_file.write_bytes(nested_bytes)

        paths = (
            final_parent,
            capture_root,
            nested,
            root_file,
            nested_file,
        )
        for path in paths:
            current = path.stat()
            if (
                int(current.st_uid) != owner_uid
                or int(current.st_gid) != verifier_gid
            ):
                os.chown(path, owner_uid, verifier_gid)
        root_file.chmod(recovery.ADOPTED_FILE_MODE)
        nested_file.chmod(recovery.ADOPTED_FILE_MODE)
        nested.chmod(recovery.ADOPTED_DIRECTORY_MODE)
        capture_root.chmod(recovery.ADOPTED_DIRECTORY_MODE)
        final_parent.chmod(recovery.FINAL_PARENT_MODE)

        def make_writable_for_cleanup() -> None:
            if not final_parent.exists():
                return
            for directory, directories, files in os.walk(
                final_parent,
                topdown=True,
                followlinks=False,
            ):
                Path(directory).chmod(0o700)
                for name in directories:
                    (Path(directory) / name).chmod(0o700)
                for name in files:
                    (Path(directory) / name).chmod(0o600)

        self.addCleanup(make_writable_for_cleanup)
        parent_info = final_parent.stat()
        root_info = capture_root.stat()
        records = [
            {"path": "", "type": "directory"},
            {
                "path": "identity.txt",
                "type": "file",
                "size": len(root_bytes),
                "sha256": hashlib.sha256(root_bytes).hexdigest(),
            },
            {"path": "nested", "type": "directory"},
            {
                "path": "nested/result.bin",
                "type": "file",
                "size": len(nested_bytes),
                "sha256": hashlib.sha256(nested_bytes).hexdigest(),
            },
        ]
        limits = {
            "max_files": 10,
            "max_directories": 10,
            "max_bytes": 10_000,
            "max_file_bytes": 1_000,
            "max_depth": 8,
        }
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        parent_fd = os.open(final_parent, flags)
        fixture = SimpleNamespace(
            owner_uid=owner_uid,
            verifier_gid=verifier_gid,
            export_gid=export_gid,
            final_name=final_name,
            final_parent=final_parent,
            capture_root=capture_root,
            root_file=root_file,
            nested_file=nested_file,
            parent_fd=parent_fd,
            parent_identity_sha256=self.object_identity_sha256(
                parent_info
            ),
            filesystem_device=int(parent_info.st_dev),
            object_identity_sha256=self.object_identity_sha256(root_info),
            object_stat_sha256=self.full_stat_sha256(root_info),
            object_nlink=int(root_info.st_nlink),
            inventory_sha256=hashlib.sha256(
                self.canonical_json(
                    sorted(records, key=lambda item: item["path"])
                )
            ).hexdigest(),
            file_count=2,
            directory_count=2,
            total_bytes=len(root_bytes) + len(nested_bytes),
            largest_file_bytes=max(len(root_bytes), len(nested_bytes)),
            maximum_depth=1,
            limits=limits,
        )

        def close_parent_fd() -> None:
            if fixture.parent_fd >= 0:
                os.close(fixture.parent_fd)
                fixture.parent_fd = -1

        self.addCleanup(close_parent_fd)
        self.bind_journal_fixture(fixture)
        store = self.journal_fixture.open_store()
        fixture.session = self.journal_fixture.reserve(store)
        self.journal_fixture.advance_to_adoption_reconciled(
            fixture.session,
            result="recovered_adoption",
        )
        return fixture

    def bind_journal_fixture(self, fixture: SimpleNamespace) -> None:
        support = self.journal_fixture
        original_details_for = support.details_for
        original_receipt = support.adoption_reconciliation_receipt

        def details_for(_support, session, state):
            value = original_details_for(session, state)
            if state == "staging_create_intent":
                value["required_device"] = fixture.filesystem_device
                value["export_gid"] = fixture.export_gid
            elif state == "capture_ready":
                value["provisional_name"] = fixture.final_name
                value["capture_object_identity_sha256"] = (
                    fixture.object_identity_sha256
                )
                event = dict(value)
                binding = event.pop("lifecycle_operation_binding")
                binding["supervisor_event_evidence_sha256"] = (
                    journal._capture_event_evidence_sha256(event)
                )
                value["lifecycle_operation_binding"] = binding
            elif state == "adoption_intent":
                value.update(
                    {
                        "provisional_name": fixture.final_name,
                        "final_name": fixture.final_name,
                        "final_parent_identity_sha256": (
                            fixture.parent_identity_sha256
                        ),
                        "final_parent_filesystem_device": (
                            fixture.filesystem_device
                        ),
                        "capture_object_identity_sha256": (
                            fixture.object_identity_sha256
                        ),
                        "verifier_gid": fixture.verifier_gid,
                        "limits": dict(fixture.limits),
                    }
                )
            return value

        def adoption_reconciliation_receipt(
            _support,
            session,
            *,
            result,
        ):
            value = original_receipt(session, result=result)
            if result == "recovered_adoption":
                value.update(
                    {
                        "final_object_stat_sha256": (
                            fixture.object_stat_sha256
                        ),
                        "final_content_inventory_sha256": (
                            fixture.inventory_sha256
                        ),
                        "final_file_count": fixture.file_count,
                        "final_directory_count": (
                            fixture.directory_count
                        ),
                        "final_total_bytes": fixture.total_bytes,
                        "final_largest_file_bytes": (
                            fixture.largest_file_bytes
                        ),
                        "final_maximum_depth": fixture.maximum_depth,
                        "final_object_owner_uid": 0,
                        "final_object_group_gid": fixture.verifier_gid,
                        "final_object_mode": (
                            recovery.ADOPTED_DIRECTORY_MODE
                        ),
                        "final_object_nlink": fixture.object_nlink,
                    }
                )
            return (
                adoption_reconciliation
                .normalize_adoption_reconciliation_receipt(value)
            )

        support.details_for = MethodType(details_for, support)
        support.adoption_reconciliation_receipt = MethodType(
            adoption_reconciliation_receipt,
            support,
        )

    def recover(self, fixture: SimpleNamespace):
        return recovery._recover_adopted_capture_for_test(
            fixture.session,
            fixture.parent_fd,
            expected_owner_uid=fixture.owner_uid,
            expected_verifier_gid=fixture.verifier_gid,
        )

    def test_public_entry_shapes_are_narrow_and_production_is_dormant(
        self,
    ) -> None:
        for callable_ in (
            recovery.recover_adopted_capture,
            recovery.recover_adopted_capture_canary,
        ):
            self.assertEqual(
                tuple(inspect.signature(callable_).parameters),
                ("session", "final_parent_fd"),
            )
        seam = inspect.signature(
            recovery._recover_adopted_capture_for_test
        )
        self.assertEqual(
            tuple(seam.parameters),
            (
                "session",
                "final_parent_fd",
                "expected_owner_uid",
                "expected_verifier_gid",
            ),
        )
        self.assertEqual(
            seam.parameters["expected_owner_uid"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(
            seam.parameters["expected_verifier_gid"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        for forbidden in (
            "path",
            "final_name",
            "record",
            "receipt",
            "evidence",
        ):
            self.assertNotIn(forbidden, seam.parameters)
        self.assertFalse(recovery.PRODUCTION_ACTIVATION)
        self.assert_code(
            "adoption_recovery_production_disabled",
            recovery.recover_adopted_capture,
            object(),
            -1,
        )

    def test_real_journal_mint_retains_and_revalidates_exact_object(
        self,
    ) -> None:
        fixture = self.make_fixture()
        real_open = os.open
        open_calls = []
        mint_calls = []
        original_mint = (
            journal.TransactionJournalSession
            .mint_recovered_adoption_evidence
        )

        def recording_open(path, flags, *args, **kwargs):
            open_calls.append((path, flags, kwargs))
            return real_open(path, flags, *args, **kwargs)

        def tracked_mint(session):
            mint_calls.append(session)
            return original_mint(session)

        with (
            mock.patch.object(
                recovery.os,
                "open",
                side_effect=recording_open,
            ),
            mock.patch.object(
                journal.TransactionJournalSession,
                "mint_recovered_adoption_evidence",
                new=tracked_mint,
            ),
        ):
            lease = self.recover(fixture)
        self.addCleanup(lambda: lease.close() if lease.active else None)
        self.assertEqual(mint_calls, [fixture.session])
        final_opens = [
            (flags, kwargs)
            for path, flags, kwargs in open_calls
            if path == fixture.final_name
        ]
        self.assertTrue(final_opens)
        for flags, arguments in final_opens:
            self.assertIn("dir_fd", arguments)
            self.assertEqual(flags & os.O_NOFOLLOW, os.O_NOFOLLOW)
            if hasattr(os, "O_CLOEXEC"):
                self.assertEqual(flags & os.O_CLOEXEC, os.O_CLOEXEC)
        file_flags = recovery._file_flags()
        if hasattr(os, "O_NONBLOCK"):
            self.assertEqual(
                file_flags & os.O_NONBLOCK,
                os.O_NONBLOCK,
            )

        evidence = lease.recovered_adoption_evidence
        self.assertEqual(
            recovered_evidence.normalize_recovered_adoption_evidence(
                evidence
            ),
            evidence,
        )
        result = lease.capture_adoption_result
        self.assertEqual(
            adoption_result.normalize_capture_adoption_result(result),
            result,
        )
        self.assertEqual(
            result["kind"],
            adoption_result.RECOVERED_ADOPTION_KIND,
        )
        provenance = lease.capture_adoption_provenance
        self.assertEqual(
            provenance,
            adoption_result.project_capture_adoption_provenance(result),
        )
        evidence["final_name"] = "caller-mutation"
        result["kind"] = adoption_result.NORMAL_ADOPTION_KIND
        provenance["kind"] = adoption_result.NORMAL_ADOPTION_KIND
        self.assertEqual(lease.final_name, fixture.final_name)
        self.assertEqual(
            lease.capture_adoption_result["kind"],
            adoption_result.RECOVERED_ADOPTION_KIND,
        )

        parent_fd, root_fd = lease._descriptor_numbers_for_test()
        self.assertFalse(os.get_inheritable(parent_fd))
        self.assertFalse(os.get_inheritable(root_fd))
        os.close(fixture.parent_fd)
        fixture.parent_fd = -1
        pre = lease.pre_verifier_revalidate()
        self.assertEqual(
            pre["transaction_journal_schema"],
            evidence["transaction_journal_schema"],
        )
        self.assertEqual(
            pre["transaction_journal_head_revision"],
            fixture.session.latest_record.revision,
        )
        self.assertEqual(
            pre["transaction_journal_head_record_sha256"],
            fixture.session.latest_record.record_sha256,
        )
        self.assertEqual(pre, lease.post_verifier_revalidate())

        with self.assertRaises(TypeError):
            copy.copy(lease)
        with self.assertRaises(TypeError):
            copy.deepcopy(lease)
        with self.assertRaises(TypeError):
            pickle.dumps(lease)
        with self.assertRaises(TypeError):
            recovery.RecoveredAdoptedCaptureLease(
                _token=object(),
                parent_fd=-1,
                root_fd=-1,
                expected_owner_uid=fixture.owner_uid,
                expected_verifier_gid=fixture.verifier_gid,
                session=None,
                live_snapshot=None,
                evidence={},
                result={},
                provenance={},
            )

        lease.close()
        self.assertFalse(lease.active)
        with self.assertRaises(OSError):
            os.fstat(parent_fd)
        with self.assertRaises(OSError):
            os.fstat(root_fd)
        self.assertTrue(fixture.capture_root.is_dir())
        self.assertTrue(fixture.root_file.is_file())

    def test_tree_mutation_fails_post_revalidation_without_cleanup(
        self,
    ) -> None:
        fixture = self.make_fixture()
        lease = self.recover(fixture)
        self.addCleanup(lambda: lease.close() if lease.active else None)
        lease.pre_verifier_revalidate()
        fixture.root_file.chmod(0o640)
        self.assert_code(
            "adoption_recovery_file_unsafe",
            lease.post_verifier_revalidate,
        )
        self.assertTrue(fixture.capture_root.exists())
        fixture.root_file.chmod(recovery.ADOPTED_FILE_MODE)
        lease.close()
        self.assertTrue(fixture.capture_root.exists())

    def test_different_parent_descriptor_is_rejected(self) -> None:
        fixture = self.make_fixture()
        other = self.journal_fixture.root / "other-final-captures"
        other.mkdir()
        if int(other.stat().st_gid) != fixture.verifier_gid:
            os.chown(other, fixture.owner_uid, fixture.verifier_gid)
        other.chmod(recovery.FINAL_PARENT_MODE)
        self.addCleanup(lambda: other.chmod(0o700) if other.exists() else None)
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(other, flags)
        self.addCleanup(os.close, descriptor)
        self.assert_code(
            "adoption_recovery_final_parent_identity_mismatch",
            recovery._recover_adopted_capture_for_test,
            fixture.session,
            descriptor,
            expected_owner_uid=fixture.owner_uid,
            expected_verifier_gid=fixture.verifier_gid,
        )

    def test_journal_head_advance_invalidates_getters_and_post_gate(
        self,
    ) -> None:
        fixture = self.make_fixture()
        lease = self.recover(fixture)
        self.addCleanup(lambda: lease.close() if lease.active else None)
        lease.pre_verifier_revalidate()
        fixture.session.append_event(
            expected_state="adoption_reconciled",
            next_state="operator_attention",
            details={
                "from_state": "adoption_reconciled",
                "reason_code": "recovered_adoption_evidence_required",
                "incident_sha256": fixture.session.latest_record.details[
                    "adoption_reconciliation_receipt_sha256"
                ],
            },
            recorded_at_unix=fixture.session.latest_record.revision + 1,
        )
        self.assert_code(
            "transaction_journal_live_snapshot_stale",
            lambda: lease.recovered_adoption_evidence,
        )
        self.assert_code(
            "transaction_journal_live_snapshot_stale",
            lease.post_verifier_revalidate,
        )
        lease.close()
        self.assertTrue(fixture.capture_root.exists())

    def test_creator_pid_binding_is_fail_closed(self) -> None:
        fixture = self.make_fixture()
        lease = self.recover(fixture)
        self.addCleanup(lambda: lease.close() if lease.active else None)
        creator_pid = os.getpid()
        with mock.patch.object(
            recovery.os,
            "getpid",
            return_value=creator_pid + 1,
        ):
            self.assertFalse(lease.active)
            self.assert_code(
                "adoption_recovery_lease_creator_process_mismatch",
                lease.pre_verifier_revalidate,
            )
            self.assert_code(
                "adoption_recovery_lease_creator_process_mismatch",
                lease.close,
            )
        lease.close()


if __name__ == "__main__":
    unittest.main()
