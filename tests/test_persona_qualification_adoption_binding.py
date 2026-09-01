from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_binding as binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_result
    as adoption_result,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_recovered_adoption_evidence
    as recovered_adoption,
)


class _RootOwnedStat:
    """Unprivileged mechanical view of the same kernel stat record."""

    def __init__(self, source: os.stat_result) -> None:
        self._source = source
        self.st_uid = 0

    def __getattr__(self, field: str) -> Any:
        return getattr(self._source, field)


class PersonaQualificationAdoptionBindingTests(unittest.TestCase):
    maxDiff = None

    capture_name = (
        "opaque-capture-0123456789abcdef0123456789abcdef"
    )
    session_id = "a" * 64
    adopted_at_unix = 1_900_000_000
    verified_at_unix = 1_900_000_001

    def setUp(self) -> None:
        if os.geteuid() < 1 or os.getegid() < 1:
            self.skipTest(
                "fixture exercises an unprivileged adopted uid/gid"
            )
        self.adopted_uid = os.geteuid()
        self.verifier_uid = os.geteuid()
        self.verifier_gid = os.getegid()
        self.capture_uid = self.verifier_uid + 10_000
        self.export_gid = self.verifier_gid + 10_000
        self._real_fstat = os.fstat

        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.addCleanup(self._make_writable, self.base)
        self.snapshot_root = self.base / self.capture_name
        self._populate_tree(self.snapshot_root)
        self.receipt = self._receipt_for_tree()

    def _make_writable(self, root: Path) -> None:
        if not root.exists():
            return
        for directory, directories, files in os.walk(
            root,
            topdown=False,
            followlinks=False,
        ):
            path = Path(directory)
            for name in files:
                child = path / name
                if not child.is_symlink():
                    try:
                        child.chmod(0o600)
                    except OSError:
                        pass
            for name in directories:
                child = path / name
                if not child.is_symlink():
                    try:
                        child.chmod(0o700)
                    except OSError:
                        pass
            try:
                path.chmod(0o700)
            except OSError:
                pass

    def _populate_tree(self, root: Path) -> None:
        nested = root / "runtime" / "state"
        nested.mkdir(parents=True)
        (root / "manifest.json").write_bytes(b'{"ok":true}\n')
        (root / "empty").write_bytes(b"")
        (nested / "status.txt").write_bytes(b"qualified\n")
        for directory, directories, files in os.walk(
            root,
            topdown=False,
            followlinks=False,
        ):
            path = Path(directory)
            for name in files:
                (path / name).chmod(binding.ADOPTED_FILE_MODE)
            for name in directories:
                (path / name).chmod(binding.ADOPTED_DIRECTORY_MODE)
            path.chmod(binding.ADOPTED_DIRECTORY_MODE)

    @staticmethod
    def _canonical_sha256(value: Any) -> str:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _stable_object_tuple(info: os.stat_result) -> list[int]:
        return [
            int(info.st_dev),
            int(info.st_ino),
            int(stat.S_IFMT(info.st_mode)),
        ]

    @staticmethod
    def _full_stat_tuple(info: os.stat_result) -> list[int]:
        return [
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

    def _inventory(
        self,
        root: Path,
    ) -> tuple[list[dict[str, Any]], int, int, int]:
        records: list[dict[str, Any]] = []
        file_count = 0
        directory_count = 0
        total_bytes = 0

        def walk(path: Path, prefix: str) -> None:
            nonlocal file_count, directory_count, total_bytes
            directory_count += 1
            records.append({"path": prefix, "type": "directory"})
            for child in sorted(path.iterdir(), key=lambda item: item.name):
                relative = (
                    f"{prefix}/{child.name}" if prefix else child.name
                )
                child_info = child.lstat()
                if stat.S_ISDIR(child_info.st_mode):
                    walk(child, relative)
                elif stat.S_ISREG(child_info.st_mode):
                    value = child.read_bytes()
                    file_count += 1
                    total_bytes += len(value)
                    records.append(
                        {
                            "path": relative,
                            "type": "file",
                            "size": len(value),
                            "sha256": hashlib.sha256(value).hexdigest(),
                        }
                    )
                else:
                    raise AssertionError(
                        f"unsupported fixture entry: {child}"
                    )

        walk(root, "")
        return (
            sorted(records, key=lambda item: item["path"]),
            file_count,
            directory_count,
            total_bytes,
        )

    def _receipt_for_tree(self, **changes: Any) -> dict[str, Any]:
        root_info = self.snapshot_root.stat(follow_symlinks=False)
        records, files, directories, total_bytes = self._inventory(
            self.snapshot_root
        )
        receipt: dict[str, Any] = {
            "schema_version": binding.ADOPTION_RECEIPT_SCHEMA,
            "status": binding.ADOPTION_STATUS,
            "session_id": self.session_id,
            "capture_adoption_policy_sha256": "1" * 64,
            "capture_selection_sha256": "2" * 64,
            "capture_plan_sha256": "3" * 64,
            "capture_manifest_sha256": "4" * 64,
            "capture_boundary_policy_sha256": "5" * 64,
            "helper_activation_policy_sha256": "6" * 64,
            "request_sha256": "8" * 64,
            "capture_uid": self.capture_uid,
            "capture_gid": self.export_gid,
            "adopted_uid": self.adopted_uid,
            "verifier_uid": self.verifier_uid,
            "verifier_gid": self.verifier_gid,
            "final_name": self.capture_name,
            "object_identity_sha256": self._canonical_sha256(
                self._stable_object_tuple(root_info)
            ),
            "provisional_stat_sha256": "7" * 64,
            "adopted_stat_sha256": self._canonical_sha256(
                self._full_stat_tuple(root_info)
            ),
            "content_inventory_sha256": self._canonical_sha256(records),
            "file_count": files,
            "directory_count": directories,
            "total_bytes": total_bytes,
            "child_pid": 12_345,
            "child_exit_status": 0,
            "child_stderr_sha256": binding.EMPTY_SHA256,
            "process_group_reaped": True,
            "staging_namespace_revoked": True,
            "same_filesystem": True,
            "rename_noreplace": True,
            "rename_primitive": "renameatx_np_excl",
            "adopted_at_unix": self.adopted_at_unix,
        }
        receipt.update(changes)
        return receipt

    def _verify(
        self,
        receipt: dict[str, Any] | None = None,
        *,
        expected_receipt_sha256: str | None = None,
        verified_at_unix: int | bool | None = None,
    ) -> dict[str, Any]:
        candidate = self.receipt if receipt is None else receipt
        digest = (
            binding.adoption_receipt_sha256(candidate)
            if expected_receipt_sha256 is None
            else expected_receipt_sha256
        )
        return binding.verify_adoption_binding(
            candidate,
            expected_receipt_sha256=digest,
            snapshot_root=self.snapshot_root,
            expected_capture_uid=self.capture_uid,
            expected_export_gid=self.export_gid,
            expected_adopted_uid=self.adopted_uid,
            expected_verifier_uid=self.verifier_uid,
            expected_verifier_gid=self.verifier_gid,
            expected_capture_selection_sha256="2" * 64,
            expected_capture_plan_sha256="3" * 64,
            expected_capture_manifest_sha256="4" * 64,
            expected_request_sha256="8" * 64,
            expected_capture_boundary_policy_sha256="5" * 64,
            expected_helper_activation_policy_sha256="6" * 64,
            expected_session_id=self.session_id,
            verified_at_unix=(
                self.verified_at_unix
                if verified_at_unix is None
                else verified_at_unix
            ),
        )

    @property
    def adoption_limits(self) -> dict[str, int]:
        return {
            "max_files": 100,
            "max_directories": 100,
            "max_bytes": 1_000_000,
            "max_file_bytes": 100_000,
            "max_depth": 10,
        }

    def _root_owned_fstat(self, descriptor: int) -> _RootOwnedStat:
        return _RootOwnedStat(self._real_fstat(descriptor))

    def _normal_root_result(self) -> dict[str, Any]:
        descriptor = os.open(self.snapshot_root, os.O_RDONLY)
        try:
            root_info = binding.os.fstat(descriptor)
        finally:
            os.close(descriptor)
        receipt = self._receipt_for_tree(
            adopted_uid=0,
            adopted_stat_sha256=self._canonical_sha256(
                self._full_stat_tuple(root_info)
            ),
        )
        return adoption_result.build_capture_adoption_result(
            adoption_result.NORMAL_ADOPTION_KIND,
            receipt,
        )

    def _recovered_root_evidence(self) -> dict[str, Any]:
        descriptor = os.open(self.snapshot_root, os.O_RDONLY)
        try:
            root_info = binding.os.fstat(descriptor)
        finally:
            os.close(descriptor)
        records, files, directories, total_bytes = self._inventory(
            self.snapshot_root
        )
        file_sizes = [
            record["size"]
            for record in records
            if record["type"] == "file"
        ]
        maximum_depth = max(
            (
                len(Path(record["path"]).parts)
                for record in records
                if (
                    record["type"] == "directory"
                    and record["path"]
                )
            ),
            default=0,
        )
        evidence: dict[str, Any] = {
            "schema_version": (
                recovered_adoption.RECOVERED_ADOPTION_EVIDENCE_SCHEMA
            ),
            "status": recovered_adoption.RECOVERED_ADOPTION_STATUS,
            "transaction_journal_schema": (
                recovered_adoption.TRANSACTION_JOURNAL_SCHEMA
            ),
            "adoption_reconciliation_receipt_schema": (
                recovered_adoption
                .ADOPTION_RECONCILIATION_RECEIPT_SCHEMA
            ),
            "instance_slug": "john-test",
            "capture_uid": self.capture_uid,
            "capture_export_gid": self.export_gid,
            "final_object_owner_uid": 0,
            "verifier_gid": self.verifier_gid,
            "final_object_group_gid": self.verifier_gid,
            "final_name": self.capture_name,
            "final_parent_filesystem_device": int(root_info.st_dev),
            "adoption_limits": self.adoption_limits,
            "reconciliation_result": (
                recovered_adoption.RECOVERED_ADOPTION_STATUS
            ),
            "final_observation": "exact_present",
            "staging_observation": "absent",
            "staging_terminal_disposition": "absent",
            "reconciled_file_count": files,
            "reconciled_directory_count": directories,
            "reconciled_total_bytes": total_bytes,
            "reconciled_largest_file_bytes": max(
                file_sizes, default=0
            ),
            "reconciled_maximum_depth": maximum_depth,
            "final_object_mode": binding.ADOPTED_DIRECTORY_MODE,
            "final_object_nlink": int(root_info.st_nlink),
            "final_parent_fsynced": True,
            "staging_parents_fsynced": True,
            "observations_rechecked_under_lock": True,
        }
        digest_fields = (
            "capture_session_id",
            "staging_transaction_intent_record_sha256",
            "capture_ready_record_sha256",
            "lifecycle_scope_empty_record_sha256",
            "lifecycle_scope_empty_receipt_sha256",
            "adoption_intent_record_sha256",
            "adoption_reconciliation_required_record_sha256",
            "adoption_reconciliation_record_sha256",
            "adoption_reconciliation_receipt_sha256",
            "capture_adoption_policy_sha256",
            "capture_selection_sha256",
            "capture_plan_sha256",
            "capture_manifest_sha256",
            "capture_request_sha256",
            "capture_boundary_policy_sha256",
            "helper_activation_policy_sha256",
            "final_parent_identity_sha256",
            "capture_object_identity_sha256",
            "reconciled_final_object_stat_sha256",
            "reconciled_content_inventory_sha256",
            "staging_terminal_receipt_sha256",
            "staging_tombstone_sha256",
            "dual_parent_lock_epoch_sha256",
        )
        evidence.update(
            {
                field: hashlib.sha256(
                    f"recovered-{field}".encode("ascii")
                ).hexdigest()
                for field in digest_fields
            }
        )
        evidence.update(
            {
                "capture_session_id": self.session_id,
                "capture_adoption_policy_sha256": "1" * 64,
                "capture_selection_sha256": "2" * 64,
                "capture_plan_sha256": "3" * 64,
                "capture_manifest_sha256": "4" * 64,
                "capture_request_sha256": "8" * 64,
                "capture_boundary_policy_sha256": "5" * 64,
                "helper_activation_policy_sha256": "6" * 64,
                "capture_object_identity_sha256": (
                    self._canonical_sha256(
                        self._stable_object_tuple(root_info)
                    )
                ),
                "reconciled_final_object_stat_sha256": (
                    self._canonical_sha256(
                        self._full_stat_tuple(root_info)
                    )
                ),
                "reconciled_content_inventory_sha256": (
                    self._canonical_sha256(records)
                ),
            }
        )
        return recovered_adoption.normalize_recovered_adoption_evidence(
            evidence
        )

    def _recovered_root_result(self) -> dict[str, Any]:
        return adoption_result.build_capture_adoption_result(
            adoption_result.RECOVERED_ADOPTION_KIND,
            self._recovered_root_evidence(),
        )

    def _verify_result(
        self,
        result: dict[str, Any],
        **changes: Any,
    ) -> dict[str, Any]:
        expected_result_sha256 = changes.pop(
            "expected_result_sha256",
            None,
        )
        if expected_result_sha256 is None:
            expected_result_sha256 = (
                adoption_result.capture_adoption_result_sha256(result)
            )
        arguments: dict[str, Any] = {
            "expected_result_sha256": expected_result_sha256,
            "snapshot_root": self.snapshot_root,
            "expected_instance_slug": "john-test",
            "expected_capture_uid": self.capture_uid,
            "expected_export_gid": self.export_gid,
            "expected_adopted_uid": 0,
            "expected_verifier_uid": self.verifier_uid,
            "expected_verifier_gid": self.verifier_gid,
            "expected_capture_adoption_policy_sha256": "1" * 64,
            "expected_capture_selection_sha256": "2" * 64,
            "expected_capture_plan_sha256": "3" * 64,
            "expected_capture_manifest_sha256": "4" * 64,
            "expected_request_sha256": "8" * 64,
            "expected_capture_boundary_policy_sha256": "5" * 64,
            "expected_helper_activation_policy_sha256": "6" * 64,
            "expected_session_id": self.session_id,
            "expected_adoption_limits": self.adoption_limits,
            "verified_at_unix": self.verified_at_unix,
        }
        arguments.update(changes)
        return binding.verify_capture_adoption_result(
            result,
            **arguments,
        )

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(
            binding.CaptureAdoptionBindingError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_receipt_normalization_and_digest_are_strict_and_canonical(
        self,
    ) -> None:
        reordered = dict(reversed(tuple(self.receipt.items())))
        normalized = binding.normalize_adoption_receipt(reordered)

        self.assertEqual(normalized, self.receipt)
        self.assertIsNot(normalized, self.receipt)
        self.assertEqual(set(normalized), binding.ADOPTION_RECEIPT_FIELDS)
        self.assertEqual(
            binding.adoption_receipt_sha256(reordered),
            self._canonical_sha256(normalized),
        )

        extra = dict(self.receipt, unexpected=True)
        self.assert_code(
            "capture_adoption_receipt_fields_invalid",
            binding.normalize_adoption_receipt,
            extra,
        )
        missing = dict(self.receipt)
        missing.pop("capture_plan_sha256")
        self.assert_code(
            "capture_adoption_receipt_fields_invalid",
            binding.normalize_adoption_receipt,
            missing,
        )
        invalid_digest = dict(
            self.receipt,
            capture_manifest_sha256="A" * 64,
        )
        self.assert_code(
            "capture_adoption_receipt_capture_manifest_sha256_invalid",
            binding.normalize_adoption_receipt,
            invalid_digest,
        )
        invalid_integer = dict(self.receipt, child_pid=True)
        self.assert_code(
            "capture_adoption_receipt_child_pid_invalid",
            binding.normalize_adoption_receipt,
            invalid_integer,
        )

    def test_live_descriptor_relative_tree_produces_exact_binding(
        self,
    ) -> None:
        evidence = self._verify()

        self.assertEqual(set(evidence), binding.ADOPTION_EVIDENCE_FIELDS)
        self.assertEqual(
            evidence,
            {
                "capture_creator_uid": self.capture_uid,
                "capture_export_gid": self.export_gid,
                "capture_adopted_uid": self.adopted_uid,
                "capture_adoption_receipt_sha256": (
                    binding.adoption_receipt_sha256(self.receipt)
                ),
                "capture_adoption_policy_sha256": "1" * 64,
                "capture_object_identity_sha256": self.receipt[
                    "object_identity_sha256"
                ],
                "capture_content_inventory_sha256": self.receipt[
                    "content_inventory_sha256"
                ],
                "capture_adopted_at_unix": self.adopted_at_unix,
                "capture_request_sha256": "8" * 64,
                "capture_boundary_policy_sha256": "5" * 64,
                "capture_helper_activation_policy_sha256": "6" * 64,
            },
        )

    def test_creator_export_adopted_and_verifier_id_tampering_fails(
        self,
    ) -> None:
        cases = {
            "capture_uid": (
                self.capture_uid + 1,
                "capture_adoption_receipt_capture_uid_mismatch",
            ),
            "capture_gid": (
                self.export_gid + 1,
                "capture_adoption_receipt_capture_gid_mismatch",
            ),
            "adopted_uid": (
                self.adopted_uid + 1,
                "capture_adoption_receipt_adopted_uid_mismatch",
            ),
            "verifier_uid": (
                self.verifier_uid + 1,
                "capture_adoption_receipt_verifier_uid_mismatch",
            ),
            "verifier_gid": (
                self.verifier_gid + 1,
                "capture_adoption_receipt_verifier_gid_mismatch",
            ),
        }
        for field, (value, code) in cases.items():
            with self.subTest(field=field):
                tampered = dict(self.receipt, **{field: value})
                self.assert_code(code, self._verify, tampered)

        same_uid = dict(
            self.receipt,
            capture_uid=self.verifier_uid,
        )
        self.assert_code(
            "capture_adoption_receipt_uid_separation_missing",
            binding.normalize_adoption_receipt,
            same_uid,
        )
        same_gid = dict(
            self.receipt,
            capture_gid=self.verifier_gid,
        )
        self.assert_code(
            "capture_adoption_receipt_group_separation_missing",
            binding.normalize_adoption_receipt,
            same_gid,
        )

    def test_receipt_digest_tampering_fails_before_tree_use(self) -> None:
        wrong = (
            "f" * 64
            if binding.adoption_receipt_sha256(self.receipt) != "f" * 64
            else "e" * 64
        )
        self.assert_code(
            "capture_adoption_receipt_digest_mismatch",
            self._verify,
            expected_receipt_sha256=wrong,
        )
        self.assert_code(
            "capture_adoption_expected_receipt_sha256_invalid",
            self._verify,
            expected_receipt_sha256="not-a-digest",
        )

    def test_root_identity_stat_and_inventory_claim_tampering_fails(
        self,
    ) -> None:
        claims = {
            "object_identity_sha256": (
                "8" * 64,
                "capture_adoption_object_identity_mismatch",
            ),
            "adopted_stat_sha256": (
                "9" * 64,
                "capture_adoption_stat_mismatch",
            ),
            "content_inventory_sha256": (
                "b" * 64,
                "capture_adoption_inventory_mismatch",
            ),
        }
        for field, (value, code) in claims.items():
            with self.subTest(field=field):
                tampered = dict(self.receipt, **{field: value})
                self.assert_code(code, self._verify, tampered)

    def test_replacing_the_named_root_is_detected_by_inode_identity(
        self,
    ) -> None:
        displaced = self.base / "displaced-capture"
        self.snapshot_root.rename(displaced)
        self._populate_tree(self.snapshot_root)

        self.assert_code(
            "capture_adoption_object_identity_mismatch",
            self._verify,
        )

    def test_root_timestamp_change_is_detected_by_full_stat_binding(
        self,
    ) -> None:
        root_info = self.snapshot_root.stat(follow_symlinks=False)
        os.utime(
            self.snapshot_root,
            ns=(
                root_info.st_atime_ns,
                root_info.st_mtime_ns + 1_000_000_000,
            ),
            follow_symlinks=False,
        )

        self.assert_code(
            "capture_adoption_stat_mismatch",
            self._verify,
        )

    def test_receipt_timestamp_is_bounded_and_strictly_typed(
        self,
    ) -> None:
        future = dict(
            self.receipt,
            adopted_at_unix=self.verified_at_unix + 1,
        )
        self.assert_code(
            "capture_adoption_receipt_time_invalid",
            self._verify,
            future,
        )
        invalid_receipt = dict(self.receipt, adopted_at_unix=True)
        self.assert_code(
            "capture_adoption_receipt_adopted_at_unix_invalid",
            binding.normalize_adoption_receipt,
            invalid_receipt,
        )
        self.assert_code(
            "capture_adoption_verified_at_unix_invalid",
            self._verify,
            verified_at_unix=True,
        )

    def test_all_authority_booleans_require_literal_true(self) -> None:
        for field in (
            "process_group_reaped",
            "staging_namespace_revoked",
            "same_filesystem",
            "rename_noreplace",
        ):
            for value in (False, 1, "true"):
                with self.subTest(field=field, value=value):
                    tampered = dict(self.receipt, **{field: value})
                    self.assert_code(
                        f"capture_adoption_receipt_{field}_invalid",
                        binding.normalize_adoption_receipt,
                        tampered,
                    )

    def test_file_content_tampering_changes_the_observed_inventory(
        self,
    ) -> None:
        manifest = self.snapshot_root / "manifest.json"
        manifest.chmod(0o640)
        manifest.write_bytes(b'{"ok":null}\n')
        manifest.chmod(binding.ADOPTED_FILE_MODE)

        self.assert_code(
            "capture_adoption_inventory_mismatch",
            self._verify,
        )

    def test_extra_content_cannot_hide_behind_an_updated_root_stat(
        self,
    ) -> None:
        self.snapshot_root.chmod(0o750)
        extra = self.snapshot_root / "unexpected.txt"
        extra.write_bytes(b"unexpected\n")
        extra.chmod(binding.ADOPTED_FILE_MODE)
        self.snapshot_root.chmod(binding.ADOPTED_DIRECTORY_MODE)
        current = self.snapshot_root.stat(follow_symlinks=False)
        tampered = dict(
            self.receipt,
            adopted_stat_sha256=self._canonical_sha256(
                self._full_stat_tuple(current)
            ),
        )

        self.assert_code(
            "capture_adoption_inventory_mismatch",
            self._verify,
            tampered,
        )

    def test_symlink_cannot_hide_behind_an_updated_root_stat(
        self,
    ) -> None:
        self.snapshot_root.chmod(0o750)
        (self.snapshot_root / "manifest-alias").symlink_to(
            "manifest.json"
        )
        self.snapshot_root.chmod(binding.ADOPTED_DIRECTORY_MODE)
        current = self.snapshot_root.stat(follow_symlinks=False)
        tampered = dict(
            self.receipt,
            adopted_stat_sha256=self._canonical_sha256(
                self._full_stat_tuple(current)
            ),
        )

        self.assert_code(
            "capture_adoption_binding_entry_type_unsafe",
            self._verify,
            tampered,
        )

    def test_result_dispatcher_preserves_normal_verification_api(
        self,
    ) -> None:
        historical = self._verify()
        self.assertEqual(set(historical), binding.ADOPTION_EVIDENCE_FIELDS)
        with mock.patch.object(
            binding.os,
            "fstat",
            side_effect=self._root_owned_fstat,
        ):
            result = self._normal_root_result()
            evidence = self._verify_result(result)
        self.assertEqual(
            set(evidence),
            binding.CAPTURE_ADOPTION_RESULT_EVIDENCE_FIELDS,
        )
        self.assertEqual(
            evidence["capture_creator_uid"],
            historical["capture_creator_uid"],
        )
        self.assertEqual(
            evidence["capture_content_inventory_sha256"],
            historical["capture_content_inventory_sha256"],
        )
        provenance = evidence["capture_adoption_provenance"]
        self.assertEqual(
            provenance["kind"],
            adoption_result.NORMAL_ADOPTION_KIND,
        )
        self.assertEqual(
            provenance["details"],
            {"adopted_at_unix": self.adopted_at_unix},
        )
        self.assertEqual(
            evidence["capture_adoption_provenance_sha256"],
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            ),
        )
        self.assertNotIn("capture_adopted_at_unix", evidence)
        self.assertNotIn(
            "capture_adoption_receipt_sha256", evidence
        )

    def test_recovered_result_reobserves_exact_tree_and_provenance(
        self,
    ) -> None:
        with mock.patch.object(
            binding.os,
            "fstat",
            side_effect=self._root_owned_fstat,
        ):
            result = self._recovered_root_result()
            evidence = self._verify_result(result)
        self.assertEqual(
            set(evidence),
            binding.CAPTURE_ADOPTION_RESULT_EVIDENCE_FIELDS,
        )
        self.assertEqual(
            evidence["capture_creator_uid"], self.capture_uid
        )
        self.assertEqual(
            evidence["capture_export_gid"], self.export_gid
        )
        self.assertEqual(evidence["capture_adopted_uid"], 0)
        self.assertEqual(
            evidence["capture_object_identity_sha256"],
            result["evidence"]["capture_object_identity_sha256"],
        )
        self.assertEqual(
            evidence["capture_content_inventory_sha256"],
            result["evidence"][
                "reconciled_content_inventory_sha256"
            ],
        )
        provenance = evidence["capture_adoption_provenance"]
        self.assertEqual(
            provenance["kind"],
            adoption_result.RECOVERED_ADOPTION_KIND,
        )
        self.assertEqual(
            evidence["capture_adoption_provenance_sha256"],
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            ),
        )
        encoded = json.dumps(evidence, sort_keys=True)
        for forbidden in (
            "adopted_at_unix",
            "child_pid",
            "child_exit_status",
            "child_stderr",
            "rename_primitive",
            "rename_noreplace",
            "capture_adoption_receipt_sha256",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_recovered_result_all_independent_bindings_fail_closed(
        self,
    ) -> None:
        with mock.patch.object(
            binding.os,
            "fstat",
            side_effect=self._root_owned_fstat,
        ):
            original = self._recovered_root_evidence()
            cases: dict[str, Any] = {
                "instance_slug": "other-instance",
                "capture_session_id": "b" * 64,
                "capture_uid": self.capture_uid + 1,
                "capture_export_gid": self.export_gid + 1,
                "capture_adoption_policy_sha256": "a" * 64,
                "capture_selection_sha256": "b" * 64,
                "capture_plan_sha256": "c" * 64,
                "capture_manifest_sha256": "d" * 64,
                "capture_request_sha256": "e" * 64,
                "capture_boundary_policy_sha256": "f" * 64,
                "helper_activation_policy_sha256": "a" * 64,
                "final_name": "opaque-capture-" + "f" * 32,
                "adoption_limits": {
                    **self.adoption_limits,
                    "max_files": 99,
                },
            }
            for field, replacement in cases.items():
                with self.subTest(field=field):
                    changed = copy.deepcopy(original)
                    changed[field] = replacement
                    result = (
                        adoption_result.build_capture_adoption_result(
                            adoption_result.RECOVERED_ADOPTION_KIND,
                            changed,
                        )
                    )
                    self.assert_code(
                        f"capture_adoption_recovered_{field}_mismatch",
                        self._verify_result,
                        result,
                    )

            changed = copy.deepcopy(original)
            changed["verifier_gid"] = self.verifier_gid + 1
            changed["final_object_group_gid"] = (
                self.verifier_gid + 1
            )
            result = adoption_result.build_capture_adoption_result(
                adoption_result.RECOVERED_ADOPTION_KIND,
                changed,
            )
            self.assert_code(
                "capture_adoption_recovered_verifier_gid_mismatch",
                self._verify_result,
                result,
            )

    def test_recovered_tree_stat_object_and_inventory_claims_are_exact(
        self,
    ) -> None:
        with mock.patch.object(
            binding.os,
            "fstat",
            side_effect=self._root_owned_fstat,
        ):
            original = self._recovered_root_evidence()
            cases = {
                "capture_object_identity_sha256": (
                    "a" * 64,
                    "capture_adoption_recovered_"
                    "object_identity_mismatch",
                ),
                "reconciled_final_object_stat_sha256": (
                    "b" * 64,
                    "capture_adoption_recovered_stat_mismatch",
                ),
                "reconciled_content_inventory_sha256": (
                    "c" * 64,
                    "capture_adoption_recovered_"
                    "reconciled_content_inventory_sha256_mismatch",
                ),
                "reconciled_file_count": (
                    original["reconciled_file_count"] + 1,
                    "capture_adoption_recovered_"
                    "reconciled_file_count_mismatch",
                ),
                "reconciled_total_bytes": (
                    original["reconciled_total_bytes"] + 1,
                    "capture_adoption_recovered_"
                    "reconciled_total_bytes_mismatch",
                ),
                "reconciled_maximum_depth": (
                    original["reconciled_maximum_depth"] - 1,
                    "capture_adoption_recovered_"
                    "reconciled_maximum_depth_mismatch",
                ),
            }
            for field, (replacement, code) in cases.items():
                with self.subTest(field=field):
                    changed = copy.deepcopy(original)
                    changed[field] = replacement
                    result = (
                        adoption_result.build_capture_adoption_result(
                            adoption_result.RECOVERED_ADOPTION_KIND,
                            changed,
                        )
                    )
                    self.assert_code(
                        code,
                        self._verify_result,
                        result,
                    )

    def test_recovered_current_tree_mutation_is_not_healed_by_history(
        self,
    ) -> None:
        with mock.patch.object(
            binding.os,
            "fstat",
            side_effect=self._root_owned_fstat,
        ):
            result = self._recovered_root_result()
            manifest = self.snapshot_root / "manifest.json"
            manifest.chmod(0o640)
            manifest.write_bytes(b'{"ok":false}\n')
            manifest.chmod(binding.ADOPTED_FILE_MODE)
            self.assert_code(
                (
                    "capture_adoption_recovered_"
                    "reconciled_content_inventory_sha256_mismatch"
                ),
                self._verify_result,
                result,
            )

    def test_result_digest_cross_kind_limits_and_root_owner_fail_closed(
        self,
    ) -> None:
        with mock.patch.object(
            binding.os,
            "fstat",
            side_effect=self._root_owned_fstat,
        ):
            result = self._recovered_root_result()
            self.assert_code(
                "capture_adoption_result_digest_mismatch",
                self._verify_result,
                result,
                expected_result_sha256="f" * 64,
            )
            relabeled = copy.deepcopy(result)
            relabeled["kind"] = adoption_result.NORMAL_ADOPTION_KIND
            self.assert_code(
                "capture_adoption_result_kind_evidence_mismatch",
                self._verify_result,
                relabeled,
                expected_result_sha256=(
                    adoption_result.capture_adoption_result_sha256(
                        result
                    )
                ),
            )
            changed_limits = {
                **self.adoption_limits,
                "max_files": 99,
            }
            self.assert_code(
                "capture_adoption_recovered_adoption_limits_mismatch",
                self._verify_result,
                result,
                expected_adoption_limits=changed_limits,
            )
            self.assert_code(
                "capture_adoption_result_adopted_uid_not_root",
                self._verify_result,
                result,
                expected_adopted_uid=self.adopted_uid,
            )


if __name__ == "__main__":
    unittest.main()
