from __future__ import annotations

import copy
import ctypes
import fcntl
import json
import os
import pickle
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_capture_plan as capture_plan,
)
from qualification_attestor import (
    john_lomein_persona_qualification_opaque_capture as opaque,
)


class PersonaQualificationOpaqueCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._cleanup_temporary)
        self.leases: list[opaque.OpaqueCaptureLease] = []
        self.addCleanup(self._cleanup_leases)
        self.root = Path(self.temporary.name).resolve()
        self.capture_uid = os.geteuid()
        self.evidence_uid = self.capture_uid if self.capture_uid > 0 else 1
        self.verifier_gid = os.getegid() if os.getegid() > 0 else 1

        self.evidence = self.root / "evidence"
        self.private = self.evidence / "private"
        self.history = self.private / "history"
        self.captures = self.root / "captures"
        self.evidence.mkdir(mode=0o700)
        self.private.mkdir(mode=0o700)
        self.history.mkdir(mode=0o700)
        self.captures.mkdir(mode=0o710)
        self.instance = self.evidence / "instance.yaml"
        self.instance_bytes = (
            b"\xff\xfe:not-yaml\n"
            b"historical_status: qualified-but-never-semantic\n"
        )
        self.instance.write_bytes(self.instance_bytes)
        self.history_file = self.history / "run-0001.private"
        self.history_bytes = (
            b"\x00\x01private historical evaluator transcript\xff"
        )
        self.history_file.write_bytes(self.history_bytes)
        self.latest_file = self.private / "latest.bin"
        self.latest_file.write_bytes(b"opaque latest bytes\n")
        for path in (
            self.evidence,
            self.private,
            self.history,
        ):
            path.chmod(0o700)
            os.chown(path, self.evidence_uid, os.getegid())
        for path in (
            self.instance,
            self.history_file,
            self.latest_file,
        ):
            path.chmod(0o600)
            os.chown(path, self.evidence_uid, os.getegid())
        self.captures.chmod(0o710)
        os.chown(self.captures, self.capture_uid, self.verifier_gid)

    def _cleanup_temporary(self) -> None:
        if not hasattr(self, "root") or not self.root.exists():
            self.temporary.cleanup()
            return
        for directory, directories, _ in os.walk(
            self.root,
            topdown=True,
        ):
            try:
                Path(directory).chmod(0o700)
            except OSError:
                pass
            for name in directories:
                try:
                    (Path(directory) / name).chmod(0o700)
                except OSError:
                    pass
        self.temporary.cleanup()

    def _cleanup_leases(self) -> None:
        for lease in reversed(self.leases):
            if lease.active:
                try:
                    lease.cleanup()
                except opaque.OpaqueCaptureError:
                    pass

    def plan(self) -> dict:
        return {
            "schema_version": capture_plan.CAPTURE_PLAN_SCHEMA,
            "instance_slug": "john-example",
            "evidence_uid": self.evidence_uid,
            "verifier_gid": self.verifier_gid,
            "sources": [
                {
                    "source_id": "instance",
                    "source_class": "instance_manifest",
                    "kind": "file",
                    "source_path": str(self.instance),
                    "destination_path": "instance/instance.bin",
                },
                {
                    "source_id": "private-history",
                    "source_class": "qualification_private",
                    "kind": "tree",
                    "source_path": str(self.private),
                    "destination_path": "private",
                },
            ],
            "limits": {
                "max_files": 16,
                "max_directories": 16,
                "max_bytes": 1024 * 1024,
                "max_file_bytes": 128 * 1024,
                "max_depth": 16,
            },
            "lifecycle": {
                "retention": "ephemeral",
                "max_capture_slots": 4,
                "max_orphan_age_seconds": 60,
            },
        }

    def capture(
        self,
        *,
        plan: dict | None = None,
        after_copy_hook=None,
    ) -> opaque.OpaqueCaptureLease:
        selected = self.plan() if plan is None else plan
        lease = opaque._capture_opaque_snapshot_from_plan(
            plan=selected,
            plan_sha256=capture_plan.capture_plan_sha256(selected),
            destination_parent=self.captures,
            capture_uid=self.capture_uid,
            after_copy_hook=after_copy_hook,
        )
        self.leases.append(lease)
        return lease

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(opaque.OpaqueCaptureError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def set_test_xattr(self, path: Path) -> tuple[ctypes.CDLL, bytes]:
        libc = ctypes.CDLL(None, use_errno=True)
        name = (
            b"com.john-lomein.test"
            if sys.platform == "darwin"
            else b"user.john-lomein-test"
        )
        value = b"1"
        value_buffer = ctypes.create_string_buffer(value)
        if sys.platform == "darwin":
            libc.setxattr.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_uint32,
                ctypes.c_int,
            ]
            result = libc.setxattr(
                os.fsencode(path),
                name,
                value_buffer,
                len(value),
                0,
                0,
            )
        else:
            libc.setxattr.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_int,
            ]
            result = libc.setxattr(
                os.fsencode(path),
                name,
                value_buffer,
                len(value),
                0,
            )
        if result != 0:
            self.skipTest("filesystem does not support test xattrs")
        return libc, name

    def remove_test_xattr(
        self,
        libc: ctypes.CDLL,
        path: Path,
        name: bytes,
    ) -> None:
        if sys.platform == "darwin":
            libc.removexattr.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_int,
            ]
            libc.removexattr(os.fsencode(path), name, 0)
        else:
            libc.removexattr.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
            ]
            libc.removexattr(os.fsencode(path), name)

    def test_successfully_copies_all_bytes_without_semantic_parsing(self) -> None:
        lease = self.capture()
        snapshot = lease.snapshot_root
        manifest = lease.manifest

        self.assertNotIn("yaml", opaque.__dict__)
        self.assertIs(opaque.PRODUCTION_ACTIVATION, False)
        self.assertNotIsInstance(lease, dict)
        self.assertEqual(
            (snapshot / "instance/instance.bin").read_bytes(),
            self.instance_bytes,
        )
        self.assertEqual(
            (snapshot / "private/history/run-0001.private").read_bytes(),
            self.history_bytes,
        )
        self.assertEqual(
            lease.capture_plan_sha256,
            capture_plan.capture_plan_sha256(self.plan()),
        )
        self.assertEqual(manifest["sources"], self.plan()["sources"])
        self.assertEqual(manifest["lifecycle"], self.plan()["lifecycle"])
        self.assertEqual(manifest["file_count"], 3)
        self.assertGreaterEqual(manifest["source_directory_count"], 3)
        reconstructed_plan = {
            "schema_version": capture_plan.CAPTURE_PLAN_SCHEMA,
            "instance_slug": manifest["instance_slug"],
            "evidence_uid": manifest["evidence_uid"],
            "verifier_gid": manifest["verifier_gid"],
            "sources": manifest["sources"],
            "limits": manifest["limits"],
            "lifecycle": manifest["lifecycle"],
        }
        self.assertEqual(
            capture_plan.normalize_capture_plan(reconstructed_plan),
            self.plan(),
        )
        tampered_manifest = copy.deepcopy(manifest)
        tampered_manifest["lifecycle"]["max_capture_slots"] += 1
        self.assert_code(
            "opaque_capture_manifest_schema_invalid",
            opaque._validate_manifest,
            tampered_manifest,
            plan=self.plan(),
            plan_sha256=lease.capture_plan_sha256,
            capture_uid=self.capture_uid,
            verifier_gid=self.verifier_gid,
        )

        root_info = snapshot.stat()
        file_info = (snapshot / "instance/instance.bin").stat()
        self.assertEqual(stat.S_IMODE(root_info.st_mode), 0o550)
        self.assertEqual(root_info.st_uid, self.capture_uid)
        self.assertEqual(root_info.st_gid, self.verifier_gid)
        self.assertEqual(stat.S_IMODE(file_info.st_mode), 0o440)
        self.assertEqual(file_info.st_gid, self.verifier_gid)

        verified = opaque.verify_sealed_opaque_capture(
            snapshot,
            plan=self.plan(),
            expected_plan_sha256=lease.capture_plan_sha256,
            expected_capture_uid=self.capture_uid,
            expected_verifier_gid=self.verifier_gid,
            expected_manifest_sha256=lease.capture_manifest_sha256,
        )
        self.assertEqual(verified, manifest)
        self.assertEqual(
            opaque.revalidate_live_opaque_sources(
                snapshot,
                plan=self.plan(),
                expected_plan_sha256=lease.capture_plan_sha256,
                expected_capture_uid=self.capture_uid,
                expected_verifier_gid=self.verifier_gid,
                expected_manifest_sha256=lease.capture_manifest_sha256,
            ),
            manifest,
        )

        opaque.cleanup_opaque_capture(lease)
        self.assertFalse(snapshot.exists())

    def test_same_byte_rewrite_is_detected_during_and_after_capture(self) -> None:
        def rewrite_during_capture() -> None:
            time.sleep(0.002)
            self.instance.write_bytes(self.instance_bytes)
            self.instance.chmod(0o600)

        self.assert_code(
            "opaque_capture_live_source_file_changed",
            self.capture,
            after_copy_hook=rewrite_during_capture,
        )
        self.assertEqual(list(self.captures.iterdir()), [])

        lease = self.capture()
        snapshot = lease.snapshot_root
        time.sleep(0.002)
        self.instance.write_bytes(self.instance_bytes)
        self.instance.chmod(0o600)
        self.assert_code(
            "opaque_capture_live_source_file_changed",
            opaque.revalidate_live_opaque_sources,
            snapshot,
            plan=self.plan(),
            expected_plan_sha256=lease.capture_plan_sha256,
            expected_capture_uid=self.capture_uid,
            expected_verifier_gid=self.verifier_gid,
            expected_manifest_sha256=lease.capture_manifest_sha256,
        )

    def test_directory_mutation_fails_and_building_snapshot_is_cleaned(self) -> None:
        added = self.private / "late-arrival.bin"

        def mutate_inventory() -> None:
            added.write_bytes(b"late")
            added.chmod(0o600)
            os.chown(added, self.evidence_uid, os.getegid())

        self.assert_code(
            "opaque_capture_source_directory_changed",
            self.capture,
            after_copy_hook=mutate_inventory,
        )
        self.assertEqual(list(self.captures.iterdir()), [])

    def test_links_extended_metadata_and_caps_fail_closed(self) -> None:
        symlink = self.private / "redirect"
        symlink.symlink_to(self.instance)
        self.assert_code(
            "opaque_capture_source_private-history_directory_entry_unsafe",
            self.capture,
        )
        symlink.unlink()

        hardlink = self.private / "hardlink.bin"
        os.link(self.latest_file, hardlink)
        self.assert_code(
            "opaque_capture_source_private-history_file_unsafe",
            self.capture,
        )
        hardlink.unlink()

        limited = copy.deepcopy(self.plan())
        limited["limits"]["max_file_bytes"] = 4
        self.assert_code(
            "opaque_capture_source_instance_unsafe",
            self.capture,
            plan=limited,
        )
        file_limited = copy.deepcopy(self.plan())
        file_limited["limits"]["max_files"] = 2
        self.assert_code(
            "opaque_capture_file_count_exceeded",
            self.capture,
            plan=file_limited,
        )
        directory_limited = copy.deepcopy(self.plan())
        directory_limited["limits"]["max_directories"] = 2
        self.assert_code(
            "opaque_capture_directory_count_exceeded",
            self.capture,
            plan=directory_limited,
        )
        total_limited = copy.deepcopy(self.plan())
        total_limited["limits"]["max_bytes"] = 100
        total_limited["limits"]["max_file_bytes"] = 100
        self.assert_code(
            "opaque_capture_size_exceeded",
            self.capture,
            plan=total_limited,
        )

        libc, attribute_name = self.set_test_xattr(self.instance)
        try:
            self.assert_code(
                "opaque_capture_source_instance_extended_metadata_unsupported",
                self.capture,
            )
        finally:
            self.remove_test_xattr(
                libc,
                self.instance,
                attribute_name,
            )

    def test_source_destination_overlap_and_extra_sealed_inventory_reject(self) -> None:
        nested_capture_parent = self.private / "captures"
        nested_capture_parent.mkdir(mode=0o710)
        os.chown(
            nested_capture_parent,
            self.capture_uid,
            self.verifier_gid,
        )
        self.assert_code(
            "opaque_capture_source_destination_overlap",
            opaque._capture_opaque_snapshot_from_plan,
            plan=self.plan(),
            plan_sha256=capture_plan.capture_plan_sha256(self.plan()),
            destination_parent=nested_capture_parent,
            capture_uid=self.capture_uid,
        )
        nested_capture_parent.rmdir()

        lease = self.capture()
        snapshot = lease.snapshot_root
        snapshot.chmod(0o700)
        extra = snapshot / "unmanifested.bin"
        extra.write_bytes(b"surprise")
        extra.chmod(0o440)
        os.chown(extra, self.capture_uid, self.verifier_gid)
        snapshot.chmod(0o550)
        self.assert_code(
            "opaque_capture_sealed_inventory_mismatch",
            opaque.verify_sealed_opaque_capture,
            snapshot,
            plan=self.plan(),
            expected_plan_sha256=lease.capture_plan_sha256,
            expected_capture_uid=self.capture_uid,
            expected_verifier_gid=self.verifier_gid,
            expected_manifest_sha256=lease.capture_manifest_sha256,
        )

    def test_cleanup_and_stale_recovery_are_descriptor_confined(self) -> None:
        building = self.captures / (
            "opaque-capture-00000000000000000000000000000000.building"
        )
        building.mkdir(mode=0o700)
        nested = building / "nested"
        nested.mkdir(mode=0o700)
        (nested / "partial.bin").write_bytes(b"partial")
        outside = self.root / "outside.bin"
        outside.write_bytes(b"keep")
        (building / "outside-link").symlink_to(outside)

        removed = opaque.recover_stale_opaque_captures(
            self.captures,
            plan=self.plan(),
            capture_uid=self.capture_uid,
            now_unix=(
                int(time.time())
                + self.plan()["lifecycle"]["max_orphan_age_seconds"]
                + 2
            ),
        )
        self.assertEqual(removed, [building.name])
        self.assertFalse(building.exists())
        self.assertEqual(outside.read_bytes(), b"keep")

        self.assert_code(
            "opaque_capture_cleanup_lease_required",
            opaque.cleanup_opaque_capture,
            outside,
        )

    def test_aged_active_final_is_skipped_and_admission_remains_busy(
        self,
    ) -> None:
        limited = copy.deepcopy(self.plan())
        limited["lifecycle"]["max_capture_slots"] = 1
        lease = self.capture(plan=limited)
        snapshot = lease.snapshot_root
        recovery_script = """
import json
import sys
from pathlib import Path
from qualification_attestor import john_lomein_persona_qualification_opaque_capture as opaque
request = json.loads(sys.stdin.read())
removed = opaque.recover_stale_opaque_captures(
    Path(request["parent"]),
    plan=request["plan"],
    capture_uid=request["capture_uid"],
    now_unix=request["now_unix"],
)
sys.stdout.write(json.dumps(removed))
"""
        completed = subprocess.run(
            [sys.executable, "-c", recovery_script],
            cwd=ROOT,
            input=json.dumps(
                {
                    "parent": str(self.captures),
                    "plan": limited,
                    "capture_uid": self.capture_uid,
                    "now_unix": (
                        int(time.time())
                        + limited["lifecycle"][
                            "max_orphan_age_seconds"
                        ]
                        + 2
                    ),
                }
            ),
            text=True,
            capture_output=True,
            close_fds=False,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), [])
        self.assertTrue(snapshot.exists())
        self.assert_code(
            "opaque_capture_admission_busy",
            self.capture,
            plan=limited,
        )

    @unittest.skipUnless(hasattr(os, "fork"), "requires fork")
    def test_unlocked_final_is_reaped_after_creator_crashes(self) -> None:
        read_result, write_result = os.pipe()
        child = os.fork()
        if child == 0:
            try:
                os.close(read_result)
                lease = opaque._capture_opaque_snapshot_from_plan(
                    plan=self.plan(),
                    plan_sha256=capture_plan.capture_plan_sha256(
                        self.plan()
                    ),
                    destination_parent=self.captures,
                    capture_uid=self.capture_uid,
                )
                os.write(
                    write_result,
                    lease.snapshot_root.name.encode("ascii"),
                )
            finally:
                # Model a process death after the atomic rename.  os._exit
                # releases the flock without running lease cleanup.
                os._exit(0)
        os.close(write_result)
        name = os.read(read_result, 512).decode("ascii")
        os.close(read_result)
        _, status = os.waitpid(child, 0)
        self.assertEqual(status, 0)
        self.assertRegex(name, opaque.CAPTURE_NAME_RE)
        snapshot = self.captures / name
        self.assertTrue(snapshot.exists())

        lock_ready_read, lock_ready_write = os.pipe()
        lock_release_read, lock_release_write = os.pipe()
        forged_locker = os.fork()
        if forged_locker == 0:
            try:
                os.close(lock_ready_read)
                os.close(lock_release_write)
                descriptor = os.open(snapshot, opaque._directory_flags())
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                os.write(lock_ready_write, b"locked")
                os.read(lock_release_read, 1)
            finally:
                os._exit(0)
        os.close(lock_ready_write)
        os.close(lock_release_read)
        self.assertEqual(os.read(lock_ready_read, 6), b"locked")
        os.close(lock_ready_read)
        try:
            removed = opaque.recover_stale_opaque_captures(
                self.captures,
                plan=self.plan(),
                capture_uid=self.capture_uid,
                now_unix=(
                    int(time.time())
                    + self.plan()["lifecycle"][
                        "max_orphan_age_seconds"
                    ]
                    + 2
                ),
            )
            self.assertEqual(removed, [name])
            self.assertFalse(snapshot.exists())
        finally:
            os.write(lock_release_write, b"x")
            os.close(lock_release_write)
            _, locker_status = os.waitpid(forged_locker, 0)
        self.assertEqual(locker_status, 0)

    def test_lease_is_cloexec_nonserializable_and_not_a_path_token(self) -> None:
        lease = self.capture()
        descriptor = lease._fileno_for_test()
        parent_descriptor = lease._parent_fileno_for_test()
        for held in (descriptor, parent_descriptor):
            descriptor_flags = fcntl.fcntl(held, fcntl.F_GETFD)
            self.assertTrue(descriptor_flags & fcntl.FD_CLOEXEC)
            self.assertFalse(os.get_inheritable(held))
        with self.assertRaises(TypeError):
            pickle.dumps(lease)
        with self.assertRaises(TypeError):
            json.dumps(lease)

        exec_probe = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import os,sys\n"
                    "fds=[int(value) for value in sys.argv[1:]]\n"
                    "for fd in fds:\n"
                    " try:\n"
                    "  os.fstat(fd)\n"
                    " except OSError:\n"
                    "  continue\n"
                    " raise SystemExit(23)\n"
                    "raise SystemExit(0)\n"
                ),
                str(descriptor),
                str(parent_descriptor),
            ],
            close_fds=False,
            check=False,
        )
        self.assertEqual(exec_probe.returncode, 0)

    def test_cleanup_rejects_replaced_name_before_deleting(self) -> None:
        lease = self.capture()
        final = lease.snapshot_root
        displaced = self.captures / (
            "opaque-capture-11111111111111111111111111111111"
        )
        os.rename(final, displaced)
        final.mkdir(mode=0o550)
        os.chown(final, self.capture_uid, self.verifier_gid)
        final.chmod(0o550)

        self.assert_code(
            "opaque_capture_cleanup_lease_inode_mismatch",
            lease.cleanup,
        )
        self.assertTrue(lease.active)
        self.assertTrue(final.exists())
        self.assertTrue(displaced.exists())

        final.chmod(0o700)
        final.rmdir()
        os.rename(displaced, final)
        lease.cleanup()
        self.assertFalse(final.exists())

    @unittest.skipUnless(hasattr(os, "fork"), "requires fork")
    def test_max_slots_one_serializes_concurrent_capture_admission(self) -> None:
        limited = copy.deepcopy(self.plan())
        limited["lifecycle"]["max_capture_slots"] = 1
        start_read, start_write = os.pipe()
        release_read, release_write = os.pipe()
        children: list[int] = []
        result_reads: list[int] = []
        for _ in range(2):
            result_read, result_write = os.pipe()
            child = os.fork()
            if child == 0:
                try:
                    os.close(start_write)
                    os.close(release_write)
                    os.close(result_read)
                    os.read(start_read, 1)
                    try:
                        lease = opaque._capture_opaque_snapshot_from_plan(
                            plan=limited,
                            plan_sha256=(
                                capture_plan.capture_plan_sha256(limited)
                            ),
                            destination_parent=self.captures,
                            capture_uid=self.capture_uid,
                            after_copy_hook=lambda: time.sleep(0.15),
                        )
                    except opaque.OpaqueCaptureError as exc:
                        outcome = f"rejected:{exc.code}"
                        lease = None
                    else:
                        outcome = "leased"
                    os.write(result_write, outcome.encode("ascii"))
                    os.read(release_read, 1)
                    if lease is not None:
                        lease.cleanup()
                    os._exit(0)
                except BaseException:
                    os._exit(31)
            os.close(result_write)
            children.append(child)
            result_reads.append(result_read)
        os.close(start_read)
        os.close(release_read)
        os.write(start_write, b"xx")
        os.close(start_write)
        outcomes = [
            os.read(descriptor, 256).decode("ascii")
            for descriptor in result_reads
        ]
        for descriptor in result_reads:
            os.close(descriptor)
        os.write(release_write, b"xx")
        os.close(release_write)
        statuses = [os.waitpid(child, 0)[1] for child in children]
        self.assertEqual(statuses, [0, 0])
        self.assertCountEqual(
            outcomes,
            ["leased", "rejected:opaque_capture_admission_busy"],
        )
        self.assertEqual(list(self.captures.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
