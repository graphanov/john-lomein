from __future__ import annotations

import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_helper as helper,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_plan as capture_plan,
)


def darwin_test_python() -> Path:
    framework = (
        Path(sys.base_prefix)
        / "Resources"
        / "Python.app"
        / "Contents"
        / "MacOS"
        / "Python"
    )
    return framework if framework.is_file() else Path(sys.executable).resolve()


class _FakeLease:
    def __init__(self, *, marker: Path | None = None) -> None:
        self.snapshot_root = Path(
            "/var/lib/john-lomein/captures/"
            "opaque-capture-0123456789abcdef0123456789abcdef"
        )
        self.capture_plan_sha256 = "a" * 64
        self.capture_manifest_sha256 = "b" * 64
        self.active = True
        self.cleanup_count = 0
        self.marker = marker

    def cleanup(self) -> None:
        if not self.active:
            return
        self.active = False
        self.cleanup_count += 1
        if self.marker is not None:
            descriptor = os.open(
                self.marker,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(descriptor)


class PersonaQualificationCaptureHelperTests(unittest.TestCase):
    maxDiff = None

    def test_measured_entrypoint_imports_under_isolated_python(self) -> None:
        entrypoint = (
            ROOT
            / "qualification_attestor"
            / "john_lomein_persona_qualification_capture_helper.py"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(entrypoint)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def plan(self) -> dict[str, object]:
        return {
            "schema_version": capture_plan.CAPTURE_PLAN_SCHEMA,
            "instance_slug": "john-example",
            "evidence_uid": 501,
            "verifier_gid": 502,
            "sources": [
                {
                    "source_id": "instance",
                    "source_class": "instance_manifest",
                    "kind": "file",
                    "source_path": "/srv/john-lomein/export/instance.yaml",
                    "destination_path": "instance/instance.yaml",
                },
                {
                    "source_id": "current-run",
                    "source_class": "qualification_private",
                    "kind": "tree",
                    "source_path": "/srv/john-lomein/export/current-run",
                    "destination_path": "private",
                },
            ],
            "limits": {
                "max_files": 32,
                "max_directories": 32,
                "max_bytes": 1024 * 1024,
                "max_file_bytes": 256 * 1024,
                "max_depth": 16,
            },
            "lifecycle": {
                "retention": "ephemeral",
                "max_capture_slots": 4,
                "max_orphan_age_seconds": 60,
            },
        }

    def policy(
        self,
        *,
        system: str = "Linux",
    ) -> helper.CaptureHelperPolicy:
        plan = capture_plan.normalize_capture_plan(self.plan())
        plan_raw = helper._canonical_json(plan)
        backend = (
            Path("/usr/bin/bwrap")
            if system == "Linux"
            else Path("/usr/bin/sandbox-exec")
        )
        loader_mounts = (
            (
                helper.ImmutableReadMount(
                    Path("/usr/lib"),
                    Path("/usr/lib"),
                    "directory",
                ),
            )
            if system == "Linux"
            else (
                helper.ImmutableReadMount(
                    Path("/System/Library/Frameworks"),
                    Path("/System/Library/Frameworks"),
                    "directory",
                ),
            )
        )
        return helper.CaptureHelperPolicy(
            system=system,  # type: ignore[arg-type]
            kernel_release="fixture-kernel",
            backend_path=backend,
            backend_sha256="c" * 64,
            bundle_root=Path("/opt/john-lomein/capture-helper"),
            bundle_sha256="d" * 64,
            python_path=Path(
                "/opt/john-lomein/capture-helper/bin/python3"
            ),
            entrypoint_path=Path(
                "/opt/john-lomein/capture-helper/capture_child.py"
            ),
            installed_plan_path=Path(
                "/etc/john-lomein/capture-plan.json"
            ),
            capture_plan_bytes=plan_raw,
            capture_plan_sha256=capture_plan.capture_plan_sha256(plan),
            source_mounts=tuple(
                helper.CaptureSourceMount(
                    Path(source["source_path"]),
                    source["kind"],
                )
                for source in plan["sources"]
            ),
            destination_parent=Path(
                "/var/lib/john-lomein/captures"
            ),
            activation_receipt_path=Path(
                "/etc/john-lomein/capture-helper-activation.json"
            ),
            helper_uid=501,
            helper_gid=502,
            timeout_seconds=120,
            denied_secret_paths=(
                helper.DeniedSecretPath(
                    "attestation_state",
                    Path("/var/lib/john-lomein/attestor/state"),
                ),
                helper.DeniedSecretPath(
                    "model_secret",
                    Path("/etc/john-lomein/model-secrets.env"),
                ),
                helper.DeniedSecretPath(
                    "private_key",
                    Path("/var/lib/john-lomein/attestor/key.pem"),
                ),
                helper.DeniedSecretPath(
                    "public_projection",
                    Path("/var/lib/john-lomein/public/trust.json"),
                ),
            ),
            loader_mounts=loader_mounts,
        )

    def command(
        self,
        *,
        session_id: str,
        sequence: int,
        command: str,
        digest: str | None = None,
        reason: str | None = None,
    ) -> dict[str, object]:
        return {
            "schema_version": helper.PROTOCOL_SCHEMA,
            "session_id": session_id,
            "sequence": sequence,
            "command": command,
            "artifact_sha256": digest,
            "reason_code": reason,
        }

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(helper.CaptureHelperError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_protocol_machine_enforces_state_sequence_and_digest_binding(
        self,
    ) -> None:
        session_id = "1" * 64
        machine = helper._ProtocolMachine(session_id)
        self.assertEqual(
            machine.accept(
                self.command(
                    session_id=session_id,
                    sequence=1,
                    command="begin_verification",
                )
            ),
            ("begin_verification", None, None),
        )
        self.assert_code(
            "capture_helper_command_sequence_invalid",
            machine.accept,
            self.command(
                session_id=session_id,
                sequence=1,
                command="complete_verification",
                digest="2" * 64,
            ),
        )
        self.assert_code(
            "capture_helper_command_out_of_order",
            machine.accept,
            self.command(
                session_id=session_id,
                sequence=2,
                command="complete_signing",
                digest="2" * 64,
            ),
        )
        self.assertEqual(
            machine.accept(
                self.command(
                    session_id=session_id,
                    sequence=2,
                    command="complete_verification",
                    digest="2" * 64,
                )
            ),
            ("complete_verification", "2" * 64, None),
        )
        self.assertEqual(machine.state, "signing_authorized")

    def test_protocol_rejects_noncanonical_duplicate_oversized_and_truncated(
        self,
    ) -> None:
        samples = (
            (
                struct.pack("!I", 14) + b'{"b":1, "a":2}',
                "capture_helper_protocol_message_noncanonical",
            ),
            (
                struct.pack("!I", 13) + b'{"a":1,"a":2}',
                "capture_helper_json_duplicate_key",
            ),
            (
                struct.pack("!I", helper.MAX_CONTROL_FRAME_BYTES + 1),
                "capture_helper_protocol_frame_size_invalid",
            ),
            (
                struct.pack("!I", 10) + b"{}",
                "capture_helper_protocol_eof",
            ),
        )
        for raw, expected in samples:
            with self.subTest(expected=expected):
                read_fd, write_fd = os.pipe()
                try:
                    os.write(write_fd, raw)
                    os.close(write_fd)
                    write_fd = -1
                    self.assert_code(
                        expected,
                        helper._read_frame,
                        read_fd,
                        maximum_bytes=helper.MAX_CONTROL_FRAME_BYTES,
                        deadline=time.monotonic() + 1,
                    )
                finally:
                    os.close(read_fd)
                    if write_fd >= 0:
                        os.close(write_fd)

    def test_child_holds_lease_across_all_digest_bound_phases(self) -> None:
        control_read, control_write = os.pipe()
        event_read, event_write = os.pipe()
        lease = _FakeLease()
        calls: list[str] = []
        failure: list[BaseException] = []
        session_id = "3" * 64

        def serve() -> None:
            try:
                helper._serve_protocol_with_lease(
                    control_fd=control_read,
                    event_fd=event_write,
                    session_id=session_id,
                    plan=self.plan(),
                    helper_uid=501,
                    helper_gid=502,
                    lease=lease,
                    deadline=time.monotonic() + 5,
                    verify_sealed=lambda: calls.append("sealed"),
                    revalidate_live=lambda: calls.append("live"),
                )
            except BaseException as exc:
                failure.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            ready = helper._read_frame(
                event_read,
                maximum_bytes=helper.MAX_EVENT_FRAME_BYTES,
                deadline=time.monotonic() + 2,
            )
            self.assertEqual(set(ready), helper.READY_FIELDS)
            self.assertNotIn("manifest", ready)
            self.assertNotIn("files", ready)
            phases = (
                ("begin_verification", None, "verification_authorized"),
                ("complete_verification", "4" * 64, "signing_authorized"),
                ("complete_signing", "5" * 64, "publication_authorized"),
                ("complete_publication", "6" * 64, "cleaned"),
            )
            for sequence, (command, digest, event) in enumerate(
                phases,
                start=1,
            ):
                helper._write_frame(
                    control_write,
                    self.command(
                        session_id=session_id,
                        sequence=sequence,
                        command=command,
                        digest=digest,
                    ),
                    maximum_bytes=helper.MAX_CONTROL_FRAME_BYTES,
                )
                response = helper._read_frame(
                    event_read,
                    maximum_bytes=helper.MAX_EVENT_FRAME_BYTES,
                    deadline=time.monotonic() + 2,
                )
                self.assertEqual(response["event"], event)
                self.assertEqual(response["artifact_sha256"], digest)
                if command != "complete_publication":
                    self.assertTrue(lease.active)
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(failure)
            self.assertEqual(lease.cleanup_count, 1)
            # complete_verification performs sealed + live before the ACK.
            self.assertEqual(
                calls,
                ["sealed", "sealed", "live", "sealed", "sealed"],
            )
        finally:
            for descriptor in (
                control_read,
                control_write,
                event_read,
                event_write,
            ):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_live_mutation_is_rejected_pre_key_but_not_after_verified_ack(
        self,
    ) -> None:
        def run(*, mutate_before_ack: bool) -> tuple[list[str], _FakeLease]:
            control_read, control_write = os.pipe()
            event_read, event_write = os.pipe()
            lease = _FakeLease()
            state = {"mutated": False}
            failure: list[BaseException] = []
            session_id = ("c" if mutate_before_ack else "d") * 64

            def live() -> None:
                if state["mutated"]:
                    raise helper.CaptureHelperError(
                        "capture_helper_source_changed_for_test"
                    )

            def serve() -> None:
                try:
                    helper._serve_protocol_with_lease(
                        control_fd=control_read,
                        event_fd=event_write,
                        session_id=session_id,
                        plan=self.plan(),
                        helper_uid=501,
                        helper_gid=502,
                        lease=lease,
                        deadline=time.monotonic() + 5,
                        verify_sealed=lambda: None,
                        revalidate_live=live,
                    )
                except BaseException as exc:
                    failure.append(exc)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                helper._read_frame(
                    event_read,
                    maximum_bytes=helper.MAX_EVENT_FRAME_BYTES,
                    deadline=time.monotonic() + 2,
                )
                helper._write_frame(
                    control_write,
                    self.command(
                        session_id=session_id,
                        sequence=1,
                        command="begin_verification",
                    ),
                    maximum_bytes=helper.MAX_CONTROL_FRAME_BYTES,
                )
                helper._read_frame(
                    event_read,
                    maximum_bytes=helper.MAX_EVENT_FRAME_BYTES,
                    deadline=time.monotonic() + 2,
                )
                state["mutated"] = mutate_before_ack
                helper._write_frame(
                    control_write,
                    self.command(
                        session_id=session_id,
                        sequence=2,
                        command="complete_verification",
                        digest="e" * 64,
                    ),
                    maximum_bytes=helper.MAX_CONTROL_FRAME_BYTES,
                )
                response = helper._read_frame(
                    event_read,
                    maximum_bytes=helper.MAX_EVENT_FRAME_BYTES,
                    deadline=time.monotonic() + 2,
                )
                if mutate_before_ack:
                    self.assertEqual(response["event"], "error")
                    self.assertEqual(
                        response["error_code"],
                        "capture_helper_source_changed_for_test",
                    )
                else:
                    self.assertEqual(response["event"], "signing_authorized")
                    state["mutated"] = True
                    for sequence, command, digest, expected in (
                        (
                            3,
                            "complete_signing",
                            "f" * 64,
                            "publication_authorized",
                        ),
                        (
                            4,
                            "complete_publication",
                            "1" * 64,
                            "cleaned",
                        ),
                    ):
                        helper._write_frame(
                            control_write,
                            self.command(
                                session_id=session_id,
                                sequence=sequence,
                                command=command,
                                digest=digest,
                            ),
                            maximum_bytes=helper.MAX_CONTROL_FRAME_BYTES,
                        )
                        response = helper._read_frame(
                            event_read,
                            maximum_bytes=helper.MAX_EVENT_FRAME_BYTES,
                            deadline=time.monotonic() + 2,
                        )
                        self.assertEqual(response["event"], expected)
                thread.join(2)
                self.assertFalse(thread.is_alive())
                return (
                    [
                        type(item).__name__
                        + ":"
                        + getattr(item, "code", "")
                        for item in failure
                    ],
                    lease,
                )
            finally:
                for descriptor in (
                    control_read,
                    control_write,
                    event_read,
                    event_write,
                ):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

        pre_key_failures, pre_key_lease = run(mutate_before_ack=True)
        self.assertEqual(
            pre_key_failures,
            [
                "CaptureHelperError:"
                "capture_helper_source_changed_for_test"
            ],
        )
        self.assertFalse(pre_key_lease.active)
        post_ack_failures, post_ack_lease = run(mutate_before_ack=False)
        self.assertEqual(post_ack_failures, [])
        self.assertFalse(post_ack_lease.active)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_parent_control_pipe_death_runs_child_lease_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "cleaned"
            control_read, control_write = os.pipe()
            event_read, event_write = os.pipe()
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(control_write)
                    os.close(event_read)
                    lease = _FakeLease(marker=marker)
                    try:
                        helper._serve_protocol_with_lease(
                            control_fd=control_read,
                            event_fd=event_write,
                            session_id="7" * 64,
                            plan=self.plan(),
                            helper_uid=501,
                            helper_gid=502,
                            lease=lease,
                            deadline=time.monotonic() + 5,
                            verify_sealed=lambda: None,
                            revalidate_live=lambda: None,
                        )
                    finally:
                        lease.cleanup()
                except BaseException:
                    pass
                finally:
                    os._exit(0)
            os.close(control_read)
            os.close(event_write)
            try:
                helper._read_frame(
                    event_read,
                    maximum_bytes=helper.MAX_EVENT_FRAME_BYTES,
                    deadline=time.monotonic() + 2,
                )
                os.close(control_write)
                control_write = -1
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists())
                waited, status = os.waitpid(pid, 0)
                self.assertEqual(waited, pid)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            finally:
                if control_write >= 0:
                    os.close(control_write)
                os.close(event_read)
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass

    def test_child_eof_forces_parent_kill_and_orphan_recovery(self) -> None:
        policy = self.policy()
        control_read, control_write = os.pipe()
        event_read, event_write = os.pipe()
        os.close(event_write)
        stderr = tempfile.TemporaryFile(mode="w+b")
        session = helper.CaptureHelperSession(
            policy=policy,
            pid=123456,
            control_fd=control_write,
            event_fd=event_read,
            stderr=stderr,
            deadline=time.monotonic() + 1,
            session_id="8" * 64,
            ready=helper.CaptureReady(
                capture_root=(
                    policy.destination_parent
                    / "opaque-capture-0123456789abcdef0123456789abcdef"
                ),
                capture_plan_sha256=policy.capture_plan_sha256,
                capture_manifest_sha256="9" * 64,
            ),
        )
        try:
            with (
                mock.patch.object(
                    helper,
                    "_kill_and_reap",
                    return_value=125,
                ) as killed,
                mock.patch.object(
                    helper,
                    "recover_stale_capture_helpers",
                    return_value=[],
                ) as recovered,
            ):
                self.assert_code(
                    "capture_helper_protocol_eof",
                    session.begin_verification,
                )
                killed.assert_called_once_with(123456)
                recovered.assert_called_once_with(
                    policy,
                    force_orphans=True,
                )
                self.assertFalse(session.active)
                self.assertEqual(session.abort(), "aborted")
                session.close()
        finally:
            os.close(control_read)
            if session.active:
                with mock.patch.object(
                    helper,
                    "recover_stale_capture_helpers",
                    return_value=[],
                ):
                    session._closed = True

    def test_wait_reap_keeps_zombie_pinned_until_group_cleanup(
        self,
    ) -> None:
        pid = 5252
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

        def waitid(idtype: int, observed_pid: int, flags: int):
            self.assertEqual(idtype, os.P_PID)
            self.assertEqual(observed_pid, pid)
            self.assertTrue(flags & os.WNOWAIT)
            self.assertFalse(state["reaped"])
            value = next(observations)
            events.append("waitid-exit" if value else "waitid-empty")
            return value

        def killpg(process_group_id: int, sig: int) -> None:
            # The seam treats waitpid as immediate numeric-ID reuse.
            self.assertFalse(state["reaped"], "killpg after PID reuse")
            self.assertEqual((process_group_id, sig), (pid, signal.SIGKILL))
            events.append("killpg")

        def waitpid(observed_pid: int, options: int) -> tuple[int, int]:
            self.assertEqual((observed_pid, options), (pid, 0))
            events.append("waitpid")
            state["reaped"] = True
            return pid, 0

        returncode = helper._wait_reap(
            pid,
            deadline=2.0,
            monotonic=lambda: 0.0,
            _syscalls=helper._WaitReapSyscalls(
                waitid=waitid,
                killpg=killpg,
                waitpid=waitpid,
                waitstatus_to_exitcode=lambda status: status,
                sleep=lambda _seconds: events.append("sleep"),
            ),
        )
        self.assertEqual(returncode, 0)
        self.assertEqual(
            events,
            [
                "waitid-empty",
                "sleep",
                "waitid-exit",
                "killpg",
                "waitpid",
            ],
        )

    def test_forced_cleanup_signals_group_before_final_wait(self) -> None:
        pid = 5353
        events: list[str] = []
        state = {"reaped": False}

        def killpg(process_group_id: int, sig: int) -> None:
            self.assertFalse(state["reaped"], "killpg after PID reuse")
            self.assertEqual((process_group_id, sig), (pid, signal.SIGKILL))
            events.append("killpg")

        def kill(process_id: int, sig: int) -> None:
            self.assertFalse(state["reaped"], "kill after PID reuse")
            self.assertEqual((process_id, sig), (pid, signal.SIGKILL))
            events.append("kill")

        def waitpid(observed_pid: int, options: int) -> tuple[int, int]:
            self.assertEqual((observed_pid, options), (pid, 0))
            events.append("waitpid")
            state["reaped"] = True
            return pid, 0

        with (
            mock.patch.object(helper.os, "killpg", side_effect=killpg),
            mock.patch.object(helper.os, "kill", side_effect=kill),
            mock.patch.object(helper.os, "waitpid", side_effect=waitpid),
            mock.patch.object(
                helper.os,
                "waitstatus_to_exitcode",
                side_effect=lambda status: status,
            ),
        ):
            self.assertEqual(helper._kill_and_reap(pid), 0)
        self.assertEqual(events, ["killpg", "kill", "waitpid"])

    def test_darwin_policy_explicitly_denies_every_secret_authority(self) -> None:
        policy = self.policy(system="Darwin")
        profile = helper.build_darwin_profile(policy)
        write_section = profile.split("(allow file-write*", 1)[1]
        self.assertTrue(profile.startswith("(version 1)\n(deny default)\n"))
        self.assertIn("(deny network*)", profile)
        self.assertIn("(deny process-fork)", profile)
        self.assertIn('(literal "/")', profile)
        self.assertIn(
            f'(literal "{policy.bundle_root.parent}")',
            profile,
        )
        self.assertNotIn(
            f'(subpath "{policy.bundle_root.parent}")',
            profile,
        )
        for denied in policy.denied_secret_paths:
            spelling = f'(subpath "{denied.path}")'
            self.assertGreaterEqual(profile.count(spelling), 2)
            self.assertNotIn(str(denied.path), write_section)
        self.assertIn(str(policy.destination_parent), write_section)
        for source in policy.source_mounts:
            self.assertNotIn(str(source.path), write_section)

    @unittest.skipUnless(
        sys.platform == "darwin"
        and Path("/usr/bin/sandbox-exec").is_file(),
        "requires macOS Seatbelt",
    )
    def test_darwin_helper_profile_starts_isolated_python(self) -> None:
        python_path = darwin_test_python()
        bundle_root = Path(sys.base_prefix).resolve()
        policy = replace(
            self.policy(system="Darwin"),
            bundle_root=bundle_root,
            python_path=python_path,
            entrypoint_path=bundle_root / "probe.py",
            loader_mounts=(
                helper.ImmutableReadMount(
                    Path("/usr/lib"),
                    Path("/usr/lib"),
                    "directory",
                ),
                helper.ImmutableReadMount(
                    Path("/System/Library/Frameworks"),
                    Path("/System/Library/Frameworks"),
                    "directory",
                ),
            ),
        )
        result = subprocess.run(
            [
                "/usr/bin/sandbox-exec",
                "-p",
                helper.build_darwin_profile(policy),
                str(python_path),
                "-I",
                "-S",
                "-B",
                "-c",
                'print("capture-seatbelt-ok")',
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "capture-seatbelt-ok\n")
        self.assertEqual(result.stderr, "")

    def test_linux_mount_namespace_exposes_only_fixed_inputs_and_capture_write(
        self,
    ) -> None:
        policy = self.policy()
        command = helper.build_linux_command(policy)
        readonly = {
            tuple(command[index + 1 : index + 3])
            for index, value in enumerate(command)
            if value == "--ro-bind"
        }
        writable = {
            tuple(command[index + 1 : index + 3])
            for index, value in enumerate(command)
            if value == "--bind"
        }
        expected_readonly = {
            (str(policy.bundle_root), str(policy.bundle_root)),
            (
                str(policy.installed_plan_path),
                str(policy.installed_plan_path),
            ),
            ("/usr/lib", "/usr/lib"),
            *(
                (str(source.path), str(source.path))
                for source in policy.source_mounts
            ),
        }
        self.assertEqual(readonly, expected_readonly)
        self.assertEqual(
            writable,
            {
                (
                    str(policy.destination_parent),
                    str(policy.destination_parent),
                )
            },
        )
        self.assertIn("--die-with-parent", command)
        self.assertIn("--unshare-all", command)
        self.assertNotIn("--share-net", command)
        rendered = "\0".join(command)
        for denied in policy.denied_secret_paths:
            self.assertNotIn(str(denied.path), rendered)
        denied_syscalls = set(
            helper.linux_seccomp_denied_syscalls("x86_64")
        )
        self.assertTrue(
            {
                "fork",
                "clone",
                "clone3",
                "socket",
                "socketpair",
                "connect",
                "io_uring_setup",
                "execveat",
            }.issubset(denied_syscalls)
        )

    def test_build_policy_uses_dynamic_plan_and_requires_matching_identity(
        self,
    ) -> None:
        plan = capture_plan.normalize_capture_plan(self.plan())
        digest = capture_plan.capture_plan_sha256(plan)
        arguments = {
            "installed_plan_path": Path(
                "/etc/john-lomein/capture-plan.json"
            ),
            "destination_parent": Path(
                "/var/lib/john-lomein/captures"
            ),
            "bundle_root": Path("/opt/john-lomein/capture-helper"),
            "bundle_sha256": "d" * 64,
            "python_path": Path(
                "/opt/john-lomein/capture-helper/bin/python3"
            ),
            "entrypoint_path": Path(
                "/opt/john-lomein/capture-helper/capture_child.py"
            ),
            "activation_receipt_path": Path(
                "/etc/john-lomein/capture-helper-activation.json"
            ),
            "helper_uid": 501,
            "helper_gid": 502,
            "timeout_seconds": 120,
            "private_key_paths": [
                Path("/var/lib/john-lomein/attestor/key.pem")
            ],
            "attestation_state_paths": [
                Path("/var/lib/john-lomein/attestor/state")
            ],
            "public_projection_paths": [
                Path("/var/lib/john-lomein/public/trust.json")
            ],
            "model_secret_paths": [
                Path("/etc/john-lomein/model-secrets.env")
            ],
            "loader_mounts": [
                helper.ImmutableReadMount(
                    Path("/usr/lib"),
                    Path("/usr/lib"),
                    "directory",
                )
            ],
            "system": "Linux",
            "backend_path": Path("/usr/bin/bwrap"),
            "backend_sha256": "c" * 64,
            "kernel_release": "fixture-kernel",
        }
        with mock.patch.object(
            capture_plan,
            "read_installed_capture_plan",
            return_value=(plan, digest),
        ):
            policy = helper.build_capture_helper_policy(**arguments)
            self.assertEqual(
                [str(item.path) for item in policy.source_mounts],
                [source["source_path"] for source in plan["sources"]],
            )
            self.assertEqual(policy.capture_plan_sha256, digest)
            bad = dict(arguments)
            bad["helper_uid"] = 777
            self.assert_code(
                "capture_helper_identity_plan_mismatch",
                helper.build_capture_helper_policy,
                **bad,
            )

    def test_secret_overlap_and_unsupported_platform_fail_closed(self) -> None:
        policy = self.policy()
        unsafe = helper.CaptureHelperPolicy(
            **{
                **policy.__dict__,
                "denied_secret_paths": (
                    policy.denied_secret_paths[0],
                    helper.DeniedSecretPath(
                        "model_secret",
                        policy.source_mounts[0].path,
                    ),
                    *policy.denied_secret_paths[2:],
                ),
            }
        )
        self.assert_code(
            "capture_helper_secret_path_allowlist_overlap",
            helper._validate_policy_shape,
            unsafe,
        )
        self.assert_code(
            "capture_helper_platform_unsupported",
            helper.build_capture_helper_policy,
            installed_plan_path=Path("/etc/plan.json"),
            destination_parent=Path("/var/captures"),
            bundle_root=Path("/opt/helper"),
            bundle_sha256="a" * 64,
            python_path=Path("/opt/helper/python"),
            entrypoint_path=Path("/opt/helper/main.py"),
            activation_receipt_path=Path("/etc/receipt.json"),
            helper_uid=501,
            helper_gid=502,
            timeout_seconds=1,
            private_key_paths=[Path("/secret/key")],
            attestation_state_paths=[Path("/secret/state")],
            public_projection_paths=[Path("/secret/public")],
            model_secret_paths=[Path("/secret/model")],
            system="Plan9",
        )

    def test_production_launch_has_two_independent_fail_closed_gates(self) -> None:
        policy = self.policy()
        self.assertIs(helper.PRODUCTION_ACTIVATION, False)
        self.assertIs(helper.CAPTURE_ADOPTION_IMPLEMENTED, False)
        self.assert_code(
            "capture_helper_production_disabled",
            helper.launch_protected_capture_helper,
            policy,
        )
        with mock.patch.object(helper, "PRODUCTION_ACTIVATION", True):
            self.assert_code(
                "capture_adoption_not_implemented",
                helper.launch_protected_capture_helper,
                policy,
            )
        self.assertIn(
            "root_owned_descriptor_relative_adoption_required",
            json.dumps(policy.activation_record()),
        )
        self.assertEqual(
            policy.activation_record()["entrypoint_role"],
            helper.SANDBOX_CHILD_ROLE,
        )
        self.assertEqual(
            policy.child_argv()[-2:],
            (str(policy.entrypoint_path), helper.CHILD_ARGUMENT),
        )

    def test_activation_receipt_is_exact_and_canary_cannot_bless_it(
        self,
    ) -> None:
        policy = self.policy()
        self.assertTrue(
            {
                "fork_denied",
                "wrapper_containment_proven",
            }.issubset(helper.CANARY_ASSERTIONS)
        )
        receipt = {
            "schema_version": helper.ACTIVATION_RECEIPT_SCHEMA,
            "status": helper.ACTIVATION_STATUS,
            "activation_policy_sha256": (
                policy.activation_policy_sha256()
            ),
            "system": policy.system,
            "kernel_release": policy.kernel_release,
            "backend_path": str(policy.backend_path),
            "backend_sha256": policy.backend_sha256,
            "bundle_sha256": policy.bundle_sha256,
            "capture_plan_sha256": policy.capture_plan_sha256,
            "helper_uid": policy.helper_uid,
            "helper_gid": policy.helper_gid,
            "assertions": {
                name: True for name in helper.CANARY_ASSERTIONS
            },
        }
        self.assertEqual(
            helper.normalize_activation_receipt(
                receipt,
                policy=policy,
            ),
            receipt,
        )
        incomplete = {
            **receipt,
            "assertions": {
                name: True
                for name in helper.CANARY_ASSERTIONS
                if name != "key_unreadable"
            },
        }
        self.assert_code(
            "capture_helper_activation_assertions_incomplete",
            helper.normalize_activation_receipt,
            incomplete,
            policy=policy,
        )
        self.assert_code(
            "capture_helper_activation_schema_version_mismatch",
            helper.normalize_activation_receipt,
            {
                **receipt,
                "schema_version": (
                    "john-lomein.persona."
                    "capture-helper-sandbox-activation.v1"
                ),
            },
            policy=policy,
        )

        sentinel = object()
        with (
            mock.patch.object(helper, "PRODUCTION_ACTIVATION", True),
            mock.patch.object(
                helper,
                "CAPTURE_ADOPTION_IMPLEMENTED",
                True,
            ),
            mock.patch.object(helper.os, "getuid", return_value=0),
            mock.patch.object(helper.os, "geteuid", return_value=0),
            mock.patch.object(helper, "_validate_policy_runtime"),
            mock.patch.object(
                helper,
                "_read_activation_receipt",
                return_value=receipt,
            ) as receipt_reader,
            mock.patch.object(
                helper,
                "_launch_validated_helper",
                return_value=sentinel,
            ) as launcher,
        ):
            self.assertIs(
                helper.launch_protected_capture_helper(policy),
                sentinel,
            )
            receipt_reader.assert_called_once_with(policy)
            launcher.assert_called_once_with(policy)

        with (
            mock.patch.object(helper.os, "getuid", return_value=0),
            mock.patch.object(helper.os, "geteuid", return_value=0),
            mock.patch.object(helper, "_validate_policy_runtime"),
            mock.patch.object(
                helper,
                "_read_activation_receipt",
            ) as receipt_reader,
            mock.patch.object(
                helper,
                "_launch_validated_helper",
                return_value=sentinel,
            ),
        ):
            self.assertIs(
                helper.launch_privileged_capture_helper_canary(policy),
                sentinel,
            )
            receipt_reader.assert_not_called()

    def test_abort_is_allowed_after_any_nonterminal_ack_and_is_idempotent(
        self,
    ) -> None:
        session_id = "a" * 64
        for commands in (
            (),
            ("begin_verification",),
            ("begin_verification", "complete_verification"),
            (
                "begin_verification",
                "complete_verification",
                "complete_signing",
            ),
        ):
            with self.subTest(commands=commands):
                machine = helper._ProtocolMachine(session_id)
                sequence = 0
                for command in commands:
                    sequence += 1
                    digest = None
                    if command != "begin_verification":
                        digest = str(sequence) * 64
                    machine.accept(
                        self.command(
                            session_id=session_id,
                            sequence=sequence,
                            command=command,
                            digest=digest,
                        )
                    )
                sequence += 1
                self.assertEqual(
                    machine.accept(
                        self.command(
                            session_id=session_id,
                            sequence=sequence,
                            command="abort",
                            reason="test_abort",
                        )
                    ),
                    ("abort", None, "test_abort"),
                )
                self.assertEqual(machine.state, "aborted")


if __name__ == "__main__":
    unittest.main()
