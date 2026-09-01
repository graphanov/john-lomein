from __future__ import annotations

import fcntl
import json
import os
import platform
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_sandbox as sandbox,
)


class PersonaQualificationSandboxTests(unittest.TestCase):
    def policy(
        self,
        *,
        system: str = "Linux",
        capture_name: str = "capture-0123456789abcdef0123456789abcdef",
        backend_path: str | None = None,
        bundle_sha256: str = "b" * 64,
        backend_sha256: str = "a" * 64,
    ) -> sandbox.QualificationSandboxPolicy:
        if backend_path is None:
            backend_path = (
                "/usr/bin/bwrap"
                if system == "Linux"
                else "/usr/bin/sandbox-exec"
            )
        if system == "Linux":
            mounts = (
                sandbox.ImmutableReadMount(
                    Path("/usr/lib"),
                    Path("/usr/lib"),
                    "directory",
                ),
                sandbox.ImmutableReadMount(
                    Path("/etc/ld.so.cache"),
                    Path("/etc/ld.so.cache"),
                    "file",
                ),
            )
        else:
            mounts = (
                sandbox.ImmutableReadMount(
                    Path("/usr/lib"),
                    Path("/usr/lib"),
                    "directory",
                ),
                sandbox.ImmutableReadMount(
                    Path("/System/Library/Frameworks"),
                    Path("/System/Library/Frameworks"),
                    "directory",
                ),
            )
        return sandbox.build_policy(
            bundle_root=Path("/opt/john-lomein/verifier/bundle"),
            bundle_sha256=bundle_sha256,
            capture_parent=Path("/var/lib/john-lomein/captures"),
            capture_root=(
                Path("/var/lib/john-lomein/captures") / capture_name
            ),
            python_path=Path(
                "/opt/john-lomein/verifier/bundle/bin/python3"
            ),
            entrypoint_path=Path(
                "/opt/john-lomein/verifier/bundle/verifier.py"
            ),
            scratch_root=Path("/var/lib/john-lomein/verifier-scratch"),
            activation_receipt_path=Path(
                "/etc/john-lomein/qualification-sandbox-activation.json"
            ),
            verifier_uid=502,
            verifier_gid=503,
            timeout_seconds=120,
            loader_mounts=mounts,
            system=system,
            backend_path=Path(backend_path),
            backend_sha256=backend_sha256,
            kernel_release="fixture-kernel",
        )

    def receipt(
        self,
        policy: sandbox.QualificationSandboxPolicy,
    ) -> dict[str, object]:
        return {
            "schema_version": sandbox.ACTIVATION_RECEIPT_SCHEMA,
            "status": sandbox.ACTIVATION_STATUS,
            "activation_policy_sha256": (
                policy.activation_policy_sha256()
            ),
            "system": policy.system,
            "kernel_release": policy.kernel_release,
            "backend_path": str(policy.backend_path),
            "backend_sha256": policy.backend_sha256,
            "bundle_sha256": policy.bundle_sha256,
            "verifier_uid": policy.verifier_uid,
            "verifier_gid": policy.verifier_gid,
            "assertions": {
                name: True for name in sandbox.CANARY_ASSERTIONS
            },
        }

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(
            sandbox.QualificationSandboxError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_linux_command_has_closed_mount_network_and_process_contract(
        self,
    ) -> None:
        policy = self.policy()
        command = sandbox.build_linux_command(policy)

        self.assertEqual(command[0], "/usr/bin/bwrap")
        self.assertIn("--die-with-parent", command)
        self.assertIn("--new-session", command)
        self.assertIn("--unshare-all", command)
        self.assertNotIn("--share-net", command)
        self.assertNotIn("--proc", command)
        self.assertEqual(
            command[command.index("--cap-drop") + 1],
            "ALL",
        )
        self.assertEqual(
            command[command.index("--tmpfs") + 1],
            "/",
        )
        self.assertEqual(
            command[command.index("--remount-ro") + 1],
            "/",
        )
        self.assertNotIn(
            ["--ro-bind", "/", "/"],
            [command[index : index + 3] for index in range(len(command))],
        )
        readonly_bindings = {
            tuple(command[index + 1 : index + 3])
            for index, value in enumerate(command)
            if value == "--ro-bind"
        }
        self.assertEqual(
            readonly_bindings,
            {
                (str(policy.bundle_root), str(policy.bundle_root)),
                (str(policy.capture_root), str(policy.capture_root)),
                ("/usr/lib", "/usr/lib"),
                ("/etc/ld.so.cache", "/etc/ld.so.cache"),
            },
        )
        scratch_index = command.index(
            "--tmpfs",
            command.index("--tmpfs") + 1,
        )
        self.assertEqual(
            command[scratch_index + 1],
            str(policy.scratch_root),
        )
        self.assertEqual(
            command[scratch_index - 2 : scratch_index],
            [
                "--size",
                str(sandbox.LINUX_SCRATCH_TMPFS_BYTES),
            ],
        )
        self.assertNotIn("--bind", command)
        self.assertEqual(
            command[command.index("--uid") + 1],
            str(policy.verifier_uid),
        )
        self.assertEqual(
            command[command.index("--gid") + 1],
            str(policy.verifier_gid),
        )
        self.assertEqual(
            command[command.index("--seccomp") + 1],
            str(sandbox.SECCOMP_FD),
        )
        separator = command.index("--")
        self.assertEqual(
            command[separator + 1 :],
            list(policy.verifier_argv()),
        )
        observed_environment: dict[str, str] = {}
        for index, value in enumerate(command):
            if value == "--setenv":
                observed_environment[command[index + 1]] = command[index + 2]
        self.assertEqual(observed_environment, policy.fixed_environment())

    def test_seatbelt_profile_is_deny_default_and_path_allowlisted(
        self,
    ) -> None:
        policy = self.policy(system="Darwin")
        profile = sandbox.build_darwin_profile(policy)
        command = sandbox.build_darwin_command(policy)

        self.assertTrue(profile.startswith("(version 1)\n(deny default)\n"))
        self.assertIn("(deny network*)", profile)
        self.assertIn("(deny process-fork)", profile)
        self.assertIn("(deny file-link)", profile)
        self.assertIn(f'(subpath "{policy.bundle_root}")', profile)
        self.assertIn(f'(subpath "{policy.capture_root}")', profile)
        self.assertIn(f'(subpath "{policy.scratch_root}")', profile)
        self.assertIn('(literal "/")', profile)
        self.assertIn(
            f'(literal "{policy.bundle_root.parent}")',
            profile,
        )
        self.assertNotIn(
            f'(subpath "{policy.bundle_root.parent}")',
            profile,
        )
        self.assertIn('(subpath "/usr/lib")', profile)
        self.assertIn(
            '(subpath "/System/Library/Frameworks")',
            profile,
        )
        write_section = profile.split("(allow file-write*", 1)[1]
        self.assertIn(str(policy.scratch_root), write_section)
        self.assertNotIn(str(policy.bundle_root), write_section)
        self.assertNotIn(str(policy.capture_root), write_section)
        self.assertNotIn("/etc/john-lomein", profile)
        self.assertEqual(command[:2], ["/usr/bin/sandbox-exec", "-p"])
        self.assertEqual(command[3:], list(policy.verifier_argv()))

    @unittest.skipUnless(
        sys.platform == "darwin"
        and Path("/usr/bin/sandbox-exec").is_file(),
        "requires macOS Seatbelt",
    )
    def test_seatbelt_profile_starts_isolated_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            capture = root / "capture"
            scratch = root / "scratch"
            capture.mkdir()
            scratch.mkdir()
            python_path = Path(sys.executable).resolve()
            bundle_root = Path(sys.base_prefix).resolve()
            policy = sandbox.QualificationSandboxPolicy(
                system="Darwin",
                kernel_release=platform.release(),
                backend_path=Path("/usr/bin/sandbox-exec"),
                backend_sha256="a" * 64,
                bundle_root=bundle_root,
                bundle_sha256="b" * 64,
                capture_parent=root,
                capture_root=capture,
                python_path=python_path,
                entrypoint_path=bundle_root / "probe.py",
                scratch_root=scratch,
                activation_receipt_path=root / "receipt.json",
                verifier_uid=max(os.geteuid(), 1),
                verifier_gid=max(os.getegid(), 1),
                timeout_seconds=10,
                loader_mounts=(
                    sandbox.ImmutableReadMount(
                        Path("/usr/lib"),
                        Path("/usr/lib"),
                        "tree",
                    ),
                    sandbox.ImmutableReadMount(
                        Path("/System/Library/Frameworks"),
                        Path("/System/Library/Frameworks"),
                        "tree",
                    ),
                ),
            )
            result = subprocess.run(
                [
                    "/usr/bin/sandbox-exec",
                    "-p",
                    sandbox.build_darwin_profile(policy),
                    str(python_path),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    'print("seatbelt-ok")',
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "seatbelt-ok\n")
        self.assertEqual(result.stderr, "")

    def test_linux_seccomp_filter_denies_descendants_network_and_escape(
        self,
    ) -> None:
        denied = set(
            sandbox.linux_seccomp_denied_syscalls("x86_64")
        )
        self.assertTrue(
            {
                "fork",
                "vfork",
                "clone",
                "clone3",
                "socket",
                "socketpair",
                "connect",
                "io_uring_setup",
                "io_uring_enter",
                "io_uring_register",
                "unshare",
                "setns",
                "mount",
                "ptrace",
                "bpf",
                "setresuid",
                "setresgid",
                "setgroups",
                "capset",
                "execveat",
            }.issubset(denied)
        )
        encoded = sandbox.build_linux_seccomp_filter("x86_64")
        self.assertGreater(len(encoded), 8)
        self.assertEqual(len(encoded) % 8, 0)
        instructions = [
            struct.unpack("=HBBI", encoded[offset : offset + 8])
            for offset in range(0, len(encoded), 8)
        ]
        x32_guard = (
            sandbox._BPF_JMP | sandbox._BPF_JSET | sandbox._BPF_K,
            0,
            1,
            sandbox._X32_SYSCALL_BIT,
        )
        self.assertIn(x32_guard, instructions)
        guard_index = instructions.index(x32_guard)
        self.assertEqual(
            instructions[guard_index + 1],
            (
                sandbox._BPF_RET | sandbox._BPF_K,
                0,
                0,
                sandbox._SECCOMP_RET_KILL_PROCESS,
            ),
        )
        arm_filter = sandbox.build_linux_seccomp_filter("aarch64")
        arm_instructions = [
            struct.unpack("=HBBI", arm_filter[offset : offset + 8])
            for offset in range(0, len(arm_filter), 8)
        ]
        self.assertNotIn(x32_guard, arm_instructions)
        self.assertNotEqual(
            encoded,
            arm_filter,
        )
        self.assert_code(
            "sandbox_linux_architecture_unsupported",
            sandbox.build_linux_seccomp_filter,
            "mips64",
        )

    def test_backend_discovery_has_no_unsandboxed_fallback(self) -> None:
        with mock.patch.object(
            sandbox,
            "_discover_backend",
            side_effect=sandbox.QualificationSandboxError(
                "sandbox_bubblewrap_unavailable"
            ),
        ):
            self.assert_code(
                "sandbox_bubblewrap_unavailable",
                sandbox.build_policy,
                bundle_root=Path("/opt/john/bundle"),
                bundle_sha256="b" * 64,
                capture_parent=Path("/var/lib/john/captures"),
                capture_root=Path(
                    "/var/lib/john/captures/capture-abc"
                ),
                python_path=Path("/opt/john/bundle/python"),
                entrypoint_path=Path("/opt/john/bundle/verifier.py"),
                scratch_root=Path("/var/lib/john/scratch"),
                activation_receipt_path=Path(
                    "/etc/john/activation.json"
                ),
                verifier_uid=502,
                verifier_gid=503,
                timeout_seconds=60,
                system="Linux",
                kernel_release="fixture",
            )

    def test_policy_rejects_path_overlap_and_seatbelt_loader_aliases(
        self,
    ) -> None:
        common = {
            "bundle_root": Path("/opt/john/bundle"),
            "bundle_sha256": "b" * 64,
            "capture_parent": Path("/var/lib/john/captures"),
            "capture_root": Path(
                "/var/lib/john/captures/capture-abc"
            ),
            "python_path": Path("/opt/john/bundle/python"),
            "entrypoint_path": Path("/opt/john/bundle/verifier.py"),
            "activation_receipt_path": Path(
                "/etc/john/activation.json"
            ),
            "verifier_uid": 502,
            "verifier_gid": 503,
            "timeout_seconds": 60,
            "system": "Darwin",
            "backend_path": Path("/usr/bin/sandbox-exec"),
            "backend_sha256": "a" * 64,
            "kernel_release": "fixture",
        }
        self.assert_code(
            "sandbox_control_paths_overlap",
            sandbox.build_policy,
            **common,
            scratch_root=Path("/opt/john/bundle/scratch"),
        )
        self.assert_code(
            "seatbelt_loader_alias_unsupported",
            sandbox.build_policy,
            **common,
            scratch_root=Path("/var/lib/john/scratch"),
            loader_mounts=(
                sandbox.ImmutableReadMount(
                    Path("/usr/lib"),
                    Path("/runtime/lib"),
                    "directory",
                ),
            ),
        )
        self.assert_code(
            "loader_mount_source_outside_system_closure",
            sandbox.build_policy,
            **common,
            scratch_root=Path("/var/lib/john/scratch"),
            loader_mounts=(
                sandbox.ImmutableReadMount(
                    Path("/etc/john/private-key.pem"),
                    Path("/etc/john/private-key.pem"),
                    "file",
                ),
            ),
        )

    def test_activation_receipt_is_strict_and_binds_static_authority(
        self,
    ) -> None:
        policy = self.policy()
        receipt = self.receipt(policy)
        self.assertEqual(
            sandbox.normalize_activation_receipt(
                receipt,
                policy=policy,
            ),
            receipt,
        )
        incomplete = json.loads(json.dumps(receipt))
        incomplete["assertions"]["network_denied"] = False
        self.assert_code(
            "sandbox_activation_assertions_incomplete",
            sandbox.normalize_activation_receipt,
            incomplete,
            policy=policy,
        )
        forged_bundle = self.policy(bundle_sha256="c" * 64)
        self.assert_code(
            "sandbox_activation_activation_policy_sha256_mismatch",
            sandbox.normalize_activation_receipt,
            receipt,
            policy=forged_bundle,
        )
        forged_backend = self.policy(backend_sha256="d" * 64)
        self.assertNotEqual(
            forged_backend.activation_policy_sha256(),
            policy.activation_policy_sha256(),
        )

    def test_activation_binds_capture_parent_but_not_each_sealed_run(
        self,
    ) -> None:
        first = self.policy(capture_name="capture-" + "1" * 32)
        second = self.policy(capture_name="capture-" + "2" * 32)
        self.assertEqual(
            first.activation_policy_sha256(),
            second.activation_policy_sha256(),
        )
        changed = sandbox.build_policy(
            bundle_root=first.bundle_root,
            bundle_sha256=first.bundle_sha256,
            capture_parent=Path("/var/lib/john-lomein/new-captures"),
            capture_root=Path(
                "/var/lib/john-lomein/new-captures/capture-" + "3" * 32
            ),
            python_path=first.python_path,
            entrypoint_path=first.entrypoint_path,
            scratch_root=first.scratch_root,
            activation_receipt_path=first.activation_receipt_path,
            verifier_uid=first.verifier_uid,
            verifier_gid=first.verifier_gid,
            timeout_seconds=first.timeout_seconds,
            loader_mounts=first.loader_mounts,
            system=first.system,
            backend_path=first.backend_path,
            backend_sha256=first.backend_sha256,
            kernel_release=first.kernel_release,
        )
        self.assertNotEqual(
            first.activation_policy_sha256(),
            changed.activation_policy_sha256(),
        )

    def test_production_launch_cannot_run_without_activation_receipt(
        self,
    ) -> None:
        policy = self.policy()
        with (
            mock.patch.object(sandbox.os, "getuid", return_value=0),
            mock.patch.object(sandbox.os, "geteuid", return_value=0),
            mock.patch.object(sandbox, "_validate_policy_runtime"),
            mock.patch.object(
                sandbox,
                "_read_activation_receipt",
                side_effect=sandbox.QualificationSandboxError(
                    "sandbox_activation_receipt_unreadable"
                ),
            ),
            mock.patch.object(sandbox, "_run_validated_policy") as run,
        ):
            self.assert_code(
                "sandbox_activation_receipt_unreadable",
                sandbox.launch_protected_verifier,
                policy,
                {"schema_version": "fixture"},
            )
        run.assert_not_called()

    def test_request_encoding_is_canonical_and_bounded(self) -> None:
        self.assertEqual(
            sandbox._encode_request({"z": 1, "a": 2}, maximum=32),
            b'{"a":2,"z":1}\n',
        )
        self.assert_code(
            "sandbox_request_too_large",
            sandbox._encode_request,
            {"value": "x" * 32},
            maximum=16,
        )
        self.assert_code(
            "sandbox_request_invalid",
            sandbox._encode_request,
            {"value": float("nan")},
            maximum=64,
        )

    def test_native_linux_privilege_check_does_not_require_procfs(
        self,
    ) -> None:
        def prctl(option, argument2=0, *_arguments):
            if option == sandbox._PR_GET_NO_NEW_PRIVS:
                return 1
            return 0

        with (
            mock.patch.object(sandbox.platform, "system", return_value="Linux"),
            mock.patch.object(
                sandbox,
                "_linux_capability_words",
                return_value=(0, 0, 0, 0, 0, 0),
            ),
            mock.patch.object(sandbox, "_prctl", side_effect=prctl),
            mock.patch.object(
                sandbox.Path,
                "read_text",
                side_effect=AssertionError("procfs must not be read"),
            ),
        ):
            sandbox.assert_linux_privilege_confinement()

        with (
            mock.patch.object(sandbox.platform, "system", return_value="Linux"),
            mock.patch.object(
                sandbox,
                "_linux_capability_words",
                return_value=(0, 1, 0, 0, 0, 0),
            ),
        ):
            self.assert_code(
                "linux_capability_residue",
                sandbox.assert_linux_privilege_confinement,
            )

    def _fixed_environment(self, scratch: Path) -> dict[str, str]:
        return {
            "HOME": str(scratch),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": sandbox.CONTROLLED_PATH,
            "TMPDIR": str(scratch),
            "TZ": "UTC",
        }

    def _supervise(
        self,
        scratch: Path,
        command: list[str],
        *,
        request: bytes = b"request\n",
        timeout: float = 2,
        stdout_maximum: int = 4096,
        stderr_maximum: int = 4096,
        seccomp_filter: bytes | None = None,
    ) -> sandbox.SandboxRunResult:
        return sandbox._supervise_command(
            command=command,
            environment=self._fixed_environment(scratch),
            cwd=scratch,
            request_bytes=request,
            scratch_root=scratch,
            verifier_uid=os.geteuid(),
            verifier_gid=os.getegid(),
            timeout_seconds=timeout,
            maximum_request_bytes=1024,
            maximum_stdout_bytes=stdout_maximum,
            maximum_stderr_bytes=stderr_maximum,
            prepare=lambda: None,
            seccomp_filter=seccomp_filter,
        )

    def test_supervisor_uses_bounded_files_and_preserves_only_seccomp_fd(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            inherited = tempfile.TemporaryFile()
            # Keep the leak canary distinct from the supervisor's reserved
            # seccomp descriptor even when descriptor 3 happens to be free.
            inherited_descriptor = fcntl.fcntl(
                inherited.fileno(),
                fcntl.F_DUPFD,
                sandbox.SECCOMP_FD + 1,
            )
            os.set_inheritable(inherited_descriptor, True)
            helper = (
                "import os,sys\n"
                "request=sys.stdin.buffer.read()\n"
                "policy=os.read(3,64)\n"
                f"extra={inherited_descriptor}\n"
                "try:\n"
                " os.fstat(extra); leaked=True\n"
                "except OSError:\n"
                " leaked=False\n"
                "sys.stdout.buffer.write(request+policy+b':'"
                "+str(leaked).encode())\n"
            )
            try:
                result = self._supervise(
                    scratch,
                    [sys.executable, "-c", helper],
                    request=b"sealed\n",
                    seccomp_filter=b"policy",
                )
            finally:
                os.close(inherited_descriptor)
                inherited.close()
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(result.stdout, b"sealed\npolicy:False")
            self.assertEqual(list(scratch.iterdir()), [])

    def test_supervisor_sets_exact_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            result = self._supervise(
                scratch,
                [
                    sys.executable,
                    "-c",
                    "import os,sys;sys.stdout.write(os.getcwd())",
                ],
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(
                result.stdout.decode(),
                str(scratch.resolve()),
            )

    def test_supervisor_deadline_always_kills_group_and_reaps_leader(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            observed_pids: list[int] = []
            kill_groups: list[tuple[int, int]] = []
            original_spawn = sandbox._spawn_child
            original_killpg = sandbox.os.killpg

            def spawn(**kwargs):
                pid = original_spawn(**kwargs)
                observed_pids.append(pid)
                return pid

            def killpg(pid, requested_signal):
                kill_groups.append((pid, requested_signal))
                return original_killpg(pid, requested_signal)

            with (
                mock.patch.object(
                    sandbox,
                    "_spawn_child",
                    side_effect=spawn,
                ),
                mock.patch.object(
                    sandbox.os,
                    "killpg",
                    side_effect=killpg,
                ),
            ):
                self.assert_code(
                    "sandbox_deadline_exceeded",
                    self._supervise,
                    scratch,
                    [sys.executable, "-c", "import time;time.sleep(10)"],
                    timeout=0.05,
                )
            self.assertEqual(len(observed_pids), 1)
            self.assertIn(
                (observed_pids[0], signal.SIGKILL),
                kill_groups,
            )
            with self.assertRaises(ChildProcessError):
                os.waitpid(observed_pids[0], os.WNOHANG)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_supervisor_cleans_process_on_internal_wait_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            observed_pids: list[int] = []
            original_spawn = sandbox._spawn_child

            def spawn(**kwargs):
                pid = original_spawn(**kwargs)
                observed_pids.append(pid)
                return pid

            with (
                mock.patch.object(
                    sandbox,
                    "_spawn_child",
                    side_effect=spawn,
                ),
                mock.patch.object(
                    sandbox,
                    "_wait_until_exit",
                    side_effect=RuntimeError("synthetic wait failure"),
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "synthetic wait failure",
                ):
                    self._supervise(
                        scratch,
                        [
                            sys.executable,
                            "-c",
                            "import time;time.sleep(10)",
                        ],
                    )
            with self.assertRaises(ChildProcessError):
                os.waitpid(observed_pids[0], os.WNOHANG)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_supervisor_reaps_before_rejecting_oversized_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            observed_pids: list[int] = []
            original_spawn = sandbox._spawn_child

            def spawn(**kwargs):
                pid = original_spawn(**kwargs)
                observed_pids.append(pid)
                return pid

            with mock.patch.object(
                sandbox,
                "_spawn_child",
                side_effect=spawn,
            ):
                self.assert_code(
                    "sandbox_stdout_too_large",
                    self._supervise,
                    scratch,
                    [
                        sys.executable,
                        "-c",
                        "import sys;sys.stdout.write('x'*1024)",
                    ],
                    stdout_maximum=32,
                )
            with self.assertRaises(ChildProcessError):
                os.waitpid(observed_pids[0], os.WNOHANG)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_supervisor_rejects_large_input_before_fork(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            with mock.patch.object(sandbox, "_spawn_child") as spawn:
                self.assert_code(
                    "sandbox_request_too_large",
                    sandbox._supervise_command,
                    command=[sys.executable, "-c", "pass"],
                    environment=self._fixed_environment(scratch),
                    cwd=scratch,
                    request_bytes=b"x" * 17,
                    scratch_root=scratch,
                    verifier_uid=os.geteuid(),
                    verifier_gid=os.getegid(),
                    timeout_seconds=1,
                    maximum_request_bytes=16,
                    maximum_stdout_bytes=32,
                    maximum_stderr_bytes=32,
                    prepare=lambda: None,
                    seccomp_filter=None,
                )
            spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
