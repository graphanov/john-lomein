#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "john_lomein_container_verifier.py"
IMAGE = "example/verifier@sha256:" + "a" * 64
LOCK = "b" * 64


def load_module() -> Any:
    spec = importlib.util.spec_from_file_location("john_lomein_container_verifier", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class ContainerVerifierTest(unittest.TestCase):
    def test_bounded_process_keeps_only_tail_of_untrusted_output(self):
        verifier = load_module()
        code, stdout, stderr, timed_out = verifier._run_bounded_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096); sys.stderr.write('y' * 4096)"],
            env=os.environ.copy(),
            timeout=10,
            max_bytes=1024,
        )

        self.assertEqual(code, 0)
        self.assertFalse(timed_out)
        self.assertTrue(stdout.startswith("[output_truncated]\n"))
        self.assertTrue(stderr.startswith("[output_truncated]\n"))
        self.assertLess(len(stdout), 1100)
        self.assertLess(len(stderr), 1100)

    def test_rejects_mutable_image_before_runtime_use(self):
        verifier = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "source.tar"
            archive.write_bytes(b"tar")
            with mock.patch.object(verifier.subprocess, "run") as run:
                result = verifier.run_container_verifier(
                    "true",
                    process_env={"HOME": tmp},
                    archive=archive,
                    image="example/verifier:latest",
                    lock_sha256=LOCK,
                )

        self.assertEqual(result[0], 997)
        self.assertEqual(result[2], "container_image_not_immutable")
        self.assertFalse(result[3])
        run.assert_not_called()

    def test_lock_attestation_mismatch_fails_before_container_run(self):
        verifier = load_module()
        inspected = [{
            "Id": "sha256:" + "c" * 64,
            "RepoDigests": [IMAGE],
            "Config": {"Labels": {
                verifier.CONTRACT_LABEL: verifier.CONTRACT_VALUE,
                verifier.LOCK_LABEL: "d" * 64,
            }},
        }]
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "source.tar"
            archive.write_bytes(b"tar")
            with (
                mock.patch.object(verifier.shutil, "which", return_value="/usr/local/bin/docker"),
                mock.patch.object(verifier, "_docker_host", return_value="unix:///tmp/docker.sock"),
                mock.patch.object(
                    verifier.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, json.dumps(inspected), ""),
                ) as run,
            ):
                result = verifier.run_container_verifier(
                    "true",
                    process_env={"HOME": tmp},
                    archive=archive,
                    image=IMAGE,
                    lock_sha256=LOCK,
                )

        self.assertEqual(result[0], 997)
        self.assertEqual(result[2], "container_image_lock_mismatch")
        self.assertFalse(result[3])
        self.assertEqual(run.call_count, 1)

    def test_runs_only_tracked_archive_with_private_loopback_and_no_parent_secrets(self):
        verifier = load_module()
        inspected = [{
            "Id": "sha256:" + "c" * 64,
            "RepoDigests": [IMAGE],
            "Config": {"Labels": {
                verifier.CONTRACT_LABEL: verifier.CONTRACT_VALUE,
                verifier.LOCK_LABEL: LOCK,
            }},
        }]
        calls: list[tuple[list[str], dict[str, str]]] = []

        def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls.append((list(command), dict(kwargs.get("env") or {})))
            if command[1:3] == ["image", "inspect"]:
                return subprocess.CompletedProcess(command, 0, json.dumps(inspected), "")
            raise AssertionError(f"unexpected subprocess.run: {command}")

        def fake_bounded(command: list[str], **kwargs: Any) -> tuple[int, str, str, bool]:
            calls.append((list(command), dict(kwargs.get("env") or {})))
            return 0, "tests passed", "", False

        old_token = os.environ.get("GH_TOKEN")
        os.environ["GH_TOKEN"] = "must-not-reach-docker"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                archive = Path(tmp) / "source.tar"
                archive.write_bytes(b"tar")
                with (
                    mock.patch.object(verifier.shutil, "which", return_value="/usr/local/bin/docker"),
                    mock.patch.object(verifier, "_docker_host", return_value="unix:///tmp/docker.sock"),
                    mock.patch.object(verifier.subprocess, "run", side_effect=fake_run),
                    mock.patch.object(verifier, "_run_bounded_process", side_effect=fake_bounded),
                ):
                    code, stdout, stderr, enforced, meta = verifier.run_container_verifier(
                        "./verify.sh --strict && npm test -- --run",
                        process_env={"HOME": tmp, "GH_TOKEN": "also-secret"},
                        archive=archive,
                        image=IMAGE,
                        lock_sha256=LOCK,
                    )
        finally:
            if old_token is None:
                os.environ.pop("GH_TOKEN", None)
            else:
                os.environ["GH_TOKEN"] = old_token

        self.assertEqual((code, stdout, stderr, enforced), (0, "tests passed", "", True))
        self.assertEqual(meta["backend"], "docker")
        self.assertEqual(meta["network"], "none")
        command, runtime_env = calls[1]
        joined = "\n".join(command)
        self.assertIn("--network\nnone", joined)
        self.assertIn("--ipc\nnone", joined)
        self.assertIn("--read-only", command)
        self.assertIn("--log-driver\nnone", joined)
        self.assertIn("--cap-drop\nALL", joined)
        self.assertIn("no-new-privileges:true", command)
        self.assertIn("65534:65534", command)
        self.assertIn("--entrypoint\n/usr/bin/timeout", joined)
        self.assertIn("--restart\nno", joined)
        self.assertIn("org.john-lomein.verifier=true", command)
        self.assertIn(f"type=bind,source={archive},target=/source.tar,readonly", command)
        self.assertNotIn("GH_TOKEN", joined)
        self.assertNotIn("GH_TOKEN", runtime_env)
        self.assertNotIn("must-not-reach-docker", repr(calls))
        self.assertNotIn("also-secret", repr(calls))


if __name__ == "__main__":
    unittest.main()
