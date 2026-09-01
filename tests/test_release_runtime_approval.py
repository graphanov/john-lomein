#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from release_broker import john_lomein_release_broker_protocol as protocol
from tests.test_release_broker_protocol import owner_envelope, release_bundle

SCRIPT = ROOT / "scripts" / "john-lomein-release-approve.py"
SPEC = importlib.util.spec_from_file_location(
    "john_lomein_release_approve_test", SCRIPT
)
assert SPEC and SPEC.loader
approval_runtime = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = approval_runtime
SPEC.loader.exec_module(approval_runtime)


CHANNEL_ID = "123456789" + "012345678"
MESSAGE_ID = "223456789" + "012345678"


def fresh_bundle() -> tuple[dict, datetime]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    bundle = release_bundle()
    bundle["created_at"] = protocol.utc_text(now - timedelta(minutes=1))
    bundle["expires_at"] = protocol.utc_text(now + timedelta(minutes=20))
    bundle["bundle_id"] = ""
    bundle["bundle_digest"] = ""
    bundle["bundle_digest"] = protocol.release_bundle_digest(bundle)
    bundle["bundle_id"] = protocol.release_bundle_id(bundle)
    return bundle, now


class CurrentReleaseApprovalRuntimeTest(unittest.TestCase):
    def test_incomplete_owner_mission_blocks_release_route(self):
        env = {
            "BOT_MISSION_COMPLETE": "0",
            "BOT_MUTATION_ENABLED": "1",
            "BOT_PROTECTED_RELEASE_BROKER_ENABLED": "1",
        }
        with self.assertRaisesRegex(
            approval_runtime.CurrentReleaseApprovalError,
            "owner mission is incomplete",
        ):
            approval_runtime._require_enabled(env)

    def test_minimal_deployed_client_passes_disabled_status_canary(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            scripts = runtime / "scripts"
            package = scripts / "release_broker"
            package.mkdir(parents=True, mode=0o700)
            runtime.chmod(0o700)
            scripts.chmod(0o700)

            for name in (
                "john-lomein-release-approve.py",
                "john-lomein-release-submit.py",
                "john_lomein_autonomy.py",
                "john_lomein_owner_actions.py",
                "john_lomein_release_packets.py",
            ):
                shutil.copy2(ROOT / "scripts" / name, scripts / name)
            for name in (
                "__init__.py",
                "john_lomein_release_broker_protocol.py",
                "john_lomein_release_broker_receipts.py",
            ):
                destination = package / name
                shutil.copy2(ROOT / "release_broker" / name, destination)
                destination.chmod(0o600)

            runtime_env = scripts / "john-lomein-instance.env"
            runtime_env.write_text(
                "\n".join(
                    (
                        "BOT_SLUG='widget-production'",
                        "BOT_REPO='acme/widget'",
                        "BOT_DEFAULT_BRANCH='main'",
                        "BOT_MISSION_COMPLETE='0'",
                        "BOT_MUTATION_ENABLED='0'",
                        "BOT_PROTECTED_RELEASE_BROKER_ENABLED='0'",
                        "BOT_ALLOWED_CHANNELS=''",
                        "BOT_FREE_RESPONSE_CHANNELS=''",
                        "BOT_NO_THREAD_CHANNELS=''",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            runtime_env.chmod(0o600)

            probe = subprocess.run(
                [
                    sys.executable,
                    str(scripts / "john-lomein-release-approve.py"),
                    "status",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                probe.returncode,
                0,
                probe.stderr + probe.stdout,
            )
            self.assertEqual(probe.stderr, "")
            status = json.loads(probe.stdout)
            self.assertFalse(status["runtime_route_enabled"])
            self.assertFalse(status["unexpected_privileged_surface"])

    def test_failed_client_load_is_removed_and_redacted(self):
        module_name = "john_lomein_release_submit_runtime"
        previous = sys.modules.pop(module_name, None)
        try:
            with tempfile.TemporaryDirectory() as temporary:
                script_dir = Path(temporary)
                (script_dir / "john-lomein-release-submit.py").write_text(
                    "raise RuntimeError('private loader detail')\n",
                    encoding="utf-8",
                )
                with mock.patch.object(
                    approval_runtime, "SCRIPT_DIR", script_dir
                ):
                    with self.assertRaisesRegex(
                        approval_runtime.CurrentReleaseApprovalError,
                        "^release submission client is unavailable$",
                    ):
                        approval_runtime._release_submit_module()
                self.assertNotIn(module_name, sys.modules)
        finally:
            if previous is not None:
                sys.modules[module_name] = previous

    def test_error_path_survives_unavailable_client_module(self):
        stderr = io.StringIO()
        with (
            mock.patch.object(
                approval_runtime,
                "_runtime_home",
                side_effect=RuntimeError("first failure"),
            ),
            mock.patch.object(
                approval_runtime,
                "_release_submit_module",
                side_effect=approval_runtime.CurrentReleaseApprovalError(
                    "release submission client is unavailable"
                ),
            ),
            contextlib.redirect_stderr(stderr),
        ):
            code = approval_runtime.main(["status"])
        self.assertEqual(code, 2)
        self.assertIn("internal runtime helper failure", stderr.getvalue())
        self.assertNotIn("first failure", stderr.getvalue())

    def test_session_identity_is_never_read_and_discord_locator_fails_closed(self):
        expected = (CHANNEL_ID, MESSAGE_ID)
        base = {
            "HERMES_SESSION_PLATFORM": "discord",
            "HERMES_SESSION_CHAT_ID": CHANNEL_ID,
            "HERMES_SESSION_MESSAGE_ID": MESSAGE_ID,
        }
        self.assertEqual(approval_runtime._session_ids(base), expected)
        self.assertEqual(
            approval_runtime._session_ids(
                {**base, "HERMES_SESSION_USER_ID": "spoofed-owner"}
            ),
            expected,
        )
        for candidate in (
            {**base, "HERMES_SESSION_PLATFORM": "cli"},
            {**base, "HERMES_SESSION_CHAT_ID": ""},
            {**base, "HERMES_SESSION_MESSAGE_ID": "not-a-snowflake"},
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    approval_runtime.CurrentReleaseApprovalError
                ):
                    approval_runtime._session_ids(candidate)

    def test_exact_approval_is_bound_to_the_stored_bundle_and_digest(self):
        bundle, _ = fresh_bundle()
        approval = approval_runtime.release_owner_approval_text(bundle)
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            bundle_dir = home / "private" / "release-bundles"
            bundle_dir.mkdir(parents=True)
            path = bundle_dir / f"{bundle['bundle_id']}.json"
            path.write_bytes(approval_runtime.packets.canonical_json(bundle))
            self.assertEqual(
                approval_runtime._load_bound_bundle(
                    home, approval_text=approval
                ),
                bundle,
            )
            wrong = approval.replace(
                bundle["bundle_digest"], "sha256:" + "f" * 64
            )
            with self.assertRaises(
                approval_runtime.CurrentReleaseApprovalError
            ):
                approval_runtime._load_bound_bundle(
                    home, approval_text=wrong
                )

    def test_spool_staging_is_mode_0640_and_idempotent(self):
        bundle, _ = fresh_bundle()
        with tempfile.TemporaryDirectory() as temporary:
            spool = Path(temporary) / "spool"
            spool.mkdir()
            spool.chmod(0o2770)

            def open_test_spool(path: Path):
                self.assertEqual(path, spool)
                descriptor = os.open(path, os.O_RDONLY)
                info = os.fstat(descriptor)
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o2770)
                return descriptor, info

            with mock.patch.object(
                approval_runtime,
                "_open_spool_directory",
                side_effect=open_test_spool,
            ):
                first = approval_runtime._stage_bundle(
                    bundle, spool_dir=spool
                )
                second = approval_runtime._stage_bundle(
                    bundle, spool_dir=spool
                )
            self.assertEqual(first, second)
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o640)
            self.assertEqual(
                first.read_bytes(),
                approval_runtime.packets.canonical_json(bundle) + b"\n",
            )

    def test_authorization_probe_is_nonexecuting_fixed_and_scrubbed(self):
        invocation = {
            "signer_user": "release-signer",
            "signer_primary_group": "release-signer-private",
            "approval_channel_ids": [CHANNEL_ID],
            "request_spool_dir": "/private/var/db/john-lomein-release-owner-gateway/requests/widget",
            "wrapper_path": "/usr/local/libexec/john-lomein-release-owner-gateway-instances/widget/mint",
        }
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, b"", b"")

        approval_runtime._probe_gateway_authorization(
            invocation, runner=runner
        )
        self.assertEqual(len(calls), 1)
        command, kwargs = calls[0]
        self.assertEqual(
            command,
            [
                "/usr/bin/sudo",
                "-n",
                "-l",
                "-u",
                "release-signer",
                "-g",
                "release-signer-private",
                "--",
                invocation["wrapper_path"],
                "--status",
            ],
        )
        self.assertEqual(
            set(kwargs["env"]),
            {"PATH", "LANG"},
        )

    def test_spool_membership_requires_requester_and_signer(self):
        invocation = {
            "signer_user": "release-signer",
            "signer_primary_group": "release-signer-private",
        }
        directory_info = SimpleNamespace(st_gid=777)
        requester = SimpleNamespace(pw_name="requester", pw_gid=20)
        signer = SimpleNamespace(pw_name="release-signer", pw_gid=30)
        with (
            mock.patch.object(
                approval_runtime.pwd,
                "getpwuid",
                return_value=requester,
            ),
            mock.patch.object(
                approval_runtime.pwd,
                "getpwnam",
                return_value=signer,
            ),
            mock.patch.object(
                approval_runtime.grp,
                "getgrgid",
                return_value=SimpleNamespace(
                    gr_name="release-signer-private"
                ),
            ),
            mock.patch.object(
                approval_runtime.os,
                "getgroups",
                return_value=[20, 777],
            ),
            mock.patch.object(
                approval_runtime.os,
                "getgrouplist",
                return_value=[30, 777],
            ),
        ):
            approval_runtime._validate_spool_membership(
                invocation, directory_info
            )
            with mock.patch.object(
                approval_runtime.os,
                "getgrouplist",
                return_value=[30],
            ):
                with self.assertRaisesRegex(
                    approval_runtime.CurrentReleaseApprovalError,
                    "membership",
                ):
                    approval_runtime._validate_spool_membership(
                        invocation, directory_info
                    )

    def test_gateway_self_check_is_fixed_nonnetwork_and_strict(self):
        invocation = {
            "signer_user": "release-signer",
            "signer_primary_group": "release-signer-private",
            "wrapper_path": "/usr/local/libexec/release-owner/mint",
        }
        calls = []
        payload = {
            "schema_version": (
                approval_runtime.GATEWAY_SELF_CHECK_SCHEMA
            ),
            "enabled": True,
            "healthy": True,
        }

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(payload, separators=(",", ":")).encode(),
                b"",
            )

        self.assertEqual(
            approval_runtime._run_gateway_self_check(
                invocation, runner=runner
            ),
            payload,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0][0],
            [
                "/usr/bin/sudo",
                "-n",
                "-u",
                "release-signer",
                "-g",
                "release-signer-private",
                "--",
                invocation["wrapper_path"],
                "--status",
            ],
        )
        self.assertEqual(set(calls[0][1]["env"]), {"PATH", "LANG"})

    def test_broker_probe_rejects_stale_socket_and_wrong_peer(self):
        client_module = approval_runtime._release_submit_module()
        config = {
            "socket_path": "/private/var/run/john-lomein-release.sock",
            "connect_timeout_seconds": 1,
            "broker_uid": 700,
        }

        class FakeSocket:
            def __init__(self, *, connect_error=None):
                self.connect_error = connect_error
                self.closed = False

            def settimeout(self, timeout):
                self.timeout = timeout

            def connect(self, path):
                self.path = path
                if self.connect_error is not None:
                    raise self.connect_error

            def close(self):
                self.closed = True

        stale = FakeSocket(connect_error=ConnectionRefusedError())
        with mock.patch.object(
            client_module, "_validate_socket_file", return_value=None
        ):
            with self.assertRaisesRegex(
                approval_runtime.CurrentReleaseApprovalError,
                "no reachable listener",
            ):
                approval_runtime._probe_broker_socket(
                    config,
                    socket_factory=lambda *args: stale,
                    peer_uid_getter=lambda sock: 700,
                )
            wrong_peer = FakeSocket()
            with self.assertRaisesRegex(
                approval_runtime.CurrentReleaseApprovalError,
                "peer identity",
            ):
                approval_runtime._probe_broker_socket(
                    config,
                    socket_factory=lambda *args: wrong_peer,
                    peer_uid_getter=lambda sock: 701,
                )
            healthy = FakeSocket()
            approval_runtime._probe_broker_socket(
                config,
                socket_factory=lambda *args: healthy,
                peer_uid_getter=lambda sock: 700,
            )
        self.assertTrue(stale.closed)
        self.assertTrue(wrong_peer.closed)
        self.assertTrue(healthy.closed)

    def test_disabled_status_flags_live_privileged_surfaces(self):
        env = {
            "BOT_SLUG": "widget-production",
            "BOT_REPO": "acme/widget",
            "BOT_DEFAULT_BRANCH": "main",
            "BOT_MISSION_COMPLETE": "0",
            "BOT_MUTATION_ENABLED": "0",
            "BOT_PROTECTED_RELEASE_BROKER_ENABLED": "0",
            "BOT_ALLOWED_CHANNELS": CHANNEL_ID,
            "BOT_FREE_RESPONSE_CHANNELS": CHANNEL_ID,
            "BOT_NO_THREAD_CHANNELS": CHANNEL_ID,
        }
        invocation = {
            "approval_channel_ids": [CHANNEL_ID],
            "request_spool_dir": "/private/spool",
            "wrapper_path": "/usr/local/libexec/wrapper",
        }
        descriptor = os.open(tempfile.gettempdir(), os.O_RDONLY)
        try:
            with (
                mock.patch.object(
                    approval_runtime,
                    "_load_invocation_config",
                    return_value=invocation,
                ),
                mock.patch.object(
                    approval_runtime,
                    "_open_spool_directory",
                    return_value=(descriptor, os.fstat(descriptor)),
                ),
                mock.patch.object(
                    approval_runtime,
                    "_validate_spool_membership",
                    return_value=None,
                ),
                mock.patch.object(
                    approval_runtime,
                    "_validate_wrapper",
                    return_value=None,
                ),
                mock.patch.object(
                    approval_runtime,
                    "_probe_gateway_authorization",
                    return_value=None,
                ),
                mock.patch.object(
                    approval_runtime,
                    "_run_gateway_self_check",
                    return_value={"enabled": True, "healthy": True},
                ),
                mock.patch.object(
                    approval_runtime,
                    "_load_broker_binding",
                    return_value={},
                ),
                mock.patch.object(
                    approval_runtime,
                    "_probe_broker_socket",
                    return_value=None,
                ),
            ):
                status_value, code = approval_runtime.runtime_status(
                    Path("/unused"), env=env
                )
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.assertEqual(code, 2)
        self.assertFalse(status_value["runtime_route_enabled"])
        self.assertTrue(status_value["unexpected_privileged_surface"])
        self.assertTrue(
            status_value["owner_gateway"]["authorization_present"]
        )
        self.assertTrue(status_value["release_broker"]["listening"])

    def test_enabled_status_requires_self_check_and_authenticated_listener(self):
        env = {
            "BOT_SLUG": "widget-production",
            "BOT_REPO": "acme/widget",
            "BOT_DEFAULT_BRANCH": "main",
            "BOT_MISSION_COMPLETE": "1",
            "BOT_MUTATION_ENABLED": "1",
            "BOT_PROTECTED_RELEASE_BROKER_ENABLED": "1",
            "BOT_ALLOWED_CHANNELS": CHANNEL_ID,
            "BOT_FREE_RESPONSE_CHANNELS": CHANNEL_ID,
            "BOT_NO_THREAD_CHANNELS": CHANNEL_ID,
        }
        invocation = {
            "approval_channel_ids": [CHANNEL_ID],
            "request_spool_dir": "/private/spool",
            "wrapper_path": "/usr/local/libexec/wrapper",
        }

        def open_spool(_):
            descriptor = os.open(tempfile.gettempdir(), os.O_RDONLY)
            return descriptor, os.fstat(descriptor)

        def inspect(self_check):
            patchers = (
                mock.patch.object(
                    approval_runtime,
                    "_load_invocation_config",
                    return_value=invocation,
                ),
                mock.patch.object(
                    approval_runtime,
                    "_open_spool_directory",
                    side_effect=open_spool,
                ),
                mock.patch.object(
                    approval_runtime,
                    "_validate_spool_membership",
                    return_value=None,
                ),
                mock.patch.object(
                    approval_runtime,
                    "_validate_wrapper",
                    return_value=None,
                ),
                mock.patch.object(
                    approval_runtime,
                    "_probe_gateway_authorization",
                    return_value=None,
                ),
                mock.patch.object(
                    approval_runtime,
                    "_run_gateway_self_check",
                    return_value=self_check,
                ),
                mock.patch.object(
                    approval_runtime,
                    "_load_broker_binding",
                    return_value={},
                ),
                mock.patch.object(
                    approval_runtime,
                    "_probe_broker_socket",
                    return_value=None,
                ),
            )
            with contextlib.ExitStack() as stack:
                for patcher in patchers:
                    stack.enter_context(patcher)
                return approval_runtime.runtime_status(
                    Path("/unused"), env=env
                )

        healthy, healthy_code = inspect(
            {"enabled": True, "healthy": True}
        )
        self.assertEqual(healthy_code, 0)
        self.assertTrue(healthy["ready"])
        self.assertTrue(healthy["owner_gateway"]["private_healthy"])

        disabled, disabled_code = inspect(
            {"enabled": False, "healthy": True}
        )
        self.assertEqual(disabled_code, 2)
        self.assertFalse(disabled["ready"])
        self.assertFalse(disabled["owner_gateway"]["private_enabled"])

    def test_approval_channels_must_be_allowed_and_no_thread(self):
        invocation = {"approval_channel_ids": [CHANNEL_ID]}
        valid = {
            "BOT_ALLOWED_CHANNELS": CHANNEL_ID,
            "BOT_FREE_RESPONSE_CHANNELS": CHANNEL_ID,
            "BOT_NO_THREAD_CHANNELS": CHANNEL_ID,
        }
        approval_runtime._validate_approval_channels(
            invocation, valid, current_channel_id=CHANNEL_ID
        )
        for candidate in (
            {**valid, "BOT_ALLOWED_CHANNELS": ""},
            {**valid, "BOT_FREE_RESPONSE_CHANNELS": ""},
            {**valid, "BOT_NO_THREAD_CHANNELS": ""},
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(
                    approval_runtime.CurrentReleaseApprovalError,
                    "allowed, free-response, and no-thread",
                ):
                    approval_runtime._validate_approval_channels(
                        invocation,
                        candidate,
                        current_channel_id=CHANNEL_ID,
                    )

    def test_exact_message_mints_once_and_submits_once(self):
        bundle, now = fresh_bundle()
        approval = approval_runtime.release_owner_approval_text(bundle)
        key = Ed25519PrivateKey.generate()
        assertion = owner_envelope(
            bundle,
            key,
            approval_text=approval,
            issued_at=protocol.utc_text(now - timedelta(seconds=10)),
            expires_at=protocol.utc_text(now + timedelta(minutes=10)),
        )
        runtime_env = {
            "BOT_SLUG": bundle["instance_slug"],
            "BOT_REPO": bundle["repository"]["full_name"],
            "BOT_DEFAULT_BRANCH": bundle["repository"]["default_branch"],
            "BOT_MISSION_COMPLETE": "1",
            "BOT_MUTATION_ENABLED": "1",
            "BOT_PROTECTED_RELEASE_BROKER_ENABLED": "1",
            "BOT_ALLOWED_CHANNELS": CHANNEL_ID,
            "BOT_FREE_RESPONSE_CHANNELS": CHANNEL_ID,
            "BOT_NO_THREAD_CHANNELS": CHANNEL_ID,
        }
        session_env = {
            "HERMES_SESSION_PLATFORM": "discord",
            "HERMES_SESSION_CHAT_ID": CHANNEL_ID,
            "HERMES_SESSION_MESSAGE_ID": MESSAGE_ID,
            "HERMES_SESSION_USER_ID": "spoofed-owner",
        }
        signer_calls = []
        submit_calls = []
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "runtime"
            bundles = home / "private" / "release-bundles"
            bundles.mkdir(parents=True)
            source = bundles / f"{bundle['bundle_id']}.json"
            source.write_bytes(
                approval_runtime.packets.canonical_json(bundle)
            )

            def signer(invocation, **kwargs):
                signer_calls.append((invocation, kwargs))
                return {
                    "ok": True,
                    "record_id": "jlros-" + "a" * 24,
                    "event_id": "jlroe-" + "b" * 24,
                    "bundle_id": bundle["bundle_id"],
                    "owner_assertion_sha256": (
                        approval_runtime.packets.sha256_json(assertion)
                    ),
                    "owner_assertion": assertion,
                }

            client = approval_runtime._release_submit_module()

            def submitter(packet_path: Path, *, runtime_home: Path):
                submit_calls.append((packet_path, runtime_home))
                packet = json.loads(packet_path.read_text(encoding="utf-8"))
                return client.VerifiedReceipt(
                    envelope={
                        "payload": {
                            "packet": {"packet_id": packet["packet_id"]},
                            "bundle": {
                                "bundle_id": bundle["bundle_id"]
                            },
                            "outcome": "succeeded",
                            "reason_code": "release_merged",
                        }
                    },
                    locator=(
                        "state/protected-releases/receipts/jlrrc-"
                        + "c" * 24
                        + ".json"
                    ),
                )

            with mock.patch.object(
                approval_runtime,
                "_stage_bundle",
                return_value=source,
            ):
                result, code = approval_runtime.approve_current_message(
                    home,
                    approval_text=approval,
                    session_env=session_env,
                    runtime_env=runtime_env,
                    invocation={
                        "approval_channel_ids": [CHANNEL_ID],
                        "request_spool_dir": str(home / "spool"),
                    },
                    signer=signer,
                    submitter=submitter,
                )
        self.assertEqual(code, 0)
        self.assertEqual(result["bundle_id"], bundle["bundle_id"])
        self.assertEqual(len(signer_calls), 1)
        self.assertEqual(len(submit_calls), 1)
        self.assertEqual(
            set(signer_calls[0][1]),
            {"bundle_path", "channel_id", "message_id"},
        )


if __name__ == "__main__":
    unittest.main()
