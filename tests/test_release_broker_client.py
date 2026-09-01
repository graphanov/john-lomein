#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MODULE = ROOT / "scripts" / "john-lomein-release-submit.py"
spec = importlib.util.spec_from_file_location(
    "john_lomein_release_submit", MODULE
)
assert spec and spec.loader
client = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = client
spec.loader.exec_module(client)

from release_broker import john_lomein_release_broker_protocol as protocol
from release_broker import john_lomein_release_broker_receipts as receipts
from tests.test_release_broker_protocol import (
    owner_envelope,
    release_bundle,
    release_packet,
)


NOW = datetime(2026, 7, 16, 12, 1, tzinfo=timezone.utc)
APPROVAL = (
    "APPROVE JOHN-LOMEIN RELEASE BUNDLE: squash-merge the exact "
    "listed PR; DO NOT publish."
)
CONFIG_DIGEST = "sha256:" + ("1" * 64)
KEY_ID = "release-receipts-2026-01"


class ReleaseBrokerClientPackageTest(unittest.TestCase):
    def test_minimal_deployed_package_imports_without_privileged_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "release_broker"
            package.mkdir()
            for name in (
                "__init__.py",
                "john_lomein_release_broker_protocol.py",
                "john_lomein_release_broker_receipts.py",
            ):
                shutil.copy2(ROOT / "release_broker" / name, package / name)

            probe = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    (
                        "import sys;"
                        "sys.path.insert(0, sys.argv[1]);"
                        "import release_broker;"
                        "from release_broker import "
                        "john_lomein_release_broker_protocol as protocol;"
                        "from release_broker import "
                        "john_lomein_release_broker_receipts as receipts;"
                        "assert protocol.PACKET_SCHEMA;"
                        "assert receipts.RECEIPT_PAYLOAD_SCHEMA;"
                        "assert not any("
                        "'john_lomein_release_broker_github_' in name "
                        "for name in sys.modules)"
                    ),
                    temporary,
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
            self.assertEqual(
                {path.name for path in package.iterdir() if path.is_file()},
                {
                    "__init__.py",
                    "john_lomein_release_broker_protocol.py",
                    "john_lomein_release_broker_receipts.py",
                },
            )


class ScriptedSocket:
    def __init__(
        self,
        response: bytes = b"",
        *,
        peer_uid: int,
        fail_send: bool = False,
        fail_recv: bool = False,
    ) -> None:
        self.response = bytearray(response)
        self.peer_uid = peer_uid
        self.fail_send = fail_send
        self.fail_recv = fail_recv
        self.sent: list[bytes] = []
        self.connected: list[str] = []
        self.shutdowns: list[int] = []
        self.closed = False
        self.family = socket.AF_UNIX

    def settimeout(self, _: float) -> None:
        return None

    def connect(self, path: str) -> None:
        self.connected.append(path)

    def getpeereid(self) -> tuple[int, int]:
        return self.peer_uid, os.getgid()

    def sendall(self, raw: bytes) -> None:
        self.sent.append(raw)
        if self.fail_send:
            raise OSError("simulated partial write")

    def shutdown(self, how: int) -> None:
        self.shutdowns.append(how)

    def recv(self, count: int) -> bytes:
        if self.fail_recv:
            raise socket.timeout()
        if not self.response:
            return b""
        result = bytes(self.response[:count])
        del self.response[:count]
        return result

    def close(self) -> None:
        self.closed = True


def framed(value: dict, *, trailing: bytes = b"") -> bytes:
    raw = protocol.canonical_json(value)
    return struct.pack("!I", len(raw)) + raw + trailing


class ReleaseBrokerClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        (self.runtime / "scripts").mkdir(mode=0o700)
        (self.runtime / "scripts" / "john-lomein-instance.env").write_text(
            "\n".join(
                [
                    "BOT_SLUG='widget-production'",
                    "BOT_REPO='acme/widget'",
                    "BOT_DEFAULT_BRANCH='main'",
                    f"BOT_HERMES_HOME='{self.runtime}'",
                    f"BOT_LOCAL='{self.root / 'repo'}'",
                    "BOT_FORBIDDEN_PATHS_JSON='[]'",
                    "BOT_FORGE_PROFILE='john-lomein-forge'",
                    "BOT_MAINTAINER_PROFILE='john-lomein-maintainer'",
                    "BOT_MISSION_COMPLETE='1'",
                    "BOT_MUTATION_ENABLED='1'",
                    "BOT_OSC_PORTFOLIO_ENABLED='0'",
                    "BOT_OSC_PORTFOLIO_BRANCH_PREFIX='portfolio/'",
                    "BOT_PROTECTED_RELEASE_BROKER_ENABLED='1'",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (
            self.runtime
            / "scripts"
            / "john-lomein-instance.env"
        ).chmod(0o600)
        self.config_root = self.root / "public"
        self.config_root.mkdir(mode=0o700)

        owner_key = Ed25519PrivateKey.generate()
        bundle = release_bundle()
        assertion = owner_envelope(
            bundle, owner_key, approval_text=APPROVAL
        )
        self.packet = release_packet(
            bundle, assertion, approval_text=APPROVAL
        )
        self.packet_path = self.root / "packet.json"
        self.write_json(self.packet_path, self.packet, 0o600)

        self.receipt_private = Ed25519PrivateKey.generate()
        self.receipt_public = (
            self.receipt_private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        private_bytes = self.receipt_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.private_path = self.config_root / "receipt.private.pem"
        self.public_path = self.config_root / "receipt.public.pem"
        self.private_path.write_bytes(private_bytes)
        self.private_path.chmod(0o600)
        self.public_path.write_bytes(self.receipt_public)
        self.public_path.chmod(0o644)
        self.broker_uid = os.getuid() + 1000
        self.config = {
            "schema_version": client.CLIENT_CONFIG_SCHEMA,
            "broker_id": "john-lomein-release-widget",
            "broker_uid": self.broker_uid,
            "requester_uid": os.getuid(),
            "submit_gid": os.getgid(),
            "broker_config_sha256": CONFIG_DIGEST,
            "socket_path": str(self.root / "release.sock"),
            "receipt_public_key_path": str(self.public_path),
            "receipt_public_key_sha256": protocol.sha256_bytes(
                self.receipt_public
            ),
            "receipt_key_id": KEY_ID,
            "connect_timeout_seconds": 5,
            "request_timeout_seconds": 30,
            "max_response_bytes": 1024 * 1024,
            "instance_slug": "widget-production",
            "repository": {
                "id": 987654,
                "full_name": "acme/widget",
                "default_branch": "main",
            },
            "github_app": {
                "app_id": 1234,
                "app_slug": "john-lomein-release",
                "installation_id": 5678,
            },
        }
        self.config_path = self.config_root / "widget-production.json"
        self.write_json(self.config_path, self.config, 0o644)
        self.success = self.signed_receipt("succeeded")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(
        self, path: Path, value: dict, mode: int = 0o600
    ) -> None:
        path.write_bytes(protocol.canonical_json(value) + b"\n")
        path.chmod(mode)

    def step_for_outcome(self, outcome: str) -> dict:
        bundle = self.packet["request"]["bundle"]
        common = {
            "position": 0,
            "pr_number": bundle["ordered_prs"][0]["number"],
            "authorized_head_sha": bundle["ordered_prs"][0][
                "head_sha"
            ],
            "expected_base_sha": bundle["initial_base_sha"],
            "precondition_digest": "sha256:" + ("2" * 64),
            "started_at": "2026-07-16T12:00:10Z",
            "completed_at": "2026-07-16T12:00:30Z",
        }
        if outcome == "succeeded":
            return {
                **common,
                "attempt_id": "jlra-attempt-1",
                "outcome": "merged",
                "reason_code": "merge_confirmed",
                "merge_sha": "d" * 40,
                "parent_sha": bundle["initial_base_sha"],
                "tree_sha": "e" * 40,
                "merged_by": "john-lomein-release[bot]",
                "attempted_at": "2026-07-16T12:00:20Z",
            }
        if outcome == "rejected":
            return {
                **common,
                "attempt_id": None,
                "outcome": "rejected",
                "reason_code": "policy_denied",
                "merge_sha": None,
                "parent_sha": None,
                "tree_sha": None,
                "merged_by": None,
                "attempted_at": None,
            }
        return {
            **common,
            "attempt_id": "jlra-attempt-1",
            "outcome": "indeterminate",
            "reason_code": "indeterminate_transport",
            "merge_sha": None,
            "parent_sha": None,
            "tree_sha": None,
            "merged_by": None,
            "attempted_at": "2026-07-16T12:00:20Z",
        }

    def signed_receipt(self, outcome: str) -> dict:
        step = self.step_for_outcome(outcome)
        if outcome == "succeeded":
            terminal_reason = "release_merged"
            final = {
                "name": "main",
                "head_sha": step["merge_sha"],
                "tree_sha": step["tree_sha"],
                "observed_at": "2026-07-16T12:00:35Z",
            }
        elif outcome == "rejected":
            terminal_reason = "policy_denied"
            final = {
                "name": "main",
                "head_sha": None,
                "tree_sha": None,
                "observed_at": None,
            }
        else:
            terminal_reason = "indeterminate_transport"
            final = {
                "name": "main",
                "head_sha": None,
                "tree_sha": None,
                "observed_at": None,
            }
        payload = receipts.build_receipt_payload(
            self.packet,
            broker_id=self.config["broker_id"],
            broker_uid=self.broker_uid,
            config_sha256=CONFIG_DIGEST,
            signing_key_id=KEY_ID,
            signing_public_key_sha256=self.config[
                "receipt_public_key_sha256"
            ],
            github_app=self.config["github_app"],
            steps=[step],
            final_branch=final,
            outcome=outcome,
            reason_code=terminal_reason,
            started_at="2026-07-16T12:00:05Z",
            completed_at="2026-07-16T12:00:40Z",
        )
        return receipts.sign_receipt(
            payload,
            private_key_path=self.private_path,
            public_key_path=self.public_path,
            expected_public_key_sha256=self.config[
                "receipt_public_key_sha256"
            ],
            expected_key_id=KEY_ID,
            key_owner_uids={os.getuid()},
            parent_owner_uids={os.getuid()},
            trusted_path_root=self.config_root,
            private_key_owner_uid=os.getuid(),
            private_key_gid=os.getgid(),
            private_key_mode=0o600,
            packet=self.packet,
        )

    def load_config(self) -> client.LoadedClientConfig:
        return client.load_client_config(
            self.config_path,
            config_owner_uids={os.getuid()},
            key_owner_uids={os.getuid()},
            parent_owner_uids={os.getuid()},
            trusted_path_root=self.config_root,
            requester_uid=os.getuid(),
            requester_groups={os.getgid()},
        )

    def submit_kwargs(self) -> dict:
        return {
            "runtime_home": self.runtime,
            "client_config_path": self.config_path,
            "now": NOW,
            "packet_owner_uids": {os.getuid()},
            "config_owner_uids": {os.getuid()},
            "key_owner_uids": {os.getuid()},
            "parent_owner_uids": {os.getuid()},
            "trusted_packet_root": self.root,
            "trusted_config_root": self.config_root,
            "requester_uid": os.getuid(),
            "requester_groups": {os.getgid()},
            "validate_socket": False,
        }

    def test_runtime_revocation_blocks_before_exchange(self):
        control = (
            self.runtime
            / "scripts"
            / "john-lomein-instance.env"
        )
        control.write_text(
            control.read_text(encoding="utf-8").replace(
                "BOT_PROTECTED_RELEASE_BROKER_ENABLED='1'",
                "BOT_PROTECTED_RELEASE_BROKER_ENABLED='0'",
            ),
            encoding="utf-8",
        )
        control.chmod(0o600)
        with mock.patch.object(client, "exchange") as exchange:
            with self.assertRaisesRegex(
                client.ReleaseSubmitError,
                "protected release authority is disabled",
            ):
                client.submit_packet(
                    self.packet_path,
                    **self.submit_kwargs(),
                )
        exchange.assert_not_called()

    def test_deployed_client_rejects_alternate_runtime(self):
        alternate = self.root / "alternate-runtime"
        (alternate / "scripts").mkdir(parents=True, mode=0o700)
        source = (
            self.runtime
            / "scripts"
            / "john-lomein-instance.env"
        ).read_text(encoding="utf-8")
        (
            alternate
            / "scripts"
            / "john-lomein-instance.env"
        ).write_text(
            source.replace(str(self.runtime), str(alternate)),
            encoding="utf-8",
        )
        (
            alternate
            / "scripts"
            / "john-lomein-instance.env"
        ).chmod(0o600)
        kwargs = self.submit_kwargs()
        kwargs["runtime_home"] = alternate
        with (
            mock.patch.object(
                client,
                "SCRIPT_DIR",
                self.runtime / "scripts",
            ),
            mock.patch.object(client, "exchange") as exchange,
        ):
            with self.assertRaisesRegex(
                client.ReleaseSubmitError,
                "does not match deployed client",
            ):
                client.submit_packet(self.packet_path, **kwargs)
        exchange.assert_not_called()

    def test_runtime_identity_must_match_packet_and_client(self):
        control = (
            self.runtime
            / "scripts"
            / "john-lomein-instance.env"
        )
        control.write_text(
            control.read_text(encoding="utf-8").replace(
                "BOT_SLUG='widget-production'",
                "BOT_SLUG='different-instance'",
            ),
            encoding="utf-8",
        )
        control.chmod(0o600)
        with mock.patch.object(client, "exchange") as exchange:
            with self.assertRaisesRegex(
                client.ReleaseSubmitError,
                "runtime authority does not match",
            ):
                client.submit_packet(
                    self.packet_path,
                    **self.submit_kwargs(),
                )
        exchange.assert_not_called()

    def test_packet_is_independently_validated_before_exchange(self):
        hostile = copy.deepcopy(self.packet)
        hostile["request"]["bundle"]["ordered_prs"][0][
            "head_sha"
        ] = "f" * 40
        self.write_json(self.packet_path, hostile)
        with mock.patch.object(client, "exchange") as exchange:
            with self.assertRaises(client.ReleaseSubmitError):
                client.submit_packet(
                    self.packet_path, **self.submit_kwargs()
                )
        exchange.assert_not_called()

    def test_client_config_and_packet_are_completely_bound(self):
        loaded = self.load_config()
        client.validate_packet_config_binding(self.packet, loaded.value)
        wrong = copy.deepcopy(self.config)
        wrong["repository"]["id"] += 1
        wrong_path = self.config_root / "wrong.json"
        self.write_json(wrong_path, wrong, 0o644)
        kwargs = self.submit_kwargs()
        kwargs["client_config_path"] = wrong_path
        with mock.patch.object(client, "exchange") as exchange:
            with self.assertRaisesRegex(
                client.ReleaseSubmitError, "repository"
            ):
                client.submit_packet(self.packet_path, **kwargs)
        exchange.assert_not_called()

    def test_stable_reads_reject_symlinks_hardlinks_and_permissions(self):
        link = self.root / "packet-link.json"
        link.symlink_to(self.packet_path)
        with self.assertRaises(client.ReleaseSubmitError):
            client.load_packet(
                link,
                now=NOW,
                packet_owner_uids={os.getuid()},
                parent_owner_uids={os.getuid()},
                trusted_path_root=self.root,
            )
        hard = self.root / "packet-hard.json"
        os.link(self.packet_path, hard)
        with self.assertRaisesRegex(client.ReleaseSubmitError, "unsafe"):
            client.load_packet(
                self.packet_path,
                now=NOW,
                packet_owner_uids={os.getuid()},
                parent_owner_uids={os.getuid()},
                trusted_path_root=self.root,
            )
        hard.unlink()
        self.packet_path.chmod(0o640)
        with self.assertRaisesRegex(client.ReleaseSubmitError, "unsafe"):
            client.load_packet(
                self.packet_path,
                now=NOW,
                packet_owner_uids={os.getuid()},
                parent_owner_uids={os.getuid()},
                trusted_path_root=self.root,
            )

    def test_client_config_rejects_wrong_identity_group_and_key(self):
        with self.assertRaisesRegex(
            client.ReleaseSubmitError, "wrong OS identity"
        ):
            client.load_client_config(
                self.config_path,
                config_owner_uids={os.getuid()},
                key_owner_uids={os.getuid()},
                parent_owner_uids={os.getuid()},
                trusted_path_root=self.config_root,
                requester_uid=os.getuid() + 1,
                requester_groups={os.getgid()},
            )
        with self.assertRaisesRegex(
            client.ReleaseSubmitError, "submit group"
        ):
            client.load_client_config(
                self.config_path,
                config_owner_uids={os.getuid()},
                key_owner_uids={os.getuid()},
                parent_owner_uids={os.getuid()},
                trusted_path_root=self.config_root,
                requester_uid=os.getuid(),
                requester_groups={os.getgid() + 1},
            )
        self.public_path.write_bytes(b"not a public key")
        with self.assertRaises(client.ReleaseSubmitError):
            self.load_config()

    def test_client_config_read_rejects_symlink_hardlink_and_permissions(self):
        symlink = self.config_root / "config-link.json"
        symlink.symlink_to(self.config_path)
        with self.assertRaises(client.ReleaseSubmitError):
            client.load_client_config(
                symlink,
                config_owner_uids={os.getuid()},
                key_owner_uids={os.getuid()},
                parent_owner_uids={os.getuid()},
                trusted_path_root=self.config_root,
                requester_uid=os.getuid(),
                requester_groups={os.getgid()},
            )
        hardlink = self.config_root / "config-hard.json"
        os.link(self.config_path, hardlink)
        with self.assertRaisesRegex(client.ReleaseSubmitError, "unsafe"):
            self.load_config()
        hardlink.unlink()
        self.config_path.chmod(0o666)
        with self.assertRaisesRegex(client.ReleaseSubmitError, "unsafe"):
            self.load_config()

    def test_kernel_peer_uid_is_checked_before_any_request_byte(self):
        scripted = ScriptedSocket(peer_uid=self.broker_uid + 1)
        with self.assertRaisesRegex(
            client.ReleaseSubmitError, "peer UID"
        ):
            client.exchange(
                {
                    "schema_version": protocol.SUBMISSION_SCHEMA,
                    "packet": self.packet,
                },
                self.config,
                validate_socket=False,
                socket_factory=lambda *_: scripted,
            )
        self.assertEqual(scripted.sent, [])
        self.assertTrue(scripted.closed)

    def test_framing_is_bounded_and_trailing_data_is_ambiguous(self):
        valid_response = {
            "schema_version": client.RESPONSE_SCHEMA,
            "ok": True,
            "receipt": self.success,
        }
        scripted = ScriptedSocket(
            framed(valid_response, trailing=b"x"),
            peer_uid=self.broker_uid,
        )
        with self.assertRaises(client.ReleaseSubmitAmbiguousError):
            client.exchange(
                {
                    "schema_version": protocol.SUBMISSION_SCHEMA,
                    "packet": self.packet,
                },
                self.config,
                validate_socket=False,
                socket_factory=lambda *_: scripted,
            )
        self.assertEqual(len(scripted.sent), 1)

        oversized = ScriptedSocket(
            struct.pack(
                "!I", self.config["max_response_bytes"] + 1
            ),
            peer_uid=self.broker_uid,
        )
        with self.assertRaises(client.ReleaseSubmitAmbiguousError):
            client.exchange(
                {
                    "schema_version": protocol.SUBMISSION_SCHEMA,
                    "packet": self.packet,
                },
                self.config,
                validate_socket=False,
                socket_factory=lambda *_: oversized,
            )
        self.assertEqual(len(oversized.sent), 1)

    def test_send_or_read_failure_is_ambiguous_and_never_retried(self):
        calls = 0
        scripted = ScriptedSocket(
            peer_uid=self.broker_uid, fail_send=True
        )

        def factory(*_: object) -> ScriptedSocket:
            nonlocal calls
            calls += 1
            return scripted

        with self.assertRaises(client.ReleaseSubmitAmbiguousError):
            client.exchange(
                {
                    "schema_version": protocol.SUBMISSION_SCHEMA,
                    "packet": self.packet,
                },
                self.config,
                validate_socket=False,
                socket_factory=factory,
            )
        self.assertEqual(calls, 1)
        self.assertEqual(len(scripted.sent), 1)

    def test_signed_receipt_rejects_tamper_wrong_key_and_wrong_binding(self):
        loaded = self.load_config()
        tampered = copy.deepcopy(self.success)
        tampered["payload"]["reason_code"] = "policy_denied"
        with self.assertRaises(client.ReleaseSubmitError):
            client.verify_signed_receipt(
                tampered,
                packet=self.packet,
                config=loaded,
                now=NOW,
            )

        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        wrong_key = client.LoadedClientConfig(
            value=loaded.value, receipt_public_key=other
        )
        with self.assertRaises(client.ReleaseSubmitError):
            client.verify_signed_receipt(
                self.success,
                packet=self.packet,
                config=wrong_key,
                now=NOW,
            )

        wrong_config = copy.deepcopy(loaded.value)
        wrong_config["broker_config_sha256"] = (
            "sha256:" + ("9" * 64)
        )
        with self.assertRaises(client.ReleaseSubmitError):
            client.verify_signed_receipt(
                self.success,
                packet=self.packet,
                config=client.LoadedClientConfig(
                    value=wrong_config,
                    receipt_public_key=loaded.receipt_public_key,
                ),
                now=NOW,
            )

    def test_submit_persists_success_and_exact_terminal_replay(self):
        response = {
            "schema_version": client.RESPONSE_SCHEMA,
            "ok": True,
            "receipt": self.success,
        }
        with mock.patch.object(client, "exchange", return_value=response):
            first = client.submit_packet(
                self.packet_path, **self.submit_kwargs()
            )
            second = client.submit_packet(
                self.packet_path, **self.submit_kwargs()
            )
        self.assertEqual(first, second)
        self.assertFalse(Path(first.locator).is_absolute())
        persisted = self.runtime / first.locator
        self.assertEqual(stat_mode(persisted), 0o600)
        self.assertEqual(
            json.loads(persisted.read_text(encoding="utf-8")),
            self.success,
        )

    def test_every_valid_negative_receipt_is_persisted(self):
        for outcome, expected_exit in (
            ("rejected", client.EXIT_REJECTED),
            ("indeterminate", client.EXIT_INDETERMINATE),
        ):
            envelope = self.signed_receipt(outcome)
            response = {
                "schema_version": client.RESPONSE_SCHEMA,
                "ok": True,
                "receipt": envelope,
            }
            with mock.patch.object(
                client, "exchange", return_value=response
            ):
                result = client.submit_packet(
                    self.packet_path, **self.submit_kwargs()
                )
            self.assertTrue((self.runtime / result.locator).is_file())
            self.assertEqual(
                client.exit_for_outcome(outcome), expected_exit
            )
        self.assertEqual(
            client.exit_for_outcome("partial"), client.EXIT_PARTIAL
        )

    def test_unsigned_daemon_error_after_send_is_ambiguous(self):
        response = {
            "schema_version": client.RESPONSE_SCHEMA,
            "ok": False,
            "error": {"code": "request_rejected"},
        }
        scripted = ScriptedSocket(
            framed(response), peer_uid=self.broker_uid
        )
        with self.assertRaisesRegex(
            client.ReleaseSubmitAmbiguousError, "no signed"
        ):
            client.exchange(
                {
                    "schema_version": protocol.SUBMISSION_SCHEMA,
                    "packet": self.packet,
                },
                self.config,
                validate_socket=False,
                socket_factory=lambda *_: scripted,
            )

    def test_offline_verification_survives_packet_and_assertion_expiry(self):
        receipt_path = self.root / "historical-receipt.json"
        self.write_json(receipt_path, self.success, 0o600)
        future = NOW + timedelta(days=30)
        result = client.verify_receipt_file(
            self.packet_path,
            receipt_path,
            runtime_home=self.runtime,
            client_config_path=self.config_path,
            now=future,
            packet_owner_uids={os.getuid()},
            receipt_owner_uids={os.getuid()},
            config_owner_uids={os.getuid()},
            key_owner_uids={os.getuid()},
            parent_owner_uids={os.getuid()},
            trusted_packet_root=self.root,
            trusted_receipt_root=self.root,
            trusted_config_root=self.config_root,
            requester_uid=os.getuid(),
            requester_groups={os.getgid()},
        )
        self.assertEqual(
            result.envelope["payload"]["outcome"], "succeeded"
        )
        self.assertTrue((self.runtime / result.locator).is_file())

    def test_receipt_store_rejects_symlink_and_conflicting_existing_file(self):
        receipts_root = (
            self.runtime / "state" / "protected-releases"
        )
        receipts_root.mkdir(parents=True, mode=0o700)
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (receipts_root / "receipts").symlink_to(
            outside, target_is_directory=True
        )
        with self.assertRaises(client.ReleaseSubmitError):
            client.persist_receipt(self.runtime, self.success)

        (receipts_root / "receipts").unlink()
        receipt_dir = receipts_root / "receipts"
        receipt_dir.mkdir(mode=0o700)
        name = (
            self.success["payload"]["receipt_id"] + ".json"
        )
        target = receipt_dir / name
        target.write_text("hostile\n", encoding="utf-8")
        target.chmod(0o600)
        with self.assertRaisesRegex(
            client.ReleaseSubmitError, "unsafe|conflicts"
        ):
            client.persist_receipt(self.runtime, self.success)

    def test_cli_output_is_public_safe_and_locator_only(self):
        result = client.VerifiedReceipt(
            envelope=self.success,
            locator=(
                "state/protected-releases/receipts/"
                f"{self.success['payload']['receipt_id']}.json"
            ),
        )
        public = client.public_result(result)
        rendered = protocol.canonical_json(public).decode()
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn("signature", rendered)
        self.assertNotIn("actor", rendered)
        self.assertFalse(Path(public["receipt_locator"]).is_absolute())
        self.assertEqual(
            client.exit_for_outcome("succeeded"), 0
        )

    def test_source_has_no_network_or_subprocess_escape_hatch(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotIn("urllib", source)
        self.assertNotIn("requests", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("http://", source)
        self.assertNotIn("https://", source)
        self.assertIn("socket.AF_UNIX", source)

    def test_main_uses_distinct_terminal_and_ambiguity_exit_codes(self):
        for outcome, expected in (
            ("succeeded", 0),
            ("rejected", client.EXIT_REJECTED),
            ("partial", client.EXIT_PARTIAL),
            ("indeterminate", client.EXIT_INDETERMINATE),
        ):
            envelope = copy.deepcopy(self.success)
            envelope["payload"]["outcome"] = outcome
            result = client.VerifiedReceipt(
                envelope=envelope,
                locator="state/protected-releases/receipts/x.json",
            )
            with mock.patch.object(
                client, "submit_packet", return_value=result
            ):
                stdout = io.BytesIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(sys, "stdout") as text_stdout,
                    mock.patch.object(sys, "stderr", stderr),
                ):
                    text_stdout.buffer = stdout
                    code = client.main(
                        [
                            "submit",
                            "--packet",
                            "packet.json",
                            "--runtime-home",
                            "runtime",
                        ]
                    )
            self.assertEqual(code, expected)

        with mock.patch.object(
            client,
            "submit_packet",
            side_effect=client.ReleaseSubmitAmbiguousError("ambiguous"),
        ):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    client.main(
                        [
                            "submit",
                            "--packet",
                            "packet.json",
                            "--runtime-home",
                            "runtime",
                        ]
                    ),
                    client.EXIT_AMBIGUOUS,
                )


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
