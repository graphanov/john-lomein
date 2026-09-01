#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from unittest import mock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from broker import john_lomein_broker_protocol as protocol
from broker import john_lomein_broker_receipts as receipts


def _load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


client = _load_script(
    "john_lomein_protected_submit_test",
    ROOT / "scripts" / "john-lomein-protected-submit.py",
)
protected = _load_script(
    "john_lomein_protected_actions_client_test",
    ROOT / "scripts" / "john_lomein_protected_actions.py",
)

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def _run(*argv: str) -> None:
    subprocess.run(
        list(argv),
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )


def _write_ed25519_pair(private_path: Path, public_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(client.canonical_json(value) + b"\n")
    path.chmod(0o600)


def _packet(
    *,
    action: str = "mark_pr_ready",
    pr_number: int = 17,
) -> dict[str, Any]:
    resolving = action == "resolve_review_thread"
    return protected.prepare_packet(
        {
            "schema_version": protected.INPUT_SCHEMA,
            "instance_slug": "widget-production",
            "action": action,
            "observed_at": "2026-07-16T11:59:00Z",
            "repo": "acme/widget",
            "pr": {
                "number": pr_number,
                "url": (
                    f"https://github.com/acme/widget/pull/{pr_number}"
                ),
                "base_branch": "main",
                "head_sha": "a" * 40,
                "author_login": "john-lomein[bot]",
                "is_draft": not resolving,
            },
            "preconditions": {
                "checks_state": "success",
                "unresolved_thread_count": 1 if resolving else 0,
                "forbidden_paths_clear": True,
                "bot_authorship_verified": True,
                "verification": {
                    "passed": True,
                    "commands_sha256": "b" * 64,
                    "result_sha256": "c" * 64,
                },
                "evidence_comment_url": (
                    f"https://github.com/acme/widget/pull/{pr_number}"
                    "#issuecomment-123"
                ),
            },
            "targets": {
                "thread_node_ids": (
                    ["PRRT_thread_1"] if resolving else []
                ),
                "thread_urls": (
                    [
                        f"https://github.com/acme/widget/pull/"
                        f"{pr_number}#discussion_r456"
                    ]
                    if resolving
                    else []
                ),
            },
        },
        now=NOW,
        ttl_seconds=300,
    )


class OneShotServer:
    def __init__(
        self,
        path: Path,
        response: bytes | None = None,
        *,
        raw_frame: bytes | None = None,
    ) -> None:
        self.path = path
        self.response = response
        self.raw_frame = raw_frame
        self.received: dict[str, Any] | None = None
        self.error: BaseException | None = None
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        os.chmod(path, 0o660)
        self.server.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    @staticmethod
    def _read_exact(connection: socket.socket, count: int) -> bytes:
        chunks: list[bytes] = []
        remaining = count
        while remaining:
            chunk = connection.recv(remaining)
            if not chunk:
                raise RuntimeError("request truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _serve(self) -> None:
        try:
            connection, _ = self.server.accept()
            with connection:
                header = self._read_exact(connection, 4)
                (length,) = struct.unpack("!I", header)
                raw = self._read_exact(connection, length)
                self.received = json.loads(raw)
                if self.raw_frame is not None:
                    connection.sendall(self.raw_frame)
                elif self.response is not None:
                    connection.sendall(
                        struct.pack("!I", len(self.response))
                        + self.response
                    )
        except BaseException as exc:  # pragma: no cover - surfaced by join
            self.error = exc
        finally:
            self.server.close()

    def __enter__(self) -> OneShotServer:
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            self.server.close()
            raise AssertionError("test broker server did not stop")
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        if self.error is not None:
            raise self.error


class BrokerClientFixture:
    root: Path
    packet: dict[str, Any]
    packet_path: Path
    private_config: dict[str, Any]
    public_config: dict[str, Any]
    public_config_path: Path

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.runtime = self.root / "runtime"
        (self.runtime / "scripts").mkdir(parents=True, mode=0o700)
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
        self.private_key = self.root / "receipt-private.pem"
        self.public_key = self.root / "receipt-public.pem"
        self.github_key = self.root / "github.pem"
        _write_ed25519_pair(self.private_key, self.public_key)
        _run(
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(self.github_key),
        )
        for path in (
            self.private_key,
            self.public_key,
            self.github_key,
        ):
            path.chmod(0o600)
        self.socket_path = self.root / "broker.sock"
        uid = os.getuid()
        fingerprint = hashlib.sha256(
            self.public_key.read_bytes()
        ).hexdigest()
        self.private_config = {
            "schema_version": protocol.CONFIG_SCHEMA,
            "enabled": True,
            "broker_id": "john-lomein-broker-widget",
            "broker_uid": uid,
            "transport": {
                "kind": protocol.TRANSPORT_KIND,
                "peer_credentials": protocol.PEER_CREDENTIAL_PROTOCOL,
                "socket_path": str(self.socket_path),
                "requester_uid": uid + 1,
                "submit_gid": os.getgid(),
                "max_request_bytes": 256 * 1024,
                "request_timeout_seconds": 10,
            },
            "github_app": {
                "app_id": 1234,
                "app_slug": "john-lomein-broker",
                "installation_id": 5678,
                "private_key_path": str(self.github_key),
                "api_base_url": protocol.GITHUB_API_BASE_URL,
            },
            "receipt_signing": {
                "key_id": "widget-receipts-2026-01",
                "private_key_path": str(self.private_key),
                "public_key_path": str(self.public_key),
                "public_key_sha256": fingerprint,
            },
            "state": {
                "database_path": str(self.root / "broker.sqlite"),
            },
            "instance": {
                "slug": "widget-production",
                "repository": {
                    "full_name": "acme/widget",
                    "id": 987654,
                    "default_branch": "main",
                },
                "policy": {
                    "allowed_actions": [
                        "mark_pr_ready",
                        "resolve_review_thread",
                    ],
                    "expected_pr_author_login": "john-lomein[bot]",
                    "required_checks": ["CI / test"],
                    "allow_no_required_checks": False,
                    "forbidden_path_prefixes": [".github/workflows"],
                    "require_same_repository_head": True,
                    "resolve_outdated_threads_only": True,
                    "require_evidence_marker": True,
                    "maximum_packet_ttl_seconds": 600,
                    "maximum_clock_skew_seconds": 30,
                    "accepted_check_conclusions": [
                        "NEUTRAL",
                        "SKIPPED",
                        "SUCCESS",
                    ],
                    "maximum_changed_files": 500,
                    "minimum_rate_limit_remaining": 100,
                },
                "budgets": {
                    "requests_per_hour": 30,
                    "mutation_attempts_per_day": 20,
                    "daily_mark_pr_ready": 10,
                    "daily_resolve_review_thread": 20,
                    "max_threads_per_submission": 1,
                    "consecutive_indeterminate_limit": 3,
                },
            },
        }
        self.public_config = {
            "schema_version": client.CLIENT_CONFIG_SCHEMA,
            "broker_id": self.private_config["broker_id"],
            "broker_uid": uid,
            "broker_config_sha256": protocol.config_digest(
                self.private_config
            ),
            "socket_path": str(self.socket_path),
            "public_key_path": str(self.public_key),
            "public_key_sha256": fingerprint,
            "key_id": "widget-receipts-2026-01",
            "connect_timeout_seconds": 5,
            "request_timeout_seconds": 10,
            "max_response_bytes": 256 * 1024,
            "instance_slug": "widget-production",
            "repository_full_name": "acme/widget",
            "repository_id": 987654,
            "default_branch": "main",
            "github_app_id": 1234,
            "github_app_slug": "john-lomein-broker",
            "github_installation_id": 5678,
        }
        self.public_config_path = self.root / "client.json"
        _write_json(self.public_config_path, self.public_config)
        self.packet = _packet()
        self.packet_path = self.root / "packet.json"
        _write_json(self.packet_path, self.packet)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def submission(
        self, packet_value: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        return {
            "schema_version": protocol.SUBMISSION_SCHEMA,
            "packet": dict(packet_value or self.packet),
        }

    def signed_completion(
        self,
        *,
        packet_value: Mapping[str, Any] | None = None,
        already_satisfied: bool = False,
    ) -> dict[str, Any]:
        selected = dict(packet_value or self.packet)
        submission = self.submission(selected)
        payload = receipts.build_receipt_payload(
            self.private_config,
            submission,
            precondition_digest="d" * 64,
            outcome="succeeded",
            reason_code=(
                "already_satisfied"
                if already_satisfied
                else "readback_verified"
            ),
            mutation_status=(
                "already_satisfied" if already_satisfied else "applied"
            ),
            readback_status="confirmed",
            started_at=NOW,
            mutation_attempted_at=(
                None
                if already_satisfied
                else NOW + timedelta(seconds=1)
            ),
            operation_id=(
                "" if already_satisfied else "github-mutation-123"
            ),
            readback_observed_at=NOW + timedelta(seconds=2),
            completed_at=NOW + timedelta(seconds=3),
            readback_head_sha=selected["request"]["pr"]["head_sha"],
            readback_pr_is_draft=False,
            resolved_thread_node_ids=selected["request"]["targets"][
                "thread_node_ids"
            ],
        )
        uid = os.getuid()
        return receipts.sign_receipt(
            payload,
            self.private_config,
            submission,
            key_owner_uids={uid},
            parent_owner_uids={uid},
            trusted_path_root=self.root,
        )

    def success_response(
        self,
        receipt: Mapping[str, Any] | None = None,
    ) -> bytes:
        return client.canonical_json(
            {
                "schema_version": client.RESPONSE_SCHEMA,
                "ok": True,
                "receipt": dict(receipt or self.signed_completion()),
            }
        )

    def submit(
        self,
        *,
        receipt_output: Path | None = None,
        validate_socket: bool = True,
        runtime_home: Path | None = None,
    ) -> dict[str, Any]:
        uid = os.getuid()
        return client.submit_packet(
            self.packet_path,
            runtime_home=runtime_home or self.runtime,
            client_config_path=self.public_config_path,
            receipt_output=receipt_output,
            now=NOW + timedelta(seconds=4),
            config_owner_uids={uid},
            key_owner_uids={uid},
            parent_owner_uids={uid},
            trusted_path_root=self.root,
            requester_uid=uid,
            allow_same_identity=True,
            validate_socket=validate_socket,
        )


class ProtectedBrokerClientTest(BrokerClientFixture, unittest.TestCase):
    def test_runtime_revocation_blocks_before_exchange(self):
        control = (
            self.runtime
            / "scripts"
            / "john-lomein-instance.env"
        )
        control.write_text(
            control.read_text(encoding="utf-8").replace(
                "BOT_MUTATION_ENABLED='1'",
                "BOT_MUTATION_ENABLED='0'",
            ),
            encoding="utf-8",
        )
        control.chmod(0o600)
        with mock.patch.object(client, "exchange") as exchange:
            with self.assertRaisesRegex(
                client.ProtectedSubmitError,
                "kill switch is disabled",
            ):
                self.submit(validate_socket=False)
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
        with (
            mock.patch.object(
                client,
                "SCRIPT_DIR",
                self.runtime / "scripts",
            ),
            mock.patch.object(client, "exchange") as exchange,
        ):
            with self.assertRaisesRegex(
                client.ProtectedSubmitError,
                "does not match deployed client",
            ):
                self.submit(
                    runtime_home=alternate,
                    validate_socket=False,
                )
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
                client.ProtectedSubmitError,
                "runtime authority does not match",
            ):
                self.submit(validate_socket=False)
        exchange.assert_not_called()

    def test_standalone_packet_contract_matches_request_producer(self):
        for packet_value in (
            self.packet,
            _packet(action="resolve_review_thread"),
        ):
            with self.subTest(
                action=packet_value["request"]["action"]
            ):
                self.assertEqual(
                    client.verify_packet(
                        packet_value,
                        now=NOW + timedelta(seconds=4),
                    ),
                    protected.verify_packet(
                        packet_value,
                        now=NOW + timedelta(seconds=4),
                    ),
                )

    def test_success_is_exactly_framed_verified_bound_and_persisted(self):
        receipt = self.signed_completion()
        output = self.root / "receipts" / "completed.json"
        output.parent.mkdir(mode=0o700)
        with OneShotServer(
            self.socket_path, self.success_response(receipt)
        ) as server:
            verified = self.submit(receipt_output=output)
        self.assertEqual(verified, receipt)
        self.assertEqual(
            client.normalize_receipt_envelope(receipt),
            receipts.normalize_receipt_envelope(receipt),
        )
        self.assertEqual(
            server.received,
            {
                "schema_version": client.SUBMISSION_SCHEMA,
                "packet": self.packet,
            },
        )
        self.assertEqual(
            output.read_bytes(),
            client.canonical_json(receipt) + b"\n",
        )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(
            client.default_client_config_path(self.packet),
            Path(
                "/private/etc/john-lomein-broker-public/"
                "widget-production.json"
            ),
        )

    def test_already_satisfied_with_confirmed_readback_is_success(self):
        receipt = self.signed_completion(already_satisfied=True)
        with OneShotServer(
            self.socket_path, self.success_response(receipt)
        ):
            self.assertEqual(self.submit(), receipt)

    def test_negative_daemon_response_and_signed_rejection_are_denied(self):
        unsigned_output = self.root / "unsigned-denial.json"
        negative = client.canonical_json(
            {
                "schema_version": client.RESPONSE_SCHEMA,
                "ok": False,
                "error": {"code": "request_rejected"},
            }
        )
        with OneShotServer(self.socket_path, negative):
            with self.assertRaises(
                client.BrokerDeniedError
            ) as denied:
                self.submit(receipt_output=unsigned_output)
        self.assertEqual(denied.exception.reason_code, "request_rejected")
        self.assertIsNone(denied.exception.receipt)
        self.assertFalse(unsigned_output.exists())

        submission = self.submission()
        rejected_payload = receipts.build_receipt_payload(
            self.private_config,
            submission,
            precondition_digest="d" * 64,
            outcome="rejected",
            reason_code="precondition_checks_failed",
            mutation_status="not_attempted",
            readback_status="not_attempted",
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=1),
        )
        uid = os.getuid()
        rejected = receipts.sign_receipt(
            rejected_payload,
            self.private_config,
            submission,
            key_owner_uids={uid},
            parent_owner_uids={uid},
            trusted_path_root=self.root,
        )
        signed_output = self.root / "signed-rejection.json"
        with OneShotServer(
            self.socket_path, self.success_response(rejected)
        ):
            with self.assertRaises(
                client.BrokerDeniedError
            ) as denied:
                self.submit(receipt_output=signed_output)
        self.assertEqual(
            denied.exception.reason_code,
            "precondition_checks_failed",
        )
        self.assertEqual(denied.exception.receipt, rejected)
        self.assertEqual(
            signed_output.read_bytes(),
            client.canonical_json(rejected) + b"\n",
        )

    def test_valid_indeterminate_receipt_is_persisted_but_not_completion(self):
        submission = self.submission()
        payload = receipts.build_receipt_payload(
            self.private_config,
            submission,
            precondition_digest="d" * 64,
            outcome="indeterminate",
            reason_code="indeterminate_readback_mismatch",
            mutation_status="applied",
            mutation_attempted_at=NOW + timedelta(seconds=1),
            operation_id="github-mutation-123",
            readback_status="not_confirmed",
            readback_observed_at=NOW + timedelta(seconds=2),
            readback_head_sha="a" * 40,
            readback_pr_is_draft=True,
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=3),
        )
        uid = os.getuid()
        indeterminate = receipts.sign_receipt(
            payload,
            self.private_config,
            submission,
            key_owner_uids={uid},
            parent_owner_uids={uid},
            trusted_path_root=self.root,
        )
        output = self.root / "indeterminate.json"
        with OneShotServer(
            self.socket_path, self.success_response(indeterminate)
        ):
            with self.assertRaises(
                client.BrokerDeniedError
            ) as denied:
                self.submit(receipt_output=output)
        self.assertEqual(
            denied.exception.reason_code,
            "indeterminate_readback_mismatch",
        )
        self.assertEqual(denied.exception.receipt, indeterminate)
        self.assertFalse(client.receipt_is_completion(indeterminate))
        self.assertEqual(
            output.read_bytes(),
            client.canonical_json(indeterminate) + b"\n",
        )

    def test_signature_tampering_and_wrong_key_fail_closed(self):
        tampered = self.signed_completion()
        tampered["signature"] = (
            ("A" if tampered["signature"][0] != "A" else "B")
            + tampered["signature"][1:]
        )
        with OneShotServer(
            self.socket_path, self.success_response(tampered)
        ):
            output = self.root / "invalid-signature.json"
            with self.assertRaisesRegex(
                client.ProtectedSubmitError, "verification failed"
            ):
                self.submit(receipt_output=output)
        self.assertFalse(output.exists())

        other_private = self.root / "other-private.pem"
        other_public = self.root / "other-public.pem"
        _write_ed25519_pair(other_private, other_public)
        other_private.chmod(0o600)
        other_public.chmod(0o600)
        hostile_config = copy.deepcopy(self.public_config)
        hostile_config["public_key_path"] = str(other_public)
        hostile_config["public_key_sha256"] = hashlib.sha256(
            other_public.read_bytes()
        ).hexdigest()
        _write_json(self.public_config_path, hostile_config)
        with OneShotServer(
            self.socket_path, self.success_response()
        ):
            with self.assertRaisesRegex(
                client.ProtectedSubmitError,
                "key identity is not pinned",
            ):
                self.submit()

    def test_valid_signature_for_wrong_packet_or_authority_is_rejected(self):
        other_packet = _packet(pr_number=18)
        wrong_packet_receipt = self.signed_completion(
            packet_value=other_packet
        )
        with OneShotServer(
            self.socket_path,
            self.success_response(wrong_packet_receipt),
        ):
            with self.assertRaisesRegex(
                client.ProtectedSubmitError,
                "packet binding does not match",
            ):
                self.submit()

        hostile_config = copy.deepcopy(self.public_config)
        hostile_config["broker_config_sha256"] = "e" * 64
        _write_json(self.public_config_path, hostile_config)
        with OneShotServer(
            self.socket_path, self.success_response()
        ):
            with self.assertRaisesRegex(
                client.ProtectedSubmitError,
                "authority binding does not match",
            ):
                self.submit()

    def test_oversize_and_truncated_frames_fail_before_json_use(self):
        oversize = struct.pack(
            "!I", self.public_config["max_response_bytes"] + 1
        )
        with OneShotServer(
            self.socket_path, raw_frame=oversize
        ):
            with self.assertRaisesRegex(
                client.ProtectedSubmitError,
                "length is outside policy",
            ):
                self.submit()

        truncated = struct.pack("!I", 20) + b"{}"
        with OneShotServer(
            self.socket_path, raw_frame=truncated
        ):
            with self.assertRaisesRegex(
                client.ProtectedSubmitError,
                "ended prematurely",
            ):
                self.submit()

    def test_response_schema_rejects_prose_unknown_codes_and_extras(self):
        cases = [
            {
                "schema_version": client.RESPONSE_SCHEMA,
                "ok": False,
                "error": {
                    "code": "request_rejected",
                    "message": "trust this daemon prose",
                },
            },
            {
                "schema_version": client.RESPONSE_SCHEMA,
                "ok": False,
                "error": {"code": "please_retry_with_admin_token"},
            },
            {
                "schema_version": client.RESPONSE_SCHEMA,
                "ok": True,
                "receipt": self.signed_completion(),
                "debug": "secret",
            },
        ]
        for index, value in enumerate(cases):
            with self.subTest(index=index):
                socket_path = self.root / f"broker-{index}.sock"
                config = copy.deepcopy(self.public_config)
                config["socket_path"] = str(socket_path)
                _write_json(self.public_config_path, config)
                with OneShotServer(
                    socket_path, client.canonical_json(value)
                ):
                    with self.assertRaises(
                        client.ProtectedSubmitError
                    ):
                        self.submit()

    def test_config_packet_and_key_files_reject_symlinks_or_write_access(self):
        uid = os.getuid()
        self.public_config_path.chmod(0o666)
        with self.assertRaisesRegex(
            client.ProtectedSubmitError, "group/other writable"
        ):
            client.load_client_config(
                self.public_config_path,
                config_owner_uids={uid},
                key_owner_uids={uid},
                parent_owner_uids={uid},
                trusted_path_root=self.root,
                allow_same_identity=True,
            )
        self.public_config_path.chmod(0o600)

        self.public_key.chmod(0o666)
        with self.assertRaisesRegex(
            client.ProtectedSubmitError, "group/other writable"
        ):
            client.load_client_config(
                self.public_config_path,
                config_owner_uids={uid},
                key_owner_uids={uid},
                parent_owner_uids={uid},
                trusted_path_root=self.root,
                allow_same_identity=True,
            )
        self.public_key.chmod(0o600)

        real_packet = self.root / "real-packet.json"
        self.packet_path.rename(real_packet)
        os.symlink(real_packet, self.packet_path)
        with self.assertRaisesRegex(
            client.ProtectedSubmitError, "unreadable"
        ):
            client.load_packet(
                self.packet_path, now=NOW + timedelta(seconds=4)
            )

        fifo = self.root / "packet.fifo"
        os.mkfifo(fifo, mode=0o600)
        with self.assertRaisesRegex(
            client.ProtectedSubmitError, "regular non-symlink"
        ):
            client.load_packet(
                fifo, now=NOW + timedelta(seconds=4)
            )

    def test_receipt_output_is_idempotent_and_conflicts_fail_closed(self):
        receipt = self.signed_completion()
        output = self.root / "receipt.json"
        first = client.persist_receipt(
            output,
            receipt,
            owner_uids={os.getuid()},
            trusted_path_root=self.root,
        )
        second = client.persist_receipt(
            output,
            receipt,
            owner_uids={os.getuid()},
            trusted_path_root=self.root,
        )
        self.assertEqual(first, second)
        output.write_text("different\n", encoding="utf-8")
        output.chmod(0o600)
        with self.assertRaisesRegex(
            client.ProtectedSubmitError, "conflicts|unsafe"
        ):
            client.persist_receipt(
                output,
                receipt,
                owner_uids={os.getuid()},
                trusted_path_root=self.root,
            )

        output.unlink()
        target = self.root / "target.json"
        target.write_text("different\n", encoding="utf-8")
        target.chmod(0o600)
        os.symlink(target, output)
        with self.assertRaisesRegex(
            client.ProtectedSubmitError, "unsafe"
        ):
            client.persist_receipt(
                output,
                receipt,
                owner_uids={os.getuid()},
                trusted_path_root=self.root,
            )

    def test_persisted_receipt_reverifies_after_packet_expiry(self):
        receipt = self.signed_completion()
        output = self.root / "receipt.json"
        client.persist_receipt(
            output,
            receipt,
            owner_uids={os.getuid()},
            trusted_path_root=self.root,
        )
        uid = os.getuid()
        verified = client.verify_receipt_file(
            self.packet_path,
            output,
            client_config_path=self.public_config_path,
            now=NOW + timedelta(days=1),
            config_owner_uids={uid},
            key_owner_uids={uid},
            parent_owner_uids={uid},
            trusted_path_root=self.root,
            requester_uid=uid + 1,
        )
        self.assertEqual(verified, receipt)

        tampered = json.loads(output.read_text(encoding="utf-8"))
        tampered["payload"]["reason_code"] = "tampered"
        _write_json(output, tampered)
        with self.assertRaisesRegex(
            client.ProtectedSubmitError,
            "completion evidence|digest does not match",
        ):
            client.verify_receipt_file(
                self.packet_path,
                output,
                client_config_path=self.public_config_path,
                now=NOW + timedelta(days=1),
                config_owner_uids={uid},
                key_owner_uids={uid},
                parent_owner_uids={uid},
                trusted_path_root=self.root,
                requester_uid=uid + 1,
            )

    def test_client_config_is_strict_and_requires_separate_identity(self):
        unknown = copy.deepcopy(self.public_config)
        unknown["debug"] = True
        with self.assertRaisesRegex(
            client.ProtectedSubmitError, "unknown fields"
        ):
            client.normalize_client_config(unknown)

        uid = os.getuid()
        with self.assertRaisesRegex(
            client.ProtectedSubmitError, "separate OS identity"
        ):
            client.load_client_config(
                self.public_config_path,
                config_owner_uids={uid},
                key_owner_uids={uid},
                parent_owner_uids={uid},
                trusted_path_root=self.root,
                requester_uid=uid,
            )


if __name__ == "__main__":
    unittest.main()
