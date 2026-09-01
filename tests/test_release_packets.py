#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SCRIPT = ROOT / "scripts" / "john_lomein_release_packets.py"
spec = importlib.util.spec_from_file_location(
    "john_lomein_release_packets", SCRIPT
)
assert spec and spec.loader
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

from release_broker import john_lomein_release_broker_protocol as broker
from tests.test_release_broker_protocol import (
    NOW,
    owner_envelope,
    release_bundle,
)


APPROVAL = (
    "APPROVE JOHN-LOMEIN RELEASE BUNDLE: squash-merge the exact listed PR; "
    "DO NOT publish."
)


class ReleasePacketRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.bundle = release_bundle()
        self.assertion = owner_envelope(
            self.bundle,
            self.private_key,
            approval_text=APPROVAL,
        )

    def prepare(self) -> dict:
        return runtime.prepare_packet(
            bundle=self.bundle,
            approval_text=APPROVAL,
            owner_assertion=self.assertion,
            now=NOW,
            ttl_seconds=300,
        )

    def test_runtime_packet_is_independently_accepted_by_protected_boundary(self):
        packet = self.prepare()
        self.assertEqual(runtime.verify_packet(packet, now=NOW), packet)
        protected = broker.normalize_release_packet(packet, now=NOW)
        self.assertEqual(protected, packet)
        verified = broker.verify_owner_assertion_signature(
            protected["request"]["owner_assertion"],
            public_key=self.public_key,
            expected_key_id="owner-2026-01",
            expected_issuer="trusted-owner-gateway",
            allowed_actor_ids={"owner-123"},
            now=NOW,
        )
        self.assertEqual(verified, self.assertion)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("Ed25519PrivateKey", source)
        self.assertNotIn("private_key.sign", source)

    def test_packet_tampering_and_owner_binding_fail_closed(self):
        packet = self.prepare()
        tampered = copy.deepcopy(packet)
        tampered["request"]["bundle"]["ordered_prs"][0][
            "head_sha"
        ] = "f" * 40
        with self.assertRaises(runtime.ReleasePacketError):
            runtime.verify_packet(tampered, now=NOW)

        tampered_tree = copy.deepcopy(packet)
        tampered_tree["request"]["bundle"]["ordered_prs"][0][
            "expected_merge_tree_sha"
        ] = "f" * 40
        with self.assertRaises(runtime.ReleasePacketError):
            runtime.verify_packet(tampered_tree, now=NOW)

        wrong_owner = copy.deepcopy(self.assertion)
        wrong_owner["payload"]["bundle_id"] = "jlb-" + "f" * 24
        with self.assertRaisesRegex(
            runtime.ReleasePacketError, "bundle_id"
        ):
            runtime.prepare_packet(
                bundle=self.bundle,
                approval_text=APPROVAL,
                owner_assertion=wrong_owner,
                now=NOW,
            )

    def test_persistence_is_mode_0600_idempotent_and_collision_safe(self):
        packet = self.prepare()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "runtime"
            path = runtime.persist_packet(home, packet, now=NOW)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                packet,
            )
            self.assertEqual(
                runtime.persist_packet(home, packet, now=NOW),
                path,
            )
            path.write_text('{"hostile":true}', encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(
                runtime.ReleasePacketError, "collision"
            ):
                runtime.persist_packet(home, packet, now=NOW)

    def test_persistence_rejects_symlinked_outbox_and_unsafe_packet_id(self):
        packet = self.prepare()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "runtime"
            state = home / "state"
            state.mkdir(parents=True)
            outside = Path(temporary) / "outside"
            outside.mkdir()
            os.symlink(
                outside,
                state / "protected-releases",
                target_is_directory=True,
            )
            with self.assertRaisesRegex(
                runtime.ReleasePacketError, "directory is unsafe"
            ):
                runtime.persist_packet(home, packet, now=NOW)

        hostile = copy.deepcopy(packet)
        hostile["packet_id"] = "../../escape"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                runtime.ReleasePacketError, "ID does not match"
            ):
                runtime.persist_packet(
                    Path(temporary), hostile, now=NOW
                )
            self.assertFalse((Path(temporary).parent / "escape").exists())

    def test_expired_assertion_cannot_prepare_a_new_packet(self):
        expired = owner_envelope(
            self.bundle,
            self.private_key,
            approval_text=APPROVAL,
            issued_at="2026-07-16T11:40:00Z",
            expires_at="2026-07-16T11:50:00Z",
        )
        with self.assertRaisesRegex(
            runtime.ReleasePacketError, "assertion has expired"
        ):
            runtime.prepare_packet(
                bundle=self.bundle,
                approval_text=APPROVAL,
                owner_assertion=expired,
                now=NOW,
            )

    def test_live_v1_refuses_multi_pr_bundle_without_train_attestation(self):
        bundle = copy.deepcopy(self.bundle)
        second = release_bundle(
            pr_number=18,
            head_sha="e" * 40,
            paths=["src/second.py"],
        )["ordered_prs"][0]
        second["position"] = 1
        bundle["ordered_prs"].append(second)
        bundle["bundle_digest"] = runtime.bundle_digest(bundle)
        bundle["bundle_id"] = runtime.bundle_id(bundle)
        assertion = owner_envelope(
            bundle,
            self.private_key,
            approval_text=APPROVAL,
        )
        with self.assertRaisesRegex(
            runtime.ReleasePacketError, "exactly one PR"
        ):
            runtime.prepare_packet(
                bundle=bundle,
                approval_text=APPROVAL,
                owner_assertion=assertion,
                now=NOW,
            )

    def test_loader_rejects_duplicate_fields_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"x":1,"x":2}', encoding="utf-8")
            with self.assertRaisesRegex(
                runtime.ReleasePacketError, "duplicate"
            ):
                runtime.load_json(duplicate, field="fixture")
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                runtime.ReleasePacketError, "unreadable"
            ):
                runtime.load_json(link, field="fixture")
            text_link = root / "approval-link.txt"
            text_link.symlink_to(target)
            with self.assertRaisesRegex(
                runtime.ReleasePacketError, "unreadable"
            ):
                runtime.load_text(
                    text_link,
                    field="approval",
                    maximum_bytes=4096,
                )

    def test_cli_prints_only_a_relative_packet_locator(self):
        current = datetime.now(timezone.utc).replace(microsecond=0)
        bundle = release_bundle()
        bundle["created_at"] = broker.utc_text(
            current - timedelta(minutes=1)
        )
        bundle["expires_at"] = broker.utc_text(
            current + timedelta(minutes=20)
        )
        bundle["bundle_digest"] = runtime.bundle_digest(bundle)
        bundle["bundle_id"] = runtime.bundle_id(bundle)
        assertion = owner_envelope(
            bundle,
            self.private_key,
            approval_text=APPROVAL,
            issued_at=broker.utc_text(current - timedelta(seconds=10)),
            expires_at=broker.utc_text(current + timedelta(minutes=10)),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle_path = root / "bundle.json"
            assertion_path = root / "assertion.json"
            approval_path = root / "approval.txt"
            home = root / "runtime"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            assertion_path.write_text(
                json.dumps(assertion), encoding="utf-8"
            )
            approval_path.write_text(APPROVAL + "\n", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = runtime.main(
                    [
                        "prepare",
                        "--bundle",
                        str(bundle_path),
                        "--approval-file",
                        str(approval_path),
                        "--owner-assertion",
                        str(assertion_path),
                        "--runtime-home",
                        str(home),
                        "--ttl-seconds",
                        "300",
                    ]
                )
            self.assertEqual(code, 0)
            result = json.loads(stdout.getvalue())
            self.assertFalse(
                Path(result["packet_locator"]).is_absolute()
            )
            self.assertTrue(
                result["packet_locator"].startswith(
                    "state/protected-releases/outbox/"
                )
            )
            self.assertNotIn(str(home), stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
